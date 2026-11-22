//! Bounded HTTP/1.1 transport for the existing private worker fixture only.
use super::*;
use lane_router::lane_client::{self as sdk, Id};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

const CAP: usize = 65_536;
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct TcpClient {
    address: SocketAddr,
    http: reqwest::Client,
}

impl TcpClient {
    pub(super) async fn send(
        &self,
        request: Request,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        self.send_bounded(request, |_| CAP)
            .await
            .expect("bounded fixture reply")
    }

    pub(super) async fn send_bounded(
        &self,
        request: Request,
        cap: impl FnOnce(StatusCode) -> usize,
    ) -> Result<
        (StatusCode, axum::http::HeaderMap, Vec<u8>),
        lane_router::lane_client::TransportError,
    > {
        use axum::http::{header, Method, Version};
        use lane_router::lane_client::TransportError;
        let (parts, body) = request.into_parts();
        assert_eq!(self.address.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(self.address.port(), 0);
        assert!(parts.uri.scheme().is_none() && parts.uri.authority().is_none());
        assert!(parts.uri.query().is_none());
        assert!(
            parts.uri.path().starts_with(&format!("{ACTOR_BASE}/"))
                || (parts.uri.path() == "/v1/diffuser/discovery" && parts.method == Method::GET)
        );
        assert!(matches!(parts.method, Method::GET | Method::POST));
        assert!(!parts.headers.contains_key(header::HOST));
        let mut response = self
            .http
            .request(
                parts.method.clone(),
                format!("http://{}{}", self.address, parts.uri),
            )
            .headers(parts.headers)
            .body(to_bytes(body, CAP).await.expect("bounded fixture request"))
            .send()
            .await
            .map_err(|_| TransportError::Unavailable)?;
        assert_eq!(response.remote_addr(), Some(self.address));
        assert_eq!(response.version(), Version::HTTP_11);
        let status = response.status();
        let headers = response.headers().clone();
        let mut bytes = Vec::new();
        let cap = CAP.min(cap(status));
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| TransportError::Unavailable)?
        {
            if chunk.len() > cap - bytes.len() {
                return Err(TransportError::ResponseLimit);
            }
            bytes.extend_from_slice(&chunk);
        }
        println!(
            "FIXTURE_HTTP {}",
            json!({
                "peer": self.address, "version": "HTTP/1.1", "method": parts.method.as_str(),
                "path": parts.uri.path(), "status": status.as_u16(),
                "content_type": headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
                "bytes": bytes.len(), "sha256": hex::encode(Sha256::digest(&bytes))
            })
        );
        Ok((status, headers, bytes))
    }
}

pub(super) struct Listener {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), &'static str>>,
}

impl Listener {
    pub(super) async fn start(app: Router) -> (Self, TcpClient) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopping) = oneshot::channel();
        let task = tokio::spawn(lane_assignment::serve_injected(listener, app, async {
            let _ = stopping.await;
        }));
        let http = reqwest::Client::builder()
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .timeout(DEADLINE)
            .build()
            .unwrap();
        (
            Self {
                stop: Some(stop),
                task,
            },
            TcpClient { address, http },
        )
    }

    pub(super) async fn close(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(DEADLINE, &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) struct SdkLoopback {
    tcp: TcpClient,
    client: Client,
    identity: sdk::Identity,
}

impl sdk::Transport for SdkLoopback {
    fn identity(&self) -> &sdk::Identity {
        &self.identity
    }

    async fn send(
        &self,
        request: axum::http::Request<axum::body::Bytes>,
        limits: sdk::ResponseLimits,
    ) -> Result<axum::http::Response<axum::body::Bytes>, sdk::TransportError> {
        let (mut parts, bytes) = request.into_parts();
        assert!(!parts.headers.contains_key("authorization"));
        parts.headers.insert(
            "authorization",
            format!("Bearer {}", self.client.token).parse().unwrap(),
        );
        let (status, headers, bytes) = self
            .tcp
            .send_bounded(Request::from_parts(parts, Body::from(bytes)), |status| {
                limits.for_status(status)
            })
            .await?;
        let mut reply = axum::http::Response::new(bytes.into());
        *reply.status_mut() = status;
        *reply.headers_mut() = headers;
        *reply.version_mut() = axum::http::Version::HTTP_11;
        Ok(reply)
    }
}

pub(super) fn typed_client(f: &Family) -> sdk::Client<SdkLoopback> {
    sdk::Client::new(SdkLoopback {
        tcp: f
            .client
            .tcp
            .clone()
            .expect("typed SDK requires fixture TCP"),
        client: f.client.clone(),
        identity: sdk::Identity {
            tenant: Id::new("tenant_123456789").unwrap(),
            project: Id::new("project_12345678").unwrap(),
            actor: Id::new("agent_1234567890").unwrap(),
        },
    })
}

pub(super) fn receipt_dir(f: &Family, name: &str) -> PathBuf {
    let path = f.root.0.join(name);
    dir(&path);
    path
}

pub(super) async fn start_http(case: &str) -> (Family, Listener) {
    let mut f = Family::start(case);
    let (listener, tcp) = Listener::start(f.client.app.take().unwrap()).await;
    drop(f.foreign.app.take());
    f.client.tcp = Some(tcp.clone());
    f.foreign.tcp = Some(tcp);
    assert!(
        f.client.tcp.is_some(),
        "SDK proof requires loopback TCP, not Router::oneshot"
    );
    (f, listener)
}

// The product binary only consumes an existing bearer; the fixture alone issues it.
async fn operator(f: &Family, auth: bool, args: &[&str], status: i32) -> Value {
    use std::process::{Command, Stdio};
    let executable = std::env::var_os("DIFFUSER_TEST_CLI").expect("CLI walkthrough binary");
    let address = f.client.tcp.as_ref().unwrap().address.to_string();
    let arguments: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let token = auth.then(|| f.client.token.clone());
    let output = tokio::task::spawn_blocking(move || {
        let mut child = Command::new(executable)
            .args([
                "diffuser",
                "operator",
                &address,
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                if auth { "bearer-stdin" } else { "anonymous" },
            ])
            .args(&arguments)
            .env_remove("LANE_JOB_ROOT")
            .stdin(if auth { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(token) = token {
            // Closing the pipe signals EOF. A preflight refusal may exit before reading.
            let write = child.stdin.take().unwrap().write_all(token.as_bytes());
            if let Err(e) = write {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
            }
        }
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    let stream = if output.status.success() {
        &output.stdout
    } else {
        &output.stderr
    };
    println!(
        "CLI_PROCESS {}",
        json!({"fixture_authority":auth,"command":args[0],
        "peer":f.client.tcp.as_ref().unwrap().address,"exit":output.status.code(),
        "output":serde_json::from_slice::<Value>(stream).ok()})
    );
    assert_eq!(output.status.code(), Some(status), "{}", args[0]);
    assert!(if status == 0 {
        output.stderr.is_empty()
    } else {
        output.stdout.is_empty()
    });
    serde_json::from_slice(stream).unwrap()
}

#[tokio::test]
#[ignore = "requires DIFFUSER_TEST_CLI and the private offline walkthrough runner"]
async fn operator_cpu_and_cuda_process_walkthrough() {
    const UUID: &str = "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const OTHER: &str = "GPU-11111111-1111-1111-1111-111111111111";
    for (case, cpu) in [("normal", true), ("cuda-b", false)] {
        let (mut f, listener) = start_http(case).await;
        f.refresh(&[]);
        let deny = operator(&f, false, &["discover"], 74).await;
        assert_eq!(deny["error"]["http_status"], 401);
        assert_eq!(deny["error"]["code"], "auth_required");
        let d = operator(&f, true, &["discover"], 0).await;
        assert!(d["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["lane_id"] == "lane_cpu_inspect" && l["accepting"] == false));
        let state = receipt_dir(&f, "cli-receipts");
        let dir = state.to_str().unwrap();
        let input = f.root.0.join("cli-input.json");
        fs::write(
            &input,
            if cpu {
                BODY
            } else {
                b"{\"schema_version\":\"diffuser-private-cuda-input/v1\",\"workload\":\"add_one\"}"
            },
        )
        .unwrap();
        f.refresh(&[]);
        let uploaded = operator(
            &f,
            true,
            &[
                "upload",
                dir,
                "start",
                "cli_upload_key_v1",
                input.to_str().unwrap(),
            ],
            0,
        )
        .await;
        let artifact = uploaded["object_id"].as_str().unwrap();
        let acquire = if cpu { "cpu-acquire" } else { "cuda-acquire" };
        let pin = if cpu { "lane_cpu_inspect" } else { UUID };
        f.refresh(&[]);
        let assigned = operator(
            &f,
            true,
            &[
                acquire,
                dir,
                "start",
                "cli_acquire_key_v1",
                pin,
                "1000",
                "16777216",
                "2097152",
                "4000",
                "12000",
            ],
            0,
        )
        .await;
        assert_eq!(assigned["state"], "assigned");
        let assignment = assigned["assignment_id"].as_str().unwrap();
        let submit = if cpu { "cpu-submit" } else { "cuda-submit" };
        let resume = if cpu { "cpu-resume" } else { "cuda-resume" };
        let key = "cli_submit_key_v1";
        let name = "cli_client_job_v1";
        let mut call = vec![
            submit, dir, "start", key, assignment, name, artifact, "4000",
        ];
        let mut read = vec![resume, dir, key];
        if !cpu {
            call.extend([UUID, "add_one"]);
            read.extend([name, artifact, "4000", UUID, "add_one"]);
            let refusal_state = receipt_dir(&f, "cli-refusal-receipts");
            let mut wrong = call.clone();
            wrong[1] = refusal_state.to_str().unwrap();
            wrong[3] = "cli_wrong_pin_key_v1";
            wrong[8] = OTHER;
            let denied = operator(&f, true, &wrong, 74).await;
            assert_eq!(denied["error"]["code"], "capability_unavailable");
            assert_eq!(denied["error"]["http_status"], 422);
            assert_eq!(worker_counts(&f.w_root).0, 0);
            wrong[8] = "0";
            assert_eq!(
                operator(&f, true, &wrong, 64).await["error"]["code"],
                "invalid_identifier"
            );
            wrong[8] = UUID;
            wrong[9] = "other";
            assert_eq!(
                operator(&f, true, &wrong, 64).await["error"]["code"],
                "unsupported_workload"
            );
        }
        f.refresh(&[]);
        let submitted = operator(&f, true, &call, 0).await;
        let job = submitted["job_id"].as_str().unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let value = operator(&f, true, &read, 0).await;
                assert_eq!(value["job"]["job_id"], job);
                if value["job"]["state"] == "succeeded" {
                    break value;
                }
                assert!(value["result"].is_null());
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        if cpu {
            assert_eq!(result["result"]["report"]["rounds"], 3);
            let expected = (0..3).fold(b"abc".to_vec(), |last, _| Sha256::digest(last).to_vec());
            assert_eq!(
                result["result"]["report"]["output_sha256"],
                hex::encode(expected)
            );
        } else {
            assert_eq!(result["result"]["report"]["device_uuid"], UUID);
            assert_eq!(result["result"]["report"]["workload"], "add_one");
            assert_eq!(
                result["result"]["report"]["values"],
                json!((1..=16).collect::<Vec<_>>())
            );
            let mut wrong = read.clone();
            wrong[6] = OTHER;
            assert_eq!(
                operator(&f, true, &wrong, 74).await["error"]["code"],
                "receipt_conflict"
            );
        }
        call[2] = "retry";
        f.refresh(&[]);
        assert_eq!(operator(&f, true, &call, 0).await["job_id"], job);
        assert_eq!(worker_counts(&f.w_root), (1, 1, 0, 0));
        let job_view = operator(&f, true, &["job", job], 0).await;
        assert_eq!(job_view, result["job"]);
        let revision = job_view["revision"].to_string();
        let cancelled = operator(
            &f,
            true,
            &["cancel", dir, "start", "cli_cancel_key_v1", job, &revision],
            0,
        )
        .await;
        assert_eq!(cancelled["state"], "succeeded"); // Existing result wins cancellation.
        f.refresh(&[]);
        let view = operator(&f, true, &["assignment", assignment], 0).await;
        let revision = view["revision"].to_string();
        let release = operator(
            &f,
            true,
            &[
                "release",
                dir,
                "start",
                "cli_release_key_v1",
                assignment,
                &revision,
            ],
            0,
        )
        .await;
        assert_eq!(release["state"], "draining");
        assert_eq!(f.counts(), (1, 1, 1));
        assert!(f
            .claims
            .lock()
            .unwrap()
            .assignment_stop_recorded(assignment)
            .unwrap());
        let (_, applied, replay) = f.cleanup(assignment);
        assert_eq!(applied["released_now"], true);
        assert_eq!(replay["released_now"], false);
        assert_eq!(f.counts(), (0, 0, 0));
        let old_expiry = {
            let a = f.authority.read().unwrap();
            a.observed_at + a.freshness_ms
        };
        tokio::time::sleep(Duration::from_millis(
            old_expiry.saturating_sub(wall_now().unwrap()) + 1,
        ))
        .await;
        let stale = operator(&f, true, &["assignment", assignment], 74).await;
        assert_eq!(stale["error"]["http_status"], 412);
        assert_eq!(stale["error"]["code"], "evidence_stale");
        f.refresh(&[]);
        assert_eq!(
            operator(&f, true, &["assignment", assignment], 0).await["state"],
            "closed"
        );
        f.shutdown();
        assert!(dead(&f.w_pin));
        assert_eq!(operator(&f, true, &read, 0).await, result);
        let id = result["job"]["result_artifact_id"].as_str().unwrap();
        let got = operator(&f, true, &["artifact", id], 0).await;
        assert_eq!(got["metadata"], result["result"]["metadata"]);
        listener.close().await;
        let mut disk = la_artifacts::ArtifactStore::open(&f.root.0.join("controller")).unwrap();
        let (manifest, bytes) = disk
            .read_manifest_and_content(
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                id,
                wall_now().unwrap(),
            )
            .unwrap();
        assert_eq!(got["content_hex"], hex::encode(&bytes));
        assert_eq!(manifest.digest, sdk::Sha256Digest::of(&bytes).as_str());
        let journal = sdk::ReceiptStore::open(&state).unwrap();
        let who = typed_client(&f).identity().clone();
        for (key, status) in [
            ("cli_upload_key_v1", 201),
            ("cli_acquire_key_v1", 202),
            ("cli_submit_key_v1", 202),
            ("cli_cancel_key_v1", 202),
            ("cli_release_key_v1", 202),
        ] {
            let receipt = journal.read(&who, &sdk::Id::new(key).unwrap()).unwrap();
            assert_eq!(receipt.http_status, Some(status));
            if key == "cli_submit_key_v1" {
                assert_eq!(
                    receipt
                        .returned
                        .unwrap()
                        .result_artifact_id
                        .unwrap()
                        .as_str(),
                    id
                );
            }
            println!(
                "CLI_MUTATION_STATUS {}",
                json!({"case":case,"key":key,"http_status":status})
            );
        }
        write_evidence(
            &format!("cli-{case}"),
            &json!({"fixture_authority":true,"case":case,"worker_exit_joined":true,
            "one_work_entry":true,"counts_after_stop":[1,1,1],"counts_after_commit":f.counts(),
            "cleanup_commit":applied,"cleanup_replay":replay,"result_sha256":manifest.digest,"reopened_store_bytes_match":true}),
        );
    }
}
