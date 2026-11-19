use super::*;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

#[derive(Debug, Eq, PartialEq)]
struct Exchange(Method, String, StatusCode);

struct Loopback {
    address: SocketAddr,
    identity: Identity,
    authorization: HeaderValue,
    http: reqwest::Client,
    exchanges: Arc<Mutex<Vec<Exchange>>>,
}

impl Transport for Loopback {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    async fn send(
        &self,
        request: WireRequest,
        limits: ResponseLimits,
    ) -> std::result::Result<WireResponse, TransportError> {
        let (parts, payload) = request.into_parts();
        if self.address.ip() != Ipv4Addr::LOCALHOST
            || self.address.port() == 0
            || parts.uri.scheme().is_some()
            || parts.uri.authority().is_some()
            || parts.uri.query().is_some()
            || !parts.uri.path().starts_with("/v1/diffuser/")
            || parts.headers.contains_key(header::AUTHORIZATION)
            || parts.headers.contains_key(header::HOST)
        {
            return Err(TransportError::Unavailable);
        }
        let mut response = self
            .http
            .request(
                parts.method.clone(),
                format!("http://{}{}", self.address, parts.uri),
            )
            .headers(parts.headers)
            .header(header::AUTHORIZATION, self.authorization.clone())
            .body(payload)
            .send()
            .await
            .map_err(|_| TransportError::Unavailable)?;
        if response.remote_addr() != Some(self.address)
            || response.version() != axum::http::Version::HTTP_11
        {
            return Err(TransportError::Unavailable);
        }
        let status = response.status();
        let headers = response.headers().clone();
        let cap = limits.for_status(status);
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| TransportError::Unavailable)?
        {
            if chunk.len() > cap.saturating_sub(bytes.len()) {
                return Err(TransportError::ResponseLimit);
            }
            bytes.extend_from_slice(&chunk);
        }
        let path = parts.uri.to_string();
        println!(
            "HTTP {}",
            json!({"peer":self.address.to_string(),"version":"HTTP/1.1","method":parts.method.as_str(),"path":path,
            "status":status.as_u16(),"content_type":headers.get(header::CONTENT_TYPE).and_then(|v|v.to_str().ok()),
            "response_bytes":bytes.len(),"response_sha256":Sha256Digest::of(&bytes)})
        );
        self.exchanges
            .lock()
            .unwrap()
            .push(Exchange(parts.method, path, status));
        let mut result = WireResponse::new(Bytes::from(bytes));
        *result.status_mut() = status;
        *result.headers_mut() = headers;
        *result.version_mut() = response.version();
        Ok(result)
    }
}

#[tokio::test]
async fn sdk_cpu_lifecycle_over_private_loopback() {
    use super::super::super::{la_artifacts, lane_assignment};
    let fixture = Fixture::with_backend(Some(true), true);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopping) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(lane_assignment::serve_injected(
        listener,
        fixture.app.clone(),
        async {
            let _ = stopping.await;
        },
    ));
    let exchanges = Arc::new(Mutex::new(Vec::new()));
    let connect = || {
        Client::new(Loopback {
            address,
            identity: fixture_identity(),
            authorization: fixture_header(&fixture.agent),
            http: reqwest::Client::builder()
                .http1_only()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .pool_max_idle_per_host(0)
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            exchanges: exchanges.clone(),
        })
    };
    let client = connect();
    let discovery = client
        .discover()
        .await
        .expect("authenticated discovery over TCP");
    let lane = discovery
        .negotiate(
            "lane_cpu_inspect",
            INSPECT_CAPABILITY,
            INSPECT_PROFILE,
            INSPECT_REVISION,
        )
        .unwrap();
    println!(
        "DISCOVERY {}",
        json!({"lane":lane.lane_id,"capability":lane.capability,"profile":lane.profile_id,"accepting":lane.accepting,"reason":lane.reason})
    );
    let journal = fixture.journal("typed-receipts");
    let journal_path = fixture.root.0.join("typed-receipts");
    let input = Bytes::from_static(
        br#"{"schema_version":"diffuser-private-sha256-input/v1","data_hex":"616263","rounds":2}"#,
    );
    let uploaded = client
        .upload(
            &journal,
            Attempt::Start(&id("fixture_upload_001")),
            input.clone(),
        )
        .await
        .unwrap();
    let assigned = client
        .acquire(
            &journal,
            Attempt::Start(&id("fixture_acquire_01")),
            &acquire_body(),
        )
        .await
        .unwrap();
    assert_eq!(assigned.state, AssignmentState::Assigned);
    let assignment = assigned.assignment_id;
    let submit_key = id("typed_cpu_submit_01");
    let submit = CpuSubmit::new(id("typed_client_job_01"), uploaded.object_id, 4000).unwrap();
    let accepted = client
        .submit_cpu(&journal, Attempt::Start(&submit_key), &assignment, &submit)
        .await
        .unwrap();
    assert_eq!(accepted.state, JobState::Succeeded);
    let resumed = client.resume_cpu_job(&journal, &submit_key).await.unwrap();
    assert_eq!(resumed.job.job_id, accepted.job_id);
    assert_eq!(resumed.job.state, JobState::Succeeded);
    let (artifact, report) = resumed.result.unwrap();
    let output = &artifact.metadata.artifact_id;
    let digest = Sha256Digest::of(&artifact.bytes);
    assert_eq!(artifact.metadata.sha256, digest);
    assert_eq!(report.sha256, Sha256Digest::of(&input));
    assert_eq!(report.bytes, input.len() as u64);
    let first_digest = hex::decode(Sha256Digest::of(b"abc").as_str()).unwrap();
    assert_eq!(report.output_sha256, Sha256Digest::of(&first_digest));
    let current = client.assignment(&assignment).await.unwrap();
    let release = client
        .release(
            &journal,
            Attempt::Start(&id("fixture_release_01")),
            &assignment,
            &Revision {
                schema_version: LaneSchema::V1,
                expected_revision: current.revision,
            },
        )
        .await
        .unwrap();
    assert_eq!(release.state, AssignmentState::Draining);
    assert!(!release.released());
    drop(client);
    drop(journal);

    let fresh = connect();
    let journal = ReceiptStore::open(journal_path).unwrap();
    assert_eq!(
        fresh.assignment(&assignment).await.unwrap().state,
        AssignmentState::Draining
    );
    let readback = fresh.resume_cpu_job(&journal, &submit_key).await.unwrap();
    assert_eq!(readback.job, resumed.job);
    assert_eq!(readback.result.unwrap(), (artifact.clone(), report.clone()));
    drop(fresh);
    drop(journal);
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let prefix = "/v1/diffuser/projects/project_12345678";
    let jobs = format!("{prefix}/jobs/{}", accepted.job_id);
    let artifacts = format!("{prefix}/artifacts/{output}");
    let content = format!("{artifacts}/content");
    let assignments = format!("{prefix}/assignments/{assignment}");
    let get = |path: &str| Exchange(Method::GET, path.into(), StatusCode::OK);
    let post = |path: &str, status| Exchange(Method::POST, path.into(), status);
    assert_eq!(
        *exchanges.lock().unwrap(),
        [
            get("/v1/diffuser/discovery"),
            post(&format!("{prefix}/artifacts"), StatusCode::CREATED),
            post(&format!("{prefix}/assignments"), StatusCode::ACCEPTED),
            post(&format!("{assignments}/jobs"), StatusCode::ACCEPTED),
            get(&jobs),
            get(&artifacts),
            get(&content),
            get(&assignments),
            post(&format!("{assignments}/release"), StatusCode::ACCEPTED),
            get(&assignments),
            get(&jobs),
            get(&artifacts),
            get(&content),
        ]
    );
    assert_eq!(
        fixture.work_entries.lock().unwrap()[0].1,
        accepted.job_id.as_str()
    );
    assert_eq!(fixture.work_entries.lock().unwrap().len(), 1);
    let root = fixture.root.0.clone();
    // Drop the router and its worker and storage handles before reopening the stores.
    let Fixture {
        app,
        agent,
        root: fixture_directory,
        work_entries,
    } = fixture;
    drop((app, agent, work_entries));
    let mut store = la_artifacts::ArtifactStore::open(&root.join("service")).unwrap();
    let identity = fixture_identity();
    let (disk, bytes) = store
        .read_manifest_and_content(
            identity.tenant.as_str(),
            identity.project.as_str(),
            identity.actor.as_str(),
            output.as_str(),
            now_ms(),
        )
        .unwrap();
    assert_eq!(disk.digest, digest.as_str());
    assert_eq!(disk.bytes, bytes.len() as u64);
    assert_eq!(disk.assignment.as_deref(), Some(assignment.as_str()));
    assert_eq!(disk.job.as_deref(), Some(accepted.job_id.as_str()));
    assert_eq!(disk.kind, "output");
    assert_eq!(bytes, artifact.bytes.as_ref());
    let worker_db = rusqlite::Connection::open_with_flags(
        root.join("worker/worker.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let (worker_state, worker_digest, worker_bytes): (String, String, i64) = worker_db.query_row(
        "SELECT o.state,r.digest,r.byte_count FROM operations o JOIN worker_result_receipts r ON r.operation=o.op WHERE o.job=?1",
        [accepted.job_id.as_str()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(
        (worker_state.as_str(), worker_digest.as_str(), worker_bytes),
        ("complete", digest.as_str(), i64::try_from(disk.bytes).unwrap())
    );
    let worker_close: i64 = worker_db
        .query_row("SELECT COUNT(*) FROM worker_close_receipts", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(worker_close, 1);
    let claims =
        super::super::super::la_store::ClaimStore::open(&root.join("service/claims.sqlite"))
            .unwrap();
    let (held, charged, outbox) = claims.counts().unwrap();
    assert_eq!((held, charged), (1, 1));
    assert_eq!(claims.state(assignment.as_str()).unwrap(), "draining");
    assert!(claims
        .assignment_stop_recorded(assignment.as_str())
        .unwrap());
    let db = rusqlite::Connection::open_with_flags(
        root.join("service/claims.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let stop_digest: Vec<u8> = db
        .query_row(
            "SELECT receipt_digest FROM la_assignment_stop_receipts WHERE assignment_id=?1",
            [assignment.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stop_digest.len(), 32);
    let witnessed: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM la_assignment_cleanup_receipts",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(witnessed, 0);
    let proof = json!({"assignment":assignment,"job":accepted.job_id,"artifact":output,"durable_bytes":disk.bytes,
        "durable_sha256":digest,"worker_receipt_sha256":worker_digest,"input_sha256":report.sha256,
        "compute_sha256":report.output_sha256,"same_bytes_after_release_request":true,"same_bytes_after_listener_and_worker_drop":true,
        "assignment_state":"draining","signed_worker_stop_ack_digest":hex::encode(stop_digest),
        "worker_close_receipts":worker_close,"witnessed_cleanup_receipts":witnessed,"held_claims":held,"quota_charges":charged,"outbox":outbox,"work_entries":1});
    println!("LIFECYCLE {proof}");
    if let Some(dir) = std::env::var_os("DIFFUSER_LOOPBACK_RECEIPT") {
        let dir = PathBuf::from(dir);
        fs::write(dir.join("durable-result.json"), bytes).unwrap();
        fs::write(
            dir.join("lifecycle.json"),
            serde_json::to_vec_pretty(&proof).unwrap(),
        )
        .unwrap();
    }
    drop((store, worker_db, claims, db));
    drop(fixture_directory);
    assert!(!root.exists());
}
