use super::{
    fixture_http::{receipt_dir, start_http, typed_client},
    *,
};
use la_backend::cuda::DeviceUuid;
use lane_router::lane_client::{
    self as sdk, Attempt, CudaAcquire as SdkAcquire, CudaDeviceUuid, CudaSubmit as SdkSubmit,
    CudaWorkload, DisconnectPolicy, Id, LaneSchema, QueuePolicy, ReceiptStore, Revision,
};
use serde::Serialize;

const GPU_A: &str = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const GPU_B: &str = "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const API: &str = "compute.cuda.add-one/v1";
const BACKEND: &str = "cuda-private-add-one/v1";
const CUDA_BODY: &[u8] =
    br#"{"schema_version":"diffuser-private-cuda-input/v1","workload":"add_one"}"#;

pub(super) fn case_pin(case: &str) -> la_backend::cuda::DeviceUuid {
    la_backend::cuda::DeviceUuid::parse(if case == "cuda-b" { GPU_B } else { GPU_A }).unwrap()
}

pub(super) fn case_mode(case: &str) -> &'static str {
    match case {
        "cuda-reversed" => "reversed",
        "cuda-b" | "cuda-a" => "",
        "cuda-missing" => "b-only",
        "cuda-no-driver" => "no-driver",
        "cuda-close-failure" => "close-failure",
        _ => panic!("unknown CUDA fixture case"),
    }
}

pub(super) fn build_helper(root: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cosp/cuda_fixture");
    let binary = root.join("cuda-helper");
    let status = Command::new("/usr/bin/timeout")
        .args([
            "-k",
            "2s",
            "30s",
            "/usr/bin/c++",
            "-std=c++17",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
        ])
        .arg(source.join("add_one.cpp"))
        .arg(source.join("fake_driver.cpp"))
        .arg("-o")
        .arg(&binary)
        .status()
        .unwrap();
    assert!(status.success(), "CUDA fixture compiler: {status}");
    let symbols = Command::new("/usr/bin/timeout")
        .args(["5s", "/usr/bin/nm", "-a"])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let symbols = String::from_utf8(symbols.stdout).unwrap();
    for name in ["dlopen", "dlsym", "dlclose"] {
        assert!(symbols
            .lines()
            .any(|line| line.ends_with(&format!(" T __wrap_{name}"))));
        assert!(!symbols
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("U {name}"))));
    }
}

// Independent wire witness and malformed/foreign request coverage.
#[derive(Serialize)]
struct CudaAcquire {
    schema_version: LaneSchema,
    capability: &'static str,
    lane_id: Option<Id>,
    profile_id: Option<&'static str>,
    resource_id: Option<Id>,
    provider_id: Option<Id>,
    requested_hardware_description: Option<String>,
    resources: CudaResources,
    queue_policy: QueuePolicy,
    requested_lease_ms: u64,
    requested_tenure_ms: u64,
}

#[derive(Serialize)]
struct CudaResources {
    cpu_millicores: u64,
    ram_bytes: u64,
    storage_bytes: u64,
    gpu_domains: [DeviceUuid; 1],
}

#[derive(Clone, Serialize)]
struct CudaSubmit {
    schema_version: &'static str,
    client_job_id: Id,
    capability: &'static str,
    profile_version: &'static str,
    input_artifact_ids: [Id; 1],
    parameters: CudaParameters,
    max_runtime_ms: u64,
    disconnect_policy: DisconnectPolicy,
}

#[derive(Clone, Serialize)]
struct CudaParameters {
    backend: &'static str,
    device_uuid: DeviceUuid,
    workload: &'static str,
}

fn acquire(uuid: &str) -> CudaAcquire {
    CudaAcquire {
        schema_version: LaneSchema::V1,
        capability: API,
        lane_id: None,
        profile_id: Some(BACKEND),
        resource_id: None,
        provider_id: None,
        requested_hardware_description: None,
        resources: CudaResources {
            cpu_millicores: 1000,
            ram_bytes: 16_777_216,
            storage_bytes: 2_097_152,
            gpu_domains: [DeviceUuid::parse(uuid).unwrap()],
        },
        queue_policy: QueuePolicy::Refuse,
        requested_lease_ms: 4000,
        requested_tenure_ms: 12000,
    }
}

fn cuda_submit(input: &str, uuid: &str) -> CudaSubmit {
    CudaSubmit {
        schema_version: "diffuser-lane/v2",
        client_job_id: Id::new("private_typed_job01").unwrap(),
        capability: API,
        profile_version: "1",
        input_artifact_ids: [Id::new(input).unwrap()],
        parameters: CudaParameters {
            backend: BACKEND,
            device_uuid: DeviceUuid::parse(uuid).unwrap(),
            workload: "add_one",
        },
        max_runtime_ms: 4000,
        disconnect_policy: DisconnectPolicy::ContinueUntilJobDeadline,
    }
}

fn typed_acquire(uuid: &str) -> SdkAcquire {
    assert_eq!(
        CudaDeviceUuid::new(uuid.to_ascii_lowercase()),
        Err(sdk::Error::InvalidIdentifier)
    );
    let request = SdkAcquire::new(
        CudaDeviceUuid::new(uuid).unwrap(),
        1000,
        16_777_216,
        2_097_152,
        4000,
        12000,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::to_value(acquire(uuid)).unwrap()
    );
    request
}

fn typed_submit(input: &str, uuid: &str) -> SdkSubmit {
    let request = SdkSubmit::new(
        Id::new("private_typed_job01").unwrap(),
        Id::new(input).unwrap(),
        CudaDeviceUuid::new(uuid).unwrap(),
        CudaWorkload::AddOne,
        4000,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::to_value(cuda_submit(input, uuid)).unwrap()
    );
    request
}

fn release_revision(view: &Value) -> Revision {
    Revision {
        schema_version: LaneSchema::V1,
        expected_revision: view["revision"].as_u64().unwrap(),
    }
}

#[tokio::test]
async fn cuda_route_exact_device_result_and_release() {
    exact_device("cuda-reversed", GPU_A, GPU_B).await;
    exact_device("cuda-b", GPU_B, GPU_A).await;
    // Same hardware order and caller pin as the dlclose-only negative.
    exact_device("cuda-a", GPU_A, GPU_B).await;
}

async fn exact_device(case: &str, wanted: &str, other: &str) {
    let (mut f, listener) = start_http(case).await;
    f.refresh(&[]);
    let client = typed_client(&f);
    let receipt_path = receipt_dir(&f, "cuda-sdk-receipts");
    let store = ReceiptStore::open(&receipt_path).unwrap();
    let acquire_key = Id::new("cuda_acquire_exact").unwrap();
    let acquired = client
        .acquire_cuda(&store, Attempt::Start(&acquire_key), &typed_acquire(wanted))
        .await
        .expect("typed CUDA acquire over fixture TCP");
    assert_eq!(acquired.state, sdk::AssignmentState::Assigned);
    let assignment_id = acquired.assignment_id.clone();
    let assignment = assignment_id.as_str();
    let assigned = serde_json::to_value(acquired).unwrap();
    let receipt = store.read(client.identity(), &acquire_key).unwrap();
    assert_eq!(receipt.http_status, Some(202));
    assert_eq!(receipt.returned.unwrap().object_id, assignment_id);
    let path = format!("/assignments/{assignment}");
    let submit_path = format!("{path}/jobs");
    let input = f.client.upload("cuda_input_exact_v1", CUDA_BODY).await;
    let request = cuda_submit(&input, wanted);
    let (_, denied) = f
        .foreign
        .call("POST", &submit_path, "cuda_foreign_post", request.clone())
        .await;
    assert_eq!(denied["error"]["code"], "object_not_found", "{denied}");
    for (mutation, code) in [
        (
            serde_json::to_value(cuda_submit(&input, other)).unwrap(),
            "capability_unavailable",
        ),
        (
            {
                let mut r = serde_json::to_value(&request).unwrap();
                r["parameters"]["workload"] = json!("other");
                r
            },
            "capability_unavailable",
        ),
        (
            {
                let mut r = serde_json::to_value(&request).unwrap();
                r["parameters"]["argv"] = json!(["ignored"]);
                r
            },
            "schema_invalid",
        ),
        (submit(&input, true), "capability_unavailable"),
        (submit(&input, false), "capability_unavailable"),
    ] {
        let (_, denied) = f
            .client
            .call("POST", &submit_path, "cuda_invalid_post", mutation)
            .await;
        assert_eq!(denied["error"]["code"], code, "{denied}");
    }
    assert_eq!(worker_counts(&f.w_root), (0, 0, 0, 0));
    assert_eq!(f.claims.lock().unwrap().job_history_count().unwrap(), 0);
    f.refresh(&[]);
    let submit_key = Id::new("cuda_submit_exact").unwrap();
    let body = typed_submit(&input, wanted);
    let wrong_body = typed_submit(&input, other);
    let refusal_store = ReceiptStore::open(receipt_dir(&f, "cuda-refusal-receipts")).unwrap();
    let denied = client
        .submit_cuda(
            &refusal_store,
            Attempt::Start(&Id::new("cuda_sdk_wrong_pin").unwrap()),
            &assignment_id,
            &wrong_body,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(denied, sdk::Error::Public(error) if error.code == sdk::PublicCode::CapabilityUnavailable && error.status == StatusCode::UNPROCESSABLE_ENTITY)
    );
    assert_eq!(worker_counts(&f.w_root), (0, 0, 0, 0));
    let accepted = client
        .submit_cuda(&store, Attempt::Start(&submit_key), &assignment_id, &body)
        .await
        .unwrap();
    let job = accepted.job_id.as_str();
    let job_path = format!("/jobs/{job}");
    let deadline = Instant::now() + Duration::from_millis(500);
    let terminal = loop {
        let (status, v) = f.client.call("GET", &job_path, "", Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        if v["state"] == "succeeded" || Instant::now() >= deadline {
            break v;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    };
    assert_eq!(terminal["state"], "succeeded", "{terminal}");
    assert_eq!(worker_counts(&f.w_root), (1, 1, 0, 0));
    let cmd = f.claims.lock().unwrap().job_permit_command(job).unwrap();
    let replay = f.replay_exact_worker_result(&cmd.operation);
    let output = terminal["result_artifact_id"].as_str().unwrap();
    let (artifact, typed_report) = client
        .resume_cuda_job(&store, &submit_key, &body)
        .await
        .unwrap()
        .result
        .unwrap();
    assert_eq!(typed_report.device_uuid.as_str(), wanted);
    assert_eq!(typed_report.workload, CudaWorkload::AddOne);
    let bytes = artifact.bytes;
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["schema_version"], "diffuser-private-cuda-output/v1");
    assert_eq!(report["device_uuid"], wanted);
    assert_eq!(report["workload"], "add_one");
    assert_eq!(report["values"], json!((1..=16).collect::<Vec<_>>()));
    assert_eq!(report["sha256"], hex::encode(Sha256::digest(CUDA_BODY)));
    assert_eq!(f.foreign.artifact(output).await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        client.resume_job(&store, &submit_key).await,
        Err(sdk::Error::ReceiptConflict)
    );
    assert_eq!(
        client.resume_cpu_job(&store, &submit_key).await,
        Err(sdk::Error::ReceiptConflict)
    );
    assert_eq!(
        client
            .resume_cuda_job(&store, &submit_key, &wrong_body)
            .await,
        Err(sdk::Error::ReceiptConflict)
    );
    let retry = client
        .submit_cuda(&store, Attempt::Retry(&submit_key), &assignment_id, &body)
        .await
        .unwrap();
    assert_eq!(&retry.job_id, &accepted.job_id);
    assert_eq!(worker_counts(&f.w_root), (1, 1, 0, 0));
    let (_, view) = f.client.call("GET", &path, "", Value::Null).await;
    let (status, close) = f
        .client
        .call(
            "POST",
            &format!("{path}/release"),
            "cuda_release_exact",
            release_revision(&view),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{close}");
    assert_eq!(f.counts(), (1, 1, 1));
    assert!(f
        .claims
        .lock()
        .unwrap()
        .assignment_stop_recorded(assignment)
        .unwrap());
    let (certificate, cleanup, cleanup_replay) = f.cleanup(assignment);
    assert_eq!(f.counts(), (0, 0, 0));
    let driver_trace = fs::read_to_string(f.root.0.join("cuda-driver.trace")).unwrap();
    assert_eq!(
        driver_trace.lines().collect::<Vec<_>>(),
        [
            "loader:fixture",
            "init",
            "count",
            "count",
            if case == "cuda-a" {
                "context:1"
            } else {
                "context:0"
            },
            "allocate:64",
            "upload",
            "module",
            "entry:add_one",
            "launch:16",
            "sync",
            "download",
            "sync",
            "free",
            "unload",
            "destroy",
            "close"
        ]
    );
    let helper_digest = file_digest(f.root.0.join("cuda-helper"));

    // Cleanup and trace readback can outlast the execution-time observation.
    // First prove that the old observation still expires, then advance the
    // existing witnessed source before shutting down the last ACK producer.
    let old_expiry = {
        let authority = f.authority.read().unwrap();
        authority.observed_at + authority.freshness_ms
    };
    tokio::time::sleep(Duration::from_millis(
        old_expiry.saturating_sub(wall_now().unwrap()) + 1,
    ))
    .await;
    let (status, _, denied) = f.client.artifact(output).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    let denied: Value = serde_json::from_slice(&denied).unwrap();
    assert_eq!(denied["error"]["code"], "evidence_stale", "{denied}");
    f.refresh(&[]);
    assert_eq!(f.counts(), (0, 0, 0));
    f.shutdown();
    drop(store);
    let store = ReceiptStore::open(&receipt_path).unwrap();
    let resumed = client
        .resume_cuda_job(&store, &submit_key, &body)
        .await
        .unwrap();
    assert_eq!(resumed.job.job_id, accepted.job_id);
    assert_eq!(resumed.result.unwrap().0.bytes, bytes);
    let receipt = store.read(client.identity(), &submit_key).unwrap();
    assert_eq!(receipt.http_status, Some(202));
    let returned = receipt.returned.unwrap();
    assert_eq!(returned.object_id, accepted.job_id);
    assert_eq!(returned.assignment_id.as_ref(), Some(&assignment_id));
    assert_eq!(
        returned.result_artifact_id.as_ref(),
        Some(&Id::new(output).unwrap())
    );
    listener.close().await;
    let mut store = la_artifacts::ArtifactStore::open(&f.root.0.join("controller")).unwrap();
    let (disk, on_disk) = store
        .read_manifest_and_content(
            "tenant_123456789",
            "project_12345678",
            "agent_1234567890",
            output,
            wall_now().unwrap(),
        )
        .unwrap();
    let digest = hex::encode(Sha256::digest(&bytes));
    assert_eq!(disk.digest, digest);
    assert_eq!(disk.bytes, bytes.len() as u64);
    assert_eq!(disk.kind, "output");
    assert_eq!(disk.assignment.as_deref(), Some(assignment));
    assert_eq!(disk.job.as_deref(), Some(job));
    assert_eq!(on_disk.as_slice(), bytes.as_ref());
    if let Some(dir) = std::env::var_os("DIFFUSER_TYPED_PROOF_DIR") {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(PathBuf::from(dir).join(format!("{case}-durable-artifact.json")))
            .unwrap();
        file.write_all(&on_disk).unwrap();
        file.sync_all().unwrap();
    }
    write_evidence(
        &format!("{case}-durable"),
        &json!({
            "sha256": digest, "bytes": disk.bytes, "artifact": output, "job": job, "sdk_receipt_returned": returned,
            "assignment": assignment, "reopened_after_worker_and_listener_exit": true
        }),
    );
    write_evidence(
        case,
        &json!({"source":f.binding.source_digest,"worker":f.w_id,"command":cmd,"assignment":assigned,"terminal":terminal,"report":report,"worker_replay":replay,"release":close,"cleanup_certificate":certificate,"cleanup":cleanup,"cleanup_replay":cleanup_replay,"counts":f.counts(),"stale_readback_code":denied["error"]["code"],"readback_source_sequence":f.sequence,"readback_after_worker_exit":true,"driver_trace":driver_trace,"helper_sha256":helper_digest}),
    );
}

#[tokio::test]
async fn cuda_route_cleanup_failure_keeps_job_and_assignment_held() {
    let case = "cuda-close-failure";
    let (mut f, listener) = start_http(case).await;
    let client = typed_client(&f);
    let store = ReceiptStore::open(receipt_dir(&f, "cuda-sdk-receipts")).unwrap();
    let channel =
        la_store::open_pinned_readonly_database(&f.w_root, "worker-channel.sqlite").unwrap();
    f.refresh(&[]);
    let assigned = client
        .acquire_cuda(
            &store,
            Attempt::Start(&Id::new("cuda_cleanup_acquire").unwrap()),
            &typed_acquire(GPU_A),
        )
        .await
        .unwrap();
    let assignment = assigned.assignment_id.as_str();
    let path = format!("/assignments/{assignment}");
    let input = f.client.upload("cuda_cleanup_input", CUDA_BODY).await;
    let body = typed_submit(&input, GPU_A);
    let submit_key = Id::new("cuda_cleanup_submit").unwrap();
    f.refresh(&[]);
    let accepted = client
        .submit_cuda(
            &store,
            Attempt::Start(&submit_key),
            &assigned.assignment_id,
            &body,
        )
        .await
        .unwrap();
    let job = accepted.job_id.as_str();
    let job_path = format!("/jobs/{job}");
    let command = f.claims.lock().unwrap().job_permit_command(job).unwrap();
    let deadline = Instant::now() + Duration::from_millis(500);
    let (observed, refused) = loop {
        let (status, observed) = f.client.call("GET", &job_path, "", Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{observed}");
        let mut rows = channel.prepare("SELECT request,response FROM channel_log WHERE response IS NOT NULL ORDER BY sequence").unwrap();
        let refusal = rows.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))).unwrap().find_map(|row| {
            let (request, response) = row.unwrap();
            let request: SignedRequest = serde_json::from_slice(&request).unwrap();
            let reply: SignedResponse = serde_json::from_slice(&response).unwrap();
            let matching_fetch = matches!(&request.request.operation, WorkerOperation::Fetch(c) if c.operation == command.operation && c.job == job);
            if !matching_fetch || !matches!(&reply.response.reply, WorkerReply::Refused { code } if code == "execution_uncertain") {
                return None;
            }
            assert!(reply.response.binding == f.binding);
            assert_eq!(reply.response.sequence, request.request.sequence);
            assert_eq!(reply.response.request_digest, hex::encode(Sha256::digest(serde_json::to_vec(&request.request).unwrap())));
            assert_eq!(typed_mac(&keys().reply, b"diffuser-rpc-response/v1\0", &reply.response).unwrap(), reply.mac);
            Some(serde_json::to_value(reply).unwrap())
        });
        if refusal.is_some() || observed["state"] == "succeeded" || Instant::now() >= deadline {
            break (observed, refusal);
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    };
    let driver_trace = fs::read_to_string(f.root.0.join("cuda-driver.trace")).unwrap();
    assert_eq!(
        driver_trace
            .lines()
            .filter(|line| *line != "CUDA cleanup failed: dlclose rc=1")
            .collect::<Vec<_>>(),
        [
            "loader:fixture",
            "init",
            "count",
            "count",
            "context:1",
            "allocate:64",
            "upload",
            "module",
            "entry:add_one",
            "launch:16",
            "sync",
            "download",
            "sync",
            "free",
            "unload",
            "destroy",
            "close",
            "injected:close-failure"
        ]
    );
    write_evidence(
        "cuda-close-failure-observed",
        &json!({"source":f.binding.source_digest,"observed":observed,"worker_fetch_refusal":refused,"driver_trace":driver_trace,"worker_counts":worker_counts(&f.w_root),"claim_counts":f.counts()}),
    );
    assert_eq!(
        observed["state"], "running",
        "cleanup failure must not publish success: {observed}"
    );
    assert!(observed["result_artifact_id"].is_null());
    let refused = refused.expect("authenticated worker Fetch must refuse uncertain execution");
    assert!(driver_trace.ends_with("injected:close-failure\nCUDA cleanup failed: dlclose rc=1\n"));

    let (status, view) = f.client.call("GET", &path, "", Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["state"], "assigned");
    let release_path = format!("{path}/release");
    let revision = release_revision(&view);

    // Start the release/readback window only after the uncertain Fetch, its
    // durable evidence, and the release request are ready. The real witness
    // still sees the same worker. Never refresh once draining: refresh
    // reconciles stops and would no longer observe the single release attempt.
    assert!(!dead(&f.w_pin));
    f.refresh(&[]);
    let (source_sequence, issued_at, expires_at) = observation_window(&f);
    let release_started = wall_now().unwrap();
    let (status, release) = f
        .client
        .call("POST", &release_path, "cuda_cleanup_release", revision)
        .await;
    let release_finished = wall_now().unwrap();
    assert_eq!(status, StatusCode::ACCEPTED,
        "POST {release_path}: {release}; source {source_sequence}, issued {issued_at}, expires {expires_at}, request [{release_started}, {release_finished}]");
    assert_eq!(release["state"], "draining");
    let (status, after_release) = f.client.call("GET", &job_path, "", Value::Null).await;
    let get_finished = wall_now().unwrap();
    assert_eq!(status, StatusCode::OK,
        "GET {job_path}: {after_release}; source {source_sequence}, issued {issued_at}, expires {expires_at}, request [{release_finished}, {get_finished}]");
    assert_eq!(after_release["state"], "stopping");
    let typed = client.resume_cuda_job(&store, &submit_key, &body).await;
    let sdk_finished = wall_now().unwrap();
    let typed = typed.unwrap_or_else(|error| panic!(
        "SDK GET {job_path}: {error:?}; source {source_sequence}, issued {issued_at}, expires {expires_at}, request [{get_finished}, {sdk_finished}]"
    ));
    assert_eq!(
        observation_window(&f),
        (source_sequence, issued_at, expires_at)
    );
    assert_eq!(typed.job.state, sdk::JobState::Stopping);
    assert_eq!(typed.job.job_id, accepted.job_id);
    assert!(typed.result.is_none());
    assert!(store
        .read(client.identity(), &submit_key)
        .unwrap()
        .returned
        .unwrap()
        .result_artifact_id
        .is_none());
    assert!(after_release["result_artifact_id"].is_null());
    assert_eq!(worker_counts(&f.w_root), (1, 0, 0, 0));
    let worker = la_store::open_pinned_readonly_database(&f.w_root, "worker.sqlite").unwrap();
    let marker: (String, bool) = worker
        .query_row(
            "SELECT state,report IS NULL FROM operations WHERE op=?1 AND job=?2",
            rusqlite::params![command.operation, job],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(marker, ("started".into(), true));
    let controller =
        la_store::open_pinned_readonly_database(&f.c_root, "lane_assignments.sqlite").unwrap();
    let result_rows: i64 = controller
        .query_row(
            "SELECT COUNT(*) FROM la_job_results WHERE job=?1",
            [job],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(result_rows, 0);
    let output_rows: i64 = controller
        .query_row(
            "SELECT COUNT(*) FROM la_artifacts WHERE kind='output'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(output_rows, 0);
    assert_eq!(f.counts(), (1, 1, 1));
    let claims = f.claims.lock().unwrap();
    assert_eq!(claims.job_history_count().unwrap(), 1);
    assert!(!claims.assignment_stop_recorded(assignment).unwrap());
    assert!(!claims.terminal_release_eligible(assignment).unwrap());
    drop(claims);
    let current = identity(f.w_id.pid).unwrap();
    assert!(current.descendants.is_empty());
    assert!(dead(f.h_pin.as_ref().unwrap()));
    let snapshot = json!({"profile":"private-loopback-cpu-fixture/v1","worker":current,"original_helper":f.h_id,"zero_descendants":true});
    let cleanup = cleanup::Certificate::inspect_fixture_witnessed_state(
        &f.binding,
        &keys(),
        &f.w_root,
        &f.c_root,
        &f.p_root,
        &f.root.0.join("custody"),
        &json!(f.w_id),
        &snapshot,
        assignment,
        wall_now().unwrap(),
        None,
    )
    .err()
    .expect("no cleanup certificate for uncertain work");
    // The witness cannot even form the claim snapshot without the stop ACK.
    assert_eq!(cleanup, "state_conflict");
    f.shutdown();
    listener.close().await;
    assert_eq!(f.counts(), (1, 1, 1));
    write_evidence(
        case,
        &json!({"source":f.binding.source_digest,"worker":f.w_id,"helper":f.h_id,"helper_sha256":file_digest(f.root.0.join("cuda-helper")),"command":command,"assignment":assigned,"observed":observed,"worker_fetch_refusal":refused,"release":release,"job_after_release":after_release,"worker_marker":marker,"worker_counts":worker_counts(&f.w_root),"result_rows":result_rows,"output_rows":output_rows,"cleanup_certificate_refused":cleanup,"process_observation":snapshot,"claim_counts_after_fixture_shutdown":f.counts(),"driver_trace":driver_trace,"release_window":{"sequence":source_sequence,"issued_at":issued_at,"expires_at":expires_at,"release_started":release_started,"release_finished":release_finished,"job_get_finished":get_finished,"sdk_get_finished":sdk_finished}}),
    );
}

// Read, but never set, the actual source used by HTTP authorization.
fn observation_window(f: &Family) -> (u64, u64, u64) {
    let authority = f.authority.read().unwrap();
    (
        authority.observation_sequence,
        authority.observed_at,
        authority
            .observed_at
            .checked_add(authority.freshness_ms)
            .unwrap(),
    )
}

#[tokio::test]
async fn cuda_route_release_refuses_actual_expired_evidence() {
    let (mut f, listener) = start_http("cuda-close-failure").await;
    let client = typed_client(&f);
    let store = ReceiptStore::open(receipt_dir(&f, "cuda-expired-receipts")).unwrap();
    f.refresh(&[]);
    let assigned = client
        .acquire_cuda(
            &store,
            Attempt::Start(&Id::new("cuda_expired_acquire").unwrap()),
            &typed_acquire(GPU_A),
        )
        .await
        .unwrap();
    let path = format!("/assignments/{}", assigned.assignment_id.as_str());
    let (status, view) = f.client.call("GET", &path, "", Value::Null).await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["state"], "assigned");
    let revision = release_revision(&view);
    let release_path = format!("{path}/release");
    let (sequence, issued_at, expires_at) = observation_window(&f);
    let held_before = f.counts();
    assert_eq!(held_before, (1, 1, 0)); // no job submitted, so no outbox entry
    let before_wait = wall_now().unwrap();
    assert!(
        before_wait < expires_at,
        "initial observation must still be fresh"
    );
    tokio::time::sleep(Duration::from_millis(expires_at - before_wait + 1)).await;
    let request_at = wall_now().unwrap();
    assert!(
        request_at >= expires_at,
        "observation must actually have expired"
    );
    assert!(!dead(&f.w_pin));
    let (status, refusal) = f
        .client
        .call("POST", &release_path, "cuda_expired_release", revision)
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{refusal}");
    assert_eq!(refusal["error"]["code"], "evidence_stale");
    assert_eq!(observation_window(&f), (sequence, issued_at, expires_at));
    let controller =
        la_store::open_pinned_readonly_database(&f.c_root, "lane_assignments.sqlite").unwrap();
    let release_rows: i64 = controller
        .query_row("SELECT COUNT(*) FROM la_assignment_release_keys", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(release_rows, 0);
    assert_eq!(f.counts(), held_before);
    assert_eq!(worker_counts(&f.w_root), (0, 0, 0, 0));
    f.shutdown();
    listener.close().await;
    assert_eq!(f.counts(), held_before);
    write_evidence(
        "cuda-expired-release",
        &json!({
            "path": release_path, "status": status.as_u16(), "refusal": refusal,
            "sequence": sequence, "issued_at": issued_at, "expires_at": expires_at,
            "request_at": request_at, "release_rows": release_rows,
            "claim_counts_before": held_before, "claim_counts": f.counts()
        }),
    );
}

#[tokio::test]
async fn cuda_route_unavailable_never_claims_or_falls_back() {
    for (case, expected_trace) in [
        ("cuda-missing", "loader:fixture\ninit\ncount\nclose\n"),
        ("cuda-no-driver", "loader:fixture\n"),
    ] {
        let mut f = Family::start(case);
        f.refresh(&[]);
        let (status, denied) = f
            .client
            .call(
                "POST",
                "/assignments",
                "cuda_acquire_missing",
                acquire(GPU_A),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{denied}");
        assert_eq!(denied["error"]["code"], "capability_unavailable");
        assert_eq!(worker_counts(&f.w_root), (0, 0, 0, 0));
        assert_eq!(f.counts(), (0, 0, 0));
        let driver_trace = fs::read_to_string(f.root.0.join("cuda-driver.trace")).unwrap();
        assert_eq!(driver_trace, expected_trace);
        f.shutdown();
        write_evidence(
            case,
            &json!({"source":f.binding.source_digest,"denied":denied,"driver_trace":driver_trace,"counts":f.counts()}),
        );
    }
    let mut f = Family::start("normal");
    f.refresh(&[]);
    let (status, denied) = f
        .client
        .call(
            "POST",
            "/assignments",
            "cuda_without_fixture",
            acquire(GPU_A),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{denied}");
    assert_eq!(denied["error"]["code"], "capability_unavailable");
    assert_eq!(worker_counts(&f.w_root), (0, 0, 0, 0));
    assert_eq!(f.counts(), (0, 0, 0));
    // The unused legacy CPU fixture still owns its idle helper. Ordinary
    // worker shutdown closes it without ever entering work.
    f.kill();
    write_evidence(
        "cuda-default-closed",
        &json!({"source":f.binding.source_digest,"denied":denied,"counts":f.counts()}),
    );
}
