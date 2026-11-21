use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

#[tokio::test]
async fn closed_discovery_uses_lane_envelope_without_legacy_state() {
    for admin in [false, true] {
        let root = std::env::temp_dir().join(format!("la-safe-{}-{admin}", std::process::id()));
        assert!(!root.exists());
        let state = Spine {
            root: root.clone(),
            edge: false,
            worker_ports: [0, 0],
            admin,
            sequence: Arc::new(Mutex::new(0)),
        };
        let response = api(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/diffuser/discovery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["schema_version"], "diffuser-lane/v1");
        assert_eq!(body["error"]["code"], "routing_closed");
        assert!(!root.exists());
    }
}

#[tokio::test]
async fn namespace_unknown_and_wrong_method_never_reach_legacy_fallback() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    for (method, path, status, code) in [
        (
            Method::GET,
            "/v1/diffuser/not-a-route",
            StatusCode::NOT_FOUND,
            "object_not_found",
        ),
        (
            Method::POST,
            "/v1/diffuser/not-a-route",
            StatusCode::NOT_FOUND,
            "object_not_found",
        ),
        (
            Method::POST,
            "/v1/diffuser/discovery",
            StatusCode::METHOD_NOT_ALLOWED,
            "unsupported_operation",
        ),
        (
            Method::GET,
            "/v1/diffuser",
            StatusCode::NOT_FOUND,
            "object_not_found",
        ),
    ] {
        let root = std::env::temp_dir().join(format!("la-fallback-{}", std::process::id()));
        assert!(!root.exists());
        let state = Spine {
            root: root.clone(),
            edge: false,
            worker_ports: [0, 0],
            admin: true,
            sequence: Arc::new(Mutex::new(0)),
        };
        let captured = calls.clone();
        let fallback = Router::new().fallback(move || async move {
            captured.fetch_add(1, Ordering::SeqCst);
            StatusCode::IM_A_TEAPOT
        });
        let response = api(state)
            .fallback_service(fallback)
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{path}");
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], code, "{path}");
        assert!(!root.exists());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn closed_known_object_reads_are_not_confused_with_unknown_paths() {
    let state = Spine {
        root: std::env::temp_dir().join(format!("la-reads-{}", std::process::id())),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    for path in [
        "/v1/diffuser/projects/project_12345678/artifacts/artifact_12345678",
        "/v1/diffuser/projects/project_12345678/artifacts/artifact_12345678/content",
        "/v1/diffuser/projects/project_12345678/assignments/assignment_12345678",
        "/v1/diffuser/projects/project_12345678/jobs/job_123456789012",
    ] {
        let response = api(state.clone())
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], "routing_closed");
    }
    assert!(!state.root.exists());
}

#[tokio::test]
async fn closed_renew_validates_body_before_refusing() {
    let state = Spine {
        root: std::env::temp_dir().join(format!("la-renew-{}", std::process::id())),
        edge: false,
        worker_ports: [0, 0],
        admin: true,
        sequence: Arc::new(Mutex::new(0)),
    };
    for (body, status, code) in [
        (
            r#"{"schema_version":"diffuser-lane/v1","expected_revision":1,"requested_lease_ms":120000}"#,
            503,
            "routing_closed",
        ),
        (
            r#"{"schema_version":"diffuser-lane/v1","expected_revision":1,"expected_revision":2,"requested_lease_ms":120000}"#,
            400,
            "duplicate_member",
        ),
        (
            r#"{"schema_version":"diffuser-lane/v1","expected_revision":1,"requested_lease_ms":120000,"extra":true}"#,
            400,
            "schema_invalid",
        ),
        (
            r#"{"schema_version":"wrong","expected_revision":1,"requested_lease_ms":120000}"#,
            400,
            "version_unsupported",
        ),
    ] {
        let response = api(state.clone()).oneshot(Request::builder()
            .method(Method::POST)
            .uri("/v1/diffuser/projects/project_12345678/assignments/assignment_12345678/renew")
            .header("content-type", "application/json")
            .header("idempotency-key", "request_1234567890")
            .body(Body::from(body)).unwrap()).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["error"]["code"], code);
    }
    assert!(!state.root.exists());
}

#[tokio::test]
async fn closed_renew_rejects_missing_idempotency_key() {
    let state = Spine {
        root: std::env::temp_dir().join(format!("la-idem-{}", std::process::id())),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let response = api(state.clone()).oneshot(Request::builder()
        .method(Method::POST).uri("/v1/diffuser/projects/project_12345678/assignments/assignment_12345678/renew")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"schema_version":"diffuser-lane/v1","expected_revision":1,"requested_lease_ms":120000}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "idempotency_required");
    assert!(!state.root.exists());
}

#[test]
fn worker_inspection_computes_real_bytes_and_provenance() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant};

    let input: Vec<u8> = (0..150_000).map(|n| (n % 251) as u8).collect();
    let result = super::la_worker::inspect(
        &mut input.as_slice(),
        "job_123456789012",
        Instant::now() + Duration::from_secs(2),
        || false,
    )
    .expect("bounded inspection should succeed");
    let report: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(report["sha256"], hex::encode(Sha256::digest(&input)));
    assert_eq!(report["bytes"], input.len());
    assert_eq!(report["capability"], "artifact.inspect.sha256/v1");
    assert_eq!(report["profile_version"], "1");
    assert_eq!(report["job_id"], "job_123456789012");
    assert!(result.len() <= 4096);
}

#[test]
fn immutable_input_persists_and_retrieval_rechecks_bytes_and_scope() {
    use sha2::{Digest, Sha256};
    let root = std::env::temp_dir().join(format!(
        "la-artifact-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let bytes = b"actual immutable project data\0\xff";
    let digest = hex::encode(Sha256::digest(bytes));
    {
        let mut store =
            super::la_artifacts::ArtifactStore::open(&root).expect("open artifact store");
        store
            .put_input(
                "tenant_123456789",
                "project_12345678",
                "actor_1234567890",
                "artifact_12345678",
                bytes,
                &digest,
                10,
                100,
            )
            .expect("store verified input");
    }
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    assert_eq!(
        store
            .read_input(
                "tenant_123456789",
                "project_12345678",
                "actor_1234567890",
                "artifact_12345678",
                11
            )
            .unwrap(),
        bytes
    );
    assert!(store
        .read_input(
            "tenant_123456789",
            "project_other123",
            "actor_1234567890",
            "artifact_12345678",
            11
        )
        .is_err());
    assert!(store
        .read_input(
            "tenant_123456789",
            "project_12345678",
            "actor_other12345",
            "artifact_12345678",
            11
        )
        .is_err());
    std::fs::write(
        root.join("artifacts").join("artifact_12345678"),
        b"tampered",
    )
    .unwrap();
    assert!(store
        .read_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_12345678",
            11
        )
        .is_err());
    std::fs::write(root.join("artifacts").join("artifact_12345678"), bytes).unwrap();
    assert!(
        store
            .read_input(
                "tenant_123456789",
                "project_12345678",
                "actor_1234567890",
                "artifact_12345678",
                11
            )
            .is_err(),
        "quarantine must persist after bytes are restored"
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn protected_worker_recovery_counts_cannot_replace_authenticated_transport() {
    use std::os::unix::fs::MetadataExt;
    let path = std::env::temp_dir().join(format!("la-worker-return-auth-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    let root = super::la_artifacts::open_owned_root(&path).unwrap();
    let m = root.metadata().unwrap();
    let channel = serde_json::json!({"binding":{"worker":"worker_cpu_000001","worker_boot":"2".repeat(64),"controller_boot":"3".repeat(64),"worker_epoch":2,"controller_epoch":1,"hardware_generation":1,"profile_epoch":1,"policy_digest":"4".repeat(64),"source_digest":"5".repeat(64),"executable_digest":"6".repeat(64)},"command_key":"a".repeat(64),"reply_key":"b".repeat(64),"authority_key":"c".repeat(64),"custody_key":"d".repeat(64),"expected_high_water":1});
    let authority = serde_json::json!({"service_bearer":"1".repeat(64),"worker_id":"worker_cpu_000001","boot_id":"2".repeat(64),"hardware_generation":1,"profile_epoch":1,"channel":channel});
    let custody = serde_json::json!({"mode":"recover","worker_id":"worker_cpu_000001","store_id":"7".repeat(64),"root_dev":m.dev(),"root_inode":m.ino(),"expected_starts":0,"expected_records":0});
    let bootstrap =
        super::la_worker::validate_bootstrap(authority.clone(), custody.clone()).unwrap();
    assert!(bootstrap.initialize_journal(&root, &path).is_err());
    assert_eq!(
        std::fs::read_dir(&path).unwrap().count(),
        0,
        "missing authenticated history must never create a replacement store"
    );
    let mut changed = authority;
    changed["hardware_generation"] = 2.into();
    assert!(super::la_worker::validate_bootstrap(changed, custody).is_err());
    drop(root);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn protected_worker_recovery_checks_custody_and_history_counts() {
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::fs::MetadataExt,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    let path = std::env::temp_dir().join(format!(
        "la-fixture-recovery-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    let root = std::fs::File::open(&path).unwrap();
    let meta = root.metadata().unwrap();
    let authority = serde_json::json!({"service_bearer":"1".repeat(64),"worker_id":"worker_cpu_000001","boot_id":"2".repeat(64),"hardware_generation":1,"profile_epoch":1});
    let custody = |mode: &str, store: &str, starts: u64, records: u64| serde_json::json!({"mode":mode,"worker_id":"worker_cpu_000001","store_id":store,"root_dev":meta.dev(),"root_inode":meta.ino(),"expected_starts":starts,"expected_records":records});
    let store = "3".repeat(64);
    let fresh =
        super::la_worker::validate_bootstrap(authority.clone(), custody("bootstrap", &store, 0, 0))
            .unwrap();
    fresh.validate_new_root(&root).unwrap();
    let mut journal = fresh.initialize_journal(&root, &path).unwrap();
    let input = b"retained fixture history";
    let digest = hex::encode(Sha256::digest(input));
    let report = journal
        .inspect_once(
            "operation_123456",
            "job_123456789012",
            input,
            &digest,
            Instant::now() + Duration::from_secs(2),
            || false,
        )
        .unwrap();
    drop(journal);
    let wrong =
        super::la_worker::validate_bootstrap(authority.clone(), custody("recover", &store, 0, 0))
            .unwrap();
    assert!(wrong.initialize_journal(&root, &path).is_err());
    let different = super::la_worker::validate_bootstrap(
        authority.clone(),
        custody("recover", &"4".repeat(64), 1, 1),
    )
    .unwrap();
    assert!(different.initialize_journal(&root, &path).is_err());
    assert!(super::la_worker::validate_bootstrap(
        authority.clone(),
        custody("recover", &store, 2, 1)
    )
    .is_err());
    assert!(super::la_worker::validate_bootstrap(
        authority.clone(),
        custody("bootstrap", &store, 1, 1)
    )
    .is_err());
    let recover =
        super::la_worker::validate_bootstrap(authority, custody("recover", &store, 1, 1)).unwrap();
    recover.validate_new_root(&root).unwrap();
    let mut reopened = recover.initialize_journal(&root, &path).unwrap();
    assert_eq!(
        reopened
            .inspect_once(
                "operation_123456",
                "job_123456789012",
                input,
                &digest,
                Instant::now() + Duration::from_secs(2),
                || panic!("recovery retry must not rerun work")
            )
            .unwrap(),
        report
    );
    drop(reopened);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn inspection_respects_size_and_stop_boundaries() {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(3);
    let full = vec![42u8; 1024 * 1024];
    assert!(
        super::la_worker::inspect(&mut full.as_slice(), "job_123456789012", deadline, || false)
            .is_ok()
    );
    let too_large = vec![42u8; 1024 * 1024 + 1];
    assert_eq!(
        super::la_worker::inspect(
            &mut too_large.as_slice(),
            "job_123456789012",
            deadline,
            || false
        )
        .unwrap_err(),
        "artifact_invalid"
    );
    assert_eq!(
        super::la_worker::inspect(
            &mut full.as_slice(),
            "job_123456789012",
            Instant::now(),
            || false
        )
        .unwrap_err(),
        "stopped"
    );
    assert_eq!(
        super::la_worker::inspect(&mut full.as_slice(), "job_123456789012", deadline, || true)
            .unwrap_err(),
        "stopped"
    );
}

#[test]
fn worker_journal_persists_one_start_and_never_recomputes_on_retry() {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-journal-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let input = b"worker journal input";
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(input));
    let other_digest = hex::encode(Sha256::digest(b"different"));
    let mut journal = super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678")
        .expect("bootstrap new worker identity");
    let first = journal
        .inspect_once(
            "operation_123456",
            "job_123456789012",
            input,
            &digest,
            Instant::now() + Duration::from_secs(2),
            || false,
        )
        .unwrap();
    drop(journal);
    let mut reopened =
        super::la_worker::OperationJournal::reopen(&path, "custody_12345678", 1).unwrap();
    let second = reopened
        .inspect_once(
            "operation_123456",
            "job_123456789012",
            input,
            &digest,
            Instant::now() + Duration::from_secs(2),
            || panic!("retry must not re-enter work"),
        )
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(reopened.start_count("operation_123456").unwrap(), 1);
    assert!(reopened
        .inspect_once(
            "operation_123456",
            "job_123456789012",
            b"different",
            &other_digest,
            Instant::now() + Duration::from_secs(2),
            || false
        )
        .is_err());
    drop(reopened);
    // Release the valid owner's lock so this refusal tests the custody value,
    // rather than merely testing that concurrent ownership is excluded.
    assert!(super::la_worker::OperationJournal::reopen(&path, "custody_wrong123", 1).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn mandate_includes_leaf_and_root_only_execution_bounds() {
    use super::la_auth::{mandate_limit, GrantBounds};
    let root = GrantBounds {
        id: "root",
        parent: None,
        run_until: Some(8000),
        execution_ceiling: Some(8000),
    };
    let leaf = GrantBounds {
        id: "leaf",
        parent: Some("root"),
        run_until: Some(3000),
        execution_ceiling: Some(7000),
    };
    assert_eq!(
        mandate_limit(0, 10000, 10000, 10000, &[root.clone(), leaf.clone()]).unwrap(),
        3000
    );
    let root_only = GrantBounds {
        run_until: Some(4500),
        execution_ceiling: Some(3500),
        ..root.clone()
    };
    assert_eq!(
        mandate_limit(0, 10000, 10000, 10000, &[root_only]).unwrap(),
        3500
    );
    let missing = GrantBounds {
        execution_ceiling: None,
        ..leaf
    };
    assert!(mandate_limit(0, 10000, 10000, 10000, &[root, missing]).is_err());
    assert!(mandate_limit(0, 10000, 10000, 10000, &[]).is_err());
}

#[test]
fn reservation_transaction_has_one_winner_and_requires_matching_ack() {
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-claim-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let db = root.join("lane_assignments.sqlite");
    super::la_store::ClaimStore::open(&db).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for i in 0..2 {
        let db = db.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut store = super::la_store::ClaimStore::open(&db).unwrap();
            let id = format!("assignment_{i:08}");
            let key = format!("request_key_{i:08}");
            barrier.wait();
            let result = store.reserve(
                &id,
                "project_12345678",
                "actor_1234567890",
                &key,
                &"a".repeat(64),
                "worker_123456789",
                7,
            );
            (id, key, result)
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.2.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.2 == Err("capacity_unavailable"))
            .count(),
        1
    );
    let winner = results.iter().find(|r| r.2.is_ok()).unwrap();
    let mut store = super::la_store::ClaimStore::open(&db).unwrap();
    assert_eq!(store.counts().unwrap(), (1, 1, 1));
    assert_eq!(store.state(&winner.0).unwrap(), "reserved");
    assert_eq!(
        store
            .reserve(
                &winner.0,
                "project_12345678",
                "actor_1234567890",
                &winner.1,
                &"a".repeat(64),
                "worker_123456789",
                7
            )
            .unwrap(),
        winner.0
    );
    assert_eq!(
        store
            .reserve(
                &winner.0,
                "project_12345678",
                "actor_1234567890",
                &winner.1,
                &"b".repeat(64),
                "worker_123456789",
                7
            )
            .unwrap_err(),
        "idempotency_conflict"
    );
    assert!(store.ack(&winner.0, "worker_123456789", 8).is_err());
    assert_eq!(store.state(&winner.0).unwrap(), "reserved");
    store.ack(&winner.0, "worker_123456789", 7).unwrap();
    assert_eq!(store.state(&winner.0).unwrap(), "assigned");
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_marker_gap_stays_uncertain_after_restart() {
    use sha2::{Digest, Sha256};
    use std::{
        cell::Cell,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    let root = std::env::temp_dir().join(format!(
        "la-gap-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let input = b"cannot rerun after start marker";
    let digest = hex::encode(Sha256::digest(input));
    let mut journal =
        super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
    let probes = Cell::new(0);
    assert_eq!(
        journal
            .inspect_once(
                "operation_123456",
                "job_123456789012",
                input,
                &digest,
                Instant::now() + Duration::from_secs(2),
                || {
                    // The first three checks validate the input before the
                    // durable start; stop at the first task-phase check.
                    let n = probes.get();
                    probes.set(n + 1);
                    n >= 3
                }
            )
            .unwrap_err(),
        "stopped"
    );
    drop(journal);
    assert!(super::la_worker::OperationJournal::reopen(&path, "custody_12345678", 0).is_err());
    let mut reopened =
        super::la_worker::OperationJournal::reopen(&path, "custody_12345678", 1).unwrap();
    assert_eq!(
        reopened
            .inspect_once(
                "operation_123456",
                "job_123456789012",
                input,
                &digest,
                Instant::now() + Duration::from_secs(2),
                || panic!("uncertain work must not restart")
            )
            .unwrap_err(),
        "execution_uncertain"
    );
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn computed_report_is_durably_published_and_read_back() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-output-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let input = b"input for published report";
    let report = super::la_worker::inspect(
        &mut input.as_slice(),
        "job_123456789012",
        Instant::now() + Duration::from_secs(2),
        || false,
    )
    .unwrap();
    let digest = hex::encode(Sha256::digest(&report));
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    store
        .put_output(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_output12",
            "assignment_12345",
            "job_123456789012",
            &report,
            &digest,
            1,
            100,
        )
        .expect("publish verified report");
    drop(store);
    let mut reopened = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    assert_eq!(
        reopened
            .read_output(
                "tenant_123456789",
                "project_12345678",
                "actor_1234567890",
                "artifact_output12",
                2
            )
            .unwrap(),
        report
    );
    assert!(reopened
        .read_output(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_output12",
            100
        )
        .is_err());
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn la_exec_child() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    match std::env::var_os("DIFFUSER_LA_TEST_CHILD") {
        None => {}
        Some(value) if value == "1" => {
            use std::os::unix::fs::FileTypeExt;
            let pipe = std::fs::metadata("/proc/self/fd/0")
                .map(|m| m.file_type().is_fifo())
                .unwrap_or(false);
            if !pipe {
                let result = super::lane_assignment::validate_startup(false);
                panic!("{}", result.expect_err("child startup must remain closed"));
            }
            if let Err(error) = read_child_config() {
                record_controller_startup_failure(error);
                panic!("{error}");
            }
            return;
        }
        Some(_) => panic!("invalid_child_intent"),
    }
    let effects = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!("la-no-authority-{}", std::process::id()));
    assert!(!root.exists());
    assert_eq!(
        super::lane_assignment::start_with(false, || {
            effects.fetch_add(1, Ordering::SeqCst);
        }),
        Err("missing_protected_channel")
    );
    // Constructing the ordinary closed namespace must not initialize its root.
    let _closed = super::lane_assignment::router();
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert!(!root.exists());
}

#[test]
fn explicit_child_intent_without_a_pipe_fails_closed() {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().unwrap();
    let listing = Command::new(&exe)
        .args(["--list", "--format", "terse"])
        .env_clear()
        .output()
        .unwrap();
    assert!(listing.status.success());
    let listing = String::from_utf8(listing.stdout).unwrap();
    assert_eq!(
        listing
            .lines()
            .filter(|line| *line == "cosp::la_tests::la_exec_child: test")
            .count(),
        1
    );
    let child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !child.status.success(),
        "explicit child must fail without a protected pipe"
    );
    assert!(String::from_utf8_lossy(&child.stderr).contains("missing_protected_channel"));
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildConfig {
    protocol_version: u64,
    run_nonce: String,
    role: String,
    root: String,
    policy_id: String,
    policy_digest: String,
    expected_executable_sha256: String,
    authority_material: serde_json::Value,
    custody_manifest: serde_json::Value,
    barrier_id: serde_json::Value,
}

// Finite structural diagnostics only: no config, authority or body buffers.
fn startup_trace(stage: &str, details: serde_json::Value) {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) },
        0
    );
    super::la_adapter::recovery_trace(
        stage,
        serde_json::json!({
            "monotonic_us": clock.tv_sec as u64 * 1_000_000 + clock.tv_nsec as u64 / 1000,
            "pid":std::process::id(), "counts":details
        }),
    );
}
struct ConfigReadTrace {
    phase: &'static str,
    frame_len: usize,
}
impl Drop for ConfigReadTrace {
    fn drop(&mut self) {
        startup_trace(
            "config_reader_end",
            serde_json::json!({"phase":self.phase,"frame_len":self.frame_len}),
        );
    }
}

// The fixture channel is not an authentication mechanism. P owns pipe custody;
// this parser only bounds and checks the frame. No role is admitted by it yet.
fn read_child_config() -> std::result::Result<(), &'static str> {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let end = start + Duration::from_secs(5);
    let mut trace = ConfigReadTrace {
        phase: "idle_wait",
        frame_len: 0,
    };
    startup_trace("config_reader_start", serde_json::json!({"budget_ms":5000}));
    let mut frame = Vec::new();
    loop {
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            startup_trace(
                "config_reader_timeout",
                serde_json::json!({"phase":trace.phase,"frame_len":frame.len(),"elapsed_us":start.elapsed().as_micros()}),
            );
            return Err("child_config_timeout");
        }
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // poll is limited to stdin, whose read end is owned by the fixture.
        let ready = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                remaining.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready == 0 {
            startup_trace(
                "config_reader_timeout",
                serde_json::json!({"phase":trace.phase,"frame_len":frame.len(),"elapsed_us":start.elapsed().as_micros()}),
            );
            return Err("child_config_timeout");
        }
        if ready < 0 {
            return Err("child_config_invalid");
        }
        let mut byte = [0u8; 1];
        // Read just one byte after poll, avoiding a buffered reader that can
        // hide already-buffered frame bytes while the writer keeps its pipe open.
        let read = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
        if read != 1 {
            return Err("child_config_invalid");
        }
        if trace.phase == "idle_wait" {
            startup_trace(
                "config_reader_first_byte",
                serde_json::json!({"elapsed_us":start.elapsed().as_micros()}),
            );
            trace.phase = "partial_frame";
        }
        if byte[0] == b'\n' {
            break;
        }
        frame.push(byte[0]);
        trace.frame_len = frame.len();
        if frame.len() >= 16 * 1024 {
            return Err("child_config_invalid");
        }
    }
    trace.phase = "parse";
    startup_trace(
        "config_reader_frame",
        serde_json::json!({"frame_len":frame.len(),"elapsed_us":start.elapsed().as_micros()}),
    );
    use zeroize::Zeroize;
    let mut normalized =
        super::la_contract::canonical_json(&frame).map_err(|_| "child_config_invalid")?;
    frame.zeroize();
    let parsed = serde_json::from_slice(&normalized);
    normalized.zeroize();
    let config: ChildConfig = parsed.map_err(|_| "child_config_invalid")?;
    let hex64 = |v: &str| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let simple = |v: &str| {
        !v.is_empty()
            && v.len() <= 128
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    if config.protocol_version != 1
        || !hex64(&config.run_nonce)
        || !matches!(
            config.role.as_str(),
            "controller" | "worker" | "claim_client"
        )
        || !matches!(
            config.policy_id.as_str(),
            "lab-proposal-v1" | "runtime-short-v1"
        )
        || !super::lane_assignment::startup_parameters_valid(
            &config.role,
            &config.root,
            &config.policy_id,
            &config.policy_digest,
        )
        || !hex64(&config.expected_executable_sha256)
        || config.root.len() > 4096
        || !std::path::Path::new(&config.root).is_absolute()
        || !config.authority_material.is_object()
        || !config.custody_manifest.is_object()
        || !match (config.role.as_str(), &config.barrier_id) {
            ("claim_client", serde_json::Value::String(id)) => simple(id),
            ("controller" | "worker", serde_json::Value::Null) => true,
            _ => false,
        }
        || std::path::Path::new(&config.root)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("child_config_invalid");
    }
    trace.phase = "executable_hash";
    startup_trace(
        "config_reader_hash_start",
        serde_json::json!({"elapsed_us":start.elapsed().as_micros()}),
    );
    if child_executable_digest(end)? != config.expected_executable_sha256 {
        return Err("child_config_invalid");
    }
    trace.phase = "bootstrap_validation";
    startup_trace(
        "config_reader_hash_end",
        serde_json::json!({"elapsed_us":start.elapsed().as_micros()}),
    );
    enum Candidate {
        Worker(super::la_worker::WorkerBootstrap),
        Controller(super::lane_assignment::ControllerBootstrap),
    }
    let candidate = match config.role.as_str() {
        "worker" => Candidate::Worker(super::la_worker::validate_bootstrap(
            config.authority_material,
            config.custody_manifest,
        )?),
        "controller" => {
            Candidate::Controller(super::lane_assignment::validate_controller_bootstrap(
                config.authority_material,
                config.custody_manifest,
            )?)
        }
        _ => return Err("startup_unavailable"),
    };
    reject_queued_startup_control()?;
    let root = super::lane_assignment::open_startup_root(&config.root)?;
    let candidate_ref = match &candidate {
        Candidate::Worker(value) => super::lane_assignment::StartupCandidate::Worker(value, &root),
        Candidate::Controller(value) => {
            super::lane_assignment::StartupCandidate::Controller(value, &root)
        }
    };
    super::lane_assignment::validate_startup_candidate(true, Some(candidate_ref))?;
    if Instant::now() >= end {
        return Err("child_config_timeout");
    }
    trace.phase = "initialization";
    startup_trace(
        "config_reader_initialization",
        serde_json::json!({"elapsed_us":start.elapsed().as_micros()}),
    );
    match candidate {
        Candidate::Worker(bootstrap) => {
            if bootstrap.is_recovery() {
                corrupt_worker_recovery(&root)?;
            }
            let journal = match bootstrap
                .initialize_journal(&root, std::path::Path::new(&config.root))
            {
                Ok(journal) => journal,
                Err(code) => {
                    if bootstrap.loss_return.is_some() {
                        use std::io::Write;
                        println!(
                            "DIFFUSER_LA_CHILD_V1 {}",
                            serde_json::json!({"kind":"WORKER_LOSS_RETURN_STARTUP_REFUSED","phase":"root","code":code,"store_opens":WORKER_STORE_OPENS.load(std::sync::atomic::Ordering::SeqCst),"listener_binds":WORKER_LISTENER_BINDS.load(std::sync::atomic::Ordering::SeqCst)})
                        );
                        std::io::stdout().flush().map_err(|_| "control_invalid")?;
                    }
                    if bootstrap.is_recovery()
                        && std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                            .is_ok_and(|s| s.starts_with("worker-close-recovery"))
                    {
                        use std::io::Write;
                        println!(
                            "DIFFUSER_LA_CHILD_V1 {}",
                            serde_json::json!({"kind":"WORKER_RECOVERY_STARTUP_REFUSED","code":code,"listener_binds":WORKER_LISTENER_BINDS.load(std::sync::atomic::Ordering::SeqCst),"store_opens":WORKER_STORE_OPENS.load(std::sync::atomic::Ordering::SeqCst)})
                        );
                        std::io::stdout().flush().map_err(|_| "control_invalid")?;
                    }
                    return Err(code);
                }
            };
            if Instant::now() >= end {
                return Err("child_config_timeout");
            }
            run_worker_child(
                bootstrap,
                journal,
                root,
                &config.run_nonce,
                &config.policy_digest,
                &config.expected_executable_sha256,
                end,
            )
        }
        Candidate::Controller(bootstrap) => {
            if bootstrap.recovery.is_some() {
                corrupt_recovery_transport(&root)?;
            }
            let stores = bootstrap.initialize_stores(&root, std::path::Path::new(&config.root))?;
            CONTROLLER_STORE_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if Instant::now() >= end {
                return Err("child_config_timeout");
            }
            run_controller_child(
                bootstrap,
                stores,
                root,
                &config.run_nonce,
                &config.policy_digest,
                &config.expected_executable_sha256,
                end,
            )
        }
    }
}

// Per-exec observations of actual constructors, retained even when unwinding
// closes the listener. Only the protected test child reads the fault selector.
pub(super) static WORKER_STORE_OPENS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static WORKER_LISTENER_BINDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
fn corrupt_worker_recovery(root: &std::fs::File) -> std::result::Result<(), &'static str> {
    let probe = std::env::var("DIFFUSER_LA_RESOURCE_PROBE").unwrap_or_default();
    let (name, sql) = match probe.as_str() {
        "worker-close-recovery-marker" => ("worker.sqlite", "DELETE FROM operations"),
        "worker-close-recovery-report" => (
            "worker.sqlite",
            "UPDATE operations SET report=zeroblob(length(report))",
        ),
        "worker-close-recovery-history" => (
            "worker-channel.sqlite",
            "DELETE FROM channel_checkpoints WHERE revision=1",
        ),
        _ => return Ok(()),
    };
    let db = super::la_store::open_pinned_database(root, name, false)?;
    if db.execute(sql, []).map_err(|_| "storage_unavailable")? != 1 {
        return Err("evidence_invalid");
    }
    Ok(())
}
static CONTROLLER_LISTENER_BINDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static CONTROLLER_STORE_OPENS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
fn controller_recovery_case() -> bool {
    matches!(
        std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref(),
        Ok("controller-recovery"
            | "controller-recovery-prefix"
            | "controller-recovery-ack"
            | "controller-recovery-gap"
            | "controller-rebind"
            | "controller-close-recovery"
            | "controller-close-recovery-envelope"
            | "controller-close-recovery-midpoint"
            | "controller-close-recovery-gap"
            | "controller-stop-recovery"
            | "controller-stop-recovery-presend"
            | "controller-stop-recovery-envelope"
            | "controller-stop-recovery-midpoint"
            | "controller-stop-recovery-gap"
            | "controller-stop-recovery-mandate"
            | "controller-never-started-m1"
            | "controller-never-started-m2"
            | "controller-never-started-m1-foreign"
            | "controller-never-started-m1-expired"
            | "controller-never-started-m2-stale")
    )
}
fn controller_close_recovery_case() -> bool {
    std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
        .is_ok_and(|v| v.starts_with("controller-close-recovery"))
}
// Test-only launch delay; uses the actual capsule's original deadline and
// real wall clock. It neither modifies evidence nor supplies verifier time.
fn recovery_test_delay(handoff: &super::la_adapter::TransportEpochHandoff, point: &str) {
    let mode = std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").unwrap_or_default();
    if mode != point && !(point == "after-install" && mode == "m2-original-deadline-refusal") {
        return;
    }
    let value = serde_json::to_value(handoff).unwrap();
    let until = value["expires_at"].as_u64().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    super::la_adapter::recovery_trace(
        "deliberate_delay",
        serde_json::json!({"point":point,"expires_at":until,"start":now}),
    );
    std::thread::sleep(std::time::Duration::from_millis(
        until.saturating_sub(now) + 40,
    ));
}
fn corrupt_consumption_witness(
    root: &std::fs::File,
) -> std::result::Result<serde_json::Value, &'static str> {
    let test_mode = std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").unwrap_or_default();
    if matches!(
        test_mode.as_str(),
        "witness-missing" | "witness-altered" | "witness-partial"
    ) {
        let (name, phase) = if test_mode == "witness-partial" {
            ("service-custody.sqlite", "recovery")
        } else {
            ("controller-channel.sqlite", "handoff")
        };
        let db = super::la_store::open_pinned_database(root, name, false)?;
        let table = if test_mode == "witness-partial" {
            "service_checkpoints"
        } else {
            "channel_checkpoints"
        };
        let mut found = None;
        let mut stmt = db
            .prepare(&format!(
                "SELECT revision,frame,ack FROM {table} ORDER BY revision"
            ))
            .map_err(|_| "evidence_invalid")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| "evidence_invalid")?;
        for row in rows {
            let (revision, frame, ack) = row.map_err(|_| "evidence_invalid")?;
            let f: serde_json::Value =
                serde_json::from_slice(&frame).map_err(|_| "evidence_invalid")?;
            if f["body"]["phase"] == phase {
                found = Some((revision, ack));
            }
        }
        drop(stmt);
        let (revision, before) = found.ok_or("evidence_invalid")?;
        let mut after: serde_json::Value =
            serde_json::from_slice(&before).map_err(|_| "evidence_invalid")?;
        if test_mode == "witness-altered" {
            after["consumption"]["observed_at"] = 0.into();
        } else {
            after
                .as_object_mut()
                .ok_or("evidence_invalid")?
                .remove("consumption");
        }
        let after = serde_json::to_vec(&after).map_err(|_| "evidence_invalid")?;
        db.execute(
            &format!("UPDATE {table} SET ack=?2 WHERE revision=?1"),
            rusqlite::params![revision, after],
        )
        .map_err(|_| "storage_unavailable")?;
        super::la_adapter::recovery_trace(
            "deliberate_witness_corruption",
            serde_json::json!({"mode":test_mode,"table":table,"revision":revision}),
        );
        return Ok(
            serde_json::json!({"kind":"CONSUMPTION_TEST_MUTATED","before":String::from_utf8(before).map_err(|_|"evidence_invalid")?,"after":String::from_utf8(after).map_err(|_|"evidence_invalid")?,"table":table,"revision":revision}),
        );
    }
    Err("evidence_invalid")
}
fn controller_stop_recovery_case() -> bool {
    std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
        .is_ok_and(|v| v.starts_with("controller-stop-recovery"))
}
fn corrupt_recovery_transport(root: &std::fs::File) -> std::result::Result<(), &'static str> {
    let probe = std::env::var("DIFFUSER_LA_RESOURCE_PROBE").unwrap_or_default();
    if !matches!(
        probe.as_str(),
        "controller-recovery-prefix"
            | "controller-recovery-ack"
            | "controller-recovery-gap"
            | "controller-close-recovery-envelope"
            | "controller-close-recovery-midpoint"
            | "controller-close-recovery-gap"
            | "controller-stop-recovery-envelope"
            | "controller-stop-recovery-midpoint"
            | "controller-stop-recovery-gap"
            | "controller-stop-recovery-mandate"
    ) {
        return Ok(());
    }
    if probe == "controller-stop-recovery-mandate" {
        let db = super::la_store::open_pinned_database(root, "lane_assignments.sqlite", false)?;
        if db.execute("UPDATE la_mandates SET body=replace(body,'cpu-artifact-inspect','foreign-profile')",[]).map_err(|_| "storage_unavailable")? != 1 { return Err("evidence_invalid") }
        return Ok(());
    }
    if matches!(
        probe.as_str(),
        "controller-close-recovery-midpoint" | "controller-stop-recovery-midpoint"
    ) {
        let db = super::la_store::open_pinned_database(root, "service-custody.sqlite", false)?;
        if db
            .execute(
                "UPDATE service_close_midpoints SET body=zeroblob(length(body))",
                [],
            )
            .map_err(|_| "storage_unavailable")?
            != 1
        {
            return Err("evidence_invalid");
        }
        return Ok(());
    }
    let db = super::la_store::open_pinned_database(root, "controller-channel.sqlite", false)?;
    let changed = match probe.as_str() {
        "controller-close-recovery-envelope" | "controller-stop-recovery-envelope" => db.execute(
            "UPDATE channel_log SET request=zeroblob(length(request)) WHERE response IS NULL",
            [],
        ),
        "controller-recovery-prefix" => db.execute(
            "UPDATE channel_checkpoints SET frame=zeroblob(length(frame)) WHERE revision=1",
            [],
        ),
        "controller-recovery-ack" => db.execute(
            "UPDATE channel_checkpoints SET ack=zeroblob(length(ack)) WHERE revision=1",
            [],
        ),
        _ => db.execute("DELETE FROM channel_checkpoints WHERE revision=1", []),
    }
    .map_err(|_| "storage_unavailable")?;
    if changed != 1 {
        return Err("evidence_invalid");
    }
    Ok(())
}
fn record_controller_startup_failure(code: &str) {
    if !controller_recovery_case() {
        return;
    }
    use std::io::Write;
    println!(
        "DIFFUSER_LA_CHILD_V1 {}",
        serde_json::json!({"kind":"RECOVERY_STARTUP_REFUSED","code":code,
        "pid":std::process::id(),"listener_binds":CONTROLLER_LISTENER_BINDS.load(std::sync::atomic::Ordering::SeqCst),
        "store_opens":CONTROLLER_STORE_OPENS.load(std::sync::atomic::Ordering::SeqCst)})
    );
    std::io::stdout().flush().unwrap();
}

// A complete second frame or an early control command is never consumed as
// another configuration. P keeps the one writer open while startup proceeds.
fn reject_queued_startup_control() -> std::result::Result<(), &'static str> {
    let mut descriptor = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if ready < 0 {
        return Err("control_invalid");
    }
    if ready == 0 {
        return Ok(());
    }
    if descriptor.revents & libc::POLLIN != 0 {
        let mut byte = [0u8; 1];
        if unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) } != 1 {
            return Err("control_closed");
        }
        return Err(if byte[0] == b'{' {
            "unexpected_config"
        } else {
            "control_invalid"
        });
    }
    if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err("control_closed");
    }
    Ok(())
}

// Qualification runs only in an explicitly configured fixture W. It exercises
// the real journal and the kernel-limited root without admitting an HTTP job.
fn worker_storage_pressure_probe(
    mut journal: super::la_worker::OperationJournal,
    root: &std::fs::File,
    bootstrap: &super::la_worker::WorkerBootstrap,
) -> std::result::Result<super::la_worker::OperationJournal, &'static str> {
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        os::fd::AsRawFd,
        time::{Duration, Instant},
    };
    let path = std::path::Path::new("/job/workerroot");
    // Qualification only: use the ordinary durable worker methods under the
    // real finite root, retain 32 maximum-size inputs and all computed reports.
    // No HTTP assignment/job is admitted and no qualification is inferred here.
    let channel = bootstrap.channel.as_ref().ok_or("evidence_invalid")?;
    let keys = channel.validate(&bootstrap.worker_id, &bootstrap.boot_id, None)?;
    let session = super::la_worker::ReservationSession {
        worker: bootstrap.worker_id.clone(),
        boot: bootstrap.boot_id.clone(),
        key: keys.reply,
    };
    let wall = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_millis() as u64)
            .map_err(|_| "clock_untrusted")
    };
    let began = wall()?;
    let terms = super::la_store::AssignmentTerms {
        cpu_millicores: 1000,
        memory_bytes: 16777216,
        storage_bytes: 2097152,
        accepted_at: began,
        lease_until: began + 4000,
        hard_until: began + 12000,
    };
    let reserve = super::la_adapter::ReserveCommand {
        worker: session.worker.clone(),
        boot: session.boot.clone(),
        assignment: "resource_assign_0".into(),
        operation: "resource_reserve_0".into(),
        fence: 1,
        lease_until: terms.lease_until,
        hard_until: terms.hard_until,
    };
    journal.bind_assignment_terms(&reserve, &terms)?;
    let mac = super::la_adapter::sign_reserve_command(&session.key, &reserve)?;
    journal.reserve_authenticated(&session, &reserve, &mac)?;
    let input = vec![0x5au8; 1024 * 1024];
    let digest = hex::encode(Sha256::digest(&input));
    let mut report = Vec::new();
    let mut active_lease = terms.lease_until;
    let mut lease_revision = 0;
    for index in 0..32 {
        let now = wall()?;
        if index > 0 && index % 8 == 0 {
            lease_revision += 1;
            let renewal = super::la_adapter::RenewCommand {
                worker: session.worker.clone(),
                boot: session.boot.clone(),
                assignment: reserve.assignment.clone(),
                fence: 1,
                operation: format!("resource_renew_{lease_revision}"),
                revision: lease_revision,
                previous_until: active_lease,
                requested_until: (now + 4000).min(terms.hard_until),
            };
            let mac = super::la_adapter::sign_renew_command(&session.key, &renewal)?;
            journal.renew_authenticated(&session, &renewal, &mac)?;
            active_lease = renewal.requested_until;
        }
        let operation = format!("resource_op_{:05}", index + 1);
        let job = format!("resource_job_{:04}", index + 1);
        let draft = super::la_auth::MandateDraft {
            tenant: "tenant_123456789".into(),
            project: "project_12345678".into(),
            actor: "agent_1234567890".into(),
            initiator: "person_123456789".into(),
            lineage: "grant_root123456".into(),
            assignment: reserve.assignment.clone(),
            job: job.clone(),
            operation: operation.clone(),
            input_digest: digest.clone(),
            profile: "cpu-artifact-inspect".into(),
            worker: session.worker.clone(),
            cpu_millicores: 1000,
            memory_bytes: 16777216,
            storage_bytes: 2097152,
            policy: "runtime-short-v1".into(),
            accepted_at: now,
            runtime_ms: 8000,
            assignment_hard: terms.hard_until,
            project_ceiling: terms.hard_until,
            chain: vec![super::la_auth::MandateGrant {
                id: "grant_root123456".into(),
                parent: None,
                run_until: terms.hard_until,
                execution_ceiling: terms.hard_until,
            }],
        };
        let mandate = super::la_store::checked_mandate(&draft)?;
        let command = super::la_adapter::InspectCommand {
            backend: None,
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: reserve.assignment.clone(),
            fence: 1,
            operation,
            job,
            input_digest: digest.clone(),
            accepted_at: now,
            mandate_until: mandate.max_until,
            permit_until: (now + 1500).min(active_lease),
        };
        journal.bind_worker_mandate(&session, &command, &mandate)?;
        let mac = super::la_adapter::sign_inspect_command(&session.key, &command)?;
        journal.accept_inspect_permit(&session, &command, &mac)?;
        let mac = super::la_adapter::sign_stage_command(&session.key, &command)?;
        journal.stage_authenticated_input(&session, &command, &mac, &input)?;
        let mac = super::la_adapter::sign_start_command(&session.key, &command)?;
        let (computed, receipt, signature) = journal.inspect_staged(&session, &command, &mac)?;
        super::la_adapter::verify_result_receipt(&session.key, &receipt, &signature)?;
        if index == 0 {
            report = computed;
        }
    }
    let overflow = journal.inspect_once(
        "resource_op_00033",
        "resource_job_0033",
        &input,
        &digest,
        Instant::now() + Duration::from_secs(1),
        || false,
    );
    if overflow.err() != Some("storage_unavailable") {
        return Err("evidence_invalid");
    }
    for index in 0..8 {
        if index > 0 {
            let now = wall()?;
            let fresh = super::la_store::AssignmentTerms {
                accepted_at: now,
                lease_until: now + 4000,
                hard_until: now + 12000,
                ..terms.clone()
            };
            let c = super::la_adapter::ReserveCommand {
                assignment: format!("resource_assign_{index}"),
                operation: format!("resource_reserve_{index}"),
                fence: index + 1,
                lease_until: fresh.lease_until,
                hard_until: fresh.hard_until,
                ..reserve.clone()
            };
            journal.bind_assignment_terms(&c, &fresh)?;
            let mac = super::la_adapter::sign_reserve_command(&session.key, &c)?;
            journal.reserve_authenticated(&session, &c, &mac)?;
        }
        let close = super::la_adapter::CloseCommand {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: format!("resource_assign_{index}"),
            fence: index + 1,
            operation: format!("resource_close_{index}"),
        };
        let mac = super::la_adapter::sign_close_command(&session.key, &close)?;
        journal.close_authenticated(&session, &close, &mac)?;
    }
    let now = wall()?;
    let ninth = super::la_adapter::ReserveCommand {
        assignment: "resource_assign_8".into(),
        operation: "resource_reserve_8".into(),
        fence: 9,
        lease_until: now + 4000,
        hard_until: now + 12000,
        ..reserve
    };
    let mac = super::la_adapter::sign_reserve_command(&session.key, &ninth)?;
    if journal.reserve_authenticated(&session, &ninth, &mac).err() != Some("capacity_unavailable") {
        return Err("evidence_invalid");
    }
    let conn = rusqlite::Connection::open(path.join("worker.sqlite"))
        .map_err(|_| "storage_unavailable")?;
    conn.execute_batch("PRAGMA synchronous=FULL;")
        .map_err(|_| "storage_unavailable")?;
    let chunk = [0x5au8; 64 * 1024];
    let mut scratch = Vec::new();
    let mut enospc = false;
    for index in 0..128 {
        let name = path.join(format!(".pressure-{index:03}"));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&name)
            .map_err(|_| "storage_unavailable")?;
        scratch.push(name);
        for _ in 0..16 {
            if let Err(error) = file.write_all(&chunk) {
                if error.raw_os_error() == Some(libc::ENOSPC) {
                    enospc = true;
                    break;
                }
                return Err("storage_unavailable");
            }
        }
        if enospc {
            break;
        }
        file.sync_all().map_err(|_| "storage_unavailable")?;
    }
    if !enospc {
        return Err("storage_unavailable");
    }
    let error = conn
        .execute(
            "INSERT INTO operations(op,job,input_digest,state) VALUES (?1,?2,?3,'started')",
            rusqlite::params!["resource_op_fail1", "resource_job_0001", digest],
        )
        .expect_err("SQLite write must fail on full root");
    if error.sqlite_error_code() != Some(rusqlite::ErrorCode::DiskFull) {
        return Err("storage_unavailable");
    }
    drop(conn);
    // Explicit fixture-only free makes room for rollback/reopen and the receipt.
    for file in scratch.iter().take(3) {
        std::fs::remove_file(file).map_err(|_| "storage_unavailable")?;
    }
    root.sync_all().map_err(|_| "storage_unavailable")?;
    drop(journal);
    journal = bootstrap.reopen_with_custody_counts(root, path, 32, 32)?;
    if journal.start_count("resource_op_fail1")? != 0 {
        return Err("evidence_invalid");
    }
    let readback = rusqlite::Connection::open(path.join("worker.sqlite"))
        .map_err(|_| "storage_unavailable")?;
    let failed_rows: i64 = readback
        .query_row(
            "SELECT COUNT(*) FROM operations WHERE op='resource_op_fail1'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "storage_unavailable")?;
    let integrity: String = readback
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| "storage_unavailable")?;
    if failed_rows != 0 || integrity != "ok" {
        return Err("evidence_invalid");
    }
    drop(readback);
    let retry = journal.inspect_once(
        "resource_op_00001",
        "resource_job_0001",
        &input,
        &digest,
        Instant::now() + Duration::from_secs(8),
        || true,
    )?;
    if retry != report {
        return Err("evidence_invalid");
    }
    let result = serde_json::json!({"kernel_errno":libc::ENOSPC,"sqlite_error":"SQLITE_FULL","failed_row_count":0,"retained_start_count":journal.start_count("resource_op_00001")?,"retained_report_sha256":hex::encode(Sha256::digest(&report)),"input_sha256":digest,"retained_jobs":32,"retained_inputs":32,"retained_outputs":32,"retained_assignments":8,"ninth_assignment_refused":true,"thirty_third_job_refused":true,"scratch_files_created":scratch.len(),"fixture_files_freed":3,"reopen_integrity":"ok"});
    let directory = format!("/proc/self/fd/{}", root.as_raw_fd());
    let temporary = format!("{directory}/.storage-result.tmp");
    let marker = format!("{directory}/.storage-result.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| "storage_unavailable")?;
    file.write_all(&serde_json::to_vec(&result).map_err(|_| "storage_unavailable")?)
        .and_then(|_| file.sync_all())
        .map_err(|_| "storage_unavailable")?;
    std::fs::rename(temporary, marker).map_err(|_| "storage_unavailable")?;
    root.sync_all().map_err(|_| "storage_unavailable")?;
    Ok(journal)
}

fn run_worker_child(
    bootstrap: super::la_worker::WorkerBootstrap,
    mut journal: super::la_worker::OperationJournal,
    root: std::fs::File,
    nonce: &str,
    policy_digest: &str,
    executable_digest: &str,
    startup_deadline: std::time::Instant,
) -> std::result::Result<(), &'static str> {
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        os::unix::fs::MetadataExt,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Instant,
    };
    // These are no-work negative probes inside the worker PID/mount view. The
    // target names belong to this fresh fixture's service root, not host paths.
    use std::os::unix::fs::OpenOptionsExt;
    let probe_name = format!(".worker-boundary-{nonce}");
    let paths = [
        format!("/job/service/{probe_name}"),
        format!("/proc/1/root/job/service/{probe_name}"),
        format!("/proc/self/root/job/service/{probe_name}"),
    ];
    let mut write_refusals = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path) {
            Ok(_) => return Err("worker_escape_detected"),
            Err(error) => write_refusals.push(serde_json::json!({"probe":index,"errno":error.raw_os_error().ok_or("startup_unavailable")?})),
        }
    }
    let input = b"diffuser-s1-worker-startup-smoke-v1";
    let mut bytes = &input[..];
    let report =
        super::la_worker::inspect(&mut bytes, "startup_smoke_001", startup_deadline, || false)?;
    let root_meta = root.metadata().map_err(|_| "startup_root_invalid")?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "startup_unavailable")?;
    WORKER_LISTENER_BINDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    listener
        .set_nonblocking(true)
        .map_err(|_| "startup_unavailable")?;
    let address = listener.local_addr().map_err(|_| "startup_unavailable")?;
    if Instant::now() >= startup_deadline {
        return Err("child_config_timeout");
    }
    let context = super::la_adapter::InventoryContext {
        bearer_digest: bootstrap.bearer_digest,
        worker_id: bootstrap.worker_id.clone(),
        boot_id: bootstrap.boot_id.clone(),
        hardware_generation: bootstrap.hardware_generation,
        profile_epoch: bootstrap.profile_epoch,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "startup_unavailable")?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let aborted = Arc::new(AtomicBool::new(false));
    let thread_aborted = aborted.clone();
    let rpc_holder = Arc::new(std::sync::Mutex::new(
        None::<Arc<std::sync::Mutex<super::la_adapter::WorkerRpc>>>,
    ));
    let activation_rpc = rpc_holder.clone();
    let activation_task = protected_activation_task(aborted.clone(), move |bytes| {
        let holder = activation_rpc.lock().map_err(|_| "storage_unavailable")?;
        let rpc = holder.as_ref().ok_or("evidence_invalid")?.clone();
        drop(holder);
        let mut state = rpc.lock().map_err(|_| "storage_unavailable")?;
        state.activate(bytes)
    })?;
    let activation_sender = activation_task.sender;
    let epoch_rpc = rpc_holder.clone();
    let epoch_task = protected_epoch_task(aborted.clone(), move |bytes| {
        let state = epoch_rpc
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let ack = state
            .lock()
            .map_err(|_| "storage_unavailable")?
            .install_controller_epoch(bytes)?;
        serde_json::to_value(ack).map_err(|_| "evidence_invalid")
    })?;
    let epoch_sender = epoch_task.sender;
    let bridge_rpc = rpc_holder.clone();
    let bridge_task = protected_epoch_task(aborted.clone(), move |bytes| {
        let state = bridge_rpc
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let mut rpc = state.lock().map_err(|_| "storage_unavailable")?;
        if let Some(bytes) = bytes.strip_prefix(b"LSBRIDGE ") {
            match rpc.install_loss_source_bridge(bytes) {
                Ok(v) => Ok(v),
                Err(code) => Ok(
                    serde_json::json!({"kind":"LOSS_SOURCE_BRIDGE_REFUSED","code":code,"admitted":false}),
                ),
            }
        } else if let Some(bytes) = bytes.strip_prefix(b"LAACTIVATE ") {
            let receipt = rpc.activate_loss_return(bytes)?;
            Ok(serde_json::json!({"kind":"LOSS_RETURN_ACTIVATED","receipt":receipt}))
        } else if let Some(bytes) = bytes.strip_prefix(b"LACOMPLETE ") {
            rpc.persist_loss_return_completion(bytes)
        } else if let Some(bytes) = bytes.strip_prefix(b"LSDISPOSITION ") {
            match rpc.commit_spent_loss(bytes) {
                Ok(v) => Ok(v),
                Err(code) => Ok(
                    serde_json::json!({"kind":"SPENT_LOSS_COMMIT_REFUSED","code":code,"admitted":false}),
                ),
            }
        } else if let Some(bytes) = bytes.strip_prefix(b"LSGUARDS ") {
            let digest: String = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
            let cap = rpc.journal.spent_loss(&digest)?;
            let super::la_adapter::WorkerRpc {
                journal, session, ..
            } = &mut *rpc;
            journal.test_retired_lookup_probes(session, &cap.command)
        } else if let Some(bytes) = bytes.strip_prefix(b"LSCOMMIT ") {
            rpc.complete_loss_source_bridge(bytes)
        } else {
            Err("evidence_invalid")
        }
    })?;
    let bridge_sender = bridge_task.sender;
    let (loss_resolution_sender, loss_resolution_receiver) =
        std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let control_rpc = rpc_holder.clone();
    let custody_link = bootstrap
        .channel
        .as_ref()
        .map(|channel| {
            let keys = channel.validate(&bootstrap.worker_id, &bootstrap.boot_id, None)?;
            protected_custody_link(&channel.binding, &keys, "worker")
        })
        .transpose()?;
    let control_custody = custody_link.clone();
    let authority_task = protected_authority_task(aborted.clone(), move |data| {
        control_rpc
            .lock()
            .map_err(|_| "storage_unavailable")
            .and_then(|holder| {
                let state = holder.as_ref().ok_or("evidence_invalid")?;
                state
                    .lock()
                    .map_err(|_| "storage_unavailable")?
                    .observe(data)
            })
    })?;
    let authority_sender = authority_task.sender;
    let control = std::thread::Builder::new()
        .name("la-worker-control".into())
        .spawn(move || {
            let mut frame = Vec::new();
            let mut sent_go = false;
            let result = loop {
                if thread_aborted.load(Ordering::SeqCst) {
                    break Err("control_stopped");
                }
                let mut poll = libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut poll, 1, 100) };
                if ready == 0 {
                    continue;
                }
                if ready < 0 {
                    break Err("control_invalid");
                }
                let mut byte = [0u8; 1];
                if unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) } != 1 {
                    break Err("control_closed");
                }
                if byte[0] == b'\n' {
                    match frame.as_slice() {
                        b"STOP" => break Ok(()),
                        b"ENTRY_CONTINUE" => {
                            if let Err(code) = super::la_worker::release_fixture_entry() {
                                break Err(code);
                            }
                            println!(
                                "DIFFUSER_LA_CHILD_V1 {}",
                                serde_json::json!({"kind":"ENTRY_CONTINUED"})
                            );
                            if std::io::stdout().flush().is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        b"GO" if !sent_go => {
                            sent_go = true;
                            frame.clear();
                        }
                        data if data.starts_with(b"CUSTODY ") => {
                            match control_custody
                                .as_ref()
                                .ok_or("evidence_invalid")
                                .and_then(|link| link.accept(&data[8..]))
                            {
                                Ok(()) => frame.clear(),
                                Err(code) => break Err(code),
                            }
                        }
                        data if data.starts_with(b"LOSSRESOLUTION ") => {
                            if data.len() > 12288 + 15
                                || loss_resolution_sender
                                    .try_send(data[15..].to_vec())
                                    .is_err()
                            {
                                break Err("evidence_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"REBIND ") => {
                            if epoch_sender.try_send(data[7..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"QUALIFY ") => {
                            if activation_sender.try_send(data[8..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"LSBRIDGE ")
                            || data.starts_with(b"LSCOMMIT ")
                            || data.starts_with(b"LSPROBE ")
                            || data.starts_with(b"LSDISPOSE ")
                            || data.starts_with(b"LSDISPOSITION ")
                            || data.starts_with(b"LSGUARDS ")
                            || data.starts_with(b"LACOMPLETE ")
                            || data.starts_with(b"LAACTIVATE ") =>
                        {
                            if bridge_sender.try_send(data.to_vec()).is_err() {
                                break Err("control_invalid");
                            };
                            frame.clear();
                        }
                        data if data.starts_with(b"AUTH ") => {
                            if authority_sender.try_send(data[5..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        _ => break Err("control_invalid"),
                    }
                } else {
                    frame.push(byte[0]);
                    if frame.len() >= 16 * 1024 {
                        break Err("control_invalid");
                    }
                }
            };
            let _ = tx.send(());
            result
        })
        .map_err(|_| "startup_unavailable")?;
    let process_seal = super::la_worker::seal_fixture_role()?;
    let ready = serde_json::json!({"kind":"READY","run_nonce":nonce,"role":"worker","pid":std::process::id(),
        "process_seal":process_seal,"boot_id":bootstrap.boot_id,"executable_sha256":executable_digest,"policy_digest":policy_digest,
        "address":address.to_string(),"store_id":bootstrap.store_id,"root_dev":root_meta.dev(),"root_inode":root_meta.ino(),
        "smoke_input_sha256":hex::encode(Sha256::digest(input)),"smoke_input_bytes":input.len(),
        "smoke_output_sha256":hex::encode(Sha256::digest(&report)),"smoke_output_bytes":report.len(),"write_refusals":write_refusals});
    if !bootstrap.is_recovery() {
        println!("\nDIFFUSER_LA_CHILD_V1 {ready}");
        std::io::stdout()
            .flush()
            .map_err(|_| "startup_unavailable")?;
    }
    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("storage")
        && !bootstrap.is_recovery()
    {
        unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        journal = match worker_storage_pressure_probe(journal, &root, &bootstrap) {
            Ok(journal) => journal,
            Err(code) => {
                println!(
                    "DIFFUSER_LA_CHILD_V1 {}",
                    serde_json::json!({"kind":"ERROR","role":"worker","code":code})
                );
                std::io::stdout().flush().map_err(|_| "control_invalid")?;
                return Err(code);
            }
        };
    }
    // Fixture-only pressure uses the real inspection loop in this W process.
    // It is never selected by an HTTP request or made an admission authority.
    let mut pressure = Vec::new();
    let pressure_stop = Arc::new(AtomicBool::new(false));
    let pressure_iterations = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let pressure_timer_stops = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut pressure_timer = None;
    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("cpu") {
        let now = Instant::now();
        let timer = super::la_worker::PermitTimer::new(
            now + std::time::Duration::from_secs(3),
            now + std::time::Duration::from_secs(4),
        )?;
        for _ in 0..4 {
            let stop = pressure_stop.clone();
            let expired = timer.stop_flag();
            let iterations = pressure_iterations.clone();
            let timer_stops = pressure_timer_stops.clone();
            pressure.push(std::thread::spawn(move || {
                let input = vec![0x5au8; 1024 * 1024];
                while !stop.load(Ordering::SeqCst) && !expired.load(Ordering::SeqCst) {
                    let _ = super::la_worker::inspect(
                        &mut input.as_slice(),
                        "resource_probe_001",
                        Instant::now() + std::time::Duration::from_secs(5),
                        || stop.load(Ordering::SeqCst) || expired.load(Ordering::SeqCst),
                    );
                    iterations.fetch_add(1, Ordering::SeqCst);
                }
                if expired.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
                    timer_stops.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        pressure_timer = Some(timer);
    }
    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("memory") {
        pressure.push(std::thread::spawn(move || {
            // Give the relay time to pin the cgroup event file before pressure.
            std::thread::sleep(std::time::Duration::from_secs(1));
            let mut blocks = Vec::new();
            loop {
                let mut block = vec![0u8; 8 * 1024 * 1024];
                for byte in block.iter_mut().step_by(4096) {
                    *byte = 1;
                }
                blocks.push(block);
                std::hint::black_box(&blocks);
            }
        }));
    }
    let router = if let Some(channel) = &bootstrap.channel {
        if channel.binding.executable_digest != executable_digest
            || channel.binding.policy_digest != policy_digest
        {
            return Err("evidence_invalid");
        }
        let keys = channel.validate(&bootstrap.worker_id, &bootstrap.boot_id, None)?;
        let transport = if let Some(handoff) = &bootstrap.loss_return {
            println!(
                "DIFFUSER_LA_CHILD_V1 {}",
                serde_json::json!({"kind":"LOSS_RESOLUTION_REQUIRED","handoff":handoff.digest()?})
            );
            std::io::stdout().flush().map_err(|_| "control_invalid")?;
            let resolution = loss_resolution_receiver
                .recv_timeout(std::time::Duration::from_millis(500))
                .map_err(|_| "evidence_invalid")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock_untrusted")?
                .as_millis() as u64;
            match handoff.reopen_worker_transport(
                &root,
                std::path::Path::new("/job/workerroot"),
                custody_link.as_ref().ok_or("evidence_invalid")?.clone(),
                &keys,
                now,
                &resolution,
            ) {
                Ok(channel) => channel,
                Err(code) => {
                    println!(
                        "DIFFUSER_LA_CHILD_V1 {}",
                        serde_json::json!({"kind":"WORKER_LOSS_RETURN_STARTUP_REFUSED","phase":"transport","code":code,"store_opens":WORKER_STORE_OPENS.load(std::sync::atomic::Ordering::SeqCst),"listener_binds":WORKER_LISTENER_BINDS.load(std::sync::atomic::Ordering::SeqCst)})
                    );
                    std::io::stdout().flush().map_err(|_| "control_invalid")?;
                    return Err(code);
                }
            }
        } else if let Some(handoff) = &bootstrap.worker_handoff {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock_untrusted")?
                .as_millis() as u64;
            handoff.reopen_worker_transport(
                &root,
                std::path::Path::new("/job/workerroot"),
                custody_link.as_ref().ok_or("evidence_invalid")?.clone(),
                &keys,
                now,
            )?
        } else {
            let mut channel =
                channel.open_channel(&root, std::path::Path::new("/job/workerroot"), true)?;
            channel.enable_custody(custody_link.as_ref().ok_or("evidence_invalid")?.clone())?;
            channel
        };
        let session = super::la_worker::ReservationSession {
            worker: bootstrap.worker_id.clone(),
            boot: bootstrap.boot_id.clone(),
            key: keys.reply,
        };
        let worker_boot = bootstrap.boot_id.clone();
        journal.observe_work_entry(Arc::new(move |operation,job| {
            let observed=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|"clock_untrusted")?.as_millis() as u64;
            println!("DIFFUSER_LA_CHILD_V1 {}",serde_json::json!({"kind":"ENTERED_WORK","worker_boot":worker_boot,"operation":operation,"job":job,"pid":std::process::id(),"marker":1,"observed_at":observed}));
            std::io::stdout().flush().map_err(|_|"control_invalid")
        }))?;
        let state = Arc::new(std::sync::Mutex::new(super::la_adapter::WorkerRpc {
            journal,
            session,
            channel: transport,
            keys,
            admission: super::la_adapter::WorkerAdmission::default(),
        }));
        *rpc_holder.lock().map_err(|_| "storage_unavailable")? = Some(state.clone());
        super::la_adapter::worker_rpc_router(context, state)
    } else {
        drop(journal);
        super::la_adapter::inventory_router(context)
    };
    if bootstrap.is_recovery() {
        println!("\nDIFFUSER_LA_CHILD_V1 {ready}");
        std::io::stdout()
            .flush()
            .map_err(|_| "startup_unavailable")?;
    }
    let served = runtime.block_on(async {
        let listener =
            tokio::net::TcpListener::from_std(listener).map_err(|_| "startup_unavailable")?;
        super::lane_assignment::serve_injected(listener, router, async {
            let _ = rx.await;
        })
        .await
    });
    aborted.store(true, Ordering::SeqCst);
    let control_result = control.join().map_err(|_| "control_invalid")?;
    let authority_result = authority_task
        .thread
        .join()
        .map_err(|_| "control_invalid")?;
    activation_task
        .thread
        .join()
        .map_err(|_| "control_invalid")??;
    epoch_task.thread.join().map_err(|_| "control_invalid")??;
    let pressure_timer_expired = pressure_timer
        .as_ref()
        .is_some_and(|timer| timer.is_stopped());
    pressure_stop.store(true, Ordering::SeqCst);
    let pressure_threads = pressure.len();
    for thread in pressure {
        thread.join().map_err(|_| "startup_unavailable")?;
    }
    served?;
    control_result?;
    authority_result?;
    let stopped = serde_json::json!({"kind":"STOPPED","run_nonce":nonce,"role":"worker","pid":std::process::id(),"fixture_pressure_threads_joined":pressure_threads,"fixture_pressure_iterations":pressure_iterations.load(Ordering::SeqCst),"fixture_pressure_timer_expired":pressure_timer_expired,"fixture_pressure_timer_stops":pressure_timer_stops.load(Ordering::SeqCst)});
    println!("DIFFUSER_LA_CHILD_V1 {stopped}");
    std::io::stdout()
        .flush()
        .map_err(|_| "startup_unavailable")?;
    Ok(())
}

fn controller_storage_capacity_probe(
    store: &mut super::la_artifacts::ArtifactStore,
) -> std::result::Result<serde_json::Value, &'static str> {
    use sha2::{Digest, Sha256};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    let input = vec![0x5a; 1048576];
    let output = vec![0x20; 4096];
    let input_digest = hex::encode(Sha256::digest(&input));
    let output_digest = hex::encode(Sha256::digest(&output));
    for index in 0..32 {
        store.put_input(
            "tenant_123456789",
            "project_12345678",
            "agent_1234567890",
            &format!("resource_input_{index:04}"),
            &input,
            &input_digest,
            now,
            now + 86400000,
        )?;
        store.put_output(
            "tenant_123456789",
            "project_12345678",
            "agent_1234567890",
            &format!("resource_output_{index:04}"),
            "resource_assign_0",
            &format!("resource_job_{index:04}"),
            &output,
            &output_digest,
            now,
            now + 86400000,
        )?;
        if (index + 1) % 8 == 0 {
            println!(
                "DIFFUSER_LA_CHILD_V1 {}",
                serde_json::json!({"kind":"ARTIFACT_HISTORY_PROGRESS","stage":"write","versions":index+1,"admitted_jobs":0})
            );
            std::io::stdout().flush().map_err(|_| "control_invalid")?;
        }
    }
    if store
        .put_input(
            "tenant_123456789",
            "project_12345678",
            "agent_1234567890",
            "resource_input_0032",
            &input,
            &input_digest,
            now,
            now + 86400000,
        )
        .err()
        != Some("storage_unavailable")
        || store
            .put_output(
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                "resource_output_0032",
                "resource_assign_0",
                "resource_job_0032",
                &output,
                &output_digest,
                now,
                now + 86400000,
            )
            .err()
            != Some("storage_unavailable")
    {
        return Err("evidence_invalid");
    }
    for index in 0..32 {
        for (kind, expected) in [("input", &input), ("output", &output)] {
            let (_, readback) = store.read_manifest_and_content(
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                &format!("resource_{kind}_{index:04}"),
                now,
            )?;
            if readback != *expected {
                return Err("evidence_invalid");
            }
        }
        if (index + 1) % 8 == 0 {
            println!(
                "DIFFUSER_LA_CHILD_V1 {}",
                serde_json::json!({"kind":"ARTIFACT_HISTORY_PROGRESS","stage":"read","versions":index+1,"admitted_jobs":0})
            );
            std::io::stdout().flush().map_err(|_| "control_invalid")?;
        }
    }
    Ok(
        serde_json::json!({"payload_class":"qualification_storage_only","input_versions":32,"output_versions":32,"input_version_bytes":1048576,"output_version_bytes":4096,"input_overflow_refused":true,"output_overflow_refused":true,"all_bytes_read_back":true,"admitted_jobs":0}),
    )
}

// Test-only bounded fault at the actual namespace terminal-reply boundary.
// The inner ordinary witness has already durably completed and been ACKed.
async fn controller_publication_barrier(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::io::Write;
    let pause =
        request.method() == axum::http::Method::POST && request.uri().path().ends_with("/jobs");
    let response = next.run(request).await;
    if !pause || response.status() != axum::http::StatusCode::ACCEPTED {
        return response;
    }
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 65536).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    if value["state"] == "succeeded" {
        println!(
            "DIFFUSER_LA_CHILD_V1 {}",
            serde_json::json!({"kind":"PUBLICATION_BARRIER","pid":std::process::id(),"response":value,"durable_terminal_reply_sent":false})
        );
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        panic!("publication barrier was not killed within its bound");
    }
    axum::response::Response::from_parts(parts, axum::body::Body::from(bytes))
}

fn run_controller_child(
    mut bootstrap: super::lane_assignment::ControllerBootstrap,
    mut stores: (
        super::la_store::ClaimStore,
        super::la_artifacts::ArtifactStore,
        Option<super::la_adapter::TransportJournal>,
    ),
    root: std::fs::File,
    nonce: &str,
    policy_digest: &str,
    executable_digest: &str,
    startup_deadline: std::time::Instant,
) -> std::result::Result<(), &'static str> {
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        os::unix::fs::MetadataExt,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Instant,
    };
    let input = b"diffuser-s1-controller-startup-smoke-v1";
    let mut bytes = &input[..];
    let report =
        super::la_worker::inspect(&mut bytes, "startup_smoke_002", startup_deadline, || false)?;
    let inventory = super::la_adapter::fetch_inventory(
        bootstrap.worker_address,
        &bootstrap.worker_bearer,
        &bootstrap.worker_id,
        &bootstrap.worker_boot_id,
    )?;
    use zeroize::Zeroize;
    bootstrap.worker_bearer.zeroize();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| u64::try_from(v.as_millis()).ok())
        .ok_or("clock_untrusted")?;
    bootstrap.context.inventory_available = true;
    bootstrap.context.inventory_observed_at = now;
    let storage_probe = if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("storage") {
        Some(controller_storage_capacity_probe(&mut stores.1)?)
    } else {
        None
    };
    let root_meta = root.metadata().map_err(|_| "startup_root_invalid")?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "startup_unavailable")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "startup_unavailable")?;
    CONTROLLER_LISTENER_BINDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let address = listener.local_addr().map_err(|_| "startup_unavailable")?;
    if Instant::now() >= startup_deadline {
        return Err("child_config_timeout");
    }
    let state = super::Spine {
        root: std::path::PathBuf::from("/job/service"),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: std::sync::Arc::new(std::sync::Mutex::new(0)),
    };
    let authority = Arc::new(std::sync::RwLock::new(bootstrap.context.clone()));
    let claims = Arc::new(std::sync::Mutex::new(stores.0));
    let source_control = bootstrap
        .channel
        .as_ref()
        .map(|channel| {
            channel
                .validate(
                    &bootstrap.worker_id,
                    &bootstrap.worker_boot_id,
                    Some(&bootstrap.boot_id),
                )
                .map(|keys| (channel.binding.clone(), keys))
        })
        .transpose()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "startup_unavailable")?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let aborted = Arc::new(AtomicBool::new(false));
    let thread_aborted = aborted.clone();
    let custody_link = source_control
        .as_ref()
        .map(|(binding, keys)| protected_custody_link(binding, keys, "controller"))
        .transpose()?;
    let control_custody = custody_link.clone();
    let domain_link = if bootstrap.recovery.is_some() {
        let (binding, keys) = source_control.as_ref().ok_or("evidence_invalid")?;
        Some(super::la_adapter::state_custody::Link::new(
            binding.clone(),
            keys,
            Box::new(|bytes| {
                let value = std::str::from_utf8(bytes).map_err(|_| "evidence_invalid")?;
                println!("DIFFUSER_LA_CHILD_V1 {{\"kind\":\"SERVICE_STATE_CHECKPOINT\",\"checkpoint\":{value}}}");
                std::io::stdout().flush().map_err(|_| "control_invalid")
            }),
        )?)
    } else if let Some(genesis) = bootstrap
        .channel
        .as_ref()
        .and_then(|c| c.service_genesis.as_ref())
    {
        use std::os::unix::fs::MetadataExt;
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        let (binding, keys) = source_control.as_ref().ok_or("evidence_invalid")?;
        if (genesis.root_dev, genesis.root_inode) != (m.dev(), m.ino())
            || genesis.controller_boot != binding.controller_boot
            || genesis.controller_epoch != binding.controller_epoch
            || genesis.expected_records != 0
        {
            return Err("evidence_invalid");
        }
        Some(super::la_adapter::state_custody::Link::new(
            binding.clone(),
            keys,
            Box::new(|bytes| {
                let value = std::str::from_utf8(bytes).map_err(|_| "evidence_invalid")?;
                println!("DIFFUSER_LA_CHILD_V1 {{\"kind\":\"SERVICE_STATE_CHECKPOINT\",\"checkpoint\":{value}}}");
                std::io::stdout().flush().map_err(|_| "control_invalid")
            }),
        )?)
    } else {
        None
    };
    let control_domain = domain_link.clone();
    let domain_holder = Arc::new(std::sync::Mutex::new(
        None::<Arc<super::la_adapter::state_custody::Session>>,
    ));
    let source_domain = domain_holder.clone();
    let require_domain = domain_link.is_some();
    let admission = super::la_adapter::WorkerAdmission::default();
    let control_admission = admission.clone();
    let activation_root = root.try_clone().map_err(|_| "storage_unavailable")?;
    let activation_context = source_control.as_ref().map(|(b, k)| (b.clone(), k.clone()));
    let recovery_context = activation_context.clone();
    let activation_domain = domain_holder.clone();
    let activation_task = protected_activation_task(aborted.clone(), move |bytes| {
        let (binding, keys) = activation_context.as_ref().ok_or("evidence_invalid")?;
        let domain = activation_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .clone();
        control_admission.install(
            bytes,
            binding,
            keys,
            &activation_root,
            "controller",
            domain.as_deref(),
        )
    })?;
    let activation_sender = activation_task.sender;
    let cleanup_context = source_control.as_ref().map(|(b, k)| (b.clone(), k.clone()));
    let cleanup_claims = claims.clone();
    let cleanup_domain = domain_holder.clone();
    let cleanup_task = protected_cleanup_task(aborted.clone(), move |bytes| {
        let (binding, keys) = cleanup_context.as_ref().ok_or("evidence_invalid")?;
        let domain = cleanup_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .clone()
            .ok_or("evidence_invalid")?;
        let current_binding = domain.binding()?;
        super::la_adapter::recovery_trace(
            "cleanup_current_binding",
            serde_json::json!({"same_controller_boot":current_binding.controller_boot==binding.controller_boot,"same_controller_epoch":current_binding.controller_epoch==binding.controller_epoch,"same_worker_boot":current_binding.worker_boot==binding.worker_boot,"worker_epoch":current_binding.worker_epoch,"controller_epoch":current_binding.controller_epoch,"bytes":bytes.len(),"frame_sha256":({use sha2::{Digest,Sha256};hex::encode(Sha256::digest(bytes))})}),
        );
        if current_binding.controller_boot != binding.controller_boot
            || current_binding.controller_epoch != binding.controller_epoch
        {
            return Err("evidence_invalid");
        }
        super::lane_assignment::apply_witnessed_cleanup(
            &cleanup_claims,
            &current_binding,
            keys,
            bytes,
            &domain,
        )
    })?;
    let cleanup_sender = cleanup_task.sender;
    let service_worker_holder = Arc::new(std::sync::Mutex::new(
        None::<Arc<std::sync::Mutex<super::lane_assignment::ServiceWorker>>>,
    ));
    let loss_worker = service_worker_holder.clone();
    let loss_claims = claims.clone();
    let loss_authority = authority.clone();
    let loss_context = source_control.as_ref().map(|(_, k)| k.clone());
    let loss_domain = domain_holder.clone();
    let loss_root = root.try_clone().map_err(|_| "storage_unavailable")?;
    let loss_task = protected_epoch_task(aborted.clone(), move |bytes| {
        let wire: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        if wire["kind"] == "diffuser-dead-worker-source/v1" {
            let cap: super::la_adapter::WorkerLossSource =
                serde_json::from_value(wire).map_err(|_| "evidence_invalid")?;
            let worker = loss_worker
                .lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .ok_or("evidence_invalid")?
                .clone();
            let domain = loss_domain
                .lock()
                .map_err(|_| "storage_unavailable")?
                .clone()
                .ok_or("evidence_invalid")?;
            return match super::lane_assignment::reconcile_protected_loss_source(
                &worker,
                &loss_claims,
                &loss_authority,
                &loss_root,
                &domain,
                &cap,
                loss_context.as_ref().ok_or("evidence_invalid")?,
            ) {
                Ok(ack) => {
                    Ok(serde_json::json!({"kind":"WORKER_LOSS_SOURCE_ACK","source_ack":ack}))
                }
                Err(code) => {
                    Ok(serde_json::json!({"kind":"WORKER_LOSS_SOURCE_REFUSED","code":code}))
                }
            };
        }
        let cap: super::la_adapter::WorkerLossSettlement =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let worker = loss_worker
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        match super::lane_assignment::settle_protected_worker_loss(
            &worker,
            &loss_claims,
            &loss_authority,
            &cap,
            loss_context.as_ref().ok_or("evidence_invalid")?,
        ) {
            Ok(ack) => Ok(ack),
            Err(code) => Ok(serde_json::json!({"kind":"WORKER_LOSS_REFUSED","code":code})),
        }
    })?;
    let loss_sender = loss_task.sender;
    let return_worker = service_worker_holder.clone();
    let return_claims = claims.clone();
    let return_domain = domain_holder.clone();
    let return_context = source_control.as_ref().map(|(_, k)| k.clone());
    let worker_return_task = protected_epoch_task(aborted.clone(), move |bytes| {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Return {
            handoff: super::la_adapter::WorkerEpochHandoff,
            address: std::net::SocketAddr,
        }
        let value: Return = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let worker = return_worker
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let domain = return_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis() as u64;
        let ack = super::lane_assignment::reconcile_protected_worker_return(
            &worker,
            &return_claims,
            &domain,
            &value.handoff,
            value.address,
            return_context.as_ref().ok_or("evidence_invalid")?,
            now,
        )?;
        serde_json::to_value(ack).map_err(|_| "evidence_invalid")
    })?;
    let worker_return_sender = worker_return_task.sender;
    let loss_return_worker = service_worker_holder.clone();
    let loss_return_claims = claims.clone();
    let loss_return_authority = authority.clone();
    let loss_return_domain = domain_holder.clone();
    let loss_return_task = protected_loss_return_task(aborted.clone(), move |bytes| {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            handoff: super::la_adapter::WorkerLossReturn,
            address: std::net::SocketAddr,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AdmissionRequest {
            kind: String,
            admission: super::la_adapter::LossReturnAdmission,
        }
        if let Some(proof) = bytes.strip_prefix(b"LAACTIVATE ") {
            let worker = loss_return_worker
                .lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .ok_or("evidence_invalid")?
                .clone();
            let domain = loss_return_domain
                .lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .ok_or("evidence_invalid")?
                .clone();
            return super::lane_assignment::activate_protected_loss_return(
                &loss_return_claims,
                &worker,
                &loss_return_authority,
                &domain,
                proof,
            );
        }
        if let Some(proof) = bytes.strip_prefix(b"LACOMPLETE ") {
            let worker = loss_return_worker
                .lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .ok_or("evidence_invalid")?
                .clone();
            let domain = loss_return_domain
                .lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .ok_or("evidence_invalid")?
                .clone();
            return super::lane_assignment::persist_protected_loss_return_completion(
                &loss_return_claims,
                &worker,
                &loss_return_authority,
                &domain,
                proof,
            );
        }
        let wire: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        if wire["kind"] == "diffuser-loss-return-admission-install/v1" {
            let request: AdmissionRequest =
                serde_json::from_value(wire).map_err(|_| "evidence_invalid")?;
            if request.kind != "diffuser-loss-return-admission-install/v1" {
                return Err("evidence_invalid");
            }
            let worker = loss_return_worker
                .lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .ok_or("evidence_invalid")?
                .clone();
            let domain = loss_return_domain
                .lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .ok_or("evidence_invalid")?
                .clone();
            return super::lane_assignment::install_protected_loss_return(
                &loss_return_claims,
                &worker,
                &loss_return_authority,
                &domain,
                &request.admission,
            );
        }
        let request: Request = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let worker = loss_return_worker
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let domain = loss_return_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        super::lane_assignment::reconcile_protected_loss_transport(
            &worker,
            &loss_return_claims,
            &loss_return_authority,
            &domain,
            &request.handoff,
            request.address,
        )
    })?;
    let loss_return_sender = loss_return_task.sender;
    let bridge_worker = service_worker_holder.clone();
    let bridge_authority = authority.clone();
    let bridge_domain = domain_holder.clone();
    let bridge_task = protected_epoch_task(aborted.clone(), move |bytes| {
        let worker = bridge_worker
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let domain = bridge_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        if let Some(bytes) = bytes.strip_prefix(b"LSDISPOSE ") {
            let cap: super::la_adapter::SpentLossDisposition =
                serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
            return match super::lane_assignment::dispose_protected_entered_loss(
                &worker,
                &bridge_authority,
                &domain,
                &cap,
            ) {
                Ok(v) => Ok(v),
                Err(code) => Ok(
                    serde_json::json!({"kind":"SPENT_LOSS_DISPOSITION_REFUSED","code":code,"admitted":false}),
                ),
            };
        }
        if bytes == b"LSPROBE {}" {
            return super::lane_assignment::probe_protected_loss_source_bridge(
                &worker,
                &bridge_authority,
                &domain,
            );
        }
        let (body, complete) = if let Some(b) = bytes.strip_prefix(b"LSBRIDGE ") {
            (b, false)
        } else if let Some(b) = bytes.strip_prefix(b"LSCOMMIT ") {
            (b, true)
        } else {
            return Err("evidence_invalid");
        };
        super::lane_assignment::reconcile_protected_loss_source_bridge(
            &worker,
            &bridge_authority,
            &domain,
            body,
            complete,
        )
    })?;
    let bridge_sender = bridge_task.sender;
    let successor_worker = service_worker_holder.clone();
    let successor_claims = claims.clone();
    let successor_domain = domain_holder.clone();
    let successor_root = root.try_clone().map_err(|_| "storage_unavailable")?;
    let successor_task = protected_activation_task(aborted.clone(), move |bytes| {
        let cap: super::la_adapter::WorkerSuccessorAdmission =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let worker = successor_worker
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let domain = successor_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        super::lane_assignment::admit_protected_worker_successor(
            &worker,
            &successor_claims,
            &successor_root,
            &domain,
            &cap,
        )
    })?;
    let successor_sender = successor_task.sender;
    let recovered_worker = service_worker_holder.clone();
    let recovered_claims = claims.clone();
    let recovered_domain = domain_holder.clone();
    let recovered_root = root.try_clone().map_err(|_| "storage_unavailable")?;
    let recovered_admission_task = protected_epoch_task(aborted.clone(), move |bytes| {
        let cap: super::la_adapter::RecoveredControllerAdmission =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let worker = recovered_worker
            .lock()
            .map_err(|_| "storage_unavailable")?
            .clone()
            .ok_or("evidence_invalid")?;
        let domain = recovered_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .clone()
            .ok_or("evidence_invalid")?;
        match super::lane_assignment::admit_protected_recovered_controller(
            &worker,
            &recovered_claims,
            &recovered_root,
            &domain,
            &cap,
        ) {
            Ok(ack) => serde_json::to_value(ack).map_err(|_| "evidence_invalid"),
            Err(code) => Ok(serde_json::json!({"kind":"RECOVERED_ADMISSION_REFUSED","code":code})),
        }
    })?;
    let recovered_admission_sender = recovered_admission_task.sender;

    let recovery_artifacts = Arc::new(std::sync::Mutex::new(
        None::<Arc<std::sync::Mutex<super::la_artifacts::ArtifactStore>>>,
    ));
    let resume_artifacts = recovery_artifacts.clone();
    let resume_worker = service_worker_holder.clone();
    let resume_claims = claims.clone();
    let resume_authority = authority.clone();
    let resume_domain = domain_holder.clone();
    let resume_root = root.try_clone().map_err(|_| "storage_unavailable")?;
    let resume_task = protected_epoch_task(aborted.clone(), move |bytes| {
        let cap: super::la_adapter::NeverStartedPermit =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let artifacts = resume_artifacts
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let worker = resume_worker
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let domain = resume_domain
            .lock()
            .map_err(|_| "storage_unavailable")?
            .as_ref()
            .ok_or("evidence_invalid")?
            .clone();
        let result = super::lane_assignment::resume_protected_never_started(
            &worker,
            &resume_claims,
            &artifacts,
            &resume_authority,
            &resume_root,
            &domain,
            &cap,
        );
        if let Err(code) = &result {
            if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").is_ok_and(|v| {
                v.ends_with("-foreign") || v.ends_with("-stale") || v.ends_with("-expired")
            }) {
                return Ok(serde_json::json!({"kind":"RECOVERY_RESUME_REFUSED","code":code}));
            }
        }
        if let Err(code) = &result {
            use std::io::Write;
            println!(
                "DIFFUSER_LA_CHILD_V1 {}",
                serde_json::json!({"kind":"RECOVERY_RESUME_REFUSED","code":code})
            );
            std::io::stdout().flush().ok();
        }
        result
    })?;
    let resume_sender = resume_task.sender;
    let source_worker = service_worker_holder.clone();
    let source_authority = authority.clone();
    let source_claims = claims.clone();
    let authority_task = protected_authority_task(aborted.clone(), move |data| {
        source_control
            .as_ref()
            .ok_or("evidence_invalid")
            .and_then(|(binding, keys)| {
                let domain = source_domain
                    .lock()
                    .map_err(|_| "storage_unavailable")?
                    .clone();
                if let Some(domain) = domain {
                    let current_binding = domain.binding()?;
                    if current_binding.controller_boot != binding.controller_boot
                        || current_binding.controller_epoch != binding.controller_epoch
                    {
                        return Err("evidence_invalid");
                    }
                    super::lane_assignment::apply_witnessed_protected_source_observation(
                        &source_authority,
                        &source_claims,
                        &current_binding,
                        keys,
                        data,
                        source_worker
                            .lock()
                            .map_err(|_| "storage_unavailable")?
                            .as_ref(),
                        &domain,
                    )
                } else if require_domain {
                    Err("evidence_invalid")
                } else {
                    super::lane_assignment::apply_protected_source_observation(
                        &source_authority,
                        &source_claims,
                        binding,
                        keys,
                        data,
                    )
                }
            })
    })?;
    let authority_sender = authority_task.sender;
    let corruption_root = root.try_clone().map_err(|_| "storage_unavailable")?;
    let control = std::thread::Builder::new()
        .name("la-controller-control".into())
        .spawn(move || {
            let mut frame = Vec::new();
            let mut sent_go = false;
            let result = loop {
                if thread_aborted.load(Ordering::SeqCst) {
                    break Err("control_stopped");
                }
                let mut poll = libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut poll, 1, 100) };
                if ready == 0 {
                    continue;
                }
                if ready < 0 {
                    break Err("control_invalid");
                }
                let mut byte = [0u8; 1];
                if unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) } != 1 {
                    break Err("control_closed");
                }
                if byte[0] == b'\n' {
                    match frame.as_slice() {
                        b"STOP" => break Ok(()),
                        b"CORRUPT_CONSUMPTION" => {
                            let result = match corrupt_consumption_witness(&corruption_root) {
                                Ok(v) => v,
                                Err(code) => break Err(code),
                            };
                            println!("DIFFUSER_LA_CHILD_V1 {result}");
                            std::io::stdout().flush().map_err(|_| "control_invalid")?;
                            frame.clear();
                        }
                        b"GO" if !sent_go => {
                            sent_go = true;
                            frame.clear();
                        }
                        data if data.starts_with(b"CUSTODY ") => {
                            match control_custody
                                .as_ref()
                                .ok_or("evidence_invalid")
                                .and_then(|link| link.accept(&data[8..]))
                            {
                                Ok(()) => frame.clear(),
                                Err(code) => break Err(code),
                            }
                        }
                        data if data.starts_with(b"STATE ") => {
                            match control_domain
                                .as_ref()
                                .ok_or("evidence_invalid")
                                .and_then(|link| link.accept(&data[6..]))
                            {
                                Ok(()) => frame.clear(),
                                Err(code) => break Err(code),
                            }
                        }
                        data if data.starts_with(b"WLOSS ") => {
                            if loss_sender.try_send(data[6..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"WLRETURN ") => {
                            if loss_return_sender.try_send(data[9..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"WRETURN ") => {
                            if worker_return_sender.try_send(data[8..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"RESUME_JOB ") => {
                            if resume_sender.try_send(data[11..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"CADMIT ") => {
                            if recovered_admission_sender
                                .try_send(data[7..].to_vec())
                                .is_err()
                            {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"WSUCCESSOR ") => {
                            if successor_sender.try_send(data[11..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"CLEANUP ") => {
                            if cleanup_sender.try_send(data[8..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"QUALIFY ") => {
                            if activation_sender.try_send(data[8..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        data if data.starts_with(b"LSBRIDGE ")
                            || data.starts_with(b"LSCOMMIT ")
                            || data.starts_with(b"LSPROBE ")
                            || data.starts_with(b"LSDISPOSE ")
                            || data.starts_with(b"LSDISPOSITION ") =>
                        {
                            if bridge_sender.try_send(data.to_vec()).is_err() {
                                break Err("control_invalid");
                            };
                            frame.clear();
                        }
                        data if data.starts_with(b"AUTH ") => {
                            if authority_sender.try_send(data[5..].to_vec()).is_err() {
                                break Err("control_invalid");
                            }
                            frame.clear();
                        }
                        _ => break Err("control_invalid"),
                    }
                } else {
                    frame.push(byte[0]);
                    if frame.len() >= 16 * 1024 {
                        break Err("control_invalid");
                    }
                }
            };
            let _ = tx.send(());
            result
        })
        .map_err(|_| "startup_unavailable")?;
    super::la_adapter::recovery_trace(
        "recovered_startup_transport",
        serde_json::json!({"handoff":bootstrap.transport_handoff.is_some()}),
    );
    let mut retained_transport = stores.2.take();
    if let Some(handoff) = &bootstrap.transport_handoff {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis() as u64;
        retained_transport
            .as_mut()
            .ok_or("evidence_invalid")?
            .install_controller_epoch(
                handoff,
                Some(custody_link.as_ref().ok_or("evidence_invalid")?.clone()),
                now,
            )?;
    }
    let domain_session = match domain_link {
        Some(link) => match if let Some(recovery) = &bootstrap.recovery {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock_untrusted")?
                .as_millis() as u64;
            super::la_adapter::state_custody::Session::recover(&root, link, recovery.service(), now)
        } else {
            super::la_adapter::state_custody::Session::create(&root, link)
        } {
            Ok(session) => Some(session),
            Err(code) => {
                use std::os::unix::fs::MetadataExt;
                let entries=[".claim-lock",".artifact-lock","lane_assignments.sqlite","artifacts","service-custody.sqlite"].iter().filter_map(|name|std::fs::metadata(format!("/job/service/{name}")).ok().map(|m|serde_json::json!({"name":name,"uid":m.uid(),"mode":m.mode(),"bytes":m.len()}))).collect::<Vec<_>>();
                println!(
                    "DIFFUSER_LA_CHILD_V1 {}",
                    serde_json::json!({"kind":"ERROR","stage":"service_state_genesis","code":code,"uid":unsafe{libc::geteuid()},"files":entries})
                );
                std::io::stdout().flush().map_err(|_| "control_invalid")?;
                return Err(code);
            }
        },
        None => None,
    };
    *domain_holder.lock().map_err(|_| "storage_unavailable")? = domain_session.clone();
    let mut reconciled_client = None;
    let (namespace, transport_probe) = if let Some(recovery) = &bootstrap.recovery {
        let (binding, keys) = recovery_context.as_ref().ok_or("evidence_invalid")?;
        if binding.executable_digest != executable_digest || binding.policy_digest != policy_digest
        {
            return Err("evidence_invalid");
        }
        if retained_transport.is_none() {
            return Err("evidence_invalid");
        }
        super::la_adapter::recovery_trace("recovered_startup_service", serde_json::json!({}));
        let mut reconciliation = Vec::new();
        if bootstrap.transport_handoff.is_some() {
            let mut client = super::la_adapter::WorkerClient::new(
                bootstrap.worker_address,
                retained_transport.take().ok_or("evidence_invalid")?,
                keys.clone(),
            )?;
            super::la_adapter::recovery_trace(
                "recovered_commands_lock_wait",
                serde_json::json!({}),
            );
            let commands = claims
                .lock()
                .map_err(|_| "storage_unavailable")?
                .reconciliation_commands()?;
            for command in commands {
                let status = client.call(
                    super::la_adapter::WorkerOperation::Status(command.clone()),
                    &[],
                )?;
                match &status {
                    super::la_adapter::WorkerReply::Status {
                        operation,
                        state,
                        starts,
                    } if operation == &command.operation
                        && *starts <= 1
                        && (*starts == 1 || state != "complete") => {}
                    _ => return Err("evidence_invalid"),
                }
                // A transport handoff cannot reuse the old activation, even
                // for this exact already-computed job and unchanged mandate.
                if !matches!(client.call(super::la_adapter::WorkerOperation::Start(command),&[])?,super::la_adapter::WorkerReply::Refused{code} if code=="evidence_invalid")
                {
                    return Err("evidence_invalid");
                }
                reconciliation.push(status);
            }
            super::la_adapter::recovery_trace(
                "recovered_commands_complete",
                serde_json::json!({"commands":reconciliation.len()}),
            );
            reconciled_client = Some(client);
        }
        let domain = domain_session.as_ref().ok_or("evidence_invalid")?;
        {
            let mut claim = claims.lock().map_err(|_| "storage_unavailable")?;
            super::lane_assignment::restore_readback_authority(&authority, &claim, keys, recovery)?;
            let op = if let Some(operation) = recovery.service().pending_stop_operation() {
                let (receipt, mac) = bootstrap
                    .transport_handoff
                    .as_ref()
                    .ok_or("evidence_invalid")?
                    .settled_stop(keys)?
                    .ok_or("evidence_invalid")?;
                claim.acknowledge_job_stop(&keys.reply, &receipt, &mac)?;
                operation
            } else if let Some(operation) = recovery.service().pending_close_operation() {
                let (receipt, mac) = bootstrap
                    .transport_handoff
                    .as_ref()
                    .ok_or("evidence_invalid")?
                    .settled_close(keys)?
                    .ok_or("evidence_invalid")?;
                claim.acknowledge_assignment_stop(&keys.reply, &receipt, &mac)?;
                operation
            } else {
                domain.begin(&recovery.digest()?)?
            };
            claim.recover_controller_identity(recovery)?;
            if recovery.service().pending_close_operation().is_some() {
                recovery_test_delay(
                    bootstrap
                        .transport_handoff
                        .as_ref()
                        .ok_or("evidence_invalid")?,
                    "after-install",
                );
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| "clock_untrusted")?
                    .as_millis() as u64;
                claim.record_recovered_close(
                    bootstrap
                        .transport_handoff
                        .as_ref()
                        .ok_or("evidence_invalid")?,
                    keys,
                    now,
                )?;
            }
            domain.complete(op, &recovery.digest()?)?;
        }
        let artifacts = Arc::new(std::sync::Mutex::new(stores.1));
        *recovery_artifacts
            .lock()
            .map_err(|_| "storage_unavailable")? = Some(artifacts.clone());
        if let Some(client) = reconciled_client.take() {
            let client = client
                .with_protected_admission(admission.clone())
                .with_service_custody(domain.clone());
            *service_worker_holder
                .lock()
                .map_err(|_| "storage_unavailable")? =
                Some(super::lane_assignment::protected_readback_worker(
                    client,
                    super::la_worker::ReservationSession {
                        worker: binding.worker.clone(),
                        boot: binding.worker_boot.clone(),
                        key: keys.reply,
                    },
                ));
        }
        (
            if bootstrap
                .transport_handoff
                .as_ref()
                .map(|h| h.recovered_job_lifecycle(keys))
                .transpose()?
                .unwrap_or(false)
            {
                super::lane_assignment::recovered_lifecycle_router(
                    authority.clone(),
                    artifacts,
                    claims.clone(),
                    service_worker_holder
                        .lock()
                        .map_err(|_| "storage_unavailable")?
                        .clone()
                        .ok_or("evidence_invalid")?,
                    recovery.authority_sequence(),
                )
            } else {
                super::lane_assignment::recovered_readback_router_shared(
                    authority.clone(),
                    artifacts,
                    claims.clone(),
                    recovery.authority_sequence(),
                )
            },
            serde_json::json!({"admission":"recovery_read_only","controller_boot":binding.controller_boot,"controller_epoch":binding.controller_epoch,"worker_boot":binding.worker_boot,"preserved_transport":true,"worker_rebound":bootstrap.transport_handoff.is_some(),"reconciliation":reconciliation,"execution_admission_closed":true}),
        )
    } else if let Some(channel) = &bootstrap.channel {
        if channel.binding.executable_digest != executable_digest
            || channel.binding.policy_digest != policy_digest
        {
            return Err("evidence_invalid");
        }
        let keys = channel.validate(
            &bootstrap.worker_id,
            &bootstrap.worker_boot_id,
            Some(&bootstrap.boot_id),
        )?;
        let mut transport =
            channel.open_channel(&root, std::path::Path::new("/job/service"), false)?;
        transport.enable_custody(custody_link.as_ref().ok_or("evidence_invalid")?.clone())?;
        let session = super::la_worker::ReservationSession {
            worker: bootstrap.worker_id.clone(),
            boot: bootstrap.worker_boot_id.clone(),
            key: keys.reply,
        };
        let mut client =
            super::la_adapter::WorkerClient::new(bootstrap.worker_address, transport, keys)?
                .with_protected_admission(admission.clone());
        if let Some(domain) = &domain_session {
            client = client.with_service_custody(domain.clone());
        }
        let reply = client.call(super::la_adapter::WorkerOperation::Probe, &[])?;
        let (worker_pid, admission) = match reply {
            super::la_adapter::WorkerReply::Probe {
                worker_pid,
                admission,
            } if admission == "resource_unqualified" => (worker_pid, admission),
            _ => return Err("evidence_invalid"),
        };
        // Non-authorizing qualification traffic exercises the actual C/W
        // transport and P witness history alongside the retained storage load.
        // Probes cannot reserve, permit or compute a user job.
        let mut transport_sequence = 1u64;
        if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("storage") {
            for _ in 0..160 {
                let response = match client.call(super::la_adapter::WorkerOperation::Probe, &[]) {
                    Ok(value) => value,
                    Err(code) => {
                        println!(
                            "DIFFUSER_LA_CHILD_V1 {}",
                            serde_json::json!({"kind":"ERROR","role":"controller","stage":"transport_history","sequence":transport_sequence+1,"code":code})
                        );
                        std::io::stdout().flush().map_err(|_| "control_invalid")?;
                        return Err(code);
                    }
                };
                match response {
                    super::la_adapter::WorkerReply::Probe {
                        worker_pid: pid,
                        admission: ref state,
                    } if pid == worker_pid && state == "resource_unqualified" => (),
                    _ => return Err("evidence_invalid"),
                }
                transport_sequence += 1;
                if (transport_sequence - 1).is_multiple_of(8) {
                    println!(
                        "DIFFUSER_LA_CHILD_V1 {}",
                        serde_json::json!({"kind":"TRANSPORT_HISTORY_PROGRESS","sequence":transport_sequence,"admitted_jobs":0})
                    );
                    std::io::stdout().flush().map_err(|_| "control_invalid")?;
                }
            }
        }
        let probe = serde_json::json!({"worker_pid":worker_pid,"admission":admission,"worker_boot":channel.binding.worker_boot,"controller_boot":channel.binding.controller_boot,"sequence":transport_sequence,"live_custody":true});
        let (router, worker) = super::lane_assignment::protected_service_router(
            authority.clone(),
            stores.1,
            claims.clone(),
            client,
            session,
        );
        *service_worker_holder
            .lock()
            .map_err(|_| "storage_unavailable")? = Some(worker);
        (router, probe)
    } else {
        (
            super::lane_assignment::injected_service_router_shared(authority.clone(), stores.1),
            serde_json::Value::Null,
        )
    };
    let namespace = if let Some(domain) = domain_session {
        super::lane_assignment::witnessed_namespace(namespace, domain)
    } else {
        namespace
    };
    let namespace = if bootstrap.reply_barrier {
        namespace.layer(axum::middleware::from_fn(controller_publication_barrier))
    } else {
        namespace
    };
    let _retained_transport = retained_transport;
    let _reconciled_client = reconciled_client;
    let router = super::api_with_namespace(state, namespace);
    let process_seal = super::la_worker::seal_fixture_role()?;
    let ready = serde_json::json!({"kind":"READY","run_nonce":nonce,"role":"controller","pid":std::process::id(),
        "process_seal":process_seal,"boot_id":bootstrap.boot_id,"worker_inventory_sha256":hex::encode(Sha256::digest(&inventory)),"worker_inventory_bytes":inventory.len(),"executable_sha256":executable_digest,"policy_digest":policy_digest,
        "storage_probe":storage_probe,"transport_probe":transport_probe,"address":address.to_string(),"store_id":bootstrap.store_id,"root_dev":root_meta.dev(),"root_inode":root_meta.ino(),
        "smoke_input_sha256":hex::encode(Sha256::digest(input)),"smoke_input_bytes":input.len(),
        "smoke_output_sha256":hex::encode(Sha256::digest(&report)),"smoke_output_bytes":report.len()});
    println!("\nDIFFUSER_LA_CHILD_V1 {ready}");
    std::io::stdout()
        .flush()
        .map_err(|_| "startup_unavailable")?;
    let served = runtime.block_on(async {
        let listener =
            tokio::net::TcpListener::from_std(listener).map_err(|_| "startup_unavailable")?;
        super::lane_assignment::serve_injected(listener, router, async {
            let _ = rx.await;
        })
        .await
    });
    aborted.store(true, Ordering::SeqCst);
    let control_result = control.join().map_err(|_| "control_invalid")?;
    let authority_result = authority_task
        .thread
        .join()
        .map_err(|_| "control_invalid")?;
    activation_task
        .thread
        .join()
        .map_err(|_| "control_invalid")??;
    recovered_admission_task
        .thread
        .join()
        .map_err(|_| "control_invalid")??;
    successor_task
        .thread
        .join()
        .map_err(|_| "control_invalid")??;
    cleanup_task
        .thread
        .join()
        .map_err(|_| "control_invalid")??;
    worker_return_task
        .thread
        .join()
        .map_err(|_| "control_invalid")??;
    resume_task.thread.join().map_err(|_| "control_invalid")??;
    loss_task.thread.join().map_err(|_| "control_invalid")??;
    served?;
    control_result?;
    authority_result?;
    let stopped = serde_json::json!({"kind":"STOPPED","run_nonce":nonce,"role":"controller","pid":std::process::id()});
    println!("DIFFUSER_LA_CHILD_V1 {stopped}");
    std::io::stdout()
        .flush()
        .map_err(|_| "startup_unavailable")?;
    Ok(())
}

fn child_executable_digest(end: std::time::Instant) -> std::result::Result<String, &'static str> {
    // /proc/self/exe names the actual executing inode, even if its pathname is replaced.
    let file = std::fs::File::open("/proc/self/exe").map_err(|_| "child_config_invalid")?;
    fixture_digest_file(file, end)
}

fn fixture_digest_file(
    mut file: std::fs::File,
    end: std::time::Instant,
) -> std::result::Result<String, &'static str> {
    use std::{
        io::Read,
        os::fd::{AsRawFd, FromRawFd},
    };
    // AF_ALG computes real SHA-256 in bounded chunks; an unavailable kernel
    // interface is a closed startup, never an override.
    let fd = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err("child_config_invalid");
    }
    let alg = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_alg = unsafe { std::mem::zeroed() };
    addr.salg_family = libc::AF_ALG as libc::sa_family_t;
    addr.salg_type[..4].copy_from_slice(b"hash");
    addr.salg_name[..6].copy_from_slice(b"sha256");
    let bound = unsafe {
        libc::bind(
            alg.as_raw_fd(),
            (&addr as *const libc::sockaddr_alg).cast(),
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    if bound != 0 {
        return Err("child_config_invalid");
    }
    let fd = unsafe {
        libc::accept4(
            alg.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err("child_config_invalid");
    }
    let digest = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buffer = [0; 64 * 1024];
    loop {
        if std::time::Instant::now() >= end {
            return Err("child_config_timeout");
        }
        let n = file.read(&mut buffer).map_err(|_| "child_config_invalid")?;
        if n == 0 {
            break;
        }
        let mut offset = 0;
        while offset < n {
            if std::time::Instant::now() >= end {
                return Err("child_config_timeout");
            }
            let sent = unsafe {
                libc::send(
                    digest.as_raw_fd(),
                    buffer[offset..n].as_ptr().cast(),
                    n - offset,
                    libc::MSG_MORE | libc::MSG_NOSIGNAL,
                )
            };
            if sent <= 0 {
                return Err("child_config_invalid");
            }
            offset += sent as usize;
        }
    }
    if std::time::Instant::now() >= end {
        return Err("child_config_timeout");
    }
    let mut hash = [0u8; 32];
    let count = unsafe { libc::recv(digest.as_raw_fd(), hash.as_mut_ptr().cast(), hash.len(), 0) };
    if count != hash.len() as isize {
        return Err("child_config_invalid");
    }
    if std::time::Instant::now() >= end {
        return Err("child_config_timeout");
    }
    Ok(hex::encode(hash))
}

#[test]
fn child_pipe_rejects_malformed_config_before_activation() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{}\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("child_config_invalid"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DIFFUSER_LA_CHILD_V1"));
}

#[test]
fn child_frame_is_processed_while_the_control_pipe_remains_open() {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // An incomplete config must be rejected promptly even while P retains its writer.
    let frame = serde_json::json!({});
    let mut pipe = child.stdin.take().unwrap();
    writeln!(pipe, "{frame}").unwrap();
    pipe.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if status.is_none() {
        child.kill().unwrap();
    }
    drop(pipe);
    let output = child.wait_with_output().unwrap();
    assert!(
        status.is_some(),
        "complete frame must be processed without waiting for EOF"
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("child_config_invalid"));
}

#[test]
fn mandate_persists_every_bound_and_its_original_binding() {
    use super::la_auth::{MandateDraft, MandateGrant};
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-mandate-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("lane.sqlite");
    let draft = MandateDraft {
        tenant: "tenant_123456789".into(),
        project: "project_12345678".into(),
        actor: "actor_1234567890".into(),
        initiator: "person_123456789".into(),
        lineage: "lineage_12345678".into(),
        assignment: "assignment_12345".into(),
        job: "job_123456789012".into(),
        operation: "operation_123456".into(),
        input_digest: "a".repeat(64),
        profile: "cpu-artifact-inspect".into(),
        worker: "worker_123456789".into(),
        cpu_millicores: 1000,
        memory_bytes: 16 * 1024 * 1024,
        storage_bytes: 2 * 1024 * 1024,
        policy: "lab-proposal-v1".into(),
        accepted_at: 0,
        runtime_ms: 10_000,
        assignment_hard: 9000,
        project_ceiling: 8500,
        chain: vec![
            MandateGrant {
                id: "grant_root123456".into(),
                parent: None,
                run_until: 8000,
                execution_ceiling: 7500,
            },
            MandateGrant {
                id: "grant_leaf123456".into(),
                parent: Some("grant_root123456".into()),
                run_until: 3000,
                execution_ceiling: 7000,
            },
        ],
    };
    let mut store = super::la_store::ClaimStore::open(&path).unwrap();
    let saved = store
        .save_mandate(&draft)
        .expect("validated mandate persists");
    assert_eq!(saved.max_until, 3000);
    assert_eq!(saved.draft, draft);
    drop(store);
    let mut store = super::la_store::ClaimStore::open(&path).unwrap();
    assert_eq!(store.load_mandate(&draft.job).unwrap(), saved);
    assert_eq!(store.save_mandate(&draft).unwrap(), saved);
    let mut changed = draft.clone();
    changed.chain[1].run_until = 4000;
    assert!(store.save_mandate(&changed).is_err());
    assert_eq!(store.load_mandate(&draft.job).unwrap(), saved);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn permit_proposal_honors_all_inclusive_deadlines_and_close() {
    use super::la_auth::proposed_permit;
    assert_eq!(
        proposed_permit(2000, 2500, 3000, 10000, 2000, 1000, 6000, false).unwrap(),
        3000
    );
    assert_eq!(
        proposed_permit(2000, 2000, 3000, 10000, 2000, 1000, 6000, false),
        Err("deadline_elapsed")
    );
    assert_eq!(
        proposed_permit(3000, 4000, 3000, 10000, 2000, 1000, 6000, false),
        Err("deadline_elapsed")
    );
    assert_eq!(
        proposed_permit(2000, 2500, 3000, 10000, 2000, 1000, 1000, false),
        Err("deadline_elapsed")
    );
    assert_eq!(
        proposed_permit(2000, 2500, 3000, 10000, 2000, 1000, 6000, true),
        Err("deadline_elapsed")
    );
    assert_eq!(
        proposed_permit(2000, 2500, 3000, 10000, 2000, 2001, 6000, false),
        Err("deadline_elapsed")
    );
}

#[test]
fn worker_permit_expires_independently_and_cannot_be_resurrected() {
    use std::{
        sync::{atomic::Ordering, mpsc},
        time::{Duration, Instant},
    };
    let start = Instant::now();
    let deadline = start + Duration::from_millis(200);
    let timer =
        super::la_worker::PermitTimer::new(deadline, start + Duration::from_secs(1)).unwrap();
    let stopped = timer.stop_flag();
    assert!(!stopped.load(Ordering::SeqCst));
    let (sender, receiver) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        while !stopped.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        sender.send(Instant::now()).unwrap();
    });
    let observed = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("independent expiry must stop work");
    thread.join().unwrap();
    assert!(observed >= deadline - Duration::from_millis(50));
    assert!(observed <= deadline + Duration::from_millis(250));
    assert!(timer
        .renew(Instant::now() + Duration::from_millis(200))
        .is_err());
    assert!(timer.stop_flag().load(Ordering::SeqCst));
}

#[test]
fn inspection_observes_independent_permit_stop() {
    use std::{
        io::{self, Read},
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };
    struct SlowInput {
        remaining: usize,
    }
    impl Read for SlowInput {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            std::thread::sleep(Duration::from_millis(20));
            output[0] = b'x';
            self.remaining -= 1;
            Ok(1)
        }
    }
    let start = Instant::now();
    let timer = super::la_worker::PermitTimer::new(
        start + Duration::from_millis(100),
        start + Duration::from_secs(1),
    )
    .unwrap();
    let stopped = timer.stop_flag();
    let result = super::la_worker::inspect(
        &mut SlowInput { remaining: 100 },
        "job_123456789012",
        start + Duration::from_secs(1),
        || stopped.load(Ordering::SeqCst),
    );
    assert_eq!(result.unwrap_err(), "stopped");
    assert!(Instant::now() < start + Duration::from_millis(600));
}

#[test]
fn worker_permit_renewal_is_bounded_by_original_hard_deadline() {
    use std::{
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };
    let start = Instant::now();
    let hard = start + Duration::from_millis(450);
    let timer =
        super::la_worker::PermitTimer::new(start + Duration::from_millis(150), hard).unwrap();
    assert!(timer.renew(hard + Duration::from_millis(1)).is_err());
    timer.renew(start + Duration::from_millis(350)).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!timer.stop_flag().load(Ordering::SeqCst));
    std::thread::sleep(Duration::from_millis(200));
    assert!(timer.stop_flag().load(Ordering::SeqCst));
}

#[test]
fn child_config_rejects_wrong_executable_identity() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let frame = serde_json::json!({"protocol_version": 1, "run_nonce": "a".repeat(64),
        "role": "worker", "root": "/job/workerroot", "policy_id": "runtime-short-v1",
        "policy_digest": super::la_contract::policy_digest("runtime-short-v1").unwrap(), "expected_executable_sha256": "0".repeat(64),
        "authority_material": {}, "custody_manifest": {}, "barrier_id": null});
    writeln!(child.stdin.take().unwrap(), "{frame}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("child_config_invalid") || error.contains("child_config_timeout"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DIFFUSER_LA_CHILD_V1"));
}

#[test]
fn delegated_authentication_checks_chain_scopes_expiry_and_revocation() {
    use super::la_auth::{authenticate, AuthorityGrant};
    use sha2::{Digest, Sha256};
    let leaf_token = b"fixture-leaf-secret-value-at-least-32-bytes";
    let root = AuthorityGrant {
        id: "grant_root123456",
        parent: None,
        tenant: "tenant_123456789",
        project: "project_12345678",
        actor: "person_123456789",
        bearer_digest: Sha256::digest(b"root-synthetic-token-32-bytes-or-more").into(),
        scopes: 0b111,
        can_delegate: true,
        enabled: true,
        member: true,
        revoked: false,
        not_before: 0,
        access_expires: 9000,
        run_until: 8000,
        execution_ceiling: 8000,
        audience: "diffuser",
    };
    let leaf = AuthorityGrant {
        id: "grant_leaf123456",
        parent: Some(root.id),
        actor: "agent_1234567890",
        bearer_digest: Sha256::digest(leaf_token).into(),
        scopes: 0b011,
        can_delegate: false,
        access_expires: 3000,
        run_until: 7000,
        execution_ceiling: 7000,
        ..root.clone()
    };
    let grants = [root.clone(), leaf.clone()];
    let auth = authenticate(
        &grants,
        leaf_token,
        root.tenant,
        root.project,
        0b001,
        1000,
        900,
        500,
    )
    .expect("valid delegated authority");
    assert_eq!(auth.actor, leaf.actor);
    assert_eq!(auth.initiator, root.actor);
    assert_eq!(auth.lineage, vec![root.id, leaf.id]);
    assert!(authenticate(
        &grants,
        leaf_token,
        root.tenant,
        root.project,
        0b100,
        1000,
        900,
        500
    )
    .is_err());
    assert!(authenticate(
        &grants,
        leaf_token,
        root.tenant,
        root.project,
        0b001,
        3000,
        2900,
        500
    )
    .is_err());
    assert!(authenticate(
        &grants,
        leaf_token,
        root.tenant,
        root.project,
        0b001,
        1000,
        500,
        500
    )
    .is_err());
    assert!(authenticate(
        &grants,
        leaf_token,
        root.tenant,
        "project_other123",
        0b001,
        1000,
        900,
        500
    )
    .is_err());
    let mut revoked = grants.clone();
    revoked[0].revoked = true;
    assert!(authenticate(
        &revoked,
        leaf_token,
        root.tenant,
        root.project,
        0b001,
        1000,
        900,
        500
    )
    .is_err());
    let mut widened = grants.clone();
    widened[1].scopes = 0b1111;
    assert!(authenticate(
        &widened,
        leaf_token,
        root.tenant,
        root.project,
        0b001,
        1000,
        900,
        500
    )
    .is_err());
}

#[tokio::test]
async fn worker_inventory_requires_internal_authority_and_reports_not_ready() {
    use sha2::{Digest, Sha256};
    let secret = b"fixture-worker-bearer-value-over-32-bytes";
    let context = super::la_adapter::InventoryContext {
        bearer_digest: Sha256::digest(secret).into(),
        worker_id: "worker_123456789".into(),
        boot_id: "worker_boot_12345".into(),
        hardware_generation: 3,
        profile_epoch: 4,
    };
    let router = super::la_adapter::inventory_router(context);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/worker/inventory")
                .header(
                    "authorization",
                    format!("Bearer {}", std::str::from_utf8(secret).unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["worker_id"], "worker_123456789");
    assert_eq!(body["boot_id"], "worker_boot_12345");
    assert_eq!(body["hardware_generation"], 3);
    assert_eq!(body["profile_epoch"], 4);
    assert_eq!(body["ready"], false);
    for authorization in [None, Some("Bearer invalid"), Some("Basic invalid")] {
        let mut request = Request::builder().uri("/v1/worker/inventory");
        if let Some(header) = authorization {
            request = request.header("authorization", header);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = router
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/v1/worker/inventory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[test]
fn canonical_request_vectors_sort_keys_and_reject_nested_duplicates() {
    use super::la_contract::canonical_json;
    assert_eq!(
        canonical_json(r#" { "z": [3, {"b": true, "a": "é"}], "a": -2 } "#.as_bytes()).unwrap(),
        "{\"a\":-2,\"z\":[3,{\"a\":\"é\",\"b\":true}]}".as_bytes()
    );
    assert_eq!(
        canonical_json(br#"{"a":{"x":1,"x":2}}"#),
        Err("duplicate_member")
    );
    assert_eq!(canonical_json(br#"{"a":1.0}"#), Err("schema_invalid"));
    assert_eq!(canonical_json(br#"{} trailing"#), Err("schema_invalid"));
    assert_eq!(canonical_json(&vec![b' '; 65537]), Err("body_too_large"));
    let too_deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert_eq!(canonical_json(too_deep.as_bytes()), Err("schema_invalid"));
}

#[tokio::test]
async fn closed_renew_rejects_duplicate_members_at_nested_depth() {
    let state = Spine {
        root: std::env::temp_dir().join(format!("la-renew-nested-{}", std::process::id())),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let response = api(state.clone()).oneshot(Request::builder().method(Method::POST)
        .uri("/v1/diffuser/projects/project_12345678/assignments/assignment_12345678/renew")
        .header("content-type", "application/json").header("idempotency-key", "request_1234567890")
        .body(Body::from(r#"{"schema_version":"diffuser-lane/v1","expected_revision":{"x":1,"x":2},"requested_lease_ms":1}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"]["code"], "duplicate_member");
    assert!(!state.root.exists());
}

#[test]
fn child_config_rejects_nested_duplicate_before_executable_check() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let frame = format!("{{\"protocol_version\":1,\"run_nonce\":\"{}\",\"role\":\"claim_client\",\"root\":\"/tmp\",\"policy_id\":\"runtime-short-v1\",\"policy_digest\":\"{}\",\"expected_executable_sha256\":\"{}\",\"authority_material\":{{\"token\":\"x\",\"token\":\"y\"}},\"custody_manifest\":{{}},\"barrier_id\":\"barrier_1\"}}\n", "a".repeat(64), "b".repeat(64), "0".repeat(64));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(frame.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("child_config_invalid"));
}

#[test]
fn worker_stop_before_start_survives_restart_and_blocks_delayed_start() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-stop-tombstone-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let input = b"a delayed start must never run";
    let digest = hex::encode(Sha256::digest(input));
    let mut worker =
        super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
    worker
        .stop_before_start("operation_123456", "job_123456789012", &digest)
        .expect("stop tombstone");
    worker
        .stop_before_start("operation_123456", "job_123456789012", &digest)
        .unwrap();
    assert_eq!(worker.start_count("operation_123456").unwrap(), 0);
    drop(worker);
    assert!(
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 0)
            .is_err()
    );
    let mut worker =
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 1)
            .unwrap();
    assert_eq!(
        worker
            .inspect_once(
                "operation_123456",
                "job_123456789012",
                input,
                &digest,
                Instant::now() + Duration::from_secs(2),
                || false
            )
            .unwrap_err(),
        "stopped"
    );
    assert_eq!(worker.start_count("operation_123456").unwrap(), 0);
    assert!(worker
        .stop_before_start("operation_123456", "job_123456789012", &"b".repeat(64))
        .is_err());
    drop(worker);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn permitted_journal_hashes_actual_bytes_and_refuses_expired_new_work() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-permitted-work-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut journal = super::la_worker::OperationJournal::bootstrap(
        &root.join("worker.sqlite"),
        "custody_12345678",
    )
    .unwrap();
    let input = b"actual bounded permitted input";
    let digest = hex::encode(Sha256::digest(input));
    let now = Instant::now();
    let permit = super::la_worker::PermitTimer::new(
        now + Duration::from_secs(2),
        now + Duration::from_secs(3),
    )
    .unwrap();
    let report = journal
        .inspect_permitted(
            "operation_123456",
            "job_123456789012",
            input,
            &digest,
            now + Duration::from_secs(2),
            &permit,
        )
        .unwrap();
    let value: Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(value["sha256"], digest);
    assert_eq!(value["bytes"], input.len());
    assert_eq!(journal.start_count("operation_123456").unwrap(), 1);
    let now = Instant::now();
    let expired = super::la_worker::PermitTimer::new(
        now + Duration::from_millis(50),
        now + Duration::from_secs(1),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(
        journal
            .inspect_permitted(
                "operation_654321",
                "job_987654321098",
                input,
                &digest,
                now + Duration::from_secs(1),
                &expired
            )
            .unwrap_err(),
        "stopped"
    );
    assert_eq!(journal.start_count("operation_654321").unwrap(), 0);
    drop(journal);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(test)]
#[test]
fn release_before_worker_ack_holds_capacity_and_late_ack_cannot_revive() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-drain-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("lane.sqlite");
    let mut store = super::la_store::ClaimStore::open(&path).unwrap();
    store
        .reserve(
            "assignment_12345",
            "project_12345678",
            "actor_1234567890",
            "request_key_12345",
            &"a".repeat(64),
            "worker_123456789",
            7,
        )
        .unwrap();
    assert_eq!(
        store
            .drain(
                "assignment_12345",
                "project_12345678",
                "actor_1234567890",
                "released",
                10
            )
            .unwrap(),
        "released"
    );
    assert_eq!(store.state("assignment_12345").unwrap(), "draining");
    assert!(store
        .ack("assignment_12345", "worker_123456789", 7)
        .is_err());
    assert_eq!(
        store
            .drain(
                "assignment_12345",
                "project_12345678",
                "actor_1234567890",
                "revoked",
                11
            )
            .unwrap(),
        "released"
    );
    assert_eq!(store.counts().unwrap(), (1, 1, 1));
    assert_eq!(
        store
            .reserve(
                "assignment_67890",
                "project_12345678",
                "actor_1234567890",
                "request_key_67890",
                &"b".repeat(64),
                "worker_123456789",
                8
            )
            .unwrap_err(),
        "capacity_unavailable"
    );
    drop(store);
    let store = super::la_store::ClaimStore::open(&path).unwrap();
    assert_eq!(store.state("assignment_12345").unwrap(), "draining");
    assert_eq!(store.counts().unwrap(), (1, 1, 1));
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(test)]
#[test]
fn worker_ack_racing_release_never_resurrects_the_assignment() {
    use std::{
        sync::{Arc, Barrier},
        time::{SystemTime, UNIX_EPOCH},
    };
    let root = std::env::temp_dir().join(format!(
        "la-ack-drain-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("lane.sqlite");
    let mut seed = super::la_store::ClaimStore::open(&path).unwrap();
    seed.reserve(
        "assignment_12345",
        "project_12345678",
        "actor_1234567890",
        "request_key_12345",
        &"a".repeat(64),
        "worker_123456789",
        7,
    )
    .unwrap();
    drop(seed);
    let barrier = Arc::new(Barrier::new(2));
    let p = path.clone();
    let b = barrier.clone();
    let ack = std::thread::spawn(move || {
        let mut s = super::la_store::ClaimStore::open(&p).unwrap();
        b.wait();
        s.ack("assignment_12345", "worker_123456789", 7)
    });
    let p = path.clone();
    let b = barrier.clone();
    let close = std::thread::spawn(move || {
        let mut s = super::la_store::ClaimStore::open(&p).unwrap();
        b.wait();
        s.drain(
            "assignment_12345",
            "project_12345678",
            "actor_1234567890",
            "released",
            10,
        )
    });
    let ack = ack.join().unwrap();
    let close = close.join().unwrap();
    assert!(ack.is_ok() || ack == Err("state_conflict"));
    assert_eq!(close.unwrap(), "released");
    let s = super::la_store::ClaimStore::open(&path).unwrap();
    assert_eq!(s.state("assignment_12345").unwrap(), "draining");
    assert_eq!(s.counts().unwrap(), (1, 1, 1));
    drop(s);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn artifact_store_rejects_symlink_database_without_touching_its_target() {
    use std::{
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };
    let root = std::env::temp_dir().join(format!(
        "la-db-link-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let inside = root.join("inside");
    std::fs::create_dir(&inside).unwrap();
    let outside = root.join("outside.sqlite");
    let db = rusqlite::Connection::open(&outside).unwrap();
    db.execute_batch(
        "CREATE TABLE sentinel(value TEXT NOT NULL); INSERT INTO sentinel VALUES('untouched');",
    )
    .unwrap();
    drop(db);
    symlink(&outside, inside.join("lane_assignments.sqlite")).unwrap();
    assert!(super::la_artifacts::ArtifactStore::open(&inside).is_err());
    let db = rusqlite::Connection::open(&outside).unwrap();
    let v: String = db
        .query_row("SELECT value FROM sentinel", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "untouched");
    let created: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='la_artifacts')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!created);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn claim_store_rejects_a_symlinked_database_target() {
    use std::{
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };
    let root = std::env::temp_dir().join(format!(
        "la-claim-link-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let outside = root.join("outside.sqlite");
    let link = root.join("lane.sqlite");
    let db = rusqlite::Connection::open(&outside).unwrap();
    db.execute_batch(
        "CREATE TABLE sentinel(value TEXT NOT NULL); INSERT INTO sentinel VALUES('untouched');",
    )
    .unwrap();
    drop(db);
    symlink(&outside, &link).unwrap();
    assert!(super::la_store::ClaimStore::open(&link).is_err());
    let db = rusqlite::Connection::open(&outside).unwrap();
    let created: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='la_assignments')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!created);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn artifact_reopen_fails_closed_on_unreconciled_staged_bytes() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-orphan-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    drop(store);
    let staged = root.join("artifacts").join("artifact_12345678");
    std::fs::write(&staged, b"ambiguous retained bytes").unwrap();
    assert!(super::la_artifacts::ArtifactStore::open(&root).is_err());
    assert_eq!(std::fs::read(&staged).unwrap(), b"ambiguous retained bytes");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn artifact_storage_error_blocks_further_publication_until_reconciliation() {
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-orphan-live-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    let staged = root.join("artifacts").join("artifact_12345678");
    std::fs::write(&staged, b"retained ambiguous bytes").unwrap();
    let bytes = b"new input";
    let digest = hex::encode(Sha256::digest(bytes));
    assert!(store
        .put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_12345678",
            bytes,
            &digest,
            1,
            100
        )
        .is_err());
    assert!(store
        .put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_87654321",
            bytes,
            &digest,
            1,
            100
        )
        .is_err());
    assert_eq!(std::fs::read(&staged).unwrap(), b"retained ambiguous bytes");
    assert!(!root.join("artifacts").join("artifact_87654321").exists());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn artifact_directory_replacement_cannot_redirect_publication() {
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };
    let root = std::env::temp_dir().join(format!(
        "la-dir-swap-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let inside = root.join("inside");
    let outside = root.join("outside");
    std::fs::create_dir(&inside).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let mut store = super::la_artifacts::ArtifactStore::open(&inside).unwrap();
    std::fs::rename(inside.join("artifacts"), inside.join("original-artifacts")).unwrap();
    symlink(&outside, inside.join("artifacts")).unwrap();
    let bytes = b"must stay in owned root";
    let digest = hex::encode(Sha256::digest(bytes));
    assert!(store
        .put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_12345678",
            bytes,
            &digest,
            1,
            100
        )
        .is_err());
    assert!(!outside.join("artifact_12345678").exists());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn artifact_root_rejects_symlinked_ancestor_before_initialization() {
    use std::{
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };
    let root = std::env::temp_dir().join(format!(
        "la-parent-link-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let real = root.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::create_dir(real.join("inside")).unwrap();
    let link = root.join("link");
    symlink(&real, &link).unwrap();
    assert!(super::la_artifacts::ArtifactStore::open(&link.join("inside")).is_err());
    assert!(!real.join("inside/artifacts").exists());
    assert!(!real.join("inside/lane_assignments.sqlite").exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_job_local_stop_interrupts_only_its_own_permit() {
    use std::{
        io::{self, Read},
        sync::{mpsc, Arc},
        time::{Duration, Instant},
    };
    struct Slow;
    impl Read for Slow {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(Duration::from_millis(20));
            out[0] = b'x';
            Ok(1)
        }
    }
    let now = Instant::now();
    let first = Arc::new(
        super::la_worker::PermitTimer::new(
            now + Duration::from_secs(2),
            now + Duration::from_secs(3),
        )
        .unwrap(),
    );
    let other = super::la_worker::PermitTimer::new(
        now + Duration::from_secs(2),
        now + Duration::from_secs(3),
    )
    .unwrap();
    let running = first.clone();
    let (tx, rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        tx.send(()).unwrap();
        super::la_worker::inspect(
            &mut Slow,
            "job_123456789012",
            now + Duration::from_secs(2),
            || running.is_stopped(),
        )
    });
    rx.recv_timeout(Duration::from_secs(1)).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let stopped_at = Instant::now();
    first.stop().expect("job-local stop");
    assert_eq!(thread.join().unwrap().unwrap_err(), "stopped");
    assert!(Instant::now() - stopped_at <= Duration::from_millis(250));
    assert!(!other.is_stopped());
    assert!(first
        .renew(Instant::now() + Duration::from_secs(1))
        .is_err());
}

#[test]
fn child_config_requires_the_barrier_field() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let frame = serde_json::json!({"protocol_version":1,"run_nonce":"a".repeat(64),"role":"claim_client","root":"/tmp","policy_id":"runtime-short-v1","policy_digest":"b".repeat(64),"expected_executable_sha256":"0".repeat(64),"authority_material":{},"custody_manifest":{}});
    writeln!(child.stdin.take().unwrap(), "{frame}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("child_config_invalid"));
}

#[test]
fn pending_permit_never_raises_acknowledged_deadline_or_revives_after_close() {
    use super::la_auth::{MandateDraft, MandateGrant};
    use std::time::{SystemTime, UNIX_EPOCH};
    let root = std::env::temp_dir().join(format!(
        "la-permit-ledger-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let draft = MandateDraft {
        tenant: "tenant_123456789".into(),
        project: "project_12345678".into(),
        actor: "actor_1234567890".into(),
        initiator: "person_123456789".into(),
        lineage: "lineage_12345678".into(),
        assignment: "assignment_12345".into(),
        job: "job_123456789012".into(),
        operation: "operation_123456".into(),
        input_digest: "a".repeat(64),
        profile: "cpu-artifact-inspect".into(),
        worker: "worker_123456789".into(),
        cpu_millicores: 1000,
        memory_bytes: 16777216,
        storage_bytes: 2097152,
        policy: "lab-proposal-v1".into(),
        accepted_at: 0,
        runtime_ms: 10000,
        assignment_hard: 10000,
        project_ceiling: 10000,
        chain: vec![
            MandateGrant {
                id: "grant_root123456".into(),
                parent: None,
                run_until: 8000,
                execution_ceiling: 8000,
            },
            MandateGrant {
                id: "grant_leaf123456".into(),
                parent: Some("grant_root123456".into()),
                run_until: 3000,
                execution_ceiling: 7000,
            },
        ],
    };
    let path = root.join("lane.sqlite");
    let mut store = super::la_store::ClaimStore::open(&path).unwrap();
    store.save_mandate(&draft).unwrap();
    store.begin_permit(&draft.job, 2500, 10000).unwrap();
    assert_eq!(
        store
            .propose_permit(&draft.job, 2000, 10000, 2000, 1000, 6000)
            .unwrap(),
        3000
    );
    let pending = store.permit_view(&draft.job).unwrap();
    assert_eq!(pending.acknowledged_until, 2500);
    assert_eq!(pending.pending_until, Some(3000));
    assert_eq!(pending.revision, 0);
    assert!(store.acknowledge_permit(&draft.job, 1, 2999, 2100).is_err());
    assert_eq!(store.permit_view(&draft.job).unwrap(), pending);
    store.acknowledge_permit(&draft.job, 1, 3000, 2100).unwrap();
    let ack = store.permit_view(&draft.job).unwrap();
    assert_eq!(ack.acknowledged_until, 3000);
    assert_eq!(ack.pending_until, None);
    assert_eq!(ack.revision, 1);
    store.close_permit(&draft.job).unwrap();
    assert!(store.acknowledge_permit(&draft.job, 1, 3000, 2200).is_err());
    let mut second = draft.clone();
    second.job = "job_987654321098".into();
    second.operation = "operation_654321".into();
    store.save_mandate(&second).unwrap();
    store.begin_permit(&second.job, 2500, 10000).unwrap();
    assert!(store
        .propose_permit(&second.job, 2500, 10000, 2000, 1000, 6000)
        .is_err());
    assert!(store.permit_view(&second.job).unwrap().closed);
    assert!(store
        .propose_permit(&second.job, 2000, 10000, 2000, 1000, 6000)
        .is_err());
    let mut third = draft.clone();
    third.job = "job_333333333333".into();
    third.operation = "operation_333333".into();
    store.save_mandate(&third).unwrap();
    store.begin_permit(&third.job, 2500, 10000).unwrap();
    assert_eq!(
        store
            .propose_permit(&third.job, 2000, 10000, 2000, 1000, 6000)
            .unwrap(),
        3000
    );
    assert!(store
        .propose_permit(&third.job, 2500, 10000, 2000, 1000, 6000)
        .is_err());
    let expired = store.permit_view(&third.job).unwrap();
    assert!(expired.closed);
    assert!(expired.pending_until.is_none());
    assert!(store.acknowledge_permit(&third.job, 1, 3000, 2501).is_err());
    drop(store);
    let store = super::la_store::ClaimStore::open(&path).unwrap();
    let closed = store.permit_view(&draft.job).unwrap();
    assert!(closed.closed);
    assert_eq!(closed.acknowledged_until, 3000);
    assert!(closed.pending_until.is_none());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn child_rejects_unsealed_policy_before_activation() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let exe = std::env::current_exe().unwrap();
    let digest =
        child_executable_digest(std::time::Instant::now() + std::time::Duration::from_secs(5))
            .unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let frame = serde_json::json!({
        "protocol_version": 1, "run_nonce": "a".repeat(64), "role": "worker",
        "root": "/job/workerroot", "policy_id": "runtime-short-v1",
        "policy_digest": "b".repeat(64), "expected_executable_sha256": digest,
        "authority_material": {}, "custody_manifest": {}, "barrier_id": null
    });
    writeln!(child.stdin.as_mut().unwrap(), "{frame}").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("child_config_invalid"),
        "unsealed policy must be rejected before activation: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("DIFFUSER_LA_CHILD_V1"));
}

#[test]
fn startup_timing_policy_snapshots_match_design_values() {
    use super::la_contract::policy_digest;
    // These independently derived vectors cover the C4/C11/C14 timing values
    // and canonical key ordering, rather than accepting a digest from config.
    assert_eq!(
        policy_digest("lab-proposal-v1").as_deref(),
        Some("433a4273fac975df880dfad972b511e1c909fe1108ecaaaf160ca2889630631e")
    );
    assert_eq!(
        policy_digest("runtime-short-v1").as_deref(),
        Some("8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e")
    );
    assert_eq!(policy_digest("unknown"), None);
}

#[test]
fn child_refuses_worker_root_incompatible_with_role() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let exe = std::env::current_exe().unwrap();
    let digest =
        child_executable_digest(std::time::Instant::now() + std::time::Duration::from_secs(5))
            .unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let frame = serde_json::json!({
        "protocol_version": 1, "run_nonce": "a".repeat(64), "role": "worker", "root": "/tmp",
        "policy_id": "runtime-short-v1", "policy_digest": super::la_contract::policy_digest("runtime-short-v1").unwrap(),
        "expected_executable_sha256": digest, "authority_material": {}, "custody_manifest": {}, "barrier_id": null
    });
    writeln!(child.stdin.as_mut().unwrap(), "{frame}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("child_config_invalid"),
        "role-incompatible root must be rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DIFFUSER_LA_CHILD_V1"));
}

#[test]
fn child_refuses_missing_worker_root_before_activation() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    assert!(!std::path::Path::new("/job/workerroot").exists());
    let exe = std::env::current_exe().unwrap();
    let digest =
        child_executable_digest(std::time::Instant::now() + std::time::Duration::from_secs(5))
            .unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let frame = serde_json::json!({
        "protocol_version": 1, "run_nonce": "a".repeat(64), "role": "worker", "root": "/job/workerroot",
        "policy_id": "runtime-short-v1", "policy_digest": super::la_contract::policy_digest("runtime-short-v1").unwrap(),
        "expected_executable_sha256": digest,
        "authority_material": {"service_bearer":"1".repeat(64),"worker_id":"worker_cpu_000001","boot_id":"2".repeat(64),"hardware_generation":1,"profile_epoch":1},
        "custody_manifest": {"mode":"bootstrap","worker_id":"worker_cpu_000001","store_id":"3".repeat(64),"root_dev":1,"root_inode":1,"expected_starts":0,"expected_records":0}, "barrier_id": null
    });
    let mut writer = child.stdin.take().unwrap();
    writeln!(writer, "{frame}").unwrap();
    writer.flush().unwrap();
    let output = child.wait_with_output().unwrap();
    drop(writer);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("startup_root_invalid"),
        "missing root must be rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DIFFUSER_LA_CHILD_V1"));
}

#[test]
fn child_self_identity_hash_finishes_within_startup_bound() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant};
    let exe = std::env::current_exe().unwrap();
    let expected = hex::encode(Sha256::digest(std::fs::read(exe).unwrap()));
    let observed = child_executable_digest(Instant::now() + Duration::from_secs(5));
    assert_eq!(observed.as_deref(), Ok(expected.as_str()));
}

struct FixtureReap(std::process::Child);
impl Drop for FixtureReap {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn fixture_collect(
    child: &mut FixtureReap,
    timeout: std::time::Duration,
) -> std::result::Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), &'static str> {
    use std::{io::Read, os::fd::AsRawFd};
    let mut stdout = child.0.stdout.take().ok_or("missing_stdout")?;
    let mut stderr = child.0.stderr.take().ok_or("missing_stderr")?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            return Err("pipe_error");
        }
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut ended = [false; 2];
    let until = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() >= until {
            return Err("output_timeout");
        }
        for (i, (stream, output)) in [
            (&mut stdout as &mut dyn Read, &mut out),
            (&mut stderr as &mut dyn Read, &mut err),
        ]
        .into_iter()
        .enumerate()
        {
            if ended[i] {
                continue;
            }
            let mut chunk = [0; 8192];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => {
                        ended[i] = true;
                        break;
                    }
                    Ok(n) => {
                        if output.len() + n > 1_048_576 {
                            return Err("output_cap");
                        }
                        output.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err("pipe_error"),
                }
            }
        }
        let status = child.0.try_wait().map_err(|_| "wait_error")?;
        if ended.iter().all(|v| *v) {
            if let Some(status) = status {
                return Ok((status, out, err));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

struct FixtureOutput {
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    out: Vec<u8>,
    err: Vec<u8>,
    ended: [bool; 2],
    scanned: usize,
}
impl FixtureOutput {
    fn take(child: &mut FixtureReap) -> std::result::Result<Self, &'static str> {
        use std::os::fd::AsRawFd;
        let stdout = child.0.stdout.take().ok_or("missing_stdout")?;
        let stderr = child.0.stderr.take().ok_or("missing_stderr")?;
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0
            {
                return Err("pipe_error");
            }
        }
        Ok(Self {
            stdout,
            stderr,
            out: Vec::new(),
            err: Vec::new(),
            ended: [false; 2],
            scanned: 0,
        })
    }
    fn pump(&mut self) -> std::result::Result<(), &'static str> {
        use std::io::Read;
        for (i, (stream, output)) in [
            (&mut self.stdout as &mut dyn Read, &mut self.out),
            (&mut self.stderr as &mut dyn Read, &mut self.err),
        ]
        .into_iter()
        .enumerate()
        {
            if self.ended[i] {
                continue;
            }
            let mut chunk = [0; 8192];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => {
                        self.ended[i] = true;
                        break;
                    }
                    Ok(n) => {
                        if output.len() + n > 1_048_576 {
                            return Err("output_cap");
                        }
                        output.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err("pipe_error"),
                }
            }
        }
        Ok(())
    }
    fn next_frame(
        &mut self,
        child: &mut FixtureReap,
        timeout: std::time::Duration,
    ) -> std::result::Result<serde_json::Value, &'static str> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            self.pump()?;
            while let Some(relative) = self.out[self.scanned..].iter().position(|v| *v == b'\n') {
                let end = self.scanned + relative;
                let line = &self.out[self.scanned..end];
                self.scanned = end + 1;
                if let Some(frame) = line.strip_prefix(b"DIFFUSER_LA_CHILD_V1 ") {
                    let normalized =
                        super::la_contract::canonical_json(frame).map_err(|_| "frame_invalid")?;
                    return serde_json::from_slice(&normalized).map_err(|_| "frame_invalid");
                }
            }
            if child.0.try_wait().map_err(|_| "wait_error")?.is_some() {
                return Err("child_exited");
            }
            if std::time::Instant::now() >= deadline {
                return Err("readiness_timeout");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    fn finish(
        &mut self,
        child: &mut FixtureReap,
        timeout: std::time::Duration,
    ) -> std::result::Result<std::process::ExitStatus, &'static str> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            self.pump()?;
            let status = child.0.try_wait().map_err(|_| "wait_error")?;
            if self.ended.iter().all(|v| *v) {
                if let Some(status) = status {
                    return Ok(status);
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err("output_timeout");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

fn fixture_selector_count(listing: &str) -> usize {
    listing
        .lines()
        .filter(|line| *line == "cosp::la_tests::la_exec_child: test")
        .count()
}

// This is a non-authorizing P protocol step. It does not qualify resources or
// accept readiness; the real C/W fixture must additionally satisfy Q1–Q9.
#[cfg(test)]
#[test]
fn la_exec_parent_custodies_child_pipe_before_non_authorizing_config() {
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let exe = std::env::current_exe().unwrap();
    let mut listing = FixtureReap(
        Command::new(&exe)
            .args(["--list", "--format", "terse"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let (status, output, _) = fixture_collect(&mut listing, Duration::from_secs(5)).unwrap();
    assert!(status.success());
    let exact = "cosp::la_tests::la_exec_child: test";
    let listing = String::from_utf8(output).unwrap();
    assert_eq!(fixture_selector_count(&listing), 1);
    assert_eq!(fixture_selector_count("not_the_child: test\n"), 0);
    assert_eq!(fixture_selector_count(&format!("{exact}\n{exact}\n")), 2);
    let hash = child_executable_digest(Instant::now() + Duration::from_secs(5)).unwrap();
    let mut nonce = [0u8; 32];
    assert_eq!(
        unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) },
        nonce.len() as isize
    );
    let nonce = hex::encode(nonce);
    let mut child = FixtureReap(
        Command::new(&exe)
            .args([
                "--exact",
                "cosp::la_tests::la_exec_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("DIFFUSER_LA_TEST_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut output = FixtureOutput::take(&mut child).unwrap();
    let pid = child.0.id();
    let proc = format!("/proc/{pid}");
    // The loader may briefly open its own descriptors. Before issuing any
    // control frame, wait within a fixed bound for the exact required FD set.
    let ready_by = Instant::now() + Duration::from_secs(2);
    loop {
        output.pump().unwrap();
        let mut current = std::fs::read_dir(format!("{proc}/fd"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        current.sort();
        if output
            .out
            .windows(b"running 1 test".len())
            .any(|value| value == b"running 1 test")
            && current == ["0", "1", "2"].map(std::ffi::OsString::from)
        {
            break;
        }
        assert!(
            Instant::now() < ready_by && child.0.try_wait().unwrap().is_none(),
            "child descriptor set did not settle before configuration"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let own = std::fs::metadata("/proc/self/exe").unwrap();
    let actual = std::fs::metadata(format!("{proc}/exe")).unwrap();
    assert_eq!((own.dev(), own.ino()), (actual.dev(), actual.ino()));
    let stat = std::fs::read_to_string(format!("{proc}/stat")).unwrap();
    let starttime = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_owned();
    let executable_arg = exe.to_string_lossy();
    let expected_args = [
        executable_arg.as_bytes(),
        b"--exact",
        b"cosp::la_tests::la_exec_child",
        b"--nocapture",
        b"--test-threads=1",
    ];
    let cmd = std::fs::read(format!("{proc}/cmdline")).unwrap();
    assert_eq!(
        cmd.split(|b| *b == 0)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>(),
        expected_args
    );
    let writer = child.0.stdin.as_mut().unwrap();
    let writer_fd = writer.as_raw_fd();
    let target = std::fs::read_link(format!("/proc/self/fd/{writer_fd}")).unwrap();
    assert!(target.to_string_lossy().starts_with("pipe:["));
    assert_eq!(target, std::fs::read_link(format!("{proc}/fd/0")).unwrap());
    let fd_flags = unsafe { libc::fcntl(writer_fd, libc::F_GETFD) };
    assert!(fd_flags >= 0 && fd_flags & libc::FD_CLOEXEC != 0);
    let parent_copies = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| std::fs::read_link(entry.path()).ok().as_ref() == Some(&target))
        .count();
    assert_eq!(parent_copies, 1);
    let mut fds = std::fs::read_dir(format!("{proc}/fd"))
        .unwrap()
        .map(|v| v.unwrap().file_name())
        .collect::<Vec<_>>();
    fds.sort();
    assert_eq!(fds, ["0", "1", "2"].map(std::ffi::OsString::from));
    let frame = serde_json::json!({"protocol_version":1,"run_nonce":nonce,"role":"worker","root":"/job/workerroot", "policy_id":"runtime-short-v1", "policy_digest":"b".repeat(64), "expected_executable_sha256":hash, "authority_material":{},"custody_manifest":{},"barrier_id":null});
    writeln!(writer, "{frame}").unwrap();
    writer.flush().unwrap();
    // Keep the sole writer open while bounded collection waits for the child.
    let status = output.finish(&mut child, Duration::from_secs(5)).unwrap();
    let out = output.out;
    let err = output.err;
    let evidence = std::env::temp_dir().join(format!("la-parent-{nonce}"));
    std::fs::create_dir(&evidence).unwrap();
    std::fs::write(evidence.join("child-stdout.log"), &out).unwrap();
    std::fs::write(evidence.join("child-stderr.log"), &err).unwrap();
    std::fs::write(evidence.join("launch.json"), serde_json::to_vec(&serde_json::json!({"pid":pid,"starttime":starttime,"executable_sha256":hash,"selector":exact,"nonce":nonce,"child_status":status.code()})).unwrap()).unwrap();
    assert!(!status.success());
    assert!(String::from_utf8_lossy(&out).contains("running 1 test"));
    assert!(!String::from_utf8_lossy(&out).contains("DIFFUSER_LA_CHILD_V1"));
    assert!(String::from_utf8_lossy(&err).contains("child_config_invalid"));
}

fn fixture_systemctl(
    args: &[&str],
) -> std::result::Result<(std::process::ExitStatus, String), &'static str> {
    use std::process::{Command, Stdio};
    let mut command = Command::new("/usr/bin/systemctl");
    command
        .args(["--user"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("XDG_RUNTIME_DIR", "/run/user/1000")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = FixtureReap(command.spawn().map_err(|_| "manager_unavailable")?);
    let (status, out, _) = fixture_collect(&mut process, std::time::Duration::from_secs(4))?;
    Ok((
        status,
        String::from_utf8(out).map_err(|_| "manager_invalid")?,
    ))
}

fn fixture_cgroup(unit: &str) -> std::result::Result<std::path::PathBuf, &'static str> {
    let (status, out) = fixture_systemctl(&["show", unit, "--property=ControlGroup", "--value"])?;
    let value = out.trim();
    if !status.success()
        || !value.starts_with("/user.slice/user-1000.slice/user@1000.service/")
        || !value.ends_with(&format!("/{unit}"))
    {
        return Err("cgroup_invalid");
    }
    Ok(std::path::Path::new("/sys/fs/cgroup").join(value.trim_start_matches('/')))
}

fn fixture_scope_command(unit: &str, cpu: &str, memory: &str, pids: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new("/usr/bin/systemd-run");
    cmd.args([
        "--user",
        "--scope",
        "--slice=app.slice",
        "--quiet",
        &format!("--unit={unit}"),
    ])
    .args([
        "--property=CPUAccounting=yes",
        "--property=CPUQuotaPeriodSec=100ms",
        "--property=MemoryAccounting=yes",
        "--property=MemorySwapMax=0",
        "--property=TasksAccounting=yes",
        "--property=Delegate=no",
        "--property=TimeoutStopSec=2s",
        "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes",
        "--property=OOMPolicy=stop",
        "--property=RuntimeMaxSec=60s",
    ])
    .arg(format!("--property=CPUQuota={cpu}"))
    .arg(format!("--property=MemoryMax={memory}"))
    .arg(format!("--property=TasksMax={pids}"))
    .arg("--")
    .env_clear()
    .env("PATH", "/usr/bin:/bin")
    .env("LANG", "C")
    .env("XDG_RUNTIME_DIR", "/run/user/1000")
    .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus");
    cmd
}

// The helper transfers a connected loopback socket only. P itself writes the
// authenticated HTTP request and validates the response; no bearer crosses argv.
fn fixture_connect(
    keeper_pid: u32,
    port: u16,
    deadline: std::time::Instant,
) -> std::result::Result<std::net::TcpStream, String> {
    use std::{
        io::Read,
        os::fd::{FromRawFd, OwnedFd},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut pair = [0; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err("socketpair_failed".into());
    }
    let recv = unsafe { std::fs::File::from_raw_fd(pair[0]) };
    let send = unsafe { std::fs::File::from_raw_fd(pair[1]) };
    let helper="/tmp/diffuser-fixture/runtime/turn-003-p-fixture/connect.py";
    let mut child = FixtureReap(
        Command::new("/usr/bin/nsenter")
            .args([
                "--target",
                &keeper_pid.to_string(),
                "--user",
                "--preserve-credentials",
                "--net",
                "--",
                "/usr/bin/python3",
                "-I",
                "-B",
                helper,
                &port.to_string(),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::from(send))
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "helper_spawn_failed")?,
    );
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("startup_timeout".into());
    }
    let received = fixture_receive_root(&recv, remaining.as_millis().clamp(1, 1_000) as i32);
    let until = deadline.min(Instant::now() + Duration::from_secs(2));
    while child
        .0
        .try_wait()
        .map_err(|_| "helper_wait_failed")?
        .is_none()
    {
        if Instant::now() >= until {
            return Err("helper_timeout".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut stderr = Vec::new();
    if let Some(err) = child.0.stderr.take() {
        err.take(65_537)
            .read_to_end(&mut stderr)
            .map_err(|_| "helper_stderr_failed")?;
    }
    if stderr.len() > 65_536 {
        return Err("helper_output_cap".into());
    }
    let (file, message) =
        received.map_err(|reason| format!("{reason}: {}", String::from_utf8_lossy(&stderr)))?;
    if message["kind"] != "SOCKET_READY" || message["port"].as_u64() != Some(port as u64) {
        return Err("helper_message_invalid".into());
    }
    let owned: OwnedFd = file.into();
    let stream = std::net::TcpStream::from(owned);
    stream
        .set_nonblocking(false)
        .map_err(|_| "socket_mode_failed")?;
    if stream.peer_addr().map_err(|_| "peer_invalid")?
        != std::net::SocketAddr::from(([127, 0, 0, 1], port))
    {
        return Err("peer_mismatch".into());
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("startup_timeout".into());
    }
    stream
        .set_read_timeout(Some(remaining.min(Duration::from_secs(3))))
        .map_err(|_| "timeout_failed")?;
    stream
        .set_write_timeout(Some(remaining.min(Duration::from_secs(1))))
        .map_err(|_| "timeout_failed")?;
    Ok(stream)
}

fn fixture_worker_http(
    keeper_pid: u32,
    port: u16,
    path: &str,
    bearer: &str,
    deadline: std::time::Instant,
) -> std::result::Result<(u16, Vec<u8>), String> {
    use std::io::{Read, Write};
    if !matches!(path, "/v1/worker/inventory" | "/v1/diffuser/discovery") {
        return Err("http_path_invalid".into());
    }
    let mut http = fixture_connect(keeper_pid, port, deadline)?;
    write!(http,"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n").map_err(|_|"http_write_failed")?;
    let mut response = Vec::new();
    http.take(65_537)
        .read_to_end(&mut response)
        .map_err(|_| "http_read_failed")?;
    if response.len() > 65_536 || std::time::Instant::now() >= deadline {
        return Err("http_bound_failed".into());
    }
    let split = response
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or("http_header_invalid")?;
    let header = std::str::from_utf8(&response[..split]).map_err(|_| "http_header_invalid")?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or("http_status_invalid")?;
    let mut length = None;
    for line in lines {
        let (key, value) = line.split_once(':').ok_or("http_header_invalid")?;
        if key.eq_ignore_ascii_case("transfer-encoding") {
            return Err("http_transfer_invalid".into());
        }
        if key.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("http_header_invalid".into());
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "http_header_invalid")?,
            );
        }
    }
    if length != Some(response.len() - split - 4) {
        return Err("http_length_invalid".into());
    }
    Ok((status, response))
}

fn fixture_limits(group: &std::path::Path, expected: [(&str, &str); 4]) -> bool {
    expected.into_iter().all(|(key, value)| {
        std::fs::read_to_string(group.join(key)).is_ok_and(|v| v.trim() == value)
    })
}

fn fixture_receive_root(
    socket: &std::fs::File,
    timeout_ms: i32,
) -> std::result::Result<(std::fs::File, serde_json::Value), &'static str> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut poll = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, timeout_ms) } != 1 {
        return Err("keeper_timeout");
    }
    let mut bytes = [0u8; 16_384];
    let mut ancillary = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&ancillary);
    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if n <= 0 || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err("keeper_message_invalid");
    }
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if cmsg.is_null() {
        return Err("keeper_fd_missing");
    }
    let valid = unsafe {
        (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
            && (*cmsg).cmsg_len
                == libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize
            && libc::CMSG_NXTHDR(&message, cmsg).is_null()
    };
    if !valid {
        return Err("keeper_fd_invalid");
    }
    let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>()) };
    if fd < 0 {
        return Err("keeper_fd_invalid");
    }
    let root = unsafe { std::fs::File::from_raw_fd(fd) };
    let body =
        serde_json::from_slice(&bytes[..n as usize]).map_err(|_| "keeper_message_invalid")?;
    Ok((root, body))
}

// Runtime plumbing only: the scoped controller can exercise synthetic artifact
// HTTP, but no job is admitted. P lacks its writable view and cannot qualify Q4/R.
#[test]
fn la_exec_parent_checks_scoped_child_and_independent_finite_root() {
    run_scoped_controller_fixture(ControllerEnding::Stop);
}

#[test]
fn controller_rejects_duplicate_config_after_ready_and_stops() {
    run_scoped_controller_fixture(ControllerEnding::Duplicate);
}

#[test]
fn controller_kill_retains_committed_input_and_worker_remains_available() {
    run_scoped_controller_fixture(ControllerEnding::Kill);
}

#[test]
fn controller_kill_during_upload_does_not_publish_partial_input() {
    run_scoped_controller_fixture(ControllerEnding::KillDuringUpload);
}

#[test]
fn controller_kill_waiting_for_transaction_leaves_no_partial_publication() {
    run_scoped_controller_fixture(ControllerEnding::KillDuringTransaction);
}

#[test]
fn worker_kill_retains_empty_journal_and_keeper_root() {
    run_scoped_controller_fixture(ControllerEnding::KillWorker);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ControllerEnding {
    Stop,
    Duplicate,
    Kill,
    KillDuringUpload,
    KillDuringTransaction,
    KillWorker,
}

#[cfg(test)]
fn run_scoped_controller_fixture(ending: ControllerEnding) {
    use std::{
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{FileTypeExt, MetadataExt},
        },
        process::Stdio,
        time::{Duration, Instant},
    };
    struct Units(Vec<String>);
    impl Drop for Units {
        fn drop(&mut self) {
            for unit in self.0.iter().rev() {
                let _ = fixture_systemctl(&["kill", "--kill-whom=all", "--signal=SIGKILL", unit]);
                let _ = fixture_systemctl(&["stop", unit]);
                let _ = fixture_systemctl(&["reset-failed", unit]);
            }
        }
    }
    let exe = std::env::current_exe().unwrap();
    let mut list = FixtureReap(
        std::process::Command::new(&exe)
            .args(["--list", "--format", "terse"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let (status, listing, _) = fixture_collect(&mut list, Duration::from_secs(5)).unwrap();
    assert!(status.success());
    assert_eq!(
        fixture_selector_count(std::str::from_utf8(&listing).unwrap()),
        1
    );
    let executable_hash = child_executable_digest(Instant::now() + Duration::from_secs(5)).unwrap();
    let mut random = [0u8; 8];
    assert_eq!(
        unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) },
        random.len() as isize
    );
    let run = hex::encode(random);
    // Record the supervisor's own mount view before starting any child. This
    // check is only one part of Q4; it cannot qualify descriptors or budgets.
    let p_mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let p_mounts_bounded = fixture_p_mounts_bounded(&p_mountinfo);
    let p_cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let p_path = p_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap();
    let p_scoped = p_path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.starts_with("diffuser-r5s1-p-") && name.ends_with(".scope"));
    if p_scoped {
        let group = std::path::Path::new("/sys/fs/cgroup").join(p_path.trim_start_matches('/'));
        assert!(fixture_limits(
            &group,
            [
                ("cpu.max", "100000 100000"),
                ("memory.max", "268435456"),
                ("memory.swap.max", "0"),
                ("pids.max", "64")
            ]
        ));
    }
    let keeper_unit = format!("diffuser-r5s1-keeper-{run}.scope");
    let worker_unit = format!("diffuser-r5s1-w-{run}.scope");
    for unit in [&keeper_unit, &worker_unit] {
        let (status, state) =
            fixture_systemctl(&["show", unit, "--property=LoadState", "--value"]).unwrap();
        assert!(
            status.success() && state.trim() == "not-found",
            "unit collision"
        );
    }
    let mut units = Units(Vec::new());
    let mut pair = [0; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        },
        0
    );
    let recv = unsafe { std::fs::File::from_raw_fd(pair[0]) };
    let send = unsafe { std::fs::File::from_raw_fd(pair[1]) };
    let fixture = "/tmp/diffuser-fixture/runtime/turn-003-p-fixture";
    let mut command = fixture_scope_command(&keeper_unit, "25%", "134217728", "16");
    command
        .args([
            "/usr/bin/bwrap",
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "HOME",
            "/job/workerroot",
            "--setenv",
            "TMPDIR",
            "/job/workerroot",
            "--setenv",
            "LANG",
            "C",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
            fixture,
            "/stage",
            "--ro-bind",
        ])
        .arg(&exe)
        .arg("/worker-test")
        .args([
            "--proc",
            "/proc",
            "--dir",
            "/tmp",
            "--dir",
            "/dev",
            "--dev-bind",
            "/dev/null",
            "/dev/null",
            "--perms",
            "0700",
            "--size",
            "67108864",
            "--tmpfs",
            "/job/workerroot",
            "--perms",
            "0700",
            "--size",
            "67108864",
            "--tmpfs",
            "/job/service",
            "--chdir",
            "/job/workerroot",
            "--remount-ro",
            "/",
            "--",
            "/usr/bin/python3",
            "-I",
            "-B",
            "/stage/keeper.py",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(send))
        .stderr(Stdio::piped());
    let mut keeper = FixtureReap(command.spawn().unwrap());
    units.0.push(keeper_unit.clone());
    let (root, ready) = fixture_receive_root(&recv, 8_000).unwrap();
    let (service_root, service_ready) = fixture_receive_root(&recv, 8_000).unwrap();
    let service_meta = service_root.metadata().unwrap();
    assert_eq!(service_ready["kind"], "SERVICE_ROOT_READY");
    assert_eq!(service_ready["capacity"], 67_108_864);
    assert_eq!(service_ready["root_dev"].as_u64(), Some(service_meta.dev()));
    assert_eq!(
        service_ready["root_inode"].as_u64(),
        Some(service_meta.ino())
    );
    let mut service_volume = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    assert_eq!(
        unsafe { libc::fstatvfs(service_root.as_raw_fd(), service_volume.as_mut_ptr()) },
        0
    );
    let service_volume = unsafe { service_volume.assume_init() };
    assert_eq!(
        service_volume.f_blocks.checked_mul(service_volume.f_frsize),
        Some(67_108_864)
    );
    let meta = root.metadata().unwrap();
    assert_eq!(ready["kind"], "KEEPER_READY");
    assert_eq!(ready["capacity"], 67_108_864);
    let mut volume = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    assert_eq!(
        unsafe { libc::fstatvfs(root.as_raw_fd(), volume.as_mut_ptr()) },
        0
    );
    let volume = unsafe { volume.assume_init() };
    assert_eq!(
        volume.f_blocks.checked_mul(volume.f_frsize),
        Some(67_108_864)
    );
    assert_eq!(ready["root_dev"].as_u64(), Some(meta.dev()));
    assert_eq!(ready["root_inode"].as_u64(), Some(meta.ino()));
    let fd_flags = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_GETFD) };
    assert!(fd_flags >= 0 && fd_flags & libc::FD_CLOEXEC != 0);
    let kg = fixture_cgroup(&keeper_unit).unwrap();
    assert!(fixture_limits(
        &kg,
        [
            ("cpu.max", "25000 100000"),
            ("memory.max", "134217728"),
            ("memory.swap.max", "0"),
            ("pids.max", "16")
        ]
    ));
    let candidates = std::fs::read_to_string(kg.join("cgroup.procs")).unwrap();
    let keeper_pids: Vec<_> = candidates
        .lines()
        .filter_map(|v| v.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| {
                exe.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("python3"))
            }) && std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmd| {
                cmd.windows(b"/stage/keeper.py".len())
                    .any(|s| s == b"/stage/keeper.py")
            })
        })
        .collect();
    assert_eq!(keeper_pids.len(), 1);
    let keeper_pid = keeper_pids[0];
    let kp = format!("/proc/{keeper_pid}");
    let keeper_stat = std::fs::read_to_string(format!("{kp}/stat")).unwrap();
    let keeper_start = keeper_stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_owned();
    let keeper_net = std::fs::read_link(format!("{kp}/ns/net")).unwrap();
    assert_ne!(keeper_net, std::fs::read_link("/proc/self/ns/net").unwrap());
    let pipe_name = std::ffi::CString::new(format!(".control-{run}")).unwrap();
    assert_eq!(
        unsafe { libc::mkfifoat(root.as_raw_fd(), pipe_name.as_ptr(), 0o600) },
        0
    );
    let mut worker_command = fixture_scope_command(&worker_unit, "100%", "536870912", "64");
    worker_command
        .args([
            "/usr/bin/nsenter",
            "--target",
            &keeper_pid.to_string(),
            "--user",
            "--preserve-credentials",
            "--mount",
            "--net",
            "--ipc",
            "--uts",
            "--pid",
            "--root",
            "--wdns=/job/workerroot",
            "--",
            "/usr/bin/bwrap",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--unshare-pid",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "HOME",
            "/job/workerroot",
            "--setenv",
            "TMPDIR",
            "/job/workerroot",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "DIFFUSER_LA_TEST_CHILD",
            "1",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
            "/worker-test",
            "/worker-test",
            "--ro-bind",
            "/stage/bootstrap.py",
            "/bootstrap.py",
            "--proc",
            "/proc",
            "--remount-ro",
            "/proc",
            "--dir",
            "/dev",
            "--dev-bind",
            "/dev/null",
            "/dev/null",
            "--bind",
            "/job/workerroot",
            "/job/workerroot",
            "--chdir",
            "/job/workerroot",
            "--remount-ro",
            "/",
            "--",
            "/usr/bin/python3",
            "-I",
            "-B",
            "/bootstrap.py",
        ])
        .arg(format!("/job/workerroot/.control-{run}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let worker_spawned = Instant::now();
    let mut worker = FixtureReap(worker_command.spawn().unwrap());
    let startup_deadline = worker_spawned + Duration::from_secs(5);
    units.0.push(worker_unit.clone());
    let open_deadline = Instant::now() + Duration::from_secs(3);
    let mut writer = loop {
        let fd = unsafe {
            libc::openat(
                root.as_raw_fd(),
                pipe_name.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break unsafe { std::fs::File::from_raw_fd(fd) };
        }
        assert!(
            Instant::now() < open_deadline,
            "worker pipe reader unavailable"
        );
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "worker exited before opening pipe"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        unsafe { libc::unlinkat(root.as_raw_fd(), pipe_name.as_ptr(), 0) },
        0
    );
    let end = Instant::now() + Duration::from_secs(3);
    let (wg, worker_pid) = loop {
        if worker.0.try_wait().unwrap().is_some() {
            let (status, out, err) = fixture_collect(&mut worker, Duration::from_secs(2)).unwrap();
            let evidence = std::env::temp_dir().join(format!("la-resource-failed-{run}"));
            std::fs::create_dir(&evidence).unwrap();
            std::fs::write(evidence.join("stdout.log"), &out).unwrap();
            std::fs::write(evidence.join("stderr.log"), &err).unwrap();
            panic!(
                "worker exited before observation: {status}; {}",
                String::from_utf8_lossy(&err)
            );
        }
        assert!(Instant::now() < end, "worker process not observed");
        if let Ok(group) = fixture_cgroup(&worker_unit) {
            if let Ok(pids) = std::fs::read_to_string(group.join("cgroup.procs")) {
                if let Some(pid) = pids
                    .lines()
                    .filter_map(|v| v.parse::<u32>().ok())
                    .find(|pid| {
                        std::fs::read_link(format!("/proc/{pid}/exe"))
                            .is_ok_and(|v| v == std::path::Path::new("/worker-test"))
                    })
                {
                    break (group, pid);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(fixture_limits(
        &wg,
        [
            ("cpu.max", "100000 100000"),
            ("memory.max", "536870912"),
            ("memory.swap.max", "0"),
            ("pids.max", "64")
        ]
    ));
    assert_ne!(wg, kg);
    let wp = format!("/proc/{worker_pid}");
    let worker_exe = std::fs::metadata(format!("{wp}/exe")).unwrap();
    let worker_file = std::fs::File::open(format!("{wp}/exe")).unwrap();
    assert_eq!(
        fixture_digest_file(worker_file, Instant::now() + Duration::from_secs(5)).unwrap(),
        executable_hash
    );
    let worker_stat = std::fs::read_to_string(format!("{wp}/stat")).unwrap();
    let worker_start = worker_stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_owned();
    let command = std::fs::read(format!("{wp}/cmdline")).unwrap();
    assert_eq!(
        command
            .split(|b| *b == 0)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>(),
        [
            b"/worker-test".as_slice(),
            b"--exact",
            b"cosp::la_tests::la_exec_child",
            b"--nocapture",
            b"--test-threads=1"
        ]
    );
    let own_exe = std::fs::metadata("/proc/self/exe").unwrap();
    assert_eq!(
        (worker_exe.dev(), worker_exe.ino()),
        (own_exe.dev(), own_exe.ino())
    );
    let worker_root = std::fs::metadata(format!("{wp}/root/job/workerroot")).unwrap();
    assert_eq!(
        (worker_root.dev(), worker_root.ino()),
        (meta.dev(), meta.ino())
    );
    assert_eq!(
        std::fs::read_link(format!("{wp}/ns/net")).unwrap(),
        keeper_net
    );
    let status = std::fs::read_to_string(format!("{wp}/status")).unwrap();
    assert!(status.lines().any(|s| s == "CapEff:\t0000000000000000"));
    assert!(status.lines().any(|s| s == "NoNewPrivs:\t1"));
    let mounts = std::fs::read_to_string(format!("{wp}/mountinfo")).unwrap();
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert!(fields.len() >= 6);
        if fields[5].split(',').any(|v| v == "rw") {
            assert!(matches!(fields[4], "/job/workerroot" | "/dev/null"));
        }
    }
    let pipe_meta = writer.metadata().unwrap();
    assert!(pipe_meta.file_type().is_fifo() && pipe_meta.nlink() == 0);
    let worker_pipe = std::fs::metadata(format!("{wp}/fd/0")).unwrap();
    assert_eq!(
        (pipe_meta.dev(), pipe_meta.ino()),
        (worker_pipe.dev(), worker_pipe.ino())
    );
    let parent_copies = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            std::fs::metadata(entry.path())
                .is_ok_and(|m| (m.dev(), m.ino()) == (pipe_meta.dev(), pipe_meta.ino()))
        })
        .count();
    assert_eq!(parent_copies, 1);
    let mut readers = Vec::new();
    let members = std::fs::read_to_string(wg.join("cgroup.procs")).unwrap();
    for pid in members.lines() {
        let entries =
            std::fs::read_dir(format!("/proc/{pid}/fd")).expect("cannot inspect a scoped process");
        for entry in entries {
            let entry = entry.expect("cannot enumerate scoped descriptor");
            let metadata =
                std::fs::metadata(entry.path()).expect("cannot inspect scoped descriptor");
            if (metadata.dev(), metadata.ino()) == (pipe_meta.dev(), pipe_meta.ino()) {
                readers.push(format!("{pid}:{}", entry.file_name().to_string_lossy()));
            }
        }
    }
    assert_eq!(
        std::fs::read_to_string(wg.join("cgroup.procs")).unwrap(),
        members,
        "worker process membership changed during custody check"
    );
    assert_eq!(
        readers,
        [format!("{worker_pid}:0")],
        "unexpected inherited control-pipe readers"
    );
    let mut descriptors = std::fs::read_dir(format!("{wp}/fd"))
        .unwrap()
        .map(|v| v.unwrap().file_name())
        .collect::<Vec<_>>();
    descriptors.sort();
    assert_eq!(descriptors, ["0", "1", "2"].map(std::ffi::OsString::from));
    let worker_stat_again = std::fs::read_to_string(format!("{wp}/stat")).unwrap();
    assert_eq!(
        worker_stat_again
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19),
        Some(worker_start.as_str())
    );
    let mut nonce = [0u8; 32];
    assert_eq!(
        unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) },
        nonce.len() as isize
    );
    let nonce = hex::encode(nonce);
    let mut secrets = [0u8; 96];
    assert_eq!(
        unsafe { libc::getrandom(secrets.as_mut_ptr().cast(), secrets.len(), 0) },
        secrets.len() as isize
    );
    let mut bearer = hex::encode(&secrets[..32]);
    let boot_id = hex::encode(&secrets[32..64]);
    let store_id = hex::encode(&secrets[64..]);
    let mut frame = serde_json::json!({"protocol_version":1,"run_nonce":nonce,"role":"worker","root":"/job/workerroot", "policy_id":"runtime-short-v1", "policy_digest":super::la_contract::policy_digest("runtime-short-v1").unwrap(), "expected_executable_sha256":executable_hash,
        "authority_material":{"service_bearer":bearer,"worker_id":"worker_cpu_000001","boot_id":boot_id,"hardware_generation":1,"profile_epoch":1},
        "custody_manifest":{"mode":"bootstrap","worker_id":"worker_cpu_000001","store_id":store_id,"root_dev":meta.dev(),"root_inode":meta.ino(),"expected_starts":0,"expected_records":0},"barrier_id":null});
    use zeroize::Zeroize;
    secrets.zeroize();
    serde_json::to_writer(&mut writer, &frame).unwrap();
    if let Some(serde_json::Value::String(secret)) = frame
        .get_mut("authority_material")
        .and_then(|v| v.get_mut("service_bearer"))
    {
        secret.zeroize();
    }
    writer.write_all(b"\n").unwrap();
    writer.flush().unwrap();
    let mut output = FixtureOutput::take(&mut worker).unwrap();
    let ready = output.next_frame(
        &mut worker,
        startup_deadline.saturating_duration_since(Instant::now()),
    );
    if ready.is_err() {
        let evidence = std::env::temp_dir().join(format!("la-resource-ready-failed-{run}"));
        std::fs::create_dir(&evidence).unwrap();
        std::fs::write(evidence.join("worker-stdout.log"), &output.out).unwrap();
        std::fs::write(evidence.join("worker-stderr.log"), &output.err).unwrap();
    }
    let ready = ready.expect("validated worker must emit a real READY frame");
    assert_eq!(ready["kind"], "READY");
    assert_eq!(ready["role"], "worker");
    assert_eq!(ready["run_nonce"], nonce);
    assert_eq!(ready["write_refusals"].as_array().map(Vec::len), Some(3));
    for entry in ready["write_refusals"].as_array().unwrap() {
        assert!(matches!(entry["errno"].as_i64(), Some(1 | 2 | 13 | 30)));
    }
    assert_eq!(
        std::fs::read_dir(format!("/proc/self/fd/{}", service_root.as_raw_fd()))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(ready["executable_sha256"], executable_hash);
    assert_eq!(
        ready["policy_digest"],
        super::la_contract::policy_digest("runtime-short-v1").unwrap()
    );
    assert_eq!(ready["boot_id"], boot_id);
    assert_eq!(ready["store_id"], store_id);
    assert_eq!(ready["root_dev"].as_u64(), Some(meta.dev()));
    assert_eq!(ready["root_inode"].as_u64(), Some(meta.ino()));
    let inner_pid = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .and_then(|v| v.split_whitespace().last())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap();
    assert_eq!(ready["pid"].as_u64(), Some(inner_pid));
    use sha2::{Digest, Sha256};
    let smoke = b"diffuser-s1-worker-startup-smoke-v1";
    let input_hash = hex::encode(Sha256::digest(smoke));
    let report=serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-artifact/v1","sha256":input_hash,"bytes":smoke.len(),"capability":"artifact.inspect.sha256/v1","profile_id":"cpu-artifact-inspect/v1","profile_version":"1","job_id":"startup_smoke_001"})).unwrap();
    assert_eq!(ready["smoke_input_sha256"], input_hash);
    assert_eq!(
        ready["smoke_input_bytes"].as_u64(),
        Some(smoke.len() as u64)
    );
    assert_eq!(
        ready["smoke_output_sha256"],
        hex::encode(Sha256::digest(&report))
    );
    assert_eq!(
        ready["smoke_output_bytes"].as_u64(),
        Some(report.len() as u64)
    );
    let address: std::net::SocketAddr = ready["address"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        address.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
    assert!(address.port() > 0);
    let evidence = std::env::temp_dir().join(format!("la-resource-parent-{run}"));
    std::fs::create_dir(&evidence).unwrap();
    std::fs::write(
        evidence.join("ready.json"),
        serde_json::to_vec(&ready).unwrap(),
    )
    .unwrap();
    std::fs::write(evidence.join("worker-stdout-before-http.log"), &output.out).unwrap();
    std::fs::write(evidence.join("worker-stderr-before-http.log"), &output.err).unwrap();
    let (http_status, response) = fixture_worker_http(
        keeper_pid,
        address.port(),
        "/v1/worker/inventory",
        &bearer,
        startup_deadline,
    )
    .expect("P must read authenticated isolated worker inventory");
    std::fs::write(evidence.join("worker-http-response.bin"), &response).unwrap();
    assert_eq!(http_status, 200);
    let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
    let body: serde_json::Value = serde_json::from_slice(&response[split + 4..]).unwrap();
    assert_eq!(body["schema_version"], "diffuser-worker/v1");
    assert_eq!(body["worker_id"], "worker_cpu_000001");
    assert_eq!(body["boot_id"], boot_id);
    assert_eq!(body["hardware_generation"], 1);
    assert_eq!(body["profile_epoch"], 1);
    assert_eq!(body["ready"], false);
    let worker_inventory_bytes = response.len() - split - 4;
    let worker_inventory_hash = hex::encode(Sha256::digest(&response[split + 4..]));
    let (unauthorized, _) = fixture_worker_http(
        keeper_pid,
        address.port(),
        "/v1/worker/inventory",
        "unrecognized-synthetic-token-with-more-than-32-bytes",
        startup_deadline,
    )
    .unwrap();
    assert_eq!(unauthorized, 401);
    let mut negative_run = [0u8; 8];
    assert_eq!(
        unsafe { libc::getrandom(negative_run.as_mut_ptr().cast(), negative_run.len(), 0) },
        negative_run.len() as isize
    );
    let negative_run = hex::encode(negative_run);
    fixture_controller_probe(
        keeper_pid,
        &keeper_net,
        &service_root,
        &negative_run,
        &executable_hash,
        address,
        &boot_id,
        &worker_inventory_hash,
        worker_inventory_bytes,
        &bearer,
        &evidence,
        true,
        ControllerEnding::Stop,
    );
    fixture_controller_probe(
        keeper_pid,
        &keeper_net,
        &service_root,
        &run,
        &executable_hash,
        address,
        &boot_id,
        &worker_inventory_hash,
        worker_inventory_bytes,
        &bearer,
        &evidence,
        false,
        ending,
    );
    if matches!(
        ending,
        ControllerEnding::Kill
            | ControllerEnding::KillDuringUpload
            | ControllerEnding::KillDuringTransaction
    ) {
        let (status, _) = fixture_worker_http(
            keeper_pid,
            address.port(),
            "/v1/worker/inventory",
            &bearer,
            startup_deadline,
        )
        .unwrap();
        assert_eq!(status, 200);
        std::fs::write(
            evidence.join("worker-after-controller-kill.json"),
            b"{\"inventory_status\":200}",
        )
        .unwrap();
    }
    bearer.zeroize();
    let status = if ending == ControllerEnding::KillWorker {
        let stat = std::fs::read_to_string(format!("{wp}/stat")).unwrap();
        assert_eq!(
            stat.rsplit_once(')').unwrap().1.split_whitespace().nth(19),
            Some(worker_start.as_str())
        );
        assert_eq!(
            unsafe { libc::kill(worker_pid as libc::pid_t, libc::SIGKILL) },
            0
        );
        let status = output.finish(&mut worker, Duration::from_secs(2)).unwrap();
        assert!(!status.success());
        assert!(!String::from_utf8_lossy(&output.out).contains("\"kind\":\"STOPPED\""));
        let keeper_after = std::fs::read_to_string(format!("{kp}/stat")).unwrap();
        assert_eq!(
            keeper_after
                .rsplit_once(')')
                .unwrap()
                .1
                .split_whitespace()
                .nth(19),
            Some(keeper_start.as_str())
        );
        let lock = super::la_artifacts::open_artifact(&root, ".worker-lock", libc::O_RDWR).unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let db = super::la_store::open_pinned_database(&root, "worker.sqlite", false).unwrap();
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .unwrap();
        let records: i64 = db
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");
        assert_eq!(records, 0);
        std::fs::write(
            evidence.join("worker-kill-retained-root.json"),
            serde_json::to_vec(&serde_json::json!({
                "signal":"SIGKILL", "integrity":"ok", "records":records, "lock_reacquired":true,
                "root_dev":meta.dev(), "root_inode":meta.ino()
            }))
            .unwrap(),
        )
        .unwrap();
        status
    } else {
        writer.write_all(b"STOP\n").unwrap();
        writer.flush().unwrap();
        let stopped = output
            .next_frame(&mut worker, Duration::from_secs(2))
            .unwrap();
        assert_eq!(stopped["kind"], "STOPPED");
        assert_eq!(stopped["run_nonce"], nonce);
        let status = output.finish(&mut worker, Duration::from_secs(2)).unwrap();
        assert!(status.success());
        status
    };
    let out = output.out;
    let err = output.err;
    let frames: Vec<_> = out
        .split(|b| *b == b'\n')
        .filter_map(|line| line.strip_prefix(b"DIFFUSER_LA_CHILD_V1 "))
        .collect();
    assert_eq!(
        frames.len(),
        if ending == ControllerEnding::KillWorker {
            1
        } else {
            2
        },
        "duplicate or extra protocol frames"
    );
    std::fs::write(evidence.join("worker-stdout.log"), &out).unwrap();
    std::fs::write(evidence.join("worker-stderr.log"), &err).unwrap();
    let journal = super::la_artifacts::open_artifact(
        &root,
        "worker.sqlite",
        libc::O_RDONLY | libc::O_NONBLOCK,
    );
    assert!(
        journal.is_ok(),
        "validated new worker must initialize its ordinary durable journal"
    );
    let mut header = [0u8; 16];
    journal.unwrap().read_exact(&mut header).unwrap();
    assert_eq!(&header, b"SQLite format 3\0");
    let after = std::fs::read_to_string(format!("{kp}/stat")).unwrap();
    assert_eq!(
        after.rsplit_once(')').unwrap().1.split_whitespace().nth(19),
        Some(keeper_start.as_str())
    );
    let after_root = root.metadata().unwrap();
    assert_eq!(
        (after_root.dev(), after_root.ino()),
        (meta.dev(), meta.ino())
    );
    writeln!(keeper.0.stdin.as_mut().unwrap(), "STOP").unwrap();
    keeper.0.stdin.as_mut().unwrap().flush().unwrap();
    let stop_by = Instant::now() + Duration::from_secs(2);
    while keeper.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < stop_by, "keeper did not stop");
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(root);
    drop(service_root);
    drop(recv);
    let mut cleanup = Vec::new();
    for (unit, group) in [(&worker_unit, &wg), (&keeper_unit, &kg)] {
        let _ = fixture_systemctl(&["stop", unit]);
        let _ = fixture_systemctl(&["reset-failed", unit]);
        let (result, state) = fixture_systemctl(&[
            "show",
            unit,
            "--property=LoadState,ActiveState,ControlGroup",
        ])
        .unwrap();
        assert!(result.success() && state.lines().any(|v| v == "ActiveState=inactive"));
        let events = std::fs::read_to_string(group.join("cgroup.events"))
            .unwrap_or_else(|_| "removed".into());
        assert!(events == "removed" || events.lines().any(|v| v == "populated 0"));
        cleanup.push(serde_json::json!({"unit":unit,"state":state,"cgroup_events":events}));
    }
    assert!(!std::path::Path::new(&kp).exists());
    assert!(!std::path::Path::new(&wp).exists());
    units.0.clear();
    std::fs::write(evidence.join("worker-mountinfo.txt"), mounts).unwrap();
    std::fs::write(evidence.join("p-mountinfo.txt"), p_mountinfo).unwrap();
    std::fs::write(evidence.join("probe.json"), serde_json::to_vec(&serde_json::json!({"kind":"NO_WORK_NOT_Q_ACCEPTANCE", "run":run,"keeper_pid":keeper_pid,"keeper_start":keeper_start,"worker_pid":worker_pid,"worker_start":worker_start,"p_cgroup":p_cgroup,"p_caps_checked":p_scoped,"p_mounts_bounded":p_mounts_bounded,"p_writable_paths_qualified":false,"cleanup":cleanup,"executable_sha256":executable_hash,"root_dev":meta.dev(),"root_inode":meta.ino(),"keeper_unit":keeper_unit,"worker_unit":worker_unit,"worker_exit":status.code()})).unwrap()).unwrap();
}

pub(super) fn fixture_discovery_context(
    now: u64,
) -> (super::lane_assignment::DiscoveryContext, String, String) {
    use super::{la_auth::OwnedAuthorityGrant, lane_assignment::DiscoveryContext};
    use sha2::{Digest, Sha256};
    let mut random = [0u8; 64];
    assert_eq!(
        unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) },
        random.len() as isize
    );
    let root_token = hex::encode(&random[..32]);
    let leaf_token = hex::encode(&random[32..]);
    assert_ne!(root_token, leaf_token);
    let root = OwnedAuthorityGrant {
        id: "grant_root123456".into(),
        parent: None,
        tenant: "tenant_123456789".into(),
        project: "project_12345678".into(),
        actor: "person_123456789".into(),
        bearer_digest: Sha256::digest(root_token.as_bytes()).into(),
        scopes: 1,
        can_delegate: true,
        enabled: true,
        member: true,
        revoked: false,
        not_before: now - 1,
        access_expires: now + 60_000,
        run_until: now + 60_000,
        execution_ceiling: now + 60_000,
        audience: "diffuser".into(),
    };
    let leaf = OwnedAuthorityGrant {
        id: "grant_leaf123456".into(),
        parent: Some(root.id.clone()),
        actor: "agent_1234567890".into(),
        bearer_digest: Sha256::digest(leaf_token.as_bytes()).into(),
        can_delegate: false,
        ..root.clone()
    };
    (
        DiscoveryContext {
            tenant: root.tenant.clone(),
            project: root.project.clone(),
            grants: vec![root, leaf],
            observed_at: now,
            observation_sequence: 0,
            freshness_ms: 6_000,
            inventory_available: true,
            inventory_observed_at: now,
            loss_scope: None,
        },
        root_token,
        leaf_token,
    )
}

async fn fixture_discovery_request(
    context: super::lane_assignment::DiscoveryContext,
    tokens: &[&str],
) -> (StatusCode, Value) {
    let state = Spine {
        root: std::env::temp_dir().join(format!("la-discovery-no-store-{}", std::process::id())),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    assert!(!state.root.exists());
    let mut request = Request::builder().uri("/v1/diffuser/discovery");
    for token in tokens {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = api_with_namespace(
        state.clone(),
        super::lane_assignment::injected_router(context),
    )
    .oneshot(request.body(Body::empty()).unwrap())
    .await
    .unwrap();
    let status = response.status();
    let body = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!state.root.exists());
    (status, body)
}

#[tokio::test]
async fn injected_discovery_accepts_current_delegated_authority_without_claiming_capacity() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (context, root_token, leaf_token) = fixture_discovery_context(now);
    for token in [&root_token, &leaf_token] {
        let (status, body) = fixture_discovery_request(context.clone(), &[token]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schema_version"], "diffuser-lane/v1");
        assert_eq!(body["queue_mode"], "refuse");
        assert_eq!(body["lanes"][0]["accepting"], false);
    }
}

#[tokio::test]
async fn injected_discovery_requires_current_chain_scope_and_fresh_observations() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (context, _, token) = fixture_discovery_context(now);
    let mut cases = Vec::new();
    let mut revoked = context.clone();
    revoked.grants[0].revoked = true;
    cases.push((revoked, StatusCode::UNAUTHORIZED, "auth_invalid"));
    let mut expired = context.clone();
    expired.grants[1].access_expires = now;
    cases.push((expired, StatusCode::UNAUTHORIZED, "auth_invalid"));
    let mut unscoped = context.clone();
    unscoped.grants[1].scopes = 0;
    cases.push((unscoped, StatusCode::FORBIDDEN, "scope_denied"));
    let mut widened = context.clone();
    widened.grants[1].scopes = 3;
    cases.push((widened, StatusCode::FORBIDDEN, "delegation_denied"));
    let mut stale = context.clone();
    stale.observed_at = now - 6_000;
    cases.push((stale, StatusCode::PRECONDITION_FAILED, "evidence_stale"));
    let mut no_inventory = context.clone();
    no_inventory.inventory_available = false;
    cases.push((
        no_inventory,
        StatusCode::SERVICE_UNAVAILABLE,
        "inventory_unavailable",
    ));
    let mut old_inventory = context.clone();
    old_inventory.inventory_observed_at = now - 6_000;
    cases.push((
        old_inventory,
        StatusCode::SERVICE_UNAVAILABLE,
        "inventory_unavailable",
    ));
    for (context, expected_status, expected_code) in cases {
        let (status, body) = fixture_discovery_request(context, &[&token]).await;
        assert_eq!(status, expected_status);
        assert_eq!(body["error"]["code"], expected_code);
    }
    for tokens in [
        vec![],
        vec!["unknown-token-with-at-least-thirty-two-bytes"],
        vec![token.as_str(), token.as_str()],
    ] {
        let (status, _) = fixture_discovery_request(context.clone(), &tokens).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[test]
fn child_rejects_absent_worker_authority_before_root_open() {
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let exe = std::env::current_exe().unwrap();
    let digest = child_executable_digest(Instant::now() + Duration::from_secs(5)).unwrap();
    let mut child = Command::new(exe)
        .args([
            "--exact",
            "cosp::la_tests::la_exec_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("DIFFUSER_LA_TEST_CHILD", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let frame = serde_json::json!({"protocol_version":1,"run_nonce":"a".repeat(64),"role":"worker","root":"/job/workerroot", "policy_id":"runtime-short-v1", "policy_digest":super::la_contract::policy_digest("runtime-short-v1").unwrap(), "expected_executable_sha256":digest,"authority_material":{},"custody_manifest":{},"barrier_id":null});
    writeln!(child.stdin.as_mut().unwrap(), "{frame}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("child_config_invalid"),
        "missing authority must be rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("DIFFUSER_LA_CHILD_V1"));
}

#[test]
fn sqlite_open_and_journals_remain_on_pinned_root_after_path_swap() {
    use std::{fs::OpenOptions, os::unix::fs::symlink};
    let base = std::env::temp_dir().join(format!("la-pinned-sqlite-{}", std::process::id()));
    assert!(!base.exists());
    std::fs::create_dir(&base).unwrap();
    let root = base.join("root");
    let held = base.join("held");
    let outside = base.join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let root_fd = OpenOptions::new().read(true).open(&root).unwrap();
    std::fs::rename(&root, &held).unwrap();
    symlink(&outside, &root).unwrap();
    let db = super::la_store::open_pinned_database(&root_fd, "lane_assignments.sqlite", true)
        .expect("SQLite must open through the pinned root");
    drop(root_fd);
    let mode: String = db
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    db.execute_batch(
        "CREATE TABLE records (id INTEGER PRIMARY KEY); INSERT INTO records VALUES (1);",
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(held.join("lane_assignments.sqlite").is_file());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    drop(db);
    std::fs::remove_file(root).unwrap();
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn pinned_sqlite_refuses_database_and_wal_symlinks() {
    use std::{fs::OpenOptions, os::unix::fs::symlink};
    let base = std::env::temp_dir().join(format!("la-pinned-links-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let root = base.join("root");
    std::fs::create_dir(&root).unwrap();
    let outside = base.join("sentinel");
    std::fs::write(&outside, b"sentinel bytes").unwrap();
    let dir = OpenOptions::new().read(true).open(&root).unwrap();
    symlink(&outside, root.join("bad.sqlite")).unwrap();
    assert!(super::la_store::open_pinned_database(&dir, "bad.sqlite", true).is_err());
    let db = super::la_store::open_pinned_database(&dir, "safe.sqlite", true).unwrap();
    db.execute_batch("CREATE TABLE records (id INTEGER PRIMARY KEY);")
        .unwrap();
    drop(db);
    symlink(&outside, root.join("safe.sqlite-wal")).unwrap();
    let attempt = super::la_store::open_pinned_database(&dir, "safe.sqlite", false);
    if let Ok(db) = attempt {
        assert!(db
            .execute_batch("PRAGMA journal_mode=WAL; INSERT INTO records VALUES (1);")
            .is_err());
    }
    assert_eq!(std::fs::read(&outside).unwrap(), b"sentinel bytes");
    drop(dir);
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn artifact_store_closes_when_owned_root_path_is_replaced() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::symlink;
    let base =
        std::env::temp_dir().join(format!("la-artifact-root-replaced-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let root = base.join("root");
    let held = base.join("held");
    let outside = base.join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    std::fs::rename(&root, &held).unwrap();
    symlink(&outside, &root).unwrap();
    let bytes = b"immutable input";
    let digest = hex::encode(Sha256::digest(bytes));
    assert_eq!(
        store.put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_12345678",
            bytes,
            &digest,
            1,
            100
        ),
        Err("storage_unavailable")
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(
        std::fs::read_dir(held.join("artifacts")).unwrap().count(),
        0
    );
    drop(store);
    std::fs::remove_file(&root).unwrap();
    std::fs::rename(&held, &root).unwrap();
    assert!(super::la_artifacts::ArtifactStore::open(&root).is_err());
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn artifact_uncertainty_blocks_other_open_handles_and_reopen() {
    use sha2::{Digest, Sha256};
    let root = std::env::temp_dir().join(format!(
        "la-artifact-cross-quarantine-{}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut first = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    let mut second = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    let bytes = b"immutable input";
    let digest = hex::encode(Sha256::digest(bytes));
    first
        .put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_12345678",
            bytes,
            &digest,
            1,
            100,
        )
        .unwrap();
    assert_eq!(
        first.put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_12345678",
            bytes,
            &digest,
            1,
            100
        ),
        Err("storage_unavailable")
    );
    assert_eq!(
        second.put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_abcdefgh",
            bytes,
            &digest,
            1,
            100
        ),
        Err("storage_unavailable")
    );
    drop(first);
    drop(second);
    assert!(super::la_artifacts::ArtifactStore::open(&root).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn claim_store_refuses_reads_after_root_path_replacement() {
    use std::os::unix::fs::symlink;
    let base = std::env::temp_dir().join(format!("la-claim-root-replaced-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let root = base.join("root");
    let held = base.join("held");
    let outside = base.join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let store = super::la_store::ClaimStore::open(&root.join("lane.sqlite")).unwrap();
    std::fs::rename(&root, &held).unwrap();
    symlink(&outside, &root).unwrap();
    assert_eq!(store.counts(), Err("storage_unavailable"));
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    drop(store);
    std::fs::remove_file(&root).unwrap();
    std::fs::rename(&held, &root).unwrap();
    assert!(super::la_store::ClaimStore::open(&root.join("lane.sqlite")).is_err());
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn worker_journal_refuses_replaced_owned_root() {
    use std::os::unix::fs::symlink;
    let base = std::env::temp_dir().join(format!("la-worker-root-replaced-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let root = base.join("root");
    let held = base.join("held");
    let outside = base.join("outside");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let journal = super::la_worker::OperationJournal::bootstrap(
        &root.join("worker.sqlite"),
        "custody_12345678",
    )
    .unwrap();
    std::fs::rename(&root, &held).unwrap();
    symlink(&outside, &root).unwrap();
    assert_eq!(
        journal.start_count("operation_123456"),
        Err("storage_unavailable")
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    drop(journal);
    std::fs::remove_file(&root).unwrap();
    std::fs::rename(&held, &root).unwrap();
    assert!(super::la_worker::OperationJournal::reopen_checked(
        &root.join("worker.sqlite"),
        "custody_12345678",
        0,
        0
    )
    .is_err());
    std::fs::remove_dir_all(base).unwrap();
}

fn fixture_artifact_http(
    keeper_pid: u32,
    port: u16,
    method: &str,
    path: &str,
    bearer: &str,
    body: &[u8],
    deadline: std::time::Instant,
) -> std::result::Result<(u16, Vec<u8>), String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    if !matches!(method, "GET" | "POST")
        || !path.starts_with("/v1/diffuser/projects/project_12345678/artifacts")
        || !path
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'/' | b'_' | b'-'))
        || body.len() > 1024
    {
        return Err("http_path_invalid".into());
    }
    let mut stream = fixture_connect(keeper_pid, port, deadline)?;
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n").map_err(|_| "http_write_failed")?;
    if method == "POST" {
        write!(stream, "Content-Type: application/octet-stream\r\nContent-Length: {}\r\nX-Diffuser-Schema: diffuser-artifact/v1\r\nX-Content-SHA256: {}\r\nIdempotency-Key: p_fixture_upload_001\r\n", body.len(), hex::encode(Sha256::digest(body))).map_err(|_| "http_write_failed")?;
    }
    stream
        .write_all(b"\r\n")
        .and_then(|_| stream.write_all(body))
        .map_err(|_| "http_write_failed")?;
    let mut response = Vec::new();
    stream
        .take(65_537)
        .read_to_end(&mut response)
        .map_err(|_| "http_read_failed")?;
    if response.len() > 65_536 || std::time::Instant::now() >= deadline {
        return Err("http_bound_failed".into());
    }
    let split = response
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or("http_header_invalid")?;
    let header = std::str::from_utf8(&response[..split]).map_err(|_| "http_header_invalid")?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .and_then(|v| v.strip_prefix("HTTP/1.1 "))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or("http_status_invalid")?;
    let mut length = None;
    for line in lines {
        let (key, value) = line.split_once(':').ok_or("http_header_invalid")?;
        if key.eq_ignore_ascii_case("transfer-encoding") {
            return Err("http_transfer_invalid".into());
        }
        if key.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("http_header_invalid".into());
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "http_header_invalid")?,
            );
        }
    }
    if length != Some(response.len() - split - 4) {
        return Err("http_length_invalid".into());
    }
    Ok((status, response[split + 4..].to_vec()))
}

#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
)]
fn fixture_controller_probe(
    keeper_pid: u32,
    keeper_net: &std::path::Path,
    service_root: &std::fs::File,
    run: &str,
    executable_hash: &str,
    worker_address: std::net::SocketAddr,
    worker_boot: &str,
    worker_inventory_hash: &str,
    worker_inventory_bytes: usize,
    worker_bearer: &str,
    evidence: &std::path::Path,
    duplicate: bool,
    ending: ControllerEnding,
) {
    use std::{
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{FileTypeExt, MetadataExt},
        },
        process::Stdio,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use zeroize::Zeroize;
    let unit = format!("diffuser-r5s1-c-{run}.scope");
    let (status, state) =
        fixture_systemctl(&["show", &unit, "--property=LoadState", "--value"]).unwrap();
    assert!(status.success() && state.trim() == "not-found");
    struct Cleanup(String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fixture_systemctl(&["kill", "--kill-whom=all", "--signal=SIGKILL", &self.0]);
            let _ = fixture_systemctl(&["stop", &self.0]);
            let _ = fixture_systemctl(&["reset-failed", &self.0]);
        }
    }
    let _cleanup = Cleanup(unit.clone());
    let meta = service_root.metadata().unwrap();
    let name = std::ffi::CString::new(format!(".control-c-{run}")).unwrap();
    assert_eq!(
        unsafe { libc::mkfifoat(service_root.as_raw_fd(), name.as_ptr(), 0o600) },
        0
    );
    let mut command = fixture_scope_command(&unit, "100%", "536870912", "64");
    command
        .args([
            "/usr/bin/nsenter",
            "--target",
            &keeper_pid.to_string(),
            "--user",
            "--preserve-credentials",
            "--mount",
            "--net",
            "--ipc",
            "--uts",
            "--pid",
            "--root",
            "--wdns=/job/service",
            "--",
            "/usr/bin/bwrap",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--unshare-pid",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "HOME",
            "/job/service",
            "--setenv",
            "TMPDIR",
            "/job/service",
            "--setenv",
            "LANG",
            "C",
            "--setenv",
            "DIFFUSER_LA_TEST_CHILD",
            "1",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--ro-bind",
            "/worker-test",
            "/worker-test",
            "--ro-bind",
            "/stage/bootstrap.py",
            "/bootstrap.py",
            "--proc",
            "/proc",
            "--remount-ro",
            "/proc",
            "--dir",
            "/dev",
            "--dev-bind",
            "/dev/null",
            "/dev/null",
            "--bind",
            "/job/service",
            "/job/service",
            "--chdir",
            "/job/service",
            "--remount-ro",
            "/",
            "--",
            "/usr/bin/python3",
            "-I",
            "-B",
            "/bootstrap.py",
        ])
        .arg(format!("/job/service/.control-c-{run}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = FixtureReap(command.spawn().unwrap());
    let deadline = started + Duration::from_secs(5);
    let mut writer = loop {
        let fd = unsafe {
            libc::openat(
                service_root.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break unsafe { std::fs::File::from_raw_fd(fd) };
        }
        assert!(
            Instant::now() < deadline && child.0.try_wait().unwrap().is_none(),
            "controller pipe unavailable"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        unsafe { libc::unlinkat(service_root.as_raw_fd(), name.as_ptr(), 0) },
        0
    );
    let (group, pid) = loop {
        assert!(
            Instant::now() < deadline && child.0.try_wait().unwrap().is_none(),
            "controller executable unavailable"
        );
        if let Ok(group) = fixture_cgroup(&unit) {
            if let Ok(pids) = std::fs::read_to_string(group.join("cgroup.procs")) {
                if let Some(pid) = pids
                    .lines()
                    .filter_map(|v| v.parse::<u32>().ok())
                    .find(|p| {
                        std::fs::read_link(format!("/proc/{p}/exe"))
                            .is_ok_and(|v| v == std::path::Path::new("/worker-test"))
                    })
                {
                    break (group, pid);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(fixture_limits(
        &group,
        [
            ("cpu.max", "100000 100000"),
            ("memory.max", "536870912"),
            ("memory.swap.max", "0"),
            ("pids.max", "64")
        ]
    ));
    let proc = format!("/proc/{pid}");
    let process_stat = std::fs::read_to_string(format!("{proc}/stat")).unwrap();
    let starttime = process_stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .to_owned();
    let cmdline = std::fs::read(format!("{proc}/cmdline")).unwrap();
    assert_eq!(
        cmdline
            .split(|b| *b == 0)
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>(),
        [
            b"/worker-test".as_slice(),
            b"--exact",
            b"cosp::la_tests::la_exec_child",
            b"--nocapture",
            b"--test-threads=1"
        ]
    );
    let exe = std::fs::metadata(format!("{proc}/exe")).unwrap();
    let own = std::fs::metadata("/proc/self/exe").unwrap();
    assert_eq!((exe.dev(), exe.ino()), (own.dev(), own.ino()));
    assert_eq!(
        fixture_digest_file(
            std::fs::File::open(format!("{proc}/exe")).unwrap(),
            deadline
        )
        .unwrap(),
        executable_hash
    );
    let root = std::fs::metadata(format!("{proc}/root/job/service")).unwrap();
    assert_eq!((root.dev(), root.ino()), (meta.dev(), meta.ino()));
    assert_eq!(
        std::fs::read_link(format!("{proc}/ns/net")).unwrap(),
        keeper_net
    );
    let process_status = std::fs::read_to_string(format!("{proc}/status")).unwrap();
    assert!(process_status
        .lines()
        .any(|v| v == "CapEff:\t0000000000000000"));
    assert!(process_status.lines().any(|v| v == "NoNewPrivs:\t1"));
    let pipe = writer.metadata().unwrap();
    assert!(pipe.file_type().is_fifo() && pipe.nlink() == 0);
    let mut readers = Vec::new();
    let members = std::fs::read_to_string(group.join("cgroup.procs")).unwrap();
    for member in members.lines() {
        for entry in std::fs::read_dir(format!("/proc/{member}/fd")).unwrap() {
            let entry = entry.unwrap();
            let m = std::fs::metadata(entry.path()).unwrap();
            if (m.dev(), m.ino()) == (pipe.dev(), pipe.ino()) {
                readers.push(format!("{member}:{}", entry.file_name().to_string_lossy()));
            }
        }
    }
    assert_eq!(
        std::fs::read_to_string(group.join("cgroup.procs")).unwrap(),
        members
    );
    assert_eq!(readers, [format!("{pid}:0")]);
    let mut fds = std::fs::read_dir(format!("{proc}/fd"))
        .unwrap()
        .map(|v| v.unwrap().file_name())
        .collect::<Vec<_>>();
    fds.sort();
    assert_eq!(fds, ["0", "1", "2"].map(std::ffi::OsString::from));
    let mounts = std::fs::read_to_string(format!("{proc}/mountinfo")).unwrap();
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert!(fields.len() >= 6);
        if fields[5].split(',').any(|v| v == "rw") {
            assert!(matches!(fields[4], "/job/service" | "/dev/null"));
        }
    }
    let stat_again = std::fs::read_to_string(format!("{proc}/stat")).unwrap();
    assert_eq!(
        stat_again
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .nth(19),
        Some(starttime.as_str())
    );
    let mut random = [0u8; 160];
    assert_eq!(
        unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) },
        random.len() as isize
    );
    let mut human = hex::encode(&random[..32]);
    let mut delegated = hex::encode(&random[32..64]);
    let nonce = hex::encode(&random[64..96]);
    let store_id = hex::encode(&random[96..128]);
    let controller_boot = hex::encode(&random[128..]);
    random.zeroize();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut frame = serde_json::json!({"protocol_version":1,"run_nonce":nonce,"role":"controller","root":"/job/service","policy_id":"runtime-short-v1","policy_digest":super::la_contract::policy_digest("runtime-short-v1").unwrap(),"expected_executable_sha256":executable_hash,
        "authority_material":{"tenant":"tenant_123456789","project":"project_12345678","root_actor":"person_123456789","leaf_actor":"agent_1234567890","root_scopes":7,"leaf_scopes":7,"root_bearer":human,"leaf_bearer":delegated,"worker_bearer":worker_bearer,"worker_address":worker_address.to_string(),"worker_id":"worker_cpu_000001","worker_boot_id":worker_boot,"boot_id":controller_boot,"observed_at":now,"access_expires":now+60_000,"run_until":now+60_000,"execution_ceiling":now+60_000},
        "custody_manifest":{"mode":"bootstrap","store_id":store_id,"root_dev":meta.dev(),"root_inode":meta.ino(),"writer_epoch":1},"barrier_id":null});
    serde_json::to_writer(&mut writer, &frame).unwrap();
    if duplicate {
        writer.write_all(b"\n").unwrap();
        serde_json::to_writer(&mut writer, &frame).unwrap();
    }
    for key in ["root_bearer", "leaf_bearer", "worker_bearer"] {
        if let Some(serde_json::Value::String(v)) = frame
            .get_mut("authority_material")
            .and_then(|v| v.get_mut(key))
        {
            v.zeroize();
        }
    }
    writer.write_all(b"\n").unwrap();
    writer.flush().unwrap();
    let mut output = FixtureOutput::take(&mut child).unwrap();
    if duplicate {
        let status = output
            .finish(
                &mut child,
                deadline.saturating_duration_since(Instant::now()),
            )
            .unwrap();
        std::fs::write(
            evidence.join("controller-duplicate-stdout.log"),
            &output.out,
        )
        .unwrap();
        std::fs::write(
            evidence.join("controller-duplicate-stderr.log"),
            &output.err,
        )
        .unwrap();
        assert!(!status.success());
        assert!(String::from_utf8_lossy(&output.err).contains("unexpected_config"));
        assert!(!String::from_utf8_lossy(&output.out).contains("DIFFUSER_LA_CHILD_V1"));
        assert_eq!(
            std::fs::read_dir(format!("/proc/self/fd/{}", service_root.as_raw_fd()))
                .unwrap()
                .count(),
            0
        );
        human.zeroize();
        delegated.zeroize();
        return;
    }
    let ready = output.next_frame(
        &mut child,
        deadline.saturating_duration_since(Instant::now()),
    );
    if ready.is_err() {
        std::fs::write(evidence.join("controller-stdout-failed.log"), &output.out).unwrap();
        std::fs::write(evidence.join("controller-stderr-failed.log"), &output.err).unwrap();
    }
    let ready = ready.expect("validated controller must emit a real READY frame");
    assert_eq!(ready["kind"], "READY");
    assert_eq!(ready["role"], "controller");
    assert_eq!(ready["run_nonce"], nonce);
    assert_eq!(ready["executable_sha256"], executable_hash);
    assert_eq!(ready["store_id"], store_id);
    assert_eq!(ready["boot_id"], controller_boot);
    assert_eq!(
        ready["policy_digest"],
        super::la_contract::policy_digest("runtime-short-v1").unwrap()
    );
    assert_eq!(ready["worker_inventory_sha256"], worker_inventory_hash);
    assert_eq!(
        ready["worker_inventory_bytes"].as_u64(),
        Some(worker_inventory_bytes as u64)
    );
    let inner_pid = process_status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .and_then(|v| v.split_whitespace().last())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap();
    assert_eq!(ready["pid"].as_u64(), Some(inner_pid));
    use sha2::{Digest, Sha256};
    let smoke = b"diffuser-s1-controller-startup-smoke-v1";
    let input_hash = hex::encode(Sha256::digest(smoke));
    let report = serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-artifact/v1","sha256":input_hash,"bytes":smoke.len(),"capability":"artifact.inspect.sha256/v1","profile_id":"cpu-artifact-inspect/v1","profile_version":"1","job_id":"startup_smoke_002"})).unwrap();
    assert_eq!(ready["smoke_input_sha256"], input_hash);
    assert_eq!(
        ready["smoke_input_bytes"].as_u64(),
        Some(smoke.len() as u64)
    );
    assert_eq!(
        ready["smoke_output_sha256"],
        hex::encode(Sha256::digest(&report))
    );
    assert_eq!(
        ready["smoke_output_bytes"].as_u64(),
        Some(report.len() as u64)
    );
    assert_eq!(ready["root_dev"].as_u64(), Some(meta.dev()));
    assert_eq!(ready["root_inode"].as_u64(), Some(meta.ino()));
    let address: std::net::SocketAddr = ready["address"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        address.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
    for (index, token) in [&human, &delegated].into_iter().enumerate() {
        let (status, response) = fixture_worker_http(
            keeper_pid,
            address.port(),
            "/v1/diffuser/discovery",
            token,
            deadline,
        )
        .unwrap();
        assert_eq!(status, 200);
        std::fs::write(
            evidence.join(format!("controller-http-{index}.bin")),
            &response,
        )
        .unwrap();
        let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response[split + 4..]).unwrap();
        assert_eq!(body["schema_version"], "diffuser-lane/v1");
        assert_eq!(body["queue_mode"], "refuse");
        assert_eq!(body["lanes"][0]["accepting"], false);
    }
    // This is an authorized C artifact operation, not an admitted worker job.
    let input = b"actual controller immutable input\0\xff";
    let artifact_path = "/v1/diffuser/projects/project_12345678/artifacts";
    let (status, receipt) = fixture_artifact_http(
        keeper_pid,
        address.port(),
        "POST",
        artifact_path,
        &delegated,
        input,
        deadline,
    )
    .unwrap();
    assert_eq!(status, 201);
    let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    let artifact_id = receipt["object_id"].as_str().unwrap();
    let content_path = format!("{artifact_path}/{artifact_id}/content");
    let (status, content) = fixture_artifact_http(
        keeper_pid,
        address.port(),
        "GET",
        &content_path,
        &delegated,
        b"",
        deadline,
    )
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(content, input);
    let (status, _) = fixture_artifact_http(
        keeper_pid,
        address.port(),
        "GET",
        &content_path,
        &human,
        b"",
        deadline,
    )
    .unwrap();
    assert_eq!(status, 404);
    let (status, retry) = fixture_artifact_http(
        keeper_pid,
        address.port(),
        "POST",
        artifact_path,
        &delegated,
        input,
        deadline,
    )
    .unwrap();
    assert_eq!(status, 201);
    let retry: serde_json::Value = serde_json::from_slice(&retry).unwrap();
    assert_eq!(retry["object_id"], artifact_id);
    std::fs::write(evidence.join("controller-artifact-probe.json"), serde_json::to_vec(&serde_json::json!({
        "artifact_id":artifact_id,"bytes":content.len(),"sha256":hex::encode(Sha256::digest(&content)),
        "upload_status":201,"read_status":200,"other_actor_status":404,"retry_status":201
    })).unwrap()).unwrap();
    let (unauthorized, _) = fixture_worker_http(
        keeper_pid,
        address.port(),
        "/v1/diffuser/discovery",
        "unrecognized-synthetic-token-with-more-than-32-bytes",
        deadline,
    )
    .unwrap();
    assert_eq!(unauthorized, 401);
    let held_transaction = if ending == ControllerEnding::KillDuringTransaction {
        let db =
            super::la_store::open_pinned_database(service_root, "lane_assignments.sqlite", false)
                .unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        Some(db)
    } else {
        None
    };
    let pending_upload = if matches!(
        ending,
        ControllerEnding::KillDuringUpload | ControllerEnding::KillDuringTransaction
    ) {
        let mut stream = fixture_connect(keeper_pid, address.port(), deadline).unwrap();
        let digest = hex::encode(Sha256::digest(b"ab"));
        write!(stream, "POST {artifact_path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {delegated}\r\nIdempotency-Key: partial_upload_001\r\nX-Diffuser-Schema: diffuser-artifact/v1\r\nX-Content-SHA256: {digest}\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").unwrap();
        stream.flush().unwrap();
        let mut interim = Vec::new();
        while !interim.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            interim.push(byte[0]);
            assert!(interim.len() <= 1024);
        }
        assert!(interim.starts_with(b"HTTP/1.1 100"));
        if ending == ControllerEnding::KillDuringTransaction {
            stream.write_all(b"ab").unwrap();
            let probe =
                super::la_artifacts::open_artifact(service_root, ".artifact-lock", libc::O_RDWR)
                    .unwrap();
            loop {
                if unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::EWOULDBLOCK)
                    );
                    break;
                }
                assert_eq!(unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_UN) }, 0);
                assert!(
                    Instant::now() < deadline,
                    "controller did not enter the blocked transaction"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        } else {
            stream.write_all(b"a").unwrap();
        }
        Some(stream)
    } else {
        None
    };
    human.zeroize();
    delegated.zeroize();
    if ending == ControllerEnding::Duplicate {
        // A second config is never accepted after activation. The existing
        // GO/STOP protocol closes the controller and yields no STOPPED claim.
        writer.write_all(b"{\"protocol_version\":1}\n").unwrap();
        writer.flush().unwrap();
        let status = output.finish(&mut child, Duration::from_secs(2)).unwrap();
        assert!(!status.success());
        assert!(String::from_utf8_lossy(&output.err).contains("control_invalid"));
        assert!(!String::from_utf8_lossy(&output.out).contains("\"kind\":\"STOPPED\""));
    } else if matches!(
        ending,
        ControllerEnding::Kill
            | ControllerEnding::KillDuringUpload
            | ControllerEnding::KillDuringTransaction
    ) {
        let stat = std::fs::read_to_string(format!("{proc}/stat")).unwrap();
        assert_eq!(
            stat.rsplit_once(')').unwrap().1.split_whitespace().nth(19),
            Some(starttime.as_str())
        );
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) }, 0);
        let status = output.finish(&mut child, Duration::from_secs(2)).unwrap();
        assert!(!status.success());
        assert!(!String::from_utf8_lossy(&output.out).contains("\"kind\":\"STOPPED\""));
        drop(pending_upload);
        if let Some(db) = held_transaction {
            db.execute_batch("ROLLBACK").unwrap();
        }
        let db =
            super::la_store::open_pinned_database(service_root, "lane_assignments.sqlite", false)
                .unwrap();
        let (stored_digest, stored_length): (String, i64) = db.query_row(
            "SELECT digest,byte_count FROM la_artifacts WHERE id=?1 AND tenant='tenant_123456789' AND project='project_12345678' AND actor='agent_1234567890'",
            [artifact_id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        let counts: (i64, i64, i64) = db.query_row(
            "SELECT (SELECT COUNT(*) FROM la_artifact_idempotency),(SELECT COUNT(*) FROM la_artifact_provenance),(SELECT COUNT(*) FROM la_artifacts)",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        assert_eq!(counts, (1, 1, 1));
        let directory = super::la_artifacts::open_artifact(
            service_root,
            "artifacts",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .unwrap();
        let file =
            super::la_artifacts::open_artifact(&directory, artifact_id, libc::O_RDONLY).unwrap();
        let mut retained = Vec::new();
        file.take(1_048_577).read_to_end(&mut retained).unwrap();
        assert_eq!(retained, input);
        assert_eq!(stored_length as usize, retained.len());
        assert_eq!(stored_digest, hex::encode(Sha256::digest(&retained)));
        assert_eq!(
            std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .unwrap()
                .count(),
            1
        );
        assert_eq!(
            super::la_artifacts::open_artifact(service_root, ".artifact-intent", libc::O_RDONLY)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::write(evidence.join("controller-kill-artifact.json"), serde_json::to_vec(&serde_json::json!({
            "signal":"SIGKILL", "during_upload":ending == ControllerEnding::KillDuringUpload,
            "during_transaction_wait":ending == ControllerEnding::KillDuringTransaction, "artifact_id":artifact_id, "sha256":stored_digest,
            "bytes":retained.len(), "idempotency_records":counts.0, "provenance_records":counts.1
        })).unwrap()).unwrap();
    } else {
        writer.write_all(b"STOP\n").unwrap();
        writer.flush().unwrap();
        let stopped = output
            .next_frame(&mut child, Duration::from_secs(2))
            .unwrap();
        assert_eq!(stopped["kind"], "STOPPED");
        assert_eq!(stopped["run_nonce"], nonce);
        let status = output.finish(&mut child, Duration::from_secs(2)).unwrap();
        assert!(status.success());
    }
    std::fs::write(
        evidence.join("controller-ready.json"),
        serde_json::to_vec(&ready).unwrap(),
    )
    .unwrap();
    std::fs::write(evidence.join("controller-stdout.log"), output.out).unwrap();
    std::fs::write(evidence.join("controller-stderr.log"), output.err).unwrap();
    std::fs::write(evidence.join("controller-mountinfo.txt"), mounts).unwrap();
    let _ = fixture_systemctl(&["stop", &unit]);
    let _ = fixture_systemctl(&["reset-failed", &unit]);
    let (state_status, state) = fixture_systemctl(&[
        "show",
        &unit,
        "--property=LoadState,ActiveState,ControlGroup",
    ])
    .unwrap();
    assert!(state_status.success() && state.lines().any(|v| v == "ActiveState=inactive"));
    let events =
        std::fs::read_to_string(group.join("cgroup.events")).unwrap_or_else(|_| "removed".into());
    assert!(events == "removed" || events.lines().any(|v| v == "populated 0"));
    assert!(!std::path::Path::new(&proc).exists());
    std::fs::write(evidence.join("controller-probe.json"), serde_json::to_vec(&serde_json::json!({"pid":pid,"starttime":starttime,"unit":unit,"cleanup_state":state,"cgroup_events":events,"service_root_dev":meta.dev(),"service_root_inode":meta.ino()})).unwrap()).unwrap();
}

// Resource preflight is intentionally not an authorization receipt. A missing
// inventory must never qualify P for work.
fn fixture_p_mounts_bounded(mountinfo: &str) -> bool {
    let mut root = false;
    let mut custody = None;
    let mut evidence = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        let fields: Vec<_> = left.split_whitespace().collect();
        let fs: Vec<_> = right.split_whitespace().collect();
        if fields.len() < 6 || fs.len() < 3 || fields[3].contains('\\') || fields[4].contains('\\')
        {
            return false;
        }
        let options: Vec<_> = fields[5].split(',').collect();
        let read_only = options.contains(&"ro");
        let writable = options.contains(&"rw");
        if read_only == writable {
            return false;
        }
        if fields[4] == "/" {
            if root || !read_only {
                return false;
            }
            root = true;
        }
        if writable {
            let target = match fields[4] {
                "/job/custody" => &mut custody,
                "/job/evidence" => &mut evidence,
                _ => return false,
            };
            if target.is_some() || fields[3] != "/" || fs[0] != "tmpfs" {
                return false;
            }
            *target = Some(fields[2]);
        }
    }
    root && custody.is_some() && evidence.is_some() && custody != evidence
}

#[test]
fn p_preflight_rejects_ambient_or_ambiguous_writable_mounts() {
    let bounded = "1 0 0:1 / / ro - tmpfs root ro\n2 1 0:2 / /job/custody rw - tmpfs custody rw\n3 1 0:3 / /job/evidence rw - tmpfs evidence rw\n";
    assert!(fixture_p_mounts_bounded(bounded));
    assert!(!fixture_p_mounts_bounded(""));
    assert!(!fixture_p_mounts_bounded(
        &bounded.replace("/ / ro", "/ / rw")
    ));
    assert!(!fixture_p_mounts_bounded(&format!(
        "{bounded}4 1 0:4 / /tmp rw - tmpfs tmp rw\n"
    )));
    assert!(!fixture_p_mounts_bounded(
        &bounded.replace("/job/custody rw", "/job/custody ro")
    ));
    assert!(!fixture_p_mounts_bounded(&format!("{bounded}garbled\n")));
}

#[tokio::test]
async fn authenticated_artifact_upload_and_readback_are_durable_and_idempotent() {
    use sha2::{Digest, Sha256};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    let root = std::env::temp_dir().join(format!("la-http-artifact-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    let router = api_with_namespace(
        state.clone(),
        super::lane_assignment::injected_service_router(context.clone(), store),
    );
    let input = b"immutable HTTP input\0\xff";
    let digest = hex::encode(Sha256::digest(input));
    let upload = |bytes: &'static [u8], digest: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/artifacts")
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", "upload_key_123456")
            .header("x-diffuser-schema", "diffuser-artifact/v1")
            .header("x-content-sha256", digest)
            .header("content-type", "application/octet-stream")
            .header("content-length", bytes.len().to_string())
            .body(Body::from(bytes))
            .unwrap()
    };
    let response = router
        .clone()
        .oneshot(upload(input, &digest))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = body["object_id"].as_str().unwrap().to_owned();
    let response = router
        .clone()
        .oneshot(upload(input, &digest))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let duplicate: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(duplicate["object_id"], id);
    let different = b"different bytes";
    let response = router
        .clone()
        .oneshot(upload(different, &hex::encode(Sha256::digest(different))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let get = |suffix: &str, auth: &str| {
        Request::builder()
            .uri(format!(
                "/v1/diffuser/projects/project_12345678/artifacts/{id}{suffix}"
            ))
            .header("authorization", format!("Bearer {auth}"))
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(get("", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let manifest: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["sha256"], digest);
    assert_eq!(manifest["bytes"], input.len());
    let response = router
        .clone()
        .oneshot(get("/content", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["etag"], format!("\"{digest}\""));
    assert_eq!(
        &axum::body::to_bytes(response.into_body(), 1048576)
            .await
            .unwrap()[..],
        input
    );
    let response = router
        .clone()
        .oneshot(get("", "wrong-token-with-at-least-thirty-two-bytes"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    drop(router);
    let reopened = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    let router = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(context, reopened),
    );
    let response = router
        .clone()
        .oneshot(upload(input, &digest))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let after_restart: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(after_restart["object_id"], id);
    assert_eq!(
        router
            .clone()
            .oneshot(get("/content", &token))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    drop(router);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn artifact_http_checks_scope_owner_revocation_and_integrity() {
    use sha2::{Digest, Sha256};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, human, delegated) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    let root = std::env::temp_dir().join(format!("la-http-acl-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let router = |context| {
        api_with_namespace(
            state.clone(),
            super::lane_assignment::injected_service_router(
                context,
                super::la_artifacts::ArtifactStore::open(&root).unwrap(),
            ),
        )
    };
    let app = router(context.clone());
    let input = b"delegated synthetic input";
    let digest = hex::encode(Sha256::digest(input));
    let upload = |token: &str, key: &str, supplied: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/artifacts")
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", key)
            .header("x-diffuser-schema", "diffuser-artifact/v1")
            .header("x-content-sha256", supplied)
            .header("content-type", "application/octet-stream")
            .body(Body::from(input.as_slice()))
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(upload(&delegated, "delegated_key_1234", &digest))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let receipt: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = receipt["object_id"].as_str().unwrap();
    let manifest = Request::builder()
        .uri(format!(
            "/v1/diffuser/projects/project_12345678/artifacts/{id}"
        ))
        .header("authorization", format!("Bearer {delegated}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(manifest).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["actor_id"], "agent_1234567890");
    assert_eq!(body["initiator_id"], "person_123456789");
    assert_eq!(
        body["provenance"]["authority_lineage"],
        serde_json::json!(["grant_root123456", "grant_leaf123456"])
    );
    let read = |token: &str| {
        Request::builder()
            .uri(format!(
                "/v1/diffuser/projects/project_12345678/artifacts/{id}/content"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(read(&human)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.clone()
            .oneshot(read(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(upload(&delegated, "bad_digest_key_123", &"0".repeat(64)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let cross_project = Request::builder()
        .uri(format!(
            "/v1/diffuser/projects/project_other123/artifacts/{id}/content"
        ))
        .header("authorization", format!("Bearer {delegated}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(cross_project).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let duplicate_auth = Request::builder()
        .uri(format!(
            "/v1/diffuser/projects/project_12345678/artifacts/{id}/content"
        ))
        .header("authorization", format!("Bearer {delegated}"))
        .header("authorization", format!("Bearer {delegated}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(duplicate_auth).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    drop(app);
    let mut revoked = context.clone();
    revoked.grants[0].revoked = true;
    let app = router(revoked);
    assert_eq!(
        app.clone()
            .oneshot(read(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    drop(app);
    let mut unscoped = context.clone();
    unscoped.grants[1].scopes = 2;
    let app = router(unscoped);
    assert_eq!(
        app.clone()
            .oneshot(read(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    drop(app);
    let mut stale = context.clone();
    stale.observed_at = now - 6000;
    let app = router(stale);
    assert_eq!(
        app.clone()
            .oneshot(read(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    drop(app);
    std::fs::write(root.join("artifacts").join(id), b"tampered").unwrap();
    let app = router(context);
    assert_eq!(
        app.clone()
            .oneshot(upload(&delegated, "delegated_key_1234", &digest))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        app.clone()
            .oneshot(read(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    std::fs::write(root.join("artifacts").join(id), input).unwrap();
    assert_eq!(
        app.clone()
            .oneshot(read(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn acquisition_validates_authority_and_constraints_before_closed_resource_gate() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, human, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 1033;
    }
    let root = std::env::temp_dir().join(format!("la-acquire-http-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let valid = serde_json::json!({"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":120000,"requested_tenure_ms":600000});
    let call = |value: &Value, token: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/assignments")
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", "acquire_test_key_001")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    };
    let response = app.clone().oneshot(call(&valid, &human)).await.unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let error: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["error"]["code"], "evidence_invalid");
    let mut provider = valid.clone();
    provider["provider_id"] = "colab".into();
    let response = app.clone().oneshot(call(&provider, &human)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["error"]["code"], "provider_unconfigured");
    let mut queued = valid.clone();
    queued["queue_policy"] = "fair_queue".into();
    assert_eq!(
        app.clone()
            .oneshot(call(&queued, &human))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_IMPLEMENTED
    );
    let response = app
        .clone()
        .oneshot(call(
            &provider,
            "incorrect-secret-at-least-thirty-two-bytes",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let mut malformed = valid.clone();
    malformed.as_object_mut().unwrap().remove("resource_id");
    assert_eq!(
        app.clone()
            .oneshot(call(&malformed, &human))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut over = valid.clone();
    over["resources"]["ram_bytes"] = (16 * 1024 * 1024 + 1).into();
    assert_eq!(
        app.clone()
            .oneshot(call(&over, &human))
            .await
            .unwrap()
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    let duplicate = Request::builder()
        .method("POST")
        .uri("/v1/diffuser/projects/project_12345678/assignments")
        .header("authorization", format!("Bearer {human}"))
        .header("idempotency-key", "acquire_test_key_001")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"schema_version":"diffuser-lane/v1","schema_version":"diffuser-lane/v1"}"#,
        ))
        .unwrap();
    let response = app.clone().oneshot(duplicate).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"]["code"], "duplicate_member");
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        0
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_artifact_uploads_do_not_split_one_idempotency_key() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    let root = std::env::temp_dir().join(format!("la-artifact-race-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let stores: Vec<_> = (0..2)
        .map(|_| super::la_artifacts::ArtifactStore::open(&root).unwrap())
        .collect();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for (index, store) in stores.into_iter().enumerate() {
        let context = context.clone();
        let token = token.clone();
        let root = root.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let state = Spine {
                root,
                edge: false,
                worker_ports: [0, 0],
                admin: false,
                sequence: Arc::new(Mutex::new(0)),
            };
            let router = api_with_namespace(
                state,
                super::lane_assignment::injected_service_router(context, store),
            );
            let body: &'static [u8] = if index == 0 {
                b"race body one"
            } else {
                b"race body two"
            };
            let digest = hex::encode(Sha256::digest(body));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            barrier.wait();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let request = Request::builder()
                    .method("POST")
                    .uri("/v1/diffuser/projects/project_12345678/artifacts")
                    .header("authorization", format!("Bearer {token}"))
                    .header("idempotency-key", "racing_key_123456")
                    .header("x-diffuser-schema", "diffuser-artifact/v1")
                    .header("x-content-sha256", &digest)
                    .header("content-type", "application/octet-stream")
                    .header("content-length", body.len().to_string())
                    .body(Body::from(body))
                    .unwrap();
                let status = runtime
                    .block_on(router.clone().oneshot(request))
                    .unwrap()
                    .status();
                if status != StatusCode::SERVICE_UNAVAILABLE {
                    break status;
                }
                assert!(Instant::now() < deadline, "storage lock did not settle");
                std::thread::sleep(Duration::from_millis(2));
            }
        }));
    }
    let mut statuses: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().as_u16())
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409]);
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        1
    );
    let db = rusqlite::Connection::open(root.join("lane_assignments.sqlite")).unwrap();
    let counts: (i64,i64,i64) = db.query_row("SELECT (SELECT COUNT(*) FROM la_artifacts),(SELECT COUNT(*) FROM la_artifact_idempotency),(SELECT COUNT(*) FROM la_artifact_provenance)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
    assert_eq!(counts, (1, 1, 1));
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn artifact_upload_rechecks_authority_after_slow_body() {
    use sha2::{Digest, Sha256};
    use std::{
        io::{Read, Write},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    context.freshness_ms = 600;
    let root = std::env::temp_dir().join(format!("la-slow-upload-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });
    let result = tokio::task::spawn_blocking(move || {
        let digest = hex::encode(Sha256::digest(b"ab"));
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        write!(socket, "POST /v1/diffuser/projects/project_12345678/artifacts HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nIdempotency-Key: slow_upload_key_001\r\nX-Diffuser-Schema: diffuser-artifact/v1\r\nX-Content-SHA256: {digest}\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nConnection: close\r\n\r\na").unwrap();
        socket.flush().unwrap();
        std::thread::sleep(Duration::from_millis(900));
        socket.write_all(b"b").unwrap();
        let mut response = Vec::new();
        socket.take(65537).read_to_end(&mut response).unwrap();
        response
    }).await.unwrap();
    let _ = stop.send(());
    server.await.unwrap();
    let head = result.split(|v| *v == b'\n').next().unwrap();
    assert!(
        head.starts_with(b"HTTP/1.1 412"),
        "unexpected status: {}",
        String::from_utf8_lossy(head)
    );
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        0
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn authenticated_routes_observe_revocation_without_restarting_controller() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, human, delegated) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    let root = std::env::temp_dir().join(format!("la-live-authority-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let authority = Arc::new(std::sync::RwLock::new(context));
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router_shared(
            authority.clone(),
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let request = |token: &str| {
        Request::builder()
            .uri("/v1/diffuser/discovery")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request(&human)).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let frame = serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1", "sequence":1, "observed_at":now, "revoked":["grant_root123456"]})).unwrap();
    super::lane_assignment::apply_authority_observation(&authority, &frame).unwrap();
    assert!(super::lane_assignment::apply_authority_observation(&authority, &frame).is_err());
    for invalid in [
        serde_json::json!({"schema_version":"diffuser-authority-observation/v1", "sequence":2, "observed_at":now + 60_000, "revoked":[]}),
        serde_json::json!({"schema_version":"diffuser-authority-observation/v1", "sequence":2, "observed_at":now, "revoked":["unknown_grant_123"]}),
        serde_json::json!({"schema_version":"diffuser-authority-observation/v1", "sequence":2, "observed_at":now, "revoked":["grant_leaf123456", "grant_leaf123456"]}),
    ] {
        assert!(super::lane_assignment::apply_authority_observation(
            &authority,
            &serde_json::to_vec(&invalid).unwrap()
        )
        .is_err());
    }
    let empty = serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1", "sequence":2, "observed_at":now, "revoked":[]})).unwrap();
    super::lane_assignment::apply_authority_observation(&authority, &empty).unwrap();
    assert!(authority.read().unwrap().grants[0].revoked);
    assert_eq!(
        app.clone().oneshot(request(&human)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(request(&delegated))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn revocation_during_artifact_transfer_prevents_publication() {
    use sha2::{Digest, Sha256};
    use std::{
        io::{Read, Write},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    let root = std::env::temp_dir().join(format!("la-revoke-upload-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let authority = Arc::new(std::sync::RwLock::new(context));
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router_shared(
            authority.clone(),
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let client = tokio::task::spawn_blocking(move || {
        let digest = hex::encode(Sha256::digest(b"ab"));
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(socket, "POST /v1/diffuser/projects/project_12345678/artifacts HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nIdempotency-Key: revoke_upload_key01\r\nX-Diffuser-Schema: diffuser-artifact/v1\r\nX-Content-SHA256: {digest}\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").unwrap();
        socket.flush().unwrap();
        let mut interim = Vec::new();
        while !interim.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            socket.read_exact(&mut byte).unwrap();
            interim.push(byte[0]);
            assert!(interim.len() <= 1024);
        }
        assert!(interim.starts_with(b"HTTP/1.1 100"));
        socket.write_all(b"a").unwrap();
        started_tx.send(()).unwrap();
        resume_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        socket.write_all(b"b").unwrap();
        let mut response = Vec::new();
        socket.take(65537).read_to_end(&mut response).unwrap();
        response
    });
    tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(3)).unwrap())
        .await
        .unwrap();
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let frame = serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1", "sequence":1, "observed_at":observed_at, "revoked":["grant_root123456"]})).unwrap();
    super::lane_assignment::apply_authority_observation(&authority, &frame).unwrap();
    resume_tx.send(()).unwrap();
    let response = client.await.unwrap();
    let _ = stop.send(());
    server.await.unwrap();
    let head = response.split(|v| *v == b'\n').next().unwrap();
    assert!(
        head.starts_with(b"HTTP/1.1 401"),
        "unexpected status: {}",
        String::from_utf8_lossy(head)
    );
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        0
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn artifact_upload_rechecks_authority_after_waiting_for_sqlite_writer() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    context.freshness_ms = 600;
    let root = std::env::temp_dir().join(format!("la-sqlite-wait-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let dbpath = root.join("lane_assignments.sqlite");
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let db = rusqlite::Connection::open(dbpath).unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(900));
        db.execute_batch("COMMIT").unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let body = b"bounded input";
    let request = Request::builder()
        .method("POST")
        .uri("/v1/diffuser/projects/project_12345678/artifacts")
        .header("authorization", format!("Bearer {token}"))
        .header("idempotency-key", "writer_wait_key_001")
        .header("x-diffuser-schema", "diffuser-artifact/v1")
        .header("x-content-sha256", hex::encode(Sha256::digest(body)))
        .header("content-type", "application/octet-stream")
        .body(Body::from(body.as_slice()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    blocker.join().unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        0
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn artifact_upload_denies_access_expiring_while_sqlite_is_busy() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
        grant.access_expires = now + 600;
    }
    let root =
        std::env::temp_dir().join(format!("la-expiring-access-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let dbpath = root.join("lane_assignments.sqlite");
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let db = rusqlite::Connection::open(dbpath).unwrap();
        db.execute_batch("BEGIN IMMEDIATE").unwrap();
        locked_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(900));
        db.execute_batch("COMMIT").unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let body = b"bounded input";
    let request = Request::builder()
        .method("POST")
        .uri("/v1/diffuser/projects/project_12345678/artifacts")
        .header("authorization", format!("Bearer {token}"))
        .header("idempotency-key", "access_wait_key_001")
        .header("x-diffuser-schema", "diffuser-artifact/v1")
        .header("x-content-sha256", hex::encode(Sha256::digest(body)))
        .header("content-type", "application/octet-stream")
        .body(Body::from(body.as_slice()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    blocker.join().unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        0
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn artifact_http_enforces_actual_and_declared_byte_limits() {
    use sha2::{Digest, Sha256};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    let root = std::env::temp_dir().join(format!("la-upload-bounds-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let make = |body: Vec<u8>, declared: Option<usize>, key: &str| {
        let digest = hex::encode(Sha256::digest(&body));
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/artifacts")
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", key)
            .header("x-diffuser-schema", "diffuser-artifact/v1")
            .header("x-content-sha256", digest)
            .header("content-type", "application/octet-stream");
        if let Some(length) = declared {
            request = request.header("content-length", length.to_string());
        }
        request.body(Body::from(body)).unwrap()
    };
    let max = vec![0x5a; 1_048_576];
    let response = app
        .clone()
        .oneshot(make(max.clone(), Some(max.len()), "bounded_key_123456"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let receipt: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = receipt["object_id"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/diffuser/projects/project_12345678/artifacts/{id}/content"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &axum::body::to_bytes(response.into_body(), 1_048_576)
            .await
            .unwrap()[..],
        &max
    );
    assert_eq!(
        app.clone()
            .oneshot(make(vec![0; 1_048_577], None, "oversize_key_12345"))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        app.clone()
            .oneshot(make(b"actual".to_vec(), Some(5), "mismatch_key_12345"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        1
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn ordinary_artifact_upload_validates_and_remains_closed_without_opening_store() {
    use sha2::{Digest, Sha256};
    let root = std::env::temp_dir().join(format!("la-ordinary-upload-{}", std::process::id()));
    assert!(!root.exists());
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: true,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api(state);
    let body = b"bounded ordinary input";
    let request = |digest: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/artifacts")
            .header("idempotency-key", "ordinary_upload_001")
            .header("x-diffuser-schema", "diffuser-artifact/v1")
            .header("x-content-sha256", digest)
            .header("content-type", "application/octet-stream")
            .header("content-length", body.len().to_string())
            .body(Body::from(body.as_slice()))
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(request(&hex::encode(Sha256::digest(body))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["error"]["code"], "routing_closed");
    assert_eq!(
        app.oneshot(request(&"0".repeat(64)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(!root.exists());
}

#[tokio::test]
async fn ordinary_acquire_is_validated_and_closed_without_claim_side_effects() {
    let root = std::env::temp_dir().join(format!("la-ordinary-acquire-{}", std::process::id()));
    assert!(!root.exists());
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: true,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api(state);
    let valid = serde_json::json!({"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":120000,"requested_tenure_ms":600000});
    let request = |value: &Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/assignments")
            .header("idempotency-key", "ordinary_acquire_001")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    };
    let response = app.clone().oneshot(request(&valid)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["error"]["code"], "routing_closed");
    let mut invalid = valid;
    invalid.as_object_mut().unwrap().remove("resource_id");
    assert_eq!(
        app.oneshot(request(&invalid)).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert!(!root.exists());
}

#[tokio::test]
async fn submit_validates_request_and_authority_but_does_not_admit_unqualified_work() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 1153;
    }
    let root = std::env::temp_dir().join(format!("la-submit-closed-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let valid = serde_json::json!({"schema_version":"diffuser-lane/v1", "client_job_id":"client_job_000001", "capability":"artifact.inspect.sha256/v1", "profile_version":"1", "input_artifact_ids":["artifact_input_001"], "parameters":{}, "max_runtime_ms":10000, "disconnect_policy":"continue_until_job_deadline"});
    let request = |value: &Value, bearer: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/assignments/assignment_000001/jobs")
            .header("authorization", format!("Bearer {bearer}"))
            .header("idempotency-key", "submit_test_key_001")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(request(&valid, &token))
            .await
            .unwrap()
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        app.clone()
            .oneshot(request(
                &valid,
                "unknown-token-with-more-than-thirty-two-bytes"
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut bad = valid.clone();
    bad["input_artifact_ids"] = serde_json::json!([]);
    assert_eq!(
        app.clone()
            .oneshot(request(&bad, &token))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut long = valid;
    long["max_runtime_ms"] = 10001.into();
    let response = app.clone().oneshot(request(&long, &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"]["code"], "runtime_limit_exceeded");
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        0
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn assignment_and_job_status_and_close_require_auth_while_store_is_unavailable() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 849;
    }
    let root = std::env::temp_dir().join(format!("la-status-close-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let read = |path: &str, bearer: &str| {
        Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap()
    };
    for path in [
        "/v1/diffuser/projects/project_12345678/assignments/assignment_000001",
        "/v1/diffuser/projects/project_12345678/jobs/job_123456789012",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(read(path, "invalid-token-with-at-least-thirty-two-bytes"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(read(path, &token))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let close = |path: &str, bearer: &str, body: &'static str| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .header("idempotency-key", "close_test_key_001")
            .body(Body::from(body))
            .unwrap()
    };
    for path in [
        "/v1/diffuser/projects/project_12345678/assignments/assignment_000001/release",
        "/v1/diffuser/projects/project_12345678/jobs/job_123456789012/cancel",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(close(
                    path,
                    "invalid-token-with-at-least-thirty-two-bytes",
                    r#"{"schema_version":"diffuser-lane/v1","expected_revision":1}"#
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            app.clone()
                .oneshot(close(
                    path,
                    &token,
                    r#"{"schema_version":"diffuser-lane/v1","expected_revision":1}"#
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            app.clone()
                .oneshot(close(
                    path,
                    &token,
                    r#"{"schema_version":"diffuser-lane/v1","unexpected":1}"#
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        std::fs::read_dir(root.join("artifacts")).unwrap().count(),
        0
    );
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn queued_request_cancellation_is_explicitly_unsupported_after_authorization() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 65;
    }
    let root = std::env::temp_dir().join(format!("la-no-queue-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    let request = |bearer: &str| {
        Request::builder().method("POST").uri("/v1/diffuser/projects/project_12345678/assignment-requests/request_123456789/cancel")
        .header("authorization", format!("Bearer {bearer}"))
        .header("idempotency-key", "queue_cancel_key_01")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"schema_version":"diffuser-lane/v1","expected_revision":1}"#)).unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(request("wrong-token-with-more-than-thirty-two-bytes"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = app.clone().oneshot(request(&token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"]["code"], "unsupported_operation");
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn injected_get_routes_do_not_implicitly_support_head() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, token, _) = fixture_discovery_context(now);
    for grant in &mut context.grants {
        grant.scopes = 7;
    }
    let root = std::env::temp_dir().join(format!("la-head-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::injected_service_router(
            context,
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
        ),
    );
    for path in [
        "/v1/diffuser/discovery",
        "/v1/diffuser/projects/project_12345678/artifacts/artifact_12345678",
        "/v1/diffuser/projects/project_12345678/artifacts/artifact_12345678/content",
    ] {
        let request = Request::builder()
            .method("HEAD")
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    drop(app);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_refuses_wrong_input_digest_before_recording_work_start() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "la-worker-input-check-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let good = b"expected immutable input";
    let digest = hex::encode(Sha256::digest(good));
    let mut journal =
        super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
    assert_eq!(
        journal.inspect_once(
            "operation_123456",
            "job_123456789012",
            b"tampered",
            &digest,
            Instant::now() + Duration::from_secs(2),
            || false
        ),
        Err("artifact_invalid")
    );
    assert_eq!(journal.start_count("operation_123456").unwrap(), 0);
    let report = journal
        .inspect_once(
            "operation_123456",
            "job_123456789012",
            good,
            &digest,
            Instant::now() + Duration::from_secs(2),
            || false,
        )
        .unwrap();
    let report: Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(report["sha256"], digest);
    assert_eq!(journal.start_count("operation_123456").unwrap(), 1);
    drop(journal);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_history_limit_keeps_tombstones_and_rejects_new_records_after_reopen() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("la-worker-history-{}-{unique}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let digest = "a".repeat(64);
    let mut journal =
        super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
    for index in 0..32 {
        journal
            .stop_before_start(
                &format!("operation_{index:08}"),
                "job_123456789012",
                &digest,
            )
            .unwrap();
    }
    assert_eq!(
        journal.stop_before_start("operation_overflow", "job_123456789012", &digest),
        Err("storage_unavailable")
    );
    assert!(journal
        .stop_before_start("operation_00000000", "job_123456789012", &digest)
        .is_ok());
    drop(journal);
    let mut reopened =
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 32)
            .unwrap();
    assert!(reopened
        .stop_before_start("operation_00000000", "job_123456789012", &digest)
        .is_ok());
    assert_eq!(
        reopened.stop_before_start("operation_overflow", "job_123456789012", &digest),
        Err("storage_unavailable")
    );
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_retry_does_not_accept_changed_bytes_under_same_digest() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "la-worker-retry-bytes-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let input = b"original input";
    let digest = hex::encode(Sha256::digest(input));
    let mut journal =
        super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
    let report = journal
        .inspect_once(
            "operation_123456",
            "job_123456789012",
            input,
            &digest,
            Instant::now() + Duration::from_secs(2),
            || false,
        )
        .unwrap();
    assert_eq!(
        journal.inspect_once(
            "operation_123456",
            "job_123456789012",
            b"changed input",
            &digest,
            Instant::now() + Duration::from_secs(2),
            || false
        ),
        Err("artifact_invalid")
    );
    assert_eq!(journal.start_count("operation_123456").unwrap(), 1);
    assert_eq!(
        journal
            .inspect_once(
                "operation_123456",
                "job_123456789012",
                input,
                &digest,
                Instant::now() + Duration::from_secs(2),
                || false
            )
            .unwrap(),
        report
    );
    drop(journal);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_reopen_rejects_semantically_corrupt_operation_history() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for case in 0..4 {
        let root = std::env::temp_dir().join(format!(
            "la-worker-corrupt-{}-{unique}-{case}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("worker.sqlite");
        let input = b"immutable worker input";
        let digest = hex::encode(Sha256::digest(input));
        let mut journal =
            super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
        let valid_report = journal
            .inspect_once(
                "operation_123456",
                "job_123456789012",
                input,
                &digest,
                Instant::now() + Duration::from_secs(2),
                || false,
            )
            .unwrap();
        drop(journal);
        let db = rusqlite::Connection::open(&path).unwrap();
        match case {
            0 => {
                db.execute("UPDATE operations SET op='bad/path'", [])
                    .unwrap();
            }
            1 => {
                db.execute("UPDATE operations SET input_digest='invalid'", [])
                    .unwrap();
            }
            2 => {
                let fake = serde_json::json!({"schema_version":"diffuser-artifact/v1", "sha256":"0".repeat(64), "bytes":input.len(), "capability":"artifact.inspect.sha256/v1", "profile_id":"cpu-artifact-inspect/v1", "profile_version":"1", "job_id":"job_123456789012"});
                db.execute(
                    "UPDATE operations SET report=?1",
                    [serde_json::to_vec(&fake).unwrap()],
                )
                .unwrap();
            }
            _ => {
                db.execute("UPDATE operations SET state='unknown'", [])
                    .unwrap();
            }
        }
        drop(db);
        assert!(
            super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 1, 1)
                .is_err(),
            "corrupt history case {case}"
        );
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute(
            "UPDATE operations SET op='operation_123456',input_digest=?1,report=?2,state='complete'",
            rusqlite::params![digest, valid_report],
        )
        .unwrap();
        drop(db);
        assert!(
            super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 1, 1)
                .is_err(),
            "detected corruption must remain quarantined after bytes are restored"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn worker_inventory_client_rejects_noncanonical_loopback_before_connecting() {
    for address in ["127.0.0.2:1", "0.0.0.0:1", "[::1]:1", "127.0.0.1:0"] {
        assert_eq!(
            super::la_adapter::fetch_inventory(
                address.parse().unwrap(),
                "synthetic-token-with-at-least-thirty-two-bytes",
                "worker_123456789",
                "worker_boot_12345"
            ),
            Err("evidence_invalid"),
            "address {address}"
        );
    }
}

#[tokio::test]
async fn duplicate_credential_identity_denies_discovery_even_with_distinct_bearer() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut context, _, token) = fixture_discovery_context(now);
    let mut conflicting = context.grants[1].clone();
    conflicting.actor = "other_actor_12345".into();
    conflicting.bearer_digest = [1; 32];
    context.grants.push(conflicting);
    let (status, body) = fixture_discovery_request(context, &[&token]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "delegation_denied");
}

#[test]
fn mandate_rejects_child_run_bound_exceeding_parent_execution_ceiling() {
    use super::la_auth::{mandate_limit, GrantBounds};
    let root = GrantBounds {
        id: "grant_root123456",
        parent: None,
        run_until: Some(8000),
        execution_ceiling: Some(4000),
    };
    let leaf = GrantBounds {
        id: "grant_leaf123456",
        parent: Some("grant_root123456"),
        run_until: Some(6000),
        execution_ceiling: Some(3000),
    };
    assert_eq!(
        mandate_limit(0, 10000, 10000, 10000, &[root, leaf]),
        Err("delegation_denied")
    );
}

#[test]
fn worker_journal_excludes_a_second_owner_and_rejects_lock_replacement() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("la-worker-owner-{}-{unique}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let mut first =
        super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
    assert!(
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 0)
            .is_err()
    );
    let lock = root.join(".worker-lock");
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&lock, b"replacement").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 0)
            .is_err()
    );
    assert!(first
        .stop_before_start("operation_123456", "job_123456789012", &"a".repeat(64))
        .is_err());
    drop(first);
    assert!(
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 0)
            .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_journal_lock_is_exclusive_across_processes_and_released_on_drop() {
    use std::{
        process::{Command, Stdio},
        time::{SystemTime, UNIX_EPOCH},
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "la-worker-lock-process-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let journal = super::la_worker::OperationJournal::bootstrap(
        &root.join("worker.sqlite"),
        "custody_12345678",
    )
    .unwrap();
    let probe = || {
        Command::new("/usr/bin/flock")
            .arg("--nonblock")
            .arg(root.join(".worker-lock"))
            .arg("/usr/bin/true")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
    };
    assert!(
        !probe().success(),
        "a separate process must not acquire a live worker lock"
    );
    drop(journal);
    assert!(
        probe().success(),
        "worker lock must release when its owner exits"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn worker_inventory_client_rejects_wrong_response_media_type() {
    use std::{
        io::{Read, Write},
        time::Duration,
    };
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = [0u8; 4096];
        let _ = stream.read(&mut request).unwrap();
        let body = r#"{"schema_version":"diffuser-worker/v1","worker_id":"worker_123456789","boot_id":"worker_boot_12345","hardware_generation":1,"profile_epoch":1,"ready":false}"#;
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    let result = super::la_adapter::fetch_inventory(
        address,
        "synthetic-token-with-at-least-thirty-two-bytes",
        "worker_123456789",
        "worker_boot_12345",
    );
    server.join().unwrap();
    assert_eq!(result, Err("evidence_invalid"));
}

#[test]
fn controller_bootstrap_refuses_scope_widening_and_noncanonical_worker_addresses() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let base = serde_json::json!({"tenant":"tenant_123456789","project":"project_12345678",
        "root_actor":"person_123456789","leaf_actor":"agent_1234567890","root_scopes":7,"leaf_scopes":7,
        "root_bearer":"1".repeat(64),"leaf_bearer":"2".repeat(64),"worker_bearer":"3".repeat(64),
        "worker_address":"127.0.0.1:1234","worker_id":"worker_cpu_000001","worker_boot_id":"4".repeat(64),
        "boot_id":"5".repeat(64),"observed_at":now,"access_expires":now+60_000,"run_until":now+60_000,"execution_ceiling":now+60_000});
    let custody = serde_json::json!({"mode":"bootstrap","store_id":"6".repeat(64),"root_dev":1,"root_inode":1,"writer_epoch":1});
    assert!(
        super::lane_assignment::validate_controller_bootstrap(base.clone(), custody.clone())
            .is_ok()
    );
    let mut widened = base.clone();
    widened["leaf_scopes"] = 8.into();
    assert!(
        super::lane_assignment::validate_controller_bootstrap(widened, custody.clone()).is_err()
    );
    let mut unknown = base.clone();
    unknown["root_scopes"] = 4096.into();
    assert!(
        super::lane_assignment::validate_controller_bootstrap(unknown, custody.clone()).is_err()
    );
    for address in ["127.0.0.2:1234", "[::1]:1234", "127.0.0.1:0"] {
        let mut invalid = base.clone();
        invalid["worker_address"] = address.into();
        assert!(
            super::lane_assignment::validate_controller_bootstrap(invalid, custody.clone())
                .is_err()
        );
    }
}

#[test]
fn worker_corrupt_database_stays_quarantined_after_bytes_are_restored() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "la-worker-db-corrupt-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("worker.sqlite");
    let journal = super::la_worker::OperationJournal::bootstrap(&path, "custody_12345678").unwrap();
    drop(journal);
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"corrupt database bytes").unwrap();
    assert!(
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 0)
            .is_err()
    );
    std::fs::write(&path, original).unwrap();
    assert!(
        super::la_worker::OperationJournal::reopen_checked(&path, "custody_12345678", 0, 0)
            .is_err(),
        "restoring database bytes must not silently clear detected corruption"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
mod bridge_v2_integration {

    use std::{
        ffi::c_void,
        fs::{self, File},
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd},
        time::{Duration, Instant},
    };

    #[repr(C)]
    struct Iov {
        base: *mut c_void,
        len: usize,
    }
    #[repr(C)]
    struct Msg {
        name: *mut c_void,
        namelen: u32,
        iov: *mut Iov,
        iovlen: usize,
        control: *mut c_void,
        controllen: usize,
        flags: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Cmsg {
        len: usize,
        level: i32,
        kind: i32,
    }
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct Cred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Vfs {
        bsize: u64,
        frsize: u64,
        blocks: u64,
        bfree: u64,
        bavail: u64,
        files: u64,
        ffree: u64,
        favail: u64,
        fsid: u64,
        flag: u64,
        namemax: u64,
        spare: [i32; 6],
    }
    unsafe extern "C" {
        fn sendmsg(fd: i32, m: *const Msg, flags: i32) -> isize;
        fn recvmsg(fd: i32, m: *mut Msg, flags: i32) -> isize;
        fn setsockopt(fd: i32, level: i32, opt: i32, v: *const c_void, len: u32) -> i32;
        fn pipe2(p: *mut i32, flags: i32) -> i32;
        fn fstatvfs(fd: i32, v: *mut Vfs) -> i32;
        fn poll(p: *mut Poll, n: usize, ms: i32) -> i32;
        fn getrandom(p: *mut u8, n: usize, flags: u32) -> isize;
        fn getuid() -> u32;
    }
    #[repr(C)]
    struct Poll {
        fd: i32,
        events: i16,
        revents: i16,
    }
    fn err() -> String {
        std::io::Error::last_os_error().to_string()
    }
    fn jsonstr(s: &str, k: &str) -> String {
        let marker = format!("\"{}\":\"", k);
        let p = s
            .find(&marker)
            .unwrap_or_else(|| panic!("missing field {k}"))
            + marker.len();
        let t = &s[p..];
        let end = t.find('"').unwrap();
        assert!(!t[..end].contains('\\'));
        t[..end].to_string()
    }
    fn jsonnum(s: &str, k: &str) -> u64 {
        let marker = format!("\"{}\":", k);
        let p = s.find(&marker).unwrap() + marker.len();
        let t = &s[p..];
        t.chars()
            .take_while(|x| x.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap()
    }
    fn randomhex() -> String {
        let mut b = [0u8; 32];
        assert_eq!(unsafe { getrandom(b.as_mut_ptr(), b.len(), 0) }, 32);
        b.iter().map(|v| format!("{v:02x}")).collect()
    }
    fn capacity(f: &File) -> u64 {
        let mut v = Vfs::default();
        assert_eq!(unsafe { fstatvfs(f.as_raw_fd(), &mut v) }, 0);
        v.blocks * v.frsize
    }
    #[derive(Clone, Copy)]
    pub enum Op {
        Hello,
        StartK,
        StartW,
        KillW,
        ReobserveLoss,
        ReobserveReturn,
        ObserveAdmission,
        StopReturnedRoles,
        RestartW,
        WaitOomW,
        StartC,
        KillC,
        RestartC,
        Observe,
        Connect,
        StopW,
        StopC,
        StopK,
        Done,
    }
    #[derive(Clone, Copy)]
    pub enum Role {
        P,
        K,
        W,
        C,
    }
    pub struct Bridge {
        seq: u32,
        host_cred: Option<Cred>,
        total: usize,
        nonce: String,
    }
    impl Bridge {
        pub fn new() -> Self {
            let one = 1i32;
            assert_eq!(unsafe { setsockopt(3, 1, 16, &one as *const _ as _, 4) }, 0);
            Self {
                seq: 0,
                host_cred: None,
                total: 0,
                nonce: std::env::var("DIFFUSER_LA_BRIDGE_NONCE").unwrap(),
            }
        }
        pub fn call(
            &mut self,
            op: Op,
            role: Role,
            arg: u16,
            rights: &[i32],
        ) -> (String, Vec<File>) {
            let op = match op {
                Op::Hello => "HELLO",
                Op::StartK => "START_K",
                Op::StartW => "START_W",
                Op::KillW => "KILL_W",
                Op::ReobserveLoss => "REOBSERVE_LOSS",
                Op::ReobserveReturn => "REOBSERVE_RETURN",
                Op::ObserveAdmission => "LOSS_ADMISSION_OBSERVE",
                Op::StopReturnedRoles => "STOP_RETURNED_ROLES",
                Op::RestartW => "RESTART_W",
                Op::WaitOomW => "WAIT_OOM_W",
                Op::StartC => "START_C",
                Op::KillC => "KILL_C",
                Op::RestartC => "RESTART_C",
                Op::Observe => "OBSERVE",
                Op::Connect => "CONNECT",
                Op::StopW => "STOP_W",
                Op::StopC => "STOP_C",
                Op::StopK => "STOP_K",
                Op::Done => "DONE",
            };
            let role = match role {
                Role::P => "P",
                Role::K => "K",
                Role::W => "W",
                Role::C => "C",
            };
            self.seq += 1;
            assert!(self.seq <= 32 && rights.len() <= 1);
            let text = format!("B2 {} {} {op} {role} {arg}", self.nonce, self.seq);
            let mut iov = Iov {
                base: text.as_ptr() as _,
                len: text.len(),
            };
            let mut ctrl = [0u64; 4];
            let mut m = Msg {
                name: std::ptr::null_mut(),
                namelen: 0,
                iov: &mut iov,
                iovlen: 1,
                control: std::ptr::null_mut(),
                controllen: 0,
                flags: 0,
            };
            if !rights.is_empty() {
                unsafe {
                    let h = ctrl.as_mut_ptr() as *mut Cmsg;
                    *h = Cmsg {
                        len: 20,
                        level: 1,
                        kind: 1,
                    };
                    *(ctrl.as_mut_ptr().cast::<u8>().add(16) as *mut i32) = rights[0];
                }
                m.control = ctrl.as_mut_ptr() as _;
                m.controllen = 24;
            }
            assert_eq!(
                unsafe { sendmsg(3, &m, 0x4000) },
                text.len() as isize,
                "send: {}",
                err()
            );
            let mut b = vec![0u8; 65536];
            let mut anc = [0u64; 32];
            let mut io = Iov {
                base: b.as_mut_ptr() as _,
                len: b.len(),
            };
            let mut rm = Msg {
                name: std::ptr::null_mut(),
                namelen: 0,
                iov: &mut io,
                iovlen: 1,
                control: anc.as_mut_ptr() as _,
                controllen: std::mem::size_of_val(&anc),
                flags: 0,
            };
            let mut p = Poll {
                fd: 3,
                events: 1,
                revents: 0,
            };
            assert!(
                unsafe { poll(&mut p, 1, 8000) } > 0,
                "bridge response timeout"
            );
            let n = unsafe { recvmsg(3, &mut rm, 0x40000000) };
            assert!(n > 0, "bridge EOF: {}", err());
            assert_eq!(rm.flags & 0x28, 0, "ancillary truncation");
            self.total += n as usize;
            assert!(self.total <= 1048576);
            let mut fds = vec![];
            let mut cred = None;
            let mut at = 0;
            while at + 16 <= rm.controllen {
                let h = unsafe { *(anc.as_ptr().cast::<u8>().add(at) as *const Cmsg) };
                assert!(h.len >= 16 && at + h.len <= rm.controllen && h.level == 1);
                if h.kind == 1 {
                    assert!((h.len - 16) % 4 == 0);
                    for off in (16..h.len).step_by(4) {
                        let f = unsafe { *(anc.as_ptr().cast::<u8>().add(at + off) as *const i32) };
                        fds.push(unsafe { File::from_raw_fd(f) });
                    }
                } else if h.kind == 2 {
                    assert_eq!(h.len, 28);
                    assert!(cred.is_none());
                    cred =
                        Some(unsafe { *(anc.as_ptr().cast::<u8>().add(at + 16) as *const Cred) });
                } else {
                    panic!("unexpected ancillary kind")
                }
                at += (h.len + 7) & !7;
            }
            let c = cred.expect("SCM_CREDENTIALS required");
            assert_eq!(c.uid, unsafe { getuid() });
            if let Some(old) = self.host_cred {
                assert_eq!((c.pid, c.uid, c.gid), (old.pid, old.uid, old.gid));
            } else {
                self.host_cred = Some(c);
            }
            let s = String::from_utf8(b[..n as usize].to_vec()).unwrap();
            assert_eq!(jsonstr(&s, "nonce"), self.nonce);
            assert_eq!(jsonnum(&s, "seq"), self.seq as u64);
            assert_eq!(jsonnum(&s, "rights"), fds.len() as u64);
            (s, fds)
        }
    }
    // One protected pipe writer descriptor per role, shared only by threads of
    // this P. The read-only role roots never become writable P storage.
    #[derive(Clone)]
    struct SharedControl(std::sync::Arc<std::sync::Mutex<File>>);
    impl SharedControl {
        fn new(file: File) -> Self {
            Self(std::sync::Arc::new(std::sync::Mutex::new(file)))
        }
        fn frame(&mut self, prefix: &[u8], bytes: &[u8]) {
            let mut writer = self.0.lock().unwrap();
            writer.write_all(prefix).unwrap();
            writer.write_all(bytes).unwrap();
            writer.write_all(b"\n").unwrap();
        }
    }
    impl AsRawFd for SharedControl {
        fn as_raw_fd(&self) -> i32 {
            self.0.lock().unwrap().as_raw_fd()
        }
    }
    impl Write for SharedControl {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.lock().unwrap().flush()
        }
        fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.0.lock().unwrap().write_all(bytes)
        }
    }
    struct WitnessFrames {
        state_ledger: std::sync::Arc<
            std::sync::Mutex<Option<super::super::la_adapter::state_custody::Ledger>>,
        >,
        transport_ledger: std::sync::Arc<std::sync::Mutex<super::super::la_adapter::CustodyLedger>>,
        root: File,
        role: String,
        stream_id: i32,
        receive: std::sync::mpsc::Receiver<String>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl WitnessFrames {
        fn start(
            frames: Frames,
            writer: SharedControl,
            root: File,
            custody: &File,
            binding: &super::super::la_adapter::ChannelBinding,
            keys: &super::super::la_adapter::ChannelKeys,
            role: &str,
        ) -> Self {
            Self::start_with_state(
                frames, writer, root, custody, binding, keys, role, None, None,
            )
        }
        #[expect(
            clippy::too_many_arguments,
            reason = "Restart preserves the exact P state ledger."
        )]
        fn start_with_state(
            mut frames: Frames,
            mut writer: SharedControl,
            root: File,
            custody: &File,
            binding: &super::super::la_adapter::ChannelBinding,
            keys: &super::super::la_adapter::ChannelKeys,
            role: &str,
            recovered: Option<
                std::sync::Arc<
                    std::sync::Mutex<Option<super::super::la_adapter::state_custody::Ledger>>,
                >,
            >,
            recovered_transport: Option<
                std::sync::Arc<std::sync::Mutex<super::super::la_adapter::CustodyLedger>>,
            >,
        ) -> Self {
            let ledger = super::super::la_adapter::CustodyLedger::bootstrap(
                custody,
                std::path::Path::new("/job/custody"),
                binding.clone(),
                role,
                keys.reply,
                keys.custody,
            )
            .unwrap();
            let role = role.to_string();
            let state_ledger = if role == "controller" {
                Some(
                    super::super::la_adapter::state_custody::Ledger::new(
                        custody,
                        binding.clone(),
                        keys,
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let state_ledger = recovered
                .unwrap_or_else(|| std::sync::Arc::new(std::sync::Mutex::new(state_ledger)));
            let retained_state_ledger = state_ledger.clone();
            let ledger = recovered_transport
                .unwrap_or_else(|| std::sync::Arc::new(std::sync::Mutex::new(ledger)));
            let retained_transport_ledger = ledger.clone();
            let role_name = role.clone();
            static STREAM: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(10000);
            let stream_id = STREAM.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let role_root = root.try_clone().unwrap();
            let custody_root = custody.try_clone().unwrap();
            let reply_key = keys.reply;
            let custody_key = keys.custody;
            let authority_key = keys.authority;
            let protected_binding = binding.clone();
            let (send, receive) = std::sync::mpsc::sync_channel(32);
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stopped = stop.clone();
            let thread = std::thread::spawn(move || {
                use std::sync::atomic::Ordering;
                let mut previous: Option<(
                    super::super::la_adapter::SignedCheckpoint,
                    super::super::la_adapter::CheckpointAck,
                )> = None;
                let mut injected_authority: Option<Vec<u8>> = None;
                while !stopped.load(Ordering::SeqCst) {
                    let alive = frames.pump_named(std::path::Path::new("/job/evidence"), stream_id);
                    while let Some(end) = frames.buf.iter().position(|b| *b == b'\n') {
                        let line = frames.buf.drain(..=end).collect::<Vec<_>>();
                        let text = String::from_utf8(line).unwrap();
                        let Some((_, json)) = text.split_once("DIFFUSER_LA_CHILD_V1 ") else {
                            continue;
                        };
                        let value: serde_json::Value = serde_json::from_str(json.trim()).unwrap();
                        if value["kind"] == "CUSTODY_CHECKPOINT" {
                            let checkpoint: super::super::la_adapter::SignedCheckpoint =
                                serde_json::from_value(value["checkpoint"].clone()).unwrap();
                            if let Some((head, ack)) =
                                previous.as_ref().filter(|_| checkpoint.revision() == 2)
                            {
                                *ledger.lock().unwrap() =
                                    super::super::la_adapter::CustodyLedger::reopen(
                                        &custody_root,
                                        std::path::Path::new("/job/custody"),
                                        head,
                                        ack,
                                        reply_key,
                                        custody_key,
                                    )
                                    .unwrap();
                            }
                            let ack = ledger.lock().unwrap().observe(&root, &checkpoint).unwrap();
                            previous = Some((checkpoint.clone(), ack.clone()));
                            if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                                == Ok("custodyloss")
                                && role == "worker"
                                && checkpoint.revision() == 2
                            {
                                println!(
                                    "{}",
                                    serde_json::json!({"kind":"CUSTODY_ACK_WITHHELD","role":role,"revision":checkpoint.revision(),"phase":"complete","admitted_jobs":0})
                                );
                                std::io::stdout().flush().unwrap();
                                continue;
                            }
                            if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                                == Ok("authorityrace")
                                && checkpoint.revision() == 1
                            {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64;
                                let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":1,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                                let signed = super::super::la_adapter::sign_source_observation(
                                    &authority_key,
                                    &protected_binding,
                                    &canonical,
                                )
                                .unwrap();
                                writer.frame(b"AUTH ", &signed);
                                injected_authority = Some(canonical);
                                println!(
                                    "{}",
                                    serde_json::json!({"kind":"AUTHORITY_QUEUED_BEFORE_CUSTODY_ACK","role":role,"revision":1})
                                );
                                std::io::stdout().flush().unwrap();
                            }
                            let bytes = serde_json::to_vec(&ack).unwrap();
                            let mut entry=serde_json::to_vec(&serde_json::json!({"checkpoint":value["checkpoint"],"ack":ack,"independent_root_read":true,"parent_fsynced_before_ack":true,"explicit_prior_head_rechecked":checkpoint.revision()==2})).unwrap();
                            entry.push(b'\n');
                            let evidence_root = File::open("/job/evidence").unwrap();
                            let mut transcript = super::super::la_artifacts::open_artifact(
                                &evidence_root,
                                &format!("{role}-live-custody.jsonl"),
                                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                            )
                            .unwrap();
                            assert!(
                                transcript.metadata().unwrap().len() + entry.len() as u64
                                    <= 1048576
                            );
                            transcript.write_all(&entry).unwrap();
                            let mut frame = b"CUSTODY ".to_vec();
                            frame.extend(bytes);
                            frame.push(b'\n');
                            if let Err(error) = writer.write_all(&frame) {
                                println!(
                                    "{}",
                                    serde_json::json!({"kind":"CUSTODY_ACK_DELIVERY_FAILED","role":role,"error":error.to_string(),"admitted_jobs":0})
                                );
                                std::io::stdout().flush().unwrap();
                            }
                        } else if value["kind"] == "SERVICE_STATE_CHECKPOINT" {
                            let checkpoint: super::super::la_adapter::state_custody::Checkpoint =
                                serde_json::from_value(value["checkpoint"].clone()).unwrap();
                            // Bounded prospective scheduling at the real independent
                            // observer. No signed bytes or validator clock are supplied.
                            if value["checkpoint"]["body"]["phase"] == "recovery"
                                && std::env::var("DIFFUSER_LA_SERVICE_OBSERVER_TEST_DELAY")
                                    .as_deref()
                                    == Ok("fixed-400ms")
                            {
                                super::super::la_adapter::recovery_trace(
                                    "P_service_observer_schedule",
                                    serde_json::json!({"delay_ms":400,"revision":value["checkpoint"]["body"]["revision"]}),
                                );
                                std::thread::sleep(std::time::Duration::from_millis(400));
                            }
                            let ack = state_ledger
                                .lock()
                                .unwrap()
                                .as_mut()
                                .expect("controller state witness")
                                .observe(&root, &checkpoint)
                                .unwrap();
                            let mut entry=serde_json::to_vec(&serde_json::json!({"checkpoint":checkpoint,"ack":ack,"independent_root_read":true,"parent_fsynced_before_ack":true})).unwrap();
                            entry.push(b'\n');
                            let mut file = fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("/job/evidence/service-state-custody.jsonl")
                                .unwrap();
                            assert!(file.metadata().unwrap().len() + entry.len() as u64 <= 1048576);
                            file.write_all(&entry).unwrap();
                            let mut frame = b"STATE ".to_vec();
                            frame.extend(serde_json::to_vec(&ack).unwrap());
                            frame.push(b'\n');
                            if let Err(error) = writer.write_all(&frame) {
                                println!(
                                    "{}",
                                    serde_json::json!({"kind":"STATE_ACK_DELIVERY_FAILED","role":role,"error":error.to_string(),"admitted_jobs":0})
                                );
                                std::io::stdout().flush().unwrap();
                            }
                        } else if value["kind"] == "ENTERED_WORK" {
                            assert_eq!(role, "worker");
                            assert_eq!(value["worker_boot"], protected_binding.worker_boot);
                            assert_eq!(value["marker"], 1);
                            let mut event = serde_json::to_vec(&value).unwrap();
                            event.push(b'\n');
                            let mut file = fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("/job/evidence/worker-entered-work.jsonl")
                                .unwrap();
                            assert!(file.metadata().unwrap().len() + event.len() as u64 <= 32768);
                            file.write_all(&event).unwrap();
                            file.sync_all().unwrap();
                        } else if value["kind"] == "STOP_SIGNALLED" {
                            assert_eq!(role, "worker");
                            assert_eq!(value["worker_boot"], protected_binding.worker_boot);
                            let mut event = serde_json::to_vec(&value).unwrap();
                            event.push(b'\n');
                            let mut file = fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("/job/evidence/worker-stop-signalled.jsonl")
                                .unwrap();
                            assert!(file.metadata().unwrap().len() + event.len() as u64 <= 32768);
                            file.write_all(&event).unwrap();
                            file.sync_all().unwrap();
                        } else if value["kind"] == "WORK_QUIESCED" {
                            assert_eq!(role, "worker");
                            assert_eq!(value["worker_boot"], protected_binding.worker_boot);
                            assert_eq!(value["task_joined"], true);
                            let mut event = serde_json::to_vec(&value).unwrap();
                            event.push(b'\n');
                            let mut file = fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("/job/evidence/worker-quiesced.jsonl")
                                .unwrap();
                            assert!(file.metadata().unwrap().len() + event.len() as u64 <= 32768);
                            file.write_all(&event).unwrap();
                            file.sync_all().unwrap();
                        } else if value["kind"] == "ERROR" {
                            println!(
                                "{}",
                                serde_json::json!({"kind":"ROLE_REPORTED_ERROR","role":role,"frame":value})
                            );
                            std::io::stdout().flush().unwrap();
                            if send.send(json.trim().to_string()).is_err() {
                                return;
                            }
                        } else if value["kind"] == "AUTHORITY_ACK"
                            && injected_authority.is_some()
                            && value["ack"]["sequence"] == 1
                        {
                            let ack: super::super::la_adapter::SourceAck =
                                serde_json::from_value(value["ack"].clone()).unwrap();
                            super::super::la_adapter::verify_source_ack(
                                &reply_key,
                                &protected_binding,
                                &role,
                                injected_authority.as_ref().unwrap(),
                                &ack,
                            )
                            .unwrap();
                            fs::write(
                                format!("/job/evidence/{role}-authority-race-ack.json"),
                                serde_json::to_vec(&value).unwrap(),
                            )
                            .unwrap();
                            injected_authority = None;
                        } else if send.send(json.trim().to_string()).is_err() {
                            return;
                        }
                    }
                    if !alive {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            });
            Self {
                state_ledger: retained_state_ledger,
                transport_ledger: retained_transport_ledger,
                root: role_root,
                role: role_name,
                stream_id,
                receive,
                stop,
                thread: Some(thread),
            }
        }
        fn next(&mut self) -> String {
            match self.receive.recv_timeout(Duration::from_secs(5)) {
                Ok(frame) => frame,
                Err(error) => {
                    use std::os::unix::fs::MetadataExt;
                    let mut files = Vec::new();
                    if let Ok(entries) =
                        fs::read_dir(format!("/proc/self/fd/{}", self.root.as_raw_fd()))
                    {
                        for entry in entries.take(257).flatten() {
                            if let Ok(meta) = entry.metadata() {
                                files.push(serde_json::json!({"name":entry.file_name().to_string_lossy(),"bytes":meta.len(),"blocks":meta.blocks(),"dev":meta.dev(),"inode":meta.ino()}));
                            }
                        }
                    }
                    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
                    let stderr =
                        File::open(format!("/job/evidence/child-{}-stderr.raw", self.stream_id))
                            .ok()
                            .map(|f| {
                                let mut bytes = Vec::new();
                                f.take(8192).read_to_end(&mut bytes).unwrap();
                                String::from_utf8_lossy(&bytes).into_owned()
                            });
                    println!(
                        "{}",
                        serde_json::json!({"kind":"ROLE_FRAME_FAILED","role":self.role,"error":error.to_string(),"files":files,"stderr":stderr,"admitted_jobs":0})
                    );
                    std::io::stdout().flush().unwrap();
                    panic!("protected role frame: {error}");
                }
            }
        }
    }
    impl Drop for WitnessFrames {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let result = thread.join();
                if !std::thread::panicking() {
                    result.expect("P custody thread");
                } else if result.is_err() {
                    eprintln!("P custody pump failed during an already failing fixture");
                }
            }
        }
    }

    struct Frames {
        out: File,
        err: File,
        buf: Vec<u8>,
        total: usize,
        eof: [bool; 2],
    }
    impl Frames {
        fn pump_pending(&mut self) -> bool {
            self.pump_into(std::path::Path::new("/job/evidence"))
        }
        fn pump_into(&mut self, archive: &std::path::Path) -> bool {
            self.pump_named(archive, self.out.as_raw_fd())
        }
        fn pump_named(&mut self, archive: &std::path::Path, stream_id: i32) -> bool {
            // POLLHUP may accompany queued bytes on either stream. Only a
            // zero-byte read proves EOF; drain both streams before disconnect.
            for index in 0..2 {
                while !self.eof[index] {
                    let stream = if index == 0 {
                        &mut self.out
                    } else {
                        &mut self.err
                    };
                    let mut descriptor = Poll {
                        fd: stream.as_raw_fd(),
                        events: 1,
                        revents: 0,
                    };
                    assert!(unsafe { poll(&mut descriptor, 1, 0) } >= 0);
                    assert_eq!(
                        descriptor.revents & (8 | 32),
                        0,
                        "role output descriptor error"
                    );
                    if descriptor.revents & (1 | 0x10) == 0 {
                        break;
                    }
                    let mut bytes = [0; 8192];
                    let n = stream.read(&mut bytes).unwrap();
                    self.total += n;
                    assert!(self.total <= 1048576, "child output cap");
                    let name = archive.join(format!(
                        "child-{}-{}.raw",
                        stream_id,
                        if index == 0 { "stdout" } else { "stderr" }
                    ));
                    let mut file = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(name)
                        .unwrap();
                    file.write_all(&bytes[..n]).unwrap();
                    if n == 0 {
                        self.eof[index] = true;
                        break;
                    }
                    if index == 0 {
                        self.buf.extend_from_slice(&bytes[..n]);
                    }
                }
            }
            !self.eof.iter().all(|ended| *ended)
        }
        fn next(&mut self) -> String {
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(n) = self.buf.iter().position(|v| *v == b'\n') {
                    let line = self.buf.drain(..=n).collect::<Vec<_>>();
                    let s = String::from_utf8(line).unwrap();
                    if let Some(p) = s.find("DIFFUSER_LA_CHILD_V1 ") {
                        return s[p + 20..].trim().to_string();
                    }
                    continue;
                }
                assert!(Instant::now() < end, "W frame timeout");
                let alive = self.pump_pending();
                assert!(
                    alive || self.buf.contains(&b'\n'),
                    "role output EOF before frame"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
    #[test]
    fn role_output_hangup_drains_both_streams_through_eof() {
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let directory = std::env::temp_dir().join(format!("la-drain-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let (out, mut output) = UnixStream::pair().unwrap();
        let (err, mut error) = UnixStream::pair().unwrap();
        let stdout = vec![b'x'; 24576];
        let stderr = vec![b'e'; 17000];
        output.write_all(&stdout).unwrap();
        error.write_all(&stderr).unwrap();
        drop(output);
        drop(error);
        let mut frames = Frames {
            out: File::from(OwnedFd::from(out)),
            err: File::from(OwnedFd::from(err)),
            buf: Vec::new(),
            total: 0,
            eof: [false; 2],
        };
        for _ in 0..32 {
            if !frames.pump_into(&directory) {
                break;
            }
        }
        assert_eq!(
            frames.buf.len(),
            stdout.len(),
            "pending stdout was discarded on hangup"
        );
        assert!(frames.buf == stdout);
        assert_eq!(
            fs::read(directory.join(format!("child-{}-stderr.raw", frames.out.as_raw_fd())))
                .unwrap(),
            stderr
        );
        fs::remove_dir_all(directory).unwrap();
    }

    // Immutable retained rows are compared byte-for-byte across terminal Close,
    // release, new admission and a distinct job; mutable claim state is excluded.
    fn retained_original_rows(root: &File, assignment: &str, job: &str) -> String {
        use sha2::{Digest, Sha256};
        let db =
            super::super::la_store::open_pinned_readonly_database(root, "lane_assignments.sqlite")
                .unwrap();
        let mut hash = Sha256::new();
        for (table, column, value) in [
            ("la_assignment_terms", "assignment_id", assignment),
            ("la_reservation_authorizations", "assignment_id", assignment),
            ("la_idempotency", "assignment_id", assignment),
            ("la_assignment_grant_charges", "assignment_id", assignment),
            ("la_job_idempotency", "job", job),
            ("la_job_grant_charges", "job", job),
            ("la_mandates", "job", job),
            ("la_job_permit_intents", "job", job),
            ("la_job_rebound_permits", "job", job),
            ("la_job_results", "job", job),
            ("la_job_outbox", "job", job),
            ("la_jobs", "id", job),
            ("la_artifacts", "job_id", job),
        ] {
            hash.update(table.as_bytes());
            let exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name=?1)",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            if !exists {
                hash.update(b"absent");
                continue;
            }
            let mut st = db
                .prepare(&format!(
                    "SELECT * FROM {table} WHERE {column}=?1 ORDER BY rowid"
                ))
                .unwrap();
            let count = st.column_count();
            let mut rows = st.query([value]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                for col in 0..count {
                    let bytes = format!("{:?}", row.get_ref(col).unwrap()).into_bytes();
                    hash.update((bytes.len() as u64).to_be_bytes());
                    hash.update(bytes);
                }
            }
        }
        hex::encode(hash.finalize())
    }

    struct KeepHttp(File);
    impl KeepHttp {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            bearer: &str,
            key: &str,
            media: &str,
            body: &[u8],
        ) -> (u16, Vec<u8>) {
            use sha2::{Digest, Sha256};
            let timeout = libc::timeval {
                tv_sec: 3,
                tv_usec: 0,
            };
            assert_eq!(
                unsafe {
                    libc::setsockopt(
                        self.0.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&timeout as *const libc::timeval).cast(),
                        std::mem::size_of_val(&timeout) as libc::socklen_t,
                    )
                },
                0
            );
            write!(self.0,"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\nConnection: keep-alive\r\nContent-Length: {}\r\n",body.len()).unwrap();
            if method == "POST" {
                write!(
                    self.0,
                    "Content-Type: {media}\r\nIdempotency-Key: {key}\r\n"
                )
                .unwrap();
            }
            if media == "application/octet-stream" && method == "POST" {
                write!(
                    self.0,
                    "X-Diffuser-Schema: diffuser-artifact/v1\r\nX-Content-SHA256: {}\r\n",
                    hex::encode(Sha256::digest(body))
                )
                .unwrap();
            }
            self.0.write_all(b"\r\n").unwrap();
            self.0.write_all(body).unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut b = [0];
                self.0.read_exact(&mut b).unwrap();
                headers.push(b[0]);
                assert!(headers.len() <= 65536);
            }
            let text = std::str::from_utf8(&headers).unwrap();
            let status = text
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            let mut lengths = text.lines().filter_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().unwrap())
            });
            let length = lengths.next().expect("bounded fixed response length");
            assert!(lengths.next().is_none() && length <= 1048576);
            assert!(!text
                .lines()
                .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:")));
            let mut bytes = vec![0; length];
            self.0.read_exact(&mut bytes).unwrap();
            (status, bytes)
        }
        fn json(
            &mut self,
            method: &str,
            path: &str,
            bearer: &str,
            key: &str,
            body: &serde_json::Value,
        ) -> (u16, serde_json::Value) {
            let bytes = if method == "POST" {
                serde_json::to_vec(body).unwrap()
            } else {
                Vec::new()
            };
            let (status, bytes) =
                self.request(method, path, bearer, key, "application/json", &bytes);
            (status, serde_json::from_slice(&bytes).unwrap())
        }
    }
    fn http(mut f: File, token: &str) -> String {
        let req=format!("GET /v1/worker/inventory HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n");
        f.write_all(req.as_bytes()).unwrap();
        let mut b = vec![];
        f.take(1048577).read_to_end(&mut b).unwrap();
        assert!(b.len() <= 1048576);
        String::from_utf8(b).unwrap()
    }
    fn artifact_http(
        mut f: File,
        method: &str,
        path: &str,
        bearer: &str,
        body: &[u8],
    ) -> (u16, Vec<u8>) {
        use sha2::{Digest, Sha256};
        write!(f, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n").unwrap();
        if method == "POST" {
            write!(f, "Content-Type: application/octet-stream\r\nContent-Length: {}\r\nX-Diffuser-Schema: diffuser-artifact/v1\r\nX-Content-SHA256: {}\r\nIdempotency-Key: bridge_fixture_upload_001\r\n", body.len(), hex::encode(Sha256::digest(body))).unwrap();
        }
        f.write_all(b"\r\n").unwrap();
        f.write_all(body).unwrap();
        read_http_response(f)
    }
    fn read_http_response(f: File) -> (u16, Vec<u8>) {
        let mut response = Vec::new();
        f.take(65_537).read_to_end(&mut response).unwrap();
        assert!(response.len() <= 65_536);
        let split = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap();
        let headers = std::str::from_utf8(&response[..split]).unwrap();
        let status = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let lengths: Vec<_> = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .collect();
        assert_eq!(lengths.len(), 1);
        assert_eq!(
            lengths[0].1.trim().parse::<usize>().unwrap(),
            response.len() - split - 4
        );
        assert!(!headers
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("transfer-encoding:")));
        (status, response[split + 4..].to_vec())
    }
    fn unqualified_acquire_http(mut f: File, bearer: &str) -> (u16, Vec<u8>) {
        let body=br#"{"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":4000,"requested_tenure_ms":12000}"#;
        write!(f,"POST /v1/diffuser/projects/project_12345678/assignments HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nIdempotency-Key: bridge_acquire_00001\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
        f.write_all(body).unwrap();
        read_http_response(f)
    }
    // Reject a writable regular file outside the role's finite root even when
    // the mount table itself looks safe: inherited FDs can bypass that view.
    fn bounded_child_fds(snapshot: &serde_json::Value, root: &str, root_dev: u64) -> bool {
        let Some(entries) = snapshot["fds"].as_array() else {
            return false;
        };
        if entries.is_empty() {
            return false;
        }
        entries.iter().all(|entry| {
            let Some(target) = entry["target"].as_str() else {
                return false;
            };
            let Some(mode) = entry["mode"].as_u64() else {
                return false;
            };
            let Some(info) = entry["info"].as_str() else {
                return false;
            };
            let Some(_flags) = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:\t"))
                .and_then(|value| u64::from_str_radix(value.trim(), 8).ok())
            else {
                return false;
            };
            match mode & libc::S_IFMT as u64 {
                // Even a read-only file can potentially be reopened via procfs.
                kind if kind == libc::S_IFREG as u64 => {
                    entry["dev"].as_u64() == Some(root_dev)
                        && target
                            .strip_prefix(root)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                        && !target.ends_with(" (deleted)")
                }
                kind if kind == libc::S_IFDIR as u64 => {
                    // Read-only directory handles can still be used with openat.
                    entry["dev"].as_u64() == Some(root_dev)
                        && (target == root
                            || target
                                .strip_prefix(root)
                                .is_some_and(|suffix| suffix.starts_with('/')))
                }
                kind if kind == libc::S_IFCHR as u64 => target == "/dev/null",
                kind if kind == libc::S_IFIFO as u64 || kind == libc::S_IFSOCK as u64 => true,
                0 => matches!(target, "anon_inode:[eventpoll]" | "anon_inode:[eventfd]"),
                _ => false,
            }
        })
    }
    // Mount options on the mount itself, not superblock options, determine
    // whether this particular namespace can write through the mount.
    fn bounded_child_mounts(mounts: &str, root: &str, root_dev: Option<u64>) -> bool {
        let mut saw_root = false;
        let mut saw_proc = false;
        let mut saw_owned = false;
        for line in mounts.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                return false;
            };
            let fields: Vec<_> = left.split_whitespace().collect();
            let fs: Vec<_> = right.split_whitespace().collect();
            if fields.len() < 6 || fs.len() < 3 || fs[0] == "autofs" {
                return false;
            }
            let rw = fields[5].split(',').any(|option| option == "rw");
            let ro = fields[5].split(',').any(|option| option == "ro");
            if rw == ro {
                return false;
            }
            match fields[4] {
                "/" => {
                    if saw_root || !ro {
                        return false;
                    }
                    saw_root = true;
                }
                "/proc" => {
                    if saw_proc || !ro || fs[0] != "proc" {
                        return false;
                    }
                    saw_proc = true;
                }
                path if path == root => {
                    if saw_owned || !rw || fs[0] != "tmpfs" || fields[3] != "/" {
                        return false;
                    }
                    if let Some(dev) = root_dev {
                        let expected = format!("{}:{}", libc::major(dev), libc::minor(dev));
                        if fields[2] != expected {
                            return false;
                        }
                    }
                    saw_owned = true;
                }
                "/dev/null" if rw => (),
                _ if rw => return false,
                _ => (),
            }
        }
        saw_root && saw_proc && saw_owned
    }
    fn bounded_parent_mounts(mounts: &str, custody_dev: u64, evidence_dev: u64) -> bool {
        if custody_dev == evidence_dev {
            return false;
        }
        let mut root = false;
        let mut proc = false;
        let mut owned = [false; 2];
        for line in mounts.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                return false;
            };
            let fields: Vec<_> = left.split_whitespace().collect();
            let fs: Vec<_> = right.split_whitespace().collect();
            if fields.len() < 6 || fs.len() < 3 || fs[0] == "autofs" {
                return false;
            }
            let rw = fields[5].split(',').any(|v| v == "rw");
            let ro = fields[5].split(',').any(|v| v == "ro");
            if rw == ro {
                return false;
            }
            match fields[4] {
                "/" => {
                    if root || !ro {
                        return false;
                    }
                    root = true;
                }
                "/proc" => {
                    if proc || !ro || fs[0] != "proc" {
                        return false;
                    }
                    proc = true;
                }
                "/job/custody" | "/job/evidence" => {
                    let (i, dev) = if fields[4] == "/job/custody" {
                        (0, custody_dev)
                    } else {
                        (1, evidence_dev)
                    };
                    if owned[i]
                        || !rw
                        || fs[0] != "tmpfs"
                        || fields[3] != "/"
                        || fields[2] != format!("{}:{}", libc::major(dev), libc::minor(dev))
                    {
                        return false;
                    }
                    owned[i] = true;
                }
                "/dev/null" if rw => (),
                _ if rw => return false,
                _ => (),
            }
        }
        root && proc && owned.into_iter().all(|value| value)
    }
    #[test]
    fn child_mount_inventory_requires_owned_root_and_read_only_proc() {
        let good = "1 0 0:1 / / ro - tmpfs root rw\n2 1 0:2 / /proc ro - proc proc rw\n3 1 0:7 /null /dev/null rw - devtmpfs devtmpfs rw\n4 1 0:42 / /job/workerroot rw - tmpfs tmpfs rw,size=65536k\n";
        let dev = libc::makedev(0, 42);
        assert!(bounded_child_mounts(good, "/job/workerroot", Some(dev)));
        for bad in [
            good.replace("/job/workerroot", "/job/other"),
            good.replace("/proc ro", "/proc rw"),
            good.replace("/ / ro", "/ / rw"),
            good.replace("0:42", "0:43"),
            good.replace("- tmpfs tmpfs rw,size", "- ext4 tmpfs rw,size"),
            format!("{good}5 1 0:9 / /outside rw - tmpfs tmpfs rw\n"),
            format!("{good}malformed\n"),
        ] {
            assert!(
                !bounded_child_mounts(&bad, "/job/workerroot", Some(dev)),
                "{bad}"
            );
        }
    }
    #[test]
    fn parent_mount_inventory_requires_both_distinct_bounded_roots() {
        let good = "1 0 0:1 / / ro - tmpfs root rw\n2 1 0:2 / /proc ro - proc proc rw\n3 1 0:42 / /job/custody rw - tmpfs tmpfs rw\n4 1 0:43 / /job/evidence rw - tmpfs tmpfs rw\n";
        let a = libc::makedev(0, 42);
        let b = libc::makedev(0, 43);
        assert!(bounded_parent_mounts(good, a, b));
        assert!(!bounded_parent_mounts(good, a, a));
        for bad in [
            good.replace("/job/evidence", "/job/missing"),
            good.replace("/proc ro", "/proc rw"),
            good.replace("0:43", "0:44"),
            format!("{good}5 1 0:9 / /outside rw - tmpfs tmpfs rw\n"),
        ] {
            assert!(!bounded_parent_mounts(&bad, a, b));
        }
    }
    #[test]
    fn live_child_descriptor_inventory_rejects_writable_bypasses() {
        let fd = |target: &str, mode: u32, dev: u64, flags: &str| serde_json::json!({"target":target,"mode":mode,"dev":dev,"info":format!("flags:\t{flags}\n")});
        let root = "/job/workerroot";
        let valid = fd("/job/workerroot/worker.sqlite", libc::S_IFREG, 42, "02");
        assert!(bounded_child_fds(
            &serde_json::json!({"fds":[valid]}),
            root,
            42
        ));
        for unsafe_fd in [
            fd("/host/outside", libc::S_IFREG, 77, "02"),
            fd("/host/outside", libc::S_IFREG, 77, "00"),
            fd("/job/workerroot-escape/file", libc::S_IFREG, 42, "01"),
            fd(
                "/job/workerroot/worker.sqlite (deleted)",
                libc::S_IFREG,
                42,
                "02",
            ),
            fd("/host", libc::S_IFDIR, 77, "00"),
            fd("anon_inode:[io_uring]", 0, 0, "02"),
            fd("anon_inode:[pidfd]", 0, 0, "02"),
        ] {
            assert!(!bounded_child_fds(
                &serde_json::json!({"fds":[unsafe_fd]}),
                root,
                42
            ));
        }
        assert!(!bounded_child_fds(&serde_json::json!({"fds":[]}), root, 42));
    }
    fn checked_snapshot(obs: &str, role: Role, initial: bool, root_dev: Option<u64>) {
        let v: serde_json::Value = serde_json::from_str(obs).unwrap();
        let snapshot = &v["snapshot"];
        let limits = &snapshot["limits"];
        let processes: std::collections::BTreeSet<u64> = limits["cgroup.procs"]
            .as_str()
            .unwrap()
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        let members = snapshot["members"].as_array().unwrap();
        let mut bound = std::collections::BTreeSet::new();
        for member in members {
            assert_eq!(member["cgroup"], snapshot["identity"]["cgroup"]);
            assert!(
                member["starttime"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
                    > 0
            );
            let hash = member["sha256"].as_str().unwrap();
            assert!(
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            );
            assert!(bound.insert(member["pid"].as_u64().unwrap()));
        }
        assert!(!bound.is_empty() && bound == processes);
        assert!(bound.contains(&snapshot["identity"]["pid"].as_u64().unwrap()));
        let expected = match role {
            Role::P => ("100000 100000", "268435456", "64"),
            Role::K => ("25000 100000", "134217728", "16"),
            Role::W | Role::C => ("100000 100000", "536870912", "64"),
        };
        assert_eq!(limits["cpu.max"], expected.0);
        assert_eq!(limits["memory.max"], expected.1);
        assert_eq!(limits["memory.swap.max"], "0");
        assert_eq!(limits["pids.max"], expected.2);
        let memory_max: u64 = expected.1.parse().unwrap();
        for field in ["memory.current", "memory.peak"] {
            assert!(limits[field].as_str().unwrap().parse::<u64>().unwrap() <= memory_max);
        }
        assert!(
            limits["pids.current"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                <= expected.2.parse::<u64>().unwrap()
        );
        let rlimits = snapshot["rlimits"].as_str().unwrap();
        let file_limit = rlimits
            .lines()
            .find(|line| line.starts_with("Max file size "))
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(
            &file_limit[..],
            ["Max", "file", "size", "1048576", "1048576", "bytes"]
        );
        let core_limit = rlimits
            .lines()
            .find(|line| line.starts_with("Max core file size "))
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(
            &core_limit[..],
            ["Max", "core", "file", "size", "0", "0", "bytes"]
        );
        if matches!(role, Role::W | Role::C) {
            if initial {
                let mut fds: Vec<_> = snapshot["fds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v["fd"].as_str().unwrap())
                    .collect();
                fds.sort();
                assert_eq!(fds, ["0", "1", "2"]);
            }
            if !initial {
                let root = if matches!(role, Role::W) {
                    "/job/workerroot"
                } else {
                    "/job/service"
                };
                assert!(
                    bounded_child_fds(snapshot, root, root_dev.unwrap()),
                    "unbounded child descriptor: {snapshot}"
                );
                // The cgroup peak covers the entire domain; retain and check
                // the process's own resident high-water mark and thread count
                // as separate startup evidence.
                let status = snapshot["status"].as_str().unwrap();
                let field = |name: &str| -> u64 {
                    let mut lines = status.lines().filter_map(|line| line.strip_prefix(name));
                    let value = lines.next().unwrap();
                    assert!(lines.next().is_none());
                    value.split_whitespace().next().unwrap().parse().unwrap()
                };
                let rss = field("VmRSS:");
                let hwm = field("VmHWM:");
                let threads = field("Threads:");
                assert!(rss > 0 && hwm >= rss && hwm <= memory_max / 1024);
                assert!((1..=64).contains(&threads));
            }
            let root = if matches!(role, Role::W) {
                "/job/workerroot"
            } else {
                "/job/service"
            };
            assert!(bounded_child_mounts(
                snapshot["mountinfo"].as_str().unwrap(),
                root,
                root_dev
            ));
        }
    }
    fn check_parent_start_fds(hello: &str) {
        let v: serde_json::Value = serde_json::from_str(hello).unwrap();
        let entries = v["snapshot"]["fds"].as_array().unwrap();
        let mut fds: Vec<_> = entries.iter().map(|v| v["fd"].as_str().unwrap()).collect();
        fds.sort();
        assert_eq!(fds, ["0", "1", "2", "3", "4", "5"]);
        let target = |fd: &str| {
            entries.iter().find(|v| v["fd"] == fd).unwrap()["target"]
                .as_str()
                .unwrap()
        };
        assert_eq!(target("0"), "/dev/null");
        assert!(target("3").starts_with("socket:["));
        let mut roots = [target("4"), target("5")];
        roots.sort();
        assert_eq!(roots, ["/job/custody", "/job/evidence"]);
        for fd in ["4", "5"] {
            let info = entries.iter().find(|v| v["fd"] == fd).unwrap()["info"]
                .as_str()
                .unwrap();
            let flags = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:\t"))
                .unwrap();
            assert_eq!(u32::from_str_radix(flags.trim(), 8).unwrap() & 3, 0);
        }
    }
    // Pin the originally inherited output and relay descriptors and account
    // for every later parent descriptor. Root handles from K are read-only;
    // the separately checked Landlock refusal probes cover procfs reopening.
    fn bounded_parent_fds(
        initial: &serde_json::Value,
        current: &serde_json::Value,
        roots: &[(u64, u64)],
    ) -> bool {
        let (Some(before), Some(after)) = (initial.as_array(), current.as_array()) else {
            return false;
        };
        for fd in ["0", "1", "2", "3"] {
            let Some(first) = before.iter().find(|item| item["fd"] == fd) else {
                return false;
            };
            let Some(last) = after.iter().find(|item| item["fd"] == fd) else {
                return false;
            };
            if ["target", "mode", "dev", "inode"]
                .iter()
                .any(|field| first[*field] != last[*field])
            {
                return false;
            }
            let flags = |entry: &serde_json::Value| {
                entry["info"]
                    .as_str()
                    .and_then(|info| info.lines().find_map(|line| line.strip_prefix("flags:\t")))
                    .map(str::to_owned)
            };
            if flags(first).is_none() || flags(first) != flags(last) {
                return false;
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for item in after {
            let (Some(fd), Some(mode), Some(dev), Some(inode), Some(info)) = (
                item["fd"].as_str(),
                item["mode"].as_u64(),
                item["dev"].as_u64(),
                item["inode"].as_u64(),
                item["info"].as_str(),
            ) else {
                return false;
            };
            if !seen.insert(fd) {
                return false;
            }
            if ["0", "1", "2", "3"].contains(&fd) {
                continue;
            }
            let Some(flags) = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:\t"))
                .and_then(|v| u64::from_str_radix(v.trim(), 8).ok())
            else {
                return false;
            };
            match mode & libc::S_IFMT as u64 {
                kind if kind == libc::S_IFDIR as u64
                    && roots.contains(&(dev, inode))
                    && flags & 3 == 0 => {}
                kind if kind == libc::S_IFIFO as u64 => (),
                _ => return false,
            }
        }
        true
    }
    #[test]
    fn parent_descriptor_inventory_rejects_unpinned_handles() {
        let fd = |n: &str, mode: u32, dev: u64, inode: u64, flags: &str| serde_json::json!({"fd":n,"target":format!("fd-{n}"),"mode":mode,"dev":dev,"inode":inode,"info":format!("flags:\t{flags}\n")});
        let initial = serde_json::json!([
            fd("0", libc::S_IFCHR, 1, 1, "02"),
            fd("1", libc::S_IFREG, 2, 2, "01"),
            fd("2", libc::S_IFREG, 3, 3, "01"),
            fd("3", libc::S_IFSOCK, 4, 4, "02")
        ]);
        let mut current = initial.as_array().unwrap().clone();
        current.push(fd("4", libc::S_IFDIR, 42, 10, "00"));
        current.push(fd("5", libc::S_IFIFO, 16, 11, "01"));
        assert!(bounded_parent_fds(
            &initial,
            &serde_json::json!(current),
            &[(42, 10)]
        ));
        for unsafe_fd in [
            fd("6", libc::S_IFREG, 42, 12, "01"),
            fd("6", libc::S_IFDIR, 43, 10, "00"),
            fd("6", libc::S_IFDIR, 42, 10, "02"),
            fd("6", libc::S_IFSOCK, 4, 4, "02"),
        ] {
            let mut unsafe_current = current.clone();
            unsafe_current.push(unsafe_fd);
            assert!(!bounded_parent_fds(
                &initial,
                &serde_json::json!(unsafe_current),
                &[(42, 10)]
            ));
        }
        current[1]["inode"] = serde_json::json!(999);
        assert!(!bounded_parent_fds(
            &initial,
            &serde_json::json!(current),
            &[(42, 10)]
        ));
    }
    fn check_control_custody(start: &str, writer: &File) {
        use std::os::unix::fs::MetadataExt;
        let v: serde_json::Value = serde_json::from_str(start).unwrap();
        let meta = writer.metadata().unwrap();
        let child = v["snapshot"]["fds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["fd"] == "0")
            .unwrap();
        assert_eq!(child["dev"].as_u64(), Some(meta.dev()));
        assert_eq!(child["inode"].as_u64(), Some(meta.ino()));
        let host = v["host_snapshot"]["fds"].as_array().unwrap();
        assert!(!host
            .iter()
            .any(|f| f["dev"].as_u64() == Some(meta.dev())
                && f["inode"].as_u64() == Some(meta.ino())));
        let matches = fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                fs::metadata(entry.path())
                    .is_ok_and(|m| m.dev() == meta.dev() && m.ino() == meta.ino())
            })
            .count();
        assert_eq!(matches, 1, "P must retain the sole local control writer");
    }
    #[test]
    fn bridge_v2_ordinary_p_startup() {
        if std::env::var("DIFFUSER_LA_BRIDGE_P").as_deref() != Ok("1") {
            let driver = std::env::var_os("DIFFUSER_LA_BRIDGE_DRIVER").unwrap_or_else(|| "/tmp/diffuser-fixture/runtime/turn-016-bridge/fixture_driver-normal.py".into());
            let output = std::process::Command::new("/usr/bin/timeout")
                .args(["-k", "2s", "75s", "/usr/bin/python3"])
                .arg(driver)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("protected bridge driver");
            assert!(
                output.status.success(),
                "bridge driver failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.len() <= 1_048_576 && output.stderr.len() <= 1_048_576);
            let result: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("bridge result");
            assert_eq!(result["outer_rc"], 0);
            assert_eq!(result["client_result"], true);
            assert_eq!(result["cleanup"], true);
            return;
        }
        let nonce = std::env::var("DIFFUSER_LA_BRIDGE_NONCE").unwrap();
        let whash = std::env::var("DIFFUSER_LA_BRIDGE_WHASH").unwrap();
        let custody = File::open("/job/custody").unwrap();
        let evidence = File::open("/job/evidence").unwrap();
        let c = capacity(&custody);
        let e = capacity(&evidence);
        assert_eq!(c, 16777216);
        assert_eq!(e, 33554432);
        for p in [
            "/usr/.bridge-v2-write",
            "/job/.bridge-v2-write",
            "/tmp/.bridge-v2-write",
        ] {
            assert!(fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p)
                .is_err());
        }
        assert!(!std::path::Path::new("/run/user/1000/bus").exists());
        use std::os::unix::fs::MetadataExt;
        let mi = fs::read_to_string("/proc/self/mountinfo").unwrap();
        assert!(bounded_parent_mounts(
            &mi,
            custody.metadata().unwrap().dev(),
            evidence.metadata().unwrap().dev()
        ));
        let process_seal = super::super::la_worker::seal_fixture_role().unwrap();
        fs::write(
            "/job/evidence/p-process-seal.json",
            serde_json::to_vec(&process_seal).unwrap(),
        )
        .unwrap();
        let mut bridge = Bridge::new();
        let (hello, hfds) = bridge.call(Op::Hello, Role::P, 0, &[]);
        assert!(hfds.is_empty());
        assert_eq!(jsonstr(&hello, "kind"), "HELLO");
        checked_snapshot(&hello, Role::P, true, None);
        check_parent_start_fds(&hello);
        let (km, roots) = bridge.call(Op::StartK, Role::K, 0, &[]);
        assert_eq!(jsonstr(&km, "kind"), "K_STARTED");
        assert_eq!(roots.len(), 2);
        assert_eq!(capacity(&roots[0]), 67108864);
        assert_eq!(capacity(&roots[1]), 67108864);
        let st = roots[0].metadata().unwrap();
        let service_st = roots[1].metadata().unwrap();
        let custody_st = custody.metadata().unwrap();
        let evidence_st = evidence.metadata().unwrap();
        let root_identities = [
            (custody_st.dev(), custody_st.ino()),
            (evidence_st.dev(), evidence_st.ino()),
            (st.dev(), st.ino()),
            (service_st.dev(), service_st.ino()),
        ];
        let mut root_devices = [
            st.dev(),
            service_st.dev(),
            custody_st.dev(),
            evidence_st.dev(),
        ];
        root_devices.sort_unstable();
        assert!(root_devices.windows(2).all(|pair| pair[0] != pair[1]));
        let mut pipe = [-1i32; 2];
        assert_eq!(unsafe { pipe2(pipe.as_mut_ptr(), 0x80000) }, 0);
        let reader = unsafe { File::from_raw_fd(pipe[0]) };
        let writer = unsafe { File::from_raw_fd(pipe[1]) };
        let (wm, mut streams) = bridge.call(Op::StartW, Role::W, 0, &[reader.as_raw_fd()]);
        drop(reader);
        assert_eq!(jsonstr(&wm, "kind"), "W_STARTED");
        assert_eq!(streams.len(), 2);
        assert_eq!(jsonstr(&wm, "sha256"), whash);
        checked_snapshot(&wm, Role::W, true, Some(st.dev()));
        check_control_custody(&wm, &writer);
        let mut writer = SharedControl::new(writer);
        let token = randomhex();
        let boot = randomhex();
        let store = randomhex();
        let cboot = randomhex();
        let command_key = randomhex();
        let reply_key = randomhex();
        let authority_key = randomhex();
        let custody_key = randomhex();
        let source_digest = std::env::var("DIFFUSER_LA_BRIDGE_SOURCE").unwrap();
        let channel = serde_json::json!({"binding":{"worker":"worker_cpu_000001","worker_boot":boot,"controller_boot":cboot,"worker_epoch":1,"controller_epoch":1,"hardware_generation":1,"profile_epoch":1,"policy_digest":"8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e","source_digest":source_digest,"executable_digest":whash},"command_key":command_key,"reply_key":reply_key,"authority_key":authority_key,"custody_key":custody_key,"expected_high_water":0});
        let binding: super::super::la_adapter::ChannelBinding =
            serde_json::from_value(channel["binding"].clone()).unwrap();
        let keys = super::super::la_adapter::ChannelKeys::from_protected_hex(
            &command_key,
            &reply_key,
            &authority_key,
            &custody_key,
        )
        .unwrap();
        let frame=format!("{{\"protocol_version\":1,\"run_nonce\":\"{nonce}\",\"role\":\"worker\",\"root\":\"/job/workerroot\",\"policy_id\":\"runtime-short-v1\",\"policy_digest\":\"8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e\",\"expected_executable_sha256\":\"{whash}\",\"authority_material\":{{\"service_bearer\":\"{token}\",\"worker_id\":\"worker_cpu_000001\",\"boot_id\":\"{boot}\",\"hardware_generation\":1,\"profile_epoch\":1}},\"custody_manifest\":{{\"mode\":\"bootstrap\",\"worker_id\":\"worker_cpu_000001\",\"store_id\":\"{store}\",\"root_dev\":{},\"root_inode\":{},\"expected_starts\":0,\"expected_records\":0}},\"barrier_id\":null}}\n",st.dev(),st.ino());
        let mut frame_value: serde_json::Value = serde_json::from_str(&frame).unwrap();
        frame_value["authority_material"]["channel"] = channel.clone();
        serde_json::to_writer(&mut writer, &frame_value).unwrap();
        writer.write_all(b"\n").unwrap();
        drop(frame_value);
        drop(frame);
        let err = streams.pop().unwrap();
        let out = streams.pop().unwrap();
        let mut frames = Frames {
            out,
            err,
            buf: vec![],
            total: 0,
            eof: [false; 2],
        };
        let ready = frames.next();
        fs::write("/job/evidence/worker-ready.json", ready.as_bytes()).unwrap();
        assert_eq!(jsonstr(&ready, "kind"), "READY");
        assert_eq!(jsonstr(&ready, "role"), "worker");
        assert_eq!(jsonstr(&ready, "executable_sha256"), whash);
        assert_eq!(
            jsonstr(&ready, "policy_digest"),
            "8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e"
        );
        assert_eq!(jsonstr(&ready, "boot_id"), boot);
        assert_eq!(jsonstr(&ready, "store_id"), store);
        let ready_v: serde_json::Value = serde_json::from_str(&ready).unwrap();
        assert_eq!(ready_v["root_dev"].as_u64(), Some(st.dev()));
        assert_eq!(ready_v["root_inode"].as_u64(), Some(st.ino()));
        assert_eq!(ready_v["write_refusals"].as_array().unwrap().len(), 3);
        for refusal in ready_v["write_refusals"].as_array().unwrap() {
            assert!(matches!(refusal["errno"].as_i64(), Some(1 | 2 | 13 | 30)));
        }
        assert_eq!(jsonstr(&ready, "run_nonce"), nonce);
        let addr = jsonstr(&ready, "address");
        assert!(addr.starts_with("127.0.0.1:"));
        let port = addr.rsplit(':').next().unwrap().parse::<u16>().unwrap();
        fs::write("/job/evidence/ready.json", &ready).unwrap();
        let storage_result = if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
            == Ok("storage")
        {
            let marker = format!(
                "/proc/self/fd/{}/.storage-result.json",
                roots[0].as_raw_fd()
            );
            let until = Instant::now() + Duration::from_secs(12);
            loop {
                if !frames.pump_pending() {
                    bridge.call(Op::Observe, Role::P, 0, &[]);
                    panic!("worker exited before retained storage qualification");
                }
                match fs::read(&marker) {
                    Ok(bytes) => {
                        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        assert_eq!(v["kernel_errno"], libc::ENOSPC);
                        assert_eq!(v["sqlite_error"], "SQLITE_FULL");
                        assert_eq!(v["failed_row_count"], 0);
                        assert_eq!(v["retained_start_count"], 1);
                        assert_eq!(v["reopen_integrity"], "ok");
                        break Some(v);
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < until =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("storage probe marker: {e}"),
                }
            }
        } else {
            None
        };
        if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("cpu") {
            let (before, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
            assert!(rights.is_empty());
            checked_snapshot(&before, Role::W, false, Some(st.dev()));
            let started = Instant::now();
            std::thread::sleep(Duration::from_millis(1600));
            let (after, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
            let elapsed = started.elapsed();
            assert!(rights.is_empty());
            checked_snapshot(&after, Role::W, false, Some(st.dev()));
            let before: serde_json::Value = serde_json::from_str(&before).unwrap();
            let after: serde_json::Value = serde_json::from_str(&after).unwrap();
            let stat = |v: &serde_json::Value, name: &str| -> u64 {
                v["snapshot"]["limits"]["cpu.stat"]
                    .as_str()
                    .unwrap()
                    .lines()
                    .find_map(|line| line.strip_prefix(&format!("{name} ")))
                    .unwrap()
                    .parse()
                    .unwrap()
            };
            let usage = stat(&after, "usage_usec") - stat(&before, "usage_usec");
            let throttled = stat(&after, "nr_throttled") - stat(&before, "nr_throttled");
            assert!(usage > 200_000 && usage as u128 <= elapsed.as_micros() * 13 / 10);
            assert!(throttled > 0);
            std::thread::sleep(Duration::from_millis(1800));
            let stop_start = Instant::now();
            writer.write_all(b"STOP\n").unwrap();
            let stopped = frames.next();
            let stop_elapsed = stop_start.elapsed();
            let stopped: serde_json::Value = serde_json::from_str(&stopped).unwrap();
            assert_eq!(stopped["kind"], "STOPPED");
            assert_eq!(stopped["run_nonce"], nonce);
            assert_eq!(stopped["fixture_pressure_threads_joined"], 4);
            assert_eq!(stopped["fixture_pressure_timer_expired"], true);
            assert_eq!(stopped["fixture_pressure_timer_stops"], 4);
            assert!(stopped["fixture_pressure_iterations"].as_u64().unwrap() > 0);
            assert!(stop_elapsed < Duration::from_secs(2));
            drop(writer);
            bridge.call(Op::StopW, Role::W, 0, &[]);
            bridge.call(Op::StopK, Role::K, 0, &[]);
            let result = serde_json::json!({"status":"CPU_PROBE_STOPPED","ordinary_p":true,"go_sent":false,"admitted_jobs":0,"elapsed_us":elapsed.as_micros() as u64,"stop_elapsed_us":stop_elapsed.as_micros() as u64,"cpu_usage_us":usage,"throttled_periods":throttled,"before":before,"after":after,"stopped":stopped});
            fs::write(
                "/job/evidence/client-result.json",
                serde_json::to_vec(&result).unwrap(),
            )
            .unwrap();
            println!("{result}");
            bridge.call(Op::Done, Role::P, 0, &[]);
            return;
        }
        if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("memory") {
            let (outcome, rights) = bridge.call(Op::WaitOomW, Role::W, 0, &[]);
            assert!(rights.is_empty());
            let outcome: serde_json::Value = serde_json::from_str(&outcome).unwrap();
            assert_eq!(outcome["kind"], "W_OOM_KILLED");
            assert!(outcome["oom_delta"].as_u64().unwrap() > 0);
            assert!(outcome["oom_kill_delta"].as_u64().unwrap() > 0);
            assert!(outcome["max_delta"].as_u64().unwrap() > 0);
            drop(writer);
            drop(frames);
            assert_eq!(
                (
                    roots[0].metadata().unwrap().dev(),
                    roots[0].metadata().unwrap().ino()
                ),
                (st.dev(), st.ino())
            );
            bridge.call(Op::StopK, Role::K, 0, &[]);
            let result = serde_json::json!({"status":"OOM_PROBE_KILLED","ordinary_p":true,"go_sent":false,"admitted_jobs":0,"outcome":outcome});
            fs::write(
                "/job/evidence/client-result.json",
                serde_json::to_vec(&result).unwrap(),
            )
            .unwrap();
            println!("{result}");
            bridge.call(Op::Done, Role::P, 0, &[]);
            return;
        }
        for role in [Role::P, Role::K, Role::W] {
            let (obs, rights) = bridge.call(Op::Observe, role, 0, &[]);
            assert!(rights.is_empty());
            checked_snapshot(&obs, role, false, Some(st.dev()));
            if matches!(role, Role::P) {
                let initial: serde_json::Value = serde_json::from_str(&hello).unwrap();
                let current: serde_json::Value = serde_json::from_str(&obs).unwrap();
                assert!(bounded_parent_fds(
                    &initial["snapshot"]["fds"],
                    &current["snapshot"]["fds"],
                    &root_identities
                ));
            }
        }
        for root in &roots {
            assert!(fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(format!(
                    "/proc/self/fd/{}/.bridge-root-refusal",
                    root.as_raw_fd()
                ))
                .is_err());
        }
        let (_, mut fd) = bridge.call(Op::Connect, Role::W, port, &[]);
        assert_eq!(fd.len(), 1);
        let good = http(fd.pop().unwrap(), &token);
        assert!(good.starts_with("HTTP/1.1 200 "));
        let body = good.split("\r\n\r\n").nth(1).unwrap();
        assert!(body.contains("\"ready\":false"));
        let (_, mut fd) = bridge.call(Op::Connect, Role::W, port, &[]);
        let bad = http(
            fd.pop().unwrap(),
            "unrecognized-synthetic-token-with-more-than-32-bytes",
        );
        assert!(bad.starts_with("HTTP/1.1 401 "));
        let mut cpipe = [-1i32; 2];
        assert_eq!(unsafe { pipe2(cpipe.as_mut_ptr(), 0x80000) }, 0);
        let creader = unsafe { File::from_raw_fd(cpipe[0]) };
        let cwriter = unsafe { File::from_raw_fd(cpipe[1]) };
        let mut frames = WitnessFrames::start(
            frames,
            writer.clone(),
            roots[0].try_clone().unwrap(),
            &custody,
            &binding,
            &keys,
            "worker",
        );
        let (cm, mut cstreams) = bridge.call(Op::StartC, Role::C, 0, &[creader.as_raw_fd()]);
        drop(creader);
        assert_eq!(jsonstr(&cm, "kind"), "C_STARTED");
        assert_eq!(jsonstr(&cm, "sha256"), whash);
        checked_snapshot(&cm, Role::C, true, Some(service_st.dev()));
        check_control_custody(&cm, &cwriter);
        let mut cwriter = SharedControl::new(cwriter);
        assert_eq!(cstreams.len(), 2);
        let human = randomhex();
        let delegated = randomhex();
        let cnonce = randomhex();
        let cstore = randomhex();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let cmeta = roots[1].metadata().unwrap();
        let mut config = serde_json::json!({"protocol_version":1,"run_nonce":cnonce,"role":"controller","root":"/job/service","policy_id":"runtime-short-v1","policy_digest":"8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e","expected_executable_sha256":whash,
          "authority_material":{"tenant":"tenant_123456789","project":"project_12345678","root_actor":"person_123456789","leaf_actor":"agent_1234567890","root_scopes":2047,"leaf_scopes":2047,"root_bearer":human,"leaf_bearer":delegated,"worker_bearer":token,"worker_address":addr,"worker_id":"worker_cpu_000001","worker_boot_id":boot,"boot_id":cboot,"observed_at":now,"access_expires":now+60_000,"run_until":now+60_000,"execution_ceiling":now+60_000},
          "custody_manifest":{"mode":"bootstrap","store_id":cstore,"root_dev":cmeta.dev(),"root_inode":cmeta.ino(),"writer_epoch":1},"barrier_id":null});
        let mut controller_channel = channel;
        if matches!(
            std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref(),
            Ok("statecustody" | "storage")
        ) || std::path::Path::new("/qualification").exists()
        {
            controller_channel["service_genesis"] = serde_json::json!({"root_dev":cmeta.dev(),"root_inode":cmeta.ino(),"controller_boot":cboot,"controller_epoch":1,"expected_records":0});
        }
        if super::controller_recovery_case() && !super::controller_close_recovery_case() {
            config["authority_material"]["reply_barrier"] = true.into();
        }
        config["authority_material"]["channel"] = controller_channel;
        let p_authority_seed = super::super::lane_assignment::validate_controller_bootstrap(
            config["authority_material"].clone(),
            config["custody_manifest"].clone(),
        )
        .unwrap()
        .context
        .clone();
        let mut returned_roles_stopped = false;
        serde_json::to_writer(&mut cwriter, &config).unwrap();
        cwriter.write_all(b"\n").unwrap();
        let restart_config = config;
        let cerr = cstreams.pop().unwrap();
        let cout = cstreams.pop().unwrap();
        let cframes = Frames {
            out: cout,
            err: cerr,
            buf: vec![],
            total: 0,
            eof: [false; 2],
        };
        let mut cframes = WitnessFrames::start(
            cframes,
            cwriter.clone(),
            roots[1].try_clone().unwrap(),
            &custody,
            &binding,
            &keys,
            "controller",
        );
        let mut cready = cframes.next();
        let mut progress = 1u64;
        let mut artifact_progress = [0u64; 2];
        let mut progress_frames = 0u64;
        loop {
            let frame: serde_json::Value = serde_json::from_str(&cready).unwrap();
            match frame["kind"].as_str().unwrap() {
                "TRANSPORT_HISTORY_PROGRESS" => {
                    assert!(storage_result.is_some());
                    let sequence = frame["sequence"].as_u64().unwrap();
                    assert_eq!(sequence, progress + 8);
                    assert!(sequence <= 161);
                    progress = sequence;
                }
                "ARTIFACT_HISTORY_PROGRESS" => {
                    assert!(storage_result.is_some());
                    let index = match frame["stage"].as_str().unwrap() {
                        "write" => 0,
                        "read" => 1,
                        _ => panic!("unknown artifact qualification stage"),
                    };
                    let count = frame["versions"].as_u64().unwrap();
                    assert_eq!(count, artifact_progress[index] + 8);
                    assert!(count <= 32);
                    artifact_progress[index] = count;
                }
                _ => break,
            }
            assert_eq!(frame["admitted_jobs"], 0);
            progress_frames += 1;
            println!(
                "{}",
                serde_json::json!({"kind":"QUALIFICATION_PROGRESS","frame":frame})
            );
            std::io::stdout().flush().unwrap();
            let observe_progress = match frame["kind"].as_str() {
                Some("ARTIFACT_HISTORY_PROGRESS") => {
                    frame["stage"] == "write" && frame["versions"] == 32
                }
                Some("TRANSPORT_HISTORY_PROGRESS") => {
                    matches!(progress, 33 | 65 | 81 | 97 | 113 | 129 | 145 | 161)
                }
                _ => false,
            };
            if observe_progress {
                let (snapshot, rights) = bridge.call(Op::Observe, Role::C, 0, &[]);
                assert!(rights.is_empty());
                fs::write(
                    format!("/job/evidence/controller-history-progress-{progress_frames:02}.json"),
                    snapshot,
                )
                .unwrap();
            }
            cready = cframes.next();
        }
        fs::write("/job/evidence/controller-ready.json", cready.as_bytes()).unwrap();
        assert_eq!(jsonstr(&cready, "kind"), "READY");
        let transport: serde_json::Value = serde_json::from_str(&cready).unwrap();
        assert_eq!(transport["transport_probe"]["worker_boot"], boot);
        assert_eq!(transport["transport_probe"]["controller_boot"], cboot);
        let expected_transport_sequence = if storage_result.is_some() {
            161u64
        } else {
            1u64
        };
        assert_eq!(
            transport["transport_probe"]["sequence"],
            expected_transport_sequence
        );
        if storage_result.is_some() {
            assert_eq!(progress, 161);
            assert_eq!(artifact_progress, [32, 32]);
        }
        assert_eq!(transport["transport_probe"]["live_custody"], true);
        for role in ["worker", "controller"] {
            for revision in 1..=expected_transport_sequence * 2 {
                assert!(
                    fs::metadata(format!("/job/custody/{role}-witness-{revision:04}.json")).is_ok()
                );
            }
        }
        assert_eq!(
            transport["transport_probe"]["admission"],
            "resource_unqualified"
        );
        fs::write(
            "/job/evidence/controller-worker-probe.json",
            serde_json::to_vec(&transport["transport_probe"]).unwrap(),
        )
        .unwrap();
        assert_eq!(jsonstr(&cready, "role"), "controller");
        assert_eq!(jsonstr(&cready, "boot_id"), cboot);
        assert_eq!(jsonstr(&cready, "store_id"), cstore);
        assert_eq!(
            jsonstr(&cready, "policy_digest"),
            "8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e"
        );
        let cr: serde_json::Value = serde_json::from_str(&cready).unwrap();
        assert_eq!(cr["root_dev"].as_u64(), Some(cmeta.dev()));
        assert_eq!(cr["root_inode"].as_u64(), Some(cmeta.ino()));
        use sha2::{Digest, Sha256};
        assert_eq!(
            cr["worker_inventory_sha256"],
            hex::encode(Sha256::digest(body.as_bytes()))
        );
        assert_eq!(
            cr["worker_inventory_bytes"].as_u64(),
            Some(body.len() as u64)
        );
        assert_eq!(jsonstr(&cready, "run_nonce"), cnonce);
        assert_eq!(jsonstr(&cready, "executable_sha256"), whash);
        for (index, name, role) in [
            (0, "worker-channel.sqlite", "worker"),
            (1, "controller-channel.sqlite", "controller"),
        ] {
            // Each bounded complete-history attestation is a distinct P
            // operation. Report its boundary using the existing pinned,
            // read-only observation protocol, rather than leaving the relay
            // idle across both expensive verifications. No deadline changes.
            if storage_result.is_some() {
                let (_, rights) = bridge.call(Op::Observe, Role::P, 0, &[]);
                assert!(rights.is_empty());
            }
            let observation = super::super::la_adapter::observe_channel_custody(
                &roots[index],
                name,
                &binding,
                &keys.reply,
                expected_transport_sequence,
            )
            .unwrap();
            let bytes = serde_json::to_vec(&observation).unwrap();
            let mut record = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(format!("/job/custody/{role}-channel-high-water.json"))
                .unwrap();
            record.write_all(&bytes).unwrap();
            record.sync_all().unwrap();
            custody.sync_all().unwrap();
            fs::write(
                format!("/job/evidence/{role}-channel-high-water.json"),
                bytes,
            )
            .unwrap();
        }
        let caddr = jsonstr(&cready, "address");
        assert!(caddr.starts_with("127.0.0.1:"));
        let cport = caddr.rsplit(':').next().unwrap().parse::<u16>().unwrap();
        let (obs, rights) = bridge.call(Op::Observe, Role::C, 0, &[]);
        assert!(rights.is_empty());
        checked_snapshot(&obs, Role::C, false, Some(cmeta.dev()));
        // Bounded fixture fault: P closes its relay write direction while P,
        // C and W are alive. The relay must observe EOF and clean its roles.
        if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("eof") {
            assert_eq!(unsafe { libc::shutdown(3, libc::SHUT_WR) }, 0);
            std::thread::sleep(Duration::from_secs(5));
            panic!("relay failed to clean P after its EOF");
        }
        let (parent, rights) = bridge.call(Op::Observe, Role::P, 0, &[]);
        assert!(rights.is_empty());
        let initial: serde_json::Value = serde_json::from_str(&hello).unwrap();
        let current: serde_json::Value = serde_json::from_str(&parent).unwrap();
        assert!(bounded_parent_fds(
            &initial["snapshot"]["fds"],
            &current["snapshot"]["fds"],
            &root_identities
        ));
        let resource_family = if std::path::Path::new("/qualification").exists() {
            let proof_root =
                super::super::la_artifacts::open_owned_root(std::path::Path::new("/qualification"))
                    .unwrap();
            let family = super::super::la_adapter::qualification::VerifiedResourceFamily::inspect(
                &proof_root,
                &binding.source_digest,
                &whash,
            )
            .expect("protected resource family predicates");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let certificate = family.seal(&binding, &keys, now, now + 1500).unwrap();
            certificate.verify(&binding, &keys, now).unwrap();
            fs::write(
                "/job/evidence/resource-qualification.json",
                serde_json::to_vec(&certificate).unwrap(),
            )
            .unwrap();
            println!(
                "{}",
                serde_json::json!({"kind":"RESOURCE_QUALIFICATION_ISSUED","evidence_digest":certificate.evidence_digest(),"admitted_jobs":0})
            );
            drop(proof_root);
            Some(family)
        } else {
            None
        };
        let mut source_sequence =
            if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("authorityrace") {
                1u64
            } else {
                0u64
            };
        let mut refresh = |writer: &mut SharedControl,
                           cwriter: &mut SharedControl,
                           frames: &mut WitnessFrames,
                           cframes: &mut WitnessFrames,
                           revoked: Vec<&str>| {
            source_sequence += 1;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":source_sequence,"observed_at":now,"revoked":revoked})).unwrap()).unwrap();
            let frame = super::super::la_adapter::sign_source_observation(
                &keys.authority,
                &binding,
                &canonical,
            )
            .unwrap();
            let mut record = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(format!("/job/custody/authority-{source_sequence:03}.json"))
                .unwrap();
            record.write_all(&frame).unwrap();
            record.sync_all().unwrap();
            custody.sync_all().unwrap();
            if resource_family.is_some() {
                cframes
                    .state_ledger
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .record_authority(&frame)
                    .unwrap();
            }
            writer.frame(b"AUTH ", &frame);
            cwriter.frame(b"AUTH ", &frame);
            let mut source_acks = Vec::new();
            for (role, receipt) in [("worker", frames.next()), ("controller", cframes.next())] {
                let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
                assert_eq!(receipt["kind"], "AUTHORITY_ACK");
                let ack: super::super::la_adapter::SourceAck =
                    serde_json::from_value(receipt["ack"].clone()).unwrap();
                super::super::la_adapter::verify_source_ack(
                    &keys.reply,
                    &binding,
                    role,
                    &canonical,
                    &ack,
                )
                .unwrap();
                fs::write(
                    format!("/job/evidence/{role}-authority-{source_sequence:03}-ack.json"),
                    serde_json::to_vec(&ack).unwrap(),
                )
                .unwrap();
                source_acks.push(ack);
            }
            // Qualification-only probes have no service execution authority.
            // In particular the initial authority-race probe deliberately
            // injects independent per-role frames. It cannot authorize a close
            // midpoint; the service witness high-water stays unset there.
            if resource_family.is_some() {
                cframes
                    .state_ledger
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .observe_authority(&frame, &source_acks[1], &source_acks[0])
                    .unwrap();
            }
        };
        if matches!(
            std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref(),
            Ok("vertical"
                | "running-stop"
                | "running-completion-wins"
                | "running-worker-loss"
                | "running-worker-loss-settle"
                | "running-worker-loss-refresh"
                | "vertical-revocation"
                | "controller-recovery"
                | "controller-recovery-prefix"
                | "controller-recovery-ack"
                | "controller-recovery-gap"
                | "controller-rebind"
                | "controller-close-recovery"
                | "controller-close-recovery-envelope"
                | "controller-close-recovery-midpoint"
                | "controller-close-recovery-gap"
                | "worker-close-recovery"
                | "worker-close-recovery-marker"
                | "worker-close-recovery-history"
                | "worker-close-recovery-report"
                | "worker-close-recovery-successor"
                | "controller-stop-recovery"
                | "controller-stop-recovery-presend"
                | "controller-stop-recovery-envelope"
                | "controller-stop-recovery-midpoint"
                | "controller-stop-recovery-gap"
                | "controller-stop-recovery-mandate"
                | "controller-never-started-m1"
                | "controller-never-started-m2"
                | "controller-never-started-m1-foreign"
                | "controller-never-started-m1-expired"
                | "controller-never-started-m2-stale")
        ) {
            let revocation_case =
                std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("vertical-revocation");
            let family = resource_family
                .as_ref()
                .expect("actual resource family required");
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let line = fs::read_to_string("/job/evidence/service-state-custody.jsonl").unwrap();
            let head: serde_json::Value =
                serde_json::from_str(line.lines().last().unwrap()).unwrap();
            let checkpoint: super::super::la_adapter::state_custody::Checkpoint =
                serde_json::from_value(head["checkpoint"].clone()).unwrap();
            let state_ack: super::super::la_adapter::state_custody::Ack =
                serde_json::from_value(head["ack"].clone()).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let resource = family.seal(&binding, &keys, now, now + 12000).unwrap();
            let activation = super::super::la_adapter::Activation::issue(
                resource,
                &binding,
                &keys,
                &roots[0],
                &roots[1],
                &checkpoint,
                &state_ack,
                1,
                now,
                now + 12000,
            )
            .unwrap();
            let bytes = serde_json::to_vec(&activation).unwrap();
            let mut record = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open("/job/custody/activation.json")
                .unwrap();
            record.write_all(&bytes).unwrap();
            record.sync_all().unwrap();
            custody.sync_all().unwrap();
            writer.frame(b"QUALIFY ", &bytes);
            cwriter.frame(b"QUALIFY ", &bytes);
            for (role, receipt) in [("worker", frames.next()), ("controller", cframes.next())] {
                let value: serde_json::Value = serde_json::from_str(&receipt).unwrap();
                assert_eq!(value["kind"], "ACTIVATION_ACK");
                let ack: super::super::la_adapter::ActivationAck =
                    serde_json::from_value(value["ack"].clone()).unwrap();
                activation.verify_ack(role, &keys, &ack).unwrap();
                fs::write(format!("/job/evidence/{role}-activation-ack.json"), receipt).unwrap();
            }
            let (_, mut sockets) = bridge.call(Op::Connect, Role::C, cport, &[]);
            let mut http = KeepHttp(sockets.pop().unwrap());
            let base = "/v1/diffuser/projects/project_12345678";
            let input = b"ordinary authenticated vertical computation\0\xff";
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let (status, uploaded) = http.request(
                "POST",
                &format!("{base}/artifacts"),
                &delegated,
                "vertical_upload_0001",
                "application/octet-stream",
                input,
            );
            assert_eq!(
                status,
                201,
                "upload: {}",
                String::from_utf8_lossy(&uploaded)
            );
            let uploaded: serde_json::Value = serde_json::from_slice(&uploaded).unwrap();
            let input_id = uploaded["object_id"].as_str().unwrap();
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let acquire = serde_json::json!({"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":4000,"requested_tenure_ms":12000});
            let (status, assignment) = http.json(
                "POST",
                &format!("{base}/assignments"),
                &delegated,
                "vertical_acquire_001",
                &acquire,
            );
            assert_eq!(status, 202, "acquire: {assignment}");
            assert_eq!(assignment["state"], "assigned");
            super::assert_development_response("AssignmentAcquired", &assignment);
            let assignment_id = assignment["assignment_id"].as_str().unwrap();
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let submit = serde_json::json!({"schema_version":"diffuser-lane/v1","client_job_id":"vertical_client_job1","capability":"artifact.inspect.sha256/v1","profile_version":"1","input_artifact_ids":[input_id],"parameters":{},"max_runtime_ms":4000,"disconnect_policy":"continue_until_job_deadline"});
            let started = Instant::now();
            let worker_close_recovery = std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                .is_ok_and(|s| s.starts_with("worker-close-recovery"));
            let close_recovery = super::controller_close_recovery_case() || worker_close_recovery;
            let never_started_case = std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                .is_ok_and(|v| v.starts_with("controller-never-started-"));
            let stop_recovery = super::controller_stop_recovery_case();
            let recovery_case = super::controller_recovery_case()
                && !close_recovery
                && !stop_recovery
                && !never_started_case;
            let mut terminal_reader = None;
            let (status, job) = if recovery_case {
                let mut socket = http.0.try_clone().unwrap();
                let body = serde_json::to_vec(&submit).unwrap();
                let header=format!("POST {base}/assignments/{assignment_id}/jobs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {delegated}\r\nIdempotency-Key: vertical_submit_001\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",body.len());
                terminal_reader = Some(std::thread::spawn(move || {
                    socket.write_all(header.as_bytes()).unwrap();
                    socket.write_all(&body).unwrap();
                    let mut byte = [0; 1];
                    socket.read(&mut byte)
                }));
                let barrier: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                assert_eq!(barrier["kind"], "PUBLICATION_BARRIER");
                fs::write(
                    "/job/evidence/publication-barrier.json",
                    serde_json::to_vec(&barrier).unwrap(),
                )
                .unwrap();
                (202, barrier["response"].clone())
            } else {
                http.json(
                    "POST",
                    &format!("{base}/assignments/{assignment_id}/jobs"),
                    &delegated,
                    "vertical_submit_001",
                    &submit,
                )
            };
            let job_ms = started.elapsed().as_millis();
            assert!(job_ms <= 8000);
            assert_eq!(status, 202, "submit: {job}");
            assert_eq!(
                job["state"],
                if stop_recovery
                    || never_started_case
                    || std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                        .is_ok_and(|v| v.starts_with("running-"))
                {
                    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                        .is_ok_and(|v| v.starts_with("controller-never-started-m1"))
                    {
                        "pending"
                    } else {
                        "running"
                    }
                } else {
                    "succeeded"
                }
            );
            super::assert_development_response("JobAccepted", &job);
            let job_id = job["job_id"].as_str().unwrap();
            if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").is_ok_and(|v| v.starts_with("running-"))
            {
                let initial: serde_json::Value = serde_json::from_str(&wm).unwrap();
                let completed = std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                    == Ok("running-completion-wins");
                let loss = std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                    .is_ok_and(|v| v.starts_with("running-worker-loss"));
                let wdb = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker.sqlite",
                )
                .unwrap();
                let (operation, marker): (String, String) = wdb
                    .query_row(
                        "SELECT op,state FROM operations WHERE job=?1",
                        [job_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(
                    marker, "started",
                    "fault must follow actual entry, before terminal work"
                );
                let original_command: String = {
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    claims
                        .query_row(
                            "SELECT command FROM la_job_permit_intents WHERE job=?1",
                            [job_id],
                            |r| r.get(0),
                        )
                        .unwrap()
                };
                let command: super::super::la_adapter::InspectCommand =
                    serde_json::from_str(&original_command).unwrap();
                assert_eq!(operation, command.operation);
                assert_eq!(command.boot, binding.worker_boot);
                drop(wdb);
                // The exact admitted process identity was independently pinned
                // at startup. Avoid delaying the fault with a second full /proc scan.
                let live = wm.clone();
                fs::write("/job/evidence/running-worker-identity.json", &live).unwrap();
                let killed = if loss {
                    let (killed, rights) = bridge.call(Op::KillW, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let killed: serde_json::Value = serde_json::from_str(&killed).unwrap();
                    assert_eq!(killed["kind"], "W_KILLED");
                    assert_eq!(killed["pidfd_dead"], true);
                    fs::write(
                        "/job/evidence/running-worker-killed.json",
                        serde_json::to_vec(&killed).unwrap(),
                    )
                    .unwrap();
                    Some(killed)
                } else {
                    None
                };
                // Wrong actor cannot issue Stop or mutate the operation.
                let revision = job["revision"].as_u64().unwrap();
                let (foreign_status, _) = http.json("POST", &format!("{base}/jobs/{job_id}/cancel"), &human, "running_foreign_001", &serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision}));
                assert_eq!(foreign_status, 404);
                if completed {
                    writer.write_all(b"ENTRY_CONTINUE\n").unwrap();
                    assert_eq!(jsonstr(&frames.next(), "kind"), "ENTRY_CONTINUED");
                    std::thread::sleep(Duration::from_millis(10));
                }
                let started_cancel = Instant::now();
                let (status, cancelled) = http.json("POST", &format!("{base}/jobs/{job_id}/cancel"), &delegated, "running_cancel_001", &serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision}));
                let cancel_http_status = status;
                if loss {
                    assert_eq!(status, 400, "cancel uncertainty: {cancelled}");
                    assert_eq!(cancelled["error"]["code"], "transport_uncertain");
                } else {
                    assert_eq!(status, 202, "cancel: {cancelled}");
                }
                if !loss {
                    assert_eq!(
                        cancelled["state"],
                        if loss {
                            "stopping"
                        } else if completed {
                            "succeeded"
                        } else {
                            "cancelled"
                        }
                    );
                }
                let cancel_ms = started_cancel.elapsed().as_millis();
                let (duplicate_status, duplicate_cancel) = http.json("POST", &format!("{base}/jobs/{job_id}/cancel"), &delegated, "running_cancel_001", &serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision}));
                if loss {
                    assert_eq!(duplicate_status,503,"pending original custody blocks a second service operation: {duplicate_cancel}");
                    assert_eq!(duplicate_cancel["error"]["code"], "storage_unavailable");
                } else {
                    assert_eq!(duplicate_status, 202);
                    assert_eq!(
                        duplicate_cancel, cancelled,
                        "terminal cancel retry must not strand transport intent"
                    );
                }
                if !loss {
                    assert!(cancel_ms < 500, "Stop ran after barrier completion");
                }
                let (status, view) = http.json(
                    "GET",
                    &format!("{base}/jobs/{job_id}"),
                    &delegated,
                    "",
                    &serde_json::Value::Null,
                );
                let read_http_status = status;
                if loss {
                    assert_eq!(status, 503, "pending exact Stop is uncertain: {view}");
                    assert_eq!(view["error"]["code"], "storage_unavailable");
                } else {
                    assert_eq!(status, 200, "status: {view}");
                    assert_eq!(view["state"], cancelled["state"]);
                }
                if completed {
                    let output = view["result_artifact_id"].as_str().unwrap();
                    let (status, report) = http.request(
                        "GET",
                        &format!("{base}/artifacts/{output}/content"),
                        &delegated,
                        "",
                        "",
                        &[],
                    );
                    assert_eq!(status, 200);
                    let parsed: serde_json::Value = serde_json::from_slice(&report).unwrap();
                    assert_eq!(parsed["sha256"], hex::encode(Sha256::digest(input)));
                    assert_eq!(parsed["job_id"], job_id);
                    fs::write("/job/evidence/running-completed-report.json", report).unwrap();
                } else {
                    assert!(view["result_artifact_id"].is_null());
                }
                let wdb = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker.sqlite",
                )
                .unwrap();
                super::super::la_worker::verify_session_history(&wdb, &keys.reply).unwrap();
                let (state, results, stops): (String,i64,i64) = wdb.query_row("SELECT state,(SELECT COUNT(*) FROM worker_result_receipts),(SELECT COUNT(*) FROM worker_stop_receipts) FROM operations WHERE op=?1", [&operation], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                assert_eq!(
                    state,
                    if loss {
                        "started"
                    } else if completed {
                        "complete"
                    } else {
                        "cancelled"
                    }
                );
                assert_eq!(results, i64::from(completed));
                assert_eq!(stops, if loss || completed { 0 } else { 1 });
                drop(wdb);
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let retained: String = claims
                    .query_row(
                        "SELECT command FROM la_job_permit_intents WHERE job=?1",
                        [job_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(retained, original_command);
                let held: (i64,i64) = claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)", [], |r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                assert_eq!(held, (1, 1));
                let rev: i64 = claims
                    .query_row(
                        "SELECT revision FROM la_assignment_revisions WHERE assignment_id=?1",
                        [assignment_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                drop(claims);
                if !loss {
                    refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
                }
                let (status, released) = http.json("POST", &format!("{base}/assignments/{assignment_id}/release"), &delegated, "running_release_001", &serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":rev}));
                let release_http_status = status;
                if loss {
                    assert_eq!(
                        status, 503,
                        "release cannot bypass the original pending Stop: {released}"
                    );
                    assert_eq!(released["error"]["code"], "storage_unavailable");
                } else {
                    assert_eq!(status, 202, "release: {released}");
                }
                let cleanup = if loss {
                    // No terminal worker receipt means no certificate, release,
                    // NeverStarted inference or replacement execution authority.
                    let observed: serde_json::Value = serde_json::from_str(&live).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    assert!(super::super::la_adapter::cleanup::Certificate::inspect(
                        &binding,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &initial["snapshot"],
                        &observed["snapshot"],
                        assignment_id,
                        now
                    )
                    .is_err());
                    serde_json::json!({"terminal_proof_missing":true,"certificate_refused":true,"released_now":false,"retry_authority":false,"never_started":false})
                } else {
                    let (observed, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    fs::write(
                        "/job/evidence/running-quiescent-occupancy.json",
                        serde_json::to_vec(&observed).unwrap(),
                    )
                    .unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let cert = super::super::la_adapter::cleanup::Certificate::inspect(
                        &binding,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &initial["snapshot"],
                        &observed["snapshot"],
                        assignment_id,
                        now,
                    )
                    .unwrap();
                    let bytes = serde_json::to_vec(&cert).unwrap();
                    fs::write("/job/evidence/running-cleanup-certificate.json", &bytes).unwrap();
                    cwriter.frame(b"CLEANUP ", &bytes);
                    let first: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(first["kind"], "CLEANUP_ACK");
                    assert_eq!(first["ack"]["released_now"], true);
                    cwriter.frame(b"CLEANUP ", &bytes);
                    let duplicate: serde_json::Value =
                        serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(duplicate["ack"]["released_now"], false);
                    serde_json::json!({"first":first,"duplicate":duplicate})
                };
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let counts: (i64,i64,i64) = claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)", [], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                assert_eq!(counts, if loss { (1, 1, 0) } else { (0, 0, 1) });
                let job_state: String = claims
                    .query_row("SELECT state FROM la_jobs WHERE id=?1", [job_id], |r| {
                        r.get(0)
                    })
                    .unwrap();
                let assignment_state: String = claims
                    .query_row(
                        "SELECT state FROM la_assignments WHERE id=?1",
                        [assignment_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                if loss {
                    assert_eq!(job_state, "stopping");
                    assert_eq!(assignment_state, "assigned");
                    let transport = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let pending: i64 = transport
                        .query_row(
                            "SELECT COUNT(*) FROM channel_log WHERE response IS NULL",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(pending, 1);
                    let pending_bytes: Vec<u8> = transport
                        .query_row(
                            "SELECT request FROM channel_log WHERE response IS NULL",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    let pending: serde_json::Value =
                        serde_json::from_slice(&pending_bytes).unwrap();
                    assert_eq!(pending["request"]["operation"]["operation"], "Stop");
                    assert_eq!(
                        pending["request"]["operation"]["command"]["operation"],
                        operation
                    );
                    fs::write(
                        "/job/evidence/running-loss-pending-stop.json",
                        &pending_bytes,
                    )
                    .unwrap();
                    let service = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "service-custody.sqlite",
                    )
                    .unwrap();
                    let midpoints: i64 = service
                        .query_row("SELECT COUNT(*) FROM service_close_midpoints", [], |r| {
                            r.get(0)
                        })
                        .unwrap();
                    assert_eq!(midpoints, 1);
                }
                drop(claims);
                let entries =
                    fs::read_to_string("/job/evidence/worker-entered-work.jsonl").unwrap();
                assert_eq!(entries.lines().count(), 1);
                let entry: serde_json::Value =
                    serde_json::from_str(entries.lines().next().unwrap()).unwrap();
                assert_eq!(entry["operation"], operation);
                assert_eq!(entry["worker_boot"], binding.worker_boot);
                if !loss && !completed {
                    let signals =
                        fs::read_to_string("/job/evidence/worker-stop-signalled.jsonl").unwrap();
                    let signal: serde_json::Value =
                        serde_json::from_str(signals.lines().next().unwrap()).unwrap();
                    assert_eq!(signal["operation"], operation);
                    assert_eq!(signal["task_exists"], true);
                    assert!(
                        signal["observed_at"].as_u64().unwrap() < command.permit_until,
                        "timer expiry cannot masquerade as running Stop"
                    );
                }
                if !loss {
                    let quiesced =
                        fs::read_to_string("/job/evidence/worker-quiesced.jsonl").unwrap();
                    assert_eq!(quiesced.lines().count(), 1);
                    let q: serde_json::Value =
                        serde_json::from_str(quiesced.lines().next().unwrap()).unwrap();
                    assert_eq!(q["operation"], operation);
                    assert_eq!(q["worker_boot"], binding.worker_boot);
                    assert_eq!(q["task_joined"], true);
                }
                let mut result = serde_json::json!({"status":if loss {"RUNNING_WORKER_LOSS_UNCERTAIN"} else if completed {"RUNNING_COMPLETION_RETAINED_RELEASED"} else {"RUNNING_STOP_QUIESCED_RELEASED"},"job":job_id,"operation":operation,"worker_boot":binding.worker_boot,"controller_boot":binding.controller_boot,"worker_epoch":1,"controller_epoch":1,"actual_work_entries":1,"state":state,"cancel_ms":cancel_ms,"cancel_http_status":cancel_http_status,"duplicate_cancel_http_status":duplicate_status,"read_http_status":read_http_status,"release_http_status":release_http_status,"job_state":job_state,"assignment_state":assignment_state,"foreign_actor_refused":true,"original_command_unchanged":true,"worker_result_receipts":results,"worker_stop_receipts":stops,"held_after":counts.0,"charged_after":counts.1,"cleanup_receipts":counts.2,"cleanup":cleanup,"killed":killed,"whole_S1_complete":false});
                if matches!(
                    std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref(),
                    Ok("running-worker-loss-settle" | "running-worker-loss-refresh")
                ) {
                    // The fixed authenticated relay just checked C/K alive and
                    // P's kernel-authenticated pinned identity at KillW. Reuse
                    // those exact observations inside the original source clock.
                    let survivors = killed.as_ref().unwrap()["survivors"].clone();
                    fs::write(
                        "/job/evidence/worker-loss-survivors.json",
                        serde_json::to_vec(&survivors).unwrap(),
                    )
                    .unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let old_state =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    let controller_state =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let mut refusals = vec![];
                    for (field, value) in [
                        ("pidfd_dead", serde_json::json!(false)),
                        ("keeper", serde_json::json!({})),
                        ("execution_domain", serde_json::json!({"quiescent":false})),
                        ("identity", serde_json::json!({})),
                    ] {
                        let mut death = killed.clone().unwrap();
                        death[field] = value;
                        assert!(
                            super::super::la_adapter::WorkerLossSettlement::prepare(
                                &cframes.transport_ledger.lock().unwrap(),
                                &frames.transport_ledger.lock().unwrap(),
                                cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                                &roots[1],
                                &roots[0],
                                &initial["snapshot"],
                                &death,
                                &survivors,
                                &keys,
                                now
                            )
                            .is_err(),
                            "unsigned independent {field} proof must refuse"
                        );
                        refusals.push(format!("independent_{field}"));
                    }
                    let cap = super::super::la_adapter::WorkerLossSettlement::prepare(
                        &cframes.transport_ledger.lock().unwrap(),
                        &frames.transport_ledger.lock().unwrap(),
                        cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &roots[1],
                        &roots[0],
                        &initial["snapshot"],
                        killed.as_ref().unwrap(),
                        &survivors,
                        &keys,
                        now,
                    )
                    .unwrap();
                    cap.verify(&keys, now).unwrap();
                    assert!(cap.verify(&keys, now + 1500).is_err());
                    let signed = serde_json::to_value(&cap).unwrap();
                    for (field, value) in [
                        ("binding", serde_json::json!({"worker_boot":"old"})),
                        ("worker_state", serde_json::json!("0".repeat(64))),
                        ("sequence", serde_json::json!(512)),
                        ("expires_at", serde_json::json!(0)),
                    ] {
                        let mut altered = signed.clone();
                        altered[field] = value;
                        // Structurally valid signed alterations reach protected
                        // verification; an invalid binding shape is parsed locally.
                        if let Ok(altered) = serde_json::from_value::<
                            super::super::la_adapter::WorkerLossSettlement,
                        >(altered.clone())
                        {
                            cwriter.frame(b"WLOSS ", &serde_json::to_vec(&altered).unwrap());
                            let ack: serde_json::Value =
                                serde_json::from_str(&cframes.next()).unwrap();
                            assert_eq!(ack["ack"]["kind"], "WORKER_LOSS_REFUSED");
                        } else {
                            assert_eq!(field, "binding");
                        }
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap(),
                            controller_state
                        );
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[0])
                                .unwrap(),
                            old_state
                        );
                        refusals.push(format!("authenticated_{field}"));
                    }
                    fs::write(
                        "/job/evidence/worker-loss-settlement.json",
                        serde_json::to_vec(&cap).unwrap(),
                    )
                    .unwrap();
                    cwriter.frame(b"WLOSS ", &serde_json::to_vec(&cap).unwrap());
                    let settled: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(
                        settled["ack"]["kind"], "WORKER_LOSS_SETTLED",
                        "settlement: {settled}"
                    );
                    assert_eq!(settled["ack"]["outcome_uncertain"], true);
                    assert_eq!(settled["ack"]["retry_authority"], false);
                    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                        == Ok("running-worker-loss-refresh")
                    {
                        std::thread::sleep(std::time::Duration::from_millis(1700));
                        let db = super::super::la_store::open_pinned_readonly_database(
                            &roots[1],
                            "lane_assignments.sqlite",
                        )
                        .unwrap();
                        let revision: i64 = db.query_row("SELECT revision FROM la_assignment_revisions WHERE assignment_id=?1", [assignment_id], |r| r.get(0)).unwrap();
                        let (status, old_close) = http.json("POST", &format!("{base}/assignments/{assignment_id}/release"), &delegated, "loss_expired_source_001", &serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision}));
                        assert_eq!(
                            status, 412,
                            "expired original source must refuse: {old_close}"
                        );
                        assert_eq!(old_close["error"]["code"], "evidence_stale");
                        let held: (i64,i64) = db.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
                        assert_eq!(held, (1, 1));
                        fs::write("/job/evidence/worker-loss-stale-close.json", serde_json::to_vec(&serde_json::json!({"status":status,"response":old_close,"held":held,"settlement":cap.digest().unwrap(),"real_delay_ms":1700})).unwrap()).unwrap();
                        drop(db);
                        let mut snapshots = serde_json::json!({});
                        for (role, name) in [
                            (Role::C, "controller"),
                            (Role::K, "keeper"),
                            (Role::P, "witness"),
                        ] {
                            let (snapshot, rights) = bridge.call(Op::Observe, role, 0, &[]);
                            assert!(rights.is_empty());
                            let snapshot: serde_json::Value =
                                serde_json::from_str(&snapshot).unwrap();
                            snapshots[name] = snapshot["snapshot"].clone();
                        }
                        let (observation, rights) = bridge.call(Op::ReobserveLoss, Role::W, 0, &[]);
                        assert!(rights.is_empty());
                        let observation: serde_json::Value =
                            serde_json::from_str(&observation).unwrap();
                        fs::write(
                            "/job/evidence/worker-loss-current-survivors.json",
                            serde_json::to_vec(&snapshots).unwrap(),
                        )
                        .unwrap();
                        fs::write(
                            "/job/evidence/worker-loss-current-observation.json",
                            serde_json::to_vec(&observation).unwrap(),
                        )
                        .unwrap();
                        let body = serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":cframes.state_ledger.lock().unwrap().as_ref().unwrap().authority_sequence()+1,"observed_at":observation["observed_at"],"revoked":[]})).unwrap();
                        let frame = super::super::la_adapter::sign_source_observation(
                            &keys.authority,
                            &binding,
                            &body,
                        )
                        .unwrap();
                        // Genuine current-source revocation is signed by P, not
                        // an altered-MAC test. C must refuse before any mutation.
                        let revoked_body=serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":cframes.state_ledger.lock().unwrap().as_ref().unwrap().authority_sequence()+1,"observed_at":observation["observed_at"],"revoked":["grant_leaf123456"]})).unwrap();
                        let revoked_frame = super::super::la_adapter::sign_source_observation(
                            &keys.authority,
                            &binding,
                            &revoked_body,
                        )
                        .unwrap();
                        let revoked_source = super::super::la_adapter::WorkerLossSource::prepare(
                            &cap,
                            &cframes.transport_ledger.lock().unwrap(),
                            &frames.transport_ledger.lock().unwrap(),
                            cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                            &roots[1],
                            &roots[0],
                            &observation,
                            &snapshots,
                            revoked_frame,
                            &keys,
                        )
                        .unwrap();
                        let unchanged =
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap();
                        cwriter.frame(b"WLOSS ", &serde_json::to_vec(&revoked_source).unwrap());
                        let refused: serde_json::Value =
                            serde_json::from_str(&cframes.next()).unwrap();
                        assert_eq!(refused["ack"]["kind"], "WORKER_LOSS_SOURCE_REFUSED");
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap(),
                            unchanged
                        );
                        fs::write("/job/evidence/worker-loss-source-revoked-refusal.json",serde_json::to_vec(&serde_json::json!({"capability":revoked_source,"response":refused,"before":unchanged,"after":unchanged})).unwrap()).unwrap();
                        let source = super::super::la_adapter::WorkerLossSource::prepare(
                            &cap,
                            &cframes.transport_ledger.lock().unwrap(),
                            &frames.transport_ledger.lock().unwrap(),
                            cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                            &roots[1],
                            &roots[0],
                            &observation,
                            &snapshots,
                            frame,
                            &keys,
                        )
                        .unwrap();
                        let before =
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap();
                        let signed = serde_json::to_value(&source).unwrap();
                        for (field, value) in [
                            ("settlement", serde_json::json!("0".repeat(64))),
                            ("previous_sequence", serde_json::json!(128)),
                            ("controller_state", serde_json::json!("0".repeat(64))),
                            ("expires_at", serde_json::json!(0)),
                        ] {
                            let mut changed = signed.clone();
                            changed[field] = value;
                            cwriter.frame(b"WLOSS ", &serde_json::to_vec(&changed).unwrap());
                            let reply: serde_json::Value =
                                serde_json::from_str(&cframes.next()).unwrap();
                            assert_eq!(reply["ack"]["kind"], "WORKER_LOSS_SOURCE_REFUSED");
                            assert_eq!(
                                super::super::la_adapter::state_custody::state_digest(&roots[1])
                                    .unwrap(),
                                before
                            );
                        }
                        cframes
                            .state_ledger
                            .lock()
                            .unwrap()
                            .as_mut()
                            .unwrap()
                            .prepare_loss_source(&source)
                            .unwrap();
                        assert!(
                            cframes
                                .state_ledger
                                .lock()
                                .unwrap()
                                .as_ref()
                                .unwrap()
                                .loss_source_anchor(&roots[1])
                                .is_err(),
                            "P-only partial source install cannot certify current C state"
                        );

                        fs::write(
                            "/job/evidence/worker-loss-source.json",
                            serde_json::to_vec(&source).unwrap(),
                        )
                        .unwrap();
                        cwriter.frame(b"WLOSS ", &serde_json::to_vec(&source).unwrap());
                        let reply: serde_json::Value =
                            serde_json::from_str(&cframes.next()).unwrap();
                        assert_eq!(
                            reply["ack"]["kind"], "WORKER_LOSS_SOURCE_ACK",
                            "source reconciliation {reply}"
                        );
                        let ack: super::super::la_adapter::SourceAck =
                            serde_json::from_value(reply["ack"]["source_ack"].clone()).unwrap();
                        cframes
                            .state_ledger
                            .lock()
                            .unwrap()
                            .as_mut()
                            .unwrap()
                            .observe_loss_source(&source, &ack)
                            .unwrap();
                        fs::write(
                            "/job/evidence/worker-loss-source-controller-ack.json",
                            serde_json::to_vec(&ack).unwrap(),
                        )
                        .unwrap();
                        let before =
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap();
                        cwriter.frame(b"WLOSS ", &serde_json::to_vec(&source).unwrap());
                        let replay: serde_json::Value =
                            serde_json::from_str(&cframes.next()).unwrap();
                        assert_eq!(replay["ack"]["kind"], "WORKER_LOSS_SOURCE_REFUSED");
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap(),
                            before
                        );
                    }
                    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                        == Ok("running-worker-loss-refresh")
                    {
                        let (status, unauthenticated) = http.json(
                            "GET",
                            &format!("{base}/jobs/job_foreign_00000001"),
                            "invalid-token",
                            "",
                            &serde_json::Value::Null,
                        );
                        assert_eq!(
                            status, 401,
                            "authentication precedes loss object scope: {unauthenticated}"
                        );
                        let (status, unauthenticated) = http.json(
                            "POST",
                            &format!("{base}/assignments"),
                            "invalid-token",
                            "loss_no_unauth_claim_001",
                            &acquire,
                        );
                        assert_eq!(
                            status, 401,
                            "authentication precedes loss routing scope: {unauthenticated}"
                        );
                        let (status, blocked) = http.json(
                            "POST",
                            &format!("{base}/assignments"),
                            &delegated,
                            "loss_no_new_claim_001",
                            &acquire,
                        );
                        assert_eq!(status, 503, "loss source cannot admit: {blocked}");
                        assert_eq!(blocked["error"]["code"], "routing_closed");
                        let (status, blocked) = http.json(
                            "POST",
                            &format!("{base}/assignments/{assignment_id}/jobs"),
                            &delegated,
                            "loss_no_new_work_0001",
                            &submit,
                        );
                        assert_eq!(status, 503, "loss source cannot submit: {blocked}");
                        let (status, blocked) = http.json(
                            "GET",
                            &format!("{base}/jobs/job_foreign_00000001"),
                            &delegated,
                            "",
                            &serde_json::Value::Null,
                        );
                        assert_eq!(status, 404, "loss source exact object: {blocked}");
                    }
                    let (status, view) = http.json(
                        "GET",
                        &format!("{base}/jobs/{job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200, "ordinary status after settlement: {view}");
                    assert_eq!(view["state"], "failed");
                    assert!(view["result_artifact_id"].is_null());
                    let (status,cancel)=http.json("POST",&format!("{base}/jobs/{job_id}/cancel"),&delegated,"running_cancel_001",&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision}));
                    assert_eq!(status, 202, "same cancel key after settlement: {cancel}");
                    assert_eq!(cancel["state"], "failed");
                    let (foreign, _) = http.json(
                        "GET",
                        &format!("{base}/jobs/{job_id}"),
                        &human,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(foreign, 404);
                    let db = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let held:(i64,i64)=db.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(held, (1, 1));
                    let revision: i64 = db
                        .query_row(
                            "SELECT revision FROM la_assignment_revisions WHERE assignment_id=?1",
                            [assignment_id],
                            |r| r.get(0),
                        )
                        .unwrap();
                    drop(db);
                    let (status,closed)=http.json("POST",&format!("{base}/assignments/{assignment_id}/release"),&delegated,"loss_terminal_close_001",&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision}));
                    assert_eq!(status, 202, "ordinary terminal Close: {closed}");
                    assert_eq!(closed["state"], crate::error_catalog::DRAINING);
                    let (status,duplicate_close)=http.json("POST",&format!("{base}/assignments/{assignment_id}/release"),&delegated,"loss_terminal_close_001",&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision}));
                    assert_eq!(status, 202);
                    assert_eq!(duplicate_close, closed);

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let (keeper_now, rights) = bridge.call(Op::Observe, Role::K, 0, &[]);
                    assert!(rights.is_empty());
                    let keeper_now: serde_json::Value = serde_json::from_str(&keeper_now).unwrap();
                    assert_eq!(keeper_now["snapshot"]["identity"], survivors["keeper"]);
                    fs::write(
                        "/job/evidence/worker-loss-cleanup-keeper.json",
                        serde_json::to_vec(&keeper_now).unwrap(),
                    )
                    .unwrap();
                    let db_before_cleanup = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let held_after_close:(i64,i64)=db_before_cleanup.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(held_after_close, (1, 1));
                    drop(db_before_cleanup);
                    let cert = super::super::la_adapter::cleanup::Certificate::inspect_worker_loss(
                        &cap,
                        &keys,
                        &frames.transport_ledger.lock().unwrap(),
                        &cframes.transport_ledger.lock().unwrap(),
                        cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &roots[0],
                        &roots[1],
                        &survivors,
                        now,
                    )
                    .unwrap();
                    let bytes = serde_json::to_vec(&cert).unwrap();
                    fs::write("/job/evidence/worker-loss-cleanup-certificate.json", &bytes)
                        .unwrap();
                    cwriter.frame(b"CLEANUP ", &bytes);
                    let first: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(first["ack"]["released_now"], true, "loss release {first}");
                    fs::write(
                        "/job/evidence/worker-loss-release-consumption.json",
                        serde_json::to_vec(&first["ack"]).unwrap(),
                    )
                    .unwrap();
                    cwriter.frame(b"CLEANUP ", &bytes);
                    let duplicate: serde_json::Value =
                        serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(duplicate["ack"]["released_now"], false);
                    let db = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64,i64)=db.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!(counts, (0, 0, 1));
                    let state: String = db
                        .query_row(
                            "SELECT state FROM la_assignments WHERE id=?1",
                            [assignment_id],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(state, "closed");
                    let original: String = db
                        .query_row(
                            "SELECT command FROM la_job_permit_intents WHERE job=?1",
                            [job_id],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(original, original_command);
                    let worker_receipts: i64 = db
                        .query_row("SELECT COUNT(*) FROM la_worker_receipts", [], |r| r.get(0))
                        .unwrap();
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                        old_state,
                        "settlement cannot rewrite any worker byte"
                    );
                    let channel = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let pending: i64 = channel
                        .query_row(
                            "SELECT COUNT(*) FROM channel_log WHERE response IS NULL",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(pending, 0);
                    let original_request:Vec<u8>=channel.query_row("SELECT request FROM channel_log WHERE json_extract(CAST(response AS TEXT),'$.kind')='diffuser-entered-worker-loss/v1'",[],|r|r.get(0)).unwrap();
                    assert_eq!(
                        original_request,
                        fs::read("/job/evidence/running-loss-pending-stop.json").unwrap()
                    );
                    let before_replay =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    cwriter.frame(b"WLOSS ", &serde_json::to_vec(&cap).unwrap());
                    let replay: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(replay["ack"]["kind"], "WORKER_LOSS_REFUSED");
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                        before_replay
                    );
                    let mut altered = serde_json::to_value(&cert).unwrap();
                    altered["body"]["claim"]["fence"] = 512.into();
                    let altered: super::super::la_adapter::cleanup::Certificate =
                        serde_json::from_value(altered).unwrap();
                    assert!(altered.verify(&binding, &keys, &roots[1], now).is_err());
                    assert!(cert.verify(&binding, &keys, &roots[1], now + 1500).is_err());
                    let worker_db = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    let worker_channel = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker-channel.sqlite",
                    )
                    .unwrap();
                    let service_db = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "service-custody.sqlite",
                    )
                    .unwrap();
                    let transport_tables = [
                        "channel_identity",
                        "channel_log",
                        "channel_checkpoints",
                        "channel_authority",
                        "channel_epochs",
                        "channel_worker_epochs",
                    ];
                    let retained = serde_json::json!({
                        "worker":super::loss_retained_tables(&worker_db,&["identity","operations","reservation_session","worker_session_generations","worker_session_snapshots","worker_reservations","worker_inspect_commands","worker_result_receipts","worker_renewals","worker_stop_receipts","worker_close_receipts","worker_input_assignments","worker_cleanup_receipts","worker_inputs","worker_assignment_terms","worker_mandates"]),
                        "worker_transport":super::loss_retained_tables(&worker_channel,&transport_tables),
                        "controller_transport":super::loss_retained_tables(&channel,&transport_tables),
                        "service":super::loss_retained_tables(&service_db,&["service_checkpoints","service_close_midpoints"]),
                        "controller":super::loss_retained_tables(&db,&["la_jobs","la_job_outbox","la_job_permit_intents","la_mandates","la_worker_cursor","la_worker_receipts","la_reservation_authorizations","la_reservations","la_quota_charges","la_assignment_grant_charges","la_assignments","la_assignment_revisions","la_close_intents","la_assignment_stop_receipts","la_worker_loss_settlements","la_worker_loss_closes","la_worker_loss_sources","la_assignment_cleanup_receipts","la_authority_observations"])
                    });
                    let retained = serde_json::to_vec(&retained).unwrap();
                    assert!(retained.len() < 1048576);
                    fs::write(
                        "/job/evidence/worker-loss-retained-product-bytes.json",
                        retained,
                    )
                    .unwrap();
                    result["status"] = "ENTERED_WORKER_LOSS_SETTLED_RELEASED".into();
                    result["held_after"] = 0.into();
                    result["charged_after"] = 0.into();
                    result["cleanup_receipts"] = 1.into();
                    result["job_state"] = "failed".into();
                    result["assignment_state"] = "closed".into();
                    result["source_reconciled"] = (std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                        .as_deref()
                        == Ok("running-worker-loss-refresh"))
                    .into();
                    result["post_settlement"] = serde_json::json!({"status_http":200,"cancel_http":202,"close_http":202,"state":"failed","outcome_uncertain":true,"entered":true,"never_started":false,"worker_bytes_unchanged":true,"original_pending_Stop_resolved":true,"pending_transport":0,"claims_held_before_cleanup":held.0,"quota_held_before_cleanup":held.1,"first":first,"duplicate":duplicate,"preactivation_refusals":refusals,"worker_receipts_unchanged_count":worker_receipts,"returned_worker_supported":false,"automatic_retry":false,"stale_settlement_replay_refused":true,"altered_cleanup_fence_refused":true,"expired_first_cleanup_refused":true,"full_retained_product_bytes":true});
                }
                if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                    == Ok("running-worker-loss-refresh")
                {
                    let before_worker =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    let before_controller =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let mut pipe = [-1; 2];
                    assert_eq!(unsafe { pipe2(pipe.as_mut_ptr(), 0x80000) }, 0);
                    let reader = unsafe { File::from_raw_fd(pipe[0]) };
                    let hold = unsafe { File::from_raw_fd(pipe[1]) };
                    let (fresh, mut streams) =
                        bridge.call(Op::RestartW, Role::W, 0, &[reader.as_raw_fd()]);
                    super::startup_trace("loss_return_restart_returned", serde_json::json!({}));
                    drop(reader);
                    checked_snapshot(&fresh, Role::W, true, Some(st.dev()));
                    if std::env::var("DIFFUSER_LA_LOSS_RETURN_TEST").as_deref() == Ok("transport") {
                        check_control_custody(&fresh, &hold);
                    }
                    super::startup_trace(
                        "loss_return_process_custody_checked",
                        serde_json::json!({}),
                    );
                    let fresh: serde_json::Value = serde_json::from_str(&fresh).unwrap();
                    let old: serde_json::Value = serde_json::from_str(&wm).unwrap();
                    let witness = super::super::la_adapter::WorkerReturnWitness::observe(
                        &binding,
                        &old["snapshot"],
                        killed.as_ref().unwrap(),
                        &fresh["snapshot"],
                        &roots[0],
                    )
                    .unwrap();
                    let mut next = binding.clone();
                    next.worker_epoch = 2;
                    next.worker_boot = randomhex();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    super::startup_trace(
                        "loss_return_completed_probe_start",
                        serde_json::json!({}),
                    );
                    let refused = super::super::la_adapter::WorkerEpochHandoff::prepare(
                        &mut cframes.transport_ledger.lock().unwrap(),
                        &mut frames.transport_ledger.lock().unwrap(),
                        &roots[1],
                        &roots[0],
                        cframes.state_ledger.lock().unwrap().as_mut().unwrap(),
                        next,
                        witness,
                        &keys,
                        now,
                    );
                    assert!(
                        refused.is_err(),
                        "completed-only handoff must not authorize entered-loss return"
                    );
                    let code = refused.err().unwrap();
                    super::startup_trace("loss_return_completed_probe_end", serde_json::json!({}));
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                        before_worker
                    );
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                        before_controller
                    );
                    fs::write("/job/evidence/worker-loss-return-boundary.json",serde_json::to_vec(&serde_json::json!({"kind":"ENTERED_LOSS_RETURN_REQUIRES_DISTINCT_PROTOCOL","fresh_process":fresh,"completed_only_handoff_refused":code,"new_worker_boot_installed":false,"worker_root_unchanged":true,"controller_root_unchanged":true,"new_work_admitted":false,"total_entries":1,"product_release_receipts":1})).unwrap()).unwrap();
                    result["entered_loss_return_boundary"] = serde_json::json!({"fresh_process_observed":true,"completed_only_handoff_refused":true,"new_work_admitted":false});
                    if std::env::var("DIFFUSER_LA_LOSS_RETURN_TEST").as_deref() == Ok("transport") {
                        // All ordinary client loss/cleanup actions above have
                        // completed. This stage authenticates transport only.
                        let cert: super::super::la_adapter::cleanup::Certificate =
                            serde_json::from_slice(
                                &fs::read("/job/evidence/worker-loss-cleanup-certificate.json")
                                    .unwrap(),
                            )
                            .unwrap();
                        let released: serde_json::Value = serde_json::from_slice(
                            &fs::read("/job/evidence/worker-loss-release-consumption.json")
                                .unwrap(),
                        )
                        .unwrap();
                        super::startup_trace(
                            "loss_return_observations_start",
                            serde_json::json!({}),
                        );
                        let mut snapshots = serde_json::json!({});
                        for (role, name) in [
                            (Role::C, "controller"),
                            (Role::K, "keeper"),
                            (Role::P, "witness"),
                        ] {
                            let (v, rights) = bridge.call(Op::Observe, role, 0, &[]);
                            assert!(rights.is_empty());
                            let v: serde_json::Value = serde_json::from_str(&v).unwrap();
                            snapshots[name] = v["snapshot"].clone();
                            super::startup_trace(
                                "loss_return_survivor_observed",
                                serde_json::json!({"role":name}),
                            );
                        }
                        snapshots["worker"] = fresh["snapshot"].clone();
                        let (observation, rights) =
                            bridge.call(Op::ReobserveReturn, Role::W, 0, &[]);
                        assert!(rights.is_empty());
                        fs::write(
                            "/job/evidence/worker-loss-return-observation.json",
                            &observation,
                        )
                        .unwrap();
                        let observation: serde_json::Value =
                            serde_json::from_str(&observation).unwrap();
                        super::startup_trace("loss_return_observations_end", serde_json::json!({}));
                        let witness = super::super::la_adapter::WorkerReturnWitness::observe(
                            &binding,
                            &old["snapshot"],
                            killed.as_ref().unwrap(),
                            &fresh["snapshot"],
                            &roots[0],
                        )
                        .unwrap();
                        let mut next = binding.clone();
                        next.worker_epoch = 2;
                        next.worker_boot = randomhex();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        let corruption =
                            std::env::var("DIFFUSER_LA_LOSS_RETURN_CORRUPT").unwrap_or_default();
                        // This real expired-FIRST test needs time to execute the
                        // root guard inside the unchanged five-second bootstrap.
                        // The negative issuer voluntarily requests 500ms, below
                        // the unchanged 1500ms authority maximum. All positive
                        // transport/source/disposition cases retain 1500ms.
                        let lifetime_ms = if corruption == "late-first" {
                            500
                        } else {
                            1500
                        };
                        super::startup_trace(
                            "loss_return_prepare_start",
                            serde_json::json!({"requested_lifetime_ms":lifetime_ms}),
                        );
                        let handoff = super::super::la_adapter::WorkerLossReturn::prepare(
                            &mut cframes.transport_ledger.lock().unwrap(),
                            &mut frames.transport_ledger.lock().unwrap(),
                            cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                            &roots[1],
                            &roots[0],
                            &cert,
                            &released,
                            next.clone(),
                            witness,
                            &observation,
                            &snapshots,
                            &keys,
                            now,
                            lifetime_ms,
                        )
                        .unwrap();
                        let capsule_clock = serde_json::to_value(&handoff).unwrap();
                        super::startup_trace(
                            "loss_return_capsule_signed",
                            serde_json::json!({"issued_at":capsule_clock["issued_at"],"expires_at":capsule_clock["expires_at"]}),
                        );
                        super::startup_trace("loss_return_probes_start", serde_json::json!({}));
                        let signed_guards = handoff
                            .test_preinstall_guards(&roots[1], &roots[0], &keys, now)
                            .unwrap();
                        super::startup_trace(
                            "loss_return_probes_end",
                            serde_json::json!({"count":signed_guards.len()}),
                        );
                        fs::write(
                            "/job/evidence/worker-loss-return-signed-guards.json",
                            serde_json::to_vec(&signed_guards).unwrap(),
                        )
                        .unwrap();
                        fs::write(
                            "/job/evidence/worker-loss-return-handoff.json",
                            serde_json::to_vec(&handoff).unwrap(),
                        )
                        .unwrap();
                        fs::write(
                            "/job/evidence/worker-loss-return-survivors.json",
                            serde_json::to_vec(&snapshots).unwrap(),
                        )
                        .unwrap();
                        let mut channel = restart_config["authority_material"]["channel"].clone();
                        channel.as_object_mut().unwrap().remove("service_genesis");
                        channel["binding"] = serde_json::to_value(&next).unwrap();
                        channel["expected_high_water"] = handoff.high_water().into();
                        let config = serde_json::json!({"protocol_version":1,"run_nonce":randomhex(),"role":"worker","root":"/job/workerroot","policy_id":"runtime-short-v1","policy_digest":next.policy_digest,"expected_executable_sha256":whash,"authority_material":{"service_bearer":token,"worker_id":next.worker,"boot_id":next.worker_boot,"hardware_generation":1,"profile_epoch":1,"channel":channel},"custody_manifest":{"mode":"recover","worker_id":next.worker,"store_id":store,"root_dev":st.dev(),"root_inode":st.ino(),"expected_starts":1,"expected_records":1,"loss_return":handoff},"barrier_id":null});
                        let config = serde_json::to_vec(&config).unwrap();
                        assert!(config.len() < 16384);
                        super::startup_trace(
                            "loss_return_config_serialized",
                            serde_json::json!({"bytes":config.len()}),
                        );
                        'entered_transport: {
                            if corruption == "late-first" {
                                let expires_at = capsule_clock["expires_at"].as_u64().unwrap();
                                let current = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis()
                                    as u64;
                                let wait_ms = expires_at.saturating_sub(current) + 40;
                                super::startup_trace(
                                    "loss_return_expiry_wait_start",
                                    serde_json::json!({"issued_at":capsule_clock["issued_at"],"expires_at":expires_at,"wait_ms":wait_ms}),
                                );
                                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                                super::startup_trace(
                                    "loss_return_expiry_wait_end",
                                    serde_json::json!({}),
                                );
                            }
                            let err = streams.pop().unwrap();
                            let out = streams.pop().unwrap();
                            let mut control = SharedControl::new(hold);
                            let mut returned = WitnessFrames::start_with_state(
                                Frames {
                                    out,
                                    err,
                                    buf: vec![],
                                    total: 0,
                                    eof: [false; 2],
                                },
                                control.clone(),
                                roots[0].try_clone().unwrap(),
                                &custody,
                                &next,
                                &keys,
                                "worker",
                                None,
                                Some(frames.transport_ledger.clone()),
                            );
                            super::startup_trace(
                                "loss_return_config_write_start",
                                serde_json::json!({"bytes":config.len()}),
                            );
                            let mut written = 0;
                            while written < config.len() {
                                let write = control.write(&config[written..]);
                                super::startup_trace(
                                    "loss_return_config_write_progress",
                                    serde_json::json!({"written_before":written,"requested":config.len()-written,"written":write.as_ref().ok(),"errno":write.as_ref().err().and_then(|e|e.raw_os_error())}),
                                );
                                let count = write.unwrap();
                                assert!(count > 0);
                                written += count;
                            }
                            control.write_all(b"\n").unwrap();
                            super::startup_trace(
                                "loss_return_config_write_end",
                                serde_json::json!({"bytes":written,"delimiter_bytes":1}),
                            );
                            let need: serde_json::Value =
                                serde_json::from_str(&returned.next()).unwrap();
                            if corruption == "late-first" {
                                assert_eq!(need["kind"], "WORKER_LOSS_RETURN_STARTUP_REFUSED");
                                assert_eq!(need["phase"], "root");
                                assert_eq!(need["code"], "evidence_invalid");
                                assert_eq!(need["store_opens"], 0);
                                assert_eq!(need["listener_binds"], 0);
                                assert_eq!(
                                    super::super::la_adapter::state_custody::state_digest(
                                        &roots[0]
                                    )
                                    .unwrap(),
                                    before_worker
                                );
                                assert_eq!(
                                    super::super::la_adapter::state_custody::state_digest(
                                        &roots[1]
                                    )
                                    .unwrap(),
                                    before_controller
                                );
                                fs::write("/job/evidence/worker-loss-return-refusal.json",serde_json::to_vec(&serde_json::json!({"case":corruption,"actual":need,"worker_unchanged":true,"controller_unchanged":true,"admitted":false})).unwrap()).unwrap();
                                result["entered_loss_transport_refusal"] = serde_json::json!({"case":corruption,"phase":"root","pre_mutation":true,"admitted":false});
                                bridge.call(Op::StopW, Role::W, 0, &[]);
                                drop(returned);
                                break 'entered_transport;
                            }
                            fs::write(
                                "/job/evidence/worker-loss-return-bootstrap-frame.json",
                                serde_json::to_vec(&need).unwrap(),
                            )
                            .unwrap();
                            assert_eq!(need["kind"], "LOSS_RESOLUTION_REQUIRED");
                            let mut resolution =
                                fs::read("/job/evidence/worker-loss-settlement.json").unwrap();
                            if corruption == "resolution" {
                                resolution=super::super::la_adapter::WorkerLossReturn::test_corrupt_resolution(&resolution).unwrap();
                            }
                            control.frame(b"LOSSRESOLUTION ", &resolution);
                            let ready: serde_json::Value =
                                serde_json::from_str(&returned.next()).unwrap();
                            fs::write(
                                "/job/evidence/worker-loss-return-transport-frame.json",
                                serde_json::to_vec(&ready).unwrap(),
                            )
                            .unwrap();
                            if corruption == "resolution" {
                                assert_eq!(ready["kind"], "WORKER_LOSS_RETURN_STARTUP_REFUSED");
                                assert_eq!(ready["phase"], "transport");
                                assert_eq!(ready["code"], "evidence_invalid");
                                let db = super::super::la_store::open_pinned_readonly_database(
                                    &roots[0],
                                    "worker-channel.sqlite",
                                )
                                .unwrap();
                                let high: i64 = db
                                    .query_row("SELECT MAX(sequence) FROM channel_log", [], |r| {
                                        r.get(0)
                                    })
                                    .unwrap();
                                assert_eq!(high + 1, handoff.high_water() as i64);
                                let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='channel_worker_epochs')",[],|r|r.get(0)).unwrap();
                                assert!(!table);
                                assert_eq!(
                                    super::super::la_adapter::state_custody::state_digest(
                                        &roots[0]
                                    )
                                    .unwrap(),
                                    before_worker
                                );
                                assert_eq!(
                                    super::super::la_adapter::state_custody::state_digest(
                                        &roots[1]
                                    )
                                    .unwrap(),
                                    before_controller
                                );
                                fs::write("/job/evidence/worker-loss-return-refusal.json",serde_json::to_vec(&serde_json::json!({"case":corruption,"actual":ready,"worker_unchanged":true,"controller_unchanged":true,"old_worker_high":high,"epoch_table":table,"admitted":false})).unwrap()).unwrap();
                                result["entered_loss_transport_refusal"] = serde_json::json!({"case":corruption,"phase":"transport","pre_mutation":true,"admitted":false});
                                bridge.call(Op::StopW, Role::W, 0, &[]);
                                drop(returned);
                                break 'entered_transport;
                            }
                            assert_eq!(
                                ready["kind"], "READY",
                                "actual returned worker frame {ready}"
                            );
                            assert_eq!(ready["boot_id"], next.worker_boot);
                            fs::write(
                                "/job/evidence/worker-loss-return-ready.json",
                                serde_json::to_vec(&ready).unwrap(),
                            )
                            .unwrap();
                            if corruption == "partial" {
                                assert!(handoff
                                    .verify_installed_transport(
                                        &roots[1],
                                        &roots[0],
                                        &keys,
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_millis()
                                            as u64
                                    )
                                    .is_err());
                                let (status, response) = http.json(
                                    "POST",
                                    &format!("{base}/assignments"),
                                    &delegated,
                                    "loss_partial_acquire_01",
                                    &acquire,
                                );
                                assert_ne!(status, 201);
                                assert_ne!(status, 202);
                                assert_eq!(
                                    super::super::la_adapter::state_custody::state_digest(
                                        &roots[0]
                                    )
                                    .unwrap(),
                                    before_worker
                                );
                                assert_eq!(
                                    super::super::la_adapter::state_custody::state_digest(
                                        &roots[1]
                                    )
                                    .unwrap(),
                                    before_controller
                                );
                                fs::write("/job/evidence/worker-loss-return-refusal.json",serde_json::to_vec(&serde_json::json!({"case":corruption,"worker_ready":ready,"acquire_status":status,"acquire_response":response,"complete_transport_refused":true,"worker_unchanged":true,"controller_unchanged":true,"admitted":false})).unwrap()).unwrap();
                                result["entered_loss_transport_refusal"] = serde_json::json!({"case":corruption,"phase":"partial_install","admitted":false});
                                control.write_all(b"STOP\n").unwrap();
                                assert_eq!(jsonstr(&returned.next(), "kind"), "STOPPED");
                                bridge.call(Op::StopW, Role::W, 0, &[]);
                                drop(returned);
                                break 'entered_transport;
                            }
                            let address: std::net::SocketAddr =
                                ready["address"].as_str().unwrap().parse().unwrap();
                            cwriter.frame(
                                b"WLRETURN ",
                                &serde_json::to_vec(
                                    &serde_json::json!({"handoff":handoff,"address":address}),
                                )
                                .unwrap(),
                            );
                            let reconciled: serde_json::Value =
                                serde_json::from_str(&cframes.next()).unwrap();
                            assert_eq!(
                                reconciled["ack"]["kind"], "ENTERED_LOSS_TRANSPORT_RECONCILED",
                                "{reconciled}"
                            );
                            handoff
                                .test_reopen_independent_ledgers(
                                    &cframes.transport_ledger.lock().unwrap(),
                                    &returned.transport_ledger.lock().unwrap(),
                                    &roots[1],
                                    &roots[0],
                                    &keys,
                                )
                                .unwrap();
                            fs::write(
                                "/job/evidence/worker-loss-return-transport-ack.json",
                                serde_json::to_vec(&reconciled).unwrap(),
                            )
                            .unwrap();
                            assert_eq!(
                                super::super::la_adapter::state_custody::state_digest(&roots[0])
                                    .unwrap(),
                                before_worker
                            );
                            assert_eq!(
                                super::super::la_adapter::state_custody::state_digest(&roots[1])
                                    .unwrap(),
                                before_controller
                            );
                            let wdb = super::super::la_store::open_pinned_readonly_database(
                                &roots[0],
                                "worker.sqlite",
                            )
                            .unwrap();
                            assert_eq!(
                                wdb.query_row(
                                    "SELECT COUNT(*) FROM operations WHERE state='started'",
                                    [],
                                    |r| r.get::<_, i64>(0)
                                )
                                .unwrap(),
                                1
                            );
                            let cdb = super::super::la_store::open_pinned_readonly_database(
                                &roots[1],
                                "lane_assignments.sqlite",
                            )
                            .unwrap();
                            assert_eq!(
                                cdb.query_row(
                                    "SELECT COUNT(*) FROM la_assignment_cleanup_receipts",
                                    [],
                                    |r| r.get::<_, i64>(0)
                                )
                                .unwrap(),
                                1
                            );
                            let wchannel = super::super::la_store::open_pinned_readonly_database(
                                &roots[0],
                                "worker-channel.sqlite",
                            )
                            .unwrap();
                            let cchannel = super::super::la_store::open_pinned_readonly_database(
                                &roots[1],
                                "controller-channel.sqlite",
                            )
                            .unwrap();
                            let retained = serde_json::json!({"worker":super::loss_retained_tables(&wchannel,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_epochs","channel_worker_epochs"]),"controller":super::loss_retained_tables(&cchannel,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_epochs","channel_worker_epochs"])});
                            let retained = serde_json::to_vec(&retained).unwrap();
                            assert!(retained.len() < 1048576);
                            fs::write(
                                "/job/evidence/worker-loss-return-retained-transport.json",
                                retained,
                            )
                            .unwrap();
                            let (input_name,input_hash):(String,String)=wdb.query_row("SELECT content,input_digest FROM worker_inputs WHERE operation=?1",[operation],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                            let mut file = super::super::la_artifacts::open_artifact(
                                &roots[0],
                                &input_name,
                                libc::O_RDONLY,
                            )
                            .unwrap();
                            let meta = file.metadata().unwrap();
                            let mut input_bytes = Vec::new();
                            file.read_to_end(&mut input_bytes).unwrap();
                            assert_eq!(hex::encode(Sha256::digest(&input_bytes)), input_hash);
                            let old_boot: String = wdb
                                .query_row("SELECT boot FROM reservation_session", [], |r| r.get(0))
                                .unwrap();
                            assert_eq!(old_boot, binding.worker_boot);
                            let generations: i64 = wdb
                                .query_row(
                                    "SELECT COUNT(*) FROM worker_session_generations",
                                    [],
                                    |r| r.get(0),
                                )
                                .unwrap();
                            assert_eq!(generations, 1);
                            let live_old_reservations: i64 = wdb
                                .query_row(
                                    "SELECT COUNT(*) FROM worker_reservations WHERE closed=0",
                                    [],
                                    |r| r.get(0),
                                )
                                .unwrap();
                            assert_eq!(live_old_reservations, 1);
                            fs::write("/job/evidence/worker-loss-return-retained-audit.json",serde_json::to_vec(&serde_json::json!({"input_file":input_name,"input_bytes":input_bytes.len(),"input_sha256":input_hash,"storage_blocks":meta.blocks(),"storage_block_bytes":512,"old_session_boot":old_boot,"session_generations":generations,"live_old_reservations":live_old_reservations,"started_operations":1,"spent_disposition":false,"source_bridge":false,"new_work_admission":false})).unwrap()).unwrap();
                            result["entered_loss_transport_return"] = serde_json::json!({"first_rpc":reconciled,"admitted":false,"worker_state_unchanged":true,"controller_state_unchanged":true,"old_started_retained":true,"source_bridge_installed":false,"disposition_installed":false,"new_work":false});
                            if corruption.starts_with("source-") || corruption == "activation" {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64;
                                let cap =
                                    super::super::la_adapter::EnteredLossSourceBridge::prepare(
                                        &handoff,
                                        &roots[1],
                                        &roots[0],
                                        &cframes.transport_ledger.lock().unwrap(),
                                        &returned.transport_ledger.lock().unwrap(),
                                        cframes.state_ledger.lock().unwrap().as_mut().unwrap(),
                                        &keys,
                                        now,
                                    )
                                    .unwrap();
                                let guards = cap.test_guards(&handoff, &keys).unwrap();
                                fs::write(
                                    "/job/evidence/entered-loss-source-signed-guards.json",
                                    serde_json::to_vec(&guards).unwrap(),
                                )
                                .unwrap();
                                let bytes = serde_json::to_vec(&cap).unwrap();
                                assert!(bytes.len() <= 12288);
                                fs::write("/job/evidence/entered-loss-source-bridge.json", &bytes)
                                    .unwrap();
                                if corruption == "source-mac" || corruption == "source-expired" {
                                    if corruption == "source-expired" {
                                        std::thread::sleep(std::time::Duration::from_millis(1700));
                                    }
                                    let attempted = if corruption == "source-mac" {
                                        serde_json::to_vec(&cap.test_corrupt_mac()).unwrap()
                                    } else {
                                        bytes.clone()
                                    };
                                    fs::write(
                                        "/job/evidence/entered-loss-source-attempted.json",
                                        &attempted,
                                    )
                                    .unwrap();
                                    control.frame(b"LSBRIDGE ", &attempted);
                                    let refused: serde_json::Value =
                                        serde_json::from_str(&returned.next()).unwrap();
                                    assert_eq!(
                                        refused["ack"]["kind"], "LOSS_SOURCE_BRIDGE_REFUSED",
                                        "{refused}"
                                    );
                                    assert_eq!(refused["ack"]["code"], "evidence_invalid");
                                    assert!(super::super::la_adapter::EnteredLossSourceBridge::test_no_role_bridge(&roots[0],"worker").unwrap());
                                    assert!(super::super::la_adapter::EnteredLossSourceBridge::test_no_role_bridge(&roots[1],"controller").unwrap());
                                    fs::write("/job/evidence/entered-loss-source-refusal.json",serde_json::to_vec(&serde_json::json!({"case":corruption,"actual":refused,"worker_bridge_absent":true,"controller_bridge_absent":true,"admitted":false})).unwrap()).unwrap();
                                    result["entered_loss_source_refusal"] =
                                        serde_json::json!({"case":corruption,"admitted":false});
                                    control.write_all(b"STOP\n").unwrap();
                                    assert_eq!(jsonstr(&returned.next(), "kind"), "STOPPED");
                                    bridge.call(Op::StopW, Role::W, 0, &[]);
                                    drop(returned);
                                    break 'entered_transport;
                                }
                                control.frame(b"LSBRIDGE ", &bytes);
                                let wa: serde_json::Value =
                                    serde_json::from_str(&returned.next()).unwrap();
                                assert_eq!(
                                    wa["ack"]["kind"], "LOSS_SOURCE_BRIDGE_INSTALLED",
                                    "{wa}"
                                );
                                fs::write(
                                    "/job/evidence/entered-loss-source-worker-ack.json",
                                    serde_json::to_vec(&wa).unwrap(),
                                )
                                .unwrap();
                                if corruption == "source-partial" {
                                    assert!(cap
                                        .complete(
                                            &roots[1],
                                            &roots[0],
                                            cframes.state_ledger.lock().unwrap().as_mut().unwrap(),
                                            &keys
                                        )
                                        .is_err());
                                    assert!(super::super::la_adapter::EnteredLossSourceBridge::test_no_role_bridge(&roots[1],"controller").unwrap());
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64;
                                    let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":6,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                                    let frame = super::super::la_adapter::sign_source_observation(
                                        &keys.authority,
                                        &next,
                                        &canonical,
                                    )
                                    .unwrap();
                                    fs::write(
                                        "/job/evidence/entered-loss-source-attempted-current.json",
                                        &frame,
                                    )
                                    .unwrap();
                                    control.frame(b"AUTH ", &frame);
                                    let refused: serde_json::Value =
                                        serde_json::from_str(&returned.next()).unwrap();
                                    assert_eq!(refused["kind"], "AUTHORITY_REFUSED", "{refused}");
                                    assert_eq!(refused["code"], "evidence_invalid");
                                    fs::write("/job/evidence/entered-loss-source-refusal.json",serde_json::to_vec(&serde_json::json!({"case":corruption,"actual":refused,"completion_refused":true,"controller_bridge_absent":true,"admitted":false})).unwrap()).unwrap();
                                    result["entered_loss_source_refusal"] =
                                        serde_json::json!({"case":corruption,"admitted":false});
                                    bridge.call(Op::StopW, Role::W, 0, &[]);
                                    drop(returned);
                                    break 'entered_transport;
                                }
                                cwriter.frame(b"LSBRIDGE ", &bytes);
                                let ca: serde_json::Value =
                                    serde_json::from_str(&cframes.next()).unwrap();
                                assert_eq!(
                                    ca["ack"]["kind"], "LOSS_SOURCE_BRIDGE_INSTALLED",
                                    "{ca}"
                                );
                                fs::write(
                                    "/job/evidence/entered-loss-source-controller-ack.json",
                                    serde_json::to_vec(&ca).unwrap(),
                                )
                                .unwrap();
                                let complete = cap
                                    .complete(
                                        &roots[1],
                                        &roots[0],
                                        cframes.state_ledger.lock().unwrap().as_mut().unwrap(),
                                        &keys,
                                    )
                                    .unwrap();
                                let bytes = serde_json::to_vec(&complete).unwrap();
                                assert!(bytes.len() <= 4096);
                                fs::write(
                                    "/job/evidence/entered-loss-source-consumption.json",
                                    &bytes,
                                )
                                .unwrap();
                                control.frame(b"LSCOMMIT ", &bytes);
                                cwriter.frame(b"LSCOMMIT ", &bytes);
                                let wa: serde_json::Value =
                                    serde_json::from_str(&returned.next()).unwrap();
                                let ca: serde_json::Value =
                                    serde_json::from_str(&cframes.next()).unwrap();
                                assert_eq!(
                                    wa["ack"]["kind"], "LOSS_SOURCE_BRIDGE_COMMITTED",
                                    "{wa}"
                                );
                                assert_eq!(
                                    ca["ack"]["kind"], "LOSS_SOURCE_BRIDGE_COMMITTED",
                                    "{ca}"
                                );
                                cap.verify_complete(
                                    &roots[1],
                                    &roots[0],
                                    cframes.state_ledger.lock().unwrap().as_mut().unwrap(),
                                    &keys,
                                )
                                .unwrap();
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64;
                                let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":6,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                                let source = super::super::la_adapter::sign_source_observation(
                                    &keys.authority,
                                    &next,
                                    &canonical,
                                )
                                .unwrap();
                                cframes
                                    .state_ledger
                                    .lock()
                                    .unwrap()
                                    .as_mut()
                                    .unwrap()
                                    .record_authority(&source)
                                    .unwrap();
                                control.frame(b"AUTH ", &source);
                                cwriter.frame(b"AUTH ", &source);
                                let wa: serde_json::Value =
                                    serde_json::from_str(&returned.next()).unwrap();
                                let ca: serde_json::Value =
                                    serde_json::from_str(&cframes.next()).unwrap();
                                assert_eq!(wa["kind"], "AUTHORITY_ACK", "{wa}");
                                assert_eq!(ca["kind"], "AUTHORITY_ACK", "{ca}");
                                cframes
                                    .state_ledger
                                    .lock()
                                    .unwrap()
                                    .as_mut()
                                    .unwrap()
                                    .observe_authority(
                                        &source,
                                        &serde_json::from_value(ca["ack"].clone()).unwrap(),
                                        &serde_json::from_value(wa["ack"].clone()).unwrap(),
                                    )
                                    .unwrap();
                                fs::write("/job/evidence/entered-loss-current-source.json",serde_json::to_vec(&serde_json::json!({"frame":String::from_utf8(source).unwrap(),"worker":wa,"controller":ca,"admitted":false})).unwrap()).unwrap();
                                cwriter.frame(b"LSPROBE ", b"{}");
                                let probe: serde_json::Value =
                                    serde_json::from_str(&cframes.next()).unwrap();
                                assert_eq!(
                                    probe["ack"]["kind"], "LOSS_SOURCE_BRIDGE_PROBE",
                                    "{probe}"
                                );
                                fs::write(
                                    "/job/evidence/entered-loss-source-next-rpc.json",
                                    serde_json::to_vec(&probe).unwrap(),
                                )
                                .unwrap();
                                let wc = super::super::la_store::open_pinned_readonly_database(
                                    &roots[0],
                                    "worker-channel.sqlite",
                                )
                                .unwrap();
                                let cc = super::super::la_store::open_pinned_readonly_database(
                                    &roots[1],
                                    "controller-channel.sqlite",
                                )
                                .unwrap();
                                let sc = super::super::la_store::open_pinned_readonly_database(
                                    &roots[1],
                                    "service-custody.sqlite",
                                )
                                .unwrap();
                                let claims = super::super::la_store::open_pinned_readonly_database(
                                    &roots[1],
                                    "lane_assignments.sqlite",
                                )
                                .unwrap();
                                let all = serde_json::json!({"worker":super::loss_retained_tables(&wc,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_epochs","channel_worker_epochs","channel_loss_source_bridge"]),"controller":super::loss_retained_tables(&cc,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_epochs","channel_worker_epochs","channel_loss_source_bridge"]),"service":super::loss_retained_tables(&sc,&["service_checkpoints","service_close_midpoints"]),"claims":super::loss_retained_tables(&claims,&["la_authority_observations","la_worker_loss_sources","la_assignment_cleanup_receipts"])});
                                let data = serde_json::to_vec(&all).unwrap();
                                assert!(data.len() < 1048576);
                                fs::write(
                                    "/job/evidence/entered-loss-source-full-history.json",
                                    data,
                                )
                                .unwrap();
                                assert!(handoff.verify_installed_transport(&roots[1],&roots[0],&keys,now).is_err(),"strict pre-bridge root frontier must remain strict after legitimate C source mutation");
                                result["entered_loss_source_bridge"] = serde_json::json!({"complete":true,"real_source_sequence":6,"next_rpc":probe,"admitted":false});
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64;
                                let disposition =
                                    super::super::la_adapter::SpentLossDisposition::issue(
                                        &handoff,
                                        &roots[0],
                                        &roots[1],
                                        &returned.transport_ledger.lock().unwrap(),
                                        &cframes.transport_ledger.lock().unwrap(),
                                        cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                                        &keys,
                                        now,
                                    )
                                    .unwrap();
                                let bytes = serde_json::to_vec(&disposition).unwrap();
                                assert!(bytes.len() <= 12288);
                                fs::write(
                                    "/job/evidence/entered-loss-spent-disposition.json",
                                    &bytes,
                                )
                                .unwrap();
                                if corruption == "source-spent-mac"
                                    || corruption == "source-spent-expired"
                                {
                                    if corruption == "source-spent-expired" {
                                        std::thread::sleep(std::time::Duration::from_millis(1700));
                                    }
                                    let attempted = if corruption == "source-spent-mac" {
                                        serde_json::to_vec(&disposition.test_corrupt_mac()).unwrap()
                                    } else {
                                        bytes.clone()
                                    };
                                    fs::write(
                                        "/job/evidence/entered-loss-spent-attempted.json",
                                        &attempted,
                                    )
                                    .unwrap();
                                    cwriter.frame(b"LSDISPOSE ", &attempted);
                                    let refused: serde_json::Value =
                                        serde_json::from_str(&cframes.next()).unwrap();
                                    assert_eq!(
                                        refused["ack"]["kind"], "SPENT_LOSS_DISPOSITION_REFUSED",
                                        "{refused}"
                                    );
                                    assert_eq!(refused["ack"]["code"], "evidence_invalid");
                                    let w = super::super::la_store::open_pinned_readonly_database(
                                        &roots[0],
                                        "worker.sqlite",
                                    )
                                    .unwrap();
                                    let occupied =
                                        super::super::la_worker::verified_execution_occupancy(
                                            &w,
                                            &roots[0],
                                            Some(&keys),
                                        )
                                        .unwrap();
                                    assert_eq!(occupied.live_operations, 1);
                                    assert_eq!(occupied.live_reservations, 1);
                                    fs::write("/job/evidence/entered-loss-spent-refusal.json",serde_json::to_vec(&serde_json::json!({"case":corruption,"actual":refused,"live_operations":occupied.live_operations,"live_reservations":occupied.live_reservations,"admitted":false})).unwrap()).unwrap();
                                    result["entered_loss_spent_refusal"] =
                                        serde_json::json!({"case":corruption,"admitted":false});
                                    control.write_all(b"STOP\n").unwrap();
                                    assert_eq!(jsonstr(&returned.next(), "kind"), "STOPPED");
                                    bridge.call(Op::StopW, Role::W, 0, &[]);
                                    drop(returned);
                                    break 'entered_transport;
                                }
                                cwriter.frame(b"LSDISPOSE ", &bytes);
                                let ack: serde_json::Value =
                                    serde_json::from_str(&cframes.next()).unwrap();
                                assert_eq!(ack["ack"]["kind"], "ENTERED_LOSS_DISPOSED", "{ack}");
                                fs::write(
                                    "/job/evidence/entered-loss-spent-install-ack.json",
                                    serde_json::to_vec(&ack).unwrap(),
                                )
                                .unwrap();
                                let wdb = super::super::la_store::open_pinned_readonly_database(
                                    &roots[0],
                                    "worker.sqlite",
                                )
                                .unwrap();
                                let before = super::super::la_worker::verified_execution_occupancy(
                                    &wdb,
                                    &roots[0],
                                    Some(&keys),
                                )
                                .unwrap();
                                assert_eq!(before.live_operations, 1);
                                assert_eq!(before.live_reservations, 1);
                                assert_eq!(before.retained_bytes, 45);
                                let proof = disposition
                                    .witness_consumed(
                                        &roots[0],
                                        &roots[1],
                                        &returned.transport_ledger.lock().unwrap(),
                                        &cframes.transport_ledger.lock().unwrap(),
                                        cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                                        &keys,
                                    )
                                    .unwrap();
                                let bytes = serde_json::to_vec(&proof).unwrap();
                                assert!(bytes.len() <= 4096);
                                fs::write(
                                    "/job/evidence/entered-loss-spent-consumption.json",
                                    &bytes,
                                )
                                .unwrap();
                                let pre_w = super::super::la_store::open_pinned_readonly_database(
                                    &roots[0],
                                    "worker-channel.sqlite",
                                )
                                .unwrap();
                                let pre_c = super::super::la_store::open_pinned_readonly_database(
                                    &roots[1],
                                    "controller-channel.sqlite",
                                )
                                .unwrap();
                                let pre = serde_json::json!({"worker":super::loss_retained_tables(&wdb,&["operations","worker_reservations","worker_spent_losses","worker_inputs","worker_session_generations","worker_session_snapshots","reservation_session"]),"worker_transport":super::loss_retained_tables(&pre_w,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_worker_epochs","channel_loss_source_bridge"]),"controller_transport":super::loss_retained_tables(&pre_c,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_worker_epochs","channel_loss_source_bridge"])});
                                let data = serde_json::to_vec(&pre).unwrap();
                                assert!(data.len() < 1048576);
                                fs::write(
                                    "/job/evidence/entered-loss-spent-precommit-full-history.json",
                                    data,
                                )
                                .unwrap();
                                if corruption == "source-spent-partial" {
                                    let occupied =
                                        super::super::la_worker::verified_execution_occupancy(
                                            &wdb,
                                            &roots[0],
                                            Some(&keys),
                                        )
                                        .unwrap();
                                    assert_eq!(occupied.live_operations, 1);
                                    assert_eq!(occupied.live_reservations, 1);
                                    fs::write("/job/evidence/entered-loss-spent-refusal.json",serde_json::to_vec(&serde_json::json!({"case":corruption,"signed_consumption_not_installed":true,"live_operations":occupied.live_operations,"live_reservations":occupied.live_reservations,"retained_bytes":occupied.retained_bytes,"admitted":false})).unwrap()).unwrap();
                                    result["entered_loss_spent_refusal"] =
                                        serde_json::json!({"case":corruption,"admitted":false});
                                    control.write_all(b"STOP\n").unwrap();
                                    assert_eq!(jsonstr(&returned.next(), "kind"), "STOPPED");
                                    bridge.call(Op::StopW, Role::W, 0, &[]);
                                    drop(returned);
                                    break 'entered_transport;
                                }
                                let bad = serde_json::to_vec(&proof.test_corrupt_mac()).unwrap();
                                fs::write(
                                    "/job/evidence/entered-loss-spent-proof-attempted.json",
                                    &bad,
                                )
                                .unwrap();
                                control.frame(b"LSDISPOSITION ", &bad);
                                let refused: serde_json::Value =
                                    serde_json::from_str(&returned.next()).unwrap();
                                assert_eq!(
                                    refused["ack"]["kind"], "SPENT_LOSS_COMMIT_REFUSED",
                                    "{refused}"
                                );
                                assert_eq!(refused["ack"]["code"], "evidence_invalid");
                                let still = super::super::la_worker::verified_execution_occupancy(
                                    &wdb,
                                    &roots[0],
                                    Some(&keys),
                                )
                                .unwrap();
                                assert_eq!(still.live_operations, 1);
                                assert_eq!(still.live_reservations, 1);
                                fs::write("/job/evidence/entered-loss-spent-proof-refusal.json",serde_json::to_vec(&serde_json::json!({"actual":refused,"live_operations":still.live_operations,"live_reservations":still.live_reservations,"admitted":false})).unwrap()).unwrap();
                                control.frame(b"LSDISPOSITION ", &bytes);
                                let committed: serde_json::Value =
                                    serde_json::from_str(&returned.next()).unwrap();
                                assert_eq!(
                                    committed["ack"]["kind"], "SPENT_LOSS_COMMITTED",
                                    "{committed}"
                                );
                                fs::write(
                                    "/job/evidence/entered-loss-spent-commit-ack.json",
                                    serde_json::to_vec(&committed).unwrap(),
                                )
                                .unwrap();
                                control.frame(
                                    b"LSGUARDS ",
                                    &serde_json::to_vec(&disposition.digest().unwrap()).unwrap(),
                                );
                                let guards: serde_json::Value =
                                    serde_json::from_str(&returned.next()).unwrap();
                                assert_eq!(
                                    guards["ack"]["kind"], "RETIRED_LOOKUP_PROBES",
                                    "{guards}"
                                );
                                assert_eq!(guards["ack"]["probes"].as_array().unwrap().len(), 29);
                                assert_eq!(
                                    guards["ack"]["complete_retained_state_unchanged"],
                                    true
                                );
                                assert_eq!(guards["ack"]["NEW_claim_held"], false);
                                fs::write(
                                    "/job/evidence/entered-loss-retired-lookup-probes.json",
                                    serde_json::to_vec(&guards).unwrap(),
                                )
                                .unwrap();
                                let after = super::super::la_worker::verified_execution_occupancy(
                                    &wdb,
                                    &roots[0],
                                    Some(&keys),
                                )
                                .unwrap();
                                assert_eq!(after.live_operations, 0);
                                assert_eq!(after.live_reservations, 0);
                                assert_eq!(after.retained_bytes, 45);
                                let raw:(i64,i64,i64,String,i64)=wdb.query_row("SELECT (SELECT COUNT(*) FROM operations WHERE state='started'),(SELECT COUNT(*) FROM worker_reservations WHERE closed=0),(SELECT COUNT(*) FROM worker_session_generations),(SELECT boot FROM reservation_session),(SELECT sequence FROM reservation_session)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
                                assert_eq!(raw.0, 1);
                                assert_eq!(raw.1, 1);
                                assert_eq!(raw.2, 1);
                                assert_eq!(raw.3, binding.worker_boot);
                                super::super::la_worker::verify_session_history(&wdb, &keys.reply)
                                    .unwrap();
                                let wc = super::super::la_store::open_pinned_readonly_database(
                                    &roots[0],
                                    "worker-channel.sqlite",
                                )
                                .unwrap();
                                let cc = super::super::la_store::open_pinned_readonly_database(
                                    &roots[1],
                                    "controller-channel.sqlite",
                                )
                                .unwrap();
                                let sc = super::super::la_store::open_pinned_readonly_database(
                                    &roots[1],
                                    "service-custody.sqlite",
                                )
                                .unwrap();
                                let retained = serde_json::json!({"worker":super::loss_retained_tables(&wdb,&["operations","worker_reservations","worker_spent_losses","worker_inputs","worker_input_assignments","worker_mandates","worker_assignment_terms","worker_session_generations","worker_session_snapshots","reservation_session","worker_inspect_commands","worker_result_receipts","worker_stop_receipts","worker_close_receipts","worker_cleanup_receipts"]),"worker_transport":super::loss_retained_tables(&wc,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_worker_epochs","channel_loss_source_bridge","channel_spent_loss_consumption"]),"controller_transport":super::loss_retained_tables(&cc,&["channel_identity","channel_log","channel_checkpoints","channel_authority","channel_worker_epochs","channel_loss_source_bridge"]),"service":super::loss_retained_tables(&sc,&["service_checkpoints","service_close_midpoints"])});
                                let data = serde_json::to_vec(&retained).unwrap();
                                assert!(data.len() < 1048576);
                                fs::write(
                                    "/job/evidence/entered-loss-spent-full-history.json",
                                    data,
                                )
                                .unwrap();
                                let name: String = wdb
                                    .query_row(
                                        "SELECT content FROM worker_inputs WHERE operation=?1",
                                        [&disposition.command.operation],
                                        |r| r.get(0),
                                    )
                                    .unwrap();
                                let mut input = super::super::la_artifacts::open_artifact(
                                    &roots[0],
                                    &name,
                                    libc::O_RDONLY,
                                )
                                .unwrap();
                                let meta = input.metadata().unwrap();
                                let mut actual_input = Vec::new();
                                input.read_to_end(&mut actual_input).unwrap();
                                assert_eq!(actual_input.len(), 45);
                                assert_eq!(
                                    hex::encode(Sha256::digest(&actual_input)),
                                    disposition.command.input_digest
                                );
                                fs::write(
                                    "/job/evidence/entered-loss-retained-input.bin",
                                    &actual_input,
                                )
                                .unwrap();
                                fs::write("/job/evidence/entered-loss-retained-storage.json",serde_json::to_vec(&serde_json::json!({"name":name,"bytes":actual_input.len(),"sha256":hex::encode(Sha256::digest(&actual_input)),"dev":meta.dev(),"inode":meta.ino(),"blocks":meta.blocks(),"block_bytes":512,"raw_started":raw.0,"raw_open_reservations":raw.1,"live_operations":after.live_operations,"live_reservations":after.live_reservations,"admitted":false})).unwrap()).unwrap();
                                result["entered_loss_disposition"] = serde_json::json!({"verified_live_operations":after.live_operations,"verified_live_reservations":after.live_reservations,"retained_bytes":after.retained_bytes,"raw_started":raw.0,"raw_open_reservations":raw.1,"session_generations":raw.2,"old_boot":raw.3,"old_cursor":raw.4,"admitted":false,"new_computation":false});
                                if corruption == "activation" {
                                    // The same protected W2/C/P/keeper and consumed
                                    // original disposition feed the delivered APIs.
                                    let (observed, rights) =
                                        bridge.call(Op::ObserveAdmission, Role::P, 0, &[]);
                                    assert!(rights.is_empty());
                                    let observed: serde_json::Value =
                                        serde_json::from_str(&observed).unwrap();
                                    assert_eq!(observed["kind"], "LOSS_ADMISSION_OBSERVED");
                                    fs::write(
                                        "/job/evidence/loss-admission-actual-processes.json",
                                        serde_json::to_vec(&observed).unwrap(),
                                    )
                                    .unwrap();
                                    // Source7 is genuinely signed now and consumed by BOTH
                                    // roles. The C-only historical source is never relabeled.
                                    let source_sequence = cframes
                                        .state_ledger
                                        .lock()
                                        .unwrap()
                                        .as_ref()
                                        .unwrap()
                                        .authority_sequence()
                                        + 1;
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64;
                                    let canonical = super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":source_sequence,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                                    let current_source =
                                        super::super::la_adapter::sign_source_observation(
                                            &keys.authority,
                                            &next,
                                            &canonical,
                                        )
                                        .unwrap();
                                    cframes
                                        .state_ledger
                                        .lock()
                                        .unwrap()
                                        .as_mut()
                                        .unwrap()
                                        .record_authority(&current_source)
                                        .unwrap();
                                    control.frame(b"AUTH ", &current_source);
                                    cwriter.frame(b"AUTH ", &current_source);
                                    let wa: serde_json::Value =
                                        serde_json::from_str(&returned.next()).unwrap();
                                    let ca: serde_json::Value =
                                        serde_json::from_str(&cframes.next()).unwrap();
                                    assert_eq!(wa["kind"], "AUTHORITY_ACK", "{wa}");
                                    assert_eq!(ca["kind"], "AUTHORITY_ACK", "{ca}");
                                    cframes
                                        .state_ledger
                                        .lock()
                                        .unwrap()
                                        .as_mut()
                                        .unwrap()
                                        .observe_authority(
                                            &current_source,
                                            &serde_json::from_value(ca["ack"].clone()).unwrap(),
                                            &serde_json::from_value(wa["ack"].clone()).unwrap(),
                                        )
                                        .unwrap();
                                    fs::write("/job/evidence/loss-admission-current-source.json",serde_json::to_vec(&serde_json::json!({"frame":String::from_utf8(current_source).unwrap(),"worker":wa,"controller":ca,"source_sequence":source_sequence})).unwrap()).unwrap();
                                    // P independently reauthenticates the entire persisted
                                    // source history against its actual protected bootstrap seed.
                                    let mut authority = p_authority_seed.clone();
                                    let claims =
                                        super::super::la_store::open_pinned_readonly_database(
                                            &roots[1],
                                            "lane_assignments.sqlite",
                                        )
                                        .unwrap();
                                    let history: Vec<(i64, Vec<u8>, Vec<u8>)> = {
                                        let mut st=claims.prepare("SELECT sequence,body,mac FROM la_authority_observations ORDER BY sequence").unwrap();
                                        let rows = st
                                            .query_map([], |r| {
                                                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                                            })
                                            .unwrap()
                                            .collect::<Result<_, _>>()
                                            .unwrap();
                                        rows
                                    };
                                    assert_eq!(history.len() as u64, source_sequence);
                                    for (index, (sequence, body, mac)) in history.iter().enumerate()
                                    {
                                        let mac: [u8; 32] = mac.clone().try_into().unwrap();
                                        super::super::la_adapter::verify_authority_observation(
                                            &keys.authority,
                                            body,
                                            &mac,
                                        )
                                        .unwrap();
                                        let row: serde_json::Value =
                                            serde_json::from_slice(body).unwrap();
                                        assert_eq!(*sequence, index as i64 + 1);
                                        assert_eq!(
                                            row["schema_version"],
                                            "diffuser-authority-observation/v1"
                                        );
                                        assert_eq!(
                                            row["sequence"].as_u64(),
                                            Some(index as u64 + 1)
                                        );
                                        let clock = row["observed_at"].as_u64().unwrap();
                                        assert!(clock >= authority.observed_at);
                                        for revoked in row["revoked"].as_array().unwrap() {
                                            let id = revoked.as_str().unwrap();
                                            let grant = authority
                                                .grants
                                                .iter_mut()
                                                .find(|g| g.id == id)
                                                .unwrap();
                                            grant.revoked = true;
                                        }
                                        authority.observation_sequence = *sequence as u64;
                                        authority.observed_at = clock;
                                    }
                                    authority.loss_scope = Some((
                                        disposition.command.job.clone(),
                                        disposition.command.assignment.clone(),
                                    ));
                                    drop(claims);
                                    let processes:super::super::la_adapter::LossReturnProcesses=serde_json::from_value(serde_json::json!({"worker_ready":ready,"controller_ready":serde_json::from_str::<serde_json::Value>(&cready).unwrap(),"worker":observed["worker"],"controller":observed["controller"],"parent":observed["parent"],"keeper":observed["keeper"],"observed_at":observed["observed_at"]})).unwrap();
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64;
                                    let resource =
                                        family.seal(&next, &keys, now, now + 12000).unwrap();
                                    super::super::la_adapter::recovery_trace(
                                        "loss_admission_genuine_prepare",
                                        serde_json::json!({"source_sequence":source_sequence,"now":now}),
                                    );
                                    let admission =
                                        super::super::la_adapter::LossReturnAdmission::prepare(
                                            &disposition,
                                            resource,
                                            processes.clone(),
                                            &roots[0],
                                            &roots[1],
                                            &returned.transport_ledger.lock().unwrap(),
                                            &cframes.transport_ledger.lock().unwrap(),
                                            cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                                            &keys,
                                            &authority,
                                        )
                                        .unwrap();
                                    let intent_readback =
                                        fs::read("/job/custody/loss-return-admission-intent.json")
                                            .unwrap();
                                    assert_eq!(
                                        intent_readback,
                                        serde_json::to_vec(&admission).unwrap()
                                    );
                                    fs::write(
                                        "/job/evidence/loss-admission-intent-readback.json",
                                        &intent_readback,
                                    )
                                    .unwrap();
                                    let install=serde_json::to_vec(&serde_json::json!({"kind":"diffuser-loss-return-admission-install/v1","admission":admission})).unwrap();
                                    fs::write("/job/evidence/loss-admission-envelope.json",serde_json::to_vec(&serde_json::json!({"install_control_bytes":install.len()+10,"frame_bound":16384,"metadata_bound":65536,"source_sequence":source_sequence,"actual_populated_current_roles":true})).unwrap()).unwrap();
                                    assert!(install.len() + 10 < 16384);
                                    cwriter.frame(b"WLRETURN ", &install);
                                    let installed: serde_json::Value =
                                        serde_json::from_str(&cframes.next()).unwrap();
                                    fs::write(
                                        "/job/evidence/loss-admission-install-ack.json",
                                        serde_json::to_vec(&installed).unwrap(),
                                    )
                                    .unwrap();
                                    assert_eq!(
                                        installed["ack"]["kind"],
                                        "LOSS_RETURN_INSTALLED_QUARANTINED",
                                        "{installed}"
                                    );
                                    let complete = admission
                                        .witness_installed(
                                            &roots[0],
                                            &roots[1],
                                            &returned.transport_ledger.lock().unwrap(),
                                            &cframes.transport_ledger.lock().unwrap(),
                                            cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                                            &keys,
                                        )
                                        .unwrap();
                                    let bytes = serde_json::to_vec(&complete).unwrap();
                                    assert!(bytes.len() + 22 < 16384);
                                    control.frame(b"LACOMPLETE ", &bytes);
                                    let wa: serde_json::Value =
                                        serde_json::from_str(&returned.next()).unwrap();
                                    assert_eq!(
                                        wa["ack"]["kind"], "LOSS_RETURN_COMPLETION_PERSISTED",
                                        "{wa}"
                                    );
                                    cwriter.frame(b"WLRETURN LACOMPLETE ", &bytes);
                                    let ca: serde_json::Value =
                                        serde_json::from_str(&cframes.next()).unwrap();
                                    assert_eq!(
                                        ca["ack"]["kind"], "LOSS_RETURN_COMPLETION_PERSISTED",
                                        "{ca}"
                                    );
                                    fs::write(
                                        "/job/evidence/loss-admission-completion-copy-acks.json",
                                        serde_json::to_vec(
                                            &serde_json::json!({"worker":wa,"controller":ca}),
                                        )
                                        .unwrap(),
                                    )
                                    .unwrap();
                                    // This actual independently fsynced named P record must
                                    // exist before either final consumer can run.
                                    let linearization = admission
                                        .linearize_completed(
                                            &roots[0],
                                            &roots[1],
                                            &mut returned.transport_ledger.lock().unwrap(),
                                            &cframes.transport_ledger.lock().unwrap(),
                                            cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                                            &keys,
                                            &authority,
                                            &processes,
                                        )
                                        .unwrap();
                                    let bytes = serde_json::to_vec(&linearization).unwrap();
                                    assert_eq!(
                                        fs::read(
                                            "/job/custody/loss-return-admission-linearization.json"
                                        )
                                        .unwrap(),
                                        bytes
                                    );
                                    fs::write(
                                        "/job/evidence/loss-admission-durable-global-readback.json",
                                        &bytes,
                                    )
                                    .unwrap();
                                    control.frame(b"LAACTIVATE ", &bytes);
                                    let wa: serde_json::Value =
                                        serde_json::from_str(&returned.next()).unwrap();
                                    fs::write(
                                        "/job/evidence/loss-admission-worker-final.json",
                                        serde_json::to_vec(&wa).unwrap(),
                                    )
                                    .unwrap();
                                    assert_eq!(wa["ack"]["kind"], "LOSS_RETURN_ACTIVATED", "{wa}");
                                    let final_c=serde_json::to_vec(&serde_json::json!({"linearization":linearization,"worker":wa["ack"]["receipt"]})).unwrap();
                                    assert!(final_c.len() + 22 < 16384);
                                    cwriter.frame(b"WLRETURN LAACTIVATE ", &final_c);
                                    let ca: serde_json::Value =
                                        serde_json::from_str(&cframes.next()).unwrap();
                                    fs::write(
                                        "/job/evidence/loss-admission-controller-final.json",
                                        serde_json::to_vec(&ca).unwrap(),
                                    )
                                    .unwrap();
                                    assert_eq!(ca["ack"]["kind"], "LOSS_RETURN_ACTIVATED", "{ca}");
                                    result["actual_final_activation"] = serde_json::json!({"worker":wa,"controller":ca,"genuine_source":source_sequence,"global_readback":true,"NEW_claim_held":false,"NEW_compute_release2_proved":false});
                                }
                            }
                            control.write_all(b"STOP\n").unwrap();
                            assert_eq!(jsonstr(&returned.next(), "kind"), "STOPPED");
                            if corruption == "activation" {
                                cwriter.write_all(b"STOP\n").unwrap();
                                assert_eq!(jsonstr(&cframes.next(), "kind"), "STOPPED");
                                let (stopped, rights) =
                                    bridge.call(Op::StopReturnedRoles, Role::P, 0, &[]);
                                assert!(rights.is_empty());
                                assert_eq!(jsonstr(&stopped, "kind"), "LOSS_RETURN_ROLES_STOPPED");
                                returned_roles_stopped = true;
                            } else {
                                bridge.call(Op::StopW, Role::W, 0, &[]);
                            }
                            drop(returned);
                        }
                    } else {
                        bridge.call(Op::StopW, Role::W, 0, &[]);
                        drop(hold);
                        drop(streams);
                    }
                }
                fs::write(
                    "/job/evidence/client-result.json",
                    serde_json::to_vec(&result).unwrap(),
                )
                .unwrap();
                if !returned_roles_stopped {
                    cwriter.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&cframes.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                }
                if !loss {
                    writer.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                }
                if !returned_roles_stopped {
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                }
                bridge.call(Op::Done, Role::P, 0, &[]);
                println!("{result}");
                return;
            }
            let original_stop_state = if stop_recovery || never_started_case {
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let original: (String, String, String, i64) = claims.query_row("SELECT p.command,m.body,j.id,p.permit_until FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1", [job_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                if !never_started_case {
                    let revision: i64 = claims
                        .query_row("SELECT revision FROM la_jobs WHERE id=?1", [job_id], |r| {
                            r.get(0)
                        })
                        .unwrap();
                    drop(claims);
                    let mut socket = http.0.try_clone().unwrap();
                    let body = serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision})).unwrap();
                    let header = format!("POST {base}/jobs/{job_id}/cancel HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {delegated}\r\nIdempotency-Key: stop_recovery_cancel_001\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",body.len());
                    terminal_reader = Some(std::thread::spawn(move || {
                        socket.write_all(header.as_bytes()).unwrap();
                        socket.write_all(&body).unwrap();
                        let mut byte = [0; 1];
                        socket.read(&mut byte)
                    }));
                    let presend = std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                        == Ok("controller-stop-recovery-presend");
                    let barrier: serde_json::Value = serde_json::from_str(&if presend {
                        cframes.next()
                    } else {
                        frames.next()
                    })
                    .unwrap();
                    assert_eq!(
                        barrier["kind"],
                        if presend {
                            "STOP_MIDPOINT_BEFORE_SEND"
                        } else {
                            "STOP_COMMITTED_BEFORE_ACK"
                        }
                    );
                    fs::write(
                        "/job/evidence/stop-boundary.json",
                        serde_json::to_vec(&barrier).unwrap(),
                    )
                    .unwrap();
                }
                Some(original)
            } else {
                None
            };
            let (output_id, report) = if stop_recovery || never_started_case {
                (String::new(), Vec::new())
            } else if recovery_case {
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let output: String = claims
                    .query_row(
                        "SELECT result_artifact FROM la_jobs WHERE id=?1 AND state='succeeded'",
                        [job_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                let worker = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker.sqlite",
                )
                .unwrap();
                let report: Vec<u8> = worker
                    .query_row(
                        "SELECT report FROM operations WHERE job=?1 AND state='complete'",
                        [job_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                (output, report)
            } else {
                refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
                let (status, view) = http.json(
                    "GET",
                    &format!("{base}/jobs/{job_id}"),
                    &delegated,
                    "",
                    &serde_json::Value::Null,
                );
                assert_eq!(status, 200);
                assert_eq!(view["state"], "succeeded");
                super::assert_development_response("JobView", &view);
                let output_id = view["result_artifact_id"].as_str().unwrap().to_owned();
                refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
                let (status, report) = http.request(
                    "GET",
                    &format!("{base}/artifacts/{output_id}/content"),
                    &delegated,
                    "",
                    "",
                    &[],
                );
                assert_eq!(status, 200);
                (output_id, report)
            };
            let (count, digest) = if !stop_recovery && !never_started_case {
                let output: serde_json::Value = serde_json::from_slice(&report).unwrap();
                assert_eq!(output["sha256"], hex::encode(Sha256::digest(input)));
                assert_eq!(output["bytes"], input.len());
                assert_eq!(output["job_id"], job_id);
                let db = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker.sqlite",
                )
                .unwrap();
                let (count, saved): (i64, Vec<u8>) = db
                    .query_row(
                        "SELECT COUNT(*),report FROM operations WHERE job=?1 AND state='complete'",
                        [job_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(count, 1);
                assert_eq!(saved, report);
                drop(db);
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let digest: String = claims
                    .query_row(
                        "SELECT report_digest FROM la_job_results WHERE job=?1",
                        [job_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(digest, hex::encode(Sha256::digest(&report)));
                drop(claims);
                (count, digest)
            } else {
                (0, String::new())
            };
            if close_recovery {
                refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let revision: i64 = claims
                    .query_row(
                        "SELECT revision FROM la_assignment_revisions WHERE assignment_id=?1",
                        [assignment_id],
                        |r| r.get(0),
                    )
                    .unwrap();
                drop(claims);
                let mut socket = http.0.try_clone().unwrap();
                let body=serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":revision})).unwrap();
                let header=format!("POST {base}/assignments/{assignment_id}/release HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {delegated}\r\nIdempotency-Key: vertical_release_01\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",body.len());
                terminal_reader = Some(std::thread::spawn(move || {
                    socket.write_all(header.as_bytes()).unwrap();
                    socket.write_all(&body).unwrap();
                    let mut byte = [0; 1];
                    socket.read(&mut byte)
                }));
                let barrier: serde_json::Value = serde_json::from_str(&frames.next()).unwrap();
                assert_eq!(barrier["kind"], "CLOSE_COMMITTED_BEFORE_ACK");
                fs::write(
                    "/job/evidence/close-before-ack.json",
                    serde_json::to_vec(&barrier).unwrap(),
                )
                .unwrap();
            }
            if worker_close_recovery {
                // W-only loss: exact protected pidfd death, unchanged live C/P/keepers.
                let before_worker =
                    super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                let before_controller =
                    super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                let ledger = frames.transport_ledger.clone();
                let (death, rights) = bridge.call(Op::KillW, Role::W, 0, &[]);
                assert!(rights.is_empty());
                fs::write("/job/evidence/worker-killed.json", &death).unwrap();
                let death: serde_json::Value = serde_json::from_str(&death).unwrap();
                assert_eq!(death["kind"], "W_KILLED");
                assert_eq!(death["pidfd_dead"], true);
                // C reports the failed HTTP send but its exact service/transport intent remains held.
                terminal_reader.take().unwrap().join().unwrap().unwrap();
                drop(writer);
                drop(frames);
                assert_eq!(
                    super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                    before_worker
                );
                assert_eq!(
                    super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                    before_controller
                );
                for (index, role) in [Role::P, Role::C, Role::K].into_iter().enumerate() {
                    let (alive, rights) = bridge.call(Op::Observe, role, 0, &[]);
                    assert!(rights.is_empty());
                    fs::write(
                        format!("/job/evidence/worker-loss-alive-{}.json", index),
                        alive,
                    )
                    .unwrap();
                }
                let mut pipe = [-1; 2];
                assert_eq!(unsafe { pipe2(pipe.as_mut_ptr(), 0x80000) }, 0);
                let reader = unsafe { File::from_raw_fd(pipe[0]) };
                let mut writer = SharedControl::new(unsafe { File::from_raw_fd(pipe[1]) });
                let (restarted, mut streams) =
                    bridge.call(Op::RestartW, Role::W, 0, &[reader.as_raw_fd()]);
                drop(reader);
                checked_snapshot(&restarted, Role::W, true, Some(st.dev()));
                check_control_custody(&restarted, &writer.0.lock().unwrap());
                let initial: serde_json::Value = serde_json::from_str(&wm).unwrap();
                let restarted: serde_json::Value = serde_json::from_str(&restarted).unwrap();
                let returning = super::super::la_adapter::WorkerReturnWitness::observe(
                    &binding,
                    &initial["snapshot"],
                    &death,
                    &restarted["snapshot"],
                    &roots[0],
                )
                .unwrap();
                let mut next = binding.clone();
                next.worker_epoch = 2;
                next.worker_boot = randomhex();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let handoff = super::super::la_adapter::WorkerEpochHandoff::prepare(
                    &mut cframes.transport_ledger.lock().unwrap(),
                    &mut ledger.lock().unwrap(),
                    &roots[1],
                    &roots[0],
                    cframes.state_ledger.lock().unwrap().as_mut().unwrap(),
                    next.clone(),
                    returning,
                    &keys,
                    now,
                )
                .unwrap();
                fs::write(
                    "/job/evidence/worker-return-handoff.json",
                    serde_json::to_vec(&handoff).unwrap(),
                )
                .unwrap();
                let nonce = randomhex();
                let mut wchannel = restart_config["authority_material"]["channel"].clone();
                wchannel.as_object_mut().unwrap().remove("service_genesis");
                wchannel["binding"] = serde_json::to_value(&next).unwrap();
                wchannel["expected_high_water"] = handoff.high_water().into();
                let config = serde_json::json!({"protocol_version":1,"run_nonce":nonce,"role":"worker","root":"/job/workerroot","policy_id":"runtime-short-v1","policy_digest":next.policy_digest,"expected_executable_sha256":whash,"authority_material":{"service_bearer":token,"worker_id":next.worker,"boot_id":next.worker_boot,"hardware_generation":1,"profile_epoch":1,"channel":wchannel},"custody_manifest":{"mode":"recover","worker_id":next.worker,"store_id":store,"root_dev":st.dev(),"root_inode":st.ino(),"expected_starts":1,"expected_records":1,"worker_handoff":handoff},"barrier_id":null});
                let bytes = serde_json::to_vec(&config).unwrap();
                assert!(bytes.len() < 16384);
                fs::write(
                    "/job/evidence/worker-recovery-config-bound.json",
                    serde_json::to_vec(&serde_json::json!({"bytes":bytes.len(),"limit":16384}))
                        .unwrap(),
                )
                .unwrap();
                let err = streams.pop().unwrap();
                let out = streams.pop().unwrap();
                let mut recovered = WitnessFrames::start_with_state(
                    Frames {
                        out,
                        err,
                        buf: vec![],
                        total: 0,
                        eof: [false; 2],
                    },
                    writer.clone(),
                    roots[0].try_clone().unwrap(),
                    &custody,
                    &next,
                    &keys,
                    "worker",
                    None,
                    Some(ledger),
                );
                writer.write_all(&bytes).unwrap();
                writer.write_all(b"\n").unwrap();
                let ready: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                fs::write(
                    "/job/evidence/worker-recovery-ready.json",
                    serde_json::to_vec(&ready).unwrap(),
                )
                .unwrap();
                if !matches!(
                    std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref(),
                    Ok("worker-close-recovery" | "worker-close-recovery-successor")
                ) {
                    assert_eq!(ready["kind"], "WORKER_RECOVERY_STARTUP_REFUSED");
                    assert_eq!(ready["code"], "evidence_invalid");
                    assert_eq!(ready["listener_binds"], 0);
                    assert_eq!(ready["store_opens"], 0);
                    let db = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64)=db.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(counts, (1, 1));
                    let result = serde_json::json!({"status":"WORKER_PREACTIVATION_CORRUPTION_REFUSED","scenario":std::env::var("DIFFUSER_LA_RESOURCE_PROBE").unwrap(),"refusal":ready,"held_claims":1,"quota_charges":1,"controller_epoch":1,"whole_S1_complete":false});
                    fs::write(
                        "/job/evidence/client-result.json",
                        serde_json::to_vec(&result).unwrap(),
                    )
                    .unwrap();
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                    cwriter.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&cframes.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                    bridge.call(Op::Done, Role::P, 0, &[]);
                    println!("{result}");
                    return;
                }
                assert_eq!(ready["kind"], "READY");
                assert_eq!(ready["boot_id"], next.worker_boot);
                let return_bytes = serde_json::to_vec(
                    &serde_json::json!({"handoff":handoff,"address":ready["address"]}),
                )
                .unwrap();
                assert!(return_bytes.len() <= 12288);
                cwriter.frame(b"WRETURN ", &return_bytes);
                let ack: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                assert_eq!(ack["kind"], "EPOCH_ACK");
                handoff
                    .verify_ack(&keys, &serde_json::from_value(ack["ack"].clone()).unwrap())
                    .unwrap();
                fs::write(
                    "/job/evidence/worker-return-controller-ack.json",
                    serde_json::to_vec(&ack).unwrap(),
                )
                .unwrap();
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let held:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT writer_epoch FROM la_controller_identity)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                assert_eq!(held, (1, 1, 1));
                drop(claims);
                let (observed, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                assert!(rights.is_empty());
                let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                assert!(super::super::la_adapter::cleanup::Certificate::inspect(
                    &binding,
                    &keys,
                    &roots[0],
                    &roots[1],
                    &custody,
                    &initial["snapshot"],
                    &observed["snapshot"],
                    assignment_id,
                    now
                )
                .is_err());
                assert!(
                    super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &restarted["snapshot"],
                        &observed["snapshot"],
                        assignment_id,
                        now
                    )
                    .is_err(),
                    "ordinary cleanup cannot inherit an old held boot"
                );
                let cert = super::super::la_adapter::cleanup::Certificate::inspect_worker_return(
                    &next,
                    &keys,
                    &roots[0],
                    &roots[1],
                    &custody,
                    &restarted["snapshot"],
                    &observed["snapshot"],
                    assignment_id,
                    now,
                    &handoff,
                )
                .unwrap();
                let bytes = serde_json::to_vec(&cert).unwrap();
                fs::write("/job/evidence/worker-return-cleanup.json", &bytes).unwrap();
                fs::write(
                    "/job/evidence/worker-return-occupancy.json",
                    serde_json::to_vec(&observed).unwrap(),
                )
                .unwrap();
                cwriter.frame(b"CLEANUP ", &bytes);
                let first: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                assert_eq!(first["ack"]["released_now"], true);
                cwriter.frame(b"CLEANUP ", &bytes);
                let duplicate: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                assert_eq!(duplicate["ack"]["released_now"], false);
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let after:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                assert_eq!(after, (0, 0, 1));
                drop(claims);
                let db = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker.sqlite",
                )
                .unwrap();
                let (starts, saved): (i64, Vec<u8>) = db
                    .query_row(
                        "SELECT COUNT(*),report FROM operations WHERE job=?1",
                        [job_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(starts, 1);
                assert_eq!(saved, report);
                drop(db);
                let entries =
                    fs::read_to_string("/job/evidence/worker-entered-work.jsonl").unwrap();
                assert_eq!(entries.lines().count(), 1);
                fs::write("/job/evidence/worker-return-report.json", &saved).unwrap();
                // Reuse the exact retained old Start envelope, including its
                // MAC and old binding. W2 must reject it before transport intent.
                let old_channel = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "controller-channel.sqlite",
                )
                .unwrap();
                let original: Vec<u8> = old_channel
                    .query_row(
                        "SELECT request FROM channel_log WHERE sequence=?1",
                        [(handoff.high_water() - 1) as i64],
                        |r| r.get(0),
                    )
                    .unwrap();
                drop(old_channel);
                let parsed: serde_json::Value = serde_json::from_slice(&original).unwrap();
                assert_eq!(parsed["request"]["operation"]["operation"], "Start");
                let mut original_frame = (original.len() as u32).to_be_bytes().to_vec();
                original_frame.extend(&original);
                let wport = ready["address"]
                    .as_str()
                    .unwrap()
                    .rsplit(':')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                let (_, mut sockets) = bridge.call(Op::Connect, Role::W, wport, &[]);
                let mut old_client = KeepHttp(sockets.pop().unwrap());
                let (old_status, _) = old_client.request(
                    "POST",
                    "/v1/worker/operations",
                    "",
                    "",
                    "application/octet-stream",
                    &original_frame,
                );
                assert_eq!(old_status, 401);
                let channel = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker-channel.sqlite",
                )
                .unwrap();
                let high: i64 = channel
                    .query_row("SELECT MAX(sequence) FROM channel_log", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(high, handoff.high_water() as i64 + 1);
                drop(channel);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":source_sequence+1,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                let source = super::super::la_adapter::sign_source_observation(
                    &keys.authority,
                    &next,
                    &canonical,
                )
                .unwrap();
                cframes
                    .state_ledger
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .record_authority(&source)
                    .unwrap();
                writer.frame(b"AUTH ", &source);
                cwriter.frame(b"AUTH ", &source);
                let wack: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                assert_eq!(wack["kind"], "AUTHORITY_ACK");
                let cack: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
                assert_eq!(cack["kind"], "AUTHORITY_ACK");
                cframes
                    .state_ledger
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .observe_authority(
                        &source,
                        &serde_json::from_value(cack["ack"].clone()).unwrap(),
                        &serde_json::from_value(wack["ack"].clone()).unwrap(),
                    )
                    .unwrap();
                let (_, mut sockets) = bridge.call(Op::Connect, Role::C, cport, &[]);
                let mut recovered_http = KeepHttp(sockets.pop().unwrap());
                let (status, readback) = recovered_http.request(
                    "GET",
                    &format!("{base}/artifacts/{output_id}/content"),
                    &delegated,
                    "",
                    "",
                    &[],
                );
                assert_eq!(status, 200);
                assert_eq!(readback, report);
                let (foreign_status, _) = recovered_http.request(
                    "GET",
                    &format!("{base}/artifacts/{output_id}/content"),
                    &human,
                    "",
                    "",
                    &[],
                );
                assert_eq!(foreign_status, 404);
                fs::write("/job/evidence/worker-return-authorized-readback.json",serde_json::to_vec(&serde_json::json!({"status":status,"foreign_status":foreign_status,"sha256":hex::encode(Sha256::digest(&readback)),"old_start_envelope_status":old_status,"old_start_allocated_no_intent":true,"controller_boot":next.controller_boot,"controller_epoch":next.controller_epoch,"worker_boot":next.worker_boot,"worker_epoch":next.worker_epoch})).unwrap()).unwrap();
                if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                    == Ok("worker-close-recovery-successor")
                {
                    let mut returned_sequence = source_sequence + 1;
                    let mut refresh_returned =
                        |writer: &mut SharedControl,
                         recovered: &mut WitnessFrames,
                         cwriter: &mut SharedControl,
                         cframes: &mut WitnessFrames| {
                            returned_sequence += 1;
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":returned_sequence,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                            let source = super::super::la_adapter::sign_source_observation(
                                &keys.authority,
                                &next,
                                &canonical,
                            )
                            .unwrap();
                            cframes
                                .state_ledger
                                .lock()
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .record_authority(&source)
                                .unwrap();
                            writer.frame(b"AUTH ", &source);
                            cwriter.frame(b"AUTH ", &source);
                            let wack: serde_json::Value =
                                serde_json::from_str(&recovered.next()).unwrap();
                            let cack: serde_json::Value =
                                serde_json::from_str(&cframes.next()).unwrap();
                            assert_eq!(wack["kind"], "AUTHORITY_ACK");
                            assert_eq!(cack["kind"], "AUTHORITY_ACK");
                            cframes
                                .state_ledger
                                .lock()
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .observe_authority(
                                    &source,
                                    &serde_json::from_value(cack["ack"].clone()).unwrap(),
                                    &serde_json::from_value(wack["ack"].clone()).unwrap(),
                                )
                                .unwrap();
                        };
                    refresh_returned(&mut writer, &mut recovered, &mut cwriter, &mut cframes);
                    let (closed_status, closed) = recovered_http.json(
                        "POST",
                        &format!("{base}/assignments"),
                        &delegated,
                        "successor_closed_001",
                        &acquire,
                    );
                    assert_eq!(
                        closed_status, 412,
                        "terminal return admission must stay closed: {closed}"
                    );
                    let (observed, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let resource = family.seal(&next, &keys, now, now + 12000).unwrap();
                    let successor = super::super::la_adapter::WorkerSuccessorAdmission::issue(
                        resource,
                        &handoff,
                        &cert,
                        &first["ack"],
                        &roots[0],
                        &roots[1],
                        &recovered.transport_ledger.lock().unwrap(),
                        &cframes.transport_ledger.lock().unwrap(),
                        cframes.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &ready,
                        &observed["snapshot"],
                        &keys,
                        now,
                        now + 12000,
                    )
                    .unwrap();
                    let original_ack: serde_json::Value = serde_json::from_slice(
                        &fs::read("/job/evidence/controller-activation-ack.json").unwrap(),
                    )
                    .unwrap();
                    assert!(
                        successor
                            .verify_ack(
                                "controller",
                                &keys,
                                &serde_json::from_value(original_ack["ack"].clone()).unwrap()
                            )
                            .is_err(),
                        "a genesis ACK cannot acknowledge successor admission"
                    );
                    let cap_bytes = serde_json::to_vec(&successor).unwrap();
                    assert!(cap_bytes.len() <= 12288);
                    fs::write("/job/evidence/worker-successor-capability.json", &cap_bytes)
                        .unwrap();
                    cwriter.frame(b"WSUCCESSOR ", &cap_bytes);
                    let admission: serde_json::Value =
                        serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(admission["kind"], "ACTIVATION_ACK");
                    successor
                        .verify_ack(
                            "controller",
                            &keys,
                            &serde_json::from_value(admission["ack"].clone()).unwrap(),
                        )
                        .unwrap();
                    fs::write(
                        "/job/evidence/worker-successor-ack.json",
                        serde_json::to_vec(&admission).unwrap(),
                    )
                    .unwrap();
                    refresh_returned(&mut writer, &mut recovered, &mut cwriter, &mut cframes);
                    let (status, new_assignment) = recovered_http.json(
                        "POST",
                        &format!("{base}/assignments"),
                        &delegated,
                        "successor_acquire_001",
                        &acquire,
                    );
                    assert_eq!(status, 202, "successor acquire: {new_assignment}");
                    assert_eq!(new_assignment["state"], "assigned");
                    let next_assignment = new_assignment["assignment_id"].as_str().unwrap();
                    assert_ne!(next_assignment, assignment_id);
                    let wdb = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    super::super::la_worker::verify_session_history(&wdb, &keys.reply).unwrap();
                    let (old_fence,new_fence,old_boot,new_boot):(i64,i64,String,String)=wdb.query_row("SELECT (SELECT fence FROM worker_reservations WHERE assignment_id=?1),(SELECT fence FROM worker_reservations WHERE assignment_id=?2),(SELECT boot FROM worker_session_snapshots WHERE assignment=?1 ORDER BY sequence DESC LIMIT 1),(SELECT boot FROM worker_session_snapshots WHERE assignment=?2 ORDER BY sequence DESC LIMIT 1)",rusqlite::params![assignment_id,next_assignment],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                    assert!(new_fence > old_fence);
                    assert_eq!(old_boot, binding.worker_boot);
                    assert_eq!(new_boot, next.worker_boot);
                    drop(wdb);
                    // Old cleanup is an exact duplicate only. It cannot release the new generation.
                    cwriter.frame(b"CLEANUP ", &bytes);
                    let stale_cleanup: serde_json::Value =
                        serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(stale_cleanup["ack"]["released_now"], false);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    assert_eq!(
                        claims
                            .query_row(
                                "SELECT COUNT(*) FROM la_reservations WHERE assignment_id=?1",
                                [next_assignment],
                                |r| r.get::<_, i64>(0)
                            )
                            .unwrap(),
                        1
                    );
                    drop(claims);
                    let (old_status, _) = old_client.request(
                        "POST",
                        "/v1/worker/operations",
                        "",
                        "",
                        "application/octet-stream",
                        &original_frame,
                    );
                    assert_eq!(old_status, 401);
                    let cdb = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let old_permit:Vec<u8>=cdb.query_row("SELECT request FROM channel_log WHERE json_extract(CAST(request AS TEXT),'$.request.operation.operation')='Permit' ORDER BY sequence LIMIT 1",[],|r|r.get(0)).unwrap();
                    drop(cdb);
                    let mut old_permit_frame = (old_permit.len() as u32).to_be_bytes().to_vec();
                    old_permit_frame.extend(&old_permit);
                    let (old_permit_status, _) = old_client.request(
                        "POST",
                        "/v1/worker/operations",
                        "",
                        "",
                        "application/octet-stream",
                        &old_permit_frame,
                    );
                    assert_eq!(old_permit_status, 401);
                    refresh_returned(&mut writer, &mut recovered, &mut cwriter, &mut cframes);
                    let new_submit = serde_json::json!({"schema_version":"diffuser-lane/v1","client_job_id":"successor_client_job1","capability":"artifact.inspect.sha256/v1","profile_version":"1","input_artifact_ids":[input_id],"parameters":{},"max_runtime_ms":4000,"disconnect_policy":"continue_until_job_deadline"});
                    let (status, new_job) = recovered_http.json(
                        "POST",
                        &format!("{base}/assignments/{next_assignment}/jobs"),
                        &delegated,
                        "successor_submit_001",
                        &new_submit,
                    );
                    assert_eq!(status, 202, "successor submit: {new_job}");
                    assert_eq!(new_job["state"], "succeeded");
                    let new_job_id = new_job["job_id"].as_str().unwrap();
                    let (status, view) = recovered_http.json(
                        "GET",
                        &format!("{base}/jobs/{new_job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200);
                    assert_eq!(view["state"], "succeeded");
                    let new_output = view["result_artifact_id"].as_str().unwrap();
                    let (status, new_report) = recovered_http.request(
                        "GET",
                        &format!("{base}/artifacts/{new_output}/content"),
                        &delegated,
                        "",
                        "",
                        &[],
                    );
                    assert_eq!(status, 200);
                    let checked: serde_json::Value = serde_json::from_slice(&new_report).unwrap();
                    assert_eq!(checked["job_id"], new_job_id);
                    assert_eq!(checked["sha256"], hex::encode(Sha256::digest(input)));
                    let (status, old_report) = recovered_http.request(
                        "GET",
                        &format!("{base}/artifacts/{output_id}/content"),
                        &delegated,
                        "",
                        "",
                        &[],
                    );
                    assert_eq!(status, 200);
                    assert_eq!(old_report, report);
                    refresh_returned(&mut writer, &mut recovered, &mut cwriter, &mut cframes);
                    let (status,released)=recovered_http.json("POST",&format!("{base}/assignments/{next_assignment}/release"),&delegated,"successor_release_001",&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0}));
                    assert_eq!(status, 202, "successor release: {released}");
                    let (observed, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let clean = super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &restarted["snapshot"],
                        &observed["snapshot"],
                        next_assignment,
                        now,
                    )
                    .unwrap();
                    cwriter.frame(b"CLEANUP ", &serde_json::to_vec(&clean).unwrap());
                    let cleanup2: serde_json::Value =
                        serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(cleanup2["ack"]["released_now"], true);
                    refresh_returned(&mut writer, &mut recovered, &mut cwriter, &mut cframes);
                    let (status, third) = recovered_http.json(
                        "POST",
                        &format!("{base}/assignments"),
                        &delegated,
                        "successor_reacquire_1",
                        &acquire,
                    );
                    assert_eq!(status, 202, "returned worker reacquire: {third}");
                    let third_id = third["assignment_id"].as_str().unwrap();
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let third_fence: i64 = claims
                        .query_row(
                            "SELECT fence FROM la_assignments WHERE id=?1",
                            [third_id],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert!(third_fence > new_fence);
                    drop(claims);
                    refresh_returned(&mut writer, &mut recovered, &mut cwriter, &mut cframes);
                    let (status,released3)=recovered_http.json("POST",&format!("{base}/assignments/{third_id}/release"),&delegated,"successor_release_003",&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0}));
                    assert_eq!(status, 202, "third release: {released3}");
                    let (observed, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let clean3 = super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &restarted["snapshot"],
                        &observed["snapshot"],
                        third_id,
                        now,
                    )
                    .unwrap();
                    cwriter.frame(b"CLEANUP ", &serde_json::to_vec(&clean3).unwrap());
                    let cleanup3: serde_json::Value =
                        serde_json::from_str(&cframes.next()).unwrap();
                    assert_eq!(cleanup3["ack"]["released_now"], true);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!(counts, (0, 0, 3));
                    drop(claims);
                    let entries =
                        fs::read_to_string("/job/evidence/worker-entered-work.jsonl").unwrap();
                    assert_eq!(entries.lines().count(), 2);
                    let db = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    super::super::la_worker::verify_session_history(&db, &keys.reply).unwrap();
                    assert_eq!(
                        db.query_row("SELECT COUNT(*) FROM operations", [], |r| r
                            .get::<_, i64>(0))
                            .unwrap(),
                        2
                    );
                    let sessions: Vec<(String, String, i64)> = {
                        let mut st=db.prepare("SELECT assignment,boot,sequence FROM worker_session_snapshots ORDER BY sequence").unwrap();
                        let rows = st
                            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap();
                        rows
                    };
                    fs::write(
                        "/job/evidence/worker-successor-snapshots.json",
                        serde_json::to_vec(&sessions).unwrap(),
                    )
                    .unwrap();
                    drop(db);
                    let result = serde_json::json!({"status":"WORKER_SUCCESSOR_EXECUTED","resumed_dispatch":true,"same_client":true,"controller_boot_unchanged":true,"worker_epoch":2,"controller_epoch":1,"old_fence":old_fence,"new_fence":new_fence,"reacquired_fence":third_fence,"worker_starts":2,"observed_work_entries":2,"original_report_preserved":true,"new_result_readback":true,"held_after":counts.0,"charged_after":counts.1,"cleanup_receipts":counts.2,"old_cleanup_preserved_new_claim":true,"old_start_refused":true,"old_permit_refused":true,"old_ack_refused":true,"first_cleanup":first,"duplicate_cleanup":duplicate,"new_cleanup":cleanup2,"final_cleanup":cleanup3,"whole_S1_complete":false});
                    fs::write(
                        "/job/evidence/client-result.json",
                        serde_json::to_vec(&result).unwrap(),
                    )
                    .unwrap();
                    writer.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                    cwriter.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&cframes.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                    bridge.call(Op::Done, Role::P, 0, &[]);
                    println!("{result}");
                    return;
                }
                let result = serde_json::json!({"status":"WORKER_ONLY_CLOSE_RECOVERY","controller_boot_unchanged":true,"controller_epoch":1,"worker_epoch":2,"held_claims":held.0,"quota_charges":held.1,"held_after":after.0,"charged_after":after.1,"cleanup_receipts":after.2,"worker_starts":starts,"observed_work_entries":1,"same_report":true,"report_sha256":hex::encode(Sha256::digest(&saved)),"old_binding_cleanup_refused":true,"ordinary_new_boot_cleanup_refused":true,"first_cleanup":first,"duplicate_cleanup":duplicate,"whole_S1_complete":false,"resumed_dispatch":false,"authorized_readback":true,"old_start_refused":true,"old_start_allocated_no_intent":true});
                fs::write(
                    "/job/evidence/client-result.json",
                    serde_json::to_vec(&result).unwrap(),
                )
                .unwrap();
                writer.write_all(b"STOP\n").unwrap();
                assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                bridge.call(Op::StopW, Role::W, 0, &[]);
                cwriter.write_all(b"STOP\n").unwrap();
                assert_eq!(jsonstr(&cframes.next(), "kind"), "STOPPED");
                bridge.call(Op::StopC, Role::C, 0, &[]);
                bridge.call(Op::StopK, Role::K, 0, &[]);
                bridge.call(Op::Done, Role::P, 0, &[]);
                println!("{result}");
                return;
            }
            if super::controller_recovery_case() {
                // Exact C-only loss; P and W control custody and finite roots survive.
                let before_worker =
                    super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                let preserved =
                    super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                let retained = cframes.state_ledger.clone();
                let transport_ledger = cframes.transport_ledger.clone();
                let (killed, rights) = bridge.call(Op::KillC, Role::C, 0, &[]);
                assert!(rights.is_empty());
                fs::write("/job/evidence/controller-killed.json", &killed).unwrap();
                assert_eq!(jsonstr(&killed, "kind"), "C_KILLED");
                let terminal_bytes = terminal_reader
                    .take()
                    .map(|r| r.join().unwrap().unwrap())
                    .unwrap_or(0);
                assert_eq!(terminal_bytes, 0, "no terminal response before C death");
                drop(cframes);
                drop(cwriter);
                drop(http);
                assert_eq!(
                    super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                    preserved
                );
                let line =
                    fs::read_to_string("/job/evidence/controller-live-custody.jsonl").unwrap();
                let head: serde_json::Value =
                    serde_json::from_str(line.lines().last().unwrap()).unwrap();
                let checkpoint = serde_json::from_value(head["checkpoint"].clone()).unwrap();
                let ack = serde_json::from_value(head["ack"].clone()).unwrap();
                let mut next = binding.clone();
                next.controller_epoch = 2;
                next.controller_boot = randomhex();
                // Observe the actual positive C2 and its original bootstrap pipe
                // before taking the single real FIRST-use observation for both
                // handoffs. Deliberately late FIRST use retains its old order.
                let restart_controller = |bridge: &mut Bridge| {
                    let mut pipe = [-1; 2];
                    assert_eq!(
                        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                        0
                    );
                    let reader = unsafe { File::from_raw_fd(pipe[0]) };
                    let cwriter = SharedControl::new(unsafe { File::from_raw_fd(pipe[1]) });
                    let (restarted, streams) =
                        bridge.call(Op::RestartC, Role::C, 0, &[reader.as_raw_fd()]);
                    drop(reader);
                    fs::write("/job/evidence/controller-restarted.json", &restarted).unwrap();
                    assert_eq!(jsonstr(&restarted, "kind"), "C_RESTARTED");
                    checked_snapshot(&restarted, Role::C, true, Some(cmeta.dev()));
                    check_control_custody(&restarted, &cwriter.0.lock().unwrap());
                    super::super::la_adapter::recovery_trace(
                        "controller_recovery_C2_staged",
                        serde_json::json!({"protected_process_observed":true,"original_pipe_custody_verified":true}),
                    );
                    (restarted, streams, cwriter)
                };
                let early_restart = if (never_started_case
                    || close_recovery
                    || stop_recovery
                    || super::controller_recovery_case())
                    && std::env::var("DIFFUSER_LA_BOOTSTRAP_ORDER_TEST").as_deref()
                        != Ok("legacy-issue-first")
                    && std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").as_deref()
                        != Ok("late-first")
                {
                    Some(restart_controller(&mut bridge))
                } else {
                    None
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                super::super::la_adapter::recovery_trace(
                    "controller_recovery_preissue",
                    serde_json::json!({"now":now,"early_C2_staged":early_restart.is_some(),"first_window_ms":1500,"parser_budget_ms":5000}),
                );
                let sequence = source_sequence; // P's ACKed source history, never the recovering DB's chosen watermark.
                let service = retained
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .authorize_consumable_recovery(&roots[1], next.clone(), now, now + 1500)
                    .unwrap();
                let handoff = transport_ledger
                    .lock()
                    .unwrap()
                    .authorize_controller_readback(
                        &roots[1],
                        service,
                        &checkpoint,
                        &ack,
                        &cstore,
                        sequence,
                        &keys,
                        now,
                    )
                    .unwrap();
                let epoch_handoff = if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                    == Ok("controller-rebind")
                    || close_recovery
                    || stop_recovery
                    || never_started_case
                {
                    let original_command: Option<super::super::la_adapter::InspectCommand> =
                        original_stop_state
                            .as_ref()
                            .filter(|_| never_started_case)
                            .map(|r| serde_json::from_str(&r.0).unwrap());
                    let capsule = if let Some(original) = &original_command {
                        super::super::la_adapter::TransportEpochHandoff::prepare_never_started(
                            &mut transport_ledger.lock().unwrap(),
                            &mut frames.transport_ledger.lock().unwrap(),
                            &roots[1],
                            &roots[0],
                            &handoff,
                            &keys,
                            now,
                            original,
                        )
                    } else {
                        super::super::la_adapter::TransportEpochHandoff::prepare(
                            &mut transport_ledger.lock().unwrap(),
                            &mut frames.transport_ledger.lock().unwrap(),
                            &roots[1],
                            &roots[0],
                            &handoff,
                            &keys,
                            now,
                        )
                    };
                    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                        == Ok("controller-stop-recovery-presend")
                    {
                        assert_eq!(capsule.err(), Some("transport_uncertain"));
                        let claims = super::super::la_store::open_pinned_readonly_database(
                            &roots[1],
                            "lane_assignments.sqlite",
                        )
                        .unwrap();
                        let held: (i64,i64,String) = claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT state FROM la_jobs)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                        assert_eq!(held, (1, 1, "stopping".into()));
                        let result = serde_json::json!({"status":"PENDING_STOP_UNCERTAIN_REFUSED","held_claims":1,"quota_charges":1,"work_entries":0,"new_activation":false,"replacement_stop":false,"original_service_operation_retained":true,"whole_S1_complete":false});
                        fs::write(
                            "/job/evidence/client-result.json",
                            serde_json::to_vec(&result).unwrap(),
                        )
                        .unwrap();
                        writer.write_all(b"STOP\n").unwrap();
                        assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                        bridge.call(Op::StopW, Role::W, 0, &[]);
                        bridge.call(Op::StopK, Role::K, 0, &[]);
                        bridge.call(Op::Done, Role::P, 0, &[]);
                        println!("{result}");
                        return;
                    }
                    let capsule = capsule.unwrap();
                    fs::write(
                        "/job/evidence/controller-transport-handoff.json",
                        serde_json::to_vec(&capsule).unwrap(),
                    )
                    .unwrap();
                    super::recovery_test_delay(&capsule, "late-first");
                    writer.frame(b"REBIND ", &serde_json::to_vec(&capsule).unwrap());
                    let observed: serde_json::Value = serde_json::from_str(&frames.next()).unwrap();
                    assert_eq!(observed["kind"], "EPOCH_ACK");
                    let ack = serde_json::from_value(observed["ack"].clone()).unwrap();
                    capsule.verify_ack("worker", &keys, &ack).unwrap();
                    fs::write(
                        "/job/evidence/worker-epoch-ack.json",
                        serde_json::to_vec(&observed).unwrap(),
                    )
                    .unwrap();
                    Some(capsule)
                } else {
                    None
                };
                fs::write(
                    "/job/evidence/controller-recovery-handoff.json",
                    serde_json::to_vec(&handoff).unwrap(),
                )
                .unwrap();
                let (_restarted, mut streams, mut cwriter) = match early_restart {
                    Some(value) => value,
                    None => restart_controller(&mut bridge),
                };
                let mut config = restart_config;
                // The publication fault belongs to the killed original boot.
                // Replayed completed receipts on C2 must reach the caller.
                config["authority_material"]["reply_barrier"] = false.into();
                let recovery_nonce = randomhex();
                config["run_nonce"] = recovery_nonce.clone().into();
                config["authority_material"]["boot_id"] = next.controller_boot.clone().into();
                config["authority_material"]["observed_at"] = now.into();
                config["authority_material"]["channel"]["binding"] =
                    serde_json::to_value(&next).unwrap();
                config["authority_material"]["channel"]
                    .as_object_mut()
                    .unwrap()
                    .remove("service_genesis");
                config["custody_manifest"]["mode"] = "readback_recovery".into();
                config["custody_manifest"]["writer_epoch"] = 2.into();
                config["custody_manifest"]["recovery"] = serde_json::to_value(&handoff).unwrap();
                if let Some(capsule) = &epoch_handoff {
                    config["custody_manifest"]["transport_handoff"] =
                        serde_json::to_value(capsule).unwrap();
                }
                let config_bytes = serde_json::to_vec(&config).unwrap();
                fs::write("/job/evidence/recovery-config-bound.json",serde_json::to_vec(&serde_json::json!({"bytes":config_bytes.len(),"limit":16384,"contains_private_material":true,"raw_config_not_exported":true})).unwrap()).unwrap();
                assert!(
                    config_bytes.len() < 16384,
                    "recovery config must fit the original pipe limit"
                );
                super::super::la_adapter::recovery_trace(
                    "controller_recovery_config_write_begin",
                    serde_json::json!({"issued_at":now,"bytes":config_bytes.len()}),
                );
                serde_json::to_writer(&mut cwriter, &config).unwrap();
                cwriter.write_all(b"\n").unwrap();
                super::super::la_adapter::recovery_trace(
                    "controller_recovery_config_write_end",
                    serde_json::json!({"issued_at":now,"bytes":config_bytes.len(),"delimiter_written":true}),
                );
                drop(config);
                let err = streams.pop().unwrap();
                let out = streams.pop().unwrap();
                let mut recovered = WitnessFrames::start_with_state(
                    Frames {
                        out,
                        err,
                        buf: vec![],
                        total: 0,
                        eof: [false; 2],
                    },
                    cwriter.clone(),
                    roots[1].try_clone().unwrap(),
                    &custody,
                    &next,
                    &keys,
                    "controller",
                    Some(retained),
                    Some(transport_ledger),
                );
                let ready: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                fs::write(
                    "/job/evidence/recovery-ready.json",
                    serde_json::to_vec(&ready).unwrap(),
                )
                .unwrap();
                if never_started_case
                    && std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").as_deref()
                        == Ok("m2-bootstrap-consumption")
                {
                    assert_eq!(ready["kind"], "READY");

                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let retained:(String,String,String,i64)=claims.query_row("SELECT p.command,m.body,j.id,p.permit_until FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                    assert_eq!(Some(&retained), original_stop_state.as_ref());
                    let held:(i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(held, (1, 1));
                    let worker = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    let entries: i64 = worker
                        .query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
                        .unwrap();
                    assert_eq!(entries, 0);
                    let command: super::super::la_adapter::InspectCommand =
                        serde_json::from_str(&retained.0).unwrap();
                    let result = serde_json::json!({"status":"M2_DIAGNOSTIC_BOUNDARY","diagnostic":"bootstrap-independent-consumption","held_claims":held.0,"quota_charges":held.1,"work_entries":entries,"original_command_mandate_unchanged":true,"original_mandate_until":command.mandate_until,"product_release_claimed":false,"original_job_lifecycle_complete":false,"whole_S1_complete":false});
                    fs::write(
                        "/job/evidence/client-result.json",
                        serde_json::to_vec(&result).unwrap(),
                    )
                    .unwrap();
                    drop(worker);
                    drop(claims);
                    cwriter.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                    writer.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                    bridge.call(Op::Done, Role::P, 0, &[]);
                    println!("{result}");
                    return;
                }
                // Stage the SAME ordinary HTTP connection inside the existing
                // deliberate post-install wait, before asking for a fresh
                // execution permit. This saves no security/deadline checks.
                let early_lifecycle_http = if never_started_case
                    && std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").as_deref()
                        == Ok("after-install")
                    && matches!(
                        std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref(),
                        Ok("controller-never-started-m1" | "controller-never-started-m2")
                    ) {
                    assert_eq!(ready["kind"], "READY", "{ready}");
                    let port = ready["address"]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let (_, mut sockets) = bridge.call(Op::Connect, Role::C, port, &[]);
                    super::super::la_adapter::recovery_trace(
                        "controller_recovery_terminal_socket_staged",
                        serde_json::json!({"same_ordinary_connection":true,"before_fresh_execution_permit":true}),
                    );
                    Some(KeepHttp(sockets.pop().unwrap()))
                } else {
                    None
                };
                if never_started_case {
                    assert_eq!(ready["kind"], "READY", "{ready}");
                    let capsule = epoch_handoff.as_ref().unwrap();
                    super::recovery_test_delay(capsule, "after-install");
                    let original: super::super::la_adapter::InspectCommand =
                        serde_json::from_str(&original_stop_state.as_ref().unwrap().0).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":sequence+1,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                    let fresh = super::super::la_adapter::sign_source_observation(
                        &keys.authority,
                        &next,
                        &canonical,
                    )
                    .unwrap();
                    recovered
                        .state_ledger
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .record_authority(&fresh)
                        .unwrap();
                    writer.frame(b"AUTH ", &fresh);
                    let wa: serde_json::Value = serde_json::from_str(&frames.next()).unwrap();
                    assert_eq!(wa["kind"], "AUTHORITY_ACK");
                    cwriter.frame(b"AUTH ", &fresh);
                    let ca: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(ca["kind"], "AUTHORITY_ACK");
                    let wa = serde_json::from_value(wa["ack"].clone()).unwrap();
                    let ca = serde_json::from_value(ca["ack"].clone()).unwrap();
                    recovered
                        .state_ledger
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .observe_authority(&fresh, &ca, &wa)
                        .unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let resource_result =
                        family.seal(&next, &keys, now, original.mandate_until.min(now + 1500));
                    if std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").as_deref()
                        == Ok("m2-original-deadline-refusal")
                    {
                        assert!(now >= original.mandate_until);
                        assert!(matches!(&resource_result, Err("evidence_invalid")));
                        super::super::la_adapter::recovery_trace(
                            "m2_original_deadline_refusal",
                            serde_json::json!({"now":now,"original_mandate_until":original.mandate_until,"requested_expiry":original.mandate_until.min(now+1500),"actual_error":"evidence_invalid","new_permit_issued":false}),
                        );

                        let claims = super::super::la_store::open_pinned_readonly_database(
                            &roots[1],
                            "lane_assignments.sqlite",
                        )
                        .unwrap();
                        let retained:(String,String,String,i64)=claims.query_row("SELECT p.command,m.body,j.id,p.permit_until FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                        assert_eq!(Some(&retained), original_stop_state.as_ref());
                        let held:(i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                        assert_eq!(held, (1, 1));
                        let worker = super::super::la_store::open_pinned_readonly_database(
                            &roots[0],
                            "worker.sqlite",
                        )
                        .unwrap();
                        // Real deadline expiry can retain an authenticated
                        // stopped-before-start tombstone. It is not work entry.
                        let (records, stopped, entries, results): (i64,i64,i64,i64) = worker.query_row(
                            "SELECT COUNT(*),COALESCE(SUM(state='stopped'),0),COALESCE(SUM(state IN ('started','complete','cancelled')),0),(SELECT COUNT(*) FROM worker_result_receipts) FROM operations",[],
                            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                        assert_eq!((records, stopped, entries, results), (1, 1, 0, 0));
                        let entered =
                            match fs::read_to_string("/job/evidence/worker-entered-work.jsonl") {
                                Ok(bytes) => bytes,
                                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                    String::new()
                                }
                                Err(error) => panic!("actual entry transcript: {error}"),
                            };
                        assert_eq!(entered.lines().count(), 0);
                        let retained_worker = super::loss_retained_tables(
                            &worker,
                            &[
                                "operations",
                                "worker_stop_receipts",
                                "worker_result_receipts",
                                "worker_reservations",
                                "worker_mandates",
                                "worker_assignment_terms",
                            ],
                        );
                        fs::write(
                            "/job/evidence/m2-deadline-retained-worker.json",
                            serde_json::to_vec(&retained_worker).unwrap(),
                        )
                        .unwrap();
                        let command: super::super::la_adapter::InspectCommand =
                            serde_json::from_str(&retained.0).unwrap();
                        let result = serde_json::json!({"status":"M2_DIAGNOSTIC_BOUNDARY","diagnostic":"original-deadline-refusal","held_claims":held.0,"quota_charges":held.1,"work_entries":entries,"raw_worker_records":records,"stopped_before_start":stopped,"worker_result_receipts":results,"actual_work_entries":entered.lines().count(),"original_command_mandate_unchanged":true,"original_mandate_until":command.mandate_until,"product_release_claimed":false,"original_job_lifecycle_complete":false,"whole_S1_complete":false});
                        fs::write(
                            "/job/evidence/client-result.json",
                            serde_json::to_vec(&result).unwrap(),
                        )
                        .unwrap();
                        drop(worker);
                        drop(claims);
                        cwriter.write_all(b"STOP\n").unwrap();
                        assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                        bridge.call(Op::StopC, Role::C, 0, &[]);
                        writer.write_all(b"STOP\n").unwrap();
                        assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                        bridge.call(Op::StopW, Role::W, 0, &[]);
                        bridge.call(Op::StopK, Role::K, 0, &[]);
                        bridge.call(Op::Done, Role::P, 0, &[]);
                        println!("{result}");
                        return;
                    }
                    let resource = resource_result.unwrap();
                    if std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").is_ok_and(|v| {
                        matches!(
                            v.as_str(),
                            "witness-missing" | "witness-altered" | "witness-partial"
                        )
                    }) {
                        cwriter.write_all(b"CORRUPT_CONSUMPTION\n").unwrap();
                        let ack: serde_json::Value =
                            serde_json::from_str(&recovered.next()).unwrap();
                        assert_eq!(ack["kind"], "CONSUMPTION_TEST_MUTATED");
                        fs::write(
                            "/job/evidence/recovery-consumption-before.json",
                            ack["before"].as_str().unwrap().as_bytes(),
                        )
                        .unwrap();
                        fs::write(
                            "/job/evidence/recovery-consumption-after.json",
                            ack["after"].as_str().unwrap().as_bytes(),
                        )
                        .unwrap();
                    }
                    super::super::la_adapter::recovery_trace(
                        "permit_factory_lock_wait",
                        serde_json::json!({"now":now}),
                    );
                    let factory_before =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let cap = super::super::la_adapter::NeverStartedPermit::issue(
                        resource,
                        capsule,
                        &recovered.transport_ledger.lock().unwrap(),
                        &frames.transport_ledger.lock().unwrap(),
                        recovered.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &roots[1],
                        &roots[0],
                        &keys,
                        now,
                    );
                    let test_mode =
                        std::env::var("DIFFUSER_LA_RECOVERY_TEST_DELAY").unwrap_or_default();
                    if matches!(
                        test_mode.as_str(),
                        "witness-missing" | "witness-altered" | "witness-partial"
                    ) {
                        assert_eq!(cap.err(), Some("evidence_invalid"));
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap(),
                            factory_before,
                            "refused factory must be read-only"
                        );
                        let claims = super::super::la_store::open_pinned_readonly_database(
                            &roots[1],
                            "lane_assignments.sqlite",
                        )
                        .unwrap();
                        let held:(i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                        assert_eq!(held, (1, 1));
                        let worker = super::super::la_store::open_pinned_readonly_database(
                            &roots[0],
                            "worker.sqlite",
                        )
                        .unwrap();
                        let entries: i64 = worker
                            .query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
                            .unwrap();
                        assert_eq!(entries, 0);
                        let installed:bool=worker.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='worker_rebound_permits')",[],|r|r.get(0)).unwrap();
                        assert!(!installed,"missing/altered/partial consumption refuses before worker permit mutation");
                        let result = serde_json::json!({"status":"NEVER_STARTED_REBOUND_REFUSED","case":test_mode,"target_guard":"authenticated_historical_consumption","read_only_factory":true,"held_claims":1,"quota_charges":1,"work_entries":0,"worker_rebound_mutations":0,"whole_S1_complete":false});
                        fs::write(
                            "/job/evidence/client-result.json",
                            serde_json::to_vec(&result).unwrap(),
                        )
                        .unwrap();
                        cwriter.write_all(b"STOP\n").unwrap();
                        assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                        bridge.call(Op::StopC, Role::C, 0, &[]);
                        writer.write_all(b"STOP\n").unwrap();
                        assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                        bridge.call(Op::StopW, Role::W, 0, &[]);
                        bridge.call(Op::StopK, Role::K, 0, &[]);
                        bridge.call(Op::Done, Role::P, 0, &[]);
                        println!("{result}");
                        return;
                    }
                    let cap = cap.unwrap();
                    fs::write(
                        "/job/evidence/never-started-permit.json",
                        serde_json::to_vec(&cap).unwrap(),
                    )
                    .unwrap();
                    let scenario = std::env::var("DIFFUSER_LA_RESOURCE_PROBE").unwrap();
                    let mut outgoing = serde_json::to_value(&cap).unwrap();
                    if scenario.ends_with("-foreign") {
                        outgoing["original"]["assignment"] = "assignment_foreign01".into();
                    }
                    if scenario.ends_with("-stale") {
                        outgoing["body"]["binding"]["controller_epoch"] = 1.into();
                    }
                    if scenario.ends_with("-expired") {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        let expiry = outgoing["body"]["expires_at"].as_u64().unwrap();
                        std::thread::sleep(std::time::Duration::from_millis(
                            expiry.saturating_sub(now) + 1,
                        ));
                    }
                    let outgoing = serde_json::to_vec(&outgoing).unwrap();
                    fs::write("/job/evidence/never-started-delivery.json", &outgoing).unwrap();
                    cwriter.frame(b"RESUME_JOB ", &outgoing);
                    let ack: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                    if scenario.ends_with("-foreign")
                        || scenario.ends_with("-stale")
                        || scenario.ends_with("-expired")
                    {
                        assert_eq!(ack["kind"], "EPOCH_ACK", "{ack}");
                        assert_eq!(ack["ack"]["kind"], "RECOVERY_RESUME_REFUSED", "{ack}");
                        let claims = super::super::la_store::open_pinned_readonly_database(
                            &roots[1],
                            "lane_assignments.sqlite",
                        )
                        .unwrap();
                        let held:(i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                        assert_eq!(held, (1, 1));
                        let worker = super::super::la_store::open_pinned_readonly_database(
                            &roots[0],
                            "worker.sqlite",
                        )
                        .unwrap();
                        let count: i64 = worker
                            .query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
                            .unwrap();
                        assert_eq!(count, 0);
                        let table:bool=worker.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='worker_rebound_permits')",[],|r|r.get(0)).unwrap();
                        assert!(
                            !table,
                            "invalid capability must precede any worker permit mutation"
                        );
                        let result = serde_json::json!({"status":"NEVER_STARTED_REBOUND_REFUSED","case":scenario,"refusal":ack["ack"],"held_claims":1,"quota_charges":1,"work_entries":0,"worker_rebound_mutations":0,"original_job":job_id,"whole_S1_complete":false});
                        fs::write(
                            "/job/evidence/client-result.json",
                            serde_json::to_vec(&result).unwrap(),
                        )
                        .unwrap();
                        cwriter.write_all(b"STOP\n").unwrap();
                        assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                        bridge.call(Op::StopC, Role::C, 0, &[]);
                        writer.write_all(b"STOP\n").unwrap();
                        assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                        bridge.call(Op::StopW, Role::W, 0, &[]);
                        bridge.call(Op::StopK, Role::K, 0, &[]);
                        bridge.call(Op::Done, Role::P, 0, &[]);
                        println!("{result}");
                        return;
                    }
                    assert_eq!(ack["kind"], "EPOCH_ACK", "{ack}");
                    assert_eq!(ack["ack"]["job"], job_id);
                    assert_eq!(ack["ack"]["state"], "succeeded");
                    fs::write(
                        "/job/evidence/never-started-execution-ack.json",
                        serde_json::to_vec(&ack).unwrap(),
                    )
                    .unwrap();
                    let mut lifecycle_sequence = sequence + u64::from(never_started_case);
                    let mut refresh_lifecycle =
                        |writer: &mut SharedControl,
                         frames: &mut WitnessFrames,
                         cwriter: &mut SharedControl,
                         recovered: &mut WitnessFrames| {
                            lifecycle_sequence += 1;
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":lifecycle_sequence,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                            let source = super::super::la_adapter::sign_source_observation(
                                &keys.authority,
                                &next,
                                &canonical,
                            )
                            .unwrap();
                            recovered
                                .state_ledger
                                .lock()
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .record_authority(&source)
                                .unwrap();
                            writer.frame(b"AUTH ", &source);
                            cwriter.frame(b"AUTH ", &source);
                            let wack: serde_json::Value =
                                serde_json::from_str(&frames.next()).unwrap();
                            let cack: serde_json::Value =
                                serde_json::from_str(&recovered.next()).unwrap();
                            assert_eq!(wack["kind"], "AUTHORITY_ACK");
                            assert_eq!(cack["kind"], "AUTHORITY_ACK");
                            fs::write(format!("/job/evidence/lifecycle-source-{lifecycle_sequence:03}.json"),
                                serde_json::to_vec(&serde_json::json!({"frame":serde_json::from_slice::<serde_json::Value>(&source).unwrap(),"worker":wack,"controller":cack})).unwrap()).unwrap();
                            recovered
                                .state_ledger
                                .lock()
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .observe_authority(
                                    &source,
                                    &serde_json::from_value(cack["ack"].clone()).unwrap(),
                                    &serde_json::from_value(wack["ack"].clone()).unwrap(),
                                )
                                .unwrap();
                        };
                    // Complete ordinary terminal Close while the ORIGINAL lease
                    // still holds; readback and every negative probe follow with
                    // the claim retained until independent cleanup below.
                    let cport = ready["address"]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let mut lifecycle_http = match early_lifecycle_http {
                        Some(http) => http,
                        None => {
                            let (_, mut sockets) = bridge.call(Op::Connect, Role::C, cport, &[]);
                            KeepHttp(sockets.pop().unwrap())
                        }
                    };
                    let close_before = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let close_state:(String,i64,i64,i64,String)=close_before.query_row("SELECT a.state,r.revision,t.lease_until,t.hard_until,j.state FROM la_assignments a JOIN la_assignment_revisions r ON r.assignment_id=a.id JOIN la_assignment_terms t ON t.assignment_id=a.id JOIN la_jobs j ON j.assignment_id=a.id WHERE a.id=?1 AND j.id=?2",rusqlite::params![assignment_id,job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
                    drop(close_before);
                    assert_eq!(
                        (
                            close_state.0.as_str(),
                            close_state.1,
                            close_state.4.as_str()
                        ),
                        ("assigned", 0, "succeeded")
                    );
                    super::super::la_adapter::recovery_trace(
                        "recovered_terminal_close_before",
                        serde_json::json!({"state":close_state.0,"revision":close_state.1,"lease_until":close_state.2,"hard_until":close_state.3,"job_state":close_state.4}),
                    );
                    let (status, released) = lifecycle_http.json("POST", &format!("{base}/assignments/{assignment_id}/release"), &delegated, "recovered_release_001", &serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0}));
                    assert_eq!(status, 202, "ordinary terminal Close: {released}");
                    let close_after = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let close_clock:(i64,String,i64,i64,i64,i64)=close_after.query_row("SELECT c.requested_at,c.first_reason,t.lease_until,t.hard_until,(SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges) FROM la_close_intents c JOIN la_assignment_terms t ON t.assignment_id=c.assignment_id WHERE c.assignment_id=?1",[assignment_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
                    assert_eq!(
                        (close_clock.2, close_clock.3),
                        (close_state.2, close_state.3)
                    );
                    assert_eq!(
                        (close_clock.1.as_str(), close_clock.4, close_clock.5),
                        ("released", 1, 1)
                    );
                    assert!(close_clock.0 < close_clock.2 && close_clock.0 < close_clock.3);
                    fs::write("/job/evidence/recovered-original-close-clock.json",serde_json::to_vec(&serde_json::json!({"requested_at":close_clock.0,"first_reason":close_clock.1,"lease_until":close_clock.2,"hard_until":close_clock.3,"held_claims":close_clock.4,"quota_charges":close_clock.5,"original_bounds_unchanged":true,"ordinary_close_before_expiry":true})).unwrap()).unwrap();
                    drop(close_after);
                    super::super::la_adapter::recovery_trace(
                        "recovered_cleanup_priority",
                        serde_json::json!({"held_before":close_clock.4,"charged_before":close_clock.5,"readback_deferred":true}),
                    );
                    let (observed, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    let initial: serde_json::Value = serde_json::from_str(&wm).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let cleanup = super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &initial["snapshot"],
                        &observed["snapshot"],
                        assignment_id,
                        now,
                    )
                    .unwrap();
                    let cleanup_bytes = serde_json::to_vec(&cleanup).unwrap();
                    fs::write(
                        "/job/evidence/recovered-original-cleanup.json",
                        &cleanup_bytes,
                    )
                    .unwrap();
                    fs::write(
                        "/job/evidence/recovered-original-occupancy.json",
                        serde_json::to_vec(&observed).unwrap(),
                    )
                    .unwrap();
                    cwriter.frame(b"CLEANUP ", &cleanup_bytes);
                    let first: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(first["ack"]["released_now"], true);
                    cwriter.frame(b"CLEANUP ", &cleanup_bytes);
                    let duplicate: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(duplicate["ack"]["released_now"], false);
                    // Cleanup is complete; obtain genuinely new sequenced W/C
                    // source ACKs before the slower retained result reads.
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let unchanged:(String,String,String,i64)=claims.query_row("SELECT p.command,m.body,j.id,p.permit_until FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                    assert_eq!(Some(&unchanged), original_stop_state.as_ref());
                    let worker = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    super::super::la_worker::verify_session_history(&worker, &keys.reply).unwrap();
                    let (records,starts,report):(i64,i64,Vec<u8>)=worker.query_row("SELECT COUNT(*),SUM(state IN ('started','complete')),report FROM operations",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!((records, starts), (1, 1));
                    let output: serde_json::Value = serde_json::from_slice(&report).unwrap();
                    assert_eq!(output["job_id"], job_id);
                    assert_eq!(output["sha256"], hex::encode(Sha256::digest(input)));
                    let entries =
                        fs::read_to_string("/job/evidence/worker-entered-work.jsonl").unwrap();
                    assert_eq!(entries.lines().count(), 1);
                    let cport = ready["address"]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let (_, mut sockets) = bridge.call(Op::Connect, Role::C, cport, &[]);
                    let mut http = KeepHttp(sockets.pop().unwrap());
                    let (status, view) = http.json(
                        "GET",
                        &format!("{base}/jobs/{job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200, "{view}");
                    assert_eq!(view["state"], "succeeded");
                    let output_id = view["result_artifact_id"].as_str().unwrap();
                    let (status, readback) = http.request(
                        "GET",
                        &format!("{base}/artifacts/{output_id}/content"),
                        &delegated,
                        "",
                        "",
                        &[],
                    );
                    assert_eq!(status, 200);
                    assert_eq!(readback, report);
                    let held:(i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(held, (0, 0), "independent cleanup precedes historical readback; held1 was captured immediately after Close");
                    // SAME retained client, ledger and worker: terminal release is
                    // followed by a DISTINCT admission and real new computation.
                    let immutable_before = retained_original_rows(&roots[1], assignment_id, job_id);
                    let (status, old_view) = lifecycle_http.json(
                        "GET",
                        &format!("{base}/jobs/{job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200, "{old_view}");
                    let old_output = old_view["result_artifact_id"].as_str().map(str::to_owned);
                    let old_bytes = old_output.as_ref().map(|output| {
                        let (status, data) = lifecycle_http.request(
                            "GET",
                            &format!("{base}/artifacts/{output}/content"),
                            &delegated,
                            "",
                            "",
                            &[],
                        );
                        assert_eq!(status, 200);
                        data
                    });
                    let (status, _) = lifecycle_http.json(
                        "POST",
                        &format!("{base}/assignments"),
                        &delegated,
                        "recovered_closed_001",
                        &acquire,
                    );
                    assert_eq!(status, 412, "new admission must remain closed");
                    // Mandatory cleanup has already durably released exactly once.
                    // Readbacks below do not create a new consumption window.
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!(counts, (0, 0, 1));
                    drop(claims);
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let (wo, _) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    let wo: serde_json::Value = serde_json::from_str(&wo).unwrap();
                    let (co, _) = bridge.call(Op::Observe, Role::C, 0, &[]);
                    let co: serde_json::Value = serde_json::from_str(&co).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let resource = family.seal(&next, &keys, now, now + 12000).unwrap();
                    let admission = super::super::la_adapter::RecoveredControllerAdmission::issue(
                        resource.clone(),
                        epoch_handoff.as_ref().unwrap(),
                        &cleanup,
                        &first["ack"],
                        &roots[0],
                        &roots[1],
                        &frames.transport_ledger.lock().unwrap(),
                        &recovered.transport_ledger.lock().unwrap(),
                        recovered.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &ready_v,
                        &ready,
                        &co["snapshot"],
                        &wo["snapshot"],
                        &keys,
                        now,
                        now + 12000,
                    )
                    .unwrap();
                    let expired = super::super::la_adapter::RecoveredControllerAdmission::issue(
                        resource,
                        epoch_handoff.as_ref().unwrap(),
                        &cleanup,
                        &first["ack"],
                        &roots[0],
                        &roots[1],
                        &frames.transport_ledger.lock().unwrap(),
                        &recovered.transport_ledger.lock().unwrap(),
                        recovered.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &ready_v,
                        &ready,
                        &co["snapshot"],
                        &wo["snapshot"],
                        &keys,
                        now,
                        now + 1,
                    )
                    .unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    let before_expired_c =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let before_expired_w =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    cwriter.frame(b"CADMIT ", &serde_json::to_vec(&expired).unwrap());
                    let refusal: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(refusal["ack"]["kind"], "RECOVERED_ADMISSION_REFUSED");
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                        before_expired_c
                    );
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                        before_expired_w
                    );
                    let cap_bytes = serde_json::to_vec(&admission).unwrap();
                    assert!(cap_bytes.len() <= 12288);
                    fs::write("/job/evidence/recovered-admission-probe.json", &cap_bytes).unwrap();
                    fs::write(
                        "/job/evidence/recovered-admission-probe-occupancy.json",
                        serde_json::to_vec(&serde_json::json!({"worker":wo,"controller":co}))
                            .unwrap(),
                    )
                    .unwrap();
                    // Altered, foreign and stale capabilities from otherwise-good
                    // state must leave both role roots and history cursors intact.
                    let before_c =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let before_w =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    for field in ["cleanup", "binding", "expiry"] {
                        let mut bad = serde_json::to_value(&admission).unwrap();
                        match field {
                            "cleanup" => bad["cleanup"] = "0".repeat(64).into(),
                            "binding" => bad["body"]["binding"]["controller_epoch"] = 1.into(),
                            _ => bad["body"]["expires_at"] = now.into(),
                        }
                        cwriter.frame(b"CADMIT ", &serde_json::to_vec(&bad).unwrap());
                        let refusal: serde_json::Value =
                            serde_json::from_str(&recovered.next()).unwrap();
                        assert_eq!(
                            refusal["ack"]["kind"], "RECOVERED_ADMISSION_REFUSED",
                            "{refusal}"
                        );
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap(),
                            before_c
                        );
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[0])
                                .unwrap(),
                            before_w
                        );
                    }
                    let old_ack: serde_json::Value = serde_json::from_slice(
                        &fs::read("/job/evidence/controller-activation-ack.json").unwrap(),
                    )
                    .unwrap();
                    assert!(admission
                        .verify_ack(
                            "controller",
                            &keys,
                            &serde_json::from_value(old_ack["ack"].clone()).unwrap()
                        )
                        .is_err());
                    if std::env::var("DIFFUSER_LA_ADMISSION_TEST_BOUNDARY").as_deref()
                        == Ok("source-near-expiry")
                    {
                        let db = super::super::la_store::open_pinned_readonly_database(
                            &roots[0],
                            "worker-channel.sqlite",
                        )
                        .unwrap();
                        let body: Vec<u8> = db
                            .query_row(
                                "SELECT body FROM channel_authority ORDER BY sequence DESC LIMIT 1",
                                [],
                                |r| r.get(0),
                            )
                            .unwrap();
                        let source: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let observed = source["observed_at"].as_u64().unwrap();
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        super::super::la_adapter::recovery_trace(
                            "admission_boundary_delay",
                            serde_json::json!({"observed_at":observed,"start":now,"target":observed+1490,"admission_expires_at":serde_json::to_value(&admission).unwrap()["body"]["expires_at"]}),
                        );
                        std::thread::sleep(std::time::Duration::from_millis(
                            (observed + 1490).saturating_sub(now),
                        ));
                    }
                    // Negative probes and their deliberate real-time expiry are
                    // complete. Qualify a DISTINCT current source and capsule at
                    // the delivery boundary; never retry the stale capsule or
                    // reinterpret its old source clock as current authority.
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let (wo, _) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    let wo: serde_json::Value = serde_json::from_str(&wo).unwrap();
                    let (co, _) = bridge.call(Op::Observe, Role::C, 0, &[]);
                    let co: serde_json::Value = serde_json::from_str(&co).unwrap();
                    let issued_now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let current_resource = family
                        .seal(&next, &keys, issued_now, issued_now + 12000)
                        .unwrap();
                    let admission = super::super::la_adapter::RecoveredControllerAdmission::issue(
                        current_resource,
                        epoch_handoff.as_ref().unwrap(),
                        &cleanup,
                        &first["ack"],
                        &roots[0],
                        &roots[1],
                        &frames.transport_ledger.lock().unwrap(),
                        &recovered.transport_ledger.lock().unwrap(),
                        recovered.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &ready_v,
                        &ready,
                        &co["snapshot"],
                        &wo["snapshot"],
                        &keys,
                        issued_now,
                        issued_now + 12000,
                    )
                    .unwrap();
                    assert!(admission
                        .verify_ack(
                            "controller",
                            &keys,
                            &serde_json::from_value(old_ack["ack"].clone()).unwrap()
                        )
                        .is_err());
                    // The original good-but-now-superseded probe must refuse
                    // before mutation. It cannot borrow the fresh source.
                    let current_c =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let current_w =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    cwriter.frame(b"CADMIT ", &cap_bytes);
                    let old_refusal: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(
                        old_refusal["ack"]["kind"], "RECOVERED_ADMISSION_REFUSED",
                        "{old_refusal}"
                    );
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                        current_c
                    );
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                        current_w
                    );
                    fs::write(
                        "/job/evidence/recovered-admission-superseded-refusal.json",
                        serde_json::to_vec(&old_refusal).unwrap(),
                    )
                    .unwrap();
                    let cap_bytes = serde_json::to_vec(&admission).unwrap();
                    assert!(cap_bytes.len() <= 12288);
                    fs::write("/job/evidence/recovered-admission.json", &cap_bytes).unwrap();
                    fs::write(
                        "/job/evidence/recovered-admission-occupancy.json",
                        serde_json::to_vec(&serde_json::json!({"worker":wo,"controller":co}))
                            .unwrap(),
                    )
                    .unwrap();
                    cwriter.frame(b"CADMIT ", &cap_bytes);
                    let admitted: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(admitted["kind"], "EPOCH_ACK", "{admitted}");
                    admission
                        .verify_ack(
                            "controller",
                            &keys,
                            &serde_json::from_value(admitted["ack"].clone()).unwrap(),
                        )
                        .unwrap();
                    fs::write(
                        "/job/evidence/recovered-admission-ack.json",
                        serde_json::to_vec(&admitted).unwrap(),
                    )
                    .unwrap();
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let (status, new_assignment) = lifecycle_http.json(
                        "POST",
                        &format!("{base}/assignments"),
                        &delegated,
                        "recovered_acquire_001",
                        &acquire,
                    );
                    assert_eq!(status, 202, "{new_assignment}");
                    assert_eq!(new_assignment["state"], "assigned");
                    let new_assignment_id = new_assignment["assignment_id"].as_str().unwrap();
                    assert_ne!(new_assignment_id, assignment_id);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let (old_fence,new_fence):(i64,i64)=claims.query_row("SELECT (SELECT fence FROM la_assignments WHERE id=?1),(SELECT fence FROM la_assignments WHERE id=?2)",rusqlite::params![assignment_id,new_assignment_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert!(new_fence > old_fence);
                    drop(claims);
                    let cert_value: serde_json::Value =
                        serde_json::from_slice(&cleanup_bytes).unwrap();
                    let expires = cert_value["body"]["expires_at"].as_u64().unwrap();
                    let clock = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    std::thread::sleep(std::time::Duration::from_millis(
                        expires.saturating_sub(clock) + 1,
                    ));
                    cwriter.frame(b"CLEANUP ", &cleanup_bytes);
                    let late: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(late["ack"]["released_now"], false);
                    // Exact old C1 Permit/Stop/Start envelopes cannot create a
                    // transport intent or mutate the higher-fence reservation.
                    let channel = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let old_commands: Vec<Vec<u8>> = {
                        let mut st=channel.prepare("SELECT request FROM channel_log WHERE json_extract(CAST(request AS TEXT),'$.request.binding.controller_epoch')=1 AND json_extract(CAST(request AS TEXT),'$.request.operation.operation') IN ('Permit','Stop','Start','Stage') ORDER BY sequence").unwrap();
                        let rows = st
                            .query_map([], |r| r.get(0))
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap();
                        rows
                    };
                    drop(channel);
                    assert!(!old_commands.is_empty());
                    let wport = ready_v["address"]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let (_, mut sockets) = bridge.call(Op::Connect, Role::W, wport, &[]);
                    let mut old_http = KeepHttp(sockets.pop().unwrap());
                    let channel = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let rebound_envelopes: Vec<Vec<u8>> = {
                        let mut st=channel.prepare("SELECT request FROM channel_log WHERE json_extract(CAST(request AS TEXT),'$.request.binding.controller_epoch')=2 AND json_extract(CAST(request AS TEXT),'$.request.operation.operation') IN ('ReboundPermit','Start') ORDER BY sequence").unwrap();
                        let rows = st
                            .query_map([], |r| r.get(0))
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap();
                        rows
                    };
                    drop(channel);
                    let before =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    for raw in &rebound_envelopes {
                        let parsed: serde_json::Value = serde_json::from_slice(raw).unwrap();
                        let op = parsed["request"]["operation"]["operation"]
                            .as_str()
                            .unwrap();
                        let mut frame = (raw.len() as u32).to_be_bytes().to_vec();
                        frame.extend(raw);
                        let (status, _) = old_http.request(
                            "POST",
                            if op == "ReboundPermit" {
                                "/v1/worker/rpc"
                            } else {
                                "/v1/worker/operations"
                            },
                            "",
                            "",
                            "application/octet-stream",
                            &frame,
                        );
                        assert_eq!(status, if op == "ReboundPermit" { 401 } else { 200 });
                    }
                    for raw in &old_commands {
                        let parsed: serde_json::Value = serde_json::from_slice(raw).unwrap();
                        let op = parsed["request"]["operation"]["operation"]
                            .as_str()
                            .unwrap();
                        // Stage carries input bytes; an old Permit suffices for
                        // every case, while Stop/Start have no payload.
                        if op == "Stage" {
                            continue;
                        }
                        let mut frame = (raw.len() as u32).to_be_bytes().to_vec();
                        frame.extend(raw);
                        let target = if op == "Stop" {
                            format!(
                                "/v1/worker/operations/{}/stop",
                                parsed["request"]["operation"]["command"]["operation"]
                                    .as_str()
                                    .unwrap()
                            )
                        } else {
                            "/v1/worker/operations".into()
                        };
                        let (status, _) = old_http.request(
                            "POST",
                            &target,
                            "",
                            "",
                            "application/octet-stream",
                            &frame,
                        );
                        assert_eq!(status, 401);
                    }
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                        before
                    );
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let fresh_submit = serde_json::json!({"schema_version":"diffuser-lane/v1","client_job_id":"recovered_client_new1","capability":"artifact.inspect.sha256/v1","profile_version":"1","input_artifact_ids":[input_id],"parameters":{},"max_runtime_ms":4000,"disconnect_policy":"continue_until_job_deadline"});
                    let (status, new_job) = lifecycle_http.json(
                        "POST",
                        &format!("{base}/assignments/{new_assignment_id}/jobs"),
                        &delegated,
                        "recovered_submit_001",
                        &fresh_submit,
                    );
                    assert_eq!(status, 202, "{new_job}");
                    assert_eq!(new_job["state"], "succeeded");
                    let new_job_id = new_job["job_id"].as_str().unwrap();
                    assert_ne!(new_job_id, job_id);
                    let (status, view) = lifecycle_http.json(
                        "GET",
                        &format!("{base}/jobs/{new_job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200);
                    let new_output = view["result_artifact_id"].as_str().unwrap();
                    let (status, new_report) = lifecycle_http.request(
                        "GET",
                        &format!("{base}/artifacts/{new_output}/content"),
                        &delegated,
                        "",
                        "",
                        &[],
                    );
                    assert_eq!(status, 200);
                    let parsed: serde_json::Value = serde_json::from_slice(&new_report).unwrap();
                    assert_eq!(parsed["job_id"], new_job_id);
                    assert_eq!(parsed["sha256"], hex::encode(Sha256::digest(input)));
                    let (status, retained) = lifecycle_http.json(
                        "GET",
                        &format!("{base}/jobs/{job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200);
                    assert_eq!(retained, old_view);
                    if let Some(output) = &old_output {
                        let (status, readback) = lifecycle_http.request(
                            "GET",
                            &format!("{base}/artifacts/{output}/content"),
                            &delegated,
                            "",
                            "",
                            &[],
                        );
                        assert_eq!(status, 200);
                        assert_eq!(Some(readback), old_bytes);
                    }
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let unchanged:(String,String,String,i64)=claims.query_row("SELECT p.command,m.body,j.id,p.permit_until FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                    assert_eq!(Some(&unchanged), original_stop_state.as_ref());
                    let held:(i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations WHERE assignment_id=?1),(SELECT COUNT(*) FROM la_quota_charges WHERE assignment_id=?1)",[new_assignment_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(held, (1, 1));
                    drop(claims);
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let (status,release2)=lifecycle_http.json("POST",&format!("{base}/assignments/{new_assignment_id}/release"),&delegated,"recovered_release_002",&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0}));
                    assert_eq!(status, 202, "{release2}");
                    let (observed, _) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let final_clean = super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &initial["snapshot"],
                        &observed["snapshot"],
                        new_assignment_id,
                        now,
                    )
                    .unwrap();
                    let final_bytes = serde_json::to_vec(&final_clean).unwrap();
                    cwriter.frame(b"CLEANUP ", &final_bytes);
                    let final_ack: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(final_ack["ack"]["released_now"], true);
                    cwriter.frame(b"CLEANUP ", &final_bytes);
                    let final_duplicate: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(final_duplicate["ack"]["released_now"], false);
                    fs::write("/job/evidence/recovered-new-cleanup.json", &final_bytes).unwrap();
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!(counts, (0, 0, 2));
                    drop(claims);
                    let worker = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    super::super::la_worker::verify_session_history(&worker, &keys.reply).unwrap();
                    let starts: i64 = worker
                        .query_row(
                            "SELECT COUNT(*) FROM operations WHERE state='complete'",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(starts, if never_started_case { 2 } else { 1 });
                    let events =
                        fs::read_to_string("/job/evidence/worker-entered-work.jsonl").unwrap();
                    assert_eq!(events.lines().count() as i64, starts);
                    assert_eq!(
                        retained_original_rows(&roots[1], assignment_id, job_id),
                        immutable_before
                    );
                    let lifecycle = serde_json::json!({"same_client":true,"same_ledger":true,"terminal_close":true,"original_cleanup":first,"duplicate_cleanup":duplicate,"late_committed_cleanup":late,"new_cleanup":final_ack,"final_duplicate":final_duplicate,"held_after":counts.0,"charged_after":counts.1,"cleanup_receipts":counts.2,"old_fence":old_fence,"new_fence":new_fence,"new_job":new_job_id,"actual_work_entries":starts,"original_state_and_result_preserved":true,"original_rows_unchanged":true,"fresh_separate_admission":true,"admission_generation":next.controller_epoch,"worker_boot_unchanged":true,"altered_foreign_stale_refused":true,"signed_expired_admission_refused":true,"immutable_original_rows_digest":immutable_before,"old_ack_refused":true,"old_commands_refused":true,"old_cleanup_preserved_new_claim":true});
                    fs::write(
                        "/job/evidence/recovered-lifecycle.json",
                        serde_json::to_vec(&lifecycle).unwrap(),
                    )
                    .unwrap();
                    let result = serde_json::json!({"status":"NEVER_STARTED_ORIGINAL_EXECUTED","case":std::env::var("DIFFUSER_LA_RESOURCE_PROBE").unwrap(),"original_job":job_id,"original_operation":original.operation,"original_command_mandate_deadlines_unchanged":true,"fresh_qualified_rebound_permit":true,"controller_epoch":2,"worker_epoch":1,"work_entries":1,"worker_starts":1,"worker_records":1,"held_claims":1,"quota_charges":1,"same_result_readback":true,"old_command_refused_after_rebound":true,"new_genesis":false,"resumed_original_job":true,"ordinary_new_assignment_admission":false,"whole_S1_complete":false});
                    let mut result = result;
                    result["lifecycle"] = lifecycle;
                    fs::write(
                        "/job/evidence/client-result.json",
                        serde_json::to_vec(&result).unwrap(),
                    )
                    .unwrap();
                    cwriter.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                    writer.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                    bridge.call(Op::Done, Role::P, 0, &[]);
                    println!("{result}");
                    return;
                }
                if stop_recovery
                    && std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                        != Ok("controller-stop-recovery")
                {
                    assert_eq!(ready["kind"], "RECOVERY_STARTUP_REFUSED", "{ready}");
                    assert_eq!(ready["code"], "evidence_invalid");
                    assert_eq!(ready["listener_binds"], 0);
                    assert_eq!(ready["store_opens"], 0);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let held:(i64,i64,String,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT state FROM la_jobs),(SELECT writer_epoch FROM la_controller_identity)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                    assert_eq!(held, (1, 1, "stopping".into(), 1));
                    let result = serde_json::json!({"status":"PENDING_STOP_CORRUPTION_REFUSED","refusal":ready,"held_claims":1,"quota_charges":1,"controller_epoch":1,"work_entries":0,"whole_S1_complete":false});
                    fs::write(
                        "/job/evidence/client-result.json",
                        serde_json::to_vec(&result).unwrap(),
                    )
                    .unwrap();
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                    writer.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                    bridge.call(Op::Done, Role::P, 0, &[]);
                    println!("{result}");
                    return;
                }
                if stop_recovery
                    && std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                        == Ok("controller-stop-recovery")
                {
                    assert_eq!(ready["kind"], "READY", "{ready}");
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let current: (String,String,String,i64) = claims.query_row("SELECT p.command,m.body,j.id,p.permit_until FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                    assert_eq!(Some(&current), original_stop_state.as_ref());
                    let state: (String,String,i64,i64,i64) = claims.query_row("SELECT (SELECT state FROM la_jobs),(SELECT action FROM la_job_outbox),(SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT writer_epoch FROM la_controller_identity)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
                    assert_eq!(state, ("cancelled".into(), "stopped".into(), 1, 1, 2));
                    let worker = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64)=worker.query_row("SELECT COUNT(*),COALESCE(SUM(state IN ('started','complete')),0) FROM operations",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(counts, (1, 0));
                    assert!(
                        fs::read_to_string("/job/evidence/worker-entered-work.jsonl")
                            .unwrap_or_default()
                            .is_empty()
                    );
                    let service = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "service-custody.sqlite",
                    )
                    .unwrap();
                    let midpoints:i64=service.query_row("SELECT COUNT(*) FROM service_checkpoints WHERE CAST(frame AS TEXT) LIKE '%stop_intent%'",[],|r|r.get(0)).unwrap();
                    assert_eq!(midpoints, 1);
                    // SAME retained client, ledger and worker: terminal release is
                    // followed by a DISTINCT admission and real new computation.
                    let immutable_before = retained_original_rows(&roots[1], assignment_id, job_id);
                    let mut lifecycle_sequence = sequence + u64::from(never_started_case);
                    let mut refresh_lifecycle =
                        |writer: &mut SharedControl,
                         frames: &mut WitnessFrames,
                         cwriter: &mut SharedControl,
                         recovered: &mut WitnessFrames| {
                            lifecycle_sequence += 1;
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":lifecycle_sequence,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                            let source = super::super::la_adapter::sign_source_observation(
                                &keys.authority,
                                &next,
                                &canonical,
                            )
                            .unwrap();
                            recovered
                                .state_ledger
                                .lock()
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .record_authority(&source)
                                .unwrap();
                            writer.frame(b"AUTH ", &source);
                            cwriter.frame(b"AUTH ", &source);
                            let wack: serde_json::Value =
                                serde_json::from_str(&frames.next()).unwrap();
                            let cack: serde_json::Value =
                                serde_json::from_str(&recovered.next()).unwrap();
                            assert_eq!(wack["kind"], "AUTHORITY_ACK");
                            assert_eq!(cack["kind"], "AUTHORITY_ACK");
                            fs::write(format!("/job/evidence/lifecycle-source-{lifecycle_sequence:03}.json"),
                                serde_json::to_vec(&serde_json::json!({"frame":serde_json::from_slice::<serde_json::Value>(&source).unwrap(),"worker":wack,"controller":cack})).unwrap()).unwrap();
                            recovered
                                .state_ledger
                                .lock()
                                .unwrap()
                                .as_mut()
                                .unwrap()
                                .observe_authority(
                                    &source,
                                    &serde_json::from_value(cack["ack"].clone()).unwrap(),
                                    &serde_json::from_value(wack["ack"].clone()).unwrap(),
                                )
                                .unwrap();
                        };
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let cport = ready["address"]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let (_, mut sockets) = bridge.call(Op::Connect, Role::C, cport, &[]);
                    let mut lifecycle_http = KeepHttp(sockets.pop().unwrap());
                    let (status, old_view) = lifecycle_http.json(
                        "GET",
                        &format!("{base}/jobs/{job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200, "{old_view}");
                    let old_output = old_view["result_artifact_id"].as_str().map(str::to_owned);
                    let old_bytes = old_output.as_ref().map(|output| {
                        let (status, data) = lifecycle_http.request(
                            "GET",
                            &format!("{base}/artifacts/{output}/content"),
                            &delegated,
                            "",
                            "",
                            &[],
                        );
                        assert_eq!(status, 200);
                        data
                    });
                    let (status, _) = lifecycle_http.json(
                        "POST",
                        &format!("{base}/assignments"),
                        &delegated,
                        "recovered_closed_001",
                        &acquire,
                    );
                    assert_eq!(status, 412, "new admission must remain closed");
                    let (status, released) = lifecycle_http.json("POST", &format!("{base}/assignments/{assignment_id}/release"), &delegated, "recovered_release_001", &serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0}));
                    assert_eq!(status, 202, "ordinary terminal Close: {released}");
                    let (observed, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    let initial: serde_json::Value = serde_json::from_str(&wm).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let cleanup = super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &initial["snapshot"],
                        &observed["snapshot"],
                        assignment_id,
                        now,
                    )
                    .unwrap();
                    let cleanup_bytes = serde_json::to_vec(&cleanup).unwrap();
                    fs::write(
                        "/job/evidence/recovered-original-cleanup.json",
                        &cleanup_bytes,
                    )
                    .unwrap();
                    fs::write(
                        "/job/evidence/recovered-original-occupancy.json",
                        serde_json::to_vec(&observed).unwrap(),
                    )
                    .unwrap();
                    cwriter.frame(b"CLEANUP ", &cleanup_bytes);
                    let first: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(first["ack"]["released_now"], true);
                    cwriter.frame(b"CLEANUP ", &cleanup_bytes);
                    let duplicate: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(duplicate["ack"]["released_now"], false);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!(counts, (0, 0, 1));
                    drop(claims);
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let (wo, _) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    let wo: serde_json::Value = serde_json::from_str(&wo).unwrap();
                    let (co, _) = bridge.call(Op::Observe, Role::C, 0, &[]);
                    let co: serde_json::Value = serde_json::from_str(&co).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let resource = family.seal(&next, &keys, now, now + 12000).unwrap();
                    let admission = super::super::la_adapter::RecoveredControllerAdmission::issue(
                        resource.clone(),
                        epoch_handoff.as_ref().unwrap(),
                        &cleanup,
                        &first["ack"],
                        &roots[0],
                        &roots[1],
                        &frames.transport_ledger.lock().unwrap(),
                        &recovered.transport_ledger.lock().unwrap(),
                        recovered.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &ready_v,
                        &ready,
                        &co["snapshot"],
                        &wo["snapshot"],
                        &keys,
                        now,
                        now + 12000,
                    )
                    .unwrap();
                    let expired = super::super::la_adapter::RecoveredControllerAdmission::issue(
                        resource,
                        epoch_handoff.as_ref().unwrap(),
                        &cleanup,
                        &first["ack"],
                        &roots[0],
                        &roots[1],
                        &frames.transport_ledger.lock().unwrap(),
                        &recovered.transport_ledger.lock().unwrap(),
                        recovered.state_ledger.lock().unwrap().as_ref().unwrap(),
                        &ready_v,
                        &ready,
                        &co["snapshot"],
                        &wo["snapshot"],
                        &keys,
                        now,
                        now + 1,
                    )
                    .unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    let before_expired_c =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let before_expired_w =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    cwriter.frame(b"CADMIT ", &serde_json::to_vec(&expired).unwrap());
                    let refusal: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(refusal["ack"]["kind"], "RECOVERED_ADMISSION_REFUSED");
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                        before_expired_c
                    );
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                        before_expired_w
                    );
                    let cap_bytes = serde_json::to_vec(&admission).unwrap();
                    assert!(cap_bytes.len() <= 12288);
                    fs::write("/job/evidence/recovered-admission.json", &cap_bytes).unwrap();
                    fs::write(
                        "/job/evidence/recovered-admission-occupancy.json",
                        serde_json::to_vec(&serde_json::json!({"worker":wo,"controller":co}))
                            .unwrap(),
                    )
                    .unwrap();
                    // Altered, foreign and stale capabilities from otherwise-good
                    // state must leave both role roots and history cursors intact.
                    let before_c =
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap();
                    let before_w =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    for field in ["cleanup", "binding", "expiry"] {
                        let mut bad = serde_json::to_value(&admission).unwrap();
                        match field {
                            "cleanup" => bad["cleanup"] = "0".repeat(64).into(),
                            "binding" => bad["body"]["binding"]["controller_epoch"] = 1.into(),
                            _ => bad["body"]["expires_at"] = now.into(),
                        }
                        cwriter.frame(b"CADMIT ", &serde_json::to_vec(&bad).unwrap());
                        let refusal: serde_json::Value =
                            serde_json::from_str(&recovered.next()).unwrap();
                        assert_eq!(
                            refusal["ack"]["kind"], "RECOVERED_ADMISSION_REFUSED",
                            "{refusal}"
                        );
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[1])
                                .unwrap(),
                            before_c
                        );
                        assert_eq!(
                            super::super::la_adapter::state_custody::state_digest(&roots[0])
                                .unwrap(),
                            before_w
                        );
                    }
                    let old_ack: serde_json::Value = serde_json::from_slice(
                        &fs::read("/job/evidence/controller-activation-ack.json").unwrap(),
                    )
                    .unwrap();
                    assert!(admission
                        .verify_ack(
                            "controller",
                            &keys,
                            &serde_json::from_value(old_ack["ack"].clone()).unwrap()
                        )
                        .is_err());
                    cwriter.frame(b"CADMIT ", &cap_bytes);
                    let admitted: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(admitted["kind"], "EPOCH_ACK", "{admitted}");
                    admission
                        .verify_ack(
                            "controller",
                            &keys,
                            &serde_json::from_value(admitted["ack"].clone()).unwrap(),
                        )
                        .unwrap();
                    fs::write(
                        "/job/evidence/recovered-admission-ack.json",
                        serde_json::to_vec(&admitted).unwrap(),
                    )
                    .unwrap();
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let (status, new_assignment) = lifecycle_http.json(
                        "POST",
                        &format!("{base}/assignments"),
                        &delegated,
                        "recovered_acquire_001",
                        &acquire,
                    );
                    assert_eq!(status, 202, "{new_assignment}");
                    assert_eq!(new_assignment["state"], "assigned");
                    let new_assignment_id = new_assignment["assignment_id"].as_str().unwrap();
                    assert_ne!(new_assignment_id, assignment_id);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let (old_fence,new_fence):(i64,i64)=claims.query_row("SELECT (SELECT fence FROM la_assignments WHERE id=?1),(SELECT fence FROM la_assignments WHERE id=?2)",rusqlite::params![assignment_id,new_assignment_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert!(new_fence > old_fence);
                    drop(claims);
                    let cert_value: serde_json::Value =
                        serde_json::from_slice(&cleanup_bytes).unwrap();
                    let expires = cert_value["body"]["expires_at"].as_u64().unwrap();
                    let clock = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    std::thread::sleep(std::time::Duration::from_millis(
                        expires.saturating_sub(clock) + 1,
                    ));
                    cwriter.frame(b"CLEANUP ", &cleanup_bytes);
                    let late: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(late["ack"]["released_now"], false);
                    // Exact old C1 Permit/Stop/Start envelopes cannot create a
                    // transport intent or mutate the higher-fence reservation.
                    let channel = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let old_commands: Vec<Vec<u8>> = {
                        let mut st=channel.prepare("SELECT request FROM channel_log WHERE json_extract(CAST(request AS TEXT),'$.request.binding.controller_epoch')=1 AND json_extract(CAST(request AS TEXT),'$.request.operation.operation') IN ('Permit','Stop','Start','Stage') ORDER BY sequence").unwrap();
                        let rows = st
                            .query_map([], |r| r.get(0))
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap();
                        rows
                    };
                    drop(channel);
                    assert!(!old_commands.is_empty());
                    let wport = ready_v["address"]
                        .as_str()
                        .unwrap()
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let (_, mut sockets) = bridge.call(Op::Connect, Role::W, wport, &[]);
                    let mut old_http = KeepHttp(sockets.pop().unwrap());
                    let channel = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let rebound_envelopes: Vec<Vec<u8>> = {
                        let mut st=channel.prepare("SELECT request FROM channel_log WHERE json_extract(CAST(request AS TEXT),'$.request.binding.controller_epoch')=2 AND json_extract(CAST(request AS TEXT),'$.request.operation.operation') IN ('ReboundPermit','Start') ORDER BY sequence").unwrap();
                        let rows = st
                            .query_map([], |r| r.get(0))
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap();
                        rows
                    };
                    drop(channel);
                    let before =
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap();
                    for raw in &rebound_envelopes {
                        let parsed: serde_json::Value = serde_json::from_slice(raw).unwrap();
                        let op = parsed["request"]["operation"]["operation"]
                            .as_str()
                            .unwrap();
                        let mut frame = (raw.len() as u32).to_be_bytes().to_vec();
                        frame.extend(raw);
                        let (status, _) = old_http.request(
                            "POST",
                            if op == "ReboundPermit" {
                                "/v1/worker/rpc"
                            } else {
                                "/v1/worker/operations"
                            },
                            "",
                            "",
                            "application/octet-stream",
                            &frame,
                        );
                        assert_eq!(status, if op == "ReboundPermit" { 401 } else { 200 });
                    }
                    for raw in &old_commands {
                        let parsed: serde_json::Value = serde_json::from_slice(raw).unwrap();
                        let op = parsed["request"]["operation"]["operation"]
                            .as_str()
                            .unwrap();
                        // Stage carries input bytes; an old Permit suffices for
                        // every case, while Stop/Start have no payload.
                        if op == "Stage" {
                            continue;
                        }
                        let mut frame = (raw.len() as u32).to_be_bytes().to_vec();
                        frame.extend(raw);
                        let target = if op == "Stop" {
                            format!(
                                "/v1/worker/operations/{}/stop",
                                parsed["request"]["operation"]["command"]["operation"]
                                    .as_str()
                                    .unwrap()
                            )
                        } else {
                            "/v1/worker/operations".into()
                        };
                        let (status, _) = old_http.request(
                            "POST",
                            &target,
                            "",
                            "",
                            "application/octet-stream",
                            &frame,
                        );
                        assert_eq!(status, 401);
                    }
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                        before
                    );
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let fresh_submit = serde_json::json!({"schema_version":"diffuser-lane/v1","client_job_id":"recovered_client_new1","capability":"artifact.inspect.sha256/v1","profile_version":"1","input_artifact_ids":[input_id],"parameters":{},"max_runtime_ms":4000,"disconnect_policy":"continue_until_job_deadline"});
                    let (status, new_job) = lifecycle_http.json(
                        "POST",
                        &format!("{base}/assignments/{new_assignment_id}/jobs"),
                        &delegated,
                        "recovered_submit_001",
                        &fresh_submit,
                    );
                    assert_eq!(status, 202, "{new_job}");
                    assert_eq!(new_job["state"], "succeeded");
                    let new_job_id = new_job["job_id"].as_str().unwrap();
                    assert_ne!(new_job_id, job_id);
                    let (status, view) = lifecycle_http.json(
                        "GET",
                        &format!("{base}/jobs/{new_job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200);
                    let new_output = view["result_artifact_id"].as_str().unwrap();
                    let (status, new_report) = lifecycle_http.request(
                        "GET",
                        &format!("{base}/artifacts/{new_output}/content"),
                        &delegated,
                        "",
                        "",
                        &[],
                    );
                    assert_eq!(status, 200);
                    let parsed: serde_json::Value = serde_json::from_slice(&new_report).unwrap();
                    assert_eq!(parsed["job_id"], new_job_id);
                    assert_eq!(parsed["sha256"], hex::encode(Sha256::digest(input)));
                    let (status, retained) = lifecycle_http.json(
                        "GET",
                        &format!("{base}/jobs/{job_id}"),
                        &delegated,
                        "",
                        &serde_json::Value::Null,
                    );
                    assert_eq!(status, 200);
                    assert_eq!(retained, old_view);
                    if let Some(output) = &old_output {
                        let (status, readback) = lifecycle_http.request(
                            "GET",
                            &format!("{base}/artifacts/{output}/content"),
                            &delegated,
                            "",
                            "",
                            &[],
                        );
                        assert_eq!(status, 200);
                        assert_eq!(Some(readback), old_bytes);
                    }
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let unchanged:(String,String,String,i64)=claims.query_row("SELECT p.command,m.body,j.id,p.permit_until FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
                    assert_eq!(Some(&unchanged), original_stop_state.as_ref());
                    let held:(i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations WHERE assignment_id=?1),(SELECT COUNT(*) FROM la_quota_charges WHERE assignment_id=?1)",[new_assignment_id],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
                    assert_eq!(held, (1, 1));
                    drop(claims);
                    refresh_lifecycle(&mut writer, &mut frames, &mut cwriter, &mut recovered);
                    let (status,release2)=lifecycle_http.json("POST",&format!("{base}/assignments/{new_assignment_id}/release"),&delegated,"recovered_release_002",&serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0}));
                    assert_eq!(status, 202, "{release2}");
                    let (observed, _) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    let observed: serde_json::Value = serde_json::from_str(&observed).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let final_clean = super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &initial["snapshot"],
                        &observed["snapshot"],
                        new_assignment_id,
                        now,
                    )
                    .unwrap();
                    let final_bytes = serde_json::to_vec(&final_clean).unwrap();
                    cwriter.frame(b"CLEANUP ", &final_bytes);
                    let final_ack: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(final_ack["ack"]["released_now"], true);
                    cwriter.frame(b"CLEANUP ", &final_bytes);
                    let final_duplicate: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(final_duplicate["ack"]["released_now"], false);
                    fs::write("/job/evidence/recovered-new-cleanup.json", &final_bytes).unwrap();
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!(counts, (0, 0, 2));
                    drop(claims);
                    let worker = super::super::la_store::open_pinned_readonly_database(
                        &roots[0],
                        "worker.sqlite",
                    )
                    .unwrap();
                    super::super::la_worker::verify_session_history(&worker, &keys.reply).unwrap();
                    let starts: i64 = worker
                        .query_row(
                            "SELECT COUNT(*) FROM operations WHERE state='complete'",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(starts, if never_started_case { 2 } else { 1 });
                    let events =
                        fs::read_to_string("/job/evidence/worker-entered-work.jsonl").unwrap();
                    assert_eq!(events.lines().count() as i64, starts);
                    assert_eq!(
                        retained_original_rows(&roots[1], assignment_id, job_id),
                        immutable_before
                    );
                    let lifecycle = serde_json::json!({"same_client":true,"same_ledger":true,"terminal_close":true,"original_cleanup":first,"duplicate_cleanup":duplicate,"late_committed_cleanup":late,"new_cleanup":final_ack,"final_duplicate":final_duplicate,"held_after":counts.0,"charged_after":counts.1,"cleanup_receipts":counts.2,"old_fence":old_fence,"new_fence":new_fence,"new_job":new_job_id,"actual_work_entries":starts,"original_state_and_result_preserved":true,"original_rows_unchanged":true,"fresh_separate_admission":true,"admission_generation":next.controller_epoch,"worker_boot_unchanged":true,"altered_foreign_stale_refused":true,"signed_expired_admission_refused":true,"immutable_original_rows_digest":immutable_before,"old_ack_refused":true,"old_commands_refused":true,"old_cleanup_preserved_new_claim":true});
                    fs::write(
                        "/job/evidence/recovered-lifecycle.json",
                        serde_json::to_vec(&lifecycle).unwrap(),
                    )
                    .unwrap();
                    let result = serde_json::json!({"status":"PENDING_STOP_RECONCILED","controller_epoch":2,"worker_epoch":1,"original_job":job_id,"original_command_mandate_deadlines_unchanged":true,"original_service_operation_settled":true,"held_claims":1,"quota_charges":1,"work_entries":0,"worker_records":1,"stop_midpoints":midpoints,"execution_admission_closed":ready["transport_probe"]["execution_admission_closed"],"replacement_stop":false,"resumed_dispatch":false,"whole_S1_complete":false});
                    let mut result = result;
                    result["lifecycle"] = lifecycle;
                    fs::write(
                        "/job/evidence/client-result.json",
                        serde_json::to_vec(&result).unwrap(),
                    )
                    .unwrap();
                    cwriter.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&recovered.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                    writer.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                    bridge.call(Op::Done, Role::P, 0, &[]);
                    println!("{result}");
                    return;
                }
                if matches!(
                    std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref(),
                    Ok("controller-recovery-prefix"
                        | "controller-recovery-ack"
                        | "controller-recovery-gap"
                        | "controller-close-recovery-envelope"
                        | "controller-close-recovery-midpoint"
                        | "controller-close-recovery-gap")
                ) {
                    // The child records actual constructor counts at failure,
                    // so listener closure during error unwind cannot hide a bind.
                    assert_eq!(ready["kind"], "RECOVERY_STARTUP_REFUSED", "{ready}");
                    assert_eq!(ready["code"], "evidence_invalid");
                    assert_eq!(
                        ready["listener_binds"], 0,
                        "corruption must precede every listener bind"
                    );
                    assert_eq!(
                        ready["store_opens"], 0,
                        "corruption must precede store construction"
                    );
                    let db = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let epoch: i64 = db
                        .query_row("SELECT writer_epoch FROM la_controller_identity", [], |r| {
                            r.get(0)
                        })
                        .unwrap();
                    assert_eq!(epoch, 1);
                    drop(db);
                    assert_eq!(
                        super::super::la_adapter::state_custody::state_digest(&roots[1]).unwrap(),
                        preserved
                    );
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let held_claims: i64 = claims
                        .query_row("SELECT COUNT(*) FROM la_reservations", [], |r| r.get(0))
                        .unwrap();
                    let quota_charges: i64 = claims
                        .query_row("SELECT COUNT(*) FROM la_quota_charges", [], |r| r.get(0))
                        .unwrap();
                    let service_close_acks: i64 = claims
                        .query_row(
                            "SELECT COUNT(*) FROM la_assignment_stop_receipts",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    let channel = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "controller-channel.sqlite",
                    )
                    .unwrap();
                    let pending_transport: i64 = channel
                        .query_row(
                            "SELECT COUNT(*) FROM channel_log WHERE response IS NULL",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    if close_recovery {
                        assert_eq!(
                            (
                                held_claims,
                                quota_charges,
                                service_close_acks,
                                pending_transport
                            ),
                            (1, 1, 0, 1)
                        );
                    }
                    let result = serde_json::json!({"status":"CORRUPTION_REFUSED_BEFORE_ACTIVATION","scenario":std::env::var("DIFFUSER_LA_RESOURCE_PROBE").unwrap(),"refusal":ready,"writer_epoch":epoch,"no_ready":true,"admitted_jobs":1,"worker_starts":1,"held_claims":held_claims,"quota_charges":quota_charges,"service_close_acks":service_close_acks,"pending_transport":pending_transport,"whole_S1_complete":false});
                    fs::write(
                        "/job/evidence/client-result.json",
                        serde_json::to_vec(&result).unwrap(),
                    )
                    .unwrap();
                    bridge.call(Op::StopC, Role::C, 0, &[]);
                    recovered.thread.take().unwrap().join().unwrap();
                    let transcript = fs::read_to_string(format!(
                        "/job/evidence/child-{}-stdout.raw",
                        recovered.stream_id
                    ))
                    .unwrap();
                    let observations: Vec<serde_json::Value> = transcript
                        .lines()
                        .filter_map(|line| {
                            line.split_once("DIFFUSER_LA_CHILD_V1 ")
                                .map(|(_, json)| serde_json::from_str(json).unwrap())
                        })
                        .collect();
                    assert_eq!(
                        observations
                            .iter()
                            .filter(|f| f["kind"] == "RECOVERY_STARTUP_REFUSED")
                            .count(),
                        1
                    );
                    assert!(!observations
                        .iter()
                        .any(|f| f["kind"] == "READY" || f["kind"] == "SERVICE_STATE_CHECKPOINT"));
                    fs::write("/job/evidence/corruption-complete-stream.json",serde_json::to_vec(&serde_json::json!({"frames":observations,"no_ready":true,"no_service_state_mutation":true,"complete_eof":true})).unwrap()).unwrap();

                    writer.write_all(b"STOP\n").unwrap();
                    assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                    bridge.call(Op::StopW, Role::W, 0, &[]);
                    bridge.call(Op::StopK, Role::K, 0, &[]);
                    bridge.call(Op::Done, Role::P, 0, &[]);
                    println!("{result}");
                    return;
                }
                assert_eq!(ready["kind"], "READY");
                assert_eq!(ready["run_nonce"], recovery_nonce);
                assert_eq!(ready["role"], "controller");
                assert_eq!(ready["executable_sha256"], whash);
                assert_eq!(ready["policy_digest"], binding.policy_digest);
                assert_eq!(ready["root_dev"], cmeta.dev());
                assert_eq!(ready["root_inode"], cmeta.ino());
                assert_eq!(ready["store_id"], cstore);
                assert_eq!(ready["boot_id"], next.controller_boot);
                assert_eq!(ready["transport_probe"]["admission"], "recovery_read_only");
                assert_eq!(
                    ready["transport_probe"]["worker_rebound"],
                    epoch_handoff.is_some()
                );
                if epoch_handoff.is_some() {
                    assert_eq!(ready["transport_probe"]["execution_admission_closed"], true);
                    assert_eq!(
                        ready["transport_probe"]["reconciliation"][0]["receipt"]["starts"],
                        1
                    );
                }
                let recovery_claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let held_at_recovery: i64 = recovery_claims
                    .query_row("SELECT COUNT(*) FROM la_reservations", [], |r| r.get(0))
                    .unwrap();
                let charged_at_recovery: i64 = recovery_claims
                    .query_row("SELECT COUNT(*) FROM la_quota_charges", [], |r| r.get(0))
                    .unwrap();
                assert_eq!((held_at_recovery, charged_at_recovery), (1, 1));
                drop(recovery_claims);
                let mut capacity_released = false;
                if close_recovery {
                    let (observation, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
                    assert!(rights.is_empty());
                    let observation: serde_json::Value =
                        serde_json::from_str(&observation).unwrap();
                    let initial: serde_json::Value = serde_json::from_str(&wm).unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    assert!(
                        super::super::la_adapter::cleanup::Certificate::inspect(
                            &binding,
                            &keys,
                            &roots[0],
                            &roots[1],
                            &custody,
                            &initial["snapshot"],
                            &observation["snapshot"],
                            assignment_id,
                            now
                        )
                        .is_err(),
                        "old binding cannot release after C2 recovery"
                    );
                    let cleanup = super::super::la_adapter::cleanup::Certificate::inspect(
                        &next,
                        &keys,
                        &roots[0],
                        &roots[1],
                        &custody,
                        &initial["snapshot"],
                        &observation["snapshot"],
                        assignment_id,
                        now,
                    )
                    .expect("fresh C2 binding and independent occupancy cleanup");
                    let bytes = serde_json::to_vec(&cleanup).unwrap();
                    fs::write("/job/evidence/recovery-cleanup.json", &bytes).unwrap();
                    fs::write(
                        "/job/evidence/recovery-cleanup-occupancy.json",
                        serde_json::to_vec(&observation).unwrap(),
                    )
                    .unwrap();
                    cwriter.frame(b"CLEANUP ", &bytes);
                    let first: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(first["kind"], "CLEANUP_ACK");
                    assert_eq!(first["ack"]["released_now"], true);
                    cwriter.frame(b"CLEANUP ", &bytes);
                    let duplicate: serde_json::Value =
                        serde_json::from_str(&recovered.next()).unwrap();
                    assert_eq!(duplicate["kind"], "CLEANUP_ACK");
                    assert_eq!(duplicate["ack"]["released_now"], false);
                    let claims = super::super::la_store::open_pinned_readonly_database(
                        &roots[1],
                        "lane_assignments.sqlite",
                    )
                    .unwrap();
                    let counts:(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    assert_eq!(counts, (0, 0, 1));
                    fs::write("/job/evidence/recovery-cleanup-acks.json",serde_json::to_vec(&serde_json::json!({"first":first,"duplicate":duplicate,"held_after":counts.0,"charged_after":counts.1,"cleanup_receipts":counts.2,"old_binding_refused":true})).unwrap()).unwrap();
                    capacity_released = true;
                }
                let cport = ready["address"]
                    .as_str()
                    .unwrap()
                    .rsplit(':')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                let (_, mut sockets) = bridge.call(Op::Connect, Role::C, cport, &[]);
                let mut http = KeepHttp(sockets.pop().unwrap());
                let (status, _) = http.json(
                    "GET",
                    &format!("{base}/jobs/{job_id}"),
                    &delegated,
                    "",
                    &serde_json::Value::Null,
                );
                assert_eq!(
                    status,
                    axum::http::StatusCode::PRECONDITION_FAILED.as_u16(),
                    "new boot requires a fresh protected source sequence"
                );
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":sequence+1,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
                let fresh = super::super::la_adapter::sign_source_observation(
                    &keys.authority,
                    &next,
                    &canonical,
                )
                .unwrap();
                recovered
                    .state_ledger
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .record_authority(&fresh)
                    .unwrap();
                cwriter.frame(b"AUTH ", &fresh);
                let observed: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                assert_eq!(observed["kind"], "AUTHORITY_ACK");
                let source_ack = serde_json::from_value(observed["ack"].clone()).unwrap();
                super::super::la_adapter::verify_source_ack(
                    &keys.reply,
                    &next,
                    "controller",
                    &canonical,
                    &source_ack,
                )
                .unwrap();
                if epoch_handoff.is_some() {
                    let replay_path = format!("{base}/assignments/{assignment_id}/jobs");
                    let (status, replayed) = http.json(
                        "POST",
                        &replay_path,
                        &delegated,
                        "vertical_submit_001",
                        &submit,
                    );
                    assert_eq!(
                        status, 202,
                        "recovered exact submission receipt: {replayed}"
                    );
                    assert_eq!(replayed["job_id"], job_id);
                    assert_eq!(replayed["state"], "succeeded");
                    super::assert_development_response("JobAccepted", &replayed);
                    let mut changed = submit.clone();
                    changed["max_runtime_ms"] = 4001.into();
                    let (status, _) = http.json(
                        "POST",
                        &replay_path,
                        &delegated,
                        "vertical_submit_001",
                        &changed,
                    );
                    assert_eq!(status, 409);
                    let (status, _) =
                        http.json("POST", &replay_path, &human, "vertical_submit_001", &submit);
                    assert_eq!(status, 404);
                    let (status, _) = http.json(
                        "POST",
                        &replay_path,
                        &delegated,
                        "recovered_new_key_01",
                        &submit,
                    );
                    assert_eq!(status, 503);
                    fs::write("/job/evidence/completed-request-retry.json",serde_json::to_vec(&serde_json::json!({"same_job":job_id,"exact_replay_status":202,"changed_content_status":409,"foreign_actor_status":404,"unknown_key_status":503,"no_new_dispatch":true})).unwrap()).unwrap();
                }
                let (status, view) = http.json(
                    "GET",
                    &format!("{base}/jobs/{job_id}"),
                    &delegated,
                    "",
                    &serde_json::Value::Null,
                );
                assert_eq!(status, 200, "recovered job: {view}");
                assert_eq!(view["result_artifact_id"], output_id);
                let (status, readback) = http.request(
                    "GET",
                    &format!("{base}/artifacts/{output_id}/content"),
                    &delegated,
                    "",
                    "",
                    &[],
                );
                assert_eq!(status, 200);
                assert_eq!(readback, report);
                let (status, _) = http.request(
                    "GET",
                    &format!("{base}/artifacts/{output_id}/content"),
                    &human,
                    "",
                    "",
                    &[],
                );
                assert_eq!(status, 404);
                let (status, _) = http.json(
                    "POST",
                    &format!("{base}/assignments"),
                    &delegated,
                    "recovery_acquire_01",
                    &acquire,
                );
                assert_eq!(status, 405);
                assert_eq!(
                    super::super::la_adapter::state_custody::state_digest(&roots[0]).unwrap(),
                    before_worker
                );
                let db = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker.sqlite",
                )
                .unwrap();
                let starts: i64 = db
                    .query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(starts, 1);
                drop(db);
                let db = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let epoch: i64 = db
                    .query_row("SELECT writer_epoch FROM la_controller_identity", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
                assert_eq!(epoch, 2);
                let held: i64 = db
                    .query_row("SELECT COUNT(*) FROM la_reservations", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(held, if close_recovery { 0 } else { 1 });
                let charges: i64 = db
                    .query_row("SELECT COUNT(*) FROM la_quota_charges", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(charges, if close_recovery { 0 } else { 1 });
                drop(db);
                fs::write("/job/evidence/recovery-report.json", &readback).unwrap();
                let events = fs::read_to_string("/job/evidence/worker-entered-work.jsonl").unwrap();
                let entries: Vec<serde_json::Value> = events
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0]["job"], job_id);
                assert_eq!(entries[0]["worker_boot"], binding.worker_boot);
                let db = super::super::la_store::open_pinned_readonly_database(
                    &roots[0],
                    "worker.sqlite",
                )
                .unwrap();
                let operation: String = db
                    .query_row("SELECT op FROM operations WHERE job=?1", [job_id], |r| {
                        r.get(0)
                    })
                    .unwrap();
                assert_eq!(entries[0]["operation"], operation);
                drop(db);

                let result = serde_json::json!({"status":"CONTROLLER_RECOVERY_READBACK","admitted_jobs":1,"worker_starts":starts,"observed_work_entries":entries.len(),"operation":operation,"report_sha256":hex::encode(Sha256::digest(&readback)),"same_report":true,"controller_epoch":epoch,"held_claims":held_at_recovery,"quota_charges":charged_at_recovery,"held_after":held,"charged_after":charges,"capacity_released":capacity_released,"interrupted_close_reconciled":close_recovery,"whole_S1_complete":false,"worker_rebound":epoch_handoff.is_some(),"transport_reconciliation":ready["transport_probe"],"completed_request_retry":epoch_handoff.is_some(),"publication_before_reply_barrier":!close_recovery,"close_before_ack_barrier":close_recovery,"terminal_bytes_before_death":terminal_bytes});
                fs::write(
                    "/job/evidence/client-result.json",
                    serde_json::to_vec(&result).unwrap(),
                )
                .unwrap();
                cwriter.write_all(b"STOP\n").unwrap();
                let stopped: serde_json::Value = serde_json::from_str(&recovered.next()).unwrap();
                assert_eq!(stopped["kind"], "STOPPED");
                bridge.call(Op::StopC, Role::C, 0, &[]);
                writer.write_all(b"STOP\n").unwrap();
                let stopped: serde_json::Value = serde_json::from_str(&frames.next()).unwrap();
                assert_eq!(stopped["kind"], "STOPPED");
                bridge.call(Op::StopW, Role::W, 0, &[]);
                bridge.call(Op::StopK, Role::K, 0, &[]);
                bridge.call(Op::Done, Role::P, 0, &[]);
                println!("{result}");
                return;
            }
            // Release is deliberately two stages: a caller closes/fences, then
            // protected P independently observes safe occupancy and both roots.
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let release_path = format!("{base}/assignments/{assignment_id}/release");
            let release =
                serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0});
            let (status, released) = http.json(
                "POST",
                &release_path,
                &delegated,
                "vertical_release_01",
                &release,
            );
            assert_eq!(status, 202, "release: {released}");
            assert_eq!(released["state"], crate::error_catalog::DRAINING);
            super::assert_development_response("AssignmentRelease", &released);
            let claims = super::super::la_store::open_pinned_readonly_database(
                &roots[1],
                "lane_assignments.sqlite",
            )
            .unwrap();
            let held: i64 = claims
                .query_row("SELECT COUNT(*) FROM la_reservations", [], |r| r.get(0))
                .unwrap();
            assert_eq!(held, 1, "worker fence is not independent cleanup proof");
            drop(claims);
            let channel = super::super::la_store::open_pinned_readonly_database(
                &roots[1],
                "controller-channel.sqlite",
            )
            .unwrap();
            let before: i64 = channel
                .query_row("SELECT MAX(sequence) FROM channel_log", [], |r| r.get(0))
                .unwrap();
            let (retry_status, retry) = http.json(
                "POST",
                &release_path,
                &delegated,
                "vertical_release_01",
                &release,
            );
            assert_eq!(retry_status, 202);
            assert_eq!(retry["state"], crate::error_catalog::DRAINING);
            let (after, pending): (i64, i64) = channel
                .query_row(
                    "SELECT MAX(sequence),SUM(response IS NULL) FROM channel_log",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(
                (after, pending),
                (before, 0),
                "acknowledged release retry cannot allocate or strand another RPC"
            );
            fs::write("/job/evidence/release-retry-before-cleanup.json",serde_json::to_vec(&serde_json::json!({"status":retry_status,"transport_before":before,"transport_after":after,"pending":pending,"held_claims":held})).unwrap()).unwrap();
            drop(channel);
            let (observation, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
            assert!(rights.is_empty());
            let observation: serde_json::Value = serde_json::from_str(&observation).unwrap();
            let initial: serde_json::Value = serde_json::from_str(&wm).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let mut foreign = observation["snapshot"].clone();
            foreign["members"].as_array_mut().unwrap().pop();
            assert!(super::super::la_adapter::cleanup::Certificate::inspect(
                &binding,
                &keys,
                &roots[0],
                &roots[1],
                &custody,
                &initial["snapshot"],
                &foreign,
                assignment_id,
                now
            )
            .is_err());
            let cleanup = super::super::la_adapter::cleanup::Certificate::inspect(
                &binding,
                &keys,
                &roots[0],
                &roots[1],
                &custody,
                &initial["snapshot"],
                &observation["snapshot"],
                assignment_id,
                now,
            )
            .expect("independent safe cleanup predicates");
            let bytes = serde_json::to_vec(&cleanup).unwrap();
            let mut record = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open("/job/custody/cleanup.json")
                .unwrap();
            record.write_all(&bytes).unwrap();
            record.sync_all().unwrap();
            custody.sync_all().unwrap();
            fs::write("/job/evidence/assignment-cleanup.json", &bytes).unwrap();
            fs::write(
                "/job/evidence/assignment-cleanup-occupancy.json",
                serde_json::to_vec(&observation).unwrap(),
            )
            .unwrap();
            cwriter.frame(b"CLEANUP ", &bytes);
            let ack: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
            assert_eq!(ack["kind"], "CLEANUP_ACK");
            assert_eq!(
                ack["ack"]["certificate_digest"],
                hex::encode(Sha256::digest(&bytes))
            );
            assert_eq!(ack["ack"]["released_now"], true);
            // A duplicate certificate cannot decrement another claim or quota.
            cwriter.frame(b"CLEANUP ", &bytes);
            let duplicate: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
            assert_eq!(duplicate["kind"], "CLEANUP_ACK");
            assert_eq!(duplicate["ack"]["released_now"], false);
            fs::write(
                "/job/evidence/assignment-cleanup-ack.json",
                serde_json::to_vec(&serde_json::json!({"first":ack,"duplicate":duplicate}))
                    .unwrap(),
            )
            .unwrap();
            let claims = super::super::la_store::open_pinned_readonly_database(
                &roots[1],
                "lane_assignments.sqlite",
            )
            .unwrap();
            let (held,charged,receipts,state):(i64,i64,i64,String)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts),(SELECT state FROM la_assignments WHERE id=?1)",[assignment_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
            assert_eq!(
                (held, charged, receipts, state.as_str()),
                (0, 0, 1, "closed")
            );
            drop(claims);
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let (status, closed) = http.json(
                "POST",
                &release_path,
                &delegated,
                "vertical_release_01",
                &release,
            );
            assert_eq!(status, 200);
            assert_eq!(closed["state"], "closed");
            super::assert_development_response("AssignmentRelease", &closed);
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let (status, next) = http.json(
                "POST",
                &format!("{base}/assignments"),
                &delegated,
                "vertical_acquire_002",
                &acquire,
            );
            assert_eq!(status, 202, "next claim: {next}");
            assert_eq!(next["state"], "assigned");
            super::assert_development_response("AssignmentAcquired", &next);
            let next_id = next["assignment_id"].as_str().unwrap();
            assert_ne!(next_id, assignment_id);
            // Old cleanup cannot consume a subsequent assignment's charge.
            cwriter.frame(b"CLEANUP ", &bytes);
            let duplicate: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
            assert_eq!(duplicate["kind"], "CLEANUP_ACK");
            assert_eq!(duplicate["ack"]["released_now"], false);
            let claims = super::super::la_store::open_pinned_readonly_database(
                &roots[1],
                "lane_assignments.sqlite",
            )
            .unwrap();
            let (held,charged,next_fence):(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT fence FROM la_assignments WHERE id=?1)",[next_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
            assert_eq!((held, charged, next_fence), (1, 1, 2));
            drop(claims);
            if revocation_case {
                refresh(
                    &mut writer,
                    &mut cwriter,
                    &mut frames,
                    &mut cframes,
                    vec!["grant_leaf123456"],
                );
                let claims = super::super::la_store::open_pinned_readonly_database(
                    &roots[1],
                    "lane_assignments.sqlite",
                )
                .unwrap();
                let (state,reason,stop):(String,String,i64)=claims.query_row("SELECT a.state,c.first_reason,(SELECT COUNT(*) FROM la_assignment_stop_receipts s WHERE s.assignment_id=a.id) FROM la_assignments a JOIN la_close_intents c ON c.assignment_id=a.id WHERE a.id=?1",[next_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                assert_eq!(
                    (state.as_str(), reason.as_str(), stop),
                    (crate::error_catalog::DRAINING, "revoked", 1)
                );
                drop(claims);
            } else {
                refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
                let (status, next_release) = http.json(
                    "POST",
                    &format!("{base}/assignments/{next_id}/release"),
                    &delegated,
                    "vertical_release_02",
                    &release,
                );
                assert_eq!(status, 202, "second fence: {next_release}");
            }
            let (observation, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
            assert!(rights.is_empty());
            let observation: serde_json::Value = serde_json::from_str(&observation).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let cleanup = super::super::la_adapter::cleanup::Certificate::inspect(
                &binding,
                &keys,
                &roots[0],
                &roots[1],
                &custody,
                &initial["snapshot"],
                &observation["snapshot"],
                next_id,
                now,
            )
            .expect("empty assignment still needs matching cleanup");
            let next_bytes = serde_json::to_vec(&cleanup).unwrap();
            fs::write("/job/evidence/next-assignment-cleanup.json", &next_bytes).unwrap();
            cwriter.frame(b"CLEANUP ", &next_bytes);
            let next_ack: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
            assert_eq!(next_ack["kind"], "CLEANUP_ACK");
            assert_eq!(next_ack["ack"]["released_now"], true);
            let claims = super::super::la_store::open_pinned_readonly_database(
                &roots[1],
                "lane_assignments.sqlite",
            )
            .unwrap();
            let (held,charged,cleaned):(i64,i64,i64)=claims.query_row("SELECT (SELECT COUNT(*) FROM la_reservations),(SELECT COUNT(*) FROM la_quota_charges),(SELECT COUNT(*) FROM la_assignment_cleanup_receipts)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
            assert_eq!((held, charged, cleaned), (0, 0, 2));
            drop(claims);
            fs::write("/job/evidence/release-capacity-result.json",serde_json::to_vec(&serde_json::json!({"held_after_worker_fence":1,"held_after_first_cleanup":0,"quota_after_first_cleanup":0,"subsequent_assignment":next_id,"subsequent_fence":next_fence,"old_cleanup_preserved_new_claim":true,"empty_assignment_verified_clean":true,"final_held":held,"final_quota":charged,"cleanup_receipts":cleaned})).unwrap()).unwrap();
            if revocation_case {
                let (status, denial) = http.request(
                    "GET",
                    &format!("{base}/artifacts/{output_id}/content"),
                    &delegated,
                    "",
                    "",
                    &[],
                );
                assert_eq!(status, 401, "revoked caller must lose read authority");
                let denial: serde_json::Value = serde_json::from_slice(&denial).unwrap();
                assert_eq!(denial["error"]["code"], "auth_invalid");
                super::assert_development_response("Error", &denial);
                let result = serde_json::json!({"status":"REVOCATION_STOPPED_RELEASED","ordinary_p":true,"admitted_jobs":1,"actual_worker_computations":1,"capacity_released":true,"revocation_closed_before_ack":true,"automatic_authenticated_worker_fence":true,"revoked_caller_refused":true,"terminal_result_preserved":true,"final_held":held,"final_quota":charged});
                fs::write(
                    "/job/evidence/client-result.json",
                    serde_json::to_vec(&result).unwrap(),
                )
                .unwrap();
                println!("{result}");
                cwriter.write_all(b"STOP\n").unwrap();
                assert_eq!(jsonstr(&cframes.next(), "kind"), "STOPPED");
                drop(cwriter);
                bridge.call(Op::StopC, Role::C, 0, &[]);
                writer.write_all(b"STOP\n").unwrap();
                assert_eq!(jsonstr(&frames.next(), "kind"), "STOPPED");
                drop(writer);
                bridge.call(Op::StopW, Role::W, 0, &[]);
                bridge.call(Op::StopK, Role::K, 0, &[]);
                bridge.call(Op::Done, Role::P, 0, &[]);
                return;
            }
            // Loss of W must not erase the already durable authorized result.
            bridge.call(Op::KillW, Role::W, 0, &[]);
            let claims = super::super::la_store::open_pinned_readonly_database(
                &roots[1],
                "lane_assignments.sqlite",
            )
            .unwrap();
            let high: i64 = claims
                .query_row(
                    "SELECT MAX(sequence) FROM la_authority_observations",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            drop(claims);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":high+1,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
            let observation = super::super::la_adapter::sign_source_observation(
                &keys.authority,
                &binding,
                &canonical,
            )
            .unwrap();
            cwriter.frame(b"AUTH ", &observation);
            let receipt: serde_json::Value = serde_json::from_str(&cframes.next()).unwrap();
            assert_eq!(receipt["kind"], "AUTHORITY_ACK");
            let ack = serde_json::from_value(receipt["ack"].clone()).unwrap();
            super::super::la_adapter::verify_source_ack(
                &keys.reply,
                &binding,
                "controller",
                &canonical,
                &ack,
            )
            .unwrap();
            let (status, recovered) = http.request(
                "GET",
                &format!("{base}/artifacts/{output_id}/content"),
                &delegated,
                "",
                "",
                &[],
            );
            assert_eq!(status, 200);
            assert_eq!(recovered, report);
            let (status, _) = http.request(
                "GET",
                &format!("{base}/artifacts/{output_id}/content"),
                &human,
                "",
                "",
                &[],
            );
            assert_eq!(status, 404);
            drop(http);
            fs::write("/job/evidence/vertical-report.json", &report).unwrap();
            let result = serde_json::json!({"status":"VERTICAL_COMPUTED_RETAINED","admitted_jobs":1,"ordinary_p":true,"actual_worker_computations":count,"job_id":job_id,"assignment_id":assignment_id,"input_bytes":input.len(),"input_sha256":hex::encode(Sha256::digest(input)),"output_bytes":report.len(),"output_sha256":digest,"job_elapsed_ms":job_ms,"durable_result_after_worker_kill":true,"foreign_actor_refused":true,"capacity_released":true,"cleanup_certificate_committed":true,"release_once_verified":true,"independent_occupancy_checked":true,"subsequent_assignment_acquired":true,"old_cleanup_preserved_new_claim":true,"empty_assignment_verified_clean":true,"resource_evidence_digest":family.seal(&binding,&keys,now,now+1500).unwrap().evidence_digest().to_owned()});
            fs::write(
                "/job/evidence/client-result.json",
                serde_json::to_vec(&result).unwrap(),
            )
            .unwrap();
            println!("{result}");
            cwriter.write_all(b"STOP\n").unwrap();
            assert_eq!(jsonstr(&cframes.next(), "kind"), "STOPPED");
            drop(cwriter);
            bridge.call(Op::StopC, Role::C, 0, &[]);
            bridge.call(Op::StopK, Role::K, 0, &[]);
            bridge.call(Op::Done, Role::P, 0, &[]);
            return;
        }
        let content_path = if storage_result.is_some() {
            let ready: serde_json::Value = serde_json::from_str(&cready).unwrap();
            let result = &ready["storage_probe"];
            assert_eq!(result["input_versions"], 32);
            assert_eq!(result["output_versions"], 32);
            assert_eq!(result["admitted_jobs"], 0);
            assert_eq!(result["input_overflow_refused"], true);
            assert_eq!(result["output_overflow_refused"], true);
            assert_eq!(result["all_bytes_read_back"], true);
            fs::write(
                "/job/evidence/controller-storage-capacity.json",
                serde_json::to_vec(result).unwrap(),
            )
            .unwrap();
            "/v1/diffuser/projects/project_12345678/artifacts/resource_input_0000/content"
                .to_owned()
        } else {
            let input = b"actual controller immutable input\0\xff";
            let path = "/v1/diffuser/projects/project_12345678/artifacts";
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let (_, mut fd) = bridge.call(Op::Connect, Role::C, cport, &[]);
            let (status, receipt) =
                artifact_http(fd.pop().unwrap(), "POST", path, &delegated, input);
            assert_eq!(status, 201);
            let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
            let object = receipt["object_id"].as_str().unwrap();
            let content_path = format!("{path}/{object}/content");
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let (_, mut fd) = bridge.call(Op::Connect, Role::C, cport, &[]);
            let (status, content) =
                artifact_http(fd.pop().unwrap(), "GET", &content_path, &delegated, b"");
            assert_eq!(status, 200);
            assert_eq!(content, input);
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let (_, mut fd) = bridge.call(Op::Connect, Role::C, cport, &[]);
            let (status, _) = artifact_http(fd.pop().unwrap(), "GET", &content_path, &human, b"");
            assert_eq!(status, 404);
            refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
            let (_, mut fd) = bridge.call(Op::Connect, Role::C, cport, &[]);
            let (status, retry) = artifact_http(fd.pop().unwrap(), "POST", path, &delegated, input);
            assert_eq!(status, 201);
            let retry: serde_json::Value = serde_json::from_slice(&retry).unwrap();
            assert_eq!(retry["object_id"], object);
            content_path
        };
        refresh(&mut writer, &mut cwriter, &mut frames, &mut cframes, vec![]);
        let (_, mut fd) = bridge.call(Op::Connect, Role::C, cport, &[]);
        let (status, refused) = unqualified_acquire_http(fd.pop().unwrap(), &delegated);
        assert_eq!(status, 412);
        let refusal: serde_json::Value = serde_json::from_slice(&refused).unwrap();
        assert_eq!(refusal["error"]["code"], "evidence_invalid");
        fs::write("/job/evidence/unqualified-acquire.json", refused).unwrap();
        refresh(
            &mut writer,
            &mut cwriter,
            &mut frames,
            &mut cframes,
            vec!["grant_root123456"],
        );
        let (_, mut fd) = bridge.call(Op::Connect, Role::C, cport, &[]);
        let (status, denied) =
            artifact_http(fd.pop().unwrap(), "GET", &content_path, &delegated, b"");
        assert_eq!(status, 401);
        fs::write("/job/evidence/revoked-parent-readback.json", denied).unwrap();
        cwriter.write_all(b"STOP\n").unwrap();
        let cstopped = cframes.next();
        assert_eq!(jsonstr(&cstopped, "kind"), "STOPPED");
        assert_eq!(jsonstr(&cstopped, "run_nonce"), cnonce);
        drop(cwriter);
        bridge.call(Op::StopC, Role::C, 0, &[]);
        let (killed, rights) = bridge.call(Op::KillW, Role::W, 0, &[]);
        assert!(rights.is_empty());
        assert_eq!(jsonstr(&killed, "kind"), "W_KILLED");
        drop(writer);
        drop(frames);
        // Capture the raw pre-open worker files, including WAL/SHM if present.
        // P only has a read-only, out-of-view descriptor to this finite root.
        let root_path = format!("/proc/self/fd/{}", roots[0].as_raw_fd());
        let mut manifest = Vec::new();
        for entry in fs::read_dir(&root_path).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            assert!(meta.is_file());
            let bytes = fs::read(entry.path()).unwrap();
            manifest.push(serde_json::json!({"name":entry.file_name().to_str().unwrap(),"dev":meta.dev(),"inode":meta.ino(),"size":meta.len(),"blocks":meta.blocks(),"sha256":hex::encode(Sha256::digest(&bytes))}));
        }
        manifest.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        assert!(manifest.iter().any(|v| v["name"] == "worker.sqlite"));
        fs::write(
            "/job/evidence/worker-preopen-manifest.json",
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(
            (
                roots[0].metadata().unwrap().dev(),
                roots[0].metadata().unwrap().ino()
            ),
            (st.dev(), st.ino())
        );
        let mut recovery_pipe = [-1i32; 2];
        assert_eq!(unsafe { pipe2(recovery_pipe.as_mut_ptr(), 0x80000) }, 0);
        let recovery_reader = unsafe { File::from_raw_fd(recovery_pipe[0]) };
        let mut recovery_writer = unsafe { File::from_raw_fd(recovery_pipe[1]) };
        let (restart, mut recovery_streams) =
            bridge.call(Op::RestartW, Role::W, 0, &[recovery_reader.as_raw_fd()]);
        drop(recovery_reader);
        assert_eq!(jsonstr(&restart, "kind"), "W_RESTARTED");
        checked_snapshot(&restart, Role::W, true, Some(st.dev()));
        check_control_custody(&restart, &recovery_writer);
        let recovery_nonce = randomhex();
        let recovery_boot = randomhex();
        let expected_history = if storage_result.is_some() { 32 } else { 0 };
        let recovery = serde_json::json!({"protocol_version":1,"run_nonce":recovery_nonce,"role":"worker","root":"/job/workerroot","policy_id":"runtime-short-v1","policy_digest":"8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e","expected_executable_sha256":whash,"authority_material":{"service_bearer":token,"worker_id":"worker_cpu_000001","boot_id":recovery_boot,"hardware_generation":1,"profile_epoch":1},"custody_manifest":{"mode":"recover","worker_id":"worker_cpu_000001","store_id":store,"root_dev":st.dev(),"root_inode":st.ino(),"expected_starts":expected_history,"expected_records":expected_history},"barrier_id":null});
        serde_json::to_writer(&mut recovery_writer, &recovery).unwrap();
        recovery_writer.write_all(b"\n").unwrap();
        let err = recovery_streams.pop().unwrap();
        let out = recovery_streams.pop().unwrap();
        let mut recovery_frames = Frames {
            out,
            err,
            buf: vec![],
            total: 0,
            eof: [false; 2],
        };
        let recovery_ready = recovery_frames.next();
        assert_eq!(jsonstr(&recovery_ready, "kind"), "READY");
        assert_eq!(jsonstr(&recovery_ready, "run_nonce"), recovery_nonce);
        assert_eq!(jsonstr(&recovery_ready, "boot_id"), recovery_boot);
        assert_eq!(jsonstr(&recovery_ready, "store_id"), store);
        let recovered: serde_json::Value = serde_json::from_str(&recovery_ready).unwrap();
        assert_eq!(recovered["root_dev"].as_u64(), Some(st.dev()));
        assert_eq!(recovered["root_inode"].as_u64(), Some(st.ino()));
        let (obs, rights) = bridge.call(Op::Observe, Role::W, 0, &[]);
        assert!(rights.is_empty());
        checked_snapshot(&obs, Role::W, false, Some(st.dev()));
        let (keeper_after_restart, rights) = bridge.call(Op::Observe, Role::K, 0, &[]);
        assert!(rights.is_empty());
        checked_snapshot(&keeper_after_restart, Role::K, false, None);
        let initial_keeper: serde_json::Value = serde_json::from_str(&km).unwrap();
        let later_keeper: serde_json::Value = serde_json::from_str(&keeper_after_restart).unwrap();
        assert_eq!(
            initial_keeper["identity"],
            later_keeper["snapshot"]["identity"]
        );
        assert_eq!(
            (
                roots[0].metadata().unwrap().dev(),
                roots[0].metadata().unwrap().ino()
            ),
            (st.dev(), st.ino())
        );
        recovery_writer.write_all(b"STOP\n").unwrap();
        let stopped = recovery_frames.next();
        assert_eq!(jsonstr(&stopped, "kind"), "STOPPED");
        assert_eq!(jsonstr(&stopped, "run_nonce"), recovery_nonce);
        drop(recovery_writer);
        bridge.call(Op::StopW, Role::W, 0, &[]);
        bridge.call(Op::StopK, Role::K, 0, &[]);
        let artifact_http_roundtrip = storage_result.is_none();
        let result=format!("{{\"status\":\"READY_200_401_STOPPED\",\"ordinary_p\":true,\"p_writable_paths_qualified\":false,\"sole_control_writer\":\"ordinary-libtest-p\",\"go_sent\":false,\"snapshot_api_exercised\":true,\"capacity_custody\":{c},\"capacity_evidence\":{e},\"controller_artifact_http_roundtrip\":{artifact_http_roundtrip},\"admitted_jobs\":0,\"good_status\":200,\"bad_status\":401,\"ready\":{ready},\"stopped\":{stopped},\"inventory\":{body}}}");
        let mut result: serde_json::Value = serde_json::from_str(&result).unwrap();
        result["worker_preopen_manifest"] = serde_json::json!(manifest);
        result["recovery_ready"] = recovered;
        result["storage_probe"] = serde_json::json!(storage_result);
        let result = serde_json::to_string(&result).unwrap();
        // Receipt goes through bounded evidence tmpfs; stdout is the operator's finite pipe/file.
        fs::write("/job/evidence/client-result.json", &result).unwrap();
        println!("{result}");
        bridge.call(Op::Done, Role::P, 0, &[]);
    }
}

#[test]
fn authenticated_reservation_receipt_is_fenced_durable_and_replay_safe() {
    use super::la_adapter::{sign_receipt, WorkerReceipt};
    use super::la_store::ClaimStore;
    let root = std::env::temp_dir().join(format!(
        "la-receipt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("claims.sqlite");
    let key = [42; 32];
    let mut store = ClaimStore::open(&path).unwrap();
    store
        .reserve(
            "assignment_12345",
            "project_12345678",
            "actor_1234567890",
            "acquire_key_12345",
            &"a".repeat(64),
            "worker_123456789",
            7,
        )
        .unwrap();
    let mut receipt = WorkerReceipt {
        worker: "worker_123456789".into(),
        boot: "boot_12345678901".into(),
        fence: 7,
        sequence: 1,
        operation: super::la_store::reservation_operation("assignment_12345", 7),
        assignment: "assignment_12345".into(),
        action: "reserved".into(),
        lease_until: 2_000,
        hard_until: 3_000,
    };
    let mac = sign_receipt(&key, &receipt).unwrap();
    let accept = |store: &mut ClaimStore, receipt: &WorkerReceipt, mac: &[u8; 32]| {
        store.acknowledge_reservation_receipt(
            &key,
            "worker_123456789",
            "boot_12345678901",
            &super::la_store::reservation_operation("assignment_12345", 7),
            receipt,
            mac,
        )
    };
    assert_eq!(
        accept(&mut store, &receipt, &[0; 32]),
        Err("evidence_invalid")
    );
    receipt.fence = 8;
    assert_eq!(accept(&mut store, &receipt, &mac), Err("evidence_invalid"));
    let bad_fence = sign_receipt(&key, &receipt).unwrap();
    assert_eq!(
        accept(&mut store, &receipt, &bad_fence),
        Err("state_conflict")
    );
    assert_eq!(store.state("assignment_12345").unwrap(), "reserved");
    receipt.fence = 7;
    accept(&mut store, &receipt, &mac).unwrap();
    assert_eq!(store.state("assignment_12345").unwrap(), "assigned");
    assert_eq!(store.counts().unwrap(), (1, 1, 0));
    drop(store);
    let mut store = ClaimStore::open(&path).unwrap();
    accept(&mut store, &receipt, &mac).unwrap();
    receipt.operation = "operation_changed".into();
    let other = sign_receipt(&key, &receipt).unwrap();
    assert_eq!(
        store.acknowledge_reservation_receipt(
            &key,
            "worker_123456789",
            "boot_12345678901",
            "operation_changed",
            &receipt,
            &other
        ),
        Err("evidence_invalid")
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn pending_job_transaction_preserves_mandate_and_idempotency() {
    use super::la_adapter::{sign_receipt, WorkerReceipt};
    use super::la_auth::{MandateDraft, MandateGrant};
    use super::la_store::ClaimStore;
    let root = std::env::temp_dir().join(format!(
        "la-job-tx-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("claims.sqlite");
    let mut store = ClaimStore::open(&path).unwrap();
    store
        .reserve(
            "assignment_12345",
            "project_12345678",
            "actor_1234567890",
            "acquire_key_12345",
            &"a".repeat(64),
            "worker_123456789",
            7,
        )
        .unwrap();
    let receipt = WorkerReceipt {
        worker: "worker_123456789".into(),
        boot: "boot_12345678901".into(),
        fence: 7,
        sequence: 1,
        operation: super::la_store::reservation_operation("assignment_12345", 7),
        assignment: "assignment_12345".into(),
        action: "reserved".into(),
        lease_until: 2_000,
        hard_until: 3_000,
    };
    let key = [42; 32];
    store
        .acknowledge_reservation_receipt(
            &key,
            &receipt.worker,
            &receipt.boot,
            &receipt.operation,
            &receipt,
            &sign_receipt(&key, &receipt).unwrap(),
        )
        .unwrap();
    let draft = MandateDraft {
        tenant: "tenant_123456789".into(),
        project: "project_12345678".into(),
        actor: "actor_1234567890".into(),
        initiator: "person_123456789".into(),
        lineage: "lineage_12345678".into(),
        assignment: "assignment_12345".into(),
        job: "job_123456789012".into(),
        operation: "operation_job123".into(),
        input_digest: "b".repeat(64),
        profile: "cpu-artifact-inspect".into(),
        worker: "worker_123456789".into(),
        cpu_millicores: 1000,
        memory_bytes: 1024,
        storage_bytes: 1024,
        policy: "lab-proposal-v1".into(),
        accepted_at: 1000,
        runtime_ms: 3000,
        assignment_hard: 5000,
        project_ceiling: 4500,
        chain: vec![
            MandateGrant {
                id: "grant_root123456".into(),
                parent: None,
                run_until: 4000,
                execution_ceiling: 3500,
            },
            MandateGrant {
                id: "grant_leaf123456".into(),
                parent: Some("grant_root123456".into()),
                run_until: 3000,
                execution_ceiling: 3200,
            },
        ],
    };
    let fp = "c".repeat(64);
    // The legacy unchecked ACK cannot provide a receipt-backed reservation.
    let legacy_root = root.join("legacy");
    std::fs::create_dir(&legacy_root).unwrap();
    let mut legacy = ClaimStore::open(&legacy_root.join("claims.sqlite")).unwrap();
    legacy
        .reserve(
            &draft.assignment,
            &draft.project,
            &draft.actor,
            "acquire_key_12345",
            &"a".repeat(64),
            &draft.worker,
            7,
        )
        .unwrap();
    legacy.ack(&draft.assignment, &draft.worker, 7).unwrap();
    assert_eq!(
        legacy.create_pending_job(&draft, "artifact_1234567", "submit_key_12345", &fp),
        Err("state_conflict")
    );
    drop(legacy);
    assert_eq!(
        store
            .create_pending_job(&draft, "artifact_1234567", "submit_key_12345", &fp)
            .unwrap(),
        draft.job
    );
    assert_eq!(
        store
            .create_pending_job(&draft, "artifact_1234567", "submit_key_12345", &fp)
            .unwrap(),
        draft.job
    );
    assert_eq!(
        store.create_pending_job(
            &draft,
            "artifact_1234567",
            "submit_key_12345",
            &"d".repeat(64)
        ),
        Err("idempotency_conflict")
    );
    assert_eq!(store.load_mandate(&draft.job).unwrap().max_until, 3000);
    assert_eq!(
        store
            .job_view(&draft.project, "other_actor_12345", &draft.job)
            .unwrap_err(),
        "object_not_found"
    );
    drop(store);
    let store = ClaimStore::open(&path).unwrap();
    let view = store
        .job_view(&draft.project, &draft.actor, &draft.job)
        .unwrap();
    assert_eq!(view.state, "pending");
    assert_eq!(view.input_artifact, "artifact_1234567");
    assert_eq!(view.result_artifact, None);
    drop(store);
    let mut store = ClaimStore::open(&path).unwrap();
    assert_eq!(
        store.request_job_stop(
            &draft.project,
            &draft.actor,
            &draft.job,
            "cancel_key_12345",
            1
        ),
        Err("state_conflict")
    );
    store
        .request_job_stop(
            &draft.project,
            &draft.actor,
            &draft.job,
            "cancel_key_12345",
            0,
        )
        .unwrap();
    store
        .request_job_stop(
            &draft.project,
            &draft.actor,
            &draft.job,
            "cancel_key_12345",
            0,
        )
        .unwrap();
    assert_eq!(
        store.request_job_stop(
            &draft.project,
            &draft.actor,
            &draft.job,
            "cancel_key_12345",
            1
        ),
        Err("idempotency_conflict")
    );
    assert_eq!(
        store
            .job_view(&draft.project, &draft.actor, &draft.job)
            .unwrap()
            .state,
        "stopping"
    );
    assert_eq!(store.counts().unwrap().0, 1);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

// Synthetic in-process evidence exercises ordinary request handlers and the
// real claim transaction. It is not worker/resource qualification.
#[tokio::test]
async fn fixture_claim_route_persists_reserved_and_scopes_retries() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut authority, human, agent) = fixture_discovery_context(now);
    for grant in &mut authority.grants {
        grant.scopes = 1 | 8 | 16 | 1024;
    }
    let authority = Arc::new(std::sync::RwLock::new(authority));
    let root = std::env::temp_dir().join(format!("la-fixture-claim-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::fixture_claim_router(
            authority.clone(),
            super::la_artifacts::ArtifactStore::open(&root).unwrap(),
            super::la_store::ClaimStore::open(&root.join("claims.sqlite")).unwrap(),
        ),
    );
    let valid = serde_json::json!({"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":120000,"requested_tenure_ms":600000});
    let acquire = |token: &str, key: &str, value: &Value| {
        Request::builder()
            .method("POST")
            .uri("/v1/diffuser/projects/project_12345678/assignments")
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", key)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    };
    let first = app
        .clone()
        .oneshot(acquire(&agent, "fixture_acquire_001", &valid))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first: Value = serde_json::from_slice(
        &axum::body::to_bytes(first.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first["state"], "reserved");
    let id = first["assignment_id"].as_str().unwrap();
    let again = app
        .clone()
        .oneshot(acquire(&agent, "fixture_acquire_001", &valid))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::ACCEPTED);
    let again: Value = serde_json::from_slice(
        &axum::body::to_bytes(again.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(again["assignment_id"], id);
    let mut changed = valid.clone();
    changed["requested_lease_ms"] = 1000.into();
    assert_eq!(
        app.clone()
            .oneshot(acquire(&agent, "fixture_acquire_001", &changed))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.clone()
            .oneshot(acquire(&human, "fixture_acquire_002", &valid))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let get = |token: &str| {
        Request::builder()
            .uri(format!(
                "/v1/diffuser/projects/project_12345678/assignments/{id}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(get(&agent)).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone().oneshot(get(&human)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    authority.write().unwrap().grants[0].revoked = true;
    assert_eq!(
        app.clone().oneshot(get(&agent)).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    drop(app);
    drop(authority);
    let store = super::la_store::ClaimStore::open(&root.join("claims.sqlite")).unwrap();
    assert_eq!(store.state(id).unwrap(), "reserved");
    assert_eq!(store.counts().unwrap(), (1, 1, 1));
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fixture_worker_reservation_command_is_authenticated_and_replay_stable() {
    use super::la_adapter::{sign_reserve_command, ReserveCommand};
    use super::la_worker::{OperationJournal, ReservationSession};
    let root = std::env::temp_dir().join(format!(
        "la-worker-reserve-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let worker_root = root.join("worker");
    let service_root = root.join("service");
    std::fs::create_dir(&worker_root).unwrap();
    std::fs::create_dir(&service_root).unwrap();
    let worker_path = worker_root.join("worker.sqlite");
    let mut worker = OperationJournal::bootstrap(&worker_path, "custody_12345678").unwrap();
    let mut service =
        super::la_store::ClaimStore::open(&service_root.join("claims.sqlite")).unwrap();
    service
        .reserve(
            "assignment_12345",
            "project_12345678",
            "actor_1234567890",
            "acquire_key_12345",
            &"a".repeat(64),
            "worker_123456789",
            7,
        )
        .unwrap();
    let session = ReservationSession {
        worker: "worker_123456789".into(),
        boot: "boot_12345678901".into(),
        key: [42; 32],
    };
    let mut command = ReserveCommand {
        worker: session.worker.clone(),
        boot: session.boot.clone(),
        assignment: "assignment_12345".into(),
        operation: super::la_store::reservation_operation("assignment_12345", 7),
        fence: 7,
        lease_until: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 60_000,
        hard_until: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 120_000,
    };
    assert!(matches!(
        worker.reserve_authenticated(&session, &command, &[0; 32]),
        Err("evidence_invalid")
    ));
    let signature = sign_reserve_command(&session.key, &command).unwrap();
    let (receipt, mac) = worker
        .reserve_authenticated(&session, &command, &signature)
        .unwrap();
    assert_eq!(receipt.sequence, 1);
    service
        .acknowledge_reservation_receipt(
            &session.key,
            &session.worker,
            &session.boot,
            &command.operation,
            &receipt,
            &mac,
        )
        .unwrap();
    assert_eq!(service.state("assignment_12345").unwrap(), "assigned");
    drop(worker);
    let mut worker =
        OperationJournal::reopen_checked(&worker_path, "custody_12345678", 0, 0).unwrap();
    let (again, again_mac) = worker
        .reserve_authenticated(&session, &command, &signature)
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&receipt).unwrap(),
        serde_json::to_vec(&again).unwrap()
    );
    assert_eq!(mac, again_mac);
    use sha2::{Digest, Sha256};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let input = b"fixture bytes for a real in-process SHA computation";
    let mut inspect = super::la_adapter::InspectCommand {
        backend: None,
        worker: session.worker.clone(),
        boot: session.boot.clone(),
        assignment: command.assignment.clone(),
        fence: 7,
        operation: "inspect_operation1".into(),
        job: "fixture_job_12345".into(),
        input_digest: hex::encode(Sha256::digest(input)),
        accepted_at: now,
        mandate_until: now + 5000,
        permit_until: now + 1500,
    };
    assert_eq!(
        worker.inspect_authenticated(&session, &inspect, &[0; 32], input),
        Err("evidence_invalid")
    );
    let permit_command_mac =
        super::la_adapter::sign_inspect_command(&session.key, &inspect).unwrap();
    let start_mac = super::la_adapter::sign_start_command(&session.key, &inspect).unwrap();
    assert_eq!(
        worker.inspect_authenticated(&session, &inspect, &start_mac, input),
        Err("evidence_invalid")
    );
    let (permit_receipt, permit_mac) = worker
        .accept_inspect_permit(&session, &inspect, &permit_command_mac)
        .unwrap();
    assert_eq!(permit_receipt.sequence, 2);
    super::la_adapter::verify_permit_receipt(&session.key, &permit_receipt, &permit_mac).unwrap();
    assert_eq!(
        worker.stage_authenticated_input(&session, &inspect, &[0; 32], input),
        Err("evidence_invalid")
    );
    let stage_mac = super::la_adapter::sign_stage_command(&session.key, &inspect).unwrap();
    assert_eq!(
        worker.stage_authenticated_input(&session, &inspect, &stage_mac, b"wrong"),
        Err("artifact_invalid")
    );
    worker
        .stage_authenticated_input(&session, &inspect, &stage_mac, input)
        .unwrap();
    worker
        .stage_authenticated_input(&session, &inspect, &stage_mac, input)
        .unwrap();
    let (report, result_receipt, result_mac) = worker
        .inspect_staged(&session, &inspect, &start_mac)
        .unwrap();
    super::la_adapter::verify_result_receipt(&session.key, &result_receipt, &result_mac).unwrap();
    let report_json: Value = serde_json::from_slice(&report).unwrap();
    assert_eq!(report_json["sha256"], hex::encode(Sha256::digest(input)));
    assert_eq!(report_json["bytes"], input.len());
    assert_eq!(
        worker
            .inspect_authenticated(&session, &inspect, &start_mac, input)
            .unwrap(),
        report
    );
    assert_eq!(worker.start_count(&inspect.operation).unwrap(), 1);
    let mut stopped = inspect.clone();
    stopped.operation = "stopped_operation1".into();
    stopped.job = "stopped_job_12345".into();
    assert_eq!(
        worker.stop_authenticated_before_start(&session, &stopped, &[0; 32]),
        Err("evidence_invalid")
    );
    let stop_mac = super::la_adapter::sign_stop_command(&session.key, &stopped).unwrap();
    worker
        .stop_authenticated_before_start(&session, &stopped, &stop_mac)
        .unwrap();
    let stopped_permit = super::la_adapter::sign_inspect_command(&session.key, &stopped).unwrap();
    let stopped_mac = super::la_adapter::sign_start_command(&session.key, &stopped).unwrap();
    worker
        .accept_inspect_permit(&session, &stopped, &stopped_permit)
        .unwrap();
    assert_eq!(
        worker.inspect_authenticated(&session, &stopped, &stopped_mac, input),
        Err("stopped")
    );
    assert_eq!(worker.start_count(&stopped.operation).unwrap(), 0);
    inspect.mandate_until += 1;
    let changed_start = super::la_adapter::sign_start_command(&session.key, &inspect).unwrap();
    assert_eq!(
        worker.inspect_authenticated(&session, &inspect, &changed_start, input),
        Err("idempotency_conflict")
    );
    command.fence = 8;
    let changed = sign_reserve_command(&session.key, &command).unwrap();
    assert!(matches!(
        worker.reserve_authenticated(&session, &command, &changed),
        Err("idempotency_conflict")
    ));
    command.assignment = "assignment_other".into();
    command.operation = "operation_other1".into();
    let second = sign_reserve_command(&session.key, &command).unwrap();
    assert!(matches!(
        worker.reserve_authenticated(&session, &command, &second),
        Err("capacity_unavailable")
    ));
    drop(worker);
    drop(service);
    std::fs::remove_dir_all(root).unwrap();
}

// This uses real route/ledger/worker code in one process with deliberately
// synthetic authority, worker key and resource evidence. It is not R proof.
async fn fixture_routes_lifecycle(execute: bool, typed: bool) {
    use sha2::{Digest, Sha256};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (mut authority, human, agent) = fixture_discovery_context(now);
    for grant in &mut authority.grants {
        grant.scopes = 2047;
    }
    let shared = Arc::new(std::sync::RwLock::new(authority));
    let root = std::env::temp_dir().join(format!(
        "la-route-lifecycle-{}-{now}-{execute}",
        std::process::id()
    ));
    let worker_root = root.join("worker");
    let service_root = root.join("service");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&worker_root).unwrap();
    std::fs::create_dir(&service_root).unwrap();
    let mut journal = super::la_worker::OperationJournal::bootstrap(
        &worker_root.join("worker.sqlite"),
        "custody_12345678",
    )
    .unwrap();
    if typed {
        journal
            .attach_backend(Box::new(
                super::la_backend::PrivateProcess::launch().unwrap(),
            ))
            .unwrap();
    }
    let session = super::la_worker::ReservationSession {
        worker: "worker_123456789".into(),
        boot: "boot_12345678901".into(),
        key: [42; 32],
    };
    let state = Spine {
        root: root.clone(),
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    let app = api_with_namespace(
        state,
        super::lane_assignment::fixture_worker_router(
            shared.clone(),
            super::la_artifacts::ArtifactStore::open(&service_root).unwrap(),
            super::la_store::ClaimStore::open(&service_root.join("claims.sqlite")).unwrap(),
            journal,
            session,
            execute,
        ),
    );
    let input: &[u8] = if typed {
        br#"{"schema_version":"diffuser-private-sha256-input/v1","data_hex":"616263","rounds":1}"#
    } else {
        b"fixture lifecycle input"
    };
    let upload = Request::builder()
        .method("POST")
        .uri("/v1/diffuser/projects/project_12345678/artifacts")
        .header("authorization", format!("Bearer {agent}"))
        .header("idempotency-key", "fixture_upload_001")
        .header("content-type", "application/octet-stream")
        .header("x-diffuser-schema", "diffuser-artifact/v1")
        .header("x-content-sha256", hex::encode(Sha256::digest(input)))
        .body(Body::from(input))
        .unwrap();
    let response = app.clone().oneshot(upload).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let receipt: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let input_id = receipt["object_id"].as_str().unwrap();
    let acquire = serde_json::json!({"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":10000,"requested_tenure_ms":600000});
    let call = |path: &str, token: &str, key: &str, value: &Value| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("idempotency-key", key)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(call(
            "/v1/diffuser/projects/project_12345678/assignments",
            &agent,
            "fixture_acquire_001",
            &acquire,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let assignment: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(assignment["state"], "assigned");
    let assignment_id = assignment["assignment_id"].as_str().unwrap();
    let mut submit = serde_json::json!({"schema_version":"diffuser-lane/v1","client_job_id":"client_job_123456","capability":"artifact.inspect.sha256/v1","profile_version":"1","input_artifact_ids":[input_id],"parameters":{},"max_runtime_ms":4000,"disconnect_policy":"continue_until_job_deadline"});
    if typed {
        submit["schema_version"] = "diffuser-lane/v2".into();
        submit["parameters"] = serde_json::json!({"backend":"cpu-private-sha256/v1"});
    }
    let path = format!("/v1/diffuser/projects/project_12345678/assignments/{assignment_id}/jobs");
    let response = app
        .clone()
        .oneshot(call(&path, &agent, "fixture_submit_001", &submit))
        .await
        .unwrap();
    let status = response.status();
    let job: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::ACCEPTED, "submit envelope {job}");
    assert_eq!(job["state"], if execute { "succeeded" } else { "pending" });
    let job_id = job["job_id"].as_str().unwrap();
    if execute {
        shared.write().unwrap().observation_sequence = 1;
        let recovered = api_with_namespace(
            Spine {
                root: root.clone(),
                edge: false,
                worker_ports: [0, 0],
                admin: false,
                sequence: Arc::new(Mutex::new(0)),
            },
            super::lane_assignment::recovered_readback_router(
                shared.clone(),
                super::la_artifacts::ArtifactStore::open(&service_root).unwrap(),
                Arc::new(Mutex::new(
                    super::la_store::ClaimStore::open(&service_root.join("claims.sqlite")).unwrap(),
                )),
                0,
            ),
        );
        let before = std::fs::read(service_root.join("claims.sqlite")).unwrap();
        let worker_before = super::la_adapter::state_custody::state_digest(
            &std::fs::File::open(&worker_root).unwrap(),
        )
        .unwrap();
        let response = recovered
            .clone()
            .oneshot(call(&path, &agent, "fixture_submit_001", &submit))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::ACCEPTED,
            "completed recovery retry must read the retained receipt"
        );
        let replay: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(replay, job);
        let mut conflict = submit.clone();
        conflict["max_runtime_ms"] = 4001.into();
        assert_eq!(
            recovered
                .clone()
                .oneshot(call(&path, &agent, "fixture_submit_001", &conflict))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            recovered
                .clone()
                .oneshot(call(&path, &human, "fixture_submit_001", &submit))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            recovered
                .clone()
                .oneshot(call(&path, &agent, "new_recovery_submit", &submit))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let grants = shared.read().unwrap().grants.clone();
        shared.write().unwrap().grants.last_mut().unwrap().id = "grant_other_leaf1".into();
        assert_eq!(
            recovered
                .clone()
                .oneshot(call(&path, &agent, "fixture_submit_001", &submit))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN,
            "same actor cannot change the charged credential lineage"
        );
        shared.write().unwrap().grants = grants.clone();
        shared
            .write()
            .unwrap()
            .grants
            .last_mut()
            .unwrap()
            .access_expires = now;
        assert_eq!(
            recovered
                .clone()
                .oneshot(call(&path, &agent, "fixture_submit_001", &submit))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        shared.write().unwrap().grants = grants.clone();
        shared.write().unwrap().grants.last_mut().unwrap().scopes = 0;
        assert_eq!(
            recovered
                .oneshot(call(&path, &agent, "fixture_submit_001", &submit))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        shared.write().unwrap().grants = grants;
        assert_eq!(
            std::fs::read(service_root.join("claims.sqlite")).unwrap(),
            before,
            "receipt retry cannot mutate claims, quotas, mandates or outbox"
        );
        assert_eq!(
            super::la_adapter::state_custody::state_digest(
                &std::fs::File::open(&worker_root).unwrap()
            )
            .unwrap(),
            worker_before
        );
    } else {
        shared.write().unwrap().observation_sequence = 1;
        let recovered = api_with_namespace(
            Spine {
                root: root.clone(),
                edge: false,
                worker_ports: [0, 0],
                admin: false,
                sequence: Arc::new(Mutex::new(0)),
            },
            super::lane_assignment::recovered_readback_router(
                shared.clone(),
                super::la_artifacts::ArtifactStore::open(&service_root).unwrap(),
                Arc::new(Mutex::new(
                    super::la_store::ClaimStore::open(&service_root.join("claims.sqlite")).unwrap(),
                )),
                0,
            ),
        );
        let response = recovered
            .oneshot(call(&path, &agent, "fixture_submit_001", &submit))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "pending work cannot be resumed through the completed-receipt path"
        );
    }
    let response = app
        .clone()
        .oneshot(call(&path, &agent, "fixture_submit_001", &submit))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let retry: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(retry["job_id"], job_id);
    let response = app
        .clone()
        .oneshot(call(&path, &agent, "fixture_alias_0001", &submit))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let alias: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(alias["job_id"], job_id);
    let mut changed = submit.clone();
    changed["max_runtime_ms"] = 3000.into();
    assert_eq!(
        app.clone()
            .oneshot(call(&path, &agent, "fixture_alias_0002", &changed))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let get = |token: &str| {
        Request::builder()
            .uri(format!(
                "/v1/diffuser/projects/project_12345678/jobs/{job_id}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(get(&agent)).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone().oneshot(get(&human)).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    if execute {
        let response = app.clone().oneshot(get(&agent)).await.unwrap();
        let view: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(view["state"], "succeeded");
        let output = view["result_artifact_id"].as_str().unwrap();
        let read = |token: &str| {
            Request::builder()
                .uri(format!(
                    "/v1/diffuser/projects/project_12345678/artifacts/{output}/content"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(read(&agent)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let report: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(report["sha256"], hex::encode(Sha256::digest(input)));
        assert_eq!(report["bytes"], input.len());
        if typed {
            assert_eq!(report["backend"], "cpu-private-sha256/v1");
            assert_eq!(report["output_sha256"], hex::encode(Sha256::digest(b"abc")));
        }
        let cancel_path = format!("/v1/diffuser/projects/project_12345678/jobs/{job_id}/cancel");
        let cancel = serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":view["revision"]});
        let response = app
            .clone()
            .oneshot(call(&cancel_path, &agent, "fixture_cancel_final", &cancel))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let terminal: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(terminal["state"], "succeeded");
        assert_eq!(
            app.clone().oneshot(read(&human)).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    } else {
        let cancel_path = format!("/v1/diffuser/projects/project_12345678/jobs/{job_id}/cancel");
        let cancel = serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0});
        assert_eq!(
            app.clone()
                .oneshot(call(&cancel_path, &agent, "fixture_cancel_001", &cancel))
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            app.clone()
                .oneshot(call(&cancel_path, &agent, "fixture_cancel_001", &cancel))
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
        let response = app.clone().oneshot(get(&agent)).await.unwrap();
        let view: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(view["state"], "cancelled");
        // Retain all 32 job/tombstone records; the 33rd must refuse rather
        // than deleting history to manufacture space.
        for index in 2..=32 {
            let mut next = submit.clone();
            next["client_job_id"] = format!("client_job_{index:06}").into();
            let submit_key = format!("fixture_submit_{index:03}");
            let response = app
                .clone()
                .oneshot(call(&path, &agent, &submit_key, &next))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED, "job {index}");
            let next_job: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let next_id = next_job["job_id"].as_str().unwrap();
            let cancel_path =
                format!("/v1/diffuser/projects/project_12345678/jobs/{next_id}/cancel");
            let cancel_key = format!("fixture_cancel_{index:03}");
            let cancel_for_job = if index == 2 {
                // Dispatch CAS won, but no worker start was sent. The signed
                // stop tombstone resolves this otherwise uncertain gap.
                let mut independent =
                    super::la_store::ClaimStore::open(&service_root.join("claims.sqlite")).unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                independent.claim_job_start(next_id, now).unwrap();
                assert_eq!(
                    independent.claim_job_start(next_id, now),
                    Err("state_conflict")
                );
                drop(independent);
                serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":1})
            } else {
                cancel.clone()
            };
            let response = app
                .clone()
                .oneshot(call(&cancel_path, &agent, &cancel_key, &cancel_for_job))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED, "cancel {index}");
            let cancelled: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(cancelled["state"], "cancelled");
        }
        let mut overflow = submit.clone();
        overflow["client_job_id"] = "client_job_000033".into();
        assert_eq!(
            app.clone()
                .oneshot(call(&path, &agent, "fixture_submit_033", &overflow))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let mut independent =
            super::la_store::ClaimStore::open(&service_root.join("claims.sqlite")).unwrap();
        let current = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert_eq!(
            independent.claim_job_start(job_id, current),
            Err("state_conflict")
        );
        drop(independent);
    }
    let renew_path =
        format!("/v1/diffuser/projects/project_12345678/assignments/{assignment_id}/renew");
    let renew = serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0,"requested_lease_ms":20000});
    let response = app
        .clone()
        .oneshot(call(&renew_path, &agent, "fixture_renew_001", &renew))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let renewed: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(renewed["renewal_state"], "acknowledged");
    assert!(
        renewed["lease_expires_at"].as_u64().unwrap()
            > assignment["lease_expires_at"].as_u64().unwrap()
    );
    let response = app
        .clone()
        .oneshot(call(&renew_path, &agent, "fixture_renew_001", &renew))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let retry: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(retry["lease_expires_at"], renewed["lease_expires_at"]);
    let release_path =
        format!("/v1/diffuser/projects/project_12345678/assignments/{assignment_id}/release");
    let release = serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":1});
    assert_eq!(
        app.clone()
            .oneshot(call(&release_path, &human, "fixture_release_01", &release))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.clone()
            .oneshot(call(&release_path, &agent, "fixture_release_01", &release))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        app.clone()
            .oneshot(call(&release_path, &agent, "fixture_release_01", &release))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    drop(app);
    drop(shared);
    let claims = super::la_store::ClaimStore::open(&service_root.join("claims.sqlite")).unwrap();
    assert_eq!(claims.counts().unwrap().0, 1);
    assert_eq!(
        claims.state(assignment_id).unwrap(),
        crate::error_catalog::DRAINING
    );
    assert!(claims.assignment_stop_recorded(assignment_id).unwrap());
    assert!(
        std::fs::read_dir(&worker_root).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("input-")),
        "closed assignment must remove staged input files before cleanup evidence"
    );
    assert_eq!(
        claims.job_history_count().unwrap(),
        if execute { 1 } else { 32 }
    );
    let command = claims.job_permit_command(job_id).unwrap();
    let session = super::la_worker::ReservationSession {
        worker: "worker_123456789".into(),
        boot: "boot_12345678901".into(),
        key: [42; 32],
    };
    let mut worker = super::la_worker::OperationJournal::reopen_checked(
        &worker_root.join("worker.sqlite"),
        "custody_12345678",
        u64::from(execute),
        if execute { 1 } else { 32 },
    )
    .unwrap();
    let start_mac = super::la_adapter::sign_start_command(&session.key, &command).unwrap();
    assert_eq!(
        worker.inspect_authenticated(&session, &command, &start_mac, input),
        Err("evidence_invalid")
    );
    drop(worker);
    drop(claims);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn fixture_routes_upload_claim_submit_status_and_cancel() {
    fixture_routes_lifecycle(false, false).await;
}

#[tokio::test]
async fn fixture_routes_authenticated_compute_and_readback() {
    fixture_routes_lifecycle(true, false).await;
}

#[tokio::test]
async fn fixture_routes_typed_sha256_compute_and_readback() {
    fixture_routes_lifecycle(true, true).await;
}

#[test]
fn synthetic_authenticated_authority_journal_replays_and_rejects_rollback() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (initial, _, _) = fixture_discovery_context(now);
    let root =
        std::env::temp_dir().join(format!("la-authority-journal-{}-{now}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("claims.sqlite");
    let mut store = super::la_store::ClaimStore::open(&path).unwrap();
    let authority = Arc::new(std::sync::RwLock::new(initial.clone()));
    let key = [73; 32];
    let first=serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":1,"observed_at":now,"revoked":["grant_root123456"]})).unwrap();
    let first = super::la_contract::canonical_json(&first).unwrap();
    assert_eq!(
        super::lane_assignment::apply_authenticated_authority_observation(
            &authority, &mut store, &key, &first, &[0; 32]
        ),
        Err("evidence_invalid")
    );
    assert_eq!(authority.read().unwrap().observation_sequence, 0);
    let mac = super::la_adapter::sign_authority_observation(&key, &first);
    super::lane_assignment::apply_authenticated_authority_observation(
        &authority, &mut store, &key, &first, &mac,
    )
    .unwrap();
    assert!(authority.read().unwrap().grants[0].revoked);
    assert_eq!(
        super::lane_assignment::apply_authenticated_authority_observation(
            &authority, &mut store, &key, &first, &mac
        ),
        Err("evidence_invalid")
    );
    let second=serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":2,"observed_at":now,"revoked":["grant_leaf123456"]})).unwrap();
    let second = super::la_contract::canonical_json(&second).unwrap();
    let mac = super::la_adapter::sign_authority_observation(&key, &second);
    super::lane_assignment::apply_authenticated_authority_observation(
        &authority, &mut store, &key, &second, &mac,
    )
    .unwrap();
    drop(store);
    let store = super::la_store::ClaimStore::open(&path).unwrap();
    let recovered = Arc::new(std::sync::RwLock::new(initial));
    assert_eq!(
        super::lane_assignment::recover_authenticated_authority(&recovered, &store, &key, 3),
        Err("evidence_invalid")
    );
    assert_eq!(recovered.read().unwrap().observation_sequence, 0);
    assert_eq!(
        super::lane_assignment::recover_authenticated_authority(&recovered, &store, &[99; 32], 2),
        Err("evidence_invalid")
    );
    super::lane_assignment::recover_authenticated_authority(&recovered, &store, &key, 2).unwrap();
    let recovered = recovered.read().unwrap();
    assert_eq!(recovered.observation_sequence, 2);
    assert!(recovered.grants.iter().all(|grant| grant.revoked));
    drop(recovered);
    drop(authority);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn synthetic_artifact_history_capacity_retains_all_versions() {
    use sha2::{Digest, Sha256};
    let root = std::env::temp_dir().join(format!(
        "la-artifact-capacity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    for index in 0..32 {
        let bytes = format!("history-version-{index}");
        let id = format!("artifact_{index:08}");
        store
            .put_input(
                "tenant_123456789",
                "project_12345678",
                "actor_1234567890",
                &id,
                bytes.as_bytes(),
                &hex::encode(Sha256::digest(bytes.as_bytes())),
                1,
                10_000,
            )
            .unwrap();
    }
    let bytes = b"overflow";
    assert_eq!(
        store.put_input(
            "tenant_123456789",
            "project_12345678",
            "actor_1234567890",
            "artifact_overflow",
            bytes,
            &hex::encode(Sha256::digest(bytes)),
            1,
            10_000
        ),
        Err("storage_unavailable")
    );
    for index in 0..32 {
        let id = format!("artifact_{index:08}");
        assert_eq!(
            store
                .read_input(
                    "tenant_123456789",
                    "project_12345678",
                    "actor_1234567890",
                    &id,
                    2
                )
                .unwrap(),
            format!("history-version-{index}").as_bytes()
        );
    }
    drop(store);
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    assert_eq!(
        store
            .read_input(
                "tenant_123456789",
                "project_12345678",
                "actor_1234567890",
                "artifact_00000000",
                2
            )
            .unwrap(),
        b"history-version-0"
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn authenticated_late_reservation_ack_cannot_revive_a_draining_claim() {
    use super::la_adapter::{sign_receipt, WorkerReceipt};
    let root = std::env::temp_dir().join(format!(
        "la-late-receipt-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut store = super::la_store::ClaimStore::open(&root.join("claims.sqlite")).unwrap();
    store
        .reserve(
            "assignment_12345",
            "project_12345678",
            "actor_1234567890",
            "acquire_key_12345",
            &"a".repeat(64),
            "worker_123456789",
            7,
        )
        .unwrap();
    store
        .drain(
            "assignment_12345",
            "project_12345678",
            "actor_1234567890",
            "released",
            100,
        )
        .unwrap();
    let receipt = WorkerReceipt {
        worker: "worker_123456789".into(),
        boot: "boot_12345678901".into(),
        fence: 7,
        sequence: 1,
        operation: super::la_store::reservation_operation("assignment_12345", 7),
        assignment: "assignment_12345".into(),
        action: "reserved".into(),
        lease_until: 2000,
        hard_until: 3000,
    };
    let key = [42; 32];
    let mac = sign_receipt(&key, &receipt).unwrap();
    assert_eq!(
        store.acknowledge_reservation_receipt(
            &key,
            &receipt.worker,
            &receipt.boot,
            &receipt.operation,
            &receipt,
            &mac
        ),
        Err("state_conflict")
    );
    assert_eq!(
        store.state("assignment_12345").unwrap(),
        crate::error_catalog::DRAINING
    );
    assert_eq!(store.counts().unwrap().0, 1);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn rpc_endpoint_rejects_unsigned_transport_before_object_lookup() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            super::la_worker::serve_inventory(
                listener,
                super::la_adapter::InventoryContext {
                    bearer_digest: [0; 32],
                    worker_id: "worker_cpu_000001".into(),
                    boot_id: "a".repeat(64),
                    hardware_generation: 1,
                    profile_epoch: 1,
                },
                async {
                    let _ = rx.await;
                },
            )
            .await
            .unwrap();
        });
    });
    let mut socket = std::net::TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    socket.write_all(b"POST /v1/worker/rpc HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    let _ = tx.send(());
    thread.join().unwrap();
    assert!(response.starts_with("HTTP/1.1 401 "), "{response}");
}

#[test]
fn artifact_history_keeps_32_input_and_32_output_versions_without_deletion() {
    use sha2::{Digest, Sha256};
    let root = std::env::temp_dir().join(format!(
        "la-both-history-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    let digest = hex::encode(Sha256::digest(b"input"));
    let output_digest = hex::encode(Sha256::digest(b"output"));
    for index in 0..32 {
        store
            .put_input(
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                &format!("history_input_{index:04}"),
                b"input",
                &digest,
                1,
                10000,
            )
            .unwrap();
    }
    for index in 0..32 {
        store
            .put_output(
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                &format!("history_output_{index:04}"),
                "assignment_00001",
                &format!("resource_job_{index:04}"),
                b"output",
                &output_digest,
                1,
                10000,
            )
            .unwrap();
    }
    assert_eq!(
        store.put_input(
            "tenant_123456789",
            "project_12345678",
            "agent_1234567890",
            "history_input_0032",
            b"input",
            &digest,
            1,
            10000
        ),
        Err("storage_unavailable")
    );
    assert_eq!(
        store.put_output(
            "tenant_123456789",
            "project_12345678",
            "agent_1234567890",
            "history_output_0032",
            "assignment_00001",
            "resource_job_0032",
            b"output",
            &output_digest,
            1,
            10000
        ),
        Err("storage_unavailable")
    );
    drop(store);
    let mut store = super::la_artifacts::ArtifactStore::open(&root).unwrap();
    for index in 0..32 {
        let (_, input) = store
            .read_manifest_and_content(
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                &format!("history_input_{index:04}"),
                2,
            )
            .unwrap();
        assert_eq!(input, b"input");
        let (_, output) = store
            .read_manifest_and_content(
                "tenant_123456789",
                "project_12345678",
                "agent_1234567890",
                &format!("history_output_{index:04}"),
                2,
            )
            .unwrap();
        assert_eq!(output, b"output");
    }
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

fn protected_custody_link(
    binding: &super::la_adapter::ChannelBinding,
    keys: &super::la_adapter::ChannelKeys,
    role: &str,
) -> std::result::Result<Arc<super::la_adapter::CustodyLink>, &'static str> {
    super::la_adapter::CustodyLink::new(
        binding.clone(),
        role,
        keys.reply,
        keys.custody,
        Box::new(|bytes| {
            use std::io::Write;
            let text = std::str::from_utf8(bytes).map_err(|_| "evidence_invalid")?;
            println!(
                "DIFFUSER_LA_CHILD_V1 {{\"kind\":\"CUSTODY_CHECKPOINT\",\"checkpoint\":{text}}}"
            );
            std::io::stdout().flush().map_err(|_| "control_invalid")
        }),
    )
}

// Protected control I/O is fixture plumbing. Verification and journal commits
// remain the ordinary authority methods; this bounded serial consumer prevents
// their operation locks from blocking delivery of a custody acknowledgment.
type ProtectedAuthorityResult = std::result::Result<(), &'static str>;
struct ProtectedAuthorityTask {
    sender: std::sync::mpsc::SyncSender<Vec<u8>>,
    thread: std::thread::JoinHandle<ProtectedAuthorityResult>,
}
fn protected_authority_task<F>(
    aborted: Arc<std::sync::atomic::AtomicBool>,
    mut apply: F,
) -> std::result::Result<ProtectedAuthorityTask, &'static str>
where
    F: FnMut(&[u8]) -> std::result::Result<super::la_adapter::SourceAck, &'static str>
        + Send
        + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(4);
    let thread = std::thread::Builder::new()
        .name("la-authority-source".into())
        .spawn(move || {
            use std::io::Write;
            let result = (|| {
                while let Ok(frame) = receiver.recv() {
                    if frame.len() > 12 * 1024 {
                        return Err("evidence_invalid");
                    }
                    let ack = match apply(&frame) {
                        Ok(a) => a,
                        Err(code) => {
                            println!(
                                "DIFFUSER_LA_CHILD_V1 {}",
                                serde_json::json!({"kind":"AUTHORITY_REFUSED","code":code})
                            );
                            std::io::stdout().flush().ok();
                            return Err(code);
                        }
                    };
                    println!(
                        "DIFFUSER_LA_CHILD_V1 {}",
                        serde_json::json!({"kind":"AUTHORITY_ACK","ack":ack})
                    );
                    std::io::stdout().flush().map_err(|_| "control_invalid")?;
                }
                Ok(())
            })();
            if result.is_err() {
                aborted.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            result
        })
        .map_err(|_| "startup_unavailable")?;
    Ok(ProtectedAuthorityTask { sender, thread })
}

struct ProtectedActivationTask {
    sender: std::sync::mpsc::SyncSender<Vec<u8>>,
    thread: std::thread::JoinHandle<std::result::Result<(), &'static str>>,
}
fn protected_activation_task<F>(
    aborted: Arc<std::sync::atomic::AtomicBool>,
    mut apply: F,
) -> std::result::Result<ProtectedActivationTask, &'static str>
where
    F: FnMut(&[u8]) -> std::result::Result<super::la_adapter::ActivationAck, &'static str>
        + Send
        + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let thread = std::thread::Builder::new()
        .name("la-protected-activation".into())
        .spawn(move || {
            use std::io::Write;
            let result = (|| {
                while let Ok(bytes) = receiver.recv() {
                    if bytes.len() > 12288 {
                        return Err("evidence_invalid");
                    }
                    let ack = apply(&bytes)?;
                    println!(
                        "DIFFUSER_LA_CHILD_V1 {}",
                        serde_json::json!({"kind":"ACTIVATION_ACK","ack":ack})
                    );
                    std::io::stdout().flush().map_err(|_| "control_invalid")?;
                }
                Ok(())
            })();
            if result.is_err() {
                aborted.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            result
        })
        .map_err(|_| "startup_unavailable")?;
    Ok(ProtectedActivationTask { sender, thread })
}

#[tokio::test]
async fn documented_namespace_requests_match_closed_routes_without_initialization() {
    use sha2::{Digest, Sha256};
    let document: Value =
        serde_json::from_str(include_str!("../../docs/cosp/lane-assignment.openapi.json")).unwrap();
    let schemas: Value =
        serde_json::from_str(include_str!("../../docs/cosp/lane-assignment.schema.json")).unwrap();
    let errors: Value =
        serde_json::from_str(include_str!("../../docs/cosp/lane-assignment-errors.json")).unwrap();
    assert_eq!(document["paths"].as_object().unwrap().len(), 12);
    assert_eq!(document["components"]["schemas"], schemas["$defs"]);
    assert!(errors["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["code"] == "routing_closed" && v["http_status"] == 503));
    let acquire = serde_json::json!({"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":4000,"requested_tenure_ms":12000});
    let submit = serde_json::json!({"schema_version":"diffuser-lane/v1","client_job_id":"contract_client_job1","capability":"artifact.inspect.sha256/v1","profile_version":"1","input_artifact_ids":["artifact_input_001"],"parameters":{},"max_runtime_ms":4000,"disconnect_policy":"continue_until_job_deadline"});
    for (template, operations) in document["paths"].as_object().unwrap() {
        assert_eq!(operations.as_object().unwrap().len(), 1);
        let (method, operation) = operations.as_object().unwrap().iter().next().unwrap();
        let path = template
            .replace("{project}", "project_12345678")
            .replace("{artifact}", "artifact_0000001")
            .replace("{assignment}", "assignment_00001")
            .replace("{job}", "job_123456789012")
            .replace("{request}", "request_00000001");
        let root = std::env::temp_dir().join(format!("la-contract-{}", std::process::id()));
        assert!(!root.exists());
        let state = Spine {
            root: root.clone(),
            edge: false,
            worker_ports: [0, 0],
            admin: true,
            sequence: Arc::new(Mutex::new(0)),
        };
        let mut request = Request::builder()
            .method(method.to_ascii_uppercase().as_str())
            .uri(&path)
            .header("idempotency-key", "contract_mutation_01");
        let body = if method == "post" {
            if operation["requestBody"]["content"]
                .get("application/octet-stream")
                .is_some()
            {
                request = request
                    .header("content-type", "application/octet-stream")
                    .header("x-diffuser-schema", "diffuser-artifact/v1")
                    .header(
                        "x-content-sha256",
                        hex::encode(Sha256::digest(b"contract input")),
                    );
                b"contract input".to_vec()
            } else {
                request = request.header("content-type", "application/json");
                let reference = operation["requestBody"]["content"]["application/json"]["schema"]
                    ["$ref"]
                    .as_str()
                    .unwrap();
                let value = match reference.rsplit('/').next().unwrap() {
                    "Acquire" => acquire.clone(),
                    "Submit" => submit.clone(),
                    "Renew" => {
                        serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0,"requested_lease_ms":1000})
                    }
                    "Revision" => {
                        serde_json::json!({"schema_version":"diffuser-lane/v1","expected_revision":0})
                    }
                    _ => panic!("unknown documented request"),
                };
                serde_json::to_vec(&value).unwrap()
            }
        } else {
            Vec::new()
        };
        let response = api(state)
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"]["code"], "routing_closed", "{path}");
        assert!(!root.exists());
    }
    for guide in [
        include_str!("../../docs/cosp/skills/COMMON.md"),
        include_str!("../../docs/cosp/skills/CODEX.md"),
        include_str!("../../docs/cosp/skills/AGY.md"),
        include_str!("../../docs/cosp/skills/GROK.md"),
    ] {
        assert!(!guide.contains("Bearer "));
        assert!(!guide.contains("ssh "));
    }
}

struct ProtectedCleanupTask {
    sender: std::sync::mpsc::SyncSender<Vec<u8>>,
    thread: std::thread::JoinHandle<std::result::Result<(), &'static str>>,
}
fn protected_cleanup_task<F>(
    aborted: Arc<std::sync::atomic::AtomicBool>,
    mut apply: F,
) -> std::result::Result<ProtectedCleanupTask, &'static str>
where
    F: FnMut(&[u8]) -> std::result::Result<serde_json::Value, &'static str> + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let thread = std::thread::Builder::new()
        .name("la-protected-cleanup".into())
        .spawn(move || {
            use std::io::Write;
            let result = (|| {
                while let Ok(bytes) = receiver.recv() {
                    if bytes.len() > 12288 {
                        return Err("evidence_invalid");
                    }
                    let ack = apply(&bytes).inspect_err(|_| {
                        super::la_adapter::recovery_trace(
                            "cleanup_apply_refused",
                            serde_json::json!({"bytes":bytes.len()}),
                        )
                    })?;
                    println!(
                        "DIFFUSER_LA_CHILD_V1 {}",
                        serde_json::json!({"kind":"CLEANUP_ACK","ack":ack})
                    );
                    std::io::stdout().flush().map_err(|_| "control_invalid")?;
                }
                Ok(())
            })();
            if result.is_err() {
                aborted.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            result
        })
        .map_err(|_| "startup_unavailable")?;
    Ok(ProtectedCleanupTask { sender, thread })
}

struct ProtectedEpochTask {
    sender: std::sync::mpsc::SyncSender<Vec<u8>>,
    thread: std::thread::JoinHandle<std::result::Result<(), &'static str>>,
}
fn protected_epoch_task<F>(
    aborted: Arc<std::sync::atomic::AtomicBool>,
    apply: F,
) -> std::result::Result<ProtectedEpochTask, &'static str>
where
    F: FnMut(&[u8]) -> std::result::Result<serde_json::Value, &'static str> + Send + 'static,
{
    protected_epoch_task_bounded::<12288, F>(aborted, apply)
}

// Only the distinct typed admission install may use the remaining space in
// the ORIGINAL 16KiB control frame (nine-byte prefix plus newline). Every old
// epoch/return control keeps its original 12288-byte body refusal.
fn protected_loss_return_task<F>(
    aborted: Arc<std::sync::atomic::AtomicBool>,
    mut apply: F,
) -> std::result::Result<ProtectedEpochTask, &'static str>
where
    F: FnMut(&[u8]) -> std::result::Result<serde_json::Value, &'static str> + Send + 'static,
{
    protected_epoch_task_bounded::<{ 16 * 1024 - 11 }, _>(aborted, move |bytes| {
        if bytes.len() > 12288 {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct AdmissionFrame {
                kind: String,
                admission: super::la_adapter::LossReturnAdmission,
            }
            let frame: AdmissionFrame =
                serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
            if frame.kind != "diffuser-loss-return-admission-install/v1" {
                return Err("evidence_invalid");
            }
            // Parse the entire fixed type, then the existing real C consumer
            // independently authenticates MAC/root/current authority and time.
            let _ = frame.admission;
            super::la_adapter::recovery_trace(
                "loss_admission_typed_frame",
                serde_json::json!({"bytes":bytes.len(),"total_frame_bytes":bytes.len()+10,"original_frame_bound":16384}),
            );
        }
        apply(bytes)
    })
}

fn protected_epoch_task_bounded<const BODY_MAX: usize, F>(
    aborted: Arc<std::sync::atomic::AtomicBool>,
    mut apply: F,
) -> std::result::Result<ProtectedEpochTask, &'static str>
where
    F: FnMut(&[u8]) -> std::result::Result<serde_json::Value, &'static str> + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let thread = std::thread::Builder::new()
        .name("la-protected-epoch".into())
        .spawn(move || {
            use std::io::Write;
            let result = (|| {
                while let Ok(bytes) = receiver.recv() {
                    if bytes.len() > BODY_MAX {
                        super::la_adapter::recovery_trace("protected_epoch_actual_frame_limit",serde_json::json!({"bytes":bytes.len(),"body_max":BODY_MAX,"refused":true}));
                        return Err("evidence_invalid");
                    }
                    let ack = apply(&bytes)?;
                    println!(
                        "DIFFUSER_LA_CHILD_V1 {}",
                        serde_json::json!({"kind":"EPOCH_ACK","ack":ack})
                    );
                    std::io::stdout().flush().map_err(|_| "control_invalid")?;
                }
                Ok(())
            })();
            if result.is_err() {
                aborted.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            result
        })
        .map_err(|_| "startup_unavailable")?;
    Ok(ProtectedEpochTask { sender, thread })
}

fn assert_development_response(name: &str, value: &serde_json::Value) {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../../docs/cosp/lane-assignment.schema.json")).unwrap();
    let schema = serde_json::json!({"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":format!("#/$defs/{name}"),"$defs":document["$defs"]});
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        validator.is_valid(value),
        "{name} response violated documented shape: {value}"
    );
}

#[test]
fn work_entry_observer_failure_retains_marker_and_cannot_reenter() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let root = std::env::temp_dir().join(format!(
        "la-entry-observer-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let mut journal = super::la_worker::OperationJournal::bootstrap(
        &root.join("worker.sqlite"),
        "custody_entry_1234",
    )
    .unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let observed = seen.clone();
    journal
        .observe_work_entry(Arc::new(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            Err("control_closed")
        }))
        .unwrap();
    let input = b"real entry callback";
    let digest = hex::encode(Sha256::digest(input));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    assert_eq!(
        journal.inspect_once(
            "operation_entry12",
            "job_entry_123456",
            input,
            &digest,
            deadline,
            || false
        ),
        Err("control_closed")
    );
    assert_eq!(journal.start_count("operation_entry12").unwrap(), 1);
    assert_eq!(
        journal.inspect_once(
            "operation_entry12",
            "job_entry_123456",
            input,
            &digest,
            deadline,
            || false
        ),
        Err("execution_uncertain")
    );
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    drop(journal);
    std::fs::remove_dir_all(root).unwrap();
}

// Exact retained non-secret product bytes, exported only by independent P's
// read-only descriptors in this bounded fixture. Transport authentication keys
// and HTTP credential material are never stored in these selected tables.
fn loss_retained_tables(db: &rusqlite::Connection, tables: &[&str]) -> serde_json::Value {
    use rusqlite::types::ValueRef;
    let mut result = serde_json::Map::new();
    for name in tables {
        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [name],
                |r| r.get(0),
            )
            .unwrap();
        if !exists {
            continue;
        }
        let mut statement = db
            .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
            .unwrap();
        let columns = statement
            .column_names()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let count = columns.len();
        let mut rows = statement.query([]).unwrap();
        let mut values = vec![];
        while let Some(row) = rows.next().unwrap() {
            assert!(values.len() < 1025);
            values.push(
                (0..count)
                    .map(|i| match row.get_ref(i).unwrap() {
                        ValueRef::Null => serde_json::Value::Null,
                        ValueRef::Integer(n) => serde_json::json!({"integer":n}),
                        ValueRef::Real(n) => serde_json::json!({"real":n}),
                        ValueRef::Text(b) => serde_json::json!({"text_hex":hex::encode(b)}),
                        ValueRef::Blob(b) => serde_json::json!({"blob_hex":hex::encode(b)}),
                    })
                    .collect::<Vec<_>>(),
            );
        }
        result.insert(
            (*name).into(),
            serde_json::json!({"columns":columns,"rows":values}),
        );
    }
    serde_json::Value::Object(result)
}

#[test]
fn protected_epoch_legacy_bound_and_typed_admission_refusal_remain_closed() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let aborted = Arc::new(AtomicBool::new(false));
    let applied = Arc::new(AtomicBool::new(false));
    let observed = applied.clone();
    let task = protected_epoch_task(aborted.clone(), move |_| {
        observed.store(true, Ordering::SeqCst);
        Ok(serde_json::json!({}))
    })
    .unwrap();
    task.sender.send(vec![b'x'; 14459]).unwrap();
    drop(task.sender);
    assert_eq!(task.thread.join().unwrap(), Err("evidence_invalid"));
    assert!(aborted.load(Ordering::SeqCst));
    assert!(!applied.load(Ordering::SeqCst));
    let aborted = Arc::new(AtomicBool::new(false));
    let observed = applied.clone();
    let task = protected_loss_return_task(aborted.clone(), move |_| {
        observed.store(true, Ordering::SeqCst);
        Ok(serde_json::json!({}))
    })
    .unwrap();
    task.sender.send(vec![b'x'; 14459]).unwrap();
    drop(task.sender);
    assert_eq!(task.thread.join().unwrap(), Err("evidence_invalid"));
    assert!(aborted.load(Ordering::SeqCst));
    assert!(!applied.load(Ordering::SeqCst));
}

#[path = "lane_client_route_tests.rs"]
mod lane_client_route_tests;
