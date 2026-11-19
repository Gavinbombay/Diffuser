//! Ordinary functional test using the existing protected service and Family fixture.
use super::{
    fixture_http::{receipt_dir, start_http, typed_client},
    *,
};
use lane_router::lane_client as sdk;

#[tokio::test]
async fn typed_cpu_process_lifecycle() {
    let (mut f, listener) = start_http("normal").await;
    f.refresh(&[]);
    let client = typed_client(&f);
    let discovery = client.discover().await.unwrap();
    let lane = discovery
        .negotiate(
            "lane_cpu_inspect",
            sdk::INSPECT_CAPABILITY,
            sdk::INSPECT_PROFILE,
            sdk::INSPECT_REVISION,
        )
        .unwrap();
    println!(
        "CPU_DISCOVERY {}",
        json!({"lane":lane.lane_id,"profile":lane.profile_id,"capability":lane.capability,"accepting":lane.accepting,"reason":lane.reason})
    );
    let receipts = receipt_dir(&f, "cpu-sdk-receipts");
    let store = sdk::ReceiptStore::open(&receipts).unwrap();
    let id = |s| sdk::Id::new(s).unwrap();
    let upload = client
        .upload(
            &store,
            sdk::Attempt::Start(&id("cpu_product_upload")),
            BODY.into(),
        )
        .await
        .unwrap();
    let acquire = sdk::Acquire {
        schema_version: sdk::LaneSchema::V1,
        capability: lane.capability.clone(),
        lane_id: lane.lane_id.clone(),
        profile_id: lane.profile_id.clone(),
        resource_id: None,
        provider_id: None,
        requested_hardware_description: None,
        resources: sdk::Resources {
            cpu_millicores: 1000,
            ram_bytes: 16_777_216,
            storage_bytes: 2_097_152,
            gpu_domains: vec![],
        },
        queue_policy: sdk::QueuePolicy::Refuse,
        requested_lease_ms: 4000,
        requested_tenure_ms: 12000,
    };
    let assigned = client
        .acquire(
            &store,
            sdk::Attempt::Start(&id("cpu_product_acquire")),
            &acquire,
        )
        .await
        .unwrap();
    assert_eq!(assigned.state, sdk::AssignmentState::Assigned);
    let assignment = &assigned.assignment_id;
    let key = id("cpu_product_submit");
    let body = sdk::CpuSubmit::new(id("cpu_product_job01"), upload.object_id, 4000).unwrap();
    f.refresh(&[]);
    let accepted = client
        .submit_cpu(&store, sdk::Attempt::Start(&key), assignment, &body)
        .await
        .unwrap();
    let resumed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let read = client.resume_cpu_job(&store, &key).await.unwrap();
            if read.job.state == sdk::JobState::Succeeded {
                break read;
            }
            assert!(read.result.is_none());
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(resumed.job.job_id, accepted.job_id);
    let (artifact, report) = resumed.result.unwrap();
    let digest = sdk::Sha256Digest::of(&artifact.bytes);
    assert_eq!(artifact.metadata.sha256, digest);
    assert_eq!(report.sha256, sdk::Sha256Digest::of(BODY));
    assert_eq!(report.rounds, 3);
    let expected = (0..3).fold(b"abc".to_vec(), |last, _| Sha256::digest(last).to_vec());
    assert_eq!(report.output_sha256.as_str(), hex::encode(expected));
    let retry = client
        .submit_cpu(&store, sdk::Attempt::Retry(&key), assignment, &body)
        .await
        .unwrap();
    assert_eq!(retry.job_id, accepted.job_id);
    assert_eq!(worker_counts(&f.w_root), (1, 1, 0, 0));
    assert!(dead(f.h_pin.as_ref().unwrap()));
    exited(f.h_id.as_ref().unwrap().pid);
    f.refresh(&[]);
    let view = client.assignment(assignment).await.unwrap();
    let release = client
        .release(
            &store,
            sdk::Attempt::Start(&id("cpu_product_release")),
            assignment,
            &sdk::Revision {
                schema_version: sdk::LaneSchema::V1,
                expected_revision: view.revision,
            },
        )
        .await
        .unwrap();
    assert_eq!(release.state, sdk::AssignmentState::Draining);
    assert!(!release.released());
    let held_after_stop = f.counts();
    assert_eq!(held_after_stop, (1, 1, 1));
    assert!(f
        .claims
        .lock()
        .unwrap()
        .assignment_stop_recorded(assignment.as_str())
        .unwrap());
    let (certificate, commit, replay) = f.cleanup(assignment.as_str());
    assert_eq!(f.counts(), (0, 0, 0));
    // Let the old observation expire normally, and get a fresh witnessed
    // observation while the worker can still independently acknowledge it.
    let old_expiry = {
        let a = f.authority.read().unwrap();
        a.observed_at + a.freshness_ms
    };
    tokio::time::sleep(Duration::from_millis(
        old_expiry.saturating_sub(wall_now().unwrap()) + 1,
    ))
    .await;
    assert!(
        matches!(client.assignment(assignment).await, Err(sdk::Error::Public(error))
        if error.status == StatusCode::PRECONDITION_FAILED && error.code == sdk::PublicCode::EvidenceStale)
    );
    f.refresh(&[]);
    assert_eq!(
        client.assignment(assignment).await.unwrap().state,
        sdk::AssignmentState::Closed
    );
    f.shutdown();
    assert!(dead(&f.w_pin));
    drop((client, store));
    let client = typed_client(&f);
    let store = sdk::ReceiptStore::open(&receipts).unwrap();
    let after_exit = client.resume_cpu_job(&store, &key).await.unwrap();
    assert_eq!(after_exit.job, resumed.job);
    assert_eq!(
        after_exit.result.unwrap(),
        (artifact.clone(), report.clone())
    );
    let receipt = store.read(client.identity(), &key).unwrap();
    assert_eq!(receipt.http_status, Some(202));
    let returned = receipt.returned.unwrap();
    assert_eq!(
        returned.result_artifact_id.as_ref(),
        Some(&artifact.metadata.artifact_id)
    );
    listener.close().await;
    let mut disk = la_artifacts::ArtifactStore::open(&f.root.0.join("controller")).unwrap();
    let who = client.identity();
    let (manifest, bytes) = disk
        .read_manifest_and_content(
            who.tenant.as_str(),
            who.project.as_str(),
            who.actor.as_str(),
            artifact.metadata.artifact_id.as_str(),
            wall_now().unwrap(),
        )
        .unwrap();
    assert_eq!(bytes, artifact.bytes.as_ref());
    assert_eq!(manifest.digest, digest.as_str());
    assert_eq!(manifest.assignment.as_deref(), Some(assignment.as_str()));
    assert_eq!(manifest.job.as_deref(), Some(accepted.job_id.as_str()));
    if let Some(dir) = std::env::var_os("DIFFUSER_TYPED_PROOF_DIR") {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(PathBuf::from(dir).join("cpu-durable-artifact.json"))
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }
    write_evidence(
        "cpu-product",
        &json!({"fixture_authority":true,"source":f.binding.source_digest,"executable_sha256":f.binding.executable_digest,"worker":f.w_id,"helper":f.h_id,"worker_counts":worker_counts(&f.w_root),"assignment":assigned,"job":after_exit.job,"artifact":artifact.metadata.artifact_id,"bytes":manifest.bytes,"sha256":digest,"input_sha256":report.sha256,"compute_sha256":report.output_sha256,"sdk_receipt_returned":returned,"release":release,"held_after_stop":held_after_stop,"cleanup_certificate":certificate,"cleanup_commit":commit,"cleanup_replay":replay,"claims_quota_outbox":f.counts(),"old_observation_refused":true,"readback_source_sequence":f.sequence,"http_read_after_joined_worker_exit":true,"reopened_store_bytes_match":true}),
    );
}
