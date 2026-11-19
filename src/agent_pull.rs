//! Validation for agent pull requests, shared with the pull handler.
use serde_json::Value;
use std::sync::OnceLock;

/// Check a pushed Colab snapshot before granting a new lease. The caller passes
/// its clock and configured floor; missing or future data fails closed.
pub fn colab_refusal(card: &Value, now: u64, floor: f64) -> Option<&'static str> {
    let epoch = card["epoch"].as_u64();
    if card["card"] != "colab-l4"
        || card["worker_id"] != "colab-l4"
        || card["stale"] != false
        || !epoch.is_some_and(|e| e <= now && now - e <= 180)
    {
        return Some(crate::error_catalog::reason(
            crate::error_catalog::STALE_STATE,
        ));
    }
    if card["seat"]["held"] != false {
        return Some(crate::error_catalog::reason(
            crate::error_catalog::SEAT_HELD,
        ));
    }
    if card["session"]["state"] != "none" || card["busy"]["by"] != "none" {
        return Some(crate::error_catalog::reason(
            crate::error_catalog::SESSION_LIVE,
        ));
    }
    if !floor.is_finite()
        || floor < 0.0
        || !card["cu"]["balance"]
            .as_f64()
            .is_some_and(|v| v.is_finite() && v > floor + 0.10)
    {
        return Some(crate::error_catalog::reason(crate::error_catalog::CU_FLOOR));
    }
    None
}

#[cfg(test)]
mod colab_gate_tests {
    use super::*;
    use serde_json::json;
    fn card() -> Value {
        json!({"card":"colab-l4","worker_id":"colab-l4","epoch":1000,"stale":false,"seat":{"held":false},"session":{"state":"none"},"busy":{"by":"none"},"cu":{"balance":6.0}})
    }
    #[test]
    fn fresh_available_card_passes() {
        assert_eq!(colab_refusal(&card(), 1180, 5.0), None);
    }
    #[test]
    fn stale_future_or_missing_state_refused() {
        assert_eq!(
            colab_refusal(&card(), 1181, 5.0),
            Some(crate::error_catalog::STALE_STATE)
        );
        assert_eq!(
            colab_refusal(&card(), 999, 5.0),
            Some(crate::error_catalog::STALE_STATE)
        );
        assert_eq!(
            colab_refusal(&json!({}), 1000, 5.0),
            Some(crate::error_catalog::STALE_STATE)
        );
    }
    #[test]
    fn occupied_card_refused() {
        let mut c = card();
        c["seat"]["held"] = json!(true);
        assert_eq!(
            colab_refusal(&c, 1000, 5.0),
            Some(crate::error_catalog::SEAT_HELD)
        );
        c = card();
        c["session"]["state"] = json!("running");
        assert_eq!(
            colab_refusal(&c, 1000, 5.0),
            Some(crate::error_catalog::SESSION_LIVE)
        );
        c = card();
        c["busy"]["by"] = json!("colab-job");
        assert_eq!(
            colab_refusal(&c, 1000, 5.0),
            Some(crate::error_catalog::SESSION_LIVE)
        );
    }
    #[test]
    fn boundary_and_unknown_balance_refused() {
        let mut c = card();
        c["cu"]["balance"] = json!(5.1);
        assert_eq!(
            colab_refusal(&c, 1000, 5.0),
            Some(crate::error_catalog::CU_FLOOR)
        );
        c["cu"]["balance"] = json!("unknown");
        assert_eq!(
            colab_refusal(&c, 1000, 5.0),
            Some(crate::error_catalog::CU_FLOOR)
        );
    }
}

/// Validate the complete request, including an optional segment report.
pub fn valid_request(request: &Value) -> bool {
    if !crate::schema_wire::agent_pull(request) {
        return false;
    }
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(include_str!("agent-pull.schema.json"))
                .expect("embedded pull schema");
            jsonschema::validator_for(&schema).expect("valid pull schema")
        })
        .is_valid(request)
}

/// Validate a pull before checking every offered lane with the existing auth path.
/// The caller must not process reports or claim work unless this succeeds.
pub fn authorize_request<E>(
    request: &Value,
    mut authorize: impl FnMut(&str) -> Result<(), E>,
) -> Result<(), PullAuthorization<E>> {
    if !valid_request(request) {
        return Err(PullAuthorization::InvalidRequest);
    }
    for lane in request["lanes"].as_array().expect("validated lanes") {
        authorize(lane.as_str().expect("validated lane")).map_err(PullAuthorization::Denied)?;
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum PullAuthorization<E> {
    InvalidRequest,
    Denied(E),
}

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use serde_json::json;
    fn request() -> Value {
        json!({"schema_version":"agent-pull/v1","agent_id":"agent-123","worker_id":"colab-l4","lanes":["tts","stt"],"wait_s":1,"state_epoch":100})
    }
    #[test]
    fn authorizes_every_offered_lane_in_order() {
        let mut seen = Vec::new();
        assert_eq!(
            authorize_request(&request(), |lane| {
                seen.push(lane.to_owned());
                Ok::<_, ()>(())
            }),
            Ok(())
        );
        assert_eq!(seen, ["tts", "stt"]);
    }
    #[test]
    fn denial_on_any_lane_refuses_the_whole_pull() {
        let mut seen = Vec::new();
        let result = authorize_request(&request(), |lane| {
            seen.push(lane.to_owned());
            if lane == "stt" {
                Err("denied")
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(PullAuthorization::Denied("denied")));
        assert_eq!(seen, ["tts", "stt"]);
    }
    #[test]
    fn malformed_request_never_calls_auth() {
        let mut called = false;
        let result = authorize_request(&json!({"lanes":["tts"]}), |_| {
            called = true;
            Ok::<_, ()>(())
        });
        assert_eq!(result, Err(PullAuthorization::InvalidRequest));
        assert!(!called);
    }
}

/// Form the response for an already-claimed lease. The caller supplies the
/// expiry from its clock and holds the job-table lock while taking this snapshot.
pub fn assigned_response(
    lease: &str,
    expires_at: &str,
    lifecycle: &crate::segment_lifecycle::Lifecycle,
    job: &Value,
) -> Option<Value> {
    if lifecycle.phase != crate::segment_lifecycle::Phase::Leased
        || lifecycle.lease_id.as_deref() != Some(lease)
    {
        return None;
    }
    Some(serde_json::json!({
        "schema_version": "agent-pull/v1", "status": "assigned", "lease_id": lease,
        "lease_expires_at": expires_at, "segment": lifecycle.segment,
        "resume_count": lifecycle.resume_count, "done_items": lifecycle.done_items, "job": job
    }))
}

/// No work is a successful pull response, not a server error.
pub fn empty_response(retry_after_s: u64) -> Value {
    serde_json::json!({"schema_version":"agent-pull/v1", "status":"empty", "retry_after_s":retry_after_s, "reason":"no-work"})
}

/// Poll a serialized pull transaction until it assigns work or the deadline
/// expires. A report is applied only on the first transaction, never replayed
/// by subsequent attempts. Each attempt must refresh its own boundary data.
pub async fn long_poll<E>(
    request: &Value,
    wait: std::time::Duration,
    interval: std::time::Duration,
    mut attempt: impl FnMut(&Value) -> Result<Option<Value>, E>,
) -> Result<Value, E> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut next = request.clone();
    loop {
        if let Some(response) = attempt(&next)? {
            return Ok(response);
        }
        if let Some(object) = next.as_object_mut() {
            object.remove("report");
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(empty_response(1));
        }
        tokio::time::sleep_until(std::cmp::min(deadline, now + interval)).await;
    }
}

#[cfg(test)]
mod long_poll_tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn report_is_processed_once_before_assignment() {
        let request = serde_json::json!({"report":{"lease_id":"lease-123"}});
        let mut calls = 0;
        let result = long_poll(
            &request,
            Duration::from_secs(1),
            Duration::from_millis(1),
            |pull| {
                calls += 1;
                assert_eq!(pull.get("report").is_some(), calls == 1);
                Ok::<_, ()>((calls == 2).then(|| serde_json::json!({"status":"assigned"})))
            },
        )
        .await
        .unwrap();
        assert_eq!(result["status"], "assigned");
        assert_eq!(calls, 2);
    }
    #[tokio::test]
    async fn empty_deadline_and_errors_return_without_replaying() {
        let request = serde_json::json!({"report":{}});
        let mut calls = 0;
        let result = long_poll(&request, Duration::ZERO, Duration::from_millis(1), |_| {
            calls += 1;
            Ok::<_, ()>(None)
        })
        .await
        .unwrap();
        assert_eq!(result["status"], "empty");
        assert_eq!(calls, 1);
        let result = long_poll(
            &request,
            Duration::from_secs(1),
            Duration::from_millis(1),
            |_| Err::<Option<Value>, _>(crate::error_catalog::INVALID_REPORT),
        )
        .await;
        assert_eq!(result, Err(crate::error_catalog::INVALID_REPORT));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn request() -> Value {
        json!({"schema_version":"agent-pull/v1", "agent_id":"agent-123", "worker_id":"colab-l4", "lanes":["tts"], "wait_s":55, "state_epoch":100})
    }
    #[test]
    fn accepts_first_pull_and_optional_class() {
        let mut v = request();
        assert!(valid_request(&v));
        v["gpu_class"] = json!("l4");
        assert!(valid_request(&v));
    }
    #[test]
    fn accepts_segment_report() {
        let mut v = request();
        v["report"] = json!({"lease_id":"lease-123", "job_id":"job-123", "segment":0, "exit_code":75, "session_lost":true, "done_items":["one"]});
        assert!(valid_request(&v));
    }
    #[test]
    fn rejects_bad_agent_or_worker() {
        let mut v = request();
        v["agent_id"] = json!("A");
        assert!(!valid_request(&v));
        v = request();
        v["worker_id"] = json!("other");
        assert!(!valid_request(&v));
    }
    #[test]
    fn rejects_invalid_wait_and_lanes() {
        let mut v = request();
        v["wait_s"] = json!(0);
        assert!(!valid_request(&v));
        v["wait_s"] = json!(61);
        assert!(!valid_request(&v));
        v = request();
        v["lanes"] = json!(["tts", "tts"]);
        assert!(!valid_request(&v));
        v["lanes"] = json!(["unknown"]);
        assert!(!valid_request(&v));
    }
    #[test]
    fn rejects_bad_report_and_extra_fields() {
        let mut v = request();
        v["report"] = json!({"lease_id":"lease-123", "job_id":"job-123", "segment":0, "exit_code":2, "done_items":[]});
        assert!(!valid_request(&v));
        v = request();
        v["unexpected"] = json!(true);
        assert!(!valid_request(&v));
    }
}

/// Pick a compatible queued job in arrival order and claim it atomically.
/// The card snapshot must already have passed freshness and availability checks.
pub fn assign_compatible(
    manager: &crate::segment_lifecycle::LeaseManager,
    queue: &[String],
    jobs: &std::collections::HashMap<String, Value>,
    lanes: &[String],
    card: &Value,
    boundary: &crate::segment_lifecycle::Boundary<'_>,
    lease: &str,
) -> std::io::Result<Option<(String, crate::segment_lifecycle::Lifecycle)>> {
    let candidates: Vec<String> = queue
        .iter()
        .filter(|id| {
            let Some(row) = jobs.get(*id) else {
                return false;
            };
            let spec = &row["spec"];
            let Some(lane) = spec["lane"].as_str() else {
                return false;
            };
            let class = spec["gpu_class"].as_str().unwrap_or("any");
            let min_vram = spec["gpu_min_vram_gb"].as_f64().unwrap_or(0.0);
            lanes.iter().any(|v| v == lane)
                && (class == "any"
                    || card["gpu_class"]
                        .as_str()
                        .is_some_and(|v| v.eq_ignore_ascii_case(class)))
                && (min_vram <= 0.0 || card["vram_gb"].as_f64().is_some_and(|v| v >= min_vram))
        })
        .cloned()
        .collect();
    manager.assign_next(&candidates, boundary, lease)
}

/// Claim work and reflect lease and boundary decisions in the visible job rows.
/// The caller holds the job-table lock across this operation and report handling.
pub fn claim_queued(
    manager: &crate::segment_lifecycle::LeaseManager,
    queue: &[String],
    jobs: &mut std::collections::HashMap<String, Value>,
    lanes: &[String],
    card: &Value,
    boundary: &crate::segment_lifecycle::Boundary<'_>,
    lease: &str,
) -> std::io::Result<Option<(String, crate::segment_lifecycle::Lifecycle)>> {
    let assigned = assign_compatible(manager, queue, jobs, lanes, card, boundary, lease)?;
    for id in queue {
        if let (Some(row), Some(lifecycle)) = (jobs.get_mut(id), manager.snapshot(id)) {
            sync_lifecycle(row, &lifecycle);
        }
    }
    Ok(assigned)
}

pub(crate) fn sync_lifecycle(row: &mut Value, lifecycle: &crate::segment_lifecycle::Lifecycle) {
    row["state"] = serde_json::json!(match lifecycle.phase {
        crate::segment_lifecycle::Phase::Queued => "queued",
        crate::segment_lifecycle::Phase::Leased => "leased",
        crate::segment_lifecycle::Phase::Done => "done",
        crate::segment_lifecycle::Phase::Failed => "failed",
        crate::segment_lifecycle::Phase::FloorStopped => "floor-stopped",
    });
    row["segment"] = serde_json::json!(lifecycle.segment);
    row["resume_count"] = serde_json::json!(lifecycle.resume_count);
    row["done_items"] = serde_json::json!(lifecycle.done_items);
    row["reason"] = serde_json::json!(lifecycle.reason);
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use crate::segment_lifecycle::{Boundary, LeaseManager};
    use serde_json::json;
    use std::{collections::HashMap, path::PathBuf};
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pull-select-{}-{:?}",
            std::process::id(),
            (
                std::thread::current().id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        ))
    }
    fn boundary(root: &std::path::Path) -> Boundary<'_> {
        Boundary {
            root,
            ts: "2026-10-31T12:00:00Z",
            job_id: "unused",
            balance: 10.0,
            floor: 5.0,
            gpu_class: "l4",
        }
    }
    fn setup() -> (LeaseManager, Vec<String>, HashMap<String, Value>) {
        let manager = LeaseManager::default();
        let ids = vec!["job-one".to_string(), "job-two".to_string()];
        for id in &ids {
            assert!(manager.insert(id.clone(), 4, 10.0));
        }
        let jobs = HashMap::from([
            (
                ids[0].clone(),
                json!({"spec":{"lane":"stt","gpu_class":"g4","gpu_min_vram_gb":80}}),
            ),
            (
                ids[1].clone(),
                json!({"spec":{"lane":"tts","gpu_class":"l4","gpu_min_vram_gb":24}}),
            ),
        ]);
        (manager, ids, jobs)
    }
    #[test]
    fn selects_matching_lane_and_class_after_incompatible_job() {
        let (m, q, j) = setup();
        let root = root();
        let b = boundary(&root);
        assert_eq!(
            assign_compatible(
                &m,
                &q,
                &j,
                &["tts".into()],
                &json!({"gpu_class":"L4","vram_gb":24}),
                &b,
                "lease-1"
            )
            .unwrap()
            .unwrap()
            .0,
            "job-two"
        );
    }
    #[test]
    fn rejects_insufficient_vram() {
        let (m, q, j) = setup();
        let root = root();
        let b = boundary(&root);
        assert!(assign_compatible(
            &m,
            &q,
            &j,
            &["tts".into()],
            &json!({"gpu_class":"L4","vram_gb":23}),
            &b,
            "lease-1"
        )
        .unwrap()
        .is_none());
    }
    #[test]
    fn rejects_missing_class_and_vram() {
        let (m, q, j) = setup();
        let root = root();
        let b = boundary(&root);
        assert!(
            assign_compatible(&m, &q, &j, &["tts".into()], &json!({}), &b, "lease-1")
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn any_class_accepts_matching_lane() {
        let (m, q, mut j) = setup();
        j.get_mut("job-two").unwrap()["spec"]["gpu_class"] = json!("any");
        let root = root();
        let b = boundary(&root);
        assert!(assign_compatible(
            &m,
            &q,
            &j,
            &["tts".into()],
            &json!({"gpu_class":"G4","vram_gb":24}),
            &b,
            "lease-1"
        )
        .unwrap()
        .is_some());
    }
    #[test]
    fn second_claim_cannot_duplicate_a_lease() {
        let (m, q, j) = setup();
        let root = root();
        let b = boundary(&root);
        let card = json!({"gpu_class":"L4","vram_gb":24});
        assert!(
            assign_compatible(&m, &q, &j, &["tts".into()], &card, &b, "lease-1")
                .unwrap()
                .is_some()
        );
        assert!(
            assign_compatible(&m, &q, &j, &["tts".into()], &card, &b, "lease-2")
                .unwrap()
                .is_none()
        );
    }
}

/// Apply a validated pull report to the lease and its visible job record.
/// The caller serializes access to the job table and supplies fresh boundary data.
pub fn apply_report(
    manager: &crate::segment_lifecycle::LeaseManager,
    jobs: &mut std::collections::HashMap<String, Value>,
    request: &Value,
    boundary: &crate::segment_lifecycle::Boundary<'_>,
) -> std::io::Result<bool> {
    if !valid_request(request) {
        return Ok(false);
    }
    let Some(report) = request.get("report") else {
        return Ok(false);
    };
    let id = report["job_id"].as_str().unwrap();
    if id != boundary.job_id || !jobs.contains_key(id) {
        return Ok(false);
    }
    let items: Vec<String> = report["done_items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    if !manager.report(
        boundary,
        report["lease_id"].as_str().unwrap(),
        report["segment"].as_u64().unwrap(),
        report["exit_code"].as_i64().unwrap() as i32,
        report["session_lost"].as_bool().unwrap_or(false),
        &items,
    )? {
        return Ok(false);
    }
    let lifecycle = manager.snapshot(id).expect("reported lease exists");
    let row = jobs.get_mut(id).expect("job checked above");
    sync_lifecycle(row, &lifecycle);
    Ok(true)
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use crate::segment_lifecycle::{Boundary, LeaseManager};
    use serde_json::json;
    use std::{collections::HashMap, path::PathBuf};
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pull-report-{}-{:?}",
            std::process::id(),
            (
                std::thread::current().id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
        ))
    }
    fn boundary(root: &std::path::Path) -> Boundary<'_> {
        Boundary {
            root,
            ts: "2026-10-31T12:00:00Z",
            job_id: "job-123",
            balance: 9.0,
            floor: 5.0,
            gpu_class: "l4",
        }
    }
    fn setup(max: u64, root: &std::path::Path) -> (LeaseManager, HashMap<String, Value>) {
        let m = LeaseManager::default();
        m.insert("job-123".into(), max, 10.0);
        assert!(m.assign(&boundary(root), "lease-123".into()).unwrap());
        (
            m,
            HashMap::from([("job-123".into(), json!({"state":"leased"}))]),
        )
    }
    fn request(exit: i32, lost: bool) -> Value {
        json!({"schema_version":"agent-pull/v1","agent_id":"agent-123","worker_id":"colab-l4","lanes":["tts"],"wait_s":1,"state_epoch":100,"report":{"lease_id":"lease-123","job_id":"job-123","segment":0,"exit_code":exit,"session_lost":lost,"done_items":["one","one"]}})
    }
    #[test]
    fn success_updates_job_and_ledger() {
        let r = root();
        let (m, mut j) = setup(3, &r);
        assert!(apply_report(&m, &mut j, &request(0, false), &boundary(&r)).unwrap());
        assert_eq!(j["job-123"]["state"], "done");
        assert!(std::fs::read_to_string(r.join("job-123/cu.csv"))
            .unwrap()
            .contains("segment-end"));
    }
    #[test]
    fn exit_75_requeues_with_unique_done_items() {
        let r = root();
        let (m, mut j) = setup(3, &r);
        assert!(apply_report(&m, &mut j, &request(75, false), &boundary(&r)).unwrap());
        assert_eq!(j["job-123"]["state"], "queued");
        assert_eq!(j["job-123"]["resume_count"], 1);
        assert_eq!(j["job-123"]["done_items"], json!(["one"]));
    }
    #[test]
    fn lost_session_requeues_same_record() {
        let r = root();
        let (m, mut j) = setup(3, &r);
        assert!(apply_report(&m, &mut j, &request(1, true), &boundary(&r)).unwrap());
        assert_eq!(j.len(), 1);
        assert_eq!(j["job-123"]["segment"], 1);
    }
    #[test]
    fn segment_limit_sets_failure_reason() {
        let r = root();
        let (m, mut j) = setup(1, &r);
        assert!(apply_report(&m, &mut j, &request(75, false), &boundary(&r)).unwrap());
        assert_eq!(
            j["job-123"]["reason"],
            crate::error_catalog::MAX_SEGS_EXCEEDED
        );
    }
    #[test]
    fn invalid_and_duplicate_reports_do_not_mutate() {
        let r = root();
        let (m, mut j) = setup(3, &r);
        let mut bad = request(0, false);
        bad["report"]["lease_id"] = json!("wrong");
        assert!(!apply_report(&m, &mut j, &bad, &boundary(&r)).unwrap());
        assert!(apply_report(&m, &mut j, &request(0, false), &boundary(&r)).unwrap());
        let before = j.clone();
        assert!(!apply_report(&m, &mut j, &request(0, false), &boundary(&r)).unwrap());
        assert_eq!(j, before);
    }
}

#[cfg(test)]
mod queue_integration_tests {
    use super::*;
    use crate::segment_lifecycle::{Boundary, LeaseManager};
    use serde_json::json;
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    struct Queue {
        manager: LeaseManager,
        ids: Vec<String>,
        jobs: HashMap<String, Value>,
        root: PathBuf,
    }
    impl Queue {
        fn new(max: u64) -> Self {
            let root = std::env::temp_dir().join(format!(
                "pull-queue-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let manager = LeaseManager::default();
            assert!(manager.insert("job-123".into(), max, 10.0));
            Self {
                manager,
                ids: vec!["job-123".into()],
                jobs: HashMap::from([(
                    "job-123".into(),
                    json!({"state":"queued","spec":{"lane":"tts","gpu_class":"l4"}}),
                )]),
                root,
            }
        }
        fn claim(
            &mut self,
            lease: &str,
            balance: f64,
        ) -> Option<(String, crate::segment_lifecycle::Lifecycle)> {
            let b = Boundary {
                root: &self.root,
                ts: "2026-10-31T12:00:00Z",
                job_id: "job-123",
                balance,
                floor: 5.0,
                gpu_class: "l4",
            };
            claim_queued(
                &self.manager,
                &self.ids,
                &mut self.jobs,
                &["tts".into()],
                &json!({"gpu_class":"L4"}),
                &b,
                lease,
            )
            .unwrap()
        }
        fn report(&mut self, lease: &str, segment: u64, exit: i32, lost: bool) {
            let b = Boundary {
                root: &self.root,
                ts: "2026-10-31T12:00:01Z",
                job_id: "job-123",
                balance: 9.0,
                floor: 5.0,
                gpu_class: "l4",
            };
            let request = json!({"schema_version":"agent-pull/v1","agent_id":"agent-123","worker_id":"colab-l4","lanes":["tts"],"wait_s":1,"state_epoch":100,"report":{"lease_id":lease,"job_id":"job-123","segment":segment,"exit_code":exit,"session_lost":lost,"done_items":["one"]}});
            assert!(apply_report(&self.manager, &mut self.jobs, &request, &b).unwrap());
        }
    }
    #[test]
    fn claim_updates_visible_job() {
        let mut q = Queue::new(4);
        assert!(q.claim("lease-1", 9.0).is_some());
        assert_eq!(q.jobs["job-123"]["state"], "leased");
    }
    #[test]
    fn floor_at_boundary_visible_and_no_new_lease() {
        let mut q = Queue::new(4);
        q.claim("lease-1", 9.0).unwrap();
        q.report("lease-1", 0, 75, false);
        assert!(q.claim("lease-2", 5.1).is_none());
        assert_eq!(q.jobs["job-123"]["state"], "floor-stopped");
        assert_eq!(q.jobs["job-123"]["reason"], crate::error_catalog::CU_FLOOR);
    }
    #[test]
    fn three_resumes_keep_one_visible_job() {
        let mut q = Queue::new(4);
        for n in 0..4 {
            let lease = format!("lease-{n}");
            q.claim(&lease, 9.0).unwrap();
            q.report(&lease, n, if n == 3 { 0 } else { 75 }, false);
        }
        assert_eq!(q.jobs.len(), 1);
        assert_eq!(q.jobs["job-123"]["resume_count"], 3);
        assert_eq!(q.jobs["job-123"]["done_items"], json!(["one"]));
        assert_eq!(q.jobs["job-123"]["state"], "done");
    }
    #[test]
    fn lost_session_and_limit_are_visible() {
        let mut q = Queue::new(2);
        q.claim("lease-1", 9.0).unwrap();
        q.report("lease-1", 0, 1, true);
        let (id, lifecycle) = q.claim("lease-2", 9.0).unwrap();
        assert_eq!(id, "job-123");
        assert_eq!(lifecycle.done_items.len(), 1);
        q.report("lease-2", 1, 75, false);
        assert_eq!(
            q.jobs["job-123"]["reason"],
            crate::error_catalog::MAX_SEGS_EXCEEDED
        );
    }
    #[test]
    fn simultaneous_claims_have_one_winner() {
        let q = Arc::new(Mutex::new(Queue::new(4)));
        let threads: Vec<_> = (0..2)
            .map(|n| {
                let q = q.clone();
                std::thread::spawn(move || {
                    q.lock()
                        .unwrap()
                        .claim(&format!("lease-{n}"), 9.0)
                        .is_some()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use crate::segment_lifecycle::Lifecycle;
    use serde_json::json;

    #[test]
    fn assigned_response_carries_resume_and_original_job() {
        let mut state = Lifecycle::new(4);
        assert!(state.assign("lease-123".into(), 9.0, 5.0));
        assert!(state.report(
            "lease-123",
            0,
            75,
            false,
            &["item-1".into(), "item-1".into()]
        ));
        assert!(state.assign("lease-456".into(), 9.0, 5.0));
        let job = json!({"job_id":"job-123", "lane":"tts"});
        let response =
            assigned_response("lease-456", "2026-10-31T12:52:40Z", &state, &job).unwrap();
        assert_eq!(
            response,
            json!({"schema_version":"agent-pull/v1", "status":"assigned", "lease_id":"lease-456", "lease_expires_at":"2026-10-31T12:52:40Z", "segment":1, "resume_count":1, "done_items":["item-1"], "job":job})
        );
        assert!(assigned_response("lease-123", "2026-10-31T12:52:40Z", &state, &job).is_none());
        assert!(state.report("lease-456", 1, 0, false, &[]));
        assert!(assigned_response("lease-456", "2026-10-31T12:52:40Z", &state, &job).is_none());
    }

    #[test]
    fn empty_response_is_contract_shaped() {
        assert_eq!(
            empty_response(2),
            json!({"schema_version":"agent-pull/v1", "status":"empty", "retry_after_s":2, "reason":"no-work"})
        );
    }
}

#[cfg(test)]
mod run35_u1 {
    use super::*;
    use crate::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn run35_u1_refusals_table() {
        let schema: Value = serde_json::from_str(include_str!("agent-pull.schema.json")).unwrap();
        let sample = schema["examples"][0].clone();
        let mut rows = Vec::new();
        for (field, value) in [
            ("agent_id", json!("unknown!")),
            ("agent_id", json!("a".repeat(65))),
            ("worker_id", json!("unknown")),
            ("lanes", json!(["unknown"])),
            ("lanes", json!([])),
            ("lanes", json!(["tts", "tts"])),
            ("wait_s", json!(0)),
            ("wait_s", json!(61)),
            ("state_epoch", json!(-1)),
            ("report", json!({})),
            ("unexpected", json!(true)),
        ] {
            let mut request = sample.clone();
            request[field] = value;
            assert!(!valid_request(&request), "{field}: {request}");
            let mut called = false;
            assert_eq!(
                authorize_request(&request, |_| {
                    called = true;
                    Ok::<_, ()>(())
                }),
                Err(PullAuthorization::InvalidRequest)
            );
            assert!(!called);
            rows.push((
                request.to_string(),
                StatusCode::BAD_REQUEST,
                error_catalog::INVALID_REQUEST,
            ));
        }
        rows.push((
            String::new(),
            StatusCode::BAD_REQUEST,
            error_catalog::INVALID_REQUEST,
        ));
        rows.push((
            " ".repeat(dispatch_kinds::Config::default().body_max + 1),
            StatusCode::PAYLOAD_TOO_LARGE,
            error_catalog::REQUEST_TOO_LARGE,
        ));
        assert!(rows.len() >= 6);
        let app = new_app(
            json!({}),
            std::env::temp_dir().join("run35-unused-pull-store"),
        );
        app.st
            .lock()
            .unwrap()
            .enqueue_agent(json!({"job_id":"job-123","lane":"tts","max_segs":2}), 9.0);
        let shared = app.st.clone();
        let snapshot = || {
            let table = shared.lock().unwrap();
            json!([
                table.jobs,
                table.agent_queue,
                table.agent_owners,
                table.busy,
                table.pids,
                table.cancel,
                table.queue_last,
                table.leases.snapshot("job-123")
            ])
        };
        let before = snapshot();
        let cards = app.cards.clone();
        let router = router_with_app(app);
        for (body, status, code) in rows {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/v1/agent/pull")
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            let body: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            let entry = error_catalog::refusal_entry(
                Some(status.as_u16()),
                body["error"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(entry.code, code);
            assert_eq!(snapshot(), before);
            assert!(cards.lock().unwrap().is_empty());
        }
        let card = json!({"card":"colab-l4","worker_id":"colab-l4","epoch":1000,"stale":false,"seat":{"held":false},"session":{"state":"none"},"busy":{"by":"none"},"cu":{"balance":6.0}});
        assert_eq!(colab_refusal(&card, 1000, 5.0), None);
        for (pointer, value, now, floor, code) in [
            (
                "/card",
                json!("unknown"),
                1000,
                5.0,
                error_catalog::STALE_STATE,
            ),
            (
                "/worker_id",
                json!("unknown"),
                1000,
                5.0,
                error_catalog::STALE_STATE,
            ),
            ("/stale", json!(true), 1000, 5.0, error_catalog::STALE_STATE),
            ("/epoch", Value::Null, 1000, 5.0, error_catalog::STALE_STATE),
            ("/epoch", json!(1001), 1000, 5.0, error_catalog::STALE_STATE),
            ("/epoch", json!(819), 1000, 5.0, error_catalog::STALE_STATE),
            (
                "/seat/held",
                json!(true),
                1000,
                5.0,
                error_catalog::SEAT_HELD,
            ),
            (
                "/session/state",
                json!("running"),
                1000,
                5.0,
                error_catalog::SESSION_LIVE,
            ),
            (
                "/busy/by",
                json!("job-123"),
                1000,
                5.0,
                error_catalog::SESSION_LIVE,
            ),
            (
                "/cu/balance",
                json!(5.1),
                1000,
                5.0,
                error_catalog::CU_FLOOR,
            ),
            (
                "/cu/balance",
                Value::Null,
                1000,
                5.0,
                error_catalog::CU_FLOOR,
            ),
            (
                "/cu/balance",
                json!(6.0),
                1000,
                f64::NAN,
                error_catalog::CU_FLOOR,
            ),
            (
                "/cu/balance",
                json!(6.0),
                1000,
                -1.0,
                error_catalog::CU_FLOOR,
            ),
        ] {
            let mut input = card.clone();
            *input.pointer_mut(pointer).unwrap() = value;
            let before = input.clone();
            assert_eq!(colab_refusal(&input, now, floor), Some(code), "{pointer}");
            let entry = error_catalog::lookup(None, code).unwrap();
            assert_eq!((entry.status, entry.code), (None, code));
            assert_eq!(input, before);
        }
    }

    #[test]
    fn run35_u1_schema_examples_round_trip() {
        let schema: Value = serde_json::from_str(include_str!("agent-pull.schema.json")).unwrap();
        let examples = schema["examples"]
            .as_array()
            .expect("nonempty schema examples");
        assert!(examples.len() >= 2);
        for sample in examples {
            assert!(valid_request(sample));
            let wire: crate::schema_wire::AgentPull =
                serde_json::from_value(sample.clone()).unwrap();
            let bytes = serde_json::to_vec(&wire).unwrap();
            let restored: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(&restored, sample);
            assert!(valid_request(&restored));
        }
    }
}
