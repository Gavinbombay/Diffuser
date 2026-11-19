//! State edges, attempt settlement and absolute deadlines over shared job rows.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub src: &'static str,
    pub dst: &'static str,
    pub trigger: &'static str,
    pub rc: Option<i64>,
    pub cite: &'static str,
}
macro_rules! edge {
    ($s:literal,$d:literal,$t:expr,$r:expr) => {
        Edge {
            src: $s,
            dst: $d,
            trigger: $t,
            rc: $r,
            cite: "A/glm-lanes-router-s02-deadline-ref-20261031/out/s02/states.py:101",
        }
    };
}
pub const EDGES: &[Edge] = &[
    edge!("queued", "dispatching", "seat-assigned", None),
    edge!("dispatching", "running", "worker-accepted", None),
    edge!("dispatching", "failed", "plan-error", None),
    edge!("dispatching", "failed", "attempt-failed", Some(1)),
    edge!(
        "dispatching",
        "refused",
        crate::error_catalog::WORKER_REFUSED,
        Some(2)
    ),
    edge!(
        "running",
        "refused",
        crate::error_catalog::WORKER_REFUSED,
        Some(2)
    ),
    edge!("running", "merging", "merge-start", Some(0)),
    edge!("merging", "done", "merge-ok", Some(0)),
    edge!("merging", "failed", "merge-error", None),
    edge!("running", "failed", "attempt-failed", Some(1)),
    edge!("running", "dispatching", "retry-elsewhere", Some(1)),
    edge!("running", "timed_out", "attempt-timeout", Some(124)),
    edge!("queued", "cancelled", "cancel-queued", None),
    edge!("dispatching", "cancelling", "cancel-requested", None),
    edge!("running", "cancelling", "cancel-requested", None),
    edge!("merging", "cancelling", "cancel-requested", None),
    edge!("cancelling", "cancelled", "cancel-observed", None),
    edge!("queued", "timed_out", "deadline", Some(124)),
    edge!("dispatching", "timed_out", "deadline", Some(124)),
    edge!("running", "timed_out", "deadline", Some(124)),
    edge!("merging", "timed_out", "deadline", Some(124)),
    edge!("cancelling", "timed_out", "deadline", Some(124)),
];
pub const STATES: &[&str] = &[
    "queued",
    "dispatching",
    "running",
    "merging",
    "cancelling",
    "done",
    "failed",
    "cancelled",
    "timed_out",
    "refused",
];
#[derive(Debug)]
pub struct Config {
    pub timeout_min: u64,
    pub attempt_max: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_min: 45,
            attempt_max: 2,
        }
    }
}
pub fn absolute(created: u64, minutes: u64) -> u64 {
    created.saturating_add(minutes.saturating_mul(60))
}
pub fn fingerprint(spec: &Value) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(spec).expect("JSON value"),
    ))
}
fn require(row: &Value, dst: &str, trigger: &str) -> Result<(), &'static str> {
    if crate::queue_policy::terminal(row) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::JOB_FROZEN,
        ));
    }
    if !STATES.contains(&dst)
        || !EDGES.iter().any(|e| {
            e.src == row["state"].as_str().unwrap_or("")
                && e.dst == dst
                && e.trigger == trigger
                && !e.cite.is_empty()
        })
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ILLEGAL_TRANSITION,
        ));
    }
    Ok(())
}
pub fn transition(row: &mut Value, dst: &str, trigger: &str, now: u64) -> Result<(), &'static str> {
    require(row, dst, trigger)?;
    let from = row["state"].clone();
    row["state"] = json!(dst);
    row["queue_reason"] = if dst == "queued" {
        json!("awaiting-seat")
    } else {
        Value::Null
    };
    if !row["journal"].is_array() {
        row["journal"] = json!([]);
    }
    row["journal"]
        .as_array_mut()
        .unwrap()
        .push(json!({"at":now,"src":from,"dst":dst,"trigger":trigger}));
    Ok(())
}
fn attempt(
    number: usize,
    worker: &str,
    state: &str,
    rc: Option<i64>,
    reason: Option<&str>,
) -> Value {
    json!({"number":number,"worker":worker,"state":state,"rc":rc,"reason":reason,"device_log":format!("attempts/{number}/device.json")})
}
fn event(row: &mut Value, state: &str, rc: Option<i64>, reason: Option<&str>, now: u64) {
    let number = row["attempts"].as_array().unwrap().len();
    if !row["device_events"].is_object() {
        row["device_events"] = json!({});
    }
    let field = number.to_string();
    if !row["device_events"][&field].is_array() {
        row["device_events"][&field] = json!([]);
    }
    row["device_events"][&field]
        .as_array_mut()
        .unwrap()
        .push(crate::log_redaction::document(
            &json!({"at":now,"state":state,"rc":rc,"reason":reason}),
        ));
}
pub fn dispatch(row: &mut Value, worker: &str, now: u64) -> Result<(), &'static str> {
    let count = row["attempts"].as_array().map_or(0, Vec::len);
    if count >= Config::default().attempt_max {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ILLEGAL_TRANSITION,
        ));
    }
    require(
        row,
        "dispatching",
        if row["state"] == "queued" {
            "seat-assigned"
        } else {
            "retry-elsewhere"
        },
    )?;
    let trigger = if row["state"] == "queued" {
        "seat-assigned"
    } else {
        "retry-elsewhere"
    };
    transition(row, "dispatching", trigger, now)?;
    if !row["attempts"].is_array() {
        row["attempts"] = json!([]);
    }
    row["attempts"].as_array_mut().unwrap().push(attempt(
        count + 1,
        worker,
        "dispatching",
        None,
        None,
    ));
    row["worker"] = json!(worker);
    event(row, "dispatching", None, None, now);
    Ok(())
}
pub fn accept(row: &mut Value, now: u64) -> Result<(), &'static str> {
    require(row, "running", "worker-accepted")?;
    if row["attempts"]
        .as_array()
        .and_then(|a| a.last())
        .is_none_or(|a| a["state"] != "dispatching" || !a["rc"].is_null())
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ILLEGAL_TRANSITION,
        ));
    }
    transition(row, "running", "worker-accepted", now)?;
    row["attempts"].as_array_mut().unwrap().last_mut().unwrap()["state"] = json!("running");
    event(row, "running", None, None, now);
    Ok(())
}
fn settle_attempt(row: &mut Value, state: &str, rc: i64, reason: Option<&str>, now: u64) {
    if let Some(a) = row["attempts"].as_array_mut().and_then(|a| a.last_mut()) {
        a["state"] = json!(state);
        a["rc"] = json!(rc);
        a["reason"] = json!(reason);
        event(row, state, Some(rc), reason, now);
    }
}
pub fn expire(row: &mut Value, now: u64) -> bool {
    if crate::queue_policy::terminal(row)
        || !row["deadline_epoch"].as_u64().is_some_and(|at| at <= now)
    {
        return false;
    }
    let len = row["attempts"].as_array().map_or(0, Vec::len);
    let open = row["attempts"]
        .as_array()
        .and_then(|a| a.last())
        .is_some_and(|a| matches!(a["state"].as_str(), Some("dispatching" | "running")));
    if open && row["active_children"].as_u64().unwrap_or(0) == 0 {
        settle_attempt(
            row,
            "timed_out",
            124,
            Some(crate::error_catalog::DEADLINE_EXCEEDED),
            now,
        );
    } else if !open && len < Config::default().attempt_max {
        let worker = row["worker"].as_str().unwrap_or("router").to_owned();
        if !row["attempts"].is_array() {
            row["attempts"] = json!([]);
        }
        row["attempts"].as_array_mut().unwrap().push(attempt(
            len + 1,
            &worker,
            "timed_out",
            Some(124),
            Some(crate::error_catalog::DEADLINE_EXCEEDED),
        ));
        row["worker"] = json!(worker);
        event(
            row,
            "timed_out",
            Some(124),
            Some(crate::error_catalog::DEADLINE_EXCEEDED),
            now,
        );
    }
    transition(row, "timed_out", "deadline", now).expect("every live state has a deadline edge");
    row["error"] = json!({"code":crate::error_catalog::reason(crate::error_catalog::DEADLINE_EXCEEDED),"retryable":false});
    row["cleanup"] = json!("unresolved");
    row["artifacts"] = json!([]);
    row["manifest"] = Value::Null;
    true
}

/// Attach OS evidence only after wait has reaped the supervised child. Policy
/// return codes retain the existing 0/1/2/124 convention; raw_rc is the OS code.
pub fn reaped(row: &mut Value, raw_rc: i64, state: &str, now: u64) {
    if row["state"] == "timed_out" {
        settle_attempt(
            row,
            "timed_out",
            124,
            Some(crate::error_catalog::DEADLINE_EXCEEDED),
            now,
        );
    } else if row["state"] == "cancelling" || state == "cancelled" {
        settle_attempt(row, "cancelled", raw_rc, None, now);
        let _ = settle_cancel(row, now);
    }
    if let Some(attempt) = row["attempts"].as_array_mut().and_then(|a| a.last_mut()) {
        attempt["raw_rc"] = json!(raw_rc);
        attempt["reaped"] = json!(true);
    }
}
pub fn process(jobs: &mut HashMap<String, Value>, now: u64) -> Vec<String> {
    let mut due: Vec<_> = jobs
        .iter()
        .filter(|(_, r)| {
            !crate::queue_policy::terminal(r)
                && r["deadline_epoch"].as_u64().is_some_and(|at| at <= now)
        })
        .map(|(id, r)| (r["position"].as_u64().unwrap_or(0), id.clone()))
        .collect();
    due.sort();
    for (_, id) in &due {
        expire(jobs.get_mut(id).unwrap(), now);
    }
    due.into_iter().map(|(_, id)| id).collect()
}
pub fn report(row: &mut Value, rc: i64, other: Option<&str>, now: u64) -> Result<(), &'static str> {
    if ![0, 1, 2, 124].contains(&rc) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if row["attempts"]
        .as_array()
        .and_then(|a| a.last())
        .is_none_or(|a| !matches!(a["state"].as_str(), Some("dispatching" | "running")))
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ILLEGAL_TRANSITION,
        ));
    }
    if expire(row, now) {
        return Ok(());
    }
    if row["state"] == "cancelling" {
        settle_attempt(row, "cancelled", rc, None, now);
        return Ok(());
    }
    let count = row["attempts"].as_array().unwrap().len();
    let retry = rc == 1
        && row["state"] == "running"
        && count < Config::default().attempt_max
        && other.is_some_and(|w| row["worker"] != w);
    let (dst, trigger, state, reason) = match rc {
        0 => ("merging", "merge-start", "done", None),
        2 => (
            "refused",
            crate::error_catalog::WORKER_REFUSED,
            "refused",
            Some(crate::error_catalog::WORKER_REFUSED),
        ),
        124 => (
            "timed_out",
            "attempt-timeout",
            "timed_out",
            Some(crate::error_catalog::DEADLINE_EXCEEDED),
        ),
        _ if retry => ("dispatching", "retry-elsewhere", "failed", None),
        _ => (
            "failed",
            "attempt-failed",
            "failed",
            Some(if count >= 2 {
                crate::error_catalog::RETRY_EXHAUSTED
            } else {
                crate::error_catalog::NO_WORKER
            }),
        ),
    };
    require(row, dst, trigger)?;
    if EDGES
        .iter()
        .find(|e| {
            e.src == row["state"].as_str().unwrap_or("") && e.dst == dst && e.trigger == trigger
        })
        .and_then(|e| e.rc)
        .is_some_and(|expected| expected != rc)
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    // Validate the complete route before mutating an attempt.
    settle_attempt(row, state, rc, reason, now);
    if retry {
        dispatch(row, other.unwrap(), now)?;
    } else {
        transition(row, dst, trigger, now)?;
        if dst != "merging" {
            row["error"] =
                json!({"code":crate::error_catalog::reason(reason.unwrap()),"retryable":false});
            row["cleanup"] = json!("unresolved");
        }
    }
    Ok(())
}
pub fn cancel(row: &mut Value, now: u64) -> Result<bool, &'static str> {
    if expire(row, now) || crate::queue_policy::terminal(row) || row["state"] == "cancelling" {
        return Ok(false);
    }
    let queued = row["state"] == "queued";
    transition(
        row,
        if queued { "cancelled" } else { "cancelling" },
        if queued {
            "cancel-queued"
        } else {
            "cancel-requested"
        },
        now,
    )?;
    row["cancel_requested"] = json!(true);
    if queued {
        row["cleanup"] = json!(
            crate::artifact_routes::cleanup_event("pending", "job-cancelled")
                .expect("cancel cleanup transition")
        );
    }
    Ok(true)
}
pub fn settle_cancel(row: &mut Value, now: u64) -> Result<(), &'static str> {
    if expire(row, now) {
        return Ok(());
    }
    transition(row, "cancelled", "cancel-observed", now)?;
    row["cleanup"] = json!(
        crate::artifact_routes::cleanup_event("pending", "job-cancelled")
            .expect("cancel cleanup transition")
    );
    Ok(())
}
pub fn merge(row: &mut Value, ok: bool, now: u64) -> Result<(), &'static str> {
    if expire(row, now) {
        return Ok(());
    }
    transition(
        row,
        if ok { "done" } else { "failed" },
        if ok { "merge-ok" } else { "merge-error" },
        now,
    )?;
    row["cleanup"] = json!(if ok { "clean" } else { "unresolved" });
    if !ok {
        row["error"] = json!({"code":crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH),"retryable":false});
    }
    Ok(())
}
pub fn write_devices(root: &Path, row: &Value) -> Result<(), &'static str> {
    let lane = crate::queue_policy::lane(row);
    let id = row["job_id"]
        .as_str()
        .filter(|s| crate::result_store::valid_id(s))
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::NO_SUCH_JOB))?;
    if !crate::LANES.contains(&lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    let guard = crate::result_store::Store::new(root, crate::result_store::Config::default());
    for a in row["attempts"].as_array().into_iter().flatten() {
        let n = a["number"]
            .as_u64()
            .filter(|n| (1..=2).contains(n))
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        let doc = json!({"api":crate::API,"lane":lane,"job_id":id,"attempt":n,"worker":a["worker"],"cartridge":row["cartridge"],"pin_sha256":row["cartridge_manifest_sha256"],"spec_sha256":row["spec_sha256"],"state":a["state"],"rc":a["rc"],"reason":a["reason"],"events":row["device_events"][n.to_string()],"observation":row["chunks"][0]["dispatch_observation"]});
        guard.write_device(lane, id, n, &doc)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{queue_policy as q, result_store as storage};
    pub(super) fn queued() -> Value {
        let mut r = q::admitted(
            &HashMap::new(),
            &json!({"job_id":"job-1","lane":"tts","timeout_min":1}),
            1000,
        );
        r["cartridge"] = json!("fixture");
        r["spec_sha256"] = json!(fingerprint(&json!({"text":"fixture"})));
        r["cartridge_manifest_sha256"] = json!(fingerprint(&json!({"pin":"fixture"})));
        r
    }
    pub(super) fn reach(state: &str) -> Value {
        let mut r = queued();
        match state {
            "queued" => {}
            "cancelled" => {
                cancel(&mut r, 1000).unwrap();
            }
            "timed_out" => {
                expire(&mut r, 1060);
            }
            _ => {
                dispatch(&mut r, "worker-a", 1000).unwrap();
                if state != "dispatching" {
                    accept(&mut r, 1000).unwrap();
                    match state {
                        "running" => {}
                        "cancelling" => {
                            cancel(&mut r, 1000).unwrap();
                        }
                        "merging" => {
                            report(&mut r, 0, None, 1000).unwrap();
                        }
                        "done" => {
                            report(&mut r, 0, None, 1000).unwrap();
                            merge(&mut r, true, 1000).unwrap();
                        }
                        "failed" => {
                            report(&mut r, 1, None, 1000).unwrap();
                        }
                        "refused" => {
                            report(&mut r, 2, None, 1000).unwrap();
                        }
                        _ => panic!("unknown fixture state"),
                    }
                }
            }
        }
        r
    }
    pub(super) fn temp() -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "deadline-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    fn expiry(state: &str) {
        let mut r = reach(state);
        assert!(!expire(&mut r, 1059));
        assert!(expire(&mut r, 1060));
        assert_eq!(r["state"], "timed_out");
        assert_eq!(r["attempts"].as_array().unwrap().last().unwrap()["rc"], 124);
        assert!(!expire(&mut r, 1060));
    }
    fn store_state(state: &str) {
        let p = temp();
        let s = storage::Store::new(&p, storage::Config::default());
        let r = reach(state);
        let v = storage::snapshot(&r, 1000);
        s.put_job("tts", "job-1", &v, &std::collections::BTreeMap::new(), 1000)
            .unwrap();
        assert_eq!(s.get_job("tts", "job-1").unwrap(), v);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!((c.timeout_min, c.attempt_max), (45, 2));
    }
    #[test]
    fn test_deadline_is_absolute_and_computed_once() {
        for m in [1, 5, 45, 360] {
            assert_eq!(absolute(1000, m), 1000 + m * 60);
        }
        let mut r = queued();
        dispatch(&mut r, "worker-a", 1010).unwrap();
        assert_eq!(r["deadline_epoch"], 1060);
    }
    #[test]
    fn test_expiry_is_inclusive_at_the_exact_tick() {
        expiry("queued");
    }
    #[test]
    fn test_expiry_uses_the_injected_clock_only() {
        let mut a = queued();
        let mut b = queued();
        assert!(expire(&mut a, 1060));
        assert!(!expire(&mut b, 1059));
        assert!(expire(&mut b, 1060));
        assert_eq!(a, b);
    }
    #[test]
    fn test_queued_job_times_out() {
        expiry("queued");
    }
    #[test]
    fn test_dispatching_job_times_out() {
        expiry("dispatching");
    }
    #[test]
    fn test_running_job_times_out() {
        expiry("running");
    }
    #[test]
    fn test_merging_job_times_out() {
        expiry("merging");
    }
    #[test]
    fn test_cancelling_job_times_out() {
        let mut r = reach("cancelling");
        expire(&mut r, 1060);
        assert_eq!(r["state"], "timed_out");
        assert_eq!(r["cancel_requested"], true);
    }
    #[test]
    fn test_attempt_timeout_reports_the_same_state() {
        let mut r = reach("running");
        report(&mut r, 124, None, 1001).unwrap();
        assert_eq!(r["state"], "timed_out");
        assert_eq!(r["attempts"][0]["rc"], 124);
    }
    #[test]
    fn test_a_never_dispatched_job_gets_exactly_one_final_record() {
        let mut r = queued();
        expire(&mut r, 1060);
        assert_eq!(r["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(r["attempts"][0]["worker"], "router");
    }
    #[test]
    fn test_an_open_attempt_is_settled_not_duplicated() {
        let mut r = reach("running");
        expire(&mut r, 1060);
        assert_eq!(r["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(r["attempts"][0]["state"], "timed_out");
    }
    #[test]
    fn test_no_record_past_the_two_attempt_cap() {
        let mut r = reach("running");
        report(&mut r, 1, Some("worker-b"), 1000).unwrap();
        accept(&mut r, 1000).unwrap();
        report(&mut r, 1, None, 1000).unwrap();
        let before = r.clone();
        assert!(!expire(&mut r, 1060));
        assert_eq!(r, before);
        assert_eq!(r["attempts"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn live_cap_spent_deadline() {
        let mut r = reach("running");
        report(&mut r, 1, Some("worker-b"), 1000).unwrap();
        accept(&mut r, 1000).unwrap();
        expire(&mut r, 1060);
        assert_eq!(r["attempts"].as_array().unwrap().len(), 2);
        assert_eq!(r["attempts"][1]["rc"], 124);
        let mut m = reach("merging");
        m["attempts"] = r["attempts"].clone();
        assert!(expire(&mut m, 1060));
        assert_eq!(m["attempts"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn test_error_and_cleanup_fields_on_expiry() {
        let mut r = queued();
        expire(&mut r, 1060);
        assert_eq!(
            r["error"],
            json!({"code":crate::error_catalog::DEADLINE_EXCEEDED,"retryable":false})
        );
        assert_eq!(r["cleanup"], "unresolved");
        assert_eq!(r["artifacts"], json!([]));
        assert!(r["manifest"].is_null());
        assert!(r["queue_reason"].is_null());
    }
    #[test]
    fn test_deadline_pass_is_idempotent() {
        let mut jobs = HashMap::from([("job-1".into(), queued())]);
        assert_eq!(process(&mut jobs, 1060), ["job-1"]);
        assert!(process(&mut jobs, 1060).is_empty());
    }
    #[test]
    fn test_expiry_frees_the_seat_for_the_next_job() {
        let mut jobs = HashMap::from([("job-1".into(), reach("running"))]);
        let mut r = queued();
        r["job_id"] = json!("job-2");
        r["deadline_epoch"] = json!(2000);
        jobs.insert("job-2".into(), r);
        assert!(q::next(&jobs, None, q::Config::default(), |_| true).is_none());
        process(&mut jobs, 1060);
        assert_eq!(
            q::next(&jobs, None, q::Config::default(), |_| true).as_deref(),
            Some("job-2")
        );
    }
    #[test]
    fn test_victims_are_reported_in_admission_order() {
        let mut jobs = HashMap::new();
        for (id, pos) in [("c", 2), ("a", 0), ("b", 1)] {
            let mut r = queued();
            r["position"] = json!(pos);
            jobs.insert(id.into(), r);
        }
        assert_eq!(process(&mut jobs, 1060), ["a", "b", "c"]);
    }
    #[test]
    fn test_no_terminal_state_is_ever_revisited() {
        for state in ["done", "failed", "cancelled", "timed_out", "refused"] {
            let mut r = reach(state);
            let before = r.clone();
            assert!(!expire(&mut r, u64::MAX));
            assert_eq!(r, before);
        }
    }
    #[test]
    fn test_the_store_freezes_terminal_documents_too() {
        let p = temp();
        let s = storage::Store::new(&p, storage::Config::default());
        let v = storage::snapshot(&reach("timed_out"), 1000);
        s.put_job("tts", "job-1", &v, &std::collections::BTreeMap::new(), 1000)
            .unwrap();
        let mut changed = v.clone();
        changed["cleanup"] = json!("clean");
        assert_eq!(
            s.put_job(
                "tts",
                "job-1",
                &changed,
                &std::collections::BTreeMap::new(),
                1000
            ),
            Err(crate::error_catalog::JOB_FROZEN)
        );
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn test_first_attempt_record_is_exactly_the_six_fields() {
        let r = reach("dispatching");
        let a = r["attempts"][0].as_object().unwrap();
        assert_eq!(
            a.keys().map(String::as_str).collect::<Vec<_>>(),
            ["device_log", "number", "rc", "reason", "state", "worker"]
        );
        assert_eq!(a["number"], 1);
        assert_eq!(a["state"], "dispatching");
        assert!(a["rc"].is_null());
    }
    #[test]
    fn test_attempt_numbers_are_sequential_and_capped() {
        let mut r = reach("running");
        report(&mut r, 1, Some("worker-b"), 1000).unwrap();
        accept(&mut r, 1000).unwrap();
        report(&mut r, 1, None, 1000).unwrap();
        assert_eq!(r["attempts"][0]["number"], 1);
        assert_eq!(r["attempts"][1]["number"], 2);
        assert!(dispatch(&mut r, "worker-c", 1000).is_err());
    }
    #[test]
    fn test_rc_conventions() {
        for (rc, want) in [
            (0, "done"),
            (1, "failed"),
            (2, "refused"),
            (124, "timed_out"),
        ] {
            let mut r = reach("running");
            report(&mut r, rc, None, 1000).unwrap();
            assert_eq!(r["attempts"][0]["state"], want);
            assert_eq!(r["attempts"][0]["rc"], rc);
        }
    }
    #[test]
    fn test_report_refuses_an_rc_outside_the_conventions() {
        for rc in [3, -1] {
            let mut r = reach("running");
            let before = r.clone();
            assert_eq!(
                report(&mut r, rc, None, 1000),
                Err(crate::error_catalog::BAD_SPEC)
            );
            assert_eq!(r, before);
        }
    }
    #[test]
    fn test_report_refuses_when_no_attempt_is_open() {
        let mut r = reach("refused");
        let before = r.clone();
        assert_eq!(
            report(&mut r, 0, None, 1000),
            Err(crate::error_catalog::ILLEGAL_TRANSITION)
        );
        assert_eq!(r, before);
    }
    fn device_logs(second: bool) {
        let p = temp();
        let mut r = reach("running");
        if second {
            report(&mut r, 1, Some("worker-b"), 1000).unwrap();
            accept(&mut r, 1001).unwrap();
        }
        report(&mut r, 0, None, 1002).unwrap();
        write_devices(&p, &r).unwrap();
        let n = if second { 2 } else { 1 };
        let v: Value = serde_json::from_slice(
            &std::fs::read(p.join(format!("lanes/tts/jobs/job-1/attempts/{n}/device.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(v["attempt"], n);
        assert_eq!(v["events"].as_array().unwrap().len(), 3);
        assert_eq!(v["events"][0]["state"], "dispatching");
        assert_eq!(v["events"][1]["state"], "running");
        assert_eq!(v["events"][2]["state"], "done");
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn test_device_json_lands_in_the_result_storage_tree() {
        device_logs(false);
    }
    #[test]
    fn test_device_json_appends_one_event_per_attempt_step() {
        device_logs(false);
    }
    #[test]
    fn test_second_attempt_gets_its_own_device_log() {
        device_logs(true);
    }
    #[test]
    fn test_one_retry_and_it_must_be_elsewhere() {
        for other in ["worker-a", "worker-b"] {
            let mut r = reach("running");
            report(&mut r, 1, Some(other), 1000).unwrap();
            assert_eq!(
                r["attempts"].as_array().unwrap().len(),
                if other == "worker-b" { 2 } else { 1 }
            );
        }
    }
    #[test]
    fn test_no_third_attempt_once_the_cap_is_spent() {
        test_attempt_numbers_are_sequential_and_capped();
    }
    #[test]
    fn test_fixed_picker_cannot_retry_so_the_job_fails_no_worker() {
        let r = reach("failed");
        assert_eq!(r["state"], "failed");
        assert_eq!(r["error"]["code"], crate::error_catalog::NO_WORKER);
    }
    #[test]
    fn test_a_refusal_is_never_retried() {
        let r = reach("refused");
        assert_eq!(r["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(r["state"], "refused");
    }
    #[test]
    fn test_attempt_cancelled_when_the_job_is_cancelling() {
        let mut r = reach("cancelling");
        report(&mut r, 0, None, 1000).unwrap();
        assert_eq!(r["attempts"][0]["state"], "cancelled");
        assert_eq!(r["state"], "cancelling");
        settle_cancel(&mut r, 1000).unwrap();
        assert_eq!(r["state"], "cancelled");
    }
    #[test]
    fn test_snapshot_fields_are_the_seventeen() {
        assert_eq!(
            storage::snapshot(&queued(), 1000)
                .as_object()
                .unwrap()
                .len(),
            17
        );
    }
    #[test]
    fn test_attempt_entries_validate_against_the_result_schema() {
        for state in STATES {
            store_state(state);
        }
    }
    #[test]
    fn test_error_field_is_the_schema_two_key_form() {
        let v = storage::snapshot(&reach("failed"), 1000);
        assert_eq!(v["error"].as_object().unwrap().len(), 2);
    }
    #[test]
    fn test_the_table_is_data() {
        assert_eq!(EDGES.len(), 22);
        for e in EDGES {
            assert!(!e.cite.is_empty());
            assert!(STATES.contains(&e.src));
            assert!(STATES.contains(&e.dst));
            if e.trigger == "deadline" {
                assert_eq!(e.rc, Some(124));
            }
        }
    }
    #[test]
    fn test_every_state_has_an_edge_or_is_terminal_only() {
        for state in STATES {
            assert_eq!(
                EDGES.iter().any(|e| e.src == *state),
                !q::terminal(&json!({"state":state}))
            );
        }
    }
    #[test]
    fn test_state_and_terminal_sets() {
        assert_eq!(STATES.len(), 10);
        assert_eq!(
            STATES
                .iter()
                .filter(|s| q::terminal(&json!({"state":s})))
                .count(),
            5
        );
    }
    #[test]
    fn test_every_legal_edge_is_takable() {
        for e in EDGES {
            let mut r = reach(e.src);
            transition(&mut r, e.dst, e.trigger, 1000).unwrap();
            assert_eq!(r["state"], e.dst);
        }
    }
    #[test]
    fn test_each_live_state_reachable_by_drivers() {
        for state in STATES {
            assert_eq!(reach(state)["state"], *state);
        }
    }
    #[test]
    fn test_every_illegal_pair_is_refused() {
        for src in STATES {
            for dst in STATES {
                if !EDGES.iter().any(|e| e.src == *src && e.dst == *dst) {
                    let mut r = reach(src);
                    let before = r.clone();
                    assert_eq!(
                        transition(&mut r, dst, "unknown", 1000),
                        Err(if q::terminal(&r) {
                            crate::error_catalog::JOB_FROZEN
                        } else {
                            crate::error_catalog::ILLEGAL_TRANSITION
                        })
                    );
                    assert_eq!(r, before);
                }
            }
        }
    }
    #[test]
    fn test_illegal_code_for_live_sources() {
        let mut r = queued();
        assert_eq!(
            transition(&mut r, "done", "merge-ok", 1000),
            Err(crate::error_catalog::ILLEGAL_TRANSITION)
        );
    }
    #[test]
    fn test_wrong_trigger_is_refused() {
        let mut r = queued();
        assert_eq!(
            transition(&mut r, "dispatching", "wrong", 1000),
            Err(crate::error_catalog::ILLEGAL_TRANSITION)
        );
    }
    #[test]
    fn test_unknown_state_name_refused() {
        let mut r = queued();
        assert_eq!(
            transition(&mut r, "flying", "wrong", 1000),
            Err(crate::error_catalog::ILLEGAL_TRANSITION)
        );
    }
    #[test]
    fn test_no_such_job_and_bad_grammar() {
        let table = crate::JobTable::default();
        for id in ["missing", "../bad", "UPPER"] {
            assert!(!table.jobs.contains_key(id));
            assert_eq!(crate::result_store::valid_id(id), id == "missing");
        }
    }
    #[test]
    fn test_error_envelope_is_the_s01_shape() {
        assert_eq!(
            q::envelope(crate::error_catalog::ILLEGAL_TRANSITION, false),
            json!({"error":crate::error_catalog::ILLEGAL_TRANSITION,"code":crate::error_catalog::ILLEGAL_TRANSITION,"retryable":false})
        );
    }
    #[test]
    fn test_terminal_states_refuse_every_edge() {
        for state in ["done", "failed", "cancelled", "timed_out", "refused"] {
            for dst in STATES {
                let mut r = reach(state);
                assert_eq!(
                    transition(&mut r, dst, "deadline", 1000),
                    Err(crate::error_catalog::JOB_FROZEN)
                );
            }
        }
    }
    #[test]
    fn test_terminal_drivers_refuse_too() {
        for state in ["done", "failed", "cancelled", "timed_out", "refused"] {
            let mut r = reach(state);
            let before = r.clone();
            assert!(dispatch(&mut r, "worker-b", 1000).is_err());
            assert!(accept(&mut r, 1000).is_err());
            assert!(merge(&mut r, true, 1000).is_err());
            assert_eq!(cancel(&mut r, 1000), Ok(false));
            assert_eq!(r, before);
        }
    }
    #[test]
    fn test_attempt_cap_and_terminal_attempts_are_frozen() {
        let mut r = reach("done");
        let before = r.clone();
        assert!(report(&mut r, 0, None, 1000).is_err());
        assert_eq!(r, before);
    }
    #[test]
    fn qc_dispatch_report_validates_before_settlement() {
        let mut r = reach("dispatching");
        let before = r.clone();
        assert_eq!(
            report(&mut r, 124, Some("worker-b"), 1000),
            Err(crate::error_catalog::ILLEGAL_TRANSITION)
        );
        assert_eq!(r, before);
        report(&mut r, 1, Some("worker-b"), 1000).unwrap();
        assert_eq!(r["state"], "failed");
        let settled = r.clone();
        assert!(accept(&mut r, 1000).is_err());
        assert_eq!(r, settled);
    }
}

#[cfg(test)]
mod reuse_tests {
    use super::tests::{queued, reach, temp};
    use super::*;
    use crate::{queue_policy as q, result_store as storage};
    #[test]
    fn test_per_lane_cap_of_128_is_the_queue_reference_s() {
        let jobs: HashMap<_, _> = (0..128).map(|n| (format!("job-{n}"), queued())).collect();
        assert_eq!(
            q::capacity(&jobs, "tts", q::Config::default(), 1000),
            Err(5)
        );
    }
    #[test]
    fn test_terminal_jobs_stop_counting_toward_the_cap() {
        let mut jobs: HashMap<_, _> = (0..128).map(|n| (format!("job-{n}"), queued())).collect();
        cancel(jobs.get_mut("job-0").unwrap(), 1000).unwrap();
        assert!(q::capacity(&jobs, "tts", q::Config::default(), 1000).is_ok());
    }
    #[test]
    fn test_unknown_lane_and_bad_timeout_are_the_queue_s_refusals() {
        for (lane, timeout, code) in [
            ("unknown", json!(45), crate::error_catalog::UNKNOWN_LANE),
            ("tts", json!(0), crate::error_catalog::BAD_SPEC),
            ("tts", json!(361), crate::error_catalog::BAD_SPEC),
            ("tts", json!(true), crate::error_catalog::BAD_SPEC),
        ] {
            assert_eq!(
                q::check(&HashMap::new(), lane, &json!({"timeout_min":timeout})),
                Err(code)
            );
        }
    }
    #[test]
    fn test_a_reused_job_id_is_refused() {
        let jobs = HashMap::from([("job-1".into(), queued())]);
        assert_eq!(
            q::check(&jobs, "tts", &json!({"job_id":"job-1"})),
            Err(crate::error_catalog::JOB_ID_EXISTS)
        );
    }
    #[test]
    fn test_deadline_is_persisted_by_admission_not_by_s02() {
        let mut r = queued();
        assert_eq!(r["deadline_epoch"], 1060);
        dispatch(&mut r, "worker-a", 1010).unwrap();
        accept(&mut r, 1020).unwrap();
        assert_eq!(r["deadline_epoch"], 1060);
    }
    fn order(lanes: bool) {
        let mut rows = HashMap::new();
        for (id, lane, p) in if lanes {
            [
                ("a", "tts", "standard"),
                ("b", "tts", "standard"),
                ("c", "diffusion-image", "standard"),
                ("d", "diffusion-image", "standard"),
            ]
        } else {
            [
                ("a", "tts", "standard"),
                ("b", "tts", "standard"),
                ("c", "tts", "owner"),
                ("d", "tts", "owner"),
            ]
        } {
            rows.insert(
                id.into(),
                q::admitted(&rows, &json!({"job_id":id,"lane":lane,"submitter":p}), 1000),
            );
        }
        let mut last = None;
        let cfg = q::Config {
            seats: 4,
            ..q::Config::default()
        };
        for want in if lanes {
            ["a", "c", "b", "d"]
        } else {
            ["c", "d", "a", "b"]
        } {
            let id = q::next(&rows, last, cfg, |_| true).unwrap();
            assert_eq!(id, want);
            last = crate::LANES.iter().position(|l| *l == q::lane(&rows[&id]));
            dispatch(rows.get_mut(&id).unwrap(), "worker-a", 1000).unwrap();
        }
    }
    #[test]
    fn test_owner_class_first_then_fifo_within_the_class() {
        order(false);
    }
    #[test]
    fn test_lanes_are_served_round_robin() {
        order(true);
    }
    #[test]
    fn test_seats_cap_concurrency_not_admission() {
        let mut rows = HashMap::from([("a".into(), reach("running")), ("b".into(), queued())]);
        assert!(q::next(&rows, None, q::Config::default(), |_| true).is_none());
        assert!(q::capacity(&rows, "tts", q::Config::default(), 1000).is_ok());
        report(rows.get_mut("a").unwrap(), 0, None, 1000).unwrap();
        merge(rows.get_mut("a").unwrap(), true, 1000).unwrap();
        assert_eq!(
            q::next(&rows, None, q::Config::default(), |_| true).as_deref(),
            Some("b")
        );
    }
    #[test]
    fn test_queue_reason_follows_the_seat() {
        let mut r = queued();
        assert_eq!(r["queue_reason"], "awaiting-seat");
        dispatch(&mut r, "worker-a", 1000).unwrap();
        assert!(r["queue_reason"].is_null());
    }
    #[test]
    fn test_the_store_sorts_and_dedupes_artifacts() {
        let p = temp();
        let s = storage::Store::new(&p, storage::Config::default());
        let sha = s.put_artifact("music-sfx", b"data", None).unwrap();
        let arts = vec![
            json!({"path":"stems/drums.wav","bytes":4,"sha256":sha}),
            json!({"path":"audio.wav","bytes":4,"sha256":sha}),
        ];
        let mut r = reach("done");
        r["lane"] = json!("music-sfx");
        r["artifacts"] = json!(arts);
        let mut v = storage::snapshot(&r, 1000);
        let meta = s
            .put_job(
                "music-sfx",
                "job-1",
                &v,
                &std::collections::BTreeMap::new(),
                1000,
            )
            .unwrap();
        assert_eq!(meta["artifacts"][0]["path"], "audio.wav");
        v["artifacts"][1] = v["artifacts"][0].clone();
        assert_eq!(
            s.put_job(
                "music-sfx",
                "job-1",
                &v,
                &std::collections::BTreeMap::new(),
                1000
            ),
            Err(crate::error_catalog::BAD_SPEC)
        );
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn test_the_store_refuses_a_snapshot_it_cannot_hold() {
        let p = temp();
        let s = storage::Store::new(&p, storage::Config::default());
        let mut v = storage::snapshot(&reach("done"), 1000);
        v["state"] = json!("flying");
        assert_eq!(
            s.put_job("tts", "job-1", &v, &std::collections::BTreeMap::new(), 1000),
            Err(crate::error_catalog::BAD_SPEC)
        );
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn test_device_logs_live_in_the_store_s_job_tree() {
        let p = temp();
        let r = reach("failed");
        write_devices(&p, &r).unwrap();
        assert!(p
            .join("lanes/tts/jobs/job-1/attempts/1/device.json")
            .is_file());
        std::fs::remove_dir_all(p).unwrap();
    }
    fn scenario() -> Vec<u8> {
        let p = temp();
        let mut r = reach("running");
        report(&mut r, 1, Some("worker-b"), 1001).unwrap();
        accept(&mut r, 1002).unwrap();
        expire(&mut r, 1060);
        write_devices(&p, &r).unwrap();
        let mut out = Vec::new();
        for n in [1, 2] {
            out.extend(
                std::fs::read(p.join(format!("lanes/tts/jobs/job-1/attempts/{n}/device.json")))
                    .unwrap(),
            );
        }
        out.extend(storage::canonical(&storage::snapshot(&r, 1000)));
        std::fs::remove_dir_all(p).unwrap();
        out
    }
    #[test]
    fn test_two_runs_with_the_same_clock_are_byte_identical() {
        assert_eq!(scenario(), scenario());
    }
    #[test]
    fn test_no_wall_clock_or_randomness_enters_a_run() {
        assert_eq!(scenario(), scenario());
    }
    #[test]
    fn test_every_live_and_terminal_snapshot_validates() {
        let p = temp();
        let s = storage::Store::new(&p, storage::Config::default());
        for (n, state) in STATES.iter().enumerate() {
            let mut v = storage::snapshot(&reach(state), 1000);
            let id = format!("job-{n}");
            v["job_id"] = json!(id);
            s.put_job("tts", &id, &v, &std::collections::BTreeMap::new(), 1000)
                .unwrap();
        }
        std::fs::remove_dir_all(p).unwrap();
    }
    fn done_artifact() -> (std::path::PathBuf, storage::Store, Value) {
        let p = temp();
        let s = storage::Store::new(&p, storage::Config::default());
        let sha = s.put_artifact("tts", b"payload", None).unwrap();
        let mut r = reach("merging");
        r["artifacts"] = json!([{"path":"speech.wav","bytes":7,"sha256":sha}]);
        merge(&mut r, true, 1000).unwrap();
        let v = storage::snapshot(&r, 1000);
        s.put_job("tts", "job-1", &v, &std::collections::BTreeMap::new(), 1000)
            .unwrap();
        (p, s, v)
    }
    #[test]
    fn test_done_snapshot_carries_artifacts_and_manifest() {
        let (p, _, v) = done_artifact();
        assert_eq!(v["artifacts"].as_array().unwrap().len(), 1);
        assert_eq!(
            v["manifest"],
            "/v1/lanes/tts/jobs/job-1/artifacts/manifest.json"
        );
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn test_artifact_triples_recompute() {
        let (p, s, v) = done_artifact();
        for a in v["artifacts"].as_array().unwrap() {
            let data = s
                .get_artifact("tts", a["sha256"].as_str().unwrap())
                .unwrap();
            assert_eq!(a["bytes"], data.len());
            assert_eq!(a["sha256"], hex::encode(Sha256::digest(data)));
        }
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn test_spec_fingerprint_matches_the_kit_canonical_form() {
        let a: Value = serde_json::from_str(r#"{"z":2,"a":{"y":2,"b":1}}"#).unwrap();
        assert_eq!(
            fingerprint(&a),
            hex::encode(Sha256::digest(br#"{"a":{"b":1,"y":2},"z":2}"#))
        );
    }
    #[test]
    fn test_stored_job_document_equals_the_snapshot() {
        let (p, s, v) = done_artifact();
        assert_eq!(s.get_job("tts", "job-1").unwrap(), v);
        assert_eq!(
            std::fs::read(p.join("lanes/tts/jobs/job-1/job.json")).unwrap(),
            storage::canonical(&v)
        );
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn test_refused_snapshots_pin_the_disclosed_schema_gap() {
        let p = temp();
        let s = storage::Store::new(&p, storage::Config::default());
        let r = reach("refused");
        let mut raw = storage::snapshot(&r, 1000);
        raw["state"] = json!("refused");
        assert_eq!(
            s.put_job(
                "tts",
                "job-1",
                &raw,
                &std::collections::BTreeMap::new(),
                1000
            ),
            Err(crate::error_catalog::BAD_SPEC)
        );
        let projected = storage::snapshot(&r, 1000);
        assert_eq!(projected["state"], "failed");
        assert_eq!(
            projected["error"]["code"],
            crate::error_catalog::WORKER_REFUSED
        );
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn run30_deadline_clock_edge_table() {
        let largest = (u64::MAX - 1000) / 60;
        for (label, minutes, now, due) in [
            ("before", 1, 1059, false),
            ("equal", 1, 1060, true),
            ("after", 1, 1061, true),
            ("zero", 0, 1000, true),
            ("largest", largest, absolute(1000, largest), true),
            ("saturated", u64::MAX, u64::MAX, true),
        ] {
            let mut row = queued();
            row["deadline_epoch"] = json!(absolute(1000, minutes));
            assert_eq!(expire(&mut row, now), due, "{label}");
            if !due {
                assert_eq!(row["state"], "queued", "{label}");
            }
            let at = absolute(1000, minutes);
            if !due {
                assert!(expire(&mut row, at), "{label}");
            }
            assert_eq!(row["state"], "timed_out", "{label}");
            assert_eq!(
                row["error"]["code"],
                crate::error_catalog::DEADLINE_EXCEEDED
            );
            assert_eq!(row["attempts"][0]["rc"], 124);
            assert_eq!(row["attempts"].as_array().unwrap().len(), 1);
            assert_eq!(row["journal"].as_array().unwrap().len(), 1);
            let settled = serde_json::to_vec(&row).unwrap();
            assert!(!expire(&mut row, at.saturating_add(1)));
            assert_eq!(serde_json::to_vec(&row).unwrap(), settled, "{label}");
        }
    }
}
