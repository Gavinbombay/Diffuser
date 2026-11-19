//! Queue policy over the router's authoritative job table.
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub per_lane: usize,
    pub global: usize,
    pub seats: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            per_lane: 128,
            global: 512,
            seats: 1,
        }
    }
}
impl Config {
    pub fn from_value(v: &Value) -> Self {
        let d = Self::default();
        Self {
            per_lane: v["queue"]["per_lane_limit"]
                .as_u64()
                .map_or(d.per_lane, |n| n as usize),
            global: v["queue"]["global_limit"]
                .as_u64()
                .map_or(d.global, |n| n as usize),
            seats: v["queue"]["seats"].as_u64().map_or(d.seats, |n| n as usize),
        }
    }
}
pub fn terminal(row: &Value) -> bool {
    matches!(
        row["state"].as_str(),
        Some("done" | "failed" | "cancelled" | "timed_out" | "refused")
    )
}
pub fn lane(row: &Value) -> &str {
    row["lane"]
        .as_str()
        .or_else(|| row["spec"]["lane"].as_str())
        .unwrap_or("")
}
pub fn envelope(code: &str, retryable: bool) -> Value {
    let catalog_code = crate::error_catalog::canonical_code(code);
    crate::error_catalog::observe(None, catalog_code);
    json!({"error":code,"code":catalog_code,"retryable":retryable})
}
pub fn capacity(
    jobs: &HashMap<String, Value>,
    requested: &str,
    cfg: Config,
    now: u64,
) -> Result<(), u64> {
    let live: Vec<_> = jobs.values().filter(|r| !terminal(r)).collect();
    if live.iter().filter(|r| lane(r) == requested).count() < cfg.per_lane
        && live.len() < cfg.global
    {
        return Ok(());
    }
    Err(jobs
        .values()
        .filter(|r| lane(r) == requested && r["state"] == "queued")
        .filter_map(|r| r["deadline_epoch"].as_u64())
        .min()
        .map_or(5, |at| at.saturating_sub(now).clamp(1, 5)))
}
pub fn check(
    jobs: &HashMap<String, Value>,
    requested: &str,
    spec: &Value,
) -> Result<(), &'static str> {
    if !crate::LANES.contains(&requested) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    if spec
        .get("submitter")
        .is_some_and(|v| v != "owner" && v != "standard")
        || spec
            .get("timeout_min")
            .filter(|v| !(spec["lane"] == "render-blender" && v.is_null()))
            .is_some_and(|v| !v.as_f64().is_some_and(|n| (1.0..=360.0).contains(&n)))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if let Some(id) = spec
        .get("job_id")
        .filter(|v| !(spec["lane"] == "render-blender" && v.is_null()))
    {
        let id = id
            .as_str()
            .filter(|s| crate::result_store::valid_id(s))
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        if jobs.contains_key(id) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::JOB_ID_EXISTS,
            ));
        }
    }
    Ok(())
}
pub fn admitted(jobs: &HashMap<String, Value>, spec: &Value, now: u64) -> Value {
    let position = jobs
        .values()
        .filter_map(|r| r["position"].as_u64())
        .max()
        .map_or(0, |n| n + 1);
    let minutes = if crate::is_bake(spec) {
        crate::bake_budget_min(spec)
    } else {
        spec["timeout_min"]
            .as_f64()
            .or_else(|| spec["deadline_min"].as_f64())
            .unwrap_or(crate::deadline::Config::default().timeout_min as f64)
    };
    let deadline = if minutes.fract() == 0.0 {
        crate::deadline::absolute(now, minutes as u64)
    } else {
        now.saturating_add((minutes * 60.0) as u64)
    };
    json!({"job_id":spec["job_id"],"lane":spec["lane"],"cartridge":spec["cartridge"],"cartridge_manifest_sha256":spec["cartridge_manifest_sha256"],"spec_sha256":crate::deadline::fingerprint(spec),"state":"queued","priority":spec["submitter"].as_str().unwrap_or("standard"),"position":position,"created_epoch":now,"deadline_epoch":deadline,"queue_reason":"awaiting-seat","cleanup":"pending"})
}
pub fn next(
    jobs: &HashMap<String, Value>,
    last: Option<usize>,
    cfg: Config,
    eligible: impl Fn(&str) -> bool,
) -> Option<String> {
    let held = jobs
        .values()
        .filter(|r| {
            matches!(
                r["state"].as_str(),
                Some("running" | "dispatching" | "merging" | "cancelling")
            )
        })
        .count();
    if held >= cfg.seats {
        return None;
    }
    for offset in 0..crate::LANES.len() {
        let index = (last.map_or(0, |n| n + 1) + offset) % crate::LANES.len();
        let found = jobs
            .iter()
            .filter(|(id, r)| {
                r["state"] == "queued" && lane(r) == crate::LANES[index] && eligible(id)
            })
            .min_by_key(|(id, r)| {
                (
                    r["priority"] != "owner",
                    r["position"].as_u64().unwrap_or(u64::MAX),
                    *id,
                )
            });
        if let Some((id, _)) = found {
            return Some(id.clone());
        }
    }
    None
}
#[cfg(test)]
pub fn tick(jobs: &mut HashMap<String, Value>, now: u64) -> Vec<String> {
    let mut expired: Vec<_> = jobs
        .iter()
        .filter(|(_, r)| !terminal(r) && r["deadline_epoch"].as_u64().is_some_and(|at| at <= now))
        .map(|(id, r)| (r["position"].as_u64().unwrap_or(0), id.clone()))
        .collect();
    expired.sort();
    for (_, id) in &expired {
        let r = jobs.get_mut(id).unwrap();
        r["state"] = json!("timed_out");
        r["queue_reason"] = Value::Null;
        r["error"] = envelope(crate::error_catalog::DEADLINE_EXCEEDED, false);
    }
    expired.into_iter().map(|(_, id)| id).collect()
}
#[cfg(test)]
pub fn cancel(row: &mut Value) -> bool {
    if terminal(row) {
        return false;
    }
    row["cancel_requested"] = json!(true);
    row["queue_reason"] = Value::Null;
    if row["state"] == "queued" {
        row["state"] = json!("cancelled");
        row["cleanup"] = json!("clean");
    } else {
        row["state"] = json!("cancelling");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn add(rows: &mut HashMap<String, Value>, id: &str, lane: &str, priority: &str, minutes: u64) {
        let spec = json!({"job_id":id,"lane":lane,"submitter":priority,"timeout_min":minutes});
        let row = admitted(rows, &spec, 0);
        rows.insert(id.into(), row);
    }
    fn take(
        rows: &mut HashMap<String, Value>,
        last: &mut Option<usize>,
        cfg: Config,
    ) -> Option<String> {
        let id = next(rows, *last, cfg, |_| true)?;
        *last = crate::LANES.iter().position(|l| *l == lane(&rows[&id]));
        rows.get_mut(&id).unwrap()["state"] = json!("running");
        Some(id)
    }
    #[test]
    fn defaults() {
        let c = Config::from_value(&json!({}));
        assert_eq!((c.per_lane, c.global, c.seats), (128, 512, 1));
    }
    #[test]
    fn t1_per_lane_cap() {
        let mut r = HashMap::new();
        for n in 0..128 {
            add(&mut r, &format!("job-{n}"), "tts", "standard", 45);
        }
        assert_eq!(capacity(&r, "tts", Config::default(), 0), Err(5));
        assert!(cancel(r.get_mut("job-0").unwrap()));
        assert!(capacity(&r, "tts", Config::default(), 0).is_ok());
        assert!(capacity(&r, "stt", Config::default(), 0).is_ok());
    }
    #[test]
    fn t2_retry_after() {
        let mut r = HashMap::new();
        add(&mut r, "one", "tts", "standard", 1);
        add(&mut r, "two", "tts", "standard", 10);
        let c = Config {
            per_lane: 2,
            ..Config::default()
        };
        for (now, hint) in [(0, 5), (57, 3), (60, 1), (61, 1)] {
            assert_eq!(capacity(&r, "tts", c, now), Err(hint));
        }
        assert_eq!(r.len(), 2);
    }
    #[test]
    fn t3_owner_priority() {
        let mut r = HashMap::new();
        for (id, p) in [
            ("s1", "standard"),
            ("s2", "standard"),
            ("o1", "owner"),
            ("o2", "owner"),
        ] {
            add(&mut r, id, "tts", p, 45);
        }
        let mut last = None;
        for want in ["o1", "o2", "s1", "s2"] {
            let id = take(&mut r, &mut last, Config::default()).unwrap();
            assert_eq!(id, want);
            r.get_mut(&id).unwrap()["state"] = json!("done");
        }
        add(&mut r, "s3", "tts", "standard", 45);
        add(&mut r, "o3", "music-sfx", "owner", 45);
        assert_eq!(
            next(&r, None, Config::default(), |_| true).as_deref(),
            Some("s3")
        );
    }
    #[test]
    fn t4_round_robin() {
        let mut r = HashMap::new();
        for (id, l) in [
            ("a", "tts"),
            ("b", "tts"),
            ("c", "tts"),
            ("d", "diffusion-image"),
            ("e", "music-sfx"),
            ("f", "music-sfx"),
        ] {
            add(&mut r, id, l, "standard", 45);
        }
        let mut last = None;
        for want in [
            "tts",
            "diffusion-image",
            "music-sfx",
            "tts",
            "music-sfx",
            "tts",
        ] {
            let id = take(&mut r, &mut last, Config::default()).unwrap();
            assert_eq!(lane(&r[&id]), want);
            assert!(take(&mut r, &mut last, Config::default()).is_none());
            r.get_mut(&id).unwrap()["state"] = json!("done");
        }
    }
    #[test]
    fn t5_expiry() {
        for state in ["queued", "running", "cancelling"] {
            let mut r = HashMap::new();
            add(&mut r, "a", "tts", "standard", 1);
            add(&mut r, "b", "tts", "standard", 45);
            r.get_mut("a").unwrap()["state"] = json!(state);
            assert!(tick(&mut r, 59).is_empty());
            assert_eq!(tick(&mut r, 60), ["a"]);
            assert_eq!(
                r["a"]["error"],
                envelope(crate::error_catalog::DEADLINE_EXCEEDED, false)
            );
            assert_eq!(
                next(&r, None, Config::default(), |_| true).as_deref(),
                Some("b")
            );
            assert!(tick(&mut r, 60).is_empty());
        }
    }
    #[test]
    fn t6_cancel() {
        let mut r = HashMap::new();
        add(&mut r, "a", "tts", "standard", 45);
        add(&mut r, "b", "tts", "standard", 45);
        assert!(cancel(r.get_mut("a").unwrap()));
        assert_eq!(r["a"]["cleanup"], "clean");
        assert!(!cancel(r.get_mut("a").unwrap()));
        let mut last = None;
        assert_eq!(
            take(&mut r, &mut last, Config::default()).as_deref(),
            Some("b")
        );
        assert!(cancel(r.get_mut("b").unwrap()));
        assert_eq!(r["b"]["state"], "cancelling");
        assert!(next(&r, last, Config::default(), |_| true).is_none());
        r.get_mut("b").unwrap()["state"] = json!("cancelled");
        assert!(!cancel(r.get_mut("b").unwrap()));
    }
    #[test]
    fn t7_global_cap() {
        let mut r = HashMap::new();
        for n in 0..10 {
            add(
                &mut r,
                &format!("job-{n}"),
                if n < 4 { "tts" } else { "diffusion-image" },
                "standard",
                45,
            );
        }
        let c = Config {
            global: 10,
            ..Config::default()
        };
        assert_eq!(capacity(&r, "stt", c, 0), Err(5));
        cancel(r.get_mut("job-0").unwrap());
        assert!(capacity(&r, "stt", c, 0).is_ok());
    }
    #[test]
    fn t8_determinism() {
        fn run() -> Vec<String> {
            let mut r = HashMap::new();
            for id in ["a", "b", "c"] {
                add(&mut r, id, "tts", "standard", 1);
            }
            tick(&mut r, 60)
        }
        assert_eq!(run(), run());
        assert_eq!(run(), ["a", "b", "c"]);
    }
    #[test]
    fn t9_refusal_shape() {
        let schema = json!({"type":"object","required":["error","code","retryable"],"additionalProperties":false,"properties":{"error":{"type":"string"},"code":{"type":"string","pattern":"^[a-z0-9][a-z0-9-]{0,63}$"},"retryable":{"type":"boolean"}}});
        let validator = jsonschema::validator_for(&schema).unwrap();
        for body in [
            envelope(crate::error_catalog::QUEUE_FULL, true),
            envelope(crate::error_catalog::DEADLINE_EXCEEDED, false),
        ] {
            assert!(validator.is_valid(&body));
            assert_eq!(body["error"], body["code"]);
        }
    }
    #[test]
    fn queued_expiry_is_published_by_scheduler() {
        let root = std::env::temp_dir().join(format!(
            "queue-expiry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut rows = HashMap::new();
        add(&mut rows, "job-1", "tts", "standard", 1);
        rows.get_mut("job-1").unwrap()["result_store_root"] = json!(root);
        let table = crate::JobTable {
            jobs: rows,
            ..Default::default()
        };
        let shared = std::sync::Arc::new(std::sync::Mutex::new(table));
        fn now() -> u64 {
            60
        }
        assert!(!crate::wait_for_turn(
            &shared,
            "job-1",
            Config::default(),
            now
        ));
        let store = crate::result_store::Store::new(&root, crate::result_store::Config::default());
        let v = store.get_job("tts", "job-1").unwrap();
        assert_eq!(v["state"], "timed_out");
        assert_eq!(v["attempts"][0]["rc"], 124);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn bake_deadline_keeps_the_existing_step_budget() {
        let spec = json!({"lane":"render-blender","type":"bake-render","job_id":"job-1","steps":["script","bake","render"]});
        assert_eq!(
            admitted(&HashMap::new(), &spec, 100)["deadline_epoch"],
            100 + 130 * 60
        );
    }
    fn run30_drain(mut jobs: HashMap<String, Value>) -> Vec<String> {
        let mut last = None;
        let mut order = Vec::new();
        while let Some(id) = next(&jobs, last, Config::default(), |_| true) {
            let row = jobs.get_mut(&id).unwrap();
            last = crate::LANES.iter().position(|name| *name == lane(row));
            row["state"] = json!("done");
            order.push(id);
        }
        assert!(jobs.values().all(terminal));
        order
    }
    #[test]
    fn run30_dispatch_order_three_runs_across_lanes() {
        assert_eq!(
            crate::LANES,
            [
                "render-blender",
                "tts",
                "stt",
                "diffusion-image",
                "diffusion-video",
                "music-sfx"
            ]
        );
        let mut expected = Vec::new();
        for suffix in ["priority", "first", "last"] {
            for index in 0..crate::LANES.len() {
                expected.push(format!("job-{index}-{suffix}"));
            }
        }
        for _ in 0..3 {
            let clock = || 1000;
            let mut jobs = HashMap::new();
            for (index, name) in crate::LANES.iter().enumerate() {
                for (suffix, priority) in [
                    ("first", "standard"),
                    ("priority", "owner"),
                    ("last", "standard"),
                ] {
                    let id = format!("job-{index}-{suffix}");
                    let row = admitted(
                        &jobs,
                        &json!({"job_id":id,"lane":name,"submitter":priority}),
                        clock(),
                    );
                    assert_eq!(row["created_epoch"], 1000);
                    jobs.insert(id, row);
                }
            }
            assert_eq!(run30_drain(jobs), expected);
        }
    }
    #[test]
    fn run30_dispatch_ties_ignore_hash_insertion_order() {
        let mut rows = Vec::new();
        let mut expected = Vec::new();
        for (suffix, priority) in [
            ("a", "owner"),
            ("b", "owner"),
            ("c", "standard"),
            ("d", "standard"),
        ] {
            for (index, name) in crate::LANES.iter().enumerate() {
                let id = format!("job-{index}-{suffix}");
                let clock = || 1000;
                let row = admitted(
                    &HashMap::new(),
                    &json!({"job_id":id,"lane":name,"submitter":priority}),
                    clock(),
                );
                assert_eq!(row["position"], 0);
                expected.push(id.clone());
                rows.push((id, row));
            }
        }
        for run in 0..3 {
            let mut permuted = rows.clone();
            match run {
                0 => {}
                1 => permuted.reverse(),
                _ => permuted.rotate_left(7),
            }
            assert_eq!(run30_drain(permuted.into_iter().collect()), expected);
        }
    }
}
