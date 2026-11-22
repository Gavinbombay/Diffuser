use crate::private_state::PrivateDir;
use serde_json::Value;
use std::{collections::HashMap, io, path::Path};

const HEADER: &str = "ts,card,util,watts,idle_min,action,job,result\n";

#[derive(Debug, PartialEq, Eq)]
struct Candidate {
    job: String,
    lane: String,
    spec: String,
    backlog_index: Option<usize>,
}

fn candidate(card: &str, job: &Value, index: Option<usize>) -> Option<Candidate> {
    let id = job["job"].as_str()?;
    if id.is_empty()
        || !id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || !matches!(card, "local-2070" | "local-3060" | "colab-l4")
        || job["card"] != card
        || job["status"] != "ready"
    {
        return None;
    }
    let lane = job["lane"]
        .as_str()
        .or_else(|| match job["path"].as_str()? {
            "wan2070" => Some("diffusion-video"),
            "render-blender" => Some("render-blender"),
            "colab-l4-run" => Some("diffusion-image"),
            _ => None,
        })?;
    if !super::LANES.contains(&lane) {
        return None;
    }
    let spec = job["args"].as_array()?.first()?.as_str()?;
    if spec.is_empty() {
        return None;
    }
    Some(Candidate {
        job: id.into(),
        lane: lane.into(),
        spec: spec.into(),
        backlog_index: index,
    })
}

fn select_candidate(card: &str, backlog: &Value, standing: &str) -> Option<Candidate> {
    if let Some(jobs) = backlog["jobs"].as_array() {
        for (index, job) in jobs.iter().enumerate() {
            if let Some(found) = candidate(card, job, Some(index)) {
                return Some(found);
            }
        }
    }
    for line in standing.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() < 4 {
            continue;
        }
        let row = serde_json::json!({"card":fields[0], "path":fields[1], "job":fields[2], "status":"ready", "args":&fields[3..]});
        if let Some(found) = candidate(card, &row, None) {
            return Some(found);
        }
    }
    None
}

pub(crate) fn idle_candidate(card: &str, row: &Value, live_job: bool, threshold: f64) -> bool {
    if card.to_ascii_lowercase().contains("b70") || row["proved"] != true || live_job {
        return false;
    }
    let state = &row["card_state"];
    let by = state["busy"]["by"].as_str().unwrap_or("");
    let ignored = by == "external-unit"
        && state["busy"]["ref"]
            .as_str()
            .is_some_and(|name| name == "ollama" || name == "llama-server");
    let available = (by == "none" && state["state"] == "idle") || ignored;
    available
        && state["util"]
            .as_f64()
            .is_some_and(|util| util >= 0.0 && util < threshold)
}

pub(crate) fn append_event(path: &Path, fields: [&str; 8]) -> io::Result<()> {
    let header = if path.metadata().map_or(true, |m| m.len() == 0) {
        HEADER
    } else {
        ""
    };
    let row = fields
        .map(|field| {
            let field = crate::log_redaction::line(field);
            if field.contains([',', '"', '\r', '\n']) {
                format!("\"{}\"", field.replace('"', "\"\""))
            } else {
                field.to_owned()
            }
        })
        .join(",");
    crate::result_store::worker_log::append(
        path,
        &format!("{header}{row}\n"),
        crate::result_store::Config::default().worker_log_max,
    )
}

// Action codes describe observation thresholds, not a retry or quota policy.
#[derive(Clone, Copy)]
enum Timeout {
    Idle,
    Gap,
    Alert,
}
fn timeout_action(kind: Timeout, elapsed: u64, limit: u64) -> (&'static str, &'static str) {
    use crate::error_catalog::*;
    let (action, code) = match kind {
        Timeout::Idle if elapsed < limit => ("wait", WATCHDOG_IDLE_WAIT),
        Timeout::Idle => ("eligible", WATCHDOG_IDLE_READY),
        Timeout::Gap if elapsed > limit => ("reset", WATCHDOG_GAP_RESET),
        Timeout::Gap => ("continue", WATCHDOG_GAP_CONTINUE),
        Timeout::Alert if elapsed < limit => ("suppress", WATCHDOG_ALERT_SUPPRESSED),
        Timeout::Alert => ("append", WATCHDOG_ALERT_READY),
    };
    (action, reason(code))
}

/// Consecutive observations are required: a gap longer than the sampling
/// interval cannot establish that the card stayed idle during the gap.
#[derive(Default)]
pub(crate) struct IdleTracker {
    cards: HashMap<String, Observation>,
}

struct Observation {
    since: u64,
    last: u64,
}

impl IdleTracker {
    pub(crate) fn observe(
        &mut self,
        card: &str,
        now: u64,
        eligible: bool,
        max_gap: u64,
    ) -> Option<u64> {
        if !eligible {
            self.cards.remove(card);
            return None;
        }
        let item = self.cards.entry(card.to_owned()).or_insert(Observation {
            since: now,
            last: now,
        });
        if now < item.last
            || timeout_action(Timeout::Gap, now.saturating_sub(item.last), max_gap).0 == "reset"
        {
            item.since = now;
        }
        item.last = now;
        Some(now - item.since)
    }
}

#[derive(Default)]
struct Watchdog {
    idle: IdleTracker,
    alerts: HashMap<String, u64>,
    dispatched: std::collections::HashSet<String>,
}

impl Watchdog {
    async fn tick(&mut self, app: &super::App, now: u64) {
        let workers = super::load_registry().unwrap_or_default();
        let probe = workers
            .iter()
            .any(|w| w.id == "local-2070")
            .then(|| super::local_card_probe(now))
            .flatten();
        self.tick_with(app, now, workers, probe, super::submit_in_process)
            .await;
    }

    async fn tick_with<F, Fut>(
        &mut self,
        app: &super::App,
        now: u64,
        workers: Vec<super::Worker>,
        probe: Option<Value>,
        submit: F,
    ) where
        F: Fn(super::App, String, axum::body::Bytes) -> Fut,
        Fut: std::future::Future<Output = axum::response::Response>,
    {
        let cfg = &app.compat["watchdog"];
        let Some(root) = cfg["directory"].as_str().map(std::path::PathBuf::from) else {
            return;
        };
        let Ok(inputs) = PrivateDir::open(&root) else {
            self.idle.cards.clear();
            return;
        };
        let state_dir = app.compat["card_state_dir"]
            .as_str()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| root.clone());
        let snapshot = super::card_state::refresh(&state_dir, now);
        *app.cards.lock().unwrap() = snapshot.clone();
        let (busy, queued_cards) = {
            let table = app.st.lock().unwrap();
            let cards = table
                .jobs
                .values()
                .filter(|job| {
                    matches!(
                        job["state"].as_str(),
                        Some("queued" | "dispatching" | "running" | "merging")
                    )
                })
                .flat_map(|job| {
                    job["spec"]["card_pref"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                })
                .collect::<std::collections::HashSet<_>>();
            (table.busy.clone(), cards)
        };
        let max_gap = 150;
        let limit = cfg["idle_seconds"].as_u64().unwrap_or(600);
        let threshold = cfg["util_threshold"].as_f64().unwrap_or(10.0);
        let off = cfg["off"].as_bool().unwrap_or(false)
            || cfg["off_file"]
                .as_str()
                .map(Path::new)
                .unwrap_or_else(|| Path::new("/etc/lanes/GPU-WATCHDOG-OFF"))
                .exists();
        for worker in workers
            .iter()
            .filter(|w| matches!(w.id.as_str(), "local-2070" | "local-3060" | "colab-l4"))
        {
            let card = &worker.id;
            let state = &snapshot[card];
            let heartbeat =
                (card == "colab-l4").then(|| serde_json::json!({"epoch":state["epoch"]}));
            let proof = super::card_state::snapshot_proof(
                state,
                Some(card),
                now,
                heartbeat
                    .as_ref()
                    .or(probe.as_ref().filter(|_| card == "local-2070")),
            )
            .is_ok();
            let row = serde_json::json!({"proved":proof, "card_state":state});
            let live = busy.get(card).copied().unwrap_or(0) > 0
                || queued_cards.contains(card)
                || (card == "colab-l4"
                    && (state["seat"]["held"] != false || state["session"]["state"] != "none"));
            let elapsed = self.idle.observe(
                card,
                now,
                worker.enabled && idle_candidate(card, &row, live, threshold),
                max_gap,
            );
            let Some(elapsed) = elapsed else {
                let action = if state["state"] == crate::error_catalog::STATE_UNREADABLE {
                    crate::error_catalog::STATE_UNREADABLE
                } else {
                    "busy"
                };
                self.event(&root, now, card, state, 0, action, "", "");
                continue;
            };
            if timeout_action(Timeout::Idle, elapsed, limit).0 == "wait" || off {
                continue;
            }
            // The private spool is the scheduler's submission authority.
            let mut backlog: Value = match inputs.read(Path::new("backlog.json")) {
                Ok(bytes) => match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(_) => {
                        self.event(
                            &root,
                            now,
                            card,
                            state,
                            elapsed,
                            "read-fail",
                            "",
                            "backlog-invalid",
                        );
                        continue;
                    }
                },
                Err(e) if e.kind() == io::ErrorKind::NotFound => serde_json::json!({"jobs":[]}),
                Err(_) => {
                    self.event(
                        &root,
                        now,
                        card,
                        state,
                        elapsed,
                        "read-fail",
                        "",
                        "backlog-unreadable",
                    );
                    continue;
                }
            };
            if !backlog["jobs"].is_array() {
                self.event(
                    &root,
                    now,
                    card,
                    state,
                    elapsed,
                    "read-fail",
                    "",
                    "backlog-invalid",
                );
                continue;
            }
            let standing = match inputs.read(Path::new("standing.tsv")).and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
            }) {
                Ok(rows) => rows,
                Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
                Err(_) => {
                    self.event(
                        &root,
                        now,
                        card,
                        state,
                        elapsed,
                        "read-fail",
                        "",
                        "standing-unreadable",
                    );
                    continue;
                }
            };
            let Some(found) = select_candidate(card, &backlog, &standing) else {
                let blocked: Vec<String> = backlog["jobs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|j| j["card"] == *card && j["status"] == "blocked")
                    .map(|j| {
                        format!(
                            "{}({})",
                            j["job"].as_str().unwrap_or(""),
                            j["why"].as_str().unwrap_or("")
                        )
                    })
                    .collect();
                self.event(
                    &root,
                    now,
                    card,
                    state,
                    elapsed,
                    "backlog-empty",
                    "",
                    &format!("{} blocked", blocked.len()),
                );
                self.alert(
                    &root,
                    now,
                    card,
                    &format!("backlog-empty {}", blocked.join(", ")),
                );
                continue;
            };
            if self.dispatched.contains(&found.job) {
                continue;
            }
            if !worker.lanes.contains(&found.lane)
                || (super::opened_lane(&found.lane) && app.compat["lanes"][&found.lane] != true)
            {
                let message = format!("router-cannot-admit lane={}", found.lane);
                self.event(
                    &root,
                    now,
                    card,
                    state,
                    elapsed,
                    "router-cannot-admit",
                    &found.job,
                    &message,
                );
                self.alert(&root, now, card, &message);
                continue;
            }
            let bytes = match inputs.read(Path::new(&found.spec)) {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.event(
                        &root,
                        now,
                        card,
                        state,
                        elapsed,
                        "fill-failed",
                        &found.job,
                        "router-error=spec-read",
                    );
                    self.alert(&root, now, card, "router-error=spec-read");
                    continue;
                }
            };
            let response = submit(app.clone(), found.lane.clone(), bytes.into()).await;
            let status = response.status();
            if !status.is_success() {
                let message = format!("router-http={}", status.as_u16());
                self.event(
                    &root,
                    now,
                    card,
                    state,
                    elapsed,
                    "fill-failed",
                    &found.job,
                    &message,
                );
                self.alert(&root, now, card, &message);
                continue;
            }
            let ts = super::utc_stamp(now)
                .map(|s| format!("{}+0000", s.trim_end_matches('Z')))
                .unwrap_or_else(|| now.to_string());
            if let Some(index) = found.backlog_index {
                backlog["jobs"][index]["status"] = serde_json::json!("dispatched");
                backlog["jobs"][index]["dispatched_at"] = serde_json::json!(ts);
                if inputs
                    .replace("backlog.json", &serde_json::to_vec_pretty(&backlog).unwrap())
                    .is_err()
                {
                    self.dispatched.insert(found.job.clone());
                    self.alert(&root, now, card, "backlog-write-failed");
                }
            } else {
                let _ = crate::result_store::worker_log::append(
                    &root.join("standing.dispatched.log"),
                    &format!("{ts}\t{card}\t{}\n", found.job),
                    crate::result_store::Config::default().worker_log_max,
                );
            }
            self.idle.observe(card, now, false, max_gap);
            self.event(
                &root,
                now,
                card,
                state,
                elapsed,
                "fill",
                &found.job,
                "rc=0 http=201",
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn event(
        &self,
        root: &Path,
        now: u64,
        card: &str,
        state: &Value,
        elapsed: u64,
        action: &str,
        job: &str,
        result: &str,
    ) {
        let ts = super::utc_stamp(now).unwrap_or_else(|| now.to_string());
        let util = state["util"].to_string();
        let watts = state["watts"].to_string();
        let mins = format!("{:.1}", elapsed as f64 / 60.0);
        let _ = append_event(
            &root.join("events.csv"),
            [&ts, card, &util, &watts, &mins, action, job, result],
        );
    }

    fn alert(&mut self, root: &Path, now: u64, card: &str, message: &str) {
        if !self.alerts.contains_key(card) {
            if let Ok(lines) = std::fs::File::open(root.join("alerts.log"))
                .and_then(|f| {
                    crate::result_store::worker_log::read(
                        f,
                        crate::result_store::Config::default().worker_log_max,
                    )
                })
                .map(|v| String::from_utf8_lossy(&v).into_owned())
            {
                if let Some(last) = lines
                    .lines()
                    .filter_map(|line| {
                        let mut fields = line.split_whitespace();
                        let epoch = fields.next()?.parse::<u64>().ok()?;
                        (fields.next()? == card).then_some(epoch)
                    })
                    .max()
                {
                    self.alerts.insert(card.to_owned(), last);
                }
            }
        }
        if self.alerts.get(card).is_some_and(|last| {
            timeout_action(Timeout::Alert, now.saturating_sub(*last), 3600).0 == "suppress"
        }) {
            return;
        }
        if crate::result_store::worker_log::append(
            &root.join("alerts.log"),
            &format!("{now} {card} {message}\n"),
            crate::result_store::Config::default().worker_log_max,
        )
        .is_ok()
        {
            self.alerts.insert(card.to_owned(), now);
        }
    }
}

pub(crate) async fn run(app: super::App) {
    let seconds = app.compat["watchdog"]["sample_seconds"]
        .as_u64()
        .unwrap_or(120)
        .clamp(1, 120);
    let mut watchdog = Watchdog::default();
    loop {
        let cfg = &app.compat["watchdog"];
        let now = cfg["clock_file"]
            .as_str()
            .zip(cfg["directory"].as_str())
            .and_then(|(clock, root)| PrivateDir::open(Path::new(root)).ok()?.read(Path::new(clock)).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| (app.clock)());
        watchdog.tick(&app, now).await;
        tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_state::{fixture_dir, fixture_file};
    use serde_json::json;

    struct Fixture {
        root: std::path::PathBuf,
        app: super::super::App,
        worker: super::super::Worker,
    }
    impl Fixture {
        fn new(with_job: bool) -> Self {
            let root = std::env::temp_dir().join(format!(
                "watchdog-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            fixture_dir(&root);
            fixture_dir(&root.join("cards"));
            fixture_file(&root.join("spec.json"), b"{}");
            if with_job {
                fixture_file(
                    &root.join("backlog.json"),
                    json!({"jobs":[{"job":"job-1","card":"local-3060","path":"render-blender","status":"ready","args":[root.join("spec.json")]}]}).to_string(),
                );
            }
            let app = super::super::new_app(
                json!({"card_state_dir":root,"watchdog":{"directory":root}}),
                root.join("store"),
            );
            let worker = super::super::Worker {
                id: "local-3060".into(),
                lanes: vec!["render-blender".into()],
                kind: "agent-push".into(),
                exec: String::new(),
                dispatch: Value::Null,
                seats: 1,
                enabled: true,
                note: String::new(),
            };
            Self { root, app, worker }
        }
        fn state(&self, now: u64) {
            let mut v: Value = serde_json::from_slice(include_bytes!(
                "../tests/fixtures/card-state/local-3060-self-probe-fresh.json"
            ))
            .unwrap();
            v["epoch"] = json!(now);
            v["self_probe"]["epoch"] = json!(now);
            fixture_file(&self.root.join("cards/local-3060.json"), v.to_string());
        }
        async fn tick(&self, w: &mut Watchdog, now: u64) {
            self.state(now);
            w.tick_with(
                &self.app,
                now,
                vec![self.worker.clone()],
                None,
                |_, _, _| async { axum::http::StatusCode::CREATED.into_response() },
            )
            .await;
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn scheduler_requires_private_backlog_standing_and_in_tree_specs() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        for (case, allowed) in [
            ("absolute", true),
            ("relative", true),
            ("standing", true),
            ("root_mode", false),
            ("backlog_mode", false),
            ("standing_mode", false),
            ("spec_mode", false),
            ("outside", false),
            ("traversal", false),
            ("symlink", false),
        ] {
            let mut f = Fixture::new(false);
            f.app.compat["watchdog"]["idle_seconds"] = json!(0);
            let spool = f.root.join("spool");
            fixture_dir(&spool);
            f.app.compat["watchdog"]["directory"] = json!(spool);
            fixture_file(&spool.join("spec.json"), "{}");
            let spec = match case {
                "absolute" => spool.join("spec.json"),
                "outside" => f.root.join("spec.json"),
                "traversal" => spool.join("../spec.json"),
                "symlink" => {
                    symlink(f.root.join("spec.json"), spool.join("link.json")).unwrap();
                    spool.join("link.json")
                }
                _ => "spec.json".into(),
            };
            if matches!(case, "standing" | "standing_mode") {
                fixture_file(
                    &spool.join("standing.tsv"),
                    format!("local-3060\trender-blender\tjob-1\t{}\n", spec.display()),
                );
            } else {
                fixture_file(
                    &spool.join("backlog.json"),
                    json!({"jobs":[{"job":"job-1","card":"local-3060","lane":"render-blender","status":"ready","args":[spec]}]}).to_string(),
                );
            }
            let permissive = match case {
                "root_mode" => Some((spool.clone(), 0o770)),
                "backlog_mode" => Some((spool.join("backlog.json"), 0o660)),
                "standing_mode" => Some((spool.join("standing.tsv"), 0o660)),
                "spec_mode" => Some((spool.join("spec.json"), 0o640)),
                _ => None,
            };
            if let Some((path, mode)) = permissive {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
            }
            let calls = std::sync::atomic::AtomicUsize::new(0);
            f.state(1000);
            Watchdog::default()
                .tick_with(&f.app, 1000, vec![f.worker.clone()], None, |_, lane, body| {
                    assert_eq!(lane, "render-blender");
                    assert_eq!(&body[..], b"{}");
                    calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    async { axum::http::StatusCode::CREATED.into_response() }
                })
                .await;
            assert_eq!(calls.into_inner(), usize::from(allowed), "{case}");
            if matches!(case, "absolute" | "relative") {
                let backlog = PrivateDir::open(&spool)
                    .unwrap()
                    .read(Path::new("backlog.json"))
                    .unwrap();
                let backlog: Value = serde_json::from_slice(&backlog).unwrap();
                assert_eq!(backlog["jobs"][0]["status"], "dispatched");
            }
        }
    }

    #[tokio::test]
    async fn idle_9_9_min_no_fill() {
        let f = Fixture::new(true);
        let mut w = Watchdog::default();
        for now in [1000, 1150, 1300, 1450, 1594] {
            f.tick(&mut w, now).await;
        }
        assert!(!f.root.join("events.csv").exists());
    }
    #[tokio::test]
    async fn idle_10_min_fills_once() {
        let f = Fixture::new(true);
        let mut w = Watchdog::default();
        for now in [1000, 1150, 1300, 1450, 1600, 1750] {
            f.tick(&mut w, now).await;
        }
        assert_eq!(
            std::fs::read_to_string(f.root.join("events.csv"))
                .unwrap()
                .matches(",fill,")
                .count(),
            1
        );
        let v: Value =
            serde_json::from_slice(&std::fs::read(f.root.join("backlog.json")).unwrap()).unwrap();
        assert_eq!(v["jobs"][0]["status"], "dispatched");
    }
    #[test]
    fn ollama_ignored() {
        let row = json!({"proved":true,"card_state":{"state":"busy","busy":{"by":"external-unit","ref":"ollama"},"util":0}});
        assert!(idle_candidate("local-3060", &row, false, 10.0));
    }
    #[tokio::test]
    async fn cannot_admit_event_alert_no_dispatch() {
        let mut f = Fixture::new(true);
        f.worker.lanes.clear();
        let mut w = Watchdog::default();
        for now in [1000, 1150, 1300, 1450, 1600] {
            f.tick(&mut w, now).await;
        }
        assert!(std::fs::read_to_string(f.root.join("events.csv"))
            .unwrap()
            .contains("router-cannot-admit"));
        assert!(std::fs::read_to_string(f.root.join("alerts.log"))
            .unwrap()
            .contains("router-cannot-admit"));
        assert!(std::fs::read_to_string(f.root.join("backlog.json"))
            .unwrap()
            .contains("ready"));
    }
    #[tokio::test]
    async fn off_switch_stops_fill_health_continues() {
        let mut f = Fixture::new(true);
        f.app.compat["watchdog"]["off"] = json!(true);
        let mut w = Watchdog::default();
        for now in [1000, 1150, 1300, 1450, 1600] {
            f.tick(&mut w, now).await;
        }
        assert!(!f.root.join("events.csv").exists());
        assert_eq!(f.app.cards.lock().unwrap()["local-3060"]["util"], 0);
    }
    #[tokio::test]
    async fn empty_backlog_one_alert_per_card_per_hour() {
        let f = Fixture::new(false);
        let mut w = Watchdog::default();
        for now in (1000..=5500).step_by(150) {
            f.tick(&mut w, now).await;
        }
        assert_eq!(
            std::fs::read_to_string(f.root.join("alerts.log"))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }
    #[test]
    fn alert_limit_survives_restart() {
        let f = Fixture::new(false);
        Watchdog::default().alert(&f.root, 1000, "local-3060", "empty");
        Watchdog::default().alert(&f.root, 1100, "local-3060", "empty");
        assert_eq!(
            std::fs::read_to_string(f.root.join("alerts.log"))
                .unwrap()
                .lines()
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn no_double_fill_concurrent_ticks() {
        let f = std::sync::Arc::new(Fixture::new(true));
        let w = std::sync::Arc::new(tokio::sync::Mutex::new(Watchdog::default()));
        for now in [1000, 1150, 1300, 1450] {
            f.tick(&mut *w.lock().await, now).await;
        }
        let a = {
            let f = f.clone();
            let w = w.clone();
            tokio::spawn(async move {
                f.tick(&mut *w.lock().await, 1600).await;
            })
        };
        let b = {
            let f = f.clone();
            let w = w.clone();
            tokio::spawn(async move {
                f.tick(&mut *w.lock().await, 1600).await;
            })
        };
        a.await.unwrap();
        b.await.unwrap();
        assert_eq!(
            std::fs::read_to_string(f.root.join("events.csv"))
                .unwrap()
                .matches(",fill,")
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn failed_submit_keeps_ready() {
        let f = Fixture::new(true);
        let mut w = Watchdog::default();
        for now in [1000, 1150, 1300, 1450] {
            f.tick(&mut w, now).await;
        }
        f.state(1600);
        w.tick_with(
            &f.app,
            1600,
            vec![f.worker.clone()],
            None,
            |_, _, _| async { axum::http::StatusCode::CONFLICT.into_response() },
        )
        .await;
        assert!(std::fs::read_to_string(f.root.join("events.csv"))
            .unwrap()
            .contains("router-http=409"));
        assert!(std::fs::read_to_string(f.root.join("backlog.json"))
            .unwrap()
            .contains("ready"));
    }
    #[test]
    fn watchdog_submit_same_cu_cap_floor_refusals_as_post() {
        use super::super::{h_submit, submit_in_process};
        use axum::{
            extract::{Path as AxPath, State},
            http::{HeaderMap, StatusCode},
        };
        use sha2::{Digest, Sha256};
        if std::env::var_os("WATCHDOG_CU_CHILD").is_none() {
            let status = crate::test_process::command()
                .args([
                    "--exact",
                    "watchdog::tests::watchdog_submit_same_cu_cap_floor_refusals_as_post",
                    "--quiet",
                ])
                .env("WATCHDOG_CU_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for (cap, balance, reason) in [(1, 20, "estimated CU exceeds cap"), (3, 5, "CU balance below floor")] {
                let mut f = Fixture::new(true);
                let auth_dir = f.root.join("auth");
                std::fs::create_dir_all(&auth_dir).unwrap();
                std::fs::write(auth_dir.join("render-blender.sha256"), hex::encode(Sha256::digest(b"<TOKEN>"))).unwrap();
                std::env::set_var("LANE_TOKEN_SHA_DIR", auth_dir);
                let floor = f.root.join("floor"); std::fs::write(&floor, "5").unwrap();
                f.app.compat["cu_floor_path"] = json!(floor); f.app.compat["cu_balance"] = json!(balance);
                let spec = json!({"spec":"job-spec/v1","job_id":"job-1","lane":"render-blender","cartridge":"fixture","card_pref":["local-3060"],"items":[{"id":"one","args":[]}],"entry":"run","seg_min":1,"deadline_min":10,"max_segs":1,"budget_cu":2,"cap_cu":cap,"outputs":"worker:/var/lib/diffuser/jobs/job-1/out"});
                let bytes = serde_json::to_vec(&spec).unwrap(); std::fs::write(f.root.join("spec.json"), &bytes).unwrap();
                let mut headers = HeaderMap::new(); headers.insert("authorization", "Bearer <TOKEN>".parse().unwrap());
                let response = h_submit(State(f.app.clone()), AxPath("render-blender".into()), headers, bytes.into()).await;
                assert_eq!(response.status(), StatusCode::CONFLICT);
                let post = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
                assert!(String::from_utf8_lossy(&post).contains(reason));
                let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
                let mut w = Watchdog::default();
                for now in [1000, 1150, 1300, 1450, 1600] {
                    f.state(now); let observed = observed.clone();
                    w.tick_with(&f.app, now, vec![f.worker.clone()], None, move |app, lane, body| {
                        let observed = observed.clone(); async move {
                            let response = submit_in_process(app, lane, body).await;
                            let status = response.status();
                            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
                            *observed.lock().unwrap() = Some((status, body.clone()));
                            (status, body).into_response()
                        }
                    }).await;
                }
                let (status, body) = observed.lock().unwrap().take().unwrap();
                assert_eq!(status, StatusCode::CONFLICT); assert_eq!(body, post);
                let backlog: Value = serde_json::from_slice(&std::fs::read(f.root.join("backlog.json")).unwrap()).unwrap();
                assert_eq!(backlog["jobs"][0]["status"], "ready");
                assert!(std::fs::read_to_string(f.root.join("events.csv")).unwrap().contains(",fill-failed,job-1,router-http=409"));
            }
        });
    }
    #[tokio::test]
    async fn unproved_state_never_fills() {
        let f = Fixture::new(true);
        let mut w = Watchdog::default();
        for now in [1000, 1150, 1300, 1450, 1600] {
            f.state(now);
            let mut v: Value = serde_json::from_slice(
                &std::fs::read(f.root.join("cards/local-3060.json")).unwrap(),
            )
            .unwrap();
            v["self_probe"]["epoch"] = json!(now - 121);
            std::fs::write(
                f.root.join("cards/local-3060.json"),
                serde_json::to_vec(&v).unwrap(),
            )
            .unwrap();
            w.tick_with(&f.app, now, vec![f.worker.clone()], None, |_, _, _| async {
                axum::http::StatusCode::CREATED.into_response()
            })
            .await;
        }
        assert!(!std::fs::read_to_string(f.root.join("events.csv"))
            .unwrap()
            .contains(",fill,"));
    }
    #[test]
    fn live_router_job_prevents_idle() {
        let row =
            json!({"proved":true,"card_state":{"state":"idle","busy":{"by":"none"},"util":0}});
        assert!(!idle_candidate("local-3060", &row, true, 10.0));
    }

    #[test]
    fn backlog_precedes_standing_and_skips_nonready() {
        let backlog = json!({"jobs":[
            {"job":"claimed", "card":"local-3060", "path":"render-blender", "status":"claimed", "args":["/tmp/a"]},
            {"job":"ready", "card":"local-3060", "path":"render-blender", "status":"ready", "args":["/tmp/b"]}
        ]});
        let found = select_candidate(
            "local-3060",
            &backlog,
            "local-3060\trender-blender\tstanding\t/tmp/c\n",
        )
        .unwrap();
        assert_eq!(
            found,
            Candidate {
                job: "ready".into(),
                lane: "render-blender".into(),
                spec: "/tmp/b".into(),
                backlog_index: Some(1)
            }
        );
    }

    #[test]
    fn standing_selection_requires_valid_row_and_lane() {
        let backlog = json!({"jobs":[{"job":"bad", "card":"local-3060", "path":"unknown", "status":"ready", "args":["/tmp/a"]}]});
        let rows = "# comment\nlocal-3060\trender-blender\tshort\nlocal-3060\trender-blender\tstand-1\t/tmp/b\n";
        let found = select_candidate("local-3060", &backlog, rows).unwrap();
        assert_eq!(found.job, "stand-1");
        assert_eq!(found.backlog_index, None);
        assert!(select_candidate("b70", &backlog, rows).is_none());
    }

    #[test]
    fn busy_via_external_unit() {
        let row = json!({"proved":true,"card_state":{"state":"busy","busy":{"by":"external-unit"},"util":0}});
        assert!(!idle_candidate("local-2070", &row, false, 10.0));
    }

    #[test]
    fn b70_skipped() {
        let row =
            json!({"proved":true,"card_state":{"state":"idle","busy":{"by":"none"},"util":0}});
        assert!(!idle_candidate("b70", &row, false, 10.0));
    }

    #[test]
    fn observations_require_continuity() {
        let mut tracker = IdleTracker::default();
        assert_eq!(tracker.observe("local-3060", 0, true, 150), Some(0));
        assert_eq!(tracker.observe("local-3060", 150, true, 150), Some(150));
        assert_eq!(tracker.observe("local-3060", 301, true, 150), Some(0));
        assert_eq!(tracker.observe("local-3060", 302, false, 150), None);
        assert_eq!(tracker.observe("local-3060", 303, true, 150), Some(0));
    }

    #[test]
    fn events_csv_header_and_rows_exact() {
        let dir = std::env::temp_dir().join(format!("watchdog-events-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.csv");
        append_event(
            &path,
            ["100", "local-3060", "0", "16", "10", "fill", "job,1", "ok"],
        )
        .unwrap();
        append_event(
            &path,
            ["101", "local-3060", "0", "16", "10", "idle", "", "ok"],
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            concat!(
                "ts,card,util,watts,idle_min,action,job,result\n",
                "100,local-3060,0,16,10,fill,\"job,1\",ok\n",
                "101,local-3060,0,16,10,idle,,ok\n"
            )
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[tokio::test]
    async fn run30_watchdog_clock_edge_table() {
        for (label, limit, now, due) in [
            ("before", 600, 599, false),
            ("equal", 600, 600, true),
            ("after", 600, 601, true),
            ("zero", 0, 0, true),
            ("largest", u64::MAX, u64::MAX, true),
        ] {
            let mut f = Fixture::new(false);
            f.worker.id = "local-2070".into();
            f.app.compat["watchdog"]["idle_seconds"] = json!(limit);
            fixture_file(
                &f.root.join("backlog.json"),
                json!({"jobs":[{
                    "job":"job-1", "card":"local-2070", "lane":"render-blender",
                    "status":"ready", "args":[f.root.join("spec.json")]
                }]}).to_string(),
            );
            let mut state: Value = serde_json::from_slice(include_bytes!(
                "../tests/fixtures/card-state/local-2070.json"
            ))
            .unwrap();
            state["epoch"] = json!(now);
            fixture_file(&f.root.join("cards/local-2070.json"), state.to_string());
            let probe = json!({"epoch":now, "util":state["util"], "watts":state["watts"]});
            let mut w = Watchdog::default();
            w.idle.cards.insert(
                "local-2070".into(),
                Observation {
                    since: 0,
                    last: now.saturating_sub(1),
                },
            );
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            for _ in 0..2 {
                let calls = calls.clone();
                w.tick_with(
                    &f.app,
                    now,
                    vec![f.worker.clone()],
                    Some(probe.clone()),
                    move |_, _, _| {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        async { axum::http::StatusCode::CREATED.into_response() }
                    },
                )
                .await;
            }
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(due),
                "{label}"
            );
            let backlog: Value =
                serde_json::from_slice(&std::fs::read(f.root.join("backlog.json")).unwrap())
                    .unwrap();
            assert_eq!(
                backlog["jobs"][0]["status"],
                if due { "dispatched" } else { "ready" },
                "{label}"
            );
            let events = std::fs::read_to_string(f.root.join("events.csv")).unwrap_or_default();
            assert_eq!(
                events.matches(",fill,").count(),
                usize::from(due),
                "{label}"
            );
        }
    }
}

#[cfg(test)]
mod run33_timeout_tests {
    use super::*;
    #[test]
    fn run33_s2_timeout_table() {
        use crate::error_catalog::*;
        let rows = [
            (Timeout::Idle, 599, 600, "wait", WATCHDOG_IDLE_WAIT),
            (Timeout::Idle, 600, 600, "eligible", WATCHDOG_IDLE_READY),
            (Timeout::Idle, 601, 600, "eligible", WATCHDOG_IDLE_READY),
            (Timeout::Gap, 149, 150, "continue", WATCHDOG_GAP_CONTINUE),
            (Timeout::Gap, 150, 150, "continue", WATCHDOG_GAP_CONTINUE),
            (Timeout::Gap, 151, 150, "reset", WATCHDOG_GAP_RESET),
            (
                Timeout::Alert,
                3599,
                3600,
                "suppress",
                WATCHDOG_ALERT_SUPPRESSED,
            ),
            (Timeout::Alert, 3600, 3600, "append", WATCHDOG_ALERT_READY),
            (Timeout::Alert, 3601, 3600, "append", WATCHDOG_ALERT_READY),
        ];
        assert_eq!(rows.len(), 9);
        let root = std::env::temp_dir().join(format!("run33-watchdog-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        for (index, (kind, elapsed, limit, action, code)) in rows.into_iter().enumerate() {
            assert_eq!(
                timeout_action(kind, elapsed, limit),
                (action, code),
                "row {index}"
            );
            assert!(TABLE.iter().any(|entry| entry.code == code));
            match kind {
                Timeout::Idle => {
                    let mut idle = IdleTracker::default();
                    for now in [1000, 1150, 1300, 1450] {
                        idle.observe("local-2070", now, true, 150);
                    }
                    let observed = idle
                        .observe("local-2070", 1000 + elapsed, true, 151)
                        .unwrap();
                    assert_eq!(observed, elapsed);
                    assert_eq!(timeout_action(kind, observed, limit), (action, code));
                }
                Timeout::Gap => {
                    let mut idle = IdleTracker::default();
                    assert_eq!(idle.observe("local-2070", 1000, true, limit), Some(0));
                    assert_eq!(
                        idle.observe("local-2070", 1000 + elapsed, true, limit),
                        Some(if action == "reset" { 0 } else { elapsed })
                    );
                }
                Timeout::Alert => {
                    let directory = root.join(index.to_string());
                    std::fs::create_dir_all(&directory).unwrap();
                    let mut watchdog = Watchdog::default();
                    watchdog.alert(&directory, 1000, "local-2070", "[R]");
                    watchdog.alert(&directory, 1000 + elapsed, "local-2070", "[R]");
                    assert_eq!(
                        std::fs::read_to_string(directory.join("alerts.log"))
                            .unwrap()
                            .lines()
                            .count(),
                        if action == "append" { 2 } else { 1 }
                    );
                }
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
