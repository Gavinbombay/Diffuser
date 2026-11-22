//! Shared configuration, planning and job execution.
use crate::*;
pub(crate) fn base_dir() -> PathBuf {
    std::env::var("LANE_ROUTER_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/workspace/ops/lanes/router"))
}
pub(crate) fn registry_path() -> PathBuf {
    std::env::var("LANE_REGISTRY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| base_dir().join("registry.json"))
}
pub(crate) fn jobs_dir() -> PathBuf {
    base_dir().join("jobs")
}
pub(crate) fn token_sha_dir() -> PathBuf {
    std::env::var("LANE_TOKEN_SHA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| base_dir().join("token-sha"))
}
pub(crate) fn now_s() -> String {
    let o = Command::new("date").arg("+%Y-%m-%d %H:%M:%S %Z").output();
    o.ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}
pub(crate) fn stamp() -> String {
    let o = Command::new("date").arg("+%Y%m%d-%H%M%S").output();
    let t = o
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{t}-{:04x}", (n ^ std::process::id()) & 0xffff)
}
pub(crate) fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
pub(crate) fn write_json(p: &Path, v: &Value) {
    let tmp = p.with_extension("json.tmp");
    if fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap()).is_ok() {
        let _ = fs::rename(&tmp, p);
    }
}
pub(crate) fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}
pub(crate) fn sigterm(pid: u32) {
    worker_process::terminate(pid);
}

// ---------------- registry and health ----------------
#[derive(Clone, Debug)]
pub(crate) struct Worker {
    pub(crate) id: String,
    pub(crate) lanes: Vec<String>,
    pub(crate) kind: String,
    pub(crate) exec: String,
    pub(crate) dispatch: Value,
    pub(crate) seats: usize,
    pub(crate) enabled: bool,
    pub(crate) note: String,
}

pub(crate) fn load_registry() -> Result<Vec<Worker>, String> {
    worker_registry::load_static(&registry_path(), clock_now())
}

/// Run a command with a wall-clock limit; returns (rc, stdout).
pub(crate) fn run_limited(cmd: &mut Command, limit: Duration) -> Result<(i32, String), String> {
    let mut ch = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    let mut out = ch.stdout.take().unwrap();
    let rd = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let t = Instant::now();
    loop {
        if let Some(st) = ch.try_wait().map_err(|e| e.to_string())? {
            return Ok((st.code().unwrap_or(-1), rd.join().unwrap_or_default()));
        }
        if t.elapsed() > limit {
            let _ = ch.kill();
            let _ = ch.wait();
            return Err("health timeout".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Live capabilities for a worker plus the router's accepting verdict and why.
pub(crate) fn registry_why(
    w: &Worker,
    lane: &str,
    busy_local: &HashMap<String, usize>,
) -> Vec<String> {
    let mut why = Vec::new();
    if !w.enabled {
        why.push(format!(
            "disabled in registry{}",
            if w.note.is_empty() {
                String::new()
            } else {
                format!(": {}", w.note)
            }
        ));
    }
    if !w.lanes.iter().any(|l| l == lane) {
        why.push(format!("does not serve {lane}"));
    }
    if dispatch_kinds::kind(&w.kind).is_err() {
        why.push(format!(
            "kind {} has no dispatch path from this host yet",
            w.kind
        ));
    }
    let used = busy_local.get(&w.id).copied().unwrap_or(0);
    if used >= w.seats {
        why.push(format!("router seats full {used}/{}", w.seats));
    }
    why
}
pub(crate) fn worker_view(w: &Worker, lane: &str, busy_local: &HashMap<String, usize>) -> Value {
    let mut why: Vec<String> = vec![];
    if matches!(w.id.as_str(), "colab-l4" | "local-3060" | "local-2070") {
        why.push("card state not proved".into());
    }
    let mut caps = Value::Null;
    why.extend(registry_why(w, lane, busy_local));
    let kind_ready = dispatch_kinds::kind(&w.kind).is_ok_and(|row| {
        row.lanes.contains(&lane)
            && (row.name == "exec"
                || w.dispatch["entry"]
                    .as_str()
                    .is_some_and(|p| Path::new(p).is_file()))
    });
    if w.enabled && kind_ready {
        match run_limited(
            Command::new(&w.exec).arg("--health"),
            Duration::from_secs(45),
        ) {
            Ok((0, s)) => match serde_json::from_str::<Value>(&s) {
                Ok(v) => caps = v,
                Err(e) => why.push(format!("health json: {e}")),
            },
            Ok((rc, _)) => why.push(format!("health rc={rc}")),
            Err(e) => why.push(e),
        }
    } else if w.enabled && !kind_ready && dispatch_kinds::kind(&w.kind).is_ok() {
        why.push(format!(
            "kind {} has no dispatch path from this host yet",
            w.kind
        ));
    }
    if !caps.is_null() {
        if caps["accepting"].as_bool() != Some(true) {
            why.push("worker says accepting:false".into());
        }
        if caps["busy"].as_bool() == Some(true) {
            why.push("worker busy".into());
        }
        // proof contract: {"pass": true, ...} (colab-l4) or {"status": "pass", ...}
        let pr = &caps["proof"];
        let passed = pr["pass"].as_bool() == Some(true)
            || pr["status"].as_str() == Some("pass")
            || pr.as_str() == Some("pass");
        if !passed {
            why.push(format!(
                "proof not passed ({})",
                if pr.is_null() {
                    "none".to_string()
                } else {
                    pr.to_string().chars().take(80).collect()
                }
            ));
        }
        if let Some(l) = caps["lane"].as_str() {
            if l != lane {
                why.push(format!("worker advertises lane {l}"));
            }
        }
        if lane == "render-blender" {
            let offered = worker_cartridges(&caps);
            if !RB_CARTRIDGES.iter().any(|c| offered.iter().any(|o| o == c)) {
                why.push(format!(
                    "blender pin mismatch: worker offers {offered:?}, lane pin {RB_CARTRIDGES:?}"
                ));
            }
        }
    }
    json!({"id": w.id, "kind": w.kind, "lanes": w.lanes, "seats": w.seats, "enabled": w.enabled,
           "accepting": why.is_empty(), "why_not": why, "capabilities": caps})
}

// Pushed cards use their own proof and availability rules, not exec health.
pub(crate) fn card_worker_view(
    w: &Worker,
    lane: &str,
    busy: &HashMap<String, usize>,
    state: &Value,
    now: u64,
    probe: Option<&Value>,
    floor: Option<f64>,
) -> Value {
    let mut why = Vec::new();
    if !w.enabled {
        why.push("disabled in registry");
    }
    if !w.lanes.iter().any(|l| l == lane) {
        why.push("lane unavailable");
    }
    if busy.get(&w.id).copied().unwrap_or(0) >= w.seats {
        why.push("router seats full");
    }
    let ignored = state["busy"]["by"] == "external-unit"
        && state["busy"]["ref"]
            .as_str()
            .is_some_and(|name| name == "ollama" || name == "llama-server");
    if !ignored && (state["state"] != "idle" || state["busy"]["by"] != "none") {
        why.push("card busy or unavailable");
    }
    if w.id == "colab-l4" {
        if state["seat"]["held"] != false || state["session"]["state"] != "none" {
            why.push("seat or session busy");
        }
        if state["cu"]["balance"]
            .as_f64()
            .zip(floor.filter(|v| v.is_finite() && *v >= 0.0))
            .is_none_or(|(balance, floor)| balance <= floor)
        {
            why.push("CU below floor or unavailable");
        }
    }
    let mut row = json!({"id":w.id,"kind":w.kind,"lanes":w.lanes,"seats":w.seats,"enabled":w.enabled,"why_not":why,"accepting":false,"capabilities":null,"card_state":state});
    card_state::apply(&mut row, state);
    card_state::annotate_proof(&mut row, state, Some(&w.id), now, probe);
    if let Some(reasons) = row["why_not"].as_array_mut() {
        reasons.retain(|v| v != "card state not proved");
    }
    if row["proved"] != true {
        row["why_not"]
            .as_array_mut()
            .unwrap()
            .push(json!("card state not proved"));
    }
    row["accepting"] = json!(row["why_not"].as_array().is_some_and(Vec::is_empty));
    row
}

pub(crate) fn local_card_probe(now: u64) -> Option<Value> {
    let (rc, output) = run_limited(
        Command::new("nvidia-smi").args([
            "--query-gpu=utilization.gpu,power.draw",
            "--format=csv,noheader,nounits",
        ]),
        Duration::from_secs(5),
    )
    .ok()?;
    if rc != 0 {
        return None;
    }
    let mut lines = output.lines();
    let line = lines.next()?;
    if lines.next().is_some() {
        return None;
    }
    let (util, watts) = line.split_once(',')?;
    Some(
        json!({"epoch":now,"util":util.trim().parse::<f64>().ok()?,"watts":watts.trim().parse::<f64>().ok()?}),
    )
}

/// Cartridges a worker offers: its explicit list, plus one derived from blender.version ("4.5.14 LTS" -> blender-4.5.14-cycles).
/// Both must agree when both are present, so a worker on the wrong build is refused, not used.
pub(crate) fn worker_cartridges(caps: &Value) -> Vec<String> {
    let listed: Vec<String> = caps["cartridges"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let derived = caps["blender"]["version"]
        .as_str()
        .and_then(|v| v.split_whitespace().next())
        .map(|v| format!("blender-{v}-cycles"));
    match derived {
        Some(d) if listed.is_empty() => vec![d],
        Some(d) => listed.into_iter().filter(|c| *c == d).collect(),
        None => listed,
    }
}

// ---------------- job spec ----------------
pub(crate) fn parse_frames(s: &str) -> Result<(u64, u64), String> {
    let (a, b) = match s.split_once('-') {
        Some((a, b)) => (a, b),
        None => (s, s),
    };
    let a: u64 = a.trim().parse().map_err(|_| format!("bad frames {s:?}"))?;
    let b: u64 = b.trim().parse().map_err(|_| format!("bad frames {s:?}"))?;
    if b < a {
        return Err("frames end < start".into());
    }
    Ok((a, b))
}

/// Split [a,b] into n contiguous ranges (n <= frame count).
pub(crate) fn split_range(a: u64, b: u64, n: usize) -> Vec<(u64, u64)> {
    let total = b - a + 1;
    let n = (n as u64).min(total).max(1);
    let (q, r) = (total / n, total % n);
    let mut out = vec![];
    let mut s = a;
    for i in 0..n {
        let len = q + if i < r { 1 } else { 0 };
        out.push((s, s + len - 1));
        s += len;
    }
    out
}

pub(crate) fn job_type(spec: &Value) -> &str {
    spec["type"].as_str().unwrap_or("render")
}
pub(crate) fn is_bake(spec: &Value) -> bool {
    job_type(spec) == "bake-render"
}
pub(crate) fn is_video(spec: &Value) -> bool {
    spec["lane"] == "diffusion-video"
}
pub(crate) fn opened_lane(lane: &str) -> bool {
    matches!(
        lane,
        "diffusion-video" | "diffusion-image" | "tts" | "stt" | "music-sfx"
    )
}
pub(crate) fn whole_job(spec: &Value) -> bool {
    is_bake(spec) || spec["lane"].as_str().is_some_and(opened_lane)
}

pub(crate) fn video_defaults(spec: &mut Value) {
    if is_video(spec) && spec.is_object() {
        if spec.get("width").is_none() {
            spec["width"] = json!(832);
        }
        if spec.get("height").is_none() {
            spec["height"] = json!(480);
        }
        if spec.get("loop").is_none() {
            spec["loop"] = json!(false);
        }
    }
}

/// bake-render frames: "A", "A-B", "a,b,c" or [a,b,c]; optional when steps has no "render".
pub(crate) fn bake_frames_ok(v: &Value) -> Result<(), String> {
    match v {
        Value::Null => Ok(()),
        Value::Array(a)
            if !a.is_empty() && a.len() <= 1000 && a.iter().all(|x| x.as_u64().is_some()) =>
        {
            Ok(())
        }
        Value::String(s) if s.contains(',') => {
            let n: Vec<&str> = s.split(',').collect();
            if n.len() <= 1000 && n.iter().all(|x| x.trim().parse::<u64>().is_ok()) {
                Ok(())
            } else {
                Err(format!("bad frames list {s:?}"))
            }
        }
        Value::String(s) => parse_frames(s).map(|_| ()),
        _ => Err("frames must be \"A-B\", \"a,b,c\" or a list".into()),
    }
}

/// Wall-clock budget for a bake-render job: its step timeouts plus 15 min for staging and the pull back.
pub(crate) fn bake_budget_min(spec: &Value) -> f64 {
    let steps: Vec<String> = spec["steps"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| {
            if spec["script"].is_string() {
                vec!["script".into(), "bake".into(), "render".into()]
            } else {
                vec!["bake".into(), "render".into()]
            }
        });
    let has = |k: &str| steps.iter().any(|x| x == k);
    let f = |k: &str, d: f64| spec[k].as_f64().unwrap_or(d);
    15.0 + if has("script") {
        f("script_timeout_min", 10.0)
    } else {
        0.0
    } + if has("bake") {
        f("bake_timeout_min", 60.0)
    } else {
        0.0
    } + if has("render") {
        f("timeout_min", 45.0)
    } else {
        0.0
    }
}

pub(crate) fn validate(spec: &Value) -> Result<(), String> {
    if let Some(lane) = spec["lane"]
        .as_str()
        .filter(|l| ["stt", "diffusion-video", "music-sfx"].contains(l))
    {
        lane_bodies::body(spec, lane, true).map_err(str::to_owned)?;
    }
    if spec["lane"] == "render-blender" {
        render_admission::body(spec).map_err(str::to_owned)?;
    }
    if spec["lane"].as_str().is_some_and(opened_lane) {
        let lane = spec["lane"].as_str().unwrap();
        let field = lane_bodies::primary_field(lane);
        if let Some(field) = field {
            if !spec[field].as_str().is_some_and(|s| !s.trim().is_empty()) {
                return Err(format!("{field} must be a nonempty string"));
            }
        }
        if is_video(spec) {
            for name in ["width", "height"] {
                let value = spec[name]
                    .as_u64()
                    .ok_or(format!("{name} must be a positive multiple of 16"))?;
                if value == 0 || value % 16 != 0 {
                    return Err(format!("{name} must be a positive multiple of 16"));
                }
            }
            if !spec["loop"].is_boolean() {
                return Err("loop must be a boolean".into());
            }
        }
        let out = spec["out"].as_str().ok_or("spec.out missing")?;
        if !out.starts_with('/')
            || out == "/mnt/gpu-preserve"
            || out.starts_with("/mnt/gpu-preserve/")
        {
            return Err("invalid out path".into());
        }
        dispatch_kinds::fresh_output(Path::new(out)).map_err(str::to_owned)?;
        if let Some(t) = spec.get("timeout_min") {
            if !t.as_f64().is_some_and(|v| (1.0..=360.0).contains(&v)) {
                return Err("timeout_min must be 1..360".into());
            }
        }
        return Ok(());
    }
    if spec["lane"].as_str() != Some("render-blender") {
        return Err(format!("lane {:?}: only render-blender is live; others are defined in SERVICE_LANES.md and wait", spec["lane"]));
    }
    let cart = spec["cartridge"].as_str().unwrap_or(RB_CARTRIDGES[0]);
    if !RB_CARTRIDGES.contains(&cart) {
        return Err(format!("unknown cartridge {cart}"));
    }
    if spec["engine"]
        .as_str()
        .map(|e| e.to_uppercase())
        .unwrap_or("CYCLES".into())
        != "CYCLES"
    {
        return Err("engine must be CYCLES".into());
    }
    let blend = spec["blend"].as_str().ok_or("spec.blend missing")?;
    if !blend.starts_with('/') || !blend.ends_with(".blend") || !Path::new(blend).is_file() {
        return Err(format!(
            "blend {blend:?} must be an existing absolute .blend"
        ));
    }
    if let Some(a) = spec["assets"].as_str() {
        if !Path::new(a).is_dir() {
            return Err(format!("assets {a:?} not a dir"));
        }
    }
    match job_type(spec) {
        "render" => {
            parse_frames(
                spec["frames"]
                    .as_str()
                    .ok_or("spec.frames missing (\"A-B\")")?,
            )?;
        }
        "bake-render" => {
            bake_frames_ok(&spec["frames"])?;
            if let Some(i) = spec.get("inputs") {
                let i = i.as_str().ok_or("inputs must be a path")?;
                if !i.starts_with('/') || !Path::new(i).is_dir() {
                    return Err(format!("inputs {i:?} must be an existing absolute folder"));
                }
            }
            for k in ["script_timeout_min", "bake_timeout_min"] {
                if let Some(v) = spec.get(k) {
                    let v = v.as_f64().ok_or(format!("{k} must be a number"))?;
                    if !(v > 0.0 && v <= 720.0) {
                        return Err(format!("{k} must be in (0, 720]"));
                    }
                }
            }
        }
        t => return Err(format!("unknown job type {t:?} (render | bake-render)")),
    }
    let out = spec["out"].as_str().ok_or("spec.out missing")?;
    if !out.starts_with('/') {
        return Err("out must be absolute".into());
    }
    if out == "/mnt/gpu-preserve" || out.starts_with("/mnt/gpu-preserve/") {
        return Err("out must never be under /mnt/gpu-preserve".into());
    }
    dispatch_kinds::fresh_output(Path::new(out)).map_err(str::to_owned)?;
    let t = spec["timeout_min"]
        .as_f64()
        .unwrap_or(render_admission::Config::default().timeout_min);
    if !(1.0..=360.0).contains(&t) {
        return Err("timeout_min must be 1..360".into());
    }
    Ok(())
}

// ---------------- job runner (shared by CLI and HTTP) ----------------
#[derive(Default)]
pub(crate) struct JobTable {
    pub(crate) queue_config: queue_policy::Config,
    pub(crate) clock: Option<fn() -> u64>,
    pub(crate) queue_last: Option<usize>,
    pub(crate) jobs: HashMap<String, Value>,
    pub(crate) agent_queue: Vec<String>,
    pub(crate) leases: segment_lifecycle::LeaseManager,
    pub(crate) agent_owners: HashMap<String, String>,
    pub(crate) pids: HashMap<String, Vec<u32>>,
    pub(crate) cancel: HashSet<String>,
    pub(crate) busy: HashMap<String, usize>,
}
impl JobTable {
    // Process a report and the next claim while the caller holds the table lock.
    // A rejected report must never be followed by a claim.
    #[allow(dead_code)] // Used by the pending HTTP pull integration.
    pub(crate) fn agent_pull_transaction(
        &mut self,
        request: &Value,
        card: &Value,
        now: u64,
        boundary: &segment_lifecycle::Boundary<'_>,
        lease: &str,
        expires_at: &str,
    ) -> std::io::Result<Result<Option<Value>, &'static str>> {
        if !agent_pull::valid_request(request) {
            return Ok(Err(crate::error_catalog::reason(
                crate::error_catalog::INVALID_REQUEST,
            )));
        }
        if let Some(report) = request.get("report") {
            let report_boundary = segment_lifecycle::Boundary {
                job_id: report["job_id"].as_str().unwrap(),
                ..*boundary
            };
            if !self.report_agent(request, &report_boundary)? {
                return Ok(Err(crate::error_catalog::reason(
                    crate::error_catalog::INVALID_REPORT,
                )));
            }
        }
        self.claim_available_agent(request, card, now, boundary, lease, expires_at)
            .map(Ok)
    }
    // Apply the availability gate and claim under the same job-table lock.
    #[allow(dead_code)] // The HTTP pull handler will call this transaction.
    pub(crate) fn claim_available_agent(
        &mut self,
        request: &Value,
        card: &Value,
        now: u64,
        boundary: &segment_lifecycle::Boundary<'_>,
        lease: &str,
        expires_at: &str,
    ) -> std::io::Result<Option<Value>> {
        if !agent_pull::valid_request(request)
            || agent_pull::colab_refusal(card, now, boundary.floor)
                .is_some_and(|reason| reason != crate::error_catalog::CU_FLOOR)
        {
            return Ok(None);
        }
        let lanes: Vec<String> = request["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let agent = request["agent_id"].as_str().unwrap();
        deadline::process(&mut self.jobs, now);
        let candidate = queue_policy::next(&self.jobs, self.queue_last, self.queue_config, |id| {
            self.agent_queue.iter().any(|queued| queued == id)
                && self.jobs[id]["spec"]["lane"]
                    .as_str()
                    .is_some_and(|l| lanes.iter().any(|offered| offered == l))
        });
        let Some(selected) = candidate else {
            return Ok(None);
        };
        self.agent_queue.retain(|id| id != &selected);
        self.agent_queue.insert(0, selected);
        let Some((id, lifecycle)) = self.claim_agent(agent, &lanes, card, boundary, lease)? else {
            return Ok(None);
        };
        self.queue_last = LANES
            .iter()
            .position(|l| *l == queue_policy::lane(&self.jobs[&id]));
        Ok(agent_pull::assigned_response(
            lease,
            expires_at,
            &lifecycle,
            &self.jobs[&id]["spec"],
        ))
    }

    // Called while the job table is locked, so admission and queue ownership
    // become visible together and duplicate job IDs cannot replace a lease.
    pub(crate) fn enqueue_agent(&mut self, spec: Value, balance: f64) -> bool {
        let Some(id) = spec["job_id"].as_str().map(str::to_owned) else {
            return false;
        };
        let Some(max_segs) = spec["max_segs"].as_u64() else {
            return false;
        };
        if self.jobs.contains_key(&id) || !self.leases.insert(id.clone(), max_segs, balance) {
            return false;
        }
        self.jobs.insert(
            id.clone(),
            json!({"job_id":id,"state":"queued", "spec":spec}),
        );
        self.agent_queue.push(id);
        true
    }

    // The table lock serializes lease ownership with the visible queue state.
    #[allow(dead_code)] // Used by the forthcoming HTTP pull integration.
    pub(crate) fn claim_agent(
        &mut self,
        agent: &str,
        lanes: &[String],
        card: &Value,
        boundary: &segment_lifecycle::Boundary<'_>,
        lease: &str,
    ) -> std::io::Result<Option<(String, segment_lifecycle::Lifecycle)>> {
        // The pull schema currently admits only colab-l4. A fresh pushed
        // snapshot can be reused by concurrent polls, so reserve the worker
        // until its outstanding lease is reported or reclaimed.
        if !self.agent_owners.is_empty() {
            return Ok(None);
        }
        let assigned = agent_pull::claim_queued(
            &self.leases,
            &self.agent_queue,
            &mut self.jobs,
            lanes,
            card,
            boundary,
            lease,
        )?;
        if assigned.is_some() {
            self.agent_owners.insert(lease.to_owned(), agent.to_owned());
        }
        Ok(assigned)
    }

    // Only call after a session is known to be lost, never to stop a live lease.
    #[allow(dead_code)] // Used by the forthcoming HTTP pull integration.
    pub(crate) fn reclaim_agent(
        &mut self,
        id: &str,
        lease: &str,
        boundary: &segment_lifecycle::Boundary<'_>,
    ) -> std::io::Result<bool> {
        if id != boundary.job_id || !self.agent_owners.contains_key(lease) {
            return Ok(false);
        }
        if !self.leases.reclaim(boundary, lease)? {
            return Ok(false);
        }
        let lifecycle = self.leases.snapshot(id).expect("reclaimed lease exists");
        if let Some(row) = self.jobs.get_mut(id) {
            agent_pull::sync_lifecycle(row, &lifecycle);
        }
        self.agent_owners.remove(lease);
        Ok(true)
    }

    #[allow(dead_code)] // Used by the forthcoming HTTP pull integration.
    pub(crate) fn report_agent(
        &mut self,
        request: &Value,
        boundary: &segment_lifecycle::Boundary<'_>,
    ) -> std::io::Result<bool> {
        if !agent_pull::valid_request(request) {
            return Ok(false);
        }
        let (Some(agent), Some(lease), Some(id)) = (
            request["agent_id"].as_str(),
            request["report"]["lease_id"].as_str(),
            request["report"]["job_id"].as_str(),
        ) else {
            return Ok(false);
        };
        if self.agent_owners.get(lease).map(String::as_str) != Some(agent) {
            return Ok(false);
        }
        // A pull must offer the reported job's lane. The HTTP handler can then
        // authenticate each offered lane before entering this transaction.
        let Some(lane) = self
            .jobs
            .get(id)
            .and_then(|job| job["spec"]["lane"].as_str())
        else {
            return Ok(false);
        };
        if !request["lanes"]
            .as_array()
            .is_some_and(|lanes| lanes.iter().any(|v| v.as_str() == Some(lane)))
        {
            return Ok(false);
        }
        if self.jobs.get(id).is_some_and(queue_policy::terminal) {
            return Ok(false);
        }
        if !agent_pull::apply_report(&self.leases, &mut self.jobs, request, boundary)? {
            return Ok(false);
        }
        self.agent_owners.remove(lease);
        Ok(true)
    }
}
pub(crate) type Shared = Arc<Mutex<JobTable>>;

pub(crate) fn persist(st: &Shared, id: &str) {
    let v = st.lock().unwrap().jobs.get(id).cloned();
    if let Some(v) = v {
        let _ = fs::create_dir_all(jobs_dir());
        write_json(&jobs_dir().join(format!("{id}.json")), &v);
        if let Some(o) = v["out"].as_str() {
            if Path::new(o).is_dir() {
                write_json(&Path::new(o).join("job-state.json"), &v);
            }
        }
    }
}
pub(crate) fn set(st: &Shared, id: &str, k: &str, v: Value) {
    let mut table = st.lock().unwrap();
    let now = (table.clock.unwrap_or(clock_now))();
    if let Some(j) = table.jobs.get_mut(id) {
        deadline::expire(j, now);
        if k == "state" {
            if !queue_policy::terminal(j) {
                let desired = v.as_str().unwrap_or("failed");
                if j["state"] == "cancelling" {
                    let _ = deadline::settle_cancel(j, now);
                } else if j["state"] != desired {
                    j[k] = v;
                }
            }
        } else if !queue_policy::terminal(j) || k == "finished" {
            j[k] = v;
        }
    }
    drop(table);
    persist(st, id);
}

pub(crate) fn resolve_manifest(spec: &Value) -> Result<cartridge::Cartridge, String> {
    let manifest_path = spec["cartridge_manifest"]
        .as_str()
        .ok_or("cartridge manifest required for resource guard")?;
    let data = fs::read(manifest_path).map_err(|e| format!("cartridge manifest: {e}"))?;
    if let Some(expected) = spec["cartridge_manifest_sha256"].as_str() {
        if hex::encode(Sha256::digest(&data)) != expected {
            return Err("cartridge manifest digest changed".into());
        }
    }
    let cart: cartridge::Cartridge =
        serde_json::from_slice(&data).map_err(|e| format!("cartridge manifest: {e}"))?;
    if cart.id != spec["cartridge"].as_str().unwrap_or(RB_CARTRIDGES[0])
        || cart.lane != spec["lane"].as_str().unwrap_or("")
    {
        return Err("cartridge identity or lane mismatch".into());
    }
    let root = spec["cartridge_directory"]
        .as_str()
        .ok_or("cartridge_directory missing")?;
    cartridge::verify(&cart, Path::new(root))?;
    Ok(cart)
}

pub(crate) fn select_manifest(spec: &mut Value, root: &Path) -> Result<(), String> {
    if spec.get("cartridge_manifest").is_none() && spec.get("cartridge_directory").is_none() {
        let (manifest, files, hash) =
            store::active_version(root, spec["lane"].as_str().unwrap_or(""))?;
        spec["cartridge_manifest"] = json!(manifest);
        spec["cartridge_directory"] = json!(files);
        spec["cartridge_manifest_sha256"] = json!(hash);
    } else {
        let path = spec["cartridge_manifest"]
            .as_str()
            .ok_or("cartridge manifest required")?;
        let data = fs::read(path).map_err(|e| format!("cartridge manifest: {e}"))?;
        spec["cartridge_manifest_sha256"] = json!(hex::encode(Sha256::digest(&data)));
    }
    let cart = resolve_manifest(spec)?;
    spec["cartridge"] = json!(cart.id);
    Ok(())
}

/// Pick workers and plan chunks. Returns (plan chunks [(worker, a, b)], worker views).
// Validate dispatch identities before any authoritative state change.
fn dispatch_identity(spec: &Value, worker: Option<&Worker>) -> Result<(), &'static str> {
    let lane = spec["lane"].as_str().unwrap_or("");
    if !LANES.contains(&lane) {
        return Err(error_catalog::reason(error_catalog::UNKNOWN_LANE));
    }
    if lane == "render-blender" && !matches!(job_type(spec), "render" | "bake-render") {
        return Err(error_catalog::reason(error_catalog::BAD_SPEC));
    }
    if let Some(worker) = worker {
        let kind = dispatch_kinds::kind(&worker.kind)
            .map_err(|_| error_catalog::reason(error_catalog::WORKER_REFUSED))?;
        if !kind.lanes.contains(&lane) || !worker.lanes.iter().any(|offered| offered == lane) {
            return Err(error_catalog::reason(error_catalog::LANE_MISMATCH));
        }
    }
    Ok(())
}

fn begin_dispatch(
    table: &mut JobTable,
    id: &str,
    spec: &Value,
    worker: &Worker,
) -> Result<(), &'static str> {
    dispatch_identity(spec, Some(worker))?;
    let now = (table.clock.unwrap_or(clock_now))();
    let row = table.jobs.get_mut(id).ok_or(error_catalog::NO_SUCH_JOB)?;
    row["state"] = json!("queued");
    deadline::dispatch(row, &worker.id, now).and_then(|()| deadline::accept(row, now))
}

#[allow(clippy::type_complexity)]
pub(crate) fn plan(
    spec: &Value,
    st: &Shared,
) -> Result<(Vec<(Worker, u64, u64)>, Vec<Value>), String> {
    dispatch_identity(spec, None).map_err(str::to_owned)?;
    let lane = spec["lane"].as_str().unwrap_or("");
    let cart = resolve_manifest(spec)?;
    let reg = load_registry()?;
    let busy = st.lock().unwrap().busy.clone();
    let mut views: Vec<Value> = reg.iter().map(|w| worker_view(w, lane, &busy)).collect();
    for v in &mut views {
        if v["accepting"] == true {
            if let Err(reason) =
                cartridge::compatible(&cart, v["id"].as_str().unwrap_or(""), &v["capabilities"])
            {
                v["accepting"] = json!(false);
                if let Some(why) = v["why_not"].as_array_mut() {
                    why.push(json!(reason));
                }
            }
        }
    }
    if is_bake(spec) {
        // only workers whose live --health lists the job type
        for v in views.iter_mut() {
            let has = v["capabilities"]["job_types"]
                .as_array()
                .map(|a| a.iter().any(|x| x == "bake-render"))
                .unwrap_or(false);
            if !has && v["accepting"] == true {
                v["accepting"] = json!(false);
                if let Some(w) = v["why_not"].as_array_mut() {
                    w.push(json!("does not advertise job type bake-render"));
                }
            }
        }
    }
    plan_from_views(spec, &reg, views)
}

#[allow(clippy::type_complexity)]
fn plan_from_views(
    spec: &Value,
    reg: &[Worker],
    views: Vec<Value>,
) -> Result<(Vec<(Worker, u64, u64)>, Vec<Value>), String> {
    dispatch_identity(spec, None).map_err(str::to_owned)?;
    let lane = spec["lane"].as_str().unwrap_or("");
    let mut ok: Vec<Worker> = reg
        .iter()
        .zip(&views)
        .filter(|(_, v)| v["accepting"] == true)
        .map(|(w, _)| w.clone())
        .collect();
    if let Some(pref) = spec["prefer"].as_array() {
        // hint only: reorder, never exclude
        let rank = |id: &str| {
            pref.iter()
                .position(|p| p.as_str() == Some(id))
                .unwrap_or(usize::MAX)
        };
        ok.sort_by_key(|w| rank(&w.id));
    }
    if ok.is_empty() {
        return Err(format!(
            "no accepting worker for {lane}: {}",
            serde_json::to_string(
                &views
                    .iter()
                    .map(|v| json!({"id": v["id"], "why_not": v["why_not"]}))
                    .collect::<Vec<_>>()
            )
            .unwrap()
        ));
    }
    for worker in &ok {
        dispatch_identity(spec, Some(worker)).map_err(str::to_owned)?;
    }
    if whole_job(spec) {
        return Ok((vec![(ok[0].clone(), 0, 0)], views));
    } // whole job, one worker; (0,0) = unchunked
    let (a, b) = parse_frames(spec["frames"].as_str().unwrap())?;
    let n = if spec["split_across_workers"].as_bool().unwrap_or(true) {
        ok.len()
    } else {
        1
    };
    let parts = split_range(a, b, n);
    Ok((
        parts
            .into_iter()
            .enumerate()
            .map(|(i, (x, y))| (ok[i].clone(), x, y))
            .collect(),
        views,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_chunk(
    st: &Shared,
    id: &str,
    spec: &Value,
    w: &Worker,
    a: u64,
    b: u64,
    deadline: Instant,
    dry: bool,
    reserved: bool,
) -> Value {
    let mut busy = st.lock().unwrap().busy.clone();
    if reserved {
        if let Some(n) = busy.get_mut(&w.id) {
            *n = n.saturating_sub(1);
        }
    }
    let view = worker_view(w, spec["lane"].as_str().unwrap_or(""), &busy);
    let guard = resolve_manifest(spec).and_then(|c| {
        if view["accepting"] != true {
            return Err(format!("worker unavailable: {}", view["why_not"]));
        }
        if is_bake(spec)
            && !view["capabilities"]["job_types"]
                .as_array()
                .is_some_and(|types| types.iter().any(|t| t == "bake-render"))
        {
            return Err("worker does not advertise job type bake-render".into());
        }
        cartridge::compatible(&c, &w.id, &view["capabilities"])
    });
    if let Err(reason) = guard {
        return json!({"frames": format!("{a}-{b}"), "worker": w.id, "state": "failed", "error": format!("dispatch guard: {reason}")});
    }
    let row = match dispatch_kinds::kind(&w.kind) {
        Ok(row) => row,
        Err(reason) => return json!({"worker":w.id,"state":"failed","rc":1,"error":reason}),
    };
    if let Err(reason) = dispatch_kinds::validate_job(spec) {
        return json!({"worker":w.id,"state":"failed","rc":1,"error":reason});
    }
    let out = PathBuf::from(spec["out"].as_str().unwrap());
    let bake = whole_job(spec);
    let name = dispatch_kinds::part_name(&w.id, bake, a, b);
    let part = out.join("parts").join(&name);
    let delivery = part.join("delivery");
    let mut sub = dispatch_kinds::build_spec(spec, None);
    sub["out"] = json!(part.to_string_lossy());
    if bake {
        // whole spec: frames, step timeouts and job_id pass through unchanged
        for k in ["prefer", "split_across_workers", "api"] {
            if let Some(o) = sub.as_object_mut() {
                o.remove(k);
            }
        }
    } else {
        sub["frames"] = json!(format!("{a}-{b}"));
        let left_min = (deadline
            .saturating_duration_since(Instant::now())
            .as_secs_f64()
            / 60.0)
            .max(1.0);
        sub["timeout_min"] = json!((left_min * 10.0).floor() / 10.0);
        for k in ["prefer", "split_across_workers", "api"] {
            if let Some(o) = sub.as_object_mut() {
                o.remove(k);
            }
        }
    }
    if row.name != "exec" {
        sub["api"] = json!(API);
        if row.spec_out {
            sub["out"] = json!(delivery);
        } else {
            sub.as_object_mut().unwrap().remove("out");
        }
    }
    let sp = out.join("parts").join(format!("{name}.spec.json"));
    let _ = fs::create_dir_all(out.join("parts"));
    write_json(&sp, &sub);
    let logp = out.join("parts").join(format!("{name}.adapter.log"));
    let mut cmd = match dispatch_kinds::command(
        row,
        &w.exec,
        &w.id,
        &w.dispatch,
        &sp,
        &delivery,
        deadline
            .saturating_duration_since(Instant::now())
            .as_secs_f64(),
        dry,
    ) {
        Ok(cmd) => cmd,
        Err(reason) => return json!({"worker":w.id,"state":"failed","rc":1,"error":reason}),
    };
    let lane = spec["lane"].as_str().unwrap_or("");
    let allowed = command_policy::authorize(lane, &cmd, &w.dispatch).and_then(|()| {
        for program in [Some(w.exec.as_str()), w.dispatch["entry"].as_str()]
            .into_iter()
            .flatten()
        {
            let program = dispatch_kinds::absolute(Path::new(program));
            command_policy::authorize(lane, &Command::new(program), &w.dispatch)?;
        }
        Ok(())
    });
    if let Err(reason) = allowed {
        return json!({"worker":w.id,"state":"refused","rc":2,"error":reason});
    }
    let argv: Vec<String> = std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|v| v.to_string_lossy().to_string())
        .collect();
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut ch = match spawn_supervised(st, id, &mut cmd) {
        Ok(c) => c,
        Err(e) => {
            return json!({"frames": format!("{a}-{b}"), "worker": w.id, "state": "failed", "error": format!("spawn {e}")})
        }
    };
    let capture = result_store::worker_log::Capture::start(
        &mut ch,
        result_store::Config::from_value(&w.dispatch).worker_log_max,
    );
    let pid = ch.id();
    st.lock()
        .unwrap()
        .pids
        .entry(id.into())
        .or_default()
        .push(pid);
    let t0 = Instant::now();
    let completion = supervise_worker(
        st,
        id,
        &mut ch,
        deadline,
        Duration::from_secs(dispatch_kinds::Config::from_value(&w.dispatch).grace_seconds),
    );
    let (rc, mut state) = match completion {
        Ok(done) => {
            use std::os::unix::process::ExitStatusExt;
            (
                done.status
                    .code()
                    .unwrap_or_else(|| -done.status.signal().unwrap_or(1)),
                done.state,
            )
        }
        Err(_) => (-1, "failed"),
    };
    if capture.finish(&logp).is_err() {
        state = "failed";
    }
    if let Some(v) = st.lock().unwrap().pids.get_mut(id) {
        v.retain(|p| *p != pid);
    }
    let mut observation = dispatch_kinds::collect(
        row,
        spec["lane"].as_str().unwrap_or(""),
        &delivery,
        &part,
        &logp,
        rc as i64,
    );
    observation["argv"] = json!(argv);
    observation["secs"] = json!(t0.elapsed().as_secs());
    observation["spec_file"] = json!(sp);
    if state == "done" {
        state = match observation["state"].as_str() {
            Some("done") => "done",
            Some("refused") => "refused",
            Some("timed_out") => "timed_out",
            Some("cancelled") => "cancelled",
            _ => "failed",
        };
    }
    if state == "done" && st.lock().unwrap().cancel.contains(id) {
        state = "cancelled";
    }
    let mapped_rc = if state == "timed_out" {
        124
    } else {
        observation["rc"].as_i64().unwrap_or(1)
    };
    let frames = if bake {
        spec["frames"].clone()
    } else {
        json!(format!("{a}-{b}"))
    };
    json!({"frames": frames, "worker": w.id, "state": if bake && rc == 2 && state == "failed" { "refused" } else { state }, "rc": mapped_rc, "raw_rc":rc, "dispatch_observation":observation, "secs": t0.elapsed().as_secs(),
           "part_dir": format!("parts/{name}"), "adapter_log": format!("parts/{name}.adapter.log")})
}

pub(crate) fn spawn_supervised(
    st: &Shared,
    id: &str,
    command: &mut Command,
) -> std::io::Result<std::process::Child> {
    {
        let mut table = st.lock().unwrap();
        let table_clock = table.clock.unwrap_or(clock_now);
        if let Some(row) = table.jobs.get_mut(id) {
            deadline::expire(row, (table_clock)());
            if queue_policy::terminal(row) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    error_catalog::JOB_FROZEN,
                ));
            }
            row["active_children"] = json!(row["active_children"].as_u64().unwrap_or(0) + 1);
        }
    }
    let result = worker_process::spawn(command);
    if result.is_err() {
        if let Some(row) = st.lock().unwrap().jobs.get_mut(id) {
            row["active_children"] = json!(row["active_children"]
                .as_u64()
                .unwrap_or(1)
                .saturating_sub(1));
        }
    }
    result
}
pub(crate) fn supervise_worker(
    st: &Shared,
    id: &str,
    child: &mut std::process::Child,
    deadline: Instant,
    grace: Duration,
) -> std::io::Result<worker_process::Completion> {
    let result = worker_process::wait(child, deadline, grace, || {
        let mut table = st.lock().unwrap();
        let now = (table.clock.unwrap_or(clock_now))();
        let cancelled = table.cancel.contains(id);
        table.jobs.get_mut(id).is_some_and(|row| {
            deadline::expire(row, now);
            cancelled
                || matches!(
                    row["state"].as_str(),
                    Some("timed_out" | "cancelling" | "cancelled")
                )
        })
    });
    let mut result = result;
    let mut table = st.lock().unwrap();
    let now = (table.clock.unwrap_or(clock_now))();
    if let Some(row) = table.jobs.get_mut(id) {
        row["active_children"] = json!(row["active_children"]
            .as_u64()
            .unwrap_or(1)
            .saturating_sub(1));
        if let Ok(done) = &mut result {
            use std::os::unix::process::ExitStatusExt;
            if row["state"] == "timed_out" {
                done.state = "timed_out";
            }
            let raw_rc = done
                .status
                .code()
                .map(i64::from)
                .unwrap_or_else(|| -i64::from(done.status.signal().unwrap_or(1)));
            deadline::reaped(row, raw_rc, done.state, now);
        }
    }
    result
}

/// Copy part artifacts to out/, verifying each against the part's SHA256SUMS.
pub(crate) fn merge(out: &Path, chunks: &[Value]) -> Result<Vec<Value>, String> {
    let mut arts: BTreeMap<String, Value> = BTreeMap::new();
    for c in chunks {
        let pd = out.join(c["part_dir"].as_str().unwrap_or(""));
        let sums = fs::read_to_string(pd.join("SHA256SUMS"))
            .map_err(|e| format!("{}: SHA256SUMS {e}", pd.display()))?;
        for line in sums.lines().filter(|l| !l.trim().is_empty()) {
            let (h, f) = line
                .split_once("  ")
                .ok_or(format!("bad SHA256SUMS line {line:?}"))?;
            if f.contains('/') || f.starts_with('.') {
                return Err(format!("unsafe artifact name {f:?}"));
            }
            if f.starts_with('_') || f.ends_with(".log") || f == "manifest.json" {
                continue;
            } // logs stay in parts/
            let src = pd.join(f);
            let got = sha256_file(&src).map_err(|e| format!("{f}: {e}"))?;
            if got != h {
                return Err(format!(
                    "hash mismatch {f}: sums {} file {}",
                    &h[..12.min(h.len())],
                    &got[..12]
                ));
            }
            if arts.contains_key(f) {
                return Err(format!("artifact {f} produced by two chunks"));
            }
            let dst = out.join(f);
            if fs::hard_link(&src, &dst).is_err() {
                fs::copy(&src, &dst).map_err(|e| format!("copy {f}: {e}"))?;
            }
            let bytes = fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
            arts.insert(
                f.into(),
                json!({"path": f, "bytes": bytes, "sha256": got, "worker": c["worker"]}),
            );
        }
    }
    let mut s = String::new();
    for (f, a) in &arts {
        s.push_str(&format!("{}  {f}\n", a["sha256"].as_str().unwrap()));
    }
    fs::write(out.join("SHA256SUMS"), s).map_err(|e| e.to_string())?;
    Ok(arts.into_values().collect())
}

/// bake-render merge: one part; relative subpaths allowed (no '..', no absolute, no dot-files), logs stay in parts/.
pub(crate) fn merge_tree(out: &Path, c: &Value) -> Result<Vec<Value>, String> {
    let pd = out.join(c["part_dir"].as_str().unwrap_or(""));
    let sums = fs::read_to_string(pd.join("SHA256SUMS"))
        .map_err(|e| format!("{}: SHA256SUMS {e}", pd.display()))?;
    let mut arts: BTreeMap<String, Value> = BTreeMap::new();
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (h, f) = line
            .split_once("  ")
            .ok_or(format!("bad SHA256SUMS line {line:?}"))?;
        if f.starts_with('/')
            || f.split('/')
                .any(|p| p.is_empty() || p == ".." || p.starts_with('.'))
        {
            return Err(format!("unsafe artifact path {f:?}"));
        }
        let base = f.rsplit('/').next().unwrap_or(f);
        if !f.contains('/')
            && (base.starts_with('_') || base.ends_with(".log") || f == "manifest.json")
        {
            continue;
        }
        let src = pd.join(f);
        if fs::symlink_metadata(&src)
            .map(|m| !m.file_type().is_file())
            .unwrap_or(true)
        {
            return Err(format!("{f}: not a regular file"));
        }
        let got = sha256_file(&src).map_err(|e| format!("{f}: {e}"))?;
        if got != h {
            return Err(format!(
                "hash mismatch {f}: sums {} file {}",
                &h[..12.min(h.len())],
                &got[..12]
            ));
        }
        let dst = out.join(f);
        if let Some(par) = dst.parent() {
            fs::create_dir_all(par).map_err(|e| format!("mkdir {}: {e}", par.display()))?;
        }
        if fs::hard_link(&src, &dst).is_err() {
            fs::copy(&src, &dst).map_err(|e| format!("copy {f}: {e}"))?;
        }
        let bytes = fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
        arts.insert(
            f.into(),
            json!({"path": f, "bytes": bytes, "sha256": got, "worker": c["worker"]}),
        );
    }
    let mut s = String::new();
    for (f, a) in &arts {
        s.push_str(&format!("{}  {f}\n", a["sha256"].as_str().unwrap()));
    }
    fs::write(out.join("SHA256SUMS"), s).map_err(|e| e.to_string())?;
    Ok(arts.into_values().collect())
}

/// Full job: validate, plan, dispatch chunks in parallel, retry a failed chunk once elsewhere, merge, manifest.
pub(crate) fn run_job(st: Shared, spec: Value, bytes: Vec<u8>, dry: bool) -> Value {
    if let Err(code) = dispatch_identity(&spec, None) {
        return queue_policy::envelope(code, false);
    }
    let mut fin = run_job_inner(st.clone(), spec, bytes, dry);
    if dry {
        return fin;
    }
    if fin["finished"].is_null() {
        fin["finished"] = json!(now_s());
    }
    let id = fin["job_id"].as_str().unwrap_or("").to_owned();
    let root = fin["result_store_root"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join("results"));
    let now = {
        let table = st.lock().unwrap();
        (table.clock.unwrap_or(clock_now))()
    };
    let published = deadline::write_devices(&root, &fin)
        .and_then(|()| result_store::publish_record(&root, &fin, now));
    if let Err(reason) = published {
        fin["state"] = json!("failed");
        fin["error"] = queue_policy::envelope(crate::error_catalog::STORAGE_UNAVAILABLE, false);
        fin["reason"] = json!(reason);
        fin["artifacts"] = json!([]);
        fin["manifest"] = Value::Null;
        fin["cleanup"] = json!("unresolved");
    }
    if let Some(out) = fin["out"]
        .as_str()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
    {
        let manifest =
            result_store::runtime_manifest(&fin, (st.lock().unwrap().clock.unwrap_or(clock_now))());
        write_json(&out.join("manifest.json"), &manifest);
    }
    st.lock().unwrap().jobs.insert(id.clone(), fin.clone());
    persist(&st, &id);
    fin
}

pub(crate) fn run_job_inner(st: Shared, mut spec: Value, spec_bytes: Vec<u8>, dry: bool) -> Value {
    if let Err(code) = dispatch_identity(&spec, None) {
        return queue_policy::envelope(code, false);
    }
    video_defaults(&mut spec);
    let mut limits = runtime_limits::Config::default();
    if spec["job_id"]
        .as_str()
        .is_some_and(|id| st.lock().unwrap().jobs.contains_key(id))
    {
        limits.tts_seconds = spec["max_output_seconds"]
            .as_u64()
            .unwrap_or(limits.tts_seconds);
    }
    let limit_error = runtime_limits::admit(&mut spec, &limits).err();
    let id = request_boundary::job_id(&spec);
    spec["job_id"] = json!(id);
    let spec_sha = serde_json::from_slice::<Value>(&spec_bytes)
        .map(|v| deadline::fingerprint(&v))
        .unwrap_or_else(|_| hex::encode(Sha256::digest(&spec_bytes)));
    let mut rec = json!({"api": API, "lane": spec["lane"], "type": job_type(&spec), "job_id": id, "cartridge": spec["cartridge"].as_str().unwrap_or(RB_CARTRIDGES[0]),
                     "state": "queued", "cartridge_manifest_sha256": spec["cartridge_manifest_sha256"], "spec_sha256": spec_sha, "out": spec["out"], "started": now_s(), "dry_run": dry, "router_pid": std::process::id()});
    {
        let mut table = st.lock().unwrap();
        if let Some(prior) = table.jobs.get(&id) {
            if queue_policy::terminal(prior) {
                return prior.clone();
            }
            for field in [
                "position",
                "priority",
                "created_epoch",
                "deadline_epoch",
                "state",
                "result_store_root",
            ] {
                rec[field] = prior[field].clone();
            }
        }
        if rec["deadline_epoch"].is_null() {
            let now = (table.clock.unwrap_or(clock_now))();
            let admitted = queue_policy::admitted(&table.jobs, &spec, now);
            for field in ["position", "priority", "created_epoch", "deadline_epoch"] {
                rec[field] = admitted[field].clone();
            }
        }
        table.jobs.insert(id.clone(), rec);
    }
    persist(&st, &id);
    if let Some(reason) = limit_error {
        set(&st, &id, "state", json!("failed"));
        set(
            &st,
            &id,
            "error",
            queue_policy::envelope(crate::error_catalog::ARTIFACT_MISMATCH, false),
        );
        set(&st, &id, "reason", json!(reason));
        return st.lock().unwrap().jobs[&id].clone();
    }
    if let Err(e) = validate(&spec) {
        set(&st, &id, "error", json!(e));
        set(&st, &id, "state", json!("failed"));
        return st.lock().unwrap().jobs[&id].clone();
    }
    if spec["cartridge_manifest_sha256"].is_null() {
        if let Err(e) = select_manifest(&mut spec, &base_dir().join("cartridges")) {
            set(&st, &id, "error", json!(e));
            set(&st, &id, "state", json!("failed"));
            return st.lock().unwrap().jobs[&id].clone();
        }
        set(
            &st,
            &id,
            "cartridge_manifest_sha256",
            spec["cartridge_manifest_sha256"].clone(),
        );
    }
    set(&st, &id, "state", json!("dispatching"));
    let (chunks, views) = match plan(&spec, &st) {
        Ok(p) => p,
        Err(e) => {
            set(&st, &id, "error", json!(e));
            set(&st, &id, "state", json!("failed"));
            return st.lock().unwrap().jobs[&id].clone();
        }
    };
    {
        let mut table = st.lock().unwrap();
        if chunks
            .iter()
            .any(|(w, _, _)| table.busy.get(&w.id).copied().unwrap_or(0) >= w.seats)
        {
            drop(table);
            set(
                &st,
                &id,
                "error",
                json!("worker capacity changed during admission"),
            );
            set(&st, &id, "state", json!("failed"));
            return st.lock().unwrap().jobs[&id].clone();
        }
        for (w, _, _) in &chunks {
            *table.busy.entry(w.id.clone()).or_default() += 1;
        }
    }
    set(
        &st,
        &id,
        "workers_seen",
        json!(views
            .iter()
            .map(|v| json!({"id": v["id"], "accepting": v["accepting"], "why_not": v["why_not"]}))
            .collect::<Vec<_>>()),
    );
    let out = PathBuf::from(spec["out"].as_str().unwrap());
    let _ = fs::create_dir_all(&out);
    persist(&st, &id);
    let budget_min = if is_bake(&spec) {
        bake_budget_min(&spec)
    } else {
        spec["timeout_min"]
            .as_f64()
            .unwrap_or(render_admission::Config::default().timeout_min)
    };
    let remaining = {
        let table = st.lock().unwrap();
        let now = (table.clock.unwrap_or(clock_now))();
        table.jobs[&id]["deadline_epoch"]
            .as_u64()
            .map_or(budget_min * 60.0, |at| at.saturating_sub(now) as f64)
    };
    let deadline = Instant::now() + Duration::from_secs_f64(remaining);
    if is_bake(&spec) {
        set(
            &st,
            &id,
            "planned",
            json!([{"worker": chunks[0].0.id, "frames": spec["frames"], "unchunked": true, "budget_min": budget_min}]),
        );
    } else {
        set(
            &st,
            &id,
            "planned",
            json!(chunks
                .iter()
                .map(|(w, a, b)| json!({"worker": w.id, "frames": format!("{a}-{b}")}))
                .collect::<Vec<_>>()),
        );
    }
    {
        let mut table = st.lock().unwrap();
        let now = (table.clock.unwrap_or(clock_now))();
        let row = table.jobs.get_mut(&id).unwrap();
        if deadline::expire(row, now) || queue_policy::terminal(row) || row["state"] == "cancelling"
        {
            if row["state"] == "cancelling" {
                let _ = deadline::settle_cancel(row, now);
            }
            let result = row.clone();
            for (worker, _, _) in &chunks {
                if let Some(n) = table.busy.get_mut(&worker.id) {
                    *n = n.saturating_sub(1);
                }
            }
            return result;
        }
        if begin_dispatch(&mut table, &id, &spec, &chunks[0].0).is_err() {
            let row = table.jobs.get_mut(&id).unwrap();
            row["state"] = json!("failed");
            return row.clone();
        }
    }
    set(&st, &id, "state", json!("running"));
    let handles: Vec<_> = chunks
        .iter()
        .cloned()
        .map(|(w, a, b)| {
            let (st2, id2, sp2) = (st.clone(), id.clone(), spec.clone());
            std::thread::spawn(move || {
                (
                    w.clone(),
                    run_chunk(&st2, &id2, &sp2, &w, a, b, deadline, dry, true),
                )
            })
        })
        .collect();
    let mut results: Vec<(Worker, Value)> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();
    {
        let mut t = st.lock().unwrap();
        for (w, _) in &results {
            if let Some(n) = t.busy.get_mut(&w.id) {
                *n = n.saturating_sub(1);
            }
        }
    }
    // one retry per failed chunk on a different accepting worker
    for result in &mut results {
        if result.1["state"] != "failed"
            || dry
            || whole_job(&spec)
            || st.lock().unwrap().cancel.contains(&id)
        {
            continue;
        }
        let used = result.0.id.clone();
        let fr = result.1["frames"].as_str().unwrap_or("").to_string();
        let busy = st.lock().unwrap().busy.clone();
        let lane = spec["lane"].as_str().unwrap_or("").to_string();
        let cart = resolve_manifest(&spec).ok();
        let alt = load_registry().unwrap_or_default().into_iter().find(|w| {
            let view = worker_view(w, &lane, &busy);
            w.id != used
                && view["accepting"] == true
                && cart.as_ref().is_some_and(|c| {
                    spec["cartridge_directory"]
                        .as_str()
                        .is_some_and(|p| cartridge::verify(c, Path::new(p)).is_ok())
                        && cartridge::compatible(c, &w.id, &view["capabilities"]).is_ok()
                })
        });
        if let (Some(w), Ok((a, b))) = (alt, parse_frames(&fr)) {
            let reserved = {
                let mut table = st.lock().unwrap();
                let count = table.busy.entry(w.id.clone()).or_default();
                if *count < w.seats {
                    *count += 1;
                    true
                } else {
                    false
                }
            };
            if reserved {
                {
                    let mut table = st.lock().unwrap();
                    let now = (table.clock.unwrap_or(clock_now))();
                    let row = table.jobs.get_mut(&id).unwrap();
                    if row["attempts"].as_array().is_some_and(|a| a.len() == 1) {
                        let _ = deadline::report(row, 1, Some(&w.id), now)
                            .and_then(|()| deadline::accept(row, now));
                    }
                }
                let mut r = run_chunk(&st, &id, &spec, &w, a, b, deadline, dry, true);
                {
                    let mut table = st.lock().unwrap();
                    *table.busy.get_mut(&w.id).unwrap() -= 1;
                }
                r["retry_of"] = json!(used);
                *result = (w, r);
            }
        }
    }
    let chunk_vals: Vec<Value> = results.iter().map(|(_, r)| r.clone()).collect();
    set(&st, &id, "chunks", json!(chunk_vals));
    let worst = if chunk_vals.iter().any(|c| c["state"] == "cancelled") {
        "cancelled"
    } else if chunk_vals.iter().any(|c| c["state"] == "timed_out") {
        "timed_out"
    } else if chunk_vals.iter().any(|c| c["state"] == "refused") {
        "refused"
    } else if chunk_vals.iter().any(|c| c["state"] != "done") {
        "failed"
    } else {
        "done"
    };
    {
        let mut table = st.lock().unwrap();
        let now = (table.clock.unwrap_or(clock_now))();
        let row = table.jobs.get_mut(&id).unwrap();
        let rc = match worst {
            "done" => 0,
            "refused" => 2,
            "timed_out" => 124,
            _ => 1,
        };
        let _ = deadline::report(row, rc, None, now);
        if row["state"] == "failed" {
            if let Some(code) = chunk_vals
                .iter()
                .find_map(|c| c["dispatch_observation"]["reason"].as_str())
                .filter(|s| result_store::valid_id(s))
            {
                row["error"] =
                    json!({"code":error_catalog::canonical_code(code),"retryable":false});
                if let Some(a) = row["attempts"].as_array_mut().and_then(|a| a.last_mut()) {
                    a["reason"] = json!(code);
                }
            }
        }
        if worst == "cancelled" {
            let _ = deadline::settle_cancel(row, now);
        }
    }
    if worst == "done" && !dry {
        set(&st, &id, "state", json!("merging"));
        match if whole_job(&spec) {
            merge_tree(&out, &chunk_vals[0])
        } else {
            merge(&out, &chunk_vals)
        } {
            Ok(arts) => {
                if let Err(reason) = runtime_limits::merged(&spec, &out, &arts, &chunk_vals) {
                    set(
                        &st,
                        &id,
                        "error",
                        queue_policy::envelope(crate::error_catalog::ARTIFACT_MISMATCH, false),
                    );
                    set(&st, &id, "reason", json!(reason));
                    set(&st, &id, "artifacts", json!([]));
                    set(&st, &id, "manifest", Value::Null);
                    set(&st, &id, "cleanup", json!("unresolved"));
                    set(&st, &id, "state", json!("failed"));
                    return st.lock().unwrap().jobs[&id].clone();
                }
                let wm: Vec<Value> = chunk_vals
                    .iter()
                    .map(|c| {
                        json!(format!(
                            "{}/manifest.json",
                            c["part_dir"].as_str().unwrap_or("")
                        ))
                    })
                    .collect();
                set(&st, &id, "artifacts", json!(arts));
                set(&st, &id, "worker_manifests", json!(wm));
                {
                    let mut table = st.lock().unwrap();
                    let now = (table.clock.unwrap_or(clock_now))();
                    let row = table.jobs.get_mut(&id).unwrap();
                    let _ = deadline::merge(row, true, now);
                }
                set(&st, &id, "state", json!("done"));
            }
            Err(e) => {
                set(&st, &id, "error", json!(format!("merge: {e}")));
                set(&st, &id, "state", json!("failed"));
            }
        }
    } else {
        set(
            &st,
            &id,
            "state",
            json!(if dry && worst == "done" {
                "done"
            } else {
                worst
            }),
        );
    }
    set(&st, &id, "finished", json!(now_s()));
    let fin = st.lock().unwrap().jobs[&id].clone();
    fin
}

/// Stale-status reaper: a job left running/dispatching/merging whose router process is gone is failed and its seat freed.
pub(crate) fn reap() -> Vec<String> {
    let mut reaped = vec![];
    let me = std::process::id();
    if let Ok(rd) = fs::read_dir(jobs_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let Ok(b) = fs::read(&p) else { continue };
            let Ok(mut v) = serde_json::from_slice::<Value>(&b) else {
                continue;
            };
            let live = matches!(
                v["state"].as_str(),
                Some("queued" | "dispatching" | "running" | "merging")
            );
            let pid = v["router_pid"].as_u64().unwrap_or(0) as u32;
            if live && pid != me && !pid_alive(pid) {
                v["state"] = json!("failed");
                v["error"] = json!("adapter_gone: router process died; reaped");
                v["reaped_at"] = json!(now_s());
                write_json(&p, &v);
                reaped.push(v["job_id"].as_str().unwrap_or("").to_string());
            }
        }
    }
    reaped
}

#[cfg(test)]
mod agent_ownership_tests {
    use super::*;

    #[test]
    fn concurrent_agents_cannot_claim_two_jobs_on_one_card() {
        let root = std::env::temp_dir().join(format!(
            "agent-card-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let table = Arc::new(Mutex::new(JobTable::default()));
        for id in ["job-123", "job-456"] {
            assert!(table
                .lock()
                .unwrap()
                .enqueue_agent(json!({"job_id":id,"max_segs":4,"lane":"tts"}), 10.0));
        }
        let threads: Vec<_> = (0..2)
            .map(|n| {
                let table = table.clone();
                let root = root.clone();
                std::thread::spawn(move || {
                    let b = segment_lifecycle::Boundary {
                        root: &root,
                        job_id: "unused",
                        ts: "2026-10-31T12:00:00Z",
                        balance: 9.0,
                        floor: 5.0,
                        gpu_class: "l4",
                    };
                    table
                        .lock()
                        .unwrap()
                        .claim_agent(
                            &format!("agent-{n}"),
                            &["tts".into()],
                            &json!({}),
                            &b,
                            &format!("lease-{n}"),
                        )
                        .unwrap()
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
        let table = table.lock().unwrap();
        assert_eq!(table.agent_owners.len(), 1);
        assert_eq!(
            table
                .jobs
                .values()
                .filter(|v| v["state"] == "leased")
                .count(),
            1
        );
        assert_eq!(
            table
                .jobs
                .values()
                .filter(|v| v["state"] == "queued")
                .count(),
            1
        );
    }

    #[test]
    fn report_must_offer_the_owned_jobs_lane() {
        let root = std::env::temp_dir().join(format!(
            "agent-lane-report-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let boundary = segment_lifecycle::Boundary {
            root: &root,
            job_id: "job-123",
            ts: "2026-10-31T12:00:00Z",
            balance: 9.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":4, "lane":"tts"}),
            10.0
        ));
        assert!(table
            .claim_agent(
                "agent-123",
                &["tts".into()],
                &json!({}),
                &boundary,
                "lease-123"
            )
            .unwrap()
            .is_some());
        let mut request = json!({"schema_version":"agent-pull/v1", "agent_id":"agent-123", "worker_id":"colab-l4", "lanes":["stt"], "wait_s":1, "state_epoch":100, "report":{"lease_id":"lease-123", "job_id":"job-123", "segment":0, "exit_code":75, "done_items":["one"]}});
        assert!(!table.report_agent(&request, &boundary).unwrap());
        assert_eq!(table.jobs["job-123"]["state"], "leased");
        assert_eq!(
            table.agent_owners.get("lease-123").map(String::as_str),
            Some("agent-123")
        );
        request["lanes"] = json!(["tts"]);
        assert!(table.report_agent(&request, &boundary).unwrap());
        assert_eq!(table.jobs["job-123"]["state"], "queued");
    }

    #[test]
    fn pull_transaction_reports_then_resumes_and_refuses_replay() {
        let root = std::env::temp_dir().join(format!(
            "agent-transaction-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let b = segment_lifecycle::Boundary {
            root: &root,
            job_id: "unused",
            ts: "2026-10-31T12:00:00Z",
            balance: 6.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":4, "lane":"tts", "gpu_class":"l4"}),
            6.0
        ));
        let mut request = json!({"schema_version":"agent-pull/v1", "agent_id":"agent-123", "worker_id":"colab-l4", "lanes":["tts"], "wait_s":1, "state_epoch":1000});
        let card = json!({"card":"colab-l4","worker_id":"colab-l4","epoch":1000,"stale":false,"seat":{"held":false},"session":{"state":"none"},"busy":{"by":"none"},"cu":{"balance":6.0},"gpu_class":"L4"});
        let first = table
            .agent_pull_transaction(
                &request,
                &card,
                1000,
                &b,
                "lease-123",
                "2026-10-31T12:01:00Z",
            )
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first["segment"], 0);
        request["report"] = json!({"lease_id":"lease-123","job_id":"job-123","segment":0,"exit_code":75,"done_items":["one"]});
        let resumed = table
            .agent_pull_transaction(
                &request,
                &card,
                1000,
                &b,
                "lease-456",
                "2026-10-31T12:01:00Z",
            )
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(resumed["segment"], 1);
        assert_eq!(resumed["done_items"], json!(["one"]));
        assert_eq!(
            table
                .agent_pull_transaction(
                    &request,
                    &card,
                    1000,
                    &b,
                    "lease-789",
                    "2026-10-31T12:01:00Z"
                )
                .unwrap(),
            Err(crate::error_catalog::INVALID_REPORT)
        );
        assert_eq!(table.jobs.len(), 1);
        assert_eq!(table.jobs["job-123"]["state"], "leased");
    }

    #[test]
    fn pull_transaction_stops_at_floor_after_report() {
        let root = std::env::temp_dir().join(format!(
            "agent-floor-transaction-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut b = segment_lifecycle::Boundary {
            root: &root,
            job_id: "unused",
            ts: "2026-10-31T12:00:00Z",
            balance: 6.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":4, "lane":"tts", "gpu_class":"l4"}),
            6.0
        ));
        let mut request = json!({"schema_version":"agent-pull/v1", "agent_id":"agent-123", "worker_id":"colab-l4", "lanes":["tts"], "wait_s":1, "state_epoch":1000});
        let mut card = json!({"card":"colab-l4","worker_id":"colab-l4","epoch":1000,"stale":false,"seat":{"held":false},"session":{"state":"none"},"busy":{"by":"none"},"cu":{"balance":6.0},"gpu_class":"L4"});
        assert!(table
            .agent_pull_transaction(
                &request,
                &card,
                1000,
                &b,
                "lease-123",
                "2026-10-31T12:01:00Z"
            )
            .unwrap()
            .unwrap()
            .is_some());
        request["report"] = json!({"lease_id":"lease-123","job_id":"job-123","segment":0,"exit_code":75,"done_items":[]});
        b.balance = 5.1;
        card["cu"]["balance"] = json!(5.1);
        assert!(table
            .agent_pull_transaction(
                &request,
                &card,
                1000,
                &b,
                "lease-456",
                "2026-10-31T12:01:00Z"
            )
            .unwrap()
            .unwrap()
            .is_none());
        assert_eq!(table.jobs["job-123"]["state"], "floor-stopped");
        assert_eq!(table.jobs["job-123"]["resume_count"], 1);
    }

    #[test]
    fn available_agent_claim_is_gated_and_returns_assigned_job() {
        let root = std::env::temp_dir().join(format!(
            "agent-gated-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let b = segment_lifecycle::Boundary {
            root: &root,
            job_id: "unused",
            ts: "2026-10-31T12:00:00Z",
            balance: 6.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":4, "lane":"tts", "gpu_class":"l4"}),
            6.0
        ));
        let request = json!({"schema_version":"agent-pull/v1", "agent_id":"agent-123", "worker_id":"colab-l4", "lanes":["tts"], "wait_s":1, "state_epoch":1000});
        let mut card = json!({"card":"colab-l4","worker_id":"colab-l4","epoch":1000,"stale":false,"seat":{"held":true},"session":{"state":"none"},"busy":{"by":"none"},"cu":{"balance":6.0},"gpu_class":"L4"});
        assert!(table
            .claim_available_agent(
                &request,
                &card,
                1000,
                &b,
                "lease-123",
                "2026-10-31T12:01:00Z"
            )
            .unwrap()
            .is_none());
        assert_eq!(table.jobs["job-123"]["state"], "queued");
        card["seat"]["held"] = json!(false);
        let response = table
            .claim_available_agent(
                &request,
                &card,
                1000,
                &b,
                "lease-123",
                "2026-10-31T12:01:00Z",
            )
            .unwrap()
            .unwrap();
        assert_eq!(response["job"]["job_id"], "job-123");
        assert_eq!(response["lease_id"], "lease-123");
        assert!(table
            .claim_available_agent(
                &request,
                &card,
                1000,
                &b,
                "lease-456",
                "2026-10-31T12:01:00Z"
            )
            .unwrap()
            .is_none());
    }

    #[test]
    fn claim_and_report_bind_the_lease_to_the_agent() {
        let root = std::env::temp_dir().join(format!(
            "agent-owner-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let boundary = segment_lifecycle::Boundary {
            root: &root,
            job_id: "job-123",
            ts: "2026-10-31T12:00:00Z",
            balance: 9.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":4, "lane":"tts", "gpu_class":"l4"}),
            10.0
        ));
        let lanes = vec!["tts".to_string()];
        let card = json!({"gpu_class":"L4"});
        assert!(table
            .claim_agent("agent-123", &lanes, &card, &boundary, "lease-123")
            .unwrap()
            .is_some());
        let mut request = json!({"schema_version":"agent-pull/v1", "agent_id":"agent-456", "worker_id":"colab-l4", "lanes":["tts"], "wait_s":1, "state_epoch":100, "report":{"lease_id":"lease-123", "job_id":"job-123", "segment":0, "exit_code":75, "done_items":["one"]}});
        assert!(!table.report_agent(&request, &boundary).unwrap());
        assert_eq!(table.jobs["job-123"]["state"], "leased");
        request["agent_id"] = json!("agent-123");
        assert!(table.report_agent(&request, &boundary).unwrap());
        assert!(!table.report_agent(&request, &boundary).unwrap());
        assert_eq!(table.jobs["job-123"]["state"], "queued");
        assert_eq!(table.jobs["job-123"]["done_items"], json!(["one"]));
        assert!(table.agent_owners.is_empty());
    }

    #[test]
    fn confirmed_loss_reclaims_same_job_and_invalidates_old_lease() {
        let root = std::env::temp_dir().join(format!(
            "reclaim-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let b = segment_lifecycle::Boundary {
            root: &root,
            job_id: "job-123",
            ts: "2026-10-31T12:00:00Z",
            balance: 9.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":3, "lane":"tts"}),
            10.0
        ));
        let lanes = vec!["tts".to_string()];
        assert!(table
            .claim_agent("agent-123", &lanes, &json!({}), &b, "lease-123")
            .unwrap()
            .is_some());
        assert!(!table.reclaim_agent("job-123", "lease-wrong", &b).unwrap());
        assert!(table.reclaim_agent("job-123", "lease-123", &b).unwrap());
        assert!(!table.reclaim_agent("job-123", "lease-123", &b).unwrap());
        assert_eq!(table.jobs.len(), 1);
        assert_eq!(table.jobs["job-123"]["resume_count"], 1);
        let (id, state) = table
            .claim_agent("agent-456", &lanes, &json!({}), &b, "lease-456")
            .unwrap()
            .unwrap();
        assert_eq!(id, "job-123");
        assert_eq!(state.segment, 1);
        let log = fs::read_to_string(root.join("job-123/cu.csv")).unwrap();
        assert!(log.contains("session-lost"));
    }

    #[test]
    fn reclaim_at_limit_fails_and_does_not_reassign() {
        let root = std::env::temp_dir().join(format!(
            "reclaim-limit-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let b = segment_lifecycle::Boundary {
            root: &root,
            job_id: "job-123",
            ts: "2026-10-31T12:00:00Z",
            balance: 9.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":1, "lane":"tts"}),
            10.0
        ));
        let lanes = vec!["tts".to_string()];
        table
            .claim_agent("agent-123", &lanes, &json!({}), &b, "lease-123")
            .unwrap()
            .unwrap();
        assert!(table.reclaim_agent("job-123", "lease-123", &b).unwrap());
        assert_eq!(
            table.jobs["job-123"]["reason"],
            crate::error_catalog::MAX_SEGS_EXCEEDED
        );
        assert!(table
            .claim_agent("agent-456", &lanes, &json!({}), &b, "lease-456")
            .unwrap()
            .is_none());
    }

    #[test]
    fn reclaim_ledger_failure_preserves_ownership() {
        let root = std::env::temp_dir().join(format!(
            "reclaim-error-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let b = segment_lifecycle::Boundary {
            root: &root,
            job_id: "job-123",
            ts: "2026-10-31T12:00:00Z",
            balance: 9.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        assert!(table.enqueue_agent(
            json!({"job_id":"job-123", "max_segs":3, "lane":"tts"}),
            10.0
        ));
        table.leases.assign(&b, "lease-123".into()).unwrap();
        table
            .agent_owners
            .insert("lease-123".into(), "agent-123".into());
        let bad = root.join("job-123/cu.csv/child");
        let bad_b = segment_lifecycle::Boundary { root: &bad, ..b };
        assert!(table.reclaim_agent("job-123", "lease-123", &bad_b).is_err());
        assert!(table.agent_owners.contains_key("lease-123"));
        assert_eq!(
            table.leases.snapshot("job-123").unwrap().phase,
            segment_lifecycle::Phase::Leased
        );
    }

    #[test]
    fn duplicate_lease_id_cannot_claim_another_job() {
        let root = std::env::temp_dir().join(format!(
            "agent-duplicate-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let boundary = segment_lifecycle::Boundary {
            root: &root,
            job_id: "unused",
            ts: "2026-10-31T12:00:00Z",
            balance: 9.0,
            floor: 5.0,
            gpu_class: "l4",
        };
        let mut table = JobTable::default();
        for id in ["job-123", "job-456"] {
            assert!(table.enqueue_agent(json!({"job_id":id, "max_segs":4, "lane":"tts"}), 10.0));
        }
        let lanes = vec!["tts".to_string()];
        assert!(table
            .claim_agent("agent-123", &lanes, &json!({}), &boundary, "lease-123")
            .unwrap()
            .is_some());
        assert!(table
            .claim_agent("agent-456", &lanes, &json!({}), &boundary, "lease-123")
            .unwrap()
            .is_none());
        assert_eq!(table.jobs["job-456"]["state"], "queued");
    }
}

#[cfg(test)]
mod run33_dispatch_tests {
    use super::*;
    fn fixed_clock() -> u64 {
        1000
    }
    fn worker() -> Worker {
        Worker {
            id: "local-2070".into(),
            lanes: vec!["render-blender".into()],
            kind: "exec".into(),
            exec: String::new(),
            dispatch: Value::Null,
            seats: 1,
            enabled: true,
            note: String::new(),
        }
    }
    fn fixture() -> (JobTable, Value) {
        let spec = json!({"job_id":"dispatch-fixture","lane":"render-blender","frames":"1-9","prefer":["local-2070"]});
        let mut table = JobTable {
            clock: Some(fixed_clock),
            ..JobTable::default()
        };
        table.jobs.insert(
            "dispatch-fixture".into(),
            queue_policy::admitted(&table.jobs, &spec, fixed_clock()),
        );
        (table, spec)
    }
    #[test]
    fn run33_s1_dispatch_determinism_three_runs() {
        let mut observations = Vec::new();
        for _ in 0..3 {
            let (mut table, spec) = fixture();
            let views = vec![json!({"id":"local-2070","accepting":true})];
            let (parts, seen) = plan_from_views(&spec, &[worker()], views).unwrap();
            assert_eq!(parts.len(), 1);
            assert_eq!((parts[0].1, parts[0].2), (1, 9));
            begin_dispatch(&mut table, "dispatch-fixture", &spec, &parts[0].0).unwrap();
            let row = &table.jobs["dispatch-fixture"];
            let events = row["device_events"]["1"].as_array().unwrap();
            assert_eq!(
                events
                    .iter()
                    .map(|event| event["state"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["dispatching", "running"]
            );
            assert!(events.iter().all(|event| event["at"] == 1000));
            observations.push(json!({"worker":parts[0].0.id,"views":seen,"row":row}));
        }
        assert_eq!(observations.len(), 3);
        assert!(observations.windows(2).all(|pair| pair[0] == pair[1]));
    }
    #[test]
    fn run33_s1_dispatch_refusal_preserves_state() {
        for (field, value, expected) in [
            ("lane", "unknown", error_catalog::UNKNOWN_LANE),
            ("type", "unknown", error_catalog::BAD_SPEC),
            ("worker", "unknown", error_catalog::WORKER_REFUSED),
        ] {
            let (mut table, mut spec) = fixture();
            let mut chosen = worker();
            if field == "worker" {
                chosen.kind = value.into();
            } else {
                spec[field] = json!(value);
            }
            let before = format!(
                "{:?}",
                (
                    &table.jobs,
                    &table.agent_queue,
                    &table.agent_owners,
                    &table.pids,
                    &table.cancel,
                    &table.busy,
                    table.queue_last
                )
            );
            assert_eq!(
                plan_from_views(
                    &spec,
                    &[chosen.clone()],
                    vec![json!({"id":"local-2070","accepting":true})]
                )
                .unwrap_err(),
                expected
            );
            assert_eq!(
                begin_dispatch(&mut table, "dispatch-fixture", &spec, &chosen),
                Err(expected)
            );
            assert!(error_catalog::TABLE
                .iter()
                .any(|entry| entry.code == expected));
            assert_eq!(
                format!(
                    "{:?}",
                    (
                        &table.jobs,
                        &table.agent_queue,
                        &table.agent_owners,
                        &table.pids,
                        &table.cancel,
                        &table.busy,
                        table.queue_last
                    )
                ),
                before
            );
            if field != "worker" {
                let shared = Arc::new(Mutex::new(table));
                let result = run_job(
                    shared.clone(),
                    spec.clone(),
                    serde_json::to_vec(&spec).unwrap(),
                    true,
                );
                assert_eq!(result["code"], expected);
                let table = shared.lock().unwrap();
                assert_eq!(
                    format!(
                        "{:?}",
                        (
                            &table.jobs,
                            &table.agent_queue,
                            &table.agent_owners,
                            &table.pids,
                            &table.cancel,
                            &table.busy,
                            table.queue_last
                        )
                    ),
                    before
                );
            }
        }
    }
}
