//! Dispatch kind contracts and adapter evidence verification.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[derive(Debug)]
pub struct Kind {
    pub name: &'static str,
    pub lanes: &'static [&'static str],
    pub argv: &'static [&'static str],
    pub script_flag: Option<&'static str>,
    pub id_flag: Option<&'static str>,
    pub budget_flag: Option<&'static str>,
    pub result_file: bool,
    pub spec_out: bool,
}
pub const KINDS: &[Kind] = &[
    Kind {
        name: "exec",
        lanes: crate::LANES,
        argv: &["--spec", "{spec}"],
        script_flag: None,
        id_flag: None,
        budget_flag: None,
        result_file: false,
        spec_out: true,
    },
    Kind {
        name: "adapter-tts",
        lanes: &["tts"],
        argv: &["--spec", "{spec}", "--out", "{delivery}"],
        script_flag: Some("--worker"),
        id_flag: None,
        budget_flag: Some("--deadline-seconds"),
        result_file: false,
        spec_out: false,
    },
    Kind {
        name: "adapter-diffusion",
        lanes: &["diffusion-image", "diffusion-video"],
        argv: &["--spec", "{spec}", "--out", "{delivery}"],
        script_flag: Some("--worker"),
        id_flag: Some("--worker-id"),
        budget_flag: Some("--timeout-secs"),
        result_file: true,
        spec_out: false,
    },
    Kind {
        name: "adapter-music-sfx",
        lanes: &["music-sfx"],
        argv: &["--job", "{spec}", "--out", "{delivery}"],
        script_flag: Some("--worker"),
        id_flag: Some("--worker-id"),
        budget_flag: Some("--budget-seconds"),
        result_file: false,
        spec_out: false,
    },
    Kind {
        name: "adapter-render-blender",
        lanes: &["render-blender"],
        argv: &["run", "--spec", "{spec}", "--worker", "{worker}"],
        script_flag: Some("--exec"),
        id_flag: None,
        budget_flag: Some("--timeout-secs"),
        result_file: false,
        spec_out: true,
    },
    Kind {
        name: "adapter-stt",
        lanes: &["stt"],
        argv: &["run", "--job", "{spec}", "--out", "{delivery}"],
        script_flag: Some("--worker-exec"),
        id_flag: Some("--worker"),
        budget_flag: Some("--timeout-secs"),
        result_file: true,
        spec_out: false,
    },
];
#[derive(Debug)]
pub struct Config {
    pub interpreter: String,
    pub grace_seconds: u64,
    pub body_max: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            interpreter: "/usr/bin/python3".into(),
            grace_seconds: 5,
            body_max: 65536,
        }
    }
}
impl Config {
    pub fn from_value(v: &Value) -> Self {
        let d = Self::default();
        Self {
            interpreter: v["interpreter"].as_str().unwrap_or(&d.interpreter).into(),
            grace_seconds: v["grace_seconds"].as_u64().unwrap_or(d.grace_seconds),
            body_max: d.body_max,
        }
    }
}
pub fn kind(name: &str) -> Result<&'static Kind, String> {
    KINDS
        .iter()
        .find(|r| r.name == name)
        .ok_or_else(|| format!("kind {name} has no dispatch path from this host yet"))
}
pub fn validate_job(v: &Value) -> Result<(), &'static str> {
    if !v.is_object()
        || !v["lane"]
            .as_str()
            .is_some_and(|l| crate::LANES.contains(&l))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if v.get("api").is_some_and(|a| a != crate::API)
        || v.get("job_id")
            .filter(|v| !v.is_null())
            .is_some_and(|id| !id.as_str().is_some_and(crate::result_store::valid_id))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if serde_json::to_vec(v)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?
        .len()
        > Config::default().body_max
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::REQUEST_TOO_LARGE,
        ));
    }
    Ok(())
}
pub fn part_name(worker: &str, whole: bool, first: u64, last: u64) -> String {
    if whole {
        format!("{worker}-bake")
    } else {
        format!("{worker}-{first}-{last}")
    }
}
pub fn fresh_output(path: &Path) -> Result<(), &'static str> {
    if path.exists()
        && (!path.is_dir()
            || fs::read_dir(path)
                .map(|mut d| d.next().is_some())
                .unwrap_or(true))
    {
        return Err("out exists and is not empty");
    }
    Ok(())
}
pub fn build_spec(job: &Value, out: Option<&str>) -> Value {
    let mut sub = job.clone();
    if let Some(out) = out {
        sub["out"] = json!(out);
    }
    if let Some(o) = sub.as_object_mut() {
        o.remove("prefer");
        o.remove("split_across_workers");
    }
    sub
}
pub(crate) fn absolute(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_owned()
    } else {
        std::env::current_dir().unwrap().join(p)
    }
}
#[allow(clippy::too_many_arguments)]
pub fn command(
    row: &Kind,
    exec: &str,
    worker: &str,
    options: &Value,
    spec: &Path,
    delivery: &Path,
    budget: f64,
    dry: bool,
) -> Result<Command, &'static str> {
    let cfg = Config::from_value(options);
    if dry && row.name != "exec" {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ADAPTER_DRY_RUN_UNSUPPORTED,
        ));
    }
    let entry = if row.name == "exec" {
        PathBuf::from(exec)
    } else {
        options["entry"]
            .as_str()
            .map(PathBuf::from)
            .ok_or_else(|| {
                crate::error_catalog::reason(crate::error_catalog::ADAPTER_ENTRY_UNSET)
            })?
    };
    if !entry.is_file() {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ADAPTER_ENTRY_UNSET,
        ));
    }
    let mut cmd = if row.name != "exec" && entry.extension().is_some_and(|s| s == "py") {
        let mut c = Command::new(&cfg.interpreter);
        c.arg(absolute(&entry));
        c
    } else {
        Command::new(absolute(&entry))
    };
    for arg in row.argv {
        match *arg {
            "{spec}" => {
                cmd.arg(absolute(spec));
            }
            "{delivery}" => {
                cmd.arg(absolute(delivery));
            }
            "{worker}" => {
                cmd.arg(worker);
            }
            other => {
                cmd.arg(other);
            }
        }
    }
    if let Some(flag) = row.script_flag {
        if Path::new(exec).is_file() && Path::new(exec) != entry {
            cmd.arg(flag).arg(absolute(Path::new(exec)));
        }
    }
    if let Some(flag) = row.id_flag {
        cmd.arg(flag).arg(worker);
    }
    if let Some(flag) = row.budget_flag {
        cmd.arg(flag).arg(if flag == "--timeout-secs" {
            (budget.max(0.0).floor() as u64).to_string()
        } else {
            budget.to_string()
        });
    }
    if dry && row.name == "exec" {
        cmd.arg("--dry-run");
    }
    Ok(cmd)
}
pub fn clamp(rc: i64) -> i64 {
    if [0, 1, 2, 124].contains(&rc) {
        rc
    } else {
        1
    }
}
pub fn rc_state(rc: i64) -> &'static str {
    match rc {
        0 => "done",
        2 => "refused",
        124 => "timed_out",
        _ => "failed",
    }
}
fn attempt_state(s: &str) -> bool {
    [
        "dispatching",
        "running",
        "done",
        "failed",
        "refused",
        "timed_out",
        "cancelled",
    ]
    .contains(&s)
}
fn result_doc(v: &Value) -> bool {
    v["api"] == crate::API
        && v["attempts"].is_array()
        && v["job_id"].is_string()
        && crate::deadline::STATES.contains(&v["state"].as_str().unwrap_or(""))
}
pub fn map_attempt(
    raw: i64,
    device: &Value,
    result: &Value,
    dispatched: bool,
    envelope: Option<&str>,
) -> (String, i64, Option<String>) {
    let mut rc = clamp(raw);
    let mut state = rc_state(rc).to_owned();
    let mut reason = envelope.map(str::to_owned);
    if let Some(s) = device["state"].as_str().filter(|s| attempt_state(s)) {
        state = s.into();
    }
    if device["timed_out"] == true {
        state = "timed_out".into();
        rc = 124;
    } else if let Some(n) = device["rc"].as_i64().filter(|n| [0, 1, 2, 124].contains(n)) {
        rc = n;
    }
    if result_doc(result) {
        if let Some(a) = result["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|a| a["state"].as_str().is_some_and(attempt_state))
        {
            state = a["state"].as_str().unwrap().into();
            if let Some(n) = a["rc"].as_i64().filter(|n| [0, 1, 2, 124].contains(n)) {
                rc = n;
            }
            if let Some(s) = a["reason"].as_str() {
                reason = Some(s.into());
            }
        }
    } else if rc == 2 && !dispatched {
        state = "refused".into();
    }
    reason = reason.filter(|s| crate::result_store::valid_id(s));
    (state, rc, reason)
}
fn json_documents(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let Some((index, _)) = text[offset..]
            .char_indices()
            .find(|(_, c)| matches!(c, '{' | '['))
        else {
            break;
        };
        offset += index;
        let mut stream = serde_json::Deserializer::from_str(&text[offset..]).into_iter::<Value>();
        match stream.next() {
            Some(Ok(v)) => {
                out.push(v);
                offset += stream.byte_offset();
            }
            _ => offset += 1,
        }
    }
    out
}
fn safe(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.starts_with('/')
        && name
            .split('/')
            .all(|p| !p.is_empty() && !p.starts_with('.'))
}
fn contained(root: &Path, p: &Path) -> Result<(), &'static str> {
    if fs::symlink_metadata(root)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?
        .file_type()
        .is_symlink()
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ARTIFACT_MISMATCH,
        ));
    }
    let base = root
        .canonicalize()
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?;
    let resolved = p
        .canonicalize()
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?;
    if !resolved.starts_with(base) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ARTIFACT_MISMATCH,
        ));
    }
    let mut ancestor = Some(p);
    while let Some(a) = ancestor {
        if a == root {
            break;
        }
        if fs::symlink_metadata(a)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?
            .file_type()
            .is_symlink()
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::ARTIFACT_MISMATCH,
            ));
        }
        ancestor = a.parent();
    }
    Ok(())
}
fn sums(dir: &Path) -> Result<BTreeMap<String, String>, &'static str> {
    let p = dir.join("SHA256SUMS");
    contained(dir, &p)?;
    let text = fs::read_to_string(p)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?;
    let mut rows = BTreeMap::new();
    for line in text.lines().filter(|s| !s.trim().is_empty()) {
        let (sha, path) = line
            .split_once("  ")
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?;
        if sha.len() != 64
            || !sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !safe(path)
            || rows.insert(path.into(), sha.into()).is_some()
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::ARTIFACT_MISMATCH,
            ));
        }
    }
    Ok(rows)
}
fn contract_path(lane: &str, path: &str) -> bool {
    crate::result_store::allowed_artifact(lane, path)
}
pub fn verify_delivery(delivery: &Path, lane: &str) -> Result<Vec<Value>, &'static str> {
    let mut rows = BTreeMap::new();
    let parts = delivery.join("parts");
    contained(delivery, &parts)?;
    for entry in fs::read_dir(&parts)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?
    {
        let dir = entry
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH))?
            .path();
        contained(delivery, &dir)?;
        if !dir.is_dir() {
            continue;
        }
        for (path, sha) in sums(&dir)? {
            let base = Path::new(&path).file_name().unwrap().to_string_lossy();
            if base.starts_with('_')
                || base.ends_with(".log")
                || [
                    "manifest.json",
                    "device.json",
                    "result.json",
                    "worker-result.json",
                ]
                .contains(&base.as_ref())
            {
                continue;
            }
            if !contract_path(lane, &path) {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::ARTIFACT_MISMATCH,
                ));
            }
            let p = dir.join(&path);
            contained(delivery, &p)?;
            let data = fs::read(&p).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH)
            })?;
            if data.is_empty()
                || data.len() > 67108864
                || hex::encode(Sha256::digest(&data)) != sha
                || rows.contains_key(&path)
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::ARTIFACT_MISMATCH,
                ));
            }
            rows.insert(
                path.clone(),
                json!({"path":path,"bytes":data.len(),"sha256":sha,"source":p}),
            );
        }
    }
    if rows.is_empty() || rows.len() > 8 {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ARTIFACT_MISMATCH,
        ));
    }
    if delivery.join("SHA256SUMS").exists() {
        let claimed = sums(delivery)?;
        let actual: BTreeMap<_, _> = rows
            .iter()
            .map(|(p, a)| (p.clone(), a["sha256"].as_str().unwrap().to_owned()))
            .collect();
        if claimed != actual {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::ARTIFACT_MISMATCH,
            ));
        }
    }
    Ok(rows.into_values().collect())
}
pub fn delivery_gap(row: &Kind, dispatched: bool, device: &Value) -> bool {
    row.name != "exec" && dispatched && !device.is_object()
}
pub fn collect(
    row: &Kind,
    lane: &str,
    delivery: &Path,
    part: &Path,
    log: &Path,
    raw: i64,
) -> Value {
    let read = |p: &Path| {
        if contained(delivery, p).is_err() {
            Value::Null
        } else {
            fs::read(p)
                .ok()
                .and_then(|d| crate::lane_gate::parse(&d).ok())
                .unwrap_or(Value::Null)
        }
    };
    let device = read(&delivery.join("attempts/1/device.json"));
    let docs = json_documents(&fs::read_to_string(log).unwrap_or_default());
    let mut result = if row.result_file {
        read(&delivery.join("result.json"))
    } else {
        Value::Null
    };
    if !result_doc(&result) {
        result = docs
            .iter()
            .rev()
            .find(|d| result_doc(d))
            .cloned()
            .unwrap_or(Value::Null);
    }
    let dispatched = delivery.join("parts").is_dir()
        && fs::read_dir(delivery.join("parts"))
            .ok()
            .is_some_and(|mut d| d.next().is_some());
    let code = docs.iter().rev().find_map(|d| d["code"].as_str());
    let (mut state, mut rc, mut reason) = map_attempt(raw, &device, &result, dispatched, code);
    if delivery_gap(row, dispatched, &device) && !matches!(state.as_str(), "timed_out" | "refused")
    {
        state = "failed".into();
        rc = 1;
        reason = Some(crate::error_catalog::ARTIFACT_MISMATCH.into());
    }
    if result.get("cartridge").is_some_and(|v| {
        !v.as_str().is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        })
    }) {
        state = "failed".into();
        rc = 1;
        reason = Some(crate::error_catalog::ARTIFACT_MISMATCH.into());
    }
    if state == "done" && row.name != "exec" {
        let normalized = (|| {
            let arts = verify_delivery(delivery, lane)?;
            fs::create_dir_all(part).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH)
            })?;
            let mut sidecar = String::new();
            for art in arts {
                let name = art["path"].as_str().unwrap();
                let dst = part.join(name);
                fs::create_dir_all(dst.parent().unwrap()).map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH)
                })?;
                fs::copy(art["source"].as_str().unwrap(), &dst).map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH)
                })?;
                sidecar.push_str(&format!("{}  {name}\n", art["sha256"].as_str().unwrap()));
            }
            fs::write(part.join("SHA256SUMS"), sidecar).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH)
            })?;
            if let Some(frames) = result.get("frames").or_else(|| device.get("frames")) {
                fs::write(
                    part.join("manifest.json"),
                    serde_json::to_vec(&json!({"frames":frames})).unwrap(),
                )
                .map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::ARTIFACT_MISMATCH)
                })?;
            }
            Ok::<(), &'static str>(())
        })();
        if let Err(code) = normalized {
            state = "failed".into();
            rc = 1;
            reason = Some(code.into());
        }
    }
    json!({"state":state,"rc":rc,"raw_rc":raw,"reason":reason,"adapter_device_log":device,"result_doc":result,"dispatched":dispatched})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    struct Fixture {
        root: PathBuf,
        lane: String,
        delivery: PathBuf,
        part: PathBuf,
        script: PathBuf,
        spec: PathBuf,
        log: PathBuf,
    }
    impl Fixture {
        fn new(lane: &str) -> Self {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "dispatch-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let delivery = root.join("delivery");
            let part = root.join("normalized");
            fs::create_dir_all(&root).unwrap();
            let script = root.join("adapter.sh");
            let spec = root.join("input.json");
            let log = root.join("adapter.log");
            fs::write(
                &spec,
                serde_json::to_vec(
                    &json!({"api":crate::API,"lane":lane,"job_id":"job-1","out":delivery}),
                )
                .unwrap(),
            )
            .unwrap();
            fs::write(&log, b"").unwrap();
            Self {
                root,
                lane: lane.into(),
                delivery,
                part,
                script,
                spec,
                log,
            }
        }
        fn paths(&self) -> Vec<String> {
            match self.lane.as_str() {
                "render-blender" => (1..=6).map(|n| format!("frame_{n:04}.png")).collect(),
                "tts" => vec!["speech.wav".into()],
                "stt" => vec!["transcript.json".into()],
                "diffusion-image" => vec!["image.png".into()],
                "diffusion-video" => vec!["video.mp4".into()],
                _ => vec!["audio.wav".into(), "stems/drums.wav".into()],
            }
        }
        fn delivery(&self) {
            let part = self.delivery.join("parts/one");
            fs::create_dir_all(&part).unwrap();
            let sha = hex::encode(Sha256::digest(b"payload"));
            let mut sums = String::new();
            for p in self.paths() {
                fs::create_dir_all(part.join(&p).parent().unwrap()).unwrap();
                fs::write(part.join(&p), b"payload").unwrap();
                sums.push_str(&format!("{sha}  {p}\n"));
            }
            fs::write(part.join("SHA256SUMS"), &sums).unwrap();
            fs::write(self.delivery.join("SHA256SUMS"), &sums).unwrap();
            fs::create_dir_all(self.delivery.join("attempts/1")).unwrap();
            fs::write(
                self.delivery.join("attempts/1/device.json"),
                br#"{"state":"done","rc":0}"#,
            )
            .unwrap();
        }
        fn script(&self) {
            let source = self.root.join("template");
            self.delivery();
            fs::rename(&self.delivery, &source).unwrap();
            let script=format!("#!/bin/sh\nif [ \"$1\" = --health ]; then\n printf '%s\\n' '{{\"accepting\":true,\"proof\":{{\"pass\":true}},\"vram_mb\":8,\"ram_mb\":8,\"backends\":[\"cpu\"],\"cartridges\":[\"blender-4.5.14-cycles\"]}}'\n exit 0\nfi\ncp -R '{}' '{}'\n",source.display(),self.delivery.display());
            fs::write(&self.script, script).unwrap();
            fs::set_permissions(&self.script, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fn row(&self) -> &'static Kind {
            kind(match self.lane.as_str() {
                "tts" => "adapter-tts",
                "stt" => "adapter-stt",
                "render-blender" => "adapter-render-blender",
                "music-sfx" => "adapter-music-sfx",
                _ => "adapter-diffusion",
            })
            .unwrap()
        }
        fn run(&self) -> Value {
            self.script();
            let mut cmd = command(
                self.row(),
                "/bin/true",
                "fixture",
                &json!({"entry":self.script}),
                &self.spec,
                &self.delivery,
                5.0,
                false,
            )
            .unwrap();
            let result = cmd.output().unwrap();
            fs::write(&self.log, result.stdout).unwrap();
            collect(
                self.row(),
                &self.lane,
                &self.delivery,
                &self.part,
                &self.log,
                result.status.code().unwrap_or(-1) as i64,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn defaults() {
        let c = Config::from_value(&Value::Null);
        assert_eq!(
            (c.interpreter.as_str(), c.grace_seconds, c.body_max),
            ("/usr/bin/python3", 5, 65536)
        );
    }
    #[test]
    fn test_flat_lanes() {
        for lane in [
            "tts",
            "stt",
            "diffusion-image",
            "diffusion-video",
            "music-sfx",
        ] {
            let f = Fixture::new(lane);
            let o = f.run();
            assert_eq!(o["state"], "done", "{lane}: {o}");
            let arts = verify_delivery(&f.delivery, lane).unwrap();
            assert_eq!(arts.len(), f.paths().len());
            for a in arts {
                let data = fs::read(f.part.join(a["path"].as_str().unwrap())).unwrap();
                assert_eq!(a["sha256"], hex::encode(Sha256::digest(data)));
            }
        }
    }
    #[test]
    fn test_render_blender_lane() {
        let f = Fixture::new("render-blender");
        assert_eq!(f.run()["state"], "done");
        assert_eq!(
            verify_delivery(&f.delivery, "render-blender")
                .unwrap()
                .len(),
            6
        );
    }
    #[test]
    fn test_exec_dispatch_through_fake_worker() {
        let f = Fixture::new("render-blender");
        f.script();
        let c = command(
            kind("exec").unwrap(),
            f.script.to_str().unwrap(),
            "fixture",
            &Value::Null,
            &f.spec,
            &f.delivery,
            5.0,
            false,
        )
        .unwrap();
        assert_eq!(
            c.get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["--spec".into(), f.spec.to_string_lossy().into_owned()]
        );
        let output = {
            let mut c = c;
            c.output().unwrap()
        };
        assert!(output.status.success());
        assert_eq!(
            collect(
                kind("exec").unwrap(),
                "render-blender",
                &f.delivery,
                &f.part,
                &f.log,
                0
            )["state"],
            "done"
        );
        assert_eq!(
            verify_delivery(&f.delivery, "render-blender")
                .unwrap()
                .len(),
            6
        );
    }
    #[test]
    fn test_rc_1_failed() {
        assert_eq!(
            map_attempt(1, &Value::Null, &Value::Null, false, None),
            ("failed".into(), 1, None)
        );
    }
    #[test]
    fn test_rc_2_refused() {
        assert_eq!(
            map_attempt(
                2,
                &Value::Null,
                &Value::Null,
                false,
                Some(crate::error_catalog::BAD_SPEC)
            ),
            (
                "refused".into(),
                2,
                Some(crate::error_catalog::BAD_SPEC.into())
            )
        );
    }
    #[test]
    fn test_rc_124_timed_out() {
        assert_eq!(
            map_attempt(124, &Value::Null, &Value::Null, false, None),
            ("timed_out".into(), 124, None)
        );
    }
    #[test]
    fn test_tampered_tts_part_fails_verification() {
        let f = Fixture::new("tts");
        f.delivery();
        fs::write(f.delivery.join("parts/one/speech.wav"), b"changed").unwrap();
        assert_eq!(
            verify_delivery(&f.delivery, "tts"),
            Err(crate::error_catalog::ARTIFACT_MISMATCH)
        );
    }
    #[test]
    fn test_tampered_exec_part_fails_verification() {
        let f = Fixture::new("render-blender");
        f.delivery();
        fs::write(f.delivery.join("parts/one/frame_0001.png"), b"changed").unwrap();
        assert_eq!(
            verify_delivery(&f.delivery, "render-blender"),
            Err(crate::error_catalog::ARTIFACT_MISMATCH)
        );
    }
    #[test]
    fn test_lying_worker_ends_failed() {
        let f = Fixture::new("tts");
        f.delivery();
        fs::write(f.delivery.join("parts/one/speech.wav"), b"changed").unwrap();
        let o = collect(f.row(), "tts", &f.delivery, &f.part, &f.log, 0);
        assert_eq!(o["state"], "failed");
        assert_eq!(o["rc"], 1);
        assert_eq!(o["reason"], crate::error_catalog::ARTIFACT_MISMATCH);
    }
    #[test]
    fn test_forged_job_sidecar_fails_verification() {
        let f = Fixture::new("tts");
        f.delivery();
        let sha = hex::encode(Sha256::digest(b"payload"));
        fs::write(
            f.delivery.join("SHA256SUMS"),
            format!("{sha}  speech.wav\n{sha}  extra.wav\n"),
        )
        .unwrap();
        assert_eq!(
            verify_delivery(&f.delivery, "tts"),
            Err(crate::error_catalog::ARTIFACT_MISMATCH)
        );
    }
    #[test]
    fn test_missing_device_log_is_a_delivery_gap() {
        assert!(delivery_gap(
            kind("adapter-tts").unwrap(),
            true,
            &Value::Null
        ));
        assert!(!delivery_gap(
            kind("adapter-tts").unwrap(),
            false,
            &Value::Null
        ));
        assert!(!delivery_gap(kind("exec").unwrap(), true, &Value::Null));
    }
    #[test]
    fn test_unknown_kind_refused_with_s01_message() {
        assert_eq!(
            kind("unknown").unwrap_err(),
            "kind unknown has no dispatch path from this host yet"
        );
    }
    #[test]
    fn test_disabled_worker_refused() {
        let w = crate::Worker {
            id: "fixture".into(),
            lanes: vec!["tts".into()],
            kind: "adapter-tts".into(),
            exec: "/bin/true".into(),
            dispatch: Value::Null,
            seats: 1,
            enabled: false,
            note: "fixture".into(),
        };
        let v = crate::worker_view(&w, "tts", &HashMap::new());
        assert_eq!(v["accepting"], false);
        assert!(v["why_not"]
            .as_array()
            .unwrap()
            .contains(&json!("disabled in registry: fixture")));
    }
    #[test]
    fn test_kind_table_names_every_entry_point() {
        assert_eq!(KINDS.len(), 6);
        for row in KINDS {
            assert!(!row.lanes.is_empty());
            let f = Fixture::new(row.lanes[0]);
            f.script();
            let c = command(
                row,
                f.script.to_str().unwrap(),
                "fixture",
                &json!({"entry":f.script}),
                &f.spec,
                &f.delivery,
                5.0,
                false,
            )
            .unwrap();
            let argv: Vec<_> = c
                .get_args()
                .map(|s| s.to_string_lossy().into_owned())
                .collect();
            assert!(argv.contains(&f.spec.to_string_lossy().into_owned()));
            if row.name != "exec" {
                assert!(row.budget_flag.is_some());
            }
            assert_eq!(
                row.spec_out,
                matches!(row.name, "exec" | "adapter-render-blender")
            );
        }
    }
    fn stored(failed: bool) {
        let f = Fixture::new("tts");
        f.delivery();
        let store = crate::result_store::Store::new(
            &f.root.join("store"),
            crate::result_store::Config::default(),
        );
        let sha = store.put_artifact("tts", b"payload", None).unwrap();
        let r = json!({"lane":"tts","job_id":"job-1","cartridge":"fixture","state":if failed{"failed"}else{"done"},"artifacts":[{"path":"speech.wav","bytes":7,"sha256":sha}],"chunks":[{"worker":"fixture","rc":if failed{1}else{0}}],"error":if failed{json!({"code":crate::error_catalog::ARTIFACT_MISMATCH,"retryable":false})}else{Value::Null}});
        let v = crate::result_store::snapshot(&r, 1000);
        let docs = if failed {
            BTreeMap::new()
        } else {
            BTreeMap::from([("manifest.json".into(), crate::result_store::canonical(&v))])
        };
        let m = store.put_job("tts", "job-1", &v, &docs, 1000).unwrap();
        assert_eq!(store.get_job("tts", "job-1").unwrap(), v);
        if !failed {
            let bytes = store.get_document("tts", "job-1", "manifest.json").unwrap();
            assert_eq!(
                m["documents"]["manifest"],
                hex::encode(Sha256::digest(bytes))
            );
        }
        assert_eq!(v.as_object().unwrap().len(), 17);
    }
    #[test]
    fn test_snapshot_and_attempts_match_the_store() {
        stored(false);
    }
    #[test]
    fn test_failed_snapshot_matches_the_store() {
        stored(true);
    }
    #[test]
    fn test_attempt_rows_are_json_not_strings() {
        let f = Fixture::new("tts");
        let o = f.run();
        let mut row = json!({"lane":"tts","job_id":"job-1","state":"queued","chunks":[{"dispatch_observation":o}]});
        crate::deadline::dispatch(&mut row, "fixture", 1000).unwrap();
        crate::deadline::accept(&mut row, 1000).unwrap();
        crate::deadline::report(&mut row, 0, None, 1000).unwrap();
        crate::deadline::write_devices(&f.root, &row).unwrap();
        let v: Value = serde_json::from_slice(
            &fs::read(f.root.join("lanes/tts/jobs/job-1/attempts/1/device.json")).unwrap(),
        )
        .unwrap();
        assert!(v["rc"].is_number());
        assert!(v["observation"]["raw_rc"].is_number());
        assert!(row["attempts"][0].is_object());
    }
    #[test]
    fn test_second_attempt_appends() {
        let mut row = json!({"lane":"tts","job_id":"job-1","state":"queued"});
        crate::deadline::dispatch(&mut row, "worker-a", 1000).unwrap();
        crate::deadline::accept(&mut row, 1000).unwrap();
        crate::deadline::report(&mut row, 1, Some("worker-b"), 1000).unwrap();
        crate::deadline::accept(&mut row, 1000).unwrap();
        crate::deadline::report(&mut row, 0, None, 1000).unwrap();
        assert_eq!(row["attempts"].as_array().unwrap().len(), 2);
        assert_eq!(row["attempts"][0]["state"], "failed");
        assert_eq!(row["attempts"][1]["state"], "done");
        assert!(crate::deadline::dispatch(&mut row, "worker-c", 1000).is_err());
    }
    #[test]
    fn test_no_socket_or_http_import() {
        let source = include_str!("dispatch_kinds.rs");
        assert!(!source
            .lines()
            .any(|line| line.trim_start().starts_with("use std::net")));
        assert!(!source
            .lines()
            .any(|line| line.trim_start().starts_with("use reqwest")));
    }
    #[test]
    fn qc_invalid_artifact_name_fails_closed() {
        let f = Fixture::new("tts");
        f.delivery();
        let part = f.delivery.join("parts/one");
        fs::rename(part.join("speech.wav"), part.join("bonus.bin")).unwrap();
        let sha = hex::encode(Sha256::digest(b"payload"));
        fs::write(part.join("SHA256SUMS"), format!("{sha}  bonus.bin\n")).unwrap();
        let o = collect(f.row(), "tts", &f.delivery, &f.part, &f.log, 0);
        assert_eq!(o["state"], "failed");
        assert_eq!(o["reason"], crate::error_catalog::ARTIFACT_MISMATCH);
    }
    #[test]
    fn qc_invalid_identity_fails_closed() {
        assert_eq!(
            validate_job(&json!({"lane":"tts","job_id":"NOT-A-VALID-ID"})),
            Err(crate::error_catalog::BAD_SPEC)
        );
        let f = Fixture::new("tts");
        f.delivery();
        fs::write(&f.log,br#"{"api":"service-lane/v1","job_id":"job-1","state":"done","cartridge":"INVALID","attempts":[{"state":"done","rc":0}]}"#).unwrap();
        assert_eq!(
            collect(f.row(), "tts", &f.delivery, &f.part, &f.log, 0)["state"],
            "failed"
        );
    }
    #[test]
    fn qc_device_log_overrides_process_rc() {
        assert_eq!(
            map_attempt(
                1,
                &json!({"state":"timed_out","rc":124}),
                &Value::Null,
                true,
                None
            )
            .0,
            "timed_out"
        );
        assert_eq!(
            map_attempt(0, &json!({"timed_out":true}), &Value::Null, true, None).1,
            124
        );
    }
    #[test]
    fn qc_result_overrides_device_and_rc() {
        let doc = json!({"api":crate::API,"job_id":"job-1","state":"failed","attempts":[{"state":"refused","rc":2,"reason":crate::error_catalog::BAD_SPEC}]});
        assert_eq!(
            map_attempt(0, &json!({"state":"done","rc":0}), &doc, true, None),
            (
                "refused".into(),
                2,
                Some(crate::error_catalog::BAD_SPEC.into())
            )
        );
    }
    #[test]
    fn qc_predispatch_refusal_requires_rc_two() {
        for rc in [1, 124, -9] {
            assert_ne!(
                map_attempt(rc, &Value::Null, &Value::Null, false, None).0,
                "refused"
            );
        }
        assert_eq!(
            map_attempt(2, &json!({"state":"done"}), &Value::Null, false, None).0,
            "refused"
        );
        assert_eq!(
            map_attempt(2, &json!({"state":"done"}), &Value::Null, true, None).0,
            "done"
        );
    }
    #[test]
    fn strict_json_rejects_duplicate_and_nonfinite() {
        for raw in [
            br#"{"x":1,"x":2}"#.as_slice(),
            br#"{"x":NaN}"#,
            br#"{"x":Infinity}"#,
        ] {
            assert!(crate::lane_gate::parse(raw).is_err());
        }
    }
    #[test]
    fn adapter_kind_uses_real_dispatch_path() {
        let mut f = Fixture::new("tts");
        let out = f.root.join("out");
        f.delivery = out.join("parts/fixture-bake/delivery");
        f.script();
        crate::command_policy::fixture_allow(&f.script);
        let files = f.root.join("files");
        fs::create_dir_all(&files).unwrap();
        fs::write(files.join("weights"), b"fixture").unwrap();
        let manifest = f.root.join("cartridge.json");
        fs::write(&manifest,serde_json::to_vec(&json!({"id":"fixture","lane":"tts","size_bytes":7,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"fixture"))}})).unwrap()).unwrap();
        let spec = json!({"lane":"tts","job_id":"job-1","text":"fixture","out":out,"cartridge":"fixture","cartridge_manifest":manifest,"cartridge_directory":files});
        let worker = crate::Worker {
            id: "fixture".into(),
            lanes: vec!["tts".into()],
            kind: "adapter-tts".into(),
            exec: f.script.to_string_lossy().into_owned(),
            dispatch: json!({"entry":f.script}),
            seats: 1,
            enabled: true,
            note: String::new(),
        };
        let table = std::sync::Arc::new(std::sync::Mutex::new(crate::JobTable::default()));
        let result = crate::run_chunk(
            &table,
            "job-1",
            &spec,
            &worker,
            0,
            0,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            false,
            false,
        );
        assert_eq!(result["state"], "done", "{result}");
        assert_eq!(result["rc"], 0);
        let args = result["dispatch_observation"]["argv"].as_array().unwrap();
        assert!(args.contains(&json!("--out")));
        assert!(args.contains(&json!("--deadline-seconds")));
        assert_eq!(
            fs::read(out.join("parts/fixture-bake/speech.wav")).unwrap(),
            b"payload"
        );
    }
}
