//! Lane-scoped, content-addressed results with immutable terminal documents.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
static LOCK: Mutex<()> = Mutex::new(());
static NEXT: AtomicU64 = AtomicU64::new(0);
const DAY: u64 = 86400;
pub mod worker_log;
type Result<T> = std::result::Result<T, &'static str>;
fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
pub fn canonical(v: &Value) -> Vec<u8> {
    let mut data = serde_json::to_vec_pretty(v).expect("JSON value");
    data.push(b'\n');
    data
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && Path::new(s)
            .components()
            .all(|c| matches!(c,Component::Normal(v) if !v.to_string_lossy().starts_with('.')))
        && !s.contains("//")
        && !s.ends_with('/')
}
fn artifact_name(path: &Path) -> Result<&str> {
    let name = path.to_str().ok_or(crate::error_catalog::PATH_UNSAFE)?;
    if !safe_path(name) {
        return Err(crate::error_catalog::PATH_UNSAFE);
    }
    Ok(name)
}
pub fn allowed_artifact(lane: &str, path: &str) -> bool {
    contract_path(lane, path)
}
fn contract_path(lane: &str, s: &str) -> bool {
    if !safe_path(s) {
        return false;
    }
    if lane == "render-blender" {
        return s
            .strip_prefix("frame_")
            .and_then(|s| s.strip_suffix(".png"))
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    }
    if s == match lane {
        "tts" => "speech.wav",
        "stt" => "transcript.json",
        "diffusion-image" => "image.png",
        "diffusion-video" => "video.mp4",
        "music-sfx" => "audio.wav",
        _ => "",
    } {
        return true;
    }
    lane == "music-sfx"
        && s.strip_prefix("stems/")
            .and_then(|s| s.strip_suffix(".wav").or_else(|| s.strip_suffix(".flac")))
            .is_some_and(valid_id)
}
#[derive(Clone)]
pub struct Config {
    pub artifact_max: usize,
    pub doc_max: usize,
    pub meta_max: usize,
    pub stale_tmp: u64,
    pub legacy_paths: bool,
    pub worker_log_max: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            artifact_max: 67108864,
            doc_max: 65536,
            meta_max: 4096,
            stale_tmp: 86400,
            legacy_paths: false,
            worker_log_max: 65536,
        }
    }
}
impl Config {
    pub fn from_value(v: &Value) -> Self {
        let d = Self::default();
        Self {
            worker_log_max: v["result_storage"]["worker_log_max_bytes"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(d.worker_log_max)
                .clamp(1, 16 * 1024 * 1024),
            stale_tmp: v["result_storage"]["stale_tmp_seconds"]
                .as_u64()
                .unwrap_or(d.stale_tmp),
            ..d
        }
    }
}
#[derive(Clone)]
pub struct Store {
    root: PathBuf,
    cfg: Config,
}
impl Store {
    pub fn new(root: &Path, cfg: Config) -> Self {
        Self {
            root: if root.is_absolute() {
                root.to_owned()
            } else {
                std::env::current_dir().unwrap().join(root)
            },
            cfg,
        }
    }
    pub fn legacy_paths(&self) -> bool {
        self.cfg.legacy_paths
    }
    fn contain(&self, p: &Path) -> Result<()> {
        if !p.starts_with(&self.root) || p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::PATH_UNSAFE,
            ));
        }
        let mut ancestor = Some(p);
        while let Some(path) = ancestor {
            match fs::symlink_metadata(path) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(crate::error_catalog::reason(
                        crate::error_catalog::PATH_UNSAFE,
                    ))
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(crate::error_catalog::reason(
                        crate::error_catalog::STORAGE_UNAVAILABLE,
                    ))
                }
            };
            ancestor = path.parent();
        }
        Ok(())
    }
    fn lane(&self, lane: &str) -> Result<PathBuf> {
        if !crate::LANES.contains(&lane) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::UNKNOWN_LANE,
            ));
        }
        let p = self.root.join("lanes").join(lane);
        self.contain(&p)?;
        Ok(p)
    }
    fn job(&self, lane: &str, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::NO_SUCH_JOB,
            ));
        }
        let p = self.lane(lane)?.join("jobs").join(id);
        self.contain(&p)?;
        Ok(p)
    }
    fn blob(&self, lane: &str, sha: &str) -> Result<PathBuf> {
        if !valid_sha(sha) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::BAD_DIGEST,
            ));
        }
        let p = self.lane(lane)?.join("blobs").join(&sha[..2]).join(sha);
        self.contain(&p)?;
        Ok(p)
    }
    fn atomic(&self, p: &Path, data: &[u8]) -> Result<()> {
        self.atomic_hook(p, data, |_| {})
    }
    fn atomic_hook(&self, p: &Path, data: &[u8], hook: impl FnOnce(&Path)) -> Result<()> {
        self.contain(p)?;
        let tmpdir = self.root.join("tmp");
        self.contain(&tmpdir)?;
        fs::create_dir_all(
            p.parent()
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::PATH_UNSAFE))?,
        )
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))?;
        fs::create_dir_all(&tmpdir)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))?;
        let tmp = tmpdir.join(format!(
            "write-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })?;
            f.write_all(data).and_then(|()| f.sync_all()).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })?;
            drop(f);
            hook(&tmp);
            self.contain(&tmp)?;
            if digest(&fs::read(&tmp).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })?) != digest(data)
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::STORAGE_UNAVAILABLE,
                ));
            }
            self.contain(p)?;
            fs::rename(&tmp, p).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })?;
            fs::File::open(p.parent().unwrap())
                .and_then(|f| f.sync_all())
                .map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })
        })();
        let _ = fs::remove_file(tmp);
        result
    }
    fn put_named_artifact(
        &self,
        lane: &str,
        name: &Path,
        data: &[u8],
        claimed: Option<&str>,
    ) -> Result<String> {
        artifact_name(name)?;
        self.put_artifact(lane, data, claimed)
    }
    pub fn put_artifact(&self, lane: &str, data: &[u8], claimed: Option<&str>) -> Result<String> {
        let _guard = LOCK.lock().unwrap();
        self.lane(lane)?;
        if data.is_empty() {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        if data.len() > self.cfg.artifact_max {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::ARTIFACT_TOO_LARGE,
            ));
        }
        let sha = digest(data);
        if let Some(v) = claimed {
            let v = v.trim().to_ascii_lowercase();
            if !valid_sha(&v) || v != sha {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::BAD_DIGEST,
                ));
            }
        }
        let p = self.blob(lane, &sha)?;
        if p.exists() {
            if fs::read(&p).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })? != data
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::DIGEST_CONFLICT,
                ));
            }
            return Ok(sha);
        }
        self.atomic(&p, data)?;
        Ok(sha)
    }
    pub fn get_artifact(&self, lane: &str, sha: &str) -> Result<Vec<u8>> {
        let p = self.blob(lane, sha)?;
        let data = fs::read(p)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::NO_SUCH_ARTIFACT))?;
        if digest(&data) != sha {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::DIGEST_CONFLICT,
            ));
        }
        Ok(data)
    }
    fn validate(&self, lane: &str, id: &str, v: &Value) -> Result<Vec<Value>> {
        let fields = [
            "api",
            "lane",
            "job_id",
            "state",
            "cartridge",
            "pin_sha256",
            "spec_sha256",
            "created_at",
            "deadline_at",
            "queue_reason",
            "worker",
            "attempts",
            "artifacts",
            "manifest",
            "error",
            "cleanup",
            "cancel_requested",
        ];
        let obj = v
            .as_object()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        if obj.len() != fields.len() || fields.iter().any(|f| !obj.contains_key(*f)) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        if v["lane"] != lane {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::LANE_MISMATCH,
            ));
        }
        if v["job_id"] != id || v["api"] != crate::API {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        if ![
            "queued",
            "dispatching",
            "running",
            "merging",
            "cancelling",
            "done",
            "failed",
            "cancelled",
            "timed_out",
        ]
        .contains(&v["state"].as_str().unwrap_or(""))
            || !crate::artifact_routes::CLEANUP_STATES
                .contains(&v["cleanup"].as_str().unwrap_or(""))
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        for field in ["cartridge", "created_at", "deadline_at"] {
            if !v[field].as_str().is_some_and(|s| !s.is_empty()) {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        for field in ["pin_sha256", "spec_sha256"] {
            if !v[field].as_str().is_some_and(valid_sha) {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        if !v["cancel_requested"].is_boolean()
            || !v["attempts"].is_array()
            || (!v["worker"].is_null() && !v["worker"].is_string())
            || (!v["queue_reason"].is_null() && !v["queue_reason"].is_string())
            || (!v["manifest"].is_null() && !v["manifest"].is_string())
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        if !v["error"].is_null() {
            let e = &v["error"];
            if !e.as_object().is_some_and(|m| m.len() == 2)
                || !e["code"].as_str().is_some_and(valid_id)
                || !e["retryable"].is_boolean()
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        let schema = serde_json::json!({"type":"object","properties":{
            "created_at":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
            "deadline_at":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"},
            "attempts":{"type":"array","maxItems":2,"items":{"type":"object","required":["number","worker","state","rc","reason","device_log"],"additionalProperties":false,"properties":{
                "number":{"type":"integer","minimum":1,"maximum":2},"worker":{"type":["string","null"]},"state":{"enum":["dispatching","running","done","failed","cancelled","timed_out","refused"]},"rc":{"type":["integer","null"]},"reason":{"type":["string","null"]},"device_log":{"type":"string","pattern":"^attempts/[12]/device[.]json$"}}}}
        }});
        if !jsonschema::validator_for(&schema)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?
            .is_valid(v)
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        for (index, attempt) in v["attempts"].as_array().unwrap().iter().enumerate() {
            if attempt["number"].as_u64() != Some(index as u64 + 1) {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        let arts = v["artifacts"]
            .as_array()
            .filter(|a| a.len() <= 8)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        if v["state"] != "done" && !arts.is_empty() {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        let mut seen = HashSet::new();
        for art in arts {
            if !art.as_object().is_some_and(|a| a.len() == 3) {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            let path = art["path"]
                .as_str()
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::PATH_UNSAFE))?;
            if !(contract_path(lane, path) || self.cfg.legacy_paths && safe_path(path)) {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::PATH_UNSAFE,
                ));
            }
            if !seen.insert(path)
                || !art["bytes"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= self.cfg.artifact_max as u64)
                || !art["sha256"].as_str().is_some_and(valid_sha)
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        let mut sorted = arts.clone();
        sorted.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
        Ok(sorted)
    }
    pub fn put_job(
        &self,
        lane: &str,
        id: &str,
        doc: &Value,
        documents: &BTreeMap<String, Vec<u8>>,
        finished: u64,
    ) -> Result<Value> {
        let _guard = LOCK.lock().unwrap();
        let dir = self.job(lane, id)?;
        let bytes = canonical(doc);
        if bytes.len() > self.cfg.doc_max {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::DOC_TOO_LARGE,
            ));
        }
        let arts = self.validate(lane, id, doc)?;
        for art in &arts {
            let data = self.get_artifact(lane, art["sha256"].as_str().unwrap())?;
            if data.len() as u64 != art["bytes"].as_u64().unwrap() {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::DIGEST_CONFLICT,
                ));
            }
        }
        for (name, data) in documents {
            if !matches!(name.as_str(), "manifest.json" | "SHA256SUMS") {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::PATH_UNSAFE,
                ));
            }
            if doc["state"] != "done" {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            if data.len() > self.cfg.doc_max {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::DOC_TOO_LARGE,
                ));
            }
        }
        let jobpath = dir.join("job.json");
        self.contain(&jobpath)?;
        let prior = if jobpath.exists() {
            Some(self.get_job(lane, id)?)
        } else {
            None
        };
        if let Some(prev) = &prior {
            if prev["spec_sha256"] != doc["spec_sha256"] {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::JOB_ID_EXISTS,
                ));
            }
            if crate::queue_policy::terminal(prev) && prev != doc {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::JOB_FROZEN,
                ));
            }
        }
        let mut doc_hashes = json!({"job":digest(&bytes),"manifest":null,"sidecar":null});
        for (name, data) in documents {
            let p = dir.join(name);
            self.contain(&p)?;
            if p.exists()
                && fs::read(&p).map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })? != *data
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::JOB_FROZEN,
                ));
            }
            doc_hashes[if name == "manifest.json" {
                "manifest"
            } else {
                "sidecar"
            }] = json!(digest(data));
        }
        let (art_days, doc_days) = retention(lane);
        let mut meta = json!({"api":crate::API,"store":"lane-store/v1","lane":lane,"job_id":id,"state":doc["state"],"finished_epoch":finished,"expires_artifacts_epoch":finished.saturating_add(art_days*DAY),"expires_docs_epoch":finished.saturating_add(doc_days*DAY),"artifacts":arts,"documents":doc_hashes});
        let metapath = dir.join("meta.json");
        self.contain(&metapath)?;
        if prior.as_ref() == Some(doc) && metapath.exists() {
            meta = self.read_json(&metapath)?;
            for (name, data) in documents {
                meta["documents"][if name == "manifest.json" {
                    "manifest"
                } else {
                    "sidecar"
                }] = json!(digest(data));
            }
        }
        let mb = serde_json::to_vec(&meta).unwrap();
        if mb.len() > self.cfg.meta_max {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::DOC_TOO_LARGE,
            ));
        }
        self.atomic(&jobpath, &bytes)?;
        for (name, data) in documents {
            self.atomic(&dir.join(name), data)?;
        }
        self.atomic(&metapath, &mb)?;
        Ok(meta)
    }
    fn read_json(&self, p: &Path) -> Result<Value> {
        self.contain(p)?;
        serde_json::from_slice(
            &fs::read(p)
                .map_err(|_| crate::error_catalog::reason(crate::error_catalog::NO_SUCH_JOB))?,
        )
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))
    }
    pub fn get_meta(&self, lane: &str, id: &str) -> Result<Value> {
        self.read_json(&self.job(lane, id)?.join("meta.json"))
    }
    pub fn get_job(&self, lane: &str, id: &str) -> Result<Value> {
        let dir = self.job(lane, id)?;
        let path = dir.join("job.json");
        self.contain(&path)?;
        let bytes = fs::read(&path)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::NO_SUCH_JOB))?;
        let v = crate::lane_gate::parse(&bytes)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))?;
        self.validate(lane, id, &v)?;
        if dir.join("meta.json").exists() {
            let meta = self.read_json(&dir.join("meta.json"))?;
            if meta["documents"]["job"] != digest(&bytes) {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::DIGEST_CONFLICT,
                ));
            }
        }
        Ok(v)
    }
    pub fn get_document(&self, lane: &str, id: &str, name: &str) -> Result<Vec<u8>> {
        if !matches!(name, "job.json" | "manifest.json" | "SHA256SUMS") {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::PATH_UNSAFE,
            ));
        }
        let dir = self.job(lane, id)?;
        let p = dir.join(name);
        self.contain(&p)?;
        let data = fs::read(p)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::NO_SUCH_ARTIFACT))?;
        let meta = self.read_json(&dir.join("meta.json"))?;
        let field = match name {
            "job.json" => "job",
            "manifest.json" => "manifest",
            _ => "sidecar",
        };
        if meta["documents"][field] != digest(&data) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::DIGEST_CONFLICT,
            ));
        }
        Ok(data)
    }
    pub fn write_device(&self, lane: &str, id: &str, number: u64, doc: &Value) -> Result<()> {
        if !(1..=2).contains(&number) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        let dir = self
            .job(lane, id)?
            .join("attempts")
            .join(number.to_string());
        self.atomic(
            &dir.join("device.json"),
            &canonical(&crate::log_redaction::document(doc)),
        )
    }
    pub fn gc(&self, now: u64, dry: bool) -> Result<Value> {
        let _guard = LOCK.lock().unwrap();
        let mut removed = Vec::new();
        let mut blobs = Vec::new();
        let mut bad = Vec::new();
        let mut dropped = Vec::new();
        let mut tmp_removed = Vec::new();
        for lane in crate::LANES {
            let base = self.lane(lane)?;
            let jobs = base.join("jobs");
            self.contain(&jobs)?;
            let mut live = HashSet::new();
            let mut uncertain = false;
            if jobs.exists() {
                for e in fs::read_dir(&jobs).map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })? {
                    let p = e
                        .map_err(|_| {
                            crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                        })?
                        .path();
                    let label = format!("{lane}/{}", p.file_name().unwrap().to_string_lossy());
                    let parsed = (|| {
                        self.contain(&p)?;
                        let m = self.read_json(&p.join("meta.json"))?;
                        let id = p.file_name().unwrap().to_str().ok_or_else(|| {
                            crate::error_catalog::reason(crate::error_catalog::BAD_SPEC)
                        })?;
                        let v = self.get_job(lane, id)?;
                        if m["lane"] != *lane
                            || m["job_id"] != id
                            || m["state"] != v["state"]
                            || !m["expires_docs_epoch"].is_u64()
                            || !m["expires_artifacts_epoch"].is_u64()
                            || !m["artifacts"].as_array().is_some_and(|a| {
                                a.iter()
                                    .all(|e| e["sha256"].as_str().is_some_and(valid_sha))
                            })
                        {
                            return Err(crate::error_catalog::reason(
                                crate::error_catalog::BAD_SPEC,
                            ));
                        }
                        Ok(m)
                    })();
                    let m = match parsed {
                        Ok(m) => m,
                        Err(_) => {
                            bad.push(label);
                            uncertain = true;
                            continue;
                        }
                    };
                    let terminal = crate::queue_policy::terminal(&m);
                    if terminal && now >= m["expires_docs_epoch"].as_u64().unwrap() {
                        removed.push(label);
                        if !dry {
                            fs::remove_dir_all(&p).map_err(|_| {
                                crate::error_catalog::reason(
                                    crate::error_catalog::STORAGE_UNAVAILABLE,
                                )
                            })?;
                        }
                        continue;
                    }
                    if !terminal || now < m["expires_artifacts_epoch"].as_u64().unwrap() {
                        for a in m["artifacts"].as_array().unwrap() {
                            live.insert(a["sha256"].as_str().unwrap().to_owned());
                        }
                    } else {
                        dropped.push(label);
                        if !dry {
                            self.atomic(&p.join("gc.json"),&serde_json::to_vec(&json!({"artifacts_dropped_epoch":now,"dropped":m["artifacts"].as_array().unwrap().iter().map(|a|a["sha256"].clone()).collect::<Vec<_>>()})).unwrap())?;
                        }
                    }
                }
            }
            let root = base.join("blobs");
            self.contain(&root)?;
            if root.exists() && !uncertain {
                for prefix in fs::read_dir(root).map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })? {
                    let p = prefix
                        .map_err(|_| {
                            crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                        })?
                        .path();
                    self.contain(&p)?;
                    if !p.is_dir() {
                        bad.push(format!("{lane}/blobs"));
                        continue;
                    }
                    for e in fs::read_dir(p).map_err(|_| {
                        crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                    })? {
                        let p = e
                            .map_err(|_| {
                                crate::error_catalog::reason(
                                    crate::error_catalog::STORAGE_UNAVAILABLE,
                                )
                            })?
                            .path();
                        self.contain(&p)?;
                        let sha = p.file_name().unwrap().to_string_lossy().to_string();
                        if !valid_sha(&sha) {
                            bad.push(format!("{lane}/blobs/{sha}"));
                            continue;
                        }
                        if !live.contains(&sha) {
                            blobs.push(format!("{lane}/{sha}"));
                            if !dry {
                                fs::remove_file(p).map_err(|_| {
                                    crate::error_catalog::reason(
                                        crate::error_catalog::STORAGE_UNAVAILABLE,
                                    )
                                })?;
                            }
                        }
                    }
                }
            }
        }
        let tmp = self.root.join("tmp");
        self.contain(&tmp)?;
        if tmp.exists() {
            for e in fs::read_dir(tmp).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })? {
                let e = e.map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })?;
                self.contain(&e.path())?;
                let m = e.metadata().map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })?;
                let modified = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                if m.is_file()
                    && modified.is_some_and(|at| now >= at.saturating_add(self.cfg.stale_tmp))
                {
                    tmp_removed.push(e.file_name().to_string_lossy().to_string());
                    if !dry {
                        fs::remove_file(e.path()).map_err(|_| {
                            crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                        })?;
                    }
                }
            }
        }
        removed.sort();
        blobs.sort();
        bad.sort();
        dropped.sort();
        tmp_removed.sort();
        Ok(
            json!({"dry_run":dry,"now":now,"jobs_removed":removed,"blobs_removed":blobs,"unparsable":bad,"jobs_artifacts_dropped":dropped,"tmp_removed":tmp_removed}),
        )
    }
}
pub fn retention(lane: &str) -> (u64, u64) {
    match lane {
        "render-blender" => (30, 90),
        "tts" | "stt" | "diffusion-image" | "music-sfx" => (14, 45),
        _ => (7, 30),
    }
}

pub fn snapshot(record: &Value, now: u64) -> Value {
    let lane = record["lane"]
        .as_str()
        .or_else(|| record["spec"]["lane"].as_str())
        .unwrap_or("");
    let state = if record["state"] == "refused" {
        "failed"
    } else {
        record["state"].as_str().unwrap_or("failed")
    };
    let done = state == "done";
    let attempts: Vec<Value> = if let Some(a) = record["attempts"].as_array() {
        a.iter()
            .map(|attempt| {
                let mut projected = serde_json::Map::new();
                for field in ["number", "worker", "state", "rc", "reason", "device_log"] {
                    projected.insert(field.into(), attempt[field].clone());
                }
                Value::Object(projected)
            })
            .collect()
    } else if let Some(chunks) = record["chunks"].as_array() {
        let worker = chunks
            .first()
            .map(|c| c["worker"].clone())
            .unwrap_or(Value::Null);
        vec![
            json!({"number":1,"worker":worker,"state":if done{"done"}else{"failed"},"rc":if done{0}else{1},"reason":record["reason"],"device_log":"attempts/1/device.json"}),
        ]
    } else {
        Vec::new()
    };
    if let Some(code) = record["error"]["code"].as_str() {
        crate::error_catalog::observe(None, code);
    }
    let error = if record["error"].is_null() {
        Value::Null
    } else {
        json!({"code":crate::error_catalog::canonical_code(record["error"]["code"].as_str().unwrap_or(crate::error_catalog::ARTIFACT_MISMATCH)),"retryable":false})
    };
    json!({"api":crate::API,"lane":lane,"job_id":record["job_id"],"state":state,"cartridge":record["cartridge"].as_str().unwrap_or("default"),"pin_sha256":record["cartridge_manifest_sha256"].as_str().map(str::to_owned).unwrap_or_else(||digest(b"unavailable pin")),"spec_sha256":record["spec_sha256"].as_str().map(str::to_owned).unwrap_or_else(||digest(&serde_json::to_vec(&record["spec"]).unwrap())),"created_at":crate::utc_stamp(record["created_epoch"].as_u64().unwrap_or(now)),"deadline_at":crate::utc_stamp(record["deadline_epoch"].as_u64().unwrap_or(now)),"queue_reason":record["queue_reason"],"worker":record["chunks"][0]["worker"],"attempts":attempts,"artifacts":if done{record["artifacts"].as_array().cloned().unwrap_or_default().iter().map(|a|json!({"path":a["path"],"bytes":a["bytes"],"sha256":a["sha256"]})).collect::<Vec<_>>()}else{Vec::new()},"manifest":if done{json!(format!("/v1/lanes/{lane}/jobs/{}/artifacts/manifest.json",record["job_id"].as_str().unwrap_or("")))}else{Value::Null},"error":error,"cleanup":if done{"clean"}else{record["cleanup"].as_str().unwrap_or(if crate::queue_policy::terminal(record){"unresolved"}else{"pending"})},"cancel_requested":record["cancel_requested"].as_bool().unwrap_or(false)})
}
pub fn runtime_manifest(record: &Value, now: u64) -> Value {
    let mut manifest = worker_log::document(record, Config::from_value(record).worker_log_max);
    if let Some(o) = manifest.as_object_mut() {
        o.remove("router_pid");
    }
    let projected = snapshot(record, now);
    for field in [
        "api",
        "lane",
        "job_id",
        "cartridge",
        "pin_sha256",
        "spec_sha256",
        "artifacts",
    ] {
        manifest[field] = projected[field].clone();
    }
    manifest
}
pub fn publish_record(root: &Path, record: &Value, now: u64) -> Result<()> {
    let cfg = Config {
        legacy_paths: true,
        ..Config::default()
    };
    let store = Store::new(root, cfg);
    let doc = snapshot(record, now);
    let lane = doc["lane"].as_str().unwrap();
    let id = doc["job_id"]
        .as_str()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    let mut documents = BTreeMap::new();
    if doc["state"] == "done" {
        let out = Path::new(
            record["out"]
                .as_str()
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?,
        );
        let guard = Store::new(out, Config::default());
        for a in doc["artifacts"].as_array().unwrap() {
            let name = a["path"]
                .as_str()
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::PATH_UNSAFE))?;
            artifact_name(Path::new(name))?;
            let p = out.join(name);
            guard.contain(&p)?;
            let data = fs::read(p).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })?;
            store.put_named_artifact(lane, Path::new(name), &data, a["sha256"].as_str())?;
        }
        for name in ["manifest.json", "SHA256SUMS"] {
            let p = out.join(name);
            guard.contain(&p)?;
            let data = if name == "manifest.json" {
                serde_json::to_vec_pretty(&runtime_manifest(record, now)).map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })?
            } else {
                fs::read(p).map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })?
            };
            documents.insert(name.into(), data);
        }
    }
    store.put_job(lane, id, &doc, &documents, now)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "result-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn store(&self) -> Store {
            Store::new(&self.0, Config::default())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn doc(lane: &str, id: &str, state: &str, arts: Vec<Value>) -> Value {
        let mut v = snapshot(
            &json!({"lane":lane,"job_id":id,"state":state,"cartridge":"fixture","spec_sha256":digest(b"spec"),"cartridge_manifest_sha256":digest(b"pin"),"artifacts":arts}),
            0,
        );
        v["artifacts"] = json!(arts);
        v
    }
    fn artifact(s: &Store, lane: &str, path: &str, data: &[u8]) -> Value {
        let sha = s.put_artifact(lane, data, None).unwrap();
        json!({"path":path,"bytes":data.len(),"sha256":sha})
    }
    #[test]
    fn defaults() {
        let c = Config::from_value(&json!({}));
        assert_eq!(
            (c.artifact_max, c.doc_max, c.meta_max, c.stale_tmp),
            (67108864, 65536, 4096, 86400)
        );
        assert_eq!(retention("render-blender"), (30, 90));
        assert_eq!(retention("tts"), (14, 45));
        assert_eq!(retention("diffusion-video"), (7, 30));
    }
    #[test]
    fn t1_round_trip() {
        let t = Temp::new();
        let s = t.store();
        let a = artifact(&s, "tts", "speech.wav", b"payload");
        let v = doc("tts", "job-1", "done", vec![a.clone()]);
        let docs = BTreeMap::from([
            ("manifest.json".into(), serde_json::to_vec(&v).unwrap()),
            (
                "SHA256SUMS".into(),
                format!("{}  speech.wav\n", a["sha256"].as_str().unwrap()).into_bytes(),
            ),
        ]);
        let m = s.put_job("tts", "job-1", &v, &docs, 100).unwrap();
        assert_eq!(s.get_job("tts", "job-1").unwrap(), v);
        assert_eq!(m["expires_docs_epoch"], 100 + 45 * DAY);
        assert_eq!(
            s.get_artifact("tts", a["sha256"].as_str().unwrap())
                .unwrap(),
            b"payload"
        );
        for (name, bytes) in &docs {
            assert_eq!(s.get_document("tts", "job-1", name).unwrap(), *bytes);
        }
        assert_eq!(
            s.put_job("tts", "job-1", &v, &BTreeMap::new(), 999)
                .unwrap(),
            m
        );
    }
    #[test]
    fn t2_sha_mismatch_refused() {
        let t = Temp::new();
        let s = t.store();
        assert_eq!(
            s.put_artifact("tts", b"a", Some(&digest(b"b"))),
            Err(crate::error_catalog::BAD_DIGEST)
        );
        assert_eq!(
            s.put_artifact("tts", b"a", Some("bad")),
            Err(crate::error_catalog::BAD_DIGEST)
        );
        let sha = s
            .put_artifact("tts", b"a", Some(&digest(b"a").to_uppercase()))
            .unwrap();
        fs::write(s.blob("tts", &sha).unwrap(), b"b").unwrap();
        assert_eq!(
            s.get_artifact("tts", &sha),
            Err(crate::error_catalog::DIGEST_CONFLICT)
        );
    }
    #[test]
    fn t3_traversal_refused() {
        let t = Temp::new();
        let s = t.store();
        for id in [
            "..",
            "../..",
            "a/b",
            "A-B",
            "-abc",
            "ab_c",
            ".hidden",
            "",
            "foo/../bar",
            "%2e%2e",
            "tts ",
        ] {
            assert_eq!(s.get_job("tts", id), Err(crate::error_catalog::NO_SUCH_JOB));
        }
        assert!(!valid_id(&"a".repeat(65)));
        for sha in ["", "abc", "../x", "AA"] {
            assert_eq!(
                s.get_artifact("tts", sha),
                Err(crate::error_catalog::BAD_DIGEST)
            );
        }
        for lane in ["nope", "TTS", "tts/jobs", "../tts", "tts/..", ""] {
            assert_eq!(
                s.get_job(lane, "job-1"),
                Err(crate::error_catalog::UNKNOWN_LANE)
            );
        }
        for name in [
            "../job.json",
            "x.json",
            "meta.json",
            "gc.json",
            "SHA256SUMS/..",
        ] {
            assert_eq!(
                s.get_document("tts", "job-1", name),
                Err(crate::error_catalog::PATH_UNSAFE)
            );
        }
        for path in [
            "../evil.wav",
            "/abs.wav",
            "a/../speech.wav",
            ".speech.wav",
            "speech.wav/..",
            "evil.txt",
            "SSH.WAV",
            "stems/../speech.wav",
            "sub/speech.wav",
        ] {
            assert!(!contract_path("tts", path));
        }
    }
    #[test]
    fn t4_retention_gc_removes_only_expired() {
        let t = Temp::new();
        let s = t.store();
        let shared = artifact(&s, "music-sfx", "audio.wav", b"shared");
        let unique = artifact(&s, "music-sfx", "stems/drums.wav", b"unique");
        let old = doc(
            "music-sfx",
            "old",
            "done",
            vec![shared.clone(), unique.clone()],
        );
        s.put_job("music-sfx", "old", &old, &BTreeMap::new(), 0)
            .unwrap();
        let fresh = doc("music-sfx", "fresh", "done", vec![shared.clone()]);
        s.put_job("music-sfx", "fresh", &fresh, &BTreeMap::new(), 19 * DAY)
            .unwrap();
        s.put_job(
            "tts",
            "live",
            &doc("tts", "live", "queued", vec![]),
            &BTreeMap::new(),
            0,
        )
        .unwrap();
        let img = artifact(&s, "diffusion-image", "image.png", b"image");
        s.put_job(
            "diffusion-image",
            "gone",
            &doc("diffusion-image", "gone", "done", vec![img]),
            &BTreeMap::new(),
            0,
        )
        .unwrap();
        let r = s.gc(46 * DAY, false).unwrap();
        assert_eq!(
            r["jobs_removed"],
            json!(["diffusion-image/gone", "music-sfx/old"])
        );
        assert!(s.get_job("tts", "live").is_ok());
        assert!(s
            .get_artifact("music-sfx", shared["sha256"].as_str().unwrap())
            .is_err());
        assert!(s
            .get_artifact("music-sfx", unique["sha256"].as_str().unwrap())
            .is_err());
        assert!(s.gc(46 * DAY, false).unwrap()["blobs_removed"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    #[test]
    fn shared_blob_survives_artifact_expiry() {
        let t = Temp::new();
        let s = t.store();
        let a = artifact(&s, "music-sfx", "audio.wav", b"shared");
        for (id, at) in [("old", 0), ("fresh", 19 * DAY)] {
            s.put_job(
                "music-sfx",
                id,
                &doc("music-sfx", id, "done", vec![a.clone()]),
                &BTreeMap::new(),
                at,
            )
            .unwrap();
        }
        s.gc(20 * DAY, false).unwrap();
        assert!(s
            .get_artifact("music-sfx", a["sha256"].as_str().unwrap())
            .is_ok());
    }
    #[test]
    fn t5_dry_run_deletes_nothing() {
        let t = Temp::new();
        let s = t.store();
        let a = artifact(&s, "tts", "speech.wav", b"a");
        let v = doc("tts", "job", "done", vec![a]);
        s.put_job("tts", "job", &v, &BTreeMap::new(), 0).unwrap();
        let before = fs::read(s.job("tts", "job").unwrap().join("meta.json")).unwrap();
        let r = s.gc(50 * DAY, true).unwrap();
        assert_eq!(r["jobs_removed"], json!(["tts/job"]));
        assert_eq!(s.get_job("tts", "job").unwrap(), v);
        assert_eq!(
            fs::read(s.job("tts", "job").unwrap().join("meta.json")).unwrap(),
            before
        );
    }
    #[test]
    fn t6_concurrent_put_idempotent() {
        let t = Temp::new();
        let s = t.store();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let s = s.clone();
                std::thread::spawn(move || {
                    let a = artifact(&s, "tts", "speech.wav", b"concurrent");
                    let v = doc("tts", "job", "done", vec![a.clone()]);
                    s.put_job("tts", "job", &v, &BTreeMap::new(), 0).unwrap();
                    a["sha256"].clone()
                })
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), digest(b"concurrent"));
        }
        assert_eq!(
            fs::read_dir(
                s.blob("tts", &digest(b"concurrent"))
                    .unwrap()
                    .parent()
                    .unwrap()
            )
            .unwrap()
            .count(),
            1
        );
    }
    #[test]
    fn t7_oversize_refused() {
        let t = Temp::new();
        let s = t.store();
        assert_eq!(
            s.put_artifact("tts", &vec![0; 67108865], None),
            Err(crate::error_catalog::ARTIFACT_TOO_LARGE)
        );
        assert_eq!(
            s.put_artifact("tts", b"", None),
            Err(crate::error_catalog::BAD_SPEC)
        );
        let mut v = doc("tts", "job", "queued", vec![]);
        v["note"] = json!("x".repeat(70000));
        assert_eq!(
            s.put_job("tts", "job", &v, &BTreeMap::new(), 0),
            Err(crate::error_catalog::DOC_TOO_LARGE)
        );
    }
    #[test]
    fn t8_immutability() {
        let t = Temp::new();
        let s = t.store();
        let mut v = doc("tts", "job", "queued", vec![]);
        s.put_job("tts", "job", &v, &BTreeMap::new(), 0).unwrap();
        v["state"] = json!("running");
        s.put_job("tts", "job", &v, &BTreeMap::new(), 0).unwrap();
        let mut other = v.clone();
        other["spec_sha256"] = json!(digest(b"different"));
        assert_eq!(
            s.put_job("tts", "job", &other, &BTreeMap::new(), 0),
            Err(crate::error_catalog::JOB_ID_EXISTS)
        );
        v["state"] = json!("done");
        let docs = BTreeMap::from([("manifest.json".into(), b"manifest".to_vec())]);
        s.put_job("tts", "job", &v, &docs, 0).unwrap();
        v["error"] = json!({"code":"x","retryable":false});
        assert_eq!(
            s.put_job("tts", "job", &v, &BTreeMap::new(), 0),
            Err(crate::error_catalog::JOB_FROZEN)
        );
        v["error"] = Value::Null;
        let changed = BTreeMap::from([("manifest.json".into(), b"changed".to_vec())]);
        assert_eq!(
            s.put_job("tts", "job", &v, &changed, 0),
            Err(crate::error_catalog::JOB_FROZEN)
        );
    }
    #[test]
    fn containment_symlink_mutation() {
        use std::os::unix::fs::symlink;
        let t = Temp::new();
        let outside = Temp::new();
        let s = t.store();
        fs::create_dir_all(t.0.join("lanes/tts")).unwrap();
        symlink(&outside.0, t.0.join("lanes/tts/blobs")).unwrap();
        assert_eq!(
            s.put_artifact("tts", b"data", None),
            Err(crate::error_catalog::PATH_UNSAFE)
        );
        assert_eq!(fs::read_dir(&outside.0).unwrap().count(), 0);
    }
    #[test]
    fn temp_rehash_mutation() {
        let t = Temp::new();
        let s = t.store();
        let p = t.0.join("doc");
        fs::write(&p, b"old").unwrap();
        assert_eq!(
            s.atomic_hook(&p, b"new", |p| fs::write(p, b"bad").unwrap()),
            Err(crate::error_catalog::STORAGE_UNAVAILABLE)
        );
        assert_eq!(fs::read(p).unwrap(), b"old");
    }
    #[test]
    fn document_atomic_rename_mutation() {
        use std::os::unix::fs::MetadataExt;
        let t = Temp::new();
        let s = t.store();
        let p = t.0.join("doc");
        fs::write(&p, b"old").unwrap();
        let held = fs::File::open(&p).unwrap();
        let ino = held.metadata().unwrap().ino();
        s.atomic(&p, b"new").unwrap();
        assert_ne!(fs::metadata(&p).unwrap().ino(), ino);
        assert_eq!(fs::read(p).unwrap(), b"new");
    }
    #[test]
    fn orphan_without_jobs_collected() {
        let t = Temp::new();
        let s = t.store();
        s.put_artifact("tts", b"orphan", None).unwrap();
        assert!(!t.0.join("lanes/tts/jobs").exists());
        assert_eq!(
            s.gc(0, false).unwrap()["blobs_removed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn invalid_metadata_reported_and_preserved() {
        let t = Temp::new();
        let s = t.store();
        s.put_job(
            "tts",
            "job",
            &doc("tts", "job", "queued", vec![]),
            &BTreeMap::new(),
            0,
        )
        .unwrap();
        let p = s.job("tts", "job").unwrap().join("meta.json");
        let mut m = s.read_json(&p).unwrap();
        m["expires_docs_epoch"] = json!("bad");
        fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(
            s.gc(u64::MAX, false).unwrap()["unparsable"],
            json!(["tts/job"])
        );
        assert!(p.exists());
    }
    #[test]
    fn exact_envelope_and_cross_lane_references() {
        let t = Temp::new();
        let s = t.store();
        let a = artifact(&s, "tts", "speech.wav", b"data");
        let mut v = doc("tts", "job", "done", vec![a.clone()]);
        v.as_object_mut().unwrap().remove("attempts");
        assert_eq!(
            s.put_job("tts", "job", &v, &BTreeMap::new(), 0),
            Err(crate::error_catalog::BAD_SPEC)
        );
        v = doc("tts", "job", "done", vec![a.clone()]);
        v["extra"] = json!(true);
        assert_eq!(
            s.put_job("tts", "job", &v, &BTreeMap::new(), 0),
            Err(crate::error_catalog::BAD_SPEC)
        );
        let cross = doc(
            "music-sfx",
            "cross",
            "done",
            vec![json!({"path":"audio.wav","bytes":4,"sha256":a["sha256"]})],
        );
        assert_eq!(
            s.put_job("music-sfx", "cross", &cross, &BTreeMap::new(), 0),
            Err(crate::error_catalog::NO_SUCH_ARTIFACT)
        );
        let live = doc("tts", "live", "running", vec![a]);
        assert_eq!(
            s.put_job("tts", "live", &live, &BTreeMap::new(), 0),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[test]
    fn documents_only_at_done() {
        let t = Temp::new();
        let s = t.store();
        let v = doc("tts", "job", "running", vec![]);
        assert_eq!(
            s.put_job(
                "tts",
                "job",
                &v,
                &BTreeMap::from([("manifest.json".into(), b"m".to_vec())]),
                0
            ),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[test]
    fn run30_artifact_refusal_table() {
        use std::os::unix::ffi::OsStringExt;
        let t = Temp::new();
        let s = t.store();
        let outside = t.0.join("outside");
        fs::write(&outside, b"unchanged").unwrap();
        let non_utf8 = PathBuf::from(std::ffi::OsString::from_vec(vec![0xff]));
        let cap = Config::default().artifact_max;
        assert_eq!(cap, 64 * 1024 * 1024);
        let large = vec![0; cap + 1];
        for (label, path, data, expected) in [
            (
                "traversal",
                PathBuf::from("../outside"),
                &b"x"[..],
                crate::error_catalog::PATH_UNSAFE,
            ),
            (
                "nested traversal",
                PathBuf::from("a/../../outside"),
                &b"x"[..],
                crate::error_catalog::PATH_UNSAFE,
            ),
            (
                "absolute",
                outside.clone(),
                &b"x"[..],
                crate::error_catalog::PATH_UNSAFE,
            ),
            (
                "empty",
                PathBuf::new(),
                &b"x"[..],
                crate::error_catalog::PATH_UNSAFE,
            ),
            (
                "non UTF-8",
                non_utf8,
                &b"x"[..],
                crate::error_catalog::PATH_UNSAFE,
            ),
            (
                "over cap",
                PathBuf::from("speech.wav"),
                large.as_slice(),
                crate::error_catalog::ARTIFACT_TOO_LARGE,
            ),
        ] {
            assert_eq!(
                s.put_named_artifact("tts", &path, data, None),
                Err(expected),
                "{label}"
            );
            assert_eq!(fs::read(&outside).unwrap(), b"unchanged", "{label}");
            assert_eq!(
                fs::read_dir(&t.0).unwrap().count(),
                1,
                "{label}: refusal created files"
            );
        }
    }
}
