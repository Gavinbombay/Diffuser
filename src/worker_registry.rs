//! Validated static configuration and offline heartbeat state with injected time.
use crate::*;
use std::io::Write;
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub heartbeat: u64,
    pub stale: u64,
    pub gone: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            heartbeat: 30,
            stale: 90,
            gone: 180,
        }
    }
}
fn thresholds() -> Value {
    let c = Config::default();
    json!({"heartbeat_interval_s":c.heartbeat,"stale_after_s":c.stale,"gone_after_s":c.gone})
}
pub fn identifier(s: &str, max: usize, extra: &[u8], upper: bool) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || (upper && b.is_ascii_uppercase())
                || extra.contains(&b)
        })
}
const ADVERTISED: &[&str] = &[
    "id",
    "lanes",
    "capabilities",
    "cartridges",
    "gpu_class",
    "max_concurrency",
    "version",
];
fn string_array(v: &Value, max: usize, chars: &[u8], width: usize) -> Result<Value, &'static str> {
    let a = v
        .as_array()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    let mut out = BTreeMap::new();
    if a.len() > max {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    for v in a {
        let s = v
            .as_str()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        if !identifier(s, width, chars, false) || out.insert(s, ()).is_some() {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    Ok(json!(out.keys().collect::<Vec<_>>()))
}
pub fn registration(v: &Value) -> Result<Value, &'static str> {
    let o = v
        .as_object()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    if o.iter()
        .any(|(f, v)| !ADVERTISED.contains(&f.as_str()) || v.is_null())
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if !v["id"].as_str().is_some_and(result_store::valid_id)
        || !v["gpu_class"]
            .as_str()
            .is_some_and(|s| identifier(s, 32, b"-", false))
        || !v["version"]
            .as_str()
            .is_some_and(|s| identifier(s, 32, b".-", true))
        || !v["max_concurrency"]
            .as_u64()
            .is_some_and(|n| (1..=16).contains(&n))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let lanes = v["lanes"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    if lanes
        .iter()
        .any(|v| !v.as_str().is_some_and(|s| LANES.contains(&s)))
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    let mut out = v.clone();
    out["lanes"] = string_array(&v["lanes"], 6, b"-", 64)?;
    for (field, chars, width) in [
        ("capabilities", b"-".as_slice(), 32),
        ("cartridges", b".-".as_slice(), 64),
    ] {
        out[field] = string_array(v.get(field).unwrap_or(&json!([])), 16, chars, width)?;
    }
    Ok(out)
}
#[derive(Debug)]
pub struct Registry {
    pub doc: Value,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            doc: json!({"api":API,"kind":"worker-registry","format":1,"thresholds":thresholds(),"saved_at":null,"workers":{},"retired":[]}),
        }
    }
}
impl Registry {
    fn get_mut(&mut self, id: &str) -> Result<&mut Value, &'static str> {
        self.doc["workers"]
            .get_mut(id)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_WORKER))
    }
    pub fn register(&mut self, v: &Value, now: u64) -> Result<Value, &'static str> {
        let mut w = registration(v)?;
        let id = w["id"].as_str().unwrap().to_owned();
        if self.doc["workers"].get(&id).is_some() {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::WORKER_ID_EXISTS,
            ));
        }
        if self.doc["retired"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["id"] == id && w["gone_because"] == "drained")
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::WORKER_ID_EXISTS,
            ));
        }
        let generation = self.doc["retired"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["id"] == id)
            .filter_map(|w| w["generation"].as_u64())
            .max()
            .unwrap_or(0)
            + 1;
        // A re-registration supersedes its tombstone, preventing ambiguous reloads.
        self.doc["retired"]
            .as_array_mut()
            .unwrap()
            .retain(|w| w["id"] != id);
        for(f,v)in json!({"state":"registering","generation":generation,"registered_at":now,"last_heartbeat_at":now,"heartbeats":0,"jobs":[],"drain_reason":null,"drained_at":null,"stale_since":null,"gone_at":null,"gone_because":null}).as_object().unwrap(){w[f]=v.clone();}
        self.doc["workers"][&id] = w;
        self.view(&id, None, None, now)
    }
    pub fn heartbeat(
        &mut self,
        id: &str,
        advertisement: Option<&Value>,
        now: u64,
    ) -> Result<Value, &'static str> {
        let current = self.doc["workers"]
            .get(id)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_WORKER))?;
        let revived = current["state"] == "stale";
        let mut clean = current.clone();
        if let Some(a) = advertisement {
            let o = a
                .as_object()
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
            if o.keys()
                .any(|f| !["capabilities", "cartridges", "version"].contains(&f.as_str()))
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            let mut base = json!({});
            for f in ADVERTISED {
                base[*f] = current[*f].clone();
            }
            for (f, v) in o {
                base[f] = v.clone();
            }
            let checked = registration(&base)?;
            for f in ["capabilities", "cartridges", "version"] {
                clean[f] = checked[f].clone();
            }
        }
        if clean["state"] == "registering" || revived {
            clean["state"] = json!(if !clean["drained_at"].is_null() {
                crate::error_catalog::DRAINING
            } else if clean["jobs"].as_array().unwrap().is_empty() {
                "ready"
            } else {
                "busy"
            });
            clean["stale_since"] = Value::Null;
        }
        clean["last_heartbeat_at"] = json!(now);
        clean["heartbeats"] = json!(clean["heartbeats"].as_u64().unwrap() + 1);
        *self.get_mut(id)? = clean;
        let mut v = self.view(id, None, None, now)?;
        v["revived"] = json!(revived);
        Ok(v)
    }
    fn retire(&mut self, id: &str, because: &str, now: u64) -> Result<Value, &'static str> {
        let mut w = self.doc["workers"]
            .as_object_mut()
            .unwrap()
            .remove(id)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_WORKER))?;
        w["state"] = json!("gone");
        w["gone_at"] = json!(now);
        w["gone_because"] = json!(because);
        w["stale_since"] = Value::Null;
        w["jobs"] = json!([]);
        self.doc["retired"].as_array_mut().unwrap().push(w.clone());
        Ok(w)
    }
    pub fn drain(
        &mut self,
        id: &str,
        reason: Option<&str>,
        now: u64,
    ) -> Result<Value, &'static str> {
        if reason.is_some_and(|s| s.is_empty() || s.chars().count() > 128) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        let w = self.get_mut(id)?;
        w["drained_at"] = json!(now);
        w["drain_reason"] = json!(reason);
        if w["state"] != "stale" {
            w["state"] = json!(crate::error_catalog::DRAINING);
        }
        if w["jobs"].as_array().unwrap().is_empty() {
            return self.retire(id, "drained", now);
        }
        self.view(id, None, None, now)
    }
    pub fn claim(&mut self, id: &str, job: &str, now: u64) -> Result<Value, &'static str> {
        if !result_store::valid_id(job) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        let w = self.get_mut(id)?;
        match w["state"].as_str().unwrap() {
            "registering" => {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::WORKER_NOT_READY,
                ))
            }
            "stale" => {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::WORKER_STALE,
                ))
            }
            crate::error_catalog::DRAINING => {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::WORKER_DRAINING,
                ))
            }
            _ => {}
        }
        let used = w["jobs"].as_array().unwrap().len();
        if w["jobs"].as_array().unwrap().contains(&json!(job)) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        if used >= w["max_concurrency"].as_u64().unwrap() as usize {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::SEATS_FULL,
            ));
        }
        let jobs = w["jobs"].as_array_mut().unwrap();
        jobs.push(json!(job));
        jobs.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        w["state"] = json!("busy");
        self.view(id, None, None, now)
    }
    pub fn release(&mut self, id: &str, job: &str, now: u64) -> Result<Value, &'static str> {
        if !result_store::valid_id(job) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        let w = self.get_mut(id)?;
        let jobs = w["jobs"].as_array_mut().unwrap();
        if !jobs.contains(&json!(job)) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        jobs.retain(|v| v != job);
        if jobs.is_empty() {
            if !w["drained_at"].is_null() {
                return self.retire(id, "drained", now);
            }
            if w["state"] == "busy" {
                w["state"] = json!("ready");
            }
        }
        self.view(id, None, None, now)
    }
    pub fn view(
        &self,
        id: &str,
        lane: Option<&str>,
        cartridge: Option<&str>,
        now: u64,
    ) -> Result<Value, &'static str> {
        if lane.is_some_and(|l| !LANES.contains(&l)) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::UNKNOWN_LANE,
            ));
        }
        let w = self.doc["workers"]
            .get(id)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_WORKER))?;
        let mut v = w.clone();
        let mut reasons = Vec::new();
        match w["state"].as_str().unwrap() {
            "registering" => {
                reasons.push("not confirmed yet: no heartbeat since registration".to_owned())
            }
            "stale" => reasons.push(format!(
                "stale: no heartbeat for {} s > {}",
                now.saturating_sub(w["last_heartbeat_at"].as_u64().unwrap()),
                Config::default().stale
            )),
            crate::error_catalog::DRAINING => reasons
                .push(crate::error_catalog::reason(crate::error_catalog::DRAINING).to_owned()),
            _ => {}
        }
        if let Some(l) = lane {
            if !w["lanes"].as_array().unwrap().contains(&json!(l)) {
                reasons.push(format!("does not serve {l}"));
            }
        }
        if let Some(c) = cartridge {
            if !w["cartridges"].as_array().unwrap().contains(&json!(c)) {
                reasons.push(format!("does not offer cartridge {c}"));
            }
        }
        let used = w["jobs"].as_array().unwrap().len() as u64;
        let seats = w["max_concurrency"].as_u64().unwrap();
        if used >= seats {
            reasons.push(format!("router seats full {used}/{seats}"));
        }
        v["used"] = json!(used);
        v["seats_free"] = json!(seats - used);
        v["accepting"] = json!(reasons.is_empty());
        v["why_not"] = json!(reasons);
        Ok(v)
    }
    pub fn candidates(&self, lane: &str, now: u64) -> Result<Vec<String>, &'static str> {
        if !LANES.contains(&lane) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::UNKNOWN_LANE,
            ));
        }
        Ok(self.doc["workers"]
            .as_object()
            .unwrap()
            .keys()
            .filter(|id| self.view(id, Some(lane), None, now).unwrap()["accepting"] == true)
            .cloned()
            .collect())
    }
    pub fn sweep(&mut self, now: u64) -> Value {
        let mut report = json!({"now":now,"stale":[],"gone":[],"reassign":[],"live":0});
        let ids = self.doc["workers"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for id in ids {
            let w = &self.doc["workers"][&id];
            let age = now.saturating_sub(w["last_heartbeat_at"].as_u64().unwrap());
            let jobs = w["jobs"].clone();
            let gone = age > Config::default().gone;
            let stale = age > Config::default().stale && w["state"] != "stale";
            if gone || stale {
                let field = if gone { "gone" } else { "stale" };
                report[field].as_array_mut().unwrap().push(json!(id));
                if !jobs.as_array().unwrap().is_empty() {
                    report["reassign"].as_array_mut().unwrap().push(json!({"worker":id,"jobs":jobs,"reason":if gone{"worker-gone"}else{crate::error_catalog::WORKER_STALE},"final":gone}));
                }
                if gone {
                    self.retire(&id, "heartbeat-lost", now).unwrap();
                } else {
                    let w = &mut self.doc["workers"][&id];
                    w["state"] = json!("stale");
                    w["stale_since"] = json!(now);
                }
            }
        }
        report["live"] = json!(self.doc["workers"]
            .as_object()
            .unwrap()
            .values()
            .filter(|w| ["ready", "busy", crate::error_catalog::DRAINING]
                .contains(&w["state"].as_str().unwrap()))
            .count());
        report
    }
    pub fn save(&mut self, path: &Path, now: u64) -> Result<(), &'static str> {
        self.doc["saved_at"] = json!(now);
        let mut temp = path.as_os_str().to_owned();
        temp.push(".tmp");
        let temp = PathBuf::from(temp);
        if fs::symlink_metadata(&temp).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::STORAGE_UNAVAILABLE,
            ));
        }
        let _ = fs::remove_file(&temp);
        let result = (|| {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })?;
            f.write_all(&result_store::canonical(&self.doc))
                .map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })?;
            f.sync_all().map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })?;
            fs::rename(&temp, path).map_err(|_| {
                crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
            })?;
            fs::File::open(
                path.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )
            .and_then(|f| f.sync_all())
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
    pub fn load(path: &Path) -> Result<Self, &'static str> {
        let bytes = fs::read(path)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))?;
        Self::decode(&bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let doc = lane_gate::parse(bytes)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))?;
        let valid = (|| {
            if doc.as_object().is_none_or(|o| o.len() != 7)
                || doc["api"] != API
                || doc["kind"] != "worker-registry"
                || doc["format"] != 1
                || doc["thresholds"] != thresholds()
                || !(doc["saved_at"].is_null() || doc["saved_at"].is_u64())
            {
                return None;
            }
            let workers = doc["workers"].as_object()?;
            let retired = doc["retired"].as_array()?;
            let mut seen = HashSet::new();
            for (id, w) in workers
                .iter()
                .map(|(id, w)| (Some(id.as_str()), w))
                .chain(retired.iter().map(|w| (None, w)))
            {
                let member = w["id"].as_str()?;
                if id.is_some_and(|id| id != member)
                    || !seen.insert(member)
                    || w.as_object()?.len() != 18
                {
                    return None;
                }
                for field in [
                    "state",
                    "generation",
                    "registered_at",
                    "last_heartbeat_at",
                    "heartbeats",
                    "jobs",
                    "drain_reason",
                    "drained_at",
                    "stale_since",
                    "gone_at",
                    "gone_because",
                ] {
                    w.get(field)?;
                }
                if w["drain_reason"]
                    .as_str()
                    .is_some_and(|s| s.is_empty() || s.chars().count() > 128)
                    || !(w["drain_reason"].is_null() || w["drain_reason"].is_string())
                {
                    return None;
                }
                let mut advertised = json!({});
                for f in ADVERTISED {
                    advertised[*f] = w.get(*f)?.clone();
                }
                if registration(&advertised).ok()? != advertised {
                    return None;
                }
                let state = w["state"].as_str()?;
                if !(if id.is_some() {
                    [
                        "registering",
                        "ready",
                        "busy",
                        "stale",
                        crate::error_catalog::DRAINING,
                    ]
                    .contains(&state)
                } else {
                    state == "gone"
                }) {
                    return None;
                }
                let jobs = w["jobs"].as_array()?;
                if string_array(&w["jobs"], 16, b"-", 64).ok()? != w["jobs"]
                    || jobs.len() > w["max_concurrency"].as_u64()? as usize
                    || w["generation"].as_u64()? == 0
                {
                    return None;
                }
                for f in ["registered_at", "last_heartbeat_at", "heartbeats"] {
                    w[f].as_u64()?;
                }
                for f in ["drained_at", "stale_since", "gone_at"] {
                    if !w[f].is_null() {
                        w[f].as_u64()?;
                    }
                }
                if state == "gone" && (!jobs.is_empty() || !w["gone_at"].is_u64())
                    || state == "busy" && jobs.is_empty()
                    || state == "ready" && !jobs.is_empty()
                    || state == "registering" && (w["heartbeats"] != 0 || !jobs.is_empty())
                {
                    return None;
                }
            }
            Some(())
        })();
        if valid.is_none() {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::STORAGE_UNAVAILABLE,
            ));
        }
        Ok(Self { doc })
    }
}
pub fn load_static(path: &Path, now: u64) -> Result<Vec<Worker>, String> {
    let raw = fs::read(path).map_err(|e| format!("registry {}: {e}", path.display()))?;
    let v = lane_gate::parse(&raw).map_err(|e| format!("registry: {e}"))?;
    if v.get("worker_state_path").is_some_and(|v| !v.is_string()) {
        return Err("registry: bad worker_state_path".into());
    }
    let rows = v["workers"]
        .as_array()
        .ok_or("registry: no workers array")?;
    let mut state = if let Some(p) = v["worker_state_path"].as_str() {
        Some(Registry::load(Path::new(p)).map_err(|e| format!("registry: {e}"))?)
    } else {
        None
    };
    if let Some(r) = state.as_mut() {
        r.sweep(now);
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for w in rows {
        let id = w["id"]
            .as_str()
            .filter(|s| result_store::valid_id(s))
            .ok_or("registry: bad worker id")?;
        if !seen.insert(id) {
            return Err("registry: worker-id-exists".into());
        }
        let lanes = w["lanes"]
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 6)
            .ok_or("registry: bad lanes")?;
        let mut lane_set = HashSet::new();
        for lane in lanes {
            if !lane.as_str().is_some_and(|s| LANES.contains(&s))
                || !lane_set.insert(lane.to_string())
            {
                return Err("registry: unknown or duplicate lane".into());
            }
        }
        let mut seats = w
            .get("seats")
            .map(|v| v.as_u64().filter(|n| (1..=16).contains(n)))
            .unwrap_or(Some(1))
            .ok_or("registry: bad seats")? as usize;
        let state_ready = if let Some(r) = state.as_ref() {
            match r.view(id, None, None, now) {
                Ok(view) => {
                    let advertised = &view["lanes"];
                    let serves_all = lanes
                        .iter()
                        .all(|lane| advertised.as_array().is_some_and(|a| a.contains(lane)));
                    let available = view["seats_free"].as_u64().unwrap_or(0) as usize;
                    seats = seats.min(available).max(1);
                    view["accepting"] == true && serves_all
                }
                Err(_) => false,
            }
        } else {
            true
        };
        out.push(Worker {
            id: id.into(),
            lanes: lanes.iter().map(|v| v.as_str().unwrap().into()).collect(),
            kind: w["kind"].as_str().unwrap_or("").into(),
            exec: w["exec"].as_str().unwrap_or("").into(),
            dispatch: w["dispatch"].clone(),
            seats,
            enabled: w["enabled"].as_bool().unwrap_or(false) && state_ready,
            note: if state_ready {
                w["note"].as_str().unwrap_or("").into()
            } else {
                "worker registry not ready".into()
            },
        });
    }
    Ok(out)
}
pub fn cli(args: &[String], now: u64) -> Result<Value, &'static str> {
    let get = |flag: &str| {
        args.iter()
            .position(|s| s == flag)
            .and_then(|n| args.get(n + 1))
            .map(String::as_str)
    };
    let path = Path::new(
        get("--state")
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?,
    );
    let action = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    let mut r = if path.exists() {
        Registry::load(path)?
    } else if action == "register" {
        Registry::default()
    } else {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::STORAGE_UNAVAILABLE,
        ));
    };
    let id = get("--id").unwrap_or("");
    let result = match action {
        "register" => {
            let bytes = fs::read(
                get("--record")
                    .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?,
            )
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
            r.register(&lane_gate::parse(&bytes)?, now)?
        }
        "heartbeat" => r.heartbeat(id, None, now)?,
        "drain" => r.drain(id, get("--reason"), now)?,
        "claim" => r.claim(
            id,
            get("--job")
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?,
            now,
        )?,
        "release" => r.release(
            id,
            get("--job")
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?,
            now,
        )?,
        "sweep" => r.sweep(now),
        "view" => return r.view(id, get("--lane"), None, now),
        "candidates" => {
            return r
                .candidates(
                    get("--lane").ok_or_else(|| {
                        crate::error_catalog::reason(crate::error_catalog::BAD_SPEC)
                    })?,
                    now,
                )
                .map(|v| json!(v))
        }
        _ => return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC)),
    };
    r.save(path, now)?;
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> Value {
        json!({"id":"fixture","lanes":["tts","render-blender"],"capabilities":["bake-render","render"],"cartridges":["blender-4.5.14-cycles","voice"],"gpu_class":"none","max_concurrency":2,"version":"worker-1.4.2"})
    }
    #[test]
    fn run32_worker_registration_refusal_table() {
        use crate::error_catalog as codes;
        let rows = [
            ("duplicate", "id", json!("fixture"), codes::WORKER_ID_EXISTS),
            (
                "unknown-lane",
                "lanes",
                json!(["unknown"]),
                codes::UNKNOWN_LANE,
            ),
            ("empty-id", "id", json!(""), codes::BAD_SPEC),
            ("long-id", "id", json!("a".repeat(97)), codes::BAD_SPEC),
            ("empty-class", "gpu_class", json!(""), codes::BAD_SPEC),
            (
                "long-class",
                "gpu_class",
                json!("a".repeat(33)),
                codes::BAD_SPEC,
            ),
            ("empty-version", "version", json!(""), codes::BAD_SPEC),
            (
                "long-version",
                "version",
                json!("a".repeat(33)),
                codes::BAD_SPEC,
            ),
            (
                "removed-id",
                "id",
                json!("fixture"),
                codes::WORKER_ID_EXISTS,
            ),
        ];
        let mut passed = 0;
        for (label, field, value, code) in rows {
            let mut r = ready();
            if label == "removed-id" {
                r.drain("fixture", None, 1031).unwrap();
            }
            let before = r.doc.clone();
            let mut advertised = record();
            advertised[field] = value;
            assert_eq!(
                r.register(&advertised, 1032),
                Err(codes::reason(code)),
                "{label}"
            );
            assert_eq!(r.doc, before, "{label}");
            assert_eq!(codes::canonical_code(code), code);
            if label == "removed-id" {
                advertised["id"] = json!("fresh-worker");
                assert!(r.register(&advertised, 1033).is_ok());
            }
            passed += 1;
        }
        assert_eq!(passed, 9);
    }
    fn ready() -> Registry {
        let mut r = Registry::default();
        r.register(&record(), 1000).unwrap();
        r.heartbeat("fixture", None, 1030).unwrap();
        r
    }
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "worker-registry-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!((c.heartbeat, c.stale, c.gone), (30, 90, 180));
    }
    #[test]
    fn register_then_heartbeat() {
        let mut r = Registry::default();
        let v = r.register(&record(), 1000).unwrap();
        assert_eq!(v["state"], "registering");
        assert_eq!(v["accepting"], false);
        assert_eq!(v["generation"], 1);
        let v = r
            .heartbeat(
                "fixture",
                Some(&json!({"version":"worker-1.5.0","cartridges":["voice"]})),
                1030,
            )
            .unwrap();
        assert_eq!(v["state"], "ready");
        assert_eq!(v["heartbeats"], 1);
        assert_eq!(v["cartridges"], json!(["voice"]));
        assert_eq!(v["revived"], false);
        assert_eq!(
            r.heartbeat("fixture", Some(&json!({"lanes":["tts"]})), 1030),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[test]
    fn registration_refusals() {
        let mut bad = Vec::new();
        for (f, v) in [
            ("id", json!("Upper")),
            ("id", json!("../escape")),
            ("lanes", json!([])),
            ("lanes", json!(["tts", "tts"])),
            ("max_concurrency", json!(0)),
            ("max_concurrency", json!(17)),
            ("max_concurrency", json!(1.5)),
            ("max_concurrency", json!(true)),
            ("gpu_class", json!("RTX 3060")),
            ("version", json!("worker 1.4")),
            ("capabilities", json!(["render", "render"])),
            ("cartridges", json!(["Upper"])),
            ("note", json!("fixture")),
            ("gpu_class", Value::Null),
        ] {
            let mut w = record();
            w[f] = v;
            bad.push(w);
        }
        let mut missing = record();
        missing.as_object_mut().unwrap().remove("id");
        bad.push(missing);
        bad.push(json!("not object"));
        for w in bad {
            let mut r = Registry::default();
            assert_eq!(r.register(&w, 1000), Err(crate::error_catalog::BAD_SPEC));
            assert!(r.doc["workers"].as_object().unwrap().is_empty());
        }
        let mut w = record();
        w["lanes"] = json!(["unknown"]);
        assert_eq!(registration(&w), Err(crate::error_catalog::UNKNOWN_LANE));
    }
    #[test]
    fn unknown_lane_refused() {
        let r = ready();
        assert_eq!(
            r.candidates("unknown", 1030),
            Err(crate::error_catalog::UNKNOWN_LANE)
        );
        assert_eq!(
            r.view("fixture", Some("unknown"), None, 1030),
            Err(crate::error_catalog::UNKNOWN_LANE)
        );
    }
    #[test]
    fn duplicate_id_refused() {
        let mut r = ready();
        let before = r.doc.clone();
        assert_eq!(
            r.register(&record(), 1030),
            Err(crate::error_catalog::WORKER_ID_EXISTS)
        );
        assert_eq!(r.doc, before);
    }
    #[test]
    fn re_register_after_gone() {
        let mut r = ready();
        r.sweep(1211);
        assert_eq!(r.doc["retired"][0]["state"], "gone");
        let v = r.register(&record(), 1300).unwrap();
        assert_eq!(v["generation"], 2);
        assert!(r.doc["retired"].as_array().unwrap().is_empty());
        assert!(Registry::decode(&serde_json::to_vec(&r.doc).unwrap()).is_ok());
    }
    #[test]
    fn seats_and_busy() {
        let mut r = ready();
        let v = r.claim("fixture", "job-1", 1030).unwrap();
        assert_eq!(v["state"], "busy");
        assert_eq!(v["seats_free"], 1);
        r.claim("fixture", "job-2", 1030).unwrap();
        assert_eq!(
            r.claim("fixture", "job-3", 1030),
            Err(crate::error_catalog::SEATS_FULL)
        );
        assert_eq!(
            r.claim("fixture", "job-1", 1030),
            Err(crate::error_catalog::BAD_SPEC)
        );
        assert_eq!(
            r.claim("absent", "job-1", 1030),
            Err(crate::error_catalog::UNKNOWN_WORKER)
        );
        assert_eq!(
            r.claim("fixture", "../escape", 1030),
            Err(crate::error_catalog::BAD_SPEC)
        );
        r.release("fixture", "job-1", 1030).unwrap();
        assert_eq!(
            r.release("fixture", "job-2", 1030).unwrap()["state"],
            "ready"
        );
        assert_eq!(
            r.release("fixture", "job-2", 1030),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[test]
    fn claim_refusals_by_state() {
        let mut r = Registry::default();
        r.register(&record(), 1000).unwrap();
        assert_eq!(
            r.claim("fixture", "job-1", 1000),
            Err(crate::error_catalog::WORKER_NOT_READY)
        );
        r.heartbeat("fixture", None, 1030).unwrap();
        r.claim("fixture", "job-1", 1030).unwrap();
        r.drain("fixture", Some("upgrade"), 1030).unwrap();
        assert_eq!(
            r.claim("fixture", "job-2", 1030),
            Err(crate::error_catalog::WORKER_DRAINING)
        );
        for reason in ["".to_owned(), "x".repeat(129)] {
            assert_eq!(
                r.drain("fixture", Some(&reason), 1030),
                Err(crate::error_catalog::BAD_SPEC)
            );
        }
        r.sweep(1121);
        assert_eq!(
            r.claim("fixture", "job-2", 1121),
            Err(crate::error_catalog::WORKER_STALE)
        );
    }
    #[test]
    fn drain_retires_when_idle() {
        let mut r = ready();
        r.claim("fixture", "job-1", 1030).unwrap();
        assert_eq!(
            r.drain("fixture", Some("upgrade"), 1030).unwrap()["state"],
            crate::error_catalog::DRAINING
        );
        assert_eq!(
            r.heartbeat("fixture", None, 1060).unwrap()["state"],
            crate::error_catalog::DRAINING
        );
        assert_eq!(
            r.release("fixture", "job-1", 1060).unwrap()["gone_because"],
            "drained"
        );
        assert!(r.doc["workers"].as_object().unwrap().is_empty());
    }
    #[test]
    fn sweep_exact_thresholds() {
        let mut r = ready();
        r.claim("fixture", "job-1", 1030).unwrap();
        for now in [1090, 1120] {
            assert_eq!(r.sweep(now)["stale"], json!([]));
        }
        assert_eq!(r.sweep(1121)["stale"], json!(["fixture"]));
        assert_eq!(r.doc["workers"]["fixture"]["jobs"], json!(["job-1"]));
        assert_eq!(r.sweep(1210)["gone"], json!([]));
        assert_eq!(r.sweep(1211)["gone"], json!(["fixture"]));
        assert_eq!(r.sweep(1211)["reassign"], json!([]));
    }
    #[test]
    fn sweep_reassign_report() {
        let mut r = ready();
        r.claim("fixture", "job-1", 1030).unwrap();
        assert_eq!(
            r.sweep(1121)["reassign"],
            json!([{"worker":"fixture","jobs":["job-1"],"reason":crate::error_catalog::WORKER_STALE,"final":false}])
        );
        assert_eq!(r.sweep(1211)["reassign"][0]["final"], true);
        assert_eq!(r.doc["retired"][0]["jobs"], json!([]));
    }
    #[test]
    fn stale_revival_keeps_drain() {
        let mut r = ready();
        r.claim("fixture", "job-1", 1030).unwrap();
        r.drain("fixture", Some("upgrade"), 1030).unwrap();
        r.sweep(1121);
        let v = r.heartbeat("fixture", None, 1121).unwrap();
        assert_eq!(v["state"], crate::error_catalog::DRAINING);
        assert_eq!(v["revived"], true);
        assert_eq!(v["jobs"], json!(["job-1"]));
    }
    #[test]
    fn candidates_and_why_not() {
        let r = ready();
        assert_eq!(r.candidates("tts", 1030).unwrap(), vec!["fixture"]);
        assert!(r.candidates("stt", 1030).unwrap().is_empty());
        assert_eq!(
            r.view("fixture", Some("stt"), Some("other"), 1030).unwrap()["why_not"],
            json!(["does not serve stt", "does not offer cartridge other"])
        );
    }
    #[test]
    fn fake_workers_beat_and_die() {
        let mut r = ready();
        for now in [1060, 1090, 1120] {
            r.heartbeat("fixture", None, now).unwrap();
            assert!(r.sweep(now)["stale"].as_array().unwrap().is_empty());
        }
        assert_eq!(r.sweep(1301)["gone"], json!(["fixture"]));
    }
    #[test]
    fn reload_equals_state() {
        let t = Temp::new();
        let p = t.0.join("state.json");
        let mut r = ready();
        r.claim("fixture", "job-1", 1030).unwrap();
        r.save(&p, 1030).unwrap();
        assert_eq!(Registry::load(&p).unwrap().doc, r.doc);
    }
    #[test]
    fn corrupt_state_refused() {
        let t = Temp::new();
        let p = t.0.join("state.json");
        let r = ready();
        let mut variants = vec![
            b"{\"workers\":".to_vec(),
            br#"{"api":1,"api":2}"#.to_vec(),
            b"[]".to_vec(),
            br#"{"api":"service-lane/v1"}"#.to_vec(),
        ];
        for (f, v) in [
            ("lanes", json!(["unknown"])),
            ("state", json!("vanished")),
            ("max_concurrency", Value::Null),
            ("exec", json!("/bin/false")),
            ("jobs", json!(["job-1", "job-2", "job-3"])),
        ] {
            let mut d = r.doc.clone();
            d["workers"]["fixture"][f] = v;
            variants.push(serde_json::to_vec(&d).unwrap());
        }
        let mut d = r.doc.clone();
        d["thresholds"]["stale_after_s"] = json!(91);
        variants.push(serde_json::to_vec(&d).unwrap());
        d = r.doc.clone();
        d["api"] = json!("other");
        variants.push(serde_json::to_vec(&d).unwrap());
        assert_eq!(variants.len(), 11);
        for raw in variants {
            fs::write(&p, &raw).unwrap();
            assert!(Registry::load(&p).is_err());
            assert_eq!(fs::read(&p).unwrap(), raw);
        }
    }
    #[test]
    fn cli_refuses_cleanly() {
        let t = Temp::new();
        let p = t.0.join("state.json");
        fs::write(&p, b"bad").unwrap();
        assert_eq!(
            cli(
                &[
                    "view".into(),
                    "--state".into(),
                    p.to_string_lossy().into(),
                    "--id".into(),
                    "fixture".into()
                ],
                1000
            ),
            Err(crate::error_catalog::STORAGE_UNAVAILABLE)
        );
    }
    #[test]
    fn atomic_persist_hygiene() {
        let t = Temp::new();
        let p = t.0.join("state.json");
        let mut r = ready();
        r.save(&p, 1030).unwrap();
        fs::write(t.0.join("state.json.tmp"), b"stale").unwrap();
        r.heartbeat("fixture", None, 1060).unwrap();
        r.save(&p, 1060).unwrap();
        assert_eq!(fs::read_dir(&t.0).unwrap().count(), 1);
        assert_eq!(Registry::load(&p).unwrap().doc, r.doc);
        let bytes = fs::read(&p).unwrap();
        assert_eq!(
            r.save(&t.0.join("absent/state.json"), 1060),
            Err(crate::error_catalog::STORAGE_UNAVAILABLE)
        );
        assert_eq!(fs::read(p).unwrap(), bytes);
    }
    #[test]
    fn schema_agreement() {
        let w = registration(&record()).unwrap();
        assert_eq!(w["lanes"], json!(["render-blender", "tts"]));
        let mut other = record();
        other["capabilities"] = json!([]);
        other["cartridges"] = json!([]);
        other["max_concurrency"] = json!(1);
        assert!(registration(&other).is_ok());
        registration_refusals();
    }
    #[test]
    fn import_audit() {
        let source = include_str!("worker_registry.rs");
        assert!(!source.lines().any(|line| line.starts_with("use std::net")));
    }
    #[test]
    fn injected_clock_is_the_only_clock() {
        let mut a = ready();
        let mut b = ready();
        for now in [900, 1120, 1121, 1210, 1211] {
            assert_eq!(a.sweep(now), b.sweep(now));
            assert_eq!(a.doc, b.doc);
        }
    }
    #[test]
    fn qc_reload_rejects_ambiguous_or_missing_fields() {
        let r = ready();
        let mut d = r.doc.clone();
        d["workers"]["fixture"]
            .as_object_mut()
            .unwrap()
            .remove("capabilities");
        assert!(Registry::decode(&serde_json::to_vec(&d).unwrap()).is_err());
        d = r.doc.clone();
        let mut retired = d["workers"]["fixture"].clone();
        retired["state"] = json!("gone");
        retired["gone_at"] = json!(1300);
        d["retired"] = json!([retired]);
        assert!(Registry::decode(&serde_json::to_vec(&d).unwrap()).is_err());
    }
    #[test]
    fn static_config_uses_registry_state() {
        let t = Temp::new();
        let state = t.0.join("state.json");
        let config = t.0.join("workers.cfg");
        let mut r = ready();
        r.save(&state, 1030).unwrap();
        fs::write(&config,serde_json::to_vec(&json!({"worker_state_path":state,"workers":[{"id":"fixture","lanes":["tts"],"kind":"exec","exec":"/bin/false","enabled":true}]})).unwrap()).unwrap();
        assert!(load_static(&config, 1120).unwrap()[0].enabled);
        assert!(!load_static(&config, 1121).unwrap()[0].enabled);
        fs::write(&config, br#"{"workers":[],"workers":[]}"#).unwrap();
        assert!(load_static(&config, 1121).is_err());
    }
}
