//! Offline lane gate and admission pin checks. No credential access.
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
static GATE_LOCK: Mutex<()> = Mutex::new(());
fn digest(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}
fn hash(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn placeholder(v: &Value) -> bool {
    v.as_str().is_none_or(|s| {
        matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "" | "placeholder" | "open" | "open-q7" | "pending" | "tbd" | "unset"
        )
    })
}
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON with unique fields")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Strict, M::Error> {
                let mut out = serde_json::Map::new();
                while let Some((field, value)) = map.next_entry::<String, Strict>()? {
                    if out.insert(field, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate field"));
                    }
                }
                Ok(Strict(Value::Object(out)))
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Strict, S::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<Strict>()? {
                    out.push(v.0);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Strict, E> {
                Ok(Strict(json!(s)))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse(data: &[u8]) -> Result<Value, &'static str> {
    serde_json::from_slice::<Strict>(data)
        .map(|v| v.0)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::BAD_JSON))
}
pub fn valid_pin(pin: &Value) -> bool {
    if !pin.as_object().is_some_and(|m| m.len() == 8) {
        return false;
    }
    pin["id"].as_str().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
    }) && hash(&pin["sha256"])
        && pin["voices"].as_array().is_some_and(|v| {
            !v.is_empty() && v.iter().all(|s| s.as_str().is_some_and(|s| !s.is_empty()))
        })
        && pin["rates"]
            .as_array()
            .is_some_and(|v| !v.is_empty() && v.iter().all(|n| n.as_u64().is_some_and(|n| n > 0)))
        && ["max_width", "max_height", "max_steps", "max_text_chars"]
            .iter()
            .all(|f| pin[*f].as_u64().is_some_and(|n| n > 0))
}
pub fn validate(doc: &Value) -> Result<(), &'static str> {
    if doc["kind"] != "cartridge-catalog/v1" {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_PINS));
    }
    let entries = doc["cartridges"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_PINS))?;
    let records = doc["lane_pins"]
        .as_array()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_PINS))?;
    let mut ids = HashSet::new();
    for e in entries {
        if !e.is_object() || !e["id"].is_string() || !ids.insert(e["id"].as_str().unwrap()) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_PINS));
        }
    }
    let mut lanes = HashSet::new();
    for r in records {
        let lane = r["lane"]
            .as_str()
            .filter(|l| crate::LANES.contains(l))
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_PINS))?;
        if !lanes.insert(lane) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_PINS));
        }
        if lane == "render-blender" {
            if r.get("pin").is_some()
                || r.get("model").is_some()
                || !r["pin_ids"].as_array().is_some_and(|a| {
                    !a.is_empty()
                        && a.iter().all(|v| {
                            v.as_str()
                                .is_some_and(|s| crate::RB_CARTRIDGES.contains(&s))
                        })
                })
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_PINS));
            }
            continue;
        }
        if (!r["model"].is_null() && !r["model"].is_string())
            || !r["cartridge"].is_string()
            || r.get("owner_approval").is_none()
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_PINS));
        }
        let e = entries
            .iter()
            .find(|e| e["id"] == r["cartridge"] && e["lane"] == lane)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_CARTRIDGE))?;
        if !e["licence"].is_string() || !hash(&e["sha256"]) || !e["pin"].is_object() {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::UNKNOWN_CARTRIDGE,
            ));
        }
        if !valid_pin(&r["pin"]) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::PIN_INCOMPATIBLE,
            ));
        }
        if r["pin"] != e["pin"] {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_PINS));
        }
    }
    if lanes.len() != crate::LANES.len() {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_PINS));
    }
    Ok(())
}
pub fn blockers(doc: &Value, lane: &str) -> Vec<&'static str> {
    let r = doc["lane_pins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["lane"] == lane)
        .unwrap();
    let e = doc["cartridges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == r["cartridge"])
        .unwrap();
    let mut out = Vec::new();
    if placeholder(&r["model"]) {
        out.push(crate::error_catalog::reason(
            crate::error_catalog::MODEL_UNRESOLVED,
        ));
    }
    let id = e["id"].as_str().unwrap();
    if placeholder(&e["licence"])
        || e["sha256"] == digest(&format!("placeholder-cartridge/{id}"))
        || r["pin"]["sha256"] == digest(lane)
    {
        out.push(crate::error_catalog::reason(
            crate::error_catalog::CARTRIDGE_PLACEHOLDER,
        ));
    }
    if placeholder(&r["owner_approval"]) {
        out.push(crate::error_catalog::reason(
            crate::error_catalog::APPROVAL_MISSING,
        ));
    }
    out
}
fn gated(lane: &str) -> Result<(), &'static str> {
    if !crate::LANES.contains(&lane) {
        Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ))
    } else if lane == "render-blender" {
        Err(crate::error_catalog::reason(
            crate::error_catalog::LANE_NOT_GATED,
        ))
    } else {
        Ok(())
    }
}
pub fn admit(config: &Value, spec: &Value) -> Result<(), &'static str> {
    let lane = spec["lane"]
        .as_str()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_LANE))?;
    if lane == "render-blender" {
        return crate::render_admission::gate(config, spec);
    }
    gated(lane)?;
    if config["lanes"][lane] != true {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::LANE_DISABLED,
        ));
    }
    if let Some(path) = config["lane_gate_state_dir"].as_str() {
        if !state(Path::new(path))?.contains(lane) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::LANE_DISABLED,
            ));
        }
    }
    let doc = if let Some(path) = config["pins_path"].as_str() {
        parse(
            &fs::read(path)
                .map_err(|_| crate::error_catalog::reason(crate::error_catalog::PINS_UNREADABLE))?,
        )?
    } else {
        config["pins"].clone()
    };
    validate(&doc)?;
    if let Some(code) = blockers(&doc, lane).first() {
        return Err(code);
    }
    let r = doc["lane_pins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["lane"] == lane)
        .unwrap();
    if spec["cartridge"] != r["cartridge"] {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PIN_INCOMPATIBLE,
        ));
    }
    bounds(&r["pin"], spec)
}
pub fn bounds(pin: &Value, spec: &Value) -> Result<(), &'static str> {
    if !valid_pin(pin) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PIN_INCOMPATIBLE,
        ));
    }
    for (field, bound) in [
        ("width", "max_width"),
        ("height", "max_height"),
        ("steps", "max_steps"),
    ] {
        if spec
            .get(field)
            .or_else(|| spec["size"].get(field))
            .is_some_and(|v| {
                !v.as_u64()
                    .is_some_and(|n| n > 0 && n <= pin[bound].as_u64().unwrap())
            })
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::PIN_INCOMPATIBLE,
            ));
        }
    }
    if spec["text"]
        .as_str()
        .is_some_and(|s| s.chars().count() as u64 > pin["max_text_chars"].as_u64().unwrap())
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PIN_INCOMPATIBLE,
        ));
    }
    if spec
        .get("sample_rate")
        .is_some_and(|v| !pin["rates"].as_array().unwrap().contains(v))
        || spec
            .get("voice")
            .is_some_and(|v| !pin["voices"].as_array().unwrap().contains(v))
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PIN_INCOMPATIBLE,
        ));
    }
    Ok(())
}
fn state(root: &Path) -> Result<BTreeSet<String>, &'static str> {
    let data = match fs::read(root.join("state.json")) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(_) => {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::STATE_UNREADABLE,
            ))
        }
    };
    let v = parse(&data)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STATE_CORRUPT))?;
    if v["kind"] != "lanegate-state/v1" {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::STATE_CORRUPT,
        ));
    }
    v["enabled"]
        .as_array()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::STATE_CORRUPT))?
        .iter()
        .map(|l| {
            l.as_str()
                .filter(|s| crate::LANES.contains(s) && *s != "render-blender")
                .map(str::to_owned)
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::STATE_CORRUPT))
        })
        .collect()
}
pub fn call(
    action: &str,
    lane: &str,
    doc: &Value,
    root: &Path,
    now: u64,
) -> Result<Value, &'static str> {
    if !matches!(action, "check" | "enable" | "disable") || (action == "check" && lane != "-") {
        return Err(crate::error_catalog::reason(crate::error_catalog::USAGE));
    }
    let _guard = GATE_LOCK.lock().unwrap();
    let result = (|| {
        let mut enabled = state(root)?;
        if action != "check" {
            gated(lane)?;
        }
        validate(doc)?;
        if action == "enable" {
            if let Some(code) = blockers(doc, lane).first() {
                return Err(*code);
            }
            enabled.insert(lane.into());
        }
        if action == "disable" {
            enabled.remove(lane);
        }
        if action == "check" {
            validate(doc)?;
            let lanes:Vec<Value>=crate::LANES.iter().map(|l| {
                let r=doc["lane_pins"].as_array().unwrap().iter().find(|r|r["lane"]==*l).unwrap();
                if *l=="render-blender" {return json!({"lane":l,"gated":false,"state":"s01-legacy","pin_ids":r["pin_ids"]});}
                let reasons=blockers(doc,l);
                json!({"lane":l,"gated":true,"state":if enabled.contains(*l){"enabled"}else{"disabled"},"model":r["model"],"cartridge":r["cartridge"],"ready":reasons.is_empty(),"blockers":reasons.iter().map(|c|json!({"code":c,"detail":c})).collect::<Vec<_>>()})
            }).collect();
            return Ok(json!({"ok":true,"gate":"lane-gate/v1","enabled":enabled,"lanes":lanes}));
        }
        fs::create_dir_all(root)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STATE_UNWRITABLE))?;
        let tmp = root.join(".state.new");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STATE_UNWRITABLE))?;
        let written = (|| {
            file.write_all(
                serde_json::to_vec(&json!({"kind":"lanegate-state/v1","enabled":enabled}))
                    .unwrap()
                    .as_slice(),
            )?;
            file.sync_all()?;
            fs::rename(&tmp, root.join("state.json"))?;
            fs::File::open(root)?.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(tmp);
            return Err(crate::error_catalog::reason(
                crate::error_catalog::STATE_UNWRITABLE,
            ));
        }
        Ok(
            json!({"ok":true,"lane":lane,"state":if enabled.contains(lane){"enabled"}else{"disabled"}}),
        )
    })();
    append_audit(root, lane, action, now, &result)?;
    result
}
fn append_audit(
    root: &Path,
    lane: &str,
    action: &str,
    now: u64,
    result: &Result<Value, &'static str>,
) -> Result<(), &'static str> {
    fs::create_dir_all(root)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::AUDIT_UNWRITABLE))?;
    let mut audit = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("audit.jsonl"))
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::AUDIT_UNWRITABLE))?;
    let line = json!({"time":crate::utc_stamp(now).ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::CLOCK_UNAVAILABLE))?,"lane":lane,"action":action,"result":if result.is_ok(){"ok"}else if result.as_ref().err().is_some_and(|e|matches!(*e,crate::error_catalog::STATE_CORRUPT|crate::error_catalog::STATE_UNREADABLE|crate::error_catalog::STATE_UNWRITABLE)){"error"}else{"refused"},"reason":result.as_ref().err().copied().unwrap_or("-")});
    writeln!(audit, "{}", crate::log_redaction::document(&line))
        .and_then(|()| audit.sync_all())
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::AUDIT_UNWRITABLE))?;
    Ok(())
}
pub fn execute(
    action: &str,
    lane: &str,
    pins: &Path,
    root: &Path,
    now: u64,
) -> Result<Value, &'static str> {
    match fs::read(pins)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::PINS_UNREADABLE))
        .and_then(|data| parse(&data))
    {
        Ok(doc) => call(action, lane, &doc, root, now),
        Err(code) => {
            let result = Err(code);
            append_audit(root, lane, action, now, &result)?;
            result
        }
    }
}

pub fn valid_cli(args: &[String]) -> bool {
    let Some(action) = args.first().map(String::as_str) else {
        return false;
    };
    let first = match action {
        "check" => 1,
        "enable" | "disable" => {
            if args.get(1).is_none_or(|s| s.starts_with('-')) {
                return false;
            }
            2
        }
        _ => return false,
    };
    let mut flags = HashSet::new();
    let mut index = first;
    while index < args.len() {
        if !matches!(args[index].as_str(), "--pins" | "--state-dir")
            || !flags.insert(args[index].as_str())
            || args.get(index + 1).is_none_or(|s| s.starts_with('-'))
        {
            return false;
        }
        index += 2;
    }
    flags.len() == 2
}

#[cfg(test)]
pub(crate) fn fixture_config(mut config: Value, lane: &str, cartridge: &str) -> Value {
    let mut entries = Vec::new();
    let mut records = Vec::new();
    for l in crate::LANES {
        if *l == "render-blender" {
            records.push(json!({"lane":l,"pin_ids":[crate::RB_CARTRIDGES[0]]}));
            continue;
        }
        let id = if *l == lane { cartridge } else { l };
        let pin = json!({"id":id,"sha256":digest("fixture pin"),"voices":["default"],"rates":[16000,22050,24000,44100,48000],"max_width":1536,"max_height":1536,"max_steps":100,"max_text_chars":10000});
        entries.push(json!({"id":id,"lane":l,"licence":"fixture","sha256":digest("fixture artifact"),"pin":pin}));
        records.push(
            json!({"lane":l,"model":"fixture","cartridge":id,"pin":pin,"owner_approval":"[owner]"}),
        );
    }
    config["pins"] =
        json!({"kind":"cartridge-catalog/v1","cartridges":entries,"lane_pins":records});
    config
}
#[cfg(test)]
pub fn gated_lanes() -> Vec<&'static str> {
    crate::LANES
        .iter()
        .copied()
        .filter(|lane| gated(lane).is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn doc() -> Value {
        fixture_config(json!({}), "tts", "voice")["pins"].clone()
    }
    fn shipped() -> Value {
        let mut d = doc();
        for r in d["lane_pins"].as_array_mut().unwrap() {
            if r["lane"] == "render-blender" {
                continue;
            }
            let l = r["lane"].as_str().unwrap().to_owned();
            r["model"] = json!("OPEN-Q7");
            r["owner_approval"] = Value::Null;
            r["pin"]["sha256"] = json!(digest(&l));
        }
        for e in d["cartridges"].as_array_mut().unwrap() {
            e["licence"] = json!("placeholder");
            e["sha256"] = json!(digest(&format!(
                "placeholder-cartridge/{}",
                e["id"].as_str().unwrap()
            )));
            e["pin"]["sha256"] = json!(digest(e["lane"].as_str().unwrap()));
        }
        d
    }
    fn root() -> std::path::PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let r = std::env::temp_dir().join(format!(
            "gate-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&r).unwrap();
        r
    }
    fn record(d: &mut Value) -> &mut Value {
        d["lane_pins"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["lane"] == "tts")
            .unwrap()
    }
    fn entry(d: &mut Value) -> &mut Value {
        d["cartridges"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["lane"] == "tts")
            .unwrap()
    }
    #[test]
    fn check_shipped() {
        let r = root();
        let d = shipped();
        validate(&d).unwrap();
        let v = call("check", "-", &d, &r, 0).unwrap();
        assert_eq!(v["enabled"], json!([]));
        assert_eq!(v["lanes"].as_array().unwrap().len(), 6);
        assert_eq!(
            blockers(&d, "tts"),
            [
                crate::error_catalog::MODEL_UNRESOLVED,
                crate::error_catalog::CARTRIDGE_PLACEHOLDER,
                crate::error_catalog::APPROVAL_MISSING
            ]
        );
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn enable_refused_shipped() {
        let r = root();
        for l in &crate::LANES[1..] {
            assert_eq!(
                call("enable", l, &shipped(), &r, 0),
                Err(crate::error_catalog::MODEL_UNRESOLVED)
            );
        }
        assert_eq!(
            fs::read_to_string(r.join("audit.jsonl"))
                .unwrap()
                .lines()
                .count(),
            5
        );
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn unknown_lane() {
        assert_eq!(gated("tts-2"), Err(crate::error_catalog::UNKNOWN_LANE));
    }
    #[test]
    fn render_not_gated() {
        let r = root();
        for action in ["enable", "disable"] {
            assert_eq!(
                call(action, "render-blender", &doc(), &r, 0),
                Err(crate::error_catalog::LANE_NOT_GATED)
            );
        }
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn bad_json() {
        assert_eq!(parse(b"{"), Err(crate::error_catalog::BAD_JSON));
    }
    #[test]
    fn duplicate_key() {
        assert_eq!(
            parse(br#"{"kind":"one","kind":"two"}"#),
            Err(crate::error_catalog::BAD_JSON)
        );
        assert_eq!(
            parse(br#"{"a":[{"x":1,"x":2}]}"#),
            Err(crate::error_catalog::BAD_JSON)
        );
    }
    #[test]
    fn shape_missing_record() {
        let mut d = doc();
        d["lane_pins"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["lane"] != "tts");
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_PINS));
    }
    #[test]
    fn pin_form() {
        let mut d = doc();
        record(&mut d)["pin"]
            .as_object_mut()
            .unwrap()
            .remove("rates");
        assert_eq!(validate(&d), Err(crate::error_catalog::PIN_INCOMPATIBLE));
    }
    #[test]
    fn pin_mismatch() {
        let mut d = doc();
        record(&mut d)["pin"]["max_steps"] = json!(50);
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_PINS));
    }
    #[test]
    fn cartridge_ghost() {
        let mut d = doc();
        record(&mut d)["cartridge"] = json!("ghost");
        assert_eq!(validate(&d), Err(crate::error_catalog::UNKNOWN_CARTRIDGE));
    }
    #[test]
    fn model_open_only() {
        let mut d = doc();
        record(&mut d)["model"] = json!("OPEN-Q7");
        assert_eq!(
            blockers(&d, "tts"),
            [crate::error_catalog::MODEL_UNRESOLVED]
        );
    }
    #[test]
    fn cartridge_placeholder_licence() {
        let mut d = doc();
        entry(&mut d)["licence"] = json!("placeholder");
        assert_eq!(
            blockers(&d, "tts"),
            [crate::error_catalog::CARTRIDGE_PLACEHOLDER]
        );
    }
    #[test]
    fn cartridge_placeholder_sha() {
        let mut d = doc();
        entry(&mut d)["sha256"] = json!(digest("placeholder-cartridge/voice"));
        assert_eq!(
            blockers(&d, "tts"),
            [crate::error_catalog::CARTRIDGE_PLACEHOLDER]
        );
    }
    #[test]
    fn cartridge_placeholder_pin_sha() {
        let mut d = doc();
        record(&mut d)["pin"]["sha256"] = json!(digest("tts"));
        assert_eq!(
            blockers(&d, "tts"),
            [crate::error_catalog::CARTRIDGE_PLACEHOLDER]
        );
    }
    #[test]
    fn approval_missing_only() {
        let mut d = doc();
        record(&mut d)["owner_approval"] = Value::Null;
        assert_eq!(
            blockers(&d, "tts"),
            [crate::error_catalog::APPROVAL_MISSING]
        );
    }
    #[test]
    fn enable_ok_filled() {
        let r = root();
        for action in ["enable", "enable", "disable", "disable"] {
            assert_eq!(
                call(action, "tts", &doc(), &r, 0).unwrap()["state"],
                if action == "enable" {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            assert_eq!(state(&r).unwrap().contains("tts"), action == "enable");
        }
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn disable_without_enable() {
        let r = root();
        assert_eq!(
            call("disable", "stt", &shipped(), &r, 0).unwrap()["state"],
            "disabled"
        );
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn audit_one_line_per_call() {
        let r = root();
        let d = doc();
        for (action, lane) in [
            ("check", "-"),
            ("enable", "tts"),
            ("disable", "tts"),
            ("enable", "tts-2"),
        ] {
            let _ = call(action, lane, &d, &r, 0);
        }
        let text = fs::read_to_string(r.join("audit.jsonl")).unwrap();
        assert_eq!(text.lines().count(), 4);
        for line in text.lines() {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(v.as_object().unwrap().len(), 5);
            assert_eq!(v["time"], "1970-01-01T00:00:00Z");
        }
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn token_files_untouched() {
        let r = root();
        let adjacent = r.join("adjacent.txt");
        fs::write(&adjacent, b"[R]").unwrap();
        let plain = root();
        assert_eq!(
            call("enable", "tts", &doc(), &r, 0),
            call("enable", "tts", &doc(), &plain, 0)
        );
        assert_eq!(fs::read(adjacent).unwrap(), b"[R]");
        assert!(!fs::read_to_string(r.join("audit.jsonl"))
            .unwrap()
            .contains("[R]"));
        fs::remove_dir_all(r).unwrap();
        fs::remove_dir_all(plain).unwrap();
    }
    #[test]
    fn state_corrupt_fails_closed() {
        let r = root();
        fs::write(r.join("state.json"), b"bad").unwrap();
        assert_eq!(
            call("enable", "tts", &doc(), &r, 0),
            Err(crate::error_catalog::STATE_CORRUPT)
        );
        let v: Value =
            serde_json::from_str(fs::read_to_string(r.join("audit.jsonl")).unwrap().trim())
                .unwrap();
        assert_eq!(v["result"], "error");
        fs::remove_dir_all(r).unwrap();
    }
    #[test]
    fn duplicate_catalog_id_refused() {
        let mut d = doc();
        let e = d["cartridges"][0].clone();
        d["cartridges"].as_array_mut().unwrap().push(e);
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_PINS));
    }
    #[test]
    fn admission_default_and_pin_limits() {
        assert_eq!(
            admit(&json!({}), &json!({"lane":"tts"})),
            Err(crate::error_catalog::LANE_DISABLED)
        );
        let c = fixture_config(json!({"lanes":{"tts":true}}), "tts", "voice");
        let mut s = json!({"lane":"tts","cartridge":"voice","sample_rate":24000});
        assert_eq!(admit(&c, &s), Ok(()));
        s["sample_rate"] = json!(1);
        assert_eq!(admit(&c, &s), Err(crate::error_catalog::PIN_INCOMPATIBLE));
        s["sample_rate"] = json!(24000);
        s["width"] = json!(1600);
        assert_eq!(admit(&c, &s), Err(crate::error_catalog::PIN_INCOMPATIBLE));
    }
    #[test]
    fn usage_is_controlled() {
        for args in [
            vec![],
            vec!["unknown"],
            vec!["enable"],
            vec!["check", "tts"],
            vec!["check", "--bad", "x"],
        ] {
            assert!(!valid_cli(
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
            ));
        }
        let r = root();
        assert_eq!(
            call("unknown", "-", &doc(), &r, 0),
            Err(crate::error_catalog::USAGE)
        );
        assert!(!r.join("audit.jsonl").exists());
        fs::remove_dir_all(r).unwrap();
    }
}
