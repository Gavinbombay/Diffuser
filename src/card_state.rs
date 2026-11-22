use serde_json::{json, Value};
use std::{collections::HashMap, path::Path, sync::OnceLock};

const CARDS: [(&str, &str); 3] = [
    ("colab-l4", "colab-l4-state.json"),
    ("local-3060", "cards/local-3060.json"),
    ("local-2070", "cards/local-2070.json"),
];

fn validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value =
            serde_json::from_str(include_str!("card-state.schema.json")).expect("embedded schema");
        jsonschema::validator_for(&schema).expect("valid embedded schema")
    })
}

/// Check an independently supplied probe against a validated, registered card.
/// No caller may treat a missing or future observation as evidence.
pub(crate) fn proof(
    state: &Value,
    registered: bool,
    now: u64,
    probe: Option<&Value>,
) -> Result<&'static str, &'static str> {
    if state["card"] == "local-3060" {
        let p = state.get("self_probe").ok_or_else(|| {
            crate::error_catalog::reason(crate::error_catalog::SELF_PROBE_MISSING)
        })?;
        if p["worker_id"] != state["worker_id"] || !p["worker_id"].is_string() {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::SELF_PROBE_WORKER_MISMATCH,
            ));
        }
    }
    if !crate::schema_wire::card_state(state) || !validator().is_valid(state) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::STATE_UNREADABLE,
        ));
    }
    if !registered {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNREGISTERED_WORKER,
        ));
    }
    let card = state["card"].as_str().unwrap_or("");
    let source = if card == "local-3060" {
        "self-probe"
    } else {
        "router-probe"
    };
    let observation = if source == "self-probe" {
        let p = state.get("self_probe").ok_or_else(|| {
            crate::error_catalog::reason(crate::error_catalog::SELF_PROBE_MISSING)
        })?;
        if p["worker_id"] != state["worker_id"] {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::SELF_PROBE_WORKER_MISMATCH,
            ));
        }
        p
    } else {
        probe.ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::PROBE_MISSING))?
    };
    let epoch = observation["epoch"]
        .as_u64()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::PROBE_MISSING))?;
    if epoch > now || now - epoch > 120 {
        return Err(if source == "self-probe" {
            "stale-self-probe"
        } else {
            "stale-probe"
        });
    }
    if card != "colab-l4"
        && ["util", "watts"].iter().any(|field| {
            observation[field]
                .as_f64()
                .zip(state[field].as_f64())
                .is_none_or(|(a, b)| a != b)
        })
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PROBE_MISMATCH,
        ));
    }
    Ok(source)
}

/// Evaluate a refreshed snapshot without mistaking the router's freshness field
/// for part of the writer's schema. Stale snapshots must never become proof.
pub(crate) fn snapshot_proof(
    state: &Value,
    registered_worker: Option<&str>,
    now: u64,
    probe: Option<&Value>,
) -> Result<&'static str, &'static str> {
    if state["stale"] != false {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::STALE_STATE,
        ));
    }
    let mut original = state.clone();
    if let Some(object) = original.as_object_mut() {
        object.remove("stale");
    }
    let registered = registered_worker.is_some_and(|id| original["worker_id"].as_str() == Some(id));
    proof(&original, registered, now, probe)
}

/// A lease can only use a fresh registered Colab snapshot whose heartbeat
/// proves the same snapshot. Availability and CU checks remain separate.
#[allow(dead_code)] // The HTTP pull integration will use this gate.
pub(crate) fn colab_proof(
    state: &Value,
    registered_worker: Option<&str>,
    now: u64,
) -> Result<&'static str, &'static str> {
    if state["card"] != "colab-l4" {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::WORKER_MISMATCH,
        ));
    }
    let heartbeat = json!({"epoch": state["epoch"]});
    snapshot_proof(state, registered_worker, now, Some(&heartbeat))
}

/// Expose the proof verdict without overriding any other admission decision.
/// A proved card may still be disabled, busy, or otherwise unsuitable.
pub(crate) fn annotate_proof(
    row: &mut Value,
    state: &Value,
    registered_worker: Option<&str>,
    now: u64,
    probe: Option<&Value>,
) {
    let source = if state["card"] == "local-3060" {
        "self-probe"
    } else {
        "router-probe"
    };
    row["proof_source"] = json!(source);
    match snapshot_proof(state, registered_worker, now, probe) {
        Ok(_) => {
            row["proved"] = json!(true);
            row["proof_reason"] = Value::Null;
        }
        Err(reason) => {
            row["proved"] = json!(false);
            row["proof_reason"] = json!(reason);
        }
    }
}

/// Refresh only snapshots delivered through the service-owned state directory.
pub(crate) fn refresh(dir: &Path, now: u64) -> HashMap<String, Value> {
    let root = crate::private_state::PrivateDir::open(dir).ok();
    refresh_with(now, |path| {
        root.as_ref()
            .ok_or(std::io::ErrorKind::PermissionDenied.into())
            .and_then(|root| root.read(path))
    })
}

fn refresh_with<F>(now: u64, mut read: F) -> HashMap<String, Value>
where
    F: FnMut(&Path) -> std::io::Result<Vec<u8>>,
{
    CARDS.iter().map(|(card, path)| {
        let state = read(Path::new(path)).ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(|v| crate::schema_wire::card_state(v) && validator().is_valid(v) && v["card"] == *card);
        let row = match state {
            Some(mut v) => {
                let stale = now.saturating_sub(v["epoch"].as_u64().unwrap_or(0)) > 180 || v["epoch"].as_u64().unwrap_or(u64::MAX) > now;
                v["stale"] = json!(stale);
                if stale {
                    for field in ["util", "watts", "vram_mb", "vram_total_mb", "ram_mb", "backends", "capacity", "gpu_class", "vram_gb"] { v[field] = json!("unknown"); }
                }
                v
            }
            None => json!({"card":card,"stale":true,"state":crate::error_catalog::STATE_UNREADABLE,"util":"unknown","watts":"unknown","vram_mb":"unknown","vram_total_mb":"unknown","ram_mb":"unknown","backends":"unknown","capacity":"unknown","gpu_class":"unknown","vram_gb":"unknown","ts":"unknown"}),
        };
        (card.to_string(), row)
    }).collect()
}

pub(crate) fn apply(row: &mut Value, state: &Value) {
    for field in [
        "util",
        "watts",
        "vram_mb",
        "vram_total_mb",
        "ram_mb",
        "backends",
        "capacity",
        "gpu_class",
        "vram_gb",
        "ts",
        "stale",
        "state",
    ] {
        row[field] = state.get(field).cloned().unwrap_or(json!("unknown"));
    }
    // Pushed state alone is not proof of dispatch eligibility. R2b provides proof.
    row["accepting"] = json!(false);
    if let Some(why) = row["why_not"].as_array_mut() {
        why.push(json!(
            if state["state"] == crate::error_catalog::STATE_UNREADABLE {
                crate::error_catalog::STATE_UNREADABLE
            } else if state["stale"] == true {
                "stale card state"
            } else {
                "card state not proved"
            }
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    #[test]
    fn run32_every_card_state_snapshot_event_pair() {
        let schema: Value = serde_json::from_str(include_str!("card-state.schema.json")).unwrap();
        let states = ["idle", "busy", "unknown"];
        assert_eq!(schema["properties"]["state"]["enum"], json!(states));
        // Pushed cards are snapshots: every schema state may replace every other.
        // Invalid snapshots become the existing fail-closed unreadable sentinel.
        let events = [
            "idle",
            "busy",
            "unknown",
            "invalid",
            "malformed",
            "missing",
            "stale",
            "future",
        ];
        let (base, probe, now) = local_proof_fixture();
        let mut evidence = Vec::new();
        for previous in states
            .into_iter()
            .chain([crate::error_catalog::STATE_UNREADABLE])
        {
            for event in events {
                let mut incoming = base.clone();
                incoming["state"] = json!(if matches!(event, "stale" | "future") {
                    "idle"
                } else {
                    event
                });
                if event == "stale" {
                    incoming["epoch"] = json!(now - 181);
                }
                if event == "future" {
                    incoming["epoch"] = json!(now + 1);
                }
                let bytes = if event == "malformed" {
                    b"{".to_vec()
                } else {
                    serde_json::to_vec(&incoming).unwrap()
                };
                let rows = refresh_with(now, |path| {
                    if path.ends_with("cards/local-2070.json") && event != "missing" {
                        Ok(bytes.clone())
                    } else {
                        Err(std::io::ErrorKind::NotFound.into())
                    }
                });
                let mut row = json!({"state":previous,"accepting":true,"why_not":[]});
                apply(&mut row, &rows["local-2070"]);
                let invalid = matches!(event, "invalid" | "malformed" | "missing");
                let expected = if invalid {
                    crate::error_catalog::STATE_UNREADABLE
                } else if matches!(event, "stale" | "future") {
                    "idle"
                } else {
                    event
                };
                assert_eq!(row["state"], expected, "{previous}/{event}");
                assert_eq!(row["accepting"], false, "{previous}/{event}");
                if invalid {
                    assert_eq!(row["why_not"][0], crate::error_catalog::STATE_UNREADABLE);
                    assert_eq!(crate::error_catalog::canonical_code(expected), expected);
                    assert!(!validator().is_valid(&incoming));
                } else if matches!(event, "stale" | "future") {
                    assert_eq!(
                        snapshot_proof(&rows["local-2070"], Some("local-2070"), now, Some(&probe)),
                        Err(crate::error_catalog::STALE_STATE)
                    );
                    assert_eq!(row["stale"], true);
                } else {
                    assert_eq!(row["stale"], false);
                    assert!(validator().is_valid(&incoming));
                }
                evidence.push(json!({"previous":previous,"event":event,"next":expected}));
            }
        }
        assert_eq!(evidence.len(), 32);
        fs::create_dir_all(crate::test_process::target_dir()).unwrap();
        fs::write(
            crate::test_process::target_dir().join("run32-r4-table.json"),
            serde_json::to_vec_pretty(&json!({"result":"PASS","pairs":evidence})).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn proof_valid_registered_probe_match_proved() {
        let (state, probe, now) = local_proof_fixture();
        assert_eq!(proof(&state, true, now, Some(&probe)), Ok("router-probe"));
    }
    #[test]
    fn proof_schema_invalid_unregistered_stale_mismatch_not_proved() {
        let (mut state, mut probe, now) = local_proof_fixture();
        assert_eq!(
            proof(&state, false, now, Some(&probe)),
            Err(crate::error_catalog::UNREGISTERED_WORKER)
        );
        assert_eq!(
            proof(&state, true, now + 121, Some(&probe)),
            Err("stale-probe")
        );
        probe["watts"] = json!(999);
        assert_eq!(
            proof(&state, true, now, Some(&probe)),
            Err(crate::error_catalog::PROBE_MISMATCH)
        );
        state["schema_version"] = json!("invalid");
        assert_eq!(
            proof(&state, true, now, Some(&probe)),
            Err(crate::error_catalog::STATE_UNREADABLE)
        );
    }
    #[test]
    fn self_probe_fresh_proved_stale_121s_and_worker_mismatch_not() {
        let mut state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/local-3060-self-probe-fresh.json"
        ))
        .unwrap();
        let epoch = state["self_probe"]["epoch"].as_u64().unwrap();
        assert_eq!(proof(&state, true, epoch + 120, None), Ok("self-probe"));
        assert_eq!(
            proof(&state, true, epoch + 121, None),
            Err("stale-self-probe")
        );
        state["self_probe"]["worker_id"] = json!("other");
        assert_eq!(
            proof(&state, true, epoch, None),
            Err(crate::error_catalog::SELF_PROBE_WORKER_MISMATCH)
        );
    }
    fn local_proof_fixture() -> (Value, Value, u64) {
        let state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/local-2070.json"
        ))
        .unwrap();
        let now = state["epoch"].as_u64().unwrap();
        let probe = json!({"epoch":now,"util":state["util"],"watts":state["watts"]});
        (state, probe, now)
    }
    #[test]
    fn router_probe_at_120_seconds_is_valid() {
        let (state, probe, now) = local_proof_fixture();
        assert_eq!(
            proof(&state, true, now + 120, Some(&probe)),
            Ok("router-probe")
        );
    }
    #[test]
    fn future_router_probe_is_refused() {
        let (state, mut probe, now) = local_proof_fixture();
        probe["epoch"] = json!(now + 1);
        assert_eq!(proof(&state, true, now, Some(&probe)), Err("stale-probe"));
    }
    #[test]
    fn missing_router_probe_is_refused() {
        let (state, _, now) = local_proof_fixture();
        assert_eq!(
            proof(&state, true, now, None),
            Err(crate::error_catalog::PROBE_MISSING)
        );
    }
    #[test]
    fn router_probe_watts_mismatch_is_refused() {
        let (state, mut probe, now) = local_proof_fixture();
        probe["watts"] = json!(999);
        assert_eq!(
            proof(&state, true, now, Some(&probe)),
            Err(crate::error_catalog::PROBE_MISMATCH)
        );
    }
    fn fresh_colab() -> (Value, u64) {
        let mut state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/colab-l4-state.json"
        ))
        .unwrap();
        let now = state["epoch"].as_u64().unwrap();
        state["stale"] = json!(false);
        (state, now)
    }
    #[test]
    fn colab_proof_accepts_registered_fresh_snapshot() {
        let (state, now) = fresh_colab();
        assert_eq!(
            colab_proof(&state, Some("colab-l4"), now),
            Ok("router-probe")
        );
    }
    #[test]
    fn colab_proof_rejects_unregistered_snapshot() {
        let (state, now) = fresh_colab();
        assert_eq!(
            colab_proof(&state, None, now),
            Err(crate::error_catalog::UNREGISTERED_WORKER)
        );
    }
    #[test]
    fn colab_proof_rejects_heartbeat_over_120_seconds() {
        let (state, now) = fresh_colab();
        assert_eq!(
            colab_proof(&state, Some("colab-l4"), now + 121),
            Err("stale-probe")
        );
    }
    #[test]
    fn colab_proof_rejects_invalid_schema() {
        let (mut state, now) = fresh_colab();
        state["schema_version"] = json!("invalid");
        assert_eq!(
            colab_proof(&state, Some("colab-l4"), now),
            Err(crate::error_catalog::STATE_UNREADABLE)
        );
    }
    #[test]
    fn colab_proof_rejects_wrong_card() {
        let (mut state, now) = fresh_colab();
        state["card"] = json!("local-2070");
        assert_eq!(
            colab_proof(&state, Some("colab-l4"), now),
            Err(crate::error_catalog::WORKER_MISMATCH)
        );
    }
    #[test]
    fn colab_heartbeat_must_be_fresh() {
        let state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/colab-l4-state.json"
        ))
        .unwrap();
        let now = state["epoch"].as_u64().unwrap();
        let heartbeat = json!({"epoch":now});
        assert_eq!(
            proof(&state, true, now + 120, Some(&heartbeat)),
            Ok("router-probe")
        );
        assert_eq!(
            proof(&state, true, now + 121, Some(&heartbeat)),
            Err("stale-probe")
        );
        assert_eq!(
            proof(&state, true, now, None),
            Err(crate::error_catalog::PROBE_MISSING)
        );
    }
    #[test]
    fn refreshed_snapshot_proof_requires_matching_registration() {
        let (dir, state) = fixture();
        let now = state["epoch"].as_u64().unwrap();
        let rows = refresh(&dir, now);
        let probe = json!({"epoch":now,"util":state["util"],"watts":state["watts"]});
        assert_eq!(
            snapshot_proof(&rows["local-2070"], Some("local-2070"), now, Some(&probe)),
            Ok("router-probe")
        );
        assert_eq!(
            snapshot_proof(&rows["local-2070"], Some("local-3060"), now, Some(&probe)),
            Err(crate::error_catalog::UNREGISTERED_WORKER)
        );
        assert_eq!(
            snapshot_proof(&rows["local-2070"], None, now, Some(&probe)),
            Err(crate::error_catalog::UNREGISTERED_WORKER)
        );
    }
    #[test]
    fn stale_or_unreadable_snapshot_never_proves() {
        let (dir, state) = fixture();
        let now = state["epoch"].as_u64().unwrap() + 181;
        let rows = refresh(&dir, now);
        assert_eq!(
            snapshot_proof(&rows["local-2070"], Some("local-2070"), now, None),
            Err(crate::error_catalog::STALE_STATE)
        );
        assert_eq!(
            snapshot_proof(&rows["local-3060"], Some("local-3060"), now, None),
            Err(crate::error_catalog::STALE_STATE)
        );
    }
    #[test]
    fn proof_annotation_preserves_other_admission_decisions() {
        let (dir, state) = fixture();
        let now = state["epoch"].as_u64().unwrap();
        let rows = refresh(&dir, now);
        let probe = json!({"epoch":now,"util":state["util"],"watts":state["watts"]});
        let mut row = json!({"accepting":false});
        annotate_proof(
            &mut row,
            &rows["local-2070"],
            Some("local-2070"),
            now,
            Some(&probe),
        );
        assert_eq!(row["proved"], true);
        assert_eq!(row["proof_source"], "router-probe");
        assert_eq!(row["accepting"], false);
        annotate_proof(&mut row, &rows["local-2070"], None, now, Some(&probe));
        assert_eq!(row["proved"], false);
        assert_eq!(
            row["proof_reason"],
            crate::error_catalog::UNREGISTERED_WORKER
        );
    }
    #[test]
    fn proof_requires_registered_matching_fresh_probe() {
        let state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/local-2070.json"
        ))
        .unwrap();
        let now = state["epoch"].as_u64().unwrap();
        let probe = json!({"epoch":now,"util":state["util"],"watts":state["watts"]});
        assert_eq!(proof(&state, true, now, Some(&probe)), Ok("router-probe"));
        assert_eq!(
            proof(&state, false, now, Some(&probe)),
            Err(crate::error_catalog::UNREGISTERED_WORKER)
        );
        assert_eq!(
            proof(&state, true, now + 121, Some(&probe)),
            Err("stale-probe")
        );
        let mut bad = probe;
        bad["util"] = json!(999);
        assert_eq!(
            proof(&state, true, now, Some(&bad)),
            Err(crate::error_catalog::PROBE_MISMATCH)
        );
        let mut bad_state = state;
        bad_state["schema_version"] = json!("invalid");
        assert_eq!(
            proof(&bad_state, true, now, Some(&bad)),
            Err(crate::error_catalog::STATE_UNREADABLE)
        );
    }
    #[test]
    fn self_probe_requires_identity_freshness_and_matching_values() {
        let mut state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/local-3060-self-probe-fresh.json"
        ))
        .unwrap();
        let now = state["epoch"].as_u64().unwrap();
        assert_eq!(proof(&state, true, now, None), Ok("self-probe"));
        assert_eq!(
            proof(
                &state,
                true,
                state["self_probe"]["epoch"].as_u64().unwrap() + 121,
                None
            ),
            Err("stale-self-probe")
        );
        state["self_probe"]["worker_id"] = json!("other");
        assert_eq!(
            proof(&state, true, now, None),
            Err(crate::error_catalog::SELF_PROBE_WORKER_MISMATCH)
        );
        state["self_probe"]["worker_id"] = json!("local-3060");
        state["self_probe"]["watts"] = json!(999);
        assert_eq!(
            proof(&state, true, now, None),
            Err(crate::error_catalog::PROBE_MISMATCH)
        );
    }
    #[test]
    fn missing_self_probe_is_not_proof() {
        let mut state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/local-3060-self-probe-fresh.json"
        ))
        .unwrap();
        let now = state["epoch"].as_u64().unwrap();
        state.as_object_mut().unwrap().remove("self_probe");
        assert_eq!(
            proof(&state, true, now, None),
            Err(crate::error_catalog::SELF_PROBE_MISSING)
        );
    }
    #[test]
    fn future_self_probe_is_not_proof() {
        let mut state: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/local-3060-self-probe-fresh.json"
        ))
        .unwrap();
        let now = state["epoch"].as_u64().unwrap();
        state["self_probe"]["epoch"] = json!(now + 1);
        assert_eq!(proof(&state, true, now, None), Err("stale-self-probe"));
    }
    fn fixture() -> (std::path::PathBuf, Value) {
        let dir = std::env::temp_dir().join(format!(
            "lane-card-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::private_state::fixture_dir(&dir);
        crate::private_state::fixture_dir(&dir.join("cards"));
        let bytes = include_bytes!("../tests/fixtures/card-state/local-2070.json");
        crate::private_state::fixture_file(&dir.join("cards/local-2070.json"), bytes);
        (dir, serde_json::from_slice(bytes).unwrap())
    }
    #[test]
    fn fresh_valid_card_stored() {
        let (dir, v) = fixture();
        let rows = refresh(&dir, v["epoch"].as_u64().unwrap());
        assert_eq!(rows["local-2070"]["util"], 3);
        assert_eq!(rows["local-2070"]["stale"], false);
    }
    #[test]
    fn colab_sample_validates_and_stores_class() {
        let (dir, _) = fixture();
        let bytes = include_bytes!("../tests/fixtures/card-state/colab-l4-state.json");
        let v: Value = serde_json::from_slice(bytes).unwrap();
        crate::private_state::fixture_file(&dir.join("colab-l4-state.json"), bytes);
        let rows = refresh(&dir, v["epoch"].as_u64().unwrap());
        assert_eq!(rows["colab-l4"]["gpu_class"], "L4");
        assert_eq!(rows["colab-l4"]["vram_gb"], 24);
    }
    #[test]
    fn freshness_boundary() {
        let (dir, v) = fixture();
        let epoch = v["epoch"].as_u64().unwrap();
        assert_eq!(
            refresh(&dir, epoch + 179)["local-2070"]["stale"],
            false
        );
        let stale = &refresh(&dir, epoch + 181)["local-2070"];
        assert_eq!(stale["stale"], true);
        assert_eq!(stale["util"], "unknown");
    }
    #[test]
    fn missing_state_unreadable() {
        let (dir, v) = fixture();
        assert_eq!(
            refresh(&dir, v["epoch"].as_u64().unwrap())["local-3060"]["state"],
            crate::error_catalog::STATE_UNREADABLE
        );
    }
    #[test]
    fn malformed_and_schema_invalid_unreadable() {
        let (dir, mut v) = fixture();
        let path = dir.join("cards/local-2070.json");
        fs::write(&path, b"{").unwrap();
        assert_eq!(
            refresh(&dir, 0)["local-2070"]["state"],
            crate::error_catalog::STATE_UNREADABLE
        );
        v["schema_version"] = json!("other");
        fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(
            refresh(&dir, 0)["local-2070"]["state"],
            crate::error_catalog::STATE_UNREADABLE
        );
    }
    #[test]
    fn workers_row_contains_stored_fields() {
        let (dir, v) = fixture();
        let rows = refresh(&dir, v["epoch"].as_u64().unwrap());
        let mut row = json!({"accepting":true,"why_not":[]});
        apply(&mut row, &rows["local-2070"]);
        for field in [
            "util",
            "watts",
            "vram_mb",
            "vram_total_mb",
            "ram_mb",
            "backends",
            "capacity",
            "vram_gb",
            "ts",
        ] {
            assert_eq!(row[field], v[field]);
        }
        assert_eq!(row["accepting"], false);
    }
}

// The writer state contract is also enforced by schema_wire before JSON Schema.
macro_rules! writer_states {
    ($( $variant:ident => $wire:literal ),+ $(,)?) => {
        #[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
        pub(crate) enum WriterState { $(#[serde(rename = $wire)] $variant),+ }
        #[cfg(test)]
        impl WriterState { const ALL: &'static [Self] = &[$(Self::$variant),+]; }
    }
}
writer_states! { Idle => "idle", Busy => "busy", Unknown => "unknown" }

#[cfg(test)]
mod run35_u3 {
    use super::*;
    use std::collections::BTreeSet;

    fn parity(schema: &Value) -> Result<(), String> {
        let names = |array: &Value| -> Result<BTreeSet<String>, String> {
            array
                .as_array()
                .ok_or("missing array")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or("non-string field".into())
                })
                .collect()
        };
        let states: BTreeSet<_> = WriterState::ALL
            .iter()
            .map(|state| {
                serde_json::to_value(state)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        if names(&schema["properties"]["state"]["enum"])? != states {
            return Err("state enum drift".into());
        }
        for state in &states {
            serde_json::from_value::<WriterState>(json!(state)).map_err(|_| "state parse drift")?;
        }
        let contracts = crate::schema_wire::card_field_contracts();
        fn objects(schema: &Value, path: &str, found: &mut BTreeSet<String>) {
            if let Some(fields) = schema["properties"].as_object() {
                found.insert(path.to_owned());
                for (field, definition) in fields {
                    objects(definition, &format!("{path}/properties/{field}"), found);
                }
            }
        }
        let mut actual_objects = BTreeSet::new();
        objects(schema, "", &mut actual_objects);
        let expected_objects = contracts
            .iter()
            .map(|(path, _, _)| (*path).to_owned())
            .collect();
        if actual_objects != expected_objects {
            return Err("object struct drift".into());
        }
        for (path, required, optional) in contracts {
            let definition = schema
                .pointer(path)
                .ok_or_else(|| format!("missing struct {path}"))?;
            let expected_required: BTreeSet<String> = required
                .iter()
                .map(|s| s.trim_start_matches("r#").into())
                .collect();
            let expected_fields: BTreeSet<String> = required
                .iter()
                .chain(optional)
                .map(|s| s.trim_start_matches("r#").into())
                .collect();
            let actual_fields: BTreeSet<String> = definition["properties"]
                .as_object()
                .ok_or("missing properties")?
                .keys()
                .cloned()
                .collect();
            if names(&definition["required"])? != expected_required
                || actual_fields != expected_fields
            {
                return Err(format!("struct field drift {path}"));
            }
            if definition["additionalProperties"] != false {
                return Err(format!("open struct drift {path}"));
            }
        }
        Ok(())
    }

    #[test]
    fn run35_u3_real_schema_parity() {
        let schema: Value = serde_json::from_str(include_str!("card-state.schema.json")).unwrap();
        assert_eq!(parity(&schema), Ok(()));
        let mut sample: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/card-state/local-2070.json"
        ))
        .unwrap();
        for state in WriterState::ALL {
            sample["state"] = serde_json::to_value(state).unwrap();
            assert!(crate::schema_wire::card_state(&sample));
            assert!(validator().is_valid(&sample));
        }
        sample["state"] = json!("planted");
        assert!(!crate::schema_wire::card_state(&sample));
    }

    #[test]
    fn run35_u3_planted_schema_drift_fails() {
        let schema: Value = serde_json::from_str(include_str!("card-state.schema.json")).unwrap();
        let mut extra = schema.clone();
        extra["properties"]["state"]["enum"]
            .as_array_mut()
            .unwrap()
            .push(json!("planted"));
        assert_eq!(parity(&extra), Err("state enum drift".into()));
        let mut missing = schema.clone();
        missing["properties"]["state"]["enum"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(parity(&missing), Err("state enum drift".into()));
        for (path, _, _) in crate::schema_wire::card_field_contracts() {
            let mut extra = schema.clone();
            extra.pointer_mut(path).unwrap()["properties"]["planted"] = json!({"type":"string"});
            assert_eq!(parity(&extra), Err(format!("struct field drift {path}")));
            let mut missing = schema.clone();
            let definition = missing.pointer_mut(path).unwrap();
            let field = definition["properties"]
                .as_object()
                .unwrap()
                .keys()
                .next()
                .unwrap()
                .clone();
            definition["properties"]
                .as_object_mut()
                .unwrap()
                .remove(&field);
            assert_eq!(parity(&missing), Err(format!("struct field drift {path}")));
        }
    }
}
