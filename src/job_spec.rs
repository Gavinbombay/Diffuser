use serde_json::Value;
use std::{path::Path, sync::OnceLock};

pub(crate) fn license_admit(
    spec: &Value,
    config: &Value,
    cart: &crate::cartridge::Cartridge,
) -> Result<(), (u16, String)> {
    let required =
        config["require_commercial"].as_bool().unwrap_or(true) || spec["use"] == "public";
    if required && !cart.license_commercial {
        return Err((
            409,
            format!("cartridge {} lacks a commercial licence", cart.id),
        ));
    }
    Ok(())
}

fn validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value =
            serde_json::from_str(include_str!("job-spec.schema.json")).expect("embedded schema");
        jsonschema::validator_for(&schema).expect("valid job schema")
    })
}

pub(crate) fn admit(
    spec: &Value,
    lane: &str,
    balance: Option<f64>,
    floor_path: &Path,
) -> Result<(), (u16, String)> {
    crate::schema_wire::normalize_job_spec(spec).map_err(|code| (422, code.to_owned()))?;
    if !validator().is_valid(spec) || spec["lane"] != lane {
        return Err((422, "invalid job-spec/v1 or lane mismatch".into()));
    }
    if let Some(estimate) = spec["budget_cu"].as_f64() {
        if estimate > spec["cap_cu"].as_f64().unwrap_or(estimate) {
            return Err((409, "estimated CU exceeds cap".into()));
        }
        let floor = std::fs::read_to_string(floor_path)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite());
        let balance = balance.filter(|v| v.is_finite());
        let (Some(balance), Some(floor)) = (balance, floor) else {
            return Err((409, "CU balance or floor unavailable".into()));
        };
        if balance - estimate < floor {
            return Err((409, "CU balance below floor".into()));
        }
    }
    Ok(())
}

/// Select only an accepting worker with the requested GPU and enough free VRAM.
pub(crate) fn gpu_admit(
    spec: &Value,
    min_vram_mb: u64,
    rows: &[Value],
) -> Result<(), (u16, String)> {
    let class = spec["gpu_class"].as_str().unwrap_or("any");
    let minimum = spec["gpu_min_vram_gb"].as_f64().unwrap_or(0.0);
    let suitable = rows.iter().any(|row| {
        if row["accepting"] != true || !preferred_card(spec, row) {
            return false;
        }
        let caps = &row["capabilities"];
        let state = row.get("card_state");
        if state.is_some_and(|s| s["stale"] != false) {
            return false;
        }
        // A pushed card state is only eligible after its independent proof
        // check. Ordinary workers retain their existing health admission path.
        if state.is_some() && row["proved"] != true {
            return false;
        }
        let field = |name: &str| state.and_then(|s| s.get(name)).unwrap_or(&caps[name]);
        let class_ok = class == "any"
            || field("gpu_class")
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case(class));
        let total_ok = minimum <= 0.0 || field("vram_gb").as_f64().is_some_and(|v| v >= minimum);
        let free_ok =
            min_vram_mb == 0 || field("vram_mb").as_u64().is_some_and(|v| v >= min_vram_mb);
        class_ok && total_ok && free_ok
    });
    if suitable {
        Ok(())
    } else {
        Err((
            409,
            "no accepting worker meets GPU and cartridge VRAM requirements".into(),
        ))
    }
}

// Physical card views must satisfy card_pref. Generic exec workers and
// anonymous capability-only callers retain their existing resource contract.
fn preferred_card(spec: &Value, row: &Value) -> bool {
    let Some(id) = row["id"]
        .as_str()
        .filter(|id| matches!(*id, "colab-l4" | "echo-3060" | "warp-2070"))
    else {
        return true;
    };
    spec["card_pref"]
        .as_array()
        .is_none_or(|cards| cards.iter().any(|card| card == id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn spec() -> Value {
        json!({"spec":"job-spec/v1","job_id":"job-123","lane":"tts","cartridge":"voice","card_pref":["colab-l4"],"items":[{"id":"one","args":[]}],"entry":"run","seg_min":1,"deadline_min":10,"max_segs":1,"budget_cu":2,"outputs":"warp:/mnt/sn850x/lanes/jobs/job-123/out"})
    }
    fn unlicensed_cart() -> crate::cartridge::Cartridge {
        serde_json::from_value(json!({"id":"voice","lane":"tts","size_bytes":1,"min_vram_mb":0,"min_ram_mb":0,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":"[R]"}})).unwrap()
    }
    #[test]
    fn cartridge_without_commercial_license_refused_when_required() {
        let cart = unlicensed_cart();
        for config in [
            json!({}),
            json!({"require_commercial":true}),
            json!({"require_commercial":"invalid"}),
        ] {
            let (code, message) = license_admit(&spec(), &config, &cart).unwrap_err();
            assert_eq!(code, 409);
            assert!(message.contains("voice"));
        }
        let mut public = spec();
        public["use"] = json!("public");
        assert_eq!(
            license_admit(&public, &json!({"require_commercial":false}), &cart)
                .unwrap_err()
                .0,
            409
        );
        assert!(validator().is_valid(&public));
    }
    #[test]
    fn cartridge_without_commercial_license_internal_job_allowed_when_disabled() {
        let mut internal = spec();
        internal["use"] = json!("internal");
        assert!(validator().is_valid(&internal));
        assert!(license_admit(
            &internal,
            &json!({"require_commercial":false}),
            &unlicensed_cart()
        )
        .is_ok());
    }
    fn floor() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "cu-floor-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&p, "3").unwrap();
        p
    }
    #[test]
    fn est_cu_over_cap_refused_409() {
        let mut s = spec();
        s["cap_cu"] = json!(1);
        assert_eq!(admit(&s, "tts", Some(10.0), &floor()).unwrap_err().0, 409);
    }
    #[test]
    fn balance_below_floor_refused_409() {
        assert_eq!(
            admit(&spec(), "tts", Some(4.9), &floor()).unwrap_err().0,
            409
        );
    }
    #[test]
    fn balance_equal_floor_admits() {
        assert!(admit(&spec(), "tts", Some(5.0), &floor()).is_ok());
    }
    #[test]
    fn gpu_min_vram_80_admits_fake_g4_96() {
        let mut job = spec();
        job["gpu_class"] = json!("g4");
        job["gpu_min_vram_gb"] = json!(80);
        let rows = vec![
            json!({"accepting":true,"capabilities":{"gpu_class":"G4","vram_gb":96,"vram_mb":90000}}),
        ];
        assert!(gpu_admit(&job, 80000, &rows).is_ok());
        assert_eq!(gpu_admit(&job, 95000, &rows).unwrap_err().0, 409);
    }
    #[test]
    fn gpu_min_vram_80_refuses_only_free_l4_409() {
        let mut job = spec();
        job["gpu_class"] = json!("g4");
        job["gpu_min_vram_gb"] = json!(80);
        let rows = vec![
            json!({"accepting":true,"capabilities":{"gpu_class":"L4","vram_gb":24,"vram_mb":24000}}),
        ];
        assert_eq!(gpu_admit(&job, 1, &rows).unwrap_err().0, 409);
        let stored = vec![
            json!({"accepting":true,"proved":true,"capabilities":{"gpu_class":"G4","vram_gb":96,"vram_mb":90000},"card_state":{"stale":false,"gpu_class":"L4","vram_gb":24,"vram_mb":24000}}),
        ];
        assert_eq!(gpu_admit(&job, 1, &stored).unwrap_err().0, 409);
    }
    #[test]
    fn pushed_card_requires_proof_for_admission() {
        let row = json!({"accepting":true,"capabilities":{},"card_state":{"stale":false,"gpu_class":"L4","vram_gb":24,"vram_mb":24000}});
        assert_eq!(
            gpu_admit(&spec(), 1, std::slice::from_ref(&row))
                .unwrap_err()
                .0,
            409
        );
        let mut proved = row;
        proved["proved"] = json!(true);
        assert!(gpu_admit(&spec(), 1, std::slice::from_ref(&proved)).is_ok());
        proved["card_state"]["stale"] = json!(true);
        assert_eq!(gpu_admit(&spec(), 1, &[proved]).unwrap_err().0, 409);
    }
    #[test]
    fn invalid_schema_and_lane_refused_422() {
        let mut s = spec();
        s["items"] = json!([]);
        assert_eq!(admit(&s, "tts", Some(5.0), &floor()).unwrap_err().0, 422);
        assert_eq!(
            admit(&spec(), "stt", Some(5.0), &floor()).unwrap_err().0,
            422
        );
    }
}

#[cfg(test)]
mod run33_wire_tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    fn collect(value: &Value, source: &str, rows: &mut Vec<(String, Value)>) {
        match value {
            Value::Object(fields) => {
                if value["spec"] == "job-spec/v1" {
                    rows.push((source.to_owned(), value.clone()));
                }
                for child in fields.values() {
                    collect(child, source, rows);
                }
            }
            Value::Array(values) => {
                for child in values {
                    collect(child, source, rows);
                }
            }
            _ => {}
        }
    }
    fn fixtures(directory: &Path, rows: &mut Vec<(String, Value)>) {
        let mut paths = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let name = path.file_name().unwrap().to_str().unwrap();
            if matches!(
                name,
                "proof" | "token-sha" | "registry.json" | "specs" | "kit" | "stalled"
            ) || path.is_symlink()
            {
                continue;
            }
            if path.is_dir() {
                fixtures(&path, rows);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                if let Ok(value) = std::fs::read(&path).and_then(|raw| {
                    serde_json::from_slice::<Value>(&raw).map_err(std::io::Error::other)
                }) {
                    collect(&value, path.to_str().unwrap(), rows);
                }
            }
        }
    }
    fn corpus() -> Vec<(String, Value)> {
        let schema: Value = serde_json::from_str(include_str!("job-spec.schema.json")).unwrap();
        let mut rows = Vec::new();
        assert!(!schema["examples"].as_array().unwrap().is_empty());
        collect(&schema["examples"], "src/job-spec.schema.json", &mut rows);
        fixtures(Path::new("tests/fixtures"), &mut rows);
        assert!(rows.len() >= 12);
        rows
    }
    fn scratch() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "run33-wire-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("floor"), "100").unwrap();
        root
    }
    #[test]
    fn run33_s5_all_examples_and_fixtures_round_trip() {
        let root = scratch();
        let rows = corpus();
        let mut evidence = Vec::new();
        for (source, value) in &rows {
            let bytes = serde_json::to_vec(value).unwrap();
            let parsed: Value = serde_json::from_slice(&bytes).unwrap();
            admit(
                &parsed,
                parsed["lane"].as_str().unwrap(),
                Some(1000.0),
                &root.join("floor"),
            )
            .unwrap();
            let output = crate::schema_wire::normalize_job_spec(&parsed).unwrap();
            assert_eq!(output, bytes, "{source}");
            let round: Value = serde_json::from_slice(&output).unwrap();
            admit(
                &round,
                round["lane"].as_str().unwrap(),
                Some(1000.0),
                &root.join("floor"),
            )
            .unwrap();
            assert_eq!(
                crate::schema_wire::normalize_job_spec(&round).unwrap(),
                bytes,
                "{source}"
            );
            evidence
                .push(json!({"source":source,"lane":value["lane"],"normalized_bytes":bytes.len()}));
        }
        assert_eq!(
            rows.iter()
                .filter_map(|(_, value)| value["lane"].as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            6
        );
        std::fs::write(
            crate::test_process::target_dir().join("run33-s5-roundtrips.json"),
            serde_json::to_vec_pretty(
                &json!({"result":"PASS","passed":rows.len(),"examples":evidence}),
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn run33_s5_unknown_fields_refused_with_catalog_code() {
        let root = scratch();
        for (source, value) in corpus() {
            for nested in [false, true] {
                let mut planted = value.clone();
                if nested {
                    planted["items"][0]["planted_extra"] = json!("[R]");
                } else {
                    planted["planted_extra"] = json!("[R]");
                }
                let before = planted.clone();
                assert_eq!(
                    crate::schema_wire::normalize_job_spec(&planted),
                    Err(crate::error_catalog::BAD_SPEC),
                    "{source}"
                );
                assert_eq!(
                    admit(
                        &planted,
                        value["lane"].as_str().unwrap(),
                        Some(1000.0),
                        &root.join("floor")
                    ),
                    Err((422, crate::error_catalog::BAD_SPEC.into())),
                    "{source}"
                );
                assert_eq!(planted, before);
                assert_eq!(
                    crate::error_catalog::canonical_code(crate::error_catalog::BAD_SPEC),
                    crate::error_catalog::BAD_SPEC
                );
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod run37_admission_tests {
    use super::*;
    use crate::error_catalog as catalog;
    use serde_json::json;

    #[test]
    fn run37_w5_gpu_and_license_refusal_table() {
        let base = json!({"card_pref":["warp-2070"],"gpu_class":"l4"});
        let card = json!({"id":"warp-2070","accepting":true,"capabilities":{"gpu_class":"L4","vram_mb":8000}});
        let licensed: crate::cartridge::Cartridge = serde_json::from_value(json!({"id":"fixture","lane":"tts","size_bytes":1,"min_vram_mb":8000,"min_ram_mb":0,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"license_commercial":true,"files":{"weights":"[R]"}})).unwrap();
        let unlicensed: crate::cartridge::Cartridge = serde_json::from_value(json!({"id":"fixture","lane":"tts","size_bytes":1,"min_vram_mb":8000,"min_ram_mb":0,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"license_commercial":false,"files":{"weights":"[R]"}})).unwrap();
        let mut missing = base.clone();
        missing["card_pref"] = json!(["colab-l4"]);
        let mut public = base.clone();
        public["use"] = json!("public");
        let mut disabled = card.clone();
        disabled["accepting"] = json!(false);
        let mut generic = card.clone();
        generic["id"] = json!("fixture");
        let rows = [
            (
                "generic exec resource contract",
                base.clone(),
                8000,
                vec![generic],
                &licensed,
                json!({}),
                None,
            ),
            (
                "below VRAM",
                base.clone(),
                8001,
                vec![card.clone()],
                &licensed,
                json!({}),
                Some((409, catalog::WORKER_NOT_READY)),
            ),
            (
                "empty cards",
                base.clone(),
                8000,
                vec![],
                &licensed,
                json!({}),
                Some((409, catalog::WORKER_NOT_READY)),
            ),
            (
                "preference absent",
                missing,
                8000,
                vec![card.clone()],
                &licensed,
                json!({}),
                Some((409, catalog::WORKER_NOT_READY)),
            ),
            (
                "unlicensed",
                base.clone(),
                8000,
                vec![card.clone()],
                &unlicensed,
                json!({}),
                Some((409, catalog::APPROVAL_MISSING)),
            ),
            (
                "valid exact VRAM",
                base.clone(),
                8000,
                vec![card.clone()],
                &licensed,
                json!({}),
                None,
            ),
            (
                "valid surplus VRAM",
                base.clone(),
                7999,
                vec![card.clone()],
                &licensed,
                json!({}),
                None,
            ),
            (
                "not accepting",
                base.clone(),
                8000,
                vec![disabled],
                &licensed,
                json!({}),
                Some((409, catalog::WORKER_NOT_READY)),
            ),
            (
                "internal opt out",
                base,
                8000,
                vec![card.clone()],
                &unlicensed,
                json!({"require_commercial":false}),
                None,
            ),
            (
                "public requires licence",
                public,
                8000,
                vec![card],
                &unlicensed,
                json!({"require_commercial":false}),
                Some((409, catalog::APPROVAL_MISSING)),
            ),
        ];
        assert_eq!(rows.len(), 10);
        for (label, spec, minimum, cards, cart, config, expected) in rows {
            let before = serde_json::to_vec(&(&spec, &cards, &config)).unwrap();
            let result = gpu_admit(&spec, minimum, &cards)
                .and_then(|()| license_admit(&spec, &config, cart));
            match expected {
                None => assert_eq!(result, Ok(()), "{label}"),
                Some((status, code)) => {
                    let (actual_status, message) = result.unwrap_err();
                    assert_eq!(actual_status, status, "{label}");
                    assert_eq!(
                        message,
                        if code == catalog::WORKER_NOT_READY {
                            "no accepting worker meets GPU and cartridge VRAM requirements"
                        } else {
                            "cartridge fixture lacks a commercial licence"
                        },
                        "{label}"
                    );
                    assert_eq!(
                        catalog::refusal_entry(Some(actual_status), &message)
                            .unwrap()
                            .code,
                        code,
                        "{label}"
                    );
                    catalog::observe(Some(actual_status), &message);
                }
            }
            assert_eq!(
                serde_json::to_vec(&(&spec, &cards, &config)).unwrap(),
                before,
                "{label} changed admission input"
            );
        }
    }
}
