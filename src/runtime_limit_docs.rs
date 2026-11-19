use super::*;
use std::collections::BTreeSet;

fn constants() -> Value {
    json!({
        "TTS_SECONDS": TTS_SECONDS, "SAMPLE_RATE": SAMPLE_RATE,
        "VIDEO_FRAMES": VIDEO_FRAMES, "MAX_ARTIFACTS": MAX_ARTIFACTS,
        "MUSIC_SECONDS_MIN": MUSIC_SECONDS_MIN, "MUSIC_SECONDS_MAX": MUSIC_SECONDS_MAX,
        "VIDEO_FRAMES_MIN": VIDEO_FRAMES_MIN, "VIDEO_FRAMES_MAX": VIDEO_FRAMES_MAX,
        "SAMPLE_RATES": SAMPLE_RATES,
    })
}

fn markdown_values(text: &str, path: &str) -> Result<Value, String> {
    let mut values = serde_json::Map::new();
    for line in text
        .lines()
        .filter(|line| line.starts_with("| runtime_limits::"))
    {
        let columns: Vec<_> = line.split('|').map(str::trim).collect();
        if columns.len() != 4 {
            return Err(format!("{path}: malformed runtime limit row"));
        }
        let name = columns[1].strip_prefix("runtime_limits::").unwrap();
        let value: Value = serde_json::from_str(columns[2])
            .map_err(|_| format!("{path}: {name} invalid value"))?;
        if values.insert(name.into(), value).is_some() {
            return Err(format!("{path}: {name} duplicate"));
        }
    }
    Ok(Value::Object(values))
}

fn compare(actual: &Value, path: &str) -> Result<(), String> {
    let expected = constants();
    let expected = expected.as_object().unwrap();
    let actual = actual
        .as_object()
        .ok_or_else(|| format!("{path}: runtime limits missing"))?;
    let names: BTreeSet<_> = expected.keys().chain(actual.keys()).collect();
    let errors: Vec<_> = names
        .into_iter()
        .filter_map(|name| {
            if expected.get(name) == actual.get(name) {
                None
            } else {
                Some(format!(
                    "{path}: {name} expected {:?}, documented {:?}",
                    expected.get(name),
                    actual.get(name)
                ))
            }
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn verify(source: &str, readme: &str, contract: &str, openapi: &Value) -> Result<(), String> {
    let declared: BTreeSet<_> = source
        .lines()
        .filter_map(|line| line.strip_prefix("pub const "))
        .map(|line| line.split(':').next().unwrap().to_owned())
        .collect();
    let values = constants();
    let measured: BTreeSet<_> = values.as_object().unwrap().keys().cloned().collect();
    if declared != measured {
        return Err(format!(
            "src/runtime_limits.rs: unmeasured constants {:?}",
            declared.symmetric_difference(&measured).collect::<Vec<_>>()
        ));
    }
    compare(&markdown_values(readme, "README.md")?, "README.md")?;
    compare(
        &markdown_values(contract, "CONTRACT-5820.md")?,
        "CONTRACT-5820.md",
    )?;
    compare(&openapi["x-runtime-limits"], "docs/openapi.json")?;
    // Check the existing prose as well as the named, bidirectional inventory.
    for (name, phrase) in [
        (
            "SAMPLE_RATE/TTS_SECONDS",
            format!("to {SAMPLE_RATE} Hz and an admitted {TTS_SECONDS} second ceiling"),
        ),
        (
            "MUSIC_SECONDS_MIN/MUSIC_SECONDS_MAX",
            format!("`duration_seconds` from {MUSIC_SECONDS_MIN} to {MUSIC_SECONDS_MAX}"),
        ),
        (
            "VIDEO_FRAMES",
            format!("Video defaults to {VIDEO_FRAMES} admitted frames"),
        ),
        (
            "VIDEO_FRAMES_MIN/VIDEO_FRAMES_MAX",
            format!("within {VIDEO_FRAMES_MIN} to {VIDEO_FRAMES_MAX}"),
        ),
        ("MAX_ARTIFACTS", format!("at most {MAX_ARTIFACTS} distinct")),
    ] {
        if !readme.contains(&phrase) {
            return Err(format!("README.md: {name} prose differs"));
        }
    }
    for (name, phrase) in [
        (
            "TTS_SECONDS/SAMPLE_RATE",
            format!("TTS defaults to {TTS_SECONDS} seconds and {SAMPLE_RATE} Hz"),
        ),
        (
            "VIDEO_FRAMES",
            format!("video defaults to {VIDEO_FRAMES} frames"),
        ),
        (
            "MUSIC_SECONDS_MIN/MUSIC_SECONDS_MAX",
            format!("music range {MUSIC_SECONDS_MIN} to {MUSIC_SECONDS_MAX} seconds"),
        ),
        (
            "VIDEO_FRAMES_MIN/VIDEO_FRAMES_MAX",
            format!("video range {VIDEO_FRAMES_MIN} to {VIDEO_FRAMES_MAX} frames"),
        ),
        (
            "MAX_ARTIFACTS",
            format!("at most {MAX_ARTIFACTS} artifacts"),
        ),
    ] {
        if !contract.contains(&phrase) {
            return Err(format!("CONTRACT-5820.md: {name} prose differs"));
        }
    }
    let cfg = Config::default();
    if (
        cfg.tts_seconds,
        cfg.sample_rate,
        cfg.video_frames,
        cfg.max_artifacts,
    ) != (TTS_SECONDS, SAMPLE_RATE, VIDEO_FRAMES, MAX_ARTIFACTS)
    {
        return Err("src/runtime_limits.rs: Config defaults differ from constants".into());
    }
    Ok(())
}

const SOURCE: &str = include_str!("runtime_limits.rs");
const README: &str = include_str!("../README.md");
const CONTRACT: &str = include_str!("../CONTRACT-5820.md");

#[test]
fn run32_runtime_limits_real_docs_pass() {
    let openapi = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
    verify(SOURCE, README, CONTRACT, &openapi).unwrap();
    std::fs::create_dir_all(crate::test_process::target_dir()).unwrap();
    std::fs::write(crate::test_process::target_dir().join("run32-r5-parity.json"), serde_json::to_vec_pretty(&json!({"result":"PASS","constants":constants(),"documents":["README.md","CONTRACT-5820.md","docs/openapi.json"]})).unwrap()).unwrap();
}

#[test]
fn run32_runtime_limits_planted_drift_fails() {
    let openapi: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
    for (name, value) in constants().as_object().unwrap() {
        let wrong = if value.is_array() {
            json!([1])
        } else {
            json!(999)
        };
        let row = format!("| runtime_limits::{name} | {value} |");
        let bad = format!("| runtime_limits::{name} | {wrong} |");
        assert!(README.contains(&row) && CONTRACT.contains(&row), "{name}");
        let error = verify(SOURCE, &README.replace(&row, &bad), CONTRACT, &openapi).unwrap_err();
        assert!(
            error.contains(name) && error.contains("README.md"),
            "{error}"
        );
        let error = verify(SOURCE, README, &CONTRACT.replace(&row, &bad), &openapi).unwrap_err();
        assert!(
            error.contains(name) && error.contains("CONTRACT-5820.md"),
            "{error}"
        );
        let mut bad_json = openapi.clone();
        bad_json["x-runtime-limits"][name] = wrong;
        let error = verify(SOURCE, README, CONTRACT, &bad_json).unwrap_err();
        assert!(
            error.contains(name) && error.contains("docs/openapi.json"),
            "{error}"
        );
        let error = verify(SOURCE, &README.replace(&row, ""), CONTRACT, &openapi).unwrap_err();
        assert!(error.contains(name), "{error}");
    }
    for (readme, contract, json_doc) in [
        (
            format!("{README}\n| runtime_limits::ORPHAN_LIMIT | 1 |\n"),
            CONTRACT.into(),
            openapi.clone(),
        ),
        (
            README.into(),
            format!("{CONTRACT}\n| runtime_limits::ORPHAN_LIMIT | 1 |\n"),
            openapi.clone(),
        ),
        (README.into(), CONTRACT.into(), {
            let mut doc = openapi.clone();
            doc["x-runtime-limits"]["ORPHAN_LIMIT"] = json!(1);
            doc
        }),
    ] {
        let error = verify(SOURCE, &readme, &contract, &json_doc).unwrap_err();
        assert!(error.contains("ORPHAN_LIMIT"), "{error}");
    }
    let error = verify(
        &format!("{SOURCE}\npub const UNMEASURED: u64 = 1;"),
        README,
        CONTRACT,
        &openapi,
    )
    .unwrap_err();
    assert!(error.contains("UNMEASURED"), "{error}");
    let error = verify(
        SOURCE,
        &README.replace("within 2 to 480", "within 2 to 479"),
        CONTRACT,
        &openapi,
    )
    .unwrap_err();
    assert!(error.contains("VIDEO_FRAMES_MAX"), "{error}");
}

// Explicit units complement the retained RUN32 value and prose checks.
const RUN36_LIMIT_DOCS: &[(&str, &str, &str)] = &[
    ("TTS_SECONDS", "300", "seconds"),
    ("SAMPLE_RATE", "24000", "hertz"),
    ("VIDEO_FRAMES", "48", "frames"),
    ("MAX_ARTIFACTS", "8", "artifacts"),
    ("MUSIC_SECONDS_MIN", "1", "seconds"),
    ("MUSIC_SECONDS_MAX", "300", "seconds"),
    ("VIDEO_FRAMES_MIN", "2", "frames"),
    ("VIDEO_FRAMES_MAX", "480", "frames"),
    (
        "SAMPLE_RATES",
        "[16000, 22050, 24000, 44100, 48000]",
        "hertz",
    ),
];

fn run36_parity(source: &str, rows: &[(&str, &str, &str)]) -> Result<(), String> {
    let pattern =
        regex::Regex::new(r"(?m)^pub const ([A-Z_]+): [^=]+ = (&?[^;]+); // unit: ([a-z]+)$")
            .unwrap();
    let mut declared = std::collections::BTreeMap::new();
    for line in source.lines().filter(|line| line.starts_with("pub const ")) {
        let row = pattern
            .captures(line)
            .ok_or_else(|| format!("limit missing value or unit: {line}"))?;
        let value: Value = serde_json::from_str(row[2].trim_start_matches('&'))
            .map_err(|_| format!("{}: invalid value", &row[1]))?;
        if declared
            .insert(row[1].to_owned(), (value, row[3].to_owned()))
            .is_some()
        {
            return Err("duplicate source limit".into());
        }
    }
    if declared.is_empty() {
        return Err("no source limits".into());
    }
    let mut documented = std::collections::BTreeMap::new();
    for (name, value, unit) in rows {
        if !["seconds", "hertz", "frames", "artifacts"].contains(unit) {
            return Err(format!("{name}: unknown unit"));
        }
        let value: Value =
            serde_json::from_str(value).map_err(|_| format!("{name}: invalid documented value"))?;
        if documented
            .insert(name.to_string(), (value, unit.to_string()))
            .is_some()
        {
            return Err("duplicate documented limit".into());
        }
    }
    if declared != documented {
        return Err(format!(
            "source/documented value or unit differs: {declared:?} / {documented:?}"
        ));
    }
    Ok(())
}

#[test]
fn run36_v3_all_runtime_values_and_units_match() {
    run36_parity(SOURCE, RUN36_LIMIT_DOCS).unwrap();
    let documented: serde_json::Map<String, Value> = RUN36_LIMIT_DOCS
        .iter()
        .map(|(name, value, _)| (name.to_string(), serde_json::from_str(value).unwrap()))
        .collect();
    assert_eq!(Value::Object(documented), constants());
    assert_eq!(RUN36_LIMIT_DOCS.len(), 9);
}

#[test]
fn run36_v3_undocumented_limit_and_bidirectional_drift_fail() {
    let extra = format!("{SOURCE}\npub const UNDOCUMENTED_LIMIT: u64 = 1; // unit: seconds\n");
    assert!(run36_parity(&extra, RUN36_LIMIT_DOCS).is_err());
    for index in 0..RUN36_LIMIT_DOCS.len() {
        let mut missing = RUN36_LIMIT_DOCS.to_vec();
        missing.remove(index);
        assert!(run36_parity(SOURCE, &missing).is_err());
        let mut wrong = RUN36_LIMIT_DOCS.to_vec();
        wrong[index].1 = "999";
        assert!(run36_parity(SOURCE, &wrong).is_err());
        wrong = RUN36_LIMIT_DOCS.to_vec();
        wrong[index].2 = if wrong[index].2 == "seconds" {
            "frames"
        } else {
            "seconds"
        };
        assert!(run36_parity(SOURCE, &wrong).is_err());
    }
    let mut extra_doc = RUN36_LIMIT_DOCS.to_vec();
    extra_doc.push(("UNDOCUMENTED_LIMIT", "1", "seconds"));
    assert!(run36_parity(SOURCE, &extra_doc).is_err());
    assert!(run36_parity(&SOURCE.replace(" // unit: seconds", ""), RUN36_LIMIT_DOCS).is_err());
}
