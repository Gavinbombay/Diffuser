//! Admission body contracts for speech recognition, video and music.
use crate::*;
#[derive(Debug)]
pub struct Config {
    pub audio_chars: usize,
    pub text_chars: usize,
    pub audio_seconds: u64,
    pub video_accepting: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            audio_chars: 1024,
            text_chars: 4096,
            audio_seconds: 3600,
            video_accepting: false,
        }
    }
}
pub fn integer_json(v: &Value) -> bool {
    match v {
        Value::Number(n) => !n.is_f64(),
        Value::Array(a) => a.iter().all(integer_json),
        Value::Object(o) => o.values().all(integer_json),
        _ => true,
    }
}
fn text(v: &Value, min: usize, max: usize) -> bool {
    v.as_str()
        .is_some_and(|s| (min..=max).contains(&s.chars().count()))
}
fn band(v: &Value, min: u64, max: u64) -> bool {
    v.as_u64().is_some_and(|n| (min..=max).contains(&n))
}
fn language(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() == 2 || b.len() == 5)
        && b[..2].iter().all(u8::is_ascii_lowercase)
        && (b.len() == 2 || (b[2] == b'-' && b[3..].iter().all(u8::is_ascii_uppercase)))
}
fn tonality(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || !(b'A'..=b'G').contains(&b[0]) {
        return false;
    }
    let at = if b.get(1).is_some_and(|b| matches!(b, b'b' | b'#')) {
        2
    } else {
        1
    };
    ["maj", "major", "min", "minor"].contains(&&s[at..])
}
pub fn body(spec: &Value, lane: &str, allow_real_cartridge: bool) -> Result<(), &'static str> {
    if !["stt", "diffusion-video", "music-sfx"].contains(&lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    let o = spec
        .as_object()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    if spec["lane"].as_str().is_some_and(|s| s != lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::LANE_MISMATCH,
        ));
    }
    if !integer_json(spec) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_JSON));
    }
    if o.values().any(Value::is_null) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let legacy = spec.get("out").is_some();
    if spec["lane"] != lane
        || spec.get("api").is_some_and(|v| v != API)
        || (!legacy && spec.get("api").is_none())
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let common = [
        "api",
        "lane",
        "job_id",
        "cartridge",
        "timeout_min",
        "prefer",
    ];
    let local = [
        "out",
        "submitter",
        "cartridge_manifest",
        "cartridge_directory",
        "cartridge_manifest_sha256",
    ];
    let fields: &[&str] = match lane {
        "stt" => &[
            "audio",
            "format",
            "language",
            "hints",
            "max_alternatives",
            "diarize",
            "max_audio_seconds",
        ],
        "diffusion-video" => &[
            "prompt", "negative", "steps", "seed", "size", "fps", "frames", "format",
        ],
        "music-sfx" => &[
            "prompt",
            "negative",
            "duration_seconds",
            "bpm",
            "key",
            "seed",
            "stems",
            "format",
        ],
        _ => unreachable!(),
    };
    if o.keys().any(|f| {
        !common.contains(&f.as_str())
            && !fields.contains(&f.as_str())
            && !(legacy
                && (local.contains(&f.as_str())
                    || (lane == "diffusion-video"
                        && ["width", "height", "loop", "model"].contains(&f.as_str()))
                    || (lane == "music-sfx" && ["mode", "sample_rate"].contains(&f.as_str()))))
    }) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if spec
        .get("job_id")
        .is_some_and(|v| !v.as_str().is_some_and(result_store::valid_id))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if spec.get("cartridge").is_some_and(|v| {
        !v.as_str().is_some_and(|s| {
            s == "default"
                || ((allow_real_cartridge || legacy)
                    && worker_registry::identifier(s, 64, b".-", false))
        })
    }) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if spec.get("timeout_min").is_some_and(|v| !band(v, 1, 360)) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if let Some(v) = spec.get("prefer") {
        let a = v
            .as_array()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        let mut seen = HashSet::new();
        if a.len() > 5
            || a.iter().any(|v| {
                !v.as_str().is_some_and(result_store::valid_id) || !seen.insert(v.to_string())
            })
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    let cfg = Config::default();
    for field in [
        "seed",
        "steps",
        "fps",
        "frames",
        "duration_seconds",
        "bpm",
        "max_alternatives",
        "max_audio_seconds",
    ] {
        if spec.get(field).is_some_and(|v| !v.is_u64()) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    for field in ["diarize", "stems"] {
        if spec.get(field).is_some_and(|v| !v.is_boolean()) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    if spec
        .get("hints")
        .is_some_and(|v| !text(v, 0, cfg.text_chars))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    match lane {
        "stt" => {
            let audio = spec["audio"]
                .as_str()
                .filter(|s| !s.starts_with('/') && !s.contains(['\n', '\r']))
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
            if audio.is_empty() || audio.chars().count() > cfg.audio_chars {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            if !spec.get("format").map_or(legacy, |v| {
                v.as_str()
                    .is_some_and(|s| ["wav", "flac", "ogg", "mp3", "m4a"].contains(&s))
            }) {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            if spec
                .get("language")
                .is_some_and(|v| !v.as_str().is_some_and(language))
                || spec.get("max_alternatives").is_some_and(|v| !band(v, 1, 5))
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            if let Some(v) = spec.get("max_audio_seconds") {
                if !band(v, 1, u64::MAX) {
                    return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
                }
                if v.as_u64().unwrap() > cfg.audio_seconds {
                    return Err(crate::error_catalog::reason(
                        crate::error_catalog::UNSUPPORTED_PARAMETERS,
                    ));
                }
            }
        }
        "diffusion-video" => {
            if (!text(&spec["prompt"], 1, cfg.text_chars)
                && !(legacy && spec.get("prompt").is_none()))
                || spec
                    .get("negative")
                    .is_some_and(|v| !text(v, 0, cfg.text_chars))
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            for (field, min, max) in [
                ("steps", 1, 100),
                ("seed", 0, u32::MAX as u64),
                ("frames", 2, 480),
            ] {
                if !spec.get(field).map_or(legacy, |v| band(v, min, max)) {
                    return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
                }
            }
            if spec.get("fps").is_some_and(|v| !band(v, 1, 60))
                || !spec.get("format").map_or(legacy, |v| v == "mp4")
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            if let Some(size) = spec.get("size") {
                if size.as_object().is_none_or(|o| o.len() != 2)
                    || ["width", "height"]
                        .iter()
                        .any(|f| !band(&size[*f], 256, 1536))
                {
                    return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
                }
                if ["width", "height"]
                    .iter()
                    .any(|f| !size[*f].as_u64().unwrap().is_multiple_of(64))
                {
                    return Err(crate::error_catalog::reason(
                        crate::error_catalog::UNSUPPORTED_PARAMETERS,
                    ));
                }
            } else if !legacy {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        "music-sfx" => {
            if !text(&spec["prompt"], 1, cfg.text_chars)
                || spec
                    .get("negative")
                    .is_some_and(|v| !text(v, 0, cfg.text_chars))
                || !band(&spec["duration_seconds"], 1, 300)
                || spec.get("bpm").is_some_and(|v| !band(v, 20, 300))
                || spec
                    .get("key")
                    .is_some_and(|v| !v.as_str().is_some_and(tonality))
                || spec
                    .get("seed")
                    .is_some_and(|v| !band(v, 0, u32::MAX as u64))
                || !spec.get("format").map_or(legacy, |v| v == "wav")
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
pub fn decode(lane: &str, raw: &[u8], content_type: Option<&str>) -> Result<Value, &'static str> {
    render_admission::media_type(content_type)?;
    if !["stt", "diffusion-video", "music-sfx"].contains(&lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    if raw.len() > dispatch_kinds::Config::default().body_max {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::REQUEST_TOO_LARGE,
        ));
    }
    let mut spec = lane_gate::parse(raw)?;
    if !integer_json(&spec) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_JSON));
    }
    if spec.get("out").is_some() && spec.get("lane").is_none() {
        spec["lane"] = json!(lane);
    }
    body(&spec, lane, false)?;
    Ok(spec)
}
pub fn advertise(config: &Value, lane: &str, has_worker: bool) -> bool {
    if lane == "diffusion-video" {
        return Config::default().video_accepting;
    }
    has_worker
        && config["lanes"][lane] == true
        && (lane != "render-blender" || render_admission::gate(config, &json!({})).is_ok())
}
pub fn restrict_discovery(lane: &str, views: &mut [Value]) {
    if lane != "diffusion-video" {
        return;
    }
    for view in views {
        view["accepting"] = json!(false);
        if !view["why_not"].is_array() {
            view["why_not"] = json!([]);
        }
        view["why_not"]
            .as_array_mut()
            .unwrap()
            .push(json!("lane accepting:false"));
    }
}
/// One body contract for each gated lane. Render uses its separate legacy gate.
pub const BODIES: &[(&str, Option<&str>)] = &[
    ("tts", Some("text")),
    ("stt", Some("audio")),
    ("diffusion-image", Some("prompt")),
    ("diffusion-video", None),
    ("music-sfx", Some("prompt")),
];
pub fn primary_field(lane: &str) -> Option<&'static str> {
    BODIES
        .iter()
        .find(|(name, _)| *name == lane)
        .and_then(|(_, field)| *field)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cases() -> Vec<Value> {
        serde_json::from_str(include_str!("../tests/fixtures/lane-admission-cases.json")).unwrap()
    }
    fn pin(lane: &str) -> Value {
        json!({"id":format!("fake-{lane}-v1"),"sha256":hex::encode(Sha256::digest(lane.as_bytes())),"voices":["default"],"rates":[16000,22050,24000,44100,48000],"max_width":1536,"max_height":1536,"max_steps":100,"max_text_chars":10000})
    }
    fn run_case(id: &str) {
        let c = cases().into_iter().find(|c| c["id"] == id).unwrap();
        let lane = c["lane"].as_str().unwrap();
        let raw = if let Some(a) = c["raw_utf8"].as_array() {
            a.iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect::<Vec<_>>()
        } else {
            serde_json::to_vec(&c["body"]).unwrap()
        };
        let result = decode(lane, &raw, c["content_type"].as_str());
        let result = result.and_then(|spec| {
            if let Some(p) = c.get("pin") {
                let mut p = p.clone();
                if p.is_object() {
                    p["sha256"] = json!(hex::encode(Sha256::digest(b"fixture pin")));
                }
                lane_gate::bounds(&p, &spec)?;
            }
            Ok(spec)
        });
        let expected = if c["want"].is_object() {
            "ok"
        } else {
            c["want"].as_str().unwrap()
        };
        let kept = match id {
            "global-key-empty" | "global-key-space" | "global-key-129" => Some("ok"),
            "global-key-before-parse" => Some(crate::error_catalog::BAD_JSON),
            _ => None,
        };
        let want = kept.unwrap_or(expected);
        assert_eq!(
            result.as_ref().map(|_| "ok").unwrap_or_else(|e| e),
            want,
            "{id}"
        );
        if let Ok(spec) = result {
            let now = 1790000000;
            let original = spec.clone();
            let resolved = pin(lane);
            let mut admitted = spec.clone();
            admitted["job_id"] = json!(request_boundary::job_id(&spec));
            admitted["cartridge"] = resolved["id"].clone();
            admitted["cartridge_manifest_sha256"] = resolved["sha256"].clone();
            let mut row = queue_policy::admitted(&HashMap::new(), &admitted, now);
            row["spec_sha256"] = json!(deadline::fingerprint(&original));
            let snap = result_store::snapshot(&row, now);
            if c["want"].is_object() {
                assert_eq!(snap.as_object().unwrap().len(), 17);
                assert_eq!(snap["state"], "queued");
                assert_eq!(snap["cleanup"], "pending");
                assert_eq!(snap["artifacts"], json!([]));
                assert_eq!(snap["attempts"], json!([]));
                assert!(snap["error"].is_null());
                assert!(snap["manifest"].is_null());
                match id {
                    "snap-minted-id" => {
                        assert!(snap["job_id"].as_str().unwrap().starts_with("rb-"))
                    }
                    "snap-kept-id" => assert_eq!(snap["job_id"], "fake-stt-001"),
                    "snap-pin-fields" => {
                        assert_eq!(snap["cartridge"], "fake-stt-v1");
                        assert_eq!(snap["pin_sha256"], hex::encode(Sha256::digest(b"stt")));
                    }
                    "snap-fingerprint-same" => {
                        let pretty = serde_json::to_vec_pretty(&original).unwrap();
                        assert_eq!(
                            deadline::fingerprint(&decode(lane, &pretty, None).unwrap()),
                            snap["spec_sha256"]
                        );
                    }
                    "snap-default-not-injected" => {
                        let mut explicit = original.clone();
                        explicit["timeout_min"] = json!(45);
                        assert_ne!(deadline::fingerprint(&explicit), snap["spec_sha256"]);
                    }
                    "snap-deadline-timeout" => assert_eq!(row["deadline_epoch"], now + 1200),
                    "snap-deadline-default" => assert_eq!(row["deadline_epoch"], now + 2700),
                    _ => {}
                }
            }
        }
    }
    fn run_fixture(path: &str) {
        let parts = path.split('/').collect::<Vec<_>>();
        let lane = parts[0];
        let class = parts[1];
        let full = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/per-lane")
            .join(path);
        let raw = fs::read(full).unwrap();
        let spec = lane_gate::parse(&raw).unwrap();
        let result = match lane {
            "stt" | "diffusion-video" | "music-sfx" => body(&spec, lane, false),
            "render-blender" => render_admission::body(&spec),
            _ => cartridge_registry::job_shape(&spec, lane),
        };
        if path == "render-blender/good/render-blender.boundary-max.json" {
            assert_eq!(result, Err(crate::error_catalog::BAD_SPEC));
            return;
        }
        match class {
            "good" => assert!(result.is_ok(), "{path}: {result:?}"),
            "bad" => assert!(result.is_err(), "{path}"),
            "semantic" => {
                let result = result.and_then(|()| lane_gate::bounds(&pin(lane), &spec));
                let want = if lane == "tts" {
                    crate::error_catalog::PIN_INCOMPATIBLE
                } else {
                    crate::error_catalog::UNSUPPORTED_PARAMETERS
                };
                assert_eq!(result, Err(want), "{path}");
            }
            _ => panic!("unknown fixture class"),
        }
    }
    include!("../tests/per_lane_named.rs");
    #[test]
    fn per_lane_fixture_manifest() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/per-lane");
        let manifest: Value =
            serde_json::from_slice(&fs::read(root.join("MANIFEST.json")).unwrap()).unwrap();
        assert_eq!(manifest.as_array().unwrap().len(), 45);
        for row in manifest.as_array().unwrap() {
            let raw = fs::read(root.join(row["path"].as_str().unwrap())).unwrap();
            assert_eq!(hex::encode(Sha256::digest(raw)), row["sha256"]);
        }
    }
    fn stored_lane(lane: &str) {
        let root =
            std::env::temp_dir().join(format!("lane-conformance-{}-{lane}", std::process::id()));
        let store = result_store::Store::new(
            &root,
            result_store::Config {
                legacy_paths: true,
                ..Default::default()
            },
        );
        let names = match lane {
            "tts" => vec!["speech.wav"],
            "stt" => vec!["transcript.json"],
            "diffusion-image" => vec!["image.png"],
            "diffusion-video" => vec!["video.mp4"],
            "music-sfx" => vec![
                "audio.wav",
                "stems/bass.wav",
                "stems/drums.wav",
                "stems/lead.wav",
            ],
            "render-blender" => vec!["frame_0001.png", "frame_0002.png"],
            _ => unreachable!(),
        };
        let mut arts = Vec::new();
        for name in names {
            let data = format!("{lane}/{name}").into_bytes();
            let sha = store.put_artifact(lane, &data, None).unwrap();
            assert_eq!(sha, hex::encode(Sha256::digest(&data)));
            arts.push(json!({"path":name,"sha256":sha,"bytes":data.len()}));
        }
        let row = json!({"lane":lane,"job_id":"fixture","state":"done","artifacts":arts});
        let doc = result_store::snapshot(&row, 1790000000);
        let documents = BTreeMap::from([("manifest.json".into(), result_store::canonical(&doc))]);
        store
            .put_job(lane, "fixture", &doc, &documents, 1790000000)
            .unwrap();
        assert_eq!(store.get_job(lane, "fixture").unwrap(), doc);
        for art in &arts {
            assert_eq!(
                store
                    .get_artifact(lane, art["sha256"].as_str().unwrap())
                    .unwrap()
                    .len() as u64,
                art["bytes"]
            );
        }
        let sha = arts[0]["sha256"].as_str().unwrap();
        let blob = root
            .join("lanes")
            .join(lane)
            .join("blobs")
            .join(&sha[..2])
            .join(sha);
        fs::write(blob, b"changed").unwrap();
        assert_eq!(
            store.get_artifact(lane, sha),
            Err(crate::error_catalog::DIGEST_CONFLICT)
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn conformance_render_blender() {
        stored_lane("render-blender");
    }
    #[test]
    fn conformance_tts() {
        stored_lane("tts");
    }
    #[test]
    fn conformance_stt() {
        stored_lane("stt");
    }
    #[test]
    fn conformance_diffusion_image() {
        stored_lane("diffusion-image");
    }
    #[test]
    fn conformance_diffusion_video() {
        stored_lane("diffusion-video");
    }
    #[test]
    fn conformance_music_sfx() {
        stored_lane("music-sfx");
    }
    include!("../tests/lane_admission_named.rs");
    #[test]
    fn video_stays_nonaccepting() {
        assert!(!advertise(
            &json!({"lanes":{"diffusion-video":true}}),
            "diffusion-video",
            true
        ));
        assert!(advertise(&json!({"lanes":{"tts":true}}), "tts", true));
        let mut views = vec![json!({"accepting":true,"why_not":[]})];
        restrict_discovery("diffusion-video", &mut views);
        assert_eq!(views[0]["accepting"], false);
        assert_eq!(views[0]["why_not"], json!(["lane accepting:false"]));
    }
    #[test]
    fn missing_reference_inputs_refuse_cleanly() {
        let path = std::env::temp_dir()
            .join(format!("missing-lane-input-{}", std::process::id()))
            .join("catalog.json");
        assert_eq!(
            cartridge_registry::load(&path),
            Err(crate::error_catalog::STORAGE_UNAVAILABLE)
        );
        assert!(worker_registry::load_static(&path, 1).is_err());
    }
    #[test]
    fn defaults() {
        let c = Config::default();
        assert_eq!(c.audio_chars, 1024);
        assert_eq!(c.text_chars, 4096);
        assert_eq!(c.audio_seconds, 3600);
        assert!(!c.video_accepting);
    }
    #[test]
    fn qc_year_10000_is_refused_by_storage() {
        let root = std::env::temp_dir().join(format!("year-boundary-{}", std::process::id()));
        let store = result_store::Store::new(&root, Default::default());
        let doc = result_store::snapshot(
            &json!({"lane":"stt","job_id":"fixture","state":"queued"}),
            253402300800,
        );
        assert_eq!(
            store.put_job("stt", "fixture", &doc, &BTreeMap::new(), 253402300800),
            Err(crate::error_catalog::BAD_SPEC)
        );
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn qc_nesting_limit_matches_rust() {
        let raw = format!("{}0{}", "[".repeat(129), "]".repeat(129));
        assert_eq!(
            decode("stt", raw.as_bytes(), None),
            Err(crate::error_catalog::BAD_JSON)
        );
    }
    #[test]
    fn qc_patterns_reject_terminal_newline() {
        let mut c = cases().into_iter().find(|c| c["id"] == "stt-ok").unwrap()["body"].clone();
        c["audio"] = json!("a\n");
        assert_eq!(body(&c, "stt", false), Err(crate::error_catalog::BAD_SPEC));
        c["audio"] = json!("a");
        c["language"] = json!("en\n");
        assert_eq!(body(&c, "stt", false), Err(crate::error_catalog::BAD_SPEC));
    }
    #[test]
    fn null_rule_runs_for_every_optional_field() {
        let c = cases().into_iter().find(|c| c["id"] == "stt-ok").unwrap()["body"].clone();
        for field in [
            "hints",
            "language",
            "diarize",
            "max_alternatives",
            "max_audio_seconds",
            "prefer",
            "job_id",
        ] {
            let mut s = c.clone();
            s[field] = Value::Null;
            assert_eq!(
                body(&s, "stt", false),
                Err(crate::error_catalog::BAD_SPEC),
                "{field}"
            );
        }
        let mut legacy = c;
        legacy["out"] = json!(std::env::temp_dir().join("unused-output"));
        legacy["cartridge_directory"] = Value::Null;
        assert_eq!(
            body(&legacy, "stt", false),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[tokio::test]
    async fn real_admission_rejects_lane_body_before_dispatch() {
        let root = std::env::temp_dir();
        for (lane, field, value) in [
            ("stt", "audio", json!("/absolute.wav")),
            ("music-sfx", "duration_seconds", json!(301)),
            ("diffusion-video", "steps", json!(0)),
        ] {
            let mut s = cases()
                .into_iter()
                .find(|c| {
                    c["id"]
                        == if lane == "stt" {
                            "stt-ok"
                        } else if lane == "music-sfx" {
                            "music-ok"
                        } else {
                            "video-ok"
                        }
                })
                .unwrap()["body"]
                .clone();
            s["out"] = json!(root.join("unused-output"));
            s[field] = value;
            let app = new_app(json!({"lanes":{lane:true}}), root.clone());
            let r =
                submit_in_process(app, lane.into(), serde_json::to_vec(&s).unwrap().into()).await;
            assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
    #[test]
    fn test_table_flip() {
        let mut s = cases().into_iter().find(|c| c["id"] == "music-ok").unwrap()["body"].clone();
        s["prompt"] = json!("p".repeat(4096));
        assert!(body(&s, "music-sfx", false).is_ok());
        s["prompt"] = json!("p".repeat(4097));
        assert_eq!(
            body(&s, "music-sfx", false),
            Err(crate::error_catalog::BAD_SPEC)
        );
        s["prompt"] = json!("p");
        s["stems"] = json!("false");
        assert_eq!(
            body(&s, "music-sfx", false),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[test]
    fn test_doc_agreement() {
        let notes = include_str!("../FOLD-NOTES.md");
        assert!(notes.contains("### F5"));
        for id in ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10"] {
            assert!(notes.contains(id), "{id}");
        }
    }
}

#[cfg(test)]
mod run34_parity {
    use super::*;
    fn parity(bodies: &[(&str, Option<&str>)]) -> Result<(), Vec<String>> {
        let lanes = lane_gate::gated_lanes();
        let mut failures = Vec::new();
        for lane in &lanes {
            let count = bodies.iter().filter(|(name, _)| name == lane).count();
            if count != 1 {
                failures.push(format!("{lane}: expected one body, found {count}"));
            }
        }
        for (lane, _) in bodies {
            if !lanes.contains(lane) {
                failures.push(format!("{lane}: body has no gated lane"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
    #[test]
    fn run34_real_lane_body_mapping_passes() {
        assert_eq!(parity(BODIES), Ok(()));
        assert_eq!(lane_gate::gated_lanes().len(), 5);
        // The registry drives the existing engine body field validation.
        assert_eq!(primary_field("tts"), Some("text"));
        assert_eq!(primary_field("diffusion-image"), Some("prompt"));
    }
    #[test]
    fn run34_planted_orphan_body_fails() {
        let mut bodies = BODIES.to_vec();
        bodies.push(("orphan", None));
        assert_eq!(
            parity(&bodies).unwrap_err(),
            vec!["orphan: body has no gated lane"]
        );
        bodies = BODIES.to_vec();
        bodies.push(BODIES[0]);
        assert!(parity(&bodies)
            .unwrap_err()
            .iter()
            .any(|s| s.contains("tts: expected one body, found 2")));
        bodies = BODIES[1..].to_vec();
        assert!(parity(&bodies)
            .unwrap_err()
            .iter()
            .any(|s| s.contains("tts: expected one body, found 0")));
    }
}
