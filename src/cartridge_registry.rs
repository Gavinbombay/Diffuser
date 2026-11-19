//! Cartridge metadata catalog validation and lane-safe resolution.
use crate::*;
pub fn digest(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub fn validate(doc: &Value) -> Result<(), &'static str> {
    if doc["kind"] != "cartridge-catalog/v1" {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::BAD_CATALOG,
        ));
    }
    let entries = doc["cartridges"]
        .as_array()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_CATALOG))?;
    let mut ids = HashSet::new();
    let mut defaults = HashSet::new();
    for e in entries {
        let o = e
            .as_object()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_CATALOG))?;
        if o.keys().any(|f| {
            ![
                "id",
                "lane",
                "version",
                "licence",
                "sha256",
                "vram_gb_min",
                "load_seconds_est",
                "params",
                "pin",
                "default",
                "notes",
            ]
            .contains(&f.as_str())
        }) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::BAD_CATALOG,
            ));
        }
        let id = e["id"]
            .as_str()
            .filter(|s| worker_registry::identifier(s, 64, b".-", false))
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_CATALOG))?;
        let lane = e["lane"]
            .as_str()
            .filter(|s| LANES.contains(s))
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_CATALOG))?;
        for (field, width, extra) in [
            ("version", 32, b".".as_slice()),
            ("licence", 64, b".+-".as_slice()),
        ] {
            if !e[field]
                .as_str()
                .is_some_and(|s| worker_registry::identifier(s, width, extra, false))
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::BAD_CATALOG,
                ));
            }
        }
        if !digest(&e["sha256"])
            || !e["vram_gb_min"]
                .as_f64()
                .is_some_and(|n| (0.0..=80.0).contains(&n))
            || !e["load_seconds_est"]
                .as_f64()
                .is_some_and(|n| (0.0..=3600.0).contains(&n))
            || e["params"].as_object().is_none_or(|o| o.len() != 1)
            || e["params"]["schema"] != format!("{lane}.params.schema.json")
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::BAD_CATALOG,
            ));
        }
        if e.get("default").is_some_and(|v| !v.is_boolean())
            || e.get("notes")
                .is_some_and(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 512))
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::BAD_CATALOG,
            ));
        }
        if (lane != "render-blender" || e.get("pin").is_some())
            && (!lane_gate::valid_pin(&e["pin"]) || e["pin"]["id"] != id)
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::BAD_CATALOG,
            ));
        }
        if !ids.insert(id) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::CARTRIDGE_ID_EXISTS,
            ));
        }
        if e["default"] == true && !defaults.insert(lane) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::BAD_CATALOG,
            ));
        }
    }
    Ok(())
}
pub fn job_shape(job: &Value, lane: &str) -> Result<(), &'static str> {
    let o = job
        .as_object()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    let body_lane = job["lane"]
        .as_str()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    if body_lane != lane {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::LANE_MISMATCH,
        ));
    }
    if job["api"] != API {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if job
        .get("job_id")
        .is_some_and(|v| !v.as_str().is_some_and(result_store::valid_id))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if let Some(t) = job.get("timeout_min") {
        if !t.as_f64().is_some_and(|n| (1.0..=360.0).contains(&n))
            || (lane != "render-blender" && !t.is_u64())
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    if let Some(p) = job.get("prefer") {
        let a = p
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
    if lane == "render-blender" {
        let mut spec = job.clone();
        if spec["cartridge"] == "default" {
            spec["cartridge"] = json!(RB_CARTRIDGES[0]);
        }
        return render_admission::body(&spec);
    }
    if ["stt", "diffusion-video", "music-sfx"].contains(&lane) {
        return lane_bodies::body(job, lane, true);
    }
    let common = [
        "api",
        "lane",
        "job_id",
        "cartridge",
        "prefer",
        "timeout_min",
        "out",
        "submitter",
        "cartridge_manifest",
        "cartridge_directory",
        "cartridge_manifest_sha256",
    ];
    let fields: &[&str] = match lane {
        "tts" => &[
            "text",
            "voice",
            "format",
            "sample_rate",
            "hints",
            "seed",
            "max_output_seconds",
        ],
        "diffusion-image" => &[
            "prompt",
            "negative_prompt",
            "negative",
            "size",
            "steps",
            "seed",
            "format",
            "guidance",
            "sampler",
        ],
        "diffusion-video" => &[
            "prompt",
            "negative_prompt",
            "negative",
            "size",
            "width",
            "height",
            "steps",
            "seed",
            "frames",
            "fps",
            "loop",
            "format",
            "guidance",
            "sampler",
        ],
        "stt" => &[
            "audio",
            "format",
            "language",
            "task",
            "timestamps",
            "max_alternatives",
            "hints",
        ],
        "music-sfx" => &[
            "prompt",
            "mode",
            "duration_seconds",
            "seed",
            "format",
            "sample_rate",
            "stems",
            "hints",
            "negative_prompt",
            "negative",
        ],
        _ => return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC)),
    };
    if o.keys()
        .any(|f| !common.contains(&f.as_str()) && !fields.contains(&f.as_str()))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if o.values().any(Value::is_null) || !lane_bodies::integer_json(job) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if job
        .get("seed")
        .is_some_and(|v| !v.as_u64().is_some_and(|n| n <= u32::MAX as u64))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    match lane {
        "tts" => {
            if !job["text"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.chars().count() <= 10000)
                || !job["voice"].as_str().is_some_and(result_store::valid_id)
                || !job["sample_rate"]
                    .as_u64()
                    .is_some_and(|n| (16000..=48000).contains(&n))
                || job["format"] != "wav"
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
        "diffusion-image" => {
            if !job["prompt"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.chars().count() <= 4096)
                || !job["steps"]
                    .as_u64()
                    .is_some_and(|n| (1..=100).contains(&n))
                || !job["seed"].as_u64().is_some_and(|n| n <= u32::MAX as u64)
                || job["format"] != "png"
                || job
                    .get("negative")
                    .is_some_and(|v| !v.as_str().is_some_and(|s| s.chars().count() <= 4096))
            {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
            let size = &job["size"];
            if size.as_object().is_none_or(|o| o.len() != 2)
                || ["width", "height"]
                    .iter()
                    .any(|f| !size[*f].as_u64().is_some_and(|n| (256..=1536).contains(&n)))
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
        }
        _ => return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC)),
    }

    Ok(())
}
pub fn resolve(
    doc: &Value,
    lane: &str,
    requested: Option<&str>,
    job: Option<&Value>,
) -> Result<Value, &'static str> {
    validate(doc)?;
    if !LANES.contains(&lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    let entries = doc["cartridges"].as_array().unwrap();
    let entry = if let Some(id) = requested {
        let e = entries
            .iter()
            .find(|e| e["id"] == id)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_CARTRIDGE))?;
        if e["lane"] != lane {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::LANE_MISMATCH,
            ));
        }
        e
    } else {
        entries
            .iter()
            .find(|e| e["lane"] == lane && e["default"] == true)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::PIN_UNSET))?
    };
    if let Some(job) = job {
        if !job.is_object() || !job["lane"].is_string() {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
        if job["lane"] != lane {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::LANE_MISMATCH,
            ));
        }
        job_shape(job, lane)?;
        if let Some(named) = job.get("cartridge") {
            let named = named
                .as_str()
                .filter(|s| worker_registry::identifier(s, 64, b".-", false))
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
            if named != "default" {
                let named_entry = entries.iter().find(|e| e["id"] == named).ok_or_else(|| {
                    crate::error_catalog::reason(crate::error_catalog::UNKNOWN_CARTRIDGE)
                })?;
                if named_entry["lane"] != lane {
                    return Err(crate::error_catalog::reason(
                        crate::error_catalog::LANE_MISMATCH,
                    ));
                }
            }
        }
        if lane == "tts" {
            let p = &entry["pin"];
            if !p["voices"].as_array().unwrap().contains(&job["voice"])
                || !p["rates"].as_array().unwrap().contains(&job["sample_rate"])
                || job["text"].as_str().unwrap().chars().count() as u64
                    > p["max_text_chars"].as_u64().unwrap()
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::PIN_INCOMPATIBLE,
                ));
            }
        }
        if lane.starts_with("diffusion-") {
            let p = &entry["pin"];
            for (field, bound) in [
                ("steps", "max_steps"),
                ("width", "max_width"),
                ("height", "max_height"),
            ] {
                if job
                    .get(field)
                    .or_else(|| job["size"].get(field))
                    .and_then(Value::as_u64)
                    .is_some_and(|n| n > p[bound].as_u64().unwrap())
                {
                    return Err(crate::error_catalog::reason(
                        crate::error_catalog::PIN_INCOMPATIBLE,
                    ));
                }
            }
        }
    }
    Ok(entry.clone())
}
pub fn load(path: &Path) -> Result<Value, &'static str> {
    let bytes = fs::read(path)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE))?;
    let doc = lane_gate::parse(&bytes)?;
    validate(&doc)?;
    Ok(doc)
}
pub fn apply_config(config: &Value, spec: &mut Value) -> Result<(), &'static str> {
    let doc = if let Some(path) = config["cartridge_catalog_path"].as_str() {
        load(Path::new(path))?
    } else if config.get("cartridge_catalog").is_some() {
        let v = config["cartridge_catalog"].clone();
        validate(&v)?;
        v
    } else {
        return Ok(());
    };
    let lane = spec["lane"]
        .as_str()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    let requested = spec["cartridge"].as_str().filter(|s| *s != "default");
    let entry = resolve(&doc, lane, requested, Some(spec))?;
    spec["cartridge"] = entry["id"].clone();
    Ok(())
}
pub fn cli(args: &[String]) -> Result<Value, &'static str> {
    let get = |flag: &str| {
        args.iter()
            .position(|v| v == flag)
            .and_then(|n| args.get(n + 1))
            .map(String::as_str)
    };
    let catalog = load(Path::new(get("--catalog").ok_or_else(|| {
        crate::error_catalog::reason(crate::error_catalog::BAD_SPEC)
    })?))?;
    let job = get("--job")
        .map(|path| {
            fs::read(path)
                .map_err(|_| {
                    crate::error_catalog::reason(crate::error_catalog::STORAGE_UNAVAILABLE)
                })
                .and_then(|raw| lane_gate::parse(&raw))
        })
        .transpose()?;
    resolve(
        &catalog,
        get("--lane")
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?,
        get("--cartridge"),
        job.as_ref(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn example() -> Value {
        let entries=LANES.iter().map(|lane|{let id=if *lane=="render-blender"{RB_CARTRIDGES[0].to_owned()}else{format!("{lane}-fixture-v1")};let mut e=json!({"id":id,"lane":lane,"version":"1","licence":"fixture","sha256":hex::encode(Sha256::digest(lane.as_bytes())),"vram_gb_min":1,"load_seconds_est":10,"params":{"schema":format!("{lane}.params.schema.json")},"default":true});if *lane!="render-blender"{e["pin"]=json!({"id":id,"sha256":hex::encode(Sha256::digest(b"fixture pin")),"voices":["default"],"rates":[16000,22050,24000,44100,48000],"max_width":1536,"max_height":1536,"max_steps":100,"max_text_chars":10000});}e}).collect::<Vec<_>>();
        json!({"kind":"cartridge-catalog/v1","cartridges":entries})
    }
    #[test]
    fn run31_registry_refusal_table() {
        let base = example();
        assert!(validate(&base).is_ok());
        let mut duplicate = base.clone();
        let row = duplicate["cartridges"][0].clone();
        duplicate["cartridges"].as_array_mut().unwrap().push(row);
        let mut rows = vec![(
            "duplicate id",
            duplicate,
            crate::error_catalog::CARTRIDGE_ID_EXISTS,
        )];
        for (label, field, value) in [
            ("unknown lane", "lane", json!("unknown")),
            ("empty id", "id", json!("")),
            ("empty version", "version", json!("")),
            ("empty licence", "licence", json!("")),
            ("long id", "id", json!("x".repeat(65))),
            ("long version", "version", json!("1".repeat(33))),
            ("long licence", "licence", json!("x".repeat(65))),
            ("long notes", "notes", json!("x".repeat(513))),
        ] {
            let mut doc = base.clone();
            doc["cartridges"][0][field] = value;
            rows.push((label, doc, crate::error_catalog::BAD_CATALOG));
        }
        assert_eq!(rows.len(), 9);
        for (label, doc, expected) in rows {
            let code = validate(&doc).unwrap_err();
            assert_eq!(code, expected, "{label}");
            assert!(
                crate::error_catalog::TABLE
                    .iter()
                    .any(|entry| entry.code == code),
                "{label}"
            );
        }
    }
    fn entry<'a>(doc: &'a mut Value, lane: &str) -> &'a mut Value {
        doc["cartridges"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e["lane"] == lane)
            .unwrap()
    }
    pub(super) fn job(lane: &str) -> Value {
        let mut s = json!({"api":API,"lane":lane,"job_id":"fixture","cartridge":"default","timeout_min":45});
        match lane {
            "render-blender" => {
                s["blend"] = json!("/scene.blend");
                s["out"] = json!("/render-output");
                s["frames"] = json!("1-6");
            }
            "tts" => {
                s["text"] = json!("fixture");
                s["voice"] = json!("default");
                s["sample_rate"] = json!(16000);
                s["format"] = json!("wav");
            }
            "diffusion-image" | "diffusion-video" => {
                s["prompt"] = json!("fixture");
                s["size"] = json!({"width":512,"height":512});
                s["steps"] = json!(30);
                s["seed"] = json!(7);
                if lane == "diffusion-video" {
                    s["frames"] = json!(48);
                    s["format"] = json!("mp4");
                } else {
                    s["format"] = json!("png");
                }
            }
            "stt" => {
                s["audio"] = json!("clip.wav");
                s["format"] = json!("wav");
            }
            "music-sfx" => {
                s["prompt"] = json!("fixture");
                s["mode"] = json!("sfx");
                s["duration_seconds"] = json!(30);
                s.as_object_mut().unwrap().remove("mode");
                s["format"] = json!("wav");
            }
            _ => unreachable!(),
        };
        s
    }
    fn good(lane: &str, with_job: bool) {
        let e = resolve(&example(), lane, None, with_job.then(|| job(lane)).as_ref()).unwrap();
        assert_eq!(e["lane"], lane);
    }
    #[test]
    fn validate_example() {
        assert!(validate(&example()).is_ok());
        assert_eq!(example()["cartridges"].as_array().unwrap().len(), 6);
    }
    macro_rules! lane_cases {($(($default:ident,$with_job:ident,$lane:literal)),*$(,)?)=>{$(#[test]fn $default(){good($lane,false);}#[test]fn $with_job(){good($lane,true);})*};}
    lane_cases!(
        (
            resolve_default_render_blender,
            resolve_job_render_blender,
            "render-blender"
        ),
        (resolve_default_tts, resolve_job_tts, "tts"),
        (resolve_default_stt, resolve_job_stt, "stt"),
        (
            resolve_default_diffusion_image,
            resolve_job_diffusion_image,
            "diffusion-image"
        ),
        (
            resolve_default_diffusion_video,
            resolve_job_diffusion_video,
            "diffusion-video"
        ),
        (
            resolve_default_music_sfx,
            resolve_job_music_sfx,
            "music-sfx"
        )
    );
    #[test]
    fn resolve_explicit() {
        let doc = example();
        let id = doc["cartridges"][1]["id"].as_str().unwrap();
        assert_eq!(resolve(&doc, "tts", Some(id), None).unwrap()["id"], id);
    }
    #[test]
    fn resolve_job_good() {
        good("tts", true);
    }
    #[test]
    fn resolve_job_bake_render() {
        let mut j = job("render-blender");
        j["type"] = json!("bake-render");
        j["steps"] = json!(["script", "bake"]);
        j["frames"] = Value::Null;
        assert!(resolve(&example(), "render-blender", None, Some(&j)).is_ok());
    }
    #[test]
    fn resolve_job_render_fractional_timeout() {
        let mut j = job("render-blender");
        j["timeout_min"] = json!(45.5);
        assert!(resolve(&example(), "render-blender", None, Some(&j)).is_ok());
    }
    #[test]
    fn bad_json() {
        assert_eq!(lane_gate::parse(b"{"), Err(crate::error_catalog::BAD_JSON));
    }
    #[test]
    fn duplicate_key() {
        assert_eq!(
            lane_gate::parse(br#"{"kind":1,"kind":2}"#),
            Err(crate::error_catalog::BAD_JSON)
        );
    }
    #[test]
    fn catalog_shape() {
        for d in [
            json!([]),
            json!({}),
            json!({"kind":"wrong","cartridges":[]}),
            json!({"kind":"cartridge-catalog/v1","cartridges":[1]}),
        ] {
            assert_eq!(validate(&d), Err(crate::error_catalog::BAD_CATALOG));
        }
    }
    #[test]
    fn entry_schema() {
        let mut d = example();
        entry(&mut d, "tts")
            .as_object_mut()
            .unwrap()
            .remove("licence");
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_CATALOG));
    }
    #[test]
    fn entry_schema_sha256() {
        let mut d = example();
        entry(&mut d, "stt")["sha256"] = json!("[R]");
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_CATALOG));
    }
    #[test]
    fn params_pointer() {
        let mut d = example();
        entry(&mut d, "tts")["params"]["schema"] = json!("stt.params.schema.json");
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_CATALOG));
    }
    #[test]
    fn pin_shape() {
        let mut d = example();
        entry(&mut d, "tts")["pin"]
            .as_object_mut()
            .unwrap()
            .remove("rates");
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_CATALOG));
    }
    #[test]
    fn pin_id() {
        let mut d = example();
        entry(&mut d, "tts")["pin"]["id"] = json!("other");
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_CATALOG));
    }
    #[test]
    fn duplicate_id() {
        let mut d = example();
        let mut clone = entry(&mut d, "tts").clone();
        clone["default"] = json!(false);
        d["cartridges"].as_array_mut().unwrap().push(clone.clone());
        assert_eq!(validate(&d), Err(crate::error_catalog::CARTRIDGE_ID_EXISTS));
        clone["id"] = json!("tts-fixture-v2");
        clone["pin"]["id"] = clone["id"].clone();
        *d["cartridges"].as_array_mut().unwrap().last_mut().unwrap() = clone;
        assert!(validate(&d).is_ok());
    }
    #[test]
    fn default_count() {
        let mut d = example();
        let mut clone = entry(&mut d, "tts").clone();
        clone["id"] = json!("tts-fixture-v2");
        clone["pin"]["id"] = clone["id"].clone();
        d["cartridges"].as_array_mut().unwrap().push(clone);
        assert_eq!(validate(&d), Err(crate::error_catalog::BAD_CATALOG));
    }
    #[test]
    fn unknown_lane() {
        assert_eq!(
            resolve(&example(), "unknown", None, None),
            Err(crate::error_catalog::UNKNOWN_LANE)
        );
    }
    #[test]
    fn unknown_cartridge() {
        assert_eq!(
            resolve(&example(), "tts", Some("unknown"), None),
            Err(crate::error_catalog::UNKNOWN_CARTRIDGE)
        );
    }
    #[test]
    fn lane_mismatch() {
        assert_eq!(
            resolve(&example(), "tts", Some(RB_CARTRIDGES[0]), None),
            Err(crate::error_catalog::LANE_MISMATCH)
        );
    }
    #[test]
    fn pin_unset() {
        let mut d = example();
        entry(&mut d, "tts")["default"] = json!(false);
        assert_eq!(
            resolve(&d, "tts", None, None),
            Err(crate::error_catalog::PIN_UNSET)
        );
    }
    #[test]
    fn pin_unset_absent() {
        let mut d = example();
        d["cartridges"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["lane"] != "tts");
        assert_eq!(
            resolve(&d, "tts", None, None),
            Err(crate::error_catalog::PIN_UNSET)
        );
    }
    fn bad_job(field: &str, value: Value, code: &str) {
        let mut j = job("tts");
        j[field] = value;
        assert_eq!(
            resolve(&example(), "tts", None, Some(&j)).unwrap_err(),
            code
        );
    }
    #[test]
    fn job_unknown_param() {
        let mut j = job("diffusion-image");
        j["count"] = json!(1);
        assert_eq!(
            resolve(&example(), "diffusion-image", None, Some(&j)),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[test]
    fn job_bad_value() {
        bad_job(
            "text",
            json!("x".repeat(10001)),
            crate::error_catalog::BAD_SPEC,
        );
    }
    #[test]
    fn job_envelope_wrong_api() {
        bad_job("api", json!("wrong-api/v9"), crate::error_catalog::BAD_SPEC);
    }
    #[test]
    fn job_envelope_bad_job_id() {
        bad_job(
            "job_id",
            json!("../invalid"),
            crate::error_catalog::BAD_SPEC,
        );
    }
    #[test]
    fn job_envelope_timeout_range() {
        bad_job("timeout_min", json!(361), crate::error_catalog::BAD_SPEC);
    }
    #[test]
    fn job_envelope_prefer_duplicate() {
        bad_job("prefer", json!(["a", "a"]), crate::error_catalog::BAD_SPEC);
    }
    #[test]
    fn job_envelope_bad() {
        let mut j = job("tts");
        j["api"] = json!("wrong");
        j["job_id"] = json!("../invalid");
        j["timeout_min"] = json!(9999);
        j["cartridge"] = json!("ghost");
        assert_eq!(
            resolve(&example(), "tts", None, Some(&j)),
            Err(crate::error_catalog::BAD_SPEC)
        );
    }
    #[test]
    fn job_cartridge() {
        bad_job(
            "cartridge",
            json!("ghost"),
            crate::error_catalog::UNKNOWN_CARTRIDGE,
        );
        bad_job(
            "cartridge",
            json!(RB_CARTRIDGES[0]),
            crate::error_catalog::LANE_MISMATCH,
        );
        let mut j = job("tts");
        j["cartridge"] = json!("tts-fixture-v1");
        assert!(resolve(&example(), "tts", None, Some(&j)).is_ok());
    }
    #[test]
    fn job_lane() {
        bad_job(
            "lane",
            json!("diffusion-image"),
            crate::error_catalog::LANE_MISMATCH,
        );
        bad_job(
            "lane",
            json!("unknown"),
            crate::error_catalog::LANE_MISMATCH,
        );
    }
    macro_rules! lane_type_cases{($(($name:ident,$v:expr)),*$(,)?)=>{$(#[test] fn $name(){bad_job("lane",$v,crate::error_catalog::BAD_SPEC);})*};}
    lane_type_cases!(
        (job_lane_type_number, json!(5)),
        (job_lane_type_bool, json!(true)),
        (job_lane_type_list, json!(["tts"])),
        (job_lane_type_object, json!({"a":1})),
        (job_lane_type_null, Value::Null)
    );
    #[test]
    fn pin_incompatible_steps() {
        let mut d = example();
        entry(&mut d, "diffusion-image")["pin"]["max_steps"] = json!(50);
        let mut j = job("diffusion-image");
        j["steps"] = json!(75);
        assert_eq!(
            resolve(&d, "diffusion-image", None, Some(&j)),
            Err(crate::error_catalog::PIN_INCOMPATIBLE)
        );
    }
    #[test]
    fn pin_incompatible_voice() {
        bad_job(
            "voice",
            json!("alloy"),
            crate::error_catalog::PIN_INCOMPATIBLE,
        );
    }
    #[test]
    fn case_count() {
        let output = crate::test_process::command()
            .args(["--list", "--format", "terse"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let listed = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            listed
                .lines()
                .filter(|s| s.starts_with("cartridge_registry::tests::") && s.ends_with(": test"))
                .count(),
            50
        );
    }
}

#[cfg(test)]
mod integration {
    use super::*;
    #[test]
    fn configured_catalog_resolves_into_admission() {
        let root = std::env::temp_dir().join(format!("catalog-config-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("catalog.json");
        fs::write(&path, serde_json::to_vec(&tests::example()).unwrap()).unwrap();
        let mut spec = tests::job("tts");
        apply_config(&json!({"cartridge_catalog_path":path}), &mut spec).unwrap();
        assert_eq!(spec["cartridge"], "tts-fixture-v1");
        fs::write(&path, br#"{"kind":1,"kind":2}"#).unwrap();
        assert_eq!(load(&path), Err(crate::error_catalog::BAD_JSON));
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn malformed_catalog_refuses_in_real_handler() {
        let app = new_app(
            json!({"lanes":{"tts":true},"cartridge_catalog":{"kind":"wrong"}}),
            std::env::temp_dir(),
        );
        let r = submit_in_process(
            app,
            "tts".into(),
            serde_json::to_vec(&tests::job("tts")).unwrap().into(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
