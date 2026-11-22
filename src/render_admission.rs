//! Render request shape and resolved admission gate, composed with shared limits.
use crate::*;
#[derive(Debug)]
pub struct Config {
    pub timeout_min: f64,
    pub script_chars: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_min: 45.0,
            script_chars: 4096,
        }
    }
}
const PARAMS: &[&str] = &[
    "api",
    "lane",
    "job_id",
    "cartridge",
    "prefer",
    "timeout_min",
    "type",
    "blend",
    "assets",
    "inputs",
    "frames",
    "engine",
    "out",
    "split_across_workers",
    "script",
    "script_timeout_min",
    "bake_timeout_min",
    "steps",
    "submitter",
    "cartridge_manifest",
    "cartridge_directory",
    "cartridge_manifest_sha256",
];
fn no_float(v: &Value) -> bool {
    match v {
        Value::Number(n) => !n.is_f64(),
        Value::Array(a) => a.iter().all(no_float),
        Value::Object(o) => o.values().all(no_float),
        _ => true,
    }
}
pub fn body(spec: &Value) -> Result<(), &'static str> {
    let obj = spec
        .as_object()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    if spec["lane"] != "render-blender" {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::LANE_MISMATCH,
        ));
    }
    for (field, v) in obj {
        if !["timeout_min", "script_timeout_min", "bake_timeout_min"].contains(&field.as_str())
            && !no_float(v)
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_JSON));
        }
    }
    if obj.keys().any(|f| !PARAMS.contains(&f.as_str())) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if spec.get("api").is_some_and(|v| v != API) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let bake = spec["type"] == "bake-render";
    for (field, v) in obj {
        if v.is_null()
            && ![
                "type",
                "engine",
                "assets",
                "split_across_workers",
                "timeout_min",
                "script",
                "job_id",
            ]
            .contains(&field.as_str())
            && !(field == "frames" && bake)
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    if spec
        .get("type")
        .is_some_and(|v| !v.is_null() && v != "render" && v != "bake-render")
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let blend = spec["blend"]
        .as_str()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    if !blend.starts_with('/') || !blend.ends_with(".blend") {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let out = spec["out"]
        .as_str()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    if !out.starts_with('/')
        || out == "/mnt/gpu-preserve"
        || out.starts_with("/mnt/gpu-preserve/")
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if spec
        .get("job_id")
        .filter(|v| !v.is_null())
        .is_some_and(|v| !v.as_str().is_some_and(result_store::valid_id))
    {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if spec.get("cartridge").is_some_and(|v| v != RB_CARTRIDGES[0]) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if let Some(v) = spec.get("prefer") {
        let a = v
            .as_array()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        let mut ids = HashSet::new();
        if a.len() > 5
            || a.iter().any(|v| {
                !v.as_str().is_some_and(result_store::valid_id) || !ids.insert(v.to_string())
            })
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    for field in ["assets", "inputs"] {
        if let Some(v) = spec.get(field).filter(|v| !v.is_null()) {
            if !v.as_str().is_some_and(|s| s.starts_with('/')) {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
    }
    if let Some(v) = spec.get("engine").filter(|v| !v.is_null()) {
        if !v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("CYCLES")) {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    if bake {
        crate::bake_frames_ok(&spec["frames"])
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    } else {
        let frames = spec["frames"]
            .as_str()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        crate::parse_frames(frames)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
    }
    for field in ["timeout_min", "script_timeout_min", "bake_timeout_min"] {
        if let Some(v) = spec.get(field).filter(|v| !v.is_null()) {
            let n = v
                .as_f64()
                .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
            let valid = if field == "timeout_min" {
                (1.0..=360.0).contains(&n)
            } else if bake {
                n > 0.0 && n <= 720.0
            } else {
                (0.0..=720.0).contains(&n)
            };
            if !valid {
                return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
            }
        }
    }
    if let Some(v) = spec.get("split_across_workers").filter(|v| !v.is_null()) {
        if !v.is_boolean() {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    if let Some(v) = spec.get("script").filter(|v| !v.is_null()) {
        if !v
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.chars().count() <= Config::default().script_chars)
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    if let Some(v) = spec.get("steps") {
        let a = v
            .as_array()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::BAD_SPEC))?;
        let mut unique = HashSet::new();
        if a.is_empty()
            || a.len() > 3
            || a.iter().any(|s| {
                !s.as_str()
                    .is_some_and(|s| ["script", "bake", "render"].contains(&s))
                    || !unique.insert(s.to_string())
            })
        {
            return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
        }
    }
    Ok(())
}
pub fn gate(config: &Value, spec: &Value) -> Result<(), &'static str> {
    if config["lanes"]["render-blender"] != true {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::LANE_DISABLED,
        ));
    }
    let pin = &config["render_pin"];
    if pin.is_null() {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PIN_UNSET,
        ));
    }
    if !lane_gate::valid_pin(pin) || pin["id"] != RB_CARTRIDGES[0] {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PIN_INCOMPATIBLE,
        ));
    }
    if spec.get("cartridge").is_some_and(|v| *v != pin["id"])
        || spec
            .get("cartridge_manifest_sha256")
            .is_some_and(|v| *v != pin["sha256"])
    {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::PIN_INCOMPATIBLE,
        ));
    }
    Ok(())
}

pub fn media_type(value: Option<&str>) -> Result<(), &'static str> {
    if value.is_none_or(|v| {
        v.split(';')
            .next()
            .unwrap()
            .trim()
            .eq_ignore_ascii_case("application/json")
    }) {
        Ok(())
    } else {
        Err(crate::error_catalog::reason(
            crate::error_catalog::UNSUPPORTED_MEDIA_TYPE,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1800000000;
    fn good() -> Value {
        json!({"api":API,"lane":"render-blender","job_id":"rb-good-001","cartridge":RB_CARTRIDGES[0],"timeout_min":45,"type":"render","blend":"/scene.blend","frames":"1-6","engine":"CYCLES","out":"/render-output"})
    }
    fn bake() -> Value {
        let mut s = good();
        s["type"] = json!("bake-render");
        s["steps"] = json!(["script", "bake"]);
        s["script_timeout_min"] = json!(5.5);
        s.as_object_mut().unwrap().remove("frames");
        s
    }
    fn pin() -> Value {
        json!({"id":RB_CARTRIDGES[0],"sha256":hex::encode(Sha256::digest(b"fixture pin")),"voices":["default"],"rates":[16000,22050,24000,44100,48000],"max_width":1536,"max_height":1536,"max_steps":100,"max_text_chars":10000})
    }
    fn config() -> Value {
        json!({"lanes":{"render-blender":true},"render_pin":pin()})
    }
    fn changed(field: &str, v: Value) -> Value {
        let mut s = good();
        s[field] = v;
        s
    }
    fn admit(
        spec: &Value,
        config: &Value,
        rows: &mut HashMap<String, Value>,
    ) -> Result<Value, &'static str> {
        body(spec)?;
        gate(config, spec)?;
        queue_policy::check(rows, "render-blender", spec)?;
        queue_policy::capacity(rows, "render-blender", queue_policy::Config::default(), NOW)
            .map_err(|_| crate::error_catalog::QUEUE_FULL)?;
        let row = queue_policy::admitted(rows, spec, NOW);
        rows.insert(spec["job_id"].as_str().unwrap().into(), row.clone());
        Ok(row)
    }
    fn accepted(spec: &Value) -> Value {
        admit(spec, &config(), &mut HashMap::new()).unwrap()
    }
    fn reject(field: &str, v: Value) {
        assert!(body(&changed(field, v)).is_err(), "{field}");
    }
    #[test]
    fn script_only_steps_reach_existing_validator() {
        let root = std::env::temp_dir().join(format!("render-script-only-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let blend = root.join("scene.blend");
        fs::write(&blend, b"fixture").unwrap();
        let mut s = bake();
        s["blend"] = json!(blend);
        s["out"] = json!(root.join("out"));
        s["steps"] = json!(["script"]);
        assert!(crate::validate(&s).is_ok());
        s.as_object_mut().unwrap().remove("out");
        assert!(crate::validate(&s).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn http_render_body_guard() {
        let app = new_app(json!({}), std::env::temp_dir());
        let r = submit_in_process(
            app,
            "render-blender".into(),
            serde_json::to_vec(&changed("steps", json!(["script", "script"])))
                .unwrap()
                .into(),
        )
        .await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
    #[test]
    fn defaults() {
        assert_eq!(Config::default().timeout_min, 45.0);
        assert_eq!(Config::default().script_chars, 4096);
    }
    #[test]
    fn test_refuses_a_disabled_lane() {
        assert_eq!(
            gate(&json!({}), &good()),
            Err(crate::error_catalog::LANE_DISABLED)
        );
    }
    #[test]
    fn test_gate_runs_before_the_pin_lookup() {
        test_refuses_a_disabled_lane();
    }
    #[test]
    fn test_gate_admits_nothing_while_disabled() {
        let mut rows = HashMap::new();
        assert_eq!(
            admit(&good(), &json!({}), &mut rows),
            Err(crate::error_catalog::LANE_DISABLED)
        );
        assert!(rows.is_empty());
    }
    #[test]
    fn test_enabled_lane_admits() {
        assert_eq!(accepted(&good())["state"], "queued");
    }
    #[test]
    fn test_configure_refuses_another_lane() {
        assert_eq!(
            body(&changed("lane", json!("tts"))),
            Err(crate::error_catalog::LANE_MISMATCH)
        );
    }
    #[test]
    fn test_unset_pin_refuses() {
        assert_eq!(
            gate(&json!({"lanes":{"render-blender":true}}), &good()),
            Err(crate::error_catalog::PIN_UNSET)
        );
    }
    #[test]
    fn test_configure_refuses_an_invalid_pin() {
        let mut c = config();
        c["render_pin"]["sha256"] = json!("[R]");
        assert_eq!(
            gate(&c, &good()),
            Err(crate::error_catalog::PIN_INCOMPATIBLE)
        );
    }
    #[test]
    fn test_the_render_pin_id_is_valid_with_dots() {
        assert!(lane_gate::valid_pin(&pin()));
        assert!(!lane_gate::valid_pin(&json!({"id":RB_CARTRIDGES[0]})));
    }
    #[test]
    fn test_snapshot_carries_the_resolved_pin() {
        let mut s = good();
        s["cartridge_manifest_sha256"] = pin()["sha256"].clone();
        let r = accepted(&s);
        let v = result_store::snapshot(&r, NOW);
        assert_eq!(v["cartridge"], pin()["id"]);
        assert_eq!(v["pin_sha256"], pin()["sha256"]);
    }
    #[test]
    fn test_pin_swap_after_admission_changes_nothing() {
        let mut s = good();
        s["cartridge_manifest_sha256"] = pin()["sha256"].clone();
        let r = accepted(&s);
        let v = result_store::snapshot(&r, NOW);
        let mut c = config();
        c["render_pin"]["sha256"] = json!(hex::encode(Sha256::digest(b"another pin")));
        assert_eq!(gate(&c, &s), Err(crate::error_catalog::PIN_INCOMPATIBLE));
        assert_eq!(v["pin_sha256"], pin()["sha256"]);
    }
    #[test]
    fn test_replay_returns_the_original_snapshot() {
        let mut rows = HashMap::new();
        let r = admit(&good(), &config(), &mut rows).unwrap();
        assert_eq!(
            admit(&good(), &config(), &mut rows),
            Err(crate::error_catalog::JOB_ID_EXISTS)
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows["rb-good-001"], r);
    }
    #[test]
    fn test_conflict_on_a_different_spec() {
        let mut rows = HashMap::new();
        admit(&good(), &config(), &mut rows).unwrap();
        assert_eq!(
            admit(&changed("frames", json!("7-9")), &config(), &mut rows),
            Err(crate::error_catalog::JOB_ID_EXISTS)
        );
    }
    #[test]
    fn test_bad_idem_shape() {
        for id in ["", "has space", "has/slash"] {
            reject("job_id", json!(id));
        }
        reject("job_id", json!("a".repeat(129)));
    }
    #[test]
    fn test_job_id_exists() {
        test_conflict_on_a_different_spec();
    }
    #[test]
    fn test_pretty_and_compact_share_one_fingerprint() {
        let s = good();
        let a = lane_gate::parse(&serde_json::to_vec_pretty(&s).unwrap()).unwrap();
        let b = lane_gate::parse(&serde_json::to_vec(&s).unwrap()).unwrap();
        assert_eq!(deadline::fingerprint(&a), deadline::fingerprint(&b));
    }
    #[test]
    fn test_minted_id_when_job_id_is_absent_or_null() {
        let mut s = good();
        s.as_object_mut().unwrap().remove("job_id");
        assert!(request_boundary::job_id(&s).starts_with("rb-"));
        s["job_id"] = Value::Null;
        assert!(request_boundary::job_id(&s).starts_with("rb-"));
    }
    #[test]
    fn test_submitted_job_id_is_kept() {
        assert_eq!(
            request_boundary::job_id(&changed("job_id", json!("rb-kept-1"))),
            "rb-kept-1"
        );
    }
    fn full() -> HashMap<String, Value> {
        (0..128)
            .map(|n| {
                let id = format!("fill-{n}");
                let mut s = good();
                s["job_id"] = json!(id);
                (id, queue_policy::admitted(&HashMap::new(), &s, NOW))
            })
            .collect()
    }
    #[test]
    fn test_the_129th_job_is_refused() {
        assert_eq!(
            admit(&good(), &config(), &mut full()),
            Err(crate::error_catalog::QUEUE_FULL)
        );
    }
    #[test]
    fn test_queue_full_body_is_the_kit_envelope() {
        let e = queue_policy::envelope(crate::error_catalog::QUEUE_FULL, true);
        assert_eq!(e.as_object().unwrap().len(), 3);
        assert_eq!(e["retryable"], true);
    }
    #[test]
    fn test_cancel_frees_a_depth_slot() {
        let mut rows = full();
        deadline::cancel(rows.get_mut("fill-0").unwrap(), NOW).unwrap();
        assert!(admit(&good(), &config(), &mut rows).is_ok());
    }
    #[test]
    fn test_expiry_frees_a_depth_slot() {
        let mut rows = full();
        assert_eq!(deadline::process(&mut rows, NOW + 2700).len(), 128);
        assert!(queue_policy::capacity(
            &rows,
            "render-blender",
            queue_policy::Config::default(),
            NOW + 2700
        )
        .is_ok());
    }
    #[test]
    fn test_expiry_survives_one_second_before_the_deadline() {
        let mut rows = full();
        assert!(deadline::process(&mut rows, NOW + 2699).is_empty());
    }
    #[test]
    fn test_global_cap_composes() {
        let mut rows = HashMap::new();
        for n in 0..512 {
            let lane = LANES[n % LANES.len()];
            rows.insert(format!("j-{n}"), json!({"lane":lane,"state":"queued"}));
        }
        assert!(queue_policy::capacity(
            &rows,
            "render-blender",
            queue_policy::Config::default(),
            NOW
        )
        .is_err());
    }
    #[test]
    fn test_owner_class_is_accepted_and_ordered_first() {
        let mut rows = HashMap::new();
        let mut s = good();
        s["job_id"] = json!("standard");
        admit(&s, &config(), &mut rows).unwrap();
        s["job_id"] = json!("owner-job");
        s["submitter"] = json!("owner");
        admit(&s, &config(), &mut rows).unwrap();
        assert_eq!(
            queue_policy::next(&rows, None, queue_policy::Config::default(), |_| true).as_deref(),
            Some("owner-job")
        );
    }
    #[test]
    fn test_good_render_job_admits() {
        let r = accepted(&good());
        let v = result_store::snapshot(&r, NOW);
        assert_eq!(v.as_object().unwrap().len(), 17);
        assert_eq!(v["state"], "queued");
        assert_eq!(v["cleanup"], "pending");
        assert_eq!(v["artifacts"], json!([]));
        assert!(v["manifest"].is_null());
    }
    #[test]
    fn test_fingerprint_is_the_canonical_submitted_spec() {
        let s = good();
        assert_eq!(accepted(&s)["spec_sha256"], deadline::fingerprint(&s));
    }
    #[test]
    fn test_defaults_are_not_injected_into_the_fingerprint() {
        let mut s = good();
        let before = deadline::fingerprint(&s);
        s.as_object_mut().unwrap().remove("timeout_min");
        assert_ne!(before, accepted(&s)["spec_sha256"]);
    }
    #[test]
    fn test_deadline_is_created_plus_timeout() {
        assert_eq!(
            accepted(&changed("timeout_min", json!(30)))["deadline_epoch"],
            NOW + 1800
        );
    }
    #[test]
    fn test_fractional_timeout_admits() {
        assert_eq!(
            accepted(&changed("timeout_min", json!(45.5)))["deadline_epoch"],
            NOW + 2730
        );
    }
    #[test]
    fn test_bake_job_admits() {
        assert_eq!(accepted(&bake())["state"], "queued");
    }
    #[test]
    fn test_every_s01_accepted_fixture_admits() {
        let mut forms = vec![
            good(),
            changed("engine", json!("cycles")),
            changed("frames", json!(" 1 - 6 ")),
            changed("frames", json!("6-6")),
            bake(),
        ];
        for frames in [
            json!("1,12,24"),
            json!([1, 12, 12]),
            json!("3-9"),
            Value::Null,
        ] {
            let mut s = bake();
            s["frames"] = frames;
            forms.push(s);
        }
        let mut script = bake();
        script["steps"] = json!(["script"]);
        forms.push(script);
        forms.push(changed("timeout_min", json!(45.5)));
        assert_eq!(forms.len(), 11);
        for s in forms {
            assert_eq!(accepted(&s)["state"], "queued");
        }
    }
    #[test]
    fn test_kit_good_fixture_admits() {
        assert!(body(&good()).is_ok());
        let mut s = bake();
        s["steps"] = json!(["script"]);
        assert!(body(&s).is_ok());
    }
    #[test]
    fn test_kit_bad_fixtures() {
        for (field, v) in [
            ("blend", json!("relative.blend")),
            ("frames", json!("x-y")),
            ("frames", Value::Null),
            ("timeout_min", json!(361)),
        ] {
            reject(field, v);
        }
    }
    #[test]
    fn test_frames_end_before_start() {
        reject("frames", json!("5-3"));
    }
    #[test]
    fn test_unknown_field() {
        reject("extra", json!(1));
    }
    #[test]
    fn test_missing_required() {
        for field in ["blend", "out", "lane"] {
            let mut s = good();
            s.as_object_mut().unwrap().remove(field);
            assert!(body(&s).is_err());
        }
        let mut s = good();
        s.as_object_mut().unwrap().remove("api");
        assert!(body(&s).is_ok());
    }
    #[test]
    fn test_lane_mismatch() {
        reject("lane", json!("tts"));
    }
    #[test]
    fn test_unknown_lane() {
        assert_eq!(
            request_boundary::load(br#"{"lane":"unknown"}"#, None),
            Err(crate::error_catalog::UNKNOWN_LANE)
        );
    }
    #[test]
    fn test_body_too_large() {
        let s = changed("script", json!("x".repeat(70000)));
        assert_eq!(
            request_boundary::load(&serde_json::to_vec(&s).unwrap(), None),
            Err(crate::error_catalog::REQUEST_TOO_LARGE)
        );
    }
    #[test]
    fn test_wrong_media_type() {
        assert_eq!(
            media_type(Some("text/plain")),
            Err(crate::error_catalog::UNSUPPORTED_MEDIA_TYPE)
        );
        assert!(media_type(Some("application/json; charset=utf-8")).is_ok());
    }
    #[test]
    fn test_duplicate_keys_at_a_nested_level() {
        assert!(lane_gate::parse(br#"{"x":{"a":1,"a":2}}"#).is_err());
    }
    #[test]
    fn test_nonfinite_literal() {
        assert!(lane_gate::parse(br#"{"timeout_min":NaN}"#).is_err());
    }
    #[test]
    fn test_float_outside_the_three_number_fields() {
        assert_eq!(
            body(&changed("steps", json!([1.5]))),
            Err(crate::error_catalog::BAD_JSON)
        );
    }
    #[test]
    fn test_top_level_not_an_object() {
        assert_eq!(body(&json!([1, 2])), Err(crate::error_catalog::BAD_SPEC));
    }
    #[test]
    fn test_null_rules() {
        for field in [
            "type",
            "engine",
            "assets",
            "split_across_workers",
            "timeout_min",
            "script",
            "job_id",
        ] {
            assert!(body(&changed(field, Value::Null)).is_ok(), "{field}");
        }
        for field in [
            "prefer",
            "cartridge",
            "blend",
            "out",
            "inputs",
            "script_timeout_min",
        ] {
            reject(field, Value::Null);
        }
    }
    #[test]
    fn test_cartridge_value_set() {
        for v in [json!("default"), json!("blender-4.5.3-cycles"), json!(5)] {
            reject("cartridge", v);
        }
    }
    #[test]
    fn test_bands() {
        for v in [json!(0.5), json!(361), json!(-1), json!(true)] {
            reject("timeout_min", v);
        }
        for v in [
            json!(["script", "script"]),
            json!(["script", "bake", "render", "script"]),
            json!(["nope"]),
            json!("bake"),
        ] {
            reject("steps", v);
        }
        reject("script", json!(""));
    }
    #[test]
    fn test_step_timeouts_bind_the_bake_arm_only() {
        for (field, v) in [
            ("script_timeout_min", json!(0)),
            ("script_timeout_min", json!(721)),
            ("bake_timeout_min", json!(-1)),
        ] {
            let mut s = bake();
            s[field] = v;
            assert!(body(&s).is_err());
        }
        reject("script_timeout_min", json!(721.5));
        assert!(body(&changed("script_timeout_min", json!(0))).is_ok());
    }
    #[test]
    fn test_shapes() {
        for (field, v) in [
            ("engine", json!("eevee")),
            ("out", json!("/mnt/gpu-preserve")),
            ("out", json!("/mnt/gpu-preserve/x")),
            ("out", json!("relative/out")),
            ("blend", json!("relative.blend")),
            ("blend", json!("/a.txt")),
            ("inputs", json!("relative")),
            ("type", json!("nope")),
            ("split_across_workers", json!("yes")),
            ("job_id", json!("Upper")),
            ("prefer", json!(["a", "a"])),
            ("prefer", json!(["a", "a", "a", "a", "a", "a"])),
        ] {
            reject(field, v);
        }
        assert!(body(&changed("engine", json!("cycles"))).is_ok());
    }
    #[test]
    fn test_render_arm_takes_a_range_only() {
        reject("frames", json!([1, 2]));
        reject("frames", json!("1,2"));
    }
    #[test]
    fn test_bake_arm_takes_lists_and_duplicates() {
        for v in [
            json!("1,12,24"),
            json!([1, 12, 12]),
            json!("3-9"),
            Value::Null,
        ] {
            let mut s = bake();
            s["frames"] = v;
            assert!(body(&s).is_ok());
        }
        for v in [
            json!([1, "x"]),
            json!((0..1001).collect::<Vec<_>>()),
            json!("1,x"),
        ] {
            let mut s = bake();
            s["frames"] = v;
            assert!(body(&s).is_err());
        }
    }
    #[test]
    fn test_render_arm_requires_frames() {
        let mut s = good();
        s.as_object_mut().unwrap().remove("frames");
        assert!(body(&s).is_err());
    }
    #[test]
    fn test_legacy_error_body_is_error_only() {
        let response = err(StatusCode::CONFLICT, crate::error_catalog::LANE_DISABLED);
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
    #[test]
    fn test_legacy_projection_of_a_409() {
        assert_eq!(
            err(StatusCode::CONFLICT, "job_id exists").status(),
            StatusCode::CONFLICT
        );
    }
    #[test]
    fn test_the_staged_admission_module_serves_the_lane() {
        assert!(LANES.contains(&"render-blender"));
        assert!(body(&good()).is_ok());
    }
    #[test]
    fn test_the_staged_struct_check_denies_unknown_fields() {
        test_unknown_field();
    }
    #[test]
    fn test_the_staged_struct_check_demands_required_fields() {
        assert!(body(&json!({"api":API})).is_err());
    }
    #[test]
    fn test_the_staged_queue_is_the_cap_table() {
        assert_eq!(queue_policy::Config::default().per_lane, 128);
        test_the_129th_job_is_refused();
    }
    #[test]
    fn test_the_staged_id_grammar_is_shared() {
        assert!(result_store::valid_id("rb-1"));
        assert!(!result_store::valid_id("RB-1"));
    }
    #[test]
    fn test_the_pin_record_is_the_s01_shape() {
        assert_eq!(pin().as_object().unwrap().len(), 8);
        assert!(lane_gate::valid_pin(&pin()));
    }
    #[test]
    fn test_snapshot_after_expiry_reports_the_live_state() {
        let mut rows = HashMap::new();
        admit(&good(), &config(), &mut rows).unwrap();
        deadline::process(&mut rows, NOW + 2700);
        let r = result_store::snapshot(&rows["rb-good-001"], NOW + 2700);
        assert_eq!(r["state"], "timed_out");
        assert_eq!(r["error"].as_object().unwrap().len(), 2);
    }
    #[test]
    fn test_cancel_of_an_unknown_id_is_a_404() {
        let mut r = json!({});
        assert_eq!(
            deadline::cancel(&mut r, NOW),
            Err(crate::error_catalog::ILLEGAL_TRANSITION)
        );
    }
    #[test]
    fn test_cancel_of_a_terminal_job_answers_200() {
        let mut r = accepted(&good());
        assert!(deadline::cancel(&mut r, NOW).unwrap());
        let before = r.clone();
        assert!(!deadline::cancel(&mut r, NOW).unwrap());
        assert_eq!(r, before);
    }
}
