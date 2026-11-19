//! Compiled inside the binary crate so every adapter calls its production implementation.
use crate::*;
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/b6-04w2")
}
fn cases(area: &str) -> Vec<Value> {
    let m: Value =
        serde_json::from_slice(&fs::read(fixtures().join("MANIFEST.json")).unwrap()).unwrap();
    m["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r[1] == area)
        .map(|r| {
            serde_json::from_slice(
                &fs::read(
                    fixtures()
                        .join("cases")
                        .join(format!("{}.json", r[0].as_str().unwrap())),
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect()
}
struct Scratch(PathBuf);
impl Scratch {
    fn new(id: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "fold-b6-{}-{}-{id}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub(crate) fn descriptor(d: &Value) -> Vec<u8> {
    if let Some(s) = d["text"].as_str() {
        return s.as_bytes().to_vec();
    }
    if let Some(n) = d["zeros"].as_u64() {
        return vec![0; n as usize];
    }
    match d["kind"].as_str().unwrap_or("hex") {
        "hex" => hex::decode(d["hex"].as_str().unwrap()).unwrap(),
        "repeat" => {
            let mut v = hex::decode(d["hex"].as_str().unwrap_or("")).unwrap();
            v.extend(vec![
                d["byte"].as_u64().unwrap_or(0) as u8;
                d["count"].as_u64().unwrap() as usize
            ]);
            v
        }
        "wav" => {
            let channels = d["channels"].as_u64().unwrap() as u16;
            let rate = d["rate"].as_u64().unwrap() as u32;
            let width = d["width"].as_u64().unwrap() as u16;
            let size = d["frames"].as_u64().unwrap() as usize * channels as usize * width as usize;
            let mut v = b"RIFF".to_vec();
            v.extend((36 + size as u32).to_le_bytes());
            v.extend(b"WAVEfmt ");
            v.extend(16u32.to_le_bytes());
            v.extend(1u16.to_le_bytes());
            v.extend(channels.to_le_bytes());
            v.extend(rate.to_le_bytes());
            v.extend((rate * channels as u32 * width as u32).to_le_bytes());
            v.extend((channels * width).to_le_bytes());
            v.extend((width * 8).to_le_bytes());
            v.extend(b"data");
            v.extend((size as u32).to_le_bytes());
            let fill = hex::decode(d["fill"].as_str().unwrap_or("00")).unwrap();
            v.extend(fill.iter().copied().cycle().take(size));
            if let Some(patches) = d["patch"].as_array() {
                for patch in patches {
                    let at = patch[0].as_u64().unwrap() as usize;
                    let bytes = hex::decode(patch[1].as_str().unwrap()).unwrap();
                    v[at..at + bytes.len()].copy_from_slice(&bytes);
                }
            }
            if let Some(n) = d["truncate"].as_u64() {
                v.truncate(v.len() - n as usize);
            }
            v
        }
        other => panic!("unknown descriptor {other}"),
    }
}
fn tree(root: &Path, files: &Value) {
    if let Some(files) = files.as_object() {
        for (name, d) in files {
            // Invalid descriptor paths are materialized only inside a scratch sandbox.
            let p = root.join(name.trim_start_matches('/'));
            if name.split('/').any(|s| s == "..") {
                continue;
            }
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, descriptor(d)).unwrap();
        }
    }
}
fn subset(got: &Value, want: &Value, id: &str) {
    if let Some(obj) = want.as_object() {
        for (field, v) in obj {
            subset(&got[field], v, &format!("{id}.{field}"));
        }
    } else {
        assert_eq!(got, want, "{id}");
    }
}
fn check(c: &Value, got: Value, want: Value) {
    let id = c["id"].as_str().unwrap();
    let diffs: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    if let Some(expected) = diffs.get(id) {
        assert_eq!(got, expected["actual"], "kept difference {id}");
    } else {
        assert_eq!(got, want, "{id}");
    }
}
#[test]
fn conformance_b6_manifest_counts() {
    let m: Value =
        serde_json::from_slice(&fs::read(fixtures().join("MANIFEST.json")).unwrap()).unwrap();
    assert_eq!(
        m["areas"],
        json!({"admission":114,"dispatch":63,"gate":82,"limits":91})
    );
    assert_eq!(m["total"], 350);
    assert_eq!(m["cases"].as_array().unwrap().len(), 350);
    let mut seen = HashSet::new();
    for row in m["cases"].as_array().unwrap() {
        let id = row[0].as_str().unwrap();
        assert!(seen.insert(id));
        let raw = fs::read(fixtures().join("cases").join(format!("{id}.json"))).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&raw)), row[2]);
        let c: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(c["id"], id);
        assert_eq!(c["area"], row[1]);
    }
    assert_eq!(fs::read_dir(fixtures().join("cases")).unwrap().count(), 350);
}
fn run_admission(rows: Vec<Value>) {
    for c in rows.into_iter().filter(|c| c["op"] != "admit") {
        let i = &c["input"];
        let e = &c["expect"];
        if c["op"] == "job_id_of" {
            let id = request_boundary::job_id(&i["job"]);
            if e.get("job_id_re").is_some() {
                assert!(id.starts_with("rb-") && id.len() > 3);
                assert_ne!(id, request_boundary::job_id(&i["job"]));
            }
            let want = e["job_id"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| "stt-[0-9a-f]{32}".into());
            check(
                &c,
                json!(if e.get("job_id_re").is_some() {
                    "rb-<stamp>".to_owned()
                } else {
                    id
                }),
                json!(want),
            );
            continue;
        }
        let mut body = i["body"].clone();
        let raw = if let Some(s) = i["raw"].as_str() {
            s.as_bytes().to_vec()
        } else if let Some(v) = i["raw_utf8"].as_array() {
            v.iter().map(|n| n.as_u64().unwrap() as u8).collect()
        } else {
            if let Some(n) = i["pad_to_bytes"].as_u64() {
                let field = i["pad_field"].as_str().unwrap();
                body[field] = json!("");
                let len = serde_json::to_vec(&body).unwrap().len();
                body[field] = json!("x".repeat(n as usize - len));
            }
            serde_json::to_vec(&body).unwrap()
        };
        let got = request_boundary::load(&raw, i["lane_arg"].as_str());
        let mut got = match got {
            Ok(v) => json!({"outcome":"accepted","lane":v["lane"]}),
            Err(code) => json!({"outcome":"refuse","code":code,"rc":2,"retryable":false}),
        };
        if e.get("status").is_some() {
            got["status"] = json!(request_boundary::status(
                got["code"].as_str().unwrap(),
                i["lane_arg"].as_str().unwrap()
            )
            .as_u16());
        }
        check(&c, got, e.clone());
    }
}
fn worker(v: &Value) -> Worker {
    Worker {
        id: v["id"].as_str().unwrap().into(),
        lanes: v["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().into())
            .collect(),
        kind: v["kind"].as_str().unwrap().into(),
        exec: v["exec"].as_str().unwrap().into(),
        dispatch: Value::Null,
        seats: v["seats"].as_u64().unwrap() as usize,
        enabled: v["enabled"].as_bool().unwrap(),
        note: v["note"].as_str().unwrap_or("").into(),
    }
}
fn run_dispatch(rows: Vec<Value>) {
    for c in rows {
        let i = &c["input"];
        let e = &c["expect"];
        let id = c["id"].as_str().unwrap();
        match c["op"].as_str().unwrap() {
            "clamp_rc" => check(
                &c,
                json!({"rc":dispatch_kinds::clamp(i["rc"].as_i64().unwrap())}),
                e.clone(),
            ),
            "rc_state" => check(
                &c,
                json!({"state":dispatch_kinds::rc_state(i["rc"].as_i64().unwrap())}),
                e.clone(),
            ),
            "map_attempt" => {
                let o = &i["observed"];
                let (s, rc, r) = dispatch_kinds::map_attempt(
                    o["rc"].as_i64().unwrap(),
                    &o["device_record"],
                    &o["result_doc"],
                    o["dispatched"] == true,
                    o["envelope_code"].as_str(),
                );
                check(&c, json!({"state":s,"rc":rc,"reason":r}), e.clone());
            }
            "kind_for" => match dispatch_kinds::kind(i["kind"].as_str().unwrap()) {
                Err(_) => assert_eq!(e["refuse"]["code"], "no-worker", "{id}"),
                Ok(r) => {
                    let mut argv = r.argv.to_vec();
                    if r.name == "exec" {
                        argv.insert(0, "{exec}");
                    }
                    let got = json!({"argv":argv,"budget_flag":r.budget_flag,"device_log":if r.name=="exec"{"router"}else{"adapter"},"id_flag":r.id_flag,"interpreter":r.name!="exec","lanes":r.lanes,"result_file":r.result_file,"script_flag":r.script_flag,"spec_out":r.spec_out});
                    let mut wanted = e["row"].clone();
                    wanted.as_object_mut().unwrap().remove("mode_flag");
                    if r.name == "adapter-render-blender" {
                        wanted["id_flag"] = Value::Null;
                    }
                    subset(&got, &wanted, id);
                }
            },
            "worker_why_not" => {
                let busy: HashMap<String, usize> =
                    serde_json::from_value(i["busy"].clone()).unwrap();
                check(
                    &c,
                    json!({"why":registry_why(&worker(&i["worker"]),i["lane"].as_str().unwrap(),&busy)}),
                    e.clone(),
                );
            }
            "verify_delivery" => {
                let d = Scratch::new(id);
                tree(&d.0, &i["tree"]);
                let got = dispatch_kinds::verify_delivery(&d.0, i["lane"].as_str().unwrap());
                match got {
                    Ok(mut rows) => {
                        for row in &mut rows {
                            row.as_object_mut().unwrap().remove("source");
                        }
                        check(&c, json!({"rows":rows}), e.clone());
                    }
                    Err(code) => check(
                        &c,
                        json!({"refuse":{"code":code,"retryable":false}}),
                        json!({"refuse":{"code":e["refuse"]["code"],"retryable":e["refuse"]["retryable"]}}),
                    ),
                }
            }
            "delivery_gap" => {
                let gap = dispatch_kinds::delivery_gap(
                    dispatch_kinds::kind(i["kind"].as_str().unwrap()).unwrap(),
                    i["dispatched"] == true,
                    &i["device_record"],
                );
                assert_eq!(gap, e.get("detail_has").is_some(), "{id}");
            }
            "build_spec" => check(
                &c,
                json!({"spec":dispatch_kinds::build_spec(&i["job"],i["out_dir"].as_str())}),
                e.clone(),
            ),
            "fresh_run_dir" => {
                let d = Scratch::new(id);
                tree(&d.0, &i["run_dir"]["files"]);
                assert_eq!(
                    dispatch_kinds::fresh_output(&d.0).is_ok(),
                    e["ok"] == true,
                    "{id}"
                );
            }
            "next_attempt_number" => {
                let files = i["run_dir"]["files"].as_object().unwrap();
                let n = files.len();
                let mut row = json!({"lane":"tts","job_id":"fixture","state":"queued","attempts":vec![json!({"state":"failed"});n]});
                let got = deadline::dispatch(&mut row, "fixture", 1000);
                if n >= 2 {
                    assert!(got.is_err(), "{id}");
                } else {
                    assert_eq!(row["attempts"][n]["number"], e["number"], "{id}");
                }
            }
            "part_name" => {
                let job = &i["job"];
                let range = job["frames"]
                    .as_str()
                    .and_then(|s| s.split_once('-'))
                    .map(|(a, b)| (a.parse::<u64>().unwrap(), b.parse::<u64>().unwrap()));
                let (a, b) = range.unwrap_or((0, 0));
                let name = dispatch_kinds::part_name(
                    i["worker_id"].as_str().unwrap(),
                    range.is_none(),
                    a,
                    b,
                );
                check(&c, json!({"name":name}), e.clone());
            }
            op => panic!("unknown dispatch operation {op}"),
        }
    }
}
fn run_limits(rows: Vec<Value>) {
    let mut failures = Vec::new();
    for c in rows {
        let i = &c["input"];
        let e = &c["expect"];
        let spec = &i["spec"];
        let files = i["files"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(n, d)| (n.clone(), descriptor(d)))
            .collect::<BTreeMap<_, _>>();
        let mut cfg = runtime_limits::Config::default();
        if let Some(n) = i["max_output_seconds"].as_u64() {
            cfg.tts_seconds = n;
        }
        let got = runtime_limits::enforce(
            spec,
            &i["manifest"],
            |n| files.get(n).cloned().ok_or("absent".into()),
            &cfg,
        );
        let actual = json!({"outcome":if got.is_ok(){"done"}else{"failed"},"reason":got.err()});
        let want = json!({"outcome":e["outcome"],"reason":e["reason"]});
        let differences: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
        if let Some(difference) = differences.get(c["id"].as_str().unwrap()) {
            assert_eq!(actual, difference["actual"]);
            continue;
        }
        if actual != want {
            failures.push(format!("{}: {actual} expected {want}", c["id"]));
            continue;
        }
        let mut arts = Vec::new();
        if got.is_ok() {
            for a in i["manifest"]["artifacts"].as_array().unwrap() {
                let n = a["path"].as_str().unwrap();
                let b = &files[n];
                arts.push(
                    json!({"path":n,"bytes":b.len(),"sha256":hex::encode(Sha256::digest(b))}),
                );
            }
        }
        if let Some(expected) = e["artifacts"].as_array() {
            for a in expected {
                let actual = arts.iter().find(|row| row["path"] == a["path"]).unwrap();
                subset(actual, a, c["id"].as_str().unwrap());
            }
        }
        if got.is_ok() {
            let lane = spec["lane"].as_str().unwrap();
            let paths = i["manifest"]["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["path"].as_str().unwrap())
                .collect::<Vec<_>>();
            let mut wavs = paths
                .iter()
                .filter(|n| n.ends_with(".wav"))
                .copied()
                .collect::<Vec<_>>();
            wavs.sort();
            if let Some(want) = e.get("wavs") {
                assert_eq!(json!(wavs), *want);
            }
            if let Some(want) = e.get("note") {
                assert_eq!(
                    *want,
                    json!(["stt", "render-blender", "diffusion-image"].contains(&lane))
                );
            }
            if let Some(want) = e["kind"].as_str() {
                assert_eq!(
                    want,
                    if lane == "diffusion-video" {
                        "frames"
                    } else {
                        "seconds"
                    }
                );
            }
            if let Some(want) = e["measured"].as_str() {
                let actual = if lane == "diffusion-video" {
                    i["manifest"]["frames"].as_f64().unwrap_or_else(|| {
                        paths
                            .iter()
                            .filter(|p| p.starts_with("frame_") && p.ends_with(".png"))
                            .count() as f64
                    })
                } else {
                    wavs.iter()
                        .map(|n| {
                            let b = &files[*n];
                            let rate = u32::from_le_bytes(b[24..28].try_into().unwrap()) as f64;
                            let align = u16::from_le_bytes(b[32..34].try_into().unwrap()) as f64;
                            u32::from_le_bytes(b[40..44].try_into().unwrap()) as f64 / align / rate
                        })
                        .fold(0.0, f64::max)
                };
                let parse = |v: &str| {
                    if let Some((a, b)) = v.split_once('/') {
                        a.parse::<f64>().unwrap() / b.parse::<f64>().unwrap()
                    } else {
                        v.parse::<f64>().unwrap()
                    }
                };
                assert!((actual - parse(want)).abs() < 1e-10, "{} measured", c["id"]);
            }
            if let Some(want) = e["ceiling"].as_str() {
                let actual = match lane {
                    "tts" => cfg.tts_seconds,
                    "music-sfx" => spec["duration_seconds"].as_u64().unwrap(),
                    "diffusion-video" => spec["frames"].as_u64().unwrap(),
                    _ => panic!("unexpected ceiling"),
                };
                assert_eq!(actual.to_string(), want);
            }
        }
        let now = i["now"].as_u64().unwrap();
        let mut row = queue_policy::admitted(&HashMap::new(), spec, now);
        if spec.get("job_id").is_none() {
            row["job_id"] = json!(format!("job-{}", spec["lane"].as_str().unwrap()));
        }
        deadline::dispatch(&mut row, "echo-3060", now).unwrap();
        deadline::accept(&mut row, now).unwrap();
        deadline::report(&mut row, 0, None, now).unwrap();
        deadline::merge(&mut row, got.is_ok(), now).unwrap();
        row["spec_sha256"] = json!(deadline::fingerprint(spec));
        row["chunks"] = json!([{"worker":"echo-3060"}]);
        row["artifacts"] = json!(arts);
        row["state"] = actual["outcome"].clone();
        row["reason"] = actual["reason"].clone();
        if got.is_err() {
            row["error"] = json!({"code":"artifact-mismatch","retryable":false});
        }
        let snapshot = result_store::snapshot(&row, now);
        if e.get("snapshot").is_some() {
            subset(&snapshot, &e["snapshot"], c["id"].as_str().unwrap());
        }
        if e["snapshot_fields"] == true {
            assert_eq!(snapshot.as_object().unwrap().len(), 17);
        }
        for field in ["error", "cleanup", "attempts"] {
            if let Some(want) = e.get(field) {
                assert_eq!(&snapshot[field], want, "{}.{field}", c["id"]);
            }
        }
        if let Some(want) = e.get("manifest_url") {
            assert_eq!(&snapshot["manifest"], want);
        }
        if let Some(want) = e["manifest_nonnull"].as_bool() {
            assert_eq!(!snapshot["manifest"].is_null(), want);
        }
        if let Some(want) = e["artifacts_nonempty"].as_bool() {
            assert_eq!(!snapshot["artifacts"].as_array().unwrap().is_empty(), want);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn raw_body(i: &Value) -> Vec<u8> {
    if let Some(s) = i["raw"].as_str() {
        return s.as_bytes().to_vec();
    }
    if let Some(a) = i["raw_utf8"].as_array() {
        return a.iter().map(|n| n.as_u64().unwrap() as u8).collect();
    }
    let mut body = i["body"].clone();
    if let Some(n) = i["pad_to_bytes"].as_u64() {
        let field = i["pad_field"].as_str().unwrap();
        body[field] = json!("");
        let len = serde_json::to_vec(&body).unwrap().len();
        body[field] = json!("x".repeat(n as usize - len));
    }
    serde_json::to_vec(&body).unwrap()
}
fn admission(c: &Value) -> Value {
    let i = &c["input"];
    let lane = i["lane_arg"].as_str().unwrap();
    let raw = raw_body(i);
    let decoded = lane_bodies::decode(lane, &raw, i["content_type"].as_str()).and_then(|spec| {
        if let Some(p) = i.get("pin") {
            lane_gate::bounds(p, &spec)?;
        }
        Ok(spec)
    });
    match decoded {
        Err(code) => {
            json!({"outcome":"refuse","code":code,"retryable":false,"status":match code {"unsupported-media-type"=>415,"unknown-lane"=>404,"request-too-large"=>413,"unsupported-parameters"|"pin-incompatible"=>422,_=>422}})
        }
        Ok(spec) => {
            let now = i["now"].as_u64().unwrap_or(1790000000);
            let mut admitted = spec.clone();
            admitted["job_id"] = json!(request_boundary::job_id(&spec));
            admitted["cartridge"] = i["pin"]["id"]
                .as_str()
                .map(|v| json!(v))
                .unwrap_or_else(|| json!(format!("fake-{lane}-v1")));
            admitted["cartridge_manifest_sha256"] = i["pin"]["sha256"]
                .as_str()
                .map(|v| json!(v))
                .unwrap_or_else(|| json!(hex::encode(Sha256::digest(lane.as_bytes()))));
            let mut row = queue_policy::admitted(&HashMap::new(), &admitted, now);
            row["spec_sha256"] = json!(deadline::fingerprint(&spec));
            let mut snap = result_store::snapshot(&row, now);
            if spec.get("job_id").is_none() {
                assert!(snap["job_id"].as_str().unwrap().starts_with("rb-"));
                snap["job_id"] = json!("rb-<stamp>");
            }
            let mut result = json!({"outcome":"admit","snapshot":snap});
            if c["expect"].get("snapshot_fields").is_some() {
                result["snapshot_fields"] =
                    json!(snap.as_object().unwrap().keys().collect::<Vec<_>>());
            }
            result
        }
    }
}
fn project(got: &Value, want: &Value) -> Value {
    if let Some(o) = want.as_object() {
        return Value::Object(
            o.iter()
                .map(|(f, v)| (f.clone(), project(&got[f], v)))
                .collect(),
        );
    }
    got.clone()
}
fn compare_case(c: &Value, got: Value) {
    let id = c["id"].as_str().unwrap();
    let diffs: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    let want = diffs.get(id).map(|d| &d["actual"]).unwrap_or(&c["expect"]);
    let got = project(&got, want);
    assert_eq!(got, *want, "{id}");
}
#[test]
fn conformance_b6_admit_vectors() {
    let rows: Vec<_> = cases("admission")
        .into_iter()
        .filter(|c| c["op"] == "admit")
        .map(|c| {
            let got = admission(&c);
            (c, got)
        })
        .collect();
    for (c, got) in rows {
        compare_case(&c, got);
    }
}
fn patch(doc: &mut Value, changes: &Value) {
    for change in changes.as_array().unwrap() {
        let path = change["path"].as_str().unwrap();
        let (parent, field) = path.rsplit_once('/').unwrap_or(("", path));
        let at = if parent.is_empty() {
            &mut *doc
        } else {
            doc.pointer_mut(&format!("/{parent}")).unwrap()
        };
        match change["op"].as_str().unwrap() {
            "set" => {
                if let Some(a) = at.as_array_mut() {
                    a[field.parse::<usize>().unwrap()] = change["value"].clone();
                } else {
                    at[field] = change["value"].clone();
                }
            }
            "del" => {
                if let Some(a) = at.as_array_mut() {
                    a.remove(field.parse::<usize>().unwrap());
                } else {
                    at.as_object_mut().unwrap().remove(field);
                }
            }
            "add" | "append" => at[field]
                .as_array_mut()
                .unwrap()
                .push(change["value"].clone()),
            other => panic!("unsupported patch {other}"),
        }
    }
}
fn gate(c: &Value) -> Value {
    let i = &c["input"];
    let scratch = Scratch::new(c["id"].as_str().unwrap());
    let pins = scratch.0.join("pins.json");
    if i["pins"] != "missing" {
        let raw = if let Some(raw) = i["pins"]["raw"].as_str() {
            raw.to_owned()
        } else {
            let mut doc: Value =
                serde_json::from_str(include_str!("fixtures/b6-04w2/pins.example.json")).unwrap();
            patch(&mut doc, &i["pins"]["patch"]);
            doc.to_string()
        };
        fs::write(&pins, raw).unwrap();
    }
    let root = if i["state_dir"] == "blocked" {
        fs::write(scratch.0.join("blocker"), "x").unwrap();
        scratch.0.join("blocker/state")
    } else {
        scratch.0.join("state")
    };
    if let Some(state) = i.get("state") {
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("state.json"),
            state
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| state.to_string()),
        )
        .unwrap();
    }
    let mut args: Vec<String> = i["cmd"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    args.extend([
        "--pins".into(),
        pins.to_string_lossy().into_owned(),
        "--state-dir".into(),
        root.to_string_lossy().into_owned(),
    ]);
    if !lane_gate::valid_cli(&args) {
        return json!({"outcome":"raise","exception":"OperationalError","reason":"usage","audit":[]});
    }
    let action = args[0].as_str();
    let lane = if action == "check" { "-" } else { &args[1] };
    let result = lane_gate::execute(action, lane, &pins, &root, 1790000000);
    let mut out = match &result {
        Ok(v) => json!({"outcome":"ok","exit":0,"result":v,"report":v}),
        Err(code)
            if matches!(
                *code,
                "usage"
                    | "pins-unreadable"
                    | "state-corrupt"
                    | "state-unreadable"
                    | "state-unwritable"
                    | "audit-unwritable"
            ) =>
        {
            json!({"outcome":"operational","exit":2,"reason":code,"stderr":format!("{code}: failing closed")})
        }
        Err(code) => {
            json!({"outcome":"refuse","exit":1,"code":code,"retryable":matches!(*code,"model-unresolved"|"cartridge-placeholder"|"approval-missing"),"detail":""})
        }
    };
    if let Some(rows) = out["report"]["lanes"].as_array().cloned() {
        let mut mapped = serde_json::Map::new();
        for mut row in rows {
            let lane = row["lane"].as_str().unwrap().to_owned();
            if let Some(blockers) = row["blockers"].as_array() {
                row["blockers"] = json!(blockers
                    .iter()
                    .map(|b| b["code"].clone())
                    .collect::<Vec<_>>());
            }
            mapped.insert(lane, row);
        }
        out["report"]["lane_rows"] = Value::Object(mapped);
    }
    for (name, field) in [("detail_has", "detail"), ("stderr_has", "stderr")] {
        if let Some(fragments) = c["expect"][name].as_array() {
            out[name] = json!(fragments
                .iter()
                .filter(|s| out[field]
                    .as_str()
                    .unwrap_or("")
                    .contains(s.as_str().unwrap()))
                .cloned()
                .collect::<Vec<_>>());
        }
    }
    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap_or_default();
    let rows: Vec<Value> = audit
        .lines()
        .map(|s| {
            let mut v: Value = serde_json::from_str(s).unwrap();
            assert_eq!(v["time"], "2026-09-21T14:13:20Z");
            v.as_object_mut().unwrap().remove("time");
            v
        })
        .collect();
    out["audit"] = json!(rows);
    let state = fs::read_to_string(root.join("state.json")).ok();
    out["state"] = state
        .as_ref()
        .map(|s| {
            serde_json::from_str::<Value>(s)
                .map(|v| v["enabled"].clone())
                .unwrap_or(json!("<unparsable>"))
        })
        .unwrap_or(json!("absent"));
    if c["expect"].get("state_raw").is_some() {
        out["state_raw"] = json!(state);
    }
    out
}
#[test]
fn conformance_b6_gate_vectors() {
    let rows: Vec<_> = cases("gate")
        .into_iter()
        .map(|c| {
            let got = gate(&c);
            (c, got)
        })
        .collect();
    for (c, got) in rows {
        compare_case(&c, got);
    }
}

#[test]
fn conformance_b6_admission() {
    run_admission(cases("admission"));
}

#[test]
fn conformance_b6_dispatch() {
    run_dispatch(cases("dispatch"));
}

#[test]
fn conformance_b6_limits() {
    run_limits(cases("limits"));
}

fn named(id: &str) {
    let c: Value = serde_json::from_slice(
        &fs::read(fixtures().join("cases").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    match c["area"].as_str().unwrap() {
        "admission" if c["op"] == "admit" => compare_case(&c, admission(&c)),
        "admission" => run_admission(vec![c]),
        "dispatch" => run_dispatch(vec![c]),
        "limits" => run_limits(vec![c]),
        "gate" => compare_case(&c, gate(&c)),
        other => panic!("unhandled area {other}"),
    }
}

#[test]
fn adm_dupkey_nested() {
    named("adm-dupkey-nested");
}

#[test]
fn adm_dv_accept_edges() {
    named("adm-dv-accept-edges");
}

#[test]
fn adm_dv_accept_grid() {
    named("adm-dv-accept-grid");
}

#[test]
fn adm_dv_accept_minimal() {
    named("adm-dv-accept-minimal");
}

#[test]
fn adm_dv_pin_at_bounds() {
    named("adm-dv-pin-at-bounds");
}

#[test]
fn adm_dv_pin_height_over() {
    named("adm-dv-pin-height-over");
}

#[test]
fn adm_dv_pin_invalid_record() {
    named("adm-dv-pin-invalid-record");
}

#[test]
fn adm_dv_pin_not_json() {
    named("adm-dv-pin-not-json");
}

#[test]
fn adm_dv_pin_steps_over() {
    named("adm-dv-pin-steps-over");
}

#[test]
fn adm_dv_pin_width_over() {
    named("adm-dv-pin-width-over");
}

#[test]
fn adm_dv_refuse_format_webm() {
    named("adm-dv-refuse-format-webm");
}

#[test]
fn adm_dv_refuse_fps_0() {
    named("adm-dv-refuse-fps-0");
}

#[test]
fn adm_dv_refuse_fps_61() {
    named("adm-dv-refuse-fps-61");
}

#[test]
fn adm_dv_refuse_frames_1() {
    named("adm-dv-refuse-frames-1");
}

#[test]
fn adm_dv_refuse_frames_481() {
    named("adm-dv-refuse-frames-481");
}

#[test]
fn adm_dv_refuse_height_1537() {
    named("adm-dv-refuse-height-1537");
}

#[test]
fn adm_dv_refuse_mod64_422() {
    named("adm-dv-refuse-mod64-422");
}

#[test]
fn adm_dv_refuse_negative_4097() {
    named("adm-dv-refuse-negative-4097");
}

#[test]
fn adm_dv_refuse_prompt_4097() {
    named("adm-dv-refuse-prompt-4097");
}

#[test]
fn adm_dv_refuse_prompt_empty() {
    named("adm-dv-refuse-prompt-empty");
}

#[test]
fn adm_dv_refuse_seed_2p32() {
    named("adm-dv-refuse-seed-2p32");
}

#[test]
fn adm_dv_refuse_seed_negative() {
    named("adm-dv-refuse-seed-negative");
}

#[test]
fn adm_dv_refuse_size_extra_field() {
    named("adm-dv-refuse-size-extra-field");
}

#[test]
fn adm_dv_refuse_size_missing_height() {
    named("adm-dv-refuse-size-missing-height");
}

#[test]
fn adm_dv_refuse_steps_0() {
    named("adm-dv-refuse-steps-0");
}

#[test]
fn adm_dv_refuse_steps_101() {
    named("adm-dv-refuse-steps-101");
}

#[test]
fn adm_dv_refuse_width_255() {
    named("adm-dv-refuse-width-255");
}

#[test]
fn adm_empty_body() {
    named("adm-empty-body");
}

#[test]
fn adm_jobid_honored() {
    named("adm-jobid-honored");
}

#[test]
fn adm_jobid_minted() {
    named("adm-jobid-minted");
}

#[test]
fn adm_lane_missing() {
    named("adm-lane-missing");
}

#[test]
fn adm_lane_unknown() {
    named("adm-lane-unknown");
}

#[test]
fn adm_minimal_accepted() {
    named("adm-minimal-accepted");
}

#[test]
fn adm_ms_accept_full() {
    named("adm-ms-accept-full");
}

#[test]
fn adm_ms_accept_key_edges() {
    named("adm-ms-accept-key-edges");
}

#[test]
fn adm_ms_accept_minimal() {
    named("adm-ms-accept-minimal");
}

#[test]
fn adm_ms_pin_ignored() {
    named("adm-ms-pin-ignored");
}

#[test]
fn adm_ms_pin_not_json() {
    named("adm-ms-pin-not-json");
}

#[test]
fn adm_ms_refuse_bpm_19() {
    named("adm-ms-refuse-bpm-19");
}

#[test]
fn adm_ms_refuse_bpm_301() {
    named("adm-ms-refuse-bpm-301");
}

#[test]
fn adm_ms_refuse_duration_0() {
    named("adm-ms-refuse-duration-0");
}

#[test]
fn adm_ms_refuse_duration_301() {
    named("adm-ms-refuse-duration-301");
}

#[test]
fn adm_ms_refuse_format_mp3() {
    named("adm-ms-refuse-format-mp3");
}

#[test]
fn adm_ms_refuse_key_hmaj() {
    named("adm-ms-refuse-key-hmaj");
}

#[test]
fn adm_ms_refuse_key_lower() {
    named("adm-ms-refuse-key-lower");
}

#[test]
fn adm_ms_refuse_negative_4097() {
    named("adm-ms-refuse-negative-4097");
}

#[test]
fn adm_ms_refuse_prompt_4097() {
    named("adm-ms-refuse-prompt-4097");
}

#[test]
fn adm_ms_refuse_seed_2p32() {
    named("adm-ms-refuse-seed-2p32");
}

#[test]
fn adm_nonfinite_infinity() {
    named("adm-nonfinite-infinity");
}

#[test]
fn adm_sh_404_render() {
    named("adm-sh-404-render");
}

#[test]
fn adm_sh_404_tts() {
    named("adm-sh-404-tts");
}

#[test]
fn adm_sh_413_65537() {
    named("adm-sh-413-65537");
}

#[test]
fn adm_sh_413_edge_65536() {
    named("adm-sh-413-edge-65536");
}

#[test]
fn adm_sh_415_edge_case() {
    named("adm-sh-415-edge-case");
}

#[test]
fn adm_sh_415_edge_params() {
    named("adm-sh-415-edge-params");
}

#[test]
fn adm_sh_415_empty() {
    named("adm-sh-415-empty");
}

#[test]
fn adm_sh_415_textplain() {
    named("adm-sh-415-textplain");
}

#[test]
fn adm_sh_badjson_dupkey() {
    named("adm-sh-badjson-dupkey");
}

#[test]
fn adm_sh_badjson_exponent() {
    named("adm-sh-badjson-exponent");
}

#[test]
fn adm_sh_badjson_float() {
    named("adm-sh-badjson-float");
}

#[test]
fn adm_sh_badjson_nan() {
    named("adm-sh-badjson-nan");
}

#[test]
fn adm_sh_badjson_trailing() {
    named("adm-sh-badjson-trailing");
}

#[test]
fn adm_sh_badjson_u64() {
    named("adm-sh-badjson-u64");
}

#[test]
fn adm_sh_badjson_utf8() {
    named("adm-sh-badjson-utf8");
}

#[test]
fn adm_sh_bool_as_int() {
    named("adm-sh-bool-as-int");
}

#[test]
fn adm_sh_env_api_wrong() {
    named("adm-sh-env-api-wrong");
}

#[test]
fn adm_sh_env_cartridge_default() {
    named("adm-sh-env-cartridge-default");
}

#[test]
fn adm_sh_env_cartridge_real() {
    named("adm-sh-env-cartridge-real");
}

#[test]
fn adm_sh_env_jobid_64() {
    named("adm-sh-env-jobid-64");
}

#[test]
fn adm_sh_env_jobid_65() {
    named("adm-sh-env-jobid-65");
}

#[test]
fn adm_sh_env_jobid_dash_start() {
    named("adm-sh-env-jobid-dash-start");
}

#[test]
fn adm_sh_env_jobid_uppercase() {
    named("adm-sh-env-jobid-uppercase");
}

#[test]
fn adm_sh_env_prefer_5() {
    named("adm-sh-env-prefer-5");
}

#[test]
fn adm_sh_env_prefer_6() {
    named("adm-sh-env-prefer-6");
}

#[test]
fn adm_sh_env_prefer_bad_id() {
    named("adm-sh-env-prefer-bad-id");
}

#[test]
fn adm_sh_env_prefer_dup() {
    named("adm-sh-env-prefer-dup");
}

#[test]
fn adm_sh_env_timeout_0() {
    named("adm-sh-env-timeout-0");
}

#[test]
fn adm_sh_env_timeout_360() {
    named("adm-sh-env-timeout-360");
}

#[test]
fn adm_sh_env_timeout_361() {
    named("adm-sh-env-timeout-361");
}

#[test]
fn adm_sh_key_128() {
    named("adm-sh-key-128");
}

#[test]
fn adm_sh_key_129() {
    named("adm-sh-key-129");
}

#[test]
fn adm_sh_key_bad_char() {
    named("adm-sh-key-bad-char");
}

#[test]
fn adm_sh_mismatch() {
    named("adm-sh-mismatch");
}

#[test]
fn adm_sh_mismatch_before_null() {
    named("adm-sh-mismatch-before-null");
}

#[test]
fn adm_sh_missing_required() {
    named("adm-sh-missing-required");
}

#[test]
fn adm_sh_nonobj_array() {
    named("adm-sh-nonobj-array");
}

#[test]
fn adm_sh_nonobj_string() {
    named("adm-sh-nonobj-string");
}

#[test]
fn adm_sh_null_jobid() {
    named("adm-sh-null-jobid");
}

#[test]
fn adm_sh_size_as_list() {
    named("adm-sh-size-as-list");
}

#[test]
fn adm_sh_size_bool_dim() {
    named("adm-sh-size-bool-dim");
}

#[test]
fn adm_sh_str_as_int() {
    named("adm-sh-str-as-int");
}

#[test]
fn adm_sh_unknown_envelope_field() {
    named("adm-sh-unknown-envelope-field");
}

#[test]
fn adm_size_edge_65536() {
    named("adm-size-edge-65536");
}

#[test]
fn adm_size_over_70000() {
    named("adm-size-over-70000");
}

#[test]
fn adm_stt_accept_audio_edge() {
    named("adm-stt-accept-audio-edge");
}

#[test]
fn adm_stt_accept_full() {
    named("adm-stt-accept-full");
}

#[test]
fn adm_stt_accept_maxsec_3600() {
    named("adm-stt-accept-maxsec-3600");
}

#[test]
fn adm_stt_accept_minimal() {
    named("adm-stt-accept-minimal");
}

#[test]
fn adm_stt_pin_ignored() {
    named("adm-stt-pin-ignored");
}

#[test]
fn adm_stt_pin_not_json() {
    named("adm-stt-pin-not-json");
}

#[test]
fn adm_stt_pin_order() {
    named("adm-stt-pin-order");
}

#[test]
fn adm_stt_refuse_audio_1025() {
    named("adm-stt-refuse-audio-1025");
}

#[test]
fn adm_stt_refuse_audio_absolute() {
    named("adm-stt-refuse-audio-absolute");
}

#[test]
fn adm_stt_refuse_audio_empty() {
    named("adm-stt-refuse-audio-empty");
}

#[test]
fn adm_stt_refuse_audio_newline() {
    named("adm-stt-refuse-audio-newline");
}

#[test]
fn adm_stt_refuse_diarize_type() {
    named("adm-stt-refuse-diarize-type");
}

#[test]
fn adm_stt_refuse_format_aiff() {
    named("adm-stt-refuse-format-aiff");
}

#[test]
fn adm_stt_refuse_hints_4097() {
    named("adm-stt-refuse-hints-4097");
}

#[test]
fn adm_stt_refuse_language() {
    named("adm-stt-refuse-language");
}

#[test]
fn adm_stt_refuse_maxalt_0() {
    named("adm-stt-refuse-maxalt-0");
}

#[test]
fn adm_stt_refuse_maxalt_6() {
    named("adm-stt-refuse-maxalt-6");
}

#[test]
fn adm_stt_refuse_maxsec_0() {
    named("adm-stt-refuse-maxsec-0");
}

#[test]
fn adm_stt_refuse_maxsec_3601() {
    named("adm-stt-refuse-maxsec-3601");
}

#[test]
fn adm_stt_refuse_seed_unknown() {
    named("adm-stt-refuse-seed-unknown");
}

#[test]
fn dsp_attempt_budget() {
    named("dsp-attempt-budget");
}

#[test]
fn dsp_attempt_first() {
    named("dsp-attempt-first");
}

#[test]
fn dsp_attempt_second() {
    named("dsp-attempt-second");
}

#[test]
fn dsp_clamp_0() {
    named("dsp-clamp-0");
}

#[test]
fn dsp_clamp_124() {
    named("dsp-clamp-124");
}

#[test]
fn dsp_clamp_2() {
    named("dsp-clamp-2");
}

#[test]
fn dsp_clamp_255() {
    named("dsp-clamp-255");
}

#[test]
fn dsp_clamp_signal() {
    named("dsp-clamp-signal");
}

#[test]
fn dsp_gap_adapter_missing() {
    named("dsp-gap-adapter-missing");
}

#[test]
fn dsp_gap_adapter_not_dispatched() {
    named("dsp-gap-adapter-not-dispatched");
}

#[test]
fn dsp_gap_exec_exempt() {
    named("dsp-gap-exec-exempt");
}

#[test]
fn dsp_kind_adapter_diffusion() {
    named("dsp-kind-adapter-diffusion");
}

#[test]
fn dsp_kind_adapter_music_sfx() {
    named("dsp-kind-adapter-music-sfx");
}

#[test]
fn dsp_kind_adapter_render_blender() {
    named("dsp-kind-adapter-render-blender");
}

#[test]
fn dsp_kind_adapter_stt() {
    named("dsp-kind-adapter-stt");
}

#[test]
fn dsp_kind_adapter_tts() {
    named("dsp-kind-adapter-tts");
}

#[test]
fn dsp_kind_exec() {
    named("dsp-kind-exec");
}

#[test]
fn dsp_kind_unknown() {
    named("dsp-kind-unknown");
}

#[test]
fn dsp_map_device_state() {
    named("dsp-map-device-state");
}

#[test]
fn dsp_map_device_timedout() {
    named("dsp-map-device-timedout");
}

#[test]
fn dsp_map_raw_signal() {
    named("dsp-map-raw-signal");
}

#[test]
fn dsp_map_rc0() {
    named("dsp-map-rc0");
}

#[test]
fn dsp_map_rc1() {
    named("dsp-map-rc1");
}

#[test]
fn dsp_map_rc124() {
    named("dsp-map-rc124");
}

#[test]
fn dsp_map_rc2_dispatched() {
    named("dsp-map-rc2-dispatched");
}

#[test]
fn dsp_map_rc2_predispatch() {
    named("dsp-map-rc2-predispatch");
}

#[test]
fn dsp_map_reason_not_slug() {
    named("dsp-map-reason-not-slug");
}

#[test]
fn dsp_map_result_doc() {
    named("dsp-map-result-doc");
}

#[test]
fn dsp_part_range() {
    named("dsp-part-range");
}

#[test]
fn dsp_part_single() {
    named("dsp-part-single");
}

#[test]
fn dsp_part_unchunked() {
    named("dsp-part-unchunked");
}

#[test]
fn dsp_rcstate_0() {
    named("dsp-rcstate-0");
}

#[test]
fn dsp_rcstate_1() {
    named("dsp-rcstate-1");
}

#[test]
fn dsp_rcstate_124() {
    named("dsp-rcstate-124");
}

#[test]
fn dsp_rcstate_2() {
    named("dsp-rcstate-2");
}

#[test]
fn dsp_rundir_absent() {
    named("dsp-rundir-absent");
}

#[test]
fn dsp_rundir_nonempty() {
    named("dsp-rundir-nonempty");
}

#[test]
fn dsp_spec_no_out() {
    named("dsp-spec-no-out");
}

#[test]
fn dsp_spec_out_narrowed() {
    named("dsp-spec-out-narrowed");
}

#[test]
fn dsp_verify_bad_sums_line() {
    named("dsp-verify-bad-sums-line");
}

#[test]
fn dsp_verify_bookkeeping_skipped() {
    named("dsp-verify-bookkeeping-skipped");
}

#[test]
fn dsp_verify_empty_artifact() {
    named("dsp-verify-empty-artifact");
}

#[test]
fn dsp_verify_flat_ok() {
    named("dsp-verify-flat-ok");
}

#[test]
fn dsp_verify_hash_mismatch() {
    named("dsp-verify-hash-mismatch");
}

#[test]
fn dsp_verify_named_file_absent() {
    named("dsp-verify-named-file-absent");
}

#[test]
fn dsp_verify_nine_artifacts() {
    named("dsp-verify-nine-artifacts");
}

#[test]
fn dsp_verify_no_parts() {
    named("dsp-verify-no-parts");
}

#[test]
fn dsp_verify_no_sums() {
    named("dsp-verify-no-sums");
}

#[test]
fn dsp_verify_sidecar_forged() {
    named("dsp-verify-sidecar-forged");
}

#[test]
fn dsp_verify_sidecar_missing_line() {
    named("dsp-verify-sidecar-missing-line");
}

#[test]
fn dsp_verify_subpath_flat_lane() {
    named("dsp-verify-subpath-flat-lane");
}

#[test]
fn dsp_verify_subpaths_ok() {
    named("dsp-verify-subpaths-ok");
}

#[test]
fn dsp_verify_two_parts_one_name() {
    named("dsp-verify-two-parts-one-name");
}

#[test]
fn dsp_verify_unsafe_absolute() {
    named("dsp-verify-unsafe-absolute");
}

#[test]
fn dsp_verify_unsafe_dotdot() {
    named("dsp-verify-unsafe-dotdot");
}

#[test]
fn dsp_verify_unsafe_leading_dot() {
    named("dsp-verify-unsafe-leading-dot");
}

#[test]
fn dsp_whynot_disabled() {
    named("dsp-whynot-disabled");
}

#[test]
fn dsp_whynot_disabled_no_note() {
    named("dsp-whynot-disabled-no-note");
}

#[test]
fn dsp_whynot_not_serving() {
    named("dsp-whynot-not-serving");
}

#[test]
fn dsp_whynot_ok() {
    named("dsp-whynot-ok");
}

#[test]
fn dsp_whynot_seats_full() {
    named("dsp-whynot-seats-full");
}

#[test]
fn dsp_whynot_two_reasons() {
    named("dsp-whynot-two-reasons");
}

#[test]
fn dsp_whynot_unknown_kind() {
    named("dsp-whynot-unknown-kind");
}

#[test]
fn gate_eg_di_approval_missing() {
    named("gate-eg-di-approval-missing");
}

#[test]
fn gate_eg_di_cart_missing() {
    named("gate-eg-di-cart-missing");
}

#[test]
fn gate_eg_di_cart_other_lane() {
    named("gate-eg-di-cart-other-lane");
}

#[test]
fn gate_eg_di_check_row() {
    named("gate-eg-di-check-row");
}

#[test]
fn gate_eg_di_disable_ok() {
    named("gate-eg-di-disable-ok");
}

#[test]
fn gate_eg_di_enable_blocked() {
    named("gate-eg-di-enable-blocked");
}

#[test]
fn gate_eg_di_enable_ok() {
    named("gate-eg-di-enable-ok");
}

#[test]
fn gate_eg_di_model_only() {
    named("gate-eg-di-model-only");
}

#[test]
fn gate_eg_di_pin_form() {
    named("gate-eg-di-pin-form");
}

#[test]
fn gate_eg_di_state_shape() {
    named("gate-eg-di-state-shape");
}

#[test]
fn gate_eg_dv_approval_missing() {
    named("gate-eg-dv-approval-missing");
}

#[test]
fn gate_eg_dv_approval_placeholder() {
    named("gate-eg-dv-approval-placeholder");
}

#[test]
fn gate_eg_dv_cart_missing() {
    named("gate-eg-dv-cart-missing");
}

#[test]
fn gate_eg_dv_cart_no_pin() {
    named("gate-eg-dv-cart-no-pin");
}

#[test]
fn gate_eg_dv_cart_pin_sha_only() {
    named("gate-eg-dv-cart-pin-sha-only");
}

#[test]
fn gate_eg_dv_check_row() {
    named("gate-eg-dv-check-row");
}

#[test]
fn gate_eg_dv_disable_ok() {
    named("gate-eg-dv-disable-ok");
}

#[test]
fn gate_eg_dv_enable_blocked() {
    named("gate-eg-dv-enable-blocked");
}

#[test]
fn gate_eg_dv_enable_ok() {
    named("gate-eg-dv-enable-ok");
}

#[test]
fn gate_eg_dv_model_only() {
    named("gate-eg-dv-model-only");
}

#[test]
fn gate_eg_dv_pin_form() {
    named("gate-eg-dv-pin-form");
}

#[test]
fn gate_eg_ms_approval_missing() {
    named("gate-eg-ms-approval-missing");
}

#[test]
fn gate_eg_ms_cart_missing() {
    named("gate-eg-ms-cart-missing");
}

#[test]
fn gate_eg_ms_check_row() {
    named("gate-eg-ms-check-row");
}

#[test]
fn gate_eg_ms_disable_not_enabled() {
    named("gate-eg-ms-disable-not-enabled");
}

#[test]
fn gate_eg_ms_disable_ok() {
    named("gate-eg-ms-disable-ok");
}

#[test]
fn gate_eg_ms_enable_blocked() {
    named("gate-eg-ms-enable-blocked");
}

#[test]
fn gate_eg_ms_enable_ok() {
    named("gate-eg-ms-enable-ok");
}

#[test]
fn gate_eg_ms_model_absent() {
    named("gate-eg-ms-model-absent");
}

#[test]
fn gate_eg_ms_model_only() {
    named("gate-eg-ms-model-only");
}

#[test]
fn gate_eg_ms_pin_form() {
    named("gate-eg-ms-pin-form");
}

#[test]
fn gate_eg_render_alt_ids() {
    named("gate-eg-render-alt-ids");
}

#[test]
fn gate_eg_render_check_row() {
    named("gate-eg-render-check-row");
}

#[test]
fn gate_eg_render_disable_refused() {
    named("gate-eg-render-disable-refused");
}

#[test]
fn gate_eg_render_enable_refused() {
    named("gate-eg-render-enable-refused");
}

#[test]
fn gate_eg_render_pins_bad_id() {
    named("gate-eg-render-pins-bad-id");
}

#[test]
fn gate_eg_render_pins_empty_ids() {
    named("gate-eg-render-pins-empty-ids");
}

#[test]
fn gate_eg_render_pins_model_key() {
    named("gate-eg-render-pins-model-key");
}

#[test]
fn gate_eg_render_pins_pin_key() {
    named("gate-eg-render-pins-pin-key");
}

#[test]
fn gate_eg_render_record_missing() {
    named("gate-eg-render-record-missing");
}

#[test]
fn gate_eg_sh_audit_unwritable() {
    named("gate-eg-sh-audit-unwritable");
}

#[test]
fn gate_eg_sh_badjson_dupkey() {
    named("gate-eg-sh-badjson-dupkey");
}

#[test]
fn gate_eg_sh_badjson_notjson() {
    named("gate-eg-sh-badjson-notjson");
}

#[test]
fn gate_eg_sh_badpins_dupe() {
    named("gate-eg-sh-badpins-dupe");
}

#[test]
fn gate_eg_sh_badpins_gated_shape() {
    named("gate-eg-sh-badpins-gated-shape");
}

#[test]
fn gate_eg_sh_badpins_model_kind() {
    named("gate-eg-sh-badpins-model-kind");
}

#[test]
fn gate_eg_sh_badpins_shape() {
    named("gate-eg-sh-badpins-shape");
}

#[test]
fn gate_eg_sh_badpins_unknown_lane_entry() {
    named("gate-eg-sh-badpins-unknown-lane-entry");
}

#[test]
fn gate_eg_sh_check_refuses_too() {
    named("gate-eg-sh-check-refuses-too");
}

#[test]
fn gate_eg_sh_disable_unknown_lane() {
    named("gate-eg-sh-disable-unknown-lane");
}

#[test]
fn gate_eg_sh_kit_missing() {
    named("gate-eg-sh-kit-missing");
}

#[test]
fn gate_eg_sh_kit_unusable() {
    named("gate-eg-sh-kit-unusable");
}

#[test]
fn gate_eg_sh_pins_unreadable() {
    named("gate-eg-sh-pins-unreadable");
}

#[test]
fn gate_eg_sh_state_bogus_lane() {
    named("gate-eg-sh-state-bogus-lane");
}

#[test]
fn gate_eg_sh_state_unreadable() {
    named("gate-eg-sh-state-unreadable");
}

#[test]
fn gate_eg_sh_unknown_lane() {
    named("gate-eg-sh-unknown-lane");
}

#[test]
fn gate_eg_sh_usage_check_with_lane() {
    named("gate-eg-sh-usage-check-with-lane");
}

#[test]
fn gate_eg_sh_usage_enable_no_lane() {
    named("gate-eg-sh-usage-enable-no-lane");
}

#[test]
fn gate_eg_sh_usage_none() {
    named("gate-eg-sh-usage-none");
}

#[test]
fn gate_eg_sh_usage_unknown_command() {
    named("gate-eg-sh-usage-unknown-command");
}

#[test]
fn gate_eg_stt_approval_missing() {
    named("gate-eg-stt-approval-missing");
}

#[test]
fn gate_eg_stt_cart_artifact_sha_only() {
    named("gate-eg-stt-cart-artifact-sha-only");
}

#[test]
fn gate_eg_stt_cart_missing() {
    named("gate-eg-stt-cart-missing");
}

#[test]
fn gate_eg_stt_check_row() {
    named("gate-eg-stt-check-row");
}

#[test]
fn gate_eg_stt_disable_ok() {
    named("gate-eg-stt-disable-ok");
}

#[test]
fn gate_eg_stt_enable_blocked() {
    named("gate-eg-stt-enable-blocked");
}

#[test]
fn gate_eg_stt_enable_ok() {
    named("gate-eg-stt-enable-ok");
}

#[test]
fn gate_eg_stt_model_marker_kind() {
    named("gate-eg-stt-model-marker-kind");
}

#[test]
fn gate_eg_stt_model_only() {
    named("gate-eg-stt-model-only");
}

#[test]
fn gate_eg_stt_pin_form() {
    named("gate-eg-stt-pin-form");
}

#[test]
fn gate_eg_stt_pin_match() {
    named("gate-eg-stt-pin-match");
}

#[test]
fn gate_eg_tts_approval_missing() {
    named("gate-eg-tts-approval-missing");
}

#[test]
fn gate_eg_tts_cart_licence_only() {
    named("gate-eg-tts-cart-licence-only");
}

#[test]
fn gate_eg_tts_cart_missing() {
    named("gate-eg-tts-cart-missing");
}

#[test]
fn gate_eg_tts_check_row() {
    named("gate-eg-tts-check-row");
}

#[test]
fn gate_eg_tts_disable_ok() {
    named("gate-eg-tts-disable-ok");
}

#[test]
fn gate_eg_tts_enable_blocked() {
    named("gate-eg-tts-enable-blocked");
}

#[test]
fn gate_eg_tts_enable_idempotent() {
    named("gate-eg-tts-enable-idempotent");
}

#[test]
fn gate_eg_tts_enable_ok() {
    named("gate-eg-tts-enable-ok");
}

#[test]
fn gate_eg_tts_model_only() {
    named("gate-eg-tts-model-only");
}

#[test]
fn gate_eg_tts_pin_form() {
    named("gate-eg-tts-pin-form");
}

#[test]
fn gate_eg_tts_state_corrupt() {
    named("gate-eg-tts-state-corrupt");
}

#[test]
fn lim_f3_missing_lane() {
    named("lim-f3-missing-lane");
}

#[test]
fn lim_f3_unknown_lane() {
    named("lim-f3-unknown-lane");
}

#[test]
fn lim_rl_di_image_bytes() {
    named("lim-rl-di-image-bytes");
}

#[test]
fn lim_rl_di_image_done() {
    named("lim-rl-di-image-done");
}

#[test]
fn lim_rl_di_image_done_sha() {
    named("lim-rl-di-image-done-sha");
}

#[test]
fn lim_rl_di_image_empty_merge() {
    named("lim-rl-di-image-empty-merge");
}

#[test]
fn lim_rl_di_image_hash() {
    named("lim-rl-di-image-hash");
}

#[test]
fn lim_rl_di_image_unreadable() {
    named("lim-rl-di-image-unreadable");
}

#[test]
fn lim_rl_di_multi_artifacts() {
    named("lim-rl-di-multi-artifacts");
}

#[test]
fn lim_rl_di_size_ignored() {
    named("lim-rl-di-size-ignored");
}

#[test]
fn lim_rl_dv_declared_negative() {
    named("lim-rl-dv-declared-negative");
}

#[test]
fn lim_rl_dv_declared_string() {
    named("lim-rl-dv-declared-string");
}

#[test]
fn lim_rl_dv_done_artifacts_only() {
    named("lim-rl-dv-done-artifacts-only");
}

#[test]
fn lim_rl_dv_done_declared() {
    named("lim-rl-dv-done-declared");
}

#[test]
fn lim_rl_dv_done_dup_paths() {
    named("lim-rl-dv-done-dup-paths");
}

#[test]
fn lim_rl_dv_done_noncontiguous() {
    named("lim-rl-dv-done-noncontiguous");
}

#[test]
fn lim_rl_dv_empty_merge() {
    named("lim-rl-dv-empty-merge");
}

#[test]
fn lim_rl_dv_hash() {
    named("lim-rl-dv-hash");
}

#[test]
fn lim_rl_dv_inconsistent() {
    named("lim-rl-dv-inconsistent");
}

#[test]
fn lim_rl_dv_no_frames_in_spec() {
    named("lim-rl-dv-no-frames-in-spec");
}

#[test]
fn lim_rl_dv_over_one_frame() {
    named("lim-rl-dv-over-one-frame");
}

#[test]
fn lim_rl_dv_unknowable_no_signal() {
    named("lim-rl-dv-unknowable-no-signal");
}

#[test]
fn lim_rl_dv_unreadable() {
    named("lim-rl-dv-unreadable");
}

#[test]
fn lim_rl_ms_done_30() {
    named("lim-rl-ms-done-30");
}

#[test]
fn lim_rl_ms_done_fraction() {
    named("lim-rl-ms-done-fraction");
}

#[test]
fn lim_rl_ms_done_stems() {
    named("lim-rl-ms-done-stems");
}

#[test]
fn lim_rl_ms_duration_zero() {
    named("lim-rl-ms-duration-zero");
}

#[test]
fn lim_rl_ms_hash() {
    named("lim-rl-ms-hash");
}

#[test]
fn lim_rl_ms_missing_audio() {
    named("lim-rl-ms-missing-audio");
}

#[test]
fn lim_rl_ms_mp3_only() {
    named("lim-rl-ms-mp3-only");
}

#[test]
fn lim_rl_ms_no_duration() {
    named("lim-rl-ms-no-duration");
}

#[test]
fn lim_rl_ms_over_half() {
    named("lim-rl-ms-over-half");
}

#[test]
fn lim_rl_ms_stem_empty() {
    named("lim-rl-ms-stem-empty");
}

#[test]
fn lim_rl_ms_stem_over() {
    named("lim-rl-ms-stem-over");
}

#[test]
fn lim_rl_ms_stem_truncated() {
    named("lim-rl-ms-stem-truncated");
}

#[test]
fn lim_rl_r_blender_bytes() {
    named("lim-rl-r-blender-bytes");
}

#[test]
fn lim_rl_r_blender_done() {
    named("lim-rl-r-blender-done");
}

#[test]
fn lim_rl_r_blender_done_sha() {
    named("lim-rl-r-blender-done-sha");
}

#[test]
fn lim_rl_r_blender_empty_merge() {
    named("lim-rl-r-blender-empty-merge");
}

#[test]
fn lim_rl_r_blender_hash() {
    named("lim-rl-r-blender-hash");
}

#[test]
fn lim_rl_r_blender_unreadable() {
    named("lim-rl-r-blender-unreadable");
}

#[test]
fn lim_rl_r_frames_ignored() {
    named("lim-rl-r-frames-ignored");
}

#[test]
fn lim_rl_r_jobid_fallback() {
    named("lim-rl-r-jobid-fallback");
}

#[test]
fn lim_rl_stt_bytes() {
    named("lim-rl-stt-bytes");
}

#[test]
fn lim_rl_stt_done() {
    named("lim-rl-stt-done");
}

#[test]
fn lim_rl_stt_done_sha() {
    named("lim-rl-stt-done-sha");
}

#[test]
fn lim_rl_stt_empty_merge() {
    named("lim-rl-stt-empty-merge");
}

#[test]
fn lim_rl_stt_hash() {
    named("lim-rl-stt-hash");
}

#[test]
fn lim_rl_stt_input_not_output() {
    named("lim-rl-stt-input-not-output");
}

#[test]
fn lim_rl_stt_unreadable() {
    named("lim-rl-stt-unreadable");
}

#[test]
fn lim_rl_stt_wav_not_measured() {
    named("lim-rl-stt-wav-not-measured");
}

#[test]
fn lim_rl_tts_done_300() {
    named("lim-rl-tts-done-300");
}

#[test]
fn lim_rl_tts_done_record_60() {
    named("lim-rl-tts-done-record-60");
}

#[test]
fn lim_rl_tts_done_second_wav() {
    named("lim-rl-tts-done-second-wav");
}

#[test]
fn lim_rl_tts_empty() {
    named("lim-rl-tts-empty");
}

#[test]
fn lim_rl_tts_empty_merge() {
    named("lim-rl-tts-empty-merge");
}

#[test]
fn lim_rl_tts_hash_bytes() {
    named("lim-rl-tts-hash-bytes");
}

#[test]
fn lim_rl_tts_hash_sha() {
    named("lim-rl-tts-hash-sha");
}

#[test]
fn lim_rl_tts_missing_artifact() {
    named("lim-rl-tts-missing-artifact");
}

#[test]
fn lim_rl_tts_not_riff() {
    named("lim-rl-tts-not-riff");
}

#[test]
fn lim_rl_tts_order_measure_first() {
    named("lim-rl-tts-order-measure-first");
}

#[test]
fn lim_rl_tts_over_one_sample() {
    named("lim-rl-tts-over-one-sample");
}

#[test]
fn lim_rl_tts_rate_mismatch() {
    named("lim-rl-tts-rate-mismatch");
}

#[test]
fn lim_rl_tts_record_zero() {
    named("lim-rl-tts-record-zero");
}

#[test]
fn lim_rl_tts_truncated() {
    named("lim-rl-tts-truncated");
}

#[test]
fn lim_rl_tts_unreadable_path() {
    named("lim-rl-tts-unreadable-path");
}

#[test]
fn lim_s05_image_empty_merge() {
    named("lim-s05-image-empty-merge");
}

#[test]
fn lim_s05_image_passes_through() {
    named("lim-s05-image-passes-through");
}

#[test]
fn lim_s05_music_at_ceiling() {
    named("lim-s05-music-at-ceiling");
}

#[test]
fn lim_s05_music_no_ceiling() {
    named("lim-s05-music-no-ceiling");
}

#[test]
fn lim_s05_music_one_sample_over() {
    named("lim-s05-music-one-sample-over");
}

#[test]
fn lim_s05_music_stem_over() {
    named("lim-s05-music-stem-over");
}

#[test]
fn lim_s05_music_zero_length() {
    named("lim-s05-music-zero-length");
}

#[test]
fn lim_s05_tts_at_ceiling() {
    named("lim-s05-tts-at-ceiling");
}

#[test]
fn lim_s05_tts_bad_header() {
    named("lim-s05-tts-bad-header");
}

#[test]
fn lim_s05_tts_bad_header_fmt() {
    named("lim-s05-tts-bad-header-fmt");
}

#[test]
fn lim_s05_tts_hash_mismatch() {
    named("lim-s05-tts-hash-mismatch");
}

#[test]
fn lim_s05_tts_hash_mismatch_sha() {
    named("lim-s05-tts-hash-mismatch-sha");
}

#[test]
fn lim_s05_tts_missing_artifact() {
    named("lim-s05-tts-missing-artifact");
}

#[test]
fn lim_s05_tts_one_sample_over() {
    named("lim-s05-tts-one-sample-over");
}

#[test]
fn lim_s05_tts_rate_mismatch() {
    named("lim-s05-tts-rate-mismatch");
}

#[test]
fn lim_s05_tts_truncated() {
    named("lim-s05-tts-truncated");
}

#[test]
fn lim_s05_tts_truncated_oversold() {
    named("lim-s05-tts-truncated-oversold");
}

#[test]
fn lim_s05_tts_under_ceiling() {
    named("lim-s05-tts-under-ceiling");
}

#[test]
fn lim_s05_tts_zero_length() {
    named("lim-s05-tts-zero-length");
}

#[test]
fn lim_s05_video_at_admitted_frames() {
    named("lim-s05-video-at-admitted-frames");
}

#[test]
fn lim_s05_video_frames_as_artifacts() {
    named("lim-s05-video-frames-as-artifacts");
}

#[test]
fn lim_s05_video_frames_disagree() {
    named("lim-s05-video-frames-disagree");
}

#[test]
fn lim_s05_video_frames_undeclared() {
    named("lim-s05-video-frames-undeclared");
}

#[test]
fn lim_s05_video_no_admitted_frames() {
    named("lim-s05-video-no-admitted-frames");
}

#[test]
fn lim_s05_video_one_frame_over() {
    named("lim-s05-video-one-frame-over");
}

#[test]
fn conformance_b6_total_passed_plus_listed_differences() {
    let m: Value =
        serde_json::from_slice(&fs::read(fixtures().join("MANIFEST.json")).unwrap()).unwrap();
    let diffs: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    let ids: HashSet<_> = m["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r[0].as_str().unwrap())
        .collect();
    for (id, d) in diffs.as_object().unwrap() {
        assert!(ids.contains(id.as_str()));
        assert!(!d["rule"].as_str().unwrap().is_empty());
        assert_eq!(
            d["reference"],
            format!(
                "A/glm-rust-port-corpus-golden-ext-20261101-b6-04w2/out/corpus/cases/{id}.json:1"
            )
        );
    }
    let different = diffs.as_object().unwrap().len();
    let passed = ids.len() - different;
    assert_eq!((passed, different), (187, 163));
    assert_eq!(passed + different, m["total"].as_u64().unwrap() as usize);
}

#[test]
fn b6_every_difference_has_class_reference_and_reason() {
    let diffs: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    for (id, entry) in diffs.as_object().unwrap() {
        assert!(
            ["fold-bug", "ref-bug", "deliberate"].contains(&entry["class"].as_str().unwrap()),
            "{id}"
        );
        assert!(entry["reason"].as_str().unwrap().len() > 80, "{id}");
        let cite = entry["ref"].as_str().unwrap();
        let (path, line) = cite.rsplit_once(':').unwrap();
        let line: usize = line.parse().unwrap();
        assert!(line > 0 && path.starts_with("A/"), "{id}: {cite}");
        let refs = std::env::var_os("DIFFUSER_REFS_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/srv/lanes/refs/diffuser-20261113"));
        let file = refs.join("accepted").join(&path[2..]);
        assert!(
            fs::read_to_string(file).unwrap().lines().count() >= line,
            "{id}: {cite}"
        );
    }
}
#[test]
fn b6_no_unfixed_fold_bug_remains() {
    let diffs: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    let unresolved: Vec<_> = diffs
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, d)| d["class"] == "fold-bug")
        .map(|(id, _)| id)
        .collect();
    assert!(unresolved.is_empty(), "unfixed fold bugs: {unresolved:?}");
    assert_eq!(
        diffs
            .as_object()
            .unwrap()
            .values()
            .filter(|d| d["class"] == "ref-bug")
            .count(),
        1
    );
    assert_eq!(
        diffs
            .as_object()
            .unwrap()
            .values()
            .filter(|d| d["class"] == "deliberate")
            .count(),
        162
    );
}

// Each family pins a production sample and every retained rationale.
fn pinned_family(family: &str, count: usize, reason: &str, sample: &str, actual: Value) {
    let differences: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    let members: Vec<_> = differences
        .as_object()
        .unwrap()
        .values()
        .filter(|entry| entry["family"] == family)
        .collect();
    assert_eq!(members.len(), count, "{family}");
    for entry in members {
        assert_eq!(entry["reason"], reason, "{family}");
    }
    assert_eq!(differences[sample]["family"], family);
    assert_eq!(
        differences[sample]["actual"], actual,
        "native sample contract"
    );
    named(sample);
}
#[test]
fn b6_family_native_minted_identifier() {
    pinned_family("native_minted_identifier", 15, "Native minted job identifiers retain the existing rb timestamp form. E7 and the existing HTTP contract pin these native refusal statuses and identifier forms; changing them would invalidate established clients and assertions.", "adm-dv-accept-grid", json!({"outcome": "admit", "snapshot": {"api": "service-lane/v1", "artifacts": [], "attempts": [], "cancel_requested": false, "cartridge": "fake-diffusion-video-v1", "cleanup": "pending", "created_at": "2026-09-21T14:13:20Z", "deadline_at": "2026-09-21T14:58:20Z", "error": null, "job_id": "rb-<stamp>", "lane": "diffusion-video", "manifest": null, "pin_sha256": "f880d4a677e0c78d860b30e99be64b392cfe86f0946713d050544959e798e623", "queue_reason": "awaiting-seat", "spec_sha256": "93e8567e5b7eb9090bfa2ada5e20bc39c6d81db71a4d03399ec9a2f86606cd38", "state": "queued", "worker": null}}));
}
#[test]
fn b6_family_opened_refusal_status() {
    pinned_family("opened_refusal_status", 59, "Opened-lane admission retains its existing HTTP 422 refusal status. E7 and the existing HTTP contract pin these native refusal statuses and identifier forms; changing them would invalidate established clients and assertions.", "adm-dv-refuse-format-webm", json!({"code": "bad-spec", "outcome": "refuse", "retryable": false, "status": 422}));
}
#[test]
fn b6_family_minted_identifier_conflict_context() {
    pinned_family("minted_identifier_conflict_context", 2, "Native minted job identifiers retain the existing rb timestamp form. E7 explicitly retained immutable job-id conflict ownership instead of adding a second replay authority.", "adm-ms-accept-key-edges", json!({"outcome": "admit", "snapshot": {"api": "service-lane/v1", "artifacts": [], "attempts": [], "cancel_requested": false, "cartridge": "fake-music-sfx-v1", "cleanup": "pending", "created_at": "2026-09-21T14:13:20Z", "deadline_at": "2026-09-21T14:58:20Z", "error": null, "job_id": "rb-<stamp>", "lane": "music-sfx", "manifest": null, "pin_sha256": "d3b024fb2305360d3d6992eeaff5268cd99b0a8bf5410e5d3bf222cc68551bdc", "queue_reason": "awaiting-seat", "spec_sha256": "2bc2941e8b5c7470bc2a9d9e8565b6a878c87e6ca5e7a32c7bc944c82400fd9c", "state": "queued", "worker": null}}));
}
#[test]
fn b6_family_refusal_status_conflict_context() {
    pinned_family("refusal_status_conflict_context", 2, "Opened-lane admission retains its existing HTTP 422 refusal status. E7 explicitly retained immutable job-id conflict ownership instead of adding a second replay authority.", "adm-ms-refuse-key-hmaj", json!({"code": "bad-spec", "outcome": "refuse", "retryable": false, "status": 422}));
}
#[test]
fn b6_family_malformed_json_status() {
    pinned_family("malformed_json_status", 4, "Existing opened-lane HTTP assertions require status 422 for malformed JSON. E7 and the existing HTTP contract pin these native refusal statuses and identifier forms; changing them would invalidate established clients and assertions.", "adm-sh-badjson-dupkey", json!({"code": "bad-json", "outcome": "refuse", "rc": 2, "retryable": false, "status": 422}));
}
#[test]
fn b6_family_no_reference_idempotency() {
    pinned_family("no_reference_idempotency", 2, "The existing native admission path does not implement the reference idempotency header policy. E7 explicitly retained immutable job-id conflict ownership instead of adding a second replay authority.", "adm-sh-key-129", json!({"outcome": "admit", "snapshot": {"api": "service-lane/v1", "artifacts": [], "attempts": [], "cancel_requested": false, "cartridge": "fake-stt-v1", "cleanup": "pending", "created_at": "2026-09-21T14:13:20Z", "deadline_at": "2026-09-21T14:58:20Z", "error": null, "job_id": "rb-<stamp>", "lane": "stt", "manifest": null, "pin_sha256": "f9eec27ab16bee422cce7c485214abaed07ba27d1c164ae0b0af04c036042358", "queue_reason": "awaiting-seat", "spec_sha256": "bd984c8b58f885be5801f834b737f32d1e6a3d96cfa50b6618994c392cabcdb7", "state": "queued", "worker": null}}));
}
#[test]
fn b6_family_whole_job_part_suffix() {
    pinned_family("whole_job_part_suffix", 2, "Whole-job part directories retain the existing -bake suffix. E2 and S03 retain established delivery layout, nonempty artifact verification and refusal wording; the difference is observable and stays asserted.", "dsp-part-single", json!({"name": "warp-2070-bake"}));
}
#[test]
fn b6_family_nonempty_delivery() {
    pinned_family("nonempty_delivery", 1, "A successful delivery must contain at least one contract artifact. E2 and S03 retain established delivery layout, nonempty artifact verification and refusal wording; the difference is observable and stays asserted.", "dsp-verify-no-parts", json!({"refuse": {"code": "artifact-mismatch", "retryable": false}}));
}
#[test]
fn b6_family_refusal_spacing() {
    pinned_family("refusal_spacing", 2, "Existing refusal text retains its space after the colon. E2 and S03 retain established delivery layout, nonempty artifact verification and refusal wording; the difference is observable and stays asserted.", "dsp-whynot-disabled", json!({"why": ["disabled in registry: maintenance"]}));
}
#[test]
fn b6_family_native_gate_contract() {
    pinned_family("native_gate_contract", 71, "Native gate preserves its existing compact diagnostics and report fields, strict render pin allowlist, durable empty disabled state, audit error ordering and independence from the Python contract kit. Native gate diagnostics, projection and state persistence are the existing E3 contract; the reference enriches presentation and does not authorize changing its admission decisions.", "gate-eg-di-approval-missing", json!({"audit": [{"action": "enable", "lane": "diffusion-image", "reason": "approval-missing", "result": "refused"}], "code": "approval-missing", "detail": "", "detail_has": [], "exit": 1, "outcome": "refuse", "retryable": true, "state": "absent"}));
}
#[test]
fn b6_family_unique_artifact_paths() {
    assert_eq!(
        runtime_limits::enforce(
            &json!({"lane":"diffusion-video"}),
            &json!({"artifacts":[{"path":"clip.mp4"},{"path":"clip.mp4"}]}),
            |_| panic!("duplicates refused before reading"),
            &runtime_limits::Config::default()
        ),
        Err(error_catalog::DUPLICATE_ARTIFACT)
    );
    pinned_family("unique_artifact_paths", 1, "The existing E2 merge rejects duplicate artifact paths before counting frames. The reference deduplicates frame numbers before measuring and accepts duplicate paths; the production result and merge contracts require unique paths, so accepting this reference case would discard artifact identity.", "lim-rl-dv-done-dup-paths", json!({"outcome": "failed", "reason": "duplicate-artifact"}));
}
#[test]
fn b6_family_artifact_count_precedence() {
    pinned_family("artifact_count_precedence", 2, "The result schema permits at most eight artifacts and E2 checks this before frame measurements. D2 and D3 are held. Artifact count validation precedes measurement; changing precedence would change a pinned decision.", "lim-rl-dv-inconsistent", json!({"outcome": "failed", "reason": "artifact-count-exceeded"}));
}

fn conformance_rows_match(manifest: &Value, differences: &Value, text: &str) -> Result<(), String> {
    let ids: HashSet<_> = manifest["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row[0].as_str().unwrap())
        .collect();
    for id in differences.as_object().unwrap().keys() {
        if !ids.contains(id.as_str()) {
            return Err(format!("{id}: difference is absent from the b6 manifest"));
        }
    }
    let mut rows = HashMap::new();
    for line in text.lines().filter(|line| line.starts_with("| ")) {
        let cells: Vec<_> = line.split('|').map(str::trim).collect();
        if cells.len() > 1 && ids.contains(cells[1]) {
            if cells.len() != 7 {
                return Err(format!("{}: malformed conformance row", cells[1]));
            }
            if rows.insert(cells[1], (cells[4], cells[5])).is_some() {
                return Err(format!("{}: duplicate conformance row", cells[1]));
            }
        }
    }
    for id in ids {
        let expected = if let Some(entry) = differences.get(id) {
            let class = entry["class"]
                .as_str()
                .ok_or_else(|| format!("{id}: missing class"))?;
            let reason = entry["reason"]
                .as_str()
                .ok_or_else(|| format!("{id}: missing reason"))?;
            (class, reason)
        } else {
            ("matches", "Reference result matches the native result.")
        };
        if rows.get(id).copied() != Some(expected) {
            return Err(format!(
                "{id}: class/reason differs from docs/CONFORMANCE-B6.md; edit the matching row"
            ));
        }
    }
    Ok(())
}
#[test]
fn b6_class_and_reason_require_matching_document_rows() {
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixtures().join("MANIFEST.json")).unwrap()).unwrap();
    let differences: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    conformance_rows_match(
        &manifest,
        &differences,
        include_str!("../docs/CONFORMANCE-B6.md"),
    )
    .unwrap();
}
#[test]
fn b6_guard_names_mutated_entry_and_accepts_matching_row_edit() {
    let manifest: Value =
        serde_json::from_slice(&fs::read(fixtures().join("MANIFEST.json")).unwrap()).unwrap();
    let differences: Value = serde_json::from_str(include_str!("b6_differences.json")).unwrap();
    let text = include_str!("../docs/CONFORMANCE-B6.md");
    let id = "lim-rl-dv-done-dup-paths";
    let row = text
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap();
    for (field, replacement) in [
        ("class", "deliberate"),
        ("reason", "A changed reason needs a matching row edit."),
    ] {
        let mut changed = differences.clone();
        let original = changed[id][field].as_str().unwrap().to_owned();
        changed[id][field] = json!(replacement);
        let error = conformance_rows_match(&manifest, &changed, text).unwrap_err();
        assert!(error.contains(id), "missing entry diagnostic: {error}");
        let edited = text.replacen(row, &row.replacen(&original, replacement, 1), 1);
        conformance_rows_match(&manifest, &changed, &edited).unwrap();
    }
    let missing = text.replacen(row, "", 1);
    assert!(conformance_rows_match(&manifest, &differences, &missing)
        .unwrap_err()
        .contains(id));
    let mut changed = differences.clone();
    changed.as_object_mut().unwrap().remove(id);
    assert!(conformance_rows_match(&manifest, &changed, text)
        .unwrap_err()
        .contains(id));
    let matching = "adm-dupkey-nested";
    changed = differences.clone();
    changed[matching] =
        json!({"class":"deliberate", "reason":"A formerly matching entry now differs."});
    assert!(conformance_rows_match(&manifest, &changed, text)
        .unwrap_err()
        .contains(matching));
}
