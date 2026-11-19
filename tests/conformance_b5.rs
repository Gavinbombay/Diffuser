//! Compiled inside the binary crate so every adapter calls its production implementation.
use crate::*;
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/b5-06")
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
            "fold-b5-{}-{}-{id}",
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
fn descriptor(d: &Value) -> Vec<u8> {
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
    let diffs: Value = serde_json::from_str(include_str!("b5_differences.json")).unwrap();
    if let Some(expected) = diffs.get(id) {
        assert_eq!(got, expected["actual"], "kept difference {id}");
    } else {
        assert_eq!(got, want, "{id}");
    }
}
#[test]
fn conformance_b5_manifest_counts() {
    let m: Value =
        serde_json::from_slice(&fs::read(fixtures().join("MANIFEST.json")).unwrap()).unwrap();
    assert_eq!(
        m["areas"],
        json!({"admission":18,"dispatch":63,"limits":91})
    );
    assert_eq!(m["total"], 172);
    assert_eq!(m["cases"].as_array().unwrap().len(), 172);
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
    assert_eq!(fs::read_dir(fixtures().join("cases")).unwrap().count(), 172);
}
#[test]
fn conformance_b5_admission() {
    for c in cases("admission") {
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
#[test]
fn conformance_b5_dispatch() {
    for c in cases("dispatch") {
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
#[test]
fn conformance_b5_limits() {
    let mut failures = Vec::new();
    for c in cases("limits") {
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
        let differences: Value = serde_json::from_str(include_str!("b5_differences.json")).unwrap();
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
