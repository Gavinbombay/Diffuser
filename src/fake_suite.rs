use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;

// The executable shim speaks newline-delimited JSON to a loopback fixture. The
// same fixture can answer health, job, chat and embedding operations.
pub(super) struct FakeWorker {
    address: std::net::SocketAddr,
    calls: Arc<Mutex<Vec<Value>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl FakeWorker {
    pub(super) fn new(health: Value, latency: Duration, failure: bool, responses: Value) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (seen, done) = (calls.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut line = String::new();
                        BufReader::new(stream.try_clone().unwrap())
                            .read_line(&mut line)
                            .unwrap();
                        let request: Value = serde_json::from_str(&line).unwrap();
                        let operation = request["operation"].as_str().unwrap();
                        let reply = if operation == "--health" {
                            health.clone()
                        } else {
                            seen.lock().unwrap().push(request.clone());
                            std::thread::sleep(latency);
                            json!({"fail":failure,"response":responses[operation]})
                        };
                        writeln!(stream, "{reply}").unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fixture listener: {e}"),
                }
            }
        });
        Self {
            address,
            calls,
            stop,
            thread: Some(thread),
        }
    }
    pub(super) fn executable(&self, path: &Path) {
        let script = format!(
            r##"#!/usr/bin/python3
import hashlib, io, json, pathlib, socket, sys, wave
operation = sys.argv[1]
spec = json.loads(pathlib.Path(sys.argv[2]).read_text()) if operation == '--spec' else (json.load(sys.stdin) if operation != '--health' else None)
with socket.create_connection(('127.0.0.1', {port})) as conn:
    conn.sendall((json.dumps({{'operation': operation, 'spec': spec}}) + '\n').encode())
    reply = json.loads(conn.makefile().readline())
if operation == '--health':
    print(json.dumps(reply))
elif reply['fail']:
    sys.exit(1)
elif operation == '--spec':
    out = pathlib.Path(spec['out']); out.mkdir(parents=True)
    name = 'frame-' + str(spec.get('frames', 'result')).replace(',', '-') + '.bin'
    data = name.encode()
    if spec.get('lane') in ('tts', 'music-sfx'):
        name = 'speech.wav' if spec['lane'] == 'tts' else 'audio.wav'
        buffer = io.BytesIO()
        with wave.open(buffer, 'wb') as audio:
            audio.setnchannels(1); audio.setsampwidth(2); audio.setframerate(spec.get('sample_rate', 24000)); audio.writeframes(bytes(2))
        data = buffer.getvalue()
    (out / name).write_bytes(data)
    (out / 'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
else:
    print(json.dumps(reply['response']))
"##,
            port = self.address.port()
        );
        fs::write(path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        crate::command_policy::fixture_allow(path);
    }
}
impl Drop for FakeWorker {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn commercial_license_gate_real_admission() {
    if std::env::var_os("LICENCE_TEST_CHILD").is_none() {
        let status = crate::test_process::command()
            .args([
                "--exact",
                "fake_suite::commercial_license_gate_real_admission",
            ])
            .env("LICENCE_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "licence-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let files = root.join("files");
    fs::create_dir_all(&files).unwrap();
    fs::write(files.join("weights"), b"abc").unwrap();
    let manifest = root.join("input.json");
    fs::write(&manifest, serde_json::to_vec(&json!({"id":"voice","lane":"tts","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
    let store_root = root.join("store");
    let hash = store::install(&store_root, &manifest, &files).unwrap();
    store::swap(&store_root, "tts", &hash).unwrap();
    let worker = FakeWorker::new(
        json!({"accepting":true,"proof":{"pass":true},"vram_mb":16,"ram_mb":16,"backends":["cpu"]}),
        Duration::ZERO,
        false,
        json!({}),
    );
    let executable = root.join("worker");
    worker.executable(&executable);
    let registry = root.join("workers.cfg");
    fs::write(&registry, serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":["tts"],"kind":"exec","exec":executable,"seats":1,"enabled":true}]})).unwrap()).unwrap();
    let auth_dir = root.join("auth");
    fs::create_dir_all(&auth_dir).unwrap();
    fs::write(
        auth_dir.join("tts.sha256"),
        hex::encode(Sha256::digest(b"<TOKEN>")),
    )
    .unwrap();
    std::env::set_var("LANE_REGISTRY", registry);
    std::env::set_var("LANE_TOKEN_SHA_DIR", auth_dir);
    let spec = json!({"spec":"job-spec/v1","job_id":"job-123","lane":"tts","cartridge":"voice","use":"internal","card_pref":["local-3060"],"items":[{"id":"one","args":[]}],"entry":"run","seg_min":1,"deadline_min":10,"max_segs":1,"outputs":"worker:/var/lib/diffuser/jobs/job-123/out"});
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for (config, expected) in [(json!({"lanes":{"tts":true}}), StatusCode::CONFLICT), (json!({"lanes":{"tts":true},"require_commercial":false}), StatusCode::ACCEPTED)] {
            let app = App { st: Arc::new(Mutex::new(JobTable::default())), compat: crate::lane_gate::fixture_config(config, "tts", "voice"), store_root: store_root.clone(), cards: Arc::new(Mutex::new(HashMap::new())), clock: clock_now };
            let mut headers = HeaderMap::new(); headers.insert("authorization", "Bearer <TOKEN>".parse().unwrap());
            let response = h_submit(State(app), AxPath("tts".into()), headers, serde_json::to_vec(&spec).unwrap().into()).await;
            assert_eq!(response.status(), expected);
        }
        let floor = root.join("cu-floor.txt"); fs::write(&floor, "5").unwrap();
        let config = json!({"lanes":{"tts":true},"require_commercial":false,"cu_balance":20,"cu_floor_path":floor,"jobs_dir":root.join("jobs")});
        let app = App { st: Arc::new(Mutex::new(JobTable::default())), compat: crate::lane_gate::fixture_config(config, "tts", "voice"), store_root: store_root.clone(), cards: Arc::new(Mutex::new(HashMap::new())), clock: clock_now };
        let mut budgeted = spec.clone(); budgeted["budget_cu"] = json!(2);
        let mut headers = HeaderMap::new(); headers.insert("authorization", "Bearer <TOKEN>".parse().unwrap());
        let response = h_submit(State(app.clone()), AxPath("tts".into()), headers, serde_json::to_vec(&budgeted).unwrap().into()).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let table = app.st.lock().unwrap();
        assert_eq!(table.agent_queue, ["job-123"]);
        assert_eq!(table.leases.snapshot("job-123").unwrap().phase, segment_lifecycle::Phase::Queued);
        drop(table);
        let ledger = fs::read_to_string(root.join("jobs/job-123/cu.csv")).unwrap();
        assert!(ledger.contains("ts,job_id,segment,event,balance,delta,floor,gpu_class,reason"));
        assert!(ledger.contains("\"job-123\",0,\"admit\",20,0,5"));
    });
}

#[test]
fn suite_a_split_capacity_and_bake() {
    if std::env::var_os("SUITE_A_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", "fake_suite::suite_a_split_capacity_and_bake"])
            .env("SUITE_A_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "suite-a-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let files = root.join("files");
    fs::create_dir_all(&files).unwrap();
    fs::write(files.join("weights"), b"abc").unwrap();
    let manifest = root.join("cart.json");
    fs::write(&manifest, serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":3,"min_vram_mb":8,"min_ram_mb":8,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
    let blend = root.join("scene.blend");
    fs::write(&blend, b"fixture").unwrap();
    let health = |vram| json!({"accepting":true,"proof":{"pass":true},"cartridges":["blender-4.5.14-cycles"],"vram_mb":vram,"ram_mb":16,"backends":["cpu"],"job_types":["bake-render"]});
    let small = FakeWorker::new(health(1), Duration::ZERO, false, json!({}));
    let first = FakeWorker::new(health(16), Duration::ZERO, false, json!({}));
    let second = FakeWorker::new(health(16), Duration::ZERO, false, json!({}));
    let workers = [&small, &first, &second];
    let mut rows = Vec::new();
    for (i, worker) in workers.iter().enumerate() {
        let path = root.join(format!("worker-{i}"));
        worker.executable(&path);
        rows.push(json!({"id":format!("worker-{i}"),"lanes":["render-blender"],"kind":"exec","exec":path,"seats":1,"enabled":true}));
    }
    let registry = root.join("workers.cfg");
    fs::write(
        &registry,
        serde_json::to_vec(&json!({"workers":rows})).unwrap(),
    )
    .unwrap();
    std::env::set_var("LANE_ROUTER_HOME", &root);
    std::env::set_var("LANE_REGISTRY", &registry);
    let state = Arc::new(Mutex::new(JobTable::default()));
    let mut spec = json!({"lane":"render-blender","blend":blend,"frames":"1-4","job_id":"split","out":root.join("split"),"cartridge_manifest":manifest,"cartridge_directory":files});
    let result = run_job(
        state.clone(),
        spec.clone(),
        spec.to_string().into_bytes(),
        false,
    );
    assert_eq!(result["state"], "done", "{result}");
    assert_eq!(result["chunks"].as_array().unwrap().len(), 2);
    assert!(small.calls.lock().unwrap().is_empty());
    assert_eq!(first.calls.lock().unwrap().len(), 1);
    assert_eq!(second.calls.lock().unwrap().len(), 1);
    let sums = fs::read_to_string(root.join("split/SHA256SUMS")).unwrap();
    assert_eq!(sums.lines().count(), 2);
    for line in sums.lines() {
        let (hash, file) = line.split_once("  ").unwrap();
        assert_eq!(sha256_file(&root.join("split").join(file)).unwrap(), hash);
    }
    spec["type"] = json!("bake-render");
    spec["job_id"] = json!("bake");
    spec["out"] = json!(root.join("bake"));
    spec["frames"] = json!("1,4");
    spec["steps"] = json!(["bake", "render"]);
    let baked = run_job(
        state.clone(),
        spec.clone(),
        spec.to_string().into_bytes(),
        false,
    );
    assert_eq!(baked["state"], "done", "{baked}");
    assert_eq!(baked["chunks"].as_array().unwrap().len(), 1);
    let calls = first.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1]["spec"]["frames"], spec["frames"]);
    assert_eq!(calls[1]["spec"]["steps"], spec["steps"]);
    assert_eq!(calls[1]["spec"]["job_id"], "bake");
    drop(calls);
    assert_eq!(second.calls.lock().unwrap().len(), 1);
    // A failing whole job is never retried on the other worker.
    drop(first);
    let failing = FakeWorker::new(health(16), Duration::ZERO, true, json!({}));
    failing.executable(&root.join("worker-1"));
    spec["job_id"] = json!("bake-fail");
    spec["out"] = json!(root.join("bake-fail"));
    let failed = run_job(state, spec.clone(), spec.to_string().into_bytes(), false);
    assert_eq!(failed["state"], "failed");
    assert_eq!(failing.calls.lock().unwrap().len(), 1);
    assert_eq!(second.calls.lock().unwrap().len(), 1);
}

#[test]
fn suite_b_c_refusal_retry_and_swap() {
    if std::env::var_os("SUITE_B_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", "fake_suite::suite_b_c_refusal_retry_and_swap"])
            .env("SUITE_B_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = std::env::temp_dir().join(format!(
        "suite-b-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let files = root.join("source");
    fs::create_dir_all(&files).unwrap();
    let manifest = root.join("input.json");
    let store_root = root.join("cartridges");
    let install = |bytes: &[u8]| {
        fs::write(files.join("weights"), bytes).unwrap();
        fs::write(&manifest, serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":bytes.len(),"min_vram_mb":8,"min_ram_mb":8,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(bytes))}})).unwrap()).unwrap();
        store::install(&store_root, &manifest, &files).unwrap()
    };
    let first_digest = install(b"abc");
    let second_digest = install(b"def");
    store::swap(&store_root, "render-blender", &first_digest).unwrap();
    let blend = root.join("scene.blend");
    fs::write(&blend, b"fixture").unwrap();
    let registry = root.join("workers.cfg");
    std::env::set_var("LANE_ROUTER_HOME", &root);
    std::env::set_var("LANE_REGISTRY", &registry);
    let row = |id: &str| json!({"id":id,"lanes":["render-blender"],"kind":"exec","exec":root.join(id),"seats":1,"enabled":true});
    let health = |accepting, vram: Value| json!({"accepting":accepting,"proof":{"pass":true},"cartridges":["blender-4.5.14-cycles"],"vram_mb":vram,"ram_mb":16,"backends":["cpu"]});
    let state = Arc::new(Mutex::new(JobTable::default()));
    let mut spec = json!({"lane":"render-blender","blend":blend,"frames":"1-1","job_id":"original","out":root.join("out"),"split_across_workers":false});
    for (index, caps) in [
        health(false, json!(16)),
        health(true, Value::Null),
        health(true, json!(-1)),
    ]
    .into_iter()
    .enumerate()
    {
        let worker = FakeWorker::new(caps, Duration::ZERO, false, json!({}));
        worker.executable(&root.join("refused"));
        fs::write(
            &registry,
            serde_json::to_vec(&json!({"workers":[row("refused")]})).unwrap(),
        )
        .unwrap();
        let mut admission = spec.clone();
        select_manifest(&mut admission, &store_root).unwrap();
        assert!(
            plan(&admission, &state)
                .unwrap_err()
                .starts_with("no accepting worker for"),
            "case {index}"
        );
        let response = tokio::runtime::Runtime::new().unwrap().block_on(async {
            let auth_dir = root.join("auth");
            fs::create_dir_all(&auth_dir).unwrap();
            fs::write(
                auth_dir.join("render-blender.sha256"),
                hex::encode(Sha256::digest(b"<TOKEN>")),
            )
            .unwrap();
            std::env::set_var("LANE_TOKEN_SHA_DIR", auth_dir);
            let mut headers = HeaderMap::new();
            headers.insert("authorization", "Bearer <TOKEN>".parse().unwrap());
            h_submit(
                State(App {
                    st: state.clone(),
                    compat: json!({}),
                    store_root: store_root.clone(),
                    cards: Arc::new(Mutex::new(HashMap::new())),
                    clock: clock_now,
                }),
                AxPath("render-blender".into()),
                headers,
                spec.to_string().into(),
            )
            .await
        });
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(worker.calls.lock().unwrap().is_empty());
    }
    let failing = FakeWorker::new(
        health(true, json!(16)),
        Duration::from_millis(400),
        true,
        json!({}),
    );
    let alternate = FakeWorker::new(health(true, json!(16)), Duration::ZERO, false, json!({}));
    failing.executable(&root.join("first"));
    alternate.executable(&root.join("alternate"));
    fs::write(
        &registry,
        serde_json::to_vec(&json!({"workers":[row("first"),row("alternate")]})).unwrap(),
    )
    .unwrap();
    let work_state = state.clone();
    let work_spec = spec.clone();
    let job = std::thread::spawn(move || {
        run_job(
            work_state,
            work_spec.clone(),
            work_spec.to_string().into_bytes(),
            false,
        )
    });
    for _ in 0..200 {
        if !failing.calls.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(failing.calls.lock().unwrap().len(), 1);
    store::swap(&store_root, "render-blender", &second_digest).unwrap();
    let result = job.join().unwrap();
    assert_eq!(result["state"], "done", "{result}");
    let stored = result_store::Store::new(
        &root.join("results"),
        result_store::Config {
            legacy_paths: true,
            ..Default::default()
        },
    );
    let served = artifact_routes::read(
        &stored,
        "render-blender",
        "original",
        Some(result["artifacts"][0]["path"].as_str().unwrap()),
        clock_now(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&served.bytes)),
        result["artifacts"][0]["sha256"]
    );
    assert_eq!(result["cartridge_manifest_sha256"], first_digest);
    assert_eq!(result["chunks"][0]["retry_of"], "first");
    for worker in [&failing, &alternate] {
        let calls = worker.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["spec"]["job_id"], "original");
        assert_eq!(calls[0]["spec"]["cartridge_manifest_sha256"], first_digest);
    }
    // Change the retry worker after planning while the first attempt is running.
    let bad = FakeWorker::new(health(true, json!(1)), Duration::ZERO, false, json!({}));
    let mut retry_spec = spec.clone();
    retry_spec["job_id"] = json!("guarded");
    retry_spec["out"] = json!(root.join("guarded"));
    let work_state = state.clone();
    let job = std::thread::spawn(move || {
        run_job(
            work_state,
            retry_spec.clone(),
            retry_spec.to_string().into_bytes(),
            false,
        )
    });
    for _ in 0..200 {
        if failing.calls.lock().unwrap().len() == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(failing.calls.lock().unwrap().len(), 2);
    bad.executable(&root.join("alternate"));
    let refused = job.join().unwrap();
    assert_eq!(refused["state"], "failed");
    assert!(bad.calls.lock().unwrap().is_empty());
    assert_eq!(alternate.calls.lock().unwrap().len(), 1);
    alternate.executable(&root.join("alternate"));
    spec["job_id"] = json!("next");
    spec["out"] = json!(root.join("next"));
    spec["prefer"] = json!(["alternate"]);
    let next = run_job(state, spec.clone(), spec.to_string().into_bytes(), false);
    assert_eq!(next["state"], "done", "{next}");
    assert_eq!(next["cartridge_manifest_sha256"], second_digest);
    assert_eq!(
        alternate.calls.lock().unwrap()[1]["spec"]["cartridge_manifest_sha256"],
        second_digest
    );
}

#[test]
fn concurrent_http_submissions_and_compat_routes() {
    if std::env::var_os("CONCURRENT_CHILD").is_none() {
        let status = crate::test_process::command()
            .args([
                "--exact",
                "fake_suite::concurrent_http_submissions_and_compat_routes",
            ])
            .env("CONCURRENT_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    use std::io::Read;
    let root = std::env::temp_dir().join(format!(
        "concurrent-http-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let files = root.join("files");
    let auth_dir = root.join("auth");
    fs::create_dir_all(&files).unwrap();
    fs::create_dir_all(&auth_dir).unwrap();
    fs::write(files.join("weights"), b"abc").unwrap();
    fs::write(
        auth_dir.join("diffusion-video.sha256"),
        hex::encode(Sha256::digest(b"<TOKEN>")),
    )
    .unwrap();
    let manifest = root.join("cart.json");
    fs::write(&manifest, serde_json::to_vec(&json!({"id":"fixture","lane":"diffusion-video","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
    let worker = FakeWorker::new(
        json!({"accepting":true,"proof":{"pass":true},"vram_mb":8,"ram_mb":8,"backends":["cpu"]}),
        Duration::from_millis(100),
        false,
        json!({"--chat":{"content":"answer","model":"fixture",(crate::error_catalog::USAGE):{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}),
    );
    let second = FakeWorker::new(
        json!({"accepting":true,"proof":{"pass":true},"vram_mb":8,"ram_mb":8,"backends":["cpu"]}),
        Duration::from_millis(100),
        false,
        json!({"--chat":{"content":"answer","model":"fixture",(crate::error_catalog::USAGE):{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}}),
    );
    let executable = root.join("worker.py");
    worker.executable(&executable);
    let executable2 = root.join("worker2.py");
    second.executable(&executable2);
    let workers = root.join("workers.cfg");
    fs::write(&workers, serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":["diffusion-video"],"kind":"exec","exec":executable,"seats":1,"enabled":true},{"id":"second","lanes":["diffusion-video"],"kind":"exec","exec":executable2,"seats":1,"enabled":true}]})).unwrap()).unwrap();
    std::env::set_var("LANE_ROUTER_HOME", &root);
    std::env::set_var("LANE_REGISTRY", &workers);
    std::env::set_var("LANE_TOKEN_SHA_DIR", &auth_dir);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let addr = listener.local_addr().unwrap();
        let app = router_with_compat(crate::lane_gate::fixture_config(json!({"lanes":{"diffusion-video":true},"routes":{"/v1/chat/completions":"diffusion-video"}}), "diffusion-video", "fixture"));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut tasks = Vec::new();
        for i in 0..20 {
            let spec = if i >= 16 { json!({"model":"fixture","messages":[{"role":"user","content":"hello"}]}) } else {
                json!({"out":root.join(format!("out-{i}")),"loop":true,"cartridge":"fixture","cartridge_manifest":manifest,"cartridge_directory":files,"job_id":if i < 8 { "same".to_string() } else { format!("job-{i}") }})
            };
            tasks.push(tokio::task::spawn_blocking(move || {
                let path = if i >= 16 { "/v1/chat/completions" } else { "/v1/lanes/diffusion-video/jobs" };
                let data = spec.to_string(); let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{data}", data.len()).unwrap();
                let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); (i, reply)
            }));
        }
        let mut accepted = Vec::new();
        for task in tasks {
            let (i, reply) = task.await.unwrap();
            if i < 16 && reply.starts_with("HTTP/1.1 202") { accepted.push(i); }
            else if i < 16 { assert!(reply.starts_with("HTTP/1.1 409"), "{reply}"); }
            else { assert!(reply.starts_with("HTTP/1.1 200") || reply.starts_with("HTTP/1.1 409"), "{reply}"); }
        }
        assert!(!accepted.is_empty());
        assert!(accepted.iter().filter(|i| **i < 8).count() <= 1);
        for _ in 0..200 {
            {
            let calls = worker.calls.lock().unwrap();
            let other_calls = second.calls.lock().unwrap();
            let job_calls: Vec<_> = calls.iter().chain(other_calls.iter()).filter(|c| c["operation"] == "--spec").collect();
            let mut ids = std::collections::HashSet::new();
            for call in &job_calls { assert!(ids.insert(call["spec"]["job_id"].as_str().unwrap().to_string())); }
            }
            if accepted.iter().all(|i| {
                let id = if *i < 8 { "same".to_string() } else { format!("job-{i}") };
                fs::read(root.join("jobs").join(format!("{id}.json"))).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).is_some_and(|v| ["done", "failed"].contains(&v["state"].as_str().unwrap_or("")))
            }) { break; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for i in &accepted {
            let id = if *i < 8 { "same".to_string() } else { format!("job-{i}") };
            let value: Value = serde_json::from_slice(&fs::read(root.join("jobs").join(format!("{id}.json"))).unwrap()).unwrap();
            assert!(["done", "failed"].contains(&value["state"].as_str().unwrap_or("")), "{value}");
        }
        let first = accepted[0];
        let id = if first < 8 { "same".to_string() } else { format!("job-{first}") };
        let duplicate = json!({"out":root.join("duplicate"),"loop":true,"cartridge":"fixture","cartridge_manifest":manifest,"cartridge_directory":files,"job_id":id}).to_string();
        let reply = tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            write!(stream, "POST /v1/lanes/diffusion-video/jobs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{duplicate}", duplicate.len()).unwrap();
            let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
        }).await.unwrap();
        assert!(reply.starts_with("HTTP/1.1 409") && reply.contains("job_id exists"), "{reply}");
        server.abort();
    });
}
