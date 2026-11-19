/// Test scripts are written then exec'd while other test threads fork. A fork that lands
/// between the script's open-for-write and close inherits the write fd, so exec fails with
/// ETXTBSY ("Text file busy") until that child execs. Wait until exec no longer reports it.
pub(super) fn wait_exec_ready(path: &std::path::Path) {
    crate::command_policy::fixture_allow(path);
    for _ in 0..400 {
        match Command::new(path)
            .arg("--health")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(5))
            }
            _ => return,
        }
    }
    panic!("script still busy after 2 s: {}", path.display());
}
use super::*;
#[test]
fn opened_lanes_http_end_to_end() {
    if std::env::var_os("OPENED_TEST_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", "tests::opened_lanes_http_end_to_end"])
            .env("OPENED_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = crate::test_process::target_dir().join(format!(
        "opened-{}-{}",
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
    let worker = root.join("worker.py");
    let fixture = crate::fake_suite::FakeWorker::new(
        json!({"accepting":true,"proof":{"pass":true},"vram_mb":8,"ram_mb":8,"backends":["cpu"]}),
        Duration::ZERO,
        false,
        json!({}),
    );
    fixture.executable(&worker);
    let lanes = ["diffusion-image", "tts", "stt", "music-sfx"];
    for lane in lanes {
        fs::write(
            auth_dir.join(format!("{lane}.sha256")),
            hex::encode(Sha256::digest(b"<TOKEN>")),
        )
        .unwrap();
    }
    let workers = root.join("workers.cfg");
    fs::write(&workers, serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":lanes,"kind":"exec","exec":worker,"seats":1,"enabled":true}]})).unwrap()).unwrap();
    std::env::set_var("LANE_ROUTER_HOME", &root);
    std::env::set_var("LANE_REGISTRY", &workers);
    std::env::set_var("LANE_TOKEN_SHA_DIR", &auth_dir);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
            use std::io::{Read, Write};
            for (lane, field) in [("diffusion-image", "prompt"), ("tts", "text"), ("stt", "audio"), ("music-sfx", "prompt")] {
                let manifest = root.join(format!("{lane}.json"));
                fs::write(&manifest, serde_json::to_vec(&json!({"id":lane,"lane":lane,"size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let addr = listener.local_addr().unwrap();
                let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(lane_gate::fixture_config(json!({"lanes":{lane:true}}), lane, lane))).await.unwrap() });
                let request = move |body: String| { let mut stream = std::net::TcpStream::connect(addr).unwrap();
                    write!(stream, "POST /v1/lanes/{lane}/jobs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                    let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply };
                let out = root.join(format!("out-{lane}"));
                let mut spec = json!({"out":out,"cartridge":lane,"cartridge_manifest":manifest,"cartridge_directory":files,"job_id":lane}); spec[field] = json!("fixture"); if lane == "music-sfx" { spec["duration_seconds"] = json!(30); }
                let reply = tokio::task::spawn_blocking({ let spec = spec.clone(); move || request(spec.to_string()) }).await.unwrap(); assert!(reply.starts_with("HTTP/1.1 202"), "{reply}");
                for _ in 0..100 { if out.join("manifest.json").exists() { break; } tokio::time::sleep(Duration::from_millis(50)).await; }
                let result: Value = serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
                assert_eq!(result["state"], "done"); let expected = match lane { "tts" => fs::read(out.join("speech.wav")).unwrap(), "music-sfx" => fs::read(out.join("audio.wav")).unwrap(), _ => b"frame-result.bin".to_vec() };
                assert_eq!(result["artifacts"][0]["sha256"], hex::encode(Sha256::digest(&expected)));
                let status = tokio::task::spawn_blocking(move || {
                    let mut stream = std::net::TcpStream::connect(addr).unwrap();
                    write!(stream, "GET /v1/lanes/{lane}/jobs/{lane} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nConnection: close\r\n\r\n").unwrap();
                    let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
                }).await.unwrap();
                assert!(status.starts_with("HTTP/1.1 200"), "{status}");
                let body: Value = serde_json::from_str(status.split_once("\r\n\r\n").unwrap().1).unwrap();
                assert_eq!(body["job_id"], lane);
                spec[field] = json!(""); spec["out"] = json!(root.join("unused"));
                let reply = tokio::task::spawn_blocking(move || request(spec.to_string())).await.unwrap(); assert!(reply.starts_with("HTTP/1.1 422"), "{reply}");
                let reply = tokio::task::spawn_blocking(move || request("{".into())).await.unwrap(); assert!(reply.starts_with("HTTP/1.1 422"), "{reply}");
                server.abort();
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let addr = listener.local_addr().unwrap();
                let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(json!({"lanes":{lane:false}}))).await.unwrap() });
                let reply = tokio::task::spawn_blocking(move || { let mut stream = std::net::TcpStream::connect(addr).unwrap(); write!(stream, "POST /v1/lanes/{lane}/jobs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").unwrap(); let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply }).await.unwrap();
                assert!(reply.starts_with("HTTP/1.1 409"), "{reply}"); server.abort();
            }
        });
}
#[test]
fn video_http_end_to_end() {
    use std::os::unix::fs::PermissionsExt;
    if std::env::var_os("VIDEO_TEST_CHILD").is_none() {
        let result = crate::test_process::command()
            .args(["--exact", "tests::video_http_end_to_end", "--nocapture"])
            .env("VIDEO_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(result.success());
        return;
    }
    let root = crate::test_process::target_dir().join(format!(
        "video-{}-{}",
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
    fs::write(&manifest, serde_json::to_vec(&json!({"id":"video-fixture","lane":"diffusion-video","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
    let worker = root.join("worker.py");
    fs::write(&worker, r##"#!/usr/bin/python3
import json, sys, pathlib, hashlib
if sys.argv[1] == '--health':
    print(json.dumps({'accepting': True, 'proof': {'pass': True}, 'lane': 'diffusion-video', 'vram_mb': 8, 'ram_mb': 8, 'backends': ['cpu']}))
else:
    spec = json.loads(pathlib.Path(sys.argv[2]).read_text())
    assert spec['width'] == 832 and spec['height'] == 480 and spec['loop'] is True
    out = pathlib.Path(spec['out'])
    out.mkdir(parents=True)
    data = b'video fixture'
    (out / 'manifest.json').write_text(json.dumps({'frames': spec['frames']}))
    (out / 'manifest.json').write_text(json.dumps({'frames': spec['frames']}))
    (out / 'clip.bin').write_bytes(data)
    (out / 'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest() + '  clip.bin\n')
"##).unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    wait_exec_ready(&worker);
    let workers = root.join("workers.cfg");
    fs::write(&workers, serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":["diffusion-video"],"kind":"exec","exec":worker,"seats":1,"enabled":true}]})).unwrap()).unwrap();
    std::env::set_var("LANE_ROUTER_HOME", &root);
    std::env::set_var("LANE_REGISTRY", &workers);
    std::env::set_var("LANE_TOKEN_SHA_DIR", &auth_dir);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
            use std::io::{Read, Write};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let app = router_with_compat(lane_gate::fixture_config(json!({"lanes":{"diffusion-video":true}}), "diffusion-video", "video-fixture"));
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let request = move |body: Value| {
                let data = body.to_string();
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "POST /v1/lanes/diffusion-video/jobs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", data.len(), data).unwrap();
                let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
            };
            let out = root.join("out");
            let spec = json!({"out":out,"loop":true,"cartridge":"video-fixture","cartridge_manifest":manifest,"cartridge_directory":files,"job_id":"video-test"});
            let reply = tokio::task::spawn_blocking({ let spec = spec.clone(); move || request(spec) }).await.unwrap();
            assert!(reply.starts_with("HTTP/1.1 202"), "{reply}");
            for _ in 0..100 {
                if out.join("manifest.json").exists() { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let result: Value = serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
            assert_eq!(result["state"], "done");
            assert_eq!(result["artifacts"][0]["sha256"], hex::encode(Sha256::digest(b"video fixture")));
            assert_eq!(sha256_file(&out.join("clip.bin")).unwrap(), result["artifacts"][0]["sha256"]);
            let stored=result_store::Store::new(&root.join("results"),result_store::Config{legacy_paths:true,..Default::default()});
            let served=artifact_routes::read(&stored,"diffusion-video","video-test",Some("clip.bin"),clock_now()).unwrap();assert_eq!(served.bytes,b"video fixture");

            for (field, value) in [("width", json!(831)), ("height", json!("480")), ("loop", json!(1))] {
                let mut bad = spec.clone(); bad[field] = value; bad["out"] = json!(root.join("unused"));
                let reply = tokio::task::spawn_blocking(move || request(bad)).await.unwrap();
                assert!(reply.starts_with("HTTP/1.1 422"), "{reply}");
                assert!(reply.contains("error"));
            }
            server.abort();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(json!({"lanes":{"diffusion-video":false}}))).await.unwrap() });
            let reply = tokio::task::spawn_blocking(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "POST /v1/lanes/diffusion-video/jobs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").unwrap();
                let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
            }).await.unwrap();
            assert!(reply.starts_with("HTTP/1.1 409") && reply.contains("lane disabled"), "{reply}");
            server.abort();
        });
}
#[test]
fn chat_refusals_over_both_http_paths() {
    if std::env::var_os("CHAT_TEST_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", "tests::chat_refusals_over_both_http_paths"])
            .env("CHAT_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = crate::test_process::target_dir().join(format!("chat-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("diffusion-video.sha256"),
        hex::encode(Sha256::digest(b"<TOKEN>")),
    )
    .unwrap();
    std::env::set_var("LANE_TOKEN_SHA_DIR", &root);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
            use std::io::{Read, Write};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = json!({"lanes":{"diffusion-video":true},"routes":{"/v1/chat/completions":"diffusion-video","/openai/v1/chat/completions":"diffusion-video"}});
            let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(config)).await.unwrap() });
            for path in ["/v1/chat/completions", "/openai/v1/chat/completions"] {
                for (body, status, field, expected) in [
                    (json!({"messages":[]}), 400, "error", "invalid_messages"),
                    (json!({"messages":[{"role":"user","content":" "}]}), 400, "error_code", crate::error_catalog::PROMPT_REQUIRED),
                    (json!({"messages":[{"role":"user","content":"hello"}],"stream":true}), 501, "error", "streaming is not supported"),
                ] {
                    let path = path.to_owned();
                    let reply = tokio::task::spawn_blocking(move || {
                        let data = body.to_string();
                        let mut stream = std::net::TcpStream::connect(addr).unwrap();
                        write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", data.len(), data).unwrap();
                        let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
                    }).await.unwrap();
                    assert!(reply.starts_with(&format!("HTTP/1.1 {status}")), "{reply}");
                    let value: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
                    assert_eq!(value[field], expected);
                }
            }
            server.abort();
        });
}
#[test]
fn chat_worker_over_both_http_paths() {
    use std::os::unix::fs::PermissionsExt;
    if std::env::var_os("CHAT_WORKER_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", "tests::chat_worker_over_both_http_paths"])
            .env("CHAT_WORKER_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root =
        crate::test_process::target_dir().join(format!("chat-worker-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("diffusion-video.sha256"),
        hex::encode(Sha256::digest(b"<TOKEN>")),
    )
    .unwrap();
    let worker = root.join("worker.py");
    fs::write(&worker, r##"#!/usr/bin/python3
import json, sys
if sys.argv[1] == '--health':
    print(json.dumps({'accepting': True, 'proof': {'pass': True}, 'lane': 'diffusion-video'}))
else:
    request = json.load(sys.stdin)
    assert sys.argv[1] == '--chat' and request['messages'][0]['content'] in ('hello', 'bad')
    if request['messages'][0]['content'] == 'bad':
        print('{}')
    else:
        print(json.dumps({'content': 'answer', 'model': request['model'], 'usage': {'prompt_tokens': 2, 'completion_tokens': 1, 'total_tokens': 3}}))
"##).unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    wait_exec_ready(&worker);
    let workers = root.join("workers.cfg");
    fs::write(&workers, serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":["diffusion-video"],"kind":"exec","exec":worker,"seats":1,"enabled":true}]})).unwrap()).unwrap();
    std::env::set_var("LANE_REGISTRY", workers);
    std::env::set_var("LANE_TOKEN_SHA_DIR", &root);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
            use std::io::{Read, Write};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let config = json!({"lanes":{"diffusion-video":true},"routes":{"/v1/chat/completions":"diffusion-video","/openai/v1/chat/completions":"diffusion-video"}});
            let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(config)).await.unwrap() });
            for path in ["/v1/chat/completions", "/openai/v1/chat/completions"] {
                for (content, status) in [("hello", 200), ("bad", 502)] {
                    let path = path.to_owned();
                    let reply = tokio::task::spawn_blocking(move || {
                        let data = json!({"model":"fixture-model","messages":[{"role":"user","content":content}]}).to_string();
                        let mut stream = std::net::TcpStream::connect(addr).unwrap();
                        write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", data.len(), data).unwrap();
                        let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
                    }).await.unwrap();
                    assert!(reply.starts_with(&format!("HTTP/1.1 {status}")), "{reply}");
                    let value: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
                    if status == 200 {
                        assert_eq!(value["object"], "chat.completion");
                        assert_eq!(value["model"], "fixture-model");
                        assert_eq!(value["choices"][0]["message"], json!({"role":"assistant","content":"answer"}));
                        assert_eq!(value["choices"][0]["finish_reason"], "stop");
                        assert_eq!(value[crate::error_catalog::USAGE], json!({"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}));
                    } else { assert_eq!(value["error"], "invalid chat worker response"); }
                }
            }
            server.abort();
        });
}
#[test]
fn embedding_worker_over_all_http_paths() {
    use std::os::unix::fs::PermissionsExt;
    if std::env::var_os("EMBED_WORKER_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", "tests::embedding_worker_over_all_http_paths"])
            .env("EMBED_WORKER_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root =
        crate::test_process::target_dir().join(format!("embed-worker-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("diffusion-video.sha256"),
        hex::encode(Sha256::digest(b"<TOKEN>")),
    )
    .unwrap();
    let worker = root.join("worker.py");
    fs::write(&worker, r##"#!/usr/bin/python3
import json, sys
if sys.argv[1] == '--health':
    print(json.dumps({'accepting': True, 'proof': {'pass': True}, 'lane': 'diffusion-video'}))
else:
    assert sys.argv[1] == '--embed'
    request = json.load(sys.stdin)
    value = request['input']
    values = value if isinstance(value, list) else [value]
    print(json.dumps({'embeddings': [[0.25, 0.5] for v in values], 'model': 'fixture', 'usage': {'prompt_tokens': len(values), 'total_tokens': len(values)}}))
"##).unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    wait_exec_ready(&worker);
    let workers = root.join("workers.cfg");
    fs::write(&workers, serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":["diffusion-video"],"kind":"exec","exec":worker,"seats":1,"enabled":true}]})).unwrap()).unwrap();
    std::env::set_var("LANE_REGISTRY", workers);
    std::env::set_var("LANE_TOKEN_SHA_DIR", &root);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
            use std::io::{Read, Write};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let paths = ["/v1/embeddings", "/openai/v1/embeddings", "/v1/embed", "/embed"];
            let routes: serde_json::Map<String, Value> = paths.iter().map(|p| (p.to_string(), json!("diffusion-video"))).collect();
            let config = json!({"lanes":{"diffusion-video":true},"routes":routes});
            let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(config)).await.unwrap() });
            for path in paths {
                for input in [json!("hello"), json!(["hello", "world"]), json!([])] {
                    let data = json!({"input":input}).to_string();
                    let reply = tokio::task::spawn_blocking(move || {
                        let mut stream = std::net::TcpStream::connect(addr).unwrap();
                        write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", data.len(), data).unwrap();
                        let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
                    }).await.unwrap();
                    let empty = input == json!([]);
                    assert!(reply.starts_with(if empty { "HTTP/1.1 422" } else { "HTTP/1.1 200" }), "{reply}");
                    let value: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
                    if !empty {
                        let count = input.as_array().map_or(1, Vec::len);
                        assert_eq!(value["model"], "fixture");
                        assert_eq!(value[crate::error_catalog::USAGE]["total_tokens"], count);
                        assert_eq!(value["uai"], json!({}));
                        if path.ends_with("embeddings") {
                            assert_eq!(value["object"], "list");
                            assert_eq!(value["data"].as_array().unwrap().len(), count);
                            for i in 0..count { assert_eq!(value["data"][i], json!({"object":"embedding","embedding":[0.25,0.5],"index":i})); }
                        } else if count == 1 { assert_eq!(value["embedding"], json!([0.25,0.5])); }
                        else { assert_eq!(value["embedding"], json!([[0.25,0.5],[0.25,0.5]])); }
                    }
                }
            }
            for (format, status) in [("base64", 200), ("other", 400)] {
                let reply = tokio::task::spawn_blocking(move || {
                    let data = json!({"input":"hello", "encoding_format":format}).to_string();
                    let mut stream = std::net::TcpStream::connect(addr).unwrap();
                    write!(stream, "POST /v1/embeddings HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", data.len(), data).unwrap();
                    let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
                }).await.unwrap();
                assert!(reply.starts_with(&format!("HTTP/1.1 {status}")), "{reply}");
                let value: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
                if status == 200 { assert_eq!(value["data"][0]["embedding"], "AACAPgAAAD8="); }
            }
            server.abort();
        });
}
#[test]
fn generate_http_end_to_end() {
    use std::os::unix::fs::PermissionsExt;
    if std::env::var_os("GENERATE_TEST_CHILD").is_none() {
        let result = crate::test_process::command()
            .args(["--exact", "tests::generate_http_end_to_end", "--nocapture"])
            .env("GENERATE_TEST_CHILD", "1")
            .status()
            .unwrap();
        assert!(result.success());
        return;
    }
    let root = crate::test_process::target_dir().join(format!(
        "generate-{}-{}",
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
    fs::write(&manifest, serde_json::to_vec(&json!({"id":"video-fixture","lane":"diffusion-video","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
    let worker = root.join("worker.py");
    fs::write(&worker, r##"#!/usr/bin/python3
import json, sys, pathlib, hashlib
if sys.argv[1] == '--health':
    print(json.dumps({'accepting': True, 'proof': {'pass': True}, 'lane': 'diffusion-video', 'vram_mb': 8, 'ram_mb': 8, 'backends': ['cpu']}))
else:
    spec = json.loads(pathlib.Path(sys.argv[2]).read_text())
    assert spec['width'] == 832 and spec['height'] == 480 and spec['loop'] is True
    out = pathlib.Path(spec['out'])
    out.mkdir(parents=True)
    data = b'video fixture'
    (out / 'manifest.json').write_text(json.dumps({'frames': spec['frames']}))
    (out / 'clip.bin').write_bytes(data)
    (out / 'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest() + '  clip.bin\n')
"##).unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    wait_exec_ready(&worker);
    let workers = root.join("workers.cfg");
    fs::write(&workers, serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":["diffusion-video"],"kind":"exec","exec":worker,"seats":1,"enabled":true}]})).unwrap()).unwrap();
    std::env::set_var("LANE_ROUTER_HOME", &root);
    std::env::set_var("LANE_REGISTRY", &workers);
    std::env::set_var("LANE_TOKEN_SHA_DIR", &auth_dir);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
            use std::io::{Read, Write};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let app = router_with_compat(lane_gate::fixture_config(json!({"lanes":{"diffusion-video":true},"routes":{"/v1/generate":"diffusion-video"}}), "diffusion-video", "video-fixture"));
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let request = move |body: Value| {
                let data = body.to_string();
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "POST /v1/generate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", data.len(), data).unwrap();
                let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
            };
            let out = root.join("out");
            let spec = json!({"out":out,"prompt":"fixture prompt","loop":true,"cartridge":"video-fixture","cartridge_manifest":manifest,"cartridge_directory":files,"job_id":"video-test"});
            let reply = tokio::task::spawn_blocking({ let spec = spec.clone(); move || request(spec) }).await.unwrap();
            assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
            let response: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(response["status"], "ok");
            assert_eq!(response["job"]["state"], "done");
            assert_eq!(response["job"]["artifacts"][0]["sha256"], hex::encode(Sha256::digest(b"video fixture")));
            for _ in 0..100 {
                if out.join("manifest.json").exists() { break; }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let result: Value = serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
            assert_eq!(result["state"], "done");
            assert_eq!(result["artifacts"][0]["sha256"], hex::encode(Sha256::digest(b"video fixture")));
            assert_eq!(sha256_file(&out.join("clip.bin")).unwrap(), result["artifacts"][0]["sha256"]);
            for (field, value) in [("width", json!(831)), ("height", json!("480")), ("loop", json!(1))] {
                let mut bad = spec.clone(); bad[field] = value; bad["out"] = json!(root.join("unused"));
                let reply = tokio::task::spawn_blocking(move || request(bad)).await.unwrap();
                assert!(reply.starts_with("HTTP/1.1 422"), "{reply}");
                assert!(reply.contains("error"));
            }
            for bad in [json!({}), json!({"prompt": " "}), json!([])] {
                let reply = tokio::task::spawn_blocking(move || request(bad)).await.unwrap();
                assert!(reply.starts_with("HTTP/1.1 422") && reply.contains("error"), "{reply}");
            }
            server.abort();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(json!({"lanes":{"diffusion-video":false},"routes":{"/v1/generate":"diffusion-video"}}))).await.unwrap() });
            let reply = tokio::task::spawn_blocking(move || {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "POST /v1/generate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").unwrap();
                let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
            }).await.unwrap();
            assert!(reply.starts_with("HTTP/1.1 409") && reply.contains("lane disabled"), "{reply}");
            server.abort();
        });
}
#[test]
fn compatibility_routes_use_configured_allowlist() {
    let paths = [
        "/v1/generate",
        "/v1/chat/completions",
        "/openai/v1/chat/completions",
        "/v1/embeddings",
        "/openai/v1/embeddings",
        "/v1/embed",
        "/embed",
        "/v1/models",
        "/openai/v1/models",
        "/models",
        "/api/v1/models",
        "/api/models",
        "/api/tags",
        "/v1/models/{id}",
    ];
    let mut config = json!({"lanes":{"custom-lane":true},"routes":{}});
    for path in paths {
        config["routes"][path] = json!("custom-lane");
        let actual = if path == "/v1/models/{id}" {
            "/v1/models/example"
        } else {
            path
        };
        assert_eq!(compat_lane(&config, actual).unwrap(), "custom-lane");
        config["lanes"]["custom-lane"] = json!(false);
        assert_eq!(compat_lane(&config, actual), Err(StatusCode::CONFLICT));
        config["routes"][path] = json!("absent");
        assert_eq!(compat_lane(&config, actual), Err(StatusCode::NOT_FOUND));
        config["lanes"]["custom-lane"] = json!(true);
    }
    assert_eq!(
        compat_lane(&Value::Null, "/v1/generate"),
        Err(StatusCode::NOT_FOUND)
    );
}

#[test]
fn embedding_input_validation() {
    for request in [
        json!({}),
        json!({"input":[]}),
        json!({"input":"  "}),
        json!({"input":["ok", ""]}),
        json!({"input":42}),
        json!({"input":vec!["x"; 33]}),
    ] {
        assert!(!embedding_input_valid(&request), "{request}");
    }
    for request in [
        json!({"input":"one"}),
        json!({"input":["one", "two"]}),
        json!({"text":"one"}),
        json!({"prompt":"one"}),
    ] {
        assert!(embedding_input_valid(&request), "{request}");
    }
    assert!(!embedding_input_valid(
        &json!({"text":"", "input":"fallback"})
    ));
}
#[tokio::test]
async fn catalog_aliases_report_active_configured_cartridges() {
    use std::io::{Read, Write};
    let root = crate::test_process::target_dir().join(format!(
        "catalog-{}-{}",
        std::process::id(),
        now_s()
    ));
    let source = root.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("weights"), b"abc").unwrap();
    let manifest = root.join("input.json");
    fs::write(&manifest, serde_json::to_vec(&json!({"id":"catalog-fixture","lane":"render-blender","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
    let store_root = root.join("store");
    let hash = store::install(&store_root, &manifest, &source).unwrap();
    store::swap(&store_root, "render-blender", &hash).unwrap();
    let paths = [
        "/v1/models",
        "/openai/v1/models",
        "/models",
        "/api/v1/models",
        "/api/models",
        "/api/tags",
        "/v1/models/catalog-fixture",
        "/v1/models/missing",
    ];
    let mut config = json!({"lanes":{"render-blender":true,"tts":false},"routes":{}});
    for path in paths {
        config["routes"][if path.starts_with("/v1/models/") {
            "/v1/models/{id}"
        } else {
            path
        }] = json!("render-blender");
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router_with_store(config, store_root))
            .await
            .unwrap()
    });
    let replies = tokio::task::spawn_blocking(move || {
        paths.map(|path| {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply
        })
    })
    .await
    .unwrap();
    for reply in &replies[..5] {
        assert!(reply.starts_with("HTTP/1.1 200"));
        let body: Value = serde_json::from_str(reply.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["object"], "list");
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        assert_eq!(body["data"][0]["id"], "catalog-fixture");
    }
    let tags: Value = serde_json::from_str(replies[5].split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert!(replies[5].starts_with("HTTP/1.1 200"));
    assert_eq!(tags["models"][0]["name"], "catalog-fixture");
    let row: Value = serde_json::from_str(replies[6].split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert!(replies[6].starts_with("HTTP/1.1 200"));
    assert_eq!(row["id"], "catalog-fixture");
    let missing: Value =
        serde_json::from_str(replies[7].split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert!(replies[7].starts_with("HTTP/1.1 404"));
    assert_eq!(
        missing["error"]["code"],
        crate::error_catalog::MODEL_NOT_FOUND
    );
    server.abort();
}
#[tokio::test]
async fn unknown_paths_and_unsupported_methods_return_json() {
    use std::io::{Read, Write};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router_with_compat(json!({})))
            .await
            .unwrap()
    });
    let replies = tokio::task::spawn_blocking(move || {
            [("GET", "/missing?query=1"), ("POST", "/missing"), ("DELETE", "/v1/models"), ("GET", "/v1/generate"), ("PATCH", "/openai/v1/files/example")].map(|(method, path)| {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap();
                let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
            })
        }).await.unwrap();
    for reply in &replies[..2] {
        assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
        let body: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body, json!({"status":"not_found", "path":"/missing"}));
    }
    for (reply, method) in replies[2..].iter().zip(["DELETE", "GET", "PATCH"]) {
        assert!(reply.starts_with("HTTP/1.1 405"), "{reply}");
        let body: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body,
            json!({"status":"method_not_allowed", "detail":"method not allowed", "method":method})
        );
    }
    server.abort();
}
#[tokio::test]
async fn compatibility_refusals_are_json_over_http() {
    use std::io::{Read, Write};
    let config = json!({"lanes":{"disabled":false},"routes":{
            "/v1/generate":"disabled", "/v1/embed":"absent"}});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router_with_compat(config))
            .await
            .unwrap()
    });
    let replies = tokio::task::spawn_blocking(move || {
            ["/v1/generate", "/v1/embed"].map(|path| {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                reply
            })
        }).await.unwrap();
    assert!(replies[0].starts_with("HTTP/1.1 409"));
    assert!(replies[0].contains("\"error\":\"lane disabled\""));
    assert!(replies[1].starts_with("HTTP/1.1 404"));
    assert!(replies[1].contains("\"error\":\"unknown lane\""));
    server.abort();
}
#[test]
fn compatibility_error_and_auth_families_over_http() {
    if std::env::var_os("ERROR_FAMILIES_CHILD").is_none() {
        let status = crate::test_process::command()
            .args([
                "--exact",
                "tests::compatibility_error_and_auth_families_over_http",
            ])
            .env("ERROR_FAMILIES_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = crate::test_process::target_dir().join(format!("errors-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("diffusion-video.sha256"),
        hex::encode(Sha256::digest(b"<TOKEN>")),
    )
    .unwrap();
    std::env::set_var("LANE_TOKEN_SHA_DIR", &root);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
            use std::io::{Read, Write};
            let paths = ["/v1/generate", "/v1/chat/completions", "/openai/v1/chat/completions", "/v1/embeddings", "/openai/v1/embeddings", "/v1/embed", "/embed"];
            let mut config = json!({"lanes":{"diffusion-video":true},"routes":{}});
            for path in paths { config["routes"][path] = json!("diffusion-video"); }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(config)).await.unwrap() });
            for path in paths {
                for (credential, payload, expected, message) in [
                    ("", "{}", 401, "bad token"),
                    ("Authorization: Bearer [R]\r\n", "{}", 401, "bad token"),
                    ("Authorization: Bearer <TOKEN>\r\n", "{", if path.contains("chat/") { 400 } else { 422 }, "invalid JSON"),
                ] {
                    let path = path.to_owned();
                    let reply = tokio::task::spawn_blocking(move || {
                        let mut stream = std::net::TcpStream::connect(addr).unwrap();
                        write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\n{credential}Content-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len()).unwrap();
                        let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
                    }).await.unwrap();
                    assert!(reply.starts_with(&format!("HTTP/1.1 {expected}")), "{reply}");
                    let body: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
                    assert_eq!(body, json!({"error":message}));
                }
            }
            server.abort();
            for (enabled, expected, message) in [(false, 409, "lane disabled"), (true, 404, "unknown lane")] {
                let mut config = json!({"lanes":{"diffusion-video":enabled},"routes":{}});
                for path in paths { config["routes"][path] = json!(if enabled { "absent" } else { "diffusion-video" }); }
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server = tokio::spawn(async move { axum::serve(listener, router_with_compat(config)).await.unwrap() });
                for path in paths {
                    let reply = tokio::task::spawn_blocking(move || {
                        let mut stream = std::net::TcpStream::connect(addr).unwrap();
                        write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        let mut reply = String::new(); stream.read_to_string(&mut reply).unwrap(); reply
                    }).await.unwrap();
                    assert!(reply.starts_with(&format!("HTTP/1.1 {expected}")), "{reply}");
                    let body: Value = serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
                    assert_eq!(body, json!({"error":message}));
                }
                server.abort();
            }
        });
}
#[tokio::test]
async fn http_handlers_report_health_and_unknown_lane() {
    use std::io::{Read, Write};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router()).await.unwrap() });
    let replies = tokio::task::spawn_blocking(move || {
            ["GET /v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", "POST /v1/lanes/unknown/jobs HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", "GET /v1/lanes/unknown/jobs/example HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"].map(|request| {
                let mut stream = std::net::TcpStream::connect(addr).unwrap();
                stream.write_all(request.as_bytes()).unwrap();
                let mut reply = String::new();
                stream.read_to_string(&mut reply).unwrap();
                reply
            })
        }).await.unwrap();
    assert!(replies[0].starts_with("HTTP/1.1 200"));
    assert!(replies[0].contains("\"ok\":true"));
    for reply in &replies[1..] {
        assert!(reply.starts_with("HTTP/1.1 404"));
        assert!(reply.contains("\"error\":\"unknown lane\""));
    }
    server.abort();
}
#[test]
fn merge_rejects_duplicate_artifacts() {
    let root = crate::test_process::target_dir().join(format!(
        "merge-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let chunks: Vec<Value> = ["a", "b"]
        .iter()
        .map(|name| {
            let part = root.join(name);
            fs::create_dir_all(&part).unwrap();
            fs::write(part.join("frame.png"), b"abc").unwrap();
            fs::write(
                part.join("SHA256SUMS"),
                format!("{}  frame.png\n", hex::encode(Sha256::digest(b"abc"))),
            )
            .unwrap();
            json!({"part_dir":name,"worker":name})
        })
        .collect();
    assert!(merge(&root, &chunks)
        .unwrap_err()
        .contains("produced by two chunks"));
}
#[test]
fn dispatch_guard_refuses_incompatible_workers() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::test_process::target_dir().join(format!(
        "guard-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let files = root.join("files");
    fs::create_dir_all(&files).unwrap();
    fs::write(files.join("weights"), b"abc").unwrap();
    let manifest = root.join("manifest.json");
    fs::write(&manifest, serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":3,"min_vram_mb":8,"min_ram_mb":16,"required_backend":"cuda","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
    let mut spec = json!({"lane":"render-blender","cartridge_manifest":manifest,"cartridge_directory":files,"out":root.join("out")});
    select_manifest(&mut spec, &root).unwrap();
    let script = root.join("worker");
    fs::write(&script, "#!/bin/sh\nif [ \"$1\" = --health ]; then printf '%s' '{\"accepting\":true,\"proof\":{\"pass\":true},\"cartridges\":[\"blender-4.5.14-cycles\"],\"vram_mb\":100,\"ram_mb\":100,\"backends\":[\"cuda\"]}'; else exit 99; fi\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    wait_exec_ready(&script);
    let w = Worker {
        id: "b70".into(),
        lanes: vec!["render-blender".into()],
        kind: "exec".into(),
        exec: script.to_string_lossy().into_owned(),
        dispatch: Value::Null,
        seats: 1,
        enabled: true,
        note: String::new(),
    };
    let st = Arc::new(Mutex::new(JobTable::default()));
    let result = run_chunk(
        &st,
        "job",
        &spec,
        &w,
        1,
        2,
        Instant::now() + Duration::from_secs(5),
        false,
        false,
    );
    assert_eq!(result["state"], "failed");
    assert!(
        result["error"]
            .as_str()
            .unwrap()
            .contains("CUDA unavailable"),
        "unexpected error: {}",
        result["error"]
    );
    assert!(!root.join("out").exists());
}
#[test]
fn selection_survives_active_swap() {
    let root = crate::test_process::target_dir().join(format!(
        "selection-swap-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let files = root.join("source");
    fs::create_dir_all(&files).unwrap();
    let manifest = root.join("input.json");
    let store = root.join("store");
    let install = |bytes: &[u8]| {
        fs::write(files.join("weights"), bytes).unwrap();
        fs::write(&manifest, serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":bytes.len(),"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(bytes))}})).unwrap()).unwrap();
        store::install(&store, &manifest, &files).unwrap()
    };
    let first = install(b"abc");
    let second = install(b"def");
    store::swap(&store, "render-blender", &first).unwrap();
    let mut spec = json!({"lane":"render-blender"});
    select_manifest(&mut spec, &store).unwrap();
    store::swap(&store, "render-blender", &second).unwrap();
    assert_eq!(spec["cartridge_manifest_sha256"], first);
    assert!(resolve_manifest(&spec).is_ok());
    assert_eq!(
        store::active_version(&store, "render-blender").unwrap().2,
        second
    );
}
#[test]
fn malformed_worker_health_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::test_process::target_dir().join(format!(
        "health-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("worker");
    fs::write(&script, "#!/bin/sh\nprintf 'invalid json'\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    wait_exec_ready(&script);
    let w = Worker {
        id: "fixture".into(),
        lanes: vec!["render-blender".into()],
        kind: "exec".into(),
        exec: script.to_string_lossy().into_owned(),
        dispatch: Value::Null,
        seats: 1,
        enabled: true,
        note: String::new(),
    };
    let view = worker_view(&w, "render-blender", &HashMap::new());
    assert_eq!(view["accepting"], false);
    assert!(view["why_not"].to_string().contains("health json"));
}
#[test]
fn missing_manifest_fails_closed() {
    assert!(resolve_manifest(&json!({"lane": "render-blender"}))
        .unwrap_err()
        .contains("manifest required"));
}
#[test]
fn pinned_manifest_change_is_refused() {
    let root = crate::test_process::target_dir().join(format!(
        "pin-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("weights"), b"abc").unwrap();
    let manifest = root.join("input.json");
    let data = serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap();
    fs::write(&manifest, &data).unwrap();
    let files = root.join("files");
    fs::create_dir(&files).unwrap();
    fs::copy(root.join("weights"), files.join("weights")).unwrap();
    let mut spec =
        json!({"lane":"render-blender","cartridge_manifest":manifest,"cartridge_directory":files});
    select_manifest(&mut spec, &root).unwrap();
    assert_eq!(
        spec["cartridge_manifest_sha256"],
        hex::encode(Sha256::digest(&data))
    );
    assert_eq!(spec["cartridge"], "blender-4.5.14-cycles");
    assert!(resolve_manifest(&spec).is_ok());
    fs::write(&manifest, b"{}").unwrap();
    assert!(resolve_manifest(&spec)
        .unwrap_err()
        .contains("digest changed"));
}
#[test]
fn split() {
    assert_eq!(split_range(1, 10, 2), vec![(1, 5), (6, 10)]);
    assert_eq!(split_range(1, 3, 5), vec![(1, 1), (2, 2), (3, 3)]);
    assert_eq!(split_range(7, 7, 2), vec![(7, 7)]);
    assert_eq!(split_range(1, 11, 3), vec![(1, 4), (5, 8), (9, 11)]);
}
#[test]
fn cartridges() {
    assert_eq!(
        worker_cartridges(
            &json!({"cartridges": ["blender-4.5.14-cycles"], "blender": {"version": "4.5.14 LTS"}})
        ),
        vec!["blender-4.5.14-cycles"]
    );
    assert!(worker_cartridges(
        &json!({"cartridges": ["blender-4.5.14-cycles"], "blender": {"version": "4.5.3 LTS"}})
    )
    .is_empty());
    assert_eq!(
        worker_cartridges(&json!({"blender": {"version": "4.5.3 LTS"}})),
        vec!["blender-4.5.3-cycles"]
    );
}
#[test]
fn bake_spec() {
    assert!(bake_frames_ok(&json!("1,12,24")).is_ok());
    assert!(bake_frames_ok(&json!([1, 12])).is_ok());
    assert!(bake_frames_ok(&json!("3-9")).is_ok());
    assert!(bake_frames_ok(&Value::Null).is_ok());
    assert!(bake_frames_ok(&json!("1,x")).is_err());
    assert!(bake_frames_ok(&json!(5)).is_err());
    assert_eq!(
        bake_budget_min(
            &json!({"script": "a.py", "script_timeout_min": 5, "bake_timeout_min": 30, "timeout_min": 20})
        ),
        70.0
    );
    assert_eq!(bake_budget_min(&json!({"steps": ["bake"]})), 75.0);
    assert!(is_bake(&json!({"type": "bake-render"})));
    assert!(!is_bake(&json!({})));
    let v = validate(
        &json!({"lane": "render-blender", "type": "nope", "blend": "/etc/hostname.blend", "out": "/tmp/x"}),
    );
    assert!(v.is_err());
}
#[test]
fn frames() {
    assert_eq!(parse_frames("5").unwrap(), (5, 5));
    assert!(parse_frames("9-3").is_err());
    assert!(parse_frames("a-b").is_err());
}
#[test]
fn binds() {
    assert!(bind_ok(&"127.0.0.1:1".parse().unwrap()));
    assert!(bind_ok(&"10.0.0.15:1".parse().unwrap()));
    assert!(!bind_ok(&"0.0.0.0:1".parse().unwrap()));
    assert!(!bind_ok(&"86.48.30.196:1".parse().unwrap()));
    assert!(!bind_ok(&"[::]:1".parse().unwrap()));
}
