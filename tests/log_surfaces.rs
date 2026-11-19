use crate::*;
fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("run23-logs-{}-{name}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}
fn input() -> String {
    format!(
        "api_key = <TOKEN>;\n{}\nlast line\n",
        "clean log line\n".repeat(10000)
    )
}
fn checked(text: &str, cap: usize) {
    assert!(!text.contains("<TOKEN>"));
    assert!(text.contains("[REDACTED_SECRET]"));
    assert!(text.contains("last line"));
    assert!(text.len() <= cap + 100, "{} > {cap} + marker", text.len());
}
#[test]
fn watchdog_csv_is_bounded_and_redacted() {
    let root = root("csv");
    let path = root.join("events.csv");
    watchdog::append_event(
        &path,
        [
            "100",
            "fixture",
            "0",
            "0",
            "5",
            "observe",
            "fixture",
            &input(),
        ],
    )
    .unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("ts,card,util,watts,idle_min,action,job,result\n"));
    checked(&text, result_store::Config::default().worker_log_max);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn manifest_log_fields_are_bounded_and_redacted() {
    let record = json!({"job_id":"fixture","lane":"tts","state":"failed","result_storage":{"worker_log_max_bytes":256},"chunks":[{"adapter_log":"parts/worker.adapter.log","dispatch_observation":{"adapter_device_log":{"stdout":input()}}}]});
    let manifest = result_store::runtime_manifest(&record, 100);
    let text = manifest["chunks"][0]["dispatch_observation"]["adapter_device_log"]["stdout"]
        .as_str()
        .unwrap();
    checked(text, 256);
    assert_eq!(
        manifest["chunks"][0]["adapter_log"],
        "parts/worker.adapter.log"
    );
}
#[test]
fn http_status_tail_is_bounded_and_redacted() {
    if std::env::var_os("STATUS_LOG_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args([
                "--exact",
                "log_surfaces::http_status_tail_is_bounded_and_redacted",
                "--quiet"
            ])
            .env("STATUS_LOG_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    let root = root("status");
    let out = root.join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("worker.adapter.log"), input()).unwrap();
    let app = new_app(
        json!({"result_storage":{"worker_log_max_bytes":256}}),
        root.join("store"),
    );
    let row = json!({"job_id":"fixture","lane":"tts","state":"done","out":out,"chunks":[{"adapter_log":"worker.adapter.log"}]});
    app.st.lock().unwrap().jobs.insert("fixture".into(), row);
    pull_http_tests::auth_fixture(&root);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer <TOKEN>".parse().unwrap());
        let response = h_job(
            State(app),
            AxPath(("tts".into(), "fixture".into())),
            headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let status: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 100000)
                .await
                .unwrap(),
        )
        .unwrap();
        checked(status["log_tail"][0].as_str().unwrap(), 256);
    });
    fs::remove_dir_all(root).unwrap();
}
fn bypasses(path: &str, source: &str) -> Vec<String> {
    if path == "src/result_store/worker_log.rs" {
        return Vec::new();
    }
    let source = error_catalog::tests::production(source);
    let writes = regex::Regex::new(
        r"(?s)(?:fs::write|File::create|OpenOptions::new|writeln!|write!)\s*\([^;]*;",
    )
    .unwrap();
    writes
        .find_iter(&source)
        .filter(|m| {
            let text = m.as_str();
            text.contains(".log")
                || text.contains("events.csv")
                || text.contains("&log")
                || text.contains("logp")
        })
        .map(|m| {
            format!(
                "{path}:{}",
                source[..m.start()].bytes().filter(|b| *b == b'\n').count() + 1
            )
        })
        .collect()
}
#[test]
fn no_log_write_path_bypasses_shared_writer() {
    let mut failures = Vec::new();
    fn visit(path: &Path, failures: &mut Vec<String>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, failures);
            } else if path.extension().is_some_and(|s| s == "rs") {
                failures.extend(bypasses(
                    path.to_str().unwrap(),
                    &fs::read_to_string(&path).unwrap(),
                ));
            }
        }
    }
    visit(Path::new("src"), &mut failures);
    assert!(failures.is_empty(), "log write bypass: {failures:?}");
    assert_eq!(
        bypasses(
            "src/planted.rs",
            "fn write() { fs::write(\"worker.log\", data); }"
        ),
        vec!["src/planted.rs:1"]
    );
    for (file, required) in [
        ("src/watchdog.rs", "worker_log::append"),
        ("src/result_store.rs", "worker_log::document"),
        ("src/routes/jobs.rs", "worker_log::status"),
    ] {
        assert!(
            fs::read_to_string(file).unwrap().contains(required),
            "missing shared writer: {file}:1"
        );
    }
}
