//! Every declared operation/status is exercised over an ephemeral loopback HTTP server.
use super::*;
use crate::contract_ref_tests::Fixture;

#[derive(Default)]
struct Coverage(BTreeMap<String, Value>);
impl Coverage {
    #[allow(clippy::too_many_arguments)]
    async fn request(
        &mut self,
        app: App,
        path: &str,
        method: &str,
        concrete: &str,
        body: String,
        approved: bool,
        content_type: &str,
        expected: u16,
    ) -> Value {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server =
            tokio::spawn(async move { axum::serve(listener, router_with_app(app)).await.unwrap() });
        let method = method.to_uppercase();
        let wire_method = method.clone();
        let concrete = concrete.to_owned();
        let content_type = content_type.to_owned();
        let raw = tokio::task::spawn_blocking(move || {
            let mut stream = std::net::TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let authorization = if approved { "Authorization: Bearer <TOKEN>\r\n" } else { "" };
            write!(stream, "{wire_method} {concrete} HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            let mut raw = String::new(); stream.read_to_string(&mut raw).unwrap(); raw
        }).await.unwrap();
        server.abort();
        let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
        let status: u16 = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        let doc = document();
        let operation = &doc["paths"][path][method.to_lowercase()];
        let response = &operation["responses"][status.to_string()];
        assert!(
            !response.is_null(),
            "undeclared {method} {path} {status}: {body}"
        );
        assert_eq!(status, expected, "{method} {path}: {body}");
        let contents = response["content"].as_object().unwrap();
        let value: Value = if contents.contains_key("application/json") {
            serde_json::from_str(body).unwrap()
        } else {
            json!(body)
        };
        let definition = if contents.contains_key("application/json") {
            &contents["application/json"]["schema"]
        } else {
            &contents.values().next().unwrap()["schema"]
        };
        let validator = schema(&doc, definition);
        let errors: Vec<_> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "{method} {path} {status}: {errors:?}; {value}"
        );
        if status >= 400 {
            for code in [
                &value["code"],
                &value["error_code"],
                &value["error"]["code"],
            ] {
                if let Some(code) = code.as_str() {
                    assert!(
                        error_catalog::route_codes(path).contains(&code),
                        "{method} {path} {status}: uncatalogued {code}"
                    );
                }
            }
        }
        self.0.insert(
            format!("{} {path} {status}", method.to_lowercase()),
            value.clone(),
        );
        value
    }
    fn missing(&self, doc: &Value) -> Vec<String> {
        let mut missing = Vec::new();
        for (path, ops) in doc["paths"].as_object().unwrap() {
            for (method, op) in ops.as_object().unwrap() {
                for status in op["responses"].as_object().unwrap().keys() {
                    let case = format!("{method} {path} {status}");
                    if !self.0.contains_key(&case) {
                        missing.push(case);
                    }
                }
            }
        }
        missing
    }
}

fn group(path: &str) -> usize {
    if path.contains("models") || path == "/api/tags" {
        0
    } else if path.contains("chat/completions") || path.contains("embed") {
        1
    } else if path == "/v1/generate" {
        2
    } else if path == "/v1/agent/pull" {
        3
    } else {
        4
    }
}
fn pull_request() -> Value {
    json!({"schema_version":"agent-pull/v1","agent_id":"agent-123","worker_id":"colab-l4","lanes":["tts"],"wait_s":1,"state_epoch":1793459400})
}
fn now() -> u64 {
    1793459400
}

async fn exercise(coverage: &mut Coverage, path: &str, method: &str, status: u16) {
    let mut f = Fixture::new();
    for lane in ["render-blender", "stt"] {
        fs::copy(
            f.root.join("auth/tts.sha256"),
            f.root.join(format!("auth/{lane}.sha256")),
        )
        .unwrap();
    }
    f.app.clock = now;
    f.app.compat["result_store_dir"] = json!(f.root.join("results"));
    f.app.compat["jobs_dir"] = json!(f.root.join("jobs"));
    f.app.compat["card_state_dir"] = json!(f.root.join("cards"));
    f.app.compat["cu_floor_path"] = json!(f.root.join("floor"));
    let mut concrete = path
        .replace("{lane}", "tts")
        .replace("{id}", "fixture")
        .replace("{name}", "manifest.json");
    let mut body = json!({});
    let mut approved = status != 401;
    let mut media = "application/json";
    let mut worker = None;
    if status == 503 {
        std::env::set_var("LANE_TOKEN_SHA_DIR", f.root.join("absent-auth"));
    }
    match group(path) {
        0 => {
            if status == 409 {
                f.app.compat["lanes"]["tts"] = json!(false);
            }
            if status == 404 {
                f.app.compat["routes"] = json!({});
            }
        }
        1 => {
            let chat = path.contains("chat");
            body = if chat {
                json!({"messages":[{"role":"user","content":"fixture"}]})
            } else {
                json!({"input":"fixture"})
            };
            if status == 404 {
                f.app.compat["routes"] = json!({});
            }
            if status == 409 {
                f.app.compat["lanes"]["tts"] = json!(false);
            }
            if status == 400 {
                body = if chat {
                    json!({})
                } else {
                    json!({"input":"fixture","encoding_format":"invalid"})
                };
            }
            if status == 422 {
                body = json!({});
            }
            if status == 501 {
                body["stream"] = json!(true);
            }
            if status == 200 || status == 502 {
                worker = Some(f.worker_result(json!([[0.25, 0.5]]), status == 502));
            }
        }
        2 => {
            body = json!({"job_id":"fixture","cartridge":"fixture","prompt":"fixture","text":"fixture","out":f.root.join("out")});
            if status == 404 {
                f.app.compat["routes"] = json!({});
            }
            if status == 409 {
                f.app.compat["lanes"]["tts"] = json!(false);
            }
            if status == 422 {
                body = json!({});
            }
            if [200, 502, 429].contains(&status) {
                worker = Some(f.worker_result(json!([]), status == 502));
            }
            if status == 429 {
                f.app.compat["queue"]["per_lane_limit"] = json!(0);
            }
        }
        3 => {
            body = pull_request();
            if status == 400 {
                body = json!({});
            }
            if status == 409 {
                fs::create_dir_all(f.root.join("cards")).unwrap();
                fs::write(f.root.join("floor"), "5").unwrap();
                fs::write(
                    f.root.join("workers.cfg"),
                    br#"{"workers":[{"id":"colab-l4","lanes":["tts"],"enabled":true}]}"#,
                )
                .unwrap();
                let mut card: Value = serde_json::from_slice(include_bytes!(
                    "fixtures/card-state/colab-l4-state.json"
                ))
                .unwrap();
                card["state"] = json!("idle");
                card["busy"] = json!({"by":"none","ref":null});
                card["seat"] = json!({"held":false,"by":""});
                card["session"]["state"] = json!("none");
                card["cu"]["balance"] = json!(9.0);
                fs::write(
                    f.root.join("cards/colab-l4-state.json"),
                    serde_json::to_vec(&card).unwrap(),
                )
                .unwrap();
                body["report"] = json!({"job_id":"job-123","lease_id":"lease-123","segment":0,"exit_code":0,"done_items":[]});
            }
        }
        _ => {
            if status == 404 {
                concrete = path
                    .replace("{lane}", "missing")
                    .replace("{id}", "fixture")
                    .replace("{name}", "manifest.json");
            }
            if path.ends_with("/jobs") {
                body = json!({"job_id":"fixture","cartridge":"fixture","text":"fixture","out":f.root.join("out")});
                if [202, 429].contains(&status) {
                    let native_store = f.root.join("cartridges");
                    let hash = store::install(
                        &native_store,
                        &f.root.join("input.json"),
                        &f.root.join("files"),
                    )
                    .unwrap();
                    store::swap(&native_store, "tts", &hash).unwrap();
                    worker = Some(f.worker(json!([])));
                }
                if status == 429 {
                    f.app.compat["queue"]["per_lane_limit"] = json!(0);
                }
                if status == 409 {
                    f.app.compat["lanes"]["tts"] = json!(false);
                }
                if status == 422 {
                    body = json!({});
                }
                if status == 400 {
                    body["submitter"] = json!("invalid");
                }
                if status == 415 {
                    concrete = "/v1/lanes/stt/jobs".into();
                    media = "text/plain";
                }
            } else if path.contains("artifacts") && [200, 409, 410, 400].contains(&status) {
                let out = f.root.join("out");
                fs::create_dir_all(&out).unwrap();
                fs::write(out.join("manifest.json"), b"{}").unwrap();
                fs::write(out.join("speech.wav"), b"fixture").unwrap();
                let digest = hex::encode(Sha256::digest(b"fixture"));
                fs::write(out.join("SHA256SUMS"), format!("{digest}  speech.wav\n")).unwrap();
                let row = json!({"job_id":"fixture","lane":"tts","state":"done","out":out,"artifacts":[{"path":"speech.wav","bytes":7,"sha256":digest}]});
                result_store::publish_record(&f.root.join("results"), &row, now()).unwrap();
                let meta_path = f.root.join("results/lanes/tts/jobs/fixture/meta.json");
                let mut meta: Value =
                    serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
                if status == 409 {
                    meta["lane"] = json!("stt");
                }
                if status == 410 {
                    meta["expires_artifacts_epoch"] = json!(0);
                    concrete = concrete.replace("manifest.json", "speech.wav");
                }
                if status == 400 {
                    concrete = concrete.replace("manifest.json", "bad!name");
                }
                fs::write(meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
            } else if (path.ends_with("/{id}") || path.ends_with("/cancel"))
                && [200, 202].contains(&status)
            {
                let row = queue_policy::admitted(
                    &HashMap::new(),
                    &json!({"job_id":"fixture","lane":"tts"}),
                    now(),
                );
                let mut row = row;
                row["result_store_root"] = json!(f.root.join("results"));
                if status == 200 && path.ends_with("/cancel") {
                    row["state"] = json!("cancelled");
                }
                f.app.st.lock().unwrap().jobs.insert("fixture".into(), row);
            }
        }
    }
    if status == 400 && path.contains("{") && !path.ends_with("{name}") && !path.ends_with("/jobs")
    {
        concrete = concrete.replace("fixture", "%FF").replace("tts", "%FF");
    }
    if path == "/v1/health" {
        approved = false;
    }
    if status == 415 {
        media = "text/plain";
    }
    let raw = if status == 413 {
        " ".repeat(dispatch_kinds::Config::default().body_max + 1)
    } else {
        body.to_string()
    };
    coverage
        .request(
            f.app.clone(),
            path,
            method,
            &concrete,
            raw,
            approved,
            media,
            status,
        )
        .await;
    // A submitted real worker must finish before its fixture directory is removed.
    if path.ends_with("/jobs") && status == 202 {
        for _ in 0..1000 {
            if f.root.join("out/manifest.json").is_file()
                && f.app
                    .st
                    .lock()
                    .unwrap()
                    .jobs
                    .get("fixture")
                    .is_some_and(queue_policy::terminal)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(f
            .app
            .st
            .lock()
            .unwrap()
            .jobs
            .get("fixture")
            .is_some_and(queue_policy::terminal));
    }
    drop(worker);
}

fn run(name: &str, selected: Option<usize>) {
    if std::env::var_os("OPENAPI_MATRIX_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args([
                "--exact",
                &format!("openapi_contract::matrix::{name}"),
                "--quiet"
            ])
            .env("OPENAPI_MATRIX_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut coverage = Coverage::default();
        let doc = document();
        for (path, ops) in doc["paths"].as_object().unwrap() {
            if selected.is_some_and(|n| n != group(path)) {
                continue;
            }
            for (method, op) in ops.as_object().unwrap() {
                for status in op["responses"].as_object().unwrap().keys() {
                    exercise(&mut coverage, path, method, status.parse().unwrap()).await;
                }
            }
        }
        assert!(!coverage.0.is_empty());
        if selected.is_none() {
            assert!(
                coverage.missing(&doc).is_empty(),
                "unexercised {:?}",
                coverage.missing(&doc)
            );
            let removed = coverage.0.keys().next().unwrap().clone();
            let value = coverage.0.remove(&removed).unwrap();
            assert_eq!(coverage.missing(&doc), vec![removed.clone()]);
            coverage.0.insert(removed, value);
            fs::write(
                crate::test_process::target_dir().join("run23-openapi-coverage.json"),
                serde_json::to_vec_pretty(&coverage.0).unwrap(),
            )
            .unwrap();
        }
    });
}
#[test]
fn all_declared_responses_are_exercised() {
    run("all_declared_responses_are_exercised", None);
}
#[test]
fn catalogs_success_and_errors() {
    run("catalogs_success_and_errors", Some(0));
}
#[test]
fn chat_embedding_success_and_errors() {
    run("chat_embedding_success_and_errors", Some(1));
}
#[test]
fn generate_success_and_errors() {
    run("generate_success_and_errors", Some(2));
}
#[test]
fn pull_success_and_errors() {
    run("pull_success_and_errors", Some(3));
}
#[test]
fn native_success_and_errors() {
    run("native_success_and_errors", Some(4));
}
