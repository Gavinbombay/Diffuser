//! Golden shapes derived by reading REF, never importing or executing it.
use super::*;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use tower::ServiceExt;

pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
    pub(crate) app: App,
}
impl Fixture {
    pub(crate) fn new() -> Self {
        let root = std::env::temp_dir().join(format!("contract-ref-{}", std::process::id()));
        fs::create_dir_all(root.join("files")).unwrap();
        fs::write(root.join("files/weights"), b"abc").unwrap();
        pull_http_tests::auth_fixture(&root);
        std::env::set_var("LANE_ROUTER_HOME", &root);
        std::env::set_var("LANE_REGISTRY", root.join("workers.cfg"));
        fs::write(root.join("workers.cfg"), br#"{"workers":[]}"#).unwrap();
        let manifest = root.join("input.json");
        fs::write(&manifest, serde_json::to_vec(&json!({"id":"fixture","lane":"tts","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":hex::encode(Sha256::digest(b"abc"))}})).unwrap()).unwrap();
        let store_root = root.join("store");
        let hash = store::install(&store_root, &manifest, &root.join("files")).unwrap();
        store::swap(&store_root, "tts", &hash).unwrap();
        let mut config = json!({"lanes":{"tts":true},"routes":{}});
        for path in [
            "/v1/generate",
            "/v1/chat/completions",
            "/openai/v1/chat/completions",
            "/v1/embeddings",
            "/openai/v1/embeddings",
            "/v1/embed",
            "/embed",
            "/v1/models",
            "/openai/v1/models",
            "/openai/models",
            "/models",
            "/api/v1/models",
            "/api/models",
            "/api/tags",
            "/v1/models/{id}",
        ] {
            config["routes"][path] = json!("tts");
        }
        Self {
            root,
            app: new_app(
                lane_gate::fixture_config(config, "tts", "fixture"),
                store_root,
            ),
        }
    }
    pub(crate) fn worker(&self, vectors: Value) -> fake_suite::FakeWorker {
        self.worker_result(vectors, false)
    }
    pub(crate) fn worker_result(&self, vectors: Value, failure: bool) -> fake_suite::FakeWorker {
        let worker = fake_suite::FakeWorker::new(
            json!({"accepting":true,"proof":{"pass":true},"vram_mb":16,"ram_mb":16,"backends":["cpu"]}),
            Duration::ZERO,
            failure,
            json!({"--chat":{"content":"answer","model":"fixture",(crate::error_catalog::USAGE):{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}},"--embed":{"embeddings":vectors,"model":"fixture",(crate::error_catalog::USAGE):{"prompt_tokens":2,"total_tokens":2}}}),
        );
        let executable = self.root.join("worker");
        worker.executable(&executable);
        tests::wait_exec_ready(&executable);
        fs::write(self.root.join("workers.cfg"), serde_json::to_vec(&json!({"workers":[{"id":"fixture","lanes":["tts"],"kind":"exec","exec":executable,"seats":1,"enabled":true}]})).unwrap()).unwrap();
        worker
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        credential: Option<&str>,
        expected: u16,
    ) -> Value {
        request(
            self.app.clone(),
            method,
            path,
            body.to_string(),
            credential,
            expected,
        )
        .await
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Terminal state precedes run_job's final persistence. Requests and
        // dispatch closures retain this exact Shared through their synchronous
        // I/O; their child writers are joined before those owners are dropped.
        // Keep the fixture root and environment alive until only we own it.
        let until = Instant::now() + Duration::from_secs(10);
        while Arc::strong_count(&self.app.st) > 1 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            Arc::strong_count(&self.app.st),
            1,
            "fixture request/dispatch owners did not quiesce before cleanup"
        );
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn run_case(name: &str, case: fn(&Fixture)) {
    // Separate processes isolate the production environment-based auth path.
    if std::env::var_os("CONTRACT_REF_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", &format!("contract_ref_tests::{name}"), "--quiet"])
            .env("CONTRACT_REF_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    case(&Fixture::new());
}
async fn request(
    app: App,
    method: &str,
    path: &str,
    body: String,
    credential: Option<&str>,
    expected: u16,
) -> Value {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(credential) = credential {
        builder = builder.header("authorization", credential);
    }
    let response = router_with_app(app)
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    assert_eq!(response.headers()["content-type"], "application/json");
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap();
    assert_eq!(status, expected, "{method} {path}: {value}");
    value
}
fn fields(value: &Value, expected: &[&str]) {
    let actual: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}
pub(crate) const APPROVED: Option<&str> = Some("Bearer <TOKEN>");

#[test]
fn contract_ref_catalog_aliases() {
    // REF listener:699-722,826,842; pool_i:1850-1874,1922-1929,1970-1988.
    run_case("contract_ref_catalog_aliases", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for path in [
                "/v1/models",
                "/openai/v1/models",
                "/openai/models",
                "/models",
                "/api/v1/models",
                "/api/models",
            ] {
                let body = f.request("GET", path, json!({}), None, 200).await;
                fields(&body, &["object", "data"]);
                assert_eq!(body["object"], "list");
                assert_eq!(body["data"].as_array().unwrap().len(), 1);
                let row = &body["data"][0];
                fields(
                    row,
                    &["id", "object", "created", "owned_by", "permission", "uai"],
                );
                assert_eq!(row["id"], "fixture");
                assert_eq!(row["object"], "model");
                assert_eq!(row["owned_by"], "tts");
                assert!(row["created"].is_u64());
                assert_eq!(row["permission"], json!([]));
                assert_eq!(row["uai"], json!({}));
                let retrieved = f
                    .request("GET", &format!("{path}/fixture"), json!({}), None, 200)
                    .await;
                fields(
                    &retrieved,
                    &["id", "object", "created", "owned_by", "permission", "uai"],
                );
                assert_eq!(retrieved["id"], row["id"]);
                let missing = f
                    .request("GET", &format!("{path}/missing"), json!({}), None, 404)
                    .await;
                fields(&missing, &["error", "uai"]);
                fields(&missing["error"], &["message", "type", "param", "code"]);
                assert_eq!(missing["error"]["type"], "invalid_request_error");
                assert_eq!(missing["error"]["param"], "model");
                assert_eq!(
                    missing["error"]["code"],
                    crate::error_catalog::MODEL_NOT_FOUND
                );
                assert_eq!(missing["uai"], json!({}));
            }
            let tags = f.request("GET", "/api/tags", json!({}), None, 200).await;
            fields(&tags, &["models"]);
            fields(&tags["models"][0], &["name", "model"]);
            assert_eq!(
                tags["models"][0],
                json!({"name":"fixture","model":"fixture"})
            );
        })
    });
}

#[test]
fn contract_ref_generate() {
    // REF listener:1330-1331; pool_i:4224-4244 (400),4517-4548 (200).
    run_case("contract_ref_generate", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
        let _worker = f.worker(json!([[0.25,0.5]]));
        let body = f.request("POST", "/v1/generate", json!({"job_id":"ref-job","cartridge":"fixture","prompt":"hello","text":"hello","out":f.root.join("out")}), APPROVED, 200).await;
        fields(&body, &["status", "job"]); assert_eq!(body["status"], "ok");
        assert_eq!(body["job"]["state"], "done"); assert_eq!(body["job"]["lane"], "tts");
        assert_eq!(body["job"]["artifacts"].as_array().unwrap().len(), 1);
        assert!(body["job"]["artifacts"][0]["sha256"].as_str().is_some_and(|value| value.len() == 64));
        let invalid = f.request("POST", "/v1/generate", json!({"prompt":""}), APPROVED, 422).await;
        assert_eq!(invalid, json!({"error":"prompt must be a nonempty string"}));
        drop(_worker);
        let _failed = f.worker_result(json!([]), true);
        let failed = f.request("POST", "/v1/generate", json!({"job_id":"ref-failed","cartridge":"fixture","prompt":"hello","text":"hello","out":f.root.join("failed-out")}), APPROVED, 502).await;
        fields(&failed, &["status", "job"]); assert_eq!(failed["status"], "error");
        assert_eq!(failed["job"]["state"], "failed");
    })
    });
}

#[test]
fn contract_ref_chat_completions() {
    // REF listener:1130-1173,1186-1233; pool_i:1204-1227,1232-1236.
    run_case("contract_ref_chat_completions", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
        let _worker = f.worker(json!([[0.25,0.5]]));
        for path in ["/v1/chat/completions", "/openai/v1/chat/completions"] {
            let body = f.request("POST", path, json!({"messages":[{"role":"user","content":"hello"}]}), APPROVED, 200).await;
            fields(&body, &["id", "object", "created", "model", "choices", crate::error_catalog::USAGE, "uai"]);
            assert!(body["id"].is_string()); assert!(body["created"].is_u64());
            assert_eq!(body["object"], "chat.completion"); assert_eq!(body["model"], "fixture");
            assert_eq!(body["choices"], json!([{"index":0,"message":{"role":"assistant","content":"answer"},"finish_reason":"stop"}]));
            assert_eq!(body[crate::error_catalog::USAGE], json!({"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}));
            assert_eq!(body["uai"], json!({}));
            let invalid = f.request("POST", path, json!({"messages":[]}), APPROVED, 400).await;
            fields(&invalid, &["status", "error", "error_code", "detail", "uai"]);
            assert_eq!(invalid["status"], "error"); assert_eq!(invalid["error"], "invalid_messages");
            assert_eq!(invalid["error_code"], crate::error_catalog::MESSAGES_REQUIRED); assert_eq!(invalid["uai"], json!({}));
            let prompt = f.request("POST", path, json!({"messages":[{"role":"assistant","content":"hello"}]}), APPROVED, 400).await;
            fields(&prompt, &["status", "error_code", "detail", "uai"]); assert_eq!(prompt["error_code"], crate::error_catalog::PROMPT_REQUIRED);
            let stream = f.request("POST", path, json!({"messages":[{"role":"user","content":"hello"}],"stream":true}), APPROVED, 501).await;
            assert_eq!(stream, json!({"error":"streaming is not supported"}));
        }
    })
    });
}

#[test]
fn contract_ref_embeddings() {
    // REF listener:200-260,1444-1464,1493-1515.
    run_case("contract_ref_embeddings", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            {
                let _worker = f.worker(json!([[0.25, 0.5]]));
                for path in ["/v1/embeddings", "/openai/v1/embeddings"] {
                    for encoding in ["float", "float32", "base64"] {
                        let body = f
                            .request(
                                "POST",
                                path,
                                json!({"input":"hello","encoding_format":encoding}),
                                APPROVED,
                                200,
                            )
                            .await;
                        fields(
                            &body,
                            &[
                                "object",
                                "data",
                                "model",
                                crate::error_catalog::USAGE,
                                "uai",
                            ],
                        );
                        assert_eq!(body["object"], "list");
                        assert_eq!(body["model"], "fixture");
                        assert_eq!(body["data"].as_array().unwrap().len(), 1);
                        fields(&body["data"][0], &["object", "embedding", "index"]);
                        assert_eq!(body["data"][0]["object"], "embedding");
                        assert_eq!(body["data"][0]["index"], 0);
                        if encoding == "base64" {
                            assert!(body["data"][0]["embedding"].is_string());
                        } else {
                            assert_eq!(body["data"][0]["embedding"], json!([0.25, 0.5]));
                        }
                        assert_eq!(
                            body[crate::error_catalog::USAGE],
                            json!({"prompt_tokens":2,"total_tokens":2})
                        );
                        assert_eq!(body["uai"], json!({}));
                    }
                    let invalid = f
                        .request(
                            "POST",
                            path,
                            json!({"input":"hello","encoding_format":"unsupported"}),
                            APPROVED,
                            400,
                        )
                        .await;
                    fields(&invalid, &["error", "uai"]);
                    fields(&invalid["error"], &["message", "type", "param", "code"]);
                    assert_eq!(
                        invalid["error"]["code"],
                        crate::error_catalog::UNSUPPORTED_ENCODING_FORMAT
                    );
                    assert_eq!(invalid["error"]["param"], "encoding_format");
                    assert_eq!(
                        f.request("POST", path, json!({"input":[]}), APPROVED, 422)
                            .await,
                        json!({"error":"input must contain nonempty text"})
                    );
                }
            }
            let _worker = f.worker(json!([[0.25, 0.5], [0.5, 0.25]]));
            for path in ["/v1/embeddings", "/openai/v1/embeddings"] {
                let batch = f
                    .request("POST", path, json!({"input":["one","two"]}), APPROVED, 200)
                    .await;
                assert_eq!(batch["data"].as_array().unwrap().len(), 2);
                assert_eq!(
                    batch["data"][1],
                    json!({"index":1,"object":"embedding","embedding":[0.5,0.25]})
                );
            }
        })
    });
}

#[test]
fn contract_ref_native_embed() {
    // REF listener:1381-1388,1518-1532; embed_worker:455-473.
    run_case("contract_ref_native_embed", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            {
                let _worker = f.worker(json!([[0.25, 0.5]]));
                for path in ["/v1/embed", "/embed"] {
                    let body = f
                        .request("POST", path, json!({"input":"hello"}), APPROVED, 200)
                        .await;
                    fields(
                        &body,
                        &[
                            "status",
                            "embedding",
                            "model",
                            crate::error_catalog::USAGE,
                            "uai",
                        ],
                    );
                    assert_eq!(body["status"], "ok");
                    assert_eq!(body["embedding"], json!([0.25, 0.5]));
                    assert_eq!(body["model"], "fixture");
                    assert_eq!(
                        body[crate::error_catalog::USAGE],
                        json!({"prompt_tokens":2,"total_tokens":2})
                    );
                    assert_eq!(body["uai"], json!({}));
                    assert_eq!(
                        f.request("POST", path, json!({"input":""}), APPROVED, 422)
                            .await,
                        json!({"error":"input must contain nonempty text"})
                    );
                }
            }
            let _worker = f.worker(json!([[0.25, 0.5], [0.5, 0.25]]));
            for path in ["/v1/embed", "/embed"] {
                let batch = f
                    .request("POST", path, json!({"input":["one","two"]}), APPROVED, 200)
                    .await;
                assert_eq!(batch["embedding"], json!([[0.25, 0.5], [0.5, 0.25]]));
                assert!(batch.get("batch").is_none());
            }
        })
    });
}

#[test]
fn contract_ref_error_shapes() {
    // REF listener:633-658,918,437-450,1062-1077,966-990;
    // pool_i:4214,4224-4244. Deliberate fold statuses are asserted too.
    run_case("contract_ref_error_shapes", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
        for method in ["GET", "POST"] {
            assert_eq!(f.request(method, "/missing?query=1", json!({}), None, 404).await, json!({"status":"not_found","path":"/missing"}));
        }
        for (method, path) in [("DELETE","/v1/models"),("GET","/v1/generate"),("PATCH","/openai/v1/files/example")] {
            assert_eq!(f.request(method, path, json!({}), None, 405).await, json!({"status":"method_not_allowed","detail":"method not allowed","method":method}));
        }
        let mut disabled = f.app.clone(); disabled.compat["lanes"]["tts"] = json!(false);
        assert_eq!(request(disabled, "POST", "/v1/generate", "{}".into(), None, 409).await, json!({"error":"lane disabled"}));
        let mut unknown = f.app.clone(); unknown.compat["routes"] = json!({});
        assert_eq!(request(unknown, "POST", "/v1/generate", "{}".into(), None, 404).await, json!({"error":"unknown lane"}));
        assert_eq!(request(f.app.clone(), "POST", "/v1/generate", "{".into(), APPROVED, 422).await, json!({"error":"invalid JSON"}));
        assert_eq!(f.request("POST", "/v1/chat/completions", json!({"messages":[{"role":"user","content":"hello"}],"stream":true}), APPROVED, 501).await, json!({"error":"streaming is not supported"}));
        assert_eq!(f.request("POST", "/v1/completions", json!({}), None, 404).await, json!({"status":"not_found","path":"/v1/completions"}));
        for path in ["/v1/chat/completions", "/v1/embeddings", "/embed"] {
            let body = f.request("POST", path, json!({"messages":[{"role":"user","content":"hello"}],"input":"hello"}), APPROVED, 409).await;
            assert_eq!(body, json!({"error":"no accepting compatibility worker"}));
        }
        {
            let _failed = f.worker_result(json!([]), true);
            for path in ["/v1/chat/completions", "/v1/embeddings", "/embed"] {
                assert_eq!(f.request("POST", path, json!({"messages":[{"role":"user","content":"hello"}],"input":"hello"}), APPROVED, 502).await, json!({"error":"compatibility worker failed"}));
            }
        }
        let _malformed = f.worker(json!([]));
        for path in ["/v1/embeddings", "/embed"] {
            assert_eq!(f.request("POST", path, json!({"input":"hello"}), APPROVED, 502).await, json!({"error":"invalid embedding worker response"}));
        }
    })
    });
}

#[test]
fn contract_ref_auth_401_403() {
    // REF pool_i:3436-3454 (hosted adapter 401/403),3998-4007 (dispatch 403).
    // Item 7 preserves lane auth, including the absence of a 403 decision.
    run_case("contract_ref_auth_401_403", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for path in [
                "/v1/generate",
                "/v1/chat/completions",
                "/openai/v1/chat/completions",
                "/v1/embeddings",
                "/openai/v1/embeddings",
                "/v1/embed",
                "/embed",
            ] {
                for credential in [None, Some("Bearer [R]")] {
                    assert_eq!(
                        f.request("POST", path, json!({}), credential, 401).await,
                        json!({"error":"bad token"})
                    );
                }
                // Authorized requests reach validation rather than a hosted 403 gate.
                let invalid = f
                    .request(
                        "POST",
                        path,
                        json!({}),
                        APPROVED,
                        if path.contains("chat/") { 400 } else { 422 },
                    )
                    .await;
                assert!(invalid.get("error").is_some());
            }
            for credential in [None, Some("Bearer [R]")] {
                assert_eq!(
                    f.request("GET", "/v1/models", json!({}), credential, 200)
                        .await["object"],
                    "list"
                );
            }
        })
    });
}

#[test]
fn contract_ref_no_reference_routes() {
    // REF listener:ALLOWED_GET_PATHS (75-118),ALLOWED_POST_PATHS (120-130).
    run_case("contract_ref_no_reference_routes", |f| {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let health = f.request("GET", "/v1/health", json!({}), None, 200).await;
            fields(&health, &["ok", "api", "lanes"]);
            assert_eq!(health["api"], "service-lane/v1");
            assert_eq!(
                f.request(
                    "GET",
                    "/v1/lanes/tts/jobs/missing",
                    json!({}),
                    APPROVED,
                    404
                )
                .await,
                json!({"error":"no such job"})
            );
        })
    });
}
