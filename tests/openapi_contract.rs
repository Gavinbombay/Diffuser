//! Native HTTP inventory and response checks, including the b6 OpenAPI QC defects.
use crate::*;
use std::io::Write;
fn document() -> Value {
    serde_json::from_str(include_str!("../docs/openapi.json")).unwrap()
}
fn documented(doc: &Value) -> HashSet<(String, String)> {
    doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .unwrap()
                .keys()
                .filter(|m| ["get", "post", "head", "put", "delete", "patch"].contains(&m.as_str()))
                .map(move |method| (path.clone(), method.clone()))
        })
        .collect()
}
fn registered() -> HashSet<(String, String)> {
    http_routes::ROUTES
        .iter()
        .map(|(p, m)| (p.replace("{*name}", "{name}"), m.to_string()))
        .collect()
}
fn schema(doc: &Value, response: &Value) -> jsonschema::Validator {
    let mut root = response.clone();
    root["components"] = doc["components"].clone();
    jsonschema::validator_for(&root).unwrap()
}
fn cite_valid(cite: &str) -> bool {
    let Some((path, line)) = cite.rsplit_once(':') else {
        return false;
    };
    let Ok(line) = line.parse::<usize>() else {
        return false;
    };
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .is_ok_and(|s| line > 0 && s.lines().count() >= line)
}
#[test]
fn openapi_registered_routes_equal_both_directions() {
    assert_eq!(documented(&document()), registered());
}
#[test]
fn openapi_qc_placeholders_cites_size_and_refs() {
    let raw = include_str!("../docs/openapi.json");
    assert!(raw.len() < 150000);
    assert!(!raw.contains("%s"));
    assert!(!raw.contains("TODO"));
    let doc = document();
    assert_eq!(doc["openapi"], "3.1.0");
    for item in doc["paths"].as_object().unwrap().values() {
        for op in item.as_object().unwrap().values() {
            for c in op["x-cite"].as_array().unwrap() {
                assert!(cite_valid(c.as_str().unwrap()), "{c}");
            }
            if let Some(request) = op.get("requestBody") {
                assert!(request["content"]["application/json"]["schema"]["$ref"].is_string());
                schema(&doc, &request["content"]["application/json"]["schema"]);
            }
            for response in op["responses"].as_object().unwrap().values() {
                for content in response["content"].as_object().unwrap().values() {
                    schema(&doc, &content["schema"]);
                }
            }
        }
    }
}
#[test]
fn openapi_checker_rejects_missing_route_and_required_field() {
    let mut doc = document();
    doc["paths"].as_object_mut().unwrap().remove("/v1/health");
    assert_ne!(documented(&doc), registered());
    let valid = json!({"ok":true,"api":API,"lanes":LANES});
    let v = schema(&doc, &json!({"$ref":"#/components/schemas/Health"}));
    assert!(v.is_valid(&valid));
    for f in ["ok", "api", "lanes"] {
        let mut bad = valid.clone();
        bad.as_object_mut().unwrap().remove(f);
        assert!(!v.is_valid(&bad), "missing {f}");
    }
}
#[test]
fn openapi_live_response_per_path_has_required_fields() {
    if std::env::var_os("OPENAPI_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args([
                "--exact",
                "openapi_contract::openapi_live_response_per_path_has_required_fields",
                "--quiet"
            ])
            .env("OPENAPI_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    let root = std::env::temp_dir().join(format!("fold-openapi-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    pull_http_tests::auth_fixture(&root);
    std::env::set_var("LANE_ROUTER_HOME", &root);
    let mut config = json!({"lanes":{"tts":true},"routes":{}});
    for (path, _) in http_routes::ROUTES {
        config["routes"][*path] = json!("tts");
    }
    let app = new_app(config, root.join("store"));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
        let admission=app.clone();
        let server=tokio::spawn(async move {axum::serve(listener,router_with_app(app)).await.unwrap();});
        let doc=document();
        for (path,method) in http_routes::ROUTES {
            let path=path.to_string();let method=method.to_uppercase();
            let concrete=path.replace("{lane}","tts").replace("{id}","fixture").replace("{*name}","speech.wav");
            let wire_method=method.clone();
            let raw=tokio::task::spawn_blocking(move ||{
                let mut stream=std::net::TcpStream::connect(addr).unwrap();stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                write!(stream,"{wire_method} {concrete} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").unwrap();
                let mut raw=String::new();stream.read_to_string(&mut raw).unwrap();raw
            }).await.unwrap();
            let (headers,body)=raw.split_once("\r\n\r\n").unwrap();let status=headers.split_whitespace().nth(1).unwrap();
            let operation=&doc["paths"][path.replace("{*name}","{name}")][method.to_lowercase()];
            let response=&operation["responses"][status]["content"]["application/json"]["schema"];
            assert!(!response.is_null(),"undocumented {path} {status}");let value:Value=serde_json::from_str(body).unwrap();
            assert!(schema(&doc,response).is_valid(&value),"{path} {status}: {value}");
        }
        for (body,expected) in [(json!({}),"MESSAGES_REQUIRED"),(json!({"messages":[{"role":"system","content":"fixture"}]}),"PROMPT_REQUIRED")] {
            let mut headers=HeaderMap::new();headers.insert("authorization","Bearer <TOKEN>".parse().unwrap());
            let response=h_chat(State(admission.clone()),OriginalUri("/v1/chat/completions".parse().unwrap()),headers,axum::body::Bytes::from(body.to_string())).await;
            assert_eq!(response.status(),StatusCode::BAD_REQUEST);
            let value:Value=serde_json::from_slice(&axum::body::to_bytes(response.into_body(),100000).await.unwrap()).unwrap();
            assert_eq!(value["error_code"],expected);
            assert!(schema(&doc,&doc["paths"]["/v1/chat/completions"]["post"]["responses"]["400"]["content"]["application/json"]["schema"]).is_valid(&value));
        }
        server.abort();
    });
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn openapi_native_pull_success_variants_match_schema() {
    let doc = document();
    let v = schema(&doc, &json!({"$ref":"#/components/schemas/PullResponse"}));
    assert!(v.is_valid(&agent_pull::empty_response(1)));
    let mut lifecycle = segment_lifecycle::Lifecycle::new(5);
    assert!(lifecycle.assign("lease-123".into(), 9.0, 5.0));
    let assigned = agent_pull::assigned_response(
        "lease-123",
        "2026-09-21T14:14:20Z",
        &lifecycle,
        &json!({"job_id":"fixture"}),
    )
    .unwrap();
    assert!(v.is_valid(&assigned));
    for field in ["lease_expires_at", "job"] {
        let mut bad = assigned.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(!v.is_valid(&bad), "missing {field}");
    }
}

#[path = "openapi_matrix.rs"]
mod matrix;

fn example_validation(doc: &Value) -> (Vec<String>, Vec<String>) {
    let mut failures = Vec::new();
    let mut pairs = Vec::new();
    for (path, operations) in doc["paths"].as_object().unwrap() {
        for (method, operation) in operations.as_object().unwrap() {
            for (status, response) in operation["responses"].as_object().unwrap() {
                let case = format!("{method} {path} {status}");
                let mut valid = true;
                for content in response["content"].as_object().unwrap().values() {
                    match content.get("example") {
                        None => {
                            failures.push(format!("{case}: missing example"));
                            valid = false;
                        }
                        Some(example) => {
                            for error in schema(doc, &content["schema"]).iter_errors(example) {
                                failures.push(format!("{case}: {error}"));
                                valid = false;
                            }
                        }
                    }
                }
                if valid {
                    pairs.push(case);
                }
            }
        }
    }
    (failures, pairs)
}
#[test]
fn openapi_response_examples_validate_all() {
    let doc = document();
    let (failures, pairs) = example_validation(&doc);
    let evidence = json!({"document_sha256":hex::encode(Sha256::digest(include_bytes!("../docs/openapi.json"))),"validated_pairs":pairs,"failures":failures});
    fs::create_dir_all(crate::test_process::target_dir()).unwrap();
    fs::write(
        crate::test_process::target_dir().join("run27-example-validation.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    assert!(
        failures.is_empty(),
        "invalid OpenAPI examples: {failures:?}"
    );
    assert!(pairs.len() >= 139);
    let source: Value =
        serde_json::from_str(include_str!("../docs/openapi-response-source.json")).unwrap();
    for case in pairs {
        let parts: Vec<_> = case.split_whitespace().collect();
        let response = &doc["paths"][parts[1]][parts[0]]["responses"][parts[2]];
        for content in response["content"].as_object().unwrap().values() {
            assert_eq!(
                content["example"], source[&case],
                "example lacks real response provenance: {case}"
            );
        }
    }
}
#[test]
fn openapi_response_examples_reject_planted_bad_body() {
    let output = Command::new("python3")
        .args(["tools/coverage-gate.py", "--self-test", "example"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut doc = document();
    doc["paths"]["/v1/health"]["get"]["responses"]["200"]["content"]["application/json"]
        ["example"] = json!({"ok":"wrong type"});
    let (failures, pairs) = example_validation(&doc);
    assert!(failures
        .iter()
        .any(|failure| failure.starts_with("get /v1/health 200:")));
    assert!(!pairs.contains(&"get /v1/health 200".to_owned()));
}
