use crate::*;
// ---------------- HTTP ----------------
#[derive(Clone)]
pub(crate) struct App {
    pub(crate) st: Shared,
    pub(crate) compat: Value,
    pub(crate) store_root: PathBuf,
    pub(crate) cards: Arc<Mutex<HashMap<String, Value>>>,
    pub(crate) clock: fn() -> u64,
}

pub(crate) fn clock_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub(crate) fn utc_stamp(epoch: u64) -> Option<String> {
    let output = Command::new("date")
        .args(["-u", "-d", &format!("@{epoch}"), "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub(crate) fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    error_catalog::observe(Some(code.as_u16()), &msg);
    (code, Json(json!({"error": msg}))).into_response()
}

/// Bearer token check: sha256(token) vs token-sha/<lane>.sha256, constant time. No file = lane refuses.
#[allow(clippy::result_large_err)]
pub(crate) fn auth(h: &HeaderMap, lane: &str) -> Result<(), Response> {
    if !LANES.contains(&lane) {
        return Err(err(StatusCode::NOT_FOUND, "unknown lane"));
    }
    let want = fs::read_to_string(token_sha_dir().join(format!("{lane}.sha256")))
        .ok()
        .map(|s| s.trim().to_lowercase())
        .and_then(|s| hex::decode(s).ok())
        .filter(|b| b.len() == 32);
    let Some(want) = want else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "lane_token_unset: [owner] has not approved a token for this lane; use the CLI",
        ));
    };
    let got = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let gh = Sha256::digest(got.as_bytes());
    if got.is_empty() || !bool::from(gh.as_slice().ct_eq(&want)) {
        return Err(err(StatusCode::UNAUTHORIZED, "bad token"));
    }
    Ok(())
}

// Compatibility routes use an explicit route-to-lane mapping and allowlist.
// An absent or malformed configuration fails closed.

/// Bound write requests before extraction so every refusal uses the catalog.
/// Missing media headers retain the existing legacy contract.
pub(crate) async fn request_guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use axum::extract::FromRequestParts;
    let (mut parts, body) = request.into_parts();
    if parts
        .extensions
        .get::<axum::extract::MatchedPath>()
        .is_some_and(|path| path.as_str().contains('{'))
        && axum::extract::RawPathParams::from_request_parts(&mut parts, &())
            .await
            .is_err()
    {
        return err(StatusCode::BAD_REQUEST, error_catalog::PATH_UNSAFE);
    }

    let body = match axum::body::to_bytes(body, dispatch_kinds::Config::default().body_max).await {
        Ok(body) => body,
        Err(_) => {
            return err(
                StatusCode::PAYLOAD_TOO_LARGE,
                error_catalog::REQUEST_TOO_LARGE,
            )
        }
    };
    if let Some(media) = parts
        .headers
        .get(axum::http::header::CONTENT_TYPE)
        .filter(|_| parts.method == Method::POST)
    {
        if let Err(code) = render_admission::media_type(media.to_str().ok()) {
            return err(StatusCode::UNSUPPORTED_MEDIA_TYPE, code);
        }
    }
    if parts.method == Method::POST {
        static DOC: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
            serde_json::from_str(include_str!("../../docs/openapi.json")).expect("shipped OpenAPI")
        });
        let template = parts
            .extensions
            .get::<axum::extract::MatchedPath>()
            .map_or("", axum::extract::MatchedPath::as_str);
        let definition =
            &DOC["paths"][template]["post"]["requestBody"]["content"]["application/json"]["schema"];
        if let Ok(value) = serde_json::from_slice::<Value>(&body) {
            if unknown_fields(&DOC, definition, &value) {
                return err(StatusCode::BAD_REQUEST, error_catalog::INVALID_REQUEST);
            }
        }
    }
    next.run(axum::extract::Request::from_parts(
        parts,
        axum::body::Body::from(body),
    ))
    .await
}

#[cfg(test)]
pub(super) async fn check_request_refusals(paths: &[&str]) {
    use tower::ServiceExt;
    let app = new_app(json!({}), std::env::temp_dir().join("unused-route-store"));
    let table = app.st.clone();
    let router = router_with_app(app);
    for path in paths {
        for (length, media, status, code) in [
            (
                dispatch_kinds::Config::default().body_max + 1,
                "application/json",
                StatusCode::PAYLOAD_TOO_LARGE,
                error_catalog::REQUEST_TOO_LARGE,
            ),
            (
                2 * 1024 * 1024 + 1,
                "application/json",
                StatusCode::PAYLOAD_TOO_LARGE,
                error_catalog::REQUEST_TOO_LARGE,
            ),
            (
                2,
                "text/plain",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                error_catalog::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                2,
                "application/jsonp",
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                error_catalog::UNSUPPORTED_MEDIA_TYPE,
            ),
        ] {
            let request = axum::http::Request::builder()
                .method(Method::POST)
                .uri(*path)
                .header(axum::http::header::CONTENT_TYPE, media)
                .body(axum::body::Body::from(vec![b' '; length]))
                .unwrap();
            let response = router.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status, "{path}: {media} {length}");
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value, json!({"error":code}), "{path}");
            assert!(error_catalog::lookup(Some(status.as_u16()), code).is_some());
            let doc: Value = serde_json::from_str(include_str!("../../docs/openapi.json")).unwrap();
            let template = if path.starts_with("/v1/lanes/") {
                if path.ends_with("/cancel") {
                    "/v1/lanes/{lane}/jobs/{id}/cancel"
                } else {
                    "/v1/lanes/{lane}/jobs"
                }
            } else {
                path
            };
            let schema = &doc["paths"][template]["post"]["responses"][status.as_str()]["content"]
                ["application/json"]["schema"];
            assert!(!schema.is_null(), "undocumented boundary: {path} {status}");
            let mut schema = schema.clone();
            schema["components"] = doc["components"].clone();
            assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
        }
    }
    assert!(
        table.lock().unwrap().jobs.is_empty(),
        "refused requests reached admission"
    );
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn common_body_size_and_content_type_refusals() {
        super::check_request_refusals(&["/v1/agent/pull"]).await;
    }
}

#[cfg(test)]
mod boundary_acceptance_tests {
    use crate::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn boundary_accepts_exact_limit_and_legacy_missing_media() {
        let app = new_app(
            json!({}),
            std::env::temp_dir().join("unused-boundary-store"),
        );
        let router = router_with_app(app);
        let mut body = vec![b' '; dispatch_kinds::Config::default().body_max];
        body[..2].copy_from_slice(b"{}");
        for media in [
            None,
            Some("application/json"),
            Some("Application/JSON; charset=utf-8"),
        ] {
            let mut request = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v1/agent/pull");
            if let Some(media) = media {
                request = request.header("content-type", media);
            }
            let response = router
                .clone()
                .oneshot(request.body(axum::body::Body::from(body.clone())).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "bounded request must reach pull shape validation"
            );
        }
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/health")
                    .header("content-type", "text/plain")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

/// Enforce only schema closures, leaving existing shape/refusal precedence intact.
fn unknown_fields(doc: &Value, definition: &Value, value: &Value) -> bool {
    if let Some(reference) = definition["$ref"].as_str() {
        return doc
            .pointer(reference.strip_prefix('#').unwrap_or(reference))
            .is_some_and(|resolved| unknown_fields(doc, resolved, value));
    }
    if let Some(fields) = value.as_object() {
        if definition["additionalProperties"] == false
            && fields
                .iter()
                .any(|(field, _)| definition["properties"].get(field).is_none())
        {
            return true;
        }
        if fields.iter().any(|(field, child)| {
            definition["properties"]
                .get(field)
                .is_some_and(|nested| unknown_fields(doc, nested, child))
        }) {
            return true;
        }
    }
    value.as_array().is_some_and(|items| {
        items
            .iter()
            .any(|child| unknown_fields(doc, &definition["items"], child))
    })
}

#[cfg(test)]
pub(super) async fn check_input_hardening(
    body_paths: &[(&str, &str)],
    path_cases: &[&str],
    refusal: &str,
) {
    use tower::ServiceExt;
    let app = new_app(
        json!({}),
        std::env::temp_dir().join("unused-run26-route-store"),
    );
    let table = app.st.clone();
    let router = router_with_app(app);
    for (path, method) in body_paths.iter().filter(|_| refusal == "body") {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(*method)
                    .uri(*path)
                    .body(axum::body::Body::from(vec![
                        b' ';
                        dispatch_kinds::Config::default(
                        )
                        .body_max
                            + 1
                    ]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{method} {path}"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"error":error_catalog::REQUEST_TOO_LARGE})
        );
    }
    for path in path_cases.iter().filter(|_| refusal == "path") {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(*path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"error":error_catalog::PATH_UNSAFE})
        );
    }
    for body in [
        json!({"unexpected":true}),
        json!({"report":{"unexpected":true}}),
    ]
    .into_iter()
    .filter(|_| refusal == "fields")
    {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/agent/pull")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap(),
            json!({"error":error_catalog::INVALID_REQUEST})
        );
    }
    assert!(table.lock().unwrap().jobs.is_empty());
}

#[cfg(test)]
mod input_hardening_tests {
    #[tokio::test]
    async fn common_body_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/agent/pull", "POST")],
            &["/v1/models/%FF"],
            "body",
        )
        .await;
    }
    #[tokio::test]
    async fn common_path_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/agent/pull", "POST")],
            &["/v1/models/%FF"],
            "path",
        )
        .await;
    }
    #[tokio::test]
    async fn common_fields_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/agent/pull", "POST")],
            &["/v1/models/%FF"],
            "fields",
        )
        .await;
    }
}

#[cfg(test)]
pub(super) fn fuzz_table(module: &str, path: &str, template: &str) {
    if std::env::var_os("ROUTE_FUZZ_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args([
                "--exact",
                &format!("routes::{module}::fuzz_tests::malformed_body_table"),
                "--quiet"
            ])
            .env("ROUTE_FUZZ_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        use tower::ServiceExt;
        let fixture = crate::contract_ref_tests::Fixture::new();
        let router = router_with_app(fixture.app.clone());
        let pull = path == "/v1/agent/pull";
        let generate = path == "/v1/generate";
        let malformed_status = if pull { 400 } else { 422 };
        let malformed_code = if pull {
            "invalid request"
        } else if generate {
            "invalid JSON"
        } else {
            error_catalog::BAD_JSON
        };
        let wrong_code = if pull {
            "invalid request"
        } else if generate {
            "request must be an object"
        } else {
            error_catalog::BAD_SPEC
        };
        let cases = [
            (
                "truncated",
                "{".to_owned(),
                malformed_status,
                malformed_code,
            ),
            (
                "wrong type",
                "[]".to_owned(),
                if pull || !generate { 400 } else { 422 },
                wrong_code,
            ),
            (
                "oversized string",
                json!({"prompt":"x".repeat(dispatch_kinds::Config::default().body_max + 1)})
                    .to_string(),
                413,
                error_catalog::REQUEST_TOO_LARGE,
            ),
            (
                "nested depth",
                format!("{}0{}", "[".repeat(140), "]".repeat(140)),
                malformed_status,
                malformed_code,
            ),
            (
                "duplicate fields",
                r#"{"lane":"tts","lane":"tts"}"#.to_owned(),
                if pull { 400 } else { 422 },
                if pull {
                    error_catalog::INVALID_REQUEST
                } else {
                    malformed_code
                },
            ),
        ];
        let doc: Value = serde_json::from_str(include_str!("../../docs/openapi.json")).unwrap();
        for (label, body, expected, message) in cases {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .header(
                            "authorization",
                            crate::contract_ref_tests::APPROVED.unwrap(),
                        )
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected, "{module}: {label}");
            assert_ne!(expected, 500);
            let value: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 10000)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(value, json!({"error":message}), "{module}: {label}");
            let entry = error_catalog::TABLE
                .iter()
                .find(|entry| {
                    entry.reason == message
                        && (entry.status.is_none() || entry.status == Some(expected))
                })
                .expect("declared catalog entry");
            assert!(
                entry.code.is_empty() || entry.code == message,
                "catalog code mismatch"
            );
            let definition = &doc["paths"][template]["post"]["responses"][expected.to_string()]
                ["content"]["application/json"]["schema"];
            assert!(definition.is_object(), "undeclared {path} {expected}");
            let mut definition = definition.clone();
            definition["components"] = doc["components"].clone();
            assert!(
                jsonschema::validator_for(&definition)
                    .unwrap()
                    .is_valid(&value),
                "{module}: {label}: {value}"
            );
        }
        assert!(fixture.app.st.lock().unwrap().jobs.is_empty());
    });
}

#[cfg(test)]
mod fuzz_tests {
    #[test]
    fn malformed_body_table() {
        super::fuzz_table("common", "/v1/agent/pull", "/v1/agent/pull");
    }
}
