use crate::*;
pub(crate) fn catalog_model_id(path: &str) -> Option<&str> {
    [
        "/v1/models/",
        "/openai/v1/models/",
        "/openai/models/",
        "/models/",
        "/api/v1/models/",
        "/api/models/",
    ]
    .into_iter()
    .find_map(|prefix| path.strip_prefix(prefix))
}

pub(crate) fn compat_lane(config: &Value, path: &str) -> Result<String, StatusCode> {
    let route = if catalog_model_id(path).is_some() {
        "/v1/models/{id}"
    } else {
        path
    };
    let lane = config["routes"][route]
        .as_str()
        .ok_or(StatusCode::NOT_FOUND)?;
    match config["lanes"].get(lane).and_then(Value::as_bool) {
        Some(true) => Ok(lane.to_owned()),
        Some(false) => Err(StatusCode::CONFLICT),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub(crate) fn embedding_input_valid(request: &Value) -> bool {
    let Some(input) = request
        .get("text")
        .or_else(|| request.get("prompt"))
        .or_else(|| request.get("input"))
    else {
        return false;
    };
    let valid_text = |v: &Value| v.as_str().is_some_and(|s| !s.trim().is_empty());
    valid_text(input)
        || input.as_array().is_some_and(|items| {
            !items.is_empty() && items.len() <= 32 && items.iter().all(valid_text)
        })
}

pub(crate) async fn h_compat(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let lane = match compat_lane(&app.compat, uri.path()) {
        Ok(lane) => lane,
        Err(StatusCode::CONFLICT) => return err(StatusCode::CONFLICT, "lane disabled"),
        Err(_) => return err(StatusCode::NOT_FOUND, "unknown lane"),
    };
    if let Err(response) = auth(&headers, &lane) {
        return response;
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "invalid JSON");
    };
    if !request.is_object() || !embedding_input_valid(&request) {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "input must contain nonempty text",
        );
    }
    let encoding = request
        .get("encoding_format")
        .map_or(Some("float"), Value::as_str);
    if !matches!(encoding, Some("float" | "float32" | "base64")) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error":{"message":"unsupported encoding_format", "type":"invalid_request_error", "param":"encoding_format", "code":crate::error_catalog::reason(crate::error_catalog::UNSUPPORTED_ENCODING_FORMAT)}, "uai":{}}))).into_response();
    }
    let encoded = encoding == Some("base64");
    let count = request
        .get("text")
        .or_else(|| request.get("prompt"))
        .or_else(|| request.get("input"))
        .unwrap()
        .as_array()
        .map_or(1, Vec::len);
    let native = uri.path() == "/v1/embed" || uri.path() == "/embed";
    let state = app.st.clone();
    let dispatched =
        tokio::task::spawn_blocking(move || compat_dispatch(&state, &lane, &request, "--embed"))
            .await;
    match dispatched {
        Ok(Ok(result)) => {
            let vectors = result["embeddings"].as_array();
            let valid = vectors.is_some_and(|v| {
                v.len() == count
                    && v.iter().all(|row| {
                        row.as_array()
                            .is_some_and(|r| !r.is_empty() && r.iter().all(Value::is_number))
                    })
            }) && result["model"].is_string()
                && result[crate::error_catalog::USAGE]["prompt_tokens"]
                    .as_u64()
                    .is_some()
                && result[crate::error_catalog::USAGE]["total_tokens"]
                    .as_u64()
                    .is_some();
            if !valid {
                return err(StatusCode::BAD_GATEWAY, "invalid embedding worker response");
            }
            let vectors = vectors.unwrap();
            if native {
                let embedding = if count == 1 {
                    vectors[0].clone()
                } else {
                    json!(vectors)
                };
                Json(json!({"status":"ok", "embedding":embedding, "model":result["model"], (crate::error_catalog::USAGE):result[crate::error_catalog::USAGE], "uai":{}})).into_response()
            } else {
                use base64::Engine;
                let data: Vec<Value> = vectors
                    .iter()
                    .enumerate()
                    .map(|(index, embedding)| {
                        let value = if encoded {
                            let bytes: Vec<u8> = embedding
                                .as_array()
                                .unwrap()
                                .iter()
                                .flat_map(|n| (n.as_f64().unwrap() as f32).to_le_bytes())
                                .collect();
                            json!(base64::engine::general_purpose::STANDARD.encode(bytes))
                        } else {
                            embedding.clone()
                        };
                        json!({"object":"embedding", "embedding":value, "index":index})
                    })
                    .collect();
                Json(json!({"object":"list", "data":data, "model":result["model"], (crate::error_catalog::USAGE):result[crate::error_catalog::USAGE], "uai":{}})).into_response()
            }
        }
        Ok(Err((status, message))) => err(status, message),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "embedding dispatch failed"),
    }
}

// The compatibility worker reads one JSON request from stdin and returns one JSON
// object on stdout. Its health check and seat accounting use the existing path.
pub(crate) fn compat_dispatch(
    st: &Shared,
    lane: &str,
    request: &Value,
    operation: &str,
) -> Result<Value, (StatusCode, &'static str)> {
    use std::io::Write;
    let workers = load_registry().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "worker registry unavailable",
        )
    })?;
    for worker in workers {
        let busy = st.lock().unwrap().busy.clone();
        if worker_view(&worker, lane, &busy)["accepting"] != true {
            continue;
        }
        command_policy::authorize(lane, &Command::new(&worker.exec), &worker.dispatch)
            .map_err(|code| (StatusCode::CONFLICT, code))?;
        {
            let mut table = st.lock().unwrap();
            let used = table.busy.entry(worker.id.clone()).or_default();
            if *used >= worker.seats {
                continue;
            }
            *used += 1;
        }
        let result = (|| {
            let mut child = Command::new(&worker.exec)
                .arg(operation)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| ())?;
            let mut input = child.stdin.take().ok_or(())?;
            let data = serde_json::to_vec(request).map_err(|_| ())?;
            let writer = std::thread::spawn(move || input.write_all(&data));
            let output = child.stdout.take().ok_or(())?;
            let reader = std::thread::spawn(move || {
                let mut data = Vec::new();
                output.take(1_000_001).read_to_end(&mut data).map(|_| data)
            });
            let start = Instant::now();
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) if start.elapsed() < Duration::from_secs(45) => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                }
            };
            let written = writer.join().map_err(|_| ())?.map_err(|_| ());
            let data = reader.join().map_err(|_| ())?.map_err(|_| ())?;
            if !status.is_some_and(|s| s.success()) || written.is_err() || data.len() > 1_000_000 {
                return Err(());
            }
            serde_json::from_slice::<Value>(&data).map_err(|_| ())
        })();
        {
            let mut table = st.lock().unwrap();
            if let Some(used) = table.busy.get_mut(&worker.id) {
                *used = used.saturating_sub(1);
            }
        }
        return result.map_err(|_| (StatusCode::BAD_GATEWAY, "compatibility worker failed"));
    }
    Err((StatusCode::CONFLICT, "no accepting compatibility worker"))
}

pub(crate) async fn h_chat(
    State(app): State<App>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let lane = match compat_lane(&app.compat, uri.path()) {
        Ok(lane) => lane,
        Err(StatusCode::CONFLICT) => return err(StatusCode::CONFLICT, "lane disabled"),
        Err(_) => return err(StatusCode::NOT_FOUND, "unknown lane"),
    };
    if let Err(response) = auth(&headers, &lane) {
        return response;
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid JSON");
    };
    if !request.is_object() {
        return err(StatusCode::BAD_REQUEST, "request must be an object");
    }
    if !request["messages"]
        .as_array()
        .is_some_and(|v| !v.is_empty())
    {
        return (StatusCode::BAD_REQUEST, Json(json!({"status":"error", "error":"invalid_messages", "error_code":crate::error_catalog::reason(crate::error_catalog::MESSAGES_REQUIRED), "detail":"messages must be a nonempty array", "uai":{}}))).into_response();
    }
    if !request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["role"] == "user" && m["content"].as_str().is_some_and(|s| !s.trim().is_empty()))
    {
        return (StatusCode::BAD_REQUEST, Json(json!({"status":"error", "error_code":crate::error_catalog::reason(crate::error_catalog::PROMPT_REQUIRED), "detail":"a substantive user message is required", "uai":{}}))).into_response();
    }
    if request.get("stream").is_some_and(|v| !v.is_boolean()) {
        return err(StatusCode::BAD_REQUEST, "stream must be a boolean");
    }
    if request["stream"] == true {
        return err(StatusCode::NOT_IMPLEMENTED, "streaming is not supported");
    }
    let state = app.st.clone();
    let dispatched =
        tokio::task::spawn_blocking(move || compat_dispatch(&state, &lane, &request, "--chat"))
            .await;
    match dispatched {
        Ok(Ok(result)) if result["content"].is_string() && result["model"].is_string()
            && result[crate::error_catalog::USAGE]["prompt_tokens"].as_u64().is_some()
            && result[crate::error_catalog::USAGE]["completion_tokens"].as_u64().is_some()
            && result[crate::error_catalog::USAGE]["total_tokens"].as_u64().is_some() => {
            Json(json!({"id":format!("chat-{}", stamp()), "object":"chat.completion",
                "created":SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                "model":result["model"], "choices":[{"index":0,"message":{"role":"assistant","content":result["content"]},"finish_reason":"stop"}],
                (crate::error_catalog::USAGE):result[crate::error_catalog::USAGE], "uai":{}})).into_response()
        },
        Ok(Ok(_)) => err(StatusCode::BAD_GATEWAY, "invalid chat worker response"),
        Ok(Err((status, message))) => err(status, message),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "chat dispatch failed"),
    }
}

pub(crate) async fn h_generate(
    State(app): State<App>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let lane = match compat_lane(&app.compat, "/v1/generate") {
        Ok(lane) => lane,
        Err(StatusCode::CONFLICT) => return err(StatusCode::CONFLICT, "lane disabled"),
        Err(_) => return err(StatusCode::NOT_FOUND, "unknown lane"),
    };
    if let Err(response) = auth(&headers, &lane) {
        return response;
    }
    let Ok(mut spec) = lane_gate::parse(&body) else {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "invalid JSON");
    };
    if !spec.is_object() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request must be an object",
        );
    }
    if !spec["prompt"]
        .as_str()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "prompt must be a nonempty string",
        );
    }
    spec["lane"] = json!(lane);
    video_defaults(&mut spec);
    if let Err(reason) = cartridge_registry::apply_config(&app.compat, &mut spec) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, reason);
    }
    if let Err(reason) =
        runtime_limits::admit(&mut spec, &runtime_limits::Config::from_value(&app.compat))
    {
        return err(StatusCode::UNPROCESSABLE_ENTITY, reason);
    }
    if let Err(e) = validate(&spec) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, e);
    }
    if let Err(reason) =
        runtime_limits::admit(&mut spec, &runtime_limits::Config::from_value(&app.compat))
    {
        return err(StatusCode::UNPROCESSABLE_ENTITY, reason);
    }
    if let Err(e) = select_manifest(&mut spec, &app.store_root) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, e);
    }
    if let Err(reason) = lane_gate::admit(&app.compat, &spec) {
        return err(StatusCode::CONFLICT, reason);
    }
    let admission_spec = spec.clone();
    let admission_state = app.st.clone();
    match tokio::task::spawn_blocking(move || plan(&admission_spec, &admission_state)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.starts_with("no accepting worker for ") => {
            return err(StatusCode::CONFLICT, e)
        }
        Ok(Err(e)) => return err(StatusCode::UNPROCESSABLE_ENTITY, e),
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "admission check failed"),
    }
    let id = spec["job_id"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| format!("gen-{}", stamp()));
    {
        let mut table = app.st.lock().unwrap();
        table.clock = Some(app.clock);
        table.queue_config = queue_policy::Config::from_value(&app.compat);
        if table.jobs.contains_key(&id) {
            return err(StatusCode::CONFLICT, "job_id exists");
        }
        if let Err(hint) = queue_policy::capacity(
            &table.jobs,
            &lane,
            queue_policy::Config::from_value(&app.compat),
            (app.clock)(),
        ) {
            return queue_refusal(hint);
        }
        spec["job_id"] = json!(id);
        let mut queued = queue_policy::admitted(&table.jobs, &spec, (app.clock)());
        queued["result_store_root"] = json!(app.compat["result_store_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| base_dir().join("results")));
        queued["spec_sha256"] = json!(deadline::fingerprint(
            &lane_gate::parse(&body).expect("validated body")
        ));
        table.jobs.insert(id.clone(), queued);
    }
    spec["job_id"] = json!(id);
    let cfg = queue_policy::Config::from_value(&app.compat);
    match tokio::task::spawn_blocking(move || {
        if wait_for_turn(&app.st, &id, cfg, app.clock) {
            run_job(app.st, spec, body.to_vec(), false)
        } else {
            app.st.lock().unwrap().jobs[&id].clone()
        }
    })
    .await
    {
        Ok(result) if result["state"] == "done" => {
            Json(json!({"status":"ok", "job":result})).into_response()
        }
        Ok(result) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"status":"error", "job":result})),
        )
            .into_response(),
        Err(_) => err(StatusCode::SERVICE_UNAVAILABLE, "generation failed"),
    }
}

pub(crate) async fn h_catalog(State(app): State<App>, OriginalUri(uri): OriginalUri) -> Response {
    match compat_lane(&app.compat, uri.path()) {
        Err(StatusCode::CONFLICT) => return err(StatusCode::CONFLICT, "lane disabled"),
        Err(_) => return err(StatusCode::NOT_FOUND, "unknown lane"),
        Ok(_) => {}
    }
    let mut rows = Vec::new();
    if let Some(lanes) = app.compat["lanes"].as_object() {
        for (lane, enabled) in lanes {
            if enabled.as_bool() != Some(true) {
                continue;
            }
            let Ok((manifest, _, _)) = store::active_version(&app.store_root, lane) else {
                continue;
            };
            let Ok(data) = fs::read(manifest) else {
                continue;
            };
            let Ok(cart) = serde_json::from_slice::<cartridge::Cartridge>(&data) else {
                continue;
            };
            if cart.lane == *lane {
                rows.push(json!({"id":cart.id,"object":"model","created":(app.clock)(),"owned_by":lane,"permission":[],"uai":{}}));
            }
        }
    }
    if let Some(id) = catalog_model_id(uri.path()) {
        return match rows.into_iter().find(|row| row["id"] == id) {
            Some(row) => Json(row).into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({"error":{"message":"Model not found","type":"invalid_request_error","param":"model","code":crate::error_catalog::reason(crate::error_catalog::MODEL_NOT_FOUND)},"uai":{}}))).into_response(),
        };
    }
    if uri.path() == "/api/tags" {
        let models: Vec<Value> = rows
            .iter()
            .map(|row| json!({"name":row["id"],"model":row["id"]}))
            .collect();
        Json(json!({"models":models})).into_response()
    } else {
        Json(json!({"object":"list","data":rows})).into_response()
    }
}

pub(crate) async fn h_not_found(method: Method, OriginalUri(uri): OriginalUri) -> Response {
    if (uri.path().starts_with("/v1/") || uri.path().starts_with("/openai/v1/"))
        && matches!(method, Method::PUT | Method::PATCH | Method::DELETE)
    {
        return h_method_not_allowed(method).await;
    }
    error_catalog::observe(Some(404), "not_found");
    (
        StatusCode::NOT_FOUND,
        Json(json!({"status":"not_found", "path":uri.path()})),
    )
        .into_response()
}

pub(crate) async fn h_method_not_allowed(method: Method) -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, Json(json!({"status":"method_not_allowed", "detail":"method not allowed", "method":method.as_str()}))).into_response()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn compat_body_size_and_content_type_refusals() {
        crate::routes::common::check_request_refusals(&[
            "/v1/generate",
            "/v1/chat/completions",
            "/openai/v1/chat/completions",
            "/v1/embeddings",
            "/openai/v1/embeddings",
            "/v1/embed",
            "/embed",
        ])
        .await;
    }
}

#[cfg(test)]
mod input_hardening_tests {
    #[tokio::test]
    async fn compat_body_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[
                ("/v1/generate", "POST"),
                ("/v1/chat/completions", "POST"),
                ("/openai/v1/chat/completions", "POST"),
                ("/v1/embeddings", "POST"),
                ("/openai/v1/embeddings", "POST"),
                ("/v1/embed", "POST"),
                ("/embed", "POST"),
                ("/v1/models", "GET"),
                ("/openai/v1/models", "GET"),
                ("/openai/models", "GET"),
                ("/models", "GET"),
                ("/api/v1/models", "GET"),
                ("/api/models", "GET"),
                ("/api/tags", "GET"),
                ("/v1/models/fixture", "GET"),
                ("/openai/v1/models/fixture", "GET"),
                ("/openai/models/fixture", "GET"),
                ("/models/fixture", "GET"),
                ("/api/v1/models/fixture", "GET"),
                ("/api/models/fixture", "GET"),
            ],
            &[
                "/v1/models/%FF",
                "/openai/v1/models/%FF",
                "/openai/models/%FF",
                "/models/%FF",
                "/api/v1/models/%FF",
                "/api/models/%FF",
            ],
            "body",
        )
        .await;
    }
    #[tokio::test]
    async fn compat_path_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[
                ("/v1/generate", "POST"),
                ("/v1/chat/completions", "POST"),
                ("/openai/v1/chat/completions", "POST"),
                ("/v1/embeddings", "POST"),
                ("/openai/v1/embeddings", "POST"),
                ("/v1/embed", "POST"),
                ("/embed", "POST"),
                ("/v1/models", "GET"),
                ("/openai/v1/models", "GET"),
                ("/openai/models", "GET"),
                ("/models", "GET"),
                ("/api/v1/models", "GET"),
                ("/api/models", "GET"),
                ("/api/tags", "GET"),
                ("/v1/models/fixture", "GET"),
                ("/openai/v1/models/fixture", "GET"),
                ("/openai/models/fixture", "GET"),
                ("/models/fixture", "GET"),
                ("/api/v1/models/fixture", "GET"),
                ("/api/models/fixture", "GET"),
            ],
            &[
                "/v1/models/%FF",
                "/openai/v1/models/%FF",
                "/openai/models/%FF",
                "/models/%FF",
                "/api/v1/models/%FF",
                "/api/models/%FF",
            ],
            "path",
        )
        .await;
    }
    #[tokio::test]
    async fn compat_fields_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[
                ("/v1/generate", "POST"),
                ("/v1/chat/completions", "POST"),
                ("/openai/v1/chat/completions", "POST"),
                ("/v1/embeddings", "POST"),
                ("/openai/v1/embeddings", "POST"),
                ("/v1/embed", "POST"),
                ("/embed", "POST"),
                ("/v1/models", "GET"),
                ("/openai/v1/models", "GET"),
                ("/openai/models", "GET"),
                ("/models", "GET"),
                ("/api/v1/models", "GET"),
                ("/api/models", "GET"),
                ("/api/tags", "GET"),
                ("/v1/models/fixture", "GET"),
                ("/openai/v1/models/fixture", "GET"),
                ("/openai/models/fixture", "GET"),
                ("/models/fixture", "GET"),
                ("/api/v1/models/fixture", "GET"),
                ("/api/models/fixture", "GET"),
            ],
            &[
                "/v1/models/%FF",
                "/openai/v1/models/%FF",
                "/openai/models/%FF",
                "/models/%FF",
                "/api/v1/models/%FF",
                "/api/models/%FF",
            ],
            "fields",
        )
        .await;
    }
}

#[cfg(test)]
mod fuzz_tests {
    #[test]
    fn malformed_body_table() {
        super::super::common::fuzz_table("compat", "/v1/generate", "/v1/generate");
    }
}

#[cfg(test)]
mod run35_u4 {
    use super::*;
    use std::collections::BTreeSet;
    use tower::ServiceExt;

    #[tokio::test]
    async fn run35_u4_all_compat_paths_table() {
        let rows: Vec<Value> =
            serde_json::from_str(include_str!("../../docs/RUN35-COMPAT.json")).unwrap();
        let doc: Value = serde_json::from_str(include_str!("../../docs/openapi.json")).unwrap();
        let source = include_str!("../http_routes.rs");
        let registered: BTreeSet<_> = source
            .lines()
            .filter(|line| {
                line.trim_start().starts_with('"')
                    && ["h_compat", "h_chat", "h_generate", "h_catalog"]
                        .iter()
                        .any(|handler| line.contains(handler))
            })
            .map(|line| line.split('"').nth(1).unwrap())
            .collect();
        let documented: BTreeSet<_> = rows
            .iter()
            .map(|row| row["path"].as_str().unwrap())
            .collect();
        assert_eq!(rows.len(), 20);
        assert_eq!(documented.len(), rows.len());
        assert_eq!(registered, documented);
        let root = std::env::temp_dir().join(format!(
            "fold-run35-compat-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        for row in rows {
            let path = row["path"].as_str().unwrap();
            let current = row["current_route"].as_str().unwrap();
            let method = row["method"].as_str().unwrap();
            let handler = row["handler"].as_str().unwrap();
            let expected = match handler {
                "h_generate" => "/v1/generate",
                "h_chat" => "/v1/chat/completions",
                "h_compat" if ["/embed", "/v1/embed"].contains(&path) => "/v1/embed",
                "h_compat" => "/v1/embeddings",
                "h_catalog" if path == "/api/tags" => "/api/tags",
                "h_catalog" if path.ends_with("{id}") => "/v1/models/{id}",
                "h_catalog" => "/v1/models",
                _ => panic!("unknown compatibility handler"),
            };
            assert_eq!(current, expected, "{path}");
            let declaration = format!("\"{path}\" => {method}({handler})");
            assert!(source.contains(&declaration), "{declaration}");
            assert!(http_routes::ROUTES.contains(&(path, method)));
            assert_eq!(doc["paths"][path][method]["x-current-route"], current);
            let uri = path.replace("{id}", "fixture");
            let mapped = if path.ends_with("{id}") {
                "/v1/models/{id}"
            } else {
                path
            };
            let config = json!({"routes":{mapped:"tts"},"lanes":{"tts":true}});
            assert_eq!(compat_lane(&config, &uri), Ok("tts".into()));
            for enabled in [false, true] {
                if enabled && handler != "h_catalog" {
                    continue;
                }
                let mut config = config.clone();
                config["lanes"]["tts"] = json!(enabled);
                let router = router_with_app(new_app(config, root.clone()));
                let response = router
                    .oneshot(
                        axum::http::Request::builder()
                            .method(method.to_uppercase().as_str())
                            .uri(&uri)
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = if enabled {
                    row["enabled_status"].as_u64().unwrap()
                } else {
                    row["disabled_status"].as_u64().unwrap()
                };
                assert_eq!(response.status().as_u16(), status as u16, "{path}");
                assert!(doc["paths"][path][method]["responses"]
                    .get(status.to_string())
                    .is_some());
            }
            let router = router_with_app(new_app(json!({}), root.clone()));
            let response = router
                .oneshot(
                    axum::http::Request::builder()
                        .method(method.to_uppercase().as_str())
                        .uri(&uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                row["unmapped_status"].as_u64().unwrap() as u16
            );
            let body: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                error_catalog::refusal_entry(Some(404), body["error"].as_str().unwrap())
                    .unwrap()
                    .code,
                error_catalog::UNKNOWN_LANE
            );
        }
        let router = router_with_app(new_app(json!({}), root.clone()));
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/openai/v1/not-a-route")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            error_catalog::lookup(Some(404), body["status"].as_str().unwrap())
                .unwrap()
                .code,
            error_catalog::UNKNOWN_ROUTE
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir(root).unwrap();
    }
}
