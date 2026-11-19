//! RUN36 route wiring is checked against the mounted declaration and live router.
use crate::*;
use std::collections::BTreeSet;
use tower::ServiceExt;

fn sources() -> BTreeMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes");
    fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_str().unwrap().to_owned(),
                fs::read_to_string(path).unwrap(),
            )
        })
        .collect()
}

fn wiring(
    modules: &BTreeMap<String, String>,
    declaration: &str,
    server: &str,
) -> Result<(), String> {
    let declared =
        regex::Regex::new(r"(?m)^pub\(crate\) (?:async )?fn (h_[a-z_]+|queue_refusal)\(").unwrap();
    let mounted = regex::Regex::new(r#"(?m)^\s*"([^"]+)" => (get|post)\((h_[a-z_]+)\)"#).unwrap();
    let mut definitions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, source) in modules {
        for row in declared.captures_iter(source) {
            definitions
                .entry(row[1].into())
                .or_default()
                .push(file.clone());
        }
    }
    let rows: Vec<_> = mounted.captures_iter(declaration).collect();
    let inventory: BTreeSet<_> = rows
        .iter()
        .map(|row| (row[1].to_owned(), row[2].to_owned()))
        .collect();
    let real: BTreeSet<_> = http_routes::ROUTES
        .iter()
        .map(|(path, method)| (path.to_string(), method.to_string()))
        .collect();
    if rows.len() != inventory.len() || inventory != real {
        return Err("mounted route inventory differs".into());
    }
    let mut used: BTreeSet<_> = rows.iter().map(|row| row[3].to_owned()).collect();
    for (reference, handler) in [
        (".fallback(h_not_found)", "h_not_found"),
        (
            ".method_not_allowed_fallback(h_method_not_allowed)",
            "h_method_not_allowed",
        ),
    ] {
        if !server.contains(reference) {
            return Err(format!("server missing {handler}"));
        }
        used.insert(handler.into());
    }
    for file in ["jobs.rs", "compat.rs"] {
        if !modules[file]
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .contains("return queue_refusal(hint);")
        {
            return Err(format!("{file}: queue refusal disconnected"));
        }
    }
    used.insert("queue_refusal".into());
    if !server.contains("http_routes::register()")
        || !server.contains(".with_state(app)")
        || !declaration.contains("from_fn(request_guard)")
    {
        return Err("server or common middleware disconnected".into());
    }
    for handler in &used {
        if definitions
            .get(handler)
            .is_none_or(|files| files.len() != 1)
        {
            return Err(format!(
                "handler {handler}: missing or duplicate definition"
            ));
        }
    }
    for handler in definitions.keys() {
        if !used.contains(handler) {
            return Err(format!("unmounted handler {handler}"));
        }
    }
    let files: BTreeSet<_> = definitions.values().flatten().map(String::as_str).collect();
    if files != BTreeSet::from(["pull.rs", "jobs.rs", "queue.rs", "compat.rs"]) {
        return Err("handler module coverage differs".into());
    }
    Ok(())
}

#[test]
fn run36_v2_real_wiring_and_common_catalog_bodies() {
    if std::env::var_os("RUN36_WIRING_CHILD").is_none() {
        let output = crate::test_process::command()
            .args([
                "--exact",
                "route_wiring_tests::run36_v2_real_wiring_and_common_catalog_bodies",
                "--quiet",
            ])
            .env("RUN36_WIRING_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        return;
    }
    wiring(
        &sources(),
        include_str!("http_routes.rs"),
        include_str!("routes/server.rs"),
    )
    .unwrap();
    let root = std::env::temp_dir().join(format!("run36-wiring-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    pull_http_tests::auth_fixture(&root);
    std::env::set_var("LANE_ROUTER_HOME", &root);
    std::env::set_var("LANE_REGISTRY", root.join("workers.cfg"));
    fs::write(root.join("workers.cfg"), br#"{"workers":[]}"#).unwrap();
    let app = new_app(
        json!({"card_state_dir":root.join("cards"),"cu_floor_path":root.join("floor"),"result_store_dir":root.join("results")}),
        root.join("store"),
    );
    let router = router_with_app(app);
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for (path, method) in http_routes::ROUTES {
            let uri = path
                .replace("{lane}", "tts")
                .replace("{id}", "missing")
                .replace("{*name}", "speech.wav");
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method(method.to_uppercase().as_str())
                        .uri(&uri)
                        .header("authorization", contract_ref_tests::APPROVED.unwrap())
                        .body(axum::body::Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
            let body: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_ne!(
                body["status"], "not_found",
                "mounted route reached unknown-path fallback: {path}"
            );
        }
        // Common's coded errors retain exact code bytes in the error member.
        for (status, code) in [
            (400, error_catalog::PATH_UNSAFE),
            (400, error_catalog::INVALID_REQUEST),
            (413, error_catalog::REQUEST_TOO_LARGE),
            (415, error_catalog::UNSUPPORTED_MEDIA_TYPE),
        ] {
            let response = err(StatusCode::from_u16(status).unwrap(), code);
            assert_eq!(response.status().as_u16(), status);
            let body: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(body["error"], code);
            assert_eq!(
                error_catalog::refusal_entry(Some(status), body["error"].as_str().unwrap())
                    .unwrap()
                    .code,
                code
            );
        }
        let response = queue_refusal(1);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["code"], error_catalog::QUEUE_FULL);
    });
    assert!(
        !root.join("jobs").exists()
            && !root.join("results").exists()
            && !root.join("store").exists()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn run36_v2_unmounted_and_duplicate_handlers_fail() {
    let modules = sources();
    let declaration = include_str!("http_routes.rs");
    let server = include_str!("routes/server.rs");
    let extra = "pub(crate) async fn h_unmounted() {}\n";
    for file in ["pull.rs", "jobs.rs", "queue.rs", "compat.rs"] {
        let mut bad = modules.clone();
        bad.get_mut(file).unwrap().insert_str(0, extra);
        assert_eq!(
            wiring(&bad, declaration, server).unwrap_err(),
            "unmounted handler h_unmounted"
        );
        let mut appended = modules.clone();
        appended.get_mut(file).unwrap().push_str(extra);
        assert_eq!(
            wiring(&appended, declaration, server).unwrap_err(),
            "unmounted handler h_unmounted"
        );
    }
    let mut duplicate = modules.clone();
    duplicate
        .get_mut("queue.rs")
        .unwrap()
        .insert_str(0, "pub(crate) async fn h_agent_pull() {}\n");
    assert!(wiring(&duplicate, declaration, server)
        .unwrap_err()
        .contains("duplicate definition"));
    assert!(wiring(
        &modules,
        declaration,
        &server.replace("http_routes::register()", "removed()")
    )
    .is_err());
    assert!(wiring(
        &modules,
        &declaration.replace("from_fn(request_guard)", "from_fn(removed)"),
        server
    )
    .is_err());
}
