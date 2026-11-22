use crate::*;
pub(crate) fn bind_ok(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v) => v.is_loopback() || v.octets()[0] == 10, // loopback, or the 10.0.0.0/24 private LAN / tunnel ends
        IpAddr::V6(v) => v.is_loopback(),
    }
}

pub(crate) fn cleanup_staging(app: &App) {
    let table = app.st.lock().unwrap();
    let mut jobs: Vec<Value> = table.jobs.values().cloned().collect();
    let records = app.compat["jobs_dir"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(jobs_dir);
    match fs::read_dir(records) {
        Ok(entries) => {
            for entry in entries {
                let record = (|| -> Result<Option<Value>, String> {
                    let entry = entry.map_err(|e| e.to_string())?;
                    if entry.file_type().map_err(|e| e.to_string())?.is_symlink() {
                        return Err("job record symlink".into());
                    }
                    if entry.path().extension().is_some_and(|ext| ext == "json") {
                        return serde_json::from_slice(
                            &fs::read(entry.path()).map_err(|e| e.to_string())?,
                        )
                        .map(Some)
                        .map_err(|e| e.to_string());
                    }
                    Ok(None)
                })();
                match record {
                    Ok(Some(record)) => jobs.push(record),
                    Ok(None) => {}
                    Err(reason) => {
                        eprintln!(
                            "staging cleanup refused: unreadable job references: {}",
                            log_redaction::line(&reason)
                        );
                        return;
                    }
                }
            }
        }
        Err(reason) if reason.kind() == std::io::ErrorKind::NotFound => {}
        Err(reason) => {
            eprintln!(
                "staging cleanup refused: unreadable job references: {}",
                log_redaction::line(&reason.to_string())
            );
            return;
        }
    }
    store::cleanup(
        &app.store_root,
        &jobs,
        &store::Config::from_value(&app.compat),
        SystemTime::now(),
        |event| eprintln!("staging cleanup: {}", log_redaction::line(event)),
    );
}

pub(crate) async fn serve(bind: &str) -> Result<(), String> {
    let addr: SocketAddr = bind.parse().map_err(|e| format!("bind {bind}: {e}"))?;
    if !bind_ok(&addr) {
        return Err(format!(
            "refusing bind {addr}: loopback or 10.x LAN only, never 0.0.0.0 or public"
        ));
    }
    let r = reap();
    if !r.is_empty() {
        eprintln!("reaped stale jobs: {r:?}");
    }
    tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let _ = tokio::task::spawn_blocking(reap).await;
        }
    });
    let config = fs::read(base_dir().join("compat-routes.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or(Value::Null);
    let app = new_app(config, base_dir().join("cartridges"));
    cleanup_staging(&app);
    let cleanup_app = app.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let current = cleanup_app.clone();
            let _ = tokio::task::spawn_blocking(move || cleanup_staging(&current)).await;
        }
    });
    if app.compat["watchdog"].is_object() {
        let watch_app = app.clone();
        tokio::spawn(async move {
            watchdog::run(watch_app).await;
        });
    }
    let r = router_with_app(app);
    let l = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("lane-router {API} listening on {addr}");
    axum::serve(l, r).await.map_err(|e| e.to_string())
}

#[cfg(test)]
pub(crate) fn router() -> Router {
    let config = fs::read(base_dir().join("compat-routes.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .unwrap_or(Value::Null);
    router_with_compat(config)
}

#[cfg(test)]
pub(crate) fn router_with_compat(config: Value) -> Router {
    router_with_store(config, base_dir().join("cartridges"))
}

#[cfg(test)]
pub(crate) fn router_with_store(config: Value, store_root: PathBuf) -> Router {
    router_with_app(new_app(config, store_root))
}

pub(crate) fn new_app(config: Value, store_root: PathBuf) -> App {
    App {
        st: Arc::new(Mutex::new(JobTable::default())),
        compat: config,
        store_root,
        cards: Arc::new(Mutex::new(HashMap::new())),
        clock: clock_now,
    }
}

pub(crate) fn router_with_app(app: App) -> Router {
    http_routes::register()
        .fallback(h_not_found)
        .method_not_allowed_fallback(h_method_not_allowed)
        .with_state(app)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn server_body_size_and_content_type_refusals() {
        crate::routes::common::check_request_refusals(&["/v1/generate"]).await;
    }
}

#[cfg(test)]
mod input_hardening_tests {
    #[tokio::test]
    async fn server_body_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/lanes", "GET")],
            &["/v1/lanes/tts/jobs/%FF"],
            "body",
        )
        .await;
    }
    #[tokio::test]
    async fn server_path_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/lanes", "GET")],
            &["/v1/lanes/tts/jobs/%FF"],
            "path",
        )
        .await;
    }
    #[tokio::test]
    async fn server_fields_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/lanes", "GET")],
            &["/v1/lanes/tts/jobs/%FF"],
            "fields",
        )
        .await;
    }
}

#[cfg(test)]
mod fuzz_tests {
    #[test]
    fn malformed_body_table() {
        super::super::common::fuzz_table("server", "/v1/generate", "/v1/generate");
    }
}
