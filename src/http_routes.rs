//! The route inventory and registrations share one declaration.
use crate::*;
macro_rules! routes {
    ($( $path:literal => $method:ident($handler:ident) $(.fallback($refusal:path))? ),* $(,)?) => {
        pub const ROUTES: &[(&str, &str)] = &[$(($path, stringify!($method))),*];
        pub fn register() -> Router<App> {
            debug_assert_eq!(ROUTES.len(), 29);
            debug_assert!(ROUTES.iter().all(|(path, _)| error_catalog::route_codes(path).iter().all(|code| error_catalog::lookup(None, code).is_some())));
            Router::new()$(.route($path, $method($handler)$(.fallback($refusal))?))*
                .route_layer(axum::middleware::from_fn(request_guard))
        }
    }
}
routes! {
    "/v1/agent/pull" => post(h_agent_pull),
    "/v1/generate" => post(h_generate),
    "/v1/chat/completions" => post(h_chat),
    "/openai/v1/chat/completions" => post(h_chat),
    "/v1/embeddings" => post(h_compat),
    "/openai/v1/embeddings" => post(h_compat),
    "/v1/embed" => post(h_compat),
    "/embed" => post(h_compat),
    "/v1/models" => get(h_catalog),
    "/openai/v1/models" => get(h_catalog),
    "/openai/models" => get(h_catalog),
    "/models" => get(h_catalog),
    "/api/v1/models" => get(h_catalog),
    "/api/models" => get(h_catalog),
    "/api/tags" => get(h_catalog),
    "/v1/models/{id}" => get(h_catalog),
    "/openai/v1/models/{id}" => get(h_catalog),
    "/openai/models/{id}" => get(h_catalog),
    "/models/{id}" => get(h_catalog),
    "/api/v1/models/{id}" => get(h_catalog),
    "/api/models/{id}" => get(h_catalog),
    "/v1/health" => get(h_health),
    "/v1/lanes" => get(h_lanes),
    "/v1/lanes/{lane}/workers" => get(h_workers),
    "/v1/lanes/{lane}/jobs" => post(h_submit),
    "/v1/lanes/{lane}/jobs/{id}" => get(h_job),
    "/v1/lanes/{lane}/jobs/{id}/artifacts" => get(h_artifact_list).fallback(artifact_routes::method_refusal),
    "/v1/lanes/{lane}/jobs/{id}/artifacts/{*name}" => get(h_artifact).fallback(artifact_routes::method_refusal),
    "/v1/lanes/{lane}/jobs/{id}/cancel" => post(h_cancel),
}

#[cfg(test)]
mod run34_parity {
    use super::*;
    use std::collections::BTreeSet;
    fn parity(doc: &Value) -> Result<(), Vec<String>> {
        let canonical = |path: &str| path.replace("{*", "{");
        let routes: BTreeSet<_> = ROUTES
            .iter()
            .map(|(path, method)| (canonical(path), method.to_string()))
            .collect();
        let mut documented = BTreeSet::new();
        for (path, operations) in doc["paths"].as_object().expect("OpenAPI paths") {
            for method in [
                "get", "post", "put", "patch", "delete", "head", "options", "trace",
            ] {
                if operations.get(method).is_some() {
                    documented.insert((canonical(path), method.to_owned()));
                }
            }
        }
        let mut failures = Vec::new();
        for (path, method) in routes.difference(&documented) {
            failures.push(format!("route missing documentation: {method} {path}"));
        }
        for (path, method) in documented.difference(&routes) {
            failures.push(format!(
                "documented operation missing route: {method} {path}"
            ));
        }
        // Registration is centralized so handlers cannot silently add routes
        // outside the inventory used to construct the actual router.
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/routes");
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                let source = std::fs::read_to_string(&path).unwrap();
                for (index, line) in source.lines().enumerate() {
                    for registration in [
                        ".route(",
                        ".route_service(",
                        ".nest(",
                        ".nest_service(",
                        ".merge(",
                    ] {
                        if line.contains(registration) {
                            failures.push(format!("src/routes/{}:{}: route registration must join http_routes inventory: {}", path.file_name().unwrap().to_str().unwrap(), index + 1, line.trim()));
                        }
                    }
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
    #[test]
    fn run34_real_http_openapi_parity_passes() {
        let doc: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
        assert_eq!(parity(&doc), Ok(()));
        assert_eq!(ROUTES.len(), 29);
    }
    #[test]
    fn run34_planted_documented_path_fails() {
        let doc: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
        let mut extra = doc.clone();
        extra["paths"]["/planted"]["post"] = json!({});
        assert_eq!(
            parity(&extra).unwrap_err(),
            vec!["documented operation missing route: post /planted"]
        );
        let mut missing = doc.clone();
        missing["paths"]
            .as_object_mut()
            .unwrap()
            .remove("/v1/health");
        assert_eq!(
            parity(&missing).unwrap_err(),
            vec!["route missing documentation: get /v1/health"]
        );
        let mut method = doc;
        method["paths"]["/v1/health"]["post"] = json!({});
        assert_eq!(
            parity(&method).unwrap_err(),
            vec!["documented operation missing route: post /v1/health"]
        );
    }
}
