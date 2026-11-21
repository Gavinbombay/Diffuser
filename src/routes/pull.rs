use crate::*;
pub(crate) async fn h_agent_pull(
    State(a): State<App>,
    h: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid request");
    };
    match agent_pull::authorize_request(&request, |lane| auth(&h, lane).map_err(Box::new)) {
        Ok(()) => {}
        Err(agent_pull::PullAuthorization::InvalidRequest) => {
            return err(StatusCode::BAD_REQUEST, "invalid request")
        }
        Err(agent_pull::PullAuthorization::Denied(response)) => return *response,
    }
    let wait = Duration::from_secs(request["wait_s"].as_u64().unwrap());
    let result = agent_pull::long_poll(&request, wait, Duration::from_millis(200), |pull| {
        let now = (a.clock)();
        let state_dir = a.compat["card_state_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/mnt/sn850x/lanes/gpu-backlog"));
        let snapshot = card_state::refresh(&state_dir, now);
        let card = &snapshot["colab-l4"];
        *a.cards.lock().unwrap() = snapshot.clone();
        let registered = load_registry().ok().is_some_and(|workers| {
            workers.iter().any(|w| {
                w.id == "colab-l4"
                    && w.enabled
                    && pull["lanes"].as_array().is_some_and(|lanes| {
                        lanes.iter().all(|lane| {
                            lane.as_str()
                                .is_some_and(|name| w.lanes.iter().any(|allowed| allowed == name))
                        })
                    })
            })
        });
        if card_state::colab_proof(card, registered.then_some("colab-l4"), now).is_err() {
            return if pull.get("report").is_some() {
                Err((StatusCode::SERVICE_UNAVAILABLE, "card proof unavailable"))
            } else {
                Ok(None)
            };
        }
        let floor_path = a.compat["cu_floor_path"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| base_dir().join("cu-floor.txt"));
        let floor = fs::read_to_string(floor_path)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
            .ok_or((StatusCode::SERVICE_UNAVAILABLE, "CU floor unavailable"))?;
        let balance = card["cu"]["balance"]
            .as_f64()
            .filter(|v| v.is_finite())
            .ok_or((StatusCode::SERVICE_UNAVAILABLE, "CU balance unavailable"))?;
        let ts = utc_stamp(now).ok_or((StatusCode::SERVICE_UNAVAILABLE, "clock unavailable"))?;
        let expiry = utc_stamp(now.saturating_add(60))
            .ok_or((StatusCode::SERVICE_UNAVAILABLE, "clock unavailable"))?;
        static NEXT_LEASE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let lease = format!(
            "lease-{}-{}-{}",
            std::process::id(),
            now,
            NEXT_LEASE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let root = a.compat["jobs_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(jobs_dir);
        let boundary = segment_lifecycle::Boundary {
            root: &root,
            job_id: "unused",
            ts: &ts,
            balance,
            floor,
            gpu_class: card["gpu_class"].as_str().unwrap_or("any"),
        };
        let mut table = a.st.lock().unwrap();
        deadline::process(&mut table.jobs, now);
        table
            .agent_pull_transaction(pull, card, now, &boundary, &lease, &expiry)
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "ledger write failed"))?
            .map_err(|_| (StatusCode::CONFLICT, "invalid report"))
    })
    .await;
    match result {
        Ok(value) => Json(value).into_response(),
        Err((code, message)) => err(code, message),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn pull_body_size_and_content_type_refusals() {
        crate::routes::common::check_request_refusals(&["/v1/agent/pull"]).await;
    }
}

#[cfg(test)]
mod input_hardening_tests {
    #[tokio::test]
    async fn pull_body_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/agent/pull", "POST")],
            &["/v1/lanes/%FF/jobs/fixture"],
            "body",
        )
        .await;
    }
    #[tokio::test]
    async fn pull_path_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/agent/pull", "POST")],
            &["/v1/lanes/%FF/jobs/fixture"],
            "path",
        )
        .await;
    }
    #[tokio::test]
    async fn pull_fields_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/agent/pull", "POST")],
            &["/v1/lanes/%FF/jobs/fixture"],
            "fields",
        )
        .await;
    }
}

#[cfg(test)]
mod fuzz_tests {
    #[test]
    fn malformed_body_table() {
        super::super::common::fuzz_table("pull", "/v1/agent/pull", "/v1/agent/pull");
    }
}
