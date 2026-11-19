use crate::*;
pub(crate) fn publish_policy(row: &Value, now: u64) -> Result<(), &'static str> {
    let root = row["result_store_root"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join("results"));
    deadline::write_devices(&root, row).and_then(|()| result_store::publish_record(&root, row, now))
}

pub(crate) fn wait_for_turn(
    st: &Shared,
    id: &str,
    cfg: queue_policy::Config,
    clock: fn() -> u64,
) -> bool {
    loop {
        let now = clock();
        let (chosen, terminal, expired) = {
            let mut table = st.lock().unwrap();
            let expired: Vec<Value> = deadline::process(&mut table.jobs, now)
                .iter()
                .map(|id| table.jobs[id].clone())
                .collect();
            let terminal = queue_policy::terminal(&table.jobs[id]);
            let chosen = !terminal
                && queue_policy::next(&table.jobs, table.queue_last, cfg, |candidate| {
                    !table.agent_queue.iter().any(|queued| queued == candidate)
                })
                .as_deref()
                    == Some(id);
            if chosen {
                table.queue_last = LANES
                    .iter()
                    .position(|l| *l == queue_policy::lane(&table.jobs[id]));
                table.jobs.get_mut(id).unwrap()["state"] = json!("dispatching");
            }
            (chosen, terminal, expired)
        };
        for row in expired {
            if let Err(reason) = publish_policy(&row, now) {
                eprintln!("deadline result write failed: {reason}");
            }
        }
        if terminal {
            return false;
        }
        if chosen {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(crate) fn queue_refusal(hint: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [("retry-after", hint.to_string())],
        Json(queue_policy::envelope(
            crate::error_catalog::QUEUE_FULL,
            true,
        )),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn queue_body_size_and_content_type_refusals() {
        crate::routes::common::check_request_refusals(&["/v1/lanes/tts/jobs"]).await;
    }
}

#[cfg(test)]
mod input_hardening_tests {
    #[tokio::test]
    async fn queue_body_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/lanes/tts/jobs", "POST")],
            &["/v1/lanes/tts/jobs/%FF/artifacts"],
            "body",
        )
        .await;
    }
    #[tokio::test]
    async fn queue_path_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/lanes/tts/jobs", "POST")],
            &["/v1/lanes/tts/jobs/%FF/artifacts"],
            "path",
        )
        .await;
    }
    #[tokio::test]
    async fn queue_fields_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[("/v1/lanes/tts/jobs", "POST")],
            &["/v1/lanes/tts/jobs/%FF/artifacts"],
            "fields",
        )
        .await;
    }
}

#[cfg(test)]
mod fuzz_tests {
    #[test]
    fn malformed_body_table() {
        super::super::common::fuzz_table("queue", "/v1/lanes/tts/jobs", "/v1/lanes/{lane}/jobs");
    }
}
