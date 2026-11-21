use crate::*;
pub(crate) async fn h_health() -> Json<Value> {
    Json(json!({"ok": true, "api": API, "lanes": LANES}))
}
pub(crate) async fn h_lanes(State(a): State<App>, h: HeaderMap) -> Response {
    if let Err(r) = auth(&h, "render-blender") {
        return r;
    }
    let busy = a.st.lock().unwrap().busy.clone();
    let reg = load_registry().unwrap_or_default();
    let v: Vec<Value> = LANES.iter().map(|l| {
        let ws: Vec<Value> = if *l == "render-blender" { reg.iter().filter(|w| w.lanes.iter().any(|x| x == l)).map(|w| worker_view(w, l, &busy)).collect() } else { vec![] };
        json!({"lane": l, "live": *l == "render-blender", "cartridges": if *l == "render-blender" { json!(RB_CARTRIDGES) } else { json!([]) },
               "accepting":lane_bodies::advertise(&a.compat,l,ws.iter().any(|w|w["accepting"]==true)), "workers_total": ws.len(), "workers_accepting":if *l=="diffusion-video"{0}else{ws.iter().filter(|w|w["accepting"]==true).count()}})
    }).collect();
    Json(json!({"api": API, "lanes": v})).into_response()
}
pub(crate) async fn h_workers(
    State(a): State<App>,
    AxPath(lane): AxPath<String>,
    h: HeaderMap,
) -> Response {
    if let Err(r) = auth(&h, &lane) {
        return r;
    }
    let busy = a.st.lock().unwrap().busy.clone();
    let reg = load_registry().unwrap_or_default();
    let state_dir = a.compat["card_state_dir"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/sn850x/lanes/gpu-backlog"));
    let cards = a.cards.clone();
    let now = (a.clock)();
    let floor_path = a.compat["cu_floor_path"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join("cu-floor.txt"));
    let floor = fs::read_to_string(floor_path)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok());
    let visibility_lane = lane.clone();
    let v = tokio::task::spawn_blocking(move || {
        let snapshot = card_state::refresh(&state_dir, now);
        *cards.lock().unwrap() = snapshot.clone();
        let local = reg
            .iter()
            .any(|w| w.id == "warp-2070")
            .then(|| local_card_probe(now))
            .flatten();
        reg.iter()
            .map(|w| {
                if let Some(state) = snapshot.get(&w.id) {
                    let heartbeat = (w.id == "colab-l4").then(|| json!({"epoch":state["epoch"]}));
                    card_worker_view(
                        w,
                        &lane,
                        &busy,
                        state,
                        now,
                        heartbeat
                            .as_ref()
                            .or(local.as_ref().filter(|_| w.id == "warp-2070")),
                        floor,
                    )
                } else {
                    worker_view(w, &lane, &busy)
                }
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();
    let mut v = v;
    lane_bodies::restrict_discovery(&visibility_lane, &mut v);
    Json(json!({"workers": v})).into_response()
}
pub(crate) async fn h_submit(
    State(a): State<App>,
    AxPath(lane): AxPath<String>,
    h: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(r) = auth(&h, &lane) {
        return r;
    }
    if ["render-blender", "stt", "diffusion-video", "music-sfx"].contains(&lane.as_str()) {
        if let Err(code) =
            render_admission::media_type(h.get("content-type").and_then(|v| v.to_str().ok()))
        {
            return err(StatusCode::UNSUPPORTED_MEDIA_TYPE, code);
        }
    }
    submit_in_process(a, lane, body).await
}

pub(crate) async fn submit_in_process(a: App, lane: String, body: axum::body::Bytes) -> Response {
    if opened_lane(&lane) && a.compat["lanes"][&lane].as_bool() != Some(true) {
        return err(StatusCode::CONFLICT, "lane disabled");
    }
    if body.len() > dispatch_kinds::Config::default().body_max {
        return err(
            StatusCode::PAYLOAD_TOO_LARGE,
            crate::error_catalog::REQUEST_TOO_LARGE,
        );
    }
    let mut spec = match request_boundary::load(&body, Some(&lane)) {
        Ok(v) => v,
        Err(reason) => return err(request_boundary::status(reason, &lane), reason),
    };
    if !spec.is_object() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "spec must be an object");
    }
    if let Err(code) = queue_policy::check(&HashMap::new(), &lane, &spec) {
        return err(
            if code == crate::error_catalog::JOB_ID_EXISTS {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            },
            code,
        );
    }
    if spec
        .get("submitter")
        .is_some_and(|v| v != "owner" && v != "standard")
    {
        return err(StatusCode::BAD_REQUEST, crate::error_catalog::BAD_SPEC);
    }
    if spec.get("spec").is_some() {
        let floor_path = a.compat["cu_floor_path"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| base_dir().join("cu-floor.txt"));
        let now = (a.clock)();
        let pushed_balance = a
            .cards
            .lock()
            .unwrap()
            .get("colab-l4")
            .filter(|v| {
                v["stale"] == false
                    && v["epoch"]
                        .as_u64()
                        .is_some_and(|epoch| epoch <= now && now - epoch <= 180)
            })
            .and_then(|v| v["cu"]["balance"].as_f64());
        let balance = pushed_balance.or_else(|| a.compat["cu_balance"].as_f64());
        if let Err((code, message)) = job_spec::admit(&spec, &lane, balance, &floor_path) {
            return err(StatusCode::from_u16(code).unwrap(), message);
        }
        let mut selected = spec.clone();
        let requested = spec["cartridge"].as_str().unwrap_or("");
        if let Err(e) = select_manifest(&mut selected, &a.store_root) {
            return err(StatusCode::CONFLICT, &e);
        }
        if selected["cartridge"] != requested {
            return err(StatusCode::CONFLICT, "requested cartridge is not active");
        }
        if let Err(reason) = lane_gate::admit(&a.compat, &spec) {
            return err(StatusCode::CONFLICT, reason);
        }
        let cart = match resolve_manifest(&selected) {
            Ok(cart) => cart,
            Err(e) => return err(StatusCode::CONFLICT, &e),
        };
        if let Err((code, message)) = job_spec::license_admit(&spec, &a.compat, &cart) {
            return err(StatusCode::from_u16(code).unwrap(), message);
        }
        let reg = match load_registry() {
            Ok(reg) => reg,
            Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &e),
        };
        let busy = a.st.lock().unwrap().busy.clone();
        let state_dir = a.compat["card_state_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/mnt/sn850x/lanes/gpu-backlog"));
        let cards = card_state::refresh(&state_dir, now);
        let local = reg
            .iter()
            .any(|w| w.id == "warp-2070")
            .then(|| local_card_probe(now))
            .flatten();
        let floor = fs::read_to_string(&floor_path)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok());
        let rows: Vec<Value> = reg
            .iter()
            .map(|w| {
                if let Some(card) = cards.get(&w.id) {
                    let heartbeat = (w.id == "colab-l4").then(|| json!({"epoch":card["epoch"]}));
                    card_worker_view(
                        w,
                        &lane,
                        &busy,
                        card,
                        now,
                        heartbeat
                            .as_ref()
                            .or(local.as_ref().filter(|_| w.id == "warp-2070")),
                        floor,
                    )
                } else {
                    worker_view(w, &lane, &busy)
                }
            })
            .collect();
        if let Err((code, message)) = job_spec::gpu_admit(&spec, cart.min_vram_mb, &rows) {
            return err(StatusCode::from_u16(code).unwrap(), &message);
        }
        let id = spec["job_id"].as_str().unwrap().to_string();
        let mut table = a.st.lock().unwrap();
        table.clock = Some(a.clock);
        table.queue_config = queue_policy::Config::from_value(&a.compat);
        if table.jobs.contains_key(&id) {
            return err(StatusCode::CONFLICT, "job_id exists");
        }
        if let Err(hint) = queue_policy::capacity(
            &table.jobs,
            &lane,
            queue_policy::Config::from_value(&a.compat),
            now,
        ) {
            return queue_refusal(hint);
        }
        let mut queued = queue_policy::admitted(&table.jobs, &spec, now);
        queued["spec_sha256"] = json!(deadline::fingerprint(
            &lane_gate::parse(&body).expect("validated body")
        ));
        if spec["budget_cu"].is_number() {
            let floor = fs::read_to_string(&floor_path)
                .ok()
                .and_then(|v| v.trim().parse::<f64>().ok());
            let ts = Command::new("date")
                .arg("-u")
                .arg("+%Y-%m-%dT%H:%M:%SZ")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok());
            let (Some(floor), Some(balance), Some(ts)) = (floor, balance, ts) else {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CU ledger data unavailable",
                );
            };
            let root = a.compat["jobs_dir"]
                .as_str()
                .map(PathBuf::from)
                .unwrap_or_else(jobs_dir);
            let entry = cu_ledger::Entry {
                ts: ts.trim(),
                job_id: &id,
                segment: 0,
                event: "admit",
                balance,
                delta: 0.0,
                floor,
                gpu_class: spec["gpu_class"].as_str().unwrap_or("any"),
                reason: "",
            };
            if cu_ledger::append(&root, &entry).is_err() {
                return err(StatusCode::SERVICE_UNAVAILABLE, "CU ledger write failed");
            }
        }
        if !table.enqueue_agent(spec, balance.unwrap_or(0.0)) {
            return err(StatusCode::CONFLICT, "job_id exists");
        }
        for (field, value) in queued.as_object().unwrap() {
            table.jobs.get_mut(&id).unwrap()[field] = value.clone();
        }
        return (
            StatusCode::ACCEPTED,
            Json(json!({"job_id":id,"state":"queued"})),
        )
            .into_response();
    }
    spec["lane"] = json!(lane);
    if ["stt", "diffusion-video", "music-sfx"].contains(&lane.as_str()) {
        if let Err(reason) = lane_bodies::decode(&lane, &body, None) {
            return err(StatusCode::UNPROCESSABLE_ENTITY, reason);
        }
    }
    video_defaults(&mut spec);
    if let Err(reason) = cartridge_registry::apply_config(&a.compat, &mut spec) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, reason);
    }

    if let Err(reason) =
        runtime_limits::admit(&mut spec, &runtime_limits::Config::from_value(&a.compat))
    {
        return err(StatusCode::UNPROCESSABLE_ENTITY, reason);
    }
    if let Err(e) = validate(&spec) {
        return err(
            if spec["lane"].as_str().is_some_and(opened_lane) {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_REQUEST
            },
            e,
        );
    }
    if lane == "render-blender" {
        if let Err(reason) = render_admission::gate(&a.compat, &spec) {
            return err(StatusCode::CONFLICT, reason);
        }
    }
    if let Err(e) = select_manifest(&mut spec, &base_dir().join("cartridges")) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, e);
    }
    if let Err(reason) = lane_gate::admit(&a.compat, &spec) {
        return err(StatusCode::CONFLICT, reason);
    }
    let admission_spec = spec.clone();
    let admission_state = a.st.clone();
    match tokio::task::spawn_blocking(move || plan(&admission_spec, &admission_state)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) if e.starts_with("no accepting worker for ") => {
            return err(StatusCode::CONFLICT, e)
        }
        Ok(Err(e)) if e.starts_with("registry ") || e.starts_with("registry:") => {
            return err(StatusCode::SERVICE_UNAVAILABLE, e)
        }
        Ok(Err(e)) => return err(StatusCode::UNPROCESSABLE_ENTITY, e),
        Err(_) => return err(StatusCode::SERVICE_UNAVAILABLE, "admission check failed"),
    }
    let id = request_boundary::job_id(&spec);
    {
        let mut table = a.st.lock().unwrap();
        table.clock = Some(a.clock);
        table.queue_config = queue_policy::Config::from_value(&a.compat);
        if table.jobs.contains_key(&id) {
            return err(StatusCode::CONFLICT, "job_id exists");
        }
        if let Err(hint) = queue_policy::capacity(
            &table.jobs,
            &lane,
            queue_policy::Config::from_value(&a.compat),
            (a.clock)(),
        ) {
            return queue_refusal(hint);
        }
        spec["job_id"] = json!(id);
        let mut queued = queue_policy::admitted(&table.jobs, &spec, (a.clock)());
        queued["result_store_root"] = json!(a.compat["result_store_dir"]
            .as_str()
            .map(PathBuf::from)
            .unwrap_or_else(|| base_dir().join("results")));
        queued["spec_sha256"] = json!(deadline::fingerprint(
            &lane_gate::parse(&body).expect("validated body")
        ));
        table.jobs.insert(id.clone(), queued);
    }
    spec["job_id"] = json!(id);
    let st = a.st.clone();
    let b = body.to_vec();
    let cfg = queue_policy::Config::from_value(&a.compat);
    let clock = a.clock;
    tokio::task::spawn_blocking(move || {
        if wait_for_turn(&st, spec["job_id"].as_str().unwrap(), cfg, clock) {
            run_job(st, spec, b, false);
        }
    });
    (
        StatusCode::ACCEPTED,
        Json(json!({"job_id": id, "state": "queued"})),
    )
        .into_response()
}
pub(crate) async fn h_job(
    State(a): State<App>,
    AxPath((lane, id)): AxPath<(String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(r) = auth(&h, &lane) {
        return r;
    }
    if !result_store::valid_id(&id) {
        return err(StatusCode::NOT_FOUND, crate::error_catalog::NO_SUCH_JOB);
    }
    let mem = a.st.lock().unwrap().jobs.get(&id).cloned();
    let v = mem.or_else(|| {
        fs::read(jobs_dir().join(format!("{id}.json")))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    });
    // Refused lookups must not expire or publish unrelated queued jobs.
    if !v
        .as_ref()
        .is_some_and(|row| queue_policy::lane(row) == lane)
    {
        return err(StatusCode::NOT_FOUND, "no such job");
    }
    let expired = {
        let mut table = a.st.lock().unwrap();
        let ids = deadline::process(&mut table.jobs, (a.clock)());
        ids.iter()
            .map(|id| table.jobs[id].clone())
            .collect::<Vec<_>>()
    };
    for row in expired {
        if let Err(reason) = publish_policy(&row, (a.clock)()) {
            return err(StatusCode::SERVICE_UNAVAILABLE, reason);
        }
    }
    let v = a.st.lock().unwrap().jobs.get(&id).cloned().or(v);
    match v {
        Some(v) if queue_policy::lane(&v) == lane => Json(result_store::worker_log::status(
            &v,
            result_store::Config::from_value(&a.compat).worker_log_max,
        ))
        .into_response(),
        _ => err(StatusCode::NOT_FOUND, "no such job"),
    }
}
pub(crate) async fn h_artifact_list(
    method: Method,
    State(a): State<App>,
    AxPath((lane, id)): AxPath<(String, String)>,
    h: HeaderMap,
) -> Response {
    if method != Method::GET {
        return artifact_routes::response(Err(artifact_routes::Failure {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: crate::error_catalog::reason(crate::error_catalog::METHOD_NOT_ALLOWED),
            retryable: false,
        }));
    }
    if let Err(r) = auth(&h, &lane) {
        return r;
    }
    let root = a.compat["result_store_dir"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join("results"));
    let store = result_store::Store::new(
        &root,
        result_store::Config {
            legacy_paths: true,
            ..result_store::Config::from_value(&a.compat)
        },
    );
    artifact_routes::response(artifact_routes::read(&store, &lane, &id, None, (a.clock)()))
}
pub(crate) async fn h_artifact(
    method: Method,
    State(a): State<App>,
    AxPath((lane, id, name)): AxPath<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    if method != Method::GET {
        return artifact_routes::response(Err(artifact_routes::Failure {
            status: StatusCode::METHOD_NOT_ALLOWED,
            code: crate::error_catalog::reason(crate::error_catalog::METHOD_NOT_ALLOWED),
            retryable: false,
        }));
    }
    if let Err(r) = auth(&h, &lane) {
        return r;
    }
    let root = a.compat["result_store_dir"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join("results"));
    let store = result_store::Store::new(
        &root,
        result_store::Config {
            legacy_paths: true,
            ..result_store::Config::from_value(&a.compat)
        },
    );
    artifact_routes::response(artifact_routes::read(
        &store,
        &lane,
        &id,
        Some(&name),
        (a.clock)(),
    ))
}
pub(crate) async fn h_cancel(
    State(a): State<App>,
    AxPath((lane, id)): AxPath<(String, String)>,
    h: HeaderMap,
) -> Response {
    if let Err(r) = auth(&h, &lane) {
        return r;
    }
    if !result_store::valid_id(&id) {
        return err(StatusCode::NOT_FOUND, crate::error_catalog::NO_SUCH_JOB);
    }
    let mut table = a.st.lock().unwrap();
    if !table
        .jobs
        .get(&id)
        .is_some_and(|row| queue_policy::lane(row) == lane)
    {
        return err(StatusCode::NOT_FOUND, crate::error_catalog::NO_SUCH_JOB);
    }
    let accepted = deadline::cancel(table.jobs.get_mut(&id).unwrap(), (a.clock)()).unwrap_or(false);
    let row = table.jobs[&id].clone();
    if accepted {
        table.cancel.insert(id.clone());
    }
    let pids = table.pids.get(&id).cloned().unwrap_or_default();
    drop(table);
    for p in &pids {
        if accepted {
            sigterm(*p);
        }
    }
    if let Err(reason) = publish_policy(&row, (a.clock)()) {
        return err(StatusCode::SERVICE_UNAVAILABLE, reason);
    }
    if accepted {
        (
            StatusCode::ACCEPTED,
            Json(json!({"job_id":id,"cancel":"requested","signalled":pids.len()})),
        )
            .into_response()
    } else {
        (StatusCode::OK, Json(row)).into_response()
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn jobs_body_size_and_content_type_refusals() {
        crate::routes::common::check_request_refusals(&[
            "/v1/lanes/tts/jobs",
            "/v1/lanes/tts/jobs/fixture/cancel",
        ])
        .await;
    }
}

#[cfg(test)]
mod input_hardening_tests {
    #[tokio::test]
    async fn jobs_body_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[
                ("/v1/health", "GET"),
                ("/v1/lanes", "GET"),
                ("/v1/lanes/tts/workers", "GET"),
                ("/v1/lanes/tts/jobs", "POST"),
                ("/v1/lanes/tts/jobs/fixture", "GET"),
                ("/v1/lanes/tts/jobs/fixture/artifacts", "GET"),
                ("/v1/lanes/tts/jobs/fixture/artifacts/name", "GET"),
                ("/v1/lanes/tts/jobs/fixture/cancel", "POST"),
            ],
            &[
                "/v1/lanes/%FF/workers",
                "/v1/lanes/tts/jobs/%FF",
                "/v1/lanes/tts/jobs/fixture/artifacts/%FF",
            ],
            "body",
        )
        .await;
    }
    #[tokio::test]
    async fn jobs_path_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[
                ("/v1/health", "GET"),
                ("/v1/lanes", "GET"),
                ("/v1/lanes/tts/workers", "GET"),
                ("/v1/lanes/tts/jobs", "POST"),
                ("/v1/lanes/tts/jobs/fixture", "GET"),
                ("/v1/lanes/tts/jobs/fixture/artifacts", "GET"),
                ("/v1/lanes/tts/jobs/fixture/artifacts/name", "GET"),
                ("/v1/lanes/tts/jobs/fixture/cancel", "POST"),
            ],
            &[
                "/v1/lanes/%FF/workers",
                "/v1/lanes/tts/jobs/%FF",
                "/v1/lanes/tts/jobs/fixture/artifacts/%FF",
            ],
            "path",
        )
        .await;
    }
    #[tokio::test]
    async fn jobs_fields_input_hardening() {
        crate::routes::common::check_input_hardening(
            &[
                ("/v1/health", "GET"),
                ("/v1/lanes", "GET"),
                ("/v1/lanes/tts/workers", "GET"),
                ("/v1/lanes/tts/jobs", "POST"),
                ("/v1/lanes/tts/jobs/fixture", "GET"),
                ("/v1/lanes/tts/jobs/fixture/artifacts", "GET"),
                ("/v1/lanes/tts/jobs/fixture/artifacts/name", "GET"),
                ("/v1/lanes/tts/jobs/fixture/cancel", "POST"),
            ],
            &[
                "/v1/lanes/%FF/workers",
                "/v1/lanes/tts/jobs/%FF",
                "/v1/lanes/tts/jobs/fixture/artifacts/%FF",
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
        super::super::common::fuzz_table("jobs", "/v1/lanes/tts/jobs", "/v1/lanes/{lane}/jobs");
    }
}

#[cfg(test)]
mod run36_v1 {
    use super::*;
    use tower::ServiceExt;

    fn inventory(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(root: &Path, folder: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(folder).unwrap() {
                let entry = entry.unwrap();
                assert!(!entry.file_type().unwrap().is_symlink());
                if entry.file_type().unwrap().is_dir() {
                    walk(root, &entry.path(), output);
                } else {
                    output.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut output = BTreeMap::new();
        walk(root, root, &mut output);
        output
    }

    #[test]
    fn run36_v1_jobs_refusal_table() {
        if std::env::var_os("RUN36_JOBS_CHILD").is_none() {
            let output = crate::test_process::command()
                .args([
                    "--exact",
                    "routes::jobs::run36_v1::run36_v1_jobs_refusal_table",
                    "--quiet",
                ])
                .env("RUN36_JOBS_CHILD", "1")
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
        let root = std::env::temp_dir().join(format!("run36-jobs-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        crate::pull_http_tests::auth_fixture(&root);
        std::env::set_var("LANE_ROUTER_HOME", &root);
        let app = new_app(
            json!({"jobs_dir":root.join("jobs"),"result_store_dir":root.join("results")}),
            root.join("store"),
        );
        app.st.lock().unwrap().jobs.insert(
            "good".into(),
            json!({"job_id":"good","lane":"tts","state":"done"}),
        );
        app.st.lock().unwrap().jobs.insert("due".into(), json!({"job_id":"due","lane":"tts","state":"queued","deadline_epoch":0,"result_store_root":root.join("results")}));
        let table = app.st.clone();
        let before = table.lock().unwrap().jobs.clone();
        let disk = inventory(&root);
        let router = router_with_app(app);
        let rows = [
            (
                "GET",
                "/v1/lanes/tts/jobs/missing",
                0,
                404,
                error_catalog::NO_SUCH_JOB,
            ),
            (
                "GET",
                "/v1/lanes/tts/jobs/bad.id",
                0,
                404,
                error_catalog::NO_SUCH_JOB,
            ),
            (
                "POST",
                "/v1/lanes/tts/jobs/missing/cancel",
                0,
                404,
                error_catalog::NO_SUCH_JOB,
            ),
            (
                "POST",
                "/v1/lanes/tts/jobs/bad.id/cancel",
                0,
                404,
                error_catalog::NO_SUCH_JOB,
            ),
            (
                "PUT",
                "/v1/lanes/tts/jobs/good/artifacts",
                0,
                405,
                error_catalog::METHOD_NOT_ALLOWED,
            ),
            (
                "POST",
                "/v1/lanes/tts/jobs",
                dispatch_kinds::Config::default().body_max + 1,
                413,
                error_catalog::REQUEST_TOO_LARGE,
            ),
        ];
        assert!(rows.len() >= 5);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for (method, path, length, status, code) in rows {
                let response = router
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .method(method)
                            .uri(path)
                            .header(
                                "authorization",
                                crate::contract_ref_tests::APPROVED.unwrap(),
                            )
                            .body(axum::body::Body::from(vec![b' '; length]))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status().as_u16(), status, "{method} {path}");
                let body: Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap(),
                )
                .unwrap();
                let message = body["error"].as_str().expect("error body");
                assert_eq!(
                    error_catalog::refusal_entry(Some(status), message)
                        .expect("catalog refusal")
                        .code,
                    code,
                    "{path}"
                );
                let state = table.lock().unwrap();
                assert_eq!(state.jobs, before);
                assert!(
                    state.agent_queue.is_empty()
                        && state.agent_owners.is_empty()
                        && state.pids.is_empty()
                        && state.cancel.is_empty()
                        && state.busy.is_empty()
                );
                assert_eq!(state.queue_last, None);
                assert_eq!(inventory(&root), disk, "refusal wrote to disk: {path}");
            }
        });
        fs::remove_dir_all(root).unwrap();
    }
}
