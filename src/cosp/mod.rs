#[path = "common_cosp.rs"]
mod common;
#[allow(dead_code)]
mod la_adapter;
mod la_backend;
pub(crate) use la_backend::maybe_private_helper;
#[allow(dead_code)]
mod la_artifacts;
#[allow(dead_code)]
mod la_auth;
#[allow(dead_code)]
mod la_contract;
#[allow(dead_code)]
mod la_store;
#[allow(dead_code)]
mod la_worker;
mod lane_assignment;
use axum::{
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Router,
};
use common::{Failure, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};
#[derive(Clone)]
struct Spine {
    root: PathBuf,
    edge: bool,
    worker_ports: [u16; 2],
    admin: bool,
    sequence: Arc<Mutex<u64>>,
}
fn err(http: u16, c: &str) -> Response {
    (StatusCode::from_u16(http).unwrap(),axum::Json(json!({"error":{"code":c,"message":c,"retryable":http>=500,"request_id":format!("req_{}",common::now())}}))).into_response()
}
fn database(s: &Spine) -> Result<rusqlite::Connection> {
    let c = common::db(&s.root.join("diffuser.sqlite"))?;
    let old: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='ready')",
            [],
            |r| r.get(0),
        )
        .map_err(|_| Failure(70, "storage_unavailable"))?;
    let current:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='build_ready_jobs')",[],|r|r.get(0)).map_err(|_|Failure(70,"storage_unavailable"))?;
    if old && !current {
        c.execute_batch("ALTER TABLE ready RENAME TO build_ready_jobs;")
            .map_err(|_| Failure(70, "storage_unavailable"))?;
    }
    c.execute_batch("CREATE TABLE IF NOT EXISTS worker_events (worker TEXT NOT NULL, at INTEGER NOT NULL, ok INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS build_ready_jobs (id TEXT PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS idem (id TEXT PRIMARY KEY, digest TEXT NOT NULL, reply TEXT NOT NULL, status INTEGER NOT NULL, expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS state (id TEXT PRIMARY KEY, body TEXT NOT NULL); INSERT OR IGNORE INTO state VALUES ('dispatch','{\"revision\":0,\"dispatch_allowed\":false,\"public_cutover_allowed\":false}');").map_err(|_|Failure(70,"storage_unavailable"))?;
    Ok(c)
}
fn gate(c: &rusqlite::Connection) -> Value {
    c.query_row("SELECT body FROM state WHERE id='dispatch'", [], |r| {
        r.get::<_, String>(0)
    })
    .ok()
    .and_then(|v| serde_json::from_str(&v).ok())
    .unwrap_or(Value::Null)
}
fn lanes() -> Vec<Value> {
    ["render-blender","tts","stt","diffusion-image","diffusion-video","music-sfx","inference.echo.cuda","inference.nuc.syl","inference.nuc.npu","inference.finn.arc","aux.free"].into_iter().map(|id|json!({"lane_id":id,"accepting":false,"disabled_reason":if id=="render-blender"{"echo-3060 retired, RULES.md:40"}else{"capability_unavailable: no admitted worker"}})).collect()
}
fn worker_call(s: &Spine, id: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let url = format!(
        "http://localhost:{}{}",
        s.worker_ports[usize::from(id == "echo")],
        path
    );
    if s.edge {
        return common::http(
            if body.is_some() { "POST" } else { "GET" },
            &url,
            body,
            None,
        );
    }
    let mut c = Command::new("ssh");
    c.args([
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "vps",
        "curl",
        "-fsS",
        "--max-time",
        "10",
        "-H",
        "'Content-Type: application/json'",
    ]);
    if body.is_some() {
        c.args(["--data-binary", "@-"]);
    }
    c.arg(&url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = c
        .spawn()
        .map_err(|_| Failure(75, "embed_workers_unavailable"))?;
    if let Some(b) = body {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b.to_string().as_bytes())
            .map_err(|_| Failure(75, "embed_workers_unavailable"))?;
    }
    let r = child
        .wait_with_output()
        .map_err(|_| Failure(75, "embed_workers_unavailable"))?;
    if !r.status.success() {
        return common::fail(75, "embed_workers_unavailable");
    }
    serde_json::from_slice(&r.stdout).map_err(|_| Failure(75, "embed_invalid_reply"))
}
fn record_worker(s: &Spine, id: &str, ok: bool) -> Result<()> {
    let db = database(s)?;
    db.execute(
        "INSERT INTO worker_events VALUES (?1,?2,?3)",
        rusqlite::params![id, common::now() as i64, ok],
    )
    .map_err(|_| Failure(70, "storage_unavailable"))?;
    Ok(())
}
fn vector_valid(v: &Value) -> bool {
    v.as_array()
        .is_some_and(|a| a.len() == 768 && a.iter().all(|n| n.as_f64().is_some_and(f64::is_finite)))
}
fn embed_health(s: &Spine) -> Result<Value> {
    let db = database(s)?;
    let mut rows = Vec::new();
    for id in ["l0", "echo"] {
        let probe = worker_call(
            s,
            id,
            if id == "echo" {
                "/v1/embed"
            } else {
                "/api/embed"
            },
            Some(
                &json!({"model":"nomic-embed-text","input":if id=="echo"{json!("COSP health probe")}else{json!(["COSP health probe"])}}),
            ),
        );
        let up = probe.as_ref().is_ok_and(|r| {
            if id == "echo" {
                r["status"] == "ok" && vector_valid(&r["embedding"])
            } else {
                vector_valid(&r["embeddings"][0])
            }
        });
        record_worker(s, id, up)?;
        let total: i64 = db
            .query_row(
                "SELECT count(*) FROM worker_events WHERE worker=?1 AND ok=0",
                [id],
                |r| r.get(0),
            )
            .map_err(|_| Failure(70, "storage_unavailable"))?;
        let delta: i64 = db
            .query_row(
                "SELECT count(*) FROM worker_events WHERE worker=?1 AND ok=0 AND at>=?2",
                rusqlite::params![id, common::now() as i64 - 300],
                |r| r.get(0),
            )
            .map_err(|_| Failure(70, "storage_unavailable"))?;
        rows.push(json!({"worker_id":id,"endpoint":if id=="l0"{"localhost:11434"}else{"localhost:15820"},"up":up,"weight":if id=="l0"{8}else{1},"fail_count_total":total,"fail_delta_5m":delta,"last_ok_at":if up{json!(common::timestamp())}else{Value::Null},"last_error_summary":if up{Value::Null}else{json!("embedding worker unavailable or invalid vector")}}));
    }
    let up = rows.iter().filter(|r| r["up"] == true).count();
    let rising = rows
        .iter()
        .any(|r| r["fail_delta_5m"].as_i64().unwrap_or(0) >= 10);
    Ok(
        json!({"model":"nomic-embed-text","dimensions":768,"healthy":up>=1,"degraded":up<2,"workers":rows,"alert_state":if up==0{"crit_all_embed_workers_down"}else if up==1||rising{"warn_single_worker_down"}else{"ok"}}),
    )
}

fn embed(s: &Spine, b: &Value) -> Result<Value> {
    if b["model"].as_str().unwrap_or("nomic-embed-text") != "nomic-embed-text" {
        return common::fail(422, "model_mismatch");
    }
    let inputs = match b.get("input") {
        Some(Value::String(v)) if !v.trim().is_empty() => vec![json!(v)],
        Some(Value::Array(a))
            if !a.is_empty()
                && a.len() <= 16
                && a.iter()
                    .all(|x| x.as_str().is_some_and(|t| !t.trim().is_empty())) =>
        {
            a.clone()
        }
        _ => return common::fail(400, "invalid_batch"),
    };
    let turn = {
        let mut t = s.sequence.lock().unwrap();
        *t += 1;
        *t
    };
    let preferred = if turn % 9 == 0 { "echo" } else { "l0" };
    for id in [preferred, if preferred == "l0" { "echo" } else { "l0" }] {
        let r = (|| {
            let mut vectors = Vec::new();
            if id == "l0" {
                let out = worker_call(
                    s,
                    id,
                    "/api/embed",
                    Some(&json!({"model":"nomic-embed-text","input":inputs})),
                )?;
                vectors = out["embeddings"]
                    .as_array()
                    .cloned()
                    .ok_or(Failure(503, "embed_invalid_reply"))?;
            } else {
                for text in &inputs {
                    let out = worker_call(
                        s,
                        id,
                        "/v1/embed",
                        Some(&json!({"model":"nomic-embed-text","input":text})),
                    )?;
                    if out["status"] != "ok" {
                        return common::fail(503, "embed_invalid_reply");
                    }
                    vectors.push(out["embedding"].clone());
                }
            }
            if vectors.len() != inputs.len()
                || !vectors.iter().all(|r| {
                    r.as_array().is_some_and(|v| {
                        v.len() == 768 && v.iter().all(|n| n.as_f64().is_some_and(f64::is_finite))
                    })
                })
            {
                return common::fail(503, "embed_invalid_reply");
            }
            Ok(
                json!({"status":"ok","model":"nomic-embed-text","dimensions":768,"worker_id":id,"embeddings":vectors,"embedding":if vectors.len()==1{vectors[0].clone()}else{json!(vectors)}}),
            )
        })();
        match r {
            Ok(v) => {
                record_worker(s, id, true)?;
                return Ok(v);
            }
            Err(_) => {
                record_worker(s, id, false)?;
            }
        }
    }
    common::fail(503, "embed_workers_unavailable")
}
fn mutation(s: &Spine, path: &str, h: &HeaderMap, b: &Value) -> Result<(u16, Value)> {
    if !s.admin {
        return common::fail(401, "auth_required");
    }
    let id = h
        .get("X-Idempotency-Id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| (16..=128).contains(&v.len()) && v.bytes().all(|x| x.is_ascii_graphic()))
        .ok_or(Failure(400, "idempotency_required"))?;
    let mut c = database(s)?;
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| Failure(70, "storage_unavailable"))?;
    let digest = common::hash(format!("{path}\n{b}"));
    let old = tx.query_row(
        "SELECT digest,reply,status FROM idem WHERE id=?1 AND expires>?2",
        rusqlite::params![id, common::now() as i64],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u16>(2)?,
            ))
        },
    );
    if let Ok((prior, reply, status)) = old {
        if prior != digest {
            return common::fail(409, "idempotency_payload_mismatch");
        }
        return Ok((
            status,
            serde_json::from_str(&reply).map_err(|_| Failure(70, "storage_unavailable"))?,
        ));
    }
    let (status, v) = if path == "/v1/admin/dispatch-gate" {
        if b["public_cutover_allowed"] == true {
            return common::fail(403, "public_cutover_owner_only");
        }
        let mut v = gate(&tx);
        if b["expected_revision"] != v["revision"] {
            return common::fail(409, "revision_conflict");
        }
        if b["dispatch_allowed"] == true {
            return common::fail(412, "zero_proven_lanes");
        }
        v["revision"] = json!(v["revision"].as_u64().unwrap_or(0) + 1);
        v["dispatch_allowed"] = json!(false);
        tx.execute(
            "UPDATE state SET body=?1 WHERE id='dispatch'",
            [v.to_string()],
        )
        .map_err(|_| Failure(70, "storage_unavailable"))?;
        (200, v)
    } else if path.ends_with("/admission") {
        return common::fail(412, "inventory_proof_missing_or_stale");
    } else if path.ends_with("/proof") {
        return common::fail(422, "worker_disabled_by_policy");
    } else if path == "/v1/build-lanes/ready" {
        let id = b["job_id"]
            .as_str()
            .filter(|v| valid_id(v))
            .ok_or(Failure(422, "brief_lint_failed"))?;
        let p = b["brief_path"]
            .as_str()
            .ok_or(Failure(422, "brief_lint_failed"))?;
        let root = PathBuf::from(p)
            .parent()
            .ok_or(Failure(422, "brief_lint_failed"))?
            .to_owned();
        let verified = validate_brief(&root)?;
        if b["brief_sha256"] != verified["brief_sha256"]
            || b["stage_manifest_sha256"]
                != json!(common::hash(common::read(
                    root.join("stage/INPUTS/STAGE-SHA256SUMS")
                )?))
        {
            return common::fail(422, "brief_lint_failed");
        }
        let mut v = b.clone();
        v["state"] = json!("ready_admitted");
        v["revision"] = json!(0);
        v["registered_at"] = json!(common::timestamp());
        v["ack_verified"] = json!(false);
        v["checkpoint_seq"] = json!(0);
        v["claimed_at"] = Value::Null;
        v["completed_at"] = Value::Null;
        v["escalation_path"] = Value::Null;
        tx.execute(
            "INSERT INTO build_ready_jobs VALUES (?1,?2)",
            rusqlite::params![id, v.to_string()],
        )
        .map_err(|_| Failure(409, "job_already_registered"))?;
        (201, v)
    } else {
        let tail = path
            .strip_prefix("/v1/build-lanes/ready/")
            .ok_or(Failure(404, "not_found"))?;
        let (id, action) = tail.split_once('/').ok_or(Failure(404, "not_found"))?;
        let raw = tx
            .query_row("SELECT body FROM build_ready_jobs WHERE id=?1", [id], |r| {
                r.get::<_, String>(0)
            })
            .map_err(|_| Failure(404, "job_not_found"))?;
        let mut v: Value =
            serde_json::from_str(&raw).map_err(|_| Failure(70, "storage_unavailable"))?;
        if b["expected_revision"] != v["revision"] {
            return common::fail(409, "revision_conflict");
        }
        match action {
            "claim" => {
                if b["runner_host"] != "nuc" {
                    return common::fail(412, "host_not_nuc");
                }
                if v["state"] != "ready_admitted"
                    && v["state"] != "paused_checkpoint"
                    && v["state"] != "escalated_halted"
                {
                    return common::fail(409, "revision_conflict");
                }
                v["state"] = json!("claimed_running");
                v["claimed_at"] = json!(common::timestamp());
            }
            "complete" => {
                if v["state"] != "claimed_running" {
                    return common::fail(409, "revision_conflict");
                }
                let result = b["result"].as_str().ok_or(Failure(400, "schema_invalid"))?;
                if result == "PASS" && b["ack_verified"] != true {
                    return common::fail(422, "ack_unverified_on_pass");
                }
                v["state"] = json!(match result {
                    "PASS" => "completed_pass",
                    "FAIL" => "completed_fail",
                    "ESCALATED" => "escalated_halted",
                    _ => return common::fail(400, "schema_invalid"),
                });
                v["result"] = b["result"].clone();
                v["ack_verified"] = b["ack_verified"].clone();
                v["completed_at"] = json!(common::timestamp());
                v["return_sha256"] = b["return_sha256"].clone();
            }
            _ => return common::fail(404, "not_found"),
        }
        v["revision"] = json!(v["revision"].as_u64().unwrap() + 1);
        tx.execute(
            "UPDATE build_ready_jobs SET body=?1 WHERE id=?2",
            rusqlite::params![v.to_string(), id],
        )
        .map_err(|_| Failure(70, "storage_unavailable"))?;
        (200, v)
    };
    tx.execute(
        "INSERT OR REPLACE INTO idem VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![
            id,
            digest,
            v.to_string(),
            status,
            (common::now() + 86400) as i64
        ],
    )
    .map_err(|_| Failure(70, "storage_unavailable"))?;
    tx.commit()
        .map_err(|_| Failure(70, "storage_unavailable"))?;
    if path.starts_with("/v1/build-lanes/") {
        let mut st = c
            .prepare("SELECT body FROM build_ready_jobs ORDER BY id")
            .map_err(|_| Failure(70, "storage_unavailable"))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|_| Failure(70, "storage_unavailable"))?;
        let mut bytes = Vec::new();
        for r in rows {
            bytes.extend(
                r.map_err(|_| Failure(70, "storage_unavailable"))?
                    .as_bytes(),
            );
            bytes.push(b'\n');
        }
        common::atomic(Path::new("/srv/lanes/state/ready-ledger.jsonl"), &bytes)?;
    }
    Ok((status, v))
}
pub fn valid_id(v: &str) -> bool {
    !v.is_empty()
        && v.len() < 150
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
pub fn validate_brief(root: &std::path::Path) -> Result<Value> {
    let data =
        common::read(root.join("BRIEF.md")).map_err(|_| Failure(61, "brief_stale_path_or_host"))?;
    let text = String::from_utf8_lossy(&data);
    if common::contains_banned_name(&text) {
        return common::fail(61, "brief_stale_path_or_host");
    }
    if !text.contains("0a")
        || !text.contains("ACK.md")
        || !text.contains("nuc")
        || regex::Regex::new(r"[A-Za-z]:\\").unwrap().is_match(&text)
    {
        return common::fail(61, "brief_stale_path_or_host");
    }
    let r = Command::new("python3")
        .arg("/srv/lanes/bin/qc_gate.py")
        .arg("check")
        .arg("--id")
        .arg(root.file_name().unwrap_or_default())
        .args(["--lane", "codex-main-nuc", "--dir"])
        .arg(root)
        .output()
        .map_err(|_| Failure(66, "qc_gate_blocked"))?;
    if !r.status.success() {
        return common::fail(66, "qc_gate_blocked");
    }
    Ok(json!({"valid":true,"brief_sha256":common::hash(data)}))
}
async fn handle(
    State(s): State<Spine>,
    OriginalUri(uri): OriginalUri,
    m: Method,
    h: HeaderMap,
    b: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let method = m.to_string();
    let r=tokio::task::spawn_blocking(move||->Result<(u16,Value)>{let data=if b.is_empty(){json!({})}else{serde_json::from_slice(&b).map_err(|_|Failure(400,"schema_invalid"))?};
 if method=="GET"{let c=database(&s)?;return Ok((200,match path.as_str(){"/health"=>{let mut v=gate(&c);v["ready"]=json!(true);v["version"]=json!("0.3.0");v["profile"]=json!(if s.edge{"embed-edge"}else{"primary"});v["lanes_summary"]=json!(lanes());v},"/v1/health"=>json!({"protocol":"service-lane/v1","lanes":lanes(),"workers":[{"worker_id":"echo-3060","accepting":false,"status":"retired"},{"worker_id":"warp-2070","accepting":false,"status":"disabled_fault"}]}),"/v1/embed/health"=>{let v=embed_health(&s)?;if v["alert_state"]=="crit_all_embed_workers_down"{return Ok((503,v))}v},"/v1/build-lanes/ready"=>{let mut st=c.prepare("SELECT body FROM build_ready_jobs ORDER BY id").map_err(|_|Failure(70,"storage_unavailable"))?;let rows=st.query_map([],|r|r.get::<_,String>(0)).map_err(|_|Failure(70,"storage_unavailable"))?;let mut items=Vec::<Value>::new();for row in rows{items.push(serde_json::from_str(&row.map_err(|_|Failure(70,"storage_unavailable"))?).map_err(|_|Failure(70,"storage_unavailable"))?)}json!({"items":items,"next_cursor":null})},_=>return common::fail(404,"not_found")}))}
 if path=="/v1/embed"&&method=="POST"{return Ok((200,embed(&s,&data)?))}
 if path.starts_with("/v1/lanes/")&&path.ends_with("/jobs")&&method=="POST"{if data["consumer"].as_str().is_none_or(|v|v.is_empty()){return common::fail(400,"consumer_missing")}return common::fail(422,"capability_unavailable")}
 mutation(&s,&path,&h,&data)
 }).await;
    match r {
        Ok(Ok((rc, v))) => (StatusCode::from_u16(rc).unwrap(), axum::Json(v)).into_response(),
        Ok(Err(Failure(rc, c))) => err(
            if (400..600).contains(&rc) {
                rc as u16
            } else {
                503
            },
            c,
        ),
        Err(_) => err(503, "service_unavailable"),
    }
}
fn api(s: Spine) -> Router {
    api_with_namespace(s, lane_assignment::router())
}
fn api_with_namespace(s: Spine, namespace: Router<Spine>) -> Router {
    api_with_namespaces(s, namespace, fleet::closed_router())
}
fn api_with_namespaces(s: Spine, namespace: Router<Spine>, fleet_ns: Router<Spine>) -> Router {
    Router::new()
        .nest("/v1/diffuser", namespace)
        .nest("/v1/fleet", fleet_ns)
        .route("/health", get(handle))
        .route("/v1/health", get(handle))
        .route("/v1/embed", post(handle))
        .route("/v1/embed/health", get(handle))
        .route("/v1/build-lanes/ready", get(handle).post(handle))
        .route("/v1/build-lanes/ready/{id}/{action}", post(handle))
        .route("/v1/admin/dispatch-gate", patch(handle))
        .route("/v1/lanes/{lane}/admission", patch(handle))
        .route("/v1/lanes/{lane}/workers/{worker}/proof", post(handle))
        .route("/v1/lanes/{lane}/jobs", post(handle))
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(s)
}
mod fleet;
mod la_protected;
mod la_startup_check;

pub fn main_cli() -> i32 {
    let a = common::args();
    if a.iter().any(|arg| arg == la_startup_check::SELECTOR) {
        return common::emit(la_startup_check::check(&a));
    }
    let root =
        PathBuf::from(common::opt(&a, "--state-dir").unwrap_or("/var/lib/uai-diffuser".into()));
    if let Some(fleet_worker_cfg) = common::opt(&a, "--fleet-worker") {
        return fleet::run_fleet_worker(Path::new(&fleet_worker_cfg));
    }
    if let Some(worker_cfg) = common::opt(&a, "--worker-config") {
        let bind = common::opt(&a, "--bind").unwrap_or("127.0.0.1:5821".into());
        return la_protected::run_worker(Path::new(&worker_cfg), &bind, &root);
    }
    let protected_cfg = common::opt(&a, "--protected-config");
    let fleet_cfg = common::opt(&a, "--fleet-config");
    let edge = common::opt(&a, "--profile").as_deref() == Some("embed-edge");
    let bind = common::opt(&a, "--bind").unwrap_or("localhost:5820".into());
    if !bind.starts_with("localhost:") {
        return common::emit(common::fail(70, "bind_refused"));
    }
    let mut worker_ports = [11434, 15820];
    for (index, option) in ["--embed-l0-port", "--embed-echo-port"]
        .into_iter()
        .enumerate()
    {
        if let Some(value) = common::opt(&a, option) {
            if !edge {
                return common::emit(common::fail(70, "worker_port_refused"));
            }
            match value.parse::<u16>() {
                Ok(port) if port > 0 => worker_ports[index] = port,
                _ => return common::emit(common::fail(70, "worker_port_refused")),
            }
        }
    }
    if fs::create_dir_all(&root).is_err() {
        return 70;
    }
    let s = Spine {
        root: root.clone(),
        edge,
        worker_ports,
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    };
    if database(&s).is_err() {
        return 70;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let admin = root.join("control.sock");
        if admin.exists() {
            if std::os::unix::net::UnixStream::connect(&admin).is_ok() {
                return 70;
            }
            let _ = fs::remove_file(&admin);
        }
        let u = match tokio::net::UnixListener::bind(&admin) {
            Ok(u) => u,
            Err(_) => return 70,
        };
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&admin, fs::Permissions::from_mode(0o600));
        let mut custodial = s.clone();
        custodial.admin = true;
        tokio::spawn(async move {
            let _ = axum::serve(u, api(custodial)).await;
        });
        // Retained router routes and handlers remain available as the fallback. No inherited worker is admitted.
        let legacy = crate::routes::router_with_app(crate::routes::new_app(
            json!({"lanes":{}}),
            root.join("cartridges"),
        ));
        let namespace = match protected_cfg {
            Some(ref cfg_path) => match la_protected::bootstrap_controller(Path::new(cfg_path), &root) {
                Ok(ns) => ns,
                Err(err) => {
                    eprintln!("protected_controller_error: {err}");
                    return 70;
                }
            },
            None => lane_assignment::router(),
        };
        let fleet_ns = match fleet_cfg {
            Some(ref cfg_path) => match fleet::router(Path::new(cfg_path), &root) {
                Ok(ns) => ns,
                Err(err) => {
                    eprintln!("fleet_controller_error: {err}");
                    return 70;
                }
            },
            None => fleet::closed_router(),
        };
        let r = api_with_namespaces(s, namespace, fleet_ns).fallback_service(legacy);
        let port = match bind
            .strip_prefix("localhost:")
            .and_then(|v| v.parse::<u16>().ok())
        {
            Some(port) => port,
            None => return 70,
        };
        let l = match tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await {
            Ok(l) => l,
            Err(_) => return 70,
        };
        if axum::serve(l, r).await.is_err() {
            70
        } else {
            0
        }
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ready_schema_migration_preserves_existing_records() {
        let p = std::env::temp_dir().join(format!(
            "cosp-db-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&p).unwrap();
        let db = common::db(&p.join("diffuser.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE ready(id TEXT PRIMARY KEY,body TEXT NOT NULL); INSERT INTO ready VALUES ('probe','{}');").unwrap();
        drop(db);
        let state = Spine {
            root: p.clone(),
            edge: false,
            worker_ports: [11434, 15820],
            admin: false,
            sequence: Arc::new(Mutex::new(0)),
        };
        let db = database(&state).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM build_ready_jobs WHERE id='probe'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        drop(db);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn id_paths_reject_traversal() {
        assert!(!valid_id("../bad"));
        assert!(valid_id("cosp-probe-1"));
    }
    #[test]
    fn all_workers_gated() {
        assert_eq!(lanes().len(), 11);
        assert!(lanes().iter().all(|v| v["accepting"] == false));
    }
    #[test]
    fn embed_model_is_fixed() {
        let s = Spine {
            root: PathBuf::new(),
            edge: true,
            worker_ports: [11434, 15820],
            admin: false,
            sequence: Arc::new(Mutex::new(0)),
        };
        assert_eq!(
            embed(&s, &json!({"model":"other","input":"a"}))
                .unwrap_err()
                .0,
            422
        );
        assert_eq!(embed(&s, &json!({"input":[]})).unwrap_err().0, 400);
    }
    #[tokio::test]
    async fn embed_unavailable_real_handler_returns_503_and_records_both_workers() {
        use tower::ServiceExt;
        let scratch = std::env::temp_dir().join(format!(
            "cosp-unavailable-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&scratch).unwrap();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let closed = listener.local_addr().unwrap().port();
        drop(listener);
        let state = Spine {
            root: scratch.clone(),
            edge: true,
            worker_ports: [closed, closed],
            admin: false,
            sequence: Arc::new(Mutex::new(0)),
        };
        let response = api(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/embed")
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(
                        json!({"model":"nomic-embed-text","input":["isolated coverage"]})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "embed_workers_unavailable");
        assert_eq!(body["error"]["retryable"], true);
        let db = database(&state).unwrap();
        for worker in ["l0", "echo"] {
            let failures: i64 = db
                .query_row(
                    "SELECT count(*) FROM worker_events WHERE worker=?1 AND ok=0",
                    [worker],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(failures, 1, "each unavailable worker must be attempted");
        }
        drop(db);
        fs::remove_dir_all(scratch).unwrap();
    }
}

#[cfg(test)]
mod la_tests;
