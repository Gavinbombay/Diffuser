//! Diffuser v1.0 Scalable Multi-Worker Fleet Router, Pluggable Workload Runner & MCP Surface.
//!
//! Mounted under `/v1/fleet/*` on `uai-diffuser` when `--fleet-config <path>` is supplied.
//! When `--fleet-config` is omitted, `/v1/fleet/*` fails closed with `503 fleet_closed`.

use axum::{
    body::Bytes,
    extract::{Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use lane_router::transport::{private_http_client, private_http_url};
use reqwest::Url;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const HEARTBEAT_TTL_MS: u64 = 45_000;
const MAX_RPC_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const RPC_MAX_AGE_MS: u64 = 60_000;
const RPC_FUTURE_SKEW_MS: u64 = 5_000;
const MAX_RPC_NONCES: usize = 8192;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct GpuInfo {
    pub(super) uuid: String,
    pub(super) name: String,
    pub(super) vram_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct CapabilityInfo {
    pub(super) capability: String,
    pub(super) kind: String,
    #[serde(default)]
    pub(super) gpu_uuid: Option<String>,
    #[serde(default)]
    pub(super) description: String,
}

#[derive(Clone, Deserialize)]
pub(super) struct FleetControllerConfig {
    pub(super) admin_token_sha256: String,
    #[serde(default)]
    pub(super) db_path: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(super) enum ProfileAdapter {
    Exec {
        command: Vec<String>,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
        #[serde(default)]
        gpu_uuid: Option<String>,
    },
    Http {
        url: String,
        #[serde(default = "default_http_method")]
        method: String,
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
        #[serde(default)]
        gpu_uuid: Option<String>,
        #[serde(default)]
        bearer_file: Option<String>,
    },
}

#[derive(Clone, Deserialize)]
pub(super) struct WorkloadProfile {
    pub(super) capability: String,
    #[serde(default)]
    pub(super) description: String,
    pub(super) adapter: ProfileAdapter,
}

#[derive(Clone, Deserialize)]
pub(super) struct FleetWorkerConfig {
    pub(super) worker_id: String,
    pub(super) host: String,
    pub(super) bind: String,
    pub(super) advertise_url: String,
    pub(super) controller_url: String,
    pub(super) enroll_bearer: String,
    pub(super) rpc_secret_hex: String,
    #[serde(default = "default_cpu")]
    pub(super) cpu_millicores: u64,
    #[serde(default = "default_ram")]
    pub(super) ram_bytes: u64,
    #[serde(default)]
    pub(super) vram_bytes: u64,
    #[serde(default = "default_true")]
    pub(super) auto_detect_gpus: bool,
    pub(super) profiles: Vec<WorkloadProfile>,
}

fn default_timeout_secs() -> u64 {
    60
}
fn default_http_method() -> String {
    "POST".to_string()
}
fn default_cpu() -> u64 {
    4000
}
fn default_ram() -> u64 {
    8 * 1024 * 1024 * 1024
}
fn default_true() -> bool {
    true
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn random_id() -> io::Result<String> {
    let mut bytes = [0; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn is_random_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn fleet_base_url(raw: &str) -> Option<Url> {
    Url::parse(raw).ok().filter(|url| {
        private_http_url(url) && url.query().is_none() && url.fragment().is_none()
    })
}

fn fleet_endpoint(base: &Url, endpoint: &str) -> Url {
    let mut url = base.clone();
    let path = format!("{}{}", url.path().trim_end_matches('/'), endpoint);
    url.set_path(&path);
    url
}

fn sign_rpc(secret_hex: &str, body: &[u8]) -> String {
    let message = [b"diffuser-fleet-rpc/v2\0".as_slice(), body].concat();
    let key = Sha256::digest(secret_hex.as_bytes()).into();
    hex::encode(super::la_adapter::receipt_mac(&key, &message))
}

fn verify_rpc(secret_hex: &str, body: &[u8], provided: &str) -> bool {
    let expected = sign_rpc(secret_hex, body);
    expected.len() == provided.len() && bool::from(expected.as_bytes().ct_eq(provided.as_bytes()))
}

fn add_rpc_session_column(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('fleet_workers') WHERE name='rpc_session')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        tx.execute("ALTER TABLE fleet_workers ADD COLUMN rpc_session TEXT", [])?;
    }
    tx.commit()
}

fn err_resp(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "schema_version": "diffuser-fleet/v1",
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

#[derive(Clone)]
struct FleetState {
    db: Arc<Mutex<Connection>>,
    admin_sha256: String,
    http: reqwest::blocking::Client,
    artifacts_dir: PathBuf,
}

#[derive(Clone)]
struct CallerAuth {
    is_admin: bool,
    actor: String,
    project: String,
    allowed_capabilities: Vec<String>,
    max_vram_bytes: u64,
}

impl FleetState {
    fn open(cfg_path: &Path, state_dir: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(cfg_path).map_err(|e| format!("fleet_config_read:{e}"))?;
        let cfg: FleetControllerConfig =
            serde_json::from_str(&raw).map_err(|e| format!("fleet_config_parse:{e}"))?;
        let admin_sha = cfg.admin_token_sha256.trim().to_ascii_lowercase();
        if admin_sha.len() != 64 || !admin_sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid_admin_token_sha256".to_string());
        }
        let db_path = cfg
            .db_path
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("fleet.sqlite"));
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("fleet_mkdir:{e}"))?;
        }
        let mut conn = Connection::open(&db_path).map_err(|e| format!("fleet_db_open:{e}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS fleet_workers (
                 worker_id TEXT PRIMARY KEY,
                 host TEXT NOT NULL,
                 rpc_url TEXT NOT NULL,
                 rpc_secret_hex TEXT NOT NULL,
                 cpu_total INTEGER NOT NULL,
                 ram_total INTEGER NOT NULL,
                 vram_total INTEGER NOT NULL,
                 cpu_reserved INTEGER NOT NULL DEFAULT 0,
                 ram_reserved INTEGER NOT NULL DEFAULT 0,
                 vram_reserved INTEGER NOT NULL DEFAULT 0,
                 gpus_json TEXT NOT NULL,
                 capabilities_json TEXT NOT NULL,
                 status TEXT NOT NULL,
                 last_heartbeat_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS fleet_tokens (
                 token_id TEXT PRIMARY KEY,
                 token_sha256 TEXT NOT NULL UNIQUE,
                 actor TEXT NOT NULL,
                 project TEXT NOT NULL,
                 allowed_capabilities_json TEXT NOT NULL,
                 max_vram_bytes INTEGER NOT NULL,
                 created_at_ms INTEGER NOT NULL,
                 expires_at_ms INTEGER NOT NULL,
                 revoked INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS fleet_jobs (
                 job_id TEXT PRIMARY KEY,
                 idempotency_key TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 project TEXT NOT NULL,
                 capability TEXT NOT NULL,
                 worker_id TEXT NOT NULL,
                 gpu_uuid TEXT,
                 state TEXT NOT NULL,
                 input_json TEXT NOT NULL,
                 output_json TEXT,
                 output_sha256 TEXT,
                 error_code TEXT,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 UNIQUE(actor, project, idempotency_key)
             );
             CREATE TABLE IF NOT EXISTS fleet_artifacts (
                 artifact_id TEXT PRIMARY KEY,
                 actor TEXT NOT NULL,
                 project TEXT NOT NULL,
                 sha256 TEXT NOT NULL,
                 bytes INTEGER NOT NULL,
                 media_type TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL
             );",
        )
        .map_err(|e| format!("fleet_schema:{e}"))?;
        add_rpc_session_column(&mut conn).map_err(|e| format!("fleet_schema:{e}"))?;

        let http = private_http_client()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| format!("fleet_http:{e}"))?;

        let artifacts_dir = state_dir.join("fleet-artifacts");
        fs::create_dir_all(&artifacts_dir).map_err(|e| format!("fleet_artifacts_mkdir:{e}"))?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            admin_sha256: admin_sha,
            http,
            artifacts_dir,
        })
    }

    fn check_admin(&self, headers: &HeaderMap) -> bool {
        let Some(tok) = bearer_from_headers(headers) else {
            return false;
        };
        let digest = sha256_hex(tok.as_bytes());
        bool::from(digest.as_bytes().ct_eq(self.admin_sha256.as_bytes()))
    }

    fn authenticate(&self, headers: &HeaderMap) -> Result<CallerAuth, (StatusCode, &'static str)> {
        let Some(tok) = bearer_from_headers(headers) else {
            return Err((StatusCode::UNAUTHORIZED, "auth_required"));
        };
        let digest = sha256_hex(tok.as_bytes());
        if bool::from(digest.as_bytes().ct_eq(self.admin_sha256.as_bytes())) {
            return Ok(CallerAuth {
                is_admin: true,
                actor: "admin".to_string(),
                project: "default".to_string(),
                allowed_capabilities: vec!["*".to_string()],
                max_vram_bytes: u64::MAX,
            });
        }
        let conn = self
            .db
            .lock()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"))?;
        let row: Option<(String, String, String, i64, i64, i64)> = conn
            .query_row(
                "SELECT actor, project, allowed_capabilities_json, max_vram_bytes, expires_at_ms, revoked
                 FROM fleet_tokens WHERE token_sha256=?1",
                [&digest],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"))?;
        let Some((actor, project, caps_json, max_vram, expires_at, revoked)) = row else {
            return Err((StatusCode::UNAUTHORIZED, "auth_invalid"));
        };
        if revoked != 0 || now_ms() >= expires_at as u64 {
            return Err((StatusCode::UNAUTHORIZED, "auth_expired_or_revoked"));
        }
        let allowed_capabilities: Vec<String> =
            serde_json::from_str(&caps_json).unwrap_or_default();
        Ok(CallerAuth {
            is_admin: false,
            actor,
            project,
            allowed_capabilities,
            max_vram_bytes: max_vram.max(0) as u64,
        })
    }

    fn capability_allowed(auth: &CallerAuth, capability: &str) -> bool {
        auth.is_admin
            || auth
                .allowed_capabilities
                .iter()
                .any(|c| c == "*" || c == capability)
    }
}

pub(super) fn closed_router() -> Router<super::Spine> {
    async fn closed() -> Response {
        err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "fleet_closed",
            "Fleet routing is closed; pass --fleet-config to enable.",
        )
    }
    Router::new()
        .route("/discover", get(closed))
        .route("/workers", get(closed))
        .route("/workers/enroll", post(closed))
        .route("/workers/{worker_id}/heartbeat", post(closed))
        .route("/workers/{worker_id}/drain", post(closed))
        .route("/tokens", post(closed))
        .route("/tokens/{token_id}/revoke", post(closed))
        .route("/jobs", post(closed))
        .route("/jobs/{job_id}", get(closed))
        .route("/artifacts", post(closed))
        .route("/artifacts/{artifact_id}", get(closed))
        .route("/artifacts/{artifact_id}/content", get(closed))
        .route("/mcp", post(closed))
}

pub(super) fn router(cfg_path: &Path, state_dir: &Path) -> Result<Router<super::Spine>, String> {
    let state = FleetState::open(cfg_path, state_dir)?;
    Ok(Router::new()
        .route("/discover", get(handle_discover))
        .route("/workers", get(handle_list_workers))
        .route("/workers/enroll", post(handle_enroll))
        .route("/workers/{worker_id}/heartbeat", post(handle_heartbeat))
        .route("/workers/{worker_id}/drain", post(handle_drain))
        .route("/tokens", post(handle_issue_token))
        .route("/tokens/{token_id}/revoke", post(handle_revoke_token))
        .route("/jobs", post(handle_submit_job))
        .route("/jobs/{job_id}", get(handle_get_job))
        .route("/artifacts", post(handle_upload_artifact).layer(axum::extract::DefaultBodyLimit::max(MAX_ARTIFACT_BYTES)))
        .route("/artifacts/{artifact_id}", get(handle_get_artifact_manifest))
        .route("/artifacts/{artifact_id}/content", get(handle_get_artifact_content))
        .route("/mcp", post(handle_mcp))
        .with_state(state))
}

#[derive(Deserialize)]
struct EnrollRequest {
    worker_id: String,
    host: String,
    rpc_url: String,
    rpc_secret_hex: String,
    rpc_session: String,
    cpu_millicores: u64,
    ram_bytes: u64,
    vram_bytes: u64,
    #[serde(default)]
    gpus: Vec<GpuInfo>,
    capabilities: Vec<CapabilityInfo>,
}

async fn handle_enroll(
    State(state): State<FleetState>,
    headers: HeaderMap,
    Json(req): Json<EnrollRequest>,
) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(StatusCode::UNAUTHORIZED, "auth_required", "admin bearer required");
    }
    let Some(rpc_url) = fleet_base_url(&req.rpc_url) else {
        return err_resp(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", "invalid RPC URL");
    };
    if req.worker_id.trim().is_empty() || req.rpc_secret_hex.len() < 32 || !is_random_id(&req.rpc_session) {
        return err_resp(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", "invalid worker_id, rpc_secret_hex, or rpc_session");
    }
    let gpus_json = serde_json::to_string(&req.gpus).unwrap_or_else(|_| "[]".into());
    let caps_json = serde_json::to_string(&req.capabilities).unwrap_or_else(|_| "[]".into());
    let ts = now_ms() as i64;
    let Ok(conn) = state.db.lock() else {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock failed");
    };
    let res = conn.execute(
        "INSERT INTO fleet_workers (worker_id, host, rpc_url, rpc_secret_hex, cpu_total, ram_total, vram_total, cpu_reserved, ram_reserved, vram_reserved, gpus_json, capabilities_json, status, last_heartbeat_ms, rpc_session)
         VALUES (?1,?2,?3,?4,?5,?6,?7,0,0,0,?8,?9,'active',?10,?11)
         ON CONFLICT(worker_id) DO UPDATE SET
           host=excluded.host,
           rpc_url=excluded.rpc_url,
           rpc_secret_hex=excluded.rpc_secret_hex,
           rpc_session=excluded.rpc_session,
           cpu_total=excluded.cpu_total,
           ram_total=excluded.ram_total,
           vram_total=excluded.vram_total,
           gpus_json=excluded.gpus_json,
           capabilities_json=excluded.capabilities_json,
           status='active',
           cpu_reserved=CASE WHEN EXISTS(SELECT 1 FROM fleet_jobs WHERE worker_id=excluded.worker_id AND state='running') THEN fleet_workers.cpu_reserved ELSE 0 END,
           ram_reserved=CASE WHEN EXISTS(SELECT 1 FROM fleet_jobs WHERE worker_id=excluded.worker_id AND state='running') THEN fleet_workers.ram_reserved ELSE 0 END,
           vram_reserved=CASE WHEN EXISTS(SELECT 1 FROM fleet_jobs WHERE worker_id=excluded.worker_id AND state='running') THEN fleet_workers.vram_reserved ELSE 0 END,
           last_heartbeat_ms=excluded.last_heartbeat_ms",
        params![
            req.worker_id,
            req.host,
            rpc_url.as_str(),
            req.rpc_secret_hex,
            req.cpu_millicores as i64,
            req.ram_bytes as i64,
            req.vram_bytes as i64,
            gpus_json,
            caps_json,
            ts,
            req.rpc_session,
        ],
    );
    if res.is_err() {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "enroll write failed");
    }
    Json(json!({
        "schema_version": "diffuser-fleet/v1",
        "enrolled": true,
        "worker_id": req.worker_id,
        "status": "active",
        "heartbeat_ms": ts
    }))
    .into_response()
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    #[serde(default)]
    gpus: Option<Vec<GpuInfo>>,
    #[serde(default)]
    capabilities: Option<Vec<CapabilityInfo>>,
}

async fn handle_heartbeat(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(worker_id): AxPath<String>,
    Json(req): Json<HeartbeatRequest>,
) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(StatusCode::UNAUTHORIZED, "auth_required", "admin bearer required");
    }
    let ts = now_ms() as i64;
    let Ok(conn) = state.db.lock() else {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock failed");
    };
    let updated = if let (Some(gpus), Some(caps)) = (&req.gpus, &req.capabilities) {
        let gj = serde_json::to_string(gpus).unwrap_or_else(|_| "[]".into());
        let cj = serde_json::to_string(caps).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "UPDATE fleet_workers SET last_heartbeat_ms=?1, gpus_json=?2, capabilities_json=?3 WHERE worker_id=?4",
            params![ts, gj, cj, worker_id],
        )
    } else {
        conn.execute(
            "UPDATE fleet_workers SET last_heartbeat_ms=?1 WHERE worker_id=?2",
            params![ts, worker_id],
        )
    };
    match updated {
        Ok(0) => err_resp(StatusCode::NOT_FOUND, "worker_not_found", "unknown worker_id"),
        Ok(_) => Json(json!({"ok": true, "worker_id": worker_id, "heartbeat_ms": ts})).into_response(),
        Err(_) => err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "heartbeat write failed"),
    }
}

async fn handle_drain(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(worker_id): AxPath<String>,
) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(StatusCode::UNAUTHORIZED, "auth_required", "admin bearer required");
    }
    let Ok(conn) = state.db.lock() else {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock failed");
    };
    match conn.execute(
        "UPDATE fleet_workers SET status='draining' WHERE worker_id=?1",
        [&worker_id],
    ) {
        Ok(0) => err_resp(StatusCode::NOT_FOUND, "worker_not_found", "unknown worker_id"),
        Ok(_) => Json(json!({"ok": true, "worker_id": worker_id, "status": "draining"})).into_response(),
        Err(_) => err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "drain write failed"),
    }
}

fn list_workers_json(state: &FleetState) -> Result<Vec<Value>, &'static str> {
    let conn = state.db.lock().map_err(|_| "storage_unavailable")?;
    let mut stmt = conn
        .prepare(
            "SELECT worker_id, host, rpc_url, cpu_total, ram_total, vram_total,
                    cpu_reserved, ram_reserved, vram_reserved, gpus_json, capabilities_json,
                    status, last_heartbeat_ms
             FROM fleet_workers ORDER BY worker_id",
        )
        .map_err(|_| "storage_unavailable")?;
    let now = now_ms();
    let rows = stmt
        .query_map([], |r| {
            let wid: String = r.get(0)?;
            let host: String = r.get(1)?;
            let rpc_url: String = r.get(2)?;
            let cpu_t: i64 = r.get(3)?;
            let ram_t: i64 = r.get(4)?;
            let vram_t: i64 = r.get(5)?;
            let cpu_r: i64 = r.get(6)?;
            let ram_r: i64 = r.get(7)?;
            let vram_r: i64 = r.get(8)?;
            let gpus_s: String = r.get(9)?;
            let caps_s: String = r.get(10)?;
            let status: String = r.get(11)?;
            let hb: i64 = r.get(12)?;
            let alive = now.saturating_sub(hb as u64) <= HEARTBEAT_TTL_MS;
            let gpus: Value = serde_json::from_str(&gpus_s).unwrap_or(json!([]));
            let caps: Value = serde_json::from_str(&caps_s).unwrap_or(json!([]));
            Ok(json!({
                "worker_id": wid,
                "host": host,
                "rpc_url": rpc_url,
                "status": status,
                "alive": alive,
                "accepting": alive && status == "active",
                "cpu_total": cpu_t,
                "cpu_free": (cpu_t - cpu_r).max(0),
                "ram_total": ram_t,
                "ram_free": (ram_t - ram_r).max(0),
                "vram_total": vram_t,
                "vram_free": (vram_t - vram_r).max(0),
                "gpus": gpus,
                "capabilities": caps,
                "last_heartbeat_ms": hb
            }))
        })
        .map_err(|_| "storage_unavailable")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "storage_unavailable")?;
    Ok(rows)
}

async fn handle_list_workers(State(state): State<FleetState>, headers: HeaderMap) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(StatusCode::UNAUTHORIZED, "auth_required", "admin bearer required");
    }
    match list_workers_json(&state) {
        Ok(workers) => Json(json!({
            "schema_version": "diffuser-fleet/v1",
            "workers": workers
        }))
        .into_response(),
        Err(c) => err_resp(StatusCode::SERVICE_UNAVAILABLE, c, "failed to query workers"),
    }
}

fn discover_json(state: &FleetState, auth: &CallerAuth) -> Result<Value, &'static str> {
    let workers = list_workers_json(state)?;
    let mut caps_out = Vec::new();
    for w in &workers {
        if w["accepting"] != true {
            continue;
        }
        if let Some(caps) = w["capabilities"].as_array() {
            for c in caps {
                let cap_name = c["capability"].as_str().unwrap_or("");
                if !FleetState::capability_allowed(auth, cap_name) {
                    continue;
                }
                caps_out.push(json!({
                    "capability": cap_name,
                    "kind": c["kind"],
                    "description": c["description"],
                    "gpu_uuid": c["gpu_uuid"],
                    "accepting": true,
                    "free_cpu_millicores": w["cpu_free"],
                    "free_ram_bytes": w["ram_free"],
                    "free_vram_bytes": w["vram_free"],
                    "gpus": w["gpus"]
                }));
            }
        }
    }
    Ok(json!({
        "schema_version": "diffuser-fleet/v1",
        "actor": auth.actor,
        "project": auth.project,
        "capabilities": caps_out
    }))
}

async fn handle_discover(State(state): State<FleetState>, headers: HeaderMap) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    match discover_json(&state, &auth) {
        Ok(v) => Json(v).into_response(),
        Err(c) => err_resp(StatusCode::SERVICE_UNAVAILABLE, c, "discover failed"),
    }
}

#[derive(Deserialize)]
struct IssueTokenRequest {
    actor: String,
    project: String,
    allowed_capabilities: Vec<String>,
    #[serde(default = "default_max_vram")]
    max_vram_bytes: u64,
    #[serde(default = "default_token_ttl")]
    ttl_secs: u64,
}
fn default_max_vram() -> u64 {
    64 * 1024 * 1024 * 1024
}
fn default_token_ttl() -> u64 {
    86_400 * 30
}

fn issue_token_inner(state: &FleetState, req: &IssueTokenRequest) -> Result<Value, &'static str> {
    if req.actor.trim().is_empty() || req.project.trim().is_empty() || req.allowed_capabilities.is_empty() {
        return Err("invalid_request");
    }
    let mut raw_bytes = [0u8; 24];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut raw_bytes))
        .map_err(|_| "entropy_unavailable")?;
    let token = format!("tok_fl_{}", hex::encode(raw_bytes));
    let token_sha = sha256_hex(token.as_bytes());
    let token_id = format!("tk_{}", &token_sha[..16]);
    let now = now_ms();
    let expires = now.saturating_add(req.ttl_secs.saturating_mul(1000));
    let caps_json = serde_json::to_string(&req.allowed_capabilities).map_err(|_| "invalid_request")?;
    let conn = state.db.lock().map_err(|_| "storage_unavailable")?;
    conn.execute(
        "INSERT INTO fleet_tokens (token_id, token_sha256, actor, project, allowed_capabilities_json, max_vram_bytes, created_at_ms, expires_at_ms, revoked)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0)",
        params![
            token_id,
            token_sha,
            req.actor,
            req.project,
            caps_json,
            req.max_vram_bytes as i64,
            now as i64,
            expires as i64
        ],
    )
    .map_err(|_| "storage_unavailable")?;
    Ok(json!({
        "schema_version": "diffuser-fleet/v1",
        "token_id": token_id,
        "token": token,
        "actor": req.actor,
        "project": req.project,
        "allowed_capabilities": req.allowed_capabilities,
        "expires_at_ms": expires
    }))
}

async fn handle_issue_token(
    State(state): State<FleetState>,
    headers: HeaderMap,
    Json(req): Json<IssueTokenRequest>,
) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(StatusCode::UNAUTHORIZED, "auth_required", "admin bearer required");
    }
    match issue_token_inner(&state, &req) {
        Ok(v) => (StatusCode::CREATED, Json(v)).into_response(),
        Err(c) => err_resp(StatusCode::UNPROCESSABLE_ENTITY, c, "token issuance failed"),
    }
}

async fn handle_revoke_token(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(token_id): AxPath<String>,
) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(StatusCode::UNAUTHORIZED, "auth_required", "admin bearer required");
    }
    let Ok(conn) = state.db.lock() else {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock failed");
    };
    match conn.execute("UPDATE fleet_tokens SET revoked=1 WHERE token_id=?1", [&token_id]) {
        Ok(0) => err_resp(StatusCode::NOT_FOUND, "token_not_found", "unknown token_id"),
        Ok(_) => Json(json!({"ok": true, "token_id": token_id, "revoked": true})).into_response(),
        Err(_) => err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "revoke failed"),
    }
}

#[derive(Deserialize)]
struct SubmitJobRequest {
    capability: String,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    pin_gpu_uuid: Option<String>,
    #[serde(default)]
    min_vram_bytes: u64,
    #[serde(default = "default_job_cpu")]
    cpu_millicores: u64,
    #[serde(default = "default_job_ram")]
    ram_bytes: u64,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}
fn default_job_cpu() -> u64 {
    500
}
fn default_job_ram() -> u64 {
    256 * 1024 * 1024
}

fn submit_job_inner(
    state: &FleetState,
    auth: &CallerAuth,
    idemp_key: &str,
    req: &SubmitJobRequest,
) -> Result<(StatusCode, Value), (StatusCode, &'static str, String)> {
    if idemp_key.trim().is_empty() || req.capability.trim().is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", "missing capability or Idempotency-Key".into()));
    }
    if !FleetState::capability_allowed(auth, &req.capability) {
        return Err((StatusCode::FORBIDDEN, "capability_forbidden", "token does not allow this capability".into()));
    }
    if req.min_vram_bytes > auth.max_vram_bytes {
        return Err((StatusCode::FORBIDDEN, "vram_limit_exceeded", "requested VRAM exceeds token limit".into()));
    }

    let now = now_ms();
    let input_str = serde_json::to_string(&req.input).unwrap_or_else(|_| "{}".into());

    // Step 1: Atomic idempotency check + scheduler match + reservation
    let (job_id, worker_id, rpc_url, rpc_secret, rpc_session, matched_gpu) = {
        let mut conn = state
            .db
            .lock()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock".into()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "tx begin".into()))?;

        // Idempotent retry lookup
        let existing: Option<(String, String, String, Option<String>, Option<String>, Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT job_id, worker_id, state, gpu_uuid, output_json, output_sha256, error_code
                 FROM fleet_jobs WHERE actor=?1 AND project=?2 AND idempotency_key=?3",
                params![auth.actor, auth.project, idemp_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
            )
            .optional()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "idemp query".into()))?;
        if let Some((jid, wid, st, gpu, out_j, out_sha, err_c)) = existing {
            let output: Value = out_j
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(Value::Null);
            return Ok((
                StatusCode::OK,
                json!({
                    "schema_version": "diffuser-fleet/v1",
                    "job_id": jid,
                    "worker_id": wid,
                    "gpu_uuid": gpu,
                    "capability": req.capability,
                    "state": st,
                    "idempotent_replay": true,
                    "output": output,
                    "output_sha256": out_sha,
                    "error_code": err_c
                }),
            ));
        }

        // Find matching live active worker
        let mut stmt = tx
            .prepare(
                "SELECT worker_id, rpc_url, rpc_secret_hex, cpu_total - cpu_reserved, ram_total - ram_reserved,
                        vram_total - vram_reserved, gpus_json, capabilities_json, last_heartbeat_ms, rpc_session
                 FROM fleet_workers WHERE status='active' AND rpc_session IS NOT NULL
                 ORDER BY (vram_total - vram_reserved) DESC, worker_id ASC",
            )
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "sched query".into()))?;

        let candidates: Vec<(String, String, String, i64, i64, i64, String, String, i64, String)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?,
                    r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?,
                ))
            })
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "sched map".into()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "sched collect".into()))?;
        drop(stmt);

        let mut chosen = None;
        for (wid, url, secret, f_cpu, f_ram, f_vram, gpus_s, caps_s, hb, session) in candidates {
            // Existing enrollments are also checked before any reservation or RPC.
            let Some(url) = fleet_base_url(&url) else {
                continue;
            };
            if !is_random_id(&session) || now.saturating_sub(hb as u64) > HEARTBEAT_TTL_MS {
                continue;
            }
            if (f_cpu as u64) < req.cpu_millicores
                || (f_ram as u64) < req.ram_bytes
                || (f_vram as u64) < req.min_vram_bytes
            {
                continue;
            }
            let caps: Vec<CapabilityInfo> = serde_json::from_str(&caps_s).unwrap_or_default();
            let gpus: Vec<GpuInfo> = serde_json::from_str(&gpus_s).unwrap_or_default();
            let matching_cap = caps.iter().find(|c| {
                if c.capability != req.capability {
                    return false;
                }
                if let Some(ref want_gpu) = req.pin_gpu_uuid {
                    c.gpu_uuid.as_deref() == Some(want_gpu.as_str())
                        || gpus.iter().any(|g| g.uuid == *want_gpu)
                } else {
                    true
                }
            });
            if let Some(cap_entry) = matching_cap {
                let gpu_sel = req
                    .pin_gpu_uuid
                    .clone()
                    .or_else(|| cap_entry.gpu_uuid.clone())
                    .or_else(|| gpus.first().map(|g| g.uuid.clone()));
                chosen = Some((wid, url, secret, session, gpu_sel));
                break;
            }
        }

        let Some((wid, url, secret, session, gpu_sel)) = chosen else {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "capability_unavailable",
                "no live worker matches capability, resources, and GPU pin".into(),
            ));
        };

        let nonce = random_id().map_err(|_| {
            (StatusCode::SERVICE_UNAVAILABLE, "entropy_unavailable", "job identity unavailable".into())
        })?;
        let jid = format!("fjob_{nonce}");

        tx.execute(
            "UPDATE fleet_workers SET cpu_reserved=cpu_reserved+?1, ram_reserved=ram_reserved+?2, vram_reserved=vram_reserved+?3 WHERE worker_id=?4",
            params![req.cpu_millicores as i64, req.ram_bytes as i64, req.min_vram_bytes as i64, wid],
        )
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "reserve failed".into()))?;

        tx.execute(
            "INSERT INTO fleet_jobs (job_id, idempotency_key, actor, project, capability, worker_id, gpu_uuid, state, input_json, created_at_ms, updated_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,'running',?8,?9,?9)",
            params![jid, idemp_key, auth.actor, auth.project, req.capability, wid, gpu_sel, input_str, now as i64],
        )
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "job insert failed".into()))?;

        tx.commit()
            .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "tx commit".into()))?;
        (jid, wid, url, secret, session, gpu_sel)
    };

    // Step 2: Dispatch signed RPC to matched worker
    let rpc_payload = serde_json::to_vec(&json!({
        "job_id": job_id,
        "rpc_session": rpc_session,
        "issued_at_ms": now_ms(),
        "capability": req.capability,
        "gpu_uuid": matched_gpu,
        "input": req.input,
        "timeout_secs": req.timeout_secs.clamp(1, 300)
    }))
    .unwrap_or_default();
    let sig = sign_rpc(&rpc_secret, &rpc_payload);

    let worker_res = state
        .http
        .post(fleet_endpoint(&rpc_url, "/v1/fleet-worker/run"))
        .header("content-type", "application/json")
        .header("x-diffuser-signature", sig)
        .body(rpc_payload)
        .send();

    let (final_state, output_val, output_sha, err_code, release_capacity) = match worker_res {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Value>() {
                Ok(body) if body["ok"] == true => {
                    let out = body["output"].clone();
                    let out_bytes = serde_json::to_vec(&out).unwrap_or_default();
                    let sha = sha256_hex(&out_bytes);
                    let clean = body["cleanup_ok"].as_bool().unwrap_or(false);
                    ("succeeded", out, Some(sha), None, clean)
                }
                Ok(body) => {
                    let clean = body["cleanup_ok"].as_bool().unwrap_or(false);
                    let code = body["error"].as_str().unwrap_or("worker_execution_failed").to_string();
                    (if clean { "failed" } else { "failed_uncertain" }, Value::Null, None, Some(code), clean)
                }
                Err(_) => ("failed_uncertain", Value::Null, None, Some("worker_invalid_reply".into()), false),
            }
        }
        Ok(resp) => (
            "failed_uncertain",
            Value::Null,
            None,
            Some(format!("worker_http_{}", resp.status().as_u16())),
            false,
        ),
        Err(_) => ("failed_uncertain", Value::Null, None, Some("worker_unreachable".into()), false),
    };

    // Step 3: Commit durable result & release capacity ONLY when cleanup_ok == true
    let out_str = if output_val.is_null() {
        None
    } else {
        Some(serde_json::to_string(&output_val).unwrap_or_else(|_| "null".into()))
    };
    let done_ts = now_ms() as i64;
    if let Ok(mut conn) = state.db.lock() {
        if let Ok(tx) = conn.transaction_with_behavior(TransactionBehavior::Immediate) {
            let _ = tx.execute(
                "UPDATE fleet_jobs SET state=?1, output_json=?2, output_sha256=?3, error_code=?4, updated_at_ms=?5 WHERE job_id=?6",
                params![final_state, out_str, output_sha, err_code, done_ts, job_id],
            );
            if release_capacity {
                let _ = tx.execute(
                    "UPDATE fleet_workers SET cpu_reserved=MAX(0, cpu_reserved-?1), ram_reserved=MAX(0, ram_reserved-?2), vram_reserved=MAX(0, vram_reserved-?3) WHERE worker_id=?4",
                    params![req.cpu_millicores as i64, req.ram_bytes as i64, req.min_vram_bytes as i64, worker_id],
                );
            } else {
                // Quarantine uncertain worker instead of blindly freeing dirty capacity
                let _ = tx.execute(
                    "UPDATE fleet_workers SET status='quarantined' WHERE worker_id=?1",
                    [&worker_id],
                );
            }
            let _ = tx.commit();
        }
    }

    Ok((
        StatusCode::OK,
        json!({
            "schema_version": "diffuser-fleet/v1",
            "job_id": job_id,
            "worker_id": worker_id,
            "gpu_uuid": matched_gpu,
            "capability": req.capability,
            "state": final_state,
            "idempotent_replay": false,
            "capacity_released": release_capacity,
            "output": output_val,
            "output_sha256": output_sha,
            "error_code": err_code
        }),
    ))
}

async fn handle_submit_job(
    State(state): State<FleetState>,
    headers: HeaderMap,
    Json(req): Json<SubmitJobRequest>,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    let idemp = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let res = tokio::task::spawn_blocking(move || submit_job_inner(&state, &auth, &idemp, &req))
        .await;
    match res {
        Ok(Ok((st, val))) => (st, Json(val)).into_response(),
        Ok(Err((st, code, msg))) => err_resp(st, code, &msg),
        Err(_) => err_resp(StatusCode::SERVICE_UNAVAILABLE, "worker_dispatch_panicked", "internal dispatch error"),
    }
}

fn get_job_inner(state: &FleetState, auth: &CallerAuth, job_id: &str) -> Result<Value, (StatusCode, &'static str)> {
    let conn = state
        .db
        .lock()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"))?;
    let row: Option<(String, String, String, String, Option<String>, String, Option<String>, Option<String>, Option<String>, i64, i64)> = conn
        .query_row(
            "SELECT actor, project, capability, worker_id, gpu_uuid, state, output_json, output_sha256, error_code, created_at_ms, updated_at_ms
             FROM fleet_jobs WHERE job_id=?1",
            [job_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?)),
        )
        .optional()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"))?;
    let Some((actor, project, capability, worker_id, gpu_uuid, st, out_j, out_sha, err_c, c_at, u_at)) = row else {
        return Err((StatusCode::NOT_FOUND, "job_not_found"));
    };
    if !auth.is_admin && (actor != auth.actor || project != auth.project) {
        return Err((StatusCode::FORBIDDEN, "forbidden"));
    }
    let output: Value = out_j
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null);
    Ok(json!({
        "schema_version": "diffuser-fleet/v1",
        "job_id": job_id,
        "actor": actor,
        "project": project,
        "capability": capability,
        "worker_id": worker_id,
        "gpu_uuid": gpu_uuid,
        "state": st,
        "output": output,
        "output_sha256": out_sha,
        "error_code": err_c,
        "created_at_ms": c_at,
        "updated_at_ms": u_at
    }))
}

async fn handle_get_job(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(job_id): AxPath<String>,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    match get_job_inner(&state, &auth, &job_id) {
        Ok(v) => Json(v).into_response(),
        Err((st, code)) => err_resp(st, code, "job read failed"),
    }
}


async fn handle_upload_artifact(
    State(state): State<FleetState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    if body.is_empty() || body.len() > MAX_ARTIFACT_BYTES {
        return err_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            "artifact_size_invalid",
            "artifact must be 1 byte to 64 MiB",
        );
    }
    let media_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let digest = sha256_hex(&body);
    let mut rnd = [0u8; 12];
    let _ = fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut rnd));
    let artifact_id = format!("fart_{}", hex::encode(rnd));
    let file_path = state.artifacts_dir.join(&artifact_id);
    if fs::write(&file_path, &body).is_err() {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "artifact write failed");
    }
    let ts = now_ms() as i64;
    let Ok(conn) = state.db.lock() else {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock failed");
    };
    if conn
        .execute(
            "INSERT INTO fleet_artifacts (artifact_id, actor, project, sha256, bytes, media_type, created_at_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![artifact_id, auth.actor, auth.project, digest, body.len() as i64, media_type, ts],
        )
        .is_err()
    {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "artifact metadata write failed");
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "schema_version": "diffuser-fleet/v1",
            "artifact_id": artifact_id,
            "sha256": digest,
            "bytes": body.len(),
            "media_type": media_type,
            "created_at_ms": ts
        })),
    )
        .into_response()
}

async fn handle_get_artifact_manifest(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(artifact_id): AxPath<String>,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    let Ok(conn) = state.db.lock() else {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock failed");
    };
    let row: Option<(String, String, String, i64, String, i64)> = conn
        .query_row(
            "SELECT actor, project, sha256, bytes, media_type, created_at_ms FROM fleet_artifacts WHERE artifact_id=?1",
            [&artifact_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()
        .unwrap_or(None);
    let Some((actor, project, digest, bytes, media_type, ts)) = row else {
        return err_resp(StatusCode::NOT_FOUND, "artifact_not_found", "unknown artifact_id");
    };
    if !auth.is_admin && (actor != auth.actor || project != auth.project) {
        return err_resp(StatusCode::FORBIDDEN, "forbidden", "artifact belongs to another caller");
    }
    Json(json!({
        "schema_version": "diffuser-fleet/v1",
        "artifact_id": artifact_id,
        "sha256": digest,
        "bytes": bytes,
        "media_type": media_type,
        "created_at_ms": ts
    }))
    .into_response()
}

async fn handle_get_artifact_content(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(artifact_id): AxPath<String>,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    if !artifact_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return err_resp(StatusCode::BAD_REQUEST, "invalid_artifact_id", "invalid characters");
    }
    let meta: Option<(String, String, String, String)> = {
        let Ok(conn) = state.db.lock() else {
            return err_resp(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "db lock failed");
        };
        conn.query_row(
            "SELECT actor, project, sha256, media_type FROM fleet_artifacts WHERE artifact_id=?1",
            [&artifact_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .unwrap_or(None)
    };
    let Some((actor, project, expected_sha, media_type)) = meta else {
        return err_resp(StatusCode::NOT_FOUND, "artifact_not_found", "unknown artifact_id");
    };
    if !auth.is_admin && (actor != auth.actor || project != auth.project) {
        return err_resp(StatusCode::FORBIDDEN, "forbidden", "artifact belongs to another caller");
    }
    let Ok(bytes) = fs::read(state.artifacts_dir.join(&artifact_id)) else {
        return err_resp(StatusCode::NOT_FOUND, "artifact_missing", "artifact bytes missing");
    };
    if sha256_hex(&bytes) != expected_sha {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "artifact_integrity_failed", "digest mismatch");
    }
    (
        StatusCode::OK,
        [
            ("content-type", media_type),
            ("x-diffuser-sha256", expected_sha),
        ],
        bytes,
    )
        .into_response()
}

// === MCP JSON-RPC 2.0 Surface (/v1/fleet/mcp) ===

async fn handle_mcp(
    State(state): State<FleetState>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    match method {
        "initialize" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": { "name": "diffuser-fleet", "version": "1.0.0" },
                "capabilities": { "tools": {} }
            }
        }))
        .into_response(),
        "tools/list" => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": [
                    {"name": "fleet_discover", "description": "Discover live Diffuser capabilities and available CPU/GPU capacity.", "inputSchema": {"type": "object", "properties": {}}},
                    {"name": "fleet_list_workers", "description": "List all enrolled Diffuser workers and live resources (admin).", "inputSchema": {"type": "object", "properties": {}}},
                    {"name": "fleet_submit_job", "description": "Submit an idempotent job by capability and optional exact GPU UUID.", "inputSchema": {"type": "object", "required": ["capability", "idempotency_key"], "properties": {"capability": {"type": "string"}, "idempotency_key": {"type": "string"}, "pin_gpu_uuid": {"type": "string"}, "input": {"type": "object"}}}},
                    {"name": "fleet_get_job", "description": "Read durable job status and verified output digest.", "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}}},
                    {"name": "fleet_issue_token", "description": "Issue a scoped caller token for a human or agent (admin).", "inputSchema": {"type": "object", "required": ["actor", "project", "allowed_capabilities"], "properties": {"actor": {"type": "string"}, "project": {"type": "string"}, "allowed_capabilities": {"type": "array", "items": {"type": "string"}}}}}
                ]
            }
        }))
        .into_response(),
        "tools/call" => {
            let name = req["params"]["name"].as_str().unwrap_or("");
            let args = req["params"]["arguments"].clone();
            let result: Result<Value, String> = match name {
                "fleet_discover" => discover_json(&state, &auth).map_err(|e| e.to_string()),
                "fleet_list_workers" => {
                    if !auth.is_admin {
                        Err("admin_required".into())
                    } else {
                        list_workers_json(&state)
                            .map(|w| json!({"workers": w}))
                            .map_err(|e| e.to_string())
                    }
                }
                "fleet_get_job" => {
                    let jid = args["job_id"].as_str().unwrap_or("");
                    get_job_inner(&state, &auth, jid).map_err(|(_, c)| c.to_string())
                }
                "fleet_issue_token" => {
                    if !auth.is_admin {
                        Err("admin_required".into())
                    } else {
                        serde_json::from_value::<IssueTokenRequest>(args)
                            .map_err(|e| format!("invalid_args:{e}"))
                            .and_then(|r| issue_token_inner(&state, &r).map_err(|e| e.to_string()))
                    }
                }
                "fleet_submit_job" => {
                    let idemp = args["idempotency_key"].as_str().unwrap_or("").to_string();
                    match serde_json::from_value::<SubmitJobRequest>(args) {
                        Ok(sub) => {
                            let st_clone = state.clone();
                            let auth_clone = auth.clone();
                            match tokio::task::spawn_blocking(move || {
                                submit_job_inner(&st_clone, &auth_clone, &idemp, &sub)
                            })
                            .await
                            {
                                Ok(Ok((_, v))) => Ok(v),
                                Ok(Err((_, c, m))) => Err(format!("{c}: {m}")),
                                Err(_) => Err("dispatch_failed".into()),
                            }
                        }
                        Err(e) => Err(format!("invalid_args:{e}")),
                    }
                }
                _ => Err("unknown_tool".into()),
            };
            match result {
                Ok(v) => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "content": [{ "type": "text", "text": serde_json::to_string(&v).unwrap_or_default() }] }
                }))
                .into_response(),
                Err(e) => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32000, "message": e }
                }))
                .into_response(),
            }
        }
        _ => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "method not found" }
        }))
        .into_response(),
    }
}

// === Standalone Pluggable Fleet Worker (--fleet-worker <config.json>) ===

fn detect_local_gpus() -> Vec<GpuInfo> {
    let Ok(out) = Command::new("nvidia-smi")
        .args(["--query-gpu=uuid,name,memory.total", "--format=csv,noheader,nounits"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let mut gpus = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() >= 3 {
            let vram_mib: u64 = parts[2].parse().unwrap_or(0);
            gpus.push(GpuInfo {
                uuid: parts[0].to_string(),
                name: parts[1].to_string(),
                vram_bytes: vram_mib.saturating_mul(1024 * 1024),
            });
        }
    }
    gpus
}

struct WorkerRuntime {
    cfg: FleetWorkerConfig,
    http: reqwest::blocking::Client,
    rpc_session: String,
    replay: Mutex<ReplayWindow>,
    clock: fn() -> u64,
}

#[derive(Default)]
struct ReplayWindow {
    latest_ms: u64,
    seen: HashMap<String, u64>,
}

impl ReplayWindow {
    fn consume(&mut self, job_id: &str, issued_at_ms: u64, now: u64) -> Result<(), &'static str> {
        // A clock rollback must never make an evicted nonce valid again.
        let oldest = self.latest_ms.max(now).saturating_sub(RPC_MAX_AGE_MS);
        if now == 0 || issued_at_ms < oldest || issued_at_ms > now.saturating_add(RPC_FUTURE_SKEW_MS) {
            return Err("rpc_timestamp_invalid");
        }
        self.latest_ms = self.latest_ms.max(now);
        self.seen.retain(|_, issued| *issued >= oldest);
        if self.seen.contains_key(job_id) {
            return Err("rpc_replayed");
        }
        if self.seen.len() >= MAX_RPC_NONCES {
            return Err("rpc_replay_cache_full");
        }
        self.seen.insert(job_id.to_owned(), issued_at_ms);
        Ok(())
    }
}

#[derive(Deserialize)]
struct WorkerRunRequest {
    job_id: String,
    rpc_session: String,
    issued_at_ms: u64,
    capability: String,
    #[serde(default)]
    gpu_uuid: Option<String>,
    #[serde(default)]
    input: Value,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}

async fn handle_worker_run(
    State(rt): State<Arc<WorkerRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_RPC_BODY_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({"ok": false, "error": "body_too_large", "cleanup_ok": true}))).into_response();
    }
    let sig = headers
        .get("x-diffuser-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !verify_rpc(&rt.cfg.rpc_secret_hex, &body, sig) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "error": "invalid_signature", "cleanup_ok": true}))).into_response();
    }
    let req: WorkerRunRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "invalid_json", "cleanup_ok": true}))).into_response(),
    };
    if req.rpc_session != rt.rpc_session || !req.job_id.strip_prefix("fjob_").is_some_and(is_random_id) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok": false, "error": "rpc_identity_invalid", "cleanup_ok": true}))).into_response();
    }
    let accepted = rt.replay.lock().map_err(|_| "rpc_replay_cache_unavailable")
        .and_then(|mut replay| replay.consume(&req.job_id, req.issued_at_ms, (rt.clock)()));
    if let Err(error) = accepted {
        let status = match error {
            "rpc_replayed" => StatusCode::CONFLICT,
            "rpc_timestamp_invalid" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        return (status, Json(json!({"ok": false, "error": error, "cleanup_ok": true}))).into_response();
    }
    let rt_clone = rt.clone();
    let res = tokio::task::spawn_blocking(move || execute_profile(&rt_clone, &req)).await;
    match res {
        Ok(v) => Json(v).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": "worker_panic", "cleanup_ok": false}))).into_response(),
    }
}

fn execute_profile(rt: &WorkerRuntime, req: &WorkerRunRequest) -> Value {
    let Some(profile) = rt
        .cfg
        .profiles
        .iter()
        .find(|p| p.capability == req.capability)
    else {
        return json!({"ok": false, "error": "capability_not_found", "cleanup_ok": true});
    };

    match &profile.adapter {
        ProfileAdapter::Exec {
            command,
            timeout_secs,
            gpu_uuid,
        } => {
            let Some((prog, args)) = command.split_first() else {
                return json!({"ok": false, "error": "empty_command", "cleanup_ok": true});
            };
            let mut cmd = Command::new(prog);
            cmd.args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env("DIFFUSER_JOB_ID", &req.job_id)
                .env("DIFFUSER_CAPABILITY", &req.capability);
            let effective_gpu = req.gpu_uuid.as_ref().or(gpu_uuid.as_ref());
            if let Some(uuid) = effective_gpu {
                cmd.env("CUDA_VISIBLE_DEVICES", uuid);
                cmd.env("DIFFUSER_GPU_UUID", uuid);
            }
            let Ok(mut child) = cmd.spawn() else {
                return json!({"ok": false, "error": "spawn_failed", "cleanup_ok": true});
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(serde_json::to_string(&req.input).unwrap_or_default().as_bytes());
            }
            let limit = Duration::from_secs(req.timeout_secs.min(*timeout_secs).clamp(1, 300));
            let deadline = std::time::Instant::now() + limit;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let out = child.wait_with_output();
                        match out {
                            Ok(o) if status.success() => {
                                let stdout_str = String::from_utf8_lossy(&o.stdout).trim().to_string();
                                let parsed: Value = serde_json::from_str(&stdout_str)
                                    .unwrap_or_else(|_| json!({"stdout": stdout_str}));
                                return json!({
                                    "ok": true,
                                    "worker_id": rt.cfg.worker_id,
                                    "gpu_uuid": effective_gpu,
                                    "output": parsed,
                                    "cleanup_ok": true
                                });
                            }
                            Ok(o) => {
                                return json!({
                                    "ok": false,
                                    "error": format!("exit_{}", status.code().unwrap_or(-1)),
                                    "stderr": String::from_utf8_lossy(&o.stderr).chars().take(512).collect::<String>(),
                                    "cleanup_ok": true
                                });
                            }
                            Err(_) => return json!({"ok": false, "error": "wait_failed", "cleanup_ok": false}),
                        }
                    }
                    Ok(None) => {
                        if std::time::Instant::now() >= deadline {
                            let _ = child.kill();
                            let reaped = child.wait().is_ok();
                            return json!({"ok": false, "error": "timeout", "cleanup_ok": reaped});
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(_) => {
                        let _ = child.kill();
                        let reaped = child.wait().is_ok();
                        return json!({"ok": false, "error": "wait_error", "cleanup_ok": reaped});
                    }
                }
            }
        }
        ProfileAdapter::Http {
            url,
            method,
            timeout_secs,
            gpu_uuid,
            bearer_file,
        } => {
            let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST);
            let mut builder = rt
                .http
                .request(m, url)
                .timeout(Duration::from_secs(req.timeout_secs.min(*timeout_secs).clamp(1, 300)))
                .json(&req.input);
            if let Some(bf) = bearer_file {
                if let Ok(tok) = fs::read_to_string(bf) {
                    let t = tok.trim();
                    if !t.is_empty() {
                        builder = builder.header("authorization", format!("Bearer {t}"));
                    }
                }
            }
            let resp = builder.send();
            match resp {
                Ok(r) if r.status().is_success() => {
                    let text = r.text().unwrap_or_default();
                    let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"body": text}));
                    json!({
                        "ok": true,
                        "worker_id": rt.cfg.worker_id,
                        "gpu_uuid": req.gpu_uuid.as_ref().or(gpu_uuid.as_ref()),
                        "output": parsed,
                        "cleanup_ok": true
                    })
                }
                Ok(r) => json!({"ok": false, "error": format!("upstream_http_{}", r.status().as_u16()), "cleanup_ok": true}),
                Err(_) => json!({"ok": false, "error": "upstream_unreachable", "cleanup_ok": true}),
            }
        }
    }
}

pub(super) fn run_fleet_worker(cfg_path: &Path) -> i32 {
    if let Err(err) = run_fleet_worker_inner(cfg_path) {
        eprintln!("fleet_worker_error: {err}");
        return 70;
    }
    0
}

fn run_fleet_worker_inner(cfg_path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(cfg_path).map_err(|e| format!("read:{e}"))?;
    let cfg: FleetWorkerConfig = serde_json::from_str(&raw).map_err(|e| format!("parse:{e}"))?;
    let bind_addr: SocketAddr = cfg.bind.parse().map_err(|e| format!("bind:{e}"))?;
    let advertise_url = fleet_base_url(&cfg.advertise_url).ok_or("invalid_advertise_url")?;
    let controller_url = fleet_base_url(&cfg.controller_url).ok_or("invalid_controller_url")?;
    // A fresh session on every start invalidates requests from before a crash.
    let rpc_session = random_id().map_err(|_| "rpc_session_entropy_unavailable")?;

    let gpus = if cfg.auto_detect_gpus {
        detect_local_gpus()
    } else {
        Vec::new()
    };
    let detected_vram: u64 = gpus.iter().map(|g| g.vram_bytes).sum();
    let vram_total = cfg.vram_bytes.max(detected_vram);

    let caps: Vec<CapabilityInfo> = cfg
        .profiles
        .iter()
        .map(|p| {
            let (kind, gpu_uuid) = match &p.adapter {
                ProfileAdapter::Exec { gpu_uuid, .. } => ("exec".to_string(), gpu_uuid.clone()),
                ProfileAdapter::Http { gpu_uuid, .. } => ("http".to_string(), gpu_uuid.clone()),
            };
            CapabilityInfo {
                capability: p.capability.clone(),
                kind,
                gpu_uuid: gpu_uuid.or_else(|| gpus.first().map(|g| g.uuid.clone())),
                description: p.description.clone(),
            }
        })
        .collect();

    let http = private_http_client()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("http:{e}"))?;

    // Enroll + background heartbeat thread
    let enroll_url = fleet_endpoint(&controller_url, "/v1/fleet/workers/enroll");
    let mut hb_url = fleet_endpoint(&controller_url, "/v1/fleet/workers");
    hb_url.path_segments_mut().unwrap().push(&cfg.worker_id).push("heartbeat");
    let enroll_body = json!({
        "worker_id": cfg.worker_id,
        "host": cfg.host,
        "rpc_url": advertise_url.as_str(),
        "rpc_secret_hex": cfg.rpc_secret_hex,
        "rpc_session": rpc_session,
        "cpu_millicores": cfg.cpu_millicores,
        "ram_bytes": cfg.ram_bytes,
        "vram_bytes": vram_total,
        "gpus": gpus,
        "capabilities": caps
    });
    let bearer = cfg.enroll_bearer.clone();
    let hb_http = http.clone();
    std::thread::spawn(move || loop {
        let _ = hb_http
            .post(enroll_url.clone())
            .header("authorization", format!("Bearer {bearer}"))
            .json(&enroll_body)
            .send();
        for _ in 0..6 {
            std::thread::sleep(Duration::from_secs(10));
            let _ = hb_http
                .post(hb_url.clone())
                .header("authorization", format!("Bearer {bearer}"))
                .json(&json!({}))
                .send();
        }
    });

    let runtime = Arc::new(WorkerRuntime {
        cfg,
        http,
        rpc_session,
        replay: Mutex::default(),
        clock: now_ms,
    });
    let app = Router::new()
        .route("/v1/fleet-worker/run", post(handle_worker_run))
        .with_state(runtime);

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio:{e}"))?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("bind:{e}"))?;
        eprintln!("fleet_worker_ready bind={bind_addr}");
        axum::serve(listener, app)
            .await
            .map_err(|e| format!("serve:{e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn worker(clock: fn() -> u64) -> Arc<WorkerRuntime> {
        let cfg = serde_json::from_value(json!({
            "worker_id": "worker", "host": "fixture", "bind": "127.0.0.1:0",
            "advertise_url": "http://127.0.0.1", "controller_url": "http://127.0.0.1",
            "enroll_bearer": "fixture", "rpc_secret_hex": SECRET, "auto_detect_gpus": false,
            "profiles": [{"capability":"fixture","adapter":{"kind":"exec","command":["/bin/cat"]}}]
        }))
        .unwrap();
        Arc::new(WorkerRuntime {
            cfg,
            http: private_http_client()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            rpc_session: SESSION.into(),
            replay: Mutex::default(),
            clock,
        })
    }

    fn signed_request(payload: &Value) -> (HeaderMap, Bytes) {
        let body = serde_json::to_vec(payload).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-diffuser-signature",
            sign_rpc(SECRET, &body).parse().unwrap(),
        );
        (headers, body.into())
    }

    #[test]
    fn worker_accepts_only_one_fresh_request_for_its_session() {
        const NOW: u64 = 120_000;
        let worker = worker(|| NOW);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut payload = json!({
                "job_id": "fjob_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "rpc_session": SESSION, "issued_at_ms": NOW, "capability": "fixture",
                "input": {"echo": "fixture"}
            });

            let (headers, _) = signed_request(&payload);
            payload["issued_at_ms"] = json!(NOW + 1);
            let (_, changed) = signed_request(&payload);
            assert_eq!(
                handle_worker_run(State(worker.clone()), headers, changed)
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );

            for (session, timestamp) in [
                (SESSION, NOW - RPC_MAX_AGE_MS - 1),
                (SESSION, NOW + RPC_FUTURE_SKEW_MS + 1),
                ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NOW),
            ] {
                payload["rpc_session"] = json!(session);
                payload["issued_at_ms"] = json!(timestamp);
                let (headers, body) = signed_request(&payload);
                assert_eq!(
                    handle_worker_run(State(worker.clone()), headers, body)
                        .await
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
            }
            assert!(worker.replay.lock().unwrap().seen.is_empty());

            payload["rpc_session"] = json!(SESSION);
            payload["issued_at_ms"] = json!(NOW);
            let (headers, body) = signed_request(&payload);
            let (first, second) = tokio::join!(
                handle_worker_run(State(worker.clone()), headers.clone(), body.clone()),
                handle_worker_run(State(worker.clone()), headers, body),
            );
            let (accepted, denied) = if first.status() == StatusCode::OK {
                (first, second)
            } else {
                (second, first)
            };
            assert_eq!(accepted.status(), StatusCode::OK);
            assert_eq!(denied.status(), StatusCode::CONFLICT);
            let body = axum::body::to_bytes(accepted.into_body(), 1024)
                .await
                .unwrap();
            let reply: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(reply["output"], payload["input"]);

            payload["job_id"] = json!("fjob_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            let (headers, body) = signed_request(&payload);
            assert_eq!(
                handle_worker_run(State(worker.clone()), headers, body)
                    .await
                    .status(),
                StatusCode::OK
            );
        });
    }

    #[test]
    fn nonce_window_fails_closed_at_capacity_and_after_clock_rollback() {
        const NOW: u64 = 120_000;
        let mut window = ReplayWindow::default();
        for job in 0..MAX_RPC_NONCES {
            assert_eq!(window.consume(&job.to_string(), NOW, NOW), Ok(()));
        }
        let expiry = NOW + RPC_MAX_AGE_MS;
        assert_eq!(window.consume("0", NOW, expiry), Err("rpc_replayed"));
        assert_eq!(
            window.consume("next", expiry, expiry),
            Err("rpc_replay_cache_full")
        );
        assert_eq!(window.consume("next", expiry + 1, expiry + 1), Ok(()));
        assert_eq!(window.consume("0", NOW, NOW), Err("rpc_timestamp_invalid"));
    }

    #[test]
    fn enrollment_and_dispatch_enforce_url_policy_and_rpc_session() {
        let root = std::env::temp_dir().join(format!("fleet-rpc-{}", std::process::id()));
        crate::private_state::fixture_dir(&root);
        let config = root.join("controller.json");
        fs::write(
            &config,
            json!({"admin_token_sha256":sha256_hex(b"fixture")}).to_string(),
        )
        .unwrap();
        let state = FleetState::open(&config, &root).unwrap();
        let worker = worker(now_ms);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (address, server) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new()
                .route("/v1/fleet-worker/run", post(handle_worker_run))
                .with_state(worker.clone());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (address, server)
        });

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer fixture".parse().unwrap());
        let mut enroll = json!({
            "worker_id": "worker", "host": "fixture", "rpc_secret_hex": SECRET, "rpc_session": SESSION,
            "cpu_millicores": 1000, "ram_bytes": 500000000, "vram_bytes": 0,
            "capabilities": [{"capability": "fixture", "kind": "exec"}]
        });
        for (url, expected) in [
            ("http://worker.example", StatusCode::UNPROCESSABLE_ENTITY),
            ("https://worker.example", StatusCode::OK),
            (&format!("http://{address}"), StatusCode::OK),
        ] {
            enroll["rpc_url"] = json!(url);
            let request = serde_json::from_value(enroll.clone()).unwrap();
            assert_eq!(
                runtime
                    .block_on(handle_enroll(
                        State(state.clone()),
                        headers.clone(),
                        Json(request)
                    ))
                    .status(),
                expected
            );
        }
        let auth = state.authenticate(&headers).unwrap();
        let request =
            serde_json::from_value(json!({"capability":"fixture","input":{"echo":"test"}}))
                .unwrap();

        for (url, session) in [
            ("http://worker.example".to_owned(), Some(SESSION)),
            (format!("http://{address}"), None),
        ] {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE fleet_workers SET rpc_url=?1, rpc_session=?2",
                params![url, session],
            )
            .unwrap();
            drop(db);
            assert_eq!(
                submit_job_inner(&state, &auth, "fixture", &request)
                    .unwrap_err()
                    .1,
                "capability_unavailable"
            );
        }
        let db = state.db.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM fleet_jobs", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        db.execute("UPDATE fleet_workers SET rpc_session=?1", [SESSION])
            .unwrap();
        drop(db);
        let (_, reply) = submit_job_inner(&state, &auth, "fixture", &request).unwrap();
        assert_eq!(reply["state"], "succeeded");
        assert_eq!(reply["output"], request.input);
        assert_eq!(reply["capacity_released"], true);
        assert_eq!(
            submit_job_inner(&state, &auth, "fixture", &request)
                .unwrap()
                .1["idempotent_replay"],
            true
        );

        server.abort();
        drop(runtime);
        drop(worker);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rpc_session_migration_preserves_existing_records_and_is_idempotent() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE fleet_workers(worker_id TEXT); INSERT INTO fleet_workers VALUES ('old');",
        )
        .unwrap();
        add_rpc_session_column(&mut db).unwrap();
        add_rpc_session_column(&mut db).unwrap();
        let old: Option<String> = db
            .query_row(
                "SELECT rpc_session FROM fleet_workers WHERE worker_id='old'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old, None);
    }
}
