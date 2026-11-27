//! Diffuser v1.0 Scalable Multi-Worker Fleet Router, Pluggable Workload Runner & MCP Surface.
//!
//! Mounted under `/v1/fleet/*` on `uai-diffuser` when `--fleet-config <path>` is supplied.
//! When `--fleet-config` is omitted, `/v1/fleet/*` fails closed with `503 fleet_closed`.

use axum::{
    body::{Body, Bytes},
    extract::{
        rejection::{JsonRejection, QueryRejection},
        DefaultBodyLimit, FromRequest, Path as AxPath, Query, Request, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use lane_router::transport::{private_http_client, private_http_url};
use reqwest::Url;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, TransactionBehavior};
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
const MAX_DRAIN_BODY_BYTES: usize = 4 * 1024;
const NO_STORE: [(header::HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];
const FLEET_UI_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
const MAX_RPC_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const RPC_MAX_AGE_MS: u64 = 60_000;
const RPC_FUTURE_SKEW_MS: u64 = 5_000;
const MAX_RPC_NONCES: usize = 8192;
/// Six hours, matching the colab-train wall.
const MAX_JOB_TIMEOUT_SECS: u64 = 21_600;
/// Extra controller wait so a worker can return its cleanup result.
const RPC_CLEANUP_BUFFER_SECS: u64 = 60;
/// Caller-supplied CPU below this floor is still charged, so a zero request cannot schedule for free.
const MIN_JOB_CPU_MILLICORES: u64 = 100;
/// Caller-supplied RAM below this floor is still charged, so a zero request cannot schedule for free.
const MIN_JOB_RAM_BYTES: u64 = 64 * 1024 * 1024;
/// Running jobs allowed for one actor and project. Enforced inside the reservation transaction.
const MAX_INFLIGHT_PER_ACTOR_PROJECT: i64 = 16;
const FINISH_ATTEMPTS: u32 = 3;
/// Unpinned jobs skip a worker at or above this live utilization.
/// That covers an external process holding the GPU, including when diffuser itself has reserved no VRAM.
const EXTERNAL_GPU_BUSY_PCT: i64 = 85;
const NVIDIA_SMI_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct GpuInfo {
    pub(super) uuid: String,
    pub(super) name: String,
    pub(super) vram_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct LiveGpuSample {
    uuid: String,
    memory_free_bytes: u64,
    memory_total_bytes: u64,
    util_pct: u64,
}

struct LiveGpuTelemetry {
    free_bytes: u64,
    util_pct: u64,
    gpus: Vec<LiveGpuSample>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct CapabilityInfo {
    pub(super) capability: String,
    pub(super) kind: String,
    #[serde(default)]
    pub(super) gpu_uuid: Option<String>,
    #[serde(default)]
    pub(super) description: String,
    /// Profile execution budget advertised by the worker. Omitted values stay at 60 seconds.
    #[serde(default = "default_timeout_secs")]
    pub(super) timeout_secs: u64,
}

#[derive(Clone, Deserialize)]
pub(super) struct FleetControllerConfig {
    pub(super) admin_token_sha256: String,
    #[serde(default)]
    pub(super) db_path: Option<String>,
    /// Exact additional browser origins permitted to use the MCP endpoint.
    #[serde(default)]
    mcp_allowed_origins: Vec<String>,
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

fn bounded_timeout_secs(secs: u64) -> u64 {
    secs.clamp(1, MAX_JOB_TIMEOUT_SECS)
}

/// Controller HTTP deadline for one worker RPC.
/// The matched profile budget is the floor. A longer caller budget is covered too.
/// Both sit well above the old fixed 120 second client ceiling.
fn rpc_http_timeout(profile_timeout_secs: u64) -> Duration {
    Duration::from_secs(
        bounded_timeout_secs(profile_timeout_secs).saturating_add(RPC_CLEANUP_BUFFER_SECS),
    )
}

/// Worker subprocess and upstream HTTP budget.
/// An omitted caller budget uses the configured profile timeout.
fn effective_exec_timeout_secs(requested: Option<u64>, profile: u64) -> u64 {
    let profile = bounded_timeout_secs(profile);
    match requested {
        Some(secs) => bounded_timeout_secs(secs).min(profile),
        None => profile,
    }
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

fn effective_vram_bytes(accounting_free: i64, live_free: Option<i64>) -> u64 {
    let accounting = accounting_free.max(0) as u64;
    match live_free {
        Some(live) if live >= 0 => accounting.min(live as u64),
        _ => accounting,
    }
}

/// Reported free bytes cannot exceed `vram_total - vram_used` on that card.
fn clamped_live_free_bytes(memory_free_bytes: u64, memory_total_bytes: u64) -> u64 {
    let visible_free = memory_free_bytes.min(memory_total_bytes);
    let used = memory_total_bytes.saturating_sub(visible_free);
    memory_free_bytes.min(memory_total_bytes.saturating_sub(used))
}

enum PinnedLiveFree {
    /// This worker did not report a per-GPU sample list.
    NoReport,
    /// Per-GPU samples exist, and the pinned UUID is not among them.
    Missing,
    /// Clamped live free bytes for the pinned UUID.
    Free(u64),
}

fn pinned_gpu_live_free(raw: Option<&str>, enrolled: &[GpuInfo], pin: &str) -> PinnedLiveFree {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return PinnedLiveFree::NoReport;
    };
    let Ok(samples) = serde_json::from_str::<Vec<LiveGpuSample>>(raw) else {
        return PinnedLiveFree::NoReport;
    };
    if samples.is_empty() {
        return PinnedLiveFree::NoReport;
    }
    let Some(sample) = samples.iter().find(|gpu| gpu.uuid == pin) else {
        return PinnedLiveFree::Missing;
    };
    let total = enrolled
        .iter()
        .find(|gpu| gpu.uuid == pin)
        .map(|gpu| gpu.vram_bytes)
        .filter(|bytes| *bytes > 0)
        .map(|bytes| sample.memory_total_bytes.min(bytes))
        .unwrap_or(sample.memory_total_bytes);
    PinnedLiveFree::Free(clamped_live_free_bytes(sample.memory_free_bytes, total))
}

fn live_free_i64(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}

fn external_gpu_busy(util: Option<i64>) -> bool {
    util.is_some_and(|pct| (0..=100).contains(&pct) && pct >= EXTERNAL_GPU_BUSY_PCT)
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
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn fleet_base_url(raw: &str) -> Option<Url> {
    Url::parse(raw)
        .ok()
        .filter(|url| private_http_url(url) && url.query().is_none() && url.fragment().is_none())
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

fn add_live_gpu_columns(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (name, ddl) in [
        (
            "live_vram_free_bytes",
            "ALTER TABLE fleet_workers ADD COLUMN live_vram_free_bytes INTEGER",
        ),
        (
            "gpu_util_pct",
            "ALTER TABLE fleet_workers ADD COLUMN gpu_util_pct INTEGER",
        ),
        (
            "gpus_live_json",
            "ALTER TABLE fleet_workers ADD COLUMN gpus_live_json TEXT",
        ),
    ] {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('fleet_workers') WHERE name=?1)",
            [name],
            |row| row.get(0),
        )?;
        if !exists {
            tx.execute(ddl, [])?;
        }
    }
    tx.commit()
}

fn add_capacity_released_column(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('fleet_jobs') WHERE name='capacity_released')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        tx.execute(
            "ALTER TABLE fleet_jobs ADD COLUMN capacity_released INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    tx.commit()
}

fn add_operator_drained_column(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('fleet_workers') WHERE name='operator_drained')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        tx.execute_batch(
            "ALTER TABLE fleet_workers ADD COLUMN operator_drained INTEGER NOT NULL DEFAULT 0 CHECK (operator_drained IN (0,1));
             UPDATE fleet_workers SET operator_drained=1 WHERE status='draining';",
        )?;
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

type FleetResult<T> = Result<T, (StatusCode, &'static str)>;
const STORAGE_UNAVAILABLE: (StatusCode, &str) =
    (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable");

fn invalid_request(message: &str) -> Response {
    err_resp(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", message)
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
    mcp_allowed_origins: Vec<String>,
    http: reqwest::blocking::Client,
    artifacts_dir: PathBuf,
}

#[derive(Clone)]
pub(super) struct FleetHealth {
    db: Arc<Mutex<Connection>>,
}

impl FleetHealth {
    pub(super) fn summary(&self) -> Value {
        let Ok(conn) = self.db.lock() else {
            return json!({
                "enabled": true,
                "fleet_dispatch_allowed": false,
                "workers_total": 0,
                "workers_active": 0,
                "workers_draining": 0,
                "workers_quarantined": 0,
                "workers_offline": 0,
                "capabilities_count": 0,
                "error": "storage_unavailable"
            });
        };
        let mut stmt = match conn
            .prepare("SELECT status, last_heartbeat_ms, capabilities_json FROM fleet_workers")
        {
            Ok(stmt) => stmt,
            Err(_) => {
                return json!({
                    "enabled": true,
                    "fleet_dispatch_allowed": false,
                    "workers_total": 0,
                    "workers_active": 0,
                    "workers_draining": 0,
                    "workers_quarantined": 0,
                    "workers_offline": 0,
                    "capabilities_count": 0,
                    "error": "storage_unavailable"
                });
            }
        };
        let now = now_ms();
        let mut workers_total: u64 = 0;
        let mut workers_active: u64 = 0;
        let mut workers_draining: u64 = 0;
        let mut workers_quarantined: u64 = 0;
        let mut workers_offline: u64 = 0;
        let mut capabilities: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();

        if let Ok(rows) = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        }) {
            for row in rows.flatten() {
                let (status, hb, caps_s) = row;
                workers_total += 1;
                let alive = now.saturating_sub(hb as u64) <= HEARTBEAT_TTL_MS;
                if !alive {
                    workers_offline += 1;
                    continue;
                }
                match status.as_str() {
                    "active" => {
                        workers_active += 1;
                        if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&caps_s) {
                            for item in items {
                                if let Some(name) = item.get("capability").and_then(Value::as_str) {
                                    if !name.is_empty() {
                                        capabilities.insert(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                    "draining" => workers_draining += 1,
                    "quarantined" => workers_quarantined += 1,
                    _ => workers_offline += 1,
                }
            }
        }

        json!({
            "enabled": true,
            "fleet_dispatch_allowed": workers_active > 0,
            "workers_total": workers_total,
            "workers_active": workers_active,
            "workers_draining": workers_draining,
            "workers_quarantined": workers_quarantined,
            "workers_offline": workers_offline,
            "capabilities_count": capabilities.len()
        })
    }
}

pub(super) fn closed_health_summary() -> Value {
    json!({
        "enabled": false,
        "fleet_dispatch_allowed": false,
        "workers_total": 0,
        "workers_active": 0,
        "workers_draining": 0,
        "workers_quarantined": 0,
        "workers_offline": 0,
        "capabilities_count": 0
    })
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
                 last_heartbeat_ms INTEGER NOT NULL,
                 live_vram_free_bytes INTEGER,
                 gpu_util_pct INTEGER,
                 gpus_live_json TEXT
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
                 capacity_released INTEGER NOT NULL DEFAULT 0,
                 created_at_ms INTEGER NOT NULL,
                 updated_at_ms INTEGER NOT NULL,
                 UNIQUE(actor, project, idempotency_key)
             );
             CREATE INDEX IF NOT EXISTS fleet_jobs_created_idx
                 ON fleet_jobs (created_at_ms DESC, job_id DESC);
             CREATE INDEX IF NOT EXISTS fleet_jobs_scope_created_idx
                 ON fleet_jobs (actor, project, created_at_ms DESC, job_id DESC);
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
        add_capacity_released_column(&mut conn).map_err(|e| format!("fleet_schema:{e}"))?;
        add_live_gpu_columns(&mut conn).map_err(|e| format!("fleet_schema:{e}"))?;
        add_operator_drained_column(&mut conn).map_err(|e| format!("fleet_schema:{e}"))?;

        let http = private_http_client()
            .timeout(rpc_http_timeout(MAX_JOB_TIMEOUT_SECS))
            .build()
            .map_err(|e| format!("fleet_http:{e}"))?;

        let artifacts_dir = state_dir.join("fleet-artifacts");
        fs::create_dir_all(&artifacts_dir).map_err(|e| format!("fleet_artifacts_mkdir:{e}"))?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            admin_sha256: admin_sha,
            mcp_allowed_origins: cfg.mcp_allowed_origins,
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
        .route("/tokens", get(closed).post(closed))
        .route("/tokens/{token_id}/revoke", post(closed))
        .route("/jobs", get(closed).post(closed))
        .route("/jobs/{job_id}", get(closed))
        .route("/ui", get(closed))
        .route("/ui/", get(closed))
        .route("/artifacts", post(closed))
        .route("/artifacts/{artifact_id}", get(closed))
        .route("/artifacts/{artifact_id}/content", get(closed))
        .route("/mcp", post(closed).get(closed).delete(closed))
}

pub(super) fn router(cfg_path: &Path, state_dir: &Path) -> Result<Router<super::Spine>, String> {
    router_with_health(cfg_path, state_dir).map(|(router, _)| router)
}

pub(super) fn router_with_health(
    cfg_path: &Path,
    state_dir: &Path,
) -> Result<(Router<super::Spine>, FleetHealth), String> {
    let state = FleetState::open(cfg_path, state_dir)?;
    let health = FleetHealth {
        db: Arc::clone(&state.db),
    };
    let router = Router::new()
        .route("/discover", get(handle_discover))
        .route("/workers", get(handle_list_workers))
        .route("/workers/enroll", post(handle_enroll))
        .route("/workers/{worker_id}/heartbeat", post(handle_heartbeat))
        .route(
            "/workers/{worker_id}/drain",
            post(handle_drain).layer(DefaultBodyLimit::max(MAX_DRAIN_BODY_BYTES)),
        )
        .route("/tokens", get(handle_list_tokens).post(handle_issue_token))
        .route("/tokens/{token_id}/revoke", post(handle_revoke_token))
        .route("/jobs", get(handle_list_jobs).post(handle_submit_job))
        .route("/jobs/{job_id}", get(handle_get_job))
        .route("/ui", get(handle_ui))
        .route("/ui/", get(handle_ui_redirect))
        .route(
            "/artifacts",
            post(handle_upload_artifact)
                .layer(axum::extract::DefaultBodyLimit::max(MAX_ARTIFACT_BYTES)),
        )
        .route(
            "/artifacts/{artifact_id}",
            get(handle_get_artifact_manifest),
        )
        .route(
            "/artifacts/{artifact_id}/content",
            get(handle_get_artifact_content),
        )
        .route(
            "/mcp",
            post(handle_mcp)
                .get(handle_mcp_unsupported)
                .delete(handle_mcp_unsupported),
        )
        .with_state(state);
    Ok((router, health))
}

async fn handle_ui() -> Response {
    (
        [
            (header::CONTENT_SECURITY_POLICY, FLEET_UI_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(include_str!("fleet_ui.html")),
    )
        .into_response()
}

async fn handle_ui_redirect() -> Response {
    (
        StatusCode::PERMANENT_REDIRECT,
        [
            (header::LOCATION, "/v1/fleet/ui"),
            (header::CACHE_CONTROL, "no-store"),
        ],
    )
        .into_response()
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
        return err_resp(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "admin bearer required",
        );
    }
    let Some(rpc_url) = fleet_base_url(&req.rpc_url) else {
        return err_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "invalid RPC URL",
        );
    };
    if req.worker_id.trim().is_empty()
        || req.rpc_secret_hex.len() < 32
        || !is_random_id(&req.rpc_session)
    {
        return err_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "invalid worker_id, rpc_secret_hex, or rpc_session",
        );
    }
    let gpus_json = serde_json::to_string(&req.gpus).unwrap_or_else(|_| "[]".into());
    let caps_json = serde_json::to_string(&req.capabilities).unwrap_or_else(|_| "[]".into());
    let ts = now_ms() as i64;
    let Ok(conn) = state.db.lock() else {
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "db lock failed",
        );
    };
    let status = conn.query_row(
        "INSERT INTO fleet_workers (worker_id, host, rpc_url, rpc_secret_hex, cpu_total, ram_total, vram_total, cpu_reserved, ram_reserved, vram_reserved, gpus_json, capabilities_json, status, last_heartbeat_ms, rpc_session)
         VALUES (?1,?2,?3,?4,?5,?6,?7,0,0,0,?8,?9,'active',?10,?11)
         ON CONFLICT(worker_id) DO UPDATE SET
           host=excluded.host,
           rpc_url=excluded.rpc_url,
           rpc_secret_hex=?4,
           rpc_session=excluded.rpc_session,
           cpu_total=excluded.cpu_total,
           ram_total=excluded.ram_total,
           vram_total=excluded.vram_total,
           gpus_json=excluded.gpus_json,
           capabilities_json=excluded.capabilities_json,
           status=CASE
               WHEN fleet_workers.status='quarantined' AND fleet_workers.rpc_session=excluded.rpc_session THEN 'quarantined'
               WHEN fleet_workers.operator_drained=1 THEN 'draining' ELSE 'active' END,
           cpu_reserved=CASE
               WHEN fleet_workers.status='quarantined' AND fleet_workers.rpc_session=excluded.rpc_session
                 OR EXISTS(SELECT 1 FROM fleet_jobs WHERE worker_id=excluded.worker_id AND state='running')
               THEN fleet_workers.cpu_reserved ELSE 0 END,
           ram_reserved=CASE
               WHEN fleet_workers.status='quarantined' AND fleet_workers.rpc_session=excluded.rpc_session
                 OR EXISTS(SELECT 1 FROM fleet_jobs WHERE worker_id=excluded.worker_id AND state='running')
               THEN fleet_workers.ram_reserved ELSE 0 END,
           vram_reserved=CASE
               WHEN fleet_workers.status='quarantined' AND fleet_workers.rpc_session=excluded.rpc_session
                 OR EXISTS(SELECT 1 FROM fleet_jobs WHERE worker_id=excluded.worker_id AND state='running')
               THEN fleet_workers.vram_reserved ELSE 0 END,
           last_heartbeat_ms=excluded.last_heartbeat_ms
         RETURNING status",
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
        |row| row.get::<_, String>(0),
    );
    let Ok(status) = status else {
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "enroll write failed",
        );
    };
    Json(json!({
        "schema_version": "diffuser-fleet/v1",
        "enrolled": true,
        "worker_id": req.worker_id,
        "status": status,
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
    /// Absent on older workers. Present null clears the last sample.
    #[serde(default)]
    live_vram_free_bytes: Option<i64>,
    #[serde(default)]
    gpu_util_pct: Option<i64>,
}

async fn handle_heartbeat(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(worker_id): AxPath<String>,
    Json(body): Json<Value>,
) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "admin bearer required",
        );
    }
    let req: HeartbeatRequest = match serde_json::from_value(body.clone()) {
        Ok(req) => req,
        Err(_) => {
            return err_resp(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_request",
                "invalid heartbeat",
            )
        }
    };
    let ts = now_ms() as i64;
    let update_inventory = req.gpus.is_some() && req.capabilities.is_some();
    let gpus_json = req
        .gpus
        .as_ref()
        .map(|gpus| serde_json::to_string(gpus).unwrap_or_else(|_| "[]".into()));
    let caps_json = req
        .capabilities
        .as_ref()
        .map(|caps| serde_json::to_string(caps).unwrap_or_else(|_| "[]".into()));
    // Key presence matters. Older workers omit these fields and must not wipe a newer sample,
    // while an explicit null means this probe failed and accounting VRAM should be used again.
    let set_live = body.get("live_vram_free_bytes").is_some();
    let live_val = req.live_vram_free_bytes.filter(|v| *v >= 0);
    let set_util = body.get("gpu_util_pct").is_some();
    let util_val = req.gpu_util_pct.filter(|v| (0..=100).contains(v));
    // Per-GPU detail is always tied to the latest heartbeat; omitting gpus_live clears any
    // prior per-GPU sample so an exact GPU pin cannot reuse stale VRAM data.
    let detail_json = match body.get("gpus_live") {
        Some(value) if !value.is_null() => {
            serde_json::from_value::<Vec<LiveGpuSample>>(value.clone())
                .ok()
                .and_then(|gpus| serde_json::to_string(&gpus).ok())
        }
        _ => None,
    };
    let Ok(conn) = state.db.lock() else {
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "db lock failed",
        );
    };
    let updated = conn.execute(
        "UPDATE fleet_workers SET
            last_heartbeat_ms=?1,
            gpus_json=CASE WHEN ?2=1 THEN ?3 ELSE gpus_json END,
            capabilities_json=CASE WHEN ?2=1 THEN ?4 ELSE capabilities_json END,
            live_vram_free_bytes=CASE WHEN ?5=1 THEN ?6 ELSE live_vram_free_bytes END,
            gpu_util_pct=CASE WHEN ?7=1 THEN ?8 ELSE gpu_util_pct END,
            gpus_live_json=?9
         WHERE worker_id=?10",
        params![
            ts,
            if update_inventory { 1 } else { 0 },
            gpus_json,
            caps_json,
            if set_live { 1 } else { 0 },
            live_val,
            if set_util { 1 } else { 0 },
            util_val,
            detail_json,
            worker_id,
        ],
    );
    match updated {
        Ok(0) => err_resp(
            StatusCode::NOT_FOUND,
            "worker_not_found",
            "unknown worker_id",
        ),
        Ok(_) => {
            Json(json!({"ok": true, "worker_id": worker_id, "heartbeat_ms": ts})).into_response()
        }
        Err(_) => err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "heartbeat write failed",
        ),
    }
}

async fn handle_drain(
    State(state): State<FleetState>,
    AxPath(worker_id): AxPath<String>,
    request: Request,
) -> Response {
    if !state.check_admin(request.headers()) {
        return err_resp(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "admin bearer required",
        );
    }
    let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = match Bytes::from_request(request, &()).await {
        Ok(bytes) => bytes,
        Err(error) if error.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return err_resp(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                "body exceeds 4 KiB",
            )
        }
        Err(_) => return invalid_request("unable to read body"),
    };
    let accepting = if bytes.is_empty() {
        false
    } else {
        let is_object = bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'{');
        let mut request = Request::new(Body::from(bytes));
        if let Some(content_type) = content_type {
            request
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
        }
        match Json::<DrainBody>::from_request(request, &()).await {
            Ok(Json(body)) if is_object => body.accepting,
            Err(JsonRejection::MissingJsonContentType(_)) => {
                return err_resp(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "invalid_request",
                    "JSON body required",
                );
            }
            _ => return invalid_request("invalid worker admission body"),
        }
    };
    match set_worker_accepting_inner(&state, &worker_id, accepting) {
        Ok(value) => Json(value).into_response(),
        Err((status, code)) => err_resp(status, code, "worker admission update failed"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainBody {
    #[serde(default)]
    accepting: bool,
}

fn set_worker_accepting_inner(
    state: &FleetState,
    worker_id: &str,
    accepting: bool,
) -> FleetResult<Value> {
    let mut conn = state.db.lock().map_err(|_| STORAGE_UNAVAILABLE)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| STORAGE_UNAVAILABLE)?;
    let status: Option<String> = tx
        .query_row(
            "SELECT status FROM fleet_workers WHERE worker_id=?1",
            [worker_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| STORAGE_UNAVAILABLE)?;
    let status = match (status.as_deref(), accepting) {
        (None, _) => return Err((StatusCode::NOT_FOUND, "worker_not_found")),
        (Some("quarantined"), true) => return Err((StatusCode::CONFLICT, "worker_quarantined")),
        (Some("quarantined"), false) => "quarantined",
        (Some(_), true) => "active",
        (Some(_), false) => "draining",
    };
    tx.execute(
        "UPDATE fleet_workers SET operator_drained=?1, status=?2 WHERE worker_id=?3",
        params![!accepting, status, worker_id],
    )
    .map_err(|_| STORAGE_UNAVAILABLE)?;
    tx.commit().map_err(|_| STORAGE_UNAVAILABLE)?;
    Ok(json!({"ok": true, "worker_id": worker_id, "status": status}))
}

fn worker_tier(worker_id: &str, vram_total: i64) -> &'static str {
    if vram_total <= 0 {
        "cpu_fallback"
    } else if worker_id.starts_with("colab")
        || worker_id.starts_with("columbus")
        || worker_id.starts_with("runpod")
    {
        "cloud_gpu"
    } else {
        "local_gpu"
    }
}

fn worker_tier_rank(worker_id: &str, vram_total: i64) -> u8 {
    match worker_tier(worker_id, vram_total) {
        "local_gpu" => 0,
        "cloud_gpu" => 1,
        _ => 2,
    }
}

fn list_workers_json(state: &FleetState) -> Result<Vec<Value>, &'static str> {
    let conn = state.db.lock().map_err(|_| "storage_unavailable")?;
    let mut stmt = conn
        .prepare(
            "SELECT worker_id, host, rpc_url, cpu_total, ram_total, vram_total,
                    cpu_reserved, ram_reserved, vram_reserved, gpus_json, capabilities_json,
                    status, last_heartbeat_ms, live_vram_free_bytes, gpu_util_pct, gpus_live_json
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
            let live_free: Option<i64> = r.get(13)?;
            let gpu_util: Option<i64> = r.get(14)?;
            let gpus_live_s: Option<String> = r.get(15)?;
            let alive = now.saturating_sub(hb as u64) <= HEARTBEAT_TTL_MS;
            let gpus: Value = serde_json::from_str(&gpus_s).unwrap_or(json!([]));
            let caps: Value = serde_json::from_str(&caps_s).unwrap_or(json!([]));
            let gpus_live: Value = gpus_live_s
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or(Value::Null);
            let accounting_vram = (vram_t - vram_r).max(0);
            Ok(json!({
                "worker_id": wid,
                "worker_tier": worker_tier(&wid, vram_t),
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
                "vram_free": accounting_vram,
                "live_vram_free": live_free,
                "gpu_util_pct": gpu_util,
                "gpus_live": gpus_live,
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
        return err_resp(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "admin bearer required",
        );
    }
    match list_workers_json(&state) {
        Ok(workers) => Json(json!({
            "schema_version": "diffuser-fleet/v1",
            "workers": workers
        }))
        .into_response(),
        Err(c) => err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            c,
            "failed to query workers",
        ),
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
                let accounting = w["vram_free"].as_i64().unwrap_or(0);
                let live = w["live_vram_free"].as_i64();
                caps_out.push(json!({
                    "capability": cap_name,
                    "worker_tier": w["worker_tier"],
                    "kind": c["kind"],
                    "description": c["description"],
                    "gpu_uuid": c["gpu_uuid"],
                    "timeout_secs": c["timeout_secs"].as_u64().map(bounded_timeout_secs).unwrap_or_else(default_timeout_secs),
                    "accepting": true,
                    "free_cpu_millicores": w["cpu_free"],
                    "free_ram_bytes": w["ram_free"],
                    "free_vram_bytes": effective_vram_bytes(accounting, live),
                    "live_vram_free": w["live_vram_free"],
                    "gpu_util_pct": w["gpu_util_pct"],
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
#[serde(default, deny_unknown_fields)]
struct TokenListFilters {
    limit: u16,
    include_revoked: bool,
}

impl Default for TokenListFilters {
    fn default() -> Self {
        Self {
            limit: 50,
            include_revoked: true,
        }
    }
}

impl TokenListFilters {
    fn is_valid(&self) -> bool {
        (1..=200).contains(&self.limit)
    }
}

#[derive(Serialize)]
struct TokenSummary {
    token_id: String,
    actor: String,
    project: String,
    allowed_capabilities: Vec<String>,
    max_vram_bytes: u64,
    created_at_ms: i64,
    expires_at_ms: u64,
    revoked: bool,
    expired: bool,
}

fn list_tokens_inner(state: &FleetState, filters: TokenListFilters) -> FleetResult<Value> {
    let conn = state.db.lock().map_err(|_| STORAGE_UNAVAILABLE)?;
    let mut stmt = conn
        .prepare(
            "SELECT token_id, actor, project, allowed_capabilities_json, max_vram_bytes,
                    created_at_ms, expires_at_ms, revoked
             FROM fleet_tokens WHERE (? OR revoked=0)
             ORDER BY created_at_ms DESC, token_id DESC LIMIT ?",
        )
        .map_err(|_| STORAGE_UNAVAILABLE)?;
    let now = now_ms();
    let tokens = stmt
        .query_map(params![filters.include_revoked, filters.limit], |row| {
            let caps_json: String = row.get(3)?;
            let expires_at_ms = row.get::<_, i64>(6)? as u64;
            Ok(TokenSummary {
                token_id: row.get(0)?,
                actor: row.get(1)?,
                project: row.get(2)?,
                allowed_capabilities: serde_json::from_str(&caps_json).unwrap_or_default(),
                max_vram_bytes: row.get::<_, i64>(4)?.max(0) as u64,
                created_at_ms: row.get(5)?,
                expires_at_ms,
                revoked: row.get::<_, i64>(7)? != 0,
                expired: now >= expires_at_ms,
            })
        })
        .map_err(|_| STORAGE_UNAVAILABLE)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| STORAGE_UNAVAILABLE)?;
    Ok(json!({"schema_version": 1, "tokens": tokens}))
}

async fn list_tokens(state: FleetState, filters: TokenListFilters) -> FleetResult<Value> {
    tokio::task::spawn_blocking(move || list_tokens_inner(&state, filters))
        .await
        .map_err(|_| STORAGE_UNAVAILABLE)?
}

async fn handle_list_tokens(
    State(state): State<FleetState>,
    headers: HeaderMap,
    query: Result<Query<TokenListFilters>, QueryRejection>,
) -> Response {
    if !state.check_admin(&headers) {
        return err_resp(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "admin bearer required",
        );
    }
    let Ok(Query(filters)) = query else {
        return invalid_request("invalid token list filters");
    };
    if !filters.is_valid() {
        return invalid_request("invalid token list filters");
    }
    match list_tokens(state, filters).await {
        Ok(value) => (NO_STORE, Json(value)).into_response(),
        Err((status, code)) => err_resp(status, code, "token list failed"),
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
    if req.actor.trim().is_empty()
        || req.project.trim().is_empty()
        || req.allowed_capabilities.is_empty()
    {
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
    let caps_json =
        serde_json::to_string(&req.allowed_capabilities).map_err(|_| "invalid_request")?;
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
        return err_resp(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "admin bearer required",
        );
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
        return err_resp(
            StatusCode::UNAUTHORIZED,
            "auth_required",
            "admin bearer required",
        );
    }
    match revoke_token_inner(&state, &token_id) {
        Ok(value) => Json(value).into_response(),
        Err((status, code)) => err_resp(status, code, "revoke failed"),
    }
}

fn revoke_token_inner(state: &FleetState, token_id: &str) -> FleetResult<Value> {
    let conn = state.db.lock().map_err(|_| STORAGE_UNAVAILABLE)?;
    let count = conn
        .execute(
            "UPDATE fleet_tokens SET revoked=1 WHERE token_id=?1",
            [token_id],
        )
        .map_err(|_| STORAGE_UNAVAILABLE)?;
    if count == 0 {
        return Err((StatusCode::NOT_FOUND, "token_not_found"));
    }
    Ok(json!({"ok": true, "token_id": token_id, "revoked": true}))
}

#[derive(Clone, Deserialize)]
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
    /// Omitted caller budgets use the matched worker profile timeout.
    #[serde(default)]
    timeout_secs: Option<u64>,
    /// Return after the job is reserved. The worker RPC continues in the background.
    #[serde(default, rename = "async")]
    run_async: bool,
}
fn default_job_cpu() -> u64 {
    500
}
fn default_job_ram() -> u64 {
    256 * 1024 * 1024
}

#[cfg(test)]
fn submit_job_inner(
    state: &FleetState,
    auth: &CallerAuth,
    idemp_key: &str,
    req: &SubmitJobRequest,
) -> Result<(StatusCode, Value), (StatusCode, &'static str, String)> {
    match prepare_job(state, auth, idemp_key, req)? {
        PrepareOutcome::Replay(value) => Ok((StatusCode::OK, value)),
        PrepareOutcome::Fresh(job) => {
            if req.run_async {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "async_runtime_required",
                    "async jobs are started by the fleet HTTP or MCP handler".into(),
                ));
            }
            let outcome = dispatch_worker(state, &job, req);
            let body = completed_reply(req, &job, &outcome, false);
            let _ = finish_job(state, &job, &outcome, false);
            Ok((StatusCode::OK, body))
        }
    }
}

async fn submit_job(
    state: FleetState,
    auth: CallerAuth,
    idemp_key: String,
    req: SubmitJobRequest,
) -> Result<(StatusCode, Value), (StatusCode, &'static str, String)> {
    let state_prep = state.clone();
    let auth_prep = auth.clone();
    let req_prep = req.clone();
    let idemp_prep = idemp_key.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        prepare_job(&state_prep, &auth_prep, &idemp_prep, &req_prep)
    })
    .await
    .map_err(|_| dispatch_panic_error())??;
    match prepared {
        PrepareOutcome::Replay(value) => Ok((StatusCode::OK, value)),
        PrepareOutcome::Fresh(job) => {
            // Sync and async both finalize on a detached task. The handler awaits
            // a oneshot only for synchronous jobs, so a dropped client cannot skip finish_job.
            let always_release = req.run_async;
            let rx = spawn_dispatch(state, job.clone(), req.clone(), always_release);
            if req.run_async {
                Ok((StatusCode::OK, running_reply(&req, &job)))
            } else {
                match rx.await {
                    Ok(result) => result,
                    Err(_) => Err(dispatch_panic_error()),
                }
            }
        }
    }
}

fn dispatch_panic_error() -> (StatusCode, &'static str, String) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "worker_dispatch_panicked",
        "internal dispatch error".to_string(),
    )
}

enum PrepareOutcome {
    Replay(Value),
    Fresh(FreshJob),
}

#[derive(Clone)]
struct FreshJob {
    job_id: String,
    worker_id: String,
    rpc_url: Url,
    rpc_secret: String,
    rpc_session: String,
    matched_gpu: Option<String>,
    profile_timeout_secs: u64,
    cpu_millicores: u64,
    ram_bytes: u64,
    min_vram_bytes: u64,
}

struct WorkerOutcome {
    state: &'static str,
    output: Value,
    output_sha256: Option<String>,
    error_code: Option<String>,
    cleanup_ok: bool,
}

fn panicked_outcome() -> WorkerOutcome {
    WorkerOutcome {
        state: "failed",
        output: Value::Null,
        output_sha256: None,
        error_code: Some("worker_dispatch_panicked".into()),
        cleanup_ok: false,
    }
}

fn persisted_state<'a>(outcome: &'a WorkerOutcome, always_release: bool) -> &'a str {
    if outcome.state == "succeeded" {
        "succeeded"
    } else if always_release {
        "failed"
    } else {
        outcome.state
    }
}

fn running_reply(req: &SubmitJobRequest, job: &FreshJob) -> Value {
    json!({
        "schema_version": "diffuser-fleet/v1",
        "job_id": job.job_id,
        "state": "running",
        "worker_id": job.worker_id,
        "capability": req.capability,
        "idempotent_replay": false,
        "capacity_released": false,
        "gpu_uuid": job.matched_gpu,
        "output": Value::Null,
        "output_sha256": Value::Null,
        "error_code": Value::Null
    })
}

fn completed_reply(
    req: &SubmitJobRequest,
    job: &FreshJob,
    outcome: &WorkerOutcome,
    always_release: bool,
) -> Value {
    json!({
        "schema_version": "diffuser-fleet/v1",
        "job_id": job.job_id,
        "worker_id": job.worker_id,
        "gpu_uuid": job.matched_gpu,
        "capability": req.capability,
        "state": persisted_state(outcome, always_release),
        "idempotent_replay": false,
        "capacity_released": always_release || outcome.cleanup_ok,
        "output": outcome.output,
        "output_sha256": outcome.output_sha256,
        "error_code": outcome.error_code
    })
}

fn prepare_job(
    state: &FleetState,
    auth: &CallerAuth,
    idemp_key: &str,
    req: &SubmitJobRequest,
) -> Result<PrepareOutcome, (StatusCode, &'static str, String)> {
    if idemp_key.trim().is_empty() || req.capability.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request",
            "missing capability or Idempotency-Key".into(),
        ));
    }
    if !FleetState::capability_allowed(auth, &req.capability) {
        return Err((
            StatusCode::FORBIDDEN,
            "capability_forbidden",
            "token does not allow this capability".into(),
        ));
    }
    if req.min_vram_bytes > auth.max_vram_bytes {
        return Err((
            StatusCode::FORBIDDEN,
            "vram_limit_exceeded",
            "requested VRAM exceeds token limit".into(),
        ));
    }

    let now = now_ms();
    let input_str = serde_json::to_string(&req.input).unwrap_or_else(|_| "{}".into());

    let mut conn = state.db.lock().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "db lock".into(),
        )
    })?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "tx begin".into(),
            )
        })?;

    let existing: Option<(String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, i64)> = tx
        .query_row(
            "SELECT job_id, worker_id, state, gpu_uuid, output_json, output_sha256, error_code, capacity_released
             FROM fleet_jobs WHERE actor=?1 AND project=?2 AND idempotency_key=?3",
            params![auth.actor, auth.project, idemp_key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
        )
        .optional()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "idemp query".into()))?;
    if let Some((jid, wid, st, gpu, out_j, out_sha, err_c, released)) = existing {
        let output: Value = out_j
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(Value::Null);
        return Ok(PrepareOutcome::Replay(json!({
            "schema_version": "diffuser-fleet/v1",
            "job_id": jid,
            "worker_id": wid,
            "gpu_uuid": gpu,
            "capability": req.capability,
            "state": st,
            "idempotent_replay": true,
            "capacity_released": released != 0,
            "output": output,
            "output_sha256": out_sha,
            "error_code": err_c
        })));
    }

    // Service-owned floors. A caller who omits resources or sends 0 still consumes capacity.
    let cpu_millicores = req.cpu_millicores.max(MIN_JOB_CPU_MILLICORES);
    let ram_bytes = req.ram_bytes.max(MIN_JOB_RAM_BYTES);

    let mut stmt = tx
        .prepare(
            "SELECT worker_id, rpc_url, rpc_secret_hex, cpu_total - cpu_reserved, ram_total - ram_reserved,
                    vram_total - vram_reserved, gpus_json, capabilities_json, last_heartbeat_ms, rpc_session,
                    live_vram_free_bytes, gpu_util_pct, gpus_live_json, vram_total
             FROM fleet_workers WHERE status='active' AND rpc_session IS NOT NULL",
        )
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "sched query".into()))?;

    let mut candidates: Vec<(
        String,
        String,
        String,
        i64,
        i64,
        i64,
        String,
        String,
        i64,
        String,
        Option<i64>,
        Option<i64>,
        Option<String>,
        i64,
    )> = stmt
        .query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
                r.get(9)?,
                r.get(10)?,
                r.get(11)?,
                r.get(12)?,
                r.get(13)?,
            ))
        })
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "sched map".into(),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "sched collect".into(),
            )
        })?;
    drop(stmt);
    candidates.sort_by(|a, b| {
        worker_tier_rank(&a.0, a.13)
            .cmp(&worker_tier_rank(&b.0, b.13))
            .then_with(|| b.5.cmp(&a.5))
            .then_with(|| a.0.cmp(&b.0))
    });

    let mut chosen = None;
    // True when a live capability match was rejected only by external utilization or live free VRAM.
    let mut blocked_by_live = false;
    for (
        wid,
        url,
        secret,
        f_cpu,
        f_ram,
        f_vram,
        gpus_s,
        caps_s,
        hb,
        session,
        live_free,
        gpu_util,
        gpus_live,
        _vram_total,
    ) in candidates
    {
        // Existing enrollments are also checked before any reservation or RPC.
        let Some(url) = fleet_base_url(&url) else {
            continue;
        };
        if !is_random_id(&session) || now.saturating_sub(hb as u64) > HEARTBEAT_TTL_MS {
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
        let Some(cap_entry) = matching_cap else {
            continue;
        };
        let cpu_ok = (f_cpu as u64) >= cpu_millicores;
        let ram_ok = (f_ram as u64) >= ram_bytes;
        let accounting_free = f_vram.max(0) as u64;
        if !cpu_ok || !ram_ok || accounting_free < req.min_vram_bytes {
            continue;
        }
        // An exact pin is admitted only on that GPU's own live free memory, never the host sum.
        let live_for_job = match req.pin_gpu_uuid.as_deref() {
            Some(pin) => match pinned_gpu_live_free(gpus_live.as_deref(), &gpus, pin) {
                PinnedLiveFree::Free(bytes) => Some(live_free_i64(bytes)),
                PinnedLiveFree::Missing | PinnedLiveFree::NoReport => Some(0),
            },
            None => live_free,
        };
        let effective = effective_vram_bytes(f_vram, live_for_job);
        if effective < req.min_vram_bytes {
            // Reserved capacity would allow the job, but the GPU does not have that much free right now.
            blocked_by_live = true;
            if req.pin_gpu_uuid.is_some() {
                // An exact UUID is never replaced with a different GPU.
                break;
            }
            continue;
        }
        if req.pin_gpu_uuid.is_none() && external_gpu_busy(gpu_util) {
            blocked_by_live = true;
            continue;
        }
        let gpu_sel = req
            .pin_gpu_uuid
            .clone()
            .or_else(|| cap_entry.gpu_uuid.clone())
            .or_else(|| gpus.first().map(|g| g.uuid.clone()));
        chosen = Some((
            wid,
            url,
            secret,
            session,
            gpu_sel,
            bounded_timeout_secs(cap_entry.timeout_secs),
        ));
        break;
    }

    let Some((wid, url, secret, session, gpu_sel, profile_timeout)) = chosen else {
        if blocked_by_live {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "capacity_exhausted",
                "all matching GPUs are externally saturated or lack live free VRAM".into(),
            ));
        }
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "capability_unavailable",
            "no live worker matches capability, resources, and GPU pin".into(),
        ));
    };

    let inflight: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM fleet_jobs WHERE actor=?1 AND project=?2 AND state='running'",
            params![auth.actor, auth.project],
            |row| row.get(0),
        )
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "inflight query".into(),
            )
        })?;
    if inflight >= MAX_INFLIGHT_PER_ACTOR_PROJECT {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "capacity_exhausted",
            "in-flight job limit reached for this actor and project".into(),
        ));
    }

    let nonce = random_id().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "entropy_unavailable",
            "job identity unavailable".into(),
        )
    })?;
    let jid = format!("fjob_{nonce}");

    tx.execute(
        "UPDATE fleet_workers SET cpu_reserved=cpu_reserved+?1, ram_reserved=ram_reserved+?2, vram_reserved=vram_reserved+?3 WHERE worker_id=?4",
        params![cpu_millicores as i64, ram_bytes as i64, req.min_vram_bytes as i64, wid],
    )
    .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "reserve failed".into()))?;

    tx.execute(
        "INSERT INTO fleet_jobs (job_id, idempotency_key, actor, project, capability, worker_id, gpu_uuid, state, input_json, capacity_released, created_at_ms, updated_at_ms)
         VALUES (?1,?2,?3,?4,?5,?6,?7,'running',?8,0,?9,?9)",
        params![jid, idemp_key, auth.actor, auth.project, req.capability, wid, gpu_sel, input_str, now as i64],
    )
    .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", "job insert failed".into()))?;

    tx.commit().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "tx commit".into(),
        )
    })?;

    Ok(PrepareOutcome::Fresh(FreshJob {
        job_id: jid,
        worker_id: wid,
        rpc_url: url,
        rpc_secret: secret,
        rpc_session: session,
        matched_gpu: gpu_sel,
        profile_timeout_secs: profile_timeout,
        cpu_millicores,
        ram_bytes,
        min_vram_bytes: req.min_vram_bytes,
    }))
}

fn dispatch_worker(state: &FleetState, job: &FreshJob, req: &SubmitJobRequest) -> WorkerOutcome {
    let profile = bounded_timeout_secs(job.profile_timeout_secs);
    let sent = match req.timeout_secs {
        Some(secs) => bounded_timeout_secs(secs),
        None => profile,
    };
    // issued_at_ms is stamped at dispatch. The worker checks freshness when the
    // RPC arrives, not when a long job later finishes.
    let rpc_payload = serde_json::to_vec(&json!({
        "job_id": job.job_id,
        "rpc_session": job.rpc_session,
        "issued_at_ms": now_ms(),
        "capability": req.capability,
        "gpu_uuid": job.matched_gpu,
        "input": req.input,
        "timeout_secs": sent
    }))
    .unwrap_or_default();
    let sig = sign_rpc(&job.rpc_secret, &rpc_payload);
    let worker_res = state
        .http
        .post(fleet_endpoint(&job.rpc_url, "/v1/fleet-worker/run"))
        .timeout(rpc_http_timeout(profile.max(sent)))
        .header("content-type", "application/json")
        .header("x-diffuser-signature", sig)
        .body(rpc_payload)
        .send();
    interpret_worker(worker_res)
}

fn interpret_worker(
    worker_res: Result<reqwest::blocking::Response, reqwest::Error>,
) -> WorkerOutcome {
    match worker_res {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>() {
            Ok(body) if body["ok"] == true => {
                let out = body["output"].clone();
                let out_bytes = serde_json::to_vec(&out).unwrap_or_default();
                let sha = sha256_hex(&out_bytes);
                let clean = body["cleanup_ok"].as_bool().unwrap_or(false);
                WorkerOutcome {
                    state: "succeeded",
                    output: out,
                    output_sha256: Some(sha),
                    error_code: None,
                    cleanup_ok: clean,
                }
            }
            Ok(body) => {
                let clean = body["cleanup_ok"].as_bool().unwrap_or(false);
                let code = body["error"]
                    .as_str()
                    .unwrap_or("worker_execution_failed")
                    .to_string();
                WorkerOutcome {
                    state: if clean { "failed" } else { "failed_uncertain" },
                    output: Value::Null,
                    output_sha256: None,
                    error_code: Some(code),
                    cleanup_ok: clean,
                }
            }
            Err(_) => WorkerOutcome {
                state: "failed_uncertain",
                output: Value::Null,
                output_sha256: None,
                error_code: Some("worker_invalid_reply".into()),
                cleanup_ok: false,
            },
        },
        Ok(resp) => WorkerOutcome {
            state: "failed_uncertain",
            output: Value::Null,
            output_sha256: None,
            error_code: Some(format!("worker_http_{}", resp.status().as_u16())),
            cleanup_ok: false,
        },
        Err(_) => WorkerOutcome {
            state: "failed_uncertain",
            output: Value::Null,
            output_sha256: None,
            error_code: Some("worker_unreachable".into()),
            cleanup_ok: false,
        },
    }
}

fn finish_job(
    state: &FleetState,
    job: &FreshJob,
    outcome: &WorkerOutcome,
    always_release: bool,
) -> Result<(), String> {
    let release = always_release || outcome.cleanup_ok;
    let final_state = persisted_state(outcome, always_release);
    let out_str = if outcome.output.is_null() {
        None
    } else {
        Some(serde_json::to_string(&outcome.output).unwrap_or_else(|_| "null".into()))
    };
    let done_ts = now_ms() as i64;
    let mut conn = state
        .db
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => {
            let msg = format!("tx begin job_id={} err={err}", job.job_id);
            eprintln!("fleet_finish_job: {msg}");
            return Err(msg);
        }
    };
    let updated = match tx.execute(
        "UPDATE fleet_jobs SET state=?1, output_json=?2, output_sha256=?3, error_code=?4, capacity_released=?5, updated_at_ms=?6
         WHERE job_id=?7 AND state='running'",
        params![
            final_state,
            out_str,
            outcome.output_sha256,
            outcome.error_code,
            if release { 1 } else { 0 },
            done_ts,
            job.job_id
        ],
    ) {
        Ok(updated) => updated,
        Err(err) => {
            let msg = format!("job update job_id={} err={err}", job.job_id);
            eprintln!("fleet_finish_job: {msg}");
            return Err(msg);
        }
    };
    if updated == 1 {
        let counter = if release {
            tx.execute(
                "UPDATE fleet_workers SET cpu_reserved=MAX(0, cpu_reserved-?1), ram_reserved=MAX(0, ram_reserved-?2), vram_reserved=MAX(0, vram_reserved-?3) WHERE worker_id=?4",
                params![job.cpu_millicores as i64, job.ram_bytes as i64, job.min_vram_bytes as i64, job.worker_id],
            )
        } else {
            tx.execute(
                "UPDATE fleet_workers SET status='quarantined' WHERE worker_id=?1",
                [&job.worker_id],
            )
        };
        match counter {
            Ok(1) => {}
            Ok(rows) => {
                let msg = format!(
                    "worker counter update matched {rows} rows job_id={} worker_id={}",
                    job.job_id, job.worker_id
                );
                eprintln!("fleet_finish_job: {msg}");
                return Err(msg);
            }
            Err(err) => {
                let msg = format!(
                    "worker counter update job_id={} worker_id={} err={err}",
                    job.job_id, job.worker_id
                );
                eprintln!("fleet_finish_job: {msg}");
                return Err(msg);
            }
        }
    } else if updated != 0 {
        let msg = format!("job update matched {updated} rows job_id={}", job.job_id);
        eprintln!("fleet_finish_job: {msg}");
        return Err(msg);
    }
    if let Err(err) = tx.commit() {
        let msg = format!("tx commit job_id={} err={err}", job.job_id);
        eprintln!("fleet_finish_job: {msg}");
        return Err(msg);
    }
    Ok(())
}

async fn finish_job_retry(
    state: &FleetState,
    job: &FreshJob,
    outcome: &WorkerOutcome,
    always_release: bool,
) -> bool {
    for attempt in 1..=FINISH_ATTEMPTS {
        if finish_job(state, job, outcome, always_release).is_ok() {
            return true;
        }
        if attempt < FINISH_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    false
}

struct AsyncRelease {
    state: FleetState,
    job: FreshJob,
    armed: bool,
}

impl Drop for AsyncRelease {
    fn drop(&mut self) {
        if self.armed {
            let _ = finish_job(&self.state, &self.job, &panicked_outcome(), true);
        }
    }
}

fn spawn_dispatch(
    state: FleetState,
    job: FreshJob,
    req: SubmitJobRequest,
    always_release: bool,
) -> tokio::sync::oneshot::Receiver<Result<(StatusCode, Value), (StatusCode, &'static str, String)>>
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        let _ = finish_job(&state, &job, &panicked_outcome(), true);
        let _ = tx.send(Err(dispatch_panic_error()));
        return rx;
    };
    // Dropping this JoinHandle detaches the task. It is not tied to the HTTP handler.
    runtime.spawn(async move {
        let mut guard = AsyncRelease {
            state: state.clone(),
            job: job.clone(),
            armed: true,
        };
        let state_call = state.clone();
        let job_call = job.clone();
        let req_call = req.clone();
        let joined =
            tokio::task::spawn_blocking(move || dispatch_worker(&state_call, &job_call, &req_call))
                .await;
        let (outcome, panicked) = match joined {
            Ok(outcome) => (outcome, false),
            Err(_) => (panicked_outcome(), true),
        };
        // A panicked worker call must not keep the reservation. The drop guard covers
        // a panic before this attempt finishes.
        let release = always_release || panicked;
        if finish_job_retry(&state, &job, &outcome, release).await {
            guard.armed = false;
        }
        let reply = if panicked {
            Err(dispatch_panic_error())
        } else if guard.armed {
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "job finalization failed".into(),
            ))
        } else {
            Ok((
                StatusCode::OK,
                completed_reply(&req, &job, &outcome, always_release),
            ))
        };
        let _ = tx.send(reply);
    });
    rx
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
    match submit_job(state, auth, idemp, req).await {
        Ok((st, val)) => (st, Json(val)).into_response(),
        Err((st, code, msg)) => err_resp(st, code, &msg),
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JobListFilters {
    #[serde(deserialize_with = "present_value")]
    limit: Option<u16>,
    #[serde(deserialize_with = "present_value")]
    state: Option<String>,
    #[serde(deserialize_with = "present_value")]
    capability: Option<String>,
    #[serde(deserialize_with = "present_value")]
    worker_id: Option<String>,
}

fn present_value<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

impl JobListFilters {
    fn is_valid(&self) -> bool {
        (1..=200).contains(&self.limit.unwrap_or(50))
            && [&self.state, &self.capability, &self.worker_id]
                .into_iter()
                .flatten()
                .all(|value| !value.trim().is_empty())
    }
}

#[derive(Serialize)]
struct JobSummary {
    job_id: String,
    idempotency_key: String,
    actor: String,
    project: String,
    capability: String,
    worker_id: String,
    gpu_uuid: Option<String>,
    state: String,
    output_sha256: Option<String>,
    error_code: Option<String>,
    capacity_released: bool,
    created_at_ms: i64,
    updated_at_ms: i64,
}

fn list_jobs_inner(
    state: &FleetState,
    auth: &CallerAuth,
    filters: &JobListFilters,
) -> FleetResult<Value> {
    let conn = state.db.lock().map_err(|_| STORAGE_UNAVAILABLE)?;
    let mut sql = String::from(
        "SELECT job_id, idempotency_key, actor, project, capability, worker_id, gpu_uuid, state,
                output_sha256, error_code, capacity_released, created_at_ms, updated_at_ms
         FROM fleet_jobs WHERE 1=1",
    );
    let mut values: Vec<&dyn rusqlite::ToSql> = Vec::new();
    if !auth.is_admin {
        sql.push_str(" AND actor=? AND project=?");
        values.extend([&auth.actor as &dyn rusqlite::ToSql, &auth.project]);
    }
    for (predicate, filter) in [
        (" AND state=?", &filters.state),
        (" AND capability=?", &filters.capability),
        (" AND worker_id=?", &filters.worker_id),
    ] {
        if let Some(value) = filter {
            sql.push_str(predicate);
            values.push(value);
        }
    }
    let limit = filters.limit.unwrap_or(50);
    sql.push_str(" ORDER BY created_at_ms DESC, job_id DESC LIMIT ?");
    values.push(&limit);
    let mut stmt = conn.prepare(&sql).map_err(|_| STORAGE_UNAVAILABLE)?;
    let jobs = stmt
        .query_map(params_from_iter(values), |row| {
            Ok(JobSummary {
                job_id: row.get(0)?,
                idempotency_key: row.get(1)?,
                actor: row.get(2)?,
                project: row.get(3)?,
                capability: row.get(4)?,
                worker_id: row.get(5)?,
                gpu_uuid: row.get(6)?,
                state: row.get(7)?,
                output_sha256: row.get(8)?,
                error_code: row.get(9)?,
                capacity_released: row.get::<_, i64>(10)? != 0,
                created_at_ms: row.get(11)?,
                updated_at_ms: row.get(12)?,
            })
        })
        .map_err(|_| STORAGE_UNAVAILABLE)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| STORAGE_UNAVAILABLE)?;
    Ok(json!({"schema_version": "diffuser-fleet/v1", "jobs": jobs}))
}

async fn list_jobs(
    state: FleetState,
    auth: CallerAuth,
    filters: JobListFilters,
) -> FleetResult<Value> {
    tokio::task::spawn_blocking(move || list_jobs_inner(&state, &auth, &filters))
        .await
        .map_err(|_| STORAGE_UNAVAILABLE)?
}

async fn handle_list_jobs(
    State(state): State<FleetState>,
    headers: HeaderMap,
    query: Result<Query<JobListFilters>, QueryRejection>,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(auth) => auth,
        Err((status, code)) => return err_resp(status, code, "authentication failed"),
    };
    let Ok(Query(filters)) = query else {
        return invalid_request("invalid job list filters");
    };
    if !filters.is_valid() {
        return invalid_request("invalid job list filters");
    }
    match list_jobs(state, auth, filters).await {
        Ok(value) => (NO_STORE, Json(value)).into_response(),
        Err((status, code)) => err_resp(status, code, "job list failed"),
    }
}

#[derive(Deserialize)]
struct JobDetailQuery {
    #[serde(default)]
    include_input: bool,
}

fn get_job_inner(
    state: &FleetState,
    auth: &CallerAuth,
    job_id: &str,
    include_input: bool,
) -> FleetResult<Value> {
    let conn = state
        .db
        .lock()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"))?;
    let row: Option<(String, String, String, String, Option<String>, String, Option<String>, Option<String>, Option<String>, i64, i64, i64, Option<String>)> = conn
        .query_row(
            "SELECT actor, project, capability, worker_id, gpu_uuid, state, output_json, output_sha256, error_code, capacity_released, created_at_ms, updated_at_ms,
                    CASE WHEN ?2 THEN input_json END
             FROM fleet_jobs WHERE job_id=?1",
            params![job_id, include_input],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?)),
        )
        .optional()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"))?;
    let Some((
        actor,
        project,
        capability,
        worker_id,
        gpu_uuid,
        st,
        out_j,
        out_sha,
        err_c,
        released,
        c_at,
        u_at,
        input,
    )) = row
    else {
        return Err((StatusCode::NOT_FOUND, "job_not_found"));
    };
    if !auth.is_admin && (actor != auth.actor || project != auth.project) {
        return Err((StatusCode::FORBIDDEN, "forbidden"));
    }
    let output: Value = out_j
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(Value::Null);
    let mut result = json!({
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
        "capacity_released": released != 0,
        "created_at_ms": c_at,
        "updated_at_ms": u_at
    });
    if let Some(input) = input {
        result["input"] = serde_json::from_str(&input).map_err(|_| STORAGE_UNAVAILABLE)?;
    }
    Ok(result)
}

async fn handle_get_job(
    State(state): State<FleetState>,
    headers: HeaderMap,
    AxPath(job_id): AxPath<String>,
    query: Result<Query<JobDetailQuery>, QueryRejection>,
) -> Response {
    let auth = match state.authenticate(&headers) {
        Ok(a) => a,
        Err((st, code)) => return err_resp(st, code, "authentication failed"),
    };
    let Ok(Query(query)) = query else {
        return invalid_request("invalid job detail query");
    };
    match get_job_inner(&state, &auth, &job_id, query.include_input) {
        Ok(v) => (NO_STORE, Json(v)).into_response(),
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
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "artifact write failed",
        );
    }
    let ts = now_ms() as i64;
    let Ok(conn) = state.db.lock() else {
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "db lock failed",
        );
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
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "db lock failed",
        );
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
        return err_resp(
            StatusCode::NOT_FOUND,
            "artifact_not_found",
            "unknown artifact_id",
        );
    };
    if !auth.is_admin && (actor != auth.actor || project != auth.project) {
        return err_resp(
            StatusCode::FORBIDDEN,
            "forbidden",
            "artifact belongs to another caller",
        );
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
        return err_resp(
            StatusCode::BAD_REQUEST,
            "invalid_artifact_id",
            "invalid characters",
        );
    }
    let meta: Option<(String, String, String, String)> = {
        let Ok(conn) = state.db.lock() else {
            return err_resp(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "db lock failed",
            );
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
        return err_resp(
            StatusCode::NOT_FOUND,
            "artifact_not_found",
            "unknown artifact_id",
        );
    };
    if !auth.is_admin && (actor != auth.actor || project != auth.project) {
        return err_resp(
            StatusCode::FORBIDDEN,
            "forbidden",
            "artifact belongs to another caller",
        );
    }
    let Ok(bytes) = fs::read(state.artifacts_dir.join(&artifact_id)) else {
        return err_resp(
            StatusCode::NOT_FOUND,
            "artifact_missing",
            "artifact bytes missing",
        );
    };
    if sha256_hex(&bytes) != expected_sha {
        return err_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            "artifact_integrity_failed",
            "digest mismatch",
        );
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

// Streamable HTTP handshake-based revisions with individual JSON-RPC messages.
const MCP_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18"];

fn mcp_transport_auth(state: &FleetState, headers: &HeaderMap) -> Result<CallerAuth, Response> {
    let auth = state.authenticate(headers).map_err(|(status, code)| {
        let mut response = err_resp(status, code, "authentication failed");
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        }
        response
    })?;
    // Native clients do not send Origin. Browsers must use a trusted local or
    // explicitly configured origin, not an arbitrary request Host header.
    let origins = headers.get_all(header::ORIGIN);
    if let Some(origin) = origins.iter().next() {
        let valid = origins.iter().count() == 1
            && origin.to_str().ok().is_some_and(|origin| {
                Url::parse(origin).ok().is_some_and(|url| {
                    matches!(url.scheme(), "http" | "https")
                        && url.origin().ascii_serialization() == origin
                        && (matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
                            || state
                                .mcp_allowed_origins
                                .iter()
                                .any(|allowed| allowed == origin))
                })
            });
        if !valid {
            return Err((StatusCode::FORBIDDEN, NO_STORE).into_response());
        }
    }
    if let Some(version) = headers.get("mcp-protocol-version") {
        if headers.get_all("mcp-protocol-version").iter().count() != 1
            || !version
                .to_str()
                .ok()
                .is_some_and(|version| MCP_VERSIONS.contains(&version))
        {
            return Err(mcp_http_error(
                StatusCode::BAD_REQUEST,
                -32600,
                "unsupported MCP protocol version",
            ));
        }
    }
    Ok(auth)
}

async fn handle_mcp_unsupported(State(state): State<FleetState>, headers: HeaderMap) -> Response {
    if let Err(response) = mcp_transport_auth(&state, &headers) {
        return response;
    }
    (
        StatusCode::METHOD_NOT_ALLOWED,
        NO_STORE,
        [(header::ALLOW, "POST")],
    )
        .into_response()
}

async fn handle_mcp(State(state): State<FleetState>, request: Request) -> Response {
    let auth = match mcp_transport_auth(&state, request.headers()) {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let req = match Json::<Value>::from_request(request, &()).await {
        Ok(Json(req)) => req,
        Err(JsonRejection::JsonSyntaxError(_) | JsonRejection::JsonDataError(_)) => {
            return mcp_error(&Value::Null, -32700, "parse error");
        }
        Err(error) => return error.into_response(),
    };
    let id = req.get("id");
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let valid_id = id.is_none_or(|id| id.is_string() || id.is_i64() || id.is_u64());
    let Some(method) = method.filter(|_| req["jsonrpc"] == "2.0" && valid_id) else {
        return mcp_error(&Value::Null, -32600, "invalid request");
    };
    let params = req.get("params");
    let valid_params = params.is_none_or(|params| {
        params.is_object() && params.get("_meta").is_none_or(Value::is_object)
    });
    // Notifications never execute a tool and never return a JSON-RPC result.
    let Some(id) = id else {
        if !valid_params {
            return (StatusCode::BAD_REQUEST, NO_STORE).into_response();
        }
        return (StatusCode::ACCEPTED, NO_STORE).into_response();
    };
    if !valid_params {
        return mcp_invalid_params(id);
    }
    match method {
        "notifications/initialized" => mcp_error(id, -32600, "initialized must be a notification"),
        "ping" => {
            if params
                .is_some_and(|params| params.as_object().unwrap().keys().any(|key| key != "_meta"))
            {
                return mcp_invalid_params(id);
            }
            mcp_result(id, json!({}))
        }
        "initialize" => {
            let Some(params) = params else {
                return mcp_invalid_params(id);
            };
            let Some(requested) = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
            else {
                return mcp_invalid_params(id);
            };
            if !params.get("capabilities").is_some_and(Value::is_object)
                || !params.get("clientInfo").is_some_and(|info| {
                    info.is_object()
                        && info.get("name").is_some_and(Value::is_string)
                        && info.get("version").is_some_and(Value::is_string)
                })
            {
                return mcp_invalid_params(id);
            }
            let version = MCP_VERSIONS
                .iter()
                .copied()
                .find(|v| *v == requested)
                .unwrap_or(MCP_VERSIONS[0]);
            mcp_result(
                id,
                json!({
                    "protocolVersion": version,
                    "serverInfo": { "name": "diffuser-fleet", "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": { "tools": {} }
                }),
            )
        }
        "tools/list" if params.is_some_and(|p| p.get("cursor").is_some()) => {
            // All tools fit on a single page; no continuation cursor is issued.
            mcp_invalid_params(id)
        }
        "tools/list" => mcp_result(
            id,
            json!({
                    "tools": [
                        {"name": "fleet_discover", "description": "Discover live Diffuser capabilities and available CPU/GPU capacity.", "inputSchema": {"type": "object", "properties": {}}},
                        {"name": "fleet_list_workers", "description": "List all enrolled Diffuser workers and live resources (admin).", "inputSchema": {"type": "object", "properties": {}}},
                        {"name": "fleet_submit_job", "description": "Submit an idempotent job by capability and optional exact GPU UUID. Set async true to return while the job is still running.", "inputSchema": {"type": "object", "required": ["capability", "idempotency_key"], "properties": {"capability": {"type": "string"}, "idempotency_key": {"type": "string"}, "pin_gpu_uuid": {"type": "string"}, "input": {"type": "object"}, "timeout_secs": {"type": "integer", "minimum": 1, "maximum": 21600}, "min_vram_bytes": {"type": "integer", "minimum": 0}, "cpu_millicores": {"type": "integer", "minimum": 0}, "ram_bytes": {"type": "integer", "minimum": 0}, "async": {"type": "boolean"}}}},
                        {"name": "fleet_get_job", "description": "Read durable job status and verified output digest.", "inputSchema": {"type": "object", "required": ["job_id"], "properties": {"job_id": {"type": "string"}}}},
                        {"name": "fleet_issue_token", "description": "Issue a scoped caller token for a human or agent (admin).", "inputSchema": {"type": "object", "required": ["actor", "project", "allowed_capabilities"], "properties": {"actor": {"type": "string"}, "project": {"type": "string"}, "allowed_capabilities": {"type": "array", "items": {"type": "string"}}, "max_vram_bytes": {"type": "integer", "minimum": 0}, "ttl_secs": {"type": "integer", "minimum": 0}}}},
                        {"name": "fleet_list_jobs", "description": "List durable job summaries in the caller's scope. Admin callers see all jobs.", "inputSchema": {"type": "object", "additionalProperties": false, "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}, "state": {"type": "string"}, "capability": {"type": "string"}, "worker_id": {"type": "string"}}}},
                        {"name": "fleet_drain_worker", "description": "Drain or resume worker admission (admin required).", "inputSchema": {"type": "object", "additionalProperties": false, "required": ["worker_id"], "properties": {"worker_id": {"type": "string", "minLength": 1}, "accepting": {"type": "boolean", "default": false}}}},
                        {"name": "fleet_revoke_token", "description": "Revoke a scoped caller token (admin required).", "inputSchema": {"type": "object", "additionalProperties": false, "required": ["token_id"], "properties": {"token_id": {"type": "string", "minLength": 1}}}},
                        {"name": "fleet_list_tokens", "description": "List scoped caller token metadata and revocation and expiry status (admin required).", "inputSchema": {"type": "object", "additionalProperties": false, "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}, "include_revoked": {"type": "boolean", "default": true}}}}
                    ]
            }),
        ),
        "tools/call" => {
            let Some(params) = params.and_then(Value::as_object) else {
                return mcp_invalid_params(id);
            };
            let Some(name) = params
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            else {
                return mcp_invalid_params(id);
            };
            let args = params.get("arguments");
            if matches!(
                name,
                "fleet_list_jobs"
                    | "fleet_drain_worker"
                    | "fleet_revoke_token"
                    | "fleet_list_tokens"
            ) {
                return mcp_fleet_tool(state, auth, id, name, args).await;
            }
            if matches!(name, "fleet_list_workers" | "fleet_issue_token") && !auth.is_admin {
                return mcp_error(id, -32000, "admin_required");
            }
            let args = match args {
                None => json!({}),
                Some(args) if args.is_object() => args.clone(),
                _ => return mcp_invalid_params(id),
            };
            match name {
                "fleet_discover" => match discover_json(&state, &auth) {
                    Ok(value) => mcp_content(id, value),
                    Err(error) => mcp_error(id, -32000, &error.to_string()),
                },
                "fleet_list_workers" => match list_workers_json(&state) {
                    Ok(workers) => mcp_content(id, json!({"workers": workers})),
                    Err(error) => mcp_error(id, -32000, &error.to_string()),
                },
                "fleet_get_job" => {
                    let Some(jid) = args["job_id"].as_str().filter(|s| !s.trim().is_empty()) else {
                        return mcp_invalid_params(id);
                    };
                    match get_job_inner(&state, &auth, jid, false) {
                        Ok(value) => mcp_content(id, value),
                        Err((status, code))
                            if status.is_server_error() || status == StatusCode::FORBIDDEN =>
                        {
                            mcp_error(id, -32000, code)
                        }
                        Err((_, code)) => mcp_tool_failure(id, code),
                    }
                }
                "fleet_issue_token" => match serde_json::from_value::<IssueTokenRequest>(args) {
                    Ok(req) => match issue_token_inner(&state, &req) {
                        Ok(value) => mcp_content(id, value),
                        Err("invalid_request") => mcp_tool_failure(id, "invalid_request"),
                        Err(error) => mcp_error(id, -32000, error),
                    },
                    Err(_) => mcp_invalid_params(id),
                },
                "fleet_submit_job" => {
                    let Some(idemp) = args["idempotency_key"]
                        .as_str()
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_owned)
                    else {
                        return mcp_invalid_params(id);
                    };
                    if args.get("input").is_some_and(|v| !v.is_object())
                        || args.get("timeout_secs").is_some_and(|v| {
                            !v.as_u64()
                                .is_some_and(|n| (1..=MAX_JOB_TIMEOUT_SECS).contains(&n))
                        })
                        || args.get("pin_gpu_uuid").is_some_and(|v| !v.is_string())
                    {
                        return mcp_invalid_params(id);
                    }
                    match serde_json::from_value::<SubmitJobRequest>(args) {
                        Ok(sub) => {
                            match submit_job(state.clone(), auth.clone(), idemp, sub).await {
                                Ok((_, v)) => mcp_content(id, v),
                                Err((status, code, message))
                                    if status.is_server_error()
                                        || status == StatusCode::FORBIDDEN =>
                                {
                                    mcp_error(id, -32000, &format!("{code}: {message}"))
                                }
                                Err((_, code, message)) => {
                                    mcp_tool_failure(id, &format!("{code}: {message}"))
                                }
                            }
                        }
                        Err(_) => mcp_invalid_params(id),
                    }
                }
                _ => mcp_error(id, -32602, "unknown tool"),
            }
        }
        _ => mcp_error(id, -32601, "method not found"),
    }
}

fn mcp_result(id: &Value, result: Value) -> Response {
    (
        NO_STORE,
        Json(json!({"jsonrpc": "2.0", "id": id, "result": result})),
    )
        .into_response()
}

fn mcp_content(id: &Value, value: Value) -> Response {
    mcp_result(
        id,
        json!({"isError": false, "content": [{"type": "text", "text": value.to_string()}]}),
    )
}

fn mcp_tool_failure(id: &Value, message: &str) -> Response {
    mcp_result(
        id,
        json!({"isError": true, "content": [{"type": "text", "text": message}]}),
    )
}

fn mcp_http_error(status: StatusCode, code: i32, message: &str) -> Response {
    let mut response = mcp_error(&Value::Null, code, message);
    *response.status_mut() = status;
    response
}

fn mcp_error(id: &Value, code: i32, message: &str) -> Response {
    (
        NO_STORE,
        Json(json!({
            "jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}
        })),
    )
        .into_response()
}

fn mcp_invalid_params(id: &Value) -> Response {
    mcp_error(id, -32602, "invalid params")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpDrainArgs {
    worker_id: String,
    #[serde(default)]
    accepting: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpRevokeArgs {
    token_id: String,
}

async fn mcp_fleet_tool(
    state: FleetState,
    auth: CallerAuth,
    id: &Value,
    name: &str,
    args: Option<&Value>,
) -> Response {
    if name != "fleet_list_jobs" && !auth.is_admin {
        return mcp_error(id, -32000, "admin_required");
    }
    let args = match args {
        None => json!({}),
        Some(args) if args.is_object() => args.clone(),
        _ => return mcp_invalid_params(id),
    };
    let result = match name {
        "fleet_list_jobs" => match serde_json::from_value::<JobListFilters>(args) {
            Ok(filters) if filters.is_valid() => list_jobs(state, auth, filters).await,
            _ => return mcp_invalid_params(id),
        },
        "fleet_list_tokens" => match serde_json::from_value::<TokenListFilters>(args) {
            Ok(filters) if filters.is_valid() => list_tokens(state, filters).await,
            _ => return mcp_invalid_params(id),
        },
        "fleet_drain_worker" => match serde_json::from_value::<McpDrainArgs>(args) {
            Ok(args) if !args.worker_id.trim().is_empty() => {
                set_worker_accepting_inner(&state, &args.worker_id, args.accepting)
            }
            _ => return mcp_invalid_params(id),
        },
        "fleet_revoke_token" => match serde_json::from_value::<McpRevokeArgs>(args) {
            Ok(args) if !args.token_id.trim().is_empty() => {
                revoke_token_inner(&state, &args.token_id)
            }
            _ => return mcp_invalid_params(id),
        },
        _ => return mcp_invalid_params(id),
    };
    match result {
        Ok(value) => mcp_content(id, value),
        Err((StatusCode::NOT_FOUND | StatusCode::CONFLICT, code)) => mcp_tool_failure(id, code),
        Err((_, code)) => mcp_error(id, -32000, code),
    }
}

// === Standalone Pluggable Fleet Worker (--fleet-worker <config.json>) ===

fn parse_live_gpu_telemetry(stdout: &str) -> Option<LiveGpuTelemetry> {
    let mut gpus = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 4 || parts.iter().any(|part| part.is_empty()) {
            continue;
        }
        let free_mib: u64 = match parts[1].parse() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let total_mib: u64 = match parts[2].parse() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let util: u64 = match parts[3].parse() {
            Ok(value) if value <= 100 => value,
            _ => continue,
        };
        gpus.push(LiveGpuSample {
            uuid: parts[0].to_string(),
            memory_free_bytes: free_mib.saturating_mul(1024 * 1024),
            memory_total_bytes: total_mib.saturating_mul(1024 * 1024),
            util_pct: util,
        });
    }
    if gpus.is_empty() {
        return None;
    }
    let free_bytes = gpus
        .iter()
        .fold(0u64, |sum, gpu| sum.saturating_add(gpu.memory_free_bytes));
    let util_pct = gpus.iter().map(|gpu| gpu.util_pct).max().unwrap_or(0);
    Some(LiveGpuTelemetry {
        free_bytes,
        util_pct,
        gpus,
    })
}

/// Live free VRAM and utilization. Missing or hung `nvidia-smi` returns None and must not fail the worker.
fn query_live_gpu_telemetry() -> Option<LiveGpuTelemetry> {
    let mut cmd = Command::new("nvidia-smi");
    cmd.args([
        "--query-gpu=uuid,memory.free,memory.total,utilization.gpu",
        "--format=csv,noheader,nounits",
    ]);
    let (rc, stdout) = crate::engine::run_limited(&mut cmd, NVIDIA_SMI_TIMEOUT).ok()?;
    if rc != 0 {
        return None;
    }
    parse_live_gpu_telemetry(&stdout)
}

fn live_heartbeat_payload() -> Value {
    match query_live_gpu_telemetry() {
        Some(sample) => json!({
            "live_vram_free_bytes": sample.free_bytes,
            "gpu_util_pct": sample.util_pct,
            "gpus_live": sample.gpus,
        }),
        None => json!({
            "live_vram_free_bytes": Value::Null,
            "gpu_util_pct": Value::Null,
            "gpus_live": Value::Null,
        }),
    }
}

fn detect_local_gpus() -> Vec<GpuInfo> {
    let Ok(out) = Command::new("nvidia-smi")
        .args([
            "--query-gpu=uuid,name,memory.total",
            "--format=csv,noheader,nounits",
        ])
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
        if now == 0
            || issued_at_ms < oldest
            || issued_at_ms > now.saturating_add(RPC_FUTURE_SKEW_MS)
        {
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
    /// Omitted budgets use the profile timeout, up to 21600 seconds.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

async fn handle_worker_run(
    State(rt): State<Arc<WorkerRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_RPC_BODY_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"ok": false, "error": "body_too_large", "cleanup_ok": true})),
        )
            .into_response();
    }
    let sig = headers
        .get("x-diffuser-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !verify_rpc(&rt.cfg.rpc_secret_hex, &body, sig) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "invalid_signature", "cleanup_ok": true})),
        )
            .into_response();
    }
    let req: WorkerRunRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"ok": false, "error": "invalid_json", "cleanup_ok": true})),
            )
                .into_response()
        }
    };
    if req.rpc_session != rt.rpc_session
        || !req.job_id.strip_prefix("fjob_").is_some_and(is_random_id)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"ok": false, "error": "rpc_identity_invalid", "cleanup_ok": true})),
        )
            .into_response();
    }
    let accepted = rt
        .replay
        .lock()
        .map_err(|_| "rpc_replay_cache_unavailable")
        .and_then(|mut replay| replay.consume(&req.job_id, req.issued_at_ms, (rt.clock)()));
    if let Err(error) = accepted {
        let status = match error {
            "rpc_replayed" => StatusCode::CONFLICT,
            "rpc_timestamp_invalid" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        return (
            status,
            Json(json!({"ok": false, "error": error, "cleanup_ok": true})),
        )
            .into_response();
    }
    let rt_clone = rt.clone();
    let res = tokio::task::spawn_blocking(move || execute_profile(&rt_clone, &req)).await;
    match res {
        Ok(v) => Json(v).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"ok": false, "error": "worker_panic", "cleanup_ok": false})),
        )
            .into_response(),
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
            let limit_secs = effective_exec_timeout_secs(req.timeout_secs, *timeout_secs);
            cmd.env("DIFFUSER_TIMEOUT_SECS", limit_secs.to_string());
            let Ok(mut child) = cmd.spawn() else {
                return json!({"ok": false, "error": "spawn_failed", "cleanup_ok": true});
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(
                    serde_json::to_string(&req.input)
                        .unwrap_or_default()
                        .as_bytes(),
                );
            }
            let limit = Duration::from_secs(limit_secs);
            let deadline = std::time::Instant::now() + limit;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let out = child.wait_with_output();
                        match out {
                            Ok(o) if status.success() => {
                                let stdout_str =
                                    String::from_utf8_lossy(&o.stdout).trim().to_string();
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
                            Err(_) => {
                                return json!({"ok": false, "error": "wait_failed", "cleanup_ok": false})
                            }
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
                .timeout(Duration::from_secs(effective_exec_timeout_secs(
                    req.timeout_secs,
                    *timeout_secs,
                )))
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
                    let parsed: Value =
                        serde_json::from_str(&text).unwrap_or_else(|_| json!({"body": text}));
                    json!({
                        "ok": true,
                        "worker_id": rt.cfg.worker_id,
                        "gpu_uuid": req.gpu_uuid.as_ref().or(gpu_uuid.as_ref()),
                        "output": parsed,
                        "cleanup_ok": true
                    })
                }
                Ok(r) => {
                    json!({"ok": false, "error": format!("upstream_http_{}", r.status().as_u16()), "cleanup_ok": true})
                }
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
            let (kind, gpu_uuid, timeout_secs) = match &p.adapter {
                ProfileAdapter::Exec {
                    gpu_uuid,
                    timeout_secs,
                    ..
                } => ("exec".to_string(), gpu_uuid.clone(), *timeout_secs),
                ProfileAdapter::Http {
                    gpu_uuid,
                    timeout_secs,
                    ..
                } => ("http".to_string(), gpu_uuid.clone(), *timeout_secs),
            };
            CapabilityInfo {
                capability: p.capability.clone(),
                kind,
                gpu_uuid: gpu_uuid.or_else(|| gpus.first().map(|g| g.uuid.clone())),
                description: p.description.clone(),
                timeout_secs: bounded_timeout_secs(timeout_secs),
            }
        })
        .collect();

    let http = private_http_client()
        .timeout(rpc_http_timeout(MAX_JOB_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("http:{e}"))?;

    // Enroll + background heartbeat thread
    let enroll_url = fleet_endpoint(&controller_url, "/v1/fleet/workers/enroll");
    let mut hb_url = fleet_endpoint(&controller_url, "/v1/fleet/workers");
    hb_url
        .path_segments_mut()
        .unwrap()
        .push(&cfg.worker_id)
        .push("heartbeat");
    let rpc_key = &cfg.rpc_secret_hex;
    let enroll_body = json!({
        "worker_id": cfg.worker_id,
        "host": cfg.host,
        "rpc_url": advertise_url.as_str(),
        "rpc_secret_hex": rpc_key,
        "rpc_session": rpc_session,
        "cpu_millicores": cfg.cpu_millicores,
        "ram_bytes": cfg.ram_bytes,
        "vram_bytes": vram_total,
        "gpus": gpus,
        "capabilities": caps
    });
    let bearer = cfg.enroll_bearer.clone();
    let hb_http = http.clone();
    let detect_gpus = cfg.auto_detect_gpus;
    std::thread::spawn(move || {
        let beat = |payload: &Value| {
            let _ = hb_http
                .post(hb_url.clone())
                .header("authorization", format!("Bearer {bearer}"))
                .json(payload)
                .send();
        };
        loop {
            let _ = hb_http
                .post(enroll_url.clone())
                .header("authorization", format!("Bearer {bearer}"))
                .json(&enroll_body)
                .send();
            if detect_gpus {
                beat(&live_heartbeat_payload());
            }
            for _ in 0..6 {
                std::thread::sleep(Duration::from_secs(10));
                if detect_gpus {
                    beat(&live_heartbeat_payload());
                } else {
                    beat(&json!({}));
                }
            }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[test]
    fn worker_tiers_classify_gpu_location_and_cpu_fallback() {
        for (worker_id, vram_total, tier, rank) in [
            ("echo-rtx3060-01", 12_000_000_000, "local_gpu", 0),
            ("colab-gpu-01", 16_000_000_000, "cloud_gpu", 1),
            ("columbus-gpu-01", 16_000_000_000, "cloud_gpu", 1),
            ("runpod-gpu-01", 16_000_000_000, "cloud_gpu", 1),
            ("nuc-cpu-01", 0, "cpu_fallback", 2),
            ("echo-rtx3060-01", -1, "cpu_fallback", 2),
            ("colab-gpu-01", 0, "cpu_fallback", 2),
            ("columbus-gpu-01", -1, "cpu_fallback", 2),
            ("runpod-gpu-01", 0, "cpu_fallback", 2),
        ] {
            assert_eq!(worker_tier(worker_id, vram_total), tier, "{worker_id}");
            assert_eq!(worker_tier_rank(worker_id, vram_total), rank, "{worker_id}");
        }
    }

    #[test]
    fn scheduler_orders_by_tier_then_free_vram_then_id_and_falls_back_to_cpu() {
        const CAPABILITY: &str = "audio.stt.whisper/v1";
        let (root, state, headers) = open_state("worker-tiers");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let auth = state.authenticate(&headers).unwrap();
        runtime.block_on(async {
            for (worker_id, vram_bytes) in [
                ("nuc-cpu-01", 0u64),
                ("runpod-gpu-01", 24_000_000_000),
                ("echo-rtx3060-02", 8_000_000_000),
                ("echo-rtx3060-01", 8_000_000_000),
                ("z-local-gpu-01", 12_000_000_000),
            ] {
                let mut enrollment = fixture_enrollment(SESSION);
                enrollment["worker_id"] = json!(worker_id);
                enrollment["vram_bytes"] = json!(vram_bytes);
                enrollment["capabilities"] = json!([{"capability": CAPABILITY, "kind": "exec"}]);
                assert_eq!(
                    handle_enroll(
                        State(state.clone()),
                        headers.clone(),
                        Json(serde_json::from_value(enrollment).unwrap()),
                    )
                    .await
                    .status(),
                    StatusCode::OK
                );
            }

            let listed =
                read_json(handle_list_workers(State(state.clone()), headers.clone()).await).await;
            let tiers = listed["workers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|worker| worker["worker_tier"].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                tiers,
                [
                    "local_gpu",
                    "local_gpu",
                    "cpu_fallback",
                    "cloud_gpu",
                    "local_gpu"
                ]
            );
            let discovered =
                read_json(handle_discover(State(state.clone()), headers.clone()).await).await;
            let offers = discovered["capabilities"].as_array().unwrap();
            assert_eq!(offers.len(), 5);
            for (offer, tier) in offers.iter().zip(tiers) {
                assert_eq!(offer["capability"], CAPABILITY);
                assert_eq!(offer["worker_tier"], tier);
            }
        });

        let req: SubmitJobRequest =
            serde_json::from_value(json!({"capability": CAPABILITY})).unwrap();
        let place = |key: &str, expected: &str| {
            let PrepareOutcome::Fresh(job) = prepare_job(&state, &auth, key, &req).unwrap() else {
                panic!("expected fresh reservation");
            };
            assert_eq!(job.worker_id, expected);
        };
        let drain = |worker_id: &str| {
            assert_eq!(
                set_worker_accepting_inner(&state, worker_id, false).unwrap()["status"],
                "draining"
            );
        };
        place("largest-local", "z-local-gpu-01");
        drain("z-local-gpu-01");
        place("local-id-tie", "echo-rtx3060-01");
        state.db.lock().unwrap().execute(
            "UPDATE fleet_workers SET vram_reserved=vram_total WHERE worker_id IN ('echo-rtx3060-01', 'runpod-gpu-01')",
            [],
        ).unwrap();
        place("local-free-vram", "echo-rtx3060-02");
        drain("echo-rtx3060-02");
        // A GPU remains in its tier even when all its VRAM is reserved.
        place("local-zero-free-vram", "echo-rtx3060-01");
        drain("echo-rtx3060-01");
        // The CPU sorts before runpod by ID and ties on free VRAM, but its tier is last.
        place("cloud-before-cpu", "runpod-gpu-01");
        drain("runpod-gpu-01");
        place("cpu-fallback", "nuc-cpu-01");

        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    fn open_state(name: &str) -> (PathBuf, FleetState, HeaderMap) {
        let root =
            std::env::temp_dir().join(format!("fleet-{name}-{}-{}", std::process::id(), now_ms()));
        let _ = fs::remove_dir_all(&root);
        crate::private_state::fixture_dir(&root);
        let config = root.join("controller.json");
        fs::write(
            &config,
            json!({"admin_token_sha256": sha256_hex(b"fixture")}).to_string(),
        )
        .unwrap();
        let state = FleetState::open(&config, &root).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer fixture".parse().unwrap());
        (root, state, headers)
    }

    async fn read_json(response: Response) -> Value {
        let (status, value) = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{value}");
        value
    }

    async fn response_json(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body)
            .unwrap_or(json!({"raw": String::from_utf8_lossy(&body).to_string()}));
        (status, value)
    }

    fn worker_reserved(state: &FleetState) -> (i64, i64, i64) {
        state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cpu_reserved, ram_reserved, vram_reserved FROM fleet_workers WHERE worker_id='worker'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
    }

    fn mcp_tool(envelope: &Value) -> Value {
        let text = envelope["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("");
        serde_json::from_str(text).unwrap_or(Value::Null)
    }

    async fn call_mcp(
        state: State<FleetState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Response {
        let mut request = Request::new(Body::from(body.to_string()));
        *request.headers_mut() = headers;
        request
            .headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        handle_mcp(state, request).await
    }

    fn mounted_fleet(root: &Path, enabled: bool) -> Router {
        let spine = super::super::Spine {
            root: root.into(),
            edge: false,
            worker_ports: [0, 0],
            admin: false,
            sequence: Arc::new(Mutex::new(0)),
        };
        let namespace = if enabled {
            router(&root.join("controller.json"), root).unwrap()
        } else {
            closed_router()
        };
        super::super::api_with_namespaces(spine, Router::new(), namespace)
    }

    async fn fleet_request(
        app: &Router,
        method: &str,
        path: &str,
        bearer: &str,
        media_type: Option<&str>,
        body: impl Into<Body>,
    ) -> Response {
        use tower::ServiceExt;
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/v1/fleet{path}"));
        if !bearer.is_empty() {
            request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        if let Some(media_type) = media_type {
            request = request.header(header::CONTENT_TYPE, media_type);
        }
        app.clone()
            .oneshot(request.body(body.into()).unwrap())
            .await
            .unwrap()
    }

    async fn fleet_json(
        app: &Router,
        method: &str,
        path: &str,
        bearer: &str,
        body: Value,
    ) -> Response {
        fleet_request(
            app,
            method,
            path,
            bearer,
            Some("application/json"),
            body.to_string(),
        )
        .await
    }

    async fn rpc(app: &Router, token: &str, body: Value) -> Value {
        let response = fleet_json(app, "POST", "/mcp", token, body).await;
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        read_json(response).await
    }

    async fn tool(app: &Router, token: &str, name: &str, arguments: Value) -> Value {
        rpc(
            app,
            token,
            json!({
                "jsonrpc":"2.0", "id":"call", "method":"tools/call",
                "params":{"name":name, "arguments":arguments}
            }),
        )
        .await
    }

    fn seed_token(
        state: &FleetState,
        name: &str,
        actor: &str,
        project: &str,
        expired: bool,
        revoked: bool,
    ) {
        let expires = if expired { 1 } else { now_ms() as i64 + 60_000 };
        state.db.lock().unwrap().execute(
            "INSERT INTO fleet_tokens (token_id, token_sha256, actor, project, allowed_capabilities_json,
                 max_vram_bytes, created_at_ms, expires_at_ms, revoked)
             VALUES (?1,?2,?3,?4,'[\"permitted\"]',0,0,?5,?6)",
            params![name, sha256_hex(name.as_bytes()), actor, project, expires, revoked],
        ).unwrap();
    }

    fn seed_job(
        state: &FleetState,
        id: &str,
        owner: (&str, &str),
        offer: (&str, &str),
        status: &str,
        at: i64,
    ) {
        state.db.lock().unwrap().execute(
            "INSERT INTO fleet_jobs (job_id,idempotency_key,actor,project,capability,worker_id,state,
                input_json,output_json,capacity_released,created_at_ms,updated_at_ms)
             VALUES (?1,?1,?2,?3,?4,?5,?6,'{\"fixture_input\":true}','null',2,?7,?7+1)",
            params![id, owner.0, owner.1, offer.0, offer.1, status, at],
        ).unwrap();
    }

    fn fixture_enrollment(session: &str) -> Value {
        json!({
            "worker_id":"worker", "host":"fixture-host", "rpc_url":"http://127.0.0.1:9",
            "rpc_secret_hex":SECRET,"rpc_session":session,
            "cpu_millicores":4000,"ram_bytes":2000000000,"vram_bytes":0,
            "capabilities":[{"capability":"fixture","kind":"exec"}]
        })
    }

    async fn enroll_fixture(app: &Router, session: &str) -> Value {
        read_json(
            fleet_json(
                app,
                "POST",
                "/workers/enroll",
                "fixture",
                fixture_enrollment(session),
            )
            .await,
        )
        .await
    }

    fn worker_admission(state: &FleetState) -> (String, bool, i64) {
        state.db.lock().unwrap().query_row(
            "SELECT status, operator_drained, last_heartbeat_ms FROM fleet_workers WHERE worker_id='worker'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap()
    }

    #[test]
    fn tokens_list_requires_admin_and_omits_secret_hashes() {
        let (root, state, _) = open_state("tokens-list");
        let app = mounted_fleet(&root, true);
        let closed = mounted_fleet(&root, false);
        let admin = "fixture";
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mut issued = Vec::new();
            for (actor, ttl_secs) in [("active", 3600), ("revoked", 3600), ("expired", 0)] {
                let response = fleet_json(
                    &app,
                    "POST",
                    "/tokens",
                    admin,
                    json!({
                        "actor": actor, "project": "guests", "allowed_capabilities": ["gpu"],
                        "max_vram_bytes": 4096, "ttl_secs": ttl_secs
                    }),
                )
                .await;
                let (status, body) = response_json(response).await;
                assert_eq!(status, StatusCode::CREATED, "{body}");
                issued.push(body);
            }
            let revoked_id = issued[1]["token_id"].as_str().unwrap();
            let revoke_path = format!("/tokens/{revoked_id}/revoke");
            let revoked = fleet_request(&app, "POST", &revoke_path, admin, None, "").await;
            assert_eq!(read_json(revoked).await["revoked"], true);
            state.db.lock().unwrap().execute(
                "UPDATE fleet_tokens SET created_at_ms = CASE WHEN token_id=?1 THEN 2 ELSE 1 END",
                [revoked_id],
            ).unwrap();

            let mut summaries = [
                (&issued[1], 2, true, false),
                (&issued[0], 1, false, false),
                (&issued[2], 1, false, true),
            ]
            .map(|(token, created_at_ms, revoked, expired)| {
                json!({
                    "token_id": token["token_id"], "actor": token["actor"],
                    "project": "guests", "allowed_capabilities": ["gpu"], "max_vram_bytes": 4096,
                    "created_at_ms": created_at_ms, "expires_at_ms": token["expires_at_ms"],
                    "revoked": revoked, "expired": expired
                })
            });
            summaries[1..].sort_by(|a, b| b["token_id"].as_str().cmp(&a["token_id"].as_str()));
            let response = fleet_request(&app, "GET", "/tokens", admin, None, "").await;
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let all = read_json(response).await;
            assert_eq!(all, json!({"schema_version": 1, "tokens": summaries}));
            for token in all["tokens"].as_array().unwrap() {
                assert!(token.get("token_sha256").is_none());
                assert!(token.get("token").is_none());
            }

            for (query, args, expected) in [
                (
                    "limit=200&include_revoked=true",
                    json!({"limit": 200, "include_revoked": true}),
                    all.clone(),
                ),
                (
                    "include_revoked=false",
                    json!({"include_revoked": false}),
                    json!({"schema_version": 1, "tokens": &summaries[1..]}),
                ),
                (
                    "limit=1&include_revoked=false",
                    json!({"limit": 1, "include_revoked": false}),
                    json!({"schema_version": 1, "tokens": &summaries[1..2]}),
                ),
            ] {
                let path = format!("/tokens?{query}");
                let response = fleet_request(&app, "GET", &path, admin, None, "").await;
                let rest = read_json(response).await;
                assert_eq!(rest, expected);
                assert_eq!(
                    mcp_tool(&tool(&app, admin, "fleet_list_tokens", args).await),
                    rest
                );
            }
            let default = rpc(
                &app,
                admin,
                json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "fleet_list_tokens"}
                }),
            )
            .await;
            assert_eq!(mcp_tool(&default), all);

            for query in [
                "limit=0",
                "limit=201",
                "limit=-1",
                "limit=abc",
                "include_revoked=1",
            ] {
                let path = format!("/tokens?{query}");
                let response = fleet_request(&app, "GET", &path, admin, None, "").await;
                let (status, body) = response_json(response).await;
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{path}");
                assert_eq!(body["error"]["code"], "invalid_request");
            }
            for args in [
                json!({"limit": 201}),
                json!({"limit": null}),
                json!({"include_revoked": "false"}),
            ] {
                let invalid = tool(&app, admin, "fleet_list_tokens", args).await;
                assert_eq!(invalid["error"]["code"], -32602);
            }

            let scoped = issued[0]["token"].as_str().unwrap();
            for bearer in ["", scoped] {
                let response = fleet_request(&app, "GET", "/tokens", bearer, None, "").await;
                let (status, body) = response_json(response).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(body["error"]["code"], "unauthorized");
            }
            let denied = tool(&app, scoped, "fleet_list_tokens", json!({})).await;
            assert_eq!(
                denied["error"],
                json!({"code": -32000, "message": "admin_required"})
            );
            let response = fleet_request(&closed, "GET", "/tokens", admin, None, "").await;
            let (status, body) = response_json(response).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"]["code"], "fleet_closed");
        });
        drop(app);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn jobs_list_requires_auth_and_scopes_actor_and_project() {
        let (root, state, _) = open_state("jobs-scope");
        seed_token(&state, "scoped", "actor-a", "project-one", false, false);
        seed_token(&state, "default-scope", "admin", "default", false, false);
        seed_token(&state, "expired", "actor-a", "project-one", true, false);
        seed_token(&state, "revoked", "actor-a", "project-one", false, true);
        for (id, owner, at) in [
            ("own", ("actor-a", "project-one"), 1),
            ("other-project", ("actor-a", "project-two"), 2),
            ("other-actor", ("actor-b", "project-one"), 3),
            ("default-owner", ("admin", "default"), 4),
        ] {
            seed_job(
                &state,
                id,
                owner,
                ("outside-allowlist", "worker"),
                "succeeded",
                at,
            );
        }
        let app = mounted_fleet(&root, true);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let admin =
                read_json(fleet_request(&app, "GET", "/jobs", "fixture", None, "").await).await;
            assert_eq!(admin["jobs"].as_array().unwrap().len(), 4);
            for (token, id) in [("scoped", "own"), ("default-scope", "default-owner")] {
                let scoped = read_json(
                    fleet_request(
                        &app,
                        "GET",
                        "/jobs?limit=1&state=succeeded",
                        token,
                        None,
                        "",
                    )
                    .await,
                )
                .await;
                assert_eq!(scoped["jobs"].as_array().unwrap().len(), 1);
                assert_eq!(scoped["jobs"][0]["job_id"], id);
                assert_eq!(scoped["jobs"][0]["capability"], "outside-allowlist");
            }
            for (token, code) in [
                ("", "auth_required"),
                ("bad", "auth_invalid"),
                ("expired", "auth_expired_or_revoked"),
                ("revoked", "auth_expired_or_revoked"),
            ] {
                let (status, body) = response_json(
                    fleet_request(
                        &app,
                        "GET",
                        "/jobs?limit=bad&actor=override",
                        token,
                        None,
                        "",
                    )
                    .await,
                )
                .await;
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(body["error"]["code"], code);
            }
            let legacy =
                read_json(fleet_request(&app, "GET", "/jobs/own", "scoped", None, "").await).await;
            assert!(legacy.get("input").is_none());
            let detail = read_json(
                fleet_request(
                    &app,
                    "GET",
                    "/jobs/own?include_input=true",
                    "scoped",
                    None,
                    "",
                )
                .await,
            )
            .await;
            assert_eq!(detail["input"], json!({"fixture_input":true}));
            assert_eq!(detail["output"], Value::Null);
            for id in ["other-actor", "other-project"] {
                let response = fleet_request(
                    &app,
                    "GET",
                    &format!("/jobs/{id}?include_input=true"),
                    "scoped",
                    None,
                    "",
                )
                .await;
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
            }
        });
        drop(app);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn jobs_list_filters_orders_and_bounds_durable_summaries() {
        let (root, state, _) = open_state("jobs-filter");
        for n in 0..205 {
            seed_job(
                &state,
                &format!("job-{n:03}"),
                ("actor", "project"),
                ("echo", "worker-a"),
                "succeeded",
                n / 2 + 10,
            );
        }
        const LITERAL: &str = " x' OR 1=1 -- ";
        seed_job(
            &state,
            "literal",
            ("actor", "project"),
            (LITERAL, "worker-b"),
            "failed_uncertain",
            1,
        );
        state.db.lock().unwrap().execute(
            "UPDATE fleet_jobs SET error_code='uncertain', gpu_uuid='fixture-gpu', output_sha256=?1, capacity_released=0
             WHERE job_id='job-204'",
            [sha256_hex(b"fixture output")],
        ).unwrap();
        drop(state);
        let app = mounted_fleet(&root, true);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for (query, limit) in [("", 50), ("?limit=1", 1), ("?limit=200", 200)] {
                let response = fleet_request(&app, "GET", &format!("/jobs{query}"), "fixture", None, "").await;
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let body = read_json(response).await;
                assert_eq!(body["schema_version"], "diffuser-fleet/v1");
                let jobs = body["jobs"].as_array().unwrap();
                assert_eq!(jobs.len(), limit);
                for (index, job) in jobs.iter().enumerate() {
                    assert_eq!(job["job_id"], format!("job-{:03}", 204 - index));
                }
                let newest = &jobs[0];
                assert_eq!(newest["capacity_released"], false);
                assert_eq!(newest["gpu_uuid"], "fixture-gpu");
                assert_eq!(newest["output_sha256"], sha256_hex(b"fixture output"));
                assert_eq!(newest["error_code"], "uncertain");
            }
            for query in ["limit=0","limit=201","limit=-1","limit=bad","limit=1.0","limit=",
                "limit=3&limit=3","state=running&state=failed","state=","capability=+","worker_id=%09",
                "capability=echo&capability=echo","worker_id=a&worker_id=b","unknown=x","actor=actor","project=project"] {
                let (status, body) = response_json(fleet_request(&app, "GET", &format!("/jobs?{query}"), "fixture", None, "").await).await;
                assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{query}");
                assert_eq!(body["error"]["code"], "invalid_request");
            }
            let mut encoded = reqwest::Url::parse("http://fixture.invalid").unwrap();
            encoded.query_pairs_mut().append_pair("capability", LITERAL);
            let cap = encoded.query().unwrap();
            for filters in [
                "state=failed_uncertain".to_string(), "worker_id=worker-b".to_string(), cap.to_string(),
                format!("state=failed_uncertain&worker_id=worker-b&{cap}"),
            ] {
                let body = read_json(fleet_request(&app, "GET", &format!("/jobs?limit=1&{filters}"), "fixture", None, "").await).await;
                assert_eq!(body["jobs"], json!([{
                    "job_id":"literal", "idempotency_key":"literal", "actor":"actor", "project":"project",
                    "capability":LITERAL, "worker_id":"worker-b", "gpu_uuid":null, "state":"failed_uncertain",
                    "output_sha256":null, "error_code":null, "capacity_released":true,
                    "created_at_ms":1, "updated_at_ms":2
                }]));
            }
            for query in ["state=unfamiliar", "state=succeeded&worker_id=worker-b"] {
                let body = read_json(fleet_request(&app, "GET", &format!("/jobs?{query}"), "fixture", None, "").await).await;
                assert_eq!(body["jobs"], json!([]));
            }
        });
        drop(app);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_drain_resume_preserves_legacy_and_requires_admin() {
        const DRAIN: &str = "/workers/worker/drain";
        let (root, state, _) = open_state("drain-rest");
        seed_token(&state, "scoped", "a", "p", false, false);
        let app = mounted_fleet(&root, true);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            enroll_fixture(&app, SESSION).await;
            let first = worker_admission(&state);
            let body =
                read_json(fleet_request(&app, "POST", DRAIN, "fixture", None, "").await).await;
            assert_eq!(
                body,
                json!({"ok":true,"worker_id":"worker","status":"draining"})
            );
            for (json_body, expected) in [
                ("{}", "draining"),
                ("{\"accepting\":false}", "draining"),
                ("{\"accepting\":true}", "active"),
                ("{\"accepting\":true}", "active"),
            ] {
                let response = fleet_request(
                    &app,
                    "POST",
                    DRAIN,
                    "fixture",
                    Some("application/json"),
                    json_body,
                )
                .await;
                assert_eq!(read_json(response).await["status"], expected);
            }
            for token in ["", "bad", "scoped"] {
                let (status, body) =
                    response_json(fleet_request(&app, "POST", DRAIN, token, None, "invalid").await)
                        .await;
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(body["error"]["code"], "auth_required");
                assert_eq!(worker_admission(&state), first);
            }
            for raw in [
                "null",
                "[]",
                "[true]",
                "{",
                "{} {}",
                "{\"accepting\":null}",
                "{\"accepting\":1}",
                "{\"drain\":false}",
                "{\"accepting\":true,\"accepting\":false}",
            ] {
                let response = fleet_request(
                    &app,
                    "POST",
                    DRAIN,
                    "fixture",
                    Some("application/json"),
                    raw,
                )
                .await;
                assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{raw}");
            }
            assert_eq!(
                fleet_request(&app, "POST", DRAIN, "fixture", Some("text/plain"), "{}")
                    .await
                    .status(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE
            );
            let size_limit = " ".repeat(MAX_DRAIN_BODY_BYTES - 2) + "{}";
            assert_eq!(
                fleet_request(
                    &app,
                    "POST",
                    DRAIN,
                    "fixture",
                    Some("application/json"),
                    size_limit.clone()
                )
                .await
                .status(),
                StatusCode::OK
            );
            assert_eq!(
                fleet_request(
                    &app,
                    "POST",
                    DRAIN,
                    "fixture",
                    Some("application/json"),
                    size_limit + " "
                )
                .await
                .status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
            let (status, body) = response_json(
                fleet_request(&app, "POST", "/workers/missing/drain", "fixture", None, "").await,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(body["error"]["code"], "worker_not_found");
            assert_eq!(worker_admission(&state), ("draining".into(), true, first.2));
            state
                .db
                .lock()
                .unwrap()
                .execute("UPDATE fleet_workers SET last_heartbeat_ms=0", [])
                .unwrap();
            let resume =
                fleet_json(&app, "POST", DRAIN, "fixture", json!({"accepting":true})).await;
            assert_eq!(read_json(resume).await["status"], "active");
            let workers =
                read_json(fleet_request(&app, "GET", "/workers", "fixture", None, "").await).await;
            assert_eq!(workers["workers"][0]["accepting"], false);
            assert_eq!(worker_admission(&state), ("active".into(), false, 0));
        });
        drop(app);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_drain_persists_across_enrollment_and_preserves_quarantine() {
        const NEXT_SESSION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const FINAL_SESSION: &str = "cccccccccccccccccccccccccccccccc";
        const DRAIN: &str = "/workers/worker/drain";
        let (root, state, headers) = open_state("drain-persist");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let app = mounted_fleet(&root, true);
        runtime.block_on(enroll_fixture(&app, SESSION));
        drop(app);
        state
            .db
            .lock()
            .unwrap()
            .execute_batch(
                "ALTER TABLE fleet_workers DROP COLUMN operator_drained;
             UPDATE fleet_workers SET status='draining';",
            )
            .unwrap();
        let app = mounted_fleet(&root, true);
        assert!(worker_admission(&state).1);
        drop(app);
        // A second startup must leave an existing flag alone.
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE fleet_workers SET operator_drained=0", [])
            .unwrap();
        let app = mounted_fleet(&root, true);
        assert!(!worker_admission(&state).1);
        let auth = state.authenticate(&headers).unwrap();
        let req: SubmitJobRequest =
            serde_json::from_value(json!({"capability":"fixture"})).unwrap();
        runtime.block_on(async {
            assert_eq!(
                fleet_request(&app, "POST", DRAIN, "fixture", None, "")
                    .await
                    .status(),
                StatusCode::OK
            );
            let heartbeat = fleet_json(
                &app,
                "POST",
                "/workers/worker/heartbeat",
                "fixture",
                json!({}),
            )
            .await;
            assert_eq!(heartbeat.status(), StatusCode::OK);
            assert_eq!(worker_admission(&state).0, "draining");
            assert_eq!(enroll_fixture(&app, SESSION).await["status"], "draining");
            assert_eq!(
                enroll_fixture(&app, NEXT_SESSION).await["status"],
                "draining"
            );
            assert_eq!(
                fleet_json(&app, "POST", DRAIN, "fixture", json!({"accepting":true}))
                    .await
                    .status(),
                StatusCode::OK
            );
            let PrepareOutcome::Fresh(job) = prepare_job(&state, &auth, "first", &req).unwrap()
            else {
                panic!("expected fresh reservation");
            };
            let reserved = worker_reserved(&state);
            assert!(reserved.0 > 0 && reserved.1 > 0);
            let before = worker_admission(&state);
            assert_eq!(
                fleet_request(&app, "POST", DRAIN, "fixture", None, "")
                    .await
                    .status(),
                StatusCode::OK
            );
            assert_eq!(worker_admission(&state).2, before.2);
            assert!(matches!(
                prepare_job(&state, &auth, "blocked", &req),
                Err((_, "capability_unavailable", _))
            ));
            assert_eq!(
                get_job_inner(&state, &auth, &job.job_id, false).unwrap()["state"],
                "running"
            );
            assert_eq!(
                enroll_fixture(&app, NEXT_SESSION).await["status"],
                "draining"
            );
            assert_eq!(worker_reserved(&state), reserved);
            let success = WorkerOutcome {
                state: "succeeded",
                output: Value::Null,
                output_sha256: None,
                error_code: None,
                cleanup_ok: true,
            };
            finish_job(&state, &job, &success, false).unwrap();
            assert_eq!(worker_reserved(&state), (0, 0, 0));
            assert_eq!(
                get_job_inner(&state, &auth, &job.job_id, false).unwrap()["state"],
                "succeeded"
            );
            assert_eq!(worker_admission(&state).0, "draining");

            assert_eq!(
                fleet_json(&app, "POST", DRAIN, "fixture", json!({"accepting":true}))
                    .await
                    .status(),
                StatusCode::OK
            );
            let PrepareOutcome::Fresh(job) =
                prepare_job(&state, &auth, "cleanup-failure", &req).unwrap()
            else {
                panic!("expected fresh reservation");
            };
            let reserved = worker_reserved(&state);
            let failure = WorkerOutcome {
                state: "failed_uncertain",
                output: Value::Null,
                output_sha256: None,
                error_code: Some("fixture_cleanup_failure".into()),
                cleanup_ok: false,
            };
            finish_job(&state, &job, &failure, false).unwrap();
            assert_eq!(worker_admission(&state).0, "quarantined");
            assert!(!worker_admission(&state).1);
            assert_eq!(
                enroll_fixture(&app, NEXT_SESSION).await["status"],
                "quarantined"
            );
            assert_eq!(worker_reserved(&state), reserved);
            let (status, body) = response_json(
                fleet_json(&app, "POST", DRAIN, "fixture", json!({"accepting":true})).await,
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body["error"]["code"], "worker_quarantined");
            assert!(!worker_admission(&state).1);
            let drained =
                read_json(fleet_request(&app, "POST", DRAIN, "fixture", None, "").await).await;
            assert_eq!(drained["status"], "quarantined");
            assert!(worker_admission(&state).1);
            assert_eq!(
                enroll_fixture(&app, FINAL_SESSION).await["status"],
                "draining"
            );
            assert_eq!(worker_reserved(&state), (0, 0, 0));
            assert!(worker_admission(&state).1);
            assert_eq!(
                fleet_json(&app, "POST", DRAIN, "fixture", json!({"accepting":true}))
                    .await
                    .status(),
                StatusCode::OK
            );
            let PrepareOutcome::Fresh(job) =
                prepare_job(&state, &auth, "drained-cleanup-failure", &req).unwrap()
            else {
                panic!("expected fresh reservation");
            };
            assert_eq!(
                fleet_request(&app, "POST", DRAIN, "fixture", None, "")
                    .await
                    .status(),
                StatusCode::OK
            );
            finish_job(&state, &job, &failure, false).unwrap();
            let (status, drained, _) = worker_admission(&state);
            assert_eq!(status, "quarantined");
            assert!(drained);
            assert_eq!(enroll_fixture(&app, SESSION).await["status"], "draining");
            assert_eq!(worker_reserved(&state), (0, 0, 0));
        });
        drop(app);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mcp_ping_initialized_and_rpc_errors() {
        let (root, state, _) = open_state("mcp-rpc");
        let app = mounted_fleet(&root, true);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for (requested, negotiated) in [
                ("2025-11-25", "2025-11-25"),
                ("2025-06-18", "2025-06-18"),
                ("2024-11-05", "2025-11-25"),
                ("unknown", "2025-11-25"),
            ] {
                let initialize = rpc(&app, "fixture", json!({
                    "jsonrpc":"2.0","id":"init","method":"initialize",
                    "params":{"protocolVersion":requested,"capabilities":{},
                    "clientInfo":{"name":"fixture-client","version":"1"}}
                })).await;
                assert_eq!(initialize, json!({"jsonrpc":"2.0","id":"init","result":{
                    "protocolVersion":negotiated,"serverInfo":{"name":"diffuser-fleet","version":env!("CARGO_PKG_VERSION")},
                    "capabilities":{"tools":{}}
                }}));
            }
            let initialized = rpc(&app, "fixture", json!({"jsonrpc":"2.0","id":4,"method":"notifications/initialized","params":{}})).await;
            assert_eq!(initialized, json!({"jsonrpc":"2.0","id":4,"error":{"code":-32600,"message":"initialized must be a notification"}}));
            let ping = rpc(&app, "fixture", json!({"jsonrpc":"2.0","id":-8,"method":"ping"})).await;
            assert_eq!(ping, json!({"jsonrpc":"2.0","id":-8,"result":{}}));
            enroll_fixture(&app, SESSION).await;
            for notification in [
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
                json!({"jsonrpc":"2.0","method":"unknown","params":{}}),
                json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"fleet_drain_worker","arguments":{"worker_id":"worker"}}}),
            ] {
                let response = fleet_json(&app, "POST", "/mcp", "fixture", notification).await;
                assert_eq!(response.status(), StatusCode::ACCEPTED);
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert!(axum::body::to_bytes(response.into_body(), 1024).await.unwrap().is_empty());
            }
            for notification in [
                json!({"jsonrpc":"2.0","method":"notifications/initialized","params":true}),
                json!({"jsonrpc":"2.0","method":"unknown","params":null}),
            ] {
                let response = fleet_json(&app, "POST", "/mcp", "fixture", notification).await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                assert!(axum::body::to_bytes(response.into_body(), 1024).await.unwrap().is_empty());
            }
            assert_eq!(worker_admission(&state).0, "active");
            for raw in ["{", "[] []", "\"unterminated"] {
                let response = fleet_request(&app, "POST", "/mcp", "fixture", Some("application/json"), raw).await;
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let body = read_json(response).await;
                assert_eq!(body["error"]["code"], -32700);
                assert_eq!(body["id"], Value::Null);
            }
            for invalid in [
                json!([]), json!(null), json!({"method":"ping","id":1}),
                json!({"jsonrpc":"1.0","method":"ping","id":1}),
                json!({"jsonrpc":"2.0","method":"","id":1}),
                json!({"jsonrpc":"2.0","method":"ping","id":null}),
                json!({"jsonrpc":"2.0","method":"ping","id":1.5}),
                json!({"jsonrpc":"2.0","method":"ping","id":true}),
            ] {
                let body = rpc(&app, "fixture", invalid).await;
                assert_eq!(body["id"], Value::Null);
                assert_eq!(body["error"]["code"], -32600);
            }
            let unknown = rpc(&app, "fixture", json!({"jsonrpc":"2.0","id":"unknown","method":"unknown"})).await;
            assert_eq!(unknown["error"]["code"], -32601);
            assert_eq!(unknown["id"], "unknown");
            for (method, params) in [
                ("ping", json!({"extra":true})), ("initialize", json!(null)),
                ("initialize", json!({})),
                ("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{}})),
                ("tools/list", json!({"cursor":"unused"})),
                ("tools/call", json!({"name":"fleet_discover","arguments":false})),
                ("tools/call", json!({"name":"fleet_get_job","arguments":{}})),
                ("notifications/initialized", json!([])), ("tools/list", json!(true)), ("tools/call", json!([])),
                ("tools/call", json!({})), ("tools/call", json!({"name":"  "})),
                ("tools/call", json!({"name":"not_a_tool","arguments":false})),
            ] {
                let body = rpc(&app, "fixture", json!({"jsonrpc":"2.0","id":2,"method":method,"params":params})).await;
                assert_eq!(body["error"]["code"], -32602);
                assert_eq!(body["id"], 2);
                assert_eq!(body["jsonrpc"], "2.0");
                assert!(body.get("result").is_none());
                assert!(body["error"]["message"].is_string());
            }
            for method in ["initialize", "notifications/initialized", "ping", "tools/list", "tools/call"] {
                let response = fleet_json(&app, "POST", "/mcp", "", json!({"jsonrpc":"2.0","method":method})).await;
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
                assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            }
            assert_eq!(fleet_request(&app, "POST", "/mcp", "fixture", Some("text/plain"), "{}").await.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(fleet_request(&app, "POST", "/mcp", "fixture", Some("application/json"), " ".repeat(1024 * 1024 + 1)).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
        });
        drop(app);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mcp_streamable_http_transport_contract() {
        let (root, state, _) = open_state("mcp-transport");
        fs::write(
            root.join("controller.json"),
            json!({
                "admin_token_sha256": sha256_hex(b"fixture"),
                "mcp_allowed_origins": ["https://fleet.example.test"]
            })
            .to_string(),
        )
        .unwrap();
        let app = mounted_fleet(&root, true);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use tower::ServiceExt;
            for (version, origin, status) in [
                ("2025-11-25", "https://fleet.example.test", StatusCode::OK),
                ("2025-06-18", "http://localhost:5820", StatusCode::OK),
                ("2025-11-25", "http://127.0.0.1:5820", StatusCode::OK),
                (
                    "2025-11-25",
                    "https://unconfigured.example.test",
                    StatusCode::FORBIDDEN,
                ),
                (
                    "unsupported",
                    "https://fleet.example.test",
                    StatusCode::BAD_REQUEST,
                ),
            ] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/v1/fleet/mcp")
                            .header(header::AUTHORIZATION, "Bearer fixture")
                            .header(header::ORIGIN, origin)
                            .header(header::CONTENT_TYPE, "application/json")
                            .header(header::ACCEPT, "application/json, text/event-stream")
                            .header("MCP-Protocol-Version", version)
                            .body(Body::from(
                                json!({"jsonrpc":"2.0","id":7,"method":"tools/list"}).to_string(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), status);
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                if status == StatusCode::OK {
                    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
                    let body = read_json(response).await;
                    assert_eq!(body["id"], 7);
                    assert_eq!(body["jsonrpc"], "2.0");
                    assert_eq!(body["result"]["tools"].as_array().unwrap().len(), 9);
                    assert!(body.get("error").is_none());
                }
            }
            for method in ["GET", "DELETE"] {
                for (token, status) in [
                    ("", StatusCode::UNAUTHORIZED),
                    ("fixture", StatusCode::METHOD_NOT_ALLOWED),
                ] {
                    let response = fleet_request(&app, method, "/mcp", token, None, "").await;
                    assert_eq!(response.status(), status);
                }
            }
        });
        drop(app);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mcp_fleet_tools_share_rest_scope_and_admin_mutations() {
        let (root, state, _) = open_state("mcp-tools");
        seed_token(&state, "scoped", "owner", "project", false, false);
        seed_job(
            &state,
            "owned",
            ("owner", "project"),
            ("elsewhere", "other"),
            "succeeded",
            1,
        );
        seed_job(
            &state,
            "foreign",
            ("owner", "other-project"),
            ("elsewhere", "other"),
            "succeeded",
            2,
        );
        let app = mounted_fleet(&root, true);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            enroll_fixture(&app, SESSION).await;
            let admin = "fixture";
            let scoped = "scoped";
            let list = json!({"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}});
            let catalog = rpc(&app, scoped, list.clone()).await;
            assert_eq!(catalog, rpc(&app, admin, list).await);
            let tools = catalog["result"]["tools"].as_array().unwrap();
            assert_eq!(catalog["jsonrpc"], "2.0");
            assert_eq!(catalog["id"], 11);
            assert!(catalog.get("error").is_none());
            for entry in tools {
                assert!(jsonschema::validator_for(&entry["inputSchema"]).is_ok());
            }
            let names = tools.iter().map(|entry| entry["name"].as_str().unwrap()).collect::<Vec<_>>();
            assert_eq!(names, ["fleet_discover", "fleet_list_workers", "fleet_submit_job", "fleet_get_job", "fleet_issue_token",
                "fleet_list_jobs", "fleet_drain_worker", "fleet_revoke_token", "fleet_list_tokens"]);
            assert_eq!(tools[2]["inputSchema"]["required"], json!(["capability", "idempotency_key"]));
            assert_eq!(tools[2]["inputSchema"]["properties"]["timeout_secs"]["maximum"], 21600);
            assert_eq!(tools[3]["inputSchema"]["required"], json!(["job_id"]));
            assert_eq!(tools[4]["inputSchema"]["required"], json!(["actor", "project", "allowed_capabilities"]));
            for entry in &tools[5..] {
                assert_eq!(entry["inputSchema"]["type"], "object");
                assert_eq!(entry["inputSchema"]["additionalProperties"], false);
            }
            assert_eq!(tools[5]["inputSchema"]["properties"]["limit"], json!({"type":"integer","minimum":1,"maximum":200,"default":50}));
            assert_eq!(tools[6]["inputSchema"]["properties"]["accepting"], json!({"type":"boolean","default":false}));
            assert_eq!(tools[6]["inputSchema"]["required"], json!(["worker_id"]));
            assert_eq!(tools[7]["inputSchema"]["required"], json!(["token_id"]));
            assert_eq!(tools[8]["inputSchema"]["properties"], json!({
                "limit": {"type":"integer","minimum":1,"maximum":200,"default":50},
                "include_revoked": {"type":"boolean","default":true}
            }));
            for token in [admin, scoped] {
                let rest = read_json(fleet_request(&app, "GET", "/jobs?state=succeeded", token, None, "").await).await;
                let mcp = tool(&app, token, "fleet_list_jobs", json!({"state":"succeeded"})).await;
                assert_eq!(mcp["result"]["content"][0]["type"], "text");
                assert_eq!(mcp_tool(&mcp), rest);
                let omitted = rpc(&app, token, json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fleet_list_jobs"}})).await;
                assert_eq!(mcp_tool(&omitted), rest);
            }

            for (name, invalid) in [
                ("fleet_list_jobs", json!(null)), ("fleet_list_jobs", json!([])), ("fleet_list_jobs", json!({"actor":"owner"})),
                ("fleet_list_jobs", json!({"limit":null})), ("fleet_list_jobs", json!({"limit":"1"})),
                ("fleet_list_jobs", json!({"limit":201})), ("fleet_list_jobs", json!({"limit":1.0})),
                ("fleet_list_jobs", json!({"state":null})), ("fleet_list_jobs", json!({"worker_id":1})),
                ("fleet_list_jobs", json!({"capability":"  "})), ("fleet_drain_worker", json!({"worker_id":" "})),
                ("fleet_drain_worker", json!({"worker_id":"worker","accepting":null})),
                ("fleet_drain_worker", json!({"worker_id":"worker","accepting":"true"})),
                ("fleet_drain_worker", json!({"worker_id":"worker","drain":false})),
                ("fleet_revoke_token", json!({"token_id":null})), ("fleet_revoke_token", json!({})),
            ] {
                assert_eq!(tool(&app, admin, name, invalid).await["error"]["code"], -32602, "{name}");
            }
            for (name, args) in [("fleet_drain_worker", json!({"worker_id":"worker"})),
                ("fleet_revoke_token", json!({"token_id":scoped})), ("fleet_drain_worker", json!(null)),
                ("fleet_revoke_token", json!({"token_id":"unknown"}))] {
                let denied = tool(&app, scoped, name, args).await;
                assert_eq!(denied["error"], json!({"code":-32000,"message":"admin_required"}));
            }
            assert_eq!(worker_admission(&state).0, "active");
            assert_eq!(fleet_request(&app, "GET", "/jobs", scoped, None, "").await.status(), StatusCode::OK);
            for (args, expected) in [(json!({"worker_id":"worker"}), "draining"), (json!({"worker_id":"worker","accepting":true}), "active")] {
                assert_eq!(mcp_tool(&tool(&app, admin, "fleet_drain_worker", args).await),
                    json!({"ok":true,"worker_id":"worker","status":expected}));
                assert_eq!(worker_admission(&state).0, expected);
            }
            state.db.lock().unwrap().execute("UPDATE fleet_workers SET status='quarantined'", []).unwrap();
            for (name, args, code) in [
                ("fleet_drain_worker", json!({"worker_id":"worker","accepting":true}), "worker_quarantined"),
                ("fleet_drain_worker", json!({"worker_id":"missing"}), "worker_not_found"),
                ("fleet_revoke_token", json!({"token_id":"missing"}), "token_not_found"),
            ] {
                let result = tool(&app, admin, name, args).await;
                assert_eq!(result["result"], json!({"isError":true,"content":[{"type":"text","text":code}]}));
            }
            assert_eq!(worker_admission(&state).0, "quarantined");
            for _ in 0..2 {
                let revoked = tool(&app, admin, "fleet_revoke_token", json!({"token_id":scoped})).await;
                assert_eq!(mcp_tool(&revoked), json!({"ok":true,"token_id":scoped,"revoked":true}));
                let (status, body) = response_json(fleet_request(&app, "GET", "/jobs", scoped, None, "").await).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(body["error"]["code"], "auth_expired_or_revoked");
            }
            assert_eq!(read_json(fleet_request(&app, "POST", "/tokens/scoped/revoke", admin, None, "").await).await,
                json!({"ok":true,"token_id":scoped,"revoked":true}));
            let missing = tool(&app, admin, "fleet_get_job", json!({"job_id":"missing"})).await;
            assert_eq!(missing["result"]["isError"], true);
            assert!(missing.get("error").is_none());
            let discovery = tool(&app, admin, "fleet_discover", json!({})).await;
            assert_eq!(discovery["result"]["isError"], false);
            let discovered = mcp_tool(&discovery);
            assert_eq!(discovered["schema_version"], "diffuser-fleet/v1");
            assert_eq!(discovered["capabilities"], json!([]));
            let workers = mcp_tool(&tool(&app, admin, "fleet_list_workers", json!({})).await);
            assert_eq!(workers["workers"][0]["worker_id"], "worker");
            let issued = mcp_tool(&tool(&app, admin, "fleet_issue_token",
                json!({"actor":"issued","project":"p","allowed_capabilities":["fixture"]})).await);
            assert_eq!(issued["actor"], "issued");
            let issued_bearer = issued["token"].as_str().unwrap();
            for name in ["fleet_list_workers", "fleet_issue_token"] {
                let denied = tool(&app, issued_bearer, name, json!({})).await;
                assert_eq!(denied["error"], json!({"code":-32000,"message":"admin_required"}));
            }
            let invalid = tool(&app, admin, "fleet_issue_token", json!({})).await;
            assert_eq!(invalid["error"]["code"], -32602);
            state.db.lock().unwrap().execute("DROP TABLE fleet_jobs", []).unwrap();
            let error = tool(&app, admin, "fleet_list_jobs", json!({})).await;
            assert_eq!(error["error"], json!({"code":-32000,"message":"storage_unavailable"}));
            let (status, body) = response_json(fleet_request(&app, "GET", "/jobs", admin, None, "").await).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body["error"]["code"], "storage_unavailable");
        });
        drop(app);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fleet_ui_headers_redirect_and_closed_routes() {
        let (root, state, _) = open_state("ui");
        let enabled = mounted_fleet(&root, true);
        let closed = mounted_fleet(&root, false);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for bearer in ["", "ignored-fixture"] {
                let response = fleet_request(&enabled, "GET", "/ui", bearer, None, "").await;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
                assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY],
                    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
                assert_eq!(response.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
                assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                assert_eq!(axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
                    include_str!("fleet_ui.html").as_bytes());
            }
            let redirect = fleet_request(&enabled, "GET", "/ui/?discard=yes", "", None, "").await;
            assert_eq!(redirect.status(), StatusCode::PERMANENT_REDIRECT);
            assert_eq!(redirect.headers()[header::LOCATION], "/v1/fleet/ui");
            assert_eq!(redirect.headers()[header::CACHE_CONTROL], "no-store");
            assert!(axum::body::to_bytes(redirect.into_body(), 1024).await.unwrap().is_empty());
            for (method, path) in [("GET","/jobs"), ("GET","/ui"), ("GET","/ui/?discard=yes"), ("POST","/jobs")] {
                let (status, body) = response_json(fleet_request(&closed, method, path, "", None, "").await).await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(body["error"]["code"], "fleet_closed");
            }
        });
        drop(enabled);
        drop(closed);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[derive(Clone)]
    struct HoldState {
        hits: Arc<AtomicUsize>,
        release: tokio::sync::watch::Receiver<bool>,
    }

    async fn handle_hold(State(rt): State<HoldState>) -> Json<Value> {
        rt.hits.fetch_add(1, Ordering::SeqCst);
        let mut release = rt.release.clone();
        while !*release.borrow() {
            if release.changed().await.is_err() {
                break;
            }
        }
        Json(json!({"ok": true, "output": {"echo": "async"}, "cleanup_ok": true}))
    }

    #[test]
    fn async_job_returns_running_then_succeeds_and_replays_without_duplicate_execution() {
        let (root, state, headers) = open_state("async");
        let hits = Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let hold = HoldState {
            hits: hits.clone(),
            release: release_rx,
        };
        let (address, server) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new()
                .route("/v1/fleet-worker/run", post(handle_hold))
                .with_state(hold);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (address, server)
        });

        let enroll = serde_json::from_value(json!({
            "worker_id": "worker", "host": "fixture", "rpc_secret_hex": SECRET, "rpc_session": SESSION,
            "rpc_url": format!("http://{address}"),
            "cpu_millicores": 4000, "ram_bytes": 2000000000, "vram_bytes": 0,
            "capabilities": [{"capability": "fixture", "kind": "exec", "timeout_secs": 60}]
        }))
        .unwrap();
        assert_eq!(
            runtime
                .block_on(handle_enroll(
                    State(state.clone()),
                    headers.clone(),
                    Json(enroll)
                ))
                .status(),
            StatusCode::OK
        );

        let req: SubmitJobRequest = serde_json::from_value(json!({
            "capability": "fixture",
            "input": {"echo": "async"},
            "async": true
        }))
        .unwrap();
        let mut submit_headers = headers.clone();
        submit_headers.insert("idempotency-key", "async-key".parse().unwrap());
        let accepted = runtime.block_on(async {
            let response = handle_submit_job(
                State(state.clone()),
                submit_headers.clone(),
                Json(req.clone()),
            )
            .await;
            read_json(response).await
        });
        assert_eq!(accepted["state"], "running");
        assert_eq!(accepted["idempotent_replay"], false);
        assert_eq!(accepted["capacity_released"], false);
        assert_eq!(accepted["capability"], "fixture");
        assert_eq!(accepted["worker_id"], "worker");
        let job_id = accepted["job_id"].as_str().unwrap().to_string();

        runtime.block_on(async {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while hits.load(Ordering::SeqCst) == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "worker was not called"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let auth = state.authenticate(&headers).unwrap();
        let running = get_job_inner(&state, &auth, &job_id, false).unwrap();
        assert_eq!(running["state"], "running");
        assert_eq!(running["capacity_released"], false);
        assert_eq!(running["worker_id"], "worker");
        assert!(running["created_at_ms"].as_i64().unwrap() > 0);

        let replay = runtime.block_on(async {
            let response =
                handle_submit_job(State(state.clone()), submit_headers.clone(), Json(req)).await;
            read_json(response).await
        });
        assert_eq!(replay["idempotent_replay"], true);
        assert_eq!(replay["job_id"], job_id);
        assert_eq!(replay["state"], "running");
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        release_tx.send(true).unwrap();
        runtime.block_on(async {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let job = get_job_inner(&state, &auth, &job_id, false).unwrap();
                if job["state"] != "running" {
                    assert_eq!(job["state"], "succeeded");
                    assert_eq!(job["output"], json!({"echo": "async"}));
                    assert_eq!(job["capacity_released"], true);
                    assert_eq!(job["error_code"], Value::Null);
                    let digest = job["output_sha256"].as_str().unwrap();
                    assert_eq!(digest.len(), 64);
                    assert!(
                        job["updated_at_ms"].as_i64().unwrap()
                            >= job["created_at_ms"].as_i64().unwrap()
                    );
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "job stayed running: {job}"
                );
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        });

        let listed = runtime.block_on(async {
            let response = handle_get_job(
                State(state.clone()),
                headers.clone(),
                AxPath(job_id.clone()),
                Ok(Query(JobDetailQuery {
                    include_input: false,
                })),
            )
            .await;
            read_json(response).await
        });
        assert_eq!(listed["state"], "succeeded");
        assert_eq!(listed["capacity_released"], true);
        assert_eq!(listed["job_id"], job_id);

        let mcp_get = runtime.block_on(async {
            let response = call_mcp(
                State(state.clone()),
                headers.clone(),
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "fleet_get_job", "arguments": {"job_id": job_id}}
                })),
            )
            .await;
            read_json(response).await
        });
        let via_mcp = mcp_tool(&mcp_get);
        assert_eq!(via_mcp["state"], "succeeded");
        assert_eq!(via_mcp["job_id"], job_id);
        assert_eq!(via_mcp["capacity_released"], true);
        assert_eq!(via_mcp["output"], json!({"echo": "async"}));
        assert_eq!(via_mcp["worker_id"], "worker");

        let issued = issue_token_inner(
            &state,
            &IssueTokenRequest {
                actor: "other".into(),
                project: "other".into(),
                allowed_capabilities: vec!["*".into()],
                max_vram_bytes: default_max_vram(),
                ttl_secs: 60,
            },
        )
        .unwrap();
        let mut foreign = HeaderMap::new();
        foreign.insert(
            "authorization",
            format!("Bearer {}", issued["token"].as_str().unwrap())
                .parse()
                .unwrap(),
        );
        assert_eq!(
            runtime
                .block_on(handle_get_job(
                    State(state.clone()),
                    foreign,
                    AxPath(job_id.clone()),
                    Ok(Query(JobDetailQuery {
                        include_input: false
                    })),
                ))
                .status(),
            StatusCode::FORBIDDEN
        );

        let after = runtime.block_on(async {
            let response = handle_submit_job(
                State(state.clone()),
                submit_headers,
                Json(serde_json::from_value(json!({"capability":"fixture","async":true})).unwrap()),
            )
            .await;
            read_json(response).await
        });
        assert_eq!(after["idempotent_replay"], true);
        assert_eq!(after["job_id"], job_id);
        assert_eq!(after["state"], "succeeded");
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        let mcp_submit = runtime.block_on(async {
            let response = call_mcp(
                State(state.clone()),
                headers.clone(),
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {
                        "name": "fleet_submit_job",
                        "arguments": {
                            "capability": "fixture",
                            "idempotency_key": "mcp-async",
                            "async": true,
                            "input": {"from": "mcp"}
                        }
                    }
                })),
            )
            .await;
            read_json(response).await
        });
        let started = mcp_tool(&mcp_submit);
        assert_eq!(started["state"], "running");
        assert_eq!(started["idempotent_replay"], false);
        assert_eq!(started["capacity_released"], false);
        assert_eq!(started["capability"], "fixture");
        let mcp_job = started["job_id"].as_str().unwrap().to_string();
        runtime.block_on(async {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let job = get_job_inner(&state, &auth, &mcp_job, false).unwrap();
                if job["state"] != "running" {
                    assert_eq!(job["state"], "succeeded");
                    assert_eq!(job["capacity_released"], true);
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "mcp job stayed running"
                );
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        });
        let mcp_replay = runtime.block_on(async {
            let response = call_mcp(
                State(state.clone()),
                headers,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {
                        "name": "fleet_submit_job",
                        "arguments": {
                            "capability": "fixture",
                            "idempotency_key": "mcp-async",
                            "async": true
                        }
                    }
                })),
            )
            .await;
            read_json(response).await
        });
        let replayed = mcp_tool(&mcp_replay);
        assert_eq!(replayed["job_id"], mcp_job);
        assert_eq!(replayed["idempotent_replay"], true);
        assert_eq!(replayed["state"], "succeeded");
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        let reserved: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cpu_reserved FROM fleet_workers WHERE worker_id='worker'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reserved, 0);

        server.abort();
        drop(runtime);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_timeout_above_120_seconds_is_honored() {
        assert_eq!(bounded_timeout_secs(5_400), 5_400);
        assert_eq!(bounded_timeout_secs(21_600), 21_600);
        assert_eq!(bounded_timeout_secs(21_601), 21_600);
        assert_eq!(bounded_timeout_secs(0), 1);
        assert_eq!(rpc_http_timeout(5_400), Duration::from_secs(5_460));
        assert!(rpc_http_timeout(5_400).as_secs() > 120);
        assert_eq!(effective_exec_timeout_secs(Some(5_400), 5_400), 5_400);
        assert_eq!(effective_exec_timeout_secs(None, 5_400), 5_400);
        assert_eq!(effective_exec_timeout_secs(Some(5_400), 60), 60);
        assert_eq!(effective_exec_timeout_secs(Some(30_000), 21_600), 21_600);

        let (root, state, headers) = open_state("timeout");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let worker = Arc::new(WorkerRuntime {
            cfg: serde_json::from_value(json!({
                "worker_id": "worker", "host": "fixture", "bind": "127.0.0.1:0",
                "advertise_url": "http://127.0.0.1", "controller_url": "http://127.0.0.1",
                "enroll_bearer": "fixture", "rpc_secret_hex": SECRET, "auto_detect_gpus": false,
                "profiles": [{
                    "capability": "long",
                    "adapter": {
                        "kind": "exec",
                        "command": ["/bin/sh", "-c", "printf %s \"$DIFFUSER_TIMEOUT_SECS\""],
                        "timeout_secs": 5400
                    }
                }]
            }))
            .unwrap(),
            http: private_http_client()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            rpc_session: SESSION.into(),
            replay: Mutex::default(),
            clock: now_ms,
        });
        let (address, server) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new()
                .route("/v1/fleet-worker/run", post(handle_worker_run))
                .with_state(worker.clone());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (address, server)
        });
        let enroll = serde_json::from_value(json!({
            "worker_id": "worker", "host": "fixture", "rpc_secret_hex": SECRET, "rpc_session": SESSION,
            "rpc_url": format!("http://{address}"),
            "cpu_millicores": 1000, "ram_bytes": 500000000, "vram_bytes": 0,
            "capabilities": [{"capability": "long", "kind": "exec", "timeout_secs": 5400}]
        }))
        .unwrap();
        assert_eq!(
            runtime
                .block_on(handle_enroll(
                    State(state.clone()),
                    headers.clone(),
                    Json(enroll)
                ))
                .status(),
            StatusCode::OK
        );
        let mut submit_headers = headers;
        submit_headers.insert("idempotency-key", "long-key".parse().unwrap());
        let reply = runtime.block_on(async {
            let response = handle_submit_job(
                State(state.clone()),
                submit_headers,
                Json(
                    serde_json::from_value(json!({
                        "capability": "long",
                        "timeout_secs": 5400,
                        "input": {}
                    }))
                    .unwrap(),
                ),
            )
            .await;
            read_json(response).await
        });
        assert_eq!(reply["state"], "succeeded");
        assert_eq!(reply["output"], 5400);
        assert_eq!(reply["capacity_released"], true);

        let direct = execute_profile(
            &worker,
            &WorkerRunRequest {
                job_id: "fjob_cccccccccccccccccccccccccccccccc".into(),
                rpc_session: SESSION.into(),
                issued_at_ms: now_ms(),
                capability: "long".into(),
                gpu_uuid: None,
                input: json!({}),
                timeout_secs: None,
            },
        );
        assert_eq!(direct["ok"], true);
        assert_eq!(direct["output"], 5400);

        server.abort();
        drop(runtime);
        drop(worker);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capacity_released_migration_is_idempotent() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE fleet_jobs(job_id TEXT); INSERT INTO fleet_jobs VALUES ('old');",
        )
        .unwrap();
        add_capacity_released_column(&mut db).unwrap();
        add_capacity_released_column(&mut db).unwrap();
        let released: i64 = db
            .query_row(
                "SELECT capacity_released FROM fleet_jobs WHERE job_id='old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(released, 0);
    }

    #[test]
    fn zero_resource_async_reserves_capacity_and_enforces_inflight_cap() {
        let (root, state, headers) = open_state("zero-cap");
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let hold = HoldState {
            hits: Arc::new(AtomicUsize::new(0)),
            release: release_rx,
        };
        let (address, server) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new()
                .route("/v1/fleet-worker/run", post(handle_hold))
                .with_state(hold);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (address, server)
        });
        let enroll = serde_json::from_value(json!({
            "worker_id": "worker", "host": "fixture", "rpc_secret_hex": SECRET, "rpc_session": SESSION,
            "rpc_url": format!("http://{address}"),
            "cpu_millicores": 8000,
            "ram_bytes": 8 * 1024 * 1024 * 1024u64,
            "vram_bytes": 0,
            "capabilities": [{"capability": "fixture", "kind": "exec", "timeout_secs": 60}]
        }))
        .unwrap();
        assert_eq!(
            runtime
                .block_on(handle_enroll(
                    State(state.clone()),
                    headers.clone(),
                    Json(enroll)
                ))
                .status(),
            StatusCode::OK
        );

        let zero_req = json!({
            "capability": "fixture",
            "async": true,
            "cpu_millicores": 0,
            "ram_bytes": 0,
            "min_vram_bytes": 0,
            "input": {}
        });
        runtime.block_on(async {
            for n in 0..MAX_INFLIGHT_PER_ACTOR_PROJECT as usize {
                let mut submit_headers = headers.clone();
                submit_headers.insert("idempotency-key", format!("zero-{n}").parse().unwrap());
                let req: SubmitJobRequest = serde_json::from_value(zero_req.clone()).unwrap();
                let response = handle_submit_job(State(state.clone()), submit_headers, Json(req)).await;
                let accepted = read_json(response).await;
                assert_eq!(accepted["state"], "running");
                assert_eq!(accepted["idempotent_replay"], false);
            }
            let (cpu, ram, vram) = worker_reserved(&state);
            let floor_cpu = MIN_JOB_CPU_MILLICORES as i64;
            let floor_ram = MIN_JOB_RAM_BYTES as i64;
            assert_eq!(cpu, floor_cpu * MAX_INFLIGHT_PER_ACTOR_PROJECT);
            assert_eq!(ram, floor_ram * MAX_INFLIGHT_PER_ACTOR_PROJECT);
            assert!(cpu > 0);
            assert!(ram > 0);
            assert_eq!(vram, 0);

            let mut replay_headers = headers.clone();
            replay_headers.insert("idempotency-key", "zero-0".parse().unwrap());
            let replay_req: SubmitJobRequest = serde_json::from_value(zero_req.clone()).unwrap();
            let replay = read_json(
                handle_submit_job(State(state.clone()), replay_headers, Json(replay_req)).await,
            )
            .await;
            assert_eq!(replay["idempotent_replay"], true);
            assert_eq!(replay["state"], "running");
            assert_eq!(worker_reserved(&state).0, floor_cpu * MAX_INFLIGHT_PER_ACTOR_PROJECT);

            let mut overflow_headers = headers.clone();
            overflow_headers.insert("idempotency-key", "zero-overflow".parse().unwrap());
            let overflow_req: SubmitJobRequest = serde_json::from_value(zero_req.clone()).unwrap();
            let (status, body) = response_json(
                handle_submit_job(State(state.clone()), overflow_headers, Json(overflow_req)).await,
            )
            .await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(body["error"]["code"], "capacity_exhausted");
            let running: i64 = state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM fleet_jobs WHERE actor='admin' AND project='default' AND state='running'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(running, MAX_INFLIGHT_PER_ACTOR_PROJECT);
            assert_eq!(worker_reserved(&state).0, floor_cpu * MAX_INFLIGHT_PER_ACTOR_PROJECT);

            let issued = issue_token_inner(
                &state,
                &IssueTokenRequest {
                    actor: "other".into(),
                    project: "side".into(),
                    allowed_capabilities: vec!["fixture".into()],
                    max_vram_bytes: default_max_vram(),
                    ttl_secs: 60,
                },
            )
            .unwrap();
            let mut other_headers = HeaderMap::new();
            other_headers.insert(
                "authorization",
                format!("Bearer {}", issued["token"].as_str().unwrap())
                    .parse()
                    .unwrap(),
            );
            other_headers.insert("idempotency-key", "other-zero".parse().unwrap());
            let other_req: SubmitJobRequest = serde_json::from_value(zero_req).unwrap();
            let other = read_json(
                handle_submit_job(State(state.clone()), other_headers, Json(other_req)).await,
            )
            .await;
            assert_eq!(other["state"], "running");
            assert_eq!(
                worker_reserved(&state).0,
                floor_cpu * (MAX_INFLIGHT_PER_ACTOR_PROJECT + 1)
            );
            let (status, _) = response_json(
                handle_submit_job(
                    State(state.clone()),
                    {
                        let mut again = headers.clone();
                        again.insert("idempotency-key", "zero-overflow-2".parse().unwrap());
                        again
                    },
                    Json(serde_json::from_value(json!({
                        "capability": "fixture",
                        "async": true,
                        "cpu_millicores": 0,
                        "ram_bytes": 0,
                        "min_vram_bytes": 0
                    }))
                    .unwrap()),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        });

        release_tx.send(true).unwrap();
        runtime.block_on(async {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let (cpu, ram, vram) = worker_reserved(&state);
                let running: i64 = state
                    .db
                    .lock()
                    .unwrap()
                    .query_row(
                        "SELECT COUNT(*) FROM fleet_jobs WHERE state='running'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                if running == 0 && cpu == 0 && ram == 0 && vram == 0 {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "zero-resource jobs stayed running={running} cpu={cpu} ram={ram}"
                );
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        });

        server.abort();
        drop(runtime);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sync_submit_drop_still_finishes_and_releases_capacity() {
        let (root, state, headers) = open_state("sync-cancel");
        let hits = Arc::new(AtomicUsize::new(0));
        let (release_tx, release_rx) = tokio::sync::watch::channel(false);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let hold = HoldState {
            hits: hits.clone(),
            release: release_rx,
        };
        let (address, server) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new()
                .route("/v1/fleet-worker/run", post(handle_hold))
                .with_state(hold);
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (address, server)
        });
        let enroll = serde_json::from_value(json!({
            "worker_id": "worker", "host": "fixture", "rpc_secret_hex": SECRET, "rpc_session": SESSION,
            "rpc_url": format!("http://{address}"),
            "cpu_millicores": 4000, "ram_bytes": 2000000000, "vram_bytes": 0,
            "capabilities": [{"capability": "fixture", "kind": "exec", "timeout_secs": 60}]
        }))
        .unwrap();
        assert_eq!(
            runtime
                .block_on(handle_enroll(
                    State(state.clone()),
                    headers.clone(),
                    Json(enroll)
                ))
                .status(),
            StatusCode::OK
        );

        let req: SubmitJobRequest = serde_json::from_value(json!({
            "capability": "fixture",
            "async": false,
            "cpu_millicores": 500,
            "ram_bytes": 128 * 1024 * 1024u64,
            "input": {"hold": true}
        }))
        .unwrap();
        let mut submit_headers = headers;
        submit_headers.insert("idempotency-key", "sync-cancel".parse().unwrap());
        runtime.block_on(async {
            let state_submit = state.clone();
            let headers_submit = submit_headers.clone();
            let req_submit = req.clone();
            let client = tokio::spawn(async move {
                handle_submit_job(State(state_submit), headers_submit, Json(req_submit)).await
            });
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while hits.load(Ordering::SeqCst) == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "worker was not called"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let (cpu, ram, _) = worker_reserved(&state);
            assert_eq!(cpu, 500);
            assert_eq!(ram, 128 * 1024 * 1024);
            let (job_state, released): (String, i64) = state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT state, capacity_released FROM fleet_jobs",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(job_state, "running");
            assert_eq!(released, 0);

            client.abort();
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                hits.load(Ordering::SeqCst),
                1,
                "dispatch was cancelled with the client"
            );
            let (still, _): (String, i64) = state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT state, capacity_released FROM fleet_jobs",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(still, "running");

            release_tx.send(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let (job_state, released): (String, i64) = state
                    .db
                    .lock()
                    .unwrap()
                    .query_row(
                        "SELECT state, capacity_released FROM fleet_jobs",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let (cpu, ram, vram) = worker_reserved(&state);
                if job_state != "running" {
                    assert_eq!(job_state, "succeeded");
                    assert_eq!(released, 1);
                    assert_eq!(cpu, 0);
                    assert_eq!(ram, 0);
                    assert_eq!(vram, 0);
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "dropped sync client left job={job_state} cpu={cpu} ram={ram}"
                );
                tokio::time::sleep(Duration::from_millis(15)).await;
            }
        });

        server.abort();
        drop(runtime);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_gpu_telemetry_parses_and_migration_keeps_existing_rows() {
        let sample =
            parse_live_gpu_telemetry("GPU-aaa, 1024, 8192, 10\nGPU-bbb, 2048, 16384, 90\n")
                .unwrap();
        assert_eq!(sample.free_bytes, (1024 + 2048) * 1024 * 1024);
        assert_eq!(sample.util_pct, 90);
        assert_eq!(sample.gpus.len(), 2);
        assert_eq!(sample.gpus[1].uuid, "GPU-bbb");
        let mixed = parse_live_gpu_telemetry("GPU-bad, 10, 20, N/A\nGPU-ok, 30, 40, 7\n").unwrap();
        assert_eq!(mixed.gpus.len(), 1);
        assert_eq!(mixed.util_pct, 7);
        assert_eq!(mixed.free_bytes, 30 * 1024 * 1024);
        assert!(parse_live_gpu_telemetry("").is_none());
        assert!(parse_live_gpu_telemetry("not,a,gpu\n").is_none());
        assert_eq!(effective_vram_bytes(5_000, Some(1_000)), 1_000);
        assert_eq!(effective_vram_bytes(500, Some(9_000)), 500);
        assert_eq!(effective_vram_bytes(500, None), 500);
        assert!(!external_gpu_busy(None));
        assert!(!external_gpu_busy(Some(84)));
        assert!(external_gpu_busy(Some(85)));
        assert!(!external_gpu_busy(Some(101)));

        let root = std::env::temp_dir().join(format!(
            "fleet-live-migrate-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = fs::remove_dir_all(&root);
        crate::private_state::fixture_dir(&root);
        let db_path = root.join("fleet.sqlite");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE fleet_workers(worker_id TEXT PRIMARY KEY, host TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active');
                 INSERT INTO fleet_workers(worker_id, host) VALUES ('old', 'homelab');",
            )
            .unwrap();
        }
        let config = root.join("controller.json");
        fs::write(
            &config,
            json!({
                "admin_token_sha256": sha256_hex(b"fixture"),
                "db_path": db_path,
            })
            .to_string(),
        )
        .unwrap();
        let state = FleetState::open(&config, &root).unwrap();
        let again = FleetState::open(&config, &root).unwrap();
        drop(again);
        let (host, live, util): (String, Option<i64>, Option<i64>) = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT host, live_vram_free_bytes, gpu_util_pct FROM fleet_workers WHERE worker_id='old'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(host, "homelab");
        assert_eq!(live, None);
        assert_eq!(util, None);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scheduler_steers_around_external_gpu_load_and_keeps_exact_pin() {
        let (root, state, headers) = open_state("live-gpu");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let auth = state.authenticate(&headers).unwrap();
        let enroll = |worker_id: &str, session: &str, vram: u64, gpu: &str| {
            serde_json::from_value(json!({
                "worker_id": worker_id,
                "host": "fixture",
                "rpc_secret_hex": SECRET,
                "rpc_session": session,
                "rpc_url": "http://127.0.0.1:9",
                "cpu_millicores": 8000,
                "ram_bytes": 8 * 1024 * 1024 * 1024u64,
                "vram_bytes": vram,
                "gpus": [{"uuid": gpu, "name": "Test", "vram_bytes": vram}],
                "capabilities": [{
                    "capability": "render",
                    "kind": "exec",
                    "gpu_uuid": gpu,
                    "timeout_secs": 60
                }]
            }))
            .unwrap()
        };
        runtime.block_on(async {
            for (worker_id, session, vram, gpu) in [
                (
                    "busy",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    20_000_000_000u64,
                    "GPU-BUSY",
                ),
                (
                    "idle",
                    "cccccccccccccccccccccccccccccccc",
                    8_000_000_000u64,
                    "GPU-IDLE",
                ),
            ] {
                assert_eq!(
                    handle_enroll(
                        State(state.clone()),
                        headers.clone(),
                        Json(enroll(worker_id, session, vram, gpu)),
                    )
                    .await
                    .status(),
                    StatusCode::OK
                );
            }
            let listed =
                read_json(handle_list_workers(State(state.clone()), headers.clone()).await).await;
            let before = &listed["workers"];
            assert_eq!(before[0]["live_vram_free"], Value::Null);
            assert_eq!(before[0]["gpu_util_pct"], Value::Null);
            assert_eq!(before[0]["gpus_live"], Value::Null);
        });

        let beat = |worker_id: &str, body: Value| {
            let state = state.clone();
            let headers = headers.clone();
            let worker_id = worker_id.to_string();
            runtime.block_on(async move {
                assert_eq!(
                    handle_heartbeat(State(state), headers, AxPath(worker_id), Json(body),)
                        .await
                        .status(),
                    StatusCode::OK
                );
            });
        };
        let place = |key: &str, body: Value| {
            let req: SubmitJobRequest = serde_json::from_value(body).unwrap();
            prepare_job(&state, &auth, key, &req)
        };
        let fresh_worker = |key: &str, body: Value| match place(key, body).unwrap() {
            PrepareOutcome::Fresh(job) => job.worker_id,
            PrepareOutcome::Replay(_) => panic!("unexpected replay"),
        };
        let base = json!({"capability": "render", "min_vram_bytes": 0, "input": {}});

        beat(
            "busy",
            json!({
                "live_vram_free_bytes": 16_000_000_000u64,
                "gpu_util_pct": 96,
                "gpus_live": [{
                    "uuid": "GPU-BUSY",
                    "memory_free_bytes": 16_000_000_000u64,
                    "memory_total_bytes": 20_000_000_000u64,
                    "util_pct": 96
                }]
            }),
        );
        beat(
            "idle",
            json!({"live_vram_free_bytes": 8_000_000_000u64, "gpu_util_pct": 3}),
        );
        // An empty heartbeat preserves host aggregates for older workers, but clears per-GPU
        // detail so exact pins cannot reuse stale per-GPU VRAM.
        beat("busy", json!({}));
        let listed = runtime.block_on(async {
            read_json(handle_list_workers(State(state.clone()), headers.clone()).await).await
        });
        let workers = listed["workers"].as_array().unwrap();
        let busy = workers.iter().find(|w| w["worker_id"] == "busy").unwrap();
        let idle = workers.iter().find(|w| w["worker_id"] == "idle").unwrap();
        assert_eq!(busy["live_vram_free"], 16_000_000_000u64);
        assert_eq!(busy["gpu_util_pct"], 96);
        assert!(busy["gpus_live"].is_null());
        assert_eq!(idle["gpu_util_pct"], 3);
        assert_eq!(fresh_worker("steer-util", base.clone()), "idle");

        beat(
            "busy",
            json!({"gpu_util_pct": 84, "live_vram_free_bytes": 16_000_000_000u64}),
        );
        assert_eq!(fresh_worker("util-84", base.clone()), "busy");

        beat(
            "busy",
            json!({"gpu_util_pct": 0, "live_vram_free_bytes": 1_000_000u64}),
        );
        beat(
            "idle",
            json!({"gpu_util_pct": 0, "live_vram_free_bytes": 8_000_000_000u64}),
        );
        let mut low = base.clone();
        low["min_vram_bytes"] = json!(1_000_000_000u64);
        assert_eq!(fresh_worker("steer-vram", low.clone()), "idle");

        beat("idle", json!({"gpu_util_pct": 90}));
        beat(
            "busy",
            json!({"gpu_util_pct": 91, "live_vram_free_bytes": 16_000_000_000u64}),
        );
        match place("all-busy", base.clone()) {
            Err((StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted", _)) => {}
            Err((_, code, _)) => panic!("expected capacity_exhausted, got {code}"),
            Ok(_) => panic!("expected capacity_exhausted, scheduled a job"),
        }

        let mut pin = base.clone();
        pin["pin_gpu_uuid"] = json!("GPU-BUSY");
        assert_eq!(fresh_worker("pin-busy", pin.clone()), "busy");

        beat(
            "busy",
            json!({
                "live_vram_free_bytes": 1_000_000u64,
                "gpu_util_pct": 0,
                "gpus_live": [{
                    "uuid": "GPU-BUSY",
                    "memory_free_bytes": 1_000_000u64,
                    "memory_total_bytes": 20_000_000_000u64,
                    "util_pct": 0
                }]
            }),
        );
        beat(
            "idle",
            json!({"gpu_util_pct": 0, "live_vram_free_bytes": 8_000_000_000u64}),
        );
        let mut pin_low = low.clone();
        pin_low["pin_gpu_uuid"] = json!("GPU-BUSY");
        match place("pin-low", pin_low) {
            Err((StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted", _)) => {}
            Err((_, code, _)) => panic!("pinned GPU should not move, got {code}"),
            Ok(_) => panic!("pinned GPU was moved to another worker"),
        }
        let jobs_on_idle_for_pin: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM fleet_jobs WHERE idempotency_key='pin-low'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(jobs_on_idle_for_pin, 0);

        let mut missing = base.clone();
        missing["pin_gpu_uuid"] = json!("GPU-MISSING");
        match place("pin-missing", missing) {
            Err((_, "capability_unavailable", _)) => {}
            Err((_, code, _)) => panic!("expected exact UUID refusal, got {code}"),
            Ok(_) => panic!("unknown GPU pin was scheduled"),
        }

        beat(
            "busy",
            json!({"live_vram_free_bytes": null, "gpu_util_pct": null, "gpus_live": null}),
        );
        beat(
            "idle",
            json!({"live_vram_free_bytes": null, "gpu_util_pct": null, "gpus_live": null}),
        );
        assert_eq!(fresh_worker("accounting-fallback", base), "busy");

        drop(runtime);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_gpu_uses_its_own_live_vram_not_the_host_sum() {
        let (root, state, headers) = open_state("pin-live-vram");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let auth = state.authenticate(&headers).unwrap();
        let card = 24_000_000_000u64;
        let enroll = serde_json::from_value(json!({
            "worker_id": "dual",
            "host": "fixture",
            "rpc_secret_hex": SECRET,
            "rpc_session": "dddddddddddddddddddddddddddddddd",
            "rpc_url": "http://127.0.0.1:9",
            "cpu_millicores": 8000,
            "ram_bytes": 8 * 1024 * 1024 * 1024u64,
            "vram_bytes": card * 2,
            "gpus": [
                {"uuid": "GPU-A", "name": "A", "vram_bytes": card},
                {"uuid": "GPU-B", "name": "B", "vram_bytes": card}
            ],
            "capabilities": [{
                "capability": "render",
                "kind": "exec",
                "timeout_secs": 60
            }]
        }))
        .unwrap();
        runtime.block_on(async {
            assert_eq!(
                handle_enroll(State(state.clone()), headers.clone(), Json(enroll))
                    .await
                    .status(),
                StatusCode::OK
            );
            assert_eq!(
                handle_heartbeat(
                    State(state.clone()),
                    headers.clone(),
                    AxPath("dual".into()),
                    Json(json!({
                        "live_vram_free_bytes": 21_000_000_000u64,
                        "gpu_util_pct": 4,
                        "gpus_live": [
                            {
                                "uuid": "GPU-A",
                                "memory_free_bytes": 1_000_000_000u64,
                                "memory_total_bytes": card,
                                "util_pct": 4
                            },
                            {
                                "uuid": "GPU-B",
                                "memory_free_bytes": 20_000_000_000u64,
                                "memory_total_bytes": card,
                                "util_pct": 1
                            }
                        ]
                    })),
                )
                .await
                .status(),
                StatusCode::OK
            );
        });
        let place = |key: &str, pin: &str| {
            let req: SubmitJobRequest = serde_json::from_value(json!({
                "capability": "render",
                "min_vram_bytes": 8_000_000_000u64,
                "pin_gpu_uuid": pin,
                "input": {}
            }))
            .unwrap();
            prepare_job(&state, &auth, key, &req)
        };
        match place("pin-a-short", "GPU-A") {
            Err((StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted", _)) => {}
            Err((_, code, _)) => panic!("pinned GPU A should be capacity_exhausted, got {code}"),
            Ok(_) => panic!("pinned GPU A was scheduled from another GPU's free VRAM"),
        }
        let reserved: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM fleet_jobs WHERE idempotency_key='pin-a-short'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reserved, 0);
        match place("pin-b-room", "GPU-B") {
            Ok(PrepareOutcome::Fresh(job)) => assert_eq!(job.worker_id, "dual"),
            Ok(PrepareOutcome::Replay(_)) => panic!("unexpected replay"),
            Err((_, code, _)) => panic!("pinned GPU B has enough live VRAM, got {code}"),
        }
        assert_eq!(
            clamped_live_free_bytes(30_000_000_000, 24_000_000_000),
            24_000_000_000
        );

        // Aggregate-only heartbeat (gpus_live null or empty) must fail closed for an exact pin.
        for (tag, gpus_live_val) in [("null", json!(null)), ("empty", json!([]))] {
            runtime.block_on(async {
                assert_eq!(
                    handle_heartbeat(
                        State(state.clone()),
                        headers.clone(),
                        AxPath("dual".into()),
                        Json(json!({
                            "live_vram_free_bytes": 21_000_000_000u64,
                            "gpu_util_pct": 4,
                            "gpus_live": gpus_live_val
                        })),
                    )
                    .await
                    .status(),
                    StatusCode::OK
                );
            });
            let key = format!("pin-a-agg-{tag}");
            match place(&key, "GPU-A") {
                Err((StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted", _)) => {}
                Err((_, code, _)) => {
                    panic!("aggregate-only pin ({tag}) should be capacity_exhausted, got {code}")
                }
                Ok(_) => {
                    panic!("aggregate-only pin ({tag}) was admitted without per-GPU telemetry")
                }
            }
            let agg_reserved: i64 = state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM fleet_jobs WHERE idempotency_key=?1",
                    [key],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(agg_reserved, 0);
        }

        // Reporting high GPU-A detail followed by a heartbeat that omits gpus_live must clear
        // the prior per-GPU sample and fail closed for an exact pin.
        runtime.block_on(async {
            assert_eq!(
                handle_heartbeat(
                    State(state.clone()),
                    headers.clone(),
                    AxPath("dual".into()),
                    Json(json!({
                        "live_vram_free_bytes": 21_000_000_000u64,
                        "gpu_util_pct": 1,
                        "gpus_live": [
                            {
                                "uuid": "GPU-A",
                                "memory_free_bytes": 20_000_000_000u64,
                                "memory_total_bytes": card,
                                "util_pct": 1
                            },
                            {
                                "uuid": "GPU-B",
                                "memory_free_bytes": 1_000_000_000u64,
                                "memory_total_bytes": card,
                                "util_pct": 4
                            }
                        ]
                    })),
                )
                .await
                .status(),
                StatusCode::OK
            );
            assert_eq!(
                handle_heartbeat(
                    State(state.clone()),
                    headers.clone(),
                    AxPath("dual".into()),
                    Json(json!({
                        "live_vram_free_bytes": 1_000_000_000u64
                    })),
                )
                .await
                .status(),
                StatusCode::OK
            );
        });
        match place("pin-a-omitted-stale", "GPU-A") {
            Err((StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted", _)) => {}
            Err((_, code, _)) => {
                panic!("stale omitted gpus_live pin should be capacity_exhausted, got {code}")
            }
            Ok(_) => panic!("stale omitted gpus_live pin was admitted from old sample"),
        }
        let stale_reserved: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM fleet_jobs WHERE idempotency_key='pin-a-omitted-stale'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stale_reserved, 0);

        drop(runtime);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn health_endpoint_includes_live_fleet_summary_and_preserves_legacy_fields() {
        let root =
            std::env::temp_dir().join(format!("diffuser-fleet-health-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let cfg_path = root.join("fleet.json");
        let admin_token = "dummy-health-test-token";
        fs::write(
            &cfg_path,
            serde_json::to_vec(&json!({
                "admin_token_sha256": sha256_hex(admin_token.as_bytes()),
                "db_path": root.join("fleet.sqlite")
            }))
            .unwrap(),
        )
        .unwrap();

        let (fleet_ns, health) = router_with_health(&cfg_path, &root).unwrap();
        let spine = super::super::Spine {
            root: root.clone(),
            edge: false,
            worker_ports: [0, 0],
            admin: false,
            sequence: Arc::new(Mutex::new(0)),
        };

        let now = now_ms() as i64;
        {
            let conn = health.db.lock().unwrap();
            conn.execute(
                "INSERT INTO fleet_workers (worker_id, host, rpc_url, rpc_secret_hex, cpu_total, ram_total, vram_total, gpus_json, capabilities_json, status, last_heartbeat_ms)
                 VALUES (?1, ?2, ?3, ?4, 4000, 8192, 12000, '[]', ?5, ?6, ?7)",
                params![
                    "w-active",
                    "echo",
                    "http://127.0.0.1:5831",
                    "00",
                    json!([{"capability":"cap.a/v1"},{"capability":"cap.b/v1"}]).to_string(),
                    "active",
                    now
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO fleet_workers (worker_id, host, rpc_url, rpc_secret_hex, cpu_total, ram_total, vram_total, gpus_json, capabilities_json, status, last_heartbeat_ms)
                 VALUES (?1, ?2, ?3, ?4, 4000, 8192, 8000, '[]', ?5, ?6, ?7)",
                params![
                    "w-draining",
                    "warp",
                    "http://127.0.0.1:5832",
                    "00",
                    json!([{"capability":"cap.c/v1"}]).to_string(),
                    "draining",
                    now
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO fleet_workers (worker_id, host, rpc_url, rpc_secret_hex, cpu_total, ram_total, vram_total, gpus_json, capabilities_json, status, last_heartbeat_ms)
                 VALUES (?1, ?2, ?3, ?4, 4000, 8192, 0, '[]', ?5, ?6, ?7)",
                params![
                    "w-offline",
                    "nuc",
                    "http://127.0.0.1:5830",
                    "00",
                    json!([{"capability":"cap.d/v1"}]).to_string(),
                    "active",
                    now - (HEARTBEAT_TTL_MS as i64) - 5_000
                ],
            )
            .unwrap();
        }

        let app = super::super::api_with_fleet_health(
            spine,
            super::super::lane_assignment::router(),
            fleet_ns,
            Some(health),
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let body: Value = rt.block_on(async {
            let resp = tower::ServiceExt::oneshot(
                app,
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        });

        assert_eq!(body["ready"], json!(true));
        assert_eq!(body["version"], json!("0.3.0"));
        assert_eq!(body["profile"], json!("primary"));
        assert!(body["lanes_summary"].is_array());
        assert_eq!(body["fleet"]["enabled"], json!(true));
        assert_eq!(body["fleet"]["fleet_dispatch_allowed"], json!(true));
        assert_eq!(body["fleet"]["workers_total"], json!(3));
        assert_eq!(body["fleet"]["workers_active"], json!(1));
        assert_eq!(body["fleet"]["workers_draining"], json!(1));
        assert_eq!(body["fleet"]["workers_quarantined"], json!(0));
        assert_eq!(body["fleet"]["workers_offline"], json!(1));
        assert_eq!(body["fleet"]["capabilities_count"], json!(2));

        let closed = closed_health_summary();
        assert_eq!(closed["enabled"], json!(false));
        assert_eq!(closed["fleet_dispatch_allowed"], json!(false));

        fs::remove_dir_all(root).unwrap();
    }
}
