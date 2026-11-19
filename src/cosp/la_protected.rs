//! Genuine protected startup for Diffuser controller and CPU/CUDA workers.
//! Activated ONLY when `--protected-config <path>` or `--worker-config <path>`
//! is explicitly supplied. Without it, ordinary startup remains fail-closed
//! (`503 routing_closed`).

use super::{
    la_adapter::{
        cleanup, sign_source_observation, state_custody, worker_rpc_router, AdmissionLease,
        ChannelBinding, ChannelKeys, CustodyLedger, CustodyLink, InventoryContext,
        SignedCheckpoint, SourceAck, TransportJournal, WorkerAdmission, WorkerClient, WorkerRpc,
    },
    la_artifacts, la_auth,
    la_backend::{
        self,
        cuda::{CudaProcess, DeviceUuid},
        Capability,
    },
    la_contract, la_store, la_worker, lane_assignment, Spine,
};
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Deserialize)]
pub(super) struct KeysConfig {
    pub(super) command: String,
    pub(super) reply: String,
    pub(super) authority: String,
    pub(super) custody: String,
}

#[derive(Clone, Deserialize)]
pub(super) struct BindingConfig {
    pub(super) worker: String,
    pub(super) worker_boot: String,
    pub(super) controller_boot: String,
    #[serde(default = "default_one")]
    pub(super) worker_epoch: u64,
    #[serde(default = "default_one")]
    pub(super) controller_epoch: u64,
    #[serde(default = "default_one")]
    pub(super) hardware_generation: u64,
    #[serde(default = "default_one")]
    pub(super) profile_epoch: u64,
    pub(super) source_digest: String,
    pub(super) executable_digest: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub(super) enum BackendConfig {
    Cpu,
    Cuda {
        device_uuid: String,
        helper_path: String,
        helper_sha256: String,
        #[serde(default = "default_cuda_as_bytes")]
        address_space_bytes: u64,
        #[serde(default = "default_cuda_cpu_secs")]
        cpu_secs: u64,
        #[serde(default = "default_cuda_ready_ms")]
        ready_timeout_ms: i32,
        #[serde(default)]
        require_ro_mount: bool,
    },
}

#[derive(Clone, Deserialize)]
pub(super) struct GrantConfig {
    pub(super) id: String,
    pub(super) parent: Option<String>,
    pub(super) actor: String,
    pub(super) bearer_sha256: String,
    #[serde(default = "default_scopes")]
    pub(super) scopes: u64,
    #[serde(default)]
    pub(super) can_delegate: bool,
    #[serde(default = "default_audience")]
    pub(super) audience: String,
    #[serde(default = "default_ttl_ms")]
    pub(super) ttl_ms: u64,
}

#[derive(Clone, Deserialize)]
pub(super) struct ProtectedControllerConfig {
    pub(super) tenant: String,
    pub(super) project: String,
    pub(super) worker_addr: String,
    pub(super) binding: BindingConfig,
    pub(super) keys: KeysConfig,
    pub(super) backend: BackendConfig,
    pub(super) grants: Vec<GrantConfig>,
    #[serde(default = "default_freshness_ms")]
    pub(super) freshness_ms: u64,
}

#[derive(Clone, Deserialize)]
pub(super) struct ProtectedWorkerConfig {
    pub(super) binding: BindingConfig,
    pub(super) keys: KeysConfig,
    pub(super) backend: BackendConfig,
    #[serde(default = "default_lease_ms")]
    pub(super) lease_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct CleanupEvidence {
    worker_root: (u64, u64),
    worker_state_digest: String,
    occupancy_digest: String,
    mac_hex: String,
}

struct WitnessCtx {
    http: reqwest::blocking::Client,
    worker_addr: SocketAddr,
    binding: ChannelBinding,
    keys: ChannelKeys,
    c_root: File,
    ledger: Arc<Mutex<state_custody::Ledger>>,
    authority: lane_assignment::SharedAuthority,
    claims: Arc<Mutex<la_store::ClaimStore>>,
    service_worker: Arc<Mutex<lane_assignment::ServiceWorker>>,
    custody: Arc<state_custody::Session>,
}

fn default_one() -> u64 {
    1
}
fn default_scopes() -> u64 {
    2047
}
fn default_audience() -> String {
    "diffuser".to_string()
}
fn default_ttl_ms() -> u64 {
    86_400_000
}
fn default_freshness_ms() -> u64 {
    1_500
}
fn default_lease_ms() -> u64 {
    300_000
}
fn default_cuda_as_bytes() -> u64 {
    64 * 1024 * 1024 * 1024
}
fn default_cuda_cpu_secs() -> u64 {
    15
}
fn default_cuda_ready_ms() -> i32 {
    10_000
}

fn wall_now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| "clock_untrusted".to_string())
}

fn decode_hex32(label: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim()).map_err(|_| format!("invalid_hex_{label}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("invalid_len_{label}"))?;
    if arr == [0u8; 32] {
        return Err(format!("zero_key_{label}"));
    }
    Ok(arr)
}

fn parse_keys(cfg: &KeysConfig) -> Result<ChannelKeys, String> {
    Ok(ChannelKeys {
        command: decode_hex32("command", &cfg.command)?,
        reply: decode_hex32("reply", &cfg.reply)?,
        authority: decode_hex32("authority", &cfg.authority)?,
        custody: decode_hex32("custody", &cfg.custody)?,
    })
}

fn self_exe_sha256() -> Result<String, String> {
    let bytes = fs::read("/proc/self/exe").map_err(|_| "exe_read_failed".to_string())?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn build_binding(cfg: &BindingConfig) -> Result<ChannelBinding, String> {
    let policy_digest = la_contract::policy_digest("runtime-short-v1")
        .ok_or_else(|| "policy_digest_unavailable".to_string())?;
    let executable_digest = match &cfg.executable_digest {
        Some(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => self_exe_sha256()?,
    };
    Ok(ChannelBinding {
        worker: cfg.worker.clone(),
        worker_boot: cfg.worker_boot.clone(),
        controller_boot: cfg.controller_boot.clone(),
        worker_epoch: cfg.worker_epoch,
        controller_epoch: cfg.controller_epoch,
        hardware_generation: cfg.hardware_generation,
        profile_epoch: cfg.profile_epoch,
        policy_digest,
        source_digest: cfg.source_digest.clone(),
        executable_digest,
    })
}

fn sign_cleanup_evidence(
    key: &[u8; 32],
    worker_root: (u64, u64),
    worker_state_digest: &str,
    occupancy_digest: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(key);
    h.update(b"\0diffuser-protected-cleanup-evidence/v1\0");
    h.update(worker_root.0.to_le_bytes());
    h.update(worker_root.1.to_le_bytes());
    h.update(worker_state_digest.as_bytes());
    h.update(b"\0");
    h.update(occupancy_digest.as_bytes());
    hex::encode(h.finalize())
}

fn attach_local_transport_witness(
    channel: &mut TransportJournal,
    binding: &ChannelBinding,
    role_name: &str,
    role_root: &File,
    custody_root: &File,
    custody_path: &Path,
    keys: &ChannelKeys,
) -> Result<(), String> {
    let ledger = Arc::new(Mutex::new(
        CustodyLedger::bootstrap(
            custody_root,
            custody_path,
            binding.clone(),
            role_name,
            keys.reply,
            keys.custody,
        )
        .map_err(|e| format!("custody_ledger_bootstrap:{e}"))?,
    ));
    let observed = role_root
        .try_clone()
        .map_err(|_| "role_root_clone_failed".to_string())?;
    let slot = Arc::new(Mutex::new(None::<std::sync::Weak<CustodyLink>>));
    let weak = slot.clone();
    let link = CustodyLink::new(
        binding.clone(),
        role_name,
        keys.reply,
        keys.custody,
        Box::new(move |frame| {
            let frame: SignedCheckpoint =
                serde_json::from_slice(frame).map_err(|_| "evidence_invalid")?;
            let ack = ledger
                .lock()
                .map_err(|_| "storage_unavailable")?
                .observe(&observed, &frame)?;
            weak.lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .and_then(|w| w.upgrade())
                .ok_or("storage_unavailable")?
                .accept(&serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?)
        }),
    )
    .map_err(|e| format!("custody_link:{e}"))?;
    *slot.lock().unwrap() = Some(Arc::downgrade(&link));
    channel
        .enable_custody(link)
        .map_err(|e| format!("enable_custody:{e}"))?;
    Ok(())
}

fn attach_local_service_witness(
    binding: &ChannelBinding,
    role_root: &File,
    custody_root: &File,
    keys: &ChannelKeys,
) -> Result<(Arc<state_custody::Session>, Arc<Mutex<state_custody::Ledger>>), String> {
    let ledger = Arc::new(Mutex::new(
        state_custody::Ledger::new(custody_root, binding.clone(), keys)
            .map_err(|e| format!("service_ledger:{e}"))?,
    ));
    let independent = ledger.clone();
    let observed = role_root
        .try_clone()
        .map_err(|_| "role_root_clone_failed".to_string())?;
    let slot = Arc::new(Mutex::new(None::<std::sync::Weak<state_custody::Link>>));
    let weak = slot.clone();
    let link = state_custody::Link::new(
        binding.clone(),
        keys,
        Box::new(move |frame| {
            let frame: state_custody::Checkpoint =
                serde_json::from_slice(frame).map_err(|_| "evidence_invalid")?;
            let ack = independent
                .lock()
                .map_err(|_| "storage_unavailable")?
                .observe(&observed, &frame)?;
            weak.lock()
                .map_err(|_| "storage_unavailable")?
                .as_ref()
                .and_then(|w| w.upgrade())
                .ok_or("storage_unavailable")?
                .accept(&serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?)
        }),
    )
    .map_err(|e| format!("service_link:{e}"))?;
    *slot.lock().unwrap() = Some(Arc::downgrade(&link));
    let session =
        state_custody::Session::create(role_root, link).map_err(|e| format!("service_session:{e}"))?;
    Ok((session, ledger))
}

fn capability_from_config(cfg: &BackendConfig) -> Result<Capability, String> {
    match cfg {
        BackendConfig::Cpu => Ok(Capability::PrivateSha256),
        BackendConfig::Cuda { device_uuid, .. } => {
            let pin = DeviceUuid::parse(device_uuid)
                .ok_or_else(|| "invalid_cuda_device_uuid".to_string())?;
            Ok(Capability::CudaAddOne(pin))
        }
    }
}

impl WitnessCtx {
    fn push_observation(&self, sequence: u64) -> Result<(), String> {
        let now = wall_now_ms()?;
        let bytes = serde_json::to_vec(&json!({
            "schema_version": "diffuser-authority-observation/v1",
            "sequence": sequence,
            "observed_at": now,
            "revoked": []
        }))
        .map_err(|e| format!("obs_json:{e}"))?;
        let frame = sign_source_observation(&self.keys.authority, &self.binding, &bytes)
            .map_err(|e| format!("sign_obs:{e}"))?;
        self.ledger
            .lock()
            .map_err(|_| "ledger_lock".to_string())?
            .record_authority(&frame)
            .map_err(|e| format!("record_authority:{e}"))?;

        let resp = self
            .http
            .post(format!(
                "http://{}/protected/source-observation",
                self.worker_addr
            ))
            .body(frame.clone())
            .send()
            .map_err(|e| format!("worker_obs_post:{e}"))?;
        if !resp.status().is_success() {
            return Err(format!("worker_obs_status:{}", resp.status().as_u16()));
        }
        let worker_ack: SourceAck = resp.json().map_err(|e| format!("worker_obs_json:{e}"))?;

        let controller_ack = lane_assignment::apply_witnessed_protected_source_observation(
            &self.authority,
            &self.claims,
            &self.binding,
            &self.keys,
            &frame,
            Some(&self.service_worker),
            &self.custody,
        )
        .map_err(|e| format!("apply_obs:{e}"))?;

        self.ledger
            .lock()
            .map_err(|_| "ledger_lock".to_string())?
            .observe_authority(&frame, &controller_ack, &worker_ack)
            .map_err(|e| format!("observe_authority:{e}"))?;
        Ok(())
    }

    fn reconcile_cleanups(&self) {
        let pending = match self.claims.lock() {
            Ok(guard) => guard
                .ready_for_cleanup_assignments(&self.binding.worker)
                .unwrap_or_default(),
            Err(_) => return,
        };
        if pending.is_empty() {
            return;
        }
        let resp = match self
            .http
            .get(format!(
                "http://{}/protected/cleanup-evidence",
                self.worker_addr
            ))
            .send()
        {
            Ok(r) if r.status().is_success() => r,
            _ => return,
        };
        let ev: CleanupEvidence = match resp.json() {
            Ok(v) => v,
            Err(_) => return,
        };
        let expected_mac = sign_cleanup_evidence(
            &self.keys.reply,
            ev.worker_root,
            &ev.worker_state_digest,
            &ev.occupancy_digest,
        );
        if ev.mac_hex != expected_mac {
            return;
        }
        for assignment in pending {
            let claim = match self.claims.lock() {
                Ok(guard) => match guard.snapshot_for_cleanup(&assignment) {
                    Ok(c) => c,
                    Err(_) => continue,
                },
                Err(_) => continue,
            };
            let Ok(now) = wall_now_ms() else { continue };
            let Ok(cert) = cleanup::Certificate::issue_protected(
                &self.binding,
                &self.keys,
                &self.c_root,
                ev.worker_root,
                ev.worker_state_digest.clone(),
                ev.occupancy_digest.clone(),
                claim,
                now,
            ) else {
                continue;
            };
            if let Ok(frame) = serde_json::to_vec(&cert) {
                let _ = lane_assignment::apply_witnessed_cleanup(
                    &self.claims,
                    &self.binding,
                    &self.keys,
                    &frame,
                    &self.custody,
                );
            }
        }
    }
}

/// Boot the protected `/v1/diffuser` namespace for `uai-diffuser --protected-config <path>`.
pub(super) fn bootstrap_controller(
    config_path: &Path,
    state_dir: &Path,
) -> Result<Router<Spine>, String> {
    let raw = fs::read_to_string(config_path).map_err(|e| format!("config_read:{e}"))?;
    let cfg: ProtectedControllerConfig =
        serde_json::from_str(&raw).map_err(|e| format!("config_parse:{e}"))?;
    if cfg.grants.is_empty() {
        return Err("grants_empty".to_string());
    }
    let keys = parse_keys(&cfg.keys)?;
    let binding = build_binding(&cfg.binding)?;
    let worker_addr: SocketAddr = cfg
        .worker_addr
        .parse()
        .map_err(|e| format!("worker_addr_invalid:{e}"))?;
    let capability = capability_from_config(&cfg.backend)?;

    unsafe {
        libc::umask(0o077);
    }
    let c_path = state_dir.join("protected-controller");
    let p_path = state_dir.join("protected-custody");
    fs::create_dir_all(&c_path).map_err(|e| format!("mkdir_controller:{e}"))?;
    fs::create_dir_all(&p_path).map_err(|e| format!("mkdir_custody:{e}"))?;
    let c_root =
        la_artifacts::open_owned_root(&c_path).map_err(|e| format!("open_c_root:{e}"))?;
    let p_root =
        la_artifacts::open_owned_root(&p_path).map_err(|e| format!("open_p_root:{e}"))?;

    let now = wall_now_ms()?;
    let mut grants = Vec::with_capacity(cfg.grants.len());
    for g in &cfg.grants {
        let digest = decode_hex32("bearer_sha256", &g.bearer_sha256)?;
        grants.push(la_auth::OwnedAuthorityGrant {
            id: g.id.clone(),
            parent: g.parent.clone(),
            tenant: cfg.tenant.clone(),
            project: cfg.project.clone(),
            actor: g.actor.clone(),
            bearer_digest: digest,
            scopes: g.scopes,
            can_delegate: g.can_delegate,
            enabled: true,
            member: true,
            revoked: false,
            not_before: now.saturating_sub(1_000),
            access_expires: now.saturating_add(g.ttl_ms),
            run_until: now.saturating_add(g.ttl_ms),
            execution_ceiling: now.saturating_add(g.ttl_ms),
            audience: g.audience.clone(),
        });
    }

    let authority: lane_assignment::SharedAuthority =
        Arc::new(RwLock::new(lane_assignment::DiscoveryContext {
            tenant: cfg.tenant.clone(),
            project: cfg.project.clone(),
            grants,
            observed_at: now,
            observation_sequence: 0,
            freshness_ms: cfg.freshness_ms.clamp(500, 6_000),
            inventory_available: true,
            inventory_observed_at: now,
            loss_scope: None,
        }));

    let artifacts =
        la_artifacts::ArtifactStore::open(&c_path).map_err(|e| format!("artifact_store:{e}"))?;
    let claims = Arc::new(Mutex::new(
        la_store::ClaimStore::open(&c_path.join("lane_assignments.sqlite"))
            .map_err(|e| format!("claim_store:{e}"))?,
    ));

    let mut channel =
        TransportJournal::create(&c_root, &c_path, "controller-channel.sqlite", binding.clone())
            .map_err(|e| format!("transport_journal:{e}"))?;
    attach_local_transport_witness(
        &mut channel,
        &binding,
        "controller",
        &c_root,
        &p_root,
        &p_path,
        &keys,
    )?;
    let (custody, ledger) = attach_local_service_witness(&binding, &c_root, &p_root, &keys)?;

    let lease_holder = Arc::new(Mutex::new(Some(AdmissionLease {
        issued_at: now,
        expires_at: now.saturating_add(300_000),
        job_scope: None,
    })));
    let admission = WorkerAdmission(lease_holder.clone());

    let session = la_worker::ReservationSession {
        worker: binding.worker.clone(),
        boot: binding.worker_boot.clone(),
        key: keys.command,
    };

    let rpc = WorkerClient::new_lan(worker_addr, channel, keys.clone())
        .map_err(|e| format!("worker_client:{e}"))?
        .with_protected_admission(admission)
        .with_protected_capability(Some(capability))
        .with_service_custody(custody.clone());

    let (routes, service_worker) = lane_assignment::protected_service_router(
        authority.clone(),
        artifacts,
        claims.clone(),
        rpc,
        session,
    );

    let http = reqwest::blocking::Client::builder()
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("http_client:{e}"))?;

    let ctx = WitnessCtx {
        http,
        worker_addr,
        binding,
        keys,
        c_root: c_root
            .try_clone()
            .map_err(|_| "c_root_clone_failed".to_string())?,
        ledger,
        authority,
        claims,
        service_worker,
        custody: custody.clone(),
    };
    ctx.push_observation(1)?;

    let interval_ms = (cfg.freshness_ms.clamp(500, 6_000) / 3).clamp(300, 1_500);
    std::thread::spawn(move || {
        let mut seq = 1u64;
        loop {
            std::thread::sleep(Duration::from_millis(interval_ms));
            if let Ok(ts) = wall_now_ms() {
                if let Ok(mut lguard) = lease_holder.lock() {
                    if let Some(lease) = lguard.as_mut() {
                        lease.issued_at = ts;
                        lease.expires_at = ts.saturating_add(300_000);
                    }
                }
            }
            seq = seq.saturating_add(1);
            let _ = ctx.push_observation(seq);
            ctx.reconcile_cleanups();
        }
    });

    Ok(lane_assignment::witnessed_namespace(routes, custody))
}

async fn handle_worker_source_observation(
    State(w_state): State<Arc<Mutex<WorkerRpc>>>,
    body: Bytes,
) -> Result<Json<SourceAck>, StatusCode> {
    let ack = w_state
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .observe(&body)
        .map_err(|_| StatusCode::PRECONDITION_FAILED)?;
    Ok(Json(ack))
}

struct WorkerEvidenceState {
    w_state: Arc<Mutex<WorkerRpc>>,
    w_root: File,
    reply_key: [u8; 32],
}

async fn handle_worker_cleanup_evidence(
    State(ev_state): State<Arc<WorkerEvidenceState>>,
) -> Result<Json<CleanupEvidence>, StatusCode> {
    use std::os::unix::fs::MetadataExt;
    let guard = ev_state
        .w_state
        .lock()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if guard.journal.running_command().is_some() {
        return Err(StatusCode::CONFLICT);
    }
    let meta = ev_state
        .w_root
        .metadata()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let worker_root = (meta.dev(), meta.ino());
    let worker_state_digest = state_custody::state_digest(&ev_state.w_root)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let occupancy_digest = hex::encode(Sha256::digest(
        format!(
            "quiescent:{}:{}:{}",
            worker_root.0, worker_root.1, worker_state_digest
        )
        .as_bytes(),
    ));
    let mac_hex = sign_cleanup_evidence(
        &ev_state.reply_key,
        worker_root,
        &worker_state_digest,
        &occupancy_digest,
    );
    Ok(Json(CleanupEvidence {
        worker_root,
        worker_state_digest,
        occupancy_digest,
        mac_hex,
    }))
}

/// Run a standalone protected CPU or CUDA worker (`uai-diffuser --worker-config <path> --bind <ip:port> --state-dir <dir>`).
pub(super) fn run_worker(config_path: &Path, bind: &str, state_dir: &Path) -> i32 {
    if let Err(err) = run_worker_inner(config_path, bind, state_dir) {
        eprintln!("protected_worker_error: {err}");
        return 70;
    }
    0
}

fn run_worker_inner(config_path: &Path, bind: &str, state_dir: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(config_path).map_err(|e| format!("config_read:{e}"))?;
    let cfg: ProtectedWorkerConfig =
        serde_json::from_str(&raw).map_err(|e| format!("config_parse:{e}"))?;
    let keys = parse_keys(&cfg.keys)?;
    let binding = build_binding(&cfg.binding)?;
    let bind_addr: SocketAddr = bind
        .parse()
        .map_err(|e| format!("worker_bind_invalid:{e}"))?;
    let allowed_ip = match bind_addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.octets()[0] == 10,
        std::net::IpAddr::V6(_) => false,
    };
    if !allowed_ip {
        return Err("worker_bind_refused".to_string());
    }

    unsafe {
        libc::umask(0o077);
    }
    let w_path = state_dir.join("protected-worker");
    let p_path = state_dir.join("protected-worker-custody");
    fs::create_dir_all(&w_path).map_err(|e| format!("mkdir_worker:{e}"))?;
    fs::create_dir_all(&p_path).map_err(|e| format!("mkdir_worker_custody:{e}"))?;
    let w_root =
        la_artifacts::open_owned_root(&w_path).map_err(|e| format!("open_w_root:{e}"))?;
    let p_root =
        la_artifacts::open_owned_root(&p_path).map_err(|e| format!("open_p_root:{e}"))?;

    let mut channel =
        TransportJournal::create(&w_root, &w_path, "worker-channel.sqlite", binding.clone())
            .map_err(|e| format!("worker_transport_journal:{e}"))?;
    attach_local_transport_witness(
        &mut channel,
        &binding,
        "worker",
        &w_root,
        &p_root,
        &p_path,
        &keys,
    )?;

    let mut journal = la_worker::OperationJournal::bootstrap(
        &w_path.join("worker.sqlite"),
        "protected_worker_runtime",
    )
    .map_err(|e| format!("worker_journal:{e}"))?;

    match &cfg.backend {
        BackendConfig::Cpu => {
            let helper = la_backend::PrivateProcess::launch()
                .map_err(|e| format!("cpu_helper_launch:{e}"))?;
            journal
                .attach_backend(Box::new(helper))
                .map_err(|e| format!("attach_cpu_backend:{e}"))?;
        }
        BackendConfig::Cuda {
            device_uuid,
            helper_path,
            helper_sha256,
            address_space_bytes,
            cpu_secs,
            ready_timeout_ms,
            require_ro_mount,
        } => {
            let pin = DeviceUuid::parse(device_uuid)
                .ok_or_else(|| "cuda_uuid_invalid".to_string())?;
            let expected_sha = decode_hex32("helper_sha256", helper_sha256)?;
            let artifact = File::open(helper_path)
                .map_err(|e| format!("cuda_helper_open:{e}"))?;
            let helper = CudaProcess::launch_native_configured(
                artifact,
                expected_sha,
                pin,
                *address_space_bytes,
                *cpu_secs,
                *ready_timeout_ms,
                *require_ro_mount,
            )
            .map_err(|e| format!("cuda_helper_launch:{e}"))?;
            journal
                .attach_backend(Box::new(helper))
                .map_err(|e| format!("attach_cuda_backend:{e}"))?;
        }
    }

    let now = wall_now_ms()?;
    let lease_holder = Arc::new(Mutex::new(Some(AdmissionLease {
        issued_at: now,
        expires_at: now.saturating_add(cfg.lease_ms),
        job_scope: None,
    })));
    let admission = WorkerAdmission(lease_holder.clone());
    let refresh_lease = lease_holder;
    let lease_ms = cfg.lease_ms;
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis((lease_ms / 3).clamp(1_000, 30_000)));
        if let Ok(ts) = wall_now_ms() {
            if let Ok(mut guard) = refresh_lease.lock() {
                if let Some(lease) = guard.as_mut() {
                    lease.issued_at = ts;
                    lease.expires_at = ts.saturating_add(lease_ms);
                }
            }
        }
    });

    let reply_key = keys.reply;
    let session = la_worker::ReservationSession {
        worker: binding.worker.clone(),
        boot: binding.worker_boot.clone(),
        key: keys.command,
    };
    let w_state = Arc::new(Mutex::new(WorkerRpc {
        journal,
        session,
        channel,
        keys,
        admission,
    }));
    {
        let mut w = w_state.lock().unwrap();
        let digest = state_custody::state_digest(&w_root)
            .map_err(|e| format!("worker_state_digest:{e}"))?;
        w.channel.set_owned_state(digest);
    }

    let ev_state = Arc::new(WorkerEvidenceState {
        w_state: w_state.clone(),
        w_root: w_root
            .try_clone()
            .map_err(|_| "w_root_clone_failed".to_string())?,
        reply_key,
    });
    let obs_route = Router::new()
        .route(
            "/protected/source-observation",
            post(handle_worker_source_observation),
        )
        .with_state(w_state.clone())
        .merge(
            Router::new()
                .route(
                    "/protected/cleanup-evidence",
                    get(handle_worker_cleanup_evidence),
                )
                .with_state(ev_state),
        );

    let router = worker_rpc_router(
        InventoryContext {
            bearer_digest: [0; 32],
            worker_id: binding.worker,
            boot_id: binding.worker_boot,
            hardware_generation: binding.hardware_generation,
            profile_epoch: binding.profile_epoch,
        },
        w_state,
    )
    .merge(obs_route);

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("tokio_rt:{e}"))?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("worker_bind:{e}"))?;
        eprintln!("protected_worker_ready bind={bind_addr}");
        axum::serve(listener, router)
            .await
            .map_err(|e| format!("worker_serve:{e}"))
    })
}
