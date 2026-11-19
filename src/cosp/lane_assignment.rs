use super::la_backend::{self, Capability};
use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

const SCOPE_DISCOVER: u64 = 1;
const SCOPE_ARTIFACT_WRITE: u64 = 2;
const SCOPE_ARTIFACT_READ: u64 = 4;
const SCOPE_ASSIGNMENT_ACQUIRE: u64 = 8;
const SCOPE_ASSIGNMENT_READ: u64 = 16;
const SCOPE_ASSIGNMENT_RENEW: u64 = 32;
const SCOPE_ASSIGNMENT_RELEASE: u64 = 64;
const SCOPE_JOB_SUBMIT: u64 = 128;
const SCOPE_JOB_READ: u64 = 256;
const SCOPE_JOB_CANCEL: u64 = 512;
const SCOPE_INSPECT_CAPABILITY: u64 = 1024;
#[cfg(test)]
const SCOPE_KNOWN: u64 = 2047;

fn error(status: StatusCode, code: &str, retry_action: &str) -> Response {
    (
        status,
        Json(json!({
            "schema_version": "diffuser-lane/v1",
            "error": {
                "code": code,
                "request_id": random_id("req").unwrap_or_else(|_| "req_unavailable_000000000000".into()),
                "retry_action": retry_action,
                "object_id": null
            }
        })),
    )
        .into_response()
}

async fn closed(method: Method) -> Response {
    if method != Method::GET {
        return method_not_allowed().await;
    }
    error(StatusCode::SERVICE_UNAVAILABLE, "routing_closed", "same_id")
}

async fn closed_artifact_upload(request: Request) -> Response {
    use sha2::{Digest, Sha256};
    let headers = request.headers();
    if unique_header(headers, "content-type") != Some("application/octet-stream") {
        return artifact_error("media_type_unsupported");
    }
    let length = if headers.contains_key(header::CONTENT_LENGTH) {
        match unique_header(headers, "content-length").and_then(|v| v.parse::<usize>().ok()) {
            Some(value) if value <= 1_048_576 => Some(value),
            Some(_) => return artifact_error("body_too_large"),
            None => return artifact_error("artifact_invalid"),
        }
    } else {
        None
    };
    if !unique_header(headers, "idempotency-key").is_some_and(|value| {
        (16..=128).contains(&value.len())
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    }) {
        return artifact_error("idempotency_required");
    }
    if unique_header(headers, "x-diffuser-schema") != Some("diffuser-artifact/v1") {
        return artifact_error("version_unsupported");
    }
    let digest = match unique_header(headers, "x-content-sha256") {
        Some(value)
            if value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            value.to_owned()
        }
        _ => return artifact_error("artifact_invalid"),
    };
    let bytes = match to_bytes(request.into_body(), 1_048_576).await {
        Ok(bytes) => bytes,
        Err(_) => return artifact_error("body_too_large"),
    };
    if length.is_some_and(|value| bytes.len() != value)
        || hex::encode(Sha256::digest(&bytes)) != digest
    {
        return artifact_error("artifact_invalid");
    }
    artifact_error("routing_closed")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewRequest {
    schema_version: String,
    expected_revision: u64,
    requested_lease_ms: u64,
}

async fn closed_renew(request: Request) -> Response {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if content_type != Some("application/json") {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "media_type_unsupported",
            "none",
        );
    }
    let mut keys = request.headers().get_all("idempotency-key").iter();
    let valid_key = match (keys.next(), keys.next()) {
        (Some(value), None) => value.to_str().ok().is_some_and(|key| {
            (16..=128).contains(&key.len())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        }),
        _ => false,
    };
    let bytes = match to_bytes(request.into_body(), 65536).await {
        Ok(bytes) => bytes,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", "none"),
    };
    let normalized = match super::la_contract::canonical_json(&bytes) {
        Ok(value) => value,
        Err(code) => return error(StatusCode::BAD_REQUEST, code, "none"),
    };
    let request: RenewRequest = match serde_json::from_slice(&normalized) {
        Ok(value) => value,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                if e.to_string().contains("duplicate field") {
                    "duplicate_member"
                } else {
                    "schema_invalid"
                },
                "none",
            )
        }
    };
    if request.schema_version != "diffuser-lane/v1" {
        return error(StatusCode::BAD_REQUEST, "version_unsupported", "none");
    }
    if request.requested_lease_ms == 0 {
        return error(StatusCode::BAD_REQUEST, "schema_invalid", "none");
    }
    if !valid_key {
        return error(StatusCode::BAD_REQUEST, "idempotency_required", "none");
    }
    let _ = request.expected_revision;
    error(StatusCode::SERVICE_UNAVAILABLE, "routing_closed", "same_id")
}

async fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "object_not_found", "none")
}

async fn method_not_allowed() -> Response {
    error(
        StatusCode::METHOD_NOT_ALLOWED,
        "unsupported_operation",
        "none",
    )
}

pub(super) fn router() -> Router<super::Spine> {
    routes(get(closed))
}
fn routes(discovery: axum::routing::MethodRouter<super::Spine>) -> Router<super::Spine> {
    Router::new()
        .route("/discovery", discovery.head(method_not_allowed))
        .route(
            "/projects/{project}/artifacts",
            post(closed_artifact_upload),
        )
        .route("/projects/{project}/assignments", post(closed_acquire))
        .route(
            "/projects/{project}/assignments/{assignment}/jobs",
            post(closed_submit),
        )
        .route("/projects/{project}/artifacts/{artifact}", get(closed))
        .route(
            "/projects/{project}/artifacts/{artifact}/content",
            get(closed),
        )
        .route("/projects/{project}/assignments/{assignment}", get(closed))
        .route(
            "/projects/{project}/assignments/{assignment}/renew",
            post(closed_renew),
        )
        .route(
            "/projects/{project}/assignments/{assignment}/release",
            post(closed_revision),
        )
        .route("/projects/{project}/jobs/{job}", get(closed))
        .route(
            "/projects/{project}/jobs/{job}/cancel",
            post(closed_revision),
        )
        .route(
            "/projects/{project}/assignment-requests/{request}/cancel",
            post(closed_revision),
        )
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
}

// Admission remains closed until the fixture can establish its complete authority
// and resource prerequisites. This check performs no initialization.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn validate_startup(has_protected_channel: bool) -> Result<(), &'static str> {
    validate_startup_candidate(has_protected_channel, None)
}

// This validates fixture startup prerequisites, including the pinned root for
// recovery. It does not grant admission or authenticate custody history.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum StartupCandidate<'a> {
    #[cfg(test)]
    Worker(&'a super::la_worker::WorkerBootstrap, &'a std::fs::File),
    #[cfg(test)]
    Controller(&'a ControllerBootstrap, &'a std::fs::File),
    #[cfg(not(test))]
    Disabled(std::marker::PhantomData<&'a ()>),
}
pub(super) fn validate_startup_candidate(
    has_protected_channel: bool,
    candidate: Option<StartupCandidate<'_>>,
) -> Result<(), &'static str> {
    if !has_protected_channel {
        return Err("missing_protected_channel");
    }
    match candidate {
        #[cfg(test)]
        Some(StartupCandidate::Worker(bootstrap, root)) => bootstrap.validate_new_root(root),
        #[cfg(test)]
        Some(StartupCandidate::Controller(bootstrap, root)) => bootstrap.validate_new_root(root),
        #[cfg(not(test))]
        Some(StartupCandidate::Disabled(_)) => Err("startup_unavailable"),
        None => Err("startup_unavailable"),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn start_with<F>(has_protected_channel: bool, activate: F) -> Result<(), &'static str>
where
    F: FnOnce(),
{
    validate_startup(has_protected_channel)?;
    activate();
    Ok(())
}

// A closed preliminary check only; it never confers startup authority. The
// root identities, custody history and external resource gates must still be
// verified before any listener or store is opened.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn startup_parameters_valid(
    role: &str,
    root: &str,
    policy_id: &str,
    digest: &str,
) -> bool {
    let role_root = matches!(
        (role, root),
        ("worker", "/job/workerroot") | ("controller" | "claim_client", "/job/service")
    );
    role_root && super::la_contract::policy_digest(policy_id).as_deref() == Some(digest)
}

/// Pin the selected finite root without following any path component. This is
/// an ordinary prerequisite, not proof of P's launch binding or of Q1–Q9.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn open_startup_root(path: &str) -> Result<std::fs::File, &'static str> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
        path::{Component, Path},
    };
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("startup_root_invalid");
    }
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/")
        .map_err(|_| "startup_root_invalid")?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name =
                    std::ffi::CString::new(name.as_bytes()).map_err(|_| "startup_root_invalid")?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err("startup_root_invalid");
                }
                dir = unsafe { std::fs::File::from_raw_fd(fd) };
            }
            _ => return Err("startup_root_invalid"),
        }
    }
    let meta = dir.metadata().map_err(|_| "startup_root_invalid")?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o777 != 0o700 {
        return Err("startup_root_invalid");
    }
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let mut volume = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatfs(dir.as_raw_fd(), filesystem.as_mut_ptr()) } != 0
        || unsafe { libc::fstatvfs(dir.as_raw_fd(), volume.as_mut_ptr()) } != 0
    {
        return Err("startup_root_invalid");
    }
    let filesystem = unsafe { filesystem.assume_init() };
    let volume = unsafe { volume.assume_init() };
    if filesystem.f_type != 0x0102_1994
        || volume.f_flag & libc::ST_RDONLY != 0
        || volume.f_blocks.checked_mul(volume.f_frsize) != Some(67_108_864)
    {
        return Err("startup_root_invalid");
    }
    let mut mounts = String::new();
    std::fs::File::open("/proc/self/mountinfo")
        .map_err(|_| "startup_root_invalid")?
        .take(1_048_577)
        .read_to_string(&mut mounts)
        .map_err(|_| "startup_root_invalid")?;
    if mounts.len() > 1_048_576
        || !mounts
            .lines()
            .any(|line| line.split_whitespace().nth(4) == path.to_str())
    {
        return Err("startup_root_invalid");
    }
    Ok(dir)
}

#[derive(Clone)]
pub(super) struct DiscoveryContext {
    pub(super) tenant: String,
    pub(super) project: String,
    pub(super) grants: Vec<super::la_auth::OwnedAuthorityGrant>,
    pub(super) observed_at: u64,
    pub(super) observation_sequence: u64,
    pub(super) freshness_ms: u64,
    pub(super) inventory_available: bool,
    pub(super) inventory_observed_at: u64,
    pub(super) loss_scope: Option<(String, String)>,
}
pub(super) type SharedAuthority = std::sync::Arc<std::sync::RwLock<DiscoveryContext>>;

// The isolated caller injects observations and digests; public constructors
// never call this. It exposes only a non-accepting catalog, not admission.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn injected_router(context: DiscoveryContext) -> Router<super::Spine> {
    routes(get(injected_discovery).with_state(std::sync::Arc::new(std::sync::RwLock::new(context))))
}

async fn injected_discovery(State(shared): State<SharedAuthority>, headers: HeaderMap) -> Response {
    let context = match shared.read() {
        Ok(context) => context,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "storage_unavailable",
                "same_id",
            )
        }
    };
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let bearer = match (values.next(), values.next()) {
        (None, None) => return error(StatusCode::UNAUTHORIZED, "auth_required", "none"),
        (Some(value), None) => value.to_str().ok().and_then(|v| v.strip_prefix("Bearer ")),
        _ => None,
    };
    let Some(bearer) = bearer else {
        return error(StatusCode::UNAUTHORIZED, "auth_invalid", "none");
    };
    let now = match std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    {
        Some(now) if now <= i64::MAX as u64 => now,
        _ => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "clock_untrusted",
                "same_id",
            )
        }
    };
    if context.freshness_ms == 0 || context.freshness_ms > 6_000 {
        return error(StatusCode::PRECONDITION_FAILED, "evidence_stale", "same_id");
    }
    let grants: Vec<_> = context
        .grants
        .iter()
        .map(super::la_auth::OwnedAuthorityGrant::borrowed)
        .collect();
    if let Err(code) = super::la_auth::authenticate(
        &grants,
        bearer.as_bytes(),
        &context.tenant,
        &context.project,
        SCOPE_DISCOVER,
        now,
        context.observed_at,
        context.freshness_ms,
    ) {
        return match code {
            "evidence_stale" => error(StatusCode::PRECONDITION_FAILED, code, "same_id"),
            "scope_denied" | "delegation_denied" => error(StatusCode::FORBIDDEN, code, "none"),
            _ => error(StatusCode::UNAUTHORIZED, "auth_invalid", "none"),
        };
    }
    if context.loss_scope.is_some() {
        return artifact_error("routing_closed");
    }
    if !context.inventory_available
        || context.inventory_observed_at > now
        || context
            .inventory_observed_at
            .checked_add(6_000)
            .is_none_or(|end| now >= end)
    {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "inventory_unavailable",
            "same_id",
        );
    }
    Json(json!({
        "schema_version":"diffuser-lane/v1", "queue_mode":"refuse",
        "lanes":[{"lane_id":"lane_cpu_inspect", "capability":"artifact.inspect.sha256/v1", "profile_id":"cpu-artifact-inspect/v1", "accepting":false, "reason":"resource_unqualified"}]
    })).into_response()
}

#[cfg(test)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerAuthority {
    tenant: String,
    project: String,
    root_actor: String,
    leaf_actor: String,
    root_scopes: u64,
    leaf_scopes: u64,
    root_bearer: String,
    leaf_bearer: String,
    worker_bearer: String,
    worker_address: String,
    worker_id: String,
    worker_boot_id: String,
    boot_id: String,
    observed_at: u64,
    access_expires: u64,
    run_until: u64,
    execution_ceiling: u64,
    #[serde(default)]
    channel: Option<super::la_adapter::ProtectedChannelBootstrap>,
    #[serde(default)]
    reply_barrier: bool,
}
#[cfg(test)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerCustody {
    mode: String,
    store_id: String,
    root_dev: u64,
    root_inode: u64,
    writer_epoch: u64,
    #[serde(default)]
    recovery: Option<Box<super::la_adapter::ControllerReadbackRecovery>>,
    #[serde(default)]
    transport_handoff: Option<Box<super::la_adapter::TransportEpochHandoff>>,
}

#[cfg(test)]
pub(super) struct ControllerBootstrap {
    pub(super) reply_barrier: bool,
    pub(super) context: DiscoveryContext,
    pub(super) worker_bearer: String,
    pub(super) worker_address: std::net::SocketAddr,
    pub(super) worker_id: String,
    pub(super) worker_boot_id: String,
    pub(super) boot_id: String,
    pub(super) store_id: String,
    pub(super) recovery: Option<Box<super::la_adapter::ControllerReadbackRecovery>>,
    pub(super) transport_handoff: Option<Box<super::la_adapter::TransportEpochHandoff>>,
    root_dev: u64,
    root_inode: u64,
    pub(super) channel: Option<super::la_adapter::ProtectedChannelBootstrap>,
}
#[cfg(test)]
impl Drop for ControllerBootstrap {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.worker_bearer.zeroize();
    }
}

#[cfg(test)]
pub(super) fn validate_controller_bootstrap(
    authority: serde_json::Value,
    custody: serde_json::Value,
) -> Result<ControllerBootstrap, &'static str> {
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;
    let mut authority: ControllerAuthority =
        serde_json::from_value(authority).map_err(|_| "child_config_invalid")?;
    let parsed: Result<ControllerCustody, _> = serde_json::from_value(custody);
    let result = (|| {
        let custody = parsed.map_err(|_| "child_config_invalid")?;
        let hex64 = |v: &str| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && v.bytes().any(|b| b != b'0')
        };
        let id = |v: &str| {
            (16..=128).contains(&v.len())
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        let address: std::net::SocketAddr = authority
            .worker_address
            .parse()
            .map_err(|_| "child_config_invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("child_config_invalid")?;
        super::la_adapter::recovery_trace(
            "controller_bootstrap_freshness",
            serde_json::json!({"observed_at":authority.observed_at,"now":now,"age_ms":now.saturating_sub(authority.observed_at),"first_window_ms":1500,"fresh":authority.observed_at<=now && authority.observed_at.checked_add(1500).is_some_and(|v|now<v)}),
        );
        if ![
            &authority.tenant,
            &authority.project,
            &authority.root_actor,
            &authority.leaf_actor,
            &authority.worker_id,
        ]
        .into_iter()
        .all(|v| id(v))
            || ![
                &authority.root_bearer,
                &authority.leaf_bearer,
                &authority.worker_bearer,
                &authority.worker_boot_id,
                &authority.boot_id,
                &custody.store_id,
            ]
            .into_iter()
            .all(|v| hex64(v))
            || authority.root_scopes == 0
            || authority.root_scopes & !SCOPE_KNOWN != 0
            || authority.leaf_scopes == 0
            || authority.leaf_scopes & !authority.root_scopes != 0
            || authority.root_bearer == authority.leaf_bearer
            || authority.root_bearer == authority.worker_bearer
            || authority.leaf_bearer == authority.worker_bearer
            || address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || address.port() == 0
            || authority.observed_at > now
            || authority
                .observed_at
                .checked_add(1_500)
                .is_none_or(|v| now >= v)
            || [
                authority.access_expires,
                authority.run_until,
                authority.execution_ceiling,
            ]
            .into_iter()
            .any(|v| v <= now || v > i64::MAX as u64)
            || !matches!(
                (
                    custody.mode.as_str(),
                    custody.writer_epoch,
                    custody.recovery.is_some()
                ),
                ("bootstrap", 1, false) | ("readback_recovery", 2.., true)
            )
            || (custody.transport_handoff.is_some() && custody.recovery.is_none())
            || custody.root_dev == 0
            || custody.root_inode == 0
        {
            return Err("child_config_invalid");
        }
        let root = super::la_auth::OwnedAuthorityGrant {
            id: "grant_root123456".into(),
            parent: None,
            tenant: authority.tenant.clone(),
            project: authority.project.clone(),
            actor: authority.root_actor.clone(),
            bearer_digest: Sha256::digest(authority.root_bearer.as_bytes()).into(),
            scopes: authority.root_scopes,
            can_delegate: true,
            enabled: true,
            member: true,
            revoked: false,
            not_before: authority.observed_at,
            access_expires: authority.access_expires,
            run_until: authority.run_until,
            execution_ceiling: authority.execution_ceiling,
            audience: "diffuser".into(),
        };
        let leaf = super::la_auth::OwnedAuthorityGrant {
            id: "grant_leaf123456".into(),
            parent: Some(root.id.clone()),
            actor: authority.leaf_actor.clone(),
            bearer_digest: Sha256::digest(authority.leaf_bearer.as_bytes()).into(),
            scopes: authority.leaf_scopes,
            can_delegate: false,
            ..root.clone()
        };
        if let Some(channel) = &authority.channel {
            channel.validate(
                &authority.worker_id,
                &authority.worker_boot_id,
                Some(&authority.boot_id),
            )?;
        }
        if let Some(recovery) = &custody.recovery {
            let channel = authority.channel.as_ref().ok_or("child_config_invalid")?;
            if recovery.binding() != &channel.binding
                || recovery.store_id() != custody.store_id
                || channel.binding.controller_epoch != custody.writer_epoch
                || channel.service_genesis.is_some()
            {
                return Err("child_config_invalid");
            }
        }
        Ok(ControllerBootstrap {
            reply_barrier: authority.reply_barrier,
            recovery: custody.recovery,
            transport_handoff: custody.transport_handoff,
            channel: authority.channel.take(),
            context: DiscoveryContext {
                tenant: authority.tenant.clone(),
                project: authority.project.clone(),
                grants: vec![root, leaf],
                observed_at: authority.observed_at,
                observation_sequence: 0,
                freshness_ms: 1_500,
                inventory_available: false,
                inventory_observed_at: 0,
                loss_scope: None,
            },
            worker_bearer: authority.worker_bearer.clone(),
            worker_address: address,
            worker_id: authority.worker_id.clone(),
            worker_boot_id: authority.worker_boot_id.clone(),
            boot_id: authority.boot_id.clone(),
            store_id: custody.store_id,
            root_dev: custody.root_dev,
            root_inode: custody.root_inode,
        })
    })();
    authority.root_bearer.zeroize();
    authority.leaf_bearer.zeroize();
    authority.worker_bearer.zeroize();
    result
}
#[cfg(test)]
impl ControllerBootstrap {
    pub(super) fn validate_new_root(&self, root: &std::fs::File) -> Result<(), &'static str> {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let meta = root.metadata().map_err(|_| "startup_root_invalid")?;
        if (meta.dev(), meta.ino()) != (self.root_dev, self.root_inode) {
            return Err("startup_root_invalid");
        }
        if let Some(recovery) = &self.recovery {
            let channel = self.channel.as_ref().ok_or("evidence_invalid")?;
            let keys =
                channel.validate(&self.worker_id, &self.worker_boot_id, Some(&self.boot_id))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock_untrusted")?
                .as_millis() as u64;
            recovery.verify(root, &channel.binding, &keys, now)?;
            if recovery.service().pending_operation().is_some() && self.transport_handoff.is_none()
            {
                return Err("evidence_invalid");
            }
            if let Some(handoff) = &self.transport_handoff {
                handoff.verify_controller(root, recovery, &keys, now)?;
            }
            return Ok(());
        }
        let mut entries = std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))
            .map_err(|_| "startup_root_invalid")?;
        if entries.next().is_some() {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn initialize_stores(
        &self,
        root: &std::fs::File,
        path: &std::path::Path,
    ) -> Result<
        (
            super::la_store::ClaimStore,
            super::la_artifacts::ArtifactStore,
            Option<super::la_adapter::TransportJournal>,
        ),
        &'static str,
    > {
        if !super::la_store::claim_root_matches(root, path) {
            return Err("startup_root_invalid");
        }
        // Verify the complete externally witnessed transport history and take
        // its exclusive lock before any store initialization or listener. The
        // returned journal owns the lock through controller startup/lifetime.
        let transport = if let Some(recovery) = &self.recovery {
            self.validate_new_root(root)?;
            let channel = self.channel.as_ref().ok_or("evidence_invalid")?;
            let keys =
                channel.validate(&self.worker_id, &self.worker_boot_id, Some(&self.boot_id))?;
            Some(recovery.reopen_transport(root, path, &keys)?)
        } else {
            None
        };
        let mut claim = super::la_store::ClaimStore::open(&path.join("lane_assignments.sqlite"))?;
        if self.recovery.is_none() {
            claim.bootstrap_controller_identity(&self.store_id, self.root_dev, self.root_inode)?;
        }
        let artifacts = super::la_artifacts::ArtifactStore::open(path)?;
        if !super::la_store::claim_root_matches(root, path) {
            return Err("startup_root_invalid");
        }
        Ok((claim, artifacts, transport))
    }
}

/// Serve a private injected service router on an already isolated listener.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) async fn serve_injected(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), &'static str> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|_| "startup_unavailable")
}

// This router is constructed only by the protected, injected controller.
// Admission routes remain closed until their complete gates are implemented.
#[derive(Clone)]
#[cfg_attr(not(test), allow(dead_code))]
struct ArtifactContext {
    authority: SharedAuthority,
    store: std::sync::Arc<std::sync::Mutex<super::la_artifacts::ArtifactStore>>,
    claims: Option<std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>>,
    worker: Option<std::sync::Arc<std::sync::Mutex<ServiceWorker>>>,
}

pub(super) struct ServiceWorker {
    journal: super::la_worker::WorkerConnection,
    session: super::la_worker::ReservationSession,
    execute: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn injected_service_router(
    context: DiscoveryContext,
    artifacts: super::la_artifacts::ArtifactStore,
) -> Router<super::Spine> {
    injected_service_router_shared(
        std::sync::Arc::new(std::sync::RwLock::new(context)),
        artifacts,
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn injected_service_router_shared(
    authority: SharedAuthority,
    artifacts: super::la_artifacts::ArtifactStore,
) -> Router<super::Spine> {
    service_routes(ArtifactContext {
        authority,
        store: std::sync::Arc::new(std::sync::Mutex::new(artifacts)),
        claims: None,
        worker: None,
    })
}

/// Supplies synthetic admission evidence only inside in-process tests.
#[cfg(test)]
pub(super) fn fixture_claim_router(
    authority: SharedAuthority,
    artifacts: super::la_artifacts::ArtifactStore,
    claims: super::la_store::ClaimStore,
) -> Router<super::Spine> {
    service_routes(ArtifactContext {
        authority,
        store: std::sync::Arc::new(std::sync::Mutex::new(artifacts)),
        claims: Some(std::sync::Arc::new(std::sync::Mutex::new(claims))),
        worker: None,
    })
}

/// In-process synthetic worker for handler tests; no runtime constructor can
/// select this fixture or treat it as evidence of Q1-Q9.
#[cfg(test)]
pub(super) fn fixture_worker_router(
    authority: SharedAuthority,
    artifacts: super::la_artifacts::ArtifactStore,
    claims: super::la_store::ClaimStore,
    journal: super::la_worker::OperationJournal,
    session: super::la_worker::ReservationSession,
    execute: bool,
) -> Router<super::Spine> {
    service_routes(ArtifactContext {
        authority,
        store: std::sync::Arc::new(std::sync::Mutex::new(artifacts)),
        claims: Some(std::sync::Arc::new(std::sync::Mutex::new(claims))),
        worker: Some(std::sync::Arc::new(std::sync::Mutex::new(ServiceWorker {
            journal: super::la_worker::WorkerConnection::Local(journal),
            session,
            execute,
        }))),
    })
}

/// Protected C bootstrap supplies the real endpoint. No public constructor can
/// select synthetic authority or a local worker backend.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn protected_service_router(
    authority: SharedAuthority,
    artifacts: super::la_artifacts::ArtifactStore,
    claims: std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    client: super::la_adapter::WorkerClient,
    session: super::la_worker::ReservationSession,
) -> (
    Router<super::Spine>,
    std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
) {
    let worker = std::sync::Arc::new(std::sync::Mutex::new(ServiceWorker {
        journal: super::la_worker::WorkerConnection::Remote(Box::new(client)),
        session,
        execute: true,
    }));
    let router = service_routes(ArtifactContext {
        authority,
        store: std::sync::Arc::new(std::sync::Mutex::new(artifacts)),
        claims: Some(claims),
        worker: Some(worker.clone()),
    });
    (router, worker)
}

/// Live C installs a DISTINCT P-authenticated W return. This closes execution
/// admission and settles only the original held close/service operation.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn reconcile_protected_worker_return(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    store: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    domain: &super::la_adapter::state_custody::Session,
    handoff: &super::la_adapter::WorkerEpochHandoff,
    address: std::net::SocketAddr,
    keys: &super::la_adapter::ChannelKeys,
    now: u64,
) -> Result<super::la_adapter::TransportEpochAck, &'static str> {
    let mut claims = store.lock().map_err(|_| "storage_unavailable")?;
    let mut worker = worker.lock().map_err(|_| "storage_unavailable")?;
    worker.execute = false;
    match &mut worker.journal {
        super::la_worker::WorkerConnection::Remote(client) => {
            client.install_worker_return(handoff, address, now)?;
        }
        #[cfg(test)]
        super::la_worker::WorkerConnection::Local(_) => return Err("evidence_invalid"),
    }
    let operation = domain.install_worker_return(handoff, keys, now)?;
    let (receipt, mac) = handoff.settled_close(keys)?;
    claims.acknowledge_assignment_stop(&keys.reply, &receipt, &mac)?;
    claims.record_worker_return_close(handoff, keys, now)?;
    domain.complete(operation, &handoff.digest()?)?;
    handoff.acknowledgment(keys)
}

/// Only protected, authenticated recovery supplies preserved stores. Mutating
/// routes remain closed; exact completed-key retries only read prior receipts.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn recovered_readback_router(
    authority: SharedAuthority,
    artifacts: super::la_artifacts::ArtifactStore,
    claims: std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    authority_high_water: u64,
) -> Router<super::Spine> {
    recovered_readback_router_shared(
        authority,
        std::sync::Arc::new(std::sync::Mutex::new(artifacts)),
        claims,
        authority_high_water,
    )
}
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn recovered_readback_router_shared(
    authority: SharedAuthority,
    artifacts: std::sync::Arc<std::sync::Mutex<super::la_artifacts::ArtifactStore>>,
    claims: std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    authority_high_water: u64,
) -> Router<super::Spine> {
    let state = ArtifactContext {
        authority: authority.clone(),
        store: artifacts,
        claims: Some(claims),
        worker: None,
    };
    let recovered_authority = (authority.clone(), authority_high_water);
    Router::new()
        .route(
            "/discovery",
            get(injected_discovery)
                .head(method_not_allowed)
                .with_state(authority),
        )
        .route(
            "/projects/{project}/artifacts/{artifact}",
            get(artifact_manifest)
                .head(method_not_allowed)
                .with_state(state.clone()),
        )
        .route(
            "/projects/{project}/artifacts/{artifact}/content",
            get(artifact_content)
                .head(method_not_allowed)
                .with_state(state.clone()),
        )
        .route(
            "/projects/{project}/assignments/{assignment}",
            get(assignment_status_unavailable)
                .head(method_not_allowed)
                .with_state(state.clone()),
        )
        .route(
            "/projects/{project}/assignments/{assignment}/jobs",
            post(recovered_completed_submit).with_state(state.clone()),
        )
        .route(
            "/projects/{project}/jobs/{job}",
            get(job_status_unavailable)
                .head(method_not_allowed)
                .with_state(state),
        )
        .fallback(closed)
        .layer(axum::middleware::from_fn_with_state(
            recovered_authority,
            require_recovery_source,
        ))
}

// A terminal receipt is readable without an execution activation. This route
// cannot create work or aliases; a missing key remains closed.
async fn recovered_completed_submit(
    State(context): State<ArtifactContext>,
    Path((project, assignment)): Path<(String, String)>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    if unique_header(&headers, "content-type") != Some("application/json") {
        return artifact_error("media_type_unsupported");
    }
    let first = match current_authority(
        &context.authority,
        &headers,
        &project,
        SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
    ) {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    if !valid_public_id(&assignment) {
        return artifact_error("object_not_found");
    }
    let Some(key) = unique_header(&headers, "idempotency-key").filter(|v| valid_public_id(v))
    else {
        return artifact_error("idempotency_required");
    };
    let bytes = match to_bytes(request.into_body(), 65536).await {
        Ok(v) => v,
        Err(_) => return artifact_error("body_too_large"),
    };
    let parsed = match parse_submit(&bytes) {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    if parsed.capability != "artifact.inspect.sha256/v1" || parsed.profile_version != "1" {
        return artifact_error("capability_unavailable");
    }
    if parsed.max_runtime_ms > 10000 {
        return artifact_error("runtime_limit_exceeded");
    }
    let fingerprint = match submit_fingerprint(&assignment, &bytes) {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    let authority = match context.authority.read() {
        Ok(v) => v,
        Err(_) => return artifact_error("storage_unavailable"),
    };
    let current = match artifact_authorize(
        &authority,
        &headers,
        &project,
        SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
    ) {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    if let Err(code) = authority_still_live(&first, &current) {
        return artifact_error(code);
    }
    let Some(claims) = &context.claims else {
        return artifact_error("routing_closed");
    };
    let store = match claims.lock() {
        Ok(v) => v,
        Err(_) => return artifact_error("storage_unavailable"),
    };
    let view = match store.completed_job_retry(
        &project,
        &current.actor,
        &assignment,
        key,
        &fingerprint,
        &current.lineage,
    ) {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    (StatusCode::ACCEPTED,Json(json!({"schema_version":"diffuser-lane/v1","job_id":view.id,"assignment_id":view.assignment,"state":view.state,"revision":view.revision}))).into_response()
}
fn submit_fingerprint(assignment: &str, bytes: &[u8]) -> Result<String, &'static str> {
    use sha2::{Digest, Sha256};
    let canonical = super::la_contract::canonical_json(bytes)?;
    let mut hash = Sha256::new();
    hash.update(b"diffuser-submit/v1\0");
    hash.update(assignment.as_bytes());
    hash.update([0]);
    hash.update(canonical);
    Ok(hex::encode(hash.finalize()))
}

async fn require_recovery_source(
    State((authority, high_water)): State<(SharedAuthority, u64)>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    {
        let current = match authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        if current.observation_sequence <= high_water {
            return artifact_error("evidence_stale");
        }
    }
    next.run(request).await
}

fn service_routes(artifact_context: ArtifactContext) -> Router<super::Spine> {
    let authority = artifact_context.authority.clone();
    Router::new()
        .route(
            "/discovery",
            get(injected_discovery)
                .head(method_not_allowed)
                .with_state(authority),
        )
        .route(
            "/projects/{project}/artifacts",
            post(upload_artifact).with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/artifacts/{artifact}",
            get(artifact_manifest)
                .head(method_not_allowed)
                .with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/artifacts/{artifact}/content",
            get(artifact_content)
                .head(method_not_allowed)
                .with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/assignments",
            post(acquire_closed_by_resource_gate).with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/assignments/{assignment}/jobs",
            post(submit_closed_by_resource_gate).with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/assignments/{assignment}",
            get(assignment_status_unavailable)
                .head(method_not_allowed)
                .with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/assignments/{assignment}/renew",
            post(renew_unavailable).with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/assignments/{assignment}/release",
            post(release_unavailable).with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/jobs/{job}",
            get(job_status_unavailable)
                .head(method_not_allowed)
                .with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/jobs/{job}/cancel",
            post(cancel_unavailable).with_state(artifact_context.clone()),
        )
        .route(
            "/projects/{project}/assignment-requests/{request}/cancel",
            post(queue_cancel_unsupported).with_state(artifact_context),
        )
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(not_found)
}

#[cfg_attr(not(test), allow(dead_code))]
fn artifact_error(code: &'static str) -> Response {
    let status = match code {
        "auth_required" | "auth_invalid" => StatusCode::UNAUTHORIZED,
        "scope_denied" | "delegation_denied" | "quota_exceeded" => StatusCode::FORBIDDEN,
        "object_not_found" | "lane_not_found" => StatusCode::NOT_FOUND,
        "idempotency_conflict" | "capacity_unavailable" | "state_conflict" => StatusCode::CONFLICT,
        "artifact_expired" => StatusCode::GONE,
        "evidence_stale" | "evidence_invalid" => StatusCode::PRECONDITION_FAILED,
        "body_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
        "media_type_unsupported" => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "artifact_invalid"
        | "provider_unconfigured"
        | "capability_unavailable"
        | "runtime_limit_exceeded" => StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_operation" => StatusCode::NOT_IMPLEMENTED,
        "routing_closed" | "storage_unavailable" | "clock_untrusted" => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::BAD_REQUEST,
    };
    let retry = if matches!(
        code,
        "routing_closed"
            | "storage_unavailable"
            | "clock_untrusted"
            | "evidence_stale"
            | "evidence_invalid"
    ) {
        "same_id"
    } else {
        "none"
    };
    error(status, code, retry)
}

#[cfg_attr(not(test), allow(dead_code))]
fn unique_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
struct RequestAuthority {
    actor: String,
    initiator: String,
    lineage: Vec<String>,
    now: u64,
    valid_until: u64,
    monotonic_until: std::time::Instant,
    expiry_error: &'static str,
}

#[cfg_attr(not(test), allow(dead_code))]
fn authority_still_live(
    previous: &RequestAuthority,
    current: &RequestAuthority,
) -> Result<(), &'static str> {
    if current.now < previous.now {
        return Err("clock_untrusted");
    }
    if std::time::Instant::now() >= previous.monotonic_until {
        return Err(previous.expiry_error);
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn artifact_authorize(
    context: &DiscoveryContext,
    headers: &HeaderMap,
    project: &str,
    scope: u64,
) -> Result<RequestAuthority, &'static str> {
    if !headers.contains_key(header::AUTHORIZATION) {
        return Err("auth_required");
    }
    let bearer = unique_header(headers, "authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or("auth_invalid")?;
    let monotonic_now = std::time::Instant::now();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| u64::try_from(v.as_millis()).ok())
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or("clock_untrusted")?;
    if context.freshness_ms == 0 || context.freshness_ms > 6_000 {
        return Err("evidence_stale");
    }
    let grants: Vec<_> = context
        .grants
        .iter()
        .map(super::la_auth::OwnedAuthorityGrant::borrowed)
        .collect();
    let authenticated = super::la_auth::authenticate(
        &grants,
        bearer.as_bytes(),
        &context.tenant,
        &context.project,
        scope,
        now,
        context.observed_at,
        context.freshness_ms,
    );
    if project != context.project {
        return match authenticated {
            Ok(_) | Err("scope_denied") => Err("object_not_found"),
            Err(code) => Err(code),
        };
    }
    let authenticated = authenticated?;
    if context.loss_scope.is_some()
        && !matches!(
            scope,
            SCOPE_JOB_READ | SCOPE_JOB_CANCEL | SCOPE_ASSIGNMENT_READ | SCOPE_ASSIGNMENT_RELEASE
        )
    {
        return Err("routing_closed");
    }
    let mut valid_until = context
        .observed_at
        .checked_add(context.freshness_ms)
        .ok_or("evidence_stale")?;
    let mut expiry_error = "evidence_stale";
    for id in &authenticated.lineage {
        let mut matching = context.grants.iter().filter(|grant| grant.id == *id);
        let grant = matching.next().ok_or("delegation_denied")?;
        if matching.next().is_some() {
            return Err("delegation_denied");
        }
        if grant.access_expires <= valid_until {
            valid_until = grant.access_expires;
            expiry_error = "auth_invalid";
        }
    }
    let remaining = valid_until
        .checked_sub(now)
        .filter(|remaining| *remaining > 0)
        .ok_or(expiry_error)?;
    let monotonic_until = monotonic_now
        .checked_add(std::time::Duration::from_millis(remaining))
        .ok_or("clock_untrusted")?;
    Ok(RequestAuthority {
        actor: authenticated.actor.to_owned(),
        initiator: authenticated.initiator.to_owned(),
        lineage: authenticated
            .lineage
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        now,
        valid_until,
        monotonic_until,
        expiry_error,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
fn current_authority(
    shared: &SharedAuthority,
    headers: &HeaderMap,
    project: &str,
    scope: u64,
) -> Result<RequestAuthority, &'static str> {
    let context = shared.read().map_err(|_| "storage_unavailable")?;
    artifact_authorize(&context, headers, project, scope)
}

#[cfg_attr(not(test), allow(dead_code))]
fn random_id(prefix: &str) -> Result<String, &'static str> {
    let mut bytes = [0u8; 16];
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) } != bytes.len() as isize
    {
        return Err("storage_unavailable");
    }
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}

#[cfg_attr(not(test), allow(dead_code))]
async fn upload_artifact(
    State(context): State<ArtifactContext>,
    Path(project): Path<String>,
    request: Request,
) -> Response {
    use sha2::{Digest, Sha256};
    let headers = request.headers().clone();
    if unique_header(&headers, "content-type") != Some("application/octet-stream") {
        return artifact_error("media_type_unsupported");
    }
    let length = if headers.contains_key(header::CONTENT_LENGTH) {
        match unique_header(&headers, "content-length").and_then(|v| v.parse::<usize>().ok()) {
            Some(n) if n <= 1_048_576 => Some(n),
            Some(_) => return artifact_error("body_too_large"),
            None => return artifact_error("artifact_invalid"),
        }
    } else {
        None // Axum's framed body is still consumed with the hard byte cap below.
    };
    let initial_authority =
        match current_authority(&context.authority, &headers, &project, SCOPE_ARTIFACT_WRITE) {
            Ok(v) => v,
            Err(code) => return artifact_error(code),
        };
    let key = match unique_header(&headers, "idempotency-key") {
        Some(v)
            if (16..=128).contains(&v.len())
                && v.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') =>
        {
            v.to_owned()
        }
        _ => return artifact_error("idempotency_required"),
    };
    if unique_header(&headers, "x-diffuser-schema") != Some("diffuser-artifact/v1") {
        return artifact_error("version_unsupported");
    }
    let digest = match unique_header(&headers, "x-content-sha256") {
        Some(v)
            if v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            v.to_owned()
        }
        _ => return artifact_error("artifact_invalid"),
    };
    let body = match to_bytes(request.into_body(), 1_048_576).await {
        Ok(v) => v,
        Err(_) => return artifact_error("body_too_large"),
    };
    if length.is_some_and(|n| body.len() != n) || hex::encode(Sha256::digest(&body)) != digest {
        return artifact_error("artifact_invalid");
    }
    // Body transfer consumes time. Recheck the same credential chain before
    // publishing; an observation or access token may have expired meanwhile.
    let current = match context.authority.read() {
        Ok(value) => value,
        Err(_) => return artifact_error("storage_unavailable"),
    };
    let authority = match artifact_authorize(&current, &headers, &project, SCOPE_ARTIFACT_WRITE) {
        Ok(value) => value,
        Err(code) => return artifact_error(code),
    };
    if authority.actor != initial_authority.actor
        || authority.initiator != initial_authority.initiator
        || authority.lineage != initial_authority.lineage
    {
        return artifact_error("auth_invalid");
    }
    if let Err(code) = authority_still_live(&initial_authority, &authority) {
        return artifact_error(code);
    }
    let actor = &authority.actor;
    let now = authority.now;
    let id = match random_id("artifact") {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    let Some(expires) = now
        .checked_add(86_400_000)
        .filter(|v| *v <= i64::MAX as u64)
    else {
        return artifact_error("clock_untrusted");
    };
    // A typed, sorted JSON value binds the route, principal and actual bytes.
    let fingerprint_data = json!({"actor": actor, "bytes": body.len(), "data_class": "synthetic", "digest": digest,
        "kind": "input", "media_type": "application/octet-stream", "operation": "artifact_upload",
        "project": project, "schema_version": "diffuser-artifact/v1", "tenant": current.tenant});
    let encoded = serde_json::to_vec(&fingerprint_data).expect("fixed JSON values");
    let normalized = match super::la_contract::canonical_json(&encoded) {
        Ok(value) => value,
        Err(_) => return artifact_error("storage_unavailable"),
    };
    let fingerprint = hex::encode(Sha256::digest(normalized));
    let stored = match context.store.lock() {
        Ok(mut store) => (|| {
            let stored_id = store.put_input_idempotent(
                &current.tenant,
                &project,
                actor,
                &id,
                &body,
                &digest,
                now,
                expires,
                &key,
                &fingerprint,
                &authority.initiator,
                &authority.lineage,
                authority.now,
                authority.valid_until,
                authority.monotonic_until,
                authority.expiry_error,
            )?;
            let still_current =
                artifact_authorize(&current, &headers, &project, SCOPE_ARTIFACT_WRITE)?;
            authority_still_live(&authority, &still_current)?;
            let (manifest, _) = store.read_manifest_and_content(
                &current.tenant,
                &project,
                actor,
                &stored_id,
                still_current.now,
            )?;
            if manifest.kind != "input"
                || manifest.initiator.is_none()
                || manifest.lineage.is_none()
            {
                return Err("storage_unavailable");
            }
            let after_read =
                artifact_authorize(&current, &headers, &project, SCOPE_ARTIFACT_WRITE)?;
            authority_still_live(&authority, &after_read)?;
            Ok(stored_id)
        })(),
        Err(_) => Err("storage_unavailable"),
    };
    let id = match stored {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    let link = format!("/v1/diffuser/projects/{project}/artifacts/{id}");
    let request_id = match random_id("req") {
        Ok(value) => value,
        Err(code) => return artifact_error(code),
    };
    (
        StatusCode::CREATED,
        Json(
            json!({"schema_version":"diffuser-lane/v1", "receipt_id":format!("receipt_{id}"),
        "request_id":request_id, "project_id":project, "object_type":"artifact", "object_id":id,
        "revision":1, "state":"published", "links":{"self":link}}),
        ),
    )
        .into_response()
}

#[cfg_attr(not(test), allow(dead_code))]
fn artifact_read(
    context: &ArtifactContext,
    headers: &HeaderMap,
    project: &str,
    artifact: &str,
) -> Result<(super::la_artifacts::ArtifactManifest, Vec<u8>), &'static str> {
    let current = context
        .authority
        .read()
        .map_err(|_| "storage_unavailable")?;
    let authority = artifact_authorize(&current, headers, project, SCOPE_ARTIFACT_READ)?;
    let mut result = context
        .store
        .lock()
        .map_err(|_| "storage_unavailable")?
        .read_manifest_and_content(
            &current.tenant,
            project,
            &authority.actor,
            artifact,
            authority.now,
        )?;
    if result.0.kind == "output" {
        let claims = context.claims.as_ref().ok_or("storage_unavailable")?;
        let claims = claims.lock().map_err(|_| "storage_unavailable")?;
        let job = result.0.job.as_deref().ok_or("storage_unavailable")?;
        let view = claims.job_view(project, &authority.actor, job)?;
        if view.state != "succeeded"
            || view.result_artifact.as_deref() != Some(artifact)
            || result.0.assignment.as_deref() != Some(view.assignment.as_str())
        {
            return Err("object_not_found");
        }
        let mandate = claims.load_mandate(job)?;
        result.0.initiator = Some(mandate.draft.initiator);
        result.0.lineage = Some(mandate.draft.chain.into_iter().map(|g| g.id).collect());
    } else if result.0.kind != "input" || result.0.initiator.is_none() || result.0.lineage.is_none()
    {
        return Err("storage_unavailable");
    }
    // Recheck after the filesystem read too; access may expire during I/O.
    let after_read = artifact_authorize(&current, headers, project, SCOPE_ARTIFACT_READ)?;
    authority_still_live(&authority, &after_read)?;
    Ok(result)
}

#[cfg_attr(not(test), allow(dead_code))]
async fn artifact_manifest(
    State(context): State<ArtifactContext>,
    Path((project, artifact)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (m, _) = match artifact_read(&context, &headers, &project, &artifact) {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    Json(json!({"schema_version":"diffuser-artifact/v1", "tenant_id":m.tenant, "project_id":m.project,
        "owner_id":m.actor, "actor_id":m.actor, "initiator_id":m.initiator, "artifact_id":m.id, "version":1, "sha256":m.digest,
        "bytes":m.bytes, "media_type":"application/octet-stream", "kind":m.kind, "data_class":"synthetic",
        "created_at":m.created, "expires_at":m.expires, "publication_state":"published",
        "assignment_id":m.assignment, "job_id":m.job, "provenance":{"source":if m.kind == "input" {"caller_upload"} else {"worker_result"}, "authority_lineage":m.lineage}})).into_response()
}

#[cfg_attr(not(test), allow(dead_code))]
async fn artifact_content(
    State(context): State<ArtifactContext>,
    Path((project, artifact)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let (m, bytes) = match artifact_read(&context, &headers, &project, &artifact) {
        Ok(v) => v,
        Err(code) => return artifact_error(code),
    };
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::ETAG, format!("\"{}\"", m.digest)),
        ],
        bytes,
    )
        .into_response()
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquireResources {
    cpu_millicores: u64,
    ram_bytes: u64,
    storage_bytes: u64,
    gpu_domains: Vec<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquireRequest {
    schema_version: String,
    capability: String,
    lane_id: Option<String>,
    profile_id: Option<String>,
    resource_id: Option<String>,
    provider_id: Option<String>,
    requested_hardware_description: Option<String>,
    resources: AcquireResources,
    queue_policy: String,
    requested_lease_ms: u64,
    requested_tenure_ms: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
fn selector_valid(value: &str, slash: bool) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'-')
                || (slash && b == b'/')
        })
}

fn parse_acquire(bytes: &[u8]) -> Result<AcquireRequest, &'static str> {
    let normalized = super::la_contract::canonical_json(bytes)?;
    let value: serde_json::Value = match serde_json::from_slice(&normalized) {
        Ok(v) => v,
        Err(_) => return Err("schema_invalid"),
    };
    let required = [
        "schema_version",
        "capability",
        "lane_id",
        "profile_id",
        "resource_id",
        "provider_id",
        "requested_hardware_description",
        "resources",
        "queue_policy",
        "requested_lease_ms",
        "requested_tenure_ms",
    ];
    if !value.as_object().is_some_and(|v| {
        v.len() == required.len() && required.iter().all(|key| v.contains_key(*key))
    }) {
        return Err("schema_invalid");
    }
    let parsed: AcquireRequest = match serde_json::from_value(value) {
        Ok(v) => v,
        Err(_) => return Err("schema_invalid"),
    };
    if parsed.schema_version != "diffuser-lane/v1" {
        return Err("version_unsupported");
    }
    if !selector_valid(&parsed.capability, true)
        || parsed
            .lane_id
            .as_deref()
            .is_some_and(|v| !selector_valid(v, false))
        || parsed
            .profile_id
            .as_deref()
            .is_some_and(|v| !selector_valid(v, true))
        || parsed
            .resource_id
            .as_deref()
            .is_some_and(|v| !selector_valid(v, false))
        || parsed
            .provider_id
            .as_deref()
            .is_some_and(|v| !selector_valid(v, false))
        || parsed
            .requested_hardware_description
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 256)
        || parsed.resources.cpu_millicores == 0
        || parsed.resources.ram_bytes == 0
        || parsed.resources.storage_bytes == 0
        || parsed.requested_lease_ms == 0
        || parsed.requested_tenure_ms == 0
        || [
            parsed.resources.cpu_millicores,
            parsed.resources.ram_bytes,
            parsed.resources.storage_bytes,
            parsed.requested_lease_ms,
            parsed.requested_tenure_ms,
        ]
        .into_iter()
        .any(|v| v > i64::MAX as u64)
        || !matches!(parsed.queue_policy.as_str(), "refuse" | "fair_queue")
    {
        return Err("schema_invalid");
    }
    Ok(parsed)
}

#[cfg_attr(not(test), allow(dead_code))]
async fn acquire_closed_by_resource_gate(
    State(context): State<ArtifactContext>,
    Path(project): Path<String>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    if unique_header(&headers, "content-type") != Some("application/json") {
        return artifact_error("media_type_unsupported");
    }
    if let Err(code) = current_authority(
        &context.authority,
        &headers,
        &project,
        SCOPE_ASSIGNMENT_ACQUIRE | SCOPE_INSPECT_CAPABILITY,
    ) {
        return artifact_error(code);
    }
    if !unique_header(&headers, "idempotency-key").is_some_and(|v| {
        (16..=128).contains(&v.len())
            && v.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    }) {
        return artifact_error("idempotency_required");
    }
    let bytes = match to_bytes(request.into_body(), 65_536).await {
        Ok(v) => v,
        Err(_) => return artifact_error("body_too_large"),
    };
    if let Err(code) = current_authority(
        &context.authority,
        &headers,
        &project,
        SCOPE_ASSIGNMENT_ACQUIRE | SCOPE_INSPECT_CAPABILITY,
    ) {
        return artifact_error(code);
    }
    let parsed = match parse_acquire(&bytes) {
        Ok(value) => value,
        Err(code) => return artifact_error(code),
    };
    if parsed.queue_policy != "refuse" {
        return artifact_error("unsupported_operation");
    }
    if parsed.provider_id.is_some() {
        return artifact_error("provider_unconfigured");
    }
    if parsed.requested_hardware_description.is_some() {
        return artifact_error("constraint_unresolved");
    }
    let cuda_pin = if parsed.capability == la_backend::cuda::CAPABILITY {
        let [uuid] = parsed.resources.gpu_domains.as_slice() else {
            return artifact_error("schema_invalid");
        };
        let Some(uuid) = la_backend::cuda::DeviceUuid::parse(uuid) else {
            return artifact_error("schema_invalid");
        };
        if parsed.profile_id.as_deref() != Some(la_backend::cuda::PROFILE) {
            return artifact_error("capability_unavailable");
        }
        Some(Capability::CudaAddOne(uuid))
    } else {
        if parsed.capability != la_backend::CAPABILITY
            || !parsed.resources.gpu_domains.is_empty()
            || parsed
                .profile_id
                .as_deref()
                .is_some_and(|v| v != "cpu-artifact-inspect/v1")
        {
            return artifact_error("capability_unavailable");
        }
        None
    };
    if parsed
        .lane_id
        .as_deref()
        .is_some_and(|v| cuda_pin.is_some() || v != "lane_cpu_inspect")
        || parsed.resource_id.is_some()
    {
        return artifact_error("lane_not_found");
    }
    if let Some(claims) = &context.claims {
        if let Some(worker) = &context.worker {
            match worker.lock() {
                Ok(mut worker) => {
                    if let Err(code) = worker.journal.admission() {
                        return artifact_error(code);
                    }
                    if worker.journal.private_cuda_backend() != cuda_pin {
                        return artifact_error("capability_unavailable");
                    }
                    if let Some(pin) = cuda_pin {
                        if !worker.execute {
                            return artifact_error("capability_unavailable");
                        }
                        if let Err(code) = worker.journal.negotiate_backend(pin) {
                            return artifact_error(code);
                        }
                    }
                }
                Err(_) => return artifact_error("storage_unavailable"),
            }
        } else if cuda_pin.is_some() {
            return artifact_error("capability_unavailable");
        }
        if parsed.resources.cpu_millicores != 1000
            || parsed.resources.ram_bytes != 16 * 1024 * 1024
            || parsed.resources.storage_bytes != 2 * 1024 * 1024
        {
            return artifact_error("capacity_unavailable");
        }
        use sha2::{Digest, Sha256};
        // Holding the observation read lock through commit prevents a local
        // revocation update from racing authorization and the claim.
        let authority = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let authorized = match artifact_authorize(
            &authority,
            &headers,
            &project,
            SCOPE_ASSIGNMENT_ACQUIRE | SCOPE_INSPECT_CAPABILITY,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let canonical = match super::la_contract::canonical_json(&bytes) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let fingerprint = hex::encode(Sha256::digest(canonical));
        let id = match random_id("assignment") {
            Ok(id) => id,
            Err(code) => return artifact_error(code),
        };
        let mut store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        // The lock can block; recheck both wall and monotonic expiry immediately
        // before the transaction, without dropping the authority lock.
        let current = match artifact_authorize(
            &authority,
            &headers,
            &project,
            SCOPE_ASSIGNMENT_ACQUIRE | SCOPE_INSPECT_CAPABILITY,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if let Err(code) = authority_still_live(&authorized, &current) {
            return artifact_error(code);
        }
        let key = unique_header(&headers, "idempotency-key").expect("validated above");
        let mut hard = match current
            .now
            .checked_add(parsed.requested_tenure_ms.min(600_000))
        {
            Some(v) => v,
            None => return artifact_error("schema_invalid"),
        };
        for id in &current.lineage {
            let Some(grant) = authority.grants.iter().find(|grant| &grant.id == id) else {
                return artifact_error("delegation_denied");
            };
            hard = hard.min(grant.run_until).min(grant.execution_ceiling);
        }
        let lease = match current
            .now
            .checked_add(parsed.requested_lease_ms.min(120_000))
        {
            Some(v) => v.min(hard),
            None => return artifact_error("schema_invalid"),
        };
        if lease <= current.now {
            return artifact_error("deadline_elapsed");
        }
        let terms = super::la_store::AssignmentTerms {
            cpu_millicores: parsed.resources.cpu_millicores,
            memory_bytes: parsed.resources.ram_bytes,
            storage_bytes: parsed.resources.storage_bytes,
            accepted_at: current.now,
            lease_until: lease,
            hard_until: hard,
        };
        let worker_id = if let Some(worker) = &context.worker {
            match worker.lock() {
                Ok(worker) => worker.session.worker.clone(),
                Err(_) => return artifact_error("storage_unavailable"),
            }
        } else {
            "worker_fixture_001".to_owned()
        };
        let assignment = match store.reserve_scoped(
            &id,
            &project,
            &current.actor,
            key,
            &fingerprint,
            &worker_id,
            &current.lineage,
            (current.valid_until.min(hard), current.monotonic_until),
            &terms,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let (mut state, fence) = match store.assignment_view(&project, &current.actor, &assignment)
        {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let terms = match store.assignment_terms(&project, &current.actor, &assignment) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if state == "reserved" {
            if let Some(worker) = &context.worker {
                if let Ok(mut worker) = worker.lock() {
                    if let Err(code) = worker.journal.bind_assignment_terms(&assignment, &terms) {
                        return artifact_error(code);
                    }
                    let command = super::la_adapter::ReserveCommand {
                        worker: worker.session.worker.clone(),
                        boot: worker.session.boot.clone(),
                        assignment: assignment.clone(),
                        fence: fence as u64,
                        operation: super::la_store::reservation_operation(&assignment, fence),
                        lease_until: terms.lease_until,
                        hard_until: terms.hard_until,
                    };
                    let key = worker.session.key;
                    if let Ok(mac) = super::la_adapter::sign_reserve_command(&key, &command) {
                        let ServiceWorker {
                            journal, session, ..
                        } = &mut *worker;
                        if let Ok((receipt, mac)) =
                            journal.reserve_authenticated(session, &command, &mac)
                        {
                            if artifact_authorize(
                                &authority,
                                &headers,
                                &project,
                                SCOPE_ASSIGNMENT_ACQUIRE | SCOPE_INSPECT_CAPABILITY,
                            )
                            .is_ok_and(|latest| {
                                authority_still_live(&current, &latest).is_ok()
                                    && latest.now < terms.lease_until
                            }) && store
                                .acknowledge_reservation_receipt(
                                    &key,
                                    &command.worker,
                                    &command.boot,
                                    &command.operation,
                                    &receipt,
                                    &mac,
                                )
                                .is_ok()
                            {
                                state = "assigned".to_owned();
                            }
                        }
                    }
                }
            }
        }
        return (StatusCode::ACCEPTED, Json(json!({"schema_version":"diffuser-lane/v1", "assignment_id":assignment, "state":state, "lease_expires_at":terms.lease_until,"hard_expires_at":terms.hard_until}))).into_response();
    }
    // Real resource and protected-worker custody are not yet established.
    artifact_error("evidence_invalid")
}

#[cfg_attr(not(test), allow(dead_code))]
// This only validates and applies a supplied synthetic observation. It does
// not authenticate its source, persist revocations, or qualify admission; no
// runtime control channel currently calls it.
pub(super) fn apply_authority_observation(
    authority: &SharedAuthority,
    bytes: &[u8],
) -> Result<(), &'static str> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Observation {
        schema_version: String,
        sequence: u64,
        observed_at: u64,
        revoked: Vec<String>,
    }
    let normalized = super::la_contract::canonical_json(bytes).map_err(|_| "evidence_invalid")?;
    let observation: Observation =
        serde_json::from_slice(&normalized).map_err(|_| "evidence_invalid")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or("clock_untrusted")?;
    let mut current = authority.write().map_err(|_| "storage_unavailable")?;
    let mut seen = std::collections::BTreeSet::new();
    if observation.schema_version != "diffuser-authority-observation/v1"
        || current.observation_sequence.checked_add(1) != Some(observation.sequence)
        || observation.observed_at < current.observed_at
        || observation.observed_at > now
        || current.freshness_ms == 0
        || current.freshness_ms > 6_000
        || observation
            .observed_at
            .checked_add(current.freshness_ms)
            .is_none_or(|end| now >= end)
        || observation.revoked.len() > current.grants.len()
        || observation.revoked.iter().any(|id| {
            !seen.insert(id.as_str())
                || current
                    .grants
                    .iter()
                    .filter(|grant| grant.id == *id)
                    .count()
                    != 1
        })
    {
        return Err("evidence_invalid");
    }
    for grant in &mut current.grants {
        if seen.contains(grant.id.as_str()) {
            grant.revoked = true;
        }
    }
    current.observed_at = observation.observed_at;
    current.observation_sequence = observation.sequence;
    Ok(())
}

async fn closed_acquire(request: Request) -> Response {
    let headers = request.headers();
    if unique_header(headers, "content-type") != Some("application/json") {
        return artifact_error("media_type_unsupported");
    }
    if !unique_header(headers, "idempotency-key").is_some_and(|value| {
        (16..=128).contains(&value.len())
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    }) {
        return artifact_error("idempotency_required");
    }
    let bytes = match to_bytes(request.into_body(), 65_536).await {
        Ok(value) => value,
        Err(_) => return artifact_error("body_too_large"),
    };
    if let Err(code) = parse_acquire(&bytes) {
        return artifact_error(code);
    }
    artifact_error("routing_closed")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitRequest {
    schema_version: String,
    client_job_id: String,
    capability: String,
    profile_version: String,
    input_artifact_ids: Vec<String>,
    parameters: serde_json::Value,
    max_runtime_ms: u64,
    disconnect_policy: String,
    #[serde(skip)]
    backend: Option<Capability>,
}

fn valid_public_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn parse_submit(bytes: &[u8]) -> Result<SubmitRequest, &'static str> {
    let normalized = super::la_contract::canonical_json(bytes)?;
    let mut request: SubmitRequest =
        serde_json::from_slice(&normalized).map_err(|_| "schema_invalid")?;
    request.backend = la_backend::negotiate(&request.schema_version, &request.parameters)?;
    if !valid_public_id(&request.client_job_id)
        || !selector_valid(&request.capability, true)
        || request.profile_version.is_empty()
        || request.profile_version.len() > 96
        || request.input_artifact_ids.len() != 1
        || !request
            .input_artifact_ids
            .iter()
            .all(|id| valid_public_id(id))
        || request.max_runtime_ms == 0
        || request.max_runtime_ms > i64::MAX as u64
        || request.disconnect_policy != "continue_until_job_deadline"
    {
        return Err("schema_invalid");
    }
    Ok(request)
}

async fn closed_submit(request: Request) -> Response {
    let headers = request.headers();
    if unique_header(headers, "content-type") != Some("application/json") {
        return artifact_error("media_type_unsupported");
    }
    if !unique_header(headers, "idempotency-key").is_some_and(valid_public_id) {
        return artifact_error("idempotency_required");
    }
    let bytes = match to_bytes(request.into_body(), 65_536).await {
        Ok(value) => value,
        Err(_) => return artifact_error("body_too_large"),
    };
    if let Err(code) = parse_submit(&bytes) {
        return artifact_error(code);
    }
    artifact_error("routing_closed")
}

#[cfg_attr(not(test), allow(dead_code))]
async fn submit_closed_by_resource_gate(
    State(context): State<ArtifactContext>,
    Path((project, assignment)): Path<(String, String)>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    if unique_header(&headers, "content-type") != Some("application/json") {
        return artifact_error("media_type_unsupported");
    }
    if let Err(code) = current_authority(
        &context.authority,
        &headers,
        &project,
        SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
    ) {
        return artifact_error(code);
    }
    if !valid_public_id(&assignment) {
        return artifact_error("object_not_found");
    }
    if !unique_header(&headers, "idempotency-key").is_some_and(valid_public_id) {
        return artifact_error("idempotency_required");
    }
    let bytes = match to_bytes(request.into_body(), 65_536).await {
        Ok(value) => value,
        Err(_) => return artifact_error("body_too_large"),
    };
    if let Err(code) = current_authority(
        &context.authority,
        &headers,
        &project,
        SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
    ) {
        return artifact_error(code);
    }
    let parsed = match parse_submit(&bytes) {
        Ok(value) => value,
        Err(code) => return artifact_error(code),
    };
    if parsed.capability != Capability::public_capability(parsed.backend)
        || parsed.profile_version != "1"
    {
        return artifact_error("capability_unavailable");
    }
    if parsed.max_runtime_ms > 10_000 {
        return artifact_error("runtime_limit_exceeded");
    }
    if let (Some(claims), Some(worker)) = (&context.claims, &context.worker) {
        match worker.lock() {
            Ok(worker) => {
                if let Err(code) = worker.journal.admission() {
                    return artifact_error(code);
                }
            }
            Err(_) => return artifact_error("storage_unavailable"),
        }
        let observation = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let authorized = match artifact_authorize(
            &observation,
            &headers,
            &project,
            SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if parsed.backend.is_some() {
            let mut store = match claims.lock() {
                Ok(store) => store,
                Err(_) => return artifact_error("storage_unavailable"),
            };
            let fingerprint = match submit_fingerprint(&assignment, &bytes) {
                Ok(value) => value,
                Err(code) => return artifact_error(code),
            };
            let key = unique_header(&headers, "idempotency-key").expect("validated above");
            match store.existing_job_retry(
                &project,
                &authorized.actor,
                &assignment,
                key,
                &fingerprint,
                &authorized.lineage,
                Some(&parsed.client_job_id),
            ) {
                Ok(existing) => {
                    if let Err(code) = settle_observed_job(
                        &context,
                        &observation,
                        &authorized,
                        &mut store,
                        &project,
                        &existing.id,
                    ) {
                        return artifact_error(code);
                    }
                    let view = match store.job_view(&project, &authorized.actor, &existing.id) {
                        Ok(view) => view,
                        Err(code) => return artifact_error(code),
                    };
                    let latest = match artifact_authorize(
                        &observation,
                        &headers,
                        &project,
                        SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
                    ) {
                        Ok(latest) => latest,
                        Err(code) => return artifact_error(code),
                    };
                    if let Err(code) = authority_still_live(&authorized, &latest) {
                        return artifact_error(code);
                    }
                    return (StatusCode::ACCEPTED, Json(json!({"schema_version":"diffuser-lane/v1","job_id":view.id,"assignment_id":assignment,"state":view.state,"revision":view.revision}))).into_response();
                }
                Err("routing_closed") => (),
                Err(code) => return artifact_error(code),
            }
        }
        let (manifest, input_bytes) = {
            let mut artifacts = match context.store.lock() {
                Ok(value) => value,
                Err(_) => return artifact_error("storage_unavailable"),
            };
            match artifacts.read_manifest_and_content(
                &observation.tenant,
                &project,
                &authorized.actor,
                &parsed.input_artifact_ids[0],
                authorized.now,
            ) {
                Ok((manifest, bytes)) if manifest.kind == "input" => (manifest, bytes),
                Ok(_) => return artifact_error("artifact_invalid"),
                Err(code) => return artifact_error(code),
            }
        };
        let mut store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let current = match artifact_authorize(
            &observation,
            &headers,
            &project,
            SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if let Err(code) = authority_still_live(&authorized, &current) {
            return artifact_error(code);
        }
        let terms = match store.assignment_terms(&project, &current.actor, &assignment) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        // This private single-worker router cannot route a CUDA assignment
        // through either SHA-256 path, even if given a valid CPU artifact.
        let cuda_pin = parsed
            .backend
            .filter(|c| matches!(c, Capability::CudaAddOne(_)));
        match worker.lock() {
            Ok(worker) if worker.journal.private_cuda_backend() == cuda_pin => (),
            Ok(_) => return artifact_error("capability_unavailable"),
            Err(_) => return artifact_error("storage_unavailable"),
        }
        if let Some(capability) = parsed.backend {
            if let Err(code) = capability.validate_input(&input_bytes) {
                return artifact_error(code);
            }
            match worker.lock() {
                Ok(mut worker) => {
                    if !worker.execute {
                        return artifact_error("capability_unavailable");
                    }
                    if let Err(code) = worker
                        .journal
                        .admission()
                        .and_then(|_| worker.journal.negotiate_backend(capability))
                    {
                        return artifact_error(code);
                    }
                }
                Err(_) => return artifact_error("storage_unavailable"),
            }
        }
        let worker_id = match worker.lock() {
            Ok(value) => value.session.worker.clone(),
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let mut chain = Vec::new();
        for id in &current.lineage {
            let Some(grant) = observation.grants.iter().find(|grant| &grant.id == id) else {
                return artifact_error("delegation_denied");
            };
            chain.push(super::la_auth::MandateGrant {
                id: grant.id.clone(),
                parent: grant.parent.clone(),
                run_until: grant.run_until,
                execution_ceiling: grant.execution_ceiling,
            });
        }
        let job = match random_id("job") {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let operation = match random_id("operation") {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let draft = super::la_auth::MandateDraft {
            tenant: observation.tenant.clone(),
            project: project.clone(),
            actor: current.actor.clone(),
            initiator: current.initiator.clone(),
            lineage: current.lineage[0].clone(),
            assignment: assignment.clone(),
            job,
            operation,
            input_digest: manifest.digest,
            profile: Capability::mandate_profile(parsed.backend),
            worker: worker_id,
            cpu_millicores: terms.cpu_millicores,
            memory_bytes: terms.memory_bytes,
            storage_bytes: terms.storage_bytes,
            policy: "lab-proposal-v1".into(),
            accepted_at: current.now,
            runtime_ms: parsed.max_runtime_ms,
            assignment_hard: terms.hard_until,
            project_ceiling: terms.hard_until,
            chain,
        };
        let (worker_boot, fence) = match (
            worker.lock(),
            store.assignment_view(&project, &current.actor, &assignment),
        ) {
            (Ok(worker), Ok((state, fence))) if state == "assigned" => {
                (worker.session.boot.clone(), fence)
            }
            _ => return artifact_error("state_conflict"),
        };
        let mut mandate_until = match current.now.checked_add(parsed.max_runtime_ms) {
            Some(value) => value.min(terms.hard_until),
            None => return artifact_error("deadline_elapsed"),
        };
        for grant in &draft.chain {
            mandate_until = mandate_until
                .min(grant.run_until)
                .min(grant.execution_ceiling);
        }
        let permit_until = match current.now.checked_add(1_500) {
            Some(value) => value
                .min(mandate_until)
                .min(terms.lease_until)
                .min(current.valid_until),
            None => return artifact_error("deadline_elapsed"),
        };
        if permit_until <= current.now {
            return artifact_error("deadline_elapsed");
        }
        let command = super::la_adapter::InspectCommand {
            backend: parsed.backend,
            worker: draft.worker.clone(),
            boot: worker_boot,
            fence: fence as u64,
            assignment: assignment.clone(),
            operation: draft.operation.clone(),
            job: draft.job.clone(),
            input_digest: draft.input_digest.clone(),
            accepted_at: current.now,
            mandate_until,
            permit_until,
        };
        let fingerprint = match submit_fingerprint(&assignment, &bytes) {
            Ok(v) => v,
            Err(code) => return artifact_error(code),
        };
        let key = unique_header(&headers, "idempotency-key").expect("validated above");
        let job = match store.create_pending_job_authorized(
            &draft,
            &parsed.input_artifact_ids[0],
            key,
            &fingerprint,
            (
                current.valid_until.min(terms.lease_until),
                current.monotonic_until,
            ),
            &command,
            &parsed.client_job_id,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        // Commit the permit ACK and send claim while the authority snapshot is
        // stable, then drop controller locks before worker computation. This
        // lets revocation and close intents advance while work is in flight.
        let mut dispatch = None;
        if let (Ok(saved), Ok(mut worker)) = (store.job_permit_command(&job), worker.lock()) {
            let key = worker.session.key;
            let bound = store
                .load_mandate(&job)
                .and_then(|mandate| worker.journal.bind_mandate(mandate));
            if let Err(code) = bound {
                return artifact_error(code);
            }
            if let Ok(mac) = super::la_adapter::sign_inspect_command(&key, &saved) {
                let ServiceWorker {
                    journal,
                    session,
                    execute,
                } = &mut *worker;
                if let Ok((receipt, mac)) = journal.accept_inspect_permit(session, &saved, &mac) {
                    if let Ok(latest) = artifact_authorize(
                        &observation,
                        &headers,
                        &project,
                        SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
                    ) {
                        if authority_still_live(&current, &latest).is_ok()
                            && store
                                .acknowledge_job_permit(&key, &receipt, &mac, latest.now)
                                .is_ok()
                            && *execute
                            && job == draft.job
                            && !(parsed.client_job_id == "vertical_client_job1"
                                && fixture_hold_before_cas())
                            && store.claim_job_start(&job, latest.now).is_ok()
                        {
                            dispatch = Some((saved, key));
                        }
                    }
                }
            }
        }
        drop(store);
        drop(observation);
        let result = if let Some((saved, key)) = dispatch {
            if let Ok(mut worker) = worker.lock() {
                let ServiceWorker {
                    journal, session, ..
                } = &mut *worker;
                match super::la_adapter::sign_stage_command(&key, &saved) {
                    Ok(stage_mac)
                        if journal
                            .stage_authenticated_input(session, &saved, &stage_mac, &input_bytes)
                            .is_ok() =>
                    {
                        #[cfg(test)]
                        if parsed.client_job_id == "vertical_client_job1"
                            && std::env::var("DIFFUSER_LA_RESOURCE_PROBE").is_ok_and(|v| {
                                v.starts_with("controller-stop-recovery")
                                    || v.starts_with("controller-never-started-m2")
                            })
                        {
                            // Fault boundary: retain the admitted original permit and staged
                            // input, but hold dispatch before the worker's durable entry.
                            // Cancellation still travels through the ordinary HTTP/RPC path.
                            None
                        } else {
                            match super::la_adapter::sign_start_command(&key, &saved) {
                                Ok(mac) => journal
                                    .inspect_staged(session, &saved, &mac)
                                    .ok()
                                    .map(|value| (key, value)),
                                Err(_) => None,
                            }
                        }
                        #[cfg(not(test))]
                        match super::la_adapter::sign_start_command(&key, &saved) {
                            Ok(mac) => journal
                                .inspect_staged(session, &saved, &mac)
                                .ok()
                                .map(|value| (key, value)),
                            Err(_) => None,
                        }
                    }
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        // Recheck current authority after work and before any publication.
        let observation = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let after = match artifact_authorize(
            &observation,
            &headers,
            &project,
            SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if let Err(code) = authority_still_live(&current, &after) {
            return artifact_error(code);
        }
        if after.actor != current.actor
            || after.initiator != current.initiator
            || after.lineage != current.lineage
        {
            return artifact_error("auth_invalid");
        }
        let mut store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let fresh = match artifact_authorize(
            &observation,
            &headers,
            &project,
            SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if let Err(code) = authority_still_live(&after, &fresh) {
            return artifact_error(code);
        }
        if let Some((key, (report, receipt, mac))) = result {
            if let Ok(output) = random_id("artifact") {
                if store
                    .record_job_result(
                        &key,
                        &receipt,
                        &mac,
                        &report,
                        input_bytes.len(),
                        &output,
                        after.now,
                    )
                    .is_ok()
                {
                    if let Ok(mut artifacts) = context.store.lock() {
                        if let Some(expires) = after.now.checked_add(86_400_000) {
                            if artifacts
                                .put_output(
                                    &observation.tenant,
                                    &project,
                                    &after.actor,
                                    &output,
                                    &assignment,
                                    &job,
                                    &report,
                                    &receipt.report_digest,
                                    after.now,
                                    expires,
                                )
                                .is_ok()
                            {
                                if let Ok((manifest, verified)) = artifacts
                                    .read_manifest_and_content(
                                        &observation.tenant,
                                        &project,
                                        &after.actor,
                                        &output,
                                        after.now,
                                    )
                                {
                                    if manifest.kind == "output"
                                        && manifest.job.as_deref() == Some(job.as_str())
                                        && manifest.assignment.as_deref()
                                            == Some(assignment.as_str())
                                        && verified == report
                                    {
                                        let _ = store.publish_job_result(
                                            &job,
                                            &output,
                                            &receipt.report_digest,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let view = match store.job_view(&project, &current.actor, &job) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        return (StatusCode::ACCEPTED,Json(json!({"schema_version":"diffuser-lane/v1","job_id":job,"assignment_id":assignment,"state":view.state,"revision":view.revision}))).into_response();
    }
    // Real resource and protected-worker custody are not yet established.
    artifact_error("evidence_invalid")
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionRequest {
    schema_version: String,
    expected_revision: u64,
}

fn parse_revision(bytes: &[u8], renew: bool) -> Result<(), &'static str> {
    let normalized = super::la_contract::canonical_json(bytes)?;
    if renew {
        let request: RenewRequest =
            serde_json::from_slice(&normalized).map_err(|_| "schema_invalid")?;
        if request.schema_version != "diffuser-lane/v1" {
            return Err("version_unsupported");
        }
        if request.requested_lease_ms == 0
            || request.requested_lease_ms > i64::MAX as u64
            || request.expected_revision > i64::MAX as u64
        {
            return Err("schema_invalid");
        }
    } else {
        let request: RevisionRequest =
            serde_json::from_slice(&normalized).map_err(|_| "schema_invalid")?;
        if request.schema_version != "diffuser-lane/v1" {
            return Err("version_unsupported");
        }
        if request.expected_revision > i64::MAX as u64 {
            return Err("schema_invalid");
        }
    }
    Ok(())
}

async fn closed_revision(request: Request) -> Response {
    let headers = request.headers();
    if unique_header(headers, "content-type") != Some("application/json") {
        return artifact_error("media_type_unsupported");
    }
    if !unique_header(headers, "idempotency-key").is_some_and(valid_public_id) {
        return artifact_error("idempotency_required");
    }
    let bytes = match to_bytes(request.into_body(), 65_536).await {
        Ok(value) => value,
        Err(_) => return artifact_error("body_too_large"),
    };
    if let Err(code) = parse_revision(&bytes, false) {
        return artifact_error(code);
    }
    artifact_error("routing_closed")
}

#[cfg_attr(not(test), allow(dead_code))]
fn unavailable_status(
    context: &ArtifactContext,
    project: &str,
    object: &str,
    headers: &HeaderMap,
    scope: u64,
) -> Response {
    if let Err(code) = current_authority(&context.authority, headers, project, scope) {
        return artifact_error(code);
    }
    if !valid_public_id(object) {
        return artifact_error("object_not_found");
    }
    // The current component ledger does not hold a complete, authenticated
    // public assignment/job representation; never synthesize one from it.
    artifact_error("storage_unavailable")
}

#[cfg_attr(not(test), allow(dead_code))]
async fn assignment_status_unavailable(
    State(context): State<ArtifactContext>,
    Path((project, object)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(claims) = &context.claims {
        let observation = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let authority =
            match artifact_authorize(&observation, &headers, &project, SCOPE_ASSIGNMENT_READ) {
                Ok(value) => value,
                Err(code) => return artifact_error(code),
            };
        if observation
            .loss_scope
            .as_ref()
            .is_some_and(|(_, assignment)| &object != assignment)
        {
            return artifact_error("object_not_found");
        }
        if !valid_public_id(&object) {
            return artifact_error("object_not_found");
        }
        let store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let current =
            match artifact_authorize(&observation, &headers, &project, SCOPE_ASSIGNMENT_READ) {
                Ok(value) => value,
                Err(code) => return artifact_error(code),
            };
        if let Err(code) = authority_still_live(&authority, &current) {
            return artifact_error(code);
        }
        if authority.actor != current.actor {
            return artifact_error("auth_invalid");
        }
        let (state, _) = match store.assignment_view(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let revision = match store.assignment_revision(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        return Json(
            json!({"schema_version":"diffuser-lane/v1", "assignment_id":object, "state":state,"revision":revision}),
        )
        .into_response();
    }
    unavailable_status(&context, &project, &object, &headers, SCOPE_ASSIGNMENT_READ)
}
#[cfg_attr(not(test), allow(dead_code))]
async fn job_status_unavailable(
    State(context): State<ArtifactContext>,
    Path((project, object)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Some(claims) = &context.claims {
        let observation = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let first = match artifact_authorize(&observation, &headers, &project, SCOPE_JOB_READ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if observation
            .loss_scope
            .as_ref()
            .is_some_and(|(job, _)| &object != job)
        {
            return artifact_error("object_not_found");
        }
        if !valid_public_id(&object) {
            return artifact_error("object_not_found");
        }
        let mut store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let current = match artifact_authorize(&observation, &headers, &project, SCOPE_JOB_READ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if let Err(code) = authority_still_live(&first, &current) {
            return artifact_error(code);
        }
        if let Err(code) = settle_observed_job(
            &context,
            &observation,
            &current,
            &mut store,
            &project,
            &object,
        ) {
            return artifact_error(code);
        }
        let view = match store.job_view(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        return Json(json!({"schema_version":"diffuser-lane/v1","job_id":view.id,"assignment_id":view.assignment,"state":view.state,"revision":view.revision,"result_artifact_id":view.result_artifact})).into_response();
    }
    unavailable_status(&context, &project, &object, &headers, SCOPE_JOB_READ)
}

#[cfg_attr(not(test), allow(dead_code))]
async fn revision_unavailable(
    context: ArtifactContext,
    project: String,
    object: String,
    request: Request,
    scope: u64,
    renew: bool,
    unsupported: bool,
) -> Response {
    let headers = request.headers().clone();
    if unique_header(&headers, "content-type") != Some("application/json") {
        return artifact_error("media_type_unsupported");
    }
    if let Err(code) = current_authority(&context.authority, &headers, &project, scope) {
        return artifact_error(code);
    }
    if !valid_public_id(&object) {
        return artifact_error("object_not_found");
    }
    if !unique_header(&headers, "idempotency-key").is_some_and(valid_public_id) {
        return artifact_error("idempotency_required");
    }
    let bytes = match to_bytes(request.into_body(), 65_536).await {
        Ok(value) => value,
        Err(_) => return artifact_error("body_too_large"),
    };
    if let Err(code) = current_authority(&context.authority, &headers, &project, scope) {
        return artifact_error(code);
    }
    if let Err(code) = parse_revision(&bytes, renew) {
        return artifact_error(code);
    }
    if unsupported {
        return artifact_error("unsupported_operation");
    }
    // Existing partial close/permit helpers do not authenticate worker receipts
    // or cover active jobs, so this path cannot execute those transitions yet.
    artifact_error("storage_unavailable")
}

#[cfg_attr(not(test), allow(dead_code))]
async fn release_unavailable(
    State(context): State<ArtifactContext>,
    Path((project, object)): Path<(String, String)>,
    request: Request,
) -> Response {
    if let Some(claims) = &context.claims {
        let headers = request.headers().clone();
        if unique_header(&headers, "content-type") != Some("application/json") {
            return artifact_error("media_type_unsupported");
        }
        if let Err(code) = current_authority(
            &context.authority,
            &headers,
            &project,
            SCOPE_ASSIGNMENT_RELEASE,
        ) {
            return artifact_error(code);
        }
        if !valid_public_id(&object) {
            return artifact_error("object_not_found");
        }
        let Some(key) = unique_header(&headers, "idempotency-key").filter(|v| valid_public_id(v))
        else {
            return artifact_error("idempotency_required");
        };
        let bytes = match to_bytes(request.into_body(), 65_536).await {
            Ok(value) => value,
            Err(_) => return artifact_error("body_too_large"),
        };
        if let Err(code) = parse_revision(&bytes, false) {
            return artifact_error(code);
        }
        let normalized = match super::la_contract::canonical_json(&bytes) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let parsed: RevisionRequest = match serde_json::from_slice(&normalized) {
            Ok(value) => value,
            Err(_) => return artifact_error("schema_invalid"),
        };
        let observation = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let first =
            match artifact_authorize(&observation, &headers, &project, SCOPE_ASSIGNMENT_RELEASE) {
                Ok(value) => value,
                Err(code) => return artifact_error(code),
            };
        if observation
            .loss_scope
            .as_ref()
            .is_some_and(|(_, assignment)| &object != assignment)
        {
            return artifact_error("object_not_found");
        }
        let mut store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let current =
            match artifact_authorize(&observation, &headers, &project, SCOPE_ASSIGNMENT_RELEASE) {
                Ok(value) => value,
                Err(code) => return artifact_error(code),
            };
        if let Err(code) = authority_still_live(&first, &current) {
            return artifact_error(code);
        }
        if let Err(code) = store.request_assignment_release(
            &project,
            &current.actor,
            &object,
            key,
            parsed.expected_revision,
            current.now,
        ) {
            return artifact_error(code);
        }
        if let Some(worker) = &context.worker {
            if let Ok(mut worker) = worker.lock() {
                let worker_key = worker.session.key;
                let ServiceWorker {
                    journal, session, ..
                } = &mut *worker;
                if let Ok(commands) = store.stopping_job_commands(&object) {
                    for command in commands {
                        if let Ok(mac) = super::la_adapter::sign_stop_command(&worker_key, &command)
                        {
                            if let Ok((receipt, mac)) =
                                journal.stop_with_receipt(session, &command, &mac)
                            {
                                let _ = store.acknowledge_job_stop(&worker_key, &receipt, &mac);
                            }
                        }
                    }
                }
                if let Ok(command) =
                    store.assignment_close_command(&project, &current.actor, &object)
                {
                    if store.close_lost_worker(&command).unwrap_or(false) {
                        // Exact independent death settlement closes this old
                        // assignment without a fictitious worker ACK.
                    } else if let Ok(mac) =
                        super::la_adapter::sign_close_command(&worker_key, &command)
                    {
                        if let Ok((receipt, mac)) =
                            journal.close_authenticated(session, &command, &mac)
                        {
                            let _ = store.acknowledge_assignment_stop(&worker_key, &receipt, &mac);
                        }
                    }
                }
            }
        }
        let state = match store.assignment_view(&project, &current.actor, &object) {
            Ok((state, _)) => state,
            Err(code) => return artifact_error(code),
        };
        let status = if state == "closed" {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        };
        return (
            status,
            Json(json!({"schema_version":"diffuser-lane/v1","assignment_id":object,"state":state})),
        )
            .into_response();
    }
    revision_unavailable(
        context,
        project,
        object,
        request,
        SCOPE_ASSIGNMENT_RELEASE,
        false,
        false,
    )
    .await
}
#[cfg_attr(not(test), allow(dead_code))]
async fn cancel_unavailable(
    State(context): State<ArtifactContext>,
    Path((project, object)): Path<(String, String)>,
    request: Request,
) -> Response {
    if let Some(claims) = &context.claims {
        let headers = request.headers().clone();
        if unique_header(&headers, "content-type") != Some("application/json") {
            return artifact_error("media_type_unsupported");
        }
        if let Err(code) =
            current_authority(&context.authority, &headers, &project, SCOPE_JOB_CANCEL)
        {
            return artifact_error(code);
        }
        if !valid_public_id(&object) {
            return artifact_error("object_not_found");
        }
        let Some(key) =
            unique_header(&headers, "idempotency-key").filter(|value| valid_public_id(value))
        else {
            return artifact_error("idempotency_required");
        };
        let bytes = match to_bytes(request.into_body(), 65_536).await {
            Ok(value) => value,
            Err(_) => return artifact_error("body_too_large"),
        };
        if let Err(code) = parse_revision(&bytes, false) {
            return artifact_error(code);
        }
        let normalized = match super::la_contract::canonical_json(&bytes) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let parsed: RevisionRequest = match serde_json::from_slice(&normalized) {
            Ok(value) => value,
            Err(_) => return artifact_error("schema_invalid"),
        };
        let observation = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let first = match artifact_authorize(&observation, &headers, &project, SCOPE_JOB_CANCEL) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if observation
            .loss_scope
            .as_ref()
            .is_some_and(|(job, _)| &object != job)
        {
            return artifact_error("object_not_found");
        }
        let mut store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let current = match artifact_authorize(&observation, &headers, &project, SCOPE_JOB_CANCEL) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        if let Err(code) = authority_still_live(&first, &current) {
            return artifact_error(code);
        }
        if let Err(code) = store.request_job_stop(
            &project,
            &current.actor,
            &object,
            key,
            parsed.expected_revision,
        ) {
            return artifact_error(code);
        }
        let needs_stop = store
            .job_view(&project, &current.actor, &object)
            .is_ok_and(|v| v.state == "stopping");
        if let (true, Some(worker), Ok(command)) = (
            needs_stop,
            &context.worker,
            store.job_permit_command(&object),
        ) {
            if let Ok(mut worker) = worker.lock() {
                let worker_key = worker.session.key;
                if let Ok(mac) = super::la_adapter::sign_stop_command(&worker_key, &command) {
                    let ServiceWorker {
                        journal, session, ..
                    } = &mut *worker;
                    if let Ok((receipt, mac)) = journal.stop_with_receipt(session, &command, &mac) {
                        if let Ok(latest) =
                            artifact_authorize(&observation, &headers, &project, SCOPE_JOB_CANCEL)
                        {
                            if authority_still_live(&current, &latest).is_ok() {
                                let _ = store.acknowledge_job_stop(&worker_key, &receipt, &mac);
                            }
                        }
                    }
                }
            }
        }
        if let Err(code) = settle_observed_job(
            &context,
            &observation,
            &current,
            &mut store,
            &project,
            &object,
        ) {
            return artifact_error(code);
        }
        let view = match store.job_view(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        return (StatusCode::ACCEPTED,Json(json!({"schema_version":"diffuser-lane/v1","job_id":object,"state":view.state,"revision":view.revision}))).into_response();
    }
    revision_unavailable(
        context,
        project,
        object,
        request,
        SCOPE_JOB_CANCEL,
        false,
        false,
    )
    .await
}
#[cfg_attr(not(test), allow(dead_code))]
async fn renew_unavailable(
    State(context): State<ArtifactContext>,
    Path((project, object)): Path<(String, String)>,
    request: Request,
) -> Response {
    if let (Some(claims), Some(worker)) = (&context.claims, &context.worker) {
        let headers = request.headers().clone();
        if unique_header(&headers, "content-type") != Some("application/json") {
            return artifact_error("media_type_unsupported");
        }
        if let Err(code) = current_authority(
            &context.authority,
            &headers,
            &project,
            SCOPE_ASSIGNMENT_RENEW,
        ) {
            return artifact_error(code);
        }
        if !valid_public_id(&object) {
            return artifact_error("object_not_found");
        }
        let Some(key) = unique_header(&headers, "idempotency-key").filter(|v| valid_public_id(v))
        else {
            return artifact_error("idempotency_required");
        };
        let bytes = match to_bytes(request.into_body(), 65_536).await {
            Ok(value) => value,
            Err(_) => return artifact_error("body_too_large"),
        };
        if let Err(code) = parse_revision(&bytes, true) {
            return artifact_error(code);
        }
        let normalized = match super::la_contract::canonical_json(&bytes) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let parsed: RenewRequest = match serde_json::from_slice(&normalized) {
            Ok(value) => value,
            Err(_) => return artifact_error("schema_invalid"),
        };
        let observation = match context.authority.read() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let first =
            match artifact_authorize(&observation, &headers, &project, SCOPE_ASSIGNMENT_RENEW) {
                Ok(value) => value,
                Err(code) => return artifact_error(code),
            };
        let mut store = match claims.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let current =
            match artifact_authorize(&observation, &headers, &project, SCOPE_ASSIGNMENT_RENEW) {
                Ok(value) => value,
                Err(code) => return artifact_error(code),
            };
        if let Err(code) = authority_still_live(&first, &current) {
            return artifact_error(code);
        }
        let terms = match store.assignment_terms(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let (_, fence) = match store.assignment_view(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let mut worker = match worker.lock() {
            Ok(value) => value,
            Err(_) => return artifact_error("storage_unavailable"),
        };
        let mut ceiling = terms.hard_until;
        for id in &current.lineage {
            let Some(grant) = observation.grants.iter().find(|g| &g.id == id) else {
                return artifact_error("delegation_denied");
            };
            ceiling = ceiling.min(grant.run_until).min(grant.execution_ceiling);
        }
        let until = match current
            .now
            .checked_add(parsed.requested_lease_ms.min(120_000))
        {
            Some(value) => value.min(ceiling),
            None => return artifact_error("schema_invalid"),
        };
        let operation = match random_id("renew") {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let revision = match parsed.expected_revision.checked_add(1) {
            Some(value) => value,
            None => return artifact_error("schema_invalid"),
        };
        let command = super::la_adapter::RenewCommand {
            worker: worker.session.worker.clone(),
            boot: worker.session.boot.clone(),
            assignment: object.clone(),
            fence: fence as u64,
            operation,
            revision,
            previous_until: terms.lease_until,
            requested_until: until,
        };
        let saved = match store.request_assignment_renewal(
            &project,
            &current.actor,
            key,
            parsed.requested_lease_ms,
            &command,
            &current.lineage,
            (current.valid_until, current.monotonic_until),
            current.now,
        ) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let worker_key = worker.session.key;
        if let Ok(mac) = super::la_adapter::sign_renew_command(&worker_key, &saved) {
            let ServiceWorker {
                journal, session, ..
            } = &mut *worker;
            if let Ok((receipt, mac)) = journal.renew_authenticated(session, &saved, &mac) {
                if let Ok(latest) =
                    artifact_authorize(&observation, &headers, &project, SCOPE_ASSIGNMENT_RENEW)
                {
                    if authority_still_live(&current, &latest).is_ok() {
                        let _ = store.acknowledge_assignment_renewal(
                            &worker_key,
                            &receipt,
                            &mac,
                            latest.now,
                        );
                    }
                }
            }
        }
        let terms = match store.assignment_terms(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let revision = match store.assignment_revision(&project, &current.actor, &object) {
            Ok(value) => value,
            Err(code) => return artifact_error(code),
        };
        let acknowledged =
            revision == saved.revision as i64 && terms.lease_until == saved.requested_until;
        return (if acknowledged {StatusCode::OK} else {StatusCode::ACCEPTED},Json(json!({"schema_version":"diffuser-lane/v1","assignment_id":object,"revision":revision,"lease_expires_at":terms.lease_until,"renewal_state":if acknowledged {"acknowledged"} else {"pending"}}))).into_response();
    }
    revision_unavailable(
        context,
        project,
        object,
        request,
        SCOPE_ASSIGNMENT_RENEW,
        true,
        false,
    )
    .await
}

#[cfg_attr(not(test), allow(dead_code))]
async fn queue_cancel_unsupported(
    State(context): State<ArtifactContext>,
    Path((project, object)): Path<(String, String)>,
    request: Request,
) -> Response {
    revision_unavailable(
        context,
        project,
        object,
        request,
        SCOPE_ASSIGNMENT_RELEASE,
        false,
        true,
    )
    .await
}

/// Apply a protected-source observation and its revocations only after the
/// authenticated durable append succeeds. The authority write lock spans the
/// validation and commit so public operations cannot race this change.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn apply_authenticated_authority_observation(
    authority: &SharedAuthority,
    store: &mut super::la_store::ClaimStore,
    key: &[u8; 32],
    bytes: &[u8],
    mac: &[u8; 32],
) -> Result<(), &'static str> {
    let canonical = super::la_contract::canonical_json(bytes).map_err(|_| "evidence_invalid")?;
    super::la_adapter::verify_authority_observation(key, &canonical, mac)?;
    let mut current = authority.write().map_err(|_| "storage_unavailable")?;
    let shadow = std::sync::Arc::new(std::sync::RwLock::new(current.clone()));
    apply_authority_observation(&shadow, &canonical)?;
    let updated = shadow.read().map_err(|_| "storage_unavailable")?.clone();
    store.append_authority_observation(key, &canonical, mac)?;
    *current = updated;
    Ok(())
}

/// Replay the authenticated journal against protected high-water custody. The
/// latest observation must still be fresh before it can authorize operations.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn recover_authenticated_authority(
    authority: &SharedAuthority,
    store: &super::la_store::ClaimStore,
    key: &[u8; 32],
    expected_sequence: u64,
) -> Result<(), &'static str> {
    let mut current = authority.write().map_err(|_| "storage_unavailable")?;
    let updated = replay_authority_history(&current, store, key, expected_sequence)?;
    if expected_sequence != 0 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if updated.freshness_ms == 0
            || updated.freshness_ms > 6000
            || updated.observed_at > now
            || updated
                .observed_at
                .checked_add(updated.freshness_ms)
                .is_none_or(|end| now >= end)
        {
            return Err("evidence_stale");
        }
    }
    *current = updated;
    Ok(())
}

/// Restore the exact signed history for a protected read-only recovery. The
/// retained observation keeps its original time, including when stale. Normal
/// handler authorization refuses it until a fresh, sequenced protected source
/// observation is committed; restart never manufactures a new freshness lease.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn restore_readback_authority(
    authority: &SharedAuthority,
    store: &super::la_store::ClaimStore,
    keys: &super::la_adapter::ChannelKeys,
    recovery: &super::la_adapter::ControllerReadbackRecovery,
) -> Result<(), &'static str> {
    let mut current = authority.write().map_err(|_| "storage_unavailable")?;
    *current = replay_authority_history(
        &current,
        store,
        &keys.authority,
        recovery.authority_sequence(),
    )?;
    Ok(())
}
fn replay_authority_history(
    seed: &DiscoveryContext,
    store: &super::la_store::ClaimStore,
    key: &[u8; 32],
    expected_sequence: u64,
) -> Result<DiscoveryContext, &'static str> {
    if store.has_loss_source()? {
        return Err("transport_uncertain");
    }
    let records = store.authority_observations(key, expected_sequence)?;
    if seed.observation_sequence != 0 {
        return Err("evidence_invalid");
    }
    let mut updated = seed.clone();
    let mut last_time = 0;
    for (index, body) in records.iter().enumerate() {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Observation {
            schema_version: String,
            sequence: u64,
            observed_at: u64,
            revoked: Vec<String>,
        }
        let item: Observation = serde_json::from_slice(body).map_err(|_| "evidence_invalid")?;
        if item.schema_version != "diffuser-authority-observation/v1"
            || item.sequence != index as u64 + 1
            || item.observed_at < last_time
            || item.revoked.len() > updated.grants.len()
        {
            return Err("evidence_invalid");
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in item.revoked {
            if !seen.insert(id.clone()) {
                return Err("evidence_invalid");
            }
            let mut matching = updated.grants.iter_mut().filter(|grant| grant.id == id);
            let grant = matching.next().ok_or("evidence_invalid")?;
            grant.revoked = true;
            if matching.next().is_some() {
                return Err("evidence_invalid");
            }
        }
        last_time = item.observed_at;
        updated.observed_at = item.observed_at;
        updated.observation_sequence = item.sequence;
    }
    Ok(updated)
}

/// The protected source uses the same authority->claim lock order as handlers.
/// Commit revocations durably before making the refreshed snapshot visible.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn apply_protected_source_observation(
    authority: &SharedAuthority,
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    binding: &super::la_adapter::ChannelBinding,
    keys: &super::la_adapter::ChannelKeys,
    frame: &[u8],
) -> Result<super::la_adapter::SourceAck, &'static str> {
    apply_protected_source_observation_inner(authority, claims, binding, keys, frame, None)
}
fn apply_protected_source_observation_inner(
    authority: &SharedAuthority,
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    binding: &super::la_adapter::ChannelBinding,
    keys: &super::la_adapter::ChannelKeys,
    frame: &[u8],
    bridge: Option<&super::la_adapter::ChannelBinding>,
) -> Result<super::la_adapter::SourceAck, &'static str> {
    let canonical = super::la_adapter::verify_source_observation(&keys.authority, binding, frame)?;
    let mut current = authority.write().map_err(|_| "storage_unavailable")?;
    if current.loss_scope.is_some() && bridge != Some(binding) {
        return Err("evidence_invalid");
    }
    let shadow = std::sync::Arc::new(std::sync::RwLock::new(current.clone()));
    apply_authority_observation(&shadow, &canonical)?;
    let updated = shadow.read().map_err(|_| "storage_unavailable")?.clone();
    let mut store = claims.lock().map_err(|_| "storage_unavailable")?;
    let mac = super::la_adapter::sign_authority_observation(&keys.authority, &canonical);
    if bridge.is_some() {
        store.append_loss_return_authority_observation(binding, keys, &canonical, &mac)?
    } else {
        store.append_authority_observation(&keys.authority, &canonical, &mac)?
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    store.tick_assignment_closures(binding, now)?;
    *current = updated;
    super::la_adapter::source_ack(&keys.reply, binding, "controller", &canonical)
}

/// The protected constructor attaches this witness only after genesis was
/// acknowledged through P's separately rooted custody channel.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn witnessed_namespace(
    router: Router<super::Spine>,
    session: std::sync::Arc<super::la_adapter::state_custody::Session>,
) -> Router<super::Spine> {
    router.layer(axum::middleware::from_fn_with_state(
        session,
        witness_namespace_request,
    ))
}
#[cfg_attr(not(test), allow(dead_code))]
async fn witness_namespace_request(
    State(session): State<std::sync::Arc<super::la_adapter::state_custody::Session>>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    use sha2::{Digest, Sha256};
    if let Err(code) = session.check() {
        return artifact_error(code);
    }
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 1_048_576).await {
        Ok(bytes) => bytes,
        Err(_) => return artifact_error("body_too_large"),
    };
    let mut hash = Sha256::new();
    hash.update(b"diffuser-service-request/v1\0");
    hash.update(parts.method.as_str().as_bytes());
    hash.update([0]);
    hash.update(parts.uri.to_string().as_bytes());
    hash.update([0]);
    for (name, value) in &parts.headers {
        hash.update(name.as_str().as_bytes());
        hash.update([0]);
        hash.update(value.as_bytes());
        hash.update([0]);
    }
    hash.update(&bytes);
    let request_digest = hex::encode(hash.finalize());
    let operation = match session.begin(&request_digest) {
        Ok(op) => op,
        Err(code) => return artifact_error(code),
    };
    let response = next
        .run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await;
    let (parts, body) = response.into_parts();
    let bytes = match to_bytes(body, 1_048_576).await {
        Ok(bytes) => bytes,
        Err(_) => return artifact_error("evidence_invalid"),
    };
    let mut hash = Sha256::new();
    hash.update(b"diffuser-service-response/v1\0");
    hash.update(parts.status.as_u16().to_be_bytes());
    hash.update(&bytes);
    if let Err(code) = session.complete(operation, &hex::encode(hash.finalize())) {
        return artifact_error(code);
    }
    Response::from_parts(parts, axum::body::Body::from(bytes))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn apply_witnessed_protected_source_observation(
    authority: &SharedAuthority,
    store: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    binding: &super::la_adapter::ChannelBinding,
    keys: &super::la_adapter::ChannelKeys,
    frame: &[u8],
    worker: Option<&std::sync::Arc<std::sync::Mutex<ServiceWorker>>>,
    session: &super::la_adapter::state_custody::Session,
) -> Result<super::la_adapter::SourceAck, &'static str> {
    use sha2::{Digest, Sha256};
    let request = hex::encode(Sha256::digest(frame));
    let loss_bridge = if authority
        .read()
        .map_err(|_| "storage_unavailable")?
        .loss_scope
        .is_some()
    {
        let w = worker
            .ok_or("evidence_invalid")?
            .lock()
            .map_err(|_| "storage_unavailable")?;
        #[cfg(not(test))]
        let super::la_worker::WorkerConnection::Remote(c) = &w.journal;
        #[cfg(test)]
        let c = match &w.journal {
            super::la_worker::WorkerConnection::Remote(c) => c,
            _ => return Err("evidence_invalid"),
        };
        let b = c.verified_loss_source_binding()?;
        if b != *binding || session.binding()? != b {
            return Err("evidence_invalid");
        };
        Some(b)
    } else {
        None
    };
    let op = session.begin(&request)?;
    let result = apply_protected_source_observation_inner(
        authority,
        store,
        binding,
        keys,
        frame,
        loss_bridge.as_ref(),
    );
    if result.is_ok() {
        if let Some(worker) = worker {
            reconcile_assignment_stops(store, worker)?;
        }
    }
    let bytes = serde_json::to_vec(&result).map_err(|_| "evidence_invalid")?;
    session.complete(op, &hex::encode(Sha256::digest(bytes)))?;
    result
}

/// Authenticated cleanup commits under the ordinary state witness before any
/// protected ACK. A lost completion cannot expose an unwitnessed release.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn apply_witnessed_cleanup(
    store: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    binding: &super::la_adapter::ChannelBinding,
    keys: &super::la_adapter::ChannelKeys,
    frame: &[u8],
    session: &super::la_adapter::state_custody::Session,
) -> Result<serde_json::Value, &'static str> {
    use sha2::{Digest, Sha256};
    if frame.len() > 12288 {
        return Err("evidence_invalid");
    }
    let certificate: super::la_adapter::cleanup::Certificate =
        serde_json::from_slice(&super::la_contract::canonical_json(frame)?)
            .map_err(|_| "evidence_invalid")?;
    let request = hex::encode(Sha256::digest(frame));
    #[cfg(test)]
    super::la_adapter::recovery_trace(
        "cleanup_service_begin",
        serde_json::json!({"bytes":frame.len(),"frame_sha256":request}),
    );
    let operation = session.begin(&request).inspect_err(|_| {
        super::la_adapter::recovery_trace("cleanup_service_begin_refused", serde_json::json!({}))
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    #[cfg(test)]
    super::la_adapter::recovery_trace("cleanup_apply_clock", serde_json::json!({"now":now}));
    let released = store
        .lock()
        .map_err(|_| "storage_unavailable")?
        .release_cleaned_assignment(binding, keys, &certificate, now)
        .inspect_err(|_| {
            super::la_adapter::recovery_trace("cleanup_release_refused", serde_json::json!({}))
        })?;
    let response = serde_json::json!({"certificate_digest":request,"released_now":released});
    #[cfg(test)]
    super::la_adapter::recovery_trace(
        "cleanup_service_complete",
        serde_json::json!({"released":released}),
    );
    session.complete(
        operation,
        &hex::encode(Sha256::digest(
            serde_json::to_vec(&response).map_err(|_| "evidence_invalid")?,
        )),
    )?;
    Ok(response)
}

/// Dispatch only durable stop/fence intents. Missing proof retains the job and
/// assignment; it never turns a transport error or absent row into cleanup.
fn reconcile_assignment_stops(
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
) -> Result<(), &'static str> {
    let mut store = claims.lock().map_err(|_| "storage_unavailable")?;
    let mut worker = worker.lock().map_err(|_| "storage_unavailable")?;
    let key = worker.session.key;
    let owners = store.draining_assignment_owners(&worker.session.worker)?;
    let ServiceWorker {
        journal, session, ..
    } = &mut *worker;
    for (project, actor, assignment) in owners {
        for command in store.stopping_job_commands(&assignment)? {
            let mac = super::la_adapter::sign_stop_command(&key, &command)?;
            if let Ok((receipt, mac)) = journal.stop_with_receipt(session, &command, &mac) {
                store.acknowledge_job_stop(&key, &receipt, &mac)?;
            }
        }
        if let Ok(command) = store.assignment_close_command(&project, &actor, &assignment) {
            let mac = super::la_adapter::sign_close_command(&key, &command)?;
            if let Ok((receipt, mac)) = journal.close_authenticated(session, &command, &mac) {
                store.acknowledge_assignment_stop(&key, &receipt, &mac)?;
            }
        }
    }
    Ok(())
}

/// The live controller reuses its ordinary client/store after a DISTINCT P
/// successor capability. Both admission and the session stay closed on failure.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn admit_protected_worker_successor(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    store: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    root: &std::fs::File,
    domain: &super::la_adapter::state_custody::Session,
    cap: &super::la_adapter::WorkerSuccessorAdmission,
) -> Result<super::la_adapter::ActivationAck, &'static str> {
    use sha2::{Digest, Sha256};
    let mut claims = store.lock().map_err(|_| "storage_unavailable")?;
    let mut worker = worker.lock().map_err(|_| "storage_unavailable")?;
    if worker.execute {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut worker.journal;
    #[cfg(test)]
    let client = match &mut worker.journal {
        super::la_worker::WorkerConnection::Remote(client) => client,
        super::la_worker::WorkerConnection::Local(_) => return Err("evidence_invalid"),
    };
    client.validate_successor(cap, root, domain)?;
    let operation = domain.begin(&cap.digest()?)?;
    let ack = client.admit_successor(cap)?;
    claims.install_worker_successor(cap)?;
    domain.complete(
        operation,
        &hex::encode(Sha256::digest(
            serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?,
        )),
    )?;
    let ack = client.finish_successor(cap)?;
    worker.session.boot = cap.binding().worker_boot.clone();
    worker.execute = true;
    Ok(ack)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn protected_readback_worker(
    client: super::la_adapter::WorkerClient,
    session: super::la_worker::ReservationSession,
) -> std::sync::Arc<std::sync::Mutex<ServiceWorker>> {
    std::sync::Arc::new(std::sync::Mutex::new(ServiceWorker {
        journal: super::la_worker::WorkerConnection::Remote(Box::new(client)),
        session,
        execute: false,
    }))
}
fn current_rebound_authority(
    a: &DiscoveryContext,
    m: &super::la_auth::StoredMandate,
    until: u64,
) -> Result<(), &'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    if a.tenant != m.draft.tenant
        || a.project != m.draft.project
        || a.observation_sequence == 0
        || now < a.observed_at
        || now
            >= a.observed_at
                .checked_add(a.freshness_ms)
                .ok_or("evidence_invalid")?
        || now >= until
        || until > m.max_until
    {
        return Err("delegation_denied");
    }
    if m.draft
        .chain
        .first()
        .is_none_or(|g| g.id != m.draft.lineage)
        || m.draft
            .chain
            .last()
            .and_then(|last| a.grants.iter().find(|g| g.id == last.id))
            .is_none_or(|g| g.actor != m.draft.actor)
        || m.draft
            .chain
            .first()
            .and_then(|first| a.grants.iter().find(|g| g.id == first.id))
            .is_none_or(|g| g.actor != m.draft.initiator)
    {
        return Err("delegation_denied");
    }
    for original in &m.draft.chain {
        let g = a
            .grants
            .iter()
            .find(|g| g.id == original.id)
            .ok_or("delegation_denied")?;
        if !g.enabled
            || !g.member
            || g.revoked
            || g.parent != original.parent
            || g.tenant != m.draft.tenant
            || g.project != m.draft.project
            || g.not_before > now
            || g.audience != "diffuser"
            || g.scopes & (SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY)
                != (SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY)
            || g.run_until < until
            || g.execution_ceiling < until
        {
            return Err("delegation_denied");
        }
    }
    Ok(())
}
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn resume_protected_never_started(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    artifacts: &std::sync::Arc<std::sync::Mutex<super::la_artifacts::ArtifactStore>>,
    authority: &SharedAuthority,
    root: &std::fs::File,
    domain: &super::la_adapter::state_custody::Session,
    cap: &super::la_adapter::NeverStartedPermit,
) -> Result<serde_json::Value, &'static str> {
    use sha2::{Digest, Sha256};
    let c = &cap.rebound;
    let mandate = claims
        .lock()
        .map_err(|_| "storage_unavailable")?
        .load_mandate(&c.job)?;
    let observation = authority.read().map_err(|_| "storage_unavailable")?;
    current_rebound_authority(&observation, &mandate, c.permit_until)?;
    let mut claim = claims.lock().map_err(|_| "storage_unavailable")?;
    let mut worker = worker.lock().map_err(|_| "storage_unavailable")?;
    let key = worker.session.key;
    #[cfg(test)]
    let super::la_worker::WorkerConnection::Remote(client) = &mut worker.journal
    else {
        return Err("evidence_invalid");
    };
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut worker.journal;
    client.validate_never_started(cap, root, domain)?;
    let op = domain.begin(&cap.digest()?)?;
    // All protected validation precedes mutation; the controller service is
    // now intentionally pending, so installing W uses the already-validated cap.
    let (receipt, mac) = client
        .call(
            super::la_adapter::WorkerOperation::ReboundPermit(Box::new(cap.clone())),
            &[],
        )
        .and_then(|r| match r {
            super::la_adapter::WorkerReply::ReboundPermitted(r, m) => Ok((r, m)),
            _ => Err("evidence_invalid"),
        })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    claim.claim_never_started_rebound(cap, &key, &receipt, &mac, now)?;
    let view = claim.job_view(&mandate.draft.project, &mandate.draft.actor, &c.job)?;
    let (manifest, input) = artifacts
        .lock()
        .map_err(|_| "storage_unavailable")?
        .read_manifest_and_content(
            &mandate.draft.tenant,
            &mandate.draft.project,
            &mandate.draft.actor,
            &view.input_artifact,
            now,
        )?;
    if manifest.digest != c.input_digest || manifest.kind != "input" {
        return Err("evidence_invalid");
    }
    drop(claim);
    drop(observation);
    let stage_mac = super::la_adapter::sign_stage_command(&key, c)?;
    let start_mac = super::la_adapter::sign_start_command(&key, c)?;
    let ServiceWorker {
        journal, session, ..
    } = &mut *worker;
    journal.stage_authenticated_input(session, c, &stage_mac, &input)?;
    let (report, result, result_mac) = journal.inspect_staged(session, c, &start_mac)?;
    #[cfg(test)]
    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
        .is_ok_and(|v| v.starts_with("controller-never-started-"))
    {
        let super::la_worker::WorkerConnection::Remote(client) = &mut worker.journal else {
            return Err("evidence_invalid");
        };
        if !matches!(client.call(super::la_adapter::WorkerOperation::Start(cap.original.clone()),&[])?,super::la_adapter::WorkerReply::Refused{code} if code=="evidence_invalid")
        {
            return Err("evidence_invalid");
        }
    }
    drop(worker);
    let observation = authority.read().map_err(|_| "storage_unavailable")?;
    current_rebound_authority(&observation, &mandate, c.permit_until)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    let output = random_id("artifact")?;
    let mut store = claims.lock().map_err(|_| "storage_unavailable")?;
    store.record_job_result(
        &key,
        &result,
        &result_mac,
        &report,
        input.len(),
        &output,
        now,
    )?;
    artifacts
        .lock()
        .map_err(|_| "storage_unavailable")?
        .put_output(
            &mandate.draft.tenant,
            &mandate.draft.project,
            &mandate.draft.actor,
            &output,
            &c.assignment,
            &c.job,
            &report,
            &result.report_digest,
            now,
            now.checked_add(86_400_000).ok_or("deadline_elapsed")?,
        )?;
    store.publish_job_result(&c.job, &output, &result.report_digest)?;
    let ack = serde_json::json!({"job":c.job,"operation":c.operation,"state":"succeeded","output":output,"report_digest":result.report_digest,"permit_sequence":receipt.sequence,"fresh_permit_until":c.permit_until,"original_permit_until":cap.original.permit_until,"original_mandate_until":c.mandate_until});
    domain.complete(
        op,
        &hex::encode(Sha256::digest(
            serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?,
        )),
    )?;
    Ok(ack)
}

fn fixture_hold_before_cas() -> bool {
    #[cfg(test)]
    {
        std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
            .is_ok_and(|v| v.starts_with("controller-never-started-m1"))
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// Recovered C keeps readback and exact terminal release available. A separate
/// authenticated admission installation opens ordinary new-work handlers.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn recovered_lifecycle_router(
    authority: SharedAuthority,
    artifacts: std::sync::Arc<std::sync::Mutex<super::la_artifacts::ArtifactStore>>,
    claims: std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    worker: std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    high_water: u64,
) -> Router<super::Spine> {
    let context = ArtifactContext {
        authority: authority.clone(),
        store: artifacts,
        claims: Some(claims),
        worker: Some(worker),
    };
    service_routes(context.clone())
        .layer(axum::middleware::from_fn_with_state(
            context,
            recovered_lifecycle_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            (authority, high_water),
            require_recovery_source,
        ))
}
async fn recovered_lifecycle_gate(
    State(context): State<ArtifactContext>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let admitted = context
        .worker
        .as_ref()
        .and_then(|w| w.lock().ok().map(|w| w.execute))
        .unwrap_or(false);
    if !admitted && request.method() != axum::http::Method::GET {
        let parts: Vec<_> = request.uri().path().split('/').collect();
        if request.method() == axum::http::Method::POST
            && parts.len() == 6
            && parts[1] == "projects"
            && parts[3] == "assignments"
        {
            let project = parts[2].to_string();
            let assignment = parts[4].to_string();
            if parts[5] == "jobs" {
                return recovered_completed_submit(
                    State(context),
                    Path((project, assignment)),
                    request,
                )
                .await;
            }
            if parts[5] == "release" {
                let authorized = match current_authority(
                    &context.authority,
                    request.headers(),
                    &project,
                    SCOPE_ASSIGNMENT_RELEASE,
                ) {
                    Ok(value) => value,
                    Err(code) => return artifact_error(code),
                };
                let eligible = context
                    .claims
                    .as_ref()
                    .and_then(|c| {
                        c.lock().ok().map(|c| {
                            c.assignment_view(&project, &authorized.actor, &assignment)?;
                            c.terminal_release_eligible(&assignment)
                        })
                    })
                    .unwrap_or(Err("evidence_invalid"));
                match eligible {
                    Ok(true) => return next.run(request).await,
                    Ok(false) => return artifact_error("routing_closed"),
                    Err(code) => return artifact_error(code),
                }
            }
        }
        return artifact_error("evidence_invalid");
    }
    next.run(request).await
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn admit_protected_recovered_controller(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    root: &std::fs::File,
    domain: &super::la_adapter::state_custody::Session,
    cap: &super::la_adapter::RecoveredControllerAdmission,
) -> Result<super::la_adapter::ActivationAck, &'static str> {
    use sha2::{Digest, Sha256};
    let mut claims = claims.lock().map_err(|_| "storage_unavailable")?;
    let mut worker = worker.lock().map_err(|_| "storage_unavailable")?;
    if worker.execute {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut worker.journal;
    #[cfg(test)]
    let client = match &mut worker.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        super::la_worker::WorkerConnection::Local(_) => return Err("evidence_invalid"),
    };
    super::la_adapter::recovery_trace(
        "recovered_admission_validate_c",
        serde_json::json!({"phase":"begin"}),
    );
    client.validate_controller_admission(cap, root, domain)?;
    super::la_adapter::recovery_trace(
        "recovered_admission_validate_c",
        serde_json::json!({"phase":"complete"}),
    );
    super::la_adapter::recovery_trace(
        "recovered_admission_service_begin",
        serde_json::json!({"phase":"begin"}),
    );
    let op = domain.begin(&cap.digest()?)?;
    super::la_adapter::recovery_trace(
        "recovered_admission_service_begin",
        serde_json::json!({"phase":"complete"}),
    );
    let ack = match client.call(
        super::la_adapter::WorkerOperation::AdmitRecoveredController(Box::new(cap.clone())),
        &[],
    )? {
        super::la_adapter::WorkerReply::SuccessorAdmitted(a) => a,
        other => {
            super::la_adapter::recovery_trace(
                "recovered_admission_worker_reply",
                serde_json::json!({"reply":other}),
            );
            return Err("evidence_invalid");
        }
    };
    client.verify_controller_admission_ack(cap, &ack)?;
    super::la_adapter::recovery_trace(
        "recovered_admission_claims_install",
        serde_json::json!({"phase":"begin"}),
    );
    claims.install_controller_admission(cap)?;
    super::la_adapter::recovery_trace(
        "recovered_admission_claims_install",
        serde_json::json!({"phase":"complete"}),
    );
    domain.complete(
        op,
        &hex::encode(Sha256::digest(
            serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?,
        )),
    )?;
    super::la_adapter::recovery_trace(
        "recovered_admission_client_finish",
        serde_json::json!({"phase":"begin"}),
    );
    let ack = client.finish_controller_admission(cap)?;
    super::la_adapter::recovery_trace(
        "recovered_admission_client_finish",
        serde_json::json!({"phase":"complete"}),
    );
    worker.execute = true;
    Ok(ack)
}

/// No background dispatcher or alternate router: ordinary authorized status and
/// cancel reconcile the original task through the same signed ordered channel.
fn settle_observed_job(
    context: &ArtifactContext,
    observation: &DiscoveryContext,
    current: &RequestAuthority,
    store: &mut super::la_store::ClaimStore,
    project: &str,
    job: &str,
) -> Result<(), &'static str> {
    let view = store.job_view(project, &current.actor, job)?;
    if !matches!(view.state.as_str(), "running" | "stopping") {
        return Ok(());
    }
    let command = store.job_permit_command(job)?;
    let Some(worker) = &context.worker else {
        return Ok(());
    };
    let mut worker = worker.lock().map_err(|_| "storage_unavailable")?;
    let key = worker.session.key;
    // A missing worker/reply leaves the operation and claim held. It is never
    // converted to a NeverStarted or stopped observation.
    let ServiceWorker {
        journal, session, ..
    } = &mut *worker;
    let reply = match journal.fetch_inspection(session, &command) {
        Ok(reply) => reply,
        Err(_) => return Ok(()),
    };
    drop(worker);
    match reply {
        super::la_adapter::WorkerReply::Stopped(receipt, mac) if view.state == "stopping" => {
            store.acknowledge_job_stop(&key, &receipt, &mac)
        }
        super::la_adapter::WorkerReply::Result(report, receipt, mac) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock_untrusted")?
                .as_millis() as u64;
            if std::time::Instant::now() >= current.monotonic_until {
                return Err(current.expiry_error);
            }
            let mandate = store.load_mandate(job)?;
            if now >= current.valid_until || now >= mandate.max_until {
                return Err("deadline_elapsed");
            }
            let (manifest, input) = context
                .store
                .lock()
                .map_err(|_| "storage_unavailable")?
                .read_manifest_and_content(
                    &observation.tenant,
                    project,
                    &current.actor,
                    &view.input_artifact,
                    now,
                )?;
            if manifest.digest != command.input_digest {
                return Err("evidence_invalid");
            }
            let output = random_id("artifact")?;
            store.record_job_result(&key, &receipt, &mac, &report, input.len(), &output, now)?;
            let mut artifacts = context.store.lock().map_err(|_| "storage_unavailable")?;
            artifacts.put_output(
                &observation.tenant,
                project,
                &current.actor,
                &output,
                &command.assignment,
                job,
                &report,
                &receipt.report_digest,
                now,
                now.checked_add(86_400_000).ok_or("deadline_elapsed")?,
            )?;
            let (manifest, bytes) = artifacts.read_manifest_and_content(
                &observation.tenant,
                project,
                &current.actor,
                &output,
                now,
            )?;
            if manifest.kind != "output"
                || bytes != report
                || manifest.job.as_deref() != Some(job)
                || manifest.assignment.as_deref() != Some(command.assignment.as_str())
            {
                return Err("evidence_invalid");
            }
            store.publish_job_result(job, &output, &receipt.report_digest)
        }
        _ => Ok(()),
    }
}

/// Protected capability ingress; no public route or alternate execution path.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn settle_protected_worker_loss(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    authority: &SharedAuthority,
    cap: &super::la_adapter::WorkerLossSettlement,
    keys: &super::la_adapter::ChannelKeys,
) -> Result<serde_json::Value, &'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    cap.verify(keys, now)?;
    let a = authority.read().map_err(|_| "storage_unavailable")?;
    if a.observation_sequence == 0
        || now < a.observed_at
        || now
            >= a.observed_at
                .checked_add(a.freshness_ms)
                .ok_or("evidence_invalid")?
        || a.freshness_ms == 0
        || a.freshness_ms > 6000
    {
        return Err("delegation_denied");
    }
    let mut store = claims.lock().map_err(|_| "storage_unavailable")?;
    let m = store.load_mandate(&cap.command.job)?;
    current_rebound_authority(&a, &m, cap.consumption_deadline().min(m.max_until))?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut w.journal;
    #[cfg(test)]
    let client = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        super::la_worker::WorkerConnection::Local(_) => return Err("evidence_invalid"),
    };
    // Locks may block: validate actual current time/source at consumption.
    current_rebound_authority(&a, &m, cap.consumption_deadline().min(m.max_until))?;
    let consumed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    client.settle_worker_loss(cap, consumed_at)?;
    let recorded_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    store.record_worker_loss(cap, keys, recorded_at)?;
    client.finish_worker_loss(cap)?;
    w.execute = false;
    Ok(
        serde_json::json!({"kind":"WORKER_LOSS_SETTLED","job":cap.command.job,"state":"failed","outcome_uncertain":true,"entered":true,"retry_authority":false,"settlement":cap.digest()?}),
    )
}

/// C-only source reconciliation is a separate authenticated protocol. Ordinary
/// source delivery cannot widen this scope or manufacture the absent W ACK.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn reconcile_protected_loss_source(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    authority: &SharedAuthority,
    root: &std::fs::File,
    domain: &super::la_adapter::state_custody::Session,
    cap: &super::la_adapter::WorkerLossSource,
    keys: &super::la_adapter::ChannelKeys,
) -> Result<super::la_adapter::SourceAck, &'static str> {
    use sha2::{Digest, Sha256};
    let now = || -> Result<u64, &'static str> {
        Ok(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis() as u64)
    };
    let mut current = authority.write().map_err(|_| "storage_unavailable")?;
    let mut store = claims.lock().map_err(|_| "storage_unavailable")?;
    if current.loss_scope.is_some()
        || current.observation_sequence != cap.previous_sequence
        || current.freshness_ms != 1500
        || domain.binding()? != cap.binding
    {
        return Err("evidence_invalid");
    }
    let canonical = cap.verify_controller(root, keys, now()?)?;
    store.authority_observations(&keys.authority, cap.previous_sequence)?;
    let shadow = std::sync::Arc::new(std::sync::RwLock::new(current.clone()));
    apply_authority_observation(&shadow, &canonical)?;
    let mut updated = shadow.read().map_err(|_| "storage_unavailable")?.clone();
    let mandate = store.load_mandate(&cap.job)?;
    if super::la_store::checked_mandate(&mandate.draft)? != mandate
        || mandate.draft.job != cap.job
        || mandate.draft.assignment != cap.assignment
        || mandate.draft.worker != cap.binding.worker
        || mandate != cap.mandate
        || mandate.draft.tenant != updated.tenant
        || mandate.draft.project != updated.project
        || mandate
            .draft
            .chain
            .first()
            .is_none_or(|g| g.id != mandate.draft.lineage)
        || mandate
            .draft
            .chain
            .first()
            .and_then(|g| updated.grants.iter().find(|a| a.id == g.id))
            .is_none_or(|g| g.actor != mandate.draft.initiator)
        || mandate
            .draft
            .chain
            .last()
            .and_then(|g| updated.grants.iter().find(|a| a.id == g.id))
            .is_none_or(|g| g.actor != mandate.draft.actor)
    {
        return Err("delegation_denied");
    }
    // Execution deadlines are retained, never extended. Cleanup still needs
    // current access, membership, lineage and the original policy/scope.
    for original in &mandate.draft.chain {
        let mut matching = updated.grants.iter().filter(|g| g.id == original.id);
        let g = matching.next().ok_or("delegation_denied")?;
        if matching.next().is_some()
            || !g.enabled
            || !g.member
            || g.revoked
            || g.parent != original.parent
            || g.tenant != updated.tenant
            || g.project != updated.project
            || g.not_before > now()?
            || g.access_expires < cap.expires_at
            || g.audience != "diffuser"
            || g.run_until != original.run_until
            || g.execution_ceiling != original.execution_ceiling
            || g.scopes
                & (SCOPE_JOB_READ
                    | SCOPE_JOB_CANCEL
                    | SCOPE_ASSIGNMENT_READ
                    | SCOPE_ASSIGNMENT_RELEASE)
                != (SCOPE_JOB_READ
                    | SCOPE_JOB_CANCEL
                    | SCOPE_ASSIGNMENT_READ
                    | SCOPE_ASSIGNMENT_RELEASE)
        {
            return Err("delegation_denied");
        }
    }
    let w = worker.lock().map_err(|_| "storage_unavailable")?;
    if w.execute {
        return Err("evidence_invalid");
    }
    // No service operation or database mutation precedes complete verification.
    cap.verify_controller(root, keys, now()?)?;
    domain.check()?;
    updated.loss_scope = Some((cap.job.clone(), cap.assignment.clone()));
    current.loss_scope = updated.loss_scope.clone();
    let operation = domain.begin(&cap.digest()?)?;
    store.record_loss_source(cap, keys, now()?)?;
    let ack = super::la_adapter::source_ack(&keys.reply, &cap.binding, "controller", &canonical)?;
    domain.complete(
        operation,
        &hex::encode(Sha256::digest(
            serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?,
        )),
    )?;
    cap.verify(keys, now()?)?;
    *current = updated;
    Ok(ack)
}

/// Reconcile entered-loss transport only. The C-only source scope and stopped
/// execution remain closed until a separate full loss-return admission exists.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn reconcile_protected_loss_transport(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    authority: &SharedAuthority,
    domain: &super::la_adapter::state_custody::Session,
    cap: &super::la_adapter::WorkerLossReturn,
    address: std::net::SocketAddr,
) -> Result<serde_json::Value, &'static str> {
    let current = authority.read().map_err(|_| "storage_unavailable")?;
    let _store = claims.lock().map_err(|_| "storage_unavailable")?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    // Transport reconciliation grants no source replay, session generation,
    // reservation retirement or execution. The live occupancy still sees loss.
    if current.loss_scope.is_none() || w.execute {
        return Err("evidence_invalid");
    }
    domain.check()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock_untrusted")?
        .as_millis() as u64;
    // This internal transport-only capability has its OWN current observation
    // and first-use clock. The old source is authenticated HISTORY, never a
    // renewed read/cleanup/execution grant; loss_scope remains installed.
    if now < current.observed_at || current.freshness_ms != 1500 {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut w.journal;
    #[cfg(test)]
    let client = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        super::la_worker::WorkerConnection::Local(_) => return Err("evidence_invalid"),
    };
    client.install_entered_loss_transport(
        cap,
        address,
        now,
        current.loss_scope.as_ref().ok_or("evidence_invalid")?,
        current.observation_sequence,
        &domain.binding()?,
    )
}

/// Protected bridge ingress preserves loss_scope and execute=false. It cannot
/// install a session generation or count the returned process as capacity.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn reconcile_protected_loss_source_bridge(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    authority: &SharedAuthority,
    domain: &super::la_adapter::state_custody::Session,
    bytes: &[u8],
    complete: bool,
) -> Result<serde_json::Value, &'static str> {
    let current = authority.read().map_err(|_| "storage_unavailable")?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    if current.loss_scope.is_none() || w.execute {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(c) = &mut w.journal;
    #[cfg(test)]
    let c = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        _ => return Err("evidence_invalid"),
    };
    if complete {
        c.complete_loss_source_bridge(bytes)
    } else {
        let cap: super::la_adapter::EnteredLossSourceBridge =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        c.install_loss_source_bridge(&cap, domain)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn probe_protected_loss_source_bridge(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    authority: &SharedAuthority,
    domain: &super::la_adapter::state_custody::Session,
) -> Result<serde_json::Value, &'static str> {
    let current = authority.read().map_err(|_| "storage_unavailable")?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    if current.loss_scope.is_none() || w.execute {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(c) = &mut w.journal;
    #[cfg(test)]
    let c = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        _ => return Err("evidence_invalid"),
    };
    let binding = c.verified_loss_source_binding()?;
    if domain.binding()? != binding {
        return Err("evidence_invalid");
    }
    let reply = c.call(super::la_adapter::WorkerOperation::Probe, &[])?;
    Ok(
        serde_json::json!({"kind":"LOSS_SOURCE_BRIDGE_PROBE","reply":reply,"binding":binding,"source_sequence":current.observation_sequence,"admitted":false}),
    )
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn dispose_protected_entered_loss(
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    authority: &SharedAuthority,
    domain: &super::la_adapter::state_custody::Session,
    cap: &super::la_adapter::SpentLossDisposition,
) -> Result<serde_json::Value, &'static str> {
    let a = authority.read().map_err(|_| "storage_unavailable")?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    if a.loss_scope.as_ref() != Some(&(cap.command.job.clone(), cap.command.assignment.clone()))
        || w.execute
    {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(c) = &mut w.journal;
    #[cfg(test)]
    let c = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        _ => return Err("evidence_invalid"),
    };
    c.dispose_entered_loss(cap, domain)
}

/// Protected distinct entered-loss install. Both service barriers remain
/// closed, including on every interrupted/partial install and lost reply.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn install_protected_loss_return(
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    authority: &SharedAuthority,
    domain: &super::la_adapter::state_custody::Session,
    cap: &super::la_adapter::LossReturnAdmission,
) -> Result<serde_json::Value, &'static str> {
    let current = authority.read().map_err(|_| "storage_unavailable")?;
    let mut store = claims.lock().map_err(|_| "storage_unavailable")?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    cap.verify_current_authority(&current)?;
    let old = cap.command();
    if current.loss_scope.as_ref() != Some(&(old.job.clone(), old.assignment.clone()))
        || w.execute
        || w.session.worker != cap.binding().worker
        || w.session.boot != cap.cursor().0
    {
        return Err("evidence_invalid");
    }
    domain.check()?;
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut w.journal;
    #[cfg(test)]
    let client = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(client) => client,
        _ => return Err("evidence_invalid"),
    };
    let result = client.install_loss_return(cap, &mut store, domain)?;
    w.session.boot = cap.binding().worker_boot.clone();
    Ok(result)
}

pub(super) fn loss_return_required_scopes() -> u64 {
    SCOPE_ASSIGNMENT_ACQUIRE | SCOPE_ARTIFACT_WRITE | SCOPE_JOB_SUBMIT | SCOPE_INSPECT_CAPABILITY
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn persist_protected_loss_return_completion(
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    authority: &SharedAuthority,
    domain: &super::la_adapter::state_custody::Session,
    bytes: &[u8],
) -> Result<serde_json::Value, &'static str> {
    let current = authority.read().map_err(|_| "storage_unavailable")?;
    let mut store = claims.lock().map_err(|_| "storage_unavailable")?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    let proof: super::la_adapter::LossReturnCompletion =
        serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
    let cap = store.load_loss_return_admission(proof.admission())?;
    cap.verify_current_authority(&current)?;
    if current.loss_scope.as_ref()
        != Some(&(cap.command().job.clone(), cap.command().assignment.clone()))
        || w.execute
        || w.session.boot != cap.binding().worker_boot
    {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut w.journal;
    #[cfg(test)]
    let client = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        _ => return Err("evidence_invalid"),
    };
    client.persist_loss_return_completion(bytes, &mut store, domain)
}

/// Final C consumption keeps the exact old scope locked until BOTH the P
/// global record and W's distinct final consumption have authenticated.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn activate_protected_loss_return(
    claims: &std::sync::Arc<std::sync::Mutex<super::la_store::ClaimStore>>,
    worker: &std::sync::Arc<std::sync::Mutex<ServiceWorker>>,
    authority: &SharedAuthority,
    domain: &super::la_adapter::state_custody::Session,
    bytes: &[u8],
) -> Result<serde_json::Value, &'static str> {
    if bytes.len() > 16 * 1024 {
        return Err("evidence_invalid");
    }
    let request: super::la_adapter::LossReturnFinalConsumption =
        serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
    let mut current = authority.write().map_err(|_| "storage_unavailable")?;
    let store = claims.lock().map_err(|_| "storage_unavailable")?;
    let mut w = worker.lock().map_err(|_| "storage_unavailable")?;
    let cap = store.load_loss_return_admission(request.linearization.admission())?;
    cap.verify_current_authority(&current)?;
    let scope = (cap.command().job.clone(), cap.command().assignment.clone());
    if current.loss_scope.as_ref() != Some(&scope)
        || w.execute
        || w.session.worker != cap.binding().worker
        || w.session.boot != cap.binding().worker_boot
    {
        return Err("evidence_invalid");
    }
    #[cfg(not(test))]
    let super::la_worker::WorkerConnection::Remote(client) = &mut w.journal;
    #[cfg(test)]
    let client = match &mut w.journal {
        super::la_worker::WorkerConnection::Remote(c) => c,
        _ => return Err("evidence_invalid"),
    };
    let value = client.activate_loss_return(&request, domain)?;
    cap.verify_current_authority(&current)?;
    current.loss_scope = None;
    w.execute = true;
    Ok(value)
}
