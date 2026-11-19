//! Internal worker transport. Ordinary service construction never mounts it.
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub(super) struct InventoryContext {
    pub(super) bearer_digest: [u8; 32],
    pub(super) worker_id: String,
    pub(super) boot_id: String,
    pub(super) hardware_generation: u64,
    pub(super) profile_epoch: u64,
}

async fn inventory(State(context): State<InventoryContext>, headers: HeaderMap) -> Response {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let bearer = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok().and_then(|s| s.strip_prefix("Bearer ")),
        _ => None,
    };
    let Some(bearer) = bearer.filter(|s| (32..=256).contains(&s.len())) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
    if !bool::from(digest.ct_eq(&context.bearer_digest)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if context.worker_id.is_empty()
        || context.boot_id.is_empty()
        || context.hardware_generation == 0
        || context.profile_epoch == 0
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    // Until startup, custody, resource and authority freshness checks are
    // integrated, this observation must never advertise admission or capacity.
    Json(serde_json::json!({
        "schema_version": "diffuser-worker/v1",
        "worker_id": context.worker_id,
        "boot_id": context.boot_id,
        "hardware_generation": context.hardware_generation,
        "profile_epoch": context.profile_epoch,
        "ready": false
    }))
    .into_response()
}

fn inventory_routes(context: InventoryContext) -> Router {
    Router::new()
        .route(
            "/v1/worker/inventory",
            get(inventory).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .with_state(context)
}

pub(super) fn inventory_router(context: InventoryContext) -> Router {
    inventory_routes(context).route("/v1/worker/rpc", axum::routing::post(rpc_closed))
}

/// Query a single injected isolated worker. DNS, redirects and proxies are not
/// part of the S1 transport; bearer bytes are never persisted or logged.
pub(super) fn fetch_inventory(
    address: std::net::SocketAddr,
    bearer: &str,
    worker_id: &str,
    boot_id: &str,
) -> Result<Vec<u8>, &'static str> {
    use std::{io::Read, time::Duration};
    if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || address.port() == 0
        || !(32..=256).contains(&bearer.len())
    {
        return Err("evidence_invalid");
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| "inventory_unavailable")?;
    let response = client
        .get(format!("http://{address}/v1/worker/inventory"))
        .bearer_auth(bearer)
        .send()
        .map_err(|_| "inventory_unavailable")?;
    if response.status() != StatusCode::OK {
        return Err("inventory_unavailable");
    }
    let mut content_types = response.headers().get_all(header::CONTENT_TYPE).iter();
    if !matches!((content_types.next(), content_types.next()), (Some(value), None) if value == "application/json")
    {
        return Err("evidence_invalid");
    }
    let mut bytes = Vec::new();
    response
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "inventory_unavailable")?;
    if bytes.len() > 65_536 {
        return Err("inventory_unavailable");
    }
    let normalized = super::la_contract::canonical_json(&bytes).map_err(|_| "evidence_invalid")?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Inventory {
        schema_version: String,
        worker_id: String,
        boot_id: String,
        hardware_generation: u64,
        profile_epoch: u64,
        ready: bool,
    }
    let body: Inventory = serde_json::from_slice(&normalized).map_err(|_| "evidence_invalid")?;
    if body.schema_version != "diffuser-worker/v1"
        || body.worker_id != worker_id
        || body.boot_id != boot_id
        || body.hardware_generation != 1
        || body.profile_epoch != 1
        || body.ready
    {
        return Err("evidence_invalid");
    }
    Ok(bytes)
}

/// A receipt is bound to one worker boot and one operation. The protected
/// transport must provision the key independently of the public API.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerReceipt {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) fence: u64,
    pub(super) sequence: u64,
    pub(super) operation: String,
    pub(super) assignment: String,
    pub(super) action: String,
    pub(super) lease_until: u64,
    pub(super) hard_until: u64,
}

// HMAC-SHA256, with a fixed-size secret supplied over the protected channel.
fn receipt_mac(key: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (i, byte) in key.iter().enumerate() {
        inner[i] ^= byte;
        outer[i] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(inner);
    hash.update(body);
    let inner_hash = hash.finalize();
    let mut hash = Sha256::new();
    hash.update(outer);
    hash.update(inner_hash);
    hash.finalize().into()
}

pub(super) fn sign_receipt(
    key: &[u8; 32],
    receipt: &WorkerReceipt,
) -> Result<[u8; 32], &'static str> {
    let body = serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?;
    Ok(receipt_mac(key, &body))
}

pub(super) fn verify_receipt(
    key: &[u8; 32],
    receipt: &WorkerReceipt,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    let body = serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?;
    if !bool::from(receipt_mac(key, &body).ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(&body).into())
}

#[cfg(test)]
mod receipt_tests {
    #[test]
    fn hmac_sha256_matches_rfc4231_case_one() {
        let mut key = [0; 32];
        key[..20].fill(0x0b);
        assert_eq!(
            hex::encode(super::receipt_mac(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}

/// Controller command authenticated over the private worker channel. The MAC
/// has a distinct domain from worker receipts and covers every routing field.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReserveCommand {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) assignment: String,
    pub(super) operation: String,
    pub(super) fence: u64,
    pub(super) lease_until: u64,
    pub(super) hard_until: u64,
}

fn command_mac(key: &[u8; 32], command: &ReserveCommand) -> Result<[u8; 32], &'static str> {
    let mut body = b"diffuser-worker-reserve/v1\0".to_vec();
    body.extend(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?);
    Ok(receipt_mac(key, &body))
}

pub(super) fn sign_reserve_command(
    key: &[u8; 32],
    command: &ReserveCommand,
) -> Result<[u8; 32], &'static str> {
    command_mac(key, command)
}

pub(super) fn verify_reserve_command(
    key: &[u8; 32],
    command: &ReserveCommand,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(command_mac(key, command)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    let body = serde_json::to_vec(command).map_err(|_| "evidence_invalid")?;
    Ok(Sha256::digest(body).into())
}

/// Start authority is scoped to one immutable operation and deadline. The
/// controller must derive it from an authorized mandate and fresh permit.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InspectCommand {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) backend: Option<super::la_backend::Capability>,
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) assignment: String,
    pub(super) fence: u64,
    pub(super) operation: String,
    pub(super) job: String,
    pub(super) input_digest: String,
    pub(super) accepted_at: u64,
    pub(super) mandate_until: u64,
    pub(super) permit_until: u64,
}

fn inspect_command_mac(key: &[u8; 32], command: &InspectCommand) -> Result<[u8; 32], &'static str> {
    let mut body = b"diffuser-worker-inspect/v1\0".to_vec();
    body.extend(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?);
    Ok(receipt_mac(key, &body))
}
pub(super) fn sign_inspect_command(
    key: &[u8; 32],
    command: &InspectCommand,
) -> Result<[u8; 32], &'static str> {
    inspect_command_mac(key, command)
}
pub(super) fn verify_inspect_command(
    key: &[u8; 32],
    command: &InspectCommand,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(inspect_command_mac(key, command)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?).into())
}

pub(super) fn sign_stop_command(
    key: &[u8; 32],
    command: &InspectCommand,
) -> Result<[u8; 32], &'static str> {
    let mut body = b"diffuser-worker-stop/v1\0".to_vec();
    body.extend(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?);
    Ok(receipt_mac(key, &body))
}
pub(super) fn verify_stop_command(
    key: &[u8; 32],
    command: &InspectCommand,
    mac: &[u8; 32],
) -> Result<(), &'static str> {
    if bool::from(sign_stop_command(key, command)?.ct_eq(mac)) {
        Ok(())
    } else {
        Err("evidence_invalid")
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PermitReceipt {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) fence: u64,
    pub(super) sequence: u64,
    pub(super) assignment: String,
    pub(super) operation: String,
    pub(super) job: String,
    pub(super) command_digest: String,
    pub(super) permit_until: u64,
}
fn permit_receipt_mac(key: &[u8; 32], receipt: &PermitReceipt) -> Result<[u8; 32], &'static str> {
    let mut body = b"diffuser-worker-permit-receipt/v1\0".to_vec();
    body.extend(serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?);
    Ok(receipt_mac(key, &body))
}
pub(super) fn sign_permit_receipt(
    key: &[u8; 32],
    receipt: &PermitReceipt,
) -> Result<[u8; 32], &'static str> {
    permit_receipt_mac(key, receipt)
}
pub(super) fn verify_permit_receipt(
    key: &[u8; 32],
    receipt: &PermitReceipt,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(permit_receipt_mac(key, receipt)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?).into())
}

pub(super) fn sign_start_command(
    key: &[u8; 32],
    command: &InspectCommand,
) -> Result<[u8; 32], &'static str> {
    let mut body = b"diffuser-worker-start/v1\0".to_vec();
    body.extend(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?);
    Ok(receipt_mac(key, &body))
}
pub(super) fn verify_start_command(
    key: &[u8; 32],
    command: &InspectCommand,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(sign_start_command(key, command)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?).into())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResultReceipt {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) fence: u64,
    pub(super) sequence: u64,
    pub(super) assignment: String,
    pub(super) operation: String,
    pub(super) job: String,
    pub(super) report_digest: String,
    pub(super) report_bytes: u64,
}
fn result_receipt_mac(key: &[u8; 32], receipt: &ResultReceipt) -> Result<[u8; 32], &'static str> {
    let mut body = b"diffuser-worker-result/v1\0".to_vec();
    body.extend(serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?);
    Ok(receipt_mac(key, &body))
}
pub(super) fn sign_result_receipt(
    key: &[u8; 32],
    receipt: &ResultReceipt,
) -> Result<[u8; 32], &'static str> {
    result_receipt_mac(key, receipt)
}
pub(super) fn verify_result_receipt(
    key: &[u8; 32],
    receipt: &ResultReceipt,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(result_receipt_mac(key, receipt)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?).into())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RenewCommand {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) assignment: String,
    pub(super) fence: u64,
    pub(super) operation: String,
    pub(super) revision: u64,
    pub(super) previous_until: u64,
    pub(super) requested_until: u64,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RenewReceipt {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) assignment: String,
    pub(super) fence: u64,
    pub(super) operation: String,
    pub(super) revision: u64,
    pub(super) sequence: u64,
    pub(super) previous_until: u64,
    pub(super) acknowledged_until: u64,
}
pub(super) fn typed_mac<T: serde::Serialize>(
    key: &[u8; 32],
    domain: &[u8],
    value: &T,
) -> Result<[u8; 32], &'static str> {
    let mut body = domain.to_vec();
    body.extend(serde_json::to_vec(value).map_err(|_| "evidence_invalid")?);
    Ok(receipt_mac(key, &body))
}
pub(super) fn sign_renew_command(
    key: &[u8; 32],
    command: &RenewCommand,
) -> Result<[u8; 32], &'static str> {
    typed_mac(key, b"diffuser-worker-renew/v1\0", command)
}
pub(super) fn verify_renew_command(
    key: &[u8; 32],
    command: &RenewCommand,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(sign_renew_command(key, command)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?).into())
}
pub(super) fn sign_renew_receipt(
    key: &[u8; 32],
    receipt: &RenewReceipt,
) -> Result<[u8; 32], &'static str> {
    typed_mac(key, b"diffuser-worker-renew-receipt/v1\0", receipt)
}
pub(super) fn verify_renew_receipt(
    key: &[u8; 32],
    receipt: &RenewReceipt,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(sign_renew_receipt(key, receipt)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?).into())
}

/// Only a protected authority source may possess this observation key.
pub(super) fn sign_authority_observation(key: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut body = b"diffuser-authority-observation/v1\0".to_vec();
    body.extend(canonical);
    receipt_mac(key, &body)
}
pub(super) fn verify_authority_observation(
    key: &[u8; 32],
    canonical: &[u8],
    mac: &[u8; 32],
) -> Result<(), &'static str> {
    if bool::from(sign_authority_observation(key, canonical).ct_eq(mac)) {
        Ok(())
    } else {
        Err("evidence_invalid")
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StopReceipt {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) assignment: String,
    pub(super) fence: u64,
    pub(super) sequence: u64,
    pub(super) operation: String,
    pub(super) job: String,
    pub(super) command_digest: String,
}
pub(super) fn sign_stop_receipt(
    key: &[u8; 32],
    receipt: &StopReceipt,
) -> Result<[u8; 32], &'static str> {
    typed_mac(key, b"diffuser-worker-stop-receipt/v1\0", receipt)
}
pub(super) fn verify_stop_receipt(
    key: &[u8; 32],
    receipt: &StopReceipt,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(sign_stop_receipt(key, receipt)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?).into())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CloseCommand {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) assignment: String,
    pub(super) fence: u64,
    pub(super) operation: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CloseReceipt {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) assignment: String,
    pub(super) fence: u64,
    pub(super) operation: String,
    pub(super) sequence: u64,
}
pub(super) fn sign_close_command(
    key: &[u8; 32],
    command: &CloseCommand,
) -> Result<[u8; 32], &'static str> {
    typed_mac(key, b"diffuser-worker-close/v1\0", command)
}
pub(super) fn verify_close_command(
    key: &[u8; 32],
    command: &CloseCommand,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(sign_close_command(key, command)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?).into())
}
pub(super) fn sign_close_receipt(
    key: &[u8; 32],
    receipt: &CloseReceipt,
) -> Result<[u8; 32], &'static str> {
    typed_mac(key, b"diffuser-worker-close-receipt/v1\0", receipt)
}
pub(super) fn verify_close_receipt(
    key: &[u8; 32],
    receipt: &CloseReceipt,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(sign_close_receipt(key, receipt)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(receipt).map_err(|_| "evidence_invalid")?).into())
}

pub(super) fn sign_stage_command(
    key: &[u8; 32],
    command: &InspectCommand,
) -> Result<[u8; 32], &'static str> {
    typed_mac(key, b"diffuser-worker-input/v1\0", command)
}
pub(super) fn verify_stage_command(
    key: &[u8; 32],
    command: &InspectCommand,
    mac: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !bool::from(sign_stage_command(key, command)?.ct_eq(mac)) {
        return Err("evidence_invalid");
    }
    Ok(Sha256::digest(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?).into())
}

// The RPC is a private, protected-bootstrap-only transport. A valid transport
// session is deliberately distinct from a qualified worker admission.
const RPC_JSON_MAX: usize = 65_536;
const RPC_INPUT_MAX: usize = 1_048_576;
const RPC_HISTORY_MAX: u64 = 512;

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChannelBinding {
    pub(super) worker: String,
    pub(super) worker_boot: String,
    pub(super) controller_boot: String,
    pub(super) worker_epoch: u64,
    pub(super) controller_epoch: u64,
    pub(super) hardware_generation: u64,
    pub(super) profile_epoch: u64,
    pub(super) policy_digest: String,
    pub(super) source_digest: String,
    pub(super) executable_digest: String,
}
impl ChannelBinding {
    fn validate(&self) -> Result<(), &'static str> {
        let id = |s: &str| {
            (16..=128).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && s.bytes().any(|b| b != b'0')
        };
        if !id(&self.worker)
            || !digest(&self.worker_boot)
            || !digest(&self.controller_boot)
            || self.worker_boot == self.controller_boot
            || self.worker_epoch == 0
            || self.controller_epoch == 0
            || self.worker_epoch > i64::MAX as u64
            || self.controller_epoch > i64::MAX as u64
            || self.hardware_generation != 1
            || self.profile_epoch != 1
            || !digest(&self.policy_digest)
            || !digest(&self.source_digest)
            || !digest(&self.executable_digest)
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

/// Per-fixture random keys arrive only on the already verified bootstrap FD.
/// Separate domains/keys keep worker replies and P observations out of commands.
#[derive(Clone)]
pub(super) struct ChannelKeys {
    pub(super) command: [u8; 32],
    pub(super) reply: [u8; 32],
    pub(super) authority: [u8; 32],
    pub(super) custody: [u8; 32],
}
impl Drop for ChannelKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.command.zeroize();
        self.reply.zeroize();
        self.authority.zeroize();
        self.custody.zeroize();
    }
}
impl ChannelKeys {
    pub(super) fn from_protected_hex(
        command: &str,
        reply: &str,
        authority: &str,
        custody: &str,
    ) -> Result<Self, &'static str> {
        fn key(s: &str) -> Result<[u8; 32], &'static str> {
            if s.len() != 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("child_config_invalid");
            }
            let mut out = [0; 32];
            hex::decode_to_slice(s, &mut out).map_err(|_| "child_config_invalid")?;
            if out == [0; 32] {
                return Err("child_config_invalid");
            }
            Ok(out)
        }
        let result = Self {
            command: key(command)?,
            reply: key(reply)?,
            authority: key(authority)?,
            custody: key(custody)?,
        };
        if result.command == result.reply
            || result.command == result.authority
            || result.reply == result.authority
            || result.custody == result.command
            || result.custody == result.reply
            || result.custody == result.authority
        {
            return Err("child_config_invalid");
        }
        Ok(result)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "operation", content = "command", deny_unknown_fields)]
pub(super) enum WorkerOperation {
    Probe,
    Backend(super::la_backend::Capability),
    Reserve(ReserveCommand, super::la_store::AssignmentTerms),
    Permit(InspectCommand, Box<super::la_auth::StoredMandate>),
    Stage(InspectCommand),
    Start(InspectCommand),
    Status(InspectCommand),
    Fetch(InspectCommand),
    Stop(InspectCommand),
    Renew(RenewCommand),
    Close(CloseCommand),
    ReconcileTerminal(TerminalReconcileCommand),
    AdmitSuccessor(Box<WorkerSuccessorAdmission>),
    ReboundPermit(Box<NeverStartedPermit>),
    AdmitRecoveredController(Box<RecoveredControllerAdmission>),
    DisposeEnteredLoss(Box<SpentLossDisposition>),
    AdmitLossReturn(Box<LossReturnAdmission>),
}
fn operation_target(operation: &WorkerOperation) -> Result<(&'static str, String), &'static str> {
    let id = |v: &str| {
        (16..=128).contains(&v.len())
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    let pair = match operation {
        WorkerOperation::Probe
        | WorkerOperation::Backend(_)
        | WorkerOperation::ReconcileTerminal(_)
        | WorkerOperation::AdmitSuccessor(_)
        | WorkerOperation::ReboundPermit(_)
        | WorkerOperation::AdmitRecoveredController(_)
        | WorkerOperation::DisposeEnteredLoss(_)
        | WorkerOperation::AdmitLossReturn(_) => ("POST", "/v1/worker/rpc".into()),
        WorkerOperation::Reserve(c, _) if id(&c.assignment) => {
            ("POST", "/v1/worker/reservations".into())
        }
        WorkerOperation::Permit(c, _) | WorkerOperation::Start(c) if id(&c.operation) => {
            ("POST", "/v1/worker/operations".into())
        }
        WorkerOperation::Stage(c) if id(&c.assignment) && id(&c.input_digest) => (
            "PUT",
            format!(
                "/v1/worker/reservations/{}/inputs/{}",
                c.assignment, c.input_digest
            ),
        ),
        WorkerOperation::Status(c) if id(&c.operation) => {
            ("GET", format!("/v1/worker/operations/{}", c.operation))
        }
        WorkerOperation::Fetch(c) if id(&c.operation) => (
            "GET",
            format!("/v1/worker/operations/{}/result", c.operation),
        ),
        WorkerOperation::Stop(c) if id(&c.operation) => (
            "POST",
            format!("/v1/worker/operations/{}/stop", c.operation),
        ),
        WorkerOperation::Renew(c) if id(&c.assignment) => (
            "POST",
            format!("/v1/worker/assignments/{}/renew", c.assignment),
        ),
        WorkerOperation::Close(c) if id(&c.assignment) => (
            "POST",
            format!("/v1/worker/assignments/{}/stop", c.assignment),
        ),
        _ => return Err("evidence_invalid"),
    };
    Ok(pair)
}

impl WorkerOperation {
    pub(super) fn typed_backend(&self) -> bool {
        match self {
            Self::Backend(_) => true,
            Self::Permit(c, _)
            | Self::Stage(c)
            | Self::Start(c)
            | Self::Status(c)
            | Self::Fetch(c)
            | Self::Stop(c) => c.backend.is_some(),
            _ => false,
        }
    }

    fn needs_admission(&self) -> bool {
        matches!(
            self,
            Self::Backend(_)
                | Self::Reserve(..)
                | Self::Permit(..)
                | Self::Stage(_)
                | Self::Start(_)
                | Self::Renew(_)
        )
    }
    fn binding(&self) -> Option<(&str, &str)> {
        match self {
            Self::Probe | Self::Backend(_) => None,
            Self::AdmitLossReturn(c) => Some((&c.binding.worker, &c.binding.worker_boot)),
            Self::DisposeEnteredLoss(c) => Some((&c.binding.worker, &c.binding.worker_boot)),
            Self::ReboundPermit(c) => Some((&c.body.binding.worker, &c.body.binding.worker_boot)),
            Self::AdmitRecoveredController(c) => {
                Some((&c.body.binding.worker, &c.body.binding.worker_boot))
            }
            Self::AdmitSuccessor(c) => Some((&c.body.binding.worker, &c.body.binding.worker_boot)),
            Self::Reserve(c, _) => Some((&c.worker, &c.boot)),
            Self::Permit(c, _)
            | Self::Stage(c)
            | Self::Start(c)
            | Self::Fetch(c)
            | Self::Status(c)
            | Self::Stop(c) => Some((&c.worker, &c.boot)),
            Self::Renew(c) => Some((&c.worker, &c.boot)),
            Self::Close(c) => Some((&c.worker, &c.boot)),
            Self::ReconcileTerminal(c) => Some((&c.worker, &c.boot)),
        }
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RpcRequest {
    version: u32,
    binding: ChannelBinding,
    sequence: u64,
    input_digest: String,
    input_bytes: u64,
    operation: WorkerOperation,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedRequest {
    request: RpcRequest,
    mac: [u8; 32],
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "receipt", deny_unknown_fields)]
pub(super) enum WorkerReply {
    Backend(super::la_backend::Capability),
    Probe {
        worker_pid: u32,
        admission: String,
    },
    Reserved(WorkerReceipt, [u8; 32]),
    Permitted(PermitReceipt, [u8; 32]),
    Staged {
        operation: String,
        command_digest: String,
        input_digest: String,
        input_bytes: u64,
    },
    Result(Vec<u8>, ResultReceipt, [u8; 32]),
    Status {
        operation: String,
        state: String,
        starts: u64,
    },
    Stopped(StopReceipt, [u8; 32]),
    Renewed(RenewReceipt, [u8; 32]),
    Closed(CloseReceipt, [u8; 32]),
    TerminalReconciled(Box<WorkerTerminalReceipt>, [u8; 32]),
    SuccessorAdmitted(ActivationAck),
    LossReturnInstalled {
        admission: String,
        installed_at: u64,
        mac: [u8; 32],
    },
    LossDisposed {
        disposition: String,
    },
    ReboundPermitted(PermitReceipt, [u8; 32]),
    Refused {
        code: String,
    },
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcResponse {
    version: u32,
    binding: ChannelBinding,
    sequence: u64,
    request_digest: String,
    reply: WorkerReply,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedResponse {
    response: RpcResponse,
    mac: [u8; 32],
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TerminalReconcileCommand {
    worker: String,
    boot: String,
    handoff: String,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerTerminalReceipt {
    binding: ChannelBinding,
    previous: ChannelBinding,
    handoff: String,
    close_digest: String,
    worker_state: String,
    seal_digest: String,
}
impl WorkerTerminalReceipt {
    fn verify(
        &self,
        keys: &ChannelKeys,
        handoff: &WorkerEpochHandoff,
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        let (close, _) = handoff.settled_close(keys)?;
        if self.binding != handoff.binding
            || self.previous != handoff.previous
            || self.handoff != handoff.digest()?
            || self.close_digest
                != hex::encode(Sha256::digest(
                    serde_json::to_vec(&close).map_err(|_| "evidence_invalid")?,
                ))
            || self.worker_state != handoff.worker_state
            || self.seal_digest.len() != 64
            || hex::decode(&self.seal_digest).is_err()
            || !bool::from(
                typed_mac(
                    &keys.reply,
                    b"diffuser-worker-terminal-reconciliation/v1\0",
                    self,
                )?
                .ct_eq(mac),
            )
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}
impl WorkerRpc {
    fn reconcile_terminal(
        &self,
        c: &TerminalReconcileCommand,
    ) -> Result<WorkerReply, &'static str> {
        let (_, epochs) = transport_epochs(&self.channel.db)?;
        let TransportTransition::Worker(h) = epochs.last().ok_or("evidence_invalid")? else {
            return Err("evidence_invalid");
        };
        h.verify_history(&self.keys.custody)?;
        if c.worker != self.session.worker
            || c.boot != self.session.boot
            || self.channel.binding != h.binding
            || c.handoff != h.digest()?
            || state_custody::state_digest(&self.channel.root)? != h.worker_state
        {
            return Err("evidence_invalid");
        }
        let status =
            std::fs::read_to_string("/proc/self/status").map_err(|_| "evidence_invalid")?;
        for line in ["NoNewPrivs:\t1", "Seccomp:\t2", "CapEff:\t0000000000000000"] {
            if !status.lines().any(|s| s == line) {
                return Err("evidence_invalid");
            }
        }
        let (close, _) = h.settled_close(&self.keys)?;
        let receipt = WorkerTerminalReceipt {
            binding: h.binding.clone(),
            previous: h.previous.clone(),
            handoff: h.digest()?,
            close_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(&close).map_err(|_| "evidence_invalid")?,
            )),
            worker_state: h.worker_state.clone(),
            seal_digest: hex::encode(Sha256::digest(status.as_bytes())),
        };
        let mac = typed_mac(
            &self.keys.reply,
            b"diffuser-worker-terminal-reconciliation/v1\0",
            &receipt,
        )?;
        Ok(WorkerReply::TerminalReconciled(Box::new(receipt), mac))
    }
}

/// One bounded journal per role, inside that role's pinned finite root. It never
/// infers a trusted recovery high-water from its own database. A pending intent
/// after a crash is uncertain, never permission to repeat an execution.
pub(super) struct TransportJournal {
    db: super::la_store::PinnedDb,
    root: std::fs::File,
    root_path: std::path::PathBuf,
    binding: ChannelBinding,
    file: std::fs::File,
    name: String,
    custody: Option<JournalCustodyState>,
    owned_state: bool,
    owned_digest: Option<String>,
}
impl TransportJournal {
    pub(super) fn create(
        root: &std::fs::File,
        path: &std::path::Path,
        name: &str,
        binding: ChannelBinding,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        binding.validate()?;
        if !super::la_store::claim_root_matches(root, path)
            || !matches!(name, "controller-channel.sqlite" | "worker-channel.sqlite")
        {
            return Err("evidence_invalid");
        }
        let file = super::la_artifacts::open_artifact(
            root,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| "storage_unavailable")?;
        if file.metadata().map_err(|_| "storage_unavailable")?.nlink() != 1 {
            return Err("evidence_invalid");
        }
        file.sync_all()
            .and_then(|_| root.sync_all())
            .map_err(|_| "storage_unavailable")?;
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_database(root, name, false)?;
        db.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE channel_identity (binding BLOB NOT NULL, role TEXT NOT NULL); CREATE TABLE channel_log (sequence INTEGER PRIMARY KEY, digest TEXT NOT NULL, response BLOB, request BLOB NOT NULL); CREATE TABLE channel_checkpoints (revision INTEGER PRIMARY KEY, frame BLOB NOT NULL, ack BLOB); CREATE TABLE channel_authority (sequence INTEGER PRIMARY KEY, observed_at INTEGER NOT NULL, body BLOB NOT NULL, frame BLOB NOT NULL); CREATE TABLE channel_epochs (epoch INTEGER PRIMARY KEY, body BLOB NOT NULL);").map_err(|_|"storage_unavailable")?;
        db.execute(
            "INSERT INTO channel_identity VALUES (?1,?2)",
            rusqlite::params![
                serde_json::to_vec(&binding).map_err(|_| "evidence_invalid")?,
                name
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        let result = Self {
            db,
            root: root.try_clone().map_err(|_| "storage_unavailable")?,
            root_path: path.to_path_buf(),
            binding,
            file,
            name: name.into(),
            owned_state: false,
            owned_digest: None,
            custody: None,
        };
        result.check()?;
        Ok(result)
    }
    pub(super) fn reopen(
        root: &std::fs::File,
        path: &std::path::Path,
        name: &str,
        binding: ChannelBinding,
        protected_high_water: u64,
    ) -> Result<Self, &'static str> {
        binding.validate()?;
        if !super::la_store::claim_root_matches(root, path)
            || !matches!(name, "controller-channel.sqlite" | "worker-channel.sqlite")
            || protected_high_water > RPC_HISTORY_MAX
        {
            return Err("evidence_invalid");
        }
        use std::os::fd::AsRawFd;
        let file = super::la_artifacts::open_artifact(root, name, libc::O_RDWR)
            .map_err(|_| "evidence_invalid")?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_database(root, name, false)?;
        let result = Self {
            db,
            root: root.try_clone().map_err(|_| "storage_unavailable")?,
            root_path: path.to_path_buf(),
            binding,
            file,
            name: name.into(),
            owned_state: false,
            owned_digest: None,
            custody: None,
        };
        result.check()?;
        let high: i64 = result
            .db
            .query_row(
                "SELECT COALESCE(MAX(sequence),0) FROM channel_log",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let count: i64 = result
            .db
            .query_row("SELECT COUNT(*) FROM channel_log", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        if high != protected_high_water as i64 || count != high {
            return Err("evidence_invalid");
        }
        Ok(result)
    }
    fn check(&self) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        if !super::la_store::claim_root_matches(&self.root, &self.root_path) {
            return Err("evidence_invalid");
        }
        let current = super::la_artifacts::open_artifact(&self.root, &self.name, libc::O_RDONLY)
            .map_err(|_| "evidence_invalid")?;
        let a = self.file.metadata().map_err(|_| "evidence_invalid")?;
        let b = current.metadata().map_err(|_| "evidence_invalid")?;
        if !a.is_file()
            || a.nlink() != 1
            || a.mode() & 0o777 != 0o600
            || a.uid() != unsafe { libc::geteuid() }
            || (a.dev(), a.ino()) != (b.dev(), b.ino())
        {
            return Err("evidence_invalid");
        }
        let identities: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM channel_identity", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        let (count,high,invalid):(i64,i64,i64)=self.db.query_row("SELECT COUNT(*),COALESCE(MAX(sequence),0),COALESCE(SUM(sequence<1 OR sequence>512 OR length(digest)!=64 OR length(response)>65536 OR length(request)<1 OR length(request)>65536),0) FROM channel_log",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"evidence_invalid")?;
        if identities != 1
            || invalid != 0
            || count != high
            || count < 0
            || count > RPC_HISTORY_MAX as i64
        {
            return Err("evidence_invalid");
        }
        let bytes: Vec<u8> = self
            .db
            .query_row("SELECT binding FROM channel_identity", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        let role: String = self
            .db
            .query_row("SELECT role FROM channel_identity", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        if role != self.name {
            return Err("evidence_invalid");
        }
        let (genesis, epochs) = transport_epochs(&self.db)?;
        let current = epochs.last().map(|e| e.binding()).unwrap_or(&genesis);
        if bytes != serde_json::to_vec(&genesis).map_err(|_| "evidence_invalid")?
            || current != &self.binding
            || (self.custody.is_none() && !epochs.is_empty())
        {
            return Err("evidence_invalid");
        }
        if self.custody.is_none() {
            transport_state_digest(&self.db, &self.binding)?;
        }
        self.check_custody()
    }
    fn next(&self, digest: &str) -> Result<u64, &'static str> {
        self.check()?;
        use rusqlite::OptionalExtension;
        let last:Option<(i64,String,bool)>=self.db.query_row("SELECT sequence,digest,response IS NULL FROM channel_log ORDER BY sequence DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|"storage_unavailable")?;
        match last {
            Some((seq, old, true)) if old == digest => {
                u64::try_from(seq).map_err(|_| "evidence_invalid")
            }
            Some((_, _, true)) => Err("transport_uncertain"),
            Some((seq, _, false)) => u64::try_from(seq)
                .ok()
                .and_then(|n| n.checked_add(1))
                .filter(|n| *n <= RPC_HISTORY_MAX)
                .ok_or("capacity_unavailable"),
            None => Ok(1),
        }
    }
    fn begin(
        &mut self,
        seq: u64,
        digest: &str,
        envelope: &[u8],
    ) -> Result<Option<Vec<u8>>, &'static str> {
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        self.check()?;
        validate_rpc_envelope(envelope, &self.name, &self.binding, seq, digest)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<(String, Option<Vec<u8>>, Vec<u8>)> = tx
            .query_row(
                "SELECT digest,response,request FROM channel_log WHERE sequence=?1",
                [seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old, response, request)) = old {
            if old != digest || request != envelope {
                return Err("evidence_invalid");
            }
            return Ok(response);
        }
        let (high,pending):(i64,i64)=tx.query_row("SELECT COALESCE(MAX(sequence),0),COUNT(CASE WHEN response IS NULL THEN 1 END) FROM channel_log",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|"storage_unavailable")?;
        if i64::try_from(seq).map_err(|_| "evidence_invalid")?
            != high.checked_add(1).ok_or("evidence_invalid")?
            || seq > RPC_HISTORY_MAX
            || pending != 0
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO channel_log VALUES (?1,?2,NULL,?3)",
            params![seq as i64, digest, envelope],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.checkpoint("intent", seq)?;
        self.check()?;
        Ok(None)
    }
    fn complete(&mut self, seq: u64, digest: &str, response: &[u8]) -> Result<(), &'static str> {
        self.check()?;
        if response.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        let n=self.db.execute("UPDATE channel_log SET response=?3 WHERE sequence=?1 AND digest=?2 AND response IS NULL",rusqlite::params![seq as i64,digest,response]).map_err(|_|"storage_unavailable")?;
        if n != 1 {
            return Err("evidence_invalid");
        }
        self.checkpoint("complete", seq)?;
        self.check()
    }
    fn pending(&self, seq: u64) -> Result<bool, &'static str> {
        use rusqlite::OptionalExtension;
        Ok(self
            .db
            .query_row(
                "SELECT response IS NULL FROM channel_log WHERE sequence=?1",
                [seq as i64],
                |r| r.get::<_, bool>(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?
            .unwrap_or(false))
    }
}

#[derive(Clone, Default)]
pub(super) struct WorkerAdmission(pub(super) std::sync::Arc<std::sync::Mutex<Option<AdmissionLease>>>);
pub(super) struct AdmissionLease {
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    pub(super) job_scope: Option<String>,
}
impl WorkerAdmission {
    pub(super) fn check(&self) -> Result<(), &'static str> {
        let current = self.0.lock().map_err(|_| "storage_unavailable")?;
        let activation = current.as_ref().ok_or("evidence_invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis();
        if now < activation.issued_at as u128 || now >= activation.expires_at as u128 {
            return Err("evidence_stale");
        }
        Ok(())
    }
    pub(super) fn install(
        &self,
        bytes: &[u8],
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        root: &std::fs::File,
        role: &str,
        domain: Option<&state_custody::Session>,
    ) -> Result<ActivationAck, &'static str> {
        if bytes.len() > 12288 {
            return Err("evidence_invalid");
        }
        let activation: Activation =
            serde_json::from_slice(&super::la_contract::canonical_json(bytes)?)
                .map_err(|_| "evidence_invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis() as u64;
        activation.verify(binding, keys, root, role, domain, now)?;
        let mut current = self.0.lock().map_err(|_| "storage_unavailable")?;
        if current.is_some() {
            return Err("evidence_invalid");
        }
        let ack = activation.acknowledgment(role, keys)?;
        *current = Some(AdmissionLease {
            issued_at: activation.body.issued_at,
            expires_at: activation.body.expires_at,
            job_scope: None,
        });
        Ok(ack)
    }
}

pub(super) struct WorkerRpc {
    pub(super) journal: super::la_worker::OperationJournal,
    pub(super) session: super::la_worker::ReservationSession,
    pub(super) channel: TransportJournal,
    pub(super) keys: ChannelKeys,
    pub(super) admission: WorkerAdmission,
}
impl WorkerRpc {
    pub(super) fn activate(&mut self, bytes: &[u8]) -> Result<ActivationAck, &'static str> {
        self.channel.loss_return_quarantine()?;
        let digest = state_custody::state_digest(&self.channel.root)?;
        let ack = self.admission.install(
            bytes,
            &self.channel.binding,
            &self.keys,
            &self.channel.root,
            "worker",
            None,
        )?;
        self.channel.owned_state = true;
        self.channel.owned_digest = Some(digest);
        Ok(ack)
    }
}
impl WorkerRpc {
    #[cfg(test)]
    fn handle(&mut self, bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        if bytes.len() < 4 {
            return Err("evidence_invalid");
        }
        let size =
            u32::from_be_bytes(bytes[..4].try_into().map_err(|_| "evidence_invalid")?) as usize;
        if size > RPC_JSON_MAX || size > bytes.len() - 4 {
            return Err("evidence_invalid");
        }
        let request: SignedRequest =
            serde_json::from_slice(&bytes[4..4 + size]).map_err(|_| "evidence_invalid")?;
        let (method, path) = operation_target(&request.request.operation)?;
        self.handle_at(bytes, method, &path)
    }
    fn handle_at(
        &mut self,
        bytes: &[u8],
        method: &str,
        path: &str,
    ) -> Result<Vec<u8>, &'static str> {
        if bytes.len() < 4 || bytes.len() > 4 + RPC_JSON_MAX + RPC_INPUT_MAX {
            return Err("evidence_invalid");
        }
        let count =
            u32::from_be_bytes(bytes[..4].try_into().map_err(|_| "evidence_invalid")?) as usize;
        if count == 0 || count > RPC_JSON_MAX || count > bytes.len() - 4 {
            return Err("evidence_invalid");
        }
        let canonical = super::la_contract::canonical_json(&bytes[4..4 + count])?;
        let signed: SignedRequest =
            serde_json::from_slice(&canonical).map_err(|_| "evidence_invalid")?;
        let req = &signed.request;
        let (expected_method, expected_path) = operation_target(&req.operation)?;
        if method != expected_method || path != expected_path {
            return Err("evidence_invalid");
        }
        if req.version != 1
            || req.binding != self.channel.binding
            || req.sequence == 0
            || req.sequence > RPC_HISTORY_MAX
            || !bool::from(
                typed_mac(&self.keys.command, b"diffuser-rpc-request/v1\0", req)?
                    .ct_eq(&signed.mac),
            )
        {
            return Err("evidence_invalid");
        }
        if let Some((worker, boot)) = req.operation.binding() {
            if worker != req.binding.worker || boot != req.binding.worker_boot {
                return Err("evidence_invalid");
            }
        }
        let input = &bytes[4 + count..];
        if input.len() as u64 != req.input_bytes
            || hex::encode(Sha256::digest(input)) != req.input_digest
            || (!matches!(req.operation, WorkerOperation::Stage(_)) && !input.is_empty())
        {
            return Err("evidence_invalid");
        }
        if !matches!(
            req.operation,
            WorkerOperation::Probe
                | WorkerOperation::DisposeEnteredLoss(_)
                | WorkerOperation::AdmitLossReturn(_)
        ) {
            self.channel.loss_return_quarantine()?;
        }
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(req).map_err(|_| "evidence_invalid")?,
        ));
        // Qualification-only maximum-retention probe. It has no reserve or
        // execution authority, but exercises the ordinary owned-state witness
        // against the actual full worker root before any resource issuance.
        #[cfg(test)]
        if req.sequence == 161
            && matches!(req.operation, WorkerOperation::Probe)
            && std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() == Ok("storage")
        {
            self.channel.owned_state = true;
        }
        if let WorkerOperation::AdmitRecoveredController(cap) = &req.operation {
            cap.verify_role(
                &self.channel.binding,
                &self.keys,
                &self.channel.root,
                "worker",
                None,
                wall_now()?,
            )?;
            self.admission.validate_controller_admission()?;
        }
        if let WorkerOperation::ReboundPermit(cap) = &req.operation {
            cap.verify_role(
                &self.channel.binding,
                &self.keys,
                &self.channel.root,
                "worker",
                None,
                wall_now()?,
            )?;
            if self
                .admission
                .0
                .lock()
                .map_err(|_| "storage_unavailable")?
                .is_some()
            {
                return Err("evidence_invalid");
            }
        }
        if let WorkerOperation::AdmitSuccessor(cap) = &req.operation {
            cap.verify_role(
                &self.channel.binding,
                &self.keys,
                &self.channel.root,
                "worker",
                None,
                wall_now()?,
            )?;
            if self
                .admission
                .0
                .lock()
                .map_err(|_| "storage_unavailable")?
                .is_some()
            {
                return Err("evidence_invalid");
            }
        }
        if let WorkerOperation::DisposeEnteredLoss(cap) = &req.operation {
            cap.verify_before(&self.channel.root, "worker", &self.keys, wall_now()?)?;
            self.journal.bind_occupancy_keys(&self.keys)?;
        }
        if let WorkerOperation::AdmitLossReturn(cap) = &req.operation {
            if req.sequence != 10 {
                return Err("evidence_invalid");
            }
            cap.verify_role(&self.channel.root, "worker", &self.keys, wall_now()?)?;
            self.journal.bind_occupancy_keys(&self.keys)?;
        }
        let was_pending = self.channel.pending(req.sequence)?;
        if let Some(cached) = self.channel.begin(
            req.sequence,
            &digest,
            &serde_json::to_vec(&signed).map_err(|_| "evidence_invalid")?,
        )? {
            return Ok(cached);
        }
        // A request with durable intent but no reply may already have executed.
        // Recovery must reconcile it; never repeat even a valid signed start.
        let result = if was_pending {
            match &req.operation {
                WorkerOperation::Start(c) | WorkerOperation::Fetch(c) if c.backend.is_some() => {
                    self.journal.retained_typed_result(&self.session, c)
                }
                _ => Err("transport_uncertain"),
            }
        } else if req.operation.needs_admission() {
            self.admission
                .check_operation(&req.operation)
                .and_then(|_| self.execute(&req.operation, input))
        } else {
            self.execute(&req.operation, input)
        };
        let reply = result.unwrap_or_else(|code| WorkerReply::Refused { code: code.into() });
        let response = RpcResponse {
            version: 1,
            binding: req.binding.clone(),
            sequence: req.sequence,
            request_digest: digest.clone(),
            reply,
        };
        let mac = typed_mac(&self.keys.reply, b"diffuser-rpc-response/v1\0", &response)?;
        let bytes = serde_json::to_vec(&SignedResponse { response, mac })
            .map_err(|_| "evidence_invalid")?;
        self.channel.complete(req.sequence, &digest, &bytes)?;
        Ok(bytes)
    }
    fn execute(&mut self, op: &WorkerOperation, input: &[u8]) -> Result<WorkerReply, &'static str> {
        match op {
            WorkerOperation::Permit(c, m) => self.authority_permits(m, c.permit_until)?,
            WorkerOperation::Stage(c) | WorkerOperation::Start(c) => {
                let m = self.journal.worker_mandate(&self.session, c)?;
                self.authority_permits(&m, c.permit_until)?;
            }
            _ => (),
        }
        if let WorkerOperation::AdmitLossReturn(cap) = op {
            let installed_at =
                self.journal
                    .install_loss_return_generation(&self.session, cap, &self.keys)?;
            return Ok(WorkerReply::LossReturnInstalled {
                admission: cap.digest()?,
                installed_at,
                mac: cap.worker_ack(&self.keys, installed_at)?,
            });
        }
        if let WorkerOperation::DisposeEnteredLoss(cap) = op {
            cap.fresh(wall_now()?)?;
            self.journal.install_spent_loss(cap, &self.keys)?;
            return Ok(WorkerReply::LossDisposed {
                disposition: cap.digest()?,
            });
        }
        if let WorkerOperation::AdmitRecoveredController(cap) = op {
            self.journal
                .install_controller_admission(&self.session, cap)?;
            let ack = cap.acknowledgment("worker", &self.keys)?;
            self.admission.set_controller_admission(cap)?;
            return Ok(WorkerReply::SuccessorAdmitted(ack));
        }
        if let WorkerOperation::ReboundPermit(cap) = op {
            let mandate = self.journal.worker_mandate(&self.session, &cap.rebound)?;
            self.authority_permits(&mandate, cap.rebound.permit_until)?;
            let (r, m) = self.journal.rebound_never_started(&self.session, cap)?;
            self.admission.set_never_started(cap)?;
            return Ok(WorkerReply::ReboundPermitted(r, m));
        }
        if let WorkerOperation::ReconcileTerminal(c) = op {
            return self.reconcile_terminal(c);
        }
        if let WorkerOperation::AdmitSuccessor(cap) = op {
            self.journal
                .install_successor_generation(&self.session, cap)?;
            let ack = cap.acknowledgment("worker", &self.keys)?;
            self.admission.set_successor(cap)?;
            return Ok(WorkerReply::SuccessorAdmitted(ack));
        }
        let key = &self.session.key;
        let s = &self.session;
        let j = &mut self.journal;
        match op {
            WorkerOperation::ReconcileTerminal(_)
            | WorkerOperation::AdmitSuccessor(_)
            | WorkerOperation::ReboundPermit(_)
            | WorkerOperation::AdmitRecoveredController(_)
            | WorkerOperation::DisposeEnteredLoss(_)
            | WorkerOperation::AdmitLossReturn(_) => Err("evidence_invalid"),
            WorkerOperation::Backend(capability) => {
                j.backend_ready(*capability)?;
                Ok(WorkerReply::Backend(*capability))
            }
            WorkerOperation::Probe => Ok(WorkerReply::Probe {
                worker_pid: std::process::id(),
                admission: "resource_unqualified".into(),
            }),
            WorkerOperation::Reserve(c, terms) => {
                j.bind_assignment_terms(c, terms)?;
                let mac = sign_reserve_command(key, c)?;
                let (r, m) = j.reserve_authenticated(s, c, &mac)?;
                Ok(WorkerReply::Reserved(r, m))
            }
            WorkerOperation::Permit(c, mandate) => {
                if let Some(capability) = c.backend {
                    j.backend_ready(capability)?;
                }
                j.bind_worker_mandate(s, c, mandate)?;
                let mac = sign_inspect_command(key, c)?;
                let (r, m) = j.accept_inspect_permit(s, c, &mac)?;
                Ok(WorkerReply::Permitted(r, m))
            }
            WorkerOperation::Stage(c) => {
                j.worker_mandate(s, c)?;
                if let Some(capability) = c.backend {
                    capability.validate_input(input)?;
                }
                let mac = sign_stage_command(key, c)?;
                j.stage_authenticated_input(s, c, &mac, input)?;
                Ok(WorkerReply::Staged {
                    operation: c.operation.clone(),
                    command_digest: hex::encode(Sha256::digest(
                        serde_json::to_vec(c).map_err(|_| "evidence_invalid")?,
                    )),
                    input_digest: c.input_digest.clone(),
                    input_bytes: input.len() as u64,
                })
            }
            WorkerOperation::Start(c) => {
                j.worker_mandate(s, c)?;
                j.start_inspection(s, c)
            }
            WorkerOperation::Fetch(c) => j.inspection_reply(s, c),
            WorkerOperation::Status(c) => {
                let (state, starts) = j.authenticated_status(s, c)?;
                Ok(WorkerReply::Status {
                    operation: c.operation.clone(),
                    state,
                    starts,
                })
            }
            WorkerOperation::Stop(c) => {
                let mac = sign_stop_command(key, c)?;
                match j.stop_with_receipt(s, c, &mac) {
                    Ok((r, m)) => Ok(WorkerReply::Stopped(r, m)),
                    Err("state_conflict") => j.inspection_reply(s, c),
                    Err(code) => Err(code),
                }
            }
            WorkerOperation::Renew(c) => {
                let mac = sign_renew_command(key, c)?;
                let (r, m) = j.renew_authenticated(s, c, &mac)?;
                Ok(WorkerReply::Renewed(r, m))
            }
            WorkerOperation::Close(c) => {
                let mac = sign_close_command(key, c)?;
                let (r, m) = j.close_authenticated(s, c, &mac)?;
                Ok(WorkerReply::Closed(r, m))
            }
        }
    }
}

static RPC_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct RpcSlot;
impl RpcSlot {
    fn acquire() -> Option<Self> {
        RPC_IN_FLIGHT
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| (n < 2).then_some(n + 1),
            )
            .ok()
            .map(|_| Self)
    }
}
impl Drop for RpcSlot {
    fn drop(&mut self) {
        RPC_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
async fn rpc_closed() -> StatusCode {
    StatusCode::UNAUTHORIZED
}
async fn rpc(
    State(state): State<std::sync::Arc<std::sync::Mutex<WorkerRpc>>>,
    request: axum::extract::Request,
) -> Response {
    let Some(slot) = RpcSlot::acquire() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let mut media = request.headers().get_all(header::CONTENT_TYPE).iter();
    if !matches!((media.next(),media.next()),(Some(value),None) if value=="application/octet-stream")
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let bytes =
        match axum::body::to_bytes(request.into_body(), 4 + RPC_JSON_MAX + RPC_INPUT_MAX).await {
            Ok(v) => v,
            Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        };
    let result = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        state
            .lock()
            .map_err(|_| "storage_unavailable")?
            .handle_at(&bytes, &method, &path)
    })
    .await;
    match result {
        Ok(Ok(bytes)) => {
            #[cfg(test)]
            if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").is_ok_and(|v| {
                v.starts_with("controller-close-recovery") || v.starts_with("worker-close-recovery")
            }) && serde_json::from_slice::<SignedResponse>(&bytes).is_ok_and(|r| {
                matches!(&r.response.reply, WorkerReply::Closed(..))
                    && (std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
                        != Ok("worker-close-recovery-successor")
                        || (r.response.binding.worker_epoch == 1 && r.response.sequence == 6))
            }) {
                use std::io::Write;
                println!(
                    "DIFFUSER_LA_CHILD_V1 {}",
                    serde_json::json!({"kind":"CLOSE_COMMITTED_BEFORE_ACK","reply_sha256":hex::encode(Sha256::digest(&bytes))})
                );
                std::io::stdout().flush().map_err(|_| ()).ok();
                // Fault injection only: after ordinary durable execution and P
                // custody, outside the worker mutex. P kills exact C here.
                tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            }
            #[cfg(test)]
            if std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                .is_ok_and(|v| v.starts_with("controller-stop-recovery"))
                && serde_json::from_slice::<SignedResponse>(&bytes)
                    .is_ok_and(|r| matches!(r.response.reply, WorkerReply::Stopped(..)))
            {
                use std::io::Write;
                println!(
                    "DIFFUSER_LA_CHILD_V1 {}",
                    serde_json::json!({"kind":"STOP_COMMITTED_BEFORE_ACK","reply_sha256":hex::encode(Sha256::digest(&bytes))})
                );
                std::io::stdout().flush().ok();
                tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            }
            ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
        }
        other => {
            recovery_trace(
                "worker_rpc_precommit_refusal",
                serde_json::json!({"result":format!("{other:?}")}),
            );
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}
pub(super) fn worker_rpc_router(
    inventory: InventoryContext,
    state: std::sync::Arc<std::sync::Mutex<WorkerRpc>>,
) -> Router {
    // The inventory never derives readiness from possession of a channel key.
    let internal = axum::Router::new()
        .route("/v1/worker/rpc", axum::routing::post(rpc))
        .route("/v1/worker/reservations", axum::routing::post(rpc))
        .route("/v1/worker/operations", axum::routing::post(rpc))
        .route(
            "/v1/worker/operations/{operation}",
            axum::routing::get(rpc).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route(
            "/v1/worker/operations/{operation}/result",
            axum::routing::get(rpc).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .route(
            "/v1/worker/operations/{operation}/stop",
            axum::routing::post(rpc),
        )
        .route(
            "/v1/worker/assignments/{assignment}/renew",
            axum::routing::post(rpc),
        )
        .route(
            "/v1/worker/assignments/{assignment}/stop",
            axum::routing::post(rpc),
        )
        .route(
            "/v1/worker/reservations/{assignment}/inputs/{artifact}",
            axum::routing::put(rpc),
        )
        .with_state(state);
    inventory_routes(inventory).merge(internal)
}

pub(super) struct WorkerClient {
    address: std::net::SocketAddr,
    pub(super) channel: TransportJournal,
    keys: ChannelKeys,
    admission: WorkerAdmission,
    terms: std::collections::BTreeMap<String, super::la_store::AssignmentTerms>,
    mandates: std::collections::BTreeMap<String, super::la_auth::StoredMandate>,
    service_custody: Option<std::sync::Arc<state_custody::Session>>,
    typed_capability: Option<super::la_backend::Capability>,
}
impl WorkerClient {
    pub(super) fn new(
        address: std::net::SocketAddr,
        channel: TransportJournal,
        keys: ChannelKeys,
    ) -> Result<Self, &'static str> {
        if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || address.port() == 0
        {
            return Err("evidence_invalid");
        }
        Ok(Self {
            address,
            channel,
            keys,
            admission: WorkerAdmission::default(),
            terms: std::collections::BTreeMap::new(),
            mandates: std::collections::BTreeMap::new(),
            service_custody: None,
            typed_capability: None,
        })
    }
    /// Protected startup worker client allowing loopback or private 10.x LAN IPv4.
    pub(super) fn new_lan(
        address: std::net::SocketAddr,
        channel: TransportJournal,
        keys: ChannelKeys,
    ) -> Result<Self, &'static str> {
        let allowed_ip = match address.ip() {
            std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.octets()[0] == 10,
            std::net::IpAddr::V6(_) => false,
        };
        if !allowed_ip || address.port() == 0 {
            return Err("evidence_invalid");
        }
        Ok(Self {
            address,
            channel,
            keys,
            admission: WorkerAdmission::default(),
            terms: std::collections::BTreeMap::new(),
            mandates: std::collections::BTreeMap::new(),
            service_custody: None,
            typed_capability: None,
        })
    }
    /// Protected startup capability binding for CPU or qualified native CUDA workers.
    pub(super) fn with_protected_capability(
        mut self,
        capability: Option<super::la_backend::Capability>,
    ) -> Self {
        self.typed_capability = capability;
        self
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn with_protected_backend(
        mut self,
        capability: Option<super::la_backend::Capability>,
    ) -> Self {
        self.typed_capability = capability.filter(|capability| {
            cfg!(test) || *capability == super::la_backend::Capability::PrivateSha256
        });
        self
    }
    pub(super) fn private_cuda_backend(&self) -> Option<super::la_backend::Capability> {
        self.typed_capability
            .filter(|c| matches!(c, super::la_backend::Capability::CudaAddOne(_)))
    }
    pub(super) fn with_protected_admission(mut self, admission: WorkerAdmission) -> Self {
        self.admission = admission;
        self
    }
    pub(super) fn with_service_custody(
        mut self,
        session: std::sync::Arc<state_custody::Session>,
    ) -> Self {
        self.service_custody = Some(session);
        self
    }
    pub(super) fn admission(&self) -> Result<(), &'static str> {
        self.admission.check()
    }
    pub(super) fn call(
        &mut self,
        operation: WorkerOperation,
        input: &[u8],
    ) -> Result<WorkerReply, &'static str> {
        if matches!(operation, WorkerOperation::Backend(capability) if self.typed_capability != Some(capability))
        {
            return Err("capability_unavailable");
        }
        if input.len() > RPC_INPUT_MAX
            || (!matches!(operation, WorkerOperation::Stage(_)) && !input.is_empty())
        {
            return Err("artifact_invalid");
        }
        if !matches!(
            operation,
            WorkerOperation::Probe
                | WorkerOperation::DisposeEnteredLoss(_)
                | WorkerOperation::AdmitLossReturn(_)
        ) {
            self.channel.loss_return_quarantine()?;
        }
        // Allocate using the normalized content, excluding the sequence. A lost
        // reply retries the same durable intent; another operation is blocked.
        let content = serde_json::to_vec(&(
            self.channel.binding.clone(),
            &operation,
            hex::encode(Sha256::digest(input)),
            input.len(),
        ))
        .map_err(|_| "evidence_invalid")?;
        let content_digest = hex::encode(Sha256::digest(&content));
        let seq = self.channel.next(&content_digest)?;
        if let WorkerOperation::AdmitLossReturn(cap) = &operation {
            if seq != 10 {
                return Err("evidence_invalid");
            }
            cap.verify_envelope(&self.keys, wall_now()?)?;
        }
        let req = RpcRequest {
            version: 1,
            binding: self.channel.binding.clone(),
            sequence: seq,
            input_digest: hex::encode(Sha256::digest(input)),
            input_bytes: input.len() as u64,
            operation,
        };
        let mac = typed_mac(&self.keys.command, b"diffuser-rpc-request/v1\0", &req)?;
        let metadata = serde_json::to_vec(&SignedRequest {
            request: req.clone(),
            mac,
        })
        .map_err(|_| "evidence_invalid")?;
        if metadata.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        if let Some(bytes) = self.channel.begin(seq, &content_digest, &metadata)? {
            return self.verify_response(seq, &req.operation, input, &bytes);
        }
        if matches!(
            req.operation,
            WorkerOperation::Close(_) | WorkerOperation::Stop(_)
        ) {
            // Both the exact transport intent and service outbox are witnessed
            // before outbound I/O. Failure retains the original uncertainty.
            self.service_custody
                .as_ref()
                .ok_or("evidence_invalid")?
                .close_midpoint(&metadata, &self.keys)?;
        }
        #[cfg(test)]
        if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref()
            == Ok("controller-stop-recovery-presend")
            && matches!(req.operation, WorkerOperation::Stop(_))
        {
            use std::io::Write;
            println!(
                "DIFFUSER_LA_CHILD_V1 {}",
                serde_json::json!({"kind":"STOP_MIDPOINT_BEFORE_SEND","sequence":seq})
            );
            std::io::stdout().flush().ok();
            std::thread::sleep(std::time::Duration::from_millis(2000));
        }
        let mut frame = (metadata.len() as u32).to_be_bytes().to_vec();
        frame.extend(metadata);
        frame.extend(input);
        let bytes = rpc_http(self.address, &req.operation, &frame)?;
        let reply = self.verify_response(seq, &req.operation, input, &bytes)?;
        self.channel.complete(seq, &content_digest, &bytes)?;
        Ok(reply)
    }
    /// Resume only the exact pending result-bearing RPC. A new operation
    /// cannot displace its signed transport intent after a lost response.
    pub(super) fn retry_pending_inspection(
        &mut self,
        command: &InspectCommand,
    ) -> Result<Option<WorkerReply>, &'static str> {
        use rusqlite::OptionalExtension;
        if command.backend.is_none() {
            return Err("evidence_invalid");
        }
        self.channel.check()?;
        let saved: Option<Vec<u8>> = self.channel.db.query_row(
            "SELECT request FROM channel_log WHERE response IS NULL ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        ).optional().map_err(|_| "storage_unavailable")?;
        let Some(saved) = saved else { return Ok(None) };
        let request: SignedRequest =
            serde_json::from_slice(&saved).map_err(|_| "evidence_invalid")?;
        let op = request.request.operation;
        if !matches!(&op, WorkerOperation::Start(c) | WorkerOperation::Fetch(c) if c == command) {
            return Err("transport_uncertain");
        }
        match self.call(op, &[])? {
            result @ WorkerReply::Result(..) => Ok(Some(result)),
            stopped @ WorkerReply::Stopped(..) => Ok(Some(stopped)),
            _ => Ok(None),
        }
    }

    pub(super) fn install_worker_return(
        &mut self,
        h: &WorkerEpochHandoff,
        address: std::net::SocketAddr,
        now: u64,
    ) -> Result<WorkerTerminalReceipt, &'static str> {
        if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || address.port() == 0
        {
            return Err("evidence_invalid");
        }
        *self.admission.0.lock().map_err(|_| "storage_unavailable")? = None;
        self.channel.install_worker_epoch(h, None, now)?;
        self.address = address;
        match self.call(
            WorkerOperation::ReconcileTerminal(TerminalReconcileCommand {
                worker: h.binding.worker.clone(),
                boot: h.binding.worker_boot.clone(),
                handoff: h.digest()?,
            }),
            &[],
        )? {
            WorkerReply::TerminalReconciled(r, m) => {
                r.verify(&self.keys, h, &m)?;
                Ok(*r)
            }
            _ => Err("evidence_invalid"),
        }
    }
    fn verify_response(
        &self,
        seq: u64,
        operation: &WorkerOperation,
        input: &[u8],
        bytes: &[u8],
    ) -> Result<WorkerReply, &'static str> {
        if bytes.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        let normalized = super::la_contract::canonical_json(bytes)?;
        let signed: SignedResponse =
            serde_json::from_slice(&normalized).map_err(|_| "evidence_invalid")?;
        let req = RpcRequest {
            version: 1,
            binding: self.channel.binding.clone(),
            sequence: seq,
            input_digest: hex::encode(Sha256::digest(input)),
            input_bytes: input.len() as u64,
            operation: operation.clone(),
        };
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(&req).map_err(|_| "evidence_invalid")?,
        ));
        let r = signed.response;
        if r.version != 1
            || r.binding != self.channel.binding
            || r.sequence != seq
            || r.request_digest != digest
            || !bool::from(
                typed_mac(&self.keys.reply, b"diffuser-rpc-response/v1\0", &r)?.ct_eq(&signed.mac),
            )
        {
            return Err("evidence_invalid");
        }
        Ok(r.reply)
    }
}

// One literal isolated peer; no DNS/proxy/redirects. Absolute wall budget and
// fixed header/body caps also bound a trickling or malformed response.
fn rpc_http(
    address: std::net::SocketAddr,
    operation: &WorkerOperation,
    frame: &[u8],
) -> Result<Vec<u8>, &'static str> {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};
    let (method, path) = operation_target(operation)?;
    let end = Instant::now() + Duration::from_millis(1000);
    let mut socket = std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500))
        .map_err(|_| "inventory_unavailable")?;
    let header=format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",frame.len());
    for part in [header.as_bytes(), frame] {
        let mut remaining = part;
        while !remaining.is_empty() {
            let budget = end
                .checked_duration_since(Instant::now())
                .filter(|v| !v.is_zero())
                .ok_or("inventory_unavailable")?;
            socket
                .set_write_timeout(Some(budget))
                .map_err(|_| "inventory_unavailable")?;
            let n = socket
                .write(remaining)
                .map_err(|_| "inventory_unavailable")?;
            if n == 0 {
                return Err("inventory_unavailable");
            }
            remaining = &remaining[n..];
        }
    }
    let mut bytes = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let remaining = end
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or("inventory_unavailable")?;
        socket
            .set_read_timeout(Some(remaining))
            .map_err(|_| "inventory_unavailable")?;
        let n = socket.read(&mut buf).map_err(|_| "inventory_unavailable")?;
        if n == 0 {
            break;
        }
        if bytes.len() + n > RPC_JSON_MAX + 8192 {
            return Err("evidence_invalid");
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    let split = bytes
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .filter(|n| *n <= 8192)
        .ok_or("evidence_invalid")?;
    let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| "evidence_invalid")?;
    let mut lines = headers.split("\r\n");
    if !lines.next().is_some_and(|l| l == "HTTP/1.1 200 OK") {
        return Err("evidence_invalid");
    }
    let mut length = None;
    let mut media = false;
    for line in lines {
        let (k, v) = line.split_once(':').ok_or("evidence_invalid")?;
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("evidence_invalid");
            }
            length = Some(v.parse::<usize>().map_err(|_| "evidence_invalid")?);
        }
        if k.eq_ignore_ascii_case("content-type") {
            if media || v != "application/json" {
                return Err("evidence_invalid");
            }
            media = true;
        }
        if k.eq_ignore_ascii_case("transfer-encoding") {
            return Err("evidence_invalid");
        }
    }
    let body = &bytes[split + 4..];
    if !media || length != Some(body.len()) || body.len() > RPC_JSON_MAX {
        return Err("evidence_invalid");
    }
    Ok(body.to_vec())
}

/// Decoded exclusively by the protected fixture bootstrap reader. This object
/// has no Debug/Serialize implementation and erases its secret strings on drop.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProtectedChannelBootstrap {
    pub(super) binding: ChannelBinding,
    command_key: String,
    reply_key: String,
    authority_key: String,
    custody_key: String,
    pub(super) expected_high_water: u64,
    #[serde(default)]
    pub(super) service_genesis: Option<ServiceGenesis>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceGenesis {
    pub(super) root_dev: u64,
    pub(super) root_inode: u64,
    pub(super) controller_boot: String,
    pub(super) controller_epoch: u64,
    pub(super) expected_records: u64,
}
impl Drop for ProtectedChannelBootstrap {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.command_key.zeroize();
        self.reply_key.zeroize();
        self.authority_key.zeroize();
        self.custody_key.zeroize();
    }
}
impl ProtectedChannelBootstrap {
    pub(super) fn validate(
        &self,
        worker: &str,
        worker_boot: &str,
        controller_boot: Option<&str>,
    ) -> Result<ChannelKeys, &'static str> {
        self.binding.validate()?;
        if self.binding.worker != worker
            || self.binding.worker_boot != worker_boot
            || controller_boot.is_some_and(|b| b != self.binding.controller_boot)
            || self.expected_high_water > RPC_HISTORY_MAX
        {
            return Err("child_config_invalid");
        }
        ChannelKeys::from_protected_hex(
            &self.command_key,
            &self.reply_key,
            &self.authority_key,
            &self.custody_key,
        )
    }
    pub(super) fn open_channel(
        &self,
        root: &std::fs::File,
        path: &std::path::Path,
        worker_role: bool,
    ) -> Result<TransportJournal, &'static str> {
        let name = if worker_role {
            "worker-channel.sqlite"
        } else {
            "controller-channel.sqlite"
        };
        if self.expected_high_water == 0 {
            TransportJournal::create(root, path, name, self.binding.clone())
        } else {
            TransportJournal::reopen(
                root,
                path,
                name,
                self.binding.clone(),
                self.expected_high_water,
            )
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceObservation {
    version: u32,
    binding: ChannelBinding,
    observation: serde_json::Value,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedSourceObservation {
    body: SourceObservation,
    mac: [u8; 32],
}

pub(super) fn sign_source_observation(
    key: &[u8; 32],
    binding: &ChannelBinding,
    bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let canonical = super::la_contract::canonical_json(bytes)?;
    let body = SourceObservation {
        version: 1,
        binding: binding.clone(),
        observation: serde_json::from_slice(&canonical).map_err(|_| "evidence_invalid")?,
    };
    let mac = typed_mac(key, b"diffuser-protected-authority/v1\0", &body)?;
    let bytes = serde_json::to_vec(&SignedSourceObservation { body, mac })
        .map_err(|_| "evidence_invalid")?;
    if bytes.len() > 12 * 1024 {
        return Err("evidence_invalid");
    }
    Ok(bytes)
}
pub(super) fn verify_source_observation(
    key: &[u8; 32],
    binding: &ChannelBinding,
    bytes: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if bytes.len() > 12 * 1024 {
        return Err("evidence_invalid");
    }
    let canonical = super::la_contract::canonical_json(bytes)?;
    let frame: SignedSourceObservation =
        serde_json::from_slice(&canonical).map_err(|_| "evidence_invalid")?;
    if frame.body.version != 1
        || frame.body.binding != *binding
        || !bool::from(
            typed_mac(key, b"diffuser-protected-authority/v1\0", &frame.body)?.ct_eq(&frame.mac),
        )
    {
        return Err("evidence_invalid");
    }
    super::la_contract::canonical_json(
        &serde_json::to_vec(&frame.body.observation).map_err(|_| "evidence_invalid")?,
    )
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceAck {
    pub(super) binding: ChannelBinding,
    pub(super) role: String,
    pub(super) sequence: u64,
    pub(super) observation_digest: String,
    mac: [u8; 32],
}
pub(super) fn source_ack(
    key: &[u8; 32],
    binding: &ChannelBinding,
    role: &str,
    canonical: &[u8],
) -> Result<SourceAck, &'static str> {
    let value: serde_json::Value =
        serde_json::from_slice(canonical).map_err(|_| "evidence_invalid")?;
    let sequence = value["sequence"].as_u64().ok_or("evidence_invalid")?;
    let observation_digest = hex::encode(Sha256::digest(canonical));
    let mac = typed_mac(
        key,
        b"diffuser-authority-ack/v1\0",
        &(binding, role, sequence, &observation_digest),
    )?;
    Ok(SourceAck {
        binding: binding.clone(),
        role: role.into(),
        sequence,
        observation_digest,
        mac,
    })
}
pub(super) fn verify_source_ack(
    key: &[u8; 32],
    binding: &ChannelBinding,
    role: &str,
    canonical: &[u8],
    ack: &SourceAck,
) -> Result<(), &'static str> {
    let expected = source_ack(key, binding, role, canonical)?;
    if ack.binding != expected.binding
        || ack.role != expected.role
        || ack.sequence != expected.sequence
        || ack.observation_digest != expected.observation_digest
        || !bool::from(ack.mac.ct_eq(&expected.mac))
    {
        return Err("evidence_invalid");
    }
    Ok(())
}

impl WorkerRpc {
    pub(super) fn observe(&mut self, frame: &[u8]) -> Result<SourceAck, &'static str> {
        self.channel.check()?;
        if matches!(
            transport_epochs(&self.channel.db)?.1.last(),
            Some(TransportTransition::EnteredLoss(_))
        ) && verified_loss_source_bridge(&self.channel.db, &self.keys)?.is_none()
        {
            return Err("evidence_invalid");
        }
        let logical = logical_worker_sources(&self.channel.db, &self.keys)?;
        let (logical_last, logical_time) = logical
            .last()
            .map(|(s, t, _, _)| (*s, *t))
            .unwrap_or((0, 0));
        let canonical =
            verify_source_observation(&self.keys.authority, &self.channel.binding, frame)?;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Observation {
            schema_version: String,
            sequence: u64,
            observed_at: u64,
            revoked: Vec<String>,
        }
        let o: Observation = serde_json::from_slice(&canonical).map_err(|_| "evidence_invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis();
        if o.schema_version != "diffuser-authority-observation/v1"
            || o.sequence == 0
            || o.sequence > 128
            || o.observed_at as u128 > now
            || now >= o.observed_at as u128 + 1500
            || o.revoked.len() > 16
            || o.revoked.iter().any(|id| {
                !(16..=128).contains(&id.len())
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
        {
            return Err("evidence_invalid");
        }
        self.channel.check()?;
        let tx = self
            .channel
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let (last, time) = (logical_last, logical_time);
        if last.checked_add(1) != Some(o.sequence as i64)
            || o.observed_at > i64::MAX as u64
            || o.observed_at < time as u64
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO channel_authority VALUES (?1,?2,?3,?4)",
            rusqlite::params![o.sequence as i64, o.observed_at as i64, canonical, frame],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        if let Some(c) = self.journal.running_command() {
            if self
                .journal
                .worker_mandate(&self.session, &c)
                .and_then(|m| self.authority_permits(&m, c.permit_until))
                .is_err()
            {
                self.journal.signal_running_stop();
            }
        }
        source_ack(
            &self.keys.reply,
            &self.channel.binding,
            "worker",
            &canonical,
        )
    }
}

#[cfg(test)]
mod rpc_tests {
    use super::*;
    use std::io::Read;
    struct Fixture {
        path: std::path::PathBuf,
        root: std::fs::File,
        state: Option<WorkerRpc>,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "la-rpc-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
            std::fs::create_dir(&path).unwrap();
            let root = super::super::la_artifacts::open_owned_root(&path).unwrap();
            let binding = ChannelBinding {
                worker: "worker_cpu_000001".into(),
                worker_boot: "a".repeat(64),
                controller_boot: "b".repeat(64),
                worker_epoch: 1,
                controller_epoch: 1,
                hardware_generation: 1,
                profile_epoch: 1,
                policy_digest: "e".repeat(64),
                source_digest: "c".repeat(64),
                executable_digest: "d".repeat(64),
            };
            let mut entropy = std::fs::File::open("/dev/urandom").unwrap();
            let mut keys = ChannelKeys {
                command: [0; 32],
                reply: [0; 32],
                authority: [0; 32],
                custody: [0; 32],
            };
            entropy.read_exact(&mut keys.command).unwrap();
            entropy.read_exact(&mut keys.reply).unwrap();
            entropy.read_exact(&mut keys.authority).unwrap();
            entropy.read_exact(&mut keys.custody).unwrap();
            let journal = super::super::la_worker::OperationJournal::bootstrap(
                &path.join("worker.sqlite"),
                "rpc_custody_00001",
            )
            .unwrap();
            let channel =
                TransportJournal::create(&root, &path, "worker-channel.sqlite", binding).unwrap();
            let session = super::super::la_worker::ReservationSession {
                worker: "worker_cpu_000001".into(),
                boot: "a".repeat(64),
                key: keys.reply,
            };
            Self {
                path,
                root,
                state: Some(WorkerRpc {
                    journal,
                    session,
                    channel,
                    keys,
                    admission: WorkerAdmission::default(),
                }),
            }
        }
        fn state(&mut self) -> &mut WorkerRpc {
            self.state.as_mut().unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.state.take());
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }
    fn frame(
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        seq: u64,
        op: WorkerOperation,
        input: &[u8],
    ) -> Vec<u8> {
        let request = RpcRequest {
            version: 1,
            binding: binding.clone(),
            sequence: seq,
            input_digest: hex::encode(Sha256::digest(input)),
            input_bytes: input.len() as u64,
            operation: op,
        };
        let mac = typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &request).unwrap();
        let metadata = serde_json::to_vec(&SignedRequest { request, mac }).unwrap();
        let mut bytes = (metadata.len() as u32).to_be_bytes().to_vec();
        bytes.extend(metadata);
        bytes.extend(input);
        bytes
    }
    fn response(bytes: &[u8]) -> WorkerReply {
        serde_json::from_slice::<SignedResponse>(bytes)
            .unwrap()
            .response
            .reply
    }
    #[test]
    fn worker_epoch_history_cannot_be_ignored_by_old_controller_index() {
        let mut f = Fixture::new();
        let binding = f.state().channel.binding.clone();
        let before = transport_state_digest(&f.state().channel.db, &binding).unwrap();
        f.state().channel.db.execute_batch(
            "CREATE TABLE channel_worker_epochs(epoch INTEGER PRIMARY KEY,body BLOB NOT NULL); INSERT INTO channel_worker_epochs VALUES(2,x'7b7d');"
        ).unwrap();
        assert!(transport_state_digest(&f.state().channel.db, &binding).is_err(),
            "an unverified independent W transition must refuse, never disappear behind the C epoch index; old digest was {before}");
    }

    fn inspect_command() -> InspectCommand {
        InspectCommand {
            backend: None,
            worker: "worker_cpu_000001".into(),
            boot: "a".repeat(64),
            assignment: "assignment_00001".into(),
            fence: 1,
            operation: "operation_000001".into(),
            job: "job_number_00001".into(),
            input_digest: hex::encode(Sha256::digest(b"input")),
            accepted_at: 1,
            mandate_until: 1000,
            permit_until: 100,
        }
    }

    fn test_mandate() -> super::super::la_auth::StoredMandate {
        let c = inspect_command();
        super::super::la_auth::StoredMandate {
            draft: super::super::la_auth::MandateDraft {
                tenant: "tenant_123456789".into(),
                project: "project_12345678".into(),
                actor: "person_123456789".into(),
                initiator: "person_123456789".into(),
                lineage: "grant_root123456".into(),
                assignment: c.assignment,
                job: c.job,
                operation: c.operation,
                input_digest: c.input_digest,
                profile: "cpu-artifact-inspect".into(),
                worker: c.worker,
                cpu_millicores: 1000,
                memory_bytes: 16777216,
                storage_bytes: 2097152,
                policy: "runtime-short-v1".into(),
                accepted_at: 1,
                runtime_ms: 999,
                assignment_hard: 2000,
                project_ceiling: 2000,
                chain: vec![super::super::la_auth::MandateGrant {
                    id: "grant_root123456".into(),
                    parent: None,
                    run_until: 2000,
                    execution_ceiling: 2000,
                }],
            },
            max_until: 1000,
        }
    }
    #[test]
    fn rpc_retained_worker_assignments_allow_eight_closed_records_then_refuse_ninth() {
        let mut f = Fixture::new();
        let s = f.state();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        for index in 0..9 {
            let c = ReserveCommand {
                worker: s.session.worker.clone(),
                boot: s.session.boot.clone(),
                assignment: format!("assignment_{index:05}"),
                operation: format!("reservation_{index:05}"),
                fence: index + 1,
                lease_until: now + 4000,
                hard_until: now + 12000,
            };
            let mac = sign_reserve_command(&s.session.key, &c).unwrap();
            let r = s.journal.reserve_authenticated(&s.session, &c, &mac);
            if index == 8 {
                assert_eq!(r.err(), Some("capacity_unavailable"));
            } else {
                assert!(r.is_ok(), "retained assignment {index}: {:?}", r.err());
                let close = CloseCommand {
                    worker: c.worker,
                    boot: c.boot,
                    assignment: c.assignment,
                    fence: c.fence,
                    operation: format!("close_record_{index:05}"),
                };
                let mac = sign_close_command(&s.session.key, &close).unwrap();
                s.journal
                    .close_authenticated(&s.session, &close, &mac)
                    .unwrap();
            }
        }
    }

    #[test]
    fn rpc_route_binding_and_independent_custody_detect_tampering_and_replacement() {
        let mut f = Fixture::new();
        let s = f.state();
        let binding = s.channel.binding.clone();
        let keys = s.keys.clone();
        let request = frame(&binding, &keys, 1, WorkerOperation::Probe, &[]);
        assert!(s
            .handle_at(&request, "POST", "/v1/worker/reservations")
            .is_err());
        let reply = s.handle(&request).unwrap();
        observe_channel_custody(&f.root, "worker-channel.sqlite", &binding, &keys.reply, 1)
            .unwrap();
        assert!(observe_channel_custody(
            &f.root,
            "worker-channel.sqlite",
            &binding,
            &keys.reply,
            0
        )
        .is_err());
        let mut bad: SignedResponse = serde_json::from_slice(&reply).unwrap();
        bad.mac[0] ^= 1;
        let bad = serde_json::to_vec(&bad).unwrap();
        f.state()
            .channel
            .db
            .execute("UPDATE channel_log SET response=?1", [bad])
            .unwrap();
        assert!(observe_channel_custody(
            &f.root,
            "worker-channel.sqlite",
            &binding,
            &keys.reply,
            1
        )
        .is_err());
        f.state()
            .channel
            .db
            .execute("UPDATE channel_log SET response=?1", [reply])
            .unwrap();
        std::fs::rename(
            f.path.join("worker-channel.sqlite"),
            f.path.join("retained-channel.sqlite"),
        )
        .unwrap();
        std::fs::copy(
            f.path.join("retained-channel.sqlite"),
            f.path.join("worker-channel.sqlite"),
        )
        .unwrap();
        assert!(f.state().channel.check().is_err());
    }
    #[test]
    fn rpc_source_revocations_stay_sticky_across_later_fresh_observations() {
        let mut f = Fixture::new();
        let s = f.state();
        let binding = s.channel.binding.clone();
        let keys = s.keys.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let m = test_mandate();
        assert!(s.authority_permits(&m, now + 100).is_err());
        for sequence in 1..=3 {
            let revoked = if sequence == 2 {
                vec!["grant_root123456"]
            } else {
                vec![]
            };
            let body=serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":sequence,"observed_at":now,"revoked":revoked})).unwrap();
            let frame = sign_source_observation(&keys.authority, &binding, &body).unwrap();
            s.observe(&frame).unwrap();
            assert_eq!(s.authority_permits(&m, now + 100).is_ok(), sequence == 1);
        }
    }

    #[test]
    fn rpc_authenticates_both_boots_epochs_sequence_and_exact_retry() {
        let mut f = Fixture::new();
        let s = f.state();
        let b = s.channel.binding.clone();
        let keys = s.keys.clone();
        for index in 0..3 {
            let mut wrong = b.clone();
            match index {
                0 => wrong.controller_epoch += 1,
                1 => wrong.worker_epoch += 1,
                _ => wrong.worker = "worker_cpu_000002".into(),
            }
            let bytes = frame(&wrong, &keys, 1, WorkerOperation::Probe, &[]);
            assert_eq!(s.handle(&bytes).err(), Some("evidence_invalid"));
        }
        for field in [
            "worker_boot",
            "controller_boot",
            "source_digest",
            "executable_digest",
        ] {
            let mut value = serde_json::to_value(&b).unwrap();
            value[field] = serde_json::Value::String("e".repeat(64));
            let wrong = serde_json::from_value(value).unwrap();
            assert!(s
                .handle(&frame(&wrong, &keys, 1, WorkerOperation::Probe, &[]))
                .is_err());
        }
        let mut bad_keys = keys.clone();
        bad_keys.command[0] ^= 1;
        assert!(s
            .handle(&frame(&b, &bad_keys, 1, WorkerOperation::Probe, &[]))
            .is_err());
        assert!(s
            .handle(&frame(&b, &keys, 2, WorkerOperation::Probe, &[]))
            .is_err());
        let bytes = frame(&b, &keys, 1, WorkerOperation::Probe, &[]);
        let first = s.handle(&bytes).unwrap();
        assert_eq!(s.handle(&bytes).unwrap(), first);
        assert!(
            matches!(response(&first),WorkerReply::Probe{admission,..} if admission=="resource_unqualified")
        );
        assert!(s
            .handle(&frame(
                &b,
                &keys,
                1,
                WorkerOperation::Status(inspect_command()),
                &[]
            ))
            .is_err());
        assert_eq!(
            s.channel
                .db
                .query_row("SELECT COUNT(*) FROM channel_log", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn rpc_stage_bounds_hash_and_qualification_are_checked_before_work() {
        let mut f = Fixture::new();
        let s = f.state();
        let b = s.channel.binding.clone();
        let keys = s.keys.clone();
        let mut bytes = frame(
            &b,
            &keys,
            1,
            WorkerOperation::Stage(inspect_command()),
            b"input",
        );
        *bytes.last_mut().unwrap() ^= 1;
        assert!(s.handle(&bytes).is_err());
        assert!(s.handle(&[0, 1, 0, 1]).is_err());
        assert!(s
            .handle(&vec![0; RPC_INPUT_MAX + RPC_JSON_MAX + 5])
            .is_err());
        for (index, op) in [
            WorkerOperation::Reserve(
                ReserveCommand {
                    worker: b.worker.clone(),
                    boot: b.worker_boot.clone(),
                    assignment: "assignment_00001".into(),
                    operation: "reservation_0001".into(),
                    fence: 1,
                    lease_until: 1000,
                    hard_until: 2000,
                },
                super::super::la_store::AssignmentTerms {
                    cpu_millicores: 1000,
                    memory_bytes: 16777216,
                    storage_bytes: 2097152,
                    accepted_at: 1,
                    lease_until: 1000,
                    hard_until: 2000,
                },
            ),
            WorkerOperation::Permit(inspect_command(), Box::new(test_mandate())),
            WorkerOperation::Stage(inspect_command()),
            WorkerOperation::Start(inspect_command()),
        ]
        .into_iter()
        .enumerate()
        {
            let input = if matches!(op, WorkerOperation::Stage(_)) {
                &b"input"[..]
            } else {
                &[]
            };
            let reply = s
                .handle(&frame(&b, &keys, index as u64 + 1, op, input))
                .unwrap();
            assert!(
                matches!(response(&reply),WorkerReply::Refused{code} if code=="evidence_invalid")
            );
        }
        assert_eq!(s.journal.start_count("operation_000001").unwrap(), 0);
    }

    #[test]
    fn rebound_admission_permits_only_the_original_command_and_deadline() {
        let c = inspect_command();
        let admission = WorkerAdmission::default();
        let now = wall_now().unwrap();
        *admission.0.lock().unwrap() = Some(AdmissionLease {
            issued_at: now,
            expires_at: now + 1000,
            job_scope: Some(command_digest(&c).unwrap()),
        });
        assert!(admission
            .check_operation(&WorkerOperation::Start(c.clone()))
            .is_ok());
        assert!(admission
            .check_operation(&WorkerOperation::Stage(c.clone()))
            .is_ok());
        let mut changed = c.clone();
        changed.job = "job_foreign_00001".into();
        assert!(admission
            .check_operation(&WorkerOperation::Start(changed))
            .is_err());
        let mut changed = c.clone();
        changed.permit_until += 1;
        assert!(admission
            .check_operation(&WorkerOperation::Start(changed))
            .is_err());
        assert!(admission
            .check_operation(&WorkerOperation::Permit(c, Box::new(test_mandate())))
            .is_err());
        admission.0.lock().unwrap().as_mut().unwrap().expires_at = now;
        assert!(admission.check().is_err());
    }

    #[test]
    fn rpc_close_without_service_midpoint_never_sends() {
        let mut f = Fixture::new();
        let binding = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let channel = TransportJournal::create(
            &f.root,
            &f.path,
            "controller-channel.sqlite",
            binding.clone(),
        )
        .unwrap();
        let mut client = WorkerClient::new(listener.local_addr().unwrap(), channel, keys).unwrap();
        let command = CloseCommand {
            worker: binding.worker,
            boot: binding.worker_boot,
            assignment: "assignment_000001".into(),
            fence: 1,
            operation: "release_assignment_000001".into(),
        };
        assert!(client.call(WorkerOperation::Close(command), &[]).is_err());
        assert!(
            listener.accept().is_err(),
            "close reached outbound I/O without P's service midpoint"
        );
        assert!(client.channel.pending(1).unwrap());
    }

    #[test]
    fn rpc_stop_without_service_midpoint_never_sends() {
        let mut f = Fixture::new();
        let binding = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let channel = TransportJournal::create(
            &f.root,
            &f.path,
            "controller-channel.sqlite",
            binding.clone(),
        )
        .unwrap();
        let mut client = WorkerClient::new(listener.local_addr().unwrap(), channel, keys).unwrap();
        let mut command = inspect_command();
        command.worker = binding.worker;
        command.boot = binding.worker_boot;
        assert!(client.call(WorkerOperation::Stop(command), &[]).is_err());
        assert!(
            listener.accept().is_err(),
            "Stop reached outbound I/O without P's exact service midpoint"
        );
        assert!(client.channel.pending(1).unwrap());
    }

    #[test]
    fn rpc_controller_persists_exact_intent_before_failed_send_and_blocks_other_work() {
        let mut f = Fixture::new();
        let binding = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let channel = TransportJournal::create(
            &f.root,
            &f.path,
            "controller-channel.sqlite",
            binding.clone(),
        )
        .unwrap();
        let mut client = WorkerClient::new(address, channel, keys.clone()).unwrap();
        assert!(client.call(WorkerOperation::Probe, &[]).is_err());
        let (saved, absent): (Vec<u8>, bool) = client
            .channel
            .db
            .query_row(
                "SELECT request,response IS NULL FROM channel_log WHERE sequence=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(absent, "lost response remains uncertain");
        assert_eq!(
            saved,
            frame(&binding, &keys, 1, WorkerOperation::Probe, &[])[4..]
        );
        assert_eq!(
            client
                .call(WorkerOperation::Status(inspect_command()), &[])
                .err(),
            Some("transport_uncertain")
        );
        let count: i64 = client
            .channel
            .db
            .query_row("SELECT COUNT(*) FROM channel_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "uncertainty cannot allocate a new sequence");
        let mut changed: SignedRequest = serde_json::from_slice(&saved).unwrap();
        changed.request.sequence = 2;
        let envelope = serde_json::to_vec(&changed).unwrap();
        assert_eq!(
            client
                .channel
                .begin(1, &rpc_content_digest(&changed.request).unwrap(), &envelope)
                .err(),
            Some("evidence_invalid")
        );
        assert_eq!(
            client
                .channel
                .db
                .query_row("SELECT request FROM channel_log", [], |r| r
                    .get::<_, Vec<u8>>(0))
                .unwrap(),
            saved
        );
        drop(client);
        let recovered =
            TransportJournal::reopen(&f.root, &f.path, "controller-channel.sqlite", binding, 1)
                .unwrap();
        assert_eq!(recovered.pending(1), Ok(true));
        assert_eq!(
            recovered
                .db
                .query_row("SELECT request FROM channel_log", [], |r| r
                    .get::<_, Vec<u8>>(0))
                .unwrap(),
            saved
        );
    }

    #[test]
    fn rpc_typed_envelope_is_retained_without_input_and_binds_witnessed_state() {
        let mut f = Fixture::new();
        let b = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let input = b"unique-raw-input-must-not-be-copied-into-transport-history";
        let bytes = frame(
            &b,
            &keys,
            1,
            WorkerOperation::Stage(inspect_command()),
            input,
        );
        let size = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        f.state().handle(&bytes).unwrap();
        let saved: Vec<u8> = f
            .state()
            .channel
            .db
            .query_row(
                "SELECT request FROM channel_log WHERE sequence=1",
                [],
                |r| r.get(0),
            )
            .expect("typed request custody must survive the operation");
        assert_eq!(saved, bytes[4..4 + size]);
        let retained: SignedRequest = serde_json::from_slice(&saved).unwrap();
        assert_eq!(retained.request.input_bytes, input.len() as u64);
        assert_eq!(
            retained.request.input_digest,
            hex::encode(Sha256::digest(input))
        );
        assert!(!saved.windows(input.len()).any(|w| w == input));
        let before = transport_state_digest(&f.state().channel.db, &b).unwrap();
        let changed = frame(&b, &keys, 1, WorkerOperation::Probe, &[]);
        f.state()
            .channel
            .db
            .execute("UPDATE channel_log SET request=?1", [&changed[4..]])
            .unwrap();
        assert!(transport_state_digest(&f.state().channel.db, &b) != Ok(before));
        assert!(
            f.state().handle(&bytes).is_err(),
            "altered envelope cannot replay a cached reply"
        );
    }

    #[test]
    fn rpc_pending_intent_and_protected_high_water_never_infer_safe_replay() {
        let mut f = Fixture::new();
        let s = f.state();
        let b = s.channel.binding.clone();
        let keys = s.keys.clone();
        let bytes = frame(&b, &keys, 1, WorkerOperation::Probe, &[]);
        let req: SignedRequest = serde_json::from_slice(&bytes[4..]).unwrap();
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&req.request).unwrap()));
        assert!(s.channel.begin(1, &digest, &bytes[4..]).unwrap().is_none());
        assert!(
            matches!(response(&s.handle(&bytes).unwrap()),WorkerReply::Refused{code} if code=="transport_uncertain")
        );
        assert!(
            TransportJournal::reopen(&f.root, &f.path, "worker-channel.sqlite", b.clone(), 0)
                .is_err()
        );
        assert!(
            TransportJournal::reopen(&f.root, &f.path, "worker-channel.sqlite", b.clone(), 2)
                .is_err()
        );
        assert!(
            TransportJournal::reopen(&f.root, &f.path, "worker-channel.sqlite", b.clone(), 1)
                .is_err()
        );
        drop(f.state.take());
        assert!(
            TransportJournal::reopen(&f.root, &f.path, "worker-channel.sqlite", b.clone(), 0)
                .is_err()
        );
        assert!(
            TransportJournal::reopen(&f.root, &f.path, "worker-channel.sqlite", b.clone(), 2)
                .is_err()
        );
        assert!(TransportJournal::reopen(&f.root, &f.path, "worker-channel.sqlite", b, 1).is_ok());
    }

    #[test]
    fn custody_observation_binds_complete_transport_content() {
        let mut f = Fixture::new();
        let b = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        f.state()
            .handle(&frame(&b, &keys, 1, WorkerOperation::Probe, &[]))
            .unwrap();
        let before =
            observe_channel_custody(&f.root, "worker-channel.sqlite", &b, &keys.reply, 1).unwrap();
        assert!(
            before["state_digest"]
                .as_str()
                .is_some_and(|s| s.len() == 64),
            "custody must bind content, not only a row count"
        );
        f.state()
            .handle(&frame(&b, &keys, 2, WorkerOperation::Probe, &[]))
            .unwrap();
        let after =
            observe_channel_custody(&f.root, "worker-channel.sqlite", &b, &keys.reply, 2).unwrap();
        assert_ne!(before["state_digest"], after["state_digest"]);
        assert_eq!(
            after,
            observe_channel_custody(&f.root, "worker-channel.sqlite", &b, &keys.reply, 2).unwrap()
        );
    }

    #[test]
    fn live_custody_persists_independent_intent_and_complete_before_reply() {
        let mut f = Fixture::new();
        let binding = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let custody_path = f.path.join("parent");
        std::fs::create_dir(&custody_path).unwrap();
        let custody_root = super::super::la_artifacts::open_owned_root(&custody_path).unwrap();
        let mut ledger = CustodyLedger::bootstrap(
            &custody_root,
            &custody_path,
            binding.clone(),
            "worker",
            keys.reply,
            keys.custody,
        )
        .unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(4);
        let link = CustodyLink::new(
            binding.clone(),
            "worker",
            keys.reply,
            keys.custody,
            Box::new(move |b| send.send(b.to_vec()).map_err(|_| "evidence_invalid")),
        )
        .unwrap();
        f.state().channel.enable_custody(link.clone()).unwrap();
        let root = f.root.try_clone().unwrap();
        let acknowledger = std::thread::spawn(move || {
            let mut saved = Vec::new();
            for revision in 1..=2 {
                let bytes = receive
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .unwrap();
                let checkpoint: SignedCheckpoint = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(checkpoint.body.revision, revision);
                let ack = ledger.observe(&root, &checkpoint).unwrap();
                assert!(
                    ledger.observe(&root, &checkpoint).is_err(),
                    "duplicate checkpoint never appends twice"
                );
                let mut bad = ack.clone();
                bad.revision += 1;
                assert!(link.accept(&serde_json::to_vec(&bad).unwrap()).is_err());
                link.accept(&serde_json::to_vec(&ack).unwrap()).unwrap();
                saved.push(checkpoint);
            }
            saved
        });
        let result = f
            .state()
            .handle(&frame(&binding, &keys, 1, WorkerOperation::Probe, &[]))
            .unwrap();
        assert!(matches!(response(&result), WorkerReply::Probe { .. }));
        let checkpoints = acknowledger.join().unwrap();
        assert_eq!(checkpoints[0].body.phase, "intent");
        assert_eq!(checkpoints[1].body.phase, "complete");
        assert_ne!(
            checkpoints[0].body.state_digest,
            checkpoints[1].body.state_digest
        );
        assert_eq!(
            checkpoints[1].body.previous,
            checkpoints[0].digest().unwrap()
        );
        for c in &checkpoints {
            assert_eq!(
                std::fs::read(
                    custody_path.join(format!("worker-witness-{:04}.json", c.body.revision))
                )
                .unwrap(),
                serde_json::to_vec(c).unwrap()
            );
        }
        f.state()
            .channel
            .db
            .execute("UPDATE channel_log SET digest=?1", ["9".repeat(64)])
            .unwrap();
        assert!(
            f.state().channel.check().is_err(),
            "same-count live history substitution refuses"
        );
        drop(f.state.take());
        assert!(
            TransportJournal::reopen(&f.root, &f.path, "worker-channel.sqlite", binding, 1)
                .is_err(),
            "numeric high-water cannot reopen witnessed history"
        );
    }

    #[test]
    fn live_custody_missing_intent_ack_blocks_execution_and_poisoned_retry() {
        let mut f = Fixture::new();
        let b = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        let link = CustodyLink::new(
            b.clone(),
            "worker",
            keys.reply,
            keys.custody,
            Box::new(move |bytes| send.send(bytes.to_vec()).map_err(|_| "evidence_invalid")),
        )
        .unwrap();
        f.state().channel.enable_custody(link.clone()).unwrap();
        let request = frame(&b, &keys, 1, WorkerOperation::Probe, &[]);
        assert!(f.state().handle(&request).is_err());
        assert!(f.state().handle(&request).is_err());
        let (rows, pending): (i64, i64) = f
            .state()
            .channel
            .db
            .query_row(
                "SELECT COUNT(*),SUM(response IS NULL) FROM channel_log",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((rows, pending), (1, 1));
        let checkpoint: SignedCheckpoint =
            serde_json::from_slice(&receive.recv().unwrap()).unwrap();
        let late = CheckpointAck::new(&keys.custody, &checkpoint).unwrap();
        assert!(link.accept(&serde_json::to_vec(&late).unwrap()).is_err());
        assert!(f.state().handle(&request).is_err());
        assert_eq!(
            f.state().journal.start_count("operation_000001").unwrap(),
            0
        );
    }

    #[test]
    fn live_custody_lost_complete_ack_never_exposes_cached_reply() {
        let mut f = Fixture::new();
        let binding = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let custody_path = f.path.join("parent");
        std::fs::create_dir(&custody_path).unwrap();
        let custody_root = super::super::la_artifacts::open_owned_root(&custody_path).unwrap();
        let mut ledger = CustodyLedger::bootstrap(
            &custody_root,
            &custody_path,
            binding.clone(),
            "worker",
            keys.reply,
            keys.custody,
        )
        .unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(4);
        let link = CustodyLink::new(
            binding.clone(),
            "worker",
            keys.reply,
            keys.custody,
            Box::new(move |b| send.send(b.to_vec()).map_err(|_| "evidence_invalid")),
        )
        .unwrap();
        f.state().channel.enable_custody(link.clone()).unwrap();
        let root = f.root.try_clone().unwrap();
        let acknowledger = std::thread::spawn(move || {
            let checkpoint: SignedCheckpoint =
                serde_json::from_slice(&receive.recv().unwrap()).unwrap();
            let ack = ledger.observe(&root, &checkpoint).unwrap();
            link.accept(&serde_json::to_vec(&ack).unwrap()).unwrap();
            let _lost = receive
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
        });
        let request = frame(&binding, &keys, 1, WorkerOperation::Probe, &[]);
        assert!(f.state().handle(&request).is_err());
        acknowledger.join().unwrap();
        assert!(
            f.state().handle(&request).is_err(),
            "no cached response without independent complete ACK"
        );
        assert_eq!(
            f.state()
                .channel
                .db
                .query_row(
                    "SELECT COUNT(*) FROM channel_log WHERE response IS NOT NULL",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(std::fs::read_dir(custody_path).unwrap().count(), 1);
    }

    #[test]
    fn witnessed_recovery_requires_exact_external_head_and_intact_both_histories() {
        let mut f = Fixture::new();
        let binding = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let custody_path = f.path.join("parent");
        std::fs::create_dir(&custody_path).unwrap();
        let custody_root = super::super::la_artifacts::open_owned_root(&custody_path).unwrap();
        let mut ledger = CustodyLedger::bootstrap(
            &custody_root,
            &custody_path,
            binding.clone(),
            "worker",
            keys.reply,
            keys.custody,
        )
        .unwrap();
        let (send, receive) = std::sync::mpsc::sync_channel(4);
        let link = CustodyLink::new(
            binding.clone(),
            "worker",
            keys.reply,
            keys.custody,
            Box::new(move |b| send.send(b.to_vec()).map_err(|_| "evidence_invalid")),
        )
        .unwrap();
        f.state().channel.enable_custody(link.clone()).unwrap();
        let root = f.root.try_clone().unwrap();
        let witness = std::thread::spawn(move || {
            let mut history = Vec::new();
            for _ in 0..2 {
                let checkpoint: SignedCheckpoint = serde_json::from_slice(
                    &receive
                        .recv_timeout(std::time::Duration::from_secs(1))
                        .unwrap(),
                )
                .unwrap();
                let ack = ledger.observe(&root, &checkpoint).unwrap();
                link.accept(&serde_json::to_vec(&ack).unwrap()).unwrap();
                history.push((checkpoint, ack));
            }
            history
        });
        let request = frame(&binding, &keys, 1, WorkerOperation::Probe, &[]);
        let response = f.state().handle(&request).unwrap();
        let history = witness.join().unwrap();
        let (head, ack) = &history[1];
        let wire: SignedRequest = serde_json::from_slice(&request[4..]).unwrap();
        let request_digest =
            hex::encode(Sha256::digest(serde_json::to_vec(&wire.request).unwrap()));
        drop(f.state.take());
        let fresh_link = || {
            CustodyLink::new(
                binding.clone(),
                "worker",
                keys.reply,
                keys.custody,
                Box::new(|_| Err("evidence_invalid")),
            )
            .unwrap()
        };
        assert!(TransportJournal::reopen(
            &f.root,
            &f.path,
            "worker-channel.sqlite",
            binding.clone(),
            1
        )
        .is_err());
        assert!(
            TransportJournal::reopen_witnessed(
                &f.root,
                &f.path,
                "worker-channel.sqlite",
                &history[0].0,
                &history[0].1,
                fresh_link()
            )
            .is_err(),
            "stale but signed external head refuses a newer channel"
        );
        let mut wrong = ack.clone();
        wrong.role = "controller".into();
        assert!(TransportJournal::reopen_witnessed(
            &f.root,
            &f.path,
            "worker-channel.sqlite",
            head,
            &wrong,
            fresh_link()
        )
        .is_err());
        let mut journal = TransportJournal::reopen_witnessed(
            &f.root,
            &f.path,
            "worker-channel.sqlite",
            head,
            ack,
            fresh_link(),
        )
        .unwrap();
        assert_eq!(
            journal
                .begin(1, &request_digest, &serde_json::to_vec(&wire).unwrap())
                .unwrap(),
            Some(response)
        );
        drop(journal);
        assert!(
            CustodyLedger::reopen(
                &custody_root,
                &custody_path,
                &history[0].0,
                &history[0].1,
                keys.reply,
                keys.custody
            )
            .is_err(),
            "P never infers away extra retained history"
        );
        let mut ledger = CustodyLedger::reopen(
            &custody_root,
            &custody_path,
            head,
            ack,
            keys.reply,
            keys.custody,
        )
        .unwrap();
        assert!(
            ledger.observe(&f.root, head).is_err(),
            "reopened P rejects an old checkpoint"
        );
        let last = custody_path.join("worker-witness-0002.json");
        let saved = std::fs::read(&last).unwrap();
        std::fs::remove_file(&last).unwrap();
        assert!(CustodyLedger::reopen(
            &custody_root,
            &custody_path,
            head,
            ack,
            keys.reply,
            keys.custody
        )
        .is_err());
        std::fs::write(&last, &saved).unwrap();
        assert!(CustodyLedger::reopen(
            &custody_root,
            &custody_path,
            head,
            ack,
            keys.reply,
            keys.custody
        )
        .is_ok());
        let db =
            super::super::la_store::open_pinned_database(&f.root, "worker-channel.sqlite", false)
                .unwrap();
        let original: Vec<u8> = db
            .query_row("SELECT request FROM channel_log", [], |r| r.get(0))
            .unwrap();
        let mut altered: SignedRequest = serde_json::from_slice(&original).unwrap();
        altered.mac[0] ^= 1;
        let altered = serde_json::to_vec(&altered).unwrap();
        db.execute("UPDATE channel_log SET request=?1", [&altered])
            .unwrap();
        assert!(
            TransportJournal::reopen_witnessed(
                &f.root,
                &f.path,
                "worker-channel.sqlite",
                head,
                ack,
                fresh_link()
            )
            .is_err(),
            "signed external head binds exact request signature bytes"
        );
        db.execute("UPDATE channel_log SET request=?1", [&original])
            .unwrap();
        db.execute("UPDATE channel_log SET digest=?1", ["9".repeat(64)])
            .unwrap();
        drop(db);
        assert!(
            TransportJournal::reopen_witnessed(
                &f.root,
                &f.path,
                "worker-channel.sqlite",
                head,
                ack,
                fresh_link()
            )
            .is_err(),
            "same-count substituted content never recovers"
        );
    }

    #[test]
    fn epoch_handoff_preserves_genesis_sequences_and_refuses_replay_and_old_commands() {
        exercise_epoch_handoff(true, false);
    }
    #[test]
    fn epoch_handoff_missing_parent_prepare_poisons_transition() {
        exercise_epoch_handoff(false, false);
    }
    #[test]
    fn combined_controller_worker_epoch_budget_refuses_before_append() {
        exercise_epoch_handoff(true, true);
    }
    fn exercise_epoch_handoff(prepared: bool, budget: bool) {
        use std::sync::{Arc, Mutex};
        let mut f = Fixture::new();
        let old = f.state().channel.binding.clone();
        let keys = f.state().keys.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let canonical=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":1,"observed_at":now,"revoked":[]})).unwrap()).unwrap();
        f.state()
            .observe(&sign_source_observation(&keys.authority, &old, &canonical).unwrap())
            .unwrap();
        let path = f.path.with_extension("epoch-custody");
        std::fs::create_dir(&path).unwrap();
        let root = super::super::la_artifacts::open_owned_root(&path).unwrap();
        let ledger = Arc::new(Mutex::new(
            CustodyLedger::bootstrap(
                &root,
                &path,
                old.clone(),
                "worker",
                keys.reply,
                keys.custody,
            )
            .unwrap(),
        ));
        let callback: Arc<Mutex<Option<std::sync::Weak<CustodyLink>>>> = Arc::new(Mutex::new(None));
        let holder = callback.clone();
        let observed = f.root.try_clone().unwrap();
        let witness = ledger.clone();
        let link = CustodyLink::new(
            old.clone(),
            "worker",
            keys.reply,
            keys.custody,
            Box::new(move |bytes| {
                let frame: SignedCheckpoint = serde_json::from_slice(bytes).unwrap();
                let ack = witness.lock().unwrap().observe(&observed, &frame)?;
                holder
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .upgrade()
                    .unwrap()
                    .accept(&serde_json::to_vec(&ack).unwrap())
            }),
        )
        .unwrap();
        *callback.lock().unwrap() = Some(Arc::downgrade(&link));
        f.state().channel.enable_custody(link).unwrap();
        std::fs::write(f.path.join("checkpoint-state.txt"), b"before").unwrap();
        f.state().channel.owned_state = true;
        let old_frame = frame(&old, &keys, 1, WorkerOperation::Probe, &[]);
        f.state().handle(&old_frame).unwrap();
        let (worker, worker_ack, worker_history) =
            ledger.lock().unwrap().completed_anchor(&f.root).unwrap();
        std::fs::write(f.path.join("checkpoint-state.txt"), b"after!").unwrap();
        assert!(
            ledger.lock().unwrap().completed_anchor(&f.root).is_err(),
            "same-length changed worker state cannot be adopted as a new trusted head"
        );
        std::fs::write(f.path.join("checkpoint-state.txt"), b"before").unwrap();
        let mut controller = worker.clone();
        controller.body.role = "controller".into();
        controller.mac = typed_mac(
            &keys.reply,
            b"diffuser-custody-checkpoint/v1\0",
            &controller.body,
        )
        .unwrap();
        let controller_ack = CheckpointAck::new(&keys.custody, &controller).unwrap();
        let mut next = old.clone();
        next.controller_epoch = 2;
        next.controller_boot = "f".repeat(64);
        let mut capsule = TransportEpochHandoff {
            previous: old.clone(),
            binding: next.clone(),
            controller,
            controller_ack,
            controller_history: "a".repeat(64),
            worker,
            worker_ack,
            worker_history,
            controller_state: "b".repeat(64),
            worker_state: state_custody::state_digest(&f.root).unwrap(),
            recovery_digest: "c".repeat(64),
            service_recovery: None,
            worker_authority: transport_authority_digest(&f.state().channel.db, 1).unwrap(),
            settlement: None,
            never_started: None,
            authority_sequence: 1,
            issued_at: now,
            expires_at: now + 1500,
            mac: [0; 32],
        };
        capsule.mac = capsule.signature(&keys.custody).unwrap();
        let mut wrong = capsule.clone();
        wrong.binding.worker_epoch = 2;
        wrong.mac = wrong.signature(&keys.custody).unwrap();
        assert!(wrong.verify(&keys.custody, now).is_err());
        let mut wrong = capsule.clone();
        wrong.binding.controller_epoch = 3;
        wrong.mac = wrong.signature(&keys.custody).unwrap();
        assert!(wrong.verify(&keys.custody, now).is_err());
        let mut wrong = capsule.clone();
        wrong.authority_sequence = 2;
        assert!(wrong.verify(&keys.custody, now).is_err());
        assert!(capsule.verify(&keys.custody, now + 1500).is_err());
        let mut wrong = capsule.clone();
        wrong.worker_history = "d".repeat(64);
        wrong.mac = wrong.signature(&keys.custody).unwrap();
        assert!(f
            .state()
            .channel
            .install_controller_epoch(&wrong, None, now)
            .is_err());
        if prepared {
            ledger.lock().unwrap().prepare_epoch(&capsule).unwrap();
            f.state()
                .channel
                .install_controller_epoch(&capsule, None, now)
                .unwrap();
            let genesis: Vec<u8> = f
                .state()
                .channel
                .db
                .query_row("SELECT binding FROM channel_identity", [], |r| r.get(0))
                .unwrap();
            assert_eq!(genesis, serde_json::to_vec(&old).unwrap());
            assert!(f.state().handle(&old_frame).is_err());
            assert!(f
                .state()
                .channel
                .install_controller_epoch(&capsule, None, now)
                .is_err());
            let bytes = frame(&next, &keys, 2, WorkerOperation::Probe, &[]);
            f.state().handle(&bytes).unwrap();
            assert_eq!(
                f.state()
                    .channel
                    .db
                    .query_row("SELECT COUNT(*) FROM channel_log", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                2
            );
            f.state().channel.validate_custody_chain().unwrap();
            let (head, ack, _) = ledger.lock().unwrap().completed_anchor(&f.root).unwrap();
            let restored =
                CustodyLedger::reopen(&root, &path, &head, &ack, keys.reply, keys.custody)
                    .expect("restore independently retained epoch transition, not a new genesis");
            assert!(restored.binding == next);
            assert_eq!(restored.head, ledger.lock().unwrap().head);
            if budget {
                // Transport-only component proof: each retained C transition
                // uses the ordinary authenticated append and independent P ACK.
                for epoch in 3..=9 {
                    let previous = f.state().channel.binding.clone();
                    let (worker, worker_ack, worker_history) =
                        ledger.lock().unwrap().completed_anchor(&f.root).unwrap();
                    let mut controller = worker.clone();
                    controller.body.role = "controller".into();
                    controller.mac = typed_mac(
                        &keys.reply,
                        b"diffuser-custody-checkpoint/v1\0",
                        &controller.body,
                    )
                    .unwrap();
                    let controller_ack = CheckpointAck::new(&keys.custody, &controller).unwrap();
                    let mut binding = previous.clone();
                    binding.controller_epoch = epoch;
                    binding.controller_boot = format!("{epoch:x}").repeat(64);
                    let mut c = TransportEpochHandoff {
                        previous,
                        binding,
                        controller,
                        controller_ack,
                        controller_history: "a".repeat(64),
                        worker,
                        worker_ack,
                        worker_history,
                        controller_state: "b".repeat(64),
                        worker_state: state_custody::state_digest(&f.root).unwrap(),
                        recovery_digest: "c".repeat(64),
                        service_recovery: None,
                        worker_authority: transport_authority_digest(&f.state().channel.db, 1)
                            .unwrap(),
                        settlement: None,
                        never_started: None,
                        authority_sequence: 1,
                        issued_at: now,
                        expires_at: now + 1500,
                        mac: [0; 32],
                    };
                    c.mac = c.signature(&keys.custody).unwrap();
                    ledger.lock().unwrap().prepare_epoch(&c).unwrap();
                    f.state()
                        .channel
                        .install_controller_epoch(&c, None, now)
                        .unwrap();
                    f.state()
                        .handle(&frame(
                            &c.binding,
                            &keys,
                            epoch,
                            WorkerOperation::Probe,
                            &[],
                        ))
                        .unwrap();
                }
                let previous = f.state().channel.binding.clone();
                let (worker, worker_ack, worker_history) =
                    ledger.lock().unwrap().completed_anchor(&f.root).unwrap();
                let mut controller = worker.clone();
                controller.body.role = "controller".into();
                controller.body.phase = "intent".into();
                controller.mac = typed_mac(
                    &keys.reply,
                    b"diffuser-custody-checkpoint/v1\0",
                    &controller.body,
                )
                .unwrap();
                let controller_ack = CheckpointAck::new(&keys.custody, &controller).unwrap();
                let mut binding = previous.clone();
                binding.worker_epoch = 2;
                binding.worker_boot = "e".repeat(64);
                let identity = |pid, cg| serde_json::json!({"pid":pid,"starttime":"1","sha256":previous.executable_digest,"exe":"/worker-test","cgroup":format!("0::/user.slice/user-1000.slice/user@1000.service/app.slice/test-{cg}.scope\n")});
                let returning = WorkerReturnWitness {
                    old_identity: identity(100, "old"),
                    new_identity: identity(101, "new"),
                    death_digest: "a".repeat(64),
                    initial_occupancy: "b".repeat(64),
                    namespace_pid: 2,
                };
                let service=serde_json::from_value(serde_json::json!({"revision":1,"head":"a".repeat(64),"history":"b".repeat(64),"state":"c".repeat(64),"operation":1,"request_digest":"d".repeat(64),"close_digest":"e".repeat(64)})).unwrap();
                // Signed synthetic capsule isolates the transport budget guard;
                // this is not a P prepare, terminal recovery or process proof.
                let settlement = String::from_utf8(
                    f.state()
                        .channel
                        .db
                        .query_row(
                            "SELECT response FROM channel_log WHERE sequence=9",
                            [],
                            |r| r.get::<_, Vec<u8>>(0),
                        )
                        .unwrap(),
                )
                .unwrap();
                let mut w = WorkerEpochHandoff {
                    version: 1,
                    previous: previous.clone(),
                    binding,
                    controller,
                    controller_ack,
                    controller_history: "a".repeat(64),
                    worker,
                    worker_ack,
                    worker_history,
                    controller_state: "b".repeat(64),
                    worker_state: state_custody::state_digest(&f.root).unwrap(),
                    worker_authority: transport_authority_digest(&f.state().channel.db, 1).unwrap(),
                    prior_epochs: transition_history_digest(
                        &transport_epochs(&f.state().channel.db).unwrap().1,
                    )
                    .unwrap(),
                    returning,
                    service,
                    settlement,
                    authority_sequence: 1,
                    issued_at: now,
                    expires_at: now + 1500,
                    mac: [0; 32],
                };
                w.mac = w.signature(&keys.custody).unwrap();
                w.verify(&keys.custody, now).unwrap();
                // A signed capsule must reserve the handoff plus the mandatory
                // terminal RPC's intent/complete pair on BOTH retained chains.
                // Synthetic authenticated heads isolate that admission boundary;
                // these are not full-history or real process recovery evidence.
                for (role, revision, allowed) in [
                    ("controller", CHECKPOINT_MAX - 3, true),
                    ("controller", CHECKPOINT_MAX - 2, false),
                    ("worker", CHECKPOINT_MAX - 3, true),
                    ("worker", CHECKPOINT_MAX - 2, false),
                ] {
                    let mut candidate = w.clone();
                    let head = if role == "controller" {
                        &mut candidate.controller
                    } else {
                        &mut candidate.worker
                    };
                    head.body.revision = revision;
                    head.mac =
                        typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", &head.body)
                            .unwrap();
                    let ack = CheckpointAck::new(&keys.custody, head).unwrap();
                    if role == "controller" {
                        candidate.controller_ack = ack;
                    } else {
                        candidate.worker_ack = ack;
                    }
                    candidate.mac = candidate.signature(&keys.custody).unwrap();
                    assert_eq!(
                        candidate.verify(&keys.custody, now).is_ok(), allowed,
                        "W recovery must reserve terminal reconciliation at {role} revision {revision}"
                    );
                }
                for (revision, allowed) in [
                    (1021, true),
                    (1022, false),
                    (1025, false),
                    (u64::MAX, false),
                ] {
                    let mut candidate = w.clone();
                    let mut service = serde_json::to_value(&candidate.service).unwrap();
                    service["revision"] = serde_json::json!(revision);
                    candidate.service = serde_json::from_value(service).unwrap();
                    candidate.mac = candidate.signature(&keys.custody).unwrap();
                    assert_eq!(
                        candidate.verify(&keys.custody, now).is_ok(),
                        allowed,
                        "service handoff, original completion and cleanup must fit at revision {revision}"
                    );
                }
                for (sequence, allowed) in [(RPC_HISTORY_MAX - 1, true), (RPC_HISTORY_MAX, false)] {
                    let mut candidate = w.clone();
                    for head in [&mut candidate.controller, &mut candidate.worker] {
                        head.body.sequence = sequence;
                        head.mac =
                            typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", &head.body)
                                .unwrap();
                    }
                    candidate.controller_ack =
                        CheckpointAck::new(&keys.custody, &candidate.controller).unwrap();
                    candidate.worker_ack =
                        CheckpointAck::new(&keys.custody, &candidate.worker).unwrap();
                    candidate.mac = candidate.signature(&keys.custody).unwrap();
                    assert_eq!(
                        candidate.verify(&keys.custody, now).is_ok(),
                        allowed,
                        "terminal RPC must fit after retained sequence {sequence}"
                    );
                }
                assert!(
                    ledger
                        .lock()
                        .unwrap()
                        .prepare_transition(&TransportTransition::Worker(Box::new(w.clone())))
                        .is_err(),
                    "P must refuse before recording a ninth transition capability"
                );
                assert!(f
                    .state()
                    .channel
                    .install_worker_epoch(&w, None, now)
                    .is_err());
                let table:bool=f.state().channel.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='channel_worker_epochs')",[],|r|r.get(0)).unwrap();
                assert!(
                    !table,
                    "full combined history must refuse before writing an unacknowledged W row"
                );
                assert!(f.state().channel.binding == previous);
                f.state().channel.check().unwrap();
                drop(f.state.take());
                std::fs::remove_dir_all(path).unwrap();
                return;
            }
            let capsule_path = path.join("worker-epoch-0002.json");
            let saved = std::fs::read(&capsule_path).unwrap();
            let mut corrupt: TransportEpochHandoff = serde_json::from_slice(&saved).unwrap();
            corrupt.mac[0] ^= 1;
            std::fs::write(&capsule_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
            assert!(
                CustodyLedger::reopen(&root, &path, &head, &ack, keys.reply, keys.custody).is_err()
            );
            std::fs::write(&capsule_path, &saved).unwrap();
            let extra = path.join("worker-epoch-0003.json");
            std::fs::write(&extra, &saved).unwrap();
            assert!(
                CustodyLedger::reopen(&root, &path, &head, &ack, keys.reply, keys.custody).is_err(),
                "uncommitted extra epoch cannot disappear on restart"
            );
            std::fs::remove_file(extra).unwrap();
            std::fs::remove_file(&capsule_path).unwrap();
            assert!(
                CustodyLedger::reopen(&root, &path, &head, &ack, keys.reply, keys.custody).is_err()
            );
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&capsule_path)
                .unwrap()
                .write_all(&saved)
                .unwrap();
            CustodyLedger::reopen(&root, &path, &head, &ack, keys.reply, keys.custody).unwrap();
            drop(f.state.take());
            let link = CustodyLink::new(
                next.clone(),
                "worker",
                keys.reply,
                keys.custody,
                Box::new(|_| Err("routing_closed")),
            )
            .unwrap();
            let recovered = TransportJournal::reopen_witnessed(
                &f.root,
                &f.path,
                "worker-channel.sqlite",
                &head,
                &ack,
                link,
            )
            .unwrap();
            recovered.validate_custody_chain().unwrap();
        } else {
            assert!(
                f.state()
                    .channel
                    .install_controller_epoch(&capsule, None, now)
                    .is_err(),
                "P has not durably prepared this epoch"
            );
            // An unacknowledged transition poisons the journal; never erase it.
            assert!(f.state().channel.check().is_err());
            assert!(f.state().handle(&old_frame).is_err());
        }
        drop(f.state.take());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn rpc_source_observation_binds_boot_role_high_water_and_revocation() {
        let mut f = Fixture::new();
        let s = f.state();
        let b = s.channel.binding.clone();
        let keys = s.keys.clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let body=serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":1,"observed_at":now,"revoked":["grant_root123456"]})).unwrap();
        let canonical = super::super::la_contract::canonical_json(&body).unwrap();
        let mut wrong = b.clone();
        wrong.controller_epoch += 1;
        let bad = sign_source_observation(&keys.authority, &wrong, &body).unwrap();
        assert!(s.observe(&bad).is_err());
        let frame = sign_source_observation(&keys.authority, &b, &body).unwrap();
        let ack = s.observe(&frame).unwrap();
        verify_source_ack(&keys.reply, &b, "worker", &canonical, &ack).unwrap();
        assert!(verify_source_ack(&keys.reply, &b, "controller", &canonical, &ack).is_err());
        assert!(s.observe(&frame).is_err());
        assert_eq!(
            s.channel
                .db
                .query_row("SELECT COUNT(*) FROM channel_authority", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn rpc_http_roundtrip_has_signed_worker_reply_and_refuses_unqualified_work() {
        let mut f = Fixture::new();
        let state = f.state.take().unwrap();
        let binding = state.channel.binding.clone();
        let keys = state.keys.clone();
        let cpath = f.path.join("controller");
        std::fs::create_dir(&cpath).unwrap();
        let croot = super::super::la_artifacts::open_owned_root(&cpath).unwrap();
        let journal =
            TransportJournal::create(&croot, &cpath, "controller-channel.sqlite", binding).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let state = std::sync::Arc::new(std::sync::Mutex::new(state));
        let observed = state.clone();
        let t = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let context = InventoryContext {
                    bearer_digest: [0; 32],
                    worker_id: "worker_cpu_000001".into(),
                    boot_id: "a".repeat(64),
                    hardware_generation: 1,
                    profile_epoch: 1,
                };
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, worker_rpc_router(context, state))
                    .with_graceful_shutdown(async {
                        let _ = rx.await;
                    })
                    .await
                    .unwrap();
            });
        });
        let mut client = WorkerClient::new(address, journal, keys).unwrap();
        assert!(client.admission().is_err());
        assert!(
            matches!(client.call(WorkerOperation::Probe,&[]).unwrap(),WorkerReply::Probe{worker_pid,..} if worker_pid==std::process::id())
        );
        assert!(
            matches!(client.call(WorkerOperation::Stage(inspect_command()),b"input").unwrap(),WorkerReply::Refused{code} if code=="evidence_invalid")
        );
        assert_eq!(
            observed
                .lock()
                .unwrap()
                .journal
                .start_count("operation_000001")
                .unwrap(),
            0
        );
        let _ = tx.send(());
        t.join().unwrap();
        drop(client);
        drop(observed);
    }
}

impl WorkerClient {
    pub(super) fn bind_assignment_terms(
        &mut self,
        assignment: &str,
        terms: &super::la_store::AssignmentTerms,
    ) -> Result<(), &'static str> {
        if self.terms.get(assignment).is_some_and(|old| old != terms) {
            return Err("evidence_invalid");
        }
        if !self.terms.contains_key(assignment) && self.terms.len() >= 8 {
            return Err("capacity_unavailable");
        }
        self.terms.insert(assignment.into(), terms.clone());
        Ok(())
    }
    pub(super) fn bind_mandate(
        &mut self,
        mandate: super::la_auth::StoredMandate,
    ) -> Result<(), &'static str> {
        if super::la_store::checked_mandate(&mandate.draft)? != mandate
            || self
                .mandates
                .get(&mandate.draft.job)
                .is_some_and(|old| old != &mandate)
        {
            return Err("evidence_invalid");
        }
        if !self.mandates.contains_key(&mandate.draft.job) && self.mandates.len() >= 32 {
            return Err("capacity_unavailable");
        }
        self.mandates.insert(mandate.draft.job.clone(), mandate);
        Ok(())
    }
    pub(super) fn reserve(&mut self, c: &ReserveCommand) -> Result<WorkerReply, &'static str> {
        let terms = self
            .terms
            .get(&c.assignment)
            .ok_or("evidence_invalid")?
            .clone();
        self.call(WorkerOperation::Reserve(c.clone(), terms), &[])
    }
    pub(super) fn permit(&mut self, c: &InspectCommand) -> Result<WorkerReply, &'static str> {
        let mandate = self.mandates.get(&c.job).ok_or("evidence_invalid")?.clone();
        self.call(WorkerOperation::Permit(c.clone(), Box::new(mandate)), &[])
    }
}

/// Read-only independent P custody observation. The returned digests and exact
/// high-water survive role death in P's separately bounded custody root. It
/// cannot activate a worker or turn an unknown/pending response into a pass.
pub(super) fn observe_channel_custody(
    root: &std::fs::File,
    name: &str,
    binding: &ChannelBinding,
    reply_key: &[u8; 32],
    expected: u64,
) -> Result<serde_json::Value, &'static str> {
    let db = super::la_store::open_pinned_readonly_database(root, name)?;
    let identities: i64 = db
        .query_row("SELECT COUNT(*) FROM channel_identity", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    if identities != 1 {
        return Err("evidence_invalid");
    }
    let identity: Vec<u8> = db
        .query_row("SELECT binding FROM channel_identity", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    if identity != serde_json::to_vec(binding).map_err(|_| "evidence_invalid")? {
        return Err("evidence_invalid");
    }
    let mut statement=db.prepare("SELECT sequence,digest,length(response),substr(response,1,65537) FROM channel_log ORDER BY sequence").map_err(|_|"evidence_invalid")?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .map_err(|_| "evidence_invalid")?;
    let mut records = Vec::new();
    for row in rows {
        let (seq, digest, length, body) = row.map_err(|_| "evidence_invalid")?;
        if seq != records.len() as i64 + 1
            || records.len() >= RPC_HISTORY_MAX as usize
            || digest.len() != 64
        {
            return Err("evidence_invalid");
        }
        let body = body.ok_or("transport_uncertain")?;
        if length != Some(body.len() as i64) || body.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        let signed: SignedResponse =
            serde_json::from_slice(&super::la_contract::canonical_json(&body)?)
                .map_err(|_| "evidence_invalid")?;
        if signed.response.version != 1
            || signed.response.binding != *binding
            || signed.response.sequence != seq as u64
            || !bool::from(
                typed_mac(reply_key, b"diffuser-rpc-response/v1\0", &signed.response)?
                    .ct_eq(&signed.mac),
            )
        {
            return Err("evidence_invalid");
        }
        records.push(serde_json::json!({"sequence":seq,"request_digest":signed.response.request_digest,"journal_digest":digest,"response_digest":hex::encode(Sha256::digest(&body))}));
    }
    if records.len() as u64 != expected {
        return Err("evidence_invalid");
    }
    Ok(
        serde_json::json!({"binding":binding,"high_water":expected,"records":records,"state_digest":transport_state_digest(&db,binding)?}),
    )
}

impl WorkerRpc {
    fn authority_permits(
        &self,
        mandate: &super::la_auth::StoredMandate,
        permit_until: u64,
    ) -> Result<(), &'static str> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis();
        let rows = logical_worker_sources(&self.channel.db, &self.keys)?;
        let mut last = 0;
        let mut observed = 0;
        let mut revoked = std::collections::BTreeSet::new();
        for row in rows {
            let (seq, time, body, frame) = row;
            if seq != last + 1
                || seq > 128
                || time < observed
                || body.len() > 12 * 1024
                || frame.len() > 12 * 1024
                || verify_source_observation(
                    &self.keys.authority,
                    &transport_authority_binding(&self.channel.db, seq as u64)?,
                    &frame,
                )? != body
            {
                return Err("evidence_invalid");
            }
            let value: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
            if value["sequence"].as_i64() != Some(seq)
                || value["observed_at"].as_i64() != Some(time)
            {
                return Err("evidence_invalid");
            }
            for id in value["revoked"].as_array().ok_or("evidence_invalid")? {
                revoked.insert(id.as_str().ok_or("evidence_invalid")?.to_owned());
            }
            last = seq;
            observed = time;
        }
        if last == 0
            || observed < 0
            || observed as u128 > now
            || now >= observed as u128 + 1500
            || permit_until as u128 > observed as u128 + 1500
            || mandate.draft.chain.iter().any(|g| revoked.contains(&g.id))
        {
            return Err("delegation_denied");
        }
        Ok(())
    }
}

// Live custody of transport mutations. The issuer remains closed: a witnessed
// transport checkpoint does not qualify resources, authority or cleanup.
const CHECKPOINT_MAX: u64 = RPC_HISTORY_MAX * 2;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChannelCheckpoint {
    binding: ChannelBinding,
    role: String,
    revision: u64,
    previous: String,
    sequence: u64,
    phase: String,
    root_dev: u64,
    root_inode: u64,
    db_dev: u64,
    db_inode: u64,
    state_digest: String,
    #[serde(default)]
    owned_state: Option<String>,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedCheckpoint {
    body: ChannelCheckpoint,
    mac: [u8; 32],
}
impl SignedCheckpoint {
    fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    pub(super) fn revision(&self) -> u64 {
        self.body.revision
    }
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointAck {
    binding: ChannelBinding,
    role: String,
    revision: u64,
    checkpoint_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumption: Option<RecoveryConsumption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    loss_consumption: Option<RecoveryConsumption>,
    mac: [u8; 32],
}
impl CheckpointAck {
    fn new(key: &[u8; 32], checkpoint: &SignedCheckpoint) -> Result<Self, &'static str> {
        let b = &checkpoint.body;
        let digest = checkpoint.digest()?;
        let mac = typed_mac(
            key,
            b"diffuser-custody-ack/v1\0",
            &(&b.binding, &b.role, b.revision, &digest),
        )?;
        Ok(Self {
            binding: b.binding.clone(),
            role: b.role.clone(),
            revision: b.revision,
            checkpoint_digest: digest,
            consumption: None,
            loss_consumption: None,
            mac,
        })
    }
    fn verify(&self, key: &[u8; 32], checkpoint: &SignedCheckpoint) -> Result<(), &'static str> {
        let expected = Self::new(key, checkpoint)?;
        if let Some(proof) = &self.consumption {
            proof.verify(key)?;
            if checkpoint.body.phase != "handoff"
                || proof.kind != checkpoint.body.role
                || proof.checkpoint != expected.checkpoint_digest
            {
                return Err("evidence_invalid");
            }
        }
        if let Some(proof) = &self.loss_consumption {
            proof.verify(key)?;
            let expected_kind = match checkpoint.body.role.as_str() {
                "worker" => "loss_worker",
                "controller" => "loss_controller",
                _ => return Err("evidence_invalid"),
            };
            if self.consumption.is_some()
                || checkpoint.body.phase != "handoff"
                || proof.kind != expected_kind
                || proof.checkpoint != expected.checkpoint_digest
            {
                return Err("evidence_invalid");
            }
        }
        if self.binding != expected.binding
            || self.role != expected.role
            || self.revision != expected.revision
            || self.checkpoint_digest != expected.checkpoint_digest
            || !bool::from(self.mac.ct_eq(&expected.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

/// P observes the installed checkpoint through its pinned read-only root,
/// fsyncs it, then signs the actual wall time. This is historical consumption,
/// never a fresh source, resource certificate, admission or execution permit.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryConsumption {
    kind: String,
    capability: String,
    checkpoint: String,
    observed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer: Option<Box<RecoveryConsumption>>,
    mac: [u8; 32],
}
impl RecoveryConsumption {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut unsigned = self.clone();
        unsigned.mac = [0; 32];
        typed_mac(key, b"diffuser-recovery-consumption/v1\0", &unsigned)
    }
    fn verify(&self, key: &[u8; 32]) -> Result<(), &'static str> {
        if !matches!(
            self.kind.as_str(),
            "worker" | "controller" | "service" | "loss_worker" | "loss_controller"
        ) || [&self.capability, &self.checkpoint]
            .iter()
            .any(|s| s.len() != 64 || hex::decode(s).is_err())
            || !bool::from(self.signature(key)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        if let Some(peer) = &self.peer {
            if !matches!(
                (self.kind.as_str(), peer.kind.as_str()),
                ("controller", "worker") | ("loss_controller", "loss_worker")
            ) || peer.peer.is_some()
                || peer.capability != self.capability
                || peer.observed_at > self.observed_at
            {
                return Err("evidence_invalid");
            }
            peer.verify(key)?;
        }
        Ok(())
    }
    fn verify_window(
        &self,
        key: &[u8; 32],
        capability: &str,
        issued: u64,
        expires: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify(key)?;
        if self.capability != capability
            || self.observed_at < issued
            || self.observed_at >= expires
            || self.observed_at > now
        {
            return Err("evidence_invalid");
        }
        if let Some(peer) = &self.peer {
            peer.verify_window(key, capability, issued, expires, now)?;
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Exact independent consumption binds kind, capsule, checkpoint and its original window."
    )]
    fn record(
        root: &std::fs::File,
        key: &[u8; 32],
        kind: &str,
        epoch: u64,
        capability: String,
        checkpoint: String,
        issued: u64,
        expires: u64,
        peer: Option<Box<Self>>,
    ) -> Result<Self, &'static str> {
        use std::io::Write;
        let now = wall_now()?;
        let mut proof = Self {
            kind: kind.into(),
            capability,
            checkpoint,
            observed_at: now,
            peer,
            mac: [0; 32],
        };
        proof.mac = proof.signature(key)?;
        recovery_trace(
            "consumption_witness_clock",
            serde_json::json!({"kind":kind,"epoch":epoch,"issued_at":issued,"expires_at":expires,"now":now,"within_window":issued<=now && now<expires}),
        );
        proof.verify_window(key, &proof.capability, issued, expires, now).inspect_err(|_| recovery_trace("consumption_witness_refused",serde_json::json!({"kind":kind,"guard":"original_window_or_authenticated_peer"})))?;
        let mut file = super::la_artifacts::open_artifact(
            root,
            &format!("recovery-consumed-{kind}-{epoch:04}.json"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| "evidence_invalid")?;
        file.write_all(&serde_json::to_vec(&proof).map_err(|_| "evidence_invalid")?)
            .and_then(|_| file.sync_all())
            .and_then(|_| root.sync_all())
            .map_err(|_| "storage_unavailable")?;
        // If persistence crosses the original bound, no ACK is returned. Its
        // absence in the role journal keeps the partial installation closed.
        let durable_now = wall_now()?;
        recovery_trace(
            "consumption_witness_fsync_clock",
            serde_json::json!({"kind":kind,"epoch":epoch,"expires_at":expires,"now":durable_now,"within_window":durable_now<expires}),
        );
        if durable_now >= expires {
            return Err("evidence_invalid");
        }
        recovery_trace(
            "consumption_witness_durable",
            serde_json::json!({"kind":kind,"observed_at":now,"expires_at":expires,"epoch":epoch}),
        );
        Ok(proof)
    }
    fn read(root: &std::fs::File, kind: &str, epoch: u64) -> Result<Self, &'static str> {
        use std::io::Read;
        let mut bytes = Vec::new();
        super::la_artifacts::open_artifact(
            root,
            &format!("recovery-consumed-{kind}-{epoch:04}.json"),
            libc::O_RDONLY,
        )
        .map_err(|_| "evidence_invalid")?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "evidence_invalid")?;
        if bytes.len() > 4096 {
            return Err("evidence_invalid");
        }
        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")
    }
}

type CheckpointEmitter = dyn Fn(&[u8]) -> Result<(), &'static str> + Send + Sync;
#[derive(Default)]
struct CheckpointWait {
    expected: Option<SignedCheckpoint>,
    ack: Option<CheckpointAck>,
    failed: bool,
}
/// The protected control reader delivers acknowledgments independently of the
/// operation lock. A timeout poisons this boot's channel; it cannot fall back to
/// unobserved work or reuse an old acknowledgment.
pub(super) struct CustodyLink {
    binding: ChannelBinding,
    role: String,
    request_key: [u8; 32],
    ack_key: [u8; 32],
    emit: Box<CheckpointEmitter>,
    wait: std::sync::Mutex<CheckpointWait>,
    changed: std::sync::Condvar,
}
impl Drop for CustodyLink {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.request_key.zeroize();
        self.ack_key.zeroize();
    }
}
impl CustodyLink {
    pub(super) fn new(
        binding: ChannelBinding,
        role: &str,
        request_key: [u8; 32],
        ack_key: [u8; 32],
        emit: Box<CheckpointEmitter>,
    ) -> Result<std::sync::Arc<Self>, &'static str> {
        binding.validate()?;
        if !matches!(role, "worker" | "controller")
            || request_key == [0; 32]
            || ack_key == [0; 32]
            || request_key == ack_key
        {
            return Err("evidence_invalid");
        }
        Ok(std::sync::Arc::new(Self {
            binding,
            role: role.into(),
            request_key,
            ack_key,
            emit,
            wait: std::sync::Mutex::new(CheckpointWait::default()),
            changed: std::sync::Condvar::new(),
        }))
    }
    pub(super) fn accept(&self, bytes: &[u8]) -> Result<(), &'static str> {
        if bytes.len() > 4096 {
            return Err("evidence_invalid");
        }
        let ack: CheckpointAck =
            serde_json::from_slice(&super::la_contract::canonical_json(bytes)?)
                .map_err(|_| "evidence_invalid")?;
        let mut wait = self.wait.lock().map_err(|_| "storage_unavailable")?;
        if wait.failed || wait.ack.is_some() {
            return Err("evidence_invalid");
        }
        ack.verify(
            &self.ack_key,
            wait.expected.as_ref().ok_or("evidence_invalid")?,
        )?;
        wait.ack = Some(ack);
        self.changed.notify_all();
        Ok(())
    }
    fn exchange(&self, checkpoint: &SignedCheckpoint) -> Result<CheckpointAck, &'static str> {
        let bytes = serde_json::to_vec(checkpoint).map_err(|_| "evidence_invalid")?;
        if bytes.len() > 4096 {
            return Err("evidence_invalid");
        }
        {
            let mut wait = self.wait.lock().map_err(|_| "storage_unavailable")?;
            if wait.failed || wait.expected.is_some() {
                return Err("evidence_invalid");
            }
            wait.expected = Some(checkpoint.clone());
            wait.ack = None;
        }
        if (self.emit)(&bytes).is_err() {
            self.wait.lock().map_err(|_| "storage_unavailable")?.failed = true;
            return Err("evidence_invalid");
        }
        let wait = self.wait.lock().map_err(|_| "storage_unavailable")?;
        let (mut wait, _) = self
            .changed
            .wait_timeout_while(wait, std::time::Duration::from_millis(500), |w| {
                w.ack.is_none() && !w.failed
            })
            .map_err(|_| "storage_unavailable")?;
        let Some(ack) = wait.ack.take() else {
            wait.failed = true;
            return Err("evidence_invalid");
        };
        ack.verify(&self.ack_key, checkpoint)?;
        wait.expected = None;
        Ok(ack)
    }
}

fn rpc_content_digest(req: &RpcRequest) -> Result<String, &'static str> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&(
            &req.binding,
            &req.operation,
            &req.input_digest,
            req.input_bytes,
        ))
        .map_err(|_| "evidence_invalid")?,
    )))
}
fn validate_rpc_envelope(
    bytes: &[u8],
    name: &str,
    binding: &ChannelBinding,
    sequence: u64,
    digest: &str,
) -> Result<(), &'static str> {
    if bytes.is_empty() || bytes.len() > RPC_JSON_MAX {
        return Err("evidence_invalid");
    }
    let signed: SignedRequest = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
    let req = &signed.request;
    if serde_json::to_vec(&signed).map_err(|_| "evidence_invalid")? != bytes
        || req.version != 1
        || req.binding != *binding
        || req.sequence != sequence
        || sequence == 0
        || sequence > RPC_HISTORY_MAX
        || req.input_bytes > RPC_INPUT_MAX as u64
        || req.input_digest.len() != 64
        || !req
            .input_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || (!matches!(req.operation, WorkerOperation::Stage(_))
            && (req.input_bytes != 0 || req.input_digest != hex::encode(Sha256::digest([]))))
        || req
            .operation
            .binding()
            .is_some_and(|(w, b)| w != binding.worker || b != binding.worker_boot)
    {
        return Err("evidence_invalid");
    }
    operation_target(&req.operation)?;
    let expected = match name {
        "controller-channel.sqlite" => rpc_content_digest(req)?,
        "worker-channel.sqlite" => hex::encode(Sha256::digest(
            serde_json::to_vec(req).map_err(|_| "evidence_invalid")?,
        )),
        _ => return Err("evidence_invalid"),
    };
    if expected != digest {
        return Err("evidence_invalid");
    }
    Ok(())
}

/// Hash the entire bounded transport history, one row at a time. A same-count
/// history substitution is different state; the count alone is not a watermark.
fn transport_state_digest(
    db: &rusqlite::Connection,
    binding: &ChannelBinding,
) -> Result<String, &'static str> {
    let identities: i64 = db
        .query_row("SELECT COUNT(*) FROM channel_identity", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    if identities != 1 {
        return Err("evidence_invalid");
    }
    let identity: Vec<u8> = db
        .query_row("SELECT binding FROM channel_identity", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    let (genesis, epochs) = transport_epochs(db)?;
    if identity != serde_json::to_vec(&genesis).map_err(|_| "evidence_invalid")?
        || epochs.last().map(|e| e.binding()).unwrap_or(&genesis) != binding
    {
        return Err("evidence_invalid");
    }
    let role: String = db
        .query_row("SELECT role FROM channel_identity", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    if !matches!(
        role.as_str(),
        "worker-channel.sqlite" | "controller-channel.sqlite"
    ) {
        return Err("evidence_invalid");
    }
    let mut hash = Sha256::new();
    hash.update(b"diffuser-channel-state/v3\0");
    hash.update(role.as_bytes());
    hash.update(&identity);
    hash.update(b"epochs/v1\0");
    for epoch in &epochs {
        let bytes = serde_json::to_vec(&epoch).map_err(|_| "evidence_invalid")?;
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut statement=db.prepare("SELECT sequence,digest,length(response),substr(response,1,65537),length(request),substr(request,1,65537) FROM channel_log ORDER BY sequence").map_err(|_|"evidence_invalid")?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })
        .map_err(|_| "evidence_invalid")?;
    let mut high = 0u64;
    let mut pending = false;
    for row in rows {
        let (sequence, digest, length, response, request_length, request) =
            row.map_err(|_| "evidence_invalid")?;
        high += 1;
        if sequence != high as i64
            || high > RPC_HISTORY_MAX
            || pending
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || response
                .as_ref()
                .is_some_and(|b| b.len() > RPC_JSON_MAX || length != Some(b.len() as i64))
        {
            return Err("evidence_invalid");
        }
        if request_length != request.len() as i64 {
            return Err("evidence_invalid");
        }
        let expected_binding = binding_in_history(
            genesis.clone(),
            &epochs,
            role.trim_end_matches("-channel.sqlite"),
            high,
            false,
        )?;
        validate_rpc_envelope(&request, &role, &expected_binding, high, &digest)?;
        hash.update((request.len() as u64).to_be_bytes());
        hash.update(&request);
        pending = response.is_none();
        // Fixed-width fields and an explicit optional-value tag bind every
        // byte without serializing binary payloads as JSON decimal arrays.
        hash.update(sequence.to_be_bytes());
        hash.update(digest.as_bytes());
        match response {
            None => hash.update([0]),
            Some(bytes) => {
                hash.update([1]);
                hash.update((bytes.len() as u64).to_be_bytes());
                hash.update(bytes);
            }
        }
    }
    Ok(hex::encode(hash.finalize()))
}

impl TransportJournal {
    /// Only the protected bootstrap path supplies a link. Existing journal
    /// checkpoints need an explicit custody recovery path, never a new genesis.
    pub(super) fn set_owned_state(&mut self, digest: String) {
        self.owned_state = true;
        self.owned_digest = Some(digest);
    }
    pub(super) fn enable_custody(
        &mut self,
        link: std::sync::Arc<CustodyLink>,
    ) -> Result<(), &'static str> {
        self.check()?;
        let role = if self.name == "worker-channel.sqlite" {
            "worker"
        } else {
            "controller"
        };
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM channel_checkpoints", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        if self.custody.is_some() || link.binding != self.binding || link.role != role || count != 0
        {
            return Err("evidence_invalid");
        }
        let state = transport_state_digest(&self.db, &self.binding)?;
        self.custody = Some((
            link,
            state,
            0,
            "0".repeat(64),
            checkpoint_bytes_digest(&self.db, 0, 0)?,
        ));
        Ok(())
    }
    fn checkpoint(&mut self, phase: &str, sequence: u64) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        let Some((link, _, old_revision, _, old_history)) = &self.custody else {
            return Ok(());
        };
        let link = link.clone();
        let old_revision = *old_revision;
        let old_history = old_history.clone();
        use rusqlite::OptionalExtension;
        let last: Option<(i64, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT revision,frame FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let (revision, previous) = match last {
            None => (1, "0".repeat(64)),
            Some((n, bytes)) => (
                u64::try_from(n)
                    .ok()
                    .and_then(|n| n.checked_add(1))
                    .ok_or("evidence_invalid")?,
                hex::encode(Sha256::digest(bytes)),
            ),
        };
        if revision > CHECKPOINT_MAX || !matches!(phase, "intent" | "complete" | "handoff") {
            return Err("evidence_invalid");
        }
        let root = self.root.metadata().map_err(|_| "evidence_invalid")?;
        let file = self.file.metadata().map_err(|_| "evidence_invalid")?;
        let state_digest = transport_state_digest(&self.db, &self.binding)?;
        let owned_state = if self.owned_state {
            let digest = state_custody::state_digest(&self.root)?;
            if phase == "intent" && self.owned_digest.as_ref().is_some_and(|old| old != &digest) {
                return Err("evidence_invalid");
            }
            Some(digest)
        } else {
            None
        };
        let body = ChannelCheckpoint {
            owned_state,
            binding: self.binding.clone(),
            role: link.role.clone(),
            revision,
            previous,
            sequence,
            phase: phase.into(),
            root_dev: root.dev(),
            root_inode: root.ino(),
            db_dev: file.dev(),
            db_inode: file.ino(),
            state_digest: state_digest.clone(),
        };
        let mac = typed_mac(
            &link.request_key,
            b"diffuser-custody-checkpoint/v1\0",
            &body,
        )?;
        let frame = SignedCheckpoint { body, mac };
        let bytes = serde_json::to_vec(&frame).map_err(|_| "evidence_invalid")?;
        self.db
            .execute(
                "INSERT INTO channel_checkpoints VALUES (?1,?2,NULL)",
                rusqlite::params![revision as i64, bytes],
            )
            .map_err(|_| "storage_unavailable")?;
        let ack = link.exchange(&frame)?;
        let bytes = serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?;
        if self
            .db
            .execute(
                "UPDATE channel_checkpoints SET ack=?2 WHERE revision=?1 AND ack IS NULL",
                rusqlite::params![revision as i64, bytes],
            )
            .map_err(|_| "storage_unavailable")?
            != 1
        {
            return Err("evidence_invalid");
        }
        let (retained_history, new_history) =
            checkpoint_history_digests(&self.db, revision, old_revision)?;
        if retained_history != old_history {
            return Err("evidence_invalid");
        }
        if phase == "complete" && self.owned_state {
            self.owned_digest = frame.body.owned_state.clone();
        }
        self.custody = Some((link, state_digest, revision, frame.digest()?, new_history));
        Ok(())
    }
}

/// P's separately rooted, append-only witness. P reads the role's durable state
/// through its independently obtained read-only root descriptor, then fsyncs its
/// own record before acknowledging. It neither opens the role DB writable nor
/// signs readiness, safe occupancy or resource qualification.
pub(super) struct CustodyLedger {
    root: std::fs::File,
    path: std::path::PathBuf,
    binding: ChannelBinding,
    role: String,
    request_key: [u8; 32],
    ack_key: [u8; 32],
    revision: u64,
    head: String,
    // Cache authenticated bytes only. Every observation still reads and hashes
    // each retained response; a changed previously verified row is invalid.
    verified_responses: std::collections::BTreeMap<u64, [u8; 32]>,
    owned_state: Option<String>,
    pending_epoch: Option<TransportTransition>,
}
impl Drop for CustodyLedger {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.request_key.zeroize();
        self.ack_key.zeroize();
    }
}
impl CustodyLedger {
    pub(super) fn bootstrap(
        root: &std::fs::File,
        path: &std::path::Path,
        binding: ChannelBinding,
        role: &str,
        request_key: [u8; 32],
        ack_key: [u8; 32],
    ) -> Result<Self, &'static str> {
        binding.validate()?;
        if !super::la_store::claim_root_matches(root, path)
            || !matches!(role, "worker" | "controller")
            || request_key == ack_key
            || request_key == [0; 32]
            || ack_key == [0; 32]
        {
            return Err("evidence_invalid");
        }
        Ok(Self {
            root: root.try_clone().map_err(|_| "storage_unavailable")?,
            path: path.into(),
            binding,
            role: role.into(),
            request_key,
            ack_key,
            revision: 0,
            head: "0".repeat(64),
            verified_responses: std::collections::BTreeMap::new(),
            owned_state: None,
            pending_epoch: None,
        })
    }
    pub(super) fn observe(
        &mut self,
        role_root: &std::fs::File,
        frame: &SignedCheckpoint,
    ) -> Result<CheckpointAck, &'static str> {
        use std::io::{Read, Write};
        use std::os::unix::fs::MetadataExt;
        let body = &frame.body;
        let transition = body.phase == "handoff";
        let expected_binding = if transition {
            self.pending_epoch
                .as_ref()
                .ok_or("evidence_invalid")?
                .binding()
        } else {
            if self.pending_epoch.is_some() {
                return Err("evidence_invalid");
            }
            &self.binding
        };
        if !super::la_store::claim_root_matches(&self.root, &self.path)
            || body.binding != *expected_binding
            || body.role != self.role
            || body.revision != self.revision.checked_add(1).ok_or("evidence_invalid")?
            || body.revision > CHECKPOINT_MAX
            || body.previous != self.head
            || body.sequence == 0
            || body.sequence > RPC_HISTORY_MAX
            || !matches!(body.phase.as_str(), "intent" | "complete" | "handoff")
            || !bool::from(
                typed_mac(&self.request_key, b"diffuser-custody-checkpoint/v1\0", body)?
                    .ct_eq(&frame.mac),
            )
        {
            return Err("evidence_invalid");
        }
        let root = role_root.metadata().map_err(|_| "evidence_invalid")?;
        if (root.dev(), root.ino()) != (body.root_dev, body.root_inode) {
            return Err("evidence_invalid");
        }
        if let Some(owned) = &body.owned_state {
            if self.role != "worker"
                || state_custody::state_digest(role_root)? != *owned
                || (body.phase == "intent"
                    && self
                        .owned_state
                        .as_ref()
                        .is_some_and(|previous| previous != owned))
            {
                return Err("evidence_invalid");
            }
        } else if self.owned_state.is_some() {
            return Err("evidence_invalid");
        }
        let name = format!("{}-channel.sqlite", self.role);
        let file = super::la_artifacts::open_artifact(role_root, &name, libc::O_RDONLY)
            .map_err(|_| "evidence_invalid")?;
        let meta = file.metadata().map_err(|_| "evidence_invalid")?;
        if (meta.dev(), meta.ino()) != (body.db_dev, body.db_inode) || meta.nlink() != 1 {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_readonly_database(role_root, &name)?;
        let tx = db
            .unchecked_transaction()
            .map_err(|_| "storage_unavailable")?;
        if transport_state_digest(&tx, &body.binding)? != body.state_digest {
            return Err("evidence_invalid");
        }
        if transition {
            let pending = self.pending_epoch.as_ref().ok_or("evidence_invalid")?;
            let (_, epochs) = transport_epochs(&tx)?;
            let last = epochs.last().ok_or("evidence_invalid")?;
            let (anchor, _, _, state) = pending.anchor(&self.role)?;
            if self.role == "controller" {
                if let Some(expected) = pending.settlement() {
                    let actual: Vec<u8> = tx
                        .query_row(
                            "SELECT response FROM channel_log WHERE sequence=?1",
                            [body.sequence as i64],
                            |r| r.get(0),
                        )
                        .map_err(|_| "evidence_invalid")?;
                    if actual != expected.as_bytes() {
                        return Err("evidence_invalid");
                    }
                }
            }
            if last.digest()? != pending.digest()?
                || body.sequence != pending.install_sequence(&self.role)?
                || body.previous != anchor.digest()?
                || state_custody::state_digest(role_root)? != state
            {
                return Err("evidence_invalid");
            }
        }
        let mut verified_responses = std::collections::BTreeMap::new();
        {
            let mut statement=tx.prepare("SELECT sequence,digest,response FROM channel_log WHERE response IS NOT NULL ORDER BY sequence").map_err(|_|"evidence_invalid")?;
            let rows = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(|_| "evidence_invalid")?;
            for row in rows {
                let (sequence, digest, bytes) = row.map_err(|_| "evidence_invalid")?;
                if bytes.len() > RPC_JSON_MAX {
                    return Err("evidence_invalid");
                }
                let mut fingerprint = Sha256::new();
                fingerprint.update(sequence.to_be_bytes());
                fingerprint.update(digest.as_bytes());
                fingerprint.update(&bytes);
                let fingerprint: [u8; 32] = fingerprint.finalize().into();
                verified_responses.insert(sequence as u64, fingerprint);
                if let Some(previous) = self.verified_responses.get(&(sequence as u64)) {
                    if *previous != fingerprint {
                        return Err("evidence_invalid");
                    }
                    continue;
                }
                if serde_json::from_slice::<serde_json::Value>(&bytes)
                    .is_ok_and(|v| v["kind"] == "diffuser-entered-worker-loss/v1")
                {
                    let cap: WorkerLossSettlement =
                        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                    let (_, epochs) = transport_epochs(&tx)?;
                    let returned = epochs.iter().find_map(|e| match e {
                        TransportTransition::EnteredLoss(h)
                            if h.high_water() == sequence as u64 =>
                        {
                            Some(h)
                        }
                        _ => None,
                    });
                    if let Some(h) = returned {
                        h.verify_history(&self.ack_key)?;
                        h.installed_resolution(&tx, &self.ack_key)?;
                    } else if self.role != "controller"
                        || cap.binding != body.binding
                        || cap.sequence != sequence as u64
                        || !bool::from(cap.signature(&self.ack_key)?.ct_eq(&cap.mac))
                        || cap.controller.digest()? != self.head
                        || cap.controller.body.revision != self.revision
                    {
                        return Err("evidence_invalid");
                    }
                    let mut saved = Vec::new();
                    super::la_artifacts::open_artifact(
                        &self.root,
                        &format!("worker-loss-{:04}.json", cap.sequence),
                        libc::O_RDONLY,
                    )
                    .map_err(|_| "evidence_invalid")?
                    .take(12289)
                    .read_to_end(&mut saved)
                    .map_err(|_| "evidence_invalid")?;
                    if saved != bytes {
                        return Err("evidence_invalid");
                    }
                    continue;
                }
                let response: SignedResponse =
                    serde_json::from_slice(&super::la_contract::canonical_json(&bytes)?)
                        .map_err(|_| "evidence_invalid")?;
                let r = &response.response;
                if r.version != 1
                    || r.binding != transport_binding_at(&tx, &self.role, sequence as u64, false)?
                    || r.sequence != sequence as u64
                    || (self.role == "worker" && r.request_digest != digest)
                    || !bool::from(
                        typed_mac(&self.request_key, b"diffuser-rpc-response/v1\0", r)?
                            .ct_eq(&response.mac),
                    )
                {
                    return Err("evidence_invalid");
                }
            }
        }

        if self
            .verified_responses
            .keys()
            .any(|sequence| !verified_responses.contains_key(sequence))
        {
            return Err("evidence_invalid");
        }
        let (high, pending): (i64, bool) = tx
            .query_row(
                "SELECT sequence,response IS NULL FROM channel_log ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if high != body.sequence as i64 || pending != (body.phase == "intent") {
            return Err("evidence_invalid");
        }
        let (count, high): (i64, i64) = tx
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(revision),0) FROM channel_checkpoints",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let saved: Vec<u8> = tx
            .query_row(
                "SELECT frame FROM channel_checkpoints WHERE revision=?1",
                [body.revision as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let bytes = serde_json::to_vec(frame).map_err(|_| "evidence_invalid")?;
        if count != body.revision as i64 || high != count || saved != bytes {
            return Err("evidence_invalid");
        }
        if body.revision > 1 {
            let previous: Vec<u8> = tx
                .query_row(
                    "SELECT frame FROM channel_checkpoints WHERE revision=?1",
                    [body.revision as i64 - 1],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            if hex::encode(Sha256::digest(previous)) != self.head {
                return Err("evidence_invalid");
            }
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        let name = format!("{}-witness-{:04}.json", self.role, body.revision);
        let mut record = super::la_artifacts::open_artifact(
            &self.root,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| "evidence_invalid")?;
        record
            .write_all(&bytes)
            .and_then(|_| record.sync_all())
            .and_then(|_| self.root.sync_all())
            .map_err(|_| "storage_unavailable")?;
        if body.phase == "complete" {
            self.owned_state = body.owned_state.clone();
        }
        let mut ack = CheckpointAck::new(&self.ack_key, frame)?;
        if let Some(TransportTransition::Controller(h)) = self.pending_epoch.as_ref().filter(|h| {
            transition
                && matches!(h, TransportTransition::Controller(c) if c.service_recovery.is_some())
        }) {
            let peer = if self.role == "controller" {
                let peer =
                    RecoveryConsumption::read(&self.root, "worker", h.binding.controller_epoch)?;
                peer.verify_window(
                    &self.ack_key,
                    &h.digest()?,
                    h.issued_at,
                    h.expires_at,
                    wall_now()?,
                )?;
                Some(Box::new(peer))
            } else {
                None
            };
            ack.consumption = Some(RecoveryConsumption::record(
                &self.root,
                &self.ack_key,
                &self.role,
                h.binding.controller_epoch,
                h.digest()?,
                frame.digest()?,
                h.issued_at,
                h.expires_at,
                peer,
            )?);
        }
        if let Some(TransportTransition::EnteredLoss(h)) =
            self.pending_epoch.as_ref().filter(|_| transition)
        {
            let peer = if self.role == "controller" {
                let peer =
                    RecoveryConsumption::read(&self.root, "loss_worker", h.binding.worker_epoch)?;
                peer.verify_window(
                    &self.ack_key,
                    &h.digest()?,
                    h.issued_at,
                    h.expires_at,
                    wall_now()?,
                )?;
                Some(Box::new(peer))
            } else {
                None
            };
            let kind = if self.role == "worker" {
                "loss_worker"
            } else {
                "loss_controller"
            };
            ack.loss_consumption = Some(RecoveryConsumption::record(
                &self.root,
                &self.ack_key,
                kind,
                h.binding.worker_epoch,
                h.digest()?,
                frame.digest()?,
                h.issued_at,
                h.expires_at,
                peer,
            )?);
        }
        self.verified_responses = verified_responses;
        if transition {
            recovery_trace(
                "P_handoff_witness_fsynced",
                serde_json::json!({"role":self.role,"revision":body.revision,"sequence":body.sequence}),
            );
            self.binding = body.binding.clone();
            self.pending_epoch = None;
        }
        self.revision = body.revision;
        self.head = frame.digest()?;
        Ok(ack)
    }
}

impl TransportJournal {
    fn validate_custody_chain(&self) -> Result<(), &'static str> {
        let Some((link, state, revision, head, _)) = &self.custody else {
            let count: i64 = self
                .db
                .query_row("SELECT COUNT(*) FROM channel_checkpoints", [], |r| r.get(0))
                .map_err(|_| "evidence_invalid")?;
            return if count == 0 {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        };
        if link.wait.lock().map_err(|_| "storage_unavailable")?.failed
            || transport_state_digest(&self.db, &self.binding)? != *state
        {
            return Err("evidence_invalid");
        }
        let mut statement=self.db.prepare("SELECT revision,length(frame),substr(frame,1,4097),length(ack),substr(ack,1,4097) FROM channel_checkpoints ORDER BY revision").map_err(|_|"evidence_invalid")?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })
            .map_err(|_| "evidence_invalid")?;
        let (genesis, epochs) = transport_epochs(&self.db)?;
        for e in &epochs {
            e.verify_history(&link.ack_key)?;
            if let TransportTransition::EnteredLoss(h) = e {
                h.installed_resolution(&self.db, &link.ack_key)?;
            }
        }
        let mut observed = 0u64;
        let mut previous = "0".repeat(64);
        for row in rows {
            let (n, length, bytes, ack_length, ack_bytes) = row.map_err(|_| "evidence_invalid")?;
            observed += 1;
            let ack_bytes = ack_bytes.ok_or("evidence_invalid")?;
            if n != observed as i64
                || observed > CHECKPOINT_MAX
                || length != bytes.len() as i64
                || bytes.len() > 4096
                || ack_length != Some(ack_bytes.len() as i64)
                || ack_bytes.len() > 4096
            {
                return Err("evidence_invalid");
            }
            let checkpoint: SignedCheckpoint =
                serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
            let b = &checkpoint.body;
            if b.binding
                != binding_in_history(genesis.clone(), &epochs, &link.role, observed, true)?
                || b.role != link.role
                || b.revision != observed
                || b.previous != previous
                || !bool::from(
                    typed_mac(&link.request_key, b"diffuser-custody-checkpoint/v1\0", b)?
                        .ct_eq(&checkpoint.mac),
                )
            {
                return Err("evidence_invalid");
            }
            let ack: CheckpointAck =
                serde_json::from_slice(&ack_bytes).map_err(|_| "evidence_invalid")?;
            ack.verify(&link.ack_key, &checkpoint)?;
            previous = checkpoint.digest()?;
        }
        if observed != *revision || previous != *head {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

impl TransportJournal {
    /// Reopening a witnessed channel requires the exact external, authenticated
    /// P checkpoint, not a row count recovered from this database. Admission is
    /// a separate guard; this never qualifies a new boot or replays an intent.
    pub(super) fn reopen_witnessed(
        root: &std::fs::File,
        path: &std::path::Path,
        name: &str,
        checkpoint: &SignedCheckpoint,
        ack: &CheckpointAck,
        link: std::sync::Arc<CustodyLink>,
    ) -> Result<Self, &'static str> {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let b = &checkpoint.body;
        let role = match name {
            "worker-channel.sqlite" => "worker",
            "controller-channel.sqlite" => "controller",
            _ => return Err("evidence_invalid"),
        };
        if !super::la_store::claim_root_matches(root, path)
            || b.binding != link.binding
            || b.role != role
            || link.role != role
            || b.revision == 0
            || b.revision > CHECKPOINT_MAX
            || b.sequence == 0
            || b.sequence > RPC_HISTORY_MAX
        {
            return Err("evidence_invalid");
        }
        ack.verify(&link.ack_key, checkpoint)?;
        let file = super::la_artifacts::open_artifact(root, name, libc::O_RDWR)
            .map_err(|_| "evidence_invalid")?;
        let r = root.metadata().map_err(|_| "evidence_invalid")?;
        let f = file.metadata().map_err(|_| "evidence_invalid")?;
        if (r.dev(), r.ino(), f.dev(), f.ino()) != (b.root_dev, b.root_inode, b.db_dev, b.db_inode)
            || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_database(root, name, false)?;
        let history_digest = checkpoint_bytes_digest(&db, b.revision, b.revision)?;
        if let Some(owned) = &b.owned_state {
            if role != "worker" || state_custody::state_digest(root)? != *owned {
                return Err("evidence_invalid");
            }
        }
        let result = Self {
            db,
            root: root.try_clone().map_err(|_| "storage_unavailable")?,
            root_path: path.into(),
            binding: b.binding.clone(),
            file,
            name: name.into(),
            owned_state: b.owned_state.is_some(),
            owned_digest: b.owned_state.clone(),
            custody: Some((
                link,
                b.state_digest.clone(),
                b.revision,
                checkpoint.digest()?,
                history_digest,
            )),
        };
        result.validate_custody_chain()?;
        result.check()?;
        let (sequence, pending): (i64, bool) = result
            .db
            .query_row(
                "SELECT sequence,response IS NULL FROM channel_log ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if sequence != b.sequence as i64 || pending != (b.phase == "intent") {
            return Err("evidence_invalid");
        }
        Ok(result)
    }
}

impl CustodyLedger {
    /// The caller supplies the last P checkpoint through protected custody. The
    /// ledger verifies every retained record against it and refuses missing,
    /// extra, reordered or changed history. It never chooses its own high-water.
    pub(super) fn reopen(
        root: &std::fs::File,
        path: &std::path::Path,
        checkpoint: &SignedCheckpoint,
        ack: &CheckpointAck,
        request_key: [u8; 32],
        ack_key: [u8; 32],
    ) -> Result<Self, &'static str> {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let body = &checkpoint.body;
        let mut result = Self::bootstrap(
            root,
            path,
            body.binding.clone(),
            &body.role,
            request_key,
            ack_key,
        )?;
        if body.revision == 0 || body.revision > CHECKPOINT_MAX {
            return Err("evidence_invalid");
        }
        ack.verify(&result.ack_key, checkpoint)?;
        let prefix = format!("{}-witness-", body.role);
        let names = std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))
            .map_err(|_| "evidence_invalid")?;
        let mut count = 0u64;
        let mut epoch_files = 0u64;
        let epoch_prefix = format!("{}-epoch-", body.role);
        let worker_epoch_prefix = format!("{}-worker-epoch-", body.role);
        for name in names {
            let name = name.map_err(|_| "evidence_invalid")?.file_name();
            if name.to_str().is_some_and(|s| {
                s.starts_with(&epoch_prefix) || s.starts_with(&worker_epoch_prefix)
            }) {
                epoch_files += 1;
                if epoch_files > 8 {
                    return Err("evidence_invalid");
                }
            }
            if name.to_str().is_some_and(|s| s.starts_with(&prefix)) {
                count += 1;
                if count > body.revision {
                    return Err("evidence_invalid");
                }
            }
        }
        if count != body.revision {
            return Err("evidence_invalid");
        }
        let mut transitions = 0u64;
        let mut previous_frame: Option<SignedCheckpoint> = None;
        for revision in 1..=body.revision {
            let name = format!("{}-witness-{revision:04}.json", body.role);
            let mut bytes = Vec::new();
            let record = super::la_artifacts::open_artifact(root, &name, libc::O_RDONLY)
                .map_err(|_| "evidence_invalid")?;
            use std::os::unix::fs::MetadataExt;
            let meta = record.metadata().map_err(|_| "evidence_invalid")?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o777 != 0o600
                || meta.len() > 4096
            {
                return Err("evidence_invalid");
            }
            record
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| "evidence_invalid")?;
            if bytes.len() > 4096 {
                return Err("evidence_invalid");
            }
            let frame: SignedCheckpoint =
                serde_json::from_slice(&super::la_contract::canonical_json(&bytes)?)
                    .map_err(|_| "evidence_invalid")?;
            let b = &frame.body;
            if revision == 1 {
                result.binding = b.binding.clone();
            }
            if b.binding != result.binding {
                let worker_transition = b.binding.worker_epoch != result.binding.worker_epoch;
                let name = if worker_transition {
                    format!(
                        "{}-worker-epoch-{:04}.json",
                        body.role, b.binding.worker_epoch
                    )
                } else {
                    format!("{}-epoch-{:04}.json", body.role, b.binding.controller_epoch)
                };
                let mut bytes = Vec::new();
                let file = super::la_artifacts::open_artifact(root, &name, libc::O_RDONLY)
                    .map_err(|_| "evidence_invalid")?;
                let meta = file.metadata().map_err(|_| "evidence_invalid")?;
                if !meta.is_file()
                    || meta.nlink() != 1
                    || meta.uid() != unsafe { libc::geteuid() }
                    || meta.mode() & 0o777 != 0o600
                    || meta.len() > 12288
                {
                    return Err("evidence_invalid");
                }
                file.take(12289)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "evidence_invalid")?;
                let canonical = super::la_contract::canonical_json(&bytes)?;
                let epoch = if worker_transition {
                    parse_worker_transition(&canonical)?
                } else {
                    TransportTransition::Controller(Box::new(
                        serde_json::from_slice(&canonical).map_err(|_| "evidence_invalid")?,
                    ))
                };
                epoch.verify_history(&ack_key)?;
                let (anchor, _, _, _) = epoch.anchor(&body.role)?;
                if b.phase != "handoff"
                    || *epoch.previous() != result.binding
                    || *epoch.binding() != b.binding
                    || b.sequence != epoch.install_sequence(&body.role)?
                    || b.revision != anchor.body.revision + 1
                    || anchor.digest()? != result.head
                    || previous_frame
                        .as_ref()
                        .ok_or("evidence_invalid")?
                        .digest()?
                        != anchor.digest()?
                {
                    return Err("evidence_invalid");
                }
                result.binding = b.binding.clone();
                transitions += 1;
            } else if b.phase == "handoff" {
                return Err("evidence_invalid");
            }
            if b.binding != result.binding
                || b.role != body.role
                || b.revision != revision
                || b.previous != result.head
                || !bool::from(
                    typed_mac(&result.request_key, b"diffuser-custody-checkpoint/v1\0", b)?
                        .ct_eq(&frame.mac),
                )
            {
                return Err("evidence_invalid");
            }
            if result.owned_state.is_some() && b.owned_state.is_none() {
                return Err("evidence_invalid");
            }
            result.owned_state = b.owned_state.clone();
            result.revision = revision;
            result.head = frame.digest()?;
            previous_frame = Some(frame);
        }
        if result.head != checkpoint.digest()?
            || result.binding != body.binding
            || epoch_files != transitions
        {
            return Err("evidence_invalid");
        }
        Ok(result)
    }
}

// Cache only an authenticated byte fingerprint. Every subsequent mutation still
// hashes every retained frame and ACK, and checks the old prefix after append.
// New rows verify their MACs at creation; recovery verifies the complete chain.
type JournalCustodyState = (std::sync::Arc<CustodyLink>, String, u64, String, String);
fn checkpoint_history_digests(
    db: &rusqlite::Connection,
    expected: u64,
    prefix: u64,
) -> Result<(String, String), &'static str> {
    if prefix > expected || expected > CHECKPOINT_MAX {
        return Err("evidence_invalid");
    }
    let mut hash = Sha256::new();
    hash.update(b"diffuser-custody-bytes/v2\0");
    let mut prefix_hash = if prefix == 0 {
        Some(hash.clone())
    } else {
        None
    };
    let mut statement=db.prepare("SELECT revision,length(frame),substr(frame,1,4097),length(ack),substr(ack,1,4097) FROM channel_checkpoints ORDER BY revision").map_err(|_|"evidence_invalid")?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })
        .map_err(|_| "evidence_invalid")?;
    let mut count = 0u64;
    for row in rows {
        let (revision, length, frame, ack_length, ack) = row.map_err(|_| "evidence_invalid")?;
        count += 1;
        let ack = ack.ok_or("evidence_invalid")?;
        if revision != count as i64
            || count > expected
            || length != frame.len() as i64
            || frame.len() > 4096
            || ack_length != Some(ack.len() as i64)
            || ack.len() > 4096
        {
            return Err("evidence_invalid");
        }
        {
            hash.update(count.to_be_bytes());
            hash.update((frame.len() as u64).to_be_bytes());
            hash.update(frame);
            hash.update((ack.len() as u64).to_be_bytes());
            hash.update(ack);
        }
        if count == prefix {
            prefix_hash = Some(hash.clone());
        }
    }
    if count != expected {
        return Err("evidence_invalid");
    }
    let mut prefix_hash = prefix_hash.ok_or("evidence_invalid")?;
    prefix_hash.update(prefix.to_be_bytes());
    hash.update(expected.to_be_bytes());
    Ok((
        hex::encode(prefix_hash.finalize()),
        hex::encode(hash.finalize()),
    ))
}
fn checkpoint_bytes_digest(
    db: &rusqlite::Connection,
    expected: u64,
    prefix: u64,
) -> Result<String, &'static str> {
    checkpoint_history_digests(db, expected, prefix).map(|v| v.0)
}

impl TransportJournal {
    fn check_custody(&self) -> Result<(), &'static str> {
        let Some((link, state, revision, _, history)) = &self.custody else {
            let count: i64 = self
                .db
                .query_row("SELECT COUNT(*) FROM channel_checkpoints", [], |r| r.get(0))
                .map_err(|_| "evidence_invalid")?;
            return if count == 0 {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        };
        if link.wait.lock().map_err(|_| "storage_unavailable")?.failed
            || transport_state_digest(&self.db, &self.binding)? != *state
            || checkpoint_bytes_digest(&self.db, *revision, *revision)? != *history
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

/// Resource qualification is a separate, protected proof. It does not grant
/// caller authority, activate a writer epoch, or assert safe capacity release.
/// Only P's read-only fixture evidence root can construct this opaque value.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) mod qualification {
    use super::{typed_mac, ChannelBinding, ChannelKeys};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::File,
        io::Read,
        os::{fd::AsRawFd, unix::fs::MetadataExt},
    };
    use subtle::ConstantTimeEq;
    const CASES: [&str; 9] = [
        "normal",
        "cpu",
        "memory",
        "storage",
        "eof",
        "pdeath",
        "hostdeath",
        "custodyloss",
        "authorityrace",
    ];
    const POLICY: &str = "8d5f303f78726f9283c7666c7a6e339a5098459500ac9e94d9c30316e2bd714e";
    fn require(value: bool) -> Result<(), &'static str> {
        if value {
            Ok(())
        } else {
            Err("evidence_invalid")
        }
    }
    fn digest(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn number(v: &Value) -> Result<u64, &'static str> {
        v.as_u64().ok_or("evidence_invalid")
    }
    fn string(v: &Value) -> Result<&str, &'static str> {
        v.as_str().ok_or("evidence_invalid")
    }
    fn counter(s: &str, key: &str) -> Result<u64, &'static str> {
        let mut values = s
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{key} ")));
        let n = values
            .next()
            .ok_or("evidence_invalid")?
            .parse()
            .map_err(|_| "evidence_invalid")?;
        require(values.next().is_none())?;
        Ok(n)
    }
    fn status(s: &str, key: &str) -> Result<u64, &'static str> {
        let mut values = s.lines().filter_map(|line| line.strip_prefix(key));
        let n = values
            .next()
            .and_then(|s| s.split_whitespace().next())
            .ok_or("evidence_invalid")?
            .parse()
            .map_err(|_| "evidence_invalid")?;
        require(values.next().is_none())?;
        Ok(n)
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Index {
        version: u32,
        source_digest: String,
        executable_digest: String,
        files: BTreeMap<String, String>,
    }
    pub(in crate::cosp) struct VerifiedResourceFamily {
        source: String,
        executable: String,
        evidence: String,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        version: u32,
        binding: ChannelBinding,
        evidence: String,
        issued_at: u64,
        expires_at: u64,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Certificate {
        body: Body,
        mac: [u8; 32],
    }
    struct Evidence {
        files: BTreeMap<String, Vec<u8>>,
    }
    impl Evidence {
        fn bytes(&self, case: &str, name: &str) -> Result<&[u8], &'static str> {
            self.files
                .get(&format!("{case}.{name}"))
                .map(Vec::as_slice)
                .ok_or("evidence_invalid")
        }
        fn json(&self, case: &str, name: &str) -> Result<Value, &'static str> {
            let bytes = super::super::la_contract::canonical_json(self.bytes(case, name)?)?;
            serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")
        }
        fn text(&self, case: &str, name: &str) -> Result<&str, &'static str> {
            std::str::from_utf8(self.bytes(case, name)?).map_err(|_| "evidence_invalid")
        }
    }
    fn read(root: &File, name: &str) -> Result<Vec<u8>, &'static str> {
        require(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        )?;
        let f = super::super::la_artifacts::open_artifact(root, name, libc::O_RDONLY)
            .map_err(|_| "evidence_invalid")?;
        let m = f.metadata().map_err(|_| "evidence_invalid")?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o222 == 0
                && m.len() <= 1048576,
        )?;
        let mut bytes = Vec::new();
        f.take(1048577)
            .read_to_end(&mut bytes)
            .map_err(|_| "evidence_invalid")?;
        require(bytes.len() as u64 == m.len())?;
        Ok(bytes)
    }
    pub(super) fn snapshot(
        v: &Value,
        role: &str,
        executable: &str,
        initial: bool,
        root_dev: Option<u64>,
    ) -> Result<(), &'static str> {
        let limits = &v["limits"];
        let (cpu, memory, pids) = match role {
            "p" => ("100000 100000", 268435456u64, 64u64),
            "k" => ("25000 100000", 134217728, 16),
            "w" | "c" => ("100000 100000", 536870912, 64),
            _ => return Err("evidence_invalid"),
        };
        require(
            limits["cpu.max"] == cpu
                && limits["memory.max"]
                    == match role {
                        "p" => "268435456",
                        "k" => "134217728",
                        _ => "536870912",
                    }
                && limits["memory.swap.max"] == "0"
                && limits["pids.max"] == if role == "k" { "16" } else { "64" },
        )?;
        for (key, max) in [
            ("memory.current", memory),
            ("memory.peak", memory),
            ("pids.current", pids),
        ] {
            let value = string(&limits[key])?
                .parse::<u64>()
                .map_err(|_| "evidence_invalid")?;
            require(value > 0 && value <= max)?;
        }
        let identity = &v["identity"];
        require(
            number(&identity["pid"])? > 0
                && string(&identity["starttime"])?
                    .parse::<u64>()
                    .map_err(|_| "evidence_invalid")?
                    > 0,
        )?;
        let cg = string(&identity["cgroup"])?;
        require(
            cg.trim().starts_with("0::/user.slice/user-1000.slice/")
                && cg.trim().ends_with(".scope"),
        )?;
        let processes: BTreeSet<u64> = string(&limits["cgroup.procs"])?
            .lines()
            .map(|s| s.parse().map_err(|_| "evidence_invalid"))
            .collect::<Result<_, _>>()?;
        let mut members = BTreeSet::new();
        for m in v["members"].as_array().ok_or("evidence_invalid")? {
            require(
                m["cgroup"] == identity["cgroup"]
                    && digest(string(&m["sha256"])?)
                    && string(&m["starttime"])?
                        .parse::<u64>()
                        .map_err(|_| "evidence_invalid")?
                        > 0
                    && members.insert(number(&m["pid"])?),
            )?;
        }
        require(
            !members.is_empty()
                && members == processes
                && members.contains(&number(&identity["pid"])?),
        )?;
        let rlimits = string(&v["rlimits"])?;
        for (prefix, expected) in [
            ("Max file size ", vec!["1048576", "1048576", "bytes"]),
            ("Max core file size ", vec!["0", "0", "bytes"]),
        ] {
            let tail = rlimits
                .lines()
                .find_map(|s| s.strip_prefix(prefix))
                .ok_or("evidence_invalid")?;
            require(tail.split_whitespace().collect::<Vec<_>>() == expected)?;
        }
        if matches!(role, "w" | "c") {
            require(identity["sha256"] == executable && identity["exe"] == "/worker-test")?;
            let root = if role == "w" {
                "/job/workerroot"
            } else {
                "/job/service"
            };
            require(bounded_child_mounts(
                string(&v["mountinfo"])?,
                root,
                root_dev,
            ))?;
            if initial {
                let fds: BTreeSet<&str> = v["fds"]
                    .as_array()
                    .ok_or("evidence_invalid")?
                    .iter()
                    .map(|f| string(&f["fd"]))
                    .collect::<Result<_, _>>()?;
                require(fds == BTreeSet::from(["0", "1", "2"]))?;
            } else {
                require(bounded_child_fds(
                    v,
                    root,
                    root_dev.ok_or("evidence_invalid")?,
                ))?;
                let s = string(&v["status"])?;
                let rss = status(s, "VmRSS:")?;
                let hwm = status(s, "VmHWM:")?;
                require(
                    rss > 0
                        && hwm >= rss
                        && hwm <= memory / 1024
                        && (1..=pids).contains(&status(s, "Threads:")?),
                )?;
            }
        }
        Ok(())
    }
    fn manager(e: &Evidence, case: &str, role: &str) -> Result<(), &'static str> {
        let s = e.text(case, &format!("MANAGER-{role}.txt"))?;
        for required in [
            "Delegate=no",
            "OOMPolicy=stop",
            "KillMode=control-group",
            "SendSIGKILL=yes",
            "RuntimeMaxUSec=1min",
            "TimeoutStopUSec=2s",
        ] {
            require(s.lines().filter(|line| *line == required).count() == 1)?;
        }
        Ok(())
    }
    fn cleanup(e: &Evidence, case: &str) -> Result<(), &'static str> {
        let c = e.json(case, "CLEANUP.json")?;
        require(c["verified"] == true)?;
        let states = c["states"].as_object().ok_or("evidence_invalid")?;
        require(!states.is_empty() && states.len() <= 16)?;
        for state in states.values() {
            require(string(state)?.lines().any(|s| s == "ActiveState=inactive"))?;
        }
        let groups = c["groups"].as_object().ok_or("evidence_invalid")?;
        require(!groups.is_empty())?;
        for state in groups.values() {
            let s = string(state)?;
            require(s == "removed" || s.lines().any(|s| s == "populated 0"))?;
        }
        let i = e.json(case, "IDENTITY-CLEANUP.json")?;
        require(i["verified"] == true)?;
        let observed = i["observed"].as_array().ok_or("evidence_invalid")?;
        require(!observed.is_empty() && observed.len() <= 128)?;
        for item in observed {
            require(item["same_identity_alive"] == false)?;
        }
        Ok(())
    }
    impl VerifiedResourceFamily {
        /// The root must be supplied by P's protected fixture custody, mounted
        /// read-only. A caller path or downloaded receipt is never accepted.
        pub(in crate::cosp) fn inspect(
            root: &File,
            source: &str,
            executable: &str,
        ) -> Result<Self, &'static str> {
            require(digest(source) && digest(executable))?;
            let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            require(unsafe { libc::fstatvfs(root.as_raw_fd(), stat.as_mut_ptr()) } == 0)?;
            let stat = unsafe { stat.assume_init() };
            require(stat.f_flag & libc::ST_RDONLY != 0)?;
            let index_bytes = read(root, "qualification-index.json")?;
            let index: Index =
                serde_json::from_slice(&super::super::la_contract::canonical_json(&index_bytes)?)
                    .map_err(|_| "evidence_invalid")?;
            require(
                index.version == 1
                    && index.source_digest == source
                    && index.executable_digest == executable
                    && !index.files.is_empty()
                    && index.files.len() <= 256,
            )?;
            let mut files = BTreeMap::new();
            let mut total = 0u64;
            for (name, hash) in &index.files {
                require(digest(hash))?;
                let bytes = read(root, name)?;
                total = total
                    .checked_add(bytes.len() as u64)
                    .ok_or("evidence_invalid")?;
                require(total <= 33554432 && hex::encode(Sha256::digest(&bytes)) == *hash)?;
                files.insert(name.clone(), bytes);
            }
            let e = Evidence { files };
            for case in CASES {
                require(e.json(case, "SCENARIO.json")?["scenario"] == case)?;
                let input = e.json(case, "INPUTS.json")?;
                require(
                    input["before"] == executable
                        && input["after"] == executable
                        && input["copied"] == executable,
                )?;
                require(e.json(case, "SOURCE-IDENTITY.json")?["source_digest"] == source)?;
                cleanup(&e, case)?;
                for role in ["p", "k", "w"] {
                    let initial =
                        e.json(case, &format!("{}-SNAPSHOT.json", role.to_uppercase()))?;
                    snapshot(&initial, role, executable, role == "w", None)?;
                    manager(&e, case, role)?;
                }
                let outer = e.json(case, "OUTER.json")?;
                let rc = outer["rc"].as_i64().ok_or("evidence_invalid")?;
                require(
                    if matches!(
                        case,
                        "normal" | "cpu" | "memory" | "storage" | "authorityrace"
                    ) {
                        rc == 0
                    } else {
                        rc != 0
                    },
                )?;
                let outputs = e.json(case, "OUTPUT-BOUNDS.json")?;
                require(
                    number(&outputs["stdout_bytes"])? <= 1048576
                        && number(&outputs["stderr_bytes"])? <= 1048576
                        && number(&outputs["evidence_bytes"])? <= 33554432
                        && number(&outputs["runtime_ms"])? <= 75000,
                )?;
            }
            for case in ["normal", "storage", "authorityrace"] {
                let result = e.json(case, "CLIENT-RESULT.json")?;
                require(
                    result["status"] == "READY_200_401_STOPPED"
                        && result["ordinary_p"] == true
                        && result["admitted_jobs"] == 0
                        && result["capacity_custody"] == 16777216
                        && result["capacity_evidence"] == 33554432
                        && result["good_status"] == 200
                        && result["bad_status"] == 401,
                )?;
                let wr = e.json(case, "P-EVIDENCE-worker-ready.json")?;
                let cr = e.json(case, "P-EVIDENCE-controller-ready.json")?;
                for ready in [&wr, &cr] {
                    require(
                        ready["executable_sha256"] == executable
                            && ready["policy_digest"] == POLICY
                            && ready["process_seal"]["fork_errno"] == libc::EPERM
                            && ready["process_seal"]["exec_errno"] == libc::EPERM
                            && ready["process_seal"]["unshare_errno"] == libc::EPERM
                            && ready["process_seal"]["no_new_privs"] == 1
                            && number(&ready["smoke_input_bytes"])? > 0
                            && number(&ready["smoke_output_bytes"])? <= 4096
                            && digest(string(&ready["smoke_input_sha256"])?)
                            && digest(string(&ready["smoke_output_sha256"])?),
                    )?;
                }
                for (role, ready) in [("w", &wr), ("c", &cr)] {
                    let live = e.json(case, &format!("{}-OBSERVED.json", role.to_uppercase()))?;
                    snapshot(
                        &live,
                        role,
                        executable,
                        false,
                        Some(number(&ready["root_dev"])?),
                    )?;
                    manager(&e, case, role)?;
                }
                let parent = e.json(case, "P-OBSERVED.json")?;
                let fddev = |path: &str| -> Result<u64, &'static str> {
                    let f = parent["fds"]
                        .as_array()
                        .ok_or("evidence_invalid")?
                        .iter()
                        .find(|f| f["target"] == path)
                        .ok_or("evidence_invalid")?;
                    number(&f["dev"])
                };
                let cdev = fddev("/job/custody")?;
                let edev = fddev("/job/evidence")?;
                require(bounded_parent_mounts(
                    string(&parent["mountinfo"])?,
                    cdev,
                    edev,
                ))?;
                let roots = [
                    (cdev, fdinode(&parent, "/job/custody")?),
                    (edev, fdinode(&parent, "/job/evidence")?),
                    (number(&wr["root_dev"])?, number(&wr["root_inode"])?),
                    (number(&cr["root_dev"])?, number(&cr["root_inode"])?),
                ];
                let start = e.json(case, "P-SNAPSHOT.json")?;
                require(bounded_parent_fds(&start["fds"], &parent["fds"], &roots))?;
                let seal = e.json(case, "P-EVIDENCE-p-process-seal.json")?;
                require(
                    seal["fork_errno"] == libc::EPERM
                        && seal["exec_errno"] == libc::EPERM
                        && seal["unshare_errno"] == libc::EPERM,
                )?;
                let before = e.json(case, "K-SNAPSHOT.json")?;
                let after = e.json(case, "K-AFTER-W-KILL.json")?;
                require(
                    before["identity"] == after["identity"]
                        && result["ready"]["root_dev"] == result["recovery_ready"]["root_dev"]
                        && result["ready"]["root_inode"] == result["recovery_ready"]["root_inode"],
                )?;
                let manifest = e.json(case, "P-EVIDENCE-worker-preopen-manifest.json")?;
                let entries = manifest.as_array().ok_or("evidence_invalid")?;
                require(!entries.is_empty() && entries.len() <= 256)?;
                for f in entries {
                    require(
                        number(&f["dev"])? == number(&wr["root_dev"])?
                            && number(&f["inode"])? > 0
                            && number(&f["size"])? <= 1048576
                            && digest(string(&f["sha256"])?),
                    )?;
                }
            }
            let cpu = e.json("cpu", "CLIENT-RESULT.json")?;
            let elapsed = number(&cpu["elapsed_us"])?;
            let usage = number(&cpu["cpu_usage_us"])?;
            require(
                cpu["status"] == "CPU_PROBE_STOPPED"
                    && usage > 200000
                    && usage as u128 <= elapsed as u128 * 13 / 10
                    && number(&cpu["throttled_periods"])? > 0
                    && number(&cpu["stop_elapsed_us"])? < 2000000
                    && cpu["stopped"]["fixture_pressure_threads_joined"] == 4
                    && cpu["stopped"]["fixture_pressure_timer_stops"] == 4
                    && cpu["stopped"]["fixture_pressure_timer_expired"] == true,
            )?;
            let oom = e.json("memory", "CLIENT-RESULT.json")?;
            require(oom["status"] == "OOM_PROBE_KILLED")?;
            let outcome = &oom["outcome"];
            for key in ["oom", "oom_kill", "max"] {
                let before = counter(string(&outcome["before"])?, key)?;
                let after = counter(string(&outcome["after"])?, key)?;
                require(after > before)?;
            }
            let keeper = e.json("memory", "K-SNAPSHOT.json")?;
            let after = e.json("memory", "K-AFTER-W-OOM.json")?;
            require(keeper["identity"] == after["identity"])?;
            let storage = e.json("storage", "CLIENT-RESULT.json")?;
            let s = &storage["storage_probe"];
            for (key, n) in [
                ("kernel_errno", 28),
                ("failed_row_count", 0),
                ("retained_start_count", 1),
                ("retained_jobs", 32),
                ("retained_inputs", 32),
                ("retained_outputs", 32),
                ("retained_assignments", 8),
                ("fixture_files_freed", 3),
            ] {
                require(s[key] == n)?;
            }
            require(
                s["sqlite_error"] == "SQLITE_FULL"
                    && s["reopen_integrity"] == "ok"
                    && s["ninth_assignment_refused"] == true
                    && s["thirty_third_job_refused"] == true,
            )?;
            let c = e.json("storage", "P-EVIDENCE-controller-ready.json")?;
            require(
                c["transport_probe"]["sequence"] == 161
                    && c["transport_probe"]["live_custody"] == true
                    && c["storage_probe"]["input_versions"] == 32
                    && c["storage_probe"]["output_versions"] == 32
                    && c["storage_probe"]["input_overflow_refused"] == true
                    && c["storage_probe"]["output_overflow_refused"] == true
                    && c["storage_probe"]["all_bytes_read_back"] == true,
            )?;
            for role in ["worker", "controller"] {
                let transcript =
                    e.text("storage", &format!("P-EVIDENCE-{role}-live-custody.jsonl"))?;
                require(transcript.lines().count() == 322)?;
                for (i, line) in transcript.lines().enumerate() {
                    let v: Value = serde_json::from_slice(
                        &super::super::la_contract::canonical_json(line.as_bytes())?,
                    )
                    .map_err(|_| "evidence_invalid")?;
                    require(
                        v["checkpoint"]["body"]["revision"] == (i + 1) as u64
                            && v["checkpoint"]["body"]["role"] == role
                            && v["ack"]["revision"] == (i + 1) as u64
                            && v["independent_root_read"] == true
                            && v["parent_fsynced_before_ack"] == true,
                    )?;
                }
            }
            let worker_history = e.text("storage", "P-EVIDENCE-worker-live-custody.jsonl")?;
            let last: Value =
                serde_json::from_str(worker_history.lines().last().ok_or("evidence_invalid")?)
                    .map_err(|_| "evidence_invalid")?;
            require(
                digest(string(&last["checkpoint"]["body"]["owned_state"])?)
                    && last["checkpoint"]["body"]["sequence"] == 161,
            )?;
            let state_history = e.text("storage", "P-EVIDENCE-service-state-custody.jsonl")?;
            let mut count = 0u64;
            for line in state_history.lines() {
                count += 1;
                let entry: Value = serde_json::from_slice(
                    &super::super::la_contract::canonical_json(line.as_bytes())?,
                )
                .map_err(|_| "evidence_invalid")?;
                require(
                    entry["checkpoint"]["body"]["revision"] == count
                        && entry["ack"]["revision"] == count
                        && entry["checkpoint"]["body"]["binding"]["source_digest"] == source
                        && digest(string(&entry["checkpoint"]["body"]["state_digest"])?)
                        && entry["independent_root_read"] == true
                        && entry["parent_fsynced_before_ack"] == true,
                )?;
            }
            require(count >= 5)?;
            require(e.json("eof", "P-EOF-OBSERVED.json")?["p_alive_at_eof"] == true)?;
            for (case, name) in [
                ("pdeath", "P-DEATH-INJECTED.json"),
                ("hostdeath", "HOST-DEATH-INJECTED.json"),
            ] {
                let v = e.json(case, name)?;
                require(
                    v["signal"] == 9 && number(&v["pid"])? > 0 && digest(string(&v["sha256"])?),
                )?;
            }
            for role in ["worker", "controller"] {
                let v = e.json(
                    "authorityrace",
                    &format!("P-EVIDENCE-{role}-authority-race-ack.json"),
                )?;
                require(
                    v["kind"] == "AUTHORITY_ACK"
                        && v["ack"]["role"] == role
                        && v["ack"]["sequence"] == 1,
                )?;
            }
            require(
                e.text("custodyloss", "client.stdout")?
                    .contains("\"kind\":\"CUSTODY_ACK_WITHHELD\""),
            )?;
            Ok(Self {
                source: source.into(),
                executable: executable.into(),
                evidence: hex::encode(Sha256::digest(index_bytes)),
            })
        }
        pub(in crate::cosp) fn seal(
            &self,
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            now: u64,
            expires: u64,
        ) -> Result<Certificate, &'static str> {
            #[cfg(test)]
            super::recovery_trace(
                "resource_factory_actual_guards",
                serde_json::json!({"now":now,"expires_at":expires,
                    "binding_valid":binding.validate().is_ok(),
                    "source_matches":binding.source_digest==self.source,
                    "executable_matches":binding.executable_digest==self.executable,
                    "policy_matches":binding.policy_digest==POLICY,
                    "now_positive":now>0,"expires_after_now":expires>now,
                    "duration_within_60000":expires>=now && expires-now<=60000}),
            );
            binding.validate()?;
            require(
                binding.source_digest == self.source
                    && binding.executable_digest == self.executable
                    && binding.policy_digest == POLICY
                    && now > 0
                    && expires > now
                    && expires - now <= 60000,
            )?;
            let body = Body {
                version: 1,
                binding: binding.clone(),
                evidence: self.evidence.clone(),
                issued_at: now,
                expires_at: expires,
            };
            let mac = typed_mac(
                &keys.custody,
                b"diffuser-resource-qualification/v1\0",
                &body,
            )?;
            Ok(Certificate { body, mac })
        }
    }
    fn fdinode(v: &Value, path: &str) -> Result<u64, &'static str> {
        number(
            &v["fds"]
                .as_array()
                .ok_or("evidence_invalid")?
                .iter()
                .find(|f| f["target"] == path)
                .ok_or("evidence_invalid")?["inode"],
        )
    }
    impl Certificate {
        pub(in crate::cosp) fn expires_at(&self) -> u64 {
            self.body.expires_at
        }

        pub(in crate::cosp) fn verify(
            &self,
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            now: u64,
        ) -> Result<(), &'static str> {
            require(
                self.body.version == 1
                    && self.body.binding == *binding
                    && digest(&self.body.evidence)
                    && self.body.issued_at <= now
                    && now < self.body.expires_at
                    && self.body.expires_at - self.body.issued_at <= 60000
                    && bool::from(
                        typed_mac(
                            &keys.custody,
                            b"diffuser-resource-qualification/v1\0",
                            &self.body,
                        )?
                        .ct_eq(&self.mac),
                    ),
            )
        }
        pub(in crate::cosp) fn evidence_digest(&self) -> &str {
            &self.body.evidence
        }
    }
    pub(super) fn bounded_child_fds(
        snapshot: &serde_json::Value,
        root: &str,
        root_dev: u64,
    ) -> bool {
        let Some(entries) = snapshot["fds"].as_array() else {
            return false;
        };
        if entries.is_empty() {
            return false;
        }
        entries.iter().all(|entry| {
            let Some(target) = entry["target"].as_str() else {
                return false;
            };
            let Some(mode) = entry["mode"].as_u64() else {
                return false;
            };
            let Some(info) = entry["info"].as_str() else {
                return false;
            };
            let Some(_flags) = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:\t"))
                .and_then(|value| u64::from_str_radix(value.trim(), 8).ok())
            else {
                return false;
            };
            match mode & libc::S_IFMT as u64 {
                // Even a read-only file can potentially be reopened via procfs.
                kind if kind == libc::S_IFREG as u64 => {
                    entry["dev"].as_u64() == Some(root_dev)
                        && target
                            .strip_prefix(root)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                        && !target.ends_with(" (deleted)")
                }
                kind if kind == libc::S_IFDIR as u64 => {
                    // Read-only directory handles can still be used with openat.
                    entry["dev"].as_u64() == Some(root_dev)
                        && (target == root
                            || target
                                .strip_prefix(root)
                                .is_some_and(|suffix| suffix.starts_with('/')))
                }
                kind if kind == libc::S_IFCHR as u64 => target == "/dev/null",
                kind if kind == libc::S_IFIFO as u64 || kind == libc::S_IFSOCK as u64 => true,
                0 => matches!(target, "anon_inode:[eventpoll]" | "anon_inode:[eventfd]"),
                _ => false,
            }
        })
    }
    pub(super) fn bounded_child_mounts(mounts: &str, root: &str, root_dev: Option<u64>) -> bool {
        let mut saw_root = false;
        let mut saw_proc = false;
        let mut saw_owned = false;
        for line in mounts.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                return false;
            };
            let fields: Vec<_> = left.split_whitespace().collect();
            let fs: Vec<_> = right.split_whitespace().collect();
            if fields.len() < 6 || fs.len() < 3 || fs[0] == "autofs" {
                return false;
            }
            let rw = fields[5].split(',').any(|option| option == "rw");
            let ro = fields[5].split(',').any(|option| option == "ro");
            if rw == ro {
                return false;
            }
            match fields[4] {
                "/" => {
                    if saw_root || !ro {
                        return false;
                    }
                    saw_root = true;
                }
                "/proc" => {
                    if saw_proc || !ro || fs[0] != "proc" {
                        return false;
                    }
                    saw_proc = true;
                }
                path if path == root => {
                    if saw_owned || !rw || fs[0] != "tmpfs" || fields[3] != "/" {
                        return false;
                    }
                    if let Some(dev) = root_dev {
                        let expected = format!("{}:{}", libc::major(dev), libc::minor(dev));
                        if fields[2] != expected {
                            return false;
                        }
                    }
                    if !fs[2].split(',').any(|option| option == "size=65536k") {
                        return false;
                    }
                    saw_owned = true;
                }
                "/dev/null" if rw => (),
                _ if rw => return false,
                _ => (),
            }
        }
        saw_root && saw_proc && saw_owned
    }
    pub(super) fn bounded_parent_mounts(mounts: &str, custody_dev: u64, evidence_dev: u64) -> bool {
        if custody_dev == evidence_dev {
            return false;
        }
        let mut root = false;
        let mut proc = false;
        let mut owned = [false; 2];
        for line in mounts.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                return false;
            };
            let fields: Vec<_> = left.split_whitespace().collect();
            let fs: Vec<_> = right.split_whitespace().collect();
            if fields.len() < 6 || fs.len() < 3 || fs[0] == "autofs" {
                return false;
            }
            let rw = fields[5].split(',').any(|v| v == "rw");
            let ro = fields[5].split(',').any(|v| v == "ro");
            if rw == ro {
                return false;
            }
            match fields[4] {
                "/" => {
                    if root || !ro {
                        return false;
                    }
                    root = true;
                }
                "/proc" => {
                    if proc || !ro || fs[0] != "proc" {
                        return false;
                    }
                    proc = true;
                }
                "/job/custody" | "/job/evidence" => {
                    let (i, dev) = if fields[4] == "/job/custody" {
                        (0, custody_dev)
                    } else {
                        (1, evidence_dev)
                    };
                    if owned[i]
                        || !rw
                        || fs[0] != "tmpfs"
                        || fields[3] != "/"
                        || fields[2] != format!("{}:{}", libc::major(dev), libc::minor(dev))
                    {
                        return false;
                    }
                    let size = if i == 0 { "size=16384k" } else { "size=32768k" };
                    if !fs[2].split(',').any(|option| option == size) {
                        return false;
                    }
                    owned[i] = true;
                }
                "/dev/null" if rw => (),
                _ if rw => return false,
                _ => (),
            }
        }
        root && proc && owned.into_iter().all(|value| value)
    }
    pub(super) fn bounded_parent_fds(
        initial: &serde_json::Value,
        current: &serde_json::Value,
        roots: &[(u64, u64)],
    ) -> bool {
        let (Some(before), Some(after)) = (initial.as_array(), current.as_array()) else {
            return false;
        };
        for fd in ["0", "1", "2", "3"] {
            let Some(first) = before.iter().find(|item| item["fd"] == fd) else {
                return false;
            };
            let Some(last) = after.iter().find(|item| item["fd"] == fd) else {
                return false;
            };
            if ["target", "mode", "dev", "inode"]
                .iter()
                .any(|field| first[*field] != last[*field])
            {
                return false;
            }
            let flags = |entry: &serde_json::Value| {
                entry["info"]
                    .as_str()
                    .and_then(|info| info.lines().find_map(|line| line.strip_prefix("flags:\t")))
                    .map(str::to_owned)
            };
            if flags(first).is_none() || flags(first) != flags(last) {
                return false;
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for item in after {
            let (Some(fd), Some(mode), Some(dev), Some(inode), Some(info)) = (
                item["fd"].as_str(),
                item["mode"].as_u64(),
                item["dev"].as_u64(),
                item["inode"].as_u64(),
                item["info"].as_str(),
            ) else {
                return false;
            };
            if !seen.insert(fd) {
                return false;
            }
            if ["0", "1", "2", "3"].contains(&fd) {
                continue;
            }
            let Some(flags) = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:\t"))
                .and_then(|v| u64::from_str_radix(v.trim(), 8).ok())
            else {
                return false;
            };
            match mode & libc::S_IFMT as u64 {
                kind if kind == libc::S_IFDIR as u64
                    && roots.contains(&(dev, inode))
                    && flags & 3 == 0 => {}
                kind if kind == libc::S_IFIFO as u64 => (),
                _ => return false,
            }
        }
        true
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn binding() -> ChannelBinding {
            ChannelBinding {
                worker: "worker_cpu_000001".into(),
                worker_boot: "a".repeat(64),
                controller_boot: "b".repeat(64),
                worker_epoch: 1,
                controller_epoch: 1,
                hardware_generation: 1,
                profile_epoch: 1,
                policy_digest: POLICY.into(),
                source_digest: "c".repeat(64),
                executable_digest: "d".repeat(64),
            }
        }
        fn keys() -> ChannelKeys {
            ChannelKeys::from_protected_hex(
                &"1".repeat(64),
                &"2".repeat(64),
                &"3".repeat(64),
                &"4".repeat(64),
            )
            .unwrap()
        }
        #[test]
        fn certificate_binds_identity_custody_key_and_exact_expiry_without_admission() {
            // Synthetic C codec evidence only. Runtime issuance must inspect
            // the entire independently supplied protected resource family.
            let b = binding();
            let k = keys();
            let family = VerifiedResourceFamily {
                source: b.source_digest.clone(),
                executable: b.executable_digest.clone(),
                evidence: "e".repeat(64),
            };
            let certificate = family.seal(&b, &k, 1000, 2500).unwrap();
            assert_eq!(certificate.verify(&b, &k, 1000), Ok(()));
            assert_eq!(certificate.verify(&b, &k, 2499), Ok(()));
            for now in [999, 2500, 2501] {
                assert!(certificate.verify(&b, &k, now).is_err());
            }
            let mut wrong = b.clone();
            wrong.worker_boot = "f".repeat(64);
            assert!(certificate.verify(&wrong, &k, 1001).is_err());
            wrong = b.clone();
            wrong.controller_epoch += 1;
            assert!(certificate.verify(&wrong, &k, 1001).is_err());
            wrong = b.clone();
            wrong.source_digest = "f".repeat(64);
            assert!(family.seal(&wrong, &k, 1000, 2500).is_err());
            let other = ChannelKeys::from_protected_hex(
                &"1".repeat(64),
                &"2".repeat(64),
                &"3".repeat(64),
                &"5".repeat(64),
            )
            .unwrap();
            assert!(certificate.verify(&b, &other, 1001).is_err());
            let mut changed = certificate.clone();
            changed.body.expires_at += 1;
            assert!(changed.verify(&b, &k, 1001).is_err());
            assert!(family.seal(&b, &k, 1000, 61001).is_err());
            assert!(super::super::WorkerAdmission::default().check().is_err());
        }
        #[test]
        fn writable_or_missing_proof_root_cannot_issue_qualification() {
            let path = std::env::temp_dir().join(format!("la-proof-deny-{}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            let root = super::super::super::la_artifacts::open_owned_root(&path).unwrap();
            assert!(
                VerifiedResourceFamily::inspect(&root, &"a".repeat(64), &"b".repeat(64)).is_err()
            );
            std::fs::remove_dir(&path).unwrap();
        }
    }
}

/// Independent custody of the controller's authority, claim and artifact state.
/// Transport journals have their own witness protocol and are excluded here to
/// avoid treating a transport-only probe as a namespace mutation.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) mod state_custody {
    use super::{typed_mac, ChannelBinding, ChannelKeys};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs::File,
        io::{Read, Write},
        os::{fd::AsRawFd, unix::fs::MetadataExt},
        sync::{Arc, Condvar, Mutex},
    };
    use subtle::ConstantTimeEq;
    type Emit = dyn Fn(&[u8]) -> Result<(), &'static str> + Send + Sync;
    fn valid(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        binding: ChannelBinding,
        revision: u64,
        previous: String,
        operation: u64,
        phase: String,
        request_digest: String,
        response_digest: Option<String>,
        root_dev: u64,
        root_inode: u64,
        state_digest: String,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Checkpoint {
        body: Body,
        mac: [u8; 32],
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Ack {
        binding: ChannelBinding,
        revision: u64,
        head: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consumption: Option<super::RecoveryConsumption>,
        mac: [u8; 32],
    }
    impl Checkpoint {
        fn head(&self) -> Result<String, &'static str> {
            Ok(hex::encode(Sha256::digest(
                serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
            )))
        }
    }
    impl Ack {
        fn new(frame: &Checkpoint, key: &[u8; 32]) -> Result<Self, &'static str> {
            let head = frame.head()?;
            let mac = typed_mac(
                key,
                b"diffuser-service-state-ack/v1\0",
                &(frame.body.binding.clone(), frame.body.revision, &head),
            )?;
            Ok(Self {
                binding: frame.body.binding.clone(),
                revision: frame.body.revision,
                head,
                consumption: None,
                mac,
            })
        }
        fn verify(&self, frame: &Checkpoint, key: &[u8; 32]) -> Result<(), &'static str> {
            let expected = Self::new(frame, key)?;
            if let Some(proof) = &self.consumption {
                proof.verify(key)?;
                if frame.body.phase != "recovery"
                    || proof.kind != "service"
                    || proof.checkpoint != expected.head
                    || proof.capability != frame.body.request_digest
                {
                    return Err("evidence_invalid");
                }
            }
            if self.binding != expected.binding
                || self.revision != expected.revision
                || self.head != expected.head
                || !bool::from(self.mac.ct_eq(&expected.mac))
            {
                Err("evidence_invalid")
            } else {
                Ok(())
            }
        }
    }
    #[derive(Default)]
    struct Wait {
        frame: Option<Checkpoint>,
        ack: Option<Ack>,
        failed: bool,
    }
    pub(in crate::cosp) struct Link {
        binding: ChannelBinding,
        request_key: [u8; 32],
        ack_key: [u8; 32],
        emit: Box<Emit>,
        wait: Mutex<Wait>,
        changed: Condvar,
    }
    impl Drop for Link {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.request_key.zeroize();
            self.ack_key.zeroize();
        }
    }
    impl Link {
        pub(in crate::cosp) fn new(
            binding: ChannelBinding,
            keys: &ChannelKeys,
            emit: Box<Emit>,
        ) -> Result<Arc<Self>, &'static str> {
            binding.validate()?;
            Ok(Arc::new(Self {
                binding,
                request_key: keys.reply,
                ack_key: keys.custody,
                emit,
                wait: Mutex::new(Wait::default()),
                changed: Condvar::new(),
            }))
        }
        pub(in crate::cosp) fn accept(&self, bytes: &[u8]) -> Result<(), &'static str> {
            if bytes.len() > 4096 {
                return Err("evidence_invalid");
            }
            let ack: Ack =
                serde_json::from_slice(&super::super::la_contract::canonical_json(bytes)?)
                    .map_err(|_| "evidence_invalid")?;
            let mut wait = self.wait.lock().map_err(|_| "storage_unavailable")?;
            if wait.failed || wait.ack.is_some() {
                return Err("evidence_invalid");
            }
            ack.verify(
                wait.frame.as_ref().ok_or("evidence_invalid")?,
                &self.ack_key,
            )?;
            wait.ack = Some(ack);
            self.changed.notify_all();
            Ok(())
        }
        fn exchange(&self, frame: &Checkpoint) -> Result<Ack, &'static str> {
            {
                let mut w = self.wait.lock().map_err(|_| "storage_unavailable")?;
                if w.failed || w.frame.is_some() {
                    return Err("evidence_invalid");
                }
                w.frame = Some(frame.clone());
            }
            let bytes = serde_json::to_vec(frame).map_err(|_| "evidence_invalid")?;
            if bytes.len() > 4096 || (self.emit)(&bytes).is_err() {
                self.wait.lock().map_err(|_| "storage_unavailable")?.failed = true;
                return Err("evidence_invalid");
            }
            let w = self.wait.lock().map_err(|_| "storage_unavailable")?;
            let (mut w, _) = self
                .changed
                .wait_timeout_while(w, std::time::Duration::from_millis(500), |w| {
                    w.ack.is_none() && !w.failed
                })
                .map_err(|_| "storage_unavailable")?;
            let Some(ack) = w.ack.take() else {
                w.failed = true;
                return Err("evidence_invalid");
            };
            ack.verify(frame, &self.ack_key)?;
            w.frame = None;
            Ok(ack)
        }
    }
    fn history(
        db: &rusqlite::Connection,
        expected: u64,
        prefix: u64,
        inject: Option<&Ack>,
    ) -> Result<String, &'static str> {
        if prefix > expected || expected > 1025 {
            return Err("evidence_invalid");
        }
        let mut hash = Sha256::new();
        hash.update(b"diffuser-service-state-history/v1\0");
        hash.update(prefix.to_be_bytes());
        let mut statement=db.prepare("SELECT revision,length(frame),substr(frame,1,4097),length(ack),substr(ack,1,4097) FROM service_checkpoints ORDER BY revision LIMIT 1026").map_err(|_|"evidence_invalid")?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })
            .map_err(|_| "evidence_invalid")?;
        let mut count = 0;
        let mut midpoints = 0;
        for row in rows {
            let (revision, length, frame, ack_length, mut ack) =
                row.map_err(|_| "evidence_invalid")?;
            count += 1;
            if revision != count as i64
                || count > expected
                || length != frame.len() as i64
                || frame.len() > 4096
                || ack
                    .as_ref()
                    .is_some_and(|a| ack_length != Some(a.len() as i64) || a.len() > 4096)
            {
                return Err("evidence_invalid");
            }
            let checkpoint: Checkpoint =
                serde_json::from_slice(&frame).map_err(|_| "evidence_invalid")?;
            if matches!(
                checkpoint.body.phase.as_str(),
                "close_intent" | "stop_intent"
            ) {
                midpoints += 1;
                let bytes: Vec<u8> = db
                    .query_row(
                        "SELECT body FROM service_close_midpoints WHERE operation=?1",
                        [checkpoint.body.operation as i64],
                        |r| r.get(0),
                    )
                    .map_err(|_| "evidence_invalid")?;
                if bytes.len() > 4096 {
                    return Err("evidence_invalid");
                }
                let close: ControlMidpoint =
                    serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                if serde_json::to_vec(&close).map_err(|_| "evidence_invalid")? != bytes
                    || close.phase()? != checkpoint.body.phase
                    || close.operation != checkpoint.body.operation
                    || close.request_digest != checkpoint.body.request_digest
                    || checkpoint.body.response_digest.as_ref() != Some(&close.digest()?)
                {
                    return Err("evidence_invalid");
                }
            }
            if let Some(value) = inject.filter(|a| a.revision == count) {
                if ack.is_some() {
                    return Err("evidence_invalid");
                }
                ack = Some(serde_json::to_vec(value).map_err(|_| "evidence_invalid")?);
            }
            if count <= prefix {
                let ack = ack.ok_or("evidence_invalid")?;
                hash.update(count.to_be_bytes());
                hash.update((frame.len() as u64).to_be_bytes());
                hash.update(frame);
                hash.update((ack.len() as u64).to_be_bytes());
                hash.update(ack);
            }
        }
        let table: bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='service_close_midpoints')",[],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        let actual: i64 = if table {
            db.query_row("SELECT COUNT(*) FROM service_close_midpoints", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?
        } else {
            0
        };
        if count != expected || actual != midpoints {
            return Err("evidence_invalid");
        }
        Ok(hex::encode(hash.finalize()))
    }
    fn excluded(name: &str) -> bool {
        matches!(
            name,
            "service-custody.sqlite"
                | "service-custody.sqlite-journal"
                | "controller-channel.sqlite"
                | "controller-channel.sqlite-journal"
                | "worker-channel.sqlite"
                | "worker-channel.sqlite-journal"
        )
    }
    /// Every contained file is read, bounded and rehashed. SQLite is in FULL
    /// rollback-journal mode; callers serialize each completed state mutation.
    pub(in crate::cosp) fn state_digest(root: &File) -> Result<String, &'static str> {
        fn visit(
            root: &File,
            relative: &str,
            entries: &mut Vec<(String, u64, u64, u32, u64, String)>,
            total: &mut u64,
        ) -> Result<(), &'static str> {
            let path = format!("/proc/self/fd/{}", root.as_raw_fd());
            let mut names = std::fs::read_dir(&path)
                .map_err(|_| "evidence_invalid")?
                .map(|entry| entry.map(|e| e.file_name()).map_err(|_| "evidence_invalid"))
                .take(257)
                .collect::<Result<Vec<_>, _>>()?;
            names.sort();
            if names.len() > 256 {
                return Err("evidence_invalid");
            }
            for name in names {
                let name = name.to_str().ok_or("evidence_invalid")?;
                if name.is_empty()
                    || name.len() > 128
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                {
                    return Err("evidence_invalid");
                }
                if relative.is_empty() && excluded(name) {
                    continue;
                }
                let path = if relative.is_empty() {
                    name.to_string()
                } else {
                    format!("{relative}/{name}")
                };
                let f = super::super::la_artifacts::open_artifact(root, name, libc::O_RDONLY)
                    .map_err(|_| "evidence_invalid")?;
                let m = f.metadata().map_err(|_| "evidence_invalid")?;
                if m.uid() != unsafe { libc::geteuid() }
                    || m.mode() & 0o022 != 0
                    || (m.is_dir() && m.mode() & 0o077 != 0)
                    || entries.len() >= 256
                {
                    return Err("evidence_invalid");
                }
                if m.is_dir() {
                    entries.push((path.clone(), m.dev(), m.ino(), m.mode(), 0, String::new()));
                    visit(&f, &path, entries, total)?;
                } else if m.is_file() && m.nlink() == 1 && m.len() <= 1048576 {
                    *total = total.checked_add(m.len()).ok_or("evidence_invalid")?;
                    if *total > 67108864 {
                        return Err("evidence_invalid");
                    }
                    let mut hash = Sha256::new();
                    let mut input = f;
                    let mut bytes = [0u8; 8192];
                    let mut read = 0;
                    loop {
                        let n = input.read(&mut bytes).map_err(|_| "evidence_invalid")?;
                        if n == 0 {
                            break;
                        }
                        read += n as u64;
                        if read > m.len() {
                            return Err("evidence_invalid");
                        }
                        hash.update(&bytes[..n]);
                    }
                    if read != m.len() {
                        return Err("evidence_invalid");
                    }
                    entries.push((
                        path,
                        m.dev(),
                        m.ino(),
                        m.mode(),
                        m.len(),
                        hex::encode(hash.finalize()),
                    ));
                } else {
                    return Err("evidence_invalid");
                }
            }
            Ok(())
        }
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        // The preexisting controller SQLite file is 0644 inside its private
        // 0700 owned root. Read bits do not create a path through that root;
        // group/other writes and traversable child directories are refused.
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("evidence_invalid");
        }
        let mut entries = Vec::new();
        visit(root, "", &mut entries, &mut 0)?;
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(&(m.dev(), m.ino(), entries)).map_err(|_| "evidence_invalid")?,
        )))
    }
    /// Exact Close or Stop service stage. The signed operation discriminant is
    /// retained; neither settlement can authorize running-job redispatch.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct ControlMidpoint {
        operation: u64,
        request_digest: String,
        envelope: String,
        pub(super) authority_sequence: u64,
    }
    impl ControlMidpoint {
        fn phase(&self) -> Result<&'static str, &'static str> {
            let signed: super::SignedRequest =
                serde_json::from_slice(self.envelope()).map_err(|_| "evidence_invalid")?;
            match signed.request.operation {
                super::WorkerOperation::Close(_) => Ok("close_intent"),
                super::WorkerOperation::Stop(_) => Ok("stop_intent"),
                _ => Err("evidence_invalid"),
            }
        }
        fn digest(&self) -> Result<String, &'static str> {
            Ok(hex::encode(Sha256::digest(
                serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
            )))
        }
        pub(super) fn envelope(&self) -> &[u8] {
            self.envelope.as_bytes()
        }
        fn verify(
            &self,
            root: &File,
            binding: &ChannelBinding,
            keys: &ChannelKeys,
        ) -> Result<(), &'static str> {
            use super::{SignedRequest, WorkerOperation};
            if self.operation == 0
                || self.operation > 512
                || !valid(&self.request_digest)
                || self.authority_sequence == 0
                || self.authority_sequence > 128
                || self.envelope.len() > 3072
            {
                return Err("evidence_invalid");
            }
            let signed: SignedRequest =
                serde_json::from_slice(self.envelope.as_bytes()).map_err(|_| "evidence_invalid")?;
            let r = &signed.request;
            super::validate_rpc_envelope(
                self.envelope.as_bytes(),
                "controller-channel.sqlite",
                binding,
                r.sequence,
                &super::rpc_content_digest(r)?,
            )?;
            if !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", r)?.ct_eq(&signed.mac),
            ) {
                return Err("evidence_invalid");
            }
            let (assignment, worker, boot, fence) = match &r.operation {
                WorkerOperation::Close(c) => (&c.assignment, &c.worker, &c.boot, c.fence),
                WorkerOperation::Stop(c) => (&c.assignment, &c.worker, &c.boot, c.fence),
                _ => return Err("evidence_invalid"),
            };
            let channel = super::super::la_store::open_pinned_readonly_database(
                root,
                "controller-channel.sqlite",
            )?;
            let (envelope, pending, high): (Vec<u8>, bool, i64) = channel.query_row(
                "SELECT request,response IS NULL,(SELECT MAX(sequence) FROM channel_log) FROM channel_log WHERE sequence=?1", [r.sequence as i64],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(|_| "evidence_invalid")?;
            if envelope != self.envelope.as_bytes() || !pending || high != r.sequence as i64 {
                return Err("evidence_invalid");
            }
            let db = super::super::la_store::open_pinned_readonly_database(
                root,
                "lane_assignments.sqlite",
            )?;
            let valid: bool = match &r.operation { WorkerOperation::Close(c) => db.query_row("SELECT EXISTS(SELECT 1 FROM la_assignments a JOIN la_reservation_authorizations r ON r.assignment_id=a.id JOIN la_close_intents c ON c.assignment_id=a.id JOIN la_outbox o ON o.assignment_id=a.id JOIN la_reservations h ON h.assignment_id=a.id JOIN la_quota_charges q ON q.assignment_id=a.id WHERE a.id=?1 AND a.worker=?2 AND a.fence=?3 AND a.state='draining' AND r.worker=a.worker AND r.boot=?4 AND r.fence=a.fence AND c.stop_operation=?5 AND o.action='stop' AND q.project=a.project AND q.actor=a.actor AND EXISTS(SELECT 1 FROM la_assignment_grant_charges g WHERE g.assignment_id=a.id) AND NOT EXISTS(SELECT 1 FROM la_jobs j WHERE j.assignment_id=a.id AND j.state IN ('pending','running','stopping','finalizing')) AND NOT EXISTS(SELECT 1 FROM la_assignment_stop_receipts s WHERE s.assignment_id=a.id))",rusqlite::params![c.assignment,c.worker,c.fence as i64,c.boot,c.operation],|row|row.get(0)).map_err(|_| "evidence_invalid")?,
                WorkerOperation::Stop(c) => {
                    let command = serde_json::to_string(c).map_err(|_| "evidence_invalid")?;
                    let digest = hex::encode(Sha256::digest(command.as_bytes()));
                    db.query_row("SELECT EXISTS(SELECT 1 FROM la_jobs j JOIN la_assignments a ON a.id=j.assignment_id JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.worker=a.worker AND r.fence=a.fence JOIN la_job_permit_intents p ON p.job=j.id JOIN la_job_outbox o ON o.job=j.id JOIN la_reservations h ON h.assignment_id=a.id JOIN la_quota_charges q ON q.assignment_id=a.id AND q.project=a.project AND q.actor=a.actor WHERE j.id=?1 AND j.assignment_id=?2 AND j.state='stopping' AND j.result_artifact IS NULL AND a.state IN ('assigned','draining') AND a.worker=?3 AND a.fence=?4 AND r.boot=?5 AND o.operation=?6 AND o.action='stop' AND p.command=?7 AND p.digest=?8 AND p.permit_until=?9 AND EXISTS(SELECT 1 FROM la_assignment_grant_charges g WHERE g.assignment_id=a.id) AND NOT EXISTS(SELECT 1 FROM la_job_results x WHERE x.job=j.id))",rusqlite::params![c.job,c.assignment,c.worker,c.fence as i64,c.boot,c.operation,command,digest,c.permit_until as i64],|row|row.get(0)).map_err(|_| "evidence_invalid")?
                },
                _ => return Err("evidence_invalid"),
            };
            if !valid {
                return Err("evidence_invalid");
            }
            let (count, high): (i64, i64) = db
                .query_row(
                    "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM la_authority_observations",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if count != self.authority_sequence as i64 || high != count {
                return Err("evidence_invalid");
            }
            for sequence in 1..=self.authority_sequence {
                let (body, mac): (Vec<u8>, Vec<u8>) = db
                    .query_row(
                        "SELECT body,mac FROM la_authority_observations WHERE sequence=?1",
                        [sequence as i64],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|_| "evidence_invalid")?;
                super::verify_authority_observation(
                    &keys.authority,
                    &body,
                    &mac.try_into().map_err(|_| "evidence_invalid")?,
                )?;
            }
            let mut st = db.prepare("SELECT j.id,m.body,m.digest FROM la_jobs j LEFT JOIN la_mandates m ON m.job=j.id WHERE j.assignment_id=?1 ORDER BY j.id LIMIT 33").map_err(|_| "evidence_invalid")?;
            let rows = st
                .query_map([assignment], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|_| "evidence_invalid")?;
            let mut count = 0;
            for row in rows {
                count += 1;
                let (job, body, digest) = row.map_err(|_| "evidence_invalid")?;
                let mandate: super::super::la_auth::StoredMandate =
                    serde_json::from_str(&body).map_err(|_| "evidence_invalid")?;
                if count > 32
                    || body.len() > 16384
                    || hex::encode(Sha256::digest(body.as_bytes())) != digest
                    || super::super::la_store::checked_mandate(&mandate.draft)? != mandate
                    || mandate.draft.job != job
                    || mandate.draft.assignment != *assignment
                    || mandate.draft.worker != *worker
                {
                    return Err("evidence_invalid");
                }
                if let WorkerOperation::Stop(c) = &r.operation {
                    if job == c.job
                        && (mandate.draft.operation != c.operation
                            || mandate.draft.input_digest != c.input_digest
                            || mandate.draft.accepted_at != c.accepted_at
                            || mandate.max_until != c.mandate_until
                            || c.permit_until > mandate.max_until
                            || c.boot != *boot
                            || c.fence != fence)
                    {
                        return Err("evidence_invalid");
                    }
                }
            }
            Ok(())
        }
    }
    struct Journal {
        root: File,
        db: super::super::la_store::PinnedDb,
        file: File,
        link: Arc<Link>,
        binding: ChannelBinding,
        revision: u64,
        head: String,
        last_state: String,
        history: String,
        pending: BTreeMap<u64, String>,
        next: u64,
        failed: bool,
        close: Option<ControlMidpoint>,
    }
    pub(in crate::cosp) struct Session(Mutex<Journal>);
    impl Session {
        pub(in crate::cosp) fn create(
            root: &File,
            link: Arc<Link>,
        ) -> Result<Arc<Self>, &'static str> {
            let file = super::super::la_artifacts::open_artifact(
                root,
                "service-custody.sqlite",
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "storage_unavailable")?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err("storage_unavailable");
            }
            let db = super::super::la_store::open_pinned_database(
                root,
                "service-custody.sqlite",
                false,
            )?;
            db.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE service_checkpoints(revision INTEGER PRIMARY KEY,frame BLOB NOT NULL,ack BLOB); CREATE TABLE service_close_midpoints(operation INTEGER PRIMARY KEY,body BLOB NOT NULL);").map_err(|_|"storage_unavailable")?;
            let initial_history = history(&db, 0, 0, None)?;
            let mut j = Journal {
                root: root.try_clone().map_err(|_| "storage_unavailable")?,
                db,
                file,
                binding: link.binding.clone(),
                link,
                revision: 0,
                head: "0".repeat(64),
                last_state: state_digest(root)?,
                history: initial_history,
                pending: BTreeMap::new(),
                next: 0,
                failed: false,
                close: None,
            };
            j.checkpoint(0, "genesis", &"0".repeat(64), None)?;
            Ok(Arc::new(Self(Mutex::new(j))))
        }
        pub(in crate::cosp) fn begin(&self, request: &str) -> Result<u64, &'static str> {
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            j.check()?;
            if !valid(request) || j.pending.len() >= 4 || j.next >= 512 || j.close.is_some() {
                return Err("storage_unavailable");
            }
            if j.pending.is_empty() && state_digest(&j.root)? != j.last_state {
                j.failed = true;
                return Err("evidence_invalid");
            }
            j.next += 1;
            let op = j.next;
            j.pending.insert(op, request.into());
            j.checkpoint(op, "intent", request, None)?;
            Ok(op)
        }
        pub(in crate::cosp) fn complete(
            &self,
            operation: u64,
            response: &str,
        ) -> Result<(), &'static str> {
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            j.check()?;
            if !valid(response) {
                j.failed = true;
                return Err("evidence_invalid");
            }
            if let Some(close) = j.close.as_ref().filter(|c| c.operation == operation) {
                let channel = super::super::la_store::open_pinned_readonly_database(
                    &j.root,
                    "controller-channel.sqlite",
                )?;
                let signed: super::SignedRequest =
                    serde_json::from_slice(close.envelope()).map_err(|_| "evidence_invalid")?;
                let pending: bool = channel
                    .query_row(
                        "SELECT response IS NULL FROM channel_log WHERE sequence=?1",
                        [signed.request.sequence as i64],
                        |r| r.get(0),
                    )
                    .map_err(|_| "evidence_invalid")?;
                if pending {
                    return Err("transport_uncertain");
                }
            }
            let request = j.pending.get(&operation).ok_or("evidence_invalid")?.clone();
            j.checkpoint(operation, "complete", &request, Some(response.into()))?;
            j.pending.remove(&operation);
            if j.close.as_ref().is_some_and(|c| c.operation == operation) {
                j.close = None;
            }
            Ok(())
        }
        pub(in crate::cosp) fn close_midpoint(
            &self,
            envelope: &[u8],
            keys: &ChannelKeys,
        ) -> Result<(), &'static str> {
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            j.check()?;
            if j.pending.len() != 1 || j.close.is_some() {
                return Err("evidence_invalid");
            }
            let (&operation, request) = j.pending.iter().next().ok_or("evidence_invalid")?;
            let claims = super::super::la_store::open_pinned_readonly_database(
                &j.root,
                "lane_assignments.sqlite",
            )?;
            let sequence: i64 = claims
                .query_row(
                    "SELECT COALESCE(MAX(sequence),0) FROM la_authority_observations",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            let close = ControlMidpoint {
                operation,
                request_digest: request.clone(),
                envelope: std::str::from_utf8(envelope)
                    .map_err(|_| "evidence_invalid")?
                    .into(),
                authority_sequence: sequence.try_into().map_err(|_| "evidence_invalid")?,
            };
            close.verify(&j.root, &j.binding, keys)?;
            let bytes = serde_json::to_vec(&close).map_err(|_| "evidence_invalid")?;
            if bytes.len() > 4096 {
                return Err("evidence_invalid");
            }
            j.close = Some(close.clone());
            j.checkpoint(
                operation,
                close.phase()?,
                &close.request_digest,
                Some(close.digest()?),
            )?;
            Ok(())
        }
        pub(in crate::cosp) fn check(&self) -> Result<(), &'static str> {
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            let result = j.check();
            if result.is_err() {
                j.failed = true;
            }
            result
        }
    }
    impl Journal {
        fn check(&self) -> Result<(), &'static str> {
            if self.failed
                || self
                    .file
                    .metadata()
                    .map_err(|_| "evidence_invalid")?
                    .nlink()
                    != 1
                || self
                    .link
                    .wait
                    .lock()
                    .map_err(|_| "storage_unavailable")?
                    .failed
            {
                return Err("evidence_invalid");
            }
            let count: i64 = self
                .db
                .query_row("SELECT COUNT(*) FROM service_checkpoints", [], |r| r.get(0))
                .map_err(|_| "evidence_invalid")?;
            if count != self.revision as i64
                || history(&self.db, self.revision, self.revision, None)? != self.history
            {
                return Err("evidence_invalid");
            }
            let pinned = super::super::la_artifacts::open_artifact(
                &self.root,
                "service-custody.sqlite",
                libc::O_RDONLY,
            )
            .map_err(|_| "evidence_invalid")?
            .metadata()
            .map_err(|_| "evidence_invalid")?;
            let m = self.file.metadata().map_err(|_| "evidence_invalid")?;
            if (pinned.dev(), pinned.ino()) != (m.dev(), m.ino()) {
                return Err("evidence_invalid");
            }
            Ok(())
        }
        fn checkpoint(
            &mut self,
            operation: u64,
            phase: &str,
            request: &str,
            response: Option<String>,
        ) -> Result<(), &'static str> {
            let result = (|| {
                self.check()?;
                let root = self.root.metadata().map_err(|_| "evidence_invalid")?;
                let revision = self.revision + 1;
                if revision > 1025 {
                    return Err("storage_unavailable");
                }
                let body = Body {
                    binding: self.binding.clone(),
                    revision,
                    previous: self.head.clone(),
                    operation,
                    phase: phase.into(),
                    request_digest: request.into(),
                    response_digest: response,
                    root_dev: root.dev(),
                    root_inode: root.ino(),
                    state_digest: state_digest(&self.root)?,
                };
                let mac = typed_mac(
                    &self.link.request_key,
                    b"diffuser-service-state-checkpoint/v1\0",
                    &body,
                )?;
                let frame = Checkpoint { body, mac };
                let bytes = serde_json::to_vec(&frame).map_err(|_| "evidence_invalid")?;
                let tx = self
                    .db
                    .unchecked_transaction()
                    .map_err(|_| "storage_unavailable")?;
                if matches!(phase, "close_intent" | "stop_intent") {
                    let close = self.close.as_ref().ok_or("evidence_invalid")?;
                    tx.execute(
                        "INSERT INTO service_close_midpoints VALUES(?1,?2)",
                        rusqlite::params![
                            operation as i64,
                            serde_json::to_vec(close).map_err(|_| "evidence_invalid")?
                        ],
                    )
                    .map_err(|_| "storage_unavailable")?;
                }
                tx.execute(
                    "INSERT INTO service_checkpoints VALUES(?1,?2,NULL)",
                    rusqlite::params![revision as i64, bytes],
                )
                .map_err(|_| "storage_unavailable")?;
                tx.commit().map_err(|_| "storage_unavailable")?;
                let ack = self.link.exchange(&frame)?;
                self.db
                    .execute(
                        "UPDATE service_checkpoints SET ack=?2 WHERE revision=?1",
                        rusqlite::params![
                            revision as i64,
                            serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?
                        ],
                    )
                    .map_err(|_| "storage_unavailable")?;
                if history(&self.db, revision, self.revision, None)? != self.history {
                    return Err("evidence_invalid");
                }
                self.history = history(&self.db, revision, revision, None)?;
                self.revision = revision;
                self.head = frame.head()?;
                self.last_state = frame.body.state_digest;
                Ok(())
            })();
            if result.is_err() {
                self.failed = true;
            }
            result
        }
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct WorkerServiceAnchor {
        revision: u64,
        head: String,
        history: String,
        state: String,
        pub(super) operation: u64,
        request_digest: String,
        close_digest: String,
    }
    impl WorkerServiceAnchor {
        pub(super) fn revision(&self) -> u64 {
            self.revision
        }
    }
    pub(super) fn worker_return_headroom(revision: u64) -> Result<(), &'static str> {
        // The same live C must append worker_handoff, finish the ORIGINAL
        // pending operation, then witness cleanup intent and completion.
        if revision == 0 || revision.checked_add(4).is_none_or(|end| end > 1025) {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    impl Ledger {
        pub(super) fn worker_return_anchor(
            &self,
            role_root: &File,
        ) -> Result<WorkerServiceAnchor, &'static str> {
            self.control_anchor(role_root, "close_intent")
        }
        pub(super) fn worker_loss_anchor(
            &self,
            role_root: &File,
        ) -> Result<WorkerServiceAnchor, &'static str> {
            let anchor = self.control_anchor(role_root, "stop_intent")?;
            for sequence in 1..=self.authority_sequence {
                let mut bytes = Vec::new();
                super::super::la_artifacts::open_artifact(
                    &self.root,
                    &format!("service-authority-{sequence:03}.json"),
                    libc::O_RDONLY,
                )
                .map_err(|_| "evidence_invalid")?
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(|_| "evidence_invalid")?;
                if bytes.len() > 16384 {
                    return Err("evidence_invalid");
                }
                let (frame, c, w): (Vec<u8>, super::SourceAck, super::SourceAck) =
                    serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                let (binding, retained) = self.retained_source(sequence)?;
                if frame != retained {
                    return Err("evidence_invalid");
                }
                let body =
                    super::verify_source_observation(&self.keys.authority, &binding, &frame)?;
                super::verify_source_ack(&self.request_key, &binding, "controller", &body, &c)?;
                super::verify_source_ack(&self.request_key, &binding, "worker", &body, &w)?;
            }
            Ok(anchor)
        }
        fn control_anchor(
            &self,
            role_root: &File,
            phase: &str,
        ) -> Result<WorkerServiceAnchor, &'static str> {
            worker_return_headroom(self.revision)?;
            let close = self.close.as_ref().ok_or("evidence_invalid")?;
            if close.phase()? != phase
                || self.recovering.is_some()
                || self.pending.len() != 1
                || self.pending.get(&close.operation) != Some(&close.request_digest)
                || close.authority_sequence != self.authority_sequence
                || self.revision == 0
                || self.revision >= 1025
            {
                return Err("evidence_invalid");
            }
            close.verify(role_root, &self.binding, &self.keys)?;
            self.verify_authority_history(role_root)?;
            let db = super::super::la_store::open_pinned_readonly_database(
                role_root,
                "service-custody.sqlite",
            )?;
            let history = history(&db, self.revision, self.revision, None)?;
            if self.history.as_ref() != Some(&history)
                || state_digest(role_root)? != self.last_state
            {
                return Err("evidence_invalid");
            }
            Ok(WorkerServiceAnchor {
                revision: self.revision,
                head: self.head.clone(),
                history,
                state: self.last_state.clone(),
                operation: close.operation,
                request_digest: close.request_digest.clone(),
                close_digest: close.digest()?,
            })
        }
        pub(in crate::cosp) fn authority_sequence(&self) -> u64 {
            self.authority_sequence
        }
        pub(super) fn worker_close_envelope(&self) -> Result<&[u8], &'static str> {
            Ok(self.close.as_ref().ok_or("evidence_invalid")?.envelope())
        }
        pub(super) fn prepare_worker_return(
            &mut self,
            root: &File,
            handoff: &super::WorkerEpochHandoff,
        ) -> Result<(), &'static str> {
            handoff.verify_history(&self.ack_key)?;
            let anchor = self.worker_return_anchor(root)?;
            if serde_json::to_vec(&anchor).map_err(|_| "evidence_invalid")?
                != serde_json::to_vec(&handoff.service).map_err(|_| "evidence_invalid")?
                || handoff.previous != self.binding
            {
                return Err("evidence_invalid");
            }
            let mut file = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!(
                    "service-worker-epoch-{:04}.json",
                    handoff.binding.worker_epoch
                ),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "evidence_invalid")?;
            file.write_all(&serde_json::to_vec(handoff).map_err(|_| "evidence_invalid")?)
                .and_then(|_| file.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            self.recovering = Some(handoff.digest()?);
            self.binding = handoff.binding.clone();
            Ok(())
        }
    }
    impl Ledger {
        pub(super) fn worker_loss_cleanup_anchor(&self, root: &File) -> Result<(), &'static str> {
            if self.loss_source_pending.is_some()
                || !self.pending.is_empty()
                || self.close.is_some()
                || self.recovering.is_some()
                || state_digest(root)? != self.last_state
            {
                return Err("evidence_invalid");
            }
            if self.authority_sequence > 0 {
                let mut bytes = Vec::new();
                super::super::la_artifacts::open_artifact(
                    &self.root,
                    &format!("service-authority-{:03}.json", self.authority_sequence),
                    libc::O_RDONLY,
                )
                .map_err(|_| "evidence_invalid")?
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(|_| "evidence_invalid")?;
                if bytes.len() > 16384 {
                    return Err("evidence_invalid");
                }
                if let Ok((cap, ack)) =
                    serde_json::from_slice::<(super::WorkerLossSource, super::SourceAck)>(&bytes)
                {
                    let body = super::verify_source_observation(
                        &self.keys.authority,
                        &self.binding,
                        &cap.frame,
                    )?;
                    // Historical verification checks its signed issuance time;
                    // the current cleanup certificate has its own finite window.
                    cap.verify(&self.keys, cap.issued_at)?;
                    cap.installed_loss(root, &self.keys)?;
                    super::verify_source_ack(
                        &self.keys.reply,
                        &self.binding,
                        "controller",
                        &body,
                        &ack,
                    )?;
                    let (binding, frame) = self.retained_source(self.authority_sequence)?;
                    let db = super::super::la_store::open_pinned_readonly_database(
                        root,
                        "lane_assignments.sqlite",
                    )?;
                    let saved: Vec<u8> = db
                        .query_row(
                            "SELECT body FROM la_worker_loss_sources WHERE sequence=?1 AND job=?2",
                            rusqlite::params![self.authority_sequence as i64, cap.job],
                            |r| r.get(0),
                        )
                        .map_err(|_| "evidence_invalid")?;
                    if ack.sequence != self.authority_sequence
                        || cap.previous_sequence + 1 != self.authority_sequence
                        || binding != cap.binding
                        || frame != cap.frame
                        || saved != serde_json::to_vec(&cap).map_err(|_| "evidence_invalid")?
                    {
                        return Err("evidence_invalid");
                    }
                } else {
                    let (frame, c, w): (Vec<u8>, super::SourceAck, super::SourceAck) =
                        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                    let body = super::verify_source_observation(
                        &self.keys.authority,
                        &self.binding,
                        &frame,
                    )?;
                    super::verify_source_ack(
                        &self.keys.reply,
                        &self.binding,
                        "controller",
                        &body,
                        &c,
                    )?;
                    super::verify_source_ack(&self.keys.reply, &self.binding, "worker", &body, &w)?;
                }
            }
            self.verify_authority_history(root)?;
            let db = super::super::la_store::open_pinned_readonly_database(
                root,
                "service-custody.sqlite",
            )?;
            if self.history.as_ref() != Some(&history(&db, self.revision, self.revision, None)?) {
                return Err("evidence_invalid");
            }
            Ok(())
        }
    }
    impl Session {
        pub(super) fn verify_worker_loss(
            &self,
            cap: &super::WorkerLossSettlement,
            keys: &ChannelKeys,
            now: u64,
        ) -> Result<(), &'static str> {
            cap.verify(keys, now)?;
            let j = self.0.lock().map_err(|_| "storage_unavailable")?;
            j.check()?;
            let a = &cap.service;
            if j.binding != cap.binding
                || j.revision != a.revision
                || j.head != a.head
                || j.history != a.history
                || j.last_state != a.state
                || state_digest(&j.root)? != a.state
                || j.pending.len() != 1
                || j.pending.get(&a.operation) != Some(&a.request_digest)
                || j.close.as_ref().ok_or("evidence_invalid")?.digest()? != a.close_digest
            {
                return Err("evidence_invalid");
            }
            Ok(())
        }
    }
    impl Session {
        pub(in crate::cosp) fn binding(&self) -> Result<ChannelBinding, &'static str> {
            Ok(self
                .0
                .lock()
                .map_err(|_| "storage_unavailable")?
                .binding
                .clone())
        }
        pub(in crate::cosp) fn install_worker_return(
            &self,
            handoff: &super::WorkerEpochHandoff,
            keys: &ChannelKeys,
            now: u64,
        ) -> Result<u64, &'static str> {
            handoff.verify(&keys.custody, now)?;
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            j.check()?;
            let a = &handoff.service;
            let close = j.close.as_ref().ok_or("evidence_invalid")?;
            if j.binding != handoff.previous
                || j.revision != a.revision
                || j.head != a.head
                || j.history != a.history
                || j.last_state != a.state
                || state_digest(&j.root)? != a.state
                || j.pending.len() != 1
                || j.pending.get(&a.operation) != Some(&a.request_digest)
                || close.digest()? != a.close_digest
                || close.operation != a.operation
            {
                return Err("evidence_invalid");
            }
            let channel = super::super::la_store::open_pinned_readonly_database(
                &j.root,
                "controller-channel.sqlite",
            )?;
            let (_, epochs) = super::transport_epochs(&channel)?;
            if epochs.last().ok_or("evidence_invalid")?.digest()? != handoff.digest()? {
                return Err("evidence_invalid");
            }
            j.binding = handoff.binding.clone();
            j.checkpoint(a.operation, "worker_handoff", &handoff.digest()?, None)?;
            Ok(a.operation)
        }
    }
    pub(in crate::cosp) struct Ledger {
        root: File,
        binding: ChannelBinding,
        request_key: [u8; 32],
        ack_key: [u8; 32],
        revision: u64,
        head: String,
        last_state: String,
        history: Option<String>,
        next: u64,
        pending: BTreeMap<u64, String>,
        recovering: Option<String>,
        close: Option<ControlMidpoint>,
        keys: ChannelKeys,
        authority_sequence: u64,
        loss_source_pending: Option<String>,
    }
    impl Drop for Ledger {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.request_key.zeroize();
            self.ack_key.zeroize();
        }
    }
    impl Ledger {
        pub(in crate::cosp) fn new(
            root: &File,
            binding: ChannelBinding,
            keys: &ChannelKeys,
        ) -> Result<Self, &'static str> {
            binding.validate()?;
            Ok(Self {
                root: root.try_clone().map_err(|_| "storage_unavailable")?,
                binding,
                request_key: keys.reply,
                ack_key: keys.custody,
                revision: 0,
                head: "0".repeat(64),
                last_state: String::new(),
                history: None,
                next: 0,
                pending: BTreeMap::new(),
                recovering: None,
                close: None,
                keys: keys.clone(),
                authority_sequence: 0,
                loss_source_pending: None,
            })
        }
        /// P durably retains the original signed authority source before
        /// delivery. This permits source-triggered fencing before C's ACK,
        /// without depending on an ACK that itself waits for that fence.
        pub(in crate::cosp) fn record_authority(
            &mut self,
            frame: &[u8],
        ) -> Result<(), &'static str> {
            if self.loss_source_pending.is_some() {
                return Err("evidence_invalid");
            }
            let body =
                super::verify_source_observation(&self.keys.authority, &self.binding, frame)?;
            let value: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
            let sequence = value["sequence"].as_u64().ok_or("evidence_invalid")?;
            if sequence != self.authority_sequence + 1 || sequence > 128 {
                return Err("evidence_invalid");
            }
            let text = std::str::from_utf8(frame).map_err(|_| "evidence_invalid")?;
            let bytes =
                serde_json::to_vec(&(&self.binding, text)).map_err(|_| "evidence_invalid")?;
            if bytes.len() > 16384 {
                return Err("evidence_invalid");
            }
            let mut file = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!("service-source-{sequence:03}.json"),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "storage_unavailable")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            self.authority_sequence = sequence;
            Ok(())
        }
        fn retained_source(
            &self,
            sequence: u64,
        ) -> Result<(ChannelBinding, Vec<u8>), &'static str> {
            let mut bytes = Vec::new();
            super::super::la_artifacts::open_artifact(
                &self.root,
                &format!("service-source-{sequence:03}.json"),
                libc::O_RDONLY,
            )
            .map_err(|_| "evidence_invalid")?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| "evidence_invalid")?;
            if bytes.len() > 16384 {
                return Err("evidence_invalid");
            }
            let (binding, text): (ChannelBinding, String) =
                serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
            Ok((binding, text.into_bytes()))
        }
        /// P retains the high-water from the exact source frame and both
        /// authenticated role ACKs, independently of C's mutable database.
        pub(in crate::cosp) fn observe_authority(
            &mut self,
            frame: &[u8],
            controller: &super::SourceAck,
            worker: &super::SourceAck,
        ) -> Result<(), &'static str> {
            let body =
                super::verify_source_observation(&self.keys.authority, &self.binding, frame)?;
            super::recovery_trace(
                "P_source_ACK_observe",
                serde_json::json!({"sequence":controller.sequence,"authority":self.authority_sequence}),
            );
            super::verify_source_ack(
                &self.request_key,
                &self.binding,
                "controller",
                &body,
                controller,
            )?;
            super::verify_source_ack(&self.request_key, &self.binding, "worker", &body, worker)?;
            if controller.sequence != self.authority_sequence
                || controller.sequence == 0
                || controller.sequence > 128
            {
                return Err("evidence_invalid");
            }
            let (binding, retained) = self.retained_source(controller.sequence)?;
            if binding != self.binding || retained != frame {
                return Err("evidence_invalid");
            }
            let record =
                serde_json::to_vec(&(frame, controller, worker)).map_err(|_| "evidence_invalid")?;
            if record.len() > 16384 {
                return Err("evidence_invalid");
            }
            let mut file = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!("service-authority-{:03}.json", controller.sequence),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "storage_unavailable")?;
            file.write_all(&record)
                .and_then(|_| file.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            Ok(())
        }
        fn verify_authority_history(&self, role_root: &File) -> Result<(), &'static str> {
            match super::super::la_artifacts::open_artifact(
                &self.root,
                &format!(
                    "service-loss-source-bridge-{:04}.json",
                    self.binding.worker_epoch
                ),
                libc::O_RDONLY,
            ) {
                Ok(file) => {
                    let mut bytes = Vec::new();
                    file.take(12289)
                        .read_to_end(&mut bytes)
                        .map_err(|_| "evidence_invalid")?;
                    if bytes.len() > 12288 {
                        return Err("evidence_invalid");
                    }
                    let cap: super::EnteredLossSourceBridge =
                        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                    super::verify_controller_loss_source_bridge(
                        role_root,
                        &self.binding,
                        &self.keys,
                    )?;
                    let db = super::super::la_store::open_pinned_readonly_database(
                        role_root,
                        "controller-channel.sqlite",
                    )?;
                    let (installed, complete) =
                        super::verified_loss_source_bridge(&db, &self.keys)?
                            .ok_or("evidence_invalid")?;
                    if installed.digest()? != cap.digest()? {
                        return Err("evidence_invalid");
                    }
                    let mut saved = Vec::new();
                    super::super::la_artifacts::open_artifact(
                        &self.root,
                        &format!(
                            "service-loss-source-consumed-{:04}.json",
                            self.binding.worker_epoch
                        ),
                        libc::O_RDONLY,
                    )
                    .map_err(|_| "evidence_invalid")?
                    .take(4097)
                    .read_to_end(&mut saved)
                    .map_err(|_| "evidence_invalid")?;
                    if saved != serde_json::to_vec(&complete).map_err(|_| "evidence_invalid")? {
                        return Err("evidence_invalid");
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => (),
                Err(_) => return Err("evidence_invalid"),
            }
            let db = super::super::la_store::open_pinned_readonly_database(
                role_root,
                "lane_assignments.sqlite",
            )?;
            for sequence in 1..=self.authority_sequence {
                let (binding, frame) = self.retained_source(sequence)?;
                let body =
                    super::verify_source_observation(&self.keys.authority, &binding, &frame)?;
                let value: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
                let saved: Vec<u8> = db
                    .query_row(
                        "SELECT body FROM la_authority_observations WHERE sequence=?1",
                        [sequence as i64],
                        |r| r.get(0),
                    )
                    .map_err(|_| "evidence_invalid")?;
                if value["sequence"].as_u64() != Some(sequence) || saved != body {
                    return Err("evidence_invalid");
                }
            }
            Ok(())
        }
        pub(in crate::cosp) fn observe(
            &mut self,
            role_root: &File,
            frame: &Checkpoint,
        ) -> Result<Ack, &'static str> {
            let b = &frame.body;
            super::recovery_trace(
                "P_service_observe_enter",
                serde_json::json!({"phase":b.phase,"revision":b.revision,"retained_revision":self.revision,"operation":b.operation,"retained_next":self.next,"pending":self.pending.len(),"recovering":self.recovering.is_some(),"binding_matches":b.binding==self.binding,"head_matches":b.previous==self.head,"state_matches":self.last_state==b.state_digest}),
            );
            let m = role_root.metadata().map_err(|_| "evidence_invalid")?;
            if b.binding != self.binding
                || b.revision != self.revision + 1
                || b.revision > 1025
                || b.previous != self.head
                || (b.root_dev, b.root_inode) != (m.dev(), m.ino())
                || !bool::from(
                    typed_mac(
                        &self.request_key,
                        b"diffuser-service-state-checkpoint/v1\0",
                        b,
                    )?
                    .ct_eq(&frame.mac),
                )
                || state_digest(role_root).inspect_err(|_| {
                    super::recovery_trace(
                        "P_service_observe_failure",
                        serde_json::json!({"guard":"state_read"}),
                    )
                })? != b.state_digest
            {
                super::recovery_trace(
                    "P_service_observe_failure",
                    serde_json::json!({"guard":"binding_revision_head_root_MAC_state"}),
                );
                return Err("evidence_invalid");
            }
            super::recovery_trace(
                "P_service_observe_guard",
                serde_json::json!({"guard":"binding_revision_head_root_MAC_state","passed":true}),
            );
            if self.recovering.as_ref().is_some_and(|digest| {
                !matches!(
                    b.phase.as_str(),
                    "recovery" | "worker_handoff" | "loss_handoff"
                ) || b.request_digest != *digest
            }) || (matches!(
                b.phase.as_str(),
                "recovery" | "worker_handoff" | "loss_handoff"
            ) && self.recovering.is_none())
            {
                return Err("evidence_invalid");
            }
            super::recovery_trace(
                "P_service_observe_guard",
                serde_json::json!({"guard":"recovery_lineage","passed":true}),
            );
            let mut consumed_recovery = None;
            match b.phase.as_str() {
                "genesis"
                    if self.revision == 0 && b.operation == 0 && b.response_digest.is_none() => {}
                "intent"
                    if self.revision > 0
                        && b.operation == self.next + 1
                        && b.operation <= 512
                        && self.pending.len() < 4
                        && valid(&b.request_digest)
                        && b.response_digest.is_none() =>
                {
                    if self.pending.is_empty() && self.last_state != b.state_digest {
                        return Err("evidence_invalid");
                    }
                }
                "recovery"
                    if self.revision > 0
                        && (self.pending.is_empty()
                            || self.close.as_ref().is_some_and(|c| {
                                self.pending.len() == 1
                                    && self.pending.get(&c.operation) == Some(&c.request_digest)
                            }))
                        && b.operation == self.next
                        && valid(&b.request_digest)
                        && b.response_digest.is_none()
                        && self.last_state == b.state_digest =>
                {
                    let bytes = super::super::la_artifacts::open_artifact(
                        &self.root,
                        &format!("service-recovery-{:04}.json", self.binding.controller_epoch),
                        libc::O_RDONLY,
                    )
                    .map_err(|_| "evidence_invalid")?;
                    let mut bytes = bytes.take(4097);
                    let mut data = Vec::new();
                    bytes
                        .read_to_end(&mut data)
                        .map_err(|_| "evidence_invalid")?;
                    if data.len() > 4096 {
                        return Err("evidence_invalid");
                    }
                    let recovery: Recovery =
                        serde_json::from_slice(&data).map_err(|_| "evidence_invalid")?;
                    if recovery.binding != self.binding
                        || recovery.revision != self.revision
                        || recovery.head != self.head
                        || recovery.digest()? != b.request_digest
                        || !bool::from(recovery.signature(&self.ack_key)?.ct_eq(&recovery.mac))
                    {
                        return Err("evidence_invalid");
                    }
                    super::recovery_trace(
                        "P_service_observe_guard",
                        serde_json::json!({"guard":"typed_recovery_binding_revision_head_digest_MAC","passed":true,"issued_at":recovery.issued_at,"expires_at":recovery.expires_at}),
                    );
                    consumed_recovery = Some(recovery);
                }
                "loss_handoff"
                    if self.pending.is_empty()
                        && self.close.is_none()
                        && b.operation == self.next
                        && b.response_digest.is_none()
                        && self.last_state == b.state_digest =>
                {
                    let mut bytes = Vec::new();
                    super::super::la_artifacts::open_artifact(
                        &self.root,
                        &format!(
                            "service-loss-source-bridge-{:04}.json",
                            self.binding.worker_epoch
                        ),
                        libc::O_RDONLY,
                    )
                    .map_err(|_| "evidence_invalid")?
                    .take(12289)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "evidence_invalid")?;
                    if bytes.len() > 12288 {
                        return Err("evidence_invalid");
                    }
                    let cap: super::EnteredLossSourceBridge =
                        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                    cap.fresh(super::wall_now()?)?;
                    if cap.binding != self.binding
                        || self.loss_source_pending.as_deref() != Some(cap.digest()?.as_str())
                        || cap.service
                            != (
                                self.head.clone(),
                                self.last_state.clone(),
                                self.history.clone().ok_or("evidence_invalid")?,
                                self.revision,
                                self.authority_sequence,
                            )
                        || b.request_digest != cap.digest()?
                        || !bool::from(cap.signature(&self.ack_key)?.ct_eq(&cap.mac))
                    {
                        return Err("evidence_invalid");
                    }
                }
                "worker_handoff"
                    if self.pending.len() == 1
                        && self.close.is_some()
                        && b.operation == self.next
                        && b.response_digest.is_none()
                        && self.last_state == b.state_digest =>
                {
                    let file = super::super::la_artifacts::open_artifact(
                        &self.root,
                        &format!("service-worker-epoch-{:04}.json", self.binding.worker_epoch),
                        libc::O_RDONLY,
                    )
                    .map_err(|_| "evidence_invalid")?;
                    let mut bytes = Vec::new();
                    file.take(12289)
                        .read_to_end(&mut bytes)
                        .map_err(|_| "evidence_invalid")?;
                    if bytes.len() > 12288 {
                        return Err("evidence_invalid");
                    }
                    let h: super::WorkerEpochHandoff =
                        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                    h.verify_history(&self.ack_key)?;
                    if h.binding != self.binding
                        || h.service.revision != self.revision
                        || h.service.head != self.head
                        || self.history.as_ref() != Some(&h.service.history)
                        || h.digest()? != b.request_digest
                        || h.service.operation != b.operation
                        || self.close.as_ref().ok_or("evidence_invalid")?.digest()?
                            != h.service.close_digest
                    {
                        return Err("evidence_invalid");
                    }
                }
                "close_intent" | "stop_intent"
                    if self.pending.len() == 1
                        && self.pending.get(&b.operation) == Some(&b.request_digest)
                        && self.close.is_none() =>
                {
                    let db = super::super::la_store::open_pinned_readonly_database(
                        role_root,
                        "service-custody.sqlite",
                    )?;
                    let bytes: Vec<u8> = db
                        .query_row(
                            "SELECT body FROM service_close_midpoints WHERE operation=?1",
                            [b.operation as i64],
                            |r| r.get(0),
                        )
                        .map_err(|_| "evidence_invalid")?;
                    if bytes.len() > 4096 {
                        return Err("evidence_invalid");
                    }
                    let close: ControlMidpoint =
                        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                    if close.operation != b.operation
                        || close.request_digest != b.request_digest
                        || b.response_digest.as_ref() != Some(&close.digest()?)
                        || close.authority_sequence != self.authority_sequence
                    {
                        return Err("evidence_invalid");
                    }
                    if close.phase()? != b.phase {
                        return Err("evidence_invalid");
                    }
                    close.verify(role_root, &self.binding, &self.keys)?;
                    self.verify_authority_history(role_root)?;
                }
                "complete"
                    if self.pending.get(&b.operation) == Some(&b.request_digest)
                        && b.response_digest.as_ref().is_some_and(|s| valid(s)) => {}
                _ => {
                    super::recovery_trace(
                        "P_service_observe_failure",
                        serde_json::json!({"guard":"phase_operation_state"}),
                    );
                    return Err("evidence_invalid");
                }
            }
            let db = super::super::la_store::open_pinned_readonly_database(
                role_root,
                "service-custody.sqlite",
            )?;
            let (count, high): (i64, i64) = db
                .query_row(
                    "SELECT COUNT(*),MAX(revision) FROM service_checkpoints",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let bytes: Vec<u8> = db
                .query_row(
                    "SELECT frame FROM service_checkpoints WHERE revision=?1",
                    [b.revision as i64],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            super::recovery_trace(
                "P_service_observe_guard",
                serde_json::json!({"guard":"phase_operation_state","passed":true,"rows":count,"high":high,"exact_typed_bytes":bytes==serde_json::to_vec(frame).map_err(|_|"evidence_invalid")?}),
            );
            if count != b.revision as i64
                || high != count
                || bytes != serde_json::to_vec(frame).map_err(|_| "evidence_invalid")?
            {
                return Err("evidence_invalid");
            }
            if let Some(previous) = &self.history {
                if history(&db, b.revision, self.revision, None)? != *previous {
                    return Err("evidence_invalid");
                }
            }
            super::recovery_trace(
                "P_service_observe_guard",
                serde_json::json!({"guard":"exact_checkpoint_and_full_history","passed":true}),
            );
            let mut ack = Ack::new(frame, &self.ack_key)?;
            let mut file = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!("service-state-{:04}.json", b.revision),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "storage_unavailable")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            super::recovery_trace(
                "P_service_observe_guard",
                serde_json::json!({"guard":"independent_checkpoint_fsync","passed":true}),
            );
            if let Some(recovery) = consumed_recovery.filter(|r| r.consumption_required) {
                ack.consumption = Some(super::RecoveryConsumption::record(
                    &self.root,
                    &self.ack_key,
                    "service",
                    self.binding.controller_epoch,
                    recovery.digest()?,
                    frame.head()?,
                    recovery.issued_at,
                    recovery.expires_at,
                    None,
                )?);
            }
            super::recovery_trace(
                "P_service_observe_guard",
                serde_json::json!({"guard":"consumption","passed":true}),
            );
            let next_history = history(&db, b.revision, b.revision, Some(&ack))?;
            match b.phase.as_str() {
                "intent" => {
                    self.next = b.operation;
                    self.pending.insert(b.operation, b.request_digest.clone());
                }
                "close_intent" | "stop_intent" => {
                    let bytes: Vec<u8> = db
                        .query_row(
                            "SELECT body FROM service_close_midpoints WHERE operation=?1",
                            [b.operation as i64],
                            |r| r.get(0),
                        )
                        .map_err(|_| "evidence_invalid")?;
                    self.close =
                        Some(serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?);
                }
                "complete" => {
                    self.pending.remove(&b.operation);
                    if self
                        .close
                        .as_ref()
                        .is_some_and(|c| c.operation == b.operation)
                    {
                        self.close = None;
                    }
                }
                _ => (),
            }
            if matches!(
                b.phase.as_str(),
                "recovery" | "worker_handoff" | "loss_handoff"
            ) {
                self.recovering = None;
            }
            self.revision = b.revision;
            self.head = frame.head()?;
            self.last_state = b.state_digest.clone();
            self.history = Some(next_history);
            Ok(ack)
        }
    }
    pub(super) fn service_request_digest(
        db: &rusqlite::Connection,
        revision: u64,
    ) -> Result<(String, Option<String>), &'static str> {
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT frame FROM service_checkpoints WHERE revision=?1",
                [revision as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let f: Checkpoint = serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        Ok((f.body.request_digest, f.body.response_digest))
    }
    pub(super) fn successor_history(
        db: &rusqlite::Connection,
        revision: u64,
    ) -> Result<String, &'static str> {
        history(db, revision, revision, None)
    }
    pub(super) fn loss_return_completion_history(
        db: &rusqlite::Connection,
        current: u64,
        completed: u64,
    ) -> Result<String, &'static str> {
        if completed.checked_add(2) != Some(current) || current > 1025 {
            return Err("evidence_invalid");
        }
        history(db, current, completed, None)
    }
    impl Ledger {
        pub(super) fn successor_anchor(
            &self,
            root: &File,
            keys: &ChannelKeys,
        ) -> Result<(String, String, String, u64, u64), &'static str> {
            if self.loss_source_pending.is_some()
                || !self.pending.is_empty()
                || self.recovering.is_some()
                || self.close.is_some()
                || self.authority_sequence == 0
                || self.request_key != keys.reply
                || self.ack_key != keys.custody
            {
                return Err("evidence_invalid");
            }
            self.verify_authority_history(root)?;
            for sequence in 1..=self.authority_sequence {
                let mut bytes = Vec::new();
                super::super::la_artifacts::open_artifact(
                    &self.root,
                    &format!("service-authority-{sequence:03}.json"),
                    libc::O_RDONLY,
                )
                .map_err(|_| "evidence_invalid")?
                .take(16385)
                .read_to_end(&mut bytes)
                .map_err(|_| "evidence_invalid")?;
                if bytes.len() > 16384 {
                    return Err("evidence_invalid");
                }
                let (frame, cack, wack): (Vec<u8>, super::SourceAck, super::SourceAck) =
                    serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                let (binding, retained) = self.retained_source(sequence)?;
                let body = super::verify_source_observation(&keys.authority, &binding, &frame)?;
                super::verify_source_ack(&keys.reply, &binding, "controller", &body, &cack)?;
                super::verify_source_ack(&keys.reply, &binding, "worker", &body, &wack)?;
                if frame != retained || cack.sequence != sequence || wack.sequence != sequence {
                    return Err("evidence_invalid");
                }
            }
            let db = super::super::la_store::open_pinned_readonly_database(
                root,
                "service-custody.sqlite",
            )?;
            let (f, a): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT frame,ack FROM service_checkpoints WHERE revision=?1",
                    [self.revision as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let f: Checkpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
            let a: Ack = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
            let (head, state) = verified_anchor(root, &f, &a, keys)?;
            let history = successor_history(&db, self.revision)?;
            if f.body.binding != self.binding
                || head != self.head
                || state != self.last_state
                || self.history.as_ref() != Some(&history)
            {
                return Err("evidence_invalid");
            }
            Ok((head, state, history, self.revision, self.authority_sequence))
        }
    }

    impl Ledger {
        pub(super) fn loss_return_root(&self) -> Result<File, &'static str> {
            self.root.try_clone().map_err(|_| "storage_unavailable")
        }
        pub(super) fn entered_loss_return_anchor(
            &self,
            root: &File,
        ) -> Result<(String, String, String, u64, u64), &'static str> {
            // Post-release custody is DISTINCT from cleanup's still-held claim
            // anchor. Exact consumed certificate/Close/settlement are checked by
            // WorkerLossReturn; original cleanup's pre-release predicate stays.
            if self.loss_source_pending.is_some()
                || !self.pending.is_empty()
                || self.recovering.is_some()
                || self.close.is_some()
                || self.revision == 0
                || self.revision >= 1025
                || self.authority_sequence == 0
                || self.request_key != self.keys.reply
                || self.ack_key != self.keys.custody
            {
                return Err("evidence_invalid");
            }
            self.verify_authority_history(root)?;
            let db = super::super::la_store::open_pinned_readonly_database(
                root,
                "service-custody.sqlite",
            )?;
            let (f, a): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT frame,ack FROM service_checkpoints WHERE revision=?1",
                    [self.revision as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let f: Checkpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
            let a: Ack = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
            let (head, state) = verified_anchor(root, &f, &a, &self.keys)?;
            let history = successor_history(&db, self.revision)?;
            if f.body.binding != self.binding
                || head != self.head
                || state != self.last_state
                || self.history.as_ref() != Some(&history)
            {
                return Err("evidence_invalid");
            }
            Ok((head, state, history, self.revision, self.authority_sequence))
        }
        pub(in crate::cosp) fn loss_source_anchor(
            &self,
            root: &File,
        ) -> Result<(String, String, String, u64, u64), &'static str> {
            self.successor_anchor(root, &self.keys)
        }
        pub(in crate::cosp) fn prepare_loss_source(
            &mut self,
            cap: &super::WorkerLossSource,
        ) -> Result<(), &'static str> {
            cap.verify(&self.keys, super::wall_now()?)?;
            if cap.service
                != (
                    self.head.clone(),
                    self.last_state.clone(),
                    self.history.clone().ok_or("evidence_invalid")?,
                    self.revision,
                    self.authority_sequence,
                )
                || self.loss_source_pending.is_some()
                || cap.binding != self.binding
                || !self.pending.is_empty()
                || self.close.is_some()
                || self.recovering.is_some()
            {
                return Err("evidence_invalid");
            }
            // Fence even a failed/partial file append. Only this exact C ACK
            // after durable installation can clear the independent barrier.
            self.loss_source_pending = Some(cap.digest()?);
            let mut f = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!("service-loss-source-{:03}.json", cap.previous_sequence + 1),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "storage_unavailable")?;
            f.write_all(&serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?)
                .and_then(|_| f.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            let pending = self.loss_source_pending.take();
            let result = self.record_authority(&cap.frame);
            self.loss_source_pending = pending;
            result
        }
        pub(in crate::cosp) fn observe_loss_source(
            &mut self,
            cap: &super::WorkerLossSource,
            ack: &super::SourceAck,
        ) -> Result<(), &'static str> {
            let body = cap.verify(&self.keys, super::wall_now()?)?;
            super::verify_source_ack(&self.request_key, &self.binding, "controller", &body, ack)?;
            let (binding, frame) = self.retained_source(ack.sequence)?;
            if self.loss_source_pending.as_deref() != Some(cap.digest()?.as_str())
                || binding != cap.binding
                || frame != cap.frame
                || ack.sequence != self.authority_sequence
                || ack.sequence != cap.previous_sequence + 1
            {
                return Err("evidence_invalid");
            }
            let mut f = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!("service-authority-{:03}.json", ack.sequence),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "storage_unavailable")?;
            // Deliberately distinct from the ordinary (frame,C ACK,W ACK) tuple.
            f.write_all(&serde_json::to_vec(&(cap, ack)).map_err(|_| "evidence_invalid")?)
                .and_then(|_| f.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            self.loss_source_pending = None;
            Ok(())
        }
    }

    impl Ledger {
        pub(super) fn prepare_entered_loss_source_bridge(
            &mut self,
            root: &File,
            cap: &super::EnteredLossSourceBridge,
        ) -> Result<(), &'static str> {
            let anchor = self.entered_loss_return_anchor(root)?;
            if anchor != cap.service || self.binding != cap.previous {
                return Err("evidence_invalid");
            }
            // Fence before the first role append; an error after this point
            // remains quarantined. No generic replay can clear this barrier.
            self.loss_source_pending = Some(cap.digest()?);
            let mut f = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!(
                    "service-loss-source-bridge-{:04}.json",
                    cap.binding.worker_epoch
                ),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "evidence_invalid")?;
            f.write_all(&serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?)
                .and_then(|_| f.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            self.recovering = Some(cap.digest()?);
            self.binding = cap.binding.clone();
            Ok(())
        }
        fn verify_loss_source_service(
            &self,
            root: &File,
            cap: &super::EnteredLossSourceBridge,
        ) -> Result<(String, String, String, u64, u64), &'static str> {
            if self.binding != cap.binding
                || self.loss_source_pending.as_deref() != Some(cap.digest()?.as_str())
                || self.recovering.is_some()
                || !self.pending.is_empty()
                || self.close.is_some()
                || self.revision != cap.service.3 + 1
                || self.last_state != cap.service.1
                || state_digest(root)? != self.last_state
            {
                return Err("evidence_invalid");
            }
            let db = super::super::la_store::open_pinned_readonly_database(
                root,
                "service-custody.sqlite",
            )?;
            let (f, a): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT frame,ack FROM service_checkpoints WHERE revision=?1",
                    [self.revision as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let f: Checkpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
            let a: Ack = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
            a.verify(&f, &self.ack_key)?;
            let current = history(&db, self.revision, self.revision, None)?;
            if f.body.phase != "loss_handoff"
                || f.body.binding != cap.binding
                || f.body.previous != cap.service.0
                || f.body.request_digest != cap.digest()?
                || f.head() != Ok(self.head.clone())
                || self.history.as_ref() != Some(&current)
                || history(&db, self.revision, cap.service.3, None)? != cap.service.2
            {
                return Err("evidence_invalid");
            }
            Ok((
                self.head.clone(),
                self.last_state.clone(),
                current,
                self.revision,
                self.authority_sequence,
            ))
        }
        pub(super) fn complete_entered_loss_source_bridge(
            &mut self,
            croot: &File,
            wroot: &File,
            cap: &super::EnteredLossSourceBridge,
            keys: &ChannelKeys,
        ) -> Result<super::LossSourceBridgeCompletion, &'static str> {
            cap.fresh(super::wall_now()?)?;
            let worker = cap.installed_ack(wroot, "worker", keys)?;
            let wt = super::wall_now()?;
            let controller = cap.installed_ack(croot, "controller", keys)?;
            let ct = super::wall_now()?;
            let anchor = self.verify_loss_source_service(croot, cap)?;
            let mut complete = super::LossSourceBridgeCompletion {
                bridge: cap.digest()?,
                worker,
                controller,
                worker_observed_at: wt,
                controller_observed_at: ct,
                service: anchor,
                mac: [0; 32],
            };
            complete.mac = complete.signature(&keys.custody)?;
            complete.verify(cap, keys, super::wall_now()?)?;
            let mut f = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!(
                    "service-loss-source-consumed-{:04}.json",
                    cap.binding.worker_epoch
                ),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "evidence_invalid")?;
            f.write_all(&serde_json::to_vec(&complete).map_err(|_| "evidence_invalid")?)
                .and_then(|_| f.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            cap.fresh(super::wall_now()?)?;
            Ok(complete)
        }
        pub(super) fn finish_entered_loss_source_bridge(
            &mut self,
            cap: &super::EnteredLossSourceBridge,
            complete: &super::LossSourceBridgeCompletion,
        ) -> Result<(), &'static str> {
            complete.verify(cap, &self.keys, super::wall_now()?)?;
            if self.loss_source_pending.as_deref() != Some(cap.digest()?.as_str())
                || self.head != complete.service.0
                || self.history.as_ref() != Some(&complete.service.2)
                || self.revision != complete.service.3
            {
                return Err("evidence_invalid");
            }
            let mut bytes = Vec::new();
            super::super::la_artifacts::open_artifact(
                &self.root,
                &format!(
                    "service-loss-source-consumed-{:04}.json",
                    cap.binding.worker_epoch
                ),
                libc::O_RDONLY,
            )
            .map_err(|_| "evidence_invalid")?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "evidence_invalid")?;
            if bytes != serde_json::to_vec(complete).map_err(|_| "evidence_invalid")? {
                return Err("evidence_invalid");
            }
            self.loss_source_pending = None;
            Ok(())
        }
    }
    impl Session {
        pub(super) fn install_loss_source_handoff(
            &self,
            cap: &super::EnteredLossSourceBridge,
            keys: &ChannelKeys,
        ) -> Result<(), &'static str> {
            cap.fresh(super::wall_now()?)?;
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            j.check()?;
            if j.binding != cap.previous
                || j.revision != cap.service.3
                || j.head != cap.service.0
                || j.last_state != cap.service.1
                || j.history != cap.service.2
                || !j.pending.is_empty()
                || j.close.is_some()
                || state_digest(&j.root)? != cap.service.1
                || j.link.request_key != keys.reply
                || j.link.ack_key != keys.custody
            {
                return Err("evidence_invalid");
            }
            j.binding = cap.binding.clone();
            let next = j.next;
            j.checkpoint(next, "loss_handoff", &cap.digest()?, None)
        }
    }

    pub(in crate::cosp) fn verified_anchor(
        root: &File,
        checkpoint: &Checkpoint,
        ack: &Ack,
        keys: &ChannelKeys,
    ) -> Result<(String, String), &'static str> {
        ack.verify(checkpoint, &keys.custody)?;
        let b = &checkpoint.body;
        if !bool::from(
            typed_mac(&keys.reply, b"diffuser-service-state-checkpoint/v1\0", b)?
                .ct_eq(&checkpoint.mac),
        ) || !matches!(b.phase.as_str(), "genesis" | "complete")
            || state_digest(root)? != b.state_digest
        {
            return Err("evidence_invalid");
        }
        let db =
            super::super::la_store::open_pinned_readonly_database(root, "service-custody.sqlite")?;
        history(&db, b.revision, b.revision, None)?;
        let (frame, saved_ack): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM service_checkpoints WHERE revision=?1",
                [b.revision as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if frame != serde_json::to_vec(checkpoint).map_err(|_| "evidence_invalid")?
            || saved_ack != serde_json::to_vec(ack).map_err(|_| "evidence_invalid")?
        {
            return Err("evidence_invalid");
        }
        Ok((checkpoint.head()?, b.state_digest.clone()))
    }

    pub(super) fn verify_recovery_consumed(
        root: &File,
        binding: &ChannelBinding,
        capability: &str,
        keys: &ChannelKeys,
        issued: u64,
        expires: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        let db =
            super::super::la_store::open_pinned_readonly_database(root, "service-custody.sqlite")?;
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM service_checkpoints", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        if count <= 0 || count > 1025 {
            return Err("evidence_invalid");
        }
        history(&db, count as u64, count as u64, None)?;
        let mut previous = "0".repeat(64);
        let mut found = false;
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        for revision in 1..=count {
            let (f, a): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT frame,ack FROM service_checkpoints WHERE revision=?1",
                    [revision],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let frame: Checkpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
            let ack: Ack = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
            ack.verify(&frame, &keys.custody)?;
            let b = &frame.body;
            if b.revision != revision as u64
                || b.previous != previous
                || (b.root_dev, b.root_inode) != (m.dev(), m.ino())
                || !bool::from(
                    typed_mac(&keys.reply, b"diffuser-service-state-checkpoint/v1\0", b)?
                        .ct_eq(&frame.mac),
                )
            {
                return Err("evidence_invalid");
            }
            previous = frame.head()?;
            if b.binding == *binding && b.phase == "recovery" && b.request_digest == capability {
                if found {
                    return Err("evidence_invalid");
                }
                ack.consumption
                    .as_ref()
                    .ok_or("evidence_invalid")?
                    .verify_window(&keys.custody, capability, issued, expires, now)?;
                found = true;
            }
        }
        if !found {
            return Err("evidence_invalid");
        }
        Ok(())
    }

    /// P-only handoff of a completed checkpoint or exact held close midpoint.
    /// This is a custody
    /// capability, never resource qualification or authority to resume work.
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Recovery {
        pub(super) previous_binding: ChannelBinding,
        pub(super) binding: ChannelBinding,
        revision: u64,
        head: String,
        history: String,
        state: String,
        pub(in crate::cosp) root_dev: u64,
        pub(in crate::cosp) root_inode: u64,
        next: u64,
        issued_at: u64,
        pub(super) expires_at: u64,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        consumption_required: bool,
        mac: [u8; 32],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub(super) close: Option<ControlMidpoint>,
    }
    impl Recovery {
        pub(in crate::cosp) fn pending_close_operation(&self) -> Option<u64> {
            self.close
                .as_ref()
                .filter(|c| c.phase().ok() == Some("close_intent"))
                .map(|c| c.operation)
        }
        pub(in crate::cosp) fn pending_stop_operation(&self) -> Option<u64> {
            self.close
                .as_ref()
                .filter(|c| c.phase().ok() == Some("stop_intent"))
                .map(|c| c.operation)
        }
        pub(in crate::cosp) fn pending_operation(&self) -> Option<u64> {
            self.close.as_ref().map(|c| c.operation)
        }
        pub(super) fn verify(
            &self,
            root: &File,
            binding: &ChannelBinding,
            key: &[u8; 32],
            now: u64,
        ) -> Result<(), &'static str> {
            let m = root.metadata().map_err(|_| "evidence_invalid")?;
            if self.binding != *binding
                || !controller_successor(&self.previous_binding, &self.binding)
                || (m.dev(), m.ino()) != (self.root_dev, self.root_inode)
                || self.issued_at > now
                || now >= self.expires_at
                || self.expires_at <= self.issued_at
                || self.expires_at - self.issued_at > 1500
                || self.revision == 0
                || self.revision >= 1025
                || self.next > 512
                || !bool::from(self.signature(key)?.ct_eq(&self.mac))
            {
                return Err("evidence_invalid");
            }
            let _exclusive = lock_existing(root)?;
            let db = super::super::la_store::open_pinned_readonly_database(
                root,
                "service-custody.sqlite",
            )?;
            if history(&db, self.revision, self.revision, None)? != self.history
                || state_digest(root)? != self.state
            {
                return Err("evidence_invalid");
            }
            Ok(())
        }
        fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
            let mut body = self.clone();
            body.mac = [0; 32];
            typed_mac(key, b"diffuser-service-recovery/v1\0", &body)
        }
        pub(super) fn digest(&self) -> Result<String, &'static str> {
            Ok(hex::encode(Sha256::digest(
                serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
            )))
        }
    }
    fn controller_successor(old: &ChannelBinding, new: &ChannelBinding) -> bool {
        let mut expected = old.clone();
        let Some(epoch) = old.controller_epoch.checked_add(1) else {
            return false;
        };
        expected.controller_epoch = epoch;
        expected.controller_boot = new.controller_boot.clone();
        new.validate().is_ok() && *new == expected && old.controller_boot != new.controller_boot
    }
    fn lock_existing(root: &File) -> Result<File, &'static str> {
        let file = super::super::la_artifacts::open_artifact(
            root,
            "service-custody.sqlite",
            libc::O_RDONLY,
        )
        .map_err(|_| "evidence_invalid")?;
        let m = file.metadata().map_err(|_| "evidence_invalid")?;
        if !m.is_file()
            || m.nlink() != 1
            || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        {
            return Err("evidence_invalid");
        }
        Ok(file)
    }
    impl Ledger {
        /// The retained P ledger supplies every trusted head. Recovering C
        /// cannot choose its own revision, state, operation high-water or epoch.
        /// Caller must also establish exact old-role death on the protected
        /// process path before using this handoff for a controller restart.
        pub(in crate::cosp) fn authorize_recovery(
            &mut self,
            role_root: &File,
            binding: ChannelBinding,
            now: u64,
            expires: u64,
        ) -> Result<Recovery, &'static str> {
            self.authorize_recovery_mode(role_root, binding, now, expires, false)
        }
        pub(in crate::cosp) fn authorize_consumable_recovery(
            &mut self,
            role_root: &File,
            binding: ChannelBinding,
            now: u64,
            expires: u64,
        ) -> Result<Recovery, &'static str> {
            self.authorize_recovery_mode(role_root, binding, now, expires, true)
        }
        fn authorize_recovery_mode(
            &mut self,
            role_root: &File,
            binding: ChannelBinding,
            now: u64,
            expires: u64,
            consumption_required: bool,
        ) -> Result<Recovery, &'static str> {
            if !controller_successor(&self.binding, &binding)
                || self.revision == 0
                || self.revision >= 1025
                || (!self.pending.is_empty()
                    && !self.close.as_ref().is_some_and(|c| {
                        self.pending.len() == 1
                            && self.pending.get(&c.operation) == Some(&c.request_digest)
                    }))
                || self.recovering.is_some()
                || expires <= now
                || expires - now > 1500
            {
                return Err("evidence_invalid");
            }
            if let Some(close) = &self.close {
                close.verify(role_root, &self.binding, &self.keys)?;
                self.verify_authority_history(role_root)?;
                if close.authority_sequence != self.authority_sequence {
                    return Err("evidence_invalid");
                }
            }
            let _lock = lock_existing(role_root)?;
            let db = super::super::la_store::open_pinned_readonly_database(
                role_root,
                "service-custody.sqlite",
            )?;
            let history_digest = history(&db, self.revision, self.revision, None)?;
            if self.history.as_ref() != Some(&history_digest)
                || state_digest(role_root)? != self.last_state
            {
                return Err("evidence_invalid");
            }
            let m = role_root.metadata().map_err(|_| "evidence_invalid")?;
            let mut recovery = Recovery {
                previous_binding: self.binding.clone(),
                binding: binding.clone(),
                revision: self.revision,
                head: self.head.clone(),
                history: history_digest,
                state: self.last_state.clone(),
                root_dev: m.dev(),
                root_inode: m.ino(),
                next: self.next,
                issued_at: now,
                expires_at: expires,
                consumption_required,
                mac: [0; 32],
                close: self.close.clone(),
            };
            recovery.mac = recovery.signature(&self.ack_key)?;
            if serde_json::to_vec(&recovery)
                .map_err(|_| "evidence_invalid")?
                .len()
                > 4096
            {
                return Err("evidence_invalid");
            }
            // O_EXCL is a durable, one-way epoch claim in P's separate root.
            // A lost reply never permits the old writer to resume issuing ACKs.
            let mut file = super::super::la_artifacts::open_artifact(
                &self.root,
                &format!("service-recovery-{:04}.json", binding.controller_epoch),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .map_err(|_| "storage_unavailable")?;
            file.write_all(&serde_json::to_vec(&recovery).map_err(|_| "evidence_invalid")?)
                .and_then(|_| file.sync_all())
                .and_then(|_| self.root.sync_all())
                .map_err(|_| "storage_unavailable")?;
            self.recovering = Some(recovery.digest()?);
            self.binding = binding;
            Ok(recovery)
        }
    }
    impl Session {
        /// Reopen exact authenticated history under the new exclusive writer.
        /// No genesis replacement, work dispatch, quota release or worker
        /// activation occurs here. Missing ACKs and all other incomplete
        /// intents close; an exact close midpoint retains its pending operation.
        pub(in crate::cosp) fn recover(
            root: &File,
            link: Arc<Link>,
            recovery: &Recovery,
            now: u64,
        ) -> Result<Arc<Self>, &'static str> {
            let m = root.metadata().map_err(|_| "evidence_invalid")?;
            if recovery.binding != link.binding
                || !controller_successor(&recovery.previous_binding, &recovery.binding)
                || (m.dev(), m.ino()) != (recovery.root_dev, recovery.root_inode)
                || recovery.issued_at > now
                || now >= recovery.expires_at
                || recovery.expires_at <= recovery.issued_at
                || recovery.expires_at - recovery.issued_at > 1500
                || recovery.revision == 0
                || recovery.revision >= 1025
                || recovery.next > 512
                || !bool::from(recovery.signature(&link.ack_key)?.ct_eq(&recovery.mac))
            {
                return Err("evidence_invalid");
            }
            let file = lock_existing(root)?;
            let db = super::super::la_store::open_pinned_database(
                root,
                "service-custody.sqlite",
                false,
            )?;
            db.execute_batch("PRAGMA synchronous=FULL;")
                .map_err(|_| "storage_unavailable")?;
            if history(&db, recovery.revision, recovery.revision, None)? != recovery.history
                || state_digest(root)? != recovery.state
            {
                return Err("evidence_invalid");
            }
            let bytes: Vec<u8> = db
                .query_row(
                    "SELECT frame FROM service_checkpoints WHERE revision=?1",
                    [recovery.revision as i64],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            let last: Checkpoint =
                serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
            if last.head()? != recovery.head
                || last.body.binding != recovery.previous_binding
                || !(matches!(
                    last.body.phase.as_str(),
                    "genesis" | "complete" | "recovery"
                ) && recovery.close.is_none()
                    || matches!(last.body.phase.as_str(), "close_intent" | "stop_intent")
                        && recovery.close.as_ref().is_some_and(|c| {
                            c.operation == last.body.operation
                                && c.phase().ok() == Some(last.body.phase.as_str())
                                && c.request_digest == last.body.request_digest
                                && c.digest().ok().as_ref() == last.body.response_digest.as_ref()
                        }))
                || !bool::from(
                    typed_mac(
                        &link.request_key,
                        b"diffuser-service-state-checkpoint/v1\0",
                        &last.body,
                    )?
                    .ct_eq(&last.mac),
                )
            {
                return Err("evidence_invalid");
            }
            let mut j = Journal {
                root: root.try_clone().map_err(|_| "storage_unavailable")?,
                db,
                file,
                binding: link.binding.clone(),
                link,
                revision: recovery.revision,
                head: recovery.head.clone(),
                last_state: recovery.state.clone(),
                history: recovery.history.clone(),
                pending: recovery
                    .close
                    .as_ref()
                    .map(|c| {
                        [(c.operation, c.request_digest.clone())]
                            .into_iter()
                            .collect()
                    })
                    .unwrap_or_default(),
                next: recovery.next,
                failed: false,
                close: recovery.close.clone(),
            };
            j.checkpoint(recovery.next, "recovery", &recovery.digest()?, None)?;
            Ok(Arc::new(Self(Mutex::new(j))))
        }
    }

    impl Session {
        /// Fixed exact frontier for loss-return copy/final consumption. Full
        /// durable history is reread; a matching scalar head is insufficient.
        pub(super) fn loss_return_completion_anchor(
            &self,
        ) -> Result<(String, String, String, u64), &'static str> {
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            let result = (|| {
                j.check()?;
                let history = successor_history(&j.db, j.revision)?;
                if !j.pending.is_empty()
                    || j.close.is_some()
                    || j.history != history
                    || state_digest(&j.root)? != j.last_state
                {
                    return Err("evidence_invalid");
                }
                Ok((j.head.clone(), j.last_state.clone(), history, j.revision))
            })();
            if result.is_err() {
                j.failed = true;
            }
            result
        }
        pub(in crate::cosp) fn activation_anchor(&self) -> Result<(String, String), &'static str> {
            let mut j = self.0.lock().map_err(|_| "storage_unavailable")?;
            let result = (|| {
                j.check()?;
                if !j.pending.is_empty() || state_digest(&j.root)? != j.last_state {
                    return Err("evidence_invalid");
                }
                Ok((j.head.clone(), j.last_state.clone()))
            })();
            if result.is_err() {
                j.failed = true;
            }
            result
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::DirBuilderExt;
        fn setup() -> (std::path::PathBuf, File, File, ChannelBinding, ChannelKeys) {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "la-state-custody-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join("custody"))
                .unwrap();
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join("service"))
                .unwrap();
            let root =
                super::super::super::la_artifacts::open_owned_root(&path.join("service")).unwrap();
            let parent =
                super::super::super::la_artifacts::open_owned_root(&path.join("custody")).unwrap();
            let binding = ChannelBinding {
                worker: "worker_cpu_000001".into(),
                worker_boot: "a".repeat(64),
                controller_boot: "b".repeat(64),
                worker_epoch: 1,
                controller_epoch: 1,
                hardware_generation: 1,
                profile_epoch: 1,
                policy_digest: "c".repeat(64),
                source_digest: "d".repeat(64),
                executable_digest: "e".repeat(64),
            };
            let keys = ChannelKeys::from_protected_hex(
                &"1".repeat(64),
                &"2".repeat(64),
                &"3".repeat(64),
                &"4".repeat(64),
            )
            .unwrap();
            (path, root, parent, binding, keys)
        }

        #[derive(Serialize, Deserialize)]
        struct RecoveryChild {
            root: std::path::PathBuf,
            binding: ChannelBinding,
            keys: [String; 4],
            recovery: Option<Recovery>,
        }
        #[test]
        fn recovery_custody_child() {
            use std::io::BufRead;
            if std::env::var_os("DIFFUSER_CUSTODY_RECOVERY_CHILD").is_none() {
                // Roleless ordinary test execution has no recovery authority.
                assert!(!controller_successor(&setup_binding(), &setup_binding()));
                return;
            }
            let read = || {
                let mut bytes = String::new();
                std::io::stdin()
                    .lock()
                    .take(16385)
                    .read_line(&mut bytes)
                    .unwrap();
                assert!(bytes.len() <= 16384);
                bytes
            };
            let config: RecoveryChild = serde_json::from_str(&read()).unwrap();
            let keys = ChannelKeys::from_protected_hex(
                &config.keys[0],
                &config.keys[1],
                &config.keys[2],
                &config.keys[3],
            )
            .unwrap();
            let root = super::super::super::la_artifacts::open_owned_root(&config.root).unwrap();
            let holder = Arc::new(Mutex::new(None::<std::sync::Weak<Link>>));
            let callback = holder.clone();
            let link = Link::new(
                config.binding,
                &keys,
                Box::new(move |bytes| {
                    println!(
                        "RECOVERY_CHECKPOINT {}",
                        std::str::from_utf8(bytes).unwrap()
                    );
                    std::io::stdout().flush().unwrap();
                    let ack = read();
                    callback
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .upgrade()
                        .unwrap()
                        .accept(ack.trim().as_bytes())
                }),
            )
            .unwrap();
            *holder.lock().unwrap() = Some(Arc::downgrade(&link));
            let session = if let Some(recovery) = config.recovery {
                Session::recover(&root, link, &recovery, 101).unwrap()
            } else {
                let session = Session::create(&root, link).unwrap();
                let op = session.begin(&"a".repeat(64)).unwrap();
                let mut file = super::super::super::la_artifacts::open_artifact(
                    &root,
                    "report.json",
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                )
                .unwrap();
                file.write_all(b"process durable report").unwrap();
                file.sync_all().unwrap();
                root.sync_all().unwrap();
                drop(file);
                session.complete(op, &"b".repeat(64)).unwrap();
                session
            };
            session.check().unwrap();
            assert_eq!(
                std::fs::read(config.root.join("report.json")).unwrap(),
                b"process durable report"
            );
            println!("RECOVERY_READY");
            std::io::stdout().flush().unwrap();
            assert_eq!(read().trim(), "STOP");
        }
        fn setup_binding() -> ChannelBinding {
            ChannelBinding {
                worker: "worker_cpu_000001".into(),
                worker_boot: "a".repeat(64),
                controller_boot: "b".repeat(64),
                worker_epoch: 1,
                controller_epoch: 1,
                hardware_generation: 1,
                profile_epoch: 1,
                policy_digest: "c".repeat(64),
                source_digest: "d".repeat(64),
                executable_digest: "e".repeat(64),
            }
        }
        #[test]
        fn process_kill_then_new_boot_recovers_exact_parent_witnessed_service_state() {
            use std::{
                io::BufRead,
                os::unix::process::ExitStatusExt,
                process::{Command, Stdio},
            };
            struct Child(std::process::Child);
            impl Drop for Child {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let (path, root, parent, binding, _) = setup();
            let mut entropy = File::open("/dev/urandom").unwrap();
            let mut random = [0u8; 128];
            entropy.read_exact(&mut random).unwrap();
            let secret: [String; 4] =
                std::array::from_fn(|i| hex::encode(&random[i * 32..(i + 1) * 32]));
            let keys =
                ChannelKeys::from_protected_hex(&secret[0], &secret[1], &secret[2], &secret[3])
                    .unwrap();
            let mut ledger = Ledger::new(&parent, binding.clone(), &keys).unwrap();
            let spawn = |config: RecoveryChild| {
                let mut child = Child(
                    Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "cosp::la_adapter::state_custody::tests::recovery_custody_child",
                            "--nocapture",
                        ])
                        .env("DIFFUSER_CUSTODY_RECOVERY_CHILD", "1")
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap(),
                );
                let mut input = child.0.stdin.take().unwrap();
                writeln!(input, "{}", serde_json::to_string(&config).unwrap()).unwrap();
                input.flush().unwrap();
                let output = child.0.stdout.take().unwrap();
                let (send, receive) = std::sync::mpsc::sync_channel(16);
                let reader = std::thread::spawn(move || {
                    for line in std::io::BufReader::new(output).lines() {
                        let Ok(line) = line else { break };
                        if send.send(line).is_err() {
                            break;
                        }
                    }
                });
                (child, input, receive, reader)
            };
            let observe = |ledger: &mut Ledger,
                           input: &mut std::process::ChildStdin,
                           receive: &std::sync::mpsc::Receiver<String>| {
                let mut frames = 0;
                loop {
                    let line = receive
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                    if let Some(bytes) = line
                        .split_once("RECOVERY_CHECKPOINT ")
                        .map(|(_, bytes)| bytes)
                    {
                        let frame: Checkpoint = serde_json::from_str(bytes).unwrap();
                        let ack = ledger.observe(&root, &frame).unwrap();
                        writeln!(input, "{}", serde_json::to_string(&ack).unwrap()).unwrap();
                        input.flush().unwrap();
                        frames += 1;
                    }
                    if line == "RECOVERY_READY" {
                        break;
                    }
                }
                frames
            };
            let (mut old, mut input, receive, reader) = spawn(RecoveryChild {
                root: path.join("service"),
                binding: binding.clone(),
                keys: secret.clone(),
                recovery: None,
            });
            assert_eq!(observe(&mut ledger, &mut input, &receive), 3);
            let old_pid = old.0.id();
            old.0.kill().unwrap();
            let status = old.0.wait().unwrap();
            assert_eq!(status.signal(), Some(9));
            reader.join().unwrap();
            drop(input);
            drop(old);
            let mut next = binding;
            next.controller_boot = "f".repeat(64);
            next.controller_epoch = 2;
            let recovery = ledger
                .authorize_recovery(&root, next.clone(), 100, 200)
                .unwrap();
            let (mut new, mut input, receive, reader) = spawn(RecoveryChild {
                root: path.join("service"),
                binding: next,
                keys: secret,
                recovery: Some(recovery),
            });
            assert_eq!(observe(&mut ledger, &mut input, &receive), 1);
            assert_ne!(old_pid, new.0.id());
            writeln!(input, "STOP").unwrap();
            input.flush().unwrap();
            drop(input);
            assert!(new.0.wait().unwrap().success());
            reader.join().unwrap();
            assert_eq!(ledger.next, 1);
            assert_eq!(ledger.revision, 4);
            println!(
                "ACTUAL_CUSTODY_RECOVERY {}",
                serde_json::json!({"old_pid":old_pid,"new_pid":new.0.id(),"old_signal":status.signal(),"controller_epoch":2,"revision":4,"operations":1,"report_sha256":hex::encode(Sha256::digest(b"process durable report")),"worker_starts":0,"admitted_jobs":0,"M6_complete":false})
            );
            std::fs::remove_dir_all(path).unwrap();
        }

        fn witnessed_link(
            root: &File,
            binding: ChannelBinding,
            keys: &ChannelKeys,
            ledger: Arc<Mutex<Ledger>>,
        ) -> Arc<Link> {
            let holder = Arc::new(Mutex::new(None::<std::sync::Weak<Link>>));
            let callback = holder.clone();
            let observed = root.try_clone().unwrap();
            let link = Link::new(
                binding,
                keys,
                Box::new(move |bytes| {
                    let frame: Checkpoint =
                        serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
                    let ack = ledger.lock().unwrap().observe(&observed, &frame)?;
                    callback
                        .lock()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .upgrade()
                        .unwrap()
                        .accept(&serde_json::to_vec(&ack).unwrap())
                }),
            )
            .unwrap();
            *holder.lock().unwrap() = Some(Arc::downgrade(&link));
            link
        }
        #[test]
        fn close_midpoint_recovers_only_exact_held_close_and_preserves_unfinished_operation() {
            use super::super::{
                CloseCommand, RpcRequest, SignedRequest, TransportJournal, WorkerOperation,
            };
            for refusal in [
                "none",
                "quota",
                "authority",
                "signature",
                "outbox",
                "history",
            ] {
                let (path, root, parent, binding, keys) = setup();
                let mut claims = super::super::super::la_store::ClaimStore::open(
                    &path.join("service/lane_assignments.sqlite"),
                )
                .unwrap();
                let body=super::super::super::la_contract::canonical_json(br#"{"schema_version":"diffuser-authority-observation/v1","sequence":1,"observed_at":100,"revoked":[]}"#).unwrap();
                let mac = super::super::sign_authority_observation(&keys.authority, &body);
                claims
                    .append_authority_observation(&keys.authority, &body, &mac)
                    .unwrap();
                let db = rusqlite::Connection::open(path.join("service/lane_assignments.sqlite"))
                    .unwrap();
                db.execute_batch("INSERT INTO la_assignments VALUES('assignment_000001','project_12345678','actor_1234567890','worker_cpu_000001',1,'assigned'); INSERT INTO la_reservations VALUES('domain_123456789','assignment_000001'); INSERT INTO la_quota_charges VALUES('assignment_000001','project_12345678','actor_1234567890'); INSERT INTO la_assignment_grant_charges VALUES('assignment_000001','grant_123456789'); INSERT INTO la_assignment_revisions VALUES('assignment_000001',1);").unwrap();
                db.execute("INSERT INTO la_reservation_authorizations VALUES('assignment_000001',?1,?2,1,'reserve_12345678')",rusqlite::params![binding.worker,binding.worker_boot]).unwrap();
                let mut channel = TransportJournal::create(
                    &root,
                    &path.join("service"),
                    "controller-channel.sqlite",
                    binding.clone(),
                )
                .unwrap();
                let ledger = Arc::new(Mutex::new(
                    Ledger::new(&parent, binding.clone(), &keys).unwrap(),
                ));
                let frame = super::super::sign_source_observation(&keys.authority, &binding, &body)
                    .unwrap();
                if refusal != "authority" {
                    let c = super::super::source_ack(&keys.reply, &binding, "controller", &body)
                        .unwrap();
                    let w =
                        super::super::source_ack(&keys.reply, &binding, "worker", &body).unwrap();
                    ledger.lock().unwrap().record_authority(&frame).unwrap();
                    ledger
                        .lock()
                        .unwrap()
                        .observe_authority(&frame, &c, &w)
                        .unwrap();
                }
                let link = witnessed_link(&root, binding.clone(), &keys, ledger.clone());
                let session = Session::create(&root, link).unwrap();
                let operation = session.begin(&"7".repeat(64)).unwrap();
                claims
                    .request_assignment_release(
                        "project_12345678",
                        "actor_1234567890",
                        "assignment_000001",
                        "release_key_123456",
                        1,
                        100,
                    )
                    .unwrap();
                let request = RpcRequest {
                    version: 1,
                    binding: binding.clone(),
                    sequence: 1,
                    input_digest: hex::encode(Sha256::digest([])),
                    input_bytes: 0,
                    operation: WorkerOperation::Close(CloseCommand {
                        worker: binding.worker.clone(),
                        boot: binding.worker_boot.clone(),
                        assignment: "assignment_000001".into(),
                        fence: 1,
                        operation: "release_assignment_000001".into(),
                    }),
                };
                let mut signature =
                    typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &request).unwrap();
                if refusal == "signature" {
                    signature[0] ^= 1;
                }
                let envelope = serde_json::to_vec(&SignedRequest {
                    request: request.clone(),
                    mac: signature,
                })
                .unwrap();
                channel
                    .begin(
                        1,
                        &super::super::rpc_content_digest(&request).unwrap(),
                        &envelope,
                    )
                    .unwrap();
                if refusal == "quota" {
                    db.execute("DELETE FROM la_quota_charges", []).unwrap();
                }
                if refusal == "outbox" {
                    db.execute("UPDATE la_outbox SET action='reserve'", [])
                        .unwrap();
                }
                if refusal == "source" {
                    let changed=super::super::super::la_contract::canonical_json(br#"{"schema_version":"diffuser-authority-observation/v1","sequence":2,"observed_at":101,"revoked":[]}"#).unwrap();
                    let mac = super::super::sign_authority_observation(&keys.authority, &changed);
                    db.execute(
                        "UPDATE la_authority_observations SET body=?1,mac=?2",
                        rusqlite::params![changed, mac.as_slice()],
                    )
                    .unwrap();
                }
                let result = session.close_midpoint(&envelope, &keys);
                if matches!(refusal, "none" | "history") {
                    result.unwrap();
                    assert_eq!(
                        session.complete(operation, &"8".repeat(64)).err(),
                        Some("transport_uncertain")
                    );
                    assert_eq!(ledger.lock().unwrap().pending.len(), 1);
                    assert!(session.begin(&"8".repeat(64)).is_err());
                    drop(session);
                    if refusal == "history" {
                        let db =
                            rusqlite::Connection::open(path.join("service/service-custody.sqlite"))
                                .unwrap();
                        db.execute(
                            "UPDATE service_close_midpoints SET body=?1",
                            [b"{}".as_slice()],
                        )
                        .unwrap();
                    }
                    let mut next = binding.clone();
                    next.controller_epoch = 2;
                    next.controller_boot = "f".repeat(64);
                    let recovered =
                        ledger
                            .lock()
                            .unwrap()
                            .authorize_recovery(&root, next.clone(), 100, 200);
                    if refusal == "history" {
                        assert!(recovered.is_err());
                    } else {
                        let recovery = recovered.unwrap();
                        assert_eq!(recovery.pending_close_operation(), Some(operation));
                        let link = witnessed_link(&root, next, &keys, ledger.clone());
                        let recovered = Session::recover(&root, link, &recovery, 100).unwrap();
                        assert_eq!(
                            recovered.0.lock().unwrap().pending.get(&operation),
                            Some(&"7".repeat(64))
                        );
                        assert!(recovered.begin(&"9".repeat(64)).is_err());
                        assert!(recovered.activation_anchor().is_err());
                    }
                } else {
                    assert!(result.is_err(), "{refusal} must refuse");
                    assert!(ledger.lock().unwrap().close.is_none());
                    drop(session);
                }
                drop(channel);
                drop(claims);
                drop(db);
                drop(root);
                drop(parent);
                std::fs::remove_dir_all(path).unwrap();
            }
        }

        #[test]
        fn controller_readback_handoff_preserves_claim_and_exact_transport_history() {
            use super::super::{
                CheckpointAck, ControllerReadbackRecovery, CustodyLedger, CustodyLink, RpcResponse,
                SignedCheckpoint, SignedResponse, TransportJournal, WorkerReply,
            };
            use std::os::unix::fs::MetadataExt;
            let (path, root, parent, binding, keys) = setup();
            let store_id = "7".repeat(64);
            let mut claims = super::super::super::la_store::ClaimStore::open(
                &path.join("service/lane_assignments.sqlite"),
            )
            .unwrap();
            let meta = root.metadata().unwrap();
            claims
                .bootstrap_controller_identity(&store_id, meta.dev(), meta.ino())
                .unwrap();
            claims
                .reserve(
                    "assignment_12345",
                    "project_12345678",
                    "actor_1234567890",
                    "reserve_key_12345",
                    &"9".repeat(64),
                    "worker_cpu_000001",
                    1,
                )
                .unwrap();
            let body=super::super::super::la_contract::canonical_json(br#"{"schema_version":"diffuser-authority-observation/v1","sequence":1,"observed_at":100,"revoked":[]}"#).unwrap();
            let mac = super::super::sign_authority_observation(&keys.authority, &body);
            claims
                .append_authority_observation(&keys.authority, &body, &mac)
                .unwrap();
            let mut channel = TransportJournal::create(
                &root,
                &path.join("service"),
                "controller-channel.sqlite",
                binding.clone(),
            )
            .unwrap();
            let mut ledger = CustodyLedger::bootstrap(
                &parent,
                &path.join("custody"),
                binding.clone(),
                "controller",
                keys.reply,
                keys.custody,
            )
            .unwrap();
            let (send, receive) = std::sync::mpsc::sync_channel(2);
            let link = CustodyLink::new(
                binding.clone(),
                "controller",
                keys.reply,
                keys.custody,
                Box::new(move |bytes| send.send(bytes.to_vec()).map_err(|_| "evidence_invalid")),
            )
            .unwrap();
            channel.enable_custody(link.clone()).unwrap();
            let observed = root.try_clone().unwrap();
            let witness = std::thread::spawn(move || {
                let mut last = None;
                for _ in 0..2 {
                    let frame: SignedCheckpoint =
                        serde_json::from_slice(&receive.recv().unwrap()).unwrap();
                    let ack = ledger.observe(&observed, &frame).unwrap();
                    link.accept(&serde_json::to_vec(&ack).unwrap()).unwrap();
                    last = Some((frame, ack));
                }
                (ledger, last.unwrap())
            });
            let request = super::super::RpcRequest {
                version: 1,
                binding: binding.clone(),
                sequence: 1,
                operation: super::super::WorkerOperation::Probe,
                input_digest: hex::encode(Sha256::digest([])),
                input_bytes: 0,
            };
            let mac =
                super::super::typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &request)
                    .unwrap();
            let request_digest = hex::encode(Sha256::digest(serde_json::to_vec(&request).unwrap()));
            let digest = super::super::rpc_content_digest(&request).unwrap();
            let envelope =
                serde_json::to_vec(&super::super::SignedRequest { request, mac }).unwrap();
            channel.begin(1, &digest, &envelope).unwrap();
            let response = RpcResponse {
                version: 1,
                binding: binding.clone(),
                sequence: 1,
                request_digest,
                reply: WorkerReply::Probe {
                    worker_pid: 1,
                    admission: "resource_unqualified".into(),
                },
            };
            let mac =
                super::super::typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &response)
                    .unwrap();
            channel
                .complete(
                    1,
                    &digest,
                    &serde_json::to_vec(&SignedResponse { response, mac }).unwrap(),
                )
                .unwrap();
            let (ledger, (checkpoint, ack)): (CustodyLedger, (SignedCheckpoint, CheckpointAck)) =
                witness.join().unwrap();
            let state = Arc::new(Mutex::new(
                Ledger::new(&parent, binding.clone(), &keys).unwrap(),
            ));
            let session = Session::create(
                &root,
                witnessed_link(&root, binding.clone(), &keys, state.clone()),
            )
            .unwrap();
            let mut next = binding.clone();
            next.controller_epoch = 2;
            next.controller_boot = "f".repeat(64);
            assert!(state
                .lock()
                .unwrap()
                .authorize_recovery(&root, next.clone(), 100, 200)
                .is_err());
            drop(session);
            drop(channel);
            let service = state
                .lock()
                .unwrap()
                .authorize_recovery(&root, next.clone(), 100, 200)
                .unwrap();
            assert!(ledger
                .authorize_controller_readback(
                    &root,
                    service.clone(),
                    &checkpoint,
                    &ack,
                    &store_id,
                    2,
                    &keys,
                    101
                )
                .is_err());
            assert!(ledger
                .authorize_controller_readback(
                    &root,
                    service.clone(),
                    &checkpoint,
                    &ack,
                    &"8".repeat(64),
                    1,
                    &keys,
                    101
                )
                .is_err());
            let recovery: ControllerReadbackRecovery = ledger
                .authorize_controller_readback(
                    &root,
                    service,
                    &checkpoint,
                    &ack,
                    &store_id,
                    1,
                    &keys,
                    101,
                )
                .unwrap();
            assert!(recovery.verify(&root, &binding, &keys, 101).is_err());
            assert!(recovery.verify(&root, &next, &keys, 200).is_err());
            let mut forged = recovery.clone();
            forged.authority_sequence = 2;
            assert!(forged.verify(&root, &next, &keys, 101).is_err());
            let mut forged = recovery.clone();
            forged.store_id = "8".repeat(64);
            assert!(forged.verify(&root, &next, &keys, 101).is_err());
            let before = std::fs::read(path.join("service/controller-channel.sqlite")).unwrap();
            let transport = recovery
                .reopen_transport(&root, &path.join("service"), &keys)
                .unwrap();
            assert!(recovery
                .reopen_transport(&root, &path.join("service"), &keys)
                .is_err());
            drop(transport);
            assert!(
                std::fs::read(path.join("service/controller-channel.sqlite")).unwrap() == before,
                "readback reopen must not mutate transport bytes"
            );
            let db = super::super::super::la_store::open_pinned_database(
                &root,
                "controller-channel.sqlite",
                false,
            )
            .unwrap();
            db.execute("UPDATE channel_log SET digest=?1", ["b".repeat(64)])
                .unwrap();
            assert!(recovery
                .reopen_transport(&root, &path.join("service"), &keys)
                .is_err());
            db.execute("UPDATE channel_log SET digest=?1", [digest])
                .unwrap();
            drop(db);
            let transport = recovery
                .reopen_transport(&root, &path.join("service"), &keys)
                .unwrap();
            drop(transport);
            let recovered = Session::recover(
                &root,
                witnessed_link(&root, next, &keys, state),
                recovery.service(),
                101,
            )
            .unwrap();
            let op = recovered.begin(&recovery.digest().unwrap()).unwrap();
            claims.recover_controller_identity(&recovery).unwrap();
            assert!(claims.recover_controller_identity(&recovery).is_err());
            recovered.complete(op, &recovery.digest().unwrap()).unwrap();
            assert_eq!(
                claims
                    .assignment_view("project_12345678", "actor_1234567890", "assignment_12345")
                    .unwrap()
                    .0,
                "reserved"
            );
            assert_eq!(
                claims.authority_observations(&keys.authority, 1).unwrap(),
                vec![body]
            );
            let db = super::super::super::la_store::open_pinned_readonly_database(
                &root,
                "lane_assignments.sqlite",
            )
            .unwrap();
            let held: i64 = db
                .query_row("SELECT COUNT(*) FROM la_reservations", [], |r| r.get(0))
                .unwrap();
            assert_eq!(held, 1);
            let epoch: i64 = db
                .query_row("SELECT writer_epoch FROM la_controller_identity", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(epoch, 2);
            drop(db);
            drop(recovered);
            drop(claims);
            drop(root);
            drop(parent);
            std::fs::remove_dir_all(path).unwrap();
        }

        #[test]
        fn controller_recovery_preserves_history_and_requires_exact_parent_handoff() {
            let (path, root, parent, binding, keys) = setup();
            let ledger = Arc::new(Mutex::new(
                Ledger::new(&parent, binding.clone(), &keys).unwrap(),
            ));
            let link = witnessed_link(&root, binding.clone(), &keys, ledger.clone());
            let session = Session::create(&root, link.clone()).unwrap();
            let op = session.begin(&"a".repeat(64)).unwrap();
            std::fs::write(path.join("service/report.json"), b"durable report bytes").unwrap();
            session.complete(op, &"b".repeat(64)).unwrap();
            let old_head = session.activation_anchor().unwrap();
            let mut next = binding.clone();
            next.controller_boot = "f".repeat(64);
            next.controller_epoch = 2;
            // Existing live writer, unfinished request, guessed epochs and a
            // new genesis must all be refused before any history is changed.
            assert!(ledger
                .lock()
                .unwrap()
                .authorize_recovery(&root, next.clone(), 100, 200)
                .is_err());
            drop(session);
            assert!(Session::create(&root, link).is_err());
            let mut wrong = next.clone();
            wrong.worker_epoch = 2;
            assert!(ledger
                .lock()
                .unwrap()
                .authorize_recovery(&root, wrong, 100, 200)
                .is_err());
            let mut wrong = next.clone();
            wrong.controller_epoch = 3;
            assert!(ledger
                .lock()
                .unwrap()
                .authorize_recovery(&root, wrong, 100, 200)
                .is_err());
            let recovery = ledger
                .lock()
                .unwrap()
                .authorize_recovery(&root, next.clone(), 100, 200)
                .unwrap();
            assert!(ledger
                .lock()
                .unwrap()
                .authorize_recovery(&root, next.clone(), 100, 200)
                .is_err());
            let link = witnessed_link(&root, next, &keys, ledger.clone());
            assert!(Session::recover(&root, link.clone(), &recovery, 200).is_err());
            let mut forged = recovery.clone();
            forged.next += 1;
            assert!(Session::recover(&root, link.clone(), &forged, 101).is_err());
            let mut forged = recovery.clone();
            forged.head = "0".repeat(64);
            assert!(Session::recover(&root, link.clone(), &forged, 101).is_err());
            // Same length substitution is detected from P's exact state head.
            std::fs::write(path.join("service/report.json"), b"changed report bytes").unwrap();
            assert!(Session::recover(&root, link.clone(), &recovery, 101).is_err());
            std::fs::write(path.join("service/report.json"), b"durable report bytes").unwrap();
            let session = Session::recover(&root, link.clone(), &recovery, 101).unwrap();
            assert!(session.activation_anchor().unwrap().0 != old_head.0);
            assert!(session.activation_anchor().unwrap().1 == old_head.1);
            assert_eq!(
                std::fs::read(path.join("service/report.json")).unwrap(),
                b"durable report bytes"
            );
            let op = session.begin(&"c".repeat(64)).unwrap();
            assert_eq!(op, 2);
            session.complete(op, &"d".repeat(64)).unwrap();
            drop(session);
            assert!(Session::recover(&root, link, &recovery, 102).is_err());
            assert!(path.join("custody/service-state-0006.json").exists());
            assert!(path.join("custody/service-recovery-0002.json").exists());
            std::fs::remove_dir_all(path).unwrap();
        }
        #[test]
        fn controller_recovery_quarantines_unfinished_or_lost_history() {
            let (path, root, parent, binding, keys) = setup();
            let ledger = Arc::new(Mutex::new(
                Ledger::new(&parent, binding.clone(), &keys).unwrap(),
            ));
            let link = witnessed_link(&root, binding.clone(), &keys, ledger.clone());
            let session = Session::create(&root, link.clone()).unwrap();
            let op = session.begin(&"a".repeat(64)).unwrap();
            let mut next = binding;
            next.controller_epoch = 2;
            next.controller_boot = "f".repeat(64);
            // Releasing the process lock alone cannot bless an incomplete op.
            drop(session);
            assert!(ledger
                .lock()
                .unwrap()
                .authorize_recovery(&root, next.clone(), 100, 200)
                .is_err());
            let db = super::super::super::la_store::open_pinned_database(
                &root,
                "service-custody.sqlite",
                false,
            )
            .unwrap();
            db.execute("DELETE FROM service_checkpoints WHERE revision=2", [])
                .unwrap();
            assert!(ledger
                .lock()
                .unwrap()
                .authorize_recovery(&root, next, 100, 200)
                .is_err());
            assert_eq!(op, 1);
            assert!(!path.join("custody/service-recovery-0002.json").exists());
            drop(db);
            std::fs::remove_dir_all(path).unwrap();
        }

        #[test]
        fn service_state_is_independently_witnessed_and_same_count_substitution_closes() {
            let (path, root, parent, binding, keys) = setup();
            let mut file = super::super::super::la_artifacts::open_artifact(
                &root,
                "state.json",
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .unwrap();
            file.write_all(b"before").unwrap();
            file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))
                .unwrap();
            drop(file);
            let (send, receive) = std::sync::mpsc::sync_channel(4);
            let link = Link::new(
                binding.clone(),
                &keys,
                Box::new(move |bytes| send.send(bytes.to_vec()).map_err(|_| "evidence_invalid")),
            )
            .unwrap();
            let control = link.clone();
            let observed = root.try_clone().unwrap();
            let mut ledger = Ledger::new(&parent, binding, &keys).unwrap();
            let task = std::thread::spawn(move || {
                for _ in 0..3 {
                    let bytes = receive
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    let frame: Checkpoint = serde_json::from_slice(&bytes).unwrap();
                    let ack = ledger.observe(&observed, &frame).unwrap();
                    assert!(ledger.observe(&observed, &frame).is_err());
                    control.accept(&serde_json::to_vec(&ack).unwrap()).unwrap();
                }
            });
            let session = Session::create(&root, link).unwrap();
            let operation = session.begin(&"a".repeat(64)).unwrap();
            let mut file = super::super::super::la_artifacts::open_artifact(
                &root,
                "state.json",
                libc::O_WRONLY | libc::O_TRUNC,
            )
            .unwrap();
            file.write_all(b"after!").unwrap();
            file.sync_all().unwrap();
            drop(file);
            session.complete(operation, &"b".repeat(64)).unwrap();
            task.join().unwrap();
            assert!(path.join("custody/service-state-0003.json").is_file());
            let mut file = super::super::super::la_artifacts::open_artifact(
                &root,
                "state.json",
                libc::O_WRONLY | libc::O_TRUNC,
            )
            .unwrap();
            file.write_all(b"other!").unwrap();
            drop(file);
            assert!(session.begin(&"c".repeat(64)).is_err());
            assert!(session.check().is_err());
            drop(session);
            drop(root);
            drop(parent);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
}

/// A P-authorized adjacent controller epoch transition. Both old transport heads
/// and the complete role-owned state are retained; this grants reconciliation
/// only. It is never an activation or a capacity-release certificate.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransportEpochHandoff {
    previous: ChannelBinding,
    binding: ChannelBinding,
    controller: SignedCheckpoint,
    controller_ack: CheckpointAck,
    controller_history: String,
    worker: SignedCheckpoint,
    worker_ack: CheckpointAck,
    worker_history: String,
    controller_state: String,
    worker_state: String,
    recovery_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_recovery: Option<String>,
    worker_authority: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settlement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    never_started: Option<InspectCommand>,
    authority_sequence: u64,
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}

/// A worker return is a reconciliation capability, never an activation. P binds
/// the protected relay's exact old pidfd death and the fresh bounded W2 process.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerReturnWitness {
    old_identity: serde_json::Value,
    new_identity: serde_json::Value,
    death_digest: String,
    initial_occupancy: String,
    namespace_pid: u32,
}
impl WorkerReturnWitness {
    pub(super) fn observe(
        previous: &ChannelBinding,
        old: &serde_json::Value,
        death: &serde_json::Value,
        fresh: &serde_json::Value,
        worker_root: &std::fs::File,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        let dev = worker_root
            .metadata()
            .map_err(|_| "evidence_invalid")?
            .dev();
        qualification::snapshot(old, "w", &previous.executable_digest, true, Some(dev))?;
        qualification::snapshot(fresh, "w", &previous.executable_digest, true, Some(dev))?;
        if death["kind"] != "W_KILLED"
            || death["signal"] != 9
            || death["pidfd_dead"] != true
            || death["rights"] != 0
            || death["identity"] != old["identity"]
            || fresh["identity"]["pid"] == old["identity"]["pid"]
            || fresh["identity"]["cgroup"] == old["identity"]["cgroup"]
            || death["seq"].as_u64().is_none_or(|n| n == 0)
            || death["nonce"]
                .as_str()
                .is_none_or(|n| n.len() != 64 || hex::decode(n).is_err())
        {
            return Err("evidence_invalid");
        }
        let value = Self {
            namespace_pid: fresh["status"]
                .as_str()
                .and_then(|s| s.lines().find_map(|l| l.strip_prefix("NSpid:")))
                .and_then(|s| s.split_whitespace().last())
                .and_then(|s| s.parse().ok())
                .ok_or("evidence_invalid")?,
            old_identity: old["identity"].clone(),
            new_identity: fresh["identity"].clone(),
            death_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(death).map_err(|_| "evidence_invalid")?,
            )),
            initial_occupancy: hex::encode(Sha256::digest(
                serde_json::to_vec(fresh).map_err(|_| "evidence_invalid")?,
            )),
        };
        value.validate(previous)?;
        Ok(value)
    }
    fn validate(&self, previous: &ChannelBinding) -> Result<(), &'static str> {
        for identity in [&self.old_identity, &self.new_identity] {
            if identity["pid"].as_u64().is_none_or(|p| p == 0)
                || identity["starttime"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_none_or(|n| n == 0)
                || identity["sha256"] != previous.executable_digest
                || identity["exe"] != "/worker-test"
                || identity["cgroup"]
                    .as_str()
                    .is_none_or(|s| !s.trim().ends_with(".scope"))
            {
                return Err("evidence_invalid");
            }
        }
        if self.namespace_pid == 0
            || self.old_identity["pid"] == self.new_identity["pid"]
            || self.old_identity["cgroup"] == self.new_identity["cgroup"]
            || [&self.death_digest, &self.initial_occupancy]
                .iter()
                .any(|s| s.len() != 64 || hex::decode(s).is_err())
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

/// DISTINCT P-authenticated adjacent W transition. All original request,
/// mandate, result and per-sequence bindings survive unchanged. This terminal
/// close mode cannot resume dispatch, inherit activation or reset a journal.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerEpochHandoff {
    version: u32,
    previous: ChannelBinding,
    binding: ChannelBinding,
    controller: SignedCheckpoint,
    controller_ack: CheckpointAck,
    controller_history: String,
    worker: SignedCheckpoint,
    worker_ack: CheckpointAck,
    worker_history: String,
    controller_state: String,
    worker_state: String,
    worker_authority: String,
    prior_epochs: String,
    returning: WorkerReturnWitness,
    service: state_custody::WorkerServiceAnchor,
    settlement: String,
    authority_sequence: u64,
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}
impl WorkerEpochHandoff {
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds both exact role histories, service midpoint and fresh worker process."
    )]
    pub(super) fn prepare(
        controller: &mut CustodyLedger,
        worker: &mut CustodyLedger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        service: &mut state_custody::Ledger,
        next: ChannelBinding,
        returning: WorkerReturnWitness,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Self, &'static str> {
        next.validate()?;
        let service_anchor = service.worker_return_anchor(croot)?;
        if controller.role != "controller"
            || worker.role != "worker"
            || controller.binding != worker.binding
            || controller.pending_epoch.is_some()
            || worker.pending_epoch.is_some()
            || controller.ack_key != keys.custody
            || worker.ack_key != keys.custody
            || controller.request_key != keys.reply
            || worker.request_key != keys.reply
        {
            return Err("evidence_invalid");
        }
        let (c, ca, ch) = controller.recovery_anchor(croot, true)?;
        let (w, wa, wh) = worker.completed_anchor(wroot)?;
        if c.body.sequence != w.body.sequence {
            return Err("transport_uncertain");
        }
        // Compare all old replies at the same sequence, not just two larger
        // counters. C/W journal request digests differ by design; reply bytes do not.
        let cd =
            super::la_store::open_pinned_readonly_database(croot, "controller-channel.sqlite")?;
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        for seq in 1..=c.body.sequence {
            type RetainedRpc = (Vec<u8>, Option<Vec<u8>>, String);
            let read = |db: &rusqlite::Connection| -> Result<RetainedRpc, &'static str> {
                db.query_row(
                    "SELECT request,response,digest FROM channel_log WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(|_| "evidence_invalid")
            };
            let cr = read(&cd)?;
            let wr = read(&wd)?;
            if cr.0 != wr.0 || wr.1.is_none() {
                return Err("transport_uncertain");
            }
            let signed: SignedRequest =
                serde_json::from_slice(&cr.0).map_err(|_| "evidence_invalid")?;
            if !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &signed.request)?
                    .ct_eq(&signed.mac),
            ) {
                return Err("evidence_invalid");
            }
            validate_rpc_envelope(
                &cr.0,
                "controller-channel.sqlite",
                &transport_binding_at(&cd, "controller", seq, false)?,
                seq,
                &cr.2,
            )?;
            validate_rpc_envelope(
                &wr.0,
                "worker-channel.sqlite",
                &transport_binding_at(&wd, "worker", seq, false)?,
                seq,
                &wr.2,
            )?;
            let reply = wr.1.as_ref().ok_or("evidence_invalid")?;
            let response: SignedResponse =
                serde_json::from_slice(reply).map_err(|_| "evidence_invalid")?;
            if serde_json::to_vec(&response).map_err(|_| "evidence_invalid")? != *reply
                || response.response.sequence != seq
                || response.response.binding != signed.request.binding
                || response.response.request_digest != wr.2
                || !bool::from(
                    typed_mac(
                        &keys.reply,
                        b"diffuser-rpc-response/v1\0",
                        &response.response,
                    )?
                    .ct_eq(&response.mac),
                )
            {
                return Err("evidence_invalid");
            }
            if seq == c.body.sequence {
                if cr.1.is_some() || service.worker_close_envelope()? != cr.0 {
                    return Err("transport_uncertain");
                }
                match &signed.request.operation {
                    WorkerOperation::Close(_) => verify_pending_close_reply(
                        croot,
                        wroot,
                        &signed.request,
                        &response.response.reply,
                        keys,
                    )?,
                    WorkerOperation::Stop(_) => verify_pending_stop_reply(
                        croot,
                        wroot,
                        &signed.request,
                        &response.response.reply,
                        keys,
                    )?,
                    _ => return Err("transport_uncertain"),
                }
            } else if cr.1 != wr.1 {
                return Err("transport_uncertain");
            }
        }
        let (count, high): (i64, i64) = wd
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM channel_authority",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if count != service.authority_sequence() as i64 || count != high {
            return Err("evidence_invalid");
        }
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        for seq in 1..=service.authority_sequence() {
            let (body, mac): (Vec<u8>, Vec<u8>) = claims
                .query_row(
                    "SELECT body,mac FROM la_authority_observations WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let mac: [u8; 32] = mac.try_into().map_err(|_| "evidence_invalid")?;
            verify_authority_observation(&keys.authority, &body, &mac)?;
            let (saved, frame): (Vec<u8>, Vec<u8>) = wd
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if saved != body
                || verify_source_observation(
                    &keys.authority,
                    &transport_authority_binding(&wd, seq)?,
                    &frame,
                )? != body
            {
                return Err("evidence_invalid");
            }
        }
        verify_completed_worker_reconciliation(&claims, wroot, &controller.binding, keys)?;
        let worker_state = state_custody::state_digest(wroot)?;
        if w.body.owned_state.as_ref() != Some(&worker_state)
            || worker.owned_state.as_ref() != Some(&worker_state)
        {
            return Err("evidence_invalid");
        }
        let worker_authority = transport_authority_digest(&wd, service.authority_sequence())?;
        let settlement = {
            let bytes: Vec<u8> = wd
                .query_row(
                    "SELECT response FROM channel_log WHERE sequence=?1",
                    [c.body.sequence as i64],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            String::from_utf8(bytes).map_err(|_| "evidence_invalid")?
        };
        let mut value = Self {
            version: 1,
            previous: controller.binding.clone(),
            binding: next,
            controller: c,
            controller_ack: ca,
            controller_history: ch,
            worker: w,
            worker_ack: wa,
            worker_history: wh,
            controller_state: state_custody::state_digest(croot)?,
            worker_state,
            prior_epochs: transition_history_digest(&transport_epochs(&wd)?.1)?,
            returning,
            service: service_anchor,
            worker_authority,
            settlement,
            authority_sequence: service.authority_sequence(),
            issued_at: now,
            expires_at: now.checked_add(1500).ok_or("evidence_invalid")?,
            mac: [0; 32],
        };
        value.mac = value.signature(&keys.custody)?;
        value.verify(&keys.custody, now)?;
        if serde_json::to_vec(&value)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 12288
        {
            return Err("evidence_invalid");
        }
        // Durable independent records precede either role's epoch ACK. Partial
        // preparation is safely nonreplayable (create_new); no new genesis.
        let transition = TransportTransition::Worker(Box::new(value.clone()));
        controller.prepare_transition(&transition)?;
        worker.prepare_transition(&transition)?;
        service.prepare_worker_return(croot, &value)?;
        Ok(value)
    }

    pub(super) fn high_water(&self) -> u64 {
        self.worker.body.sequence
    }
    pub(super) fn binding(&self) -> &ChannelBinding {
        &self.binding
    }
    pub(super) fn verify_worker_root(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify(&keys.custody, now)?;
        let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| "evidence_invalid")?;
        let starttime = stat
            .rsplit_once(") ")
            .and_then(|(_, s)| s.split_whitespace().nth(19))
            .ok_or("evidence_invalid")?;
        if std::process::id() != self.returning.namespace_pid
            || self.returning.new_identity["starttime"] != starttime
        {
            return Err("evidence_invalid");
        }

        let db = super::la_store::open_pinned_readonly_database(root, "worker-channel.sqlite")?;
        let h = &self.worker;
        let meta = root.metadata().map_err(|_| "evidence_invalid")?;
        use std::os::unix::fs::MetadataExt;
        if (meta.dev(), meta.ino()) != (h.body.root_dev, h.body.root_inode)
            || state_custody::state_digest(root)? != self.worker_state
            || transport_state_digest(&db, &self.previous)? != h.body.state_digest
            || checkpoint_bytes_digest(&db, h.body.revision, h.body.revision)?
                != self.worker_history
            || transport_authority_digest(&db, self.authority_sequence)? != self.worker_authority
            || transition_history_digest(&transport_epochs(&db)?.1)? != self.prior_epochs
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, h, &keys.reply, &keys.custody)?;
        let saved: Vec<u8> = db
            .query_row(
                "SELECT response FROM channel_log WHERE sequence=?1",
                [h.body.sequence as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if saved != self.settlement.as_bytes() {
            return Err("evidence_invalid");
        }
        self.settled_close(keys)?;
        Ok(())
    }
    pub(super) fn reopen_worker_transport(
        &self,
        root: &std::fs::File,
        path: &std::path::Path,
        link: std::sync::Arc<CustodyLink>,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<TransportJournal, &'static str> {
        self.verify_worker_root(root, keys, now)?;
        if link.binding != self.binding || link.role != "worker" {
            return Err("evidence_invalid");
        }
        let old = CustodyLink::new(
            self.previous.clone(),
            "worker",
            keys.reply,
            keys.custody,
            Box::new(|_| Err("evidence_invalid")),
        )?;
        let mut channel = TransportJournal::reopen_witnessed(
            root,
            path,
            "worker-channel.sqlite",
            &self.worker,
            &self.worker_ack,
            old,
        )?;
        channel.install_worker_epoch(self, Some(link), now)?;
        Ok(channel)
    }
    pub(super) fn settled_close(
        &self,
        keys: &ChannelKeys,
    ) -> Result<(CloseReceipt, [u8; 32]), &'static str> {
        let signed: SignedResponse =
            serde_json::from_slice(self.settlement.as_bytes()).map_err(|_| "evidence_invalid")?;
        if signed.response.binding != self.previous
            || signed.response.sequence != self.worker.body.sequence
            || !bool::from(
                typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &signed.response)?
                    .ct_eq(&signed.mac),
            )
        {
            return Err("evidence_invalid");
        }
        match signed.response.reply {
            WorkerReply::Closed(r, m) => {
                verify_close_receipt(&keys.reply, &r, &m)?;
                if r.worker != self.previous.worker || r.boot != self.previous.worker_boot {
                    return Err("evidence_invalid");
                }
                Ok((r, m))
            }
            _ => Err("evidence_invalid"),
        }
    }
    pub(super) fn close_window(
        &self,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(CloseReceipt, cleanup::Reconciliation), &'static str> {
        self.verify(&keys.custody, now)?;
        let (receipt, _) = self.settled_close(keys)?;
        let window = cleanup::Reconciliation {
            binding: self.binding.clone(),
            handoff: self.digest()?,
            receipt_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(&receipt).map_err(|_| "evidence_invalid")?,
            )),
            observed_at: now,
            expires_at: now
                .checked_add(cleanup::deadline_ms(&self.binding)?)
                .ok_or("evidence_invalid")?,
        };
        Ok((receipt, window))
    }
    pub(super) fn acknowledgment(
        &self,
        keys: &ChannelKeys,
    ) -> Result<TransportEpochAck, &'static str> {
        let digest = self.digest()?;
        let mac = typed_mac(
            &keys.reply,
            b"diffuser-worker-epoch-ack/v1\0",
            &(&self.binding, &digest),
        )?;
        Ok(TransportEpochAck {
            binding: self.binding.clone(),
            role: "controller".into(),
            digest,
            mac,
        })
    }
    pub(super) fn verify_ack(
        &self,
        keys: &ChannelKeys,
        ack: &TransportEpochAck,
    ) -> Result<(), &'static str> {
        let expected = self.acknowledgment(keys)?;
        if ack.binding != expected.binding
            || ack.role != expected.role
            || ack.digest != expected.digest
            || !bool::from(ack.mac.ct_eq(&expected.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut unsigned = self.clone();
        unsigned.mac = [0; 32];
        typed_mac(key, b"diffuser-worker-epoch-handoff/v1\0", &unsigned)
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    fn anchor(
        &self,
        role: &str,
    ) -> Result<(&SignedCheckpoint, &CheckpointAck, &str, &str), &'static str> {
        match role {
            "controller" => Ok((
                &self.controller,
                &self.controller_ack,
                &self.controller_history,
                &self.controller_state,
            )),
            "worker" => Ok((
                &self.worker,
                &self.worker_ack,
                &self.worker_history,
                &self.worker_state,
            )),
            _ => Err("evidence_invalid"),
        }
    }
    fn verify_history(&self, key: &[u8; 32]) -> Result<(), &'static str> {
        self.previous.validate()?;
        self.binding.validate()?;
        self.returning.validate(&self.previous)?;
        state_custody::worker_return_headroom(self.service.revision())?;
        let mut expected = self.previous.clone();
        expected.worker_epoch = expected
            .worker_epoch
            .checked_add(1)
            .ok_or("evidence_invalid")?;
        expected.worker_boot = self.binding.worker_boot.clone();
        if self.version != 1
            || self.binding != expected
            || self.previous.worker_boot == self.binding.worker_boot
            || self.binding.worker_epoch > 9
            || self.authority_sequence == 0
            || self.authority_sequence > 128
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 1500
            || self.settlement.len() > RPC_JSON_MAX
            || !bool::from(self.signature(key)?.ct_eq(&self.mac))
            || [
                &self.controller_history,
                &self.worker_history,
                &self.controller_state,
                &self.worker_state,
                &self.worker_authority,
                &self.prior_epochs,
            ]
            .iter()
            .any(|s| s.len() != 64 || hex::decode(s).is_err())
        {
            return Err("evidence_invalid");
        }
        for role in ["controller", "worker"] {
            let (head, ack, _, _) = self.anchor(role)?;
            if head.body.binding != self.previous
                || head.body.role != role
                || head.body.phase
                    != if role == "controller" {
                        "intent"
                    } else {
                        "complete"
                    }
                || head.body.revision == 0
                // One handoff checkpoint followed by the compulsory terminal
                // RPC intent/complete pair must fit before P signs or either
                // role appends a transition. Old replies settle in the handoff.
                || head.body.revision.checked_add(3).is_none_or(|end| end > CHECKPOINT_MAX)
                || head.body.sequence == 0
                || head.body.sequence >= RPC_HISTORY_MAX
            {
                return Err("evidence_invalid");
            }
            ack.verify(key, head)?;
        }
        if self.controller.body.sequence != self.worker.body.sequence
            || self.worker.body.owned_state.as_ref() != Some(&self.worker_state)
        {
            return Err("transport_uncertain");
        }
        Ok(())
    }
    fn verify(&self, key: &[u8; 32], now: u64) -> Result<(), &'static str> {
        self.verify_history(key)?;
        recovery_trace(
            "handoff_time_check",
            serde_json::json!({"now":now,"issued_at":self.issued_at,"expires_at":self.expires_at,"epoch":self.binding.controller_epoch,"sequence":self.authority_sequence}),
        );
        if self.issued_at > now || now >= self.expires_at {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

/// Reconciles ONE consumed entered-loss transport. This is distinct from the
/// completed-only handoff and grants neither source replay nor live capacity.
/// The original W checkpoint ends N-1; its appended resolution N retains the
/// exact original request and independently signed P settlement, never a W reply.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerLossReturn {
    kind: String,
    previous: ChannelBinding,
    binding: ChannelBinding,
    controller: SignedCheckpoint,
    controller_ack: CheckpointAck,
    controller_history: String,
    worker: SignedCheckpoint,
    worker_ack: CheckpointAck,
    worker_history: String,
    controller_state: String,
    worker_state: String,
    worker_authority: String,
    authority_sequence: u64,
    prior_epochs: String,
    resolution: String,
    request: String,
    cleanup: String,
    cleanup_receipt: String,
    cleanup_consumed_at: u64,
    source_bridge: String,
    service: (String, String, String, u64, u64),
    observation: String,
    returning: WorkerReturnWitness,
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}
impl WorkerLossReturn {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut unsigned = self.clone();
        unsigned.mac = [0; 32];
        typed_mac(
            key,
            b"diffuser-entered-loss-transport-return/v1\0",
            &unsigned,
        )
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        value_digest(self)
    }
    pub(super) fn binding(&self) -> &ChannelBinding {
        &self.binding
    }
    pub(super) fn high_water(&self) -> u64 {
        self.controller.body.sequence
    }
    fn anchor(
        &self,
        role: &str,
    ) -> Result<(&SignedCheckpoint, &CheckpointAck, &str, &str), &'static str> {
        match role {
            "controller" => Ok((
                &self.controller,
                &self.controller_ack,
                &self.controller_history,
                &self.controller_state,
            )),
            "worker" => Ok((
                &self.worker,
                &self.worker_ack,
                &self.worker_history,
                &self.worker_state,
            )),
            _ => Err("evidence_invalid"),
        }
    }
    fn verify_history(&self, key: &[u8; 32]) -> Result<(), &'static str> {
        self.previous.validate()?;
        self.binding.validate()?;
        self.returning.validate(&self.previous)?;
        let mut next = self.previous.clone();
        next.worker_epoch = next.worker_epoch.checked_add(1).ok_or("evidence_invalid")?;
        next.worker_boot = self.binding.worker_boot.clone();
        if self.kind != "diffuser-entered-loss-transport-return/v1"
            || self.binding != next
            || next.worker_epoch > 9
            || next.worker_boot == self.previous.worker_boot
            || self.worker.body.sequence.checked_add(1) != Some(self.high_water())
            || self.high_water() >= RPC_HISTORY_MAX
            || self.worker.body.owned_state.as_ref() != Some(&self.worker_state)
            || self.authority_sequence == 0
            || self
                .authority_sequence
                .checked_add(2)
                .is_none_or(|n| n > 128)
            || self.service.4 != self.authority_sequence + 1
            || self.service.3 == 0
            || self.service.3 >= 1025
            || self.service.1 != self.controller_state
            || self.cleanup_consumed_at == 0
            || self.cleanup_consumed_at > self.issued_at
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 1500
            || !bool::from(self.signature(key)?.ct_eq(&self.mac))
            || [
                &self.controller_history,
                &self.worker_history,
                &self.controller_state,
                &self.worker_state,
                &self.worker_authority,
                &self.prior_epochs,
                &self.resolution,
                &self.request,
                &self.cleanup,
                &self.cleanup_receipt,
                &self.source_bridge,
                &self.observation,
                &self.service.0,
                &self.service.2,
            ]
            .iter()
            .any(|s| s.len() != 64 || hex::decode(s).is_err())
        {
            return Err("evidence_invalid");
        }
        for role in ["controller", "worker"] {
            let (head, ack, _, _) = self.anchor(role)?;
            if head.body.binding != self.previous
                || head.body.role != role
                || head.body.phase != "complete"
                || head.body.sequence == 0
                || head.body.revision == 0
                || head
                    .body
                    .revision
                    .checked_add(3)
                    .is_none_or(|n| n > CHECKPOINT_MAX)
            {
                return Err("evidence_invalid");
            }
            ack.verify(key, head)?;
        }
        Ok(())
    }
    fn verify(&self, key: &[u8; 32], now: u64) -> Result<(), &'static str> {
        self.verify_history(key)?;
        if now < self.issued_at || now >= self.expires_at {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    /// Validate the distinct P resolution in its exact old sequence/binding.
    /// It is deliberately not deserialized or authenticated as SignedResponse.
    fn verify_resolution(
        &self,
        request: &[u8],
        response: &[u8],
        key: &[u8; 32],
    ) -> Result<WorkerLossSettlement, &'static str> {
        let loss: WorkerLossSettlement =
            serde_json::from_slice(response).map_err(|_| "evidence_invalid")?;
        if loss.kind != "diffuser-entered-worker-loss/v1"
            || serde_json::to_vec(&loss).map_err(|_| "evidence_invalid")? != response
            || !bool::from(loss.signature(key)?.ct_eq(&loss.mac))
            || loss.digest()? != self.resolution
            || loss.binding != self.previous
            || loss.sequence != self.high_water()
            || loss.request.as_bytes() != request
            || hex::encode(Sha256::digest(request)) != self.request
            || loss.worker.digest()? != self.worker.digest()?
            || loss.worker_history != self.worker_history
            || loss.worker_state != self.worker_state
            || loss.authority_sequence != self.authority_sequence
            || loss.authority_digest != self.worker_authority
        {
            return Err("evidence_invalid");
        }
        Ok(loss)
    }
    fn installed_resolution(
        &self,
        db: &rusqlite::Connection,
        key: &[u8; 32],
    ) -> Result<(), &'static str> {
        let (request, response): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT request,response FROM channel_log WHERE sequence=?1",
                [self.high_water() as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        self.verify_resolution(&request, &response, key)?;
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds consumed loss cleanup, both asymmetric histories and independently observed current processes/roots."
    )]
    pub(super) fn prepare(
        controller: &mut CustodyLedger,
        worker: &mut CustodyLedger,
        service: &state_custody::Ledger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        certificate: &cleanup::Certificate,
        cleanup_ack: &serde_json::Value,
        next: ChannelBinding,
        returning: WorkerReturnWitness,
        observation: &serde_json::Value,
        snapshots: &serde_json::Value,
        keys: &ChannelKeys,
        now: u64,
        lifetime_ms: u64,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        // Issuers may request a shorter FIRST-use lifetime. Verification keeps
        // the original 1500ms maximum and the independently observed deadline.
        if !(1..=1500).contains(&lifetime_ms) {
            return Err("evidence_invalid");
        }
        recovery_trace(
            "loss_return_prepare",
            serde_json::json!({"stage":"begin","now":now,"source_sequence":service.authority_sequence()}),
        );
        let loss = certificate.loss.as_ref().ok_or("evidence_invalid")?;
        loss.verify_history(keys)?;
        if controller.role != "controller"
            || worker.role != "worker"
            || controller.binding != loss.binding
            || worker.binding != loss.binding
            || controller.pending_epoch.is_some()
            || worker.pending_epoch.is_some()
            || controller.request_key != keys.reply
            || worker.request_key != keys.reply
            || controller.ack_key != keys.custody
            || worker.ack_key != keys.custody
        {
            return Err("evidence_invalid");
        }
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        let cert_bytes = serde_json::to_vec(certificate).map_err(|_| "evidence_invalid")?;
        let cleanup = hex::encode(Sha256::digest(&cert_bytes));
        let (saved,time):(Vec<u8>,i64)=claims.query_row(
            "SELECT certificate,released_at FROM la_assignment_cleanup_receipts WHERE assignment_id=?1 AND digest=?2",
            rusqlite::params![loss.command.assignment,cleanup],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|"evidence_invalid")?;
        let consumed = u64::try_from(time).map_err(|_| "evidence_invalid")?;
        if saved != cert_bytes || consumed > now {
            return Err("evidence_invalid");
        }
        let cert = certificate.verify(&loss.binding, keys, croot, consumed)?;
        let closed:bool=claims.query_row("SELECT EXISTS(SELECT 1 FROM la_assignments a JOIN la_jobs j ON j.assignment_id=a.id JOIN la_job_outbox o ON o.job=j.id WHERE a.id=?1 AND a.state='closed' AND j.id=?2 AND j.state='failed' AND j.result_artifact IS NULL AND o.action='worker_lost_uncertain') AND (SELECT COUNT(*) FROM la_jobs)=1 AND NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges) AND NOT EXISTS(SELECT 1 FROM la_assignments WHERE state!='closed')",rusqlite::params![loss.command.assignment,loss.command.job],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        let saved_loss: Vec<u8> = claims
            .query_row(
                "SELECT body FROM la_worker_loss_settlements WHERE job=?1 AND assignment_id=?2",
                rusqlite::params![loss.command.job, loss.command.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let close: Vec<u8> = claims
            .query_row(
                "SELECT body FROM la_worker_loss_closes WHERE assignment_id=?1",
                [&loss.command.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let close: WorkerLossClose =
            serde_json::from_slice(&close).map_err(|_| "evidence_invalid")?;
        let wm = wroot.metadata().map_err(|_| "evidence_invalid")?;
        if cert.version != 2
            || cert.worker_root != (wm.dev(), wm.ino())
            || !closed
            || saved_loss != serde_json::to_vec(loss).map_err(|_| "evidence_invalid")?
            || close.kind != "diffuser-dead-domain-close/v1"
            || close.settlement != loss.digest()?
            || close.command.assignment != loss.command.assignment
            || close.command.fence != loss.command.fence
            || close.command.worker != loss.binding.worker
            || close.command.boot != loss.binding.worker_boot
            || Sha256::digest(serde_json::to_vec(&close).map_err(|_| "evidence_invalid")?)
                .as_slice()
                != cert.claim.stop_digest
            || cleanup_ack["released_now"] != true
            || cleanup_ack["certificate_digest"] != cleanup
        {
            return Err("evidence_invalid");
        }
        recovery_trace(
            "loss_return_prepare",
            serde_json::json!({"stage":"consumed_cleanup","consumed_at":consumed}),
        );
        // Fresh independent old-domain death, unchanged survivors and root occupancy.
        let observed = observation["observed_at"]
            .as_u64()
            .ok_or("evidence_invalid")?;
        if observed > now
            || now >= observed.checked_add(1500).ok_or("evidence_invalid")?
            || observation["kind"] != "LOSS_RETURN_REOBSERVED"
            || observation["new_worker"] != returning.new_identity
            || observation["nonce"] != loss.death["nonce"]
            || observation["seq"].as_u64().is_none_or(|n| n == 0 || n > 32)
            || observation["seq"].as_u64() <= loss.death["seq"].as_u64()
            || observation["pidfd_dead"] != true
            || observation["execution_domain"]["quiescent"] != true
            || observation["execution_domain"]["recursive"] != true
            || observation["rights"] != 0
            || observation["identity"] != loss.death["identity"]
            || observation["execution_domain"]["cgroup"] != loss.death["identity"]["cgroup"]
            || observation["survivors"] != loss.survivors
            || returning.old_identity != loss.death["identity"]
        {
            return Err("evidence_invalid");
        }
        for (role, name) in [("c", "controller"), ("k", "keeper"), ("p", "witness")] {
            qualification::snapshot(
                &snapshots[name],
                role,
                &loss.binding.executable_digest,
                false,
                if role == "c" {
                    Some(croot.metadata().map_err(|_| "evidence_invalid")?.dev())
                } else {
                    None
                },
            )?;
            if snapshots[name]["identity"] != loss.survivors[name] {
                return Err("evidence_invalid");
            }
        }
        verify_loss_root_occupancy(observation, wroot, croot)?;
        returning.validate(&loss.binding)?;
        qualification::snapshot(
            &snapshots["worker"],
            "w",
            &loss.binding.executable_digest,
            true,
            Some(wroot.metadata().map_err(|_| "evidence_invalid")?.dev()),
        )?;
        let fresh_pid = snapshots["worker"]["status"]
            .as_str()
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("NSpid:")))
            .and_then(|s| s.split_whitespace().last())
            .and_then(|s| s.parse::<u32>().ok());
        if snapshots["worker"]["identity"] != returning.new_identity
            || value_digest(&snapshots["worker"])? != returning.initial_occupancy
            || fresh_pid != Some(returning.namespace_pid)
        {
            return Err("evidence_invalid");
        }
        recovery_trace(
            "loss_return_prepare",
            serde_json::json!({"stage":"fresh_processes","observed_at":observed}),
        );
        let (c, ca, ch) = controller.completed_anchor(croot)?;
        let (w, wa, wh) = worker.completed_anchor(wroot)?;
        if c.body.sequence != loss.sequence
            || w.digest()? != loss.worker.digest()?
            || wh != loss.worker_history
            || state_custody::state_digest(wroot)? != loss.worker_state
        {
            return Err("evidence_invalid");
        }
        let cd =
            super::la_store::open_pinned_readonly_database(croot, "controller-channel.sqlite")?;
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        let prior = transport_epochs(&wd)?.1;
        if transition_history_digest(&transport_epochs(&cd)?.1)?
            != transition_history_digest(&prior)?
            || prior.len() >= 8
        {
            return Err("evidence_invalid");
        }
        // Preserve and authenticate the ENTIRE equal prefix before resolution N.
        for n in 1..loss.sequence {
            let read = |db: &rusqlite::Connection| -> Result<(Vec<u8>, Vec<u8>), &'static str> {
                db.query_row(
                    "SELECT request,response FROM channel_log WHERE sequence=?1",
                    [n as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")
            };
            let cr = read(&cd)?;
            let wr = read(&wd)?;
            if cr != wr {
                return Err("evidence_invalid");
            }
            let req: SignedRequest =
                serde_json::from_slice(&wr.0).map_err(|_| "evidence_invalid")?;
            let rep: SignedResponse =
                serde_json::from_slice(&wr.1).map_err(|_| "evidence_invalid")?;
            if !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &req.request)?
                    .ct_eq(&req.mac),
            ) || !bool::from(
                typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &rep.response)?
                    .ct_eq(&rep.mac),
            ) || rep.response.binding != req.request.binding
                || rep.response.sequence != n
                || rep.response.request_digest
                    != hex::encode(Sha256::digest(
                        serde_json::to_vec(&req.request).map_err(|_| "evidence_invalid")?,
                    ))
            {
                return Err("evidence_invalid");
            }
        }
        recovery_trace(
            "loss_return_prepare",
            serde_json::json!({"stage":"full_transport_prefix"}),
        );
        let bridge = service.loss_return_source(croot, wroot, loss, keys, now)?;
        recovery_trace(
            "loss_return_prepare",
            serde_json::json!({"stage":"full_history"}),
        );
        let service_anchor = service.entered_loss_return_anchor(croot)?;
        let mut value = Self {
            kind: "diffuser-entered-loss-transport-return/v1".into(),
            previous: loss.binding.clone(),
            binding: next,
            controller: c,
            controller_ack: ca,
            controller_history: ch,
            worker: w,
            worker_ack: wa,
            worker_history: wh,
            controller_state: state_custody::state_digest(croot)?,
            worker_state: loss.worker_state.clone(),
            worker_authority: transport_authority_digest(&wd, loss.authority_sequence)?,
            authority_sequence: loss.authority_sequence,
            prior_epochs: transition_history_digest(&prior)?,
            resolution: loss.digest()?,
            request: hex::encode(Sha256::digest(loss.request.as_bytes())),
            cleanup,
            cleanup_receipt: value_digest(cleanup_ack)?,
            cleanup_consumed_at: consumed,
            source_bridge: bridge,
            service: service_anchor,
            observation: value_digest(&(observation, snapshots))?,
            returning,
            issued_at: now,
            expires_at: now
                .checked_add(lifetime_ms)
                .ok_or("evidence_invalid")?
                .min(observed + 1500),
            mac: [0; 32],
        };
        value.mac = value.signature(&keys.custody)?;
        value.verify(&keys.custody, wall_now()?)?;
        value.installed_resolution(&cd, &keys.custody)?;
        if serde_json::to_vec(&value)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 12288
        {
            return Err("evidence_invalid");
        }
        let transition = TransportTransition::EnteredLoss(Box::new(value.clone()));
        controller.prepare_transition(&transition)?;
        worker.prepare_transition(&transition)?;
        Ok(value)
    }
    pub(super) fn verify_worker_root(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        recovery_trace(
            "loss_return_worker_root_time_check",
            serde_json::json!({"now":now,"issued_at":self.issued_at,"expires_at":self.expires_at}),
        );
        self.verify(&keys.custody, now)?;
        let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| "evidence_invalid")?;
        let start = stat
            .rsplit_once(") ")
            .and_then(|(_, s)| s.split_whitespace().nth(19))
            .ok_or("evidence_invalid")?;
        if std::process::id() != self.returning.namespace_pid
            || self.returning.new_identity["starttime"] != start
        {
            return Err("evidence_invalid");
        }
        self.verify_role_root(root, "worker", keys)
    }
    fn verify_role_root(
        &self,
        root: &std::fs::File,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        let (h, _, history, state) = self.anchor(role)?;
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        if (m.dev(), m.ino()) != (h.body.root_dev, h.body.root_inode)
            || state_custody::state_digest(root)? != state
            || transport_state_digest(&db, &self.previous)? != h.body.state_digest
            || checkpoint_bytes_digest(&db, h.body.revision, h.body.revision)? != history
            || transition_history_digest(&transport_epochs(&db)?.1)? != self.prior_epochs
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, h, &keys.reply, &keys.custody)?;
        if role == "worker"
            && transport_authority_digest(&db, self.authority_sequence)? != self.worker_authority
        {
            return Err("evidence_invalid");
        }
        if role == "controller" {
            self.installed_resolution(&db, &keys.custody)?;
        }
        Ok(())
    }
    pub(super) fn reopen_worker_transport(
        &self,
        root: &std::fs::File,
        path: &std::path::Path,
        link: std::sync::Arc<CustodyLink>,
        keys: &ChannelKeys,
        now: u64,
        resolution: &[u8],
    ) -> Result<TransportJournal, &'static str> {
        self.verify_worker_root(root, keys, now)?;
        if link.binding != self.binding || link.role != "worker" {
            return Err("evidence_invalid");
        }
        let old = CustodyLink::new(
            self.previous.clone(),
            "worker",
            keys.reply,
            keys.custody,
            Box::new(|_| Err("evidence_invalid")),
        )?;
        let mut channel = TransportJournal::reopen_witnessed(
            root,
            path,
            "worker-channel.sqlite",
            &self.worker,
            &self.worker_ack,
            old,
        )?;
        channel.install_transition_with_resolution(
            &TransportTransition::EnteredLoss(Box::new(self.clone())),
            Some(link),
            now,
            Some(resolution),
        )?;
        Ok(channel)
    }
}
pub(super) fn value_digest<T: serde::Serialize>(value: &T) -> Result<String, &'static str> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| "evidence_invalid")?,
    )))
}
fn verify_loss_root_occupancy(
    observation: &serde_json::Value,
    wroot: &std::fs::File,
    croot: &std::fs::File,
) -> Result<(), &'static str> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    if observation["occupancy"]
        .as_array()
        .is_none_or(|a| a.len() != 2)
    {
        return Err("evidence_invalid");
    }
    for (i, root) in [wroot, croot].into_iter().enumerate() {
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(root.as_raw_fd(), st.as_mut_ptr()) } != 0 {
            return Err("evidence_invalid");
        }
        let st = unsafe { st.assume_init() };
        let o = &observation["occupancy"][i];
        if o["dev"].as_u64() != Some(m.dev())
            || o["inode"].as_u64() != Some(m.ino())
            || o["capacity"].as_u64() != Some(st.f_blocks * st.f_frsize)
            || o["available"].as_u64() != Some(st.f_bavail * st.f_frsize)
            || st.f_blocks * st.f_frsize != 67108864
            || st.f_bavail == 0
        {
            return Err("evidence_invalid");
        }
    }
    Ok(())
}
impl state_custody::Ledger {
    /// All old dual ACKs and the one distinct surviving-C ACK remain explicit.
    /// No W ACK is synthesized for the C-only observation S+1.
    fn loss_return_source(
        &self,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        loss: &WorkerLossSettlement,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<String, &'static str> {
        use std::io::Read;
        if self.authority_sequence() != loss.authority_sequence + 1 {
            return Err("evidence_invalid");
        }
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        let mut last = None;
        for n in 1..=self.authority_sequence() {
            let mut bytes = Vec::new();
            super::la_artifacts::open_artifact(
                &self.loss_return_root()?,
                &format!("service-authority-{n:03}.json"),
                libc::O_RDONLY,
            )
            .map_err(|_| "evidence_invalid")?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| "evidence_invalid")?;
            if bytes.len() > 16384 {
                return Err("evidence_invalid");
            }
            if n <= loss.authority_sequence {
                let (frame, c, w): (Vec<u8>, SourceAck, SourceAck) =
                    serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                let binding = transport_authority_binding(&wd, n)?;
                let body = verify_source_observation(&keys.authority, &binding, &frame)?;
                verify_source_ack(&keys.reply, &binding, "controller", &body, &c)?;
                verify_source_ack(&keys.reply, &binding, "worker", &body, &w)?;
                let saved: (Vec<u8>, Vec<u8>) = wd
                    .query_row(
                        "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                        [n as i64],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(|_| "evidence_invalid")?;
                if saved != (body, frame)
                    || c.sequence != n
                    || w.sequence != n
                    || c.binding != w.binding
                {
                    return Err("evidence_invalid");
                }
            } else {
                let (cap, ack): (WorkerLossSource, SourceAck) =
                    serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                // Historical ACK verification only: it cannot refresh source
                // authority or clear the cleanup scope. P is the same surviving
                // ledger that durably consumed this exact ACK originally.
                let body = cap.verify(keys, cap.issued_at)?;
                if cap.issued_at > now {
                    return Err("evidence_invalid");
                }
                verify_source_ack(&keys.reply, &loss.binding, "controller", &body, &ack)?;
                let db = super::la_store::open_pinned_readonly_database(
                    croot,
                    "lane_assignments.sqlite",
                )?;
                let saved: Vec<u8> = db
                    .query_row(
                        "SELECT body FROM la_worker_loss_sources WHERE sequence=?1 AND job=?2",
                        rusqlite::params![n as i64, loss.command.job],
                        |r| r.get(0),
                    )
                    .map_err(|_| "evidence_invalid")?;
                if saved != serde_json::to_vec(&cap).map_err(|_| "evidence_invalid")?
                    || cap.settlement != loss.digest()?
                    || cap.previous_sequence != loss.authority_sequence
                    || cap.binding != loss.binding
                    || ack.sequence != n
                {
                    return Err("evidence_invalid");
                }
                last = Some(hex::encode(Sha256::digest(&bytes)));
            }
        }
        last.ok_or("evidence_invalid")
    }
}

// Untagged serialization preserves every existing controller capsule byte.
// Worker capsules have a separate version, shape, signature domain and table.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum TransportTransition {
    Controller(Box<TransportEpochHandoff>),
    Worker(Box<WorkerEpochHandoff>),
    EnteredLoss(Box<WorkerLossReturn>),
}
impl TransportTransition {
    fn previous(&self) -> &ChannelBinding {
        match self {
            Self::Controller(e) => &e.previous,
            Self::Worker(e) => &e.previous,
            Self::EnteredLoss(e) => &e.previous,
        }
    }
    fn binding(&self) -> &ChannelBinding {
        match self {
            Self::Controller(e) => &e.binding,
            Self::Worker(e) => &e.binding,
            Self::EnteredLoss(e) => &e.binding,
        }
    }
    fn authority_sequence(&self) -> u64 {
        match self {
            Self::Controller(e) => e.authority_sequence,
            Self::Worker(e) => e.authority_sequence,
            Self::EnteredLoss(e) => e.authority_sequence,
        }
    }
    fn worker_authority(&self) -> &str {
        match self {
            Self::Controller(e) => &e.worker_authority,
            Self::Worker(e) => &e.worker_authority,
            Self::EnteredLoss(e) => &e.worker_authority,
        }
    }
    fn settlement(&self) -> Option<&str> {
        match self {
            Self::Controller(e) => e.settlement.as_deref(),
            Self::Worker(e) => Some(&e.settlement),
            Self::EnteredLoss(_) => None,
        }
    }
    fn anchor(
        &self,
        role: &str,
    ) -> Result<(&SignedCheckpoint, &CheckpointAck, &str, &str), &'static str> {
        match self {
            Self::Controller(e) => e.anchor(role),
            Self::Worker(e) => e.anchor(role),
            Self::EnteredLoss(e) => e.anchor(role),
        }
    }
    fn digest(&self) -> Result<String, &'static str> {
        match self {
            Self::Controller(e) => e.digest(),
            Self::Worker(e) => e.digest(),
            Self::EnteredLoss(e) => e.digest(),
        }
    }
    fn verify_history(&self, key: &[u8; 32]) -> Result<(), &'static str> {
        match self {
            Self::Controller(e) => e.verify_history(key),
            Self::Worker(e) => e.verify_history(key),
            Self::EnteredLoss(e) => e.verify_history(key),
        }
    }
    fn verify(&self, key: &[u8; 32], now: u64) -> Result<(), &'static str> {
        match self {
            Self::Controller(e) => e.verify(key, now),
            Self::Worker(e) => e.verify(key, now),
            Self::EnteredLoss(e) => e.verify(key, now),
        }
    }
    fn filename(&self, role: &str) -> String {
        match self {
            Self::Controller(e) => format!("{role}-epoch-{:04}.json", e.binding.controller_epoch),
            Self::Worker(e) => format!("{role}-worker-epoch-{:04}.json", e.binding.worker_epoch),
            Self::EnteredLoss(e) => {
                format!("{role}-worker-epoch-{:04}.json", e.binding.worker_epoch)
            }
        }
    }
}
fn parse_worker_transition(bytes: &[u8]) -> Result<TransportTransition, &'static str> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
    if value.get("kind").is_some() {
        let h: WorkerLossReturn = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        if h.kind != "diffuser-entered-loss-transport-return/v1" {
            return Err("evidence_invalid");
        }
        Ok(TransportTransition::EnteredLoss(Box::new(h)))
    } else {
        Ok(TransportTransition::Worker(Box::new(
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?,
        )))
    }
}
impl TransportTransition {
    fn install_sequence(&self, role: &str) -> Result<u64, &'static str> {
        match self {
            Self::EnteredLoss(h) => Ok(h.high_water()),
            _ => Ok(self.anchor(role)?.0.body.sequence),
        }
    }
}
fn transition_history_digest(epochs: &[TransportTransition]) -> Result<String, &'static str> {
    let mut hash = Sha256::new();
    hash.update(b"diffuser-independent-epoch-history/v1\0");
    for e in epochs {
        let bytes = serde_json::to_vec(e).map_err(|_| "evidence_invalid")?;
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}
impl TransportEpochHandoff {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut unsigned = self.clone();
        unsigned.mac = [0; 32];
        typed_mac(key, b"diffuser-transport-epoch-handoff/v1\0", &unsigned)
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    fn anchor(
        &self,
        role: &str,
    ) -> Result<(&SignedCheckpoint, &CheckpointAck, &str, &str), &'static str> {
        match role {
            "controller" => Ok((
                &self.controller,
                &self.controller_ack,
                &self.controller_history,
                &self.controller_state,
            )),
            "worker" => Ok((
                &self.worker,
                &self.worker_ack,
                &self.worker_history,
                &self.worker_state,
            )),
            _ => Err("evidence_invalid"),
        }
    }
    fn verify_history(&self, key: &[u8; 32]) -> Result<(), &'static str> {
        self.previous.validate()?;
        self.binding.validate()?;
        let mut expected = self.previous.clone();
        expected.controller_epoch = expected
            .controller_epoch
            .checked_add(1)
            .ok_or("evidence_invalid")?;
        expected.controller_boot = self.binding.controller_boot.clone();
        if self.binding != expected
            || self.previous.controller_boot == self.binding.controller_boot
            || self.binding.controller_epoch > 9
            || self.authority_sequence == 0
            || self.authority_sequence > 128
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 1500
            || !bool::from(self.signature(key)?.ct_eq(&self.mac))
            || [
                &self.controller_history,
                &self.worker_history,
                &self.controller_state,
                &self.worker_state,
                &self.recovery_digest,
                &self.worker_authority,
            ]
            .iter()
            .any(|s| s.len() != 64 || hex::decode(s).is_err())
        {
            return Err("evidence_invalid");
        }
        for role in ["controller", "worker"] {
            let (head, ack, _, _) = self.anchor(role)?;
            if head.body.binding != self.previous
                || head.body.role != role
                || head.body.phase
                    != if role == "controller" && self.settlement.is_some() {
                        "intent"
                    } else {
                        "complete"
                    }
                || head.body.revision == 0
                || head.body.revision >= CHECKPOINT_MAX
                || head.body.sequence == 0
                || head.body.sequence >= RPC_HISTORY_MAX
            {
                return Err("evidence_invalid");
            }
            ack.verify(key, head)?;
        }
        if self.controller.body.sequence != self.worker.body.sequence {
            return Err("transport_uncertain");
        }
        Ok(())
    }
    fn verify(&self, key: &[u8; 32], now: u64) -> Result<(), &'static str> {
        self.verify_history(key)?;
        recovery_trace(
            "handoff_time_check",
            serde_json::json!({"now":now,"issued_at":self.issued_at,"expires_at":self.expires_at,"epoch":self.binding.controller_epoch,"sequence":self.authority_sequence}),
        );
        if self.issued_at > now || now >= self.expires_at {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    pub(super) fn prepare(
        controller: &mut CustodyLedger,
        worker: &mut CustodyLedger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        recovery: &ControllerReadbackRecovery,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Self, &'static str> {
        Self::prepare_mode(controller, worker, croot, wroot, recovery, keys, now, None)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Exact original-job opt-in, never inferred from missing replies."
    )]
    pub(super) fn prepare_never_started(
        controller: &mut CustodyLedger,
        worker: &mut CustodyLedger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        recovery: &ControllerReadbackRecovery,
        keys: &ChannelKeys,
        now: u64,
        original: &InspectCommand,
    ) -> Result<Self, &'static str> {
        Self::prepare_mode(
            controller,
            worker,
            croot,
            wroot,
            recovery,
            keys,
            now,
            Some(original.clone()),
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Both independent roles and exact scoped recovery mode are bound."
    )]
    fn prepare_mode(
        controller: &mut CustodyLedger,
        worker: &mut CustodyLedger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        recovery: &ControllerReadbackRecovery,
        keys: &ChannelKeys,
        now: u64,
        never_started: Option<InspectCommand>,
    ) -> Result<Self, &'static str> {
        recovery.verify(croot, recovery.binding(), keys, now)?;
        if controller.role != "controller"
            || worker.role != "worker"
            || controller.binding != worker.binding
            || controller.binding != recovery.service.previous_binding
            || controller.pending_epoch.is_some()
            || worker.pending_epoch.is_some()
            || controller.ack_key != keys.custody
            || worker.ack_key != keys.custody
            || controller.request_key != keys.reply
            || worker.request_key != keys.reply
        {
            return Err("evidence_invalid");
        }
        let (c, ca, ch) = controller.recovery_anchor(croot, recovery.service.close.is_some())?;
        let (w, wa, wh) = worker.completed_anchor(wroot)?;
        if c.digest()? != recovery.checkpoint.digest()? || c.body.sequence != w.body.sequence {
            return Err("transport_uncertain");
        }
        // Compare all old replies at the same sequence, not just two larger
        // counters. C/W journal request digests differ by design; reply bytes do not.
        let cd =
            super::la_store::open_pinned_readonly_database(croot, "controller-channel.sqlite")?;
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        for seq in 1..=c.body.sequence {
            type RetainedRpc = (Vec<u8>, Option<Vec<u8>>, String);
            let read = |db: &rusqlite::Connection| -> Result<RetainedRpc, &'static str> {
                db.query_row(
                    "SELECT request,response,digest FROM channel_log WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(|_| "evidence_invalid")
            };
            let cr = read(&cd)?;
            let wr = read(&wd)?;
            if cr.0 != wr.0 || wr.1.is_none() {
                return Err("transport_uncertain");
            }
            let signed: SignedRequest =
                serde_json::from_slice(&cr.0).map_err(|_| "evidence_invalid")?;
            if !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &signed.request)?
                    .ct_eq(&signed.mac),
            ) {
                return Err("evidence_invalid");
            }
            validate_rpc_envelope(
                &cr.0,
                "controller-channel.sqlite",
                &transport_binding_at(&cd, "controller", seq, false)?,
                seq,
                &cr.2,
            )?;
            validate_rpc_envelope(
                &wr.0,
                "worker-channel.sqlite",
                &transport_binding_at(&wd, "worker", seq, false)?,
                seq,
                &wr.2,
            )?;
            let reply = wr.1.as_ref().ok_or("evidence_invalid")?;
            let response: SignedResponse =
                serde_json::from_slice(reply).map_err(|_| "evidence_invalid")?;
            if serde_json::to_vec(&response).map_err(|_| "evidence_invalid")? != *reply
                || response.response.sequence != seq
                || response.response.binding != signed.request.binding
                || response.response.request_digest != wr.2
                || !bool::from(
                    typed_mac(
                        &keys.reply,
                        b"diffuser-rpc-response/v1\0",
                        &response.response,
                    )?
                    .ct_eq(&response.mac),
                )
            {
                return Err("evidence_invalid");
            }
            if seq == c.body.sequence && recovery.service.close.is_some() {
                let close = recovery.service.close.as_ref().ok_or("evidence_invalid")?;
                if cr.1.is_some()
                    || close.envelope() != cr.0
                    || close.authority_sequence != recovery.authority_sequence
                {
                    return Err("transport_uncertain");
                }
                match &signed.request.operation {
                    WorkerOperation::Close(_) => verify_pending_close_reply(
                        croot,
                        wroot,
                        &signed.request,
                        &response.response.reply,
                        keys,
                    )?,
                    WorkerOperation::Stop(_) => verify_pending_stop_reply(
                        croot,
                        wroot,
                        &signed.request,
                        &response.response.reply,
                        keys,
                    )?,
                    _ => return Err("transport_uncertain"),
                }
            } else if cr.1 != wr.1 {
                return Err("transport_uncertain");
            }
        }
        let (count, high): (i64, i64) = wd
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM channel_authority",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if count != recovery.authority_sequence as i64 || count != high {
            return Err("evidence_invalid");
        }
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        for seq in 1..=recovery.authority_sequence {
            let (body, mac): (Vec<u8>, Vec<u8>) = claims
                .query_row(
                    "SELECT body,mac FROM la_authority_observations WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let mac: [u8; 32] = mac.try_into().map_err(|_| "evidence_invalid")?;
            verify_authority_observation(&keys.authority, &body, &mac)?;
            let (saved, frame): (Vec<u8>, Vec<u8>) = wd
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if saved != body
                || verify_source_observation(
                    &keys.authority,
                    &transport_authority_binding(&wd, seq)?,
                    &frame,
                )? != body
            {
                return Err("evidence_invalid");
            }
        }
        if let Some(original) = &never_started {
            if recovery.service.pending_operation().is_some() {
                return Err("transport_uncertain");
            }
            verify_matching_recovery_histories(&cd, &wd, keys, original)?;
            verify_never_started(&claims, wroot, &controller.binding, keys, original)?;
        } else if recovery.service.pending_stop_operation().is_none() {
            verify_completed_worker_reconciliation(&claims, wroot, &controller.binding, keys)?;
        }
        let worker_state = state_custody::state_digest(wroot)?;
        if w.body.owned_state.as_ref() != Some(&worker_state)
            || worker.owned_state.as_ref() != Some(&worker_state)
        {
            return Err("evidence_invalid");
        }
        let worker_authority = transport_authority_digest(&wd, recovery.authority_sequence)?;
        let settlement = if recovery.service.close.is_some() {
            let bytes: Vec<u8> = wd
                .query_row(
                    "SELECT response FROM channel_log WHERE sequence=?1",
                    [c.body.sequence as i64],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            Some(String::from_utf8(bytes).map_err(|_| "evidence_invalid")?)
        } else {
            None
        };
        let mut value = Self {
            previous: controller.binding.clone(),
            binding: recovery.binding().clone(),
            controller: c,
            controller_ack: ca,
            controller_history: ch,
            worker: w,
            worker_ack: wa,
            worker_history: wh,
            controller_state: state_custody::state_digest(croot)?,
            worker_state,
            recovery_digest: recovery.digest()?,
            service_recovery: Some(recovery.service.digest()?),
            worker_authority,
            settlement,
            never_started,
            authority_sequence: recovery.authority_sequence,
            issued_at: now,
            expires_at: recovery
                .service
                .expires_at
                .min(now.checked_add(1500).ok_or("evidence_invalid")?),
            mac: [0; 32],
        };
        value.mac = value.signature(&keys.custody)?;
        value.verify(&keys.custody, now)?;
        if serde_json::to_vec(&value)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 12288
        {
            return Err("evidence_invalid");
        }
        // Durable independent records precede either role's epoch ACK. Partial
        // preparation is safely nonreplayable (create_new); no new genesis.
        controller.prepare_epoch(&value)?;
        worker.prepare_epoch(&value)?;
        Ok(value)
    }
}
impl CustodyLedger {
    fn completed_anchor(
        &self,
        root: &std::fs::File,
    ) -> Result<(SignedCheckpoint, CheckpointAck, String), &'static str> {
        self.recovery_anchor(root, false)
    }
    fn recovery_anchor(
        &self,
        root: &std::fs::File,
        pending: bool,
    ) -> Result<(SignedCheckpoint, CheckpointAck, String), &'static str> {
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{}-channel.sqlite", self.role),
        )?;
        let (frame, ack): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints WHERE revision=?1",
                [self.revision as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let frame: SignedCheckpoint =
            serde_json::from_slice(&frame).map_err(|_| "evidence_invalid")?;
        let ack: CheckpointAck = serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
        if frame.digest()? != self.head
            || frame.body.binding != self.binding
            || frame.body.phase != if pending { "intent" } else { "complete" }
            || frame.body.role != self.role
            || transport_state_digest(&db, &self.binding)? != frame.body.state_digest
        {
            return Err("evidence_invalid");
        }
        ack.verify(&self.ack_key, &frame)?;
        if let Some(owned) = &frame.body.owned_state {
            if self.role != "worker"
                || self.owned_state.as_ref() != Some(owned)
                || state_custody::state_digest(root)? != *owned
            {
                return Err("evidence_invalid");
            }
        } else if self.owned_state.is_some() {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, &frame, &self.request_key, &self.ack_key)?;
        Ok((
            frame,
            ack,
            checkpoint_bytes_digest(&db, self.revision, self.revision)?,
        ))
    }
    fn prepare_epoch(&mut self, handoff: &TransportEpochHandoff) -> Result<(), &'static str> {
        self.prepare_transition(&TransportTransition::Controller(Box::new(handoff.clone())))
    }
    fn prepare_transition(&mut self, handoff: &TransportTransition) -> Result<(), &'static str> {
        use std::io::Write;
        handoff.verify_history(&self.ack_key)?;
        let (head, _, _, _) = handoff.anchor(&self.role)?;
        if self.pending_epoch.is_some()
            || head.digest()? != self.head
            || *handoff.previous() != self.binding
        {
            return Err("evidence_invalid");
        }
        use std::os::fd::AsRawFd;
        let controller_prefix = format!("{}-epoch-", self.role);
        let worker_prefix = format!("{}-worker-epoch-", self.role);
        let mut transitions = 0u64;
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", self.root.as_raw_fd()))
            .map_err(|_| "evidence_invalid")?
        {
            let name = entry.map_err(|_| "evidence_invalid")?.file_name();
            if name
                .to_str()
                .is_some_and(|n| n.starts_with(&controller_prefix) || n.starts_with(&worker_prefix))
            {
                transitions += 1;
                if transitions >= 8 {
                    return Err("storage_unavailable");
                }
            }
        }
        let name = handoff.filename(&self.role);
        let mut f = super::la_artifacts::open_artifact(
            &self.root,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| "storage_unavailable")?;
        f.write_all(&serde_json::to_vec(handoff).map_err(|_| "evidence_invalid")?)
            .and_then(|_| f.sync_all())
            .and_then(|_| self.root.sync_all())
            .map_err(|_| "storage_unavailable")?;
        self.pending_epoch = Some(handoff.clone());
        Ok(())
    }
}
// Parse bounded signed transition rows without replacing the immutable genesis.
fn transport_epochs(
    db: &rusqlite::Connection,
) -> Result<(ChannelBinding, Vec<TransportTransition>), &'static str> {
    let bytes: Vec<u8> = db
        .query_row("SELECT binding FROM channel_identity", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    let genesis: ChannelBinding = serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
    genesis.validate()?;
    let mut pending = Vec::new();
    for worker in [false, true] {
        let table = if worker {
            "channel_worker_epochs"
        } else {
            "channel_epochs"
        };
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if !exists {
            if worker {
                continue;
            } else {
                return Err("evidence_invalid");
            }
        }
        if worker {
            let count: i64 = db
                .query_row("SELECT COUNT(*) FROM channel_worker_epochs", [], |r| {
                    r.get(0)
                })
                .map_err(|_| "evidence_invalid")?;
            if count == 0 {
                return Err("evidence_invalid");
            }
        }
        let mut st=db.prepare(&format!("SELECT epoch,length(body),substr(body,1,12289) FROM {table} ORDER BY epoch LIMIT 9")).map_err(|_| "evidence_invalid")?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| "evidence_invalid")?;
        for row in rows {
            let (n, len, bytes) = row.map_err(|_| "evidence_invalid")?;
            if pending.len() >= 8 || bytes.len() > 12288 || len != bytes.len() as i64 {
                return Err("evidence_invalid");
            }
            let e = if worker {
                let e = parse_worker_transition(&bytes)?;
                if n != e.binding().worker_epoch as i64 {
                    return Err("evidence_invalid");
                }
                e
            } else {
                let e: TransportEpochHandoff =
                    serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                if n != e.binding.controller_epoch as i64 {
                    return Err("evidence_invalid");
                }
                TransportTransition::Controller(Box::new(e))
            };
            if serde_json::to_vec(&e).map_err(|_| "evidence_invalid")? != bytes {
                return Err("evidence_invalid");
            }
            pending.push(e);
        }
    }
    let mut last = genesis.clone();
    let mut epochs = Vec::new();
    while !pending.is_empty() {
        let candidates: Vec<usize> = pending
            .iter()
            .enumerate()
            .filter(|(_, e)| *e.previous() == last)
            .map(|(i, _)| i)
            .collect();
        if candidates.len() != 1 {
            return Err("evidence_invalid");
        }
        let e = pending.remove(candidates[0]);
        let prior = match &e {
            TransportTransition::Worker(w) => Some(&w.prior_epochs),
            TransportTransition::EnteredLoss(w) => Some(&w.prior_epochs),
            _ => None,
        };
        if prior.is_some_and(|p| transition_history_digest(&epochs).as_ref() != Ok(p)) {
            return Err("evidence_invalid");
        }
        last = e.binding().clone();
        epochs.push(e);
    }
    Ok((genesis, epochs))
}
fn transport_binding_at(
    db: &rusqlite::Connection,
    role: &str,
    number: u64,
    checkpoint: bool,
) -> Result<ChannelBinding, &'static str> {
    let (binding, epochs) = transport_epochs(db)?;
    binding_in_history(binding, &epochs, role, number, checkpoint)
}
fn binding_in_history(
    mut binding: ChannelBinding,
    epochs: &[TransportTransition],
    role: &str,
    number: u64,
    checkpoint: bool,
) -> Result<ChannelBinding, &'static str> {
    for e in epochs {
        let (head, _, _, _) = e.anchor(role)?;
        let boundary = if checkpoint {
            head.body.revision
        } else {
            match e {
                TransportTransition::EnteredLoss(h) => h.high_water(),
                _ => head.body.sequence,
            }
        };
        if number > boundary {
            binding = e.binding().clone();
        } else {
            break;
        }
    }
    Ok(binding)
}

// This first epoch-handoff mode deliberately accepts only fully published,
// completed jobs. Pending/running/uncertain histories require the later dispatch
// reconciliation protocol and cannot inherit a resource activation here.
fn verify_pending_close_reply(
    controller_root: &std::fs::File,
    worker_root: &std::fs::File,
    request: &RpcRequest,
    reply: &WorkerReply,
    keys: &ChannelKeys,
) -> Result<(), &'static str> {
    use std::os::fd::AsRawFd;
    let WorkerOperation::Close(command) = &request.operation else {
        return Err("evidence_invalid");
    };
    let WorkerReply::Closed(receipt, mac) = reply else {
        return Err("transport_uncertain");
    };
    verify_close_receipt(&keys.reply, receipt, mac)?;
    if (
        receipt.worker.as_str(),
        receipt.boot.as_str(),
        receipt.assignment.as_str(),
        receipt.fence,
        receipt.operation.as_str(),
    ) != (
        command.worker.as_str(),
        command.boot.as_str(),
        command.assignment.as_str(),
        command.fence,
        command.operation.as_str(),
    ) {
        return Err("evidence_invalid");
    }
    let worker = super::la_store::open_pinned_readonly_database(worker_root, "worker.sqlite")?;
    let controller =
        super::la_store::open_pinned_readonly_database(controller_root, "lane_assignments.sqlite")?;
    let closed: bool=worker.query_row("SELECT EXISTS(SELECT 1 FROM worker_cleanup_receipts c JOIN worker_close_receipts s ON s.operation=c.operation AND s.sequence=c.sequence JOIN worker_reservations r ON r.assignment_id=c.assignment AND r.fence=c.fence AND r.closed=1 JOIN worker_session_snapshots x ON x.assignment=c.assignment AND x.worker=?5 AND x.boot=?6 AND x.sequence=c.sequence AND x.fence=c.fence WHERE c.assignment=?1 AND c.operation=?2 AND c.fence=?3 AND c.sequence=?4) AND NOT EXISTS(SELECT 1 FROM operations WHERE state='started')",rusqlite::params![receipt.assignment,receipt.operation,receipt.fence as i64,receipt.sequence as i64,receipt.worker,receipt.boot],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
    let previous: i64 = controller
        .query_row(
            "SELECT sequence FROM la_worker_cursor WHERE worker=?1 AND boot=?2",
            rusqlite::params![receipt.worker, receipt.boot],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    if !closed || previous.checked_add(1) != Some(receipt.sequence as i64) {
        return Err("evidence_invalid");
    }
    let mut entries = 0;
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", worker_root.as_raw_fd()))
        .map_err(|_| "evidence_invalid")?
    {
        entries += 1;
        if entries > 256
            || entry
                .map_err(|_| "evidence_invalid")?
                .file_name()
                .to_string_lossy()
                .starts_with("input-")
        {
            return Err("evidence_invalid");
        }
    }
    verify_completed_worker_reconciliation(&controller, worker_root, &request.binding, keys)
}
fn verify_pending_stop_reply(
    controller_root: &std::fs::File,
    worker_root: &std::fs::File,
    request: &RpcRequest,
    reply: &WorkerReply,
    keys: &ChannelKeys,
) -> Result<(), &'static str> {
    let WorkerOperation::Stop(c) = &request.operation else {
        return Err("evidence_invalid");
    };
    let WorkerReply::Stopped(r, mac) = reply else {
        return Err("transport_uncertain");
    };
    verify_stop_receipt(&keys.reply, r, mac)?;
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(c).map_err(|_| "evidence_invalid")?,
    ));
    if r.worker != c.worker
        || r.boot != c.boot
        || r.assignment != c.assignment
        || r.fence != c.fence
        || r.operation != c.operation
        || r.job != c.job
        || r.command_digest != digest
        || r.sequence == 0
    {
        return Err("evidence_invalid");
    }
    let worker = super::la_store::open_pinned_readonly_database(worker_root, "worker.sqlite")?;
    let claims =
        super::la_store::open_pinned_readonly_database(controller_root, "lane_assignments.sqlite")?;
    let exact: bool = worker.query_row("SELECT EXISTS(SELECT 1 FROM worker_stop_receipts r JOIN worker_inspect_commands p ON p.operation=r.operation AND p.command_digest=r.command_digest JOIN worker_session_snapshots s ON s.sequence=r.sequence AND s.assignment=?2 AND s.worker=?3 AND s.boot=?4 AND s.fence=?5 AND s.event='stop' WHERE r.operation=?1 AND r.sequence=?6 AND hex(r.command_digest)=upper(?7))", rusqlite::params![c.operation,c.assignment,c.worker,c.boot,c.fence as i64,r.sequence as i64,digest], |row|row.get(0)).map_err(|_| "evidence_invalid")?;
    let previous: i64 = claims
        .query_row(
            "SELECT sequence FROM la_worker_cursor WHERE worker=?1 AND boot=?2",
            rusqlite::params![c.worker, c.boot],
            |row| row.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    if !exact || previous.checked_add(1) != Some(r.sequence as i64) {
        return Err("evidence_invalid");
    }
    verify_worker_reconciliation(&claims, worker_root, &request.binding, keys, Some(c))
}
fn verify_completed_worker_reconciliation(
    claims: &rusqlite::Connection,
    root: &std::fs::File,
    binding: &ChannelBinding,
    keys: &ChannelKeys,
) -> Result<(), &'static str> {
    verify_worker_reconciliation(claims, root, binding, keys, None)
}
fn verify_worker_reconciliation(
    claims: &rusqlite::Connection,
    root: &std::fs::File,
    binding: &ChannelBinding,
    keys: &ChannelKeys,
    stopped: Option<&InspectCommand>,
) -> Result<(), &'static str> {
    let worker = super::la_store::open_pinned_readonly_database(root, "worker.sqlite")?;
    super::la_worker::verify_session_history(&worker, &keys.reply)?;
    let mut st=claims.prepare("SELECT j.id,j.state,p.command,p.digest,r.report_digest,m.body FROM la_jobs j LEFT JOIN la_job_permit_intents p ON p.job=j.id LEFT JOIN la_job_results r ON r.job=j.id LEFT JOIN la_mandates m ON m.job=j.id ORDER BY j.id LIMIT 33").map_err(|_|"evidence_invalid")?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
            ))
        })
        .map_err(|_| "evidence_invalid")?;
    let mut count = 0i64;
    for row in rows {
        count += 1;
        let (job, state, command, digest, report, mandate) =
            row.map_err(|_| "transport_uncertain")?;
        if count > 32
            || !(state == "succeeded"
                || state == "stopping" && stopped.is_some_and(|c| c.job == job))
            || hex::encode(Sha256::digest(command.as_bytes())) != digest
        {
            return Err("transport_uncertain");
        }
        let c: InspectCommand = serde_json::from_str(&command).map_err(|_| "evidence_invalid")?;
        if c.job != job || c.worker != binding.worker {
            return Err("evidence_invalid");
        }
        if stopped.is_some_and(|target| {
            target.job == job && serde_json::to_vec(target).ok() != serde_json::to_vec(&c).ok()
        }) {
            return Err("evidence_invalid");
        }
        let saved: (String, String, String, Option<Vec<u8>>) = worker
            .query_row(
                "SELECT job,input_digest,state,report FROM operations WHERE op=?1",
                [&c.operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "transport_uncertain")?;
        let m: Vec<u8> = worker
            .query_row(
                "SELECT body FROM worker_mandates WHERE job=?1",
                [&job],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let reserved:bool=worker.query_row("SELECT EXISTS(SELECT 1 FROM worker_reservations r JOIN worker_session_snapshots s ON s.assignment=r.assignment_id AND s.fence=r.fence WHERE r.assignment_id=?1 AND r.fence=?2 AND s.worker=?3 AND s.boot=?4)",rusqlite::params![c.assignment,c.fence as i64,c.worker,c.boot],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if saved.0 != job
            || saved.1 != c.input_digest
            || if stopped.is_some_and(|target| target.job == job) {
                saved.2 != "stopped" || saved.3.is_some() || report.is_some()
            } else {
                saved.2 != "complete"
                    || saved.3.as_ref().is_none_or(|bytes| {
                        bytes.len() > 4096 || Some(hex::encode(Sha256::digest(bytes))) != report
                    })
            }
            || m != mandate.as_bytes()
            || !reserved
        {
            return Err("evidence_invalid");
        }
    }
    let actual: i64 = worker
        .query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    if actual != count {
        return Err("transport_uncertain");
    }
    Ok(())
}
fn transport_authority_binding(
    db: &rusqlite::Connection,
    sequence: u64,
) -> Result<ChannelBinding, &'static str> {
    let (mut binding, epochs) = transport_epochs(db)?;
    for e in epochs {
        let boundary = match &e {
            TransportTransition::EnteredLoss(h) => h.authority_sequence + 1,
            _ => e.authority_sequence(),
        };
        if sequence > boundary {
            binding = e.binding().clone();
        } else {
            break;
        }
    }
    Ok(binding)
}
fn transport_authority_digest(
    db: &rusqlite::Connection,
    expected: u64,
) -> Result<String, &'static str> {
    if loss_bridge_table(db)? {
        return Err("evidence_invalid");
    }
    let mut hash = Sha256::new();
    hash.update(b"diffuser-transport-authority-history/v1\0");
    let mut st = db
        .prepare("SELECT sequence,observed_at,body,frame FROM channel_authority ORDER BY sequence")
        .map_err(|_| "evidence_invalid")?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|_| "evidence_invalid")?;
    let mut n = 0u64;
    for row in rows {
        let (seq, time, body, frame) = row.map_err(|_| "evidence_invalid")?;
        n += 1;
        if n > 128 || seq != n as i64 || body.len() > 12288 || frame.len() > 12288 {
            return Err("evidence_invalid");
        }
        hash.update(seq.to_be_bytes());
        hash.update(time.to_be_bytes());
        hash.update((body.len() as u64).to_be_bytes());
        hash.update(body);
        hash.update((frame.len() as u64).to_be_bytes());
        hash.update(frame);
    }
    if n != expected {
        return Err("evidence_invalid");
    }
    Ok(hex::encode(hash.finalize()))
}
fn verify_transport_chain(
    db: &rusqlite::Connection,
    head: &SignedCheckpoint,
    reply: &[u8; 32],
    custody: &[u8; 32],
) -> Result<(), &'static str> {
    let (genesis, epochs) = transport_epochs(db)?;
    for e in &epochs {
        e.verify_history(custody)?;
        if let TransportTransition::EnteredLoss(h) = e {
            h.installed_resolution(db, custody)?;
        }
    }
    let mut previous = "0".repeat(64);
    for n in 1..=head.body.revision {
        let (f, a): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints WHERE revision=?1",
                [n as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if f.len() > 4096 || a.len() > 4096 {
            return Err("evidence_invalid");
        }
        let f: SignedCheckpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
        let a: CheckpointAck = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
        if f.body.revision != n
            || f.body.previous != previous
            || f.body.role != head.body.role
            || f.body.binding
                != binding_in_history(genesis.clone(), &epochs, &head.body.role, n, true)?
            || !bool::from(
                typed_mac(reply, b"diffuser-custody-checkpoint/v1\0", &f.body)?.ct_eq(&f.mac),
            )
        {
            return Err("evidence_invalid");
        }
        a.verify(custody, &f)?;
        previous = f.digest()?;
    }
    if previous != head.digest()? {
        return Err("evidence_invalid");
    }
    checkpoint_bytes_digest(db, head.body.revision, head.body.revision)?;
    Ok(())
}
impl TransportJournal {
    pub(super) fn install_controller_epoch(
        &mut self,
        handoff: &TransportEpochHandoff,
        link: Option<std::sync::Arc<CustodyLink>>,
        now: u64,
    ) -> Result<(), &'static str> {
        self.install_transition(
            &TransportTransition::Controller(Box::new(handoff.clone())),
            link,
            now,
        )
    }
    pub(super) fn install_worker_epoch(
        &mut self,
        handoff: &WorkerEpochHandoff,
        link: Option<std::sync::Arc<CustodyLink>>,
        now: u64,
    ) -> Result<(), &'static str> {
        self.install_transition(
            &TransportTransition::Worker(Box::new(handoff.clone())),
            link,
            now,
        )
    }
    fn install_transition(
        &mut self,
        handoff: &TransportTransition,
        link: Option<std::sync::Arc<CustodyLink>>,
        now: u64,
    ) -> Result<(), &'static str> {
        self.install_transition_with_resolution(handoff, link, now, None)
    }
    fn install_transition_with_resolution(
        &mut self,
        handoff: &TransportTransition,
        link: Option<std::sync::Arc<CustodyLink>>,
        now: u64,
        resolution: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        self.check()?;
        let (old_link, _, revision, head, _) = self.custody.as_ref().ok_or("evidence_invalid")?;
        recovery_trace(
            "install_begin",
            serde_json::json!({"role":old_link.role,"supplied_now":now,"revision":revision,"epoch":handoff.binding().controller_epoch}),
        );
        handoff.verify(&old_link.ack_key, now)?;
        let role = old_link.role.clone();
        let (anchor, _, history, state) = handoff.anchor(&role)?;
        if self.binding != *handoff.previous()
            || *revision != anchor.body.revision
            || *head != anchor.digest()?
            || checkpoint_bytes_digest(&self.db, *revision, *revision)? != history
            || state_custody::state_digest(&self.root)? != state
        {
            return Err("evidence_invalid");
        }
        if transport_epochs(&self.db)?.1.len() >= 8 {
            return Err("storage_unavailable");
        }
        self.validate_custody_chain()?;
        if role == "worker"
            && transport_authority_digest(&self.db, handoff.authority_sequence())?
                != handoff.worker_authority()
        {
            return Err("evidence_invalid");
        }
        let link = link.unwrap_or_else(|| old_link.clone());
        if link.role != role
            || link.request_key != old_link.request_key
            || link.ack_key != old_link.ack_key
        {
            return Err("evidence_invalid");
        }
        let bytes = serde_json::to_vec(handoff).map_err(|_| "evidence_invalid")?;
        if bytes.len() > 12288 {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|_| "storage_unavailable")?;
        if role == "controller" {
            if let Some(reply) = handoff.settlement() {
                let n = tx
                    .execute(
                        "UPDATE channel_log SET response=?2 WHERE sequence=?1 AND response IS NULL",
                        rusqlite::params![anchor.body.sequence as i64, reply.as_bytes()],
                    )
                    .map_err(|_| "evidence_invalid")?;
                if n != 1 {
                    return Err("evidence_invalid");
                }
            }
        }
        if let TransportTransition::EnteredLoss(h) = handoff {
            if role == "worker" {
                let resolution = resolution.ok_or("evidence_invalid")?;
                if resolution.len() > 12288 {
                    return Err("evidence_invalid");
                }
                let loss: WorkerLossSettlement =
                    serde_json::from_slice(resolution).map_err(|_| "evidence_invalid")?;
                h.verify_resolution(loss.request.as_bytes(), resolution, &old_link.ack_key)?;
                let signed: SignedRequest =
                    serde_json::from_str(&loss.request).map_err(|_| "evidence_invalid")?;
                let digest = hex::encode(Sha256::digest(
                    serde_json::to_vec(&signed.request).map_err(|_| "evidence_invalid")?,
                ));
                tx.execute(
                    "INSERT INTO channel_log VALUES(?1,?2,?3,?4)",
                    rusqlite::params![
                        h.high_water() as i64,
                        digest,
                        resolution,
                        loss.request.as_bytes()
                    ],
                )
                .map_err(|_| "evidence_invalid")?;
            } else {
                h.installed_resolution(&tx, &old_link.ack_key)?;
            }
        }
        match handoff {
            TransportTransition::EnteredLoss(e) => {
                tx.execute_batch("CREATE TABLE IF NOT EXISTS channel_worker_epochs(epoch INTEGER PRIMARY KEY,body BLOB NOT NULL);").map_err(|_|"storage_unavailable")?;
                tx.execute(
                    "INSERT INTO channel_worker_epochs VALUES(?1,?2)",
                    rusqlite::params![e.binding.worker_epoch as i64, bytes],
                )
                .map_err(|_| "evidence_invalid")?;
            }
            TransportTransition::Controller(e) => {
                tx.execute(
                    "INSERT INTO channel_epochs VALUES (?1,?2)",
                    rusqlite::params![e.binding.controller_epoch as i64, bytes],
                )
                .map_err(|_| "evidence_invalid")?;
            }
            TransportTransition::Worker(e) => {
                // Explicit authenticated version append; never migrate or replace genesis/history.
                tx.execute_batch("CREATE TABLE IF NOT EXISTS channel_worker_epochs(epoch INTEGER PRIMARY KEY,body BLOB NOT NULL);").map_err(|_| "storage_unavailable")?;
                tx.execute(
                    "INSERT INTO channel_worker_epochs VALUES (?1,?2)",
                    rusqlite::params![e.binding.worker_epoch as i64, bytes],
                )
                .map_err(|_| "evidence_invalid")?;
            }
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.binding = handoff.binding().clone();
        self.custody.as_mut().ok_or("evidence_invalid")?.0 = link;
        // No public/worker operation can observe the transition before P has
        // independently read and fsynced its exact new-state checkpoint.
        recovery_trace(
            "install_committed",
            serde_json::json!({"role":role,"sequence":anchor.body.sequence}),
        );
        self.checkpoint("handoff", handoff.install_sequence(&role)?)?;
        recovery_trace(
            "install_ack_durable",
            serde_json::json!({"role":role,"sequence":anchor.body.sequence}),
        );
        self.check()
    }
}
impl WorkerRpc {
    pub(super) fn install_controller_epoch(
        &mut self,
        bytes: &[u8],
    ) -> Result<TransportEpochAck, &'static str> {
        if bytes.len() > 12288 {
            return Err("evidence_invalid");
        }
        let handoff: TransportEpochHandoff =
            serde_json::from_slice(&super::la_contract::canonical_json(bytes)?)
                .map_err(|_| "evidence_invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis() as u64;
        // Invalidate old activation before changing transport epochs. A failed
        // handoff cannot preserve execution authority from the old controller.
        *self.admission.0.lock().map_err(|_| "storage_unavailable")? = None;
        self.channel.install_controller_epoch(&handoff, None, now)?;
        handoff.acknowledgment("worker", &self.keys)
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransportEpochAck {
    binding: ChannelBinding,
    role: String,
    digest: String,
    mac: [u8; 32],
}
impl TransportEpochHandoff {
    fn acknowledgment(
        &self,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<TransportEpochAck, &'static str> {
        let digest = self.digest()?;
        let mac = typed_mac(
            &keys.reply,
            b"diffuser-transport-epoch-ack/v1\0",
            &(&self.binding, role, &digest),
        )?;
        Ok(TransportEpochAck {
            binding: self.binding.clone(),
            role: role.into(),
            digest,
            mac,
        })
    }
    pub(super) fn verify_ack(
        &self,
        role: &str,
        keys: &ChannelKeys,
        ack: &TransportEpochAck,
    ) -> Result<(), &'static str> {
        let expected = self.acknowledgment(role, keys)?;
        if ack.binding != expected.binding
            || ack.role != expected.role
            || ack.digest != expected.digest
            || !bool::from(ack.mac.ct_eq(&expected.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn verify_consumed(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        self.verify_history(&keys.custody)?;
        let db = super::la_store::open_pinned_readonly_database(root, "controller-channel.sqlite")?;
        let (_, epochs) = transport_epochs(&db)?;
        if epochs.last().ok_or("evidence_invalid")?.digest()? != self.digest()? {
            return Err("evidence_invalid");
        }
        let (count, high): (i64, i64) = db
            .query_row(
                "SELECT COUNT(*),MAX(revision) FROM channel_checkpoints",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let revision = self.controller.body.revision + 1;
        if count != high || count < revision as i64 || count > CHECKPOINT_MAX as i64 {
            return Err("evidence_invalid");
        }
        recovery_trace(
            "consumption_full_history",
            serde_json::json!({"current_revision":count,"retained_prefix":self.controller.body.revision}),
        );
        let (f, a): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints WHERE revision=?1",
                [revision as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let frame: SignedCheckpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
        let ack: CheckpointAck = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
        let b = &frame.body;
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        ack.verify(&keys.custody, &frame)?;
        let db_meta =
            super::la_artifacts::open_artifact(root, "controller-channel.sqlite", libc::O_RDONLY)
                .map_err(|_| "evidence_invalid")?
                .metadata()
                .map_err(|_| "evidence_invalid")?;
        if b.binding != self.binding
            || b.role != "controller"
            || b.phase != "handoff"
            || b.revision != revision
            || b.sequence != self.controller.body.sequence
            || b.previous != self.controller.digest()?
            || (b.root_dev, b.root_inode) != (m.dev(), m.ino())
            || (b.db_dev, b.db_inode) != (db_meta.dev(), db_meta.ino())
            || !bool::from(
                typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", b)?.ct_eq(&frame.mac),
            )
            || checkpoint_bytes_digest(&db, count as u64, self.controller.body.revision)?
                != self.controller_history
        {
            return Err("evidence_invalid");
        }
        let proof = ack.consumption.as_ref().ok_or("evidence_invalid")?;
        proof.verify_window(
            &keys.custody,
            &self.digest()?,
            self.issued_at,
            self.expires_at,
            now,
        )?;
        if proof.peer.as_ref().is_none_or(|p| p.kind != "worker") {
            return Err("evidence_invalid");
        }
        // Full retained transport chain, including every ACK and epoch. No
        // cross-state parsing cache or history reset is used here.
        let latest: Vec<u8> = db
            .query_row(
                "SELECT frame FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let latest: SignedCheckpoint =
            serde_json::from_slice(&latest).map_err(|_| "evidence_invalid")?;
        verify_transport_chain(&db, &latest, &keys.reply, &keys.custody)?;
        state_custody::verify_recovery_consumed(
            root,
            &self.binding,
            self.service_recovery.as_deref().ok_or("evidence_invalid")?,
            keys,
            self.issued_at,
            self.expires_at,
            now,
        )?;
        recovery_trace(
            "historical_consumption_verified",
            serde_json::json!({"observed_at":proof.observed_at,"original_expires_at":self.expires_at,"now":now}),
        );
        Ok(())
    }
    pub(super) fn recovered_close_window(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Option<(CloseReceipt, cleanup::Reconciliation)>, &'static str> {
        recovery_trace(
            "recovered_close_window",
            serde_json::json!({"now":now,"issued_at":self.issued_at,"expires_at":self.expires_at}),
        );
        self.verify_consumed(root, keys, now)?;
        let Some((receipt, _)) = self.settled_close(keys)? else {
            return Ok(None);
        };
        if self.controller.body.phase != "intent" || self.worker.body.phase != "complete" {
            return Err("evidence_invalid");
        }
        let window = cleanup::Reconciliation {
            binding: self.binding.clone(),
            handoff: self.digest()?,
            receipt_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(&receipt).map_err(|_| "evidence_invalid")?,
            )),
            observed_at: now,
            expires_at: now
                .checked_add(cleanup::deadline_ms(&self.binding)?)
                .ok_or("evidence_invalid")?,
        };
        Ok(Some((receipt, window)))
    }
    pub(super) fn settled_close(
        &self,
        keys: &ChannelKeys,
    ) -> Result<Option<(CloseReceipt, [u8; 32])>, &'static str> {
        let Some(bytes) = &self.settlement else {
            return Ok(None);
        };
        if bytes.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        let signed: SignedResponse =
            serde_json::from_slice(bytes.as_bytes()).map_err(|_| "evidence_invalid")?;
        if signed.response.binding != self.previous
            || signed.response.sequence != self.controller.body.sequence
            || !bool::from(
                typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &signed.response)?
                    .ct_eq(&signed.mac),
            )
        {
            return Err("evidence_invalid");
        }
        match signed.response.reply {
            WorkerReply::Closed(receipt, mac) => {
                verify_close_receipt(&keys.reply, &receipt, &mac)?;
                Ok(Some((receipt, mac)))
            }
            WorkerReply::Stopped(..) => Ok(None),
            _ => Err("evidence_invalid"),
        }
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn settled_stop(
        &self,
        keys: &ChannelKeys,
    ) -> Result<Option<(StopReceipt, [u8; 32])>, &'static str> {
        let Some(bytes) = &self.settlement else {
            return Ok(None);
        };
        let signed: SignedResponse =
            serde_json::from_slice(bytes.as_bytes()).map_err(|_| "evidence_invalid")?;
        if signed.response.binding != self.previous
            || signed.response.sequence != self.controller.body.sequence
            || !bool::from(
                typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &signed.response)?
                    .ct_eq(&signed.mac),
            )
        {
            return Err("evidence_invalid");
        }
        match signed.response.reply {
            WorkerReply::Stopped(receipt, mac) => {
                verify_stop_receipt(&keys.reply, &receipt, &mac)?;
                Ok(Some((receipt, mac)))
            }
            WorkerReply::Closed(..) => Ok(None),
            _ => Err("transport_uncertain"),
        }
    }
    pub(super) fn verify_controller(
        &self,
        root: &std::fs::File,
        recovery: &ControllerReadbackRecovery,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify(&keys.custody, now)?;
        if self.binding != *recovery.binding()
            || self.previous != recovery.service.previous_binding
            || self.recovery_digest != recovery.digest()?
            || self.authority_sequence != recovery.authority_sequence
            || self.controller_state != state_custody::state_digest(root)?
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

/// A protected controller can recover durable reads before it is allowed to
/// dispatch again. This capability preserves the old transport binding and
/// locks its exact witnessed history; it does not requalify the worker or free
/// capacity. P must establish old-role death before issuance.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControllerReadbackRecovery {
    service: state_custody::Recovery,
    checkpoint: SignedCheckpoint,
    ack: CheckpointAck,
    store_id: String,
    authority_sequence: u64,
    mac: [u8; 32],
}
impl ControllerReadbackRecovery {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut value = self.clone();
        value.mac = [0; 32];
        typed_mac(
            &keys.custody,
            b"diffuser-controller-readback-recovery/v1\0",
            &value,
        )
    }
    pub(super) fn binding(&self) -> &ChannelBinding {
        &self.service.binding
    }
    pub(super) fn service(&self) -> &state_custody::Recovery {
        &self.service
    }
    pub(in crate::cosp) fn authority_sequence(&self) -> u64 {
        self.authority_sequence
    }
    pub(super) fn store_id(&self) -> &str {
        &self.store_id
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    pub(super) fn verify(
        &self,
        root: &std::fs::File,
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.service.verify(root, binding, &keys.custody, now)?;
        if self.store_id.len() != 64
            || hex::decode(&self.store_id).is_err()
            || self.authority_sequence == 0
            || self.authority_sequence > 128
            || self.checkpoint.body.binding != self.service.previous_binding
            || self.checkpoint.body.role != "controller"
            || !(self.checkpoint.body.phase == "complete" && self.service.close.is_none()
                || self.checkpoint.body.phase == "intent" && self.service.close.is_some())
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        self.ack.verify(&keys.custody, &self.checkpoint)?;
        Ok(())
    }
    pub(super) fn reopen_transport(
        &self,
        root: &std::fs::File,
        path: &std::path::Path,
        keys: &ChannelKeys,
    ) -> Result<TransportJournal, &'static str> {
        // This link can verify the old chain but cannot acknowledge a new
        // mutation. No recovered read router owns a WorkerClient.
        let link = CustodyLink::new(
            self.service.previous_binding.clone(),
            "controller",
            keys.reply,
            keys.custody,
            Box::new(|_| Err("routing_closed")),
        )?;
        TransportJournal::reopen_witnessed(
            root,
            path,
            "controller-channel.sqlite",
            &self.checkpoint,
            &self.ack,
            link,
        )
    }
}
impl CustodyLedger {
    #[expect(
        clippy::too_many_arguments,
        reason = "Handoff binds two independently retained histories and authority high-water."
    )]
    pub(super) fn authorize_controller_readback(
        &self,
        root: &std::fs::File,
        service: state_custody::Recovery,
        checkpoint: &SignedCheckpoint,
        ack: &CheckpointAck,
        store_id: &str,
        authority_sequence: u64,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<ControllerReadbackRecovery, &'static str> {
        if self.role != "controller"
            || self.binding != service.previous_binding
            || self.head != checkpoint.digest()?
            || self.revision != checkpoint.body.revision
            || self.request_key != keys.reply
            || self.ack_key != keys.custody
        {
            return Err("evidence_invalid");
        }
        let mut value = ControllerReadbackRecovery {
            service,
            checkpoint: checkpoint.clone(),
            ack: ack.clone(),
            store_id: store_id.into(),
            authority_sequence,
            mac: [0; 32],
        };
        value.mac = value.signature(keys)?;
        value.verify(root, value.binding(), keys, now)?;
        // P has only a read-only role-root view. Verify the exact retained
        // head without opening a writer or inheriting the child's lock.
        let db = super::la_store::open_pinned_readonly_database(root, "controller-channel.sqlite")?;
        if transport_state_digest(&db, &self.binding)? != checkpoint.body.state_digest {
            return Err("evidence_invalid");
        }
        let (frame, stored_ack): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints WHERE revision=?1",
                [checkpoint.body.revision as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if frame != serde_json::to_vec(checkpoint).map_err(|_| "evidence_invalid")?
            || stored_ack != serde_json::to_vec(ack).map_err(|_| "evidence_invalid")?
        {
            return Err("evidence_invalid");
        }
        checkpoint_bytes_digest(&db, checkpoint.body.revision, checkpoint.body.revision)?;
        let claims =
            super::la_store::open_pinned_readonly_database(root, "lane_assignments.sqlite")?;
        let identity: (String, i64, i64, i64) = claims
            .query_row(
                "SELECT store_id,root_dev,root_inode,writer_epoch FROM la_controller_identity",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if identity
            != (
                store_id.into(),
                value.service.root_dev as i64,
                value.service.root_inode as i64,
                value.service.previous_binding.controller_epoch as i64,
            )
        {
            return Err("evidence_invalid");
        }
        let (count, high): (i64, i64) = claims
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM la_authority_observations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if count != authority_sequence as i64 || high != count {
            return Err("evidence_invalid");
        }
        Ok(value)
    }
}

// This extension is sealed only by a verified resource family and protected
// current-root observations. Receiving it never bypasses request authorization.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationBody {
    binding: ChannelBinding,
    resource: qualification::Certificate,
    worker_dev: u64,
    worker_inode: u64,
    worker_state: String,
    controller_dev: u64,
    controller_inode: u64,
    controller_state: String,
    controller_head: String,
    authority_sequence: u64,
    issued_at: u64,
    expires_at: u64,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Activation {
    body: ActivationBody,
    mac: [u8; 32],
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActivationAck {
    binding: ChannelBinding,
    role: String,
    activation_digest: String,
    mac: [u8; 32],
}
impl Activation {
    #[expect(
        clippy::too_many_arguments,
        reason = "Protected activation binds independently checked role roots and authority head."
    )]
    pub(super) fn issue(
        resource: qualification::Certificate,
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        worker: &std::fs::File,
        controller: &std::fs::File,
        checkpoint: &state_custody::Checkpoint,
        ack: &state_custody::Ack,
        authority_sequence: u64,
        now: u64,
        expires: u64,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        resource.verify(binding, keys, now)?;
        let anchor = state_custody::verified_anchor(controller, checkpoint, ack, keys)?;
        if authority_sequence == 0
            || authority_sequence > 128
            || expires <= now
            || expires - now > 12000
            || expires > resource.expires_at()
        {
            return Err("evidence_invalid");
        }
        // A current signed authority source is also required at each worker
        // permit/start. This genesis check disallows adopting existing work.
        let workerdb = super::la_store::open_pinned_readonly_database(worker, "worker.sqlite")?;
        let starts: i64 = workerdb
            .query_row("SELECT COUNT(*) FROM operations", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        let claims =
            super::la_store::open_pinned_readonly_database(controller, "lane_assignments.sqlite")?;
        let assignments: i64 = claims
            .query_row("SELECT COUNT(*) FROM la_assignments", [], |r| r.get(0))
            .map_err(|_| "evidence_invalid")?;
        if starts != 0 || assignments != 0 {
            return Err("evidence_invalid");
        }
        let (count, high): (i64, i64) = claims
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM la_authority_observations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if count != authority_sequence as i64 || high != count {
            return Err("evidence_invalid");
        }
        let w = worker.metadata().map_err(|_| "evidence_invalid")?;
        let c = controller.metadata().map_err(|_| "evidence_invalid")?;
        let body = ActivationBody {
            binding: binding.clone(),
            resource,
            worker_dev: w.dev(),
            worker_inode: w.ino(),
            worker_state: state_custody::state_digest(worker)?,
            controller_dev: c.dev(),
            controller_inode: c.ino(),
            controller_state: anchor.1,
            controller_head: anchor.0,
            authority_sequence,
            issued_at: now,
            expires_at: expires,
        };
        let mac = typed_mac(&keys.custody, b"diffuser-protected-activation/v1\0", &body)?;
        Ok(Self { body, mac })
    }
    fn verify(
        &self,
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        root: &std::fs::File,
        role: &str,
        domain: Option<&state_custody::Session>,
        now: u64,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        self.body.resource.verify(binding, keys, now)?;
        if self.body.binding != *binding
            || self.body.issued_at > now
            || now >= self.body.expires_at
            || self.body.expires_at - self.body.issued_at > 12000
            || self.body.expires_at > self.body.resource.expires_at()
            || !bool::from(
                typed_mac(
                    &keys.custody,
                    b"diffuser-protected-activation/v1\0",
                    &self.body,
                )?
                .ct_eq(&self.mac),
            )
        {
            return Err("evidence_invalid");
        }
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        let (dev, ino, state) = match role {
            "worker" => (
                self.body.worker_dev,
                self.body.worker_inode,
                &self.body.worker_state,
            ),
            "controller" => (
                self.body.controller_dev,
                self.body.controller_inode,
                &self.body.controller_state,
            ),
            _ => return Err("evidence_invalid"),
        };
        if (m.dev(), m.ino()) != (dev, ino) || state_custody::state_digest(root)? != *state {
            return Err("evidence_invalid");
        }
        if role == "controller" {
            let (head, state) = domain.ok_or("evidence_invalid")?.activation_anchor()?;
            if head != self.body.controller_head || state != self.body.controller_state {
                return Err("evidence_invalid");
            }
        } else {
            let db = super::la_store::open_pinned_readonly_database(root, "worker-channel.sqlite")?;
            let (count, high): (i64, i64) = db
                .query_row(
                    "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM channel_authority",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if count != self.body.authority_sequence as i64 || high != count {
                return Err("evidence_invalid");
            }
            let (canonical, frame): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [count],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if verify_source_observation(&keys.authority, binding, &frame)? != canonical {
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
    fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    fn acknowledgment(
        &self,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<ActivationAck, &'static str> {
        let activation_digest = self.digest()?;
        let mac = typed_mac(
            &keys.reply,
            b"diffuser-protected-activation-ack/v1\0",
            &(self.body.binding.clone(), role, &activation_digest),
        )?;
        Ok(ActivationAck {
            binding: self.body.binding.clone(),
            role: role.into(),
            activation_digest,
            mac,
        })
    }
    pub(super) fn verify_ack(
        &self,
        role: &str,
        keys: &ChannelKeys,
        ack: &ActivationAck,
    ) -> Result<(), &'static str> {
        let expected = self.acknowledgment(role, keys)?;
        if expected.binding != ack.binding
            || expected.role != ack.role
            || expected.activation_digest != ack.activation_digest
            || !bool::from(expected.mac.ct_eq(&ack.mac))
        {
            Err("evidence_invalid")
        } else {
            Ok(())
        }
    }
}

/// Protected P observes sealed worker containment and both pinned roots. A
/// worker tombstone alone can never construct the capacity-release certificate.
pub(super) mod cleanup {
    use super::*;
    use rusqlite::{params, OptionalExtension};
    use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

    #[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Reconciliation {
        pub(in crate::cosp) binding: ChannelBinding,
        pub(in crate::cosp) handoff: String,
        pub(in crate::cosp) receipt_digest: String,
        pub(in crate::cosp) observed_at: u64,
        pub(in crate::cosp) expires_at: u64,
    }
    #[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Claim {
        pub(in crate::cosp) assignment: String,
        pub(in crate::cosp) worker: String,
        pub(in crate::cosp) boot: String,
        pub(in crate::cosp) fence: u64,
        pub(in crate::cosp) operation: String,
        pub(in crate::cosp) sequence: u64,
        pub(in crate::cosp) stop_digest: Vec<u8>,
        revision: u64,
        requested_at: u64,
        jobs_digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub(super) reconciliation: Option<Reconciliation>,
    }
    impl Claim {
        pub(super) fn certificate_expiry(
            &self,
            binding: &ChannelBinding,
            now: u64,
        ) -> Result<u64, &'static str> {
            let expires = now
                .checked_add(1500)
                .ok_or("evidence_invalid")?
                .min(self.cleanup_deadline(binding)?);
            if expires <= now
                || now < self.requested_at
                || self
                    .reconciliation
                    .as_ref()
                    .is_some_and(|r| now < r.observed_at)
            {
                return Err("evidence_invalid");
            }
            Ok(expires)
        }
        fn cleanup_deadline(&self, binding: &ChannelBinding) -> Result<u64, &'static str> {
            if let Some(r) = &self.reconciliation {
                if r.binding != *binding
                    || r.receipt_digest != hex::encode(&self.stop_digest)
                    || r.handoff.len() != 64
                    || hex::decode(&r.handoff).is_err()
                    || r.observed_at < self.requested_at
                    || r.expires_at <= r.observed_at
                    || r.expires_at - r.observed_at > deadline_ms(binding)?
                {
                    return Err("evidence_invalid");
                }
                Ok(r.expires_at)
            } else {
                self.requested_at
                    .checked_add(deadline_ms(binding)?)
                    .ok_or("evidence_invalid")
            }
        }
    }
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Body {
        pub(super) version: u32,
        pub(super) binding: ChannelBinding,
        pub(in crate::cosp) claim: Claim,
        pub(super) controller_root: (u64, u64),
        pub(super) worker_root: (u64, u64),
        pub(super) worker_state_digest: String,
        pub(super) occupancy_digest: String,
        pub(super) observed_at: u64,
        pub(super) expires_at: u64,
    }
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(in crate::cosp) struct Certificate {
        pub(super) body: Body,
        pub(super) mac: [u8; 32],
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub(super) loss: Option<Box<WorkerLossSettlement>>,
    }

    #[track_caller]
    fn require(ok: bool) -> Result<(), &'static str> {
        #[cfg(test)]
        super::recovery_trace(
            "cleanup_actual_predicate",
            serde_json::json!({"line":std::panic::Location::caller().line(),"ok":ok}),
        );
        if ok {
            Ok(())
        } else {
            Err("evidence_invalid")
        }
    }
    fn predicate(name: &str, ok: bool) -> bool {
        #[cfg(test)]
        super::recovery_trace(
            "cleanup_actual_guard",
            serde_json::json!({"guard":name,"ok":ok}),
        );
        #[cfg(not(test))]
        let _ = name;
        ok
    }
    fn hash<T: serde::Serialize>(v: &T) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(v).map_err(|_| "evidence_invalid")?,
        )))
    }
    pub(in crate::cosp) fn claim_snapshot(
        db: &rusqlite::Connection,
        assignment: &str,
    ) -> Result<Claim, &'static str> {
        let loss_table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='la_worker_loss_closes')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if loss_table {
            let close: Option<Vec<u8>> = db
                .query_row(
                    "SELECT body FROM la_worker_loss_closes WHERE assignment_id=?1",
                    [assignment],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| "evidence_invalid")?;
            if let Some(close) = close {
                return loss_claim_snapshot(db, assignment, &close);
            }
        }
        let mut claim = db.query_row("SELECT a.worker,r.boot,a.fence,c.stop_operation,w.sequence,s.receipt_digest,v.revision,c.requested_at FROM la_assignments a JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.worker=a.worker AND r.fence=a.fence JOIN la_close_intents c ON c.assignment_id=a.id JOIN la_assignment_stop_receipts s ON s.assignment_id=a.id JOIN la_worker_receipts w ON w.worker=a.worker AND w.boot=r.boot AND w.digest=s.receipt_digest JOIN la_worker_cursor u ON u.worker=w.worker AND u.boot=w.boot AND u.sequence=w.sequence JOIN la_assignment_revisions v ON v.assignment_id=a.id WHERE a.id=?1 AND a.state IN ('draining','quarantined')",[assignment],|r| Ok(Claim {assignment:assignment.into(),worker:r.get(0)?,boot:r.get(1)?,fence:r.get::<_,i64>(2)? as u64,operation:r.get(3)?,sequence:r.get::<_,i64>(4)? as u64,stop_digest:r.get(5)?,revision:r.get::<_,i64>(6)? as u64,requested_at:r.get::<_,i64>(7)? as u64,jobs_digest:String::new(),reconciliation:None})).optional().map_err(|_| "evidence_invalid")?.ok_or("state_conflict")?;
        let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='la_close_reconciliations')",[],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        if table {
            let bytes: Option<Vec<u8>> = db
                .query_row(
                    "SELECT body FROM la_close_reconciliations WHERE assignment_id=?1",
                    [assignment],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| "evidence_invalid")?;
            if let Some(bytes) = bytes {
                if bytes.len() > 4096 {
                    return Err("evidence_invalid");
                }
                let r: Reconciliation =
                    serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
                if serde_json::to_vec(&r).map_err(|_| "evidence_invalid")? != bytes {
                    return Err("evidence_invalid");
                }
                claim.reconciliation = Some(r);
            }
        }
        let state: String = db
            .query_row(
                "SELECT state FROM la_assignments WHERE id=?1",
                [assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if state == "quarantined" && claim.reconciliation.is_none() {
            return Err("state_conflict");
        }
        let mut statement = db.prepare("SELECT j.id,o.operation,j.state,j.result_artifact,r.report_digest FROM la_jobs j JOIN la_job_outbox o ON o.job=j.id LEFT JOIN la_job_results r ON r.job=j.id WHERE j.assignment_id=?1 ORDER BY j.id").map_err(|_| "evidence_invalid")?;
        let rows = statement
            .query_map([assignment], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(|_| "evidence_invalid")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "evidence_invalid")?;
        require(
            rows.len() <= 32
                && rows.iter().all(|r| {
                    matches!(r.2.as_str(), "succeeded" | "cancelled")
                        && (r.2 != "succeeded" || (r.3.is_some() && r.4.is_some()))
                }),
        )?;
        let total: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM la_jobs WHERE assignment_id=?1",
                [assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        require(
            total == rows.len() as i64
                && claim.stop_digest.len() == 32
                && claim.fence > 0
                && claim.sequence > 0
                && [
                    claim.fence,
                    claim.sequence,
                    claim.revision,
                    claim.requested_at,
                ]
                .iter()
                .all(|v| *v <= i64::MAX as u64),
        )?;
        let receipt = CloseReceipt {
            worker: claim.worker.clone(),
            boot: claim.boot.clone(),
            assignment: assignment.into(),
            fence: claim.fence,
            operation: claim.operation.clone(),
            sequence: claim.sequence,
        };
        require(
            Sha256::digest(serde_json::to_vec(&receipt).map_err(|_| "evidence_invalid")?)
                .as_slice()
                == claim.stop_digest,
        )?;
        claim.jobs_digest = hash(&rows)?;
        Ok(claim)
    }
    fn loss_claim_snapshot(
        db: &rusqlite::Connection,
        assignment: &str,
        close: &[u8],
    ) -> Result<Claim, &'static str> {
        let record: WorkerLossClose =
            serde_json::from_slice(close).map_err(|_| "evidence_invalid")?;
        let c = &record.command;
        require(
            record.kind == "diffuser-dead-domain-close/v1"
                && c.assignment == assignment
                && serde_json::to_vec(&record).map_err(|_| "evidence_invalid")? == close,
        )?;
        let cap: Vec<u8> = db
            .query_row(
                "SELECT body FROM la_worker_loss_settlements WHERE assignment_id=?1",
                [assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let cap: WorkerLossSettlement =
            serde_json::from_slice(&cap).map_err(|_| "evidence_invalid")?;
        require(
            cap.digest()? == record.settlement
                && c.worker == cap.command.worker
                && c.boot == cap.command.boot
                && c.fence == cap.command.fence,
        )?;
        let (sequence,revision,requested_at):(i64,i64,i64)=db.query_row("SELECT w.sequence,v.revision,i.requested_at FROM la_assignments a JOIN la_worker_cursor w ON w.worker=a.worker JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.boot=w.boot AND r.fence=a.fence JOIN la_close_intents i ON i.assignment_id=a.id JOIN la_assignment_revisions v ON v.assignment_id=a.id WHERE a.id=?1 AND a.worker=?2 AND r.boot=?3 AND a.fence=?4 AND a.state='draining' AND i.stop_operation=?5",params![assignment,c.worker,c.boot,c.fence as i64,c.operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"evidence_invalid")?;
        let rows: Vec<(String, String, String, Option<String>)> = {
            let mut st=db.prepare("SELECT j.id,o.operation,j.state,j.result_artifact FROM la_jobs j JOIN la_job_outbox o ON o.job=j.id WHERE j.assignment_id=?1").map_err(|_|"evidence_invalid")?;
            let rows = st
                .query_map([assignment], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
                .map_err(|_| "evidence_invalid")?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "evidence_invalid")?;
            rows
        };
        require(
            rows.len() == 1
                && rows[0].0 == cap.command.job
                && rows[0].1 == cap.command.operation
                && rows[0].2 == "failed"
                && rows[0].3.is_none()
                && sequence > 0,
        )?;
        Ok(Claim {
            assignment: assignment.into(),
            worker: c.worker.clone(),
            boot: c.boot.clone(),
            fence: c.fence,
            operation: c.operation.clone(),
            sequence: sequence as u64,
            stop_digest: Sha256::digest(close).to_vec(),
            revision: u64::try_from(revision).map_err(|_| "evidence_invalid")?,
            requested_at: u64::try_from(requested_at).map_err(|_| "evidence_invalid")?,
            jobs_digest: hash(&rows)?,
            reconciliation: None,
        })
    }
    fn external_anchor(root: &File, prefix: &str, max: u64) -> Result<Vec<u8>, &'static str> {
        use std::os::fd::AsRawFd;
        let mut count = 0u64;
        let mut entries = 0;
        for name in std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))
            .map_err(|_| "evidence_invalid")?
        {
            entries += 1;
            require(entries <= 4096)?;
            let name = name.map_err(|_| "evidence_invalid")?.file_name();
            if name.to_str().is_some_and(|s| s.starts_with(prefix)) {
                count += 1;
                require(count <= max)?;
            }
        }
        require(count > 0)?;
        let file = super::super::la_artifacts::open_artifact(
            root,
            &format!("{prefix}{count:04}.json"),
            libc::O_RDONLY,
        )
        .map_err(|_| "evidence_invalid")?;
        let m = file.metadata().map_err(|_| "evidence_invalid")?;
        require(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o777 == 0o600
                && m.len() <= 4096,
        )?;
        let mut bytes = Vec::new();
        file.take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| "evidence_invalid")?;
        require(bytes.len() as u64 == m.len())?;
        Ok(bytes)
    }
    pub(in crate::cosp) fn deadline_ms(binding: &ChannelBinding) -> Result<u64, &'static str> {
        if super::super::la_contract::policy_digest("runtime-short-v1").as_deref()
            == Some(&binding.policy_digest)
        {
            Ok(1500)
        } else if super::super::la_contract::policy_digest("lab-proposal-v1").as_deref()
            == Some(&binding.policy_digest)
        {
            Ok(5000)
        } else {
            Err("evidence_invalid")
        }
    }
    impl Certificate {
        pub(in crate::cosp) fn assignment(&self) -> &str {
            &self.body.claim.assignment
        }
        /// Inputs are obtained from the already authenticated fixed P relay and
        /// read-only root descriptors, never from a public request or W ACK.
        #[expect(
            clippy::too_many_arguments,
            reason = "Independent cleanup binds containment, roots, epochs, claim and time."
        )]
        pub(in crate::cosp) fn inspect(
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            worker_root: &File,
            controller_root: &File,
            custody_root: &File,
            initial_snapshot: &serde_json::Value,
            current_snapshot: &serde_json::Value,
            assignment: &str,
            now: u64,
        ) -> Result<Self, &'static str> {
            Self::inspect_inner(
                binding,
                keys,
                worker_root,
                controller_root,
                custody_root,
                initial_snapshot,
                current_snapshot,
                assignment,
                now,
                None,
            )
        }
        #[expect(
            clippy::too_many_arguments,
            reason = "Distinct worker-return cleanup binds the original held claim and fresh W2 proof."
        )]
        pub(in crate::cosp) fn inspect_worker_return(
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            worker_root: &File,
            controller_root: &File,
            custody_root: &File,
            initial_snapshot: &serde_json::Value,
            current_snapshot: &serde_json::Value,
            assignment: &str,
            now: u64,
            handoff: &WorkerEpochHandoff,
        ) -> Result<Self, &'static str> {
            Self::inspect_inner(
                binding,
                keys,
                worker_root,
                controller_root,
                custody_root,
                initial_snapshot,
                current_snapshot,
                assignment,
                now,
                Some(handoff),
            )
        }
        #[expect(
            clippy::too_many_arguments,
            reason = "Both typed modes share exact independent cleanup, roots and occupancy checks."
        )]
        pub(in crate::cosp) fn inspect_inner(
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            worker_root: &File,
            controller_root: &File,
            custody_root: &File,
            initial_snapshot: &serde_json::Value,
            current_snapshot: &serde_json::Value,
            assignment: &str,
            now: u64,
            worker_return: Option<&WorkerEpochHandoff>,
        ) -> Result<Self, &'static str> {
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_enter",
                serde_json::json!({"now":now,"worker_epoch":binding.worker_epoch,"controller_epoch":binding.controller_epoch}),
            );
            binding.validate()?;
            let wm = worker_root.metadata().map_err(|_| "evidence_invalid")?;
            let cm = controller_root.metadata().map_err(|_| "evidence_invalid")?;
            qualification::snapshot(
                current_snapshot,
                "w",
                &binding.executable_digest,
                false,
                Some(wm.dev()),
            )?;
            require(
                current_snapshot["identity"] == initial_snapshot["identity"]
                    && current_snapshot["members"] == initial_snapshot["members"],
            )?;
            let status = current_snapshot["status"]
                .as_str()
                .ok_or("evidence_invalid")?;
            for line in ["NoNewPrivs:\t1", "Seccomp:\t2", "CapEff:\t0000000000000000"] {
                require(status.lines().any(|s| s == line))?;
            }
            Self::inspect_witnessed_state(
                binding,
                keys,
                worker_root,
                controller_root,
                custody_root,
                std::path::Path::new("/job/custody"),
                &initial_snapshot["identity"],
                current_snapshot,
                assignment,
                now,
                worker_return,
                (wm, cm),
            )
        }

        // The original protected snapshot verifier is above. The finite
        // loopback fixture also uses this durable-state verifier after its
        // independent PID/limits/quiescence check.
        #[expect(
            clippy::too_many_arguments,
            reason = "These are separate witness inputs."
        )]
        #[cfg(test)]
        pub(super) fn inspect_fixture_witnessed_state(
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            worker_root: &File,
            controller_root: &File,
            custody_root: &File,
            custody_path: &std::path::Path,
            initial_identity: &serde_json::Value,
            process_observation: &serde_json::Value,
            assignment: &str,
            now: u64,
            worker_return: Option<&WorkerEpochHandoff>,
        ) -> Result<Self, &'static str> {
            let wm = worker_root.metadata().map_err(|_| "evidence_invalid")?;
            let cm = controller_root.metadata().map_err(|_| "evidence_invalid")?;
            Self::inspect_witnessed_state(
                binding,
                keys,
                worker_root,
                controller_root,
                custody_root,
                custody_path,
                initial_identity,
                process_observation,
                assignment,
                now,
                worker_return,
                (wm, cm),
            )
        }

        #[expect(
            clippy::too_many_arguments,
            reason = "These are separate witness inputs."
        )]
        fn inspect_witnessed_state(
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            worker_root: &File,
            controller_root: &File,
            custody_root: &File,
            custody_path: &std::path::Path,
            initial_identity: &serde_json::Value,
            process_observation: &serde_json::Value,
            assignment: &str,
            now: u64,
            worker_return: Option<&WorkerEpochHandoff>,
            (wm, cm): (std::fs::Metadata, std::fs::Metadata),
        ) -> Result<Self, &'static str> {
            let c = super::super::la_store::open_pinned_readonly_database(
                controller_root,
                "lane_assignments.sqlite",
            )?;
            let claim = claim_snapshot(&c, assignment).inspect_err(|_| {
                super::recovery_trace("cleanup_claim_snapshot_refused", serde_json::json!({}))
            })?;
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_claim_clock",
                serde_json::json!({"now":now,"requested_at":claim.requested_at,"deadline":claim.cleanup_deadline(binding).ok(),"same_worker":claim.worker==binding.worker,"same_boot":claim.boot==binding.worker_boot,"reconciled":claim.reconciliation.is_some()}),
            );
            // Ordinary cleanup keeps the original exact boot predicate. Only
            // this separately authenticated terminal-return operation can bind
            // an old held claim to a fresh W2; the original session is unchanged.
            let expected_boot = if let Some(h) = worker_return {
                h.verify_history(&keys.custody)?;
                require(
                    h.binding == *binding
                        && h.previous.worker == claim.worker
                        && h.previous.worker_boot == claim.boot
                        && *initial_identity == h.returning.new_identity
                        && claim
                            .reconciliation
                            .as_ref()
                            .is_some_and(|r| r.handoff == h.digest().unwrap_or_default()),
                )?;
                let channel = super::super::la_store::open_pinned_readonly_database(
                    worker_root,
                    "worker-channel.sqlite",
                )?;
                let (_, epochs) = transport_epochs(&channel)?;
                require(epochs.last().ok_or("evidence_invalid")?.digest()? == h.digest()?)?;
                let (req, rep): (Vec<u8>, Vec<u8>) = channel
                    .query_row(
                        "SELECT request,response FROM channel_log WHERE sequence=?1",
                        [(h.worker.body.sequence + 1) as i64],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(|_| "evidence_invalid")?;
                let request: SignedRequest =
                    serde_json::from_slice(&req).map_err(|_| "evidence_invalid")?;
                let signed: SignedResponse =
                    serde_json::from_slice(&rep).map_err(|_| "evidence_invalid")?;
                let WorkerOperation::ReconcileTerminal(c) = &request.request.operation else {
                    return Err("evidence_invalid");
                };
                let WorkerReply::TerminalReconciled(r, m) = &signed.response.reply else {
                    return Err("evidence_invalid");
                };
                r.verify(keys, h, m)?;
                require(
                    request.request.binding == *binding
                        && c.handoff == h.digest()?
                        && c.worker == binding.worker
                        && c.boot == binding.worker_boot
                        && signed.response.binding == *binding
                        && signed.response.sequence == h.worker.body.sequence + 1
                        && signed.response.request_digest
                            == hex::encode(Sha256::digest(
                                serde_json::to_vec(&request.request)
                                    .map_err(|_| "evidence_invalid")?,
                            ))
                        && bool::from(
                            typed_mac(
                                &keys.command,
                                b"diffuser-rpc-request/v1\0",
                                &request.request,
                            )?
                            .ct_eq(&request.mac),
                        )
                        && bool::from(
                            typed_mac(
                                &keys.reply,
                                b"diffuser-rpc-response/v1\0",
                                &signed.response,
                            )?
                            .ct_eq(&signed.mac),
                        ),
                )?;
                &h.previous.worker_boot
            } else {
                &binding.worker_boot
            };
            require(
                claim.worker == binding.worker
                    && claim.boot == *expected_boot
                    && now >= claim.requested_at
                    && claim
                        .reconciliation
                        .as_ref()
                        .is_none_or(|r| now >= r.observed_at)
                    && now < claim.cleanup_deadline(binding)?,
            )?;
            let w = super::super::la_store::open_pinned_readonly_database(
                worker_root,
                "worker.sqlite",
            )?;
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_phase",
                serde_json::json!({"phase":"session_history"}),
            );
            super::super::la_worker::verify_session_history(&w, &keys.reply)?;
            let session: (String, String, u64, u64) = w
                .query_row(
                    "SELECT worker,boot,sequence,fence FROM worker_session_snapshots WHERE assignment=?1 AND sequence=?2",
                    params![claim.assignment,claim.sequence as i64],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get::<_, i64>(2)? as u64,
                            r.get::<_, i64>(3)? as u64,
                        ))
                    },
                )
                .map_err(|_| "evidence_invalid")?;
            require(
                session
                    == (
                        claim.worker.clone(),
                        claim.boot.clone(),
                        claim.sequence,
                        claim.fence,
                    ),
            )?;
            let clean:bool=w.query_row("SELECT EXISTS(SELECT 1 FROM worker_cleanup_receipts c JOIN worker_reservations r ON r.assignment_id=c.assignment AND r.fence=c.fence AND r.closed=1 JOIN worker_close_receipts s ON s.operation=c.operation AND s.sequence=c.sequence WHERE c.assignment=?1 AND c.operation=?2 AND c.fence=?3 AND c.sequence=?4) ",params![assignment,claim.operation,claim.fence as i64,claim.sequence as i64],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_phase",
                serde_json::json!({"phase":"occupancy"}),
            );
            let occupancy =
                super::super::la_worker::verified_execution_occupancy(&w, worker_root, Some(keys))?;
            let clean = clean && occupancy.live_reservations == 0 && occupancy.live_operations == 0;
            require(clean)?;
            // A retained input name, orphan or partial stage refuses cleanup.
            let path = format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(worker_root)
            );
            for entry in std::fs::read_dir(path)
                .map_err(|_| "evidence_invalid")?
                .take(257)
            {
                require(
                    !entry
                        .map_err(|_| "evidence_invalid")?
                        .file_name()
                        .to_string_lossy()
                        .starts_with("input-"),
                )?;
            }
            let artifacts = super::super::la_artifacts::open_artifact(
                controller_root,
                "artifacts",
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
            .map_err(|_| "evidence_invalid")?;
            let mut statement = w
                .prepare("SELECT op,job,state,report FROM operations ORDER BY op")
                .map_err(|_| "evidence_invalid")?;
            let rows = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                })
                .map_err(|_| "evidence_invalid")?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "evidence_invalid")?;
            require(rows.len() <= 32)?;
            for (op, job, state, report) in rows {
                let known:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM la_jobs j JOIN la_job_outbox o ON o.job=j.id JOIN la_assignments a ON a.id=j.assignment_id WHERE j.id=?1 AND o.operation=?2 AND (j.assignment_id=?3 OR (a.state='closed' AND EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts c WHERE c.assignment_id=a.id))) AND j.state IN ('succeeded','cancelled'))",params![job,op,assignment],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
                require(known)?;
                if state == "complete" {
                    let report = report.ok_or("evidence_invalid")?;
                    require(report.len() <= 4096)?;
                    let (output,digest,bytes):(String,String,u64)=c.query_row("SELECT a.id,a.digest,a.byte_count FROM la_jobs j JOIN la_job_results r ON r.job=j.id JOIN la_artifacts a ON a.id=r.output_id AND a.id=j.result_artifact AND a.digest=r.report_digest AND a.job_id=j.id AND a.assignment_id=j.assignment_id AND a.actor=j.actor AND a.project=j.project WHERE j.id=?1 AND a.kind='output' AND a.quarantined=0",[&job],|r|Ok((r.get(0)?,r.get(1)?,r.get::<_,i64>(2)? as u64))).map_err(|_| "evidence_invalid")?;
                    require(
                        bytes == report.len() as u64
                            && digest == hex::encode(Sha256::digest(&report)),
                    )?;
                    let f = super::super::la_artifacts::open_artifact(
                        &artifacts,
                        &output,
                        libc::O_RDONLY,
                    )
                    .map_err(|_| "evidence_invalid")?;
                    let mut content = Vec::new();
                    f.take(4097)
                        .read_to_end(&mut content)
                        .map_err(|_| "evidence_invalid")?;
                    require(content == report)?;
                } else {
                    require(matches!(state.as_str(), "stopped" | "cancelled") && report.is_none())?;
                }
            }
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_phase",
                serde_json::json!({"phase":"worker_state"}),
            );
            let worker_state_digest = state_custody::state_digest(worker_root)?;
            // Compare both roots with P's separately retained high-water. The
            // child database cannot select a regressed checkpoint for itself.
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_phase",
                serde_json::json!({"phase":"worker_anchor"}),
            );
            let worker_anchor = external_anchor(custody_root, "worker-witness-", CHECKPOINT_MAX)?;
            let checkpoint: SignedCheckpoint =
                serde_json::from_slice(&worker_anchor).map_err(|_| "evidence_invalid")?;
            let channel = super::super::la_store::open_pinned_readonly_database(
                worker_root,
                "worker-channel.sqlite",
            )?;
            let (count, high): (i64, i64) = channel
                .query_row(
                    "SELECT COUNT(*),COALESCE(MAX(revision),0) FROM channel_checkpoints",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            require(
                count == checkpoint.body.revision as i64
                    && high == count
                    && checkpoint.body.binding == *binding
                    && checkpoint.body.role == "worker"
                    && checkpoint.body.phase == "complete"
                    && checkpoint.body.owned_state.as_deref() == Some(&worker_state_digest)
                    && transport_state_digest(&channel, binding)? == checkpoint.body.state_digest,
            )?;
            let (saved, ack): (Vec<u8>, Vec<u8>) = channel
                .query_row(
                    "SELECT frame,ack FROM channel_checkpoints WHERE revision=?1",
                    [count],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            require(saved == worker_anchor)?;
            let ack: CheckpointAck =
                serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_phase",
                serde_json::json!({"phase":"worker_ledger"}),
            );
            CustodyLedger::reopen(
                custody_root,
                custody_path,
                &checkpoint,
                &ack,
                keys.reply,
                keys.custody,
            )?;
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_phase",
                serde_json::json!({"phase":"controller_anchor"}),
            );
            let controller_anchor = external_anchor(custody_root, "service-state-", 2048)?;
            let checkpoint: state_custody::Checkpoint =
                serde_json::from_slice(&controller_anchor).map_err(|_| "evidence_invalid")?;
            let checkpoints = super::super::la_store::open_pinned_readonly_database(
                controller_root,
                "service-custody.sqlite",
            )?;
            let (saved, ack): (Vec<u8>, Vec<u8>) = checkpoints
                .query_row(
                    "SELECT frame,ack FROM service_checkpoints ORDER BY revision DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            require(saved == controller_anchor)?;
            let ack: state_custody::Ack =
                serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_inspect_phase",
                serde_json::json!({"phase":"controller_ledger"}),
            );
            state_custody::verified_anchor(controller_root, &checkpoint, &ack, keys)?;
            let expires_at = claim.certificate_expiry(binding, now)?;
            let body = Body {
                version: 1,
                binding: binding.clone(),
                claim,
                controller_root: (cm.dev(), cm.ino()),
                worker_root: (wm.dev(), wm.ino()),
                worker_state_digest,
                occupancy_digest: hash(process_observation)?,
                observed_at: now,
                expires_at,
            };
            let mac = typed_mac(&keys.custody, b"diffuser-cleanup-occupancy/v1\0", &body)?;
            let certificate = Self {
                body,
                mac,
                loss: None,
            };
            certificate.verify(binding, keys, controller_root, now)?;
            Ok(certificate)
        }
        #[expect(
            clippy::too_many_arguments,
            reason = "Protected cleanup certificate binds channel, keys, controller/worker roots, digests, claim, and clock."
        )]
        pub(in crate::cosp) fn issue_protected(
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            controller_root: &File,
            worker_root: (u64, u64),
            worker_state_digest: String,
            occupancy_digest: String,
            claim: Claim,
            now: u64,
        ) -> Result<Self, &'static str> {
            use std::os::unix::fs::MetadataExt;
            binding.validate()?;
            let cm = controller_root.metadata().map_err(|_| "evidence_invalid")?;
            let expires_at = claim.certificate_expiry(binding, now)?;
            let body = Body {
                version: 1,
                binding: binding.clone(),
                claim,
                controller_root: (cm.dev(), cm.ino()),
                worker_root,
                worker_state_digest,
                occupancy_digest,
                observed_at: now,
                expires_at,
            };
            let mac = typed_mac(&keys.custody, b"diffuser-cleanup-occupancy/v1\0", &body)?;
            Ok(Self {
                body,
                mac,
                loss: None,
            })
        }
        pub(in crate::cosp) fn verify(
            &self,
            binding: &ChannelBinding,
            keys: &ChannelKeys,
            root: &File,
            now: u64,
        ) -> Result<&Body, &'static str> {
            #[cfg(test)]
            super::recovery_trace(
                "cleanup_verify_clock",
                serde_json::json!({"now":now,"observed_at":self.body.observed_at,"expires_at":self.body.expires_at,"cleanup_deadline":self.body.claim.cleanup_deadline(binding).ok(),"same_binding":&self.body.binding==binding,"version":self.body.version,"worker_epoch":binding.worker_epoch,"controller_epoch":binding.controller_epoch}),
            );
            binding.validate()?;
            let m = root.metadata().map_err(|_| "evidence_invalid")?;
            require(
                ((self.body.version == 1 && self.loss.is_none())
                    || (self.body.version == 2 && self.loss.is_some()))
                    && predicate("binding", &self.body.binding == binding)
                    && predicate(
                        "controller_root",
                        self.body.controller_root == (m.dev(), m.ino()),
                    )
                    && predicate("not_before", self.body.observed_at <= now)
                    && predicate("certificate_expiry", now < self.body.expires_at)
                    && self
                        .body
                        .expires_at
                        .checked_sub(self.body.observed_at)
                        .is_some_and(|duration| (1..=1500).contains(&duration))
                    && bool::from(
                        typed_mac(
                            &keys.custody,
                            b"diffuser-cleanup-occupancy/v1\0",
                            &self.body,
                        )?
                        .ct_eq(&self.mac),
                    ),
            )?;
            if let Some(cap) = &self.loss {
                cap.verify_history(keys)?;
                require(
                    cap.binding == *binding
                        && cap.digest()? == self.body.occupancy_digest
                        && cap.worker_state == self.body.worker_state_digest
                        && cap.command.assignment == self.body.claim.assignment
                        && cap.command.fence == self.body.claim.fence
                        && cap.binding.worker == self.body.claim.worker
                        && cap.binding.worker_boot == self.body.claim.boot,
                )?;
            }
            require(
                self.body.worker_state_digest.len() == 64
                    && self.body.occupancy_digest.len() == 64
                    && self
                        .body
                        .claim
                        .reconciliation
                        .as_ref()
                        .is_none_or(|r| now >= r.observed_at)
                    && predicate(
                        "original_cleanup_deadline",
                        now < self.body.claim.cleanup_deadline(binding)?,
                    ),
            )?;
            Ok(&self.body)
        }
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn fixture() -> (
        std::path::PathBuf,
        super::super::la_store::ClaimStore,
        ChannelBinding,
        ChannelKeys,
        cleanup::Certificate,
        u64,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let root = std::env::temp_dir().join(format!(
            "la-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = super::super::la_store::ClaimStore::open(&root.join("lane_assignments.sqlite"))
            .unwrap();
        let binding = ChannelBinding {
            worker: "worker_123456789".into(),
            worker_boot: "1".repeat(64),
            controller_boot: "2".repeat(64),
            worker_epoch: 1,
            controller_epoch: 1,
            hardware_generation: 1,
            profile_epoch: 1,
            policy_digest: super::super::la_contract::policy_digest("runtime-short-v1").unwrap(),
            source_digest: "4".repeat(64),
            executable_digest: "5".repeat(64),
        };
        let keys = ChannelKeys {
            command: [1; 32],
            reply: [2; 32],
            authority: [3; 32],
            custody: [4; 32],
        };
        let receipt = CloseReceipt {
            worker: binding.worker.clone(),
            boot: binding.worker_boot.clone(),
            assignment: "assignment_000001".into(),
            fence: 1,
            operation: "release_assignment_000001".into(),
            sequence: 2,
        };
        let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&receipt).unwrap()).into();
        let db = rusqlite::Connection::open(root.join("lane_assignments.sqlite")).unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON; INSERT INTO la_assignments VALUES ('assignment_000001','project_12345678','actor_1234567890','worker_123456789',1,'draining'); INSERT INTO la_reservations VALUES ('cpu-artifact-inspect','assignment_000001'); INSERT INTO la_quota_charges VALUES ('assignment_000001','project_12345678','actor_1234567890'); INSERT INTO la_assignment_grant_charges VALUES ('assignment_000001','grant_root123456'); INSERT INTO la_assignment_revisions VALUES ('assignment_000001',1); INSERT INTO la_outbox VALUES ('assignment_000001','stop');").unwrap();
        db.execute("INSERT INTO la_reservation_authorizations VALUES ('assignment_000001',?1,?2,1,'reserve_operation1')",rusqlite::params![binding.worker,binding.worker_boot]).unwrap();
        db.execute("INSERT INTO la_close_intents VALUES ('assignment_000001','released',?1,'release_assignment_000001')",[now as i64]).unwrap();
        db.execute(
            "INSERT INTO la_assignment_stop_receipts VALUES ('assignment_000001',?1)",
            [digest.as_slice()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO la_worker_receipts VALUES (?1,?2,2,?3)",
            rusqlite::params![binding.worker, binding.worker_boot, digest.as_slice()],
        )
        .unwrap();
        db.execute(
            "INSERT INTO la_worker_cursor VALUES (?1,?2,2)",
            rusqlite::params![binding.worker, binding.worker_boot],
        )
        .unwrap();
        let claim = cleanup::claim_snapshot(&db, "assignment_000001").unwrap();
        let m = std::fs::metadata(&root).unwrap();
        let body = cleanup::Body {
            version: 1,
            binding: binding.clone(),
            claim,
            controller_root: (m.dev(), m.ino()),
            worker_root: (1, 2),
            worker_state_digest: "6".repeat(64),
            occupancy_digest: "7".repeat(64),
            observed_at: now,
            expires_at: now + 1500,
        };
        let mac = typed_mac(&keys.custody, b"diffuser-cleanup-occupancy/v1\0", &body).unwrap();
        let cert = cleanup::Certificate {
            body,
            mac,
            loss: None,
        };
        (root, store, binding, keys, cert, now)
    }
    #[test]
    fn synthetic_cleanup_refuses_bad_stale_foreign_epoch_and_changed_claim_without_freeing() {
        let (root, mut store, binding, keys, cert, now) = fixture();
        assert_eq!(store.counts().unwrap(), (1, 1, 1));
        let mut bad = cert.clone();
        bad.mac[0] ^= 1;
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &bad, now)
            .is_err());
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &cert, now + 1500)
            .is_err());
        let mut epoch = binding.clone();
        epoch.controller_epoch += 1;
        assert!(store
            .release_cleaned_assignment(&epoch, &keys, &cert, now)
            .is_err());
        let other = std::fs::File::open(root.parent().unwrap()).unwrap();
        assert!(cert.verify(&binding, &keys, &other, now).is_err());
        let db = rusqlite::Connection::open(root.join("lane_assignments.sqlite")).unwrap();
        db.execute(
            "UPDATE la_assignments SET state='unknown-cleanup-state'",
            [],
        )
        .unwrap();
        assert_eq!(
            store.release_cleaned_assignment(&binding, &keys, &cert, now),
            Err("state_conflict")
        );
        assert_eq!(store.counts().unwrap(), (1, 1, 1));
        db.execute("UPDATE la_assignments SET state='draining'", [])
            .unwrap();
        db.execute("UPDATE la_worker_cursor SET sequence=3", [])
            .unwrap();
        assert_eq!(
            store.release_cleaned_assignment(&binding, &keys, &cert, now),
            Err("state_conflict")
        );
        assert_eq!(store.counts().unwrap(), (1, 1, 1));
        db.execute("UPDATE la_worker_cursor SET sequence=2", [])
            .unwrap();
        db.execute("UPDATE la_assignment_revisions SET revision=2", [])
            .unwrap();
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &cert, now)
            .is_err());
        assert_eq!(store.counts().unwrap(), (1, 1, 1));
        db.execute("UPDATE la_assignment_revisions SET revision=1", [])
            .unwrap();
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &cert, now)
            .unwrap());
        assert_eq!(store.counts().unwrap(), (0, 0, 0));
        assert!(!store
            .release_cleaned_assignment(&binding, &keys, &cert, now)
            .unwrap());
        let retained: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM la_assignment_grant_charges",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retained, 1);
        drop(db);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn synthetic_lease_hard_and_cleanup_deadlines_close_without_releasing() {
        for hard_first in [false, true] {
            let (root, mut store, binding, _keys, _cert, now) = fixture();
            let db = rusqlite::Connection::open(root.join("lane_assignments.sqlite")).unwrap();
            db.execute_batch(
                "UPDATE la_assignments SET state='assigned'; DELETE FROM la_close_intents;",
            )
            .unwrap();
            db.execute("INSERT INTO la_assignment_terms VALUES ('assignment_000001',1000,16777216,2097152,?1,?2,?3)",rusqlite::params![now as i64,(now+1000) as i64,(now+if hard_first {1000} else {2000}) as i64]).unwrap();
            store.tick_assignment_closures(&binding, now + 999).unwrap();
            assert_eq!(store.state("assignment_000001").unwrap(), "assigned");
            store
                .tick_assignment_closures(&binding, now + 1000)
                .unwrap();
            assert_eq!(store.state("assignment_000001").unwrap(), "draining");
            let reason: String = db
                .query_row("SELECT first_reason FROM la_close_intents", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(
                reason,
                if hard_first {
                    "hard_expired"
                } else {
                    "lease_expired"
                }
            );
            store
                .tick_assignment_closures(&binding, now + 2499)
                .unwrap();
            assert_eq!(store.state("assignment_000001").unwrap(), "draining");
            store
                .tick_assignment_closures(&binding, now + 2500)
                .unwrap();
            assert_eq!(store.state("assignment_000001").unwrap(), "quarantined");
            assert_eq!(store.counts().unwrap(), (1, 1, 1));
            let unchanged: String = db
                .query_row("SELECT first_reason FROM la_close_intents", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(unchanged, reason);
            drop(db);
            drop(store);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn synthetic_revocation_append_atomically_closes_lineage_and_retains_charges() {
        let (root, mut store, binding, keys, _cert, now) = fixture();
        let db = rusqlite::Connection::open(root.join("lane_assignments.sqlite")).unwrap();
        db.execute_batch("UPDATE la_assignments SET state='assigned'; DELETE FROM la_close_intents; INSERT INTO la_jobs VALUES ('job_123456789012','assignment_000001','project_12345678','actor_1234567890','artifact_1234567','running',1,NULL); INSERT INTO la_job_outbox VALUES ('job_123456789012','operation_123456','sent'); INSERT INTO la_mandates VALUES ('job_123456789012','{}','unused'); INSERT INTO la_permits VALUES ('job_123456789012',99999,99999,1,2,100000,0);").unwrap();
        let frame=super::super::la_contract::canonical_json(&serde_json::to_vec(&serde_json::json!({"schema_version":"diffuser-authority-observation/v1","sequence":1,"observed_at":now,"revoked":["grant_root123456"]})).unwrap()).unwrap();
        let mac = sign_authority_observation(&keys.authority, &frame);
        store
            .append_authority_observation(&keys.authority, &frame, &mac)
            .unwrap();
        assert_eq!(store.state("assignment_000001").unwrap(), "draining");
        assert_eq!(store.counts().unwrap(), (1, 1, 1));
        let (reason,job,action,closed,pending):(String,String,String,i64,Option<i64>)=db.query_row("SELECT (SELECT first_reason FROM la_close_intents),(SELECT state FROM la_jobs),(SELECT action FROM la_job_outbox),(SELECT closed FROM la_permits),(SELECT pending_until FROM la_permits)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
        assert_eq!(
            (
                reason.as_str(),
                job.as_str(),
                action.as_str(),
                closed,
                pending
            ),
            ("revoked", "stopping", "stop", 1, None)
        );
        store
            .tick_assignment_closures(&binding, now + 1500)
            .unwrap();
        assert_eq!(store.state("assignment_000001").unwrap(), "quarantined");
        assert_eq!(store.counts().unwrap(), (1, 1, 1));
        drop(db);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn synthetic_recovered_close_window_requires_exact_new_binding_and_preserves_new_claim() {
        let (root, mut store, mut binding, keys, old, now) = fixture();
        let db = rusqlite::Connection::open(root.join("lane_assignments.sqlite")).unwrap();
        let original = now - 2000;
        db.execute(
            "UPDATE la_close_intents SET requested_at=?1",
            [original as i64],
        )
        .unwrap();
        db.execute("UPDATE la_assignments SET state='quarantined'", [])
            .unwrap();
        assert!(
            cleanup::claim_snapshot(&db, "assignment_000001").is_err(),
            "ordinary expired/quarantined cleanup still refuses"
        );
        binding.controller_epoch = 2;
        binding.controller_boot = "f".repeat(64);
        let reconciliation = cleanup::Reconciliation {
            binding: binding.clone(),
            handoff: "a".repeat(64),
            receipt_digest: hex::encode(&old.body.claim.stop_digest),
            observed_at: now,
            expires_at: now + 1500,
        };
        db.execute_batch("CREATE TABLE la_close_reconciliations(assignment_id TEXT PRIMARY KEY,body BLOB NOT NULL)").unwrap();
        db.execute(
            "INSERT INTO la_close_reconciliations VALUES('assignment_000001',?1)",
            [serde_json::to_vec(&reconciliation).unwrap()],
        )
        .unwrap();
        let mut cert = old.clone();
        cert.body.binding = binding.clone();
        cert.body.claim = cleanup::claim_snapshot(&db, "assignment_000001").unwrap();
        let sign = |c: &mut cleanup::Certificate| {
            c.mac = typed_mac(&keys.custody, b"diffuser-cleanup-occupancy/v1\0", &c.body).unwrap();
        };
        sign(&mut cert);
        assert_eq!(
            cert.body.claim.certificate_expiry(&binding, now).unwrap(),
            now + 1500
        );
        assert_eq!(
            cert.body
                .claim
                .certificate_expiry(&binding, now + 1000)
                .unwrap(),
            now + 1500
        );
        assert!(cert
            .body
            .claim
            .certificate_expiry(&binding, now + 1500)
            .is_err());
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &old, now)
            .is_err());
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &cert, now + 1500)
            .is_err());
        let mut changed = serde_json::to_value(&cert).unwrap();
        changed["body"]["claim"]["reconciliation"]["receipt_digest"] = "0".repeat(64).into();
        let mut bad: cleanup::Certificate = serde_json::from_value(changed).unwrap();
        sign(&mut bad);
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &bad, now)
            .is_err());
        let mut changed = serde_json::to_value(&cert).unwrap();
        changed["body"]["claim"]["reconciliation"]["expires_at"] = (now + 1501).into();
        let mut bad: cleanup::Certificate = serde_json::from_value(changed).unwrap();
        sign(&mut bad);
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &bad, now)
            .is_err());
        assert_eq!(store.counts().unwrap().0, 1);
        assert!(store
            .release_cleaned_assignment(&binding, &keys, &cert, now)
            .unwrap());
        let retained: i64 = db
            .query_row("SELECT requested_at FROM la_close_intents", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            retained, original as i64,
            "recovery does not reset original close time"
        );
        let terms = super::super::la_store::AssignmentTerms {
            cpu_millicores: 1000,
            memory_bytes: 16777216,
            storage_bytes: 2097152,
            accepted_at: now,
            lease_until: now + 1000,
            hard_until: now + 4000,
        };
        store
            .reserve_scoped(
                "assignment_000002",
                "project_12345678",
                "actor_1234567890",
                "recovery_key_00002",
                &"1".repeat(64),
                &binding.worker,
                &["grant_1234567890".into()],
                (
                    now + 1000,
                    std::time::Instant::now() + std::time::Duration::from_millis(1000),
                ),
                &terms,
            )
            .unwrap();
        let fence: i64 = db
            .query_row(
                "SELECT fence FROM la_assignments WHERE id='assignment_000002'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(fence > cert.body.claim.fence as i64);
        assert!(!store
            .release_cleaned_assignment(&binding, &keys, &cert, now)
            .unwrap());
        let counts = store.counts().unwrap();
        assert_eq!((counts.0, counts.1), (1, 1));
        drop(db);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_cleanup_race_releases_once_and_old_proof_preserves_new_claim() {
        for epoch in [1, 2] {
            let (root, store, mut binding, keys, mut cert, now) = fixture();
            assert!(store.assignment_close_command("project_12345678","actor_1234567890","assignment_000001").is_err(),"an acknowledged close must not allocate a new transport intent while cleanup is pending");
            if epoch == 2 {
                binding.controller_epoch = 2;
                binding.controller_boot = "f".repeat(64);
                cert.body.binding = binding.clone();
                cert.mac = typed_mac(
                    &keys.custody,
                    b"diffuser-cleanup-occupancy/v1\0",
                    &cert.body,
                )
                .unwrap();
            }
            drop(store);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let stores: Vec<_> = (0..2)
                .map(|_| {
                    super::super::la_store::ClaimStore::open(&root.join("lane_assignments.sqlite"))
                        .unwrap()
                })
                .collect();
            let handles: Vec<_> = stores
                .into_iter()
                .map(|mut store| {
                    let binding = binding.clone();
                    let keys = keys.clone();
                    let cert = cert.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        store.release_cleaned_assignment(&binding, &keys, &cert, now)
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            // ClaimStore uses a nonblocking process lock. A contending caller may
            // retry the identical certificate; it must never release twice.
            assert_eq!(results.iter().filter(|r| matches!(r, Ok(true))).count(), 1);
            let mut store =
                super::super::la_store::ClaimStore::open(&root.join("lane_assignments.sqlite"))
                    .unwrap();
            assert!(!store
                .release_cleaned_assignment(&binding, &keys, &cert, now)
                .unwrap());
            let db = rusqlite::Connection::open(root.join("lane_assignments.sqlite")).unwrap();
            db.execute_batch("INSERT INTO la_assignments VALUES ('assignment_000002','project_12345678','actor_1234567890','worker_123456789',2,'assigned'); INSERT INTO la_reservations VALUES ('cpu-artifact-inspect','assignment_000002'); INSERT INTO la_quota_charges VALUES ('assignment_000002','project_12345678','actor_1234567890');").unwrap();
            assert!(!store
                .release_cleaned_assignment(&binding, &keys, &cert, now)
                .unwrap());
            assert!(
                !store
                    .release_cleaned_assignment(&binding, &keys, &cert, now + 1500)
                    .unwrap(),
                "an expired exact committed receipt is a no-op read, not a late consumption"
            );
            let mut forged = cert.clone();
            forged.mac[0] ^= 1;
            assert!(store
                .release_cleaned_assignment(&binding, &keys, &forged, now + 1500)
                .is_err());
            assert_eq!(store.counts().unwrap(), (1, 1, 0));
            drop(db);
            drop(store);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

/// This capability admits a qualified returned worker after terminal cleanup.
/// It is distinct from genesis activation and from either epoch reconciliation.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerSuccessorAdmission {
    body: ActivationBody,
    handoff: String,
    cleanup: String,
    cleanup_ack: String,
    cleanup_consumed_at: u64,
    terminal: String,
    worker_anchor: SignedCheckpoint,
    worker_history: String,
    controller_anchor: SignedCheckpoint,
    controller_history: String,
    service_revision: u64,
    service_history: String,
    generation: u64,
    previous_boot: String,
    sequence: u64,
    fence: u64,
    occupancy: String,
    authority_history: String,
    process: serde_json::Value,
    mac: [u8; 32],
}
impl WorkerSuccessorAdmission {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut value = self.clone();
        value.mac = [0; 32];
        typed_mac(
            &keys.custody,
            b"diffuser-worker-successor-admission/v1\0",
            &value,
        )
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    pub(super) fn binding(&self) -> &ChannelBinding {
        &self.body.binding
    }
    pub(super) fn cursor(&self) -> (&str, u64, u64, u64) {
        (
            &self.previous_boot,
            self.generation,
            self.sequence,
            self.fence,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds independent cleanup, both retained role histories, fresh resource and process evidence."
    )]
    pub(super) fn issue(
        resource: qualification::Certificate,
        h: &WorkerEpochHandoff,
        certificate: &cleanup::Certificate,
        cleanup_ack: &serde_json::Value,
        worker: &std::fs::File,
        controller: &std::fs::File,
        worker_ledger: &CustodyLedger,
        controller_ledger: &CustodyLedger,
        service: &state_custody::Ledger,
        ready: &serde_json::Value,
        occupancy: &serde_json::Value,
        keys: &ChannelKeys,
        now: u64,
        expires: u64,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        let binding = h.binding();
        h.verify_history(&keys.custody)?;
        resource.verify(binding, keys, now)?;
        // A consumed cleanup is historical evidence, not a fresh certificate
        // to consume again. Authenticate its exact durable bytes and the time
        // it was used within the ORIGINAL certificate window. Fresh successor
        // qualification/source/occupancy and this capability have their own
        // ordinary expiry; no old window, lease or permit is extended.
        let claims =
            super::la_store::open_pinned_readonly_database(controller, "lane_assignments.sqlite")?;
        let certificate_bytes = serde_json::to_vec(certificate).map_err(|_| "evidence_invalid")?;
        let cert_digest = hex::encode(Sha256::digest(&certificate_bytes));
        let (saved,consumed_at):(Vec<u8>,i64)=claims.query_row("SELECT certificate,released_at FROM la_assignment_cleanup_receipts WHERE assignment_id=?1 AND digest=?2",rusqlite::params![certificate.body.claim.assignment,cert_digest],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_| "evidence_invalid")?;
        let cleanup_consumed_at = u64::try_from(consumed_at).map_err(|_| "evidence_invalid")?;
        if saved != certificate_bytes || cleanup_consumed_at > now {
            return Err("evidence_invalid");
        }
        let cert = certificate.verify(binding, keys, controller, cleanup_consumed_at)?;
        if cert
            .claim
            .reconciliation
            .as_ref()
            .is_none_or(|r| r.handoff != h.digest().unwrap_or_default())
            || cert.claim.boot != h.previous.worker_boot
            || cleanup_ack["released_now"] != true
            || cleanup_ack["certificate_digest"] != cert_digest
            || expires <= now
            || expires - now > 12000
            || expires > resource.expires_at()
            || worker_ledger.binding != *binding
            || controller_ledger.binding != *binding
            || worker_ledger.role != "worker"
            || controller_ledger.role != "controller"
            || worker_ledger.request_key != keys.reply
            || controller_ledger.request_key != keys.reply
            || worker_ledger.ack_key != keys.custody
            || controller_ledger.ack_key != keys.custody
        {
            return Err("evidence_invalid");
        }
        let wm = worker.metadata().map_err(|_| "evidence_invalid")?;
        let cm = controller.metadata().map_err(|_| "evidence_invalid")?;
        qualification::snapshot(
            occupancy,
            "w",
            &binding.executable_digest,
            false,
            Some(wm.dev()),
        )?;
        if occupancy["identity"] != h.returning.new_identity
            || occupancy["identity"]["starttime"].as_str().is_none()
            || ready["kind"] != "READY"
            || ready["role"] != "worker"
            || ready["boot_id"] != binding.worker_boot
            || ready["pid"] != h.returning.namespace_pid
            || ready["root_dev"] != wm.dev()
            || ready["root_inode"] != wm.ino()
            || ready["executable_sha256"] != binding.executable_digest
            || ready["policy_digest"] != binding.policy_digest
            || ready["process_seal"]["fork_errno"] != libc::EPERM
            || ready["process_seal"]["exec_errno"] != libc::EPERM
            || ready["process_seal"]["unshare_errno"] != libc::EPERM
            || ready["process_seal"]["no_new_privs"] != 1
            || ready["process_seal"]["mechanism"] != "seccomp-thread-only-tsync-v1"
            || ready["process_seal"]["architecture"] != "x86_64"
            || ready["process_seal"]["filter_sha256"]
                != "d08dcce79447d75446943abae0ad012a8fc3fa4dab11a06eb3593c7230d0c02c"
            || !occupancy["status"].as_str().is_some_and(|s| {
                ["NoNewPrivs:\t1", "Seccomp:\t2", "CapEff:\t0000000000000000"]
                    .iter()
                    .all(|line| s.lines().any(|v| v == *line))
            })
        {
            return Err("evidence_invalid");
        }
        let (wa, _, wh) = worker_ledger.completed_anchor(worker)?;
        let (ca, _, ch) = controller_ledger.completed_anchor(controller)?;
        if wa.body.sequence != h.high_water() + 1
            || ca.body.sequence != wa.body.sequence
            || wa.body.sequence >= RPC_HISTORY_MAX
            || wa
                .body
                .revision
                .checked_add(2)
                .is_none_or(|r| r > CHECKPOINT_MAX)
            || ca
                .body
                .revision
                .checked_add(2)
                .is_none_or(|r| r > CHECKPOINT_MAX)
        {
            return Err("evidence_invalid");
        }
        let wd = super::la_store::open_pinned_readonly_database(worker, "worker-channel.sqlite")?;
        let cd = super::la_store::open_pinned_readonly_database(
            controller,
            "controller-channel.sqlite",
        )?;
        let claims =
            super::la_store::open_pinned_readonly_database(controller, "lane_assignments.sqlite")?;
        let state = super::la_store::open_pinned_readonly_database(worker, "worker.sqlite")?;
        super::la_worker::verify_session_history(&state, &keys.reply)?;
        verify_completed_worker_reconciliation(&claims, worker, binding, keys)?;
        let released:bool=claims.query_row("SELECT EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts WHERE assignment_id=?1 AND digest=?2) AND NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges) AND NOT EXISTS(SELECT 1 FROM la_assignments WHERE state!='closed')",rusqlite::params![cert.claim.assignment,cert_digest],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        let (old_boot,sequence,fence):(String,u64,u64)=claims.query_row("SELECT boot,sequence,(SELECT MAX(fence) FROM la_assignments WHERE worker=?1) FROM la_worker_cursor WHERE worker=?1",[&binding.worker],|r|Ok((r.get(0)?,u64::try_from(r.get::<_,i64>(1)?).map_err(|_|rusqlite::Error::InvalidQuery)?,u64::try_from(r.get::<_,i64>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?))).map_err(|_| "evidence_invalid")?;
        let generation: i64 = state
            .query_row(
                "SELECT MAX(generation)+1 FROM worker_session_generations",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let cursor: (String, String, u64, u64) = state
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        u64::try_from(r.get::<_, i64>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        u64::try_from(r.get::<_, i64>(3)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .map_err(|_| "evidence_invalid")?;
        if !released
            || cursor != (binding.worker.clone(), old_boot.clone(), sequence, fence)
            || old_boot != h.previous.worker_boot
            || sequence != cert.claim.sequence
            || fence != cert.claim.fence
            || u64::try_from(generation).ok() != Some(binding.worker_epoch)
        {
            return Err("evidence_invalid");
        }
        let mut terminal = String::new();
        for seq in 1..=wa.body.sequence {
            let read = |db: &rusqlite::Connection| -> Result<(Vec<u8>, Vec<u8>), &'static str> {
                db.query_row(
                    "SELECT request,response FROM channel_log WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")
            };
            let (request, response) = read(&wd)?;
            if read(&cd)? != (request.clone(), response.clone()) {
                return Err("evidence_invalid");
            }
            let req: SignedRequest =
                serde_json::from_slice(&request).map_err(|_| "evidence_invalid")?;
            let rep: SignedResponse =
                serde_json::from_slice(&response).map_err(|_| "evidence_invalid")?;
            if !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &req.request)?
                    .ct_eq(&req.mac),
            ) || !bool::from(
                typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &rep.response)?
                    .ct_eq(&rep.mac),
            ) || rep.response.sequence != seq
                || rep.response.binding != req.request.binding
                || rep.response.request_digest
                    != hex::encode(Sha256::digest(
                        serde_json::to_vec(&req.request).map_err(|_| "evidence_invalid")?,
                    ))
            {
                return Err("evidence_invalid");
            }
            if seq == wa.body.sequence {
                let WorkerReply::TerminalReconciled(r, m) = &rep.response.reply else {
                    return Err("evidence_invalid");
                };
                r.verify(keys, h, m)?;
                terminal = hex::encode(Sha256::digest(response));
            }
        }
        let (head, controller_state, service_history, revision, authority_sequence) =
            service.successor_anchor(controller, keys)?;
        let (count, high): (u64, u64) = wd
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM channel_authority",
                [],
                |r| {
                    Ok((
                        u64::try_from(r.get::<_, i64>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        u64::try_from(r.get::<_, i64>(1)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .map_err(|_| "evidence_invalid")?;
        if count != authority_sequence
            || high != count
            || authority_sequence <= h.authority_sequence
            || revision.checked_add(2).is_none_or(|r| r > 1025)
        {
            return Err("evidence_invalid");
        }
        let (ccount, chigh): (i64, i64) = claims
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM la_authority_observations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if ccount != authority_sequence as i64 || chigh != ccount {
            return Err("evidence_invalid");
        }
        for seq in 1..=authority_sequence {
            let (body, frame): (Vec<u8>, Vec<u8>) = wd
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let (cbody, cmac): (Vec<u8>, Vec<u8>) = claims
                .query_row(
                    "SELECT body,mac FROM la_authority_observations WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let cmac: [u8; 32] = cmac.try_into().map_err(|_| "evidence_invalid")?;
            verify_authority_observation(&keys.authority, &cbody, &cmac)?;
            if body != cbody
                || verify_source_observation(
                    &keys.authority,
                    &transport_authority_binding(&wd, seq)?,
                    &frame,
                )? != body
            {
                return Err("evidence_invalid");
            }
            if seq == count {
                let v: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
                let observed = v["observed_at"].as_u64().ok_or("evidence_invalid")?;
                if v["sequence"] != count
                    || observed > now
                    || now - observed >= 1500
                    || verify_source_observation(&keys.authority, binding, &frame)? != body
                {
                    return Err("evidence_stale");
                }
            }
        }
        let body = ActivationBody {
            binding: binding.clone(),
            resource,
            worker_dev: wm.dev(),
            worker_inode: wm.ino(),
            worker_state: state_custody::state_digest(worker)?,
            controller_dev: cm.dev(),
            controller_inode: cm.ino(),
            controller_state,
            controller_head: head,
            authority_sequence,
            issued_at: now,
            expires_at: expires,
        };
        let mut value = Self {
            body,
            handoff: h.digest()?,
            cleanup: cert_digest,
            cleanup_consumed_at,
            cleanup_ack: hex::encode(Sha256::digest(
                serde_json::to_vec(cleanup_ack).map_err(|_| "evidence_invalid")?,
            )),
            terminal,
            worker_anchor: wa,
            worker_history: wh,
            controller_anchor: ca,
            controller_history: ch,
            service_revision: revision,
            service_history,
            generation: generation as u64,
            previous_boot: old_boot,
            sequence,
            fence,
            occupancy: hex::encode(Sha256::digest(
                serde_json::to_vec(occupancy).map_err(|_| "evidence_invalid")?,
            )),
            authority_history: transport_authority_digest(&wd, authority_sequence)?,
            process: occupancy["identity"].clone(),
            mac: [0; 32],
        };
        value.mac = value.signature(keys)?;
        if serde_json::to_vec(&value)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 12288
        {
            return Err("evidence_invalid");
        }
        Ok(value)
    }
    fn verify_role(
        &self,
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        root: &std::fs::File,
        role: &str,
        domain: Option<&state_custody::Session>,
        now: u64,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        self.body.resource.verify(binding, keys, now)?;
        if self.body.binding != *binding
            || self.body.issued_at > now
            || now >= self.body.expires_at
            || self.body.expires_at <= self.body.issued_at
            || self.body.expires_at - self.body.issued_at > 12000
            || self.body.expires_at > self.body.resource.expires_at()
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        let (dev, ino, state, anchor, history) = match role {
            "worker" => (
                self.body.worker_dev,
                self.body.worker_inode,
                &self.body.worker_state,
                &self.worker_anchor,
                &self.worker_history,
            ),
            "controller" => (
                self.body.controller_dev,
                self.body.controller_inode,
                &self.body.controller_state,
                &self.controller_anchor,
                &self.controller_history,
            ),
            _ => return Err("evidence_invalid"),
        };
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        if (m.dev(), m.ino()) != (dev, ino) || state_custody::state_digest(root)? != *state {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        verify_transport_chain(&db, anchor, &keys.reply, &keys.custody)?;
        if transport_state_digest(&db, binding)? != anchor.body.state_digest
            || checkpoint_bytes_digest(&db, anchor.body.revision, anchor.body.revision)? != *history
        {
            return Err("evidence_invalid");
        }
        let (_, epochs) = transport_epochs(&db)?;
        let Some(TransportTransition::Worker(h)) = epochs.last() else {
            return Err("evidence_invalid");
        };
        if h.digest()? != self.handoff
            || h.binding != *binding
            || h.returning.new_identity != self.process
        {
            return Err("evidence_invalid");
        }
        if role == "worker" {
            let proc =
                std::fs::read_to_string("/proc/self/stat").map_err(|_| "evidence_invalid")?;
            let start = proc
                .rsplit_once(") ")
                .and_then(|(_, s)| s.split_whitespace().nth(19))
                .ok_or("evidence_invalid")?;
            if std::process::id() != h.returning.namespace_pid || self.process["starttime"] != start
            {
                return Err("evidence_invalid");
            }
            let state = super::la_store::open_pinned_readonly_database(root, "worker.sqlite")?;
            super::la_worker::verify_session_history(&state, &keys.reply)?;
            if transport_authority_digest(&db, self.body.authority_sequence)?
                != self.authority_history
            {
                return Err("evidence_invalid");
            }
            let (body, frame): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [self.body.authority_sequence as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if verify_source_observation(&keys.authority, binding, &frame)? != body {
                return Err("evidence_invalid");
            }
            let source: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
            let observed = source["observed_at"].as_u64().ok_or("evidence_invalid")?;
            if observed > now || now - observed >= 1500 {
                return Err("evidence_stale");
            }
        } else {
            let (head, state) = domain.ok_or("evidence_invalid")?.activation_anchor()?;
            let service =
                super::la_store::open_pinned_readonly_database(root, "service-custody.sqlite")?;
            if head != self.body.controller_head
                || state != self.body.controller_state
                || state_custody::successor_history(&service, self.service_revision)?
                    != self.service_history
            {
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
    fn acknowledgment(
        &self,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<ActivationAck, &'static str> {
        let activation_digest = self.digest()?;
        let mac = typed_mac(
            &keys.reply,
            b"diffuser-worker-successor-ack/v1\0",
            &(self.binding(), role, &activation_digest),
        )?;
        Ok(ActivationAck {
            binding: self.binding().clone(),
            role: role.into(),
            activation_digest,
            mac,
        })
    }
    pub(super) fn verify_ack(
        &self,
        role: &str,
        keys: &ChannelKeys,
        ack: &ActivationAck,
    ) -> Result<(), &'static str> {
        let expected = self.acknowledgment(role, keys)?;
        if ack.binding != expected.binding
            || ack.role != expected.role
            || ack.activation_digest != expected.activation_digest
            || !bool::from(expected.mac.ct_eq(&ack.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

// Bounded, non-secret process diagnostics. These traces carry clocks, finite
// counters and digests only; they are not authority or consumption evidence.
pub(super) fn recovery_trace(stage: &str, details: serde_json::Value) {
    #[cfg(test)]
    eprintln!(
        "RECOVERY_TRACE {}",
        serde_json::json!({"stage":stage,"wall_ms":wall_now().ok(),"details":details})
    );
    #[cfg(not(test))]
    let _ = (stage, details);
}

fn wall_now() -> Result<u64, &'static str> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis(),
    )
    .map_err(|_| "clock_untrusted")
}
impl WorkerAdmission {
    fn set_successor(&self, cap: &WorkerSuccessorAdmission) -> Result<(), &'static str> {
        let mut current = self.0.lock().map_err(|_| "storage_unavailable")?;
        if current.is_some() || wall_now()? >= cap.body.expires_at {
            return Err("evidence_invalid");
        }
        *current = Some(AdmissionLease {
            issued_at: cap.body.issued_at,
            expires_at: cap.body.expires_at,
            job_scope: None,
        });
        Ok(())
    }
}
impl WorkerClient {
    pub(super) fn validate_successor(
        &self,
        cap: &WorkerSuccessorAdmission,
        root: &std::fs::File,
        domain: &state_custody::Session,
    ) -> Result<(), &'static str> {
        self.channel.check()?;
        if self
            .admission
            .0
            .lock()
            .map_err(|_| "storage_unavailable")?
            .is_some()
        {
            return Err("evidence_invalid");
        }
        cap.verify_role(
            &self.channel.binding,
            &self.keys,
            root,
            "controller",
            Some(domain),
            wall_now()?,
        )
    }
    pub(super) fn admit_successor(
        &mut self,
        cap: &WorkerSuccessorAdmission,
    ) -> Result<ActivationAck, &'static str> {
        match self.call(WorkerOperation::AdmitSuccessor(Box::new(cap.clone())), &[])? {
            WorkerReply::SuccessorAdmitted(ack) => {
                cap.verify_ack("worker", &self.keys, &ack)?;
                Ok(ack)
            }
            _ => Err("evidence_invalid"),
        }
    }
    pub(super) fn finish_successor(
        &self,
        cap: &WorkerSuccessorAdmission,
    ) -> Result<ActivationAck, &'static str> {
        self.admission.set_successor(cap)?;
        cap.acknowledgment("controller", &self.keys)
    }
}

// Never-started recovery is a separate, single-job capability. Original rows
// remain immutable; a fresh short permit is appended under current authority
// and the original job, mandate and lease deadlines.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NeverStartedPermit {
    body: ActivationBody,
    pub(super) original: InspectCommand,
    pub(super) rebound: InspectCommand,
    handoff: String,
    authority_history: String,
    worker_history: String,
    controller_history: String,
    service_history: String,
    sequence: u64,
    mac: [u8; 32],
}
fn command_digest(c: &InspectCommand) -> Result<String, &'static str> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(c).map_err(|_| "evidence_invalid")?,
    )))
}
fn verify_never_started(
    claims: &rusqlite::Connection,
    root: &std::fs::File,
    binding: &ChannelBinding,
    keys: &ChannelKeys,
    c: &InspectCommand,
) -> Result<(), &'static str> {
    let worker = super::la_store::open_pinned_readonly_database(root, "worker.sqlite")?;
    super::la_worker::verify_session_history(&worker, &keys.reply)?;
    let digest = command_digest(c)?;
    // This first bounded mode supports one original job. Other retained jobs
    // require an explicit extension, never an inferred absence shortcut.
    let exact: bool = claims.query_row("SELECT (SELECT COUNT(*) FROM la_jobs)=1 AND EXISTS(SELECT 1 FROM la_jobs j JOIN la_assignments a ON a.id=j.assignment_id JOIN la_reservation_authorizations r ON r.assignment_id=a.id JOIN la_job_permit_intents p ON p.job=j.id JOIN la_job_outbox o ON o.job=j.id JOIN la_quota_charges q ON q.assignment_id=a.id JOIN la_reservations h ON h.assignment_id=a.id WHERE j.id=?1 AND j.assignment_id=?2 AND a.worker=?3 AND r.worker=a.worker AND r.boot=?4 AND r.fence=a.fence AND a.fence=?5 AND a.state='assigned' AND j.state IN ('pending','running') AND j.result_artifact IS NULL AND o.operation=?6 AND ((j.state='pending' AND o.action='start') OR (j.state='running' AND o.action='sent')) AND p.digest=?7 AND p.command=?8 AND p.acknowledged=1 AND p.permit_until=?9) AND NOT EXISTS(SELECT 1 FROM la_close_intents) AND NOT EXISTS(SELECT 1 FROM la_job_results)",rusqlite::params![c.job,c.assignment,c.worker,c.boot,c.fence as i64,c.operation,digest,serde_json::to_string(c).map_err(|_| "evidence_invalid")?,c.permit_until as i64],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
    let absent: bool = worker.query_row("SELECT NOT EXISTS(SELECT 1 FROM operations) AND NOT EXISTS(SELECT 1 FROM worker_stop_receipts) AND NOT EXISTS(SELECT 1 FROM worker_result_receipts) AND NOT EXISTS(SELECT 1 FROM worker_cleanup_receipts) AND EXISTS(SELECT 1 FROM worker_inspect_commands i JOIN worker_reservations r ON r.assignment_id=?2 JOIN reservation_session s ON s.fence=r.fence WHERE i.operation=?1 AND hex(i.command_digest)=upper(?3) AND r.fence=?4 AND s.worker=?5 AND s.boot=?6 AND r.closed=0)",rusqlite::params![c.operation,c.assignment,digest,c.fence as i64,c.worker,c.boot],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
    let (mandate, hash): (String, String) = claims
        .query_row(
            "SELECT body,digest FROM la_mandates WHERE job=?1",
            [&c.job],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| "evidence_invalid")?;
    let m: super::la_auth::StoredMandate =
        serde_json::from_str(&mandate).map_err(|_| "evidence_invalid")?;
    let saved: Vec<u8> = worker
        .query_row(
            "SELECT body FROM worker_mandates WHERE job=?1",
            [&c.job],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    if !exact
        || !absent
        || c.worker != binding.worker
        || c.boot != binding.worker_boot
        || c.accepted_at != m.draft.accepted_at
        || c.mandate_until != m.max_until
        || m.draft.job != c.job
        || m.draft.operation != c.operation
        || m.draft.assignment != c.assignment
        || m.draft.worker != c.worker
        || m.draft.input_digest != c.input_digest
        || super::la_store::checked_mandate(&m.draft)? != m
        || hex::encode(Sha256::digest(mandate.as_bytes())) != hash
        || saved != mandate.as_bytes()
    {
        return Err("transport_uncertain");
    }
    Ok(())
}
fn verify_matching_recovery_histories(
    cd: &rusqlite::Connection,
    wd: &rusqlite::Connection,
    keys: &ChannelKeys,
    original: &InspectCommand,
) -> Result<(), &'static str> {
    let count: i64 = cd
        .query_row("SELECT COUNT(*) FROM channel_log", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    let other: i64 = wd
        .query_row("SELECT COUNT(*) FROM channel_log", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    if count != other || !(1..=512).contains(&count) {
        return Err("transport_uncertain");
    }
    for seq in 1..=count {
        let read = |db: &rusqlite::Connection| -> Result<(Vec<u8>, Vec<u8>, String), &'static str> {
            db.query_row(
                "SELECT request,response,digest FROM channel_log WHERE sequence=?1",
                [seq],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| "transport_uncertain")
        };
        let c = read(cd)?;
        let w = read(wd)?;
        if c.0 != w.0 || c.1 != w.1 {
            return Err("transport_uncertain");
        }
        let req: SignedRequest = serde_json::from_slice(&w.0).map_err(|_| "evidence_invalid")?;
        let rep: SignedResponse = serde_json::from_slice(&w.1).map_err(|_| "evidence_invalid")?;
        validate_rpc_envelope(
            &c.0,
            "controller-channel.sqlite",
            &transport_binding_at(cd, "controller", seq as u64, false)?,
            seq as u64,
            &c.2,
        )?;
        validate_rpc_envelope(
            &w.0,
            "worker-channel.sqlite",
            &transport_binding_at(wd, "worker", seq as u64, false)?,
            seq as u64,
            &w.2,
        )?;
        if !bool::from(
            typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &req.request)?.ct_eq(&req.mac),
        ) || !bool::from(
            typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &rep.response)?.ct_eq(&rep.mac),
        ) || rep.response.binding != req.request.binding
            || rep.response.sequence != seq as u64
            || rep.response.request_digest != w.2
        {
            return Err("evidence_invalid");
        }
        if let WorkerOperation::Start(c) = &req.request.operation {
            if c.operation == original.operation
                && !matches!(rep.response.reply,WorkerReply::Refused{ref code} if code=="evidence_invalid")
            {
                return Err("transport_uncertain");
            }
        }
    }
    Ok(())
}
impl NeverStartedPermit {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut unsigned = self.clone();
        unsigned.mac = [0; 32];
        typed_mac(
            &keys.custody,
            b"diffuser-never-started-rebound-permit/v1\0",
            &unsigned,
        )
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds current independent role histories, resource family, service and source."
    )]
    pub(super) fn issue(
        resource: qualification::Certificate,
        handoff: &TransportEpochHandoff,
        controller: &CustodyLedger,
        worker: &CustodyLedger,
        service: &state_custody::Ledger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        let c = handoff.never_started.as_ref().ok_or("evidence_invalid")?;
        let binding = &handoff.binding;
        recovery_trace(
            "never_started_issue",
            serde_json::json!({"now":now,"handoff_issued":handoff.issued_at,"handoff_expires":handoff.expires_at,"original_permit":c.permit_until,"mandate_until":c.mandate_until,"controller_revision":controller.revision,"worker_revision":worker.revision}),
        );
        handoff
            .verify_consumed(croot, keys, now)
            .inspect_err(|code| {
                recovery_trace(
                    "never_started_handoff_refused",
                    serde_json::json!({"code":code}),
                )
            })?;
        recovery_trace("never_started_handoff_verified", serde_json::json!({}));
        resource.verify(binding, keys, now)?;
        if controller.binding != *binding
            || worker.binding != *binding
            || controller.request_key != keys.reply
            || worker.request_key != keys.reply
            || controller.ack_key != keys.custody
            || worker.ack_key != keys.custody
            || c.permit_until > c.mandate_until
        {
            return Err("deadline_elapsed");
        }
        let (cf, _, ch) = controller.completed_anchor(croot)?;
        let (wf, _, wh) = worker.completed_anchor(wroot)?;
        recovery_trace(
            "never_started_transport_verified",
            serde_json::json!({"sequence":cf.body.sequence}),
        );
        let (head, state, sh, _, authority) = service.successor_anchor(croot, keys)?;
        recovery_trace(
            "never_started_service_verified",
            serde_json::json!({"authority":authority}),
        );
        let cd =
            super::la_store::open_pinned_readonly_database(croot, "controller-channel.sqlite")?;
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        verify_matching_recovery_histories(&cd, &wd, keys, c)?;
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        verify_never_started(&claims, wroot, binding, keys, c)?;
        let worker_state = state_custody::state_digest(wroot)?;
        if cf.body.sequence != wf.body.sequence
            || wf.body.owned_state.as_ref() != Some(&worker_state)
            || authority <= handoff.authority_sequence
        {
            return Err("evidence_invalid");
        }
        let (count, high): (i64, i64) = wd
            .query_row(
                "SELECT COUNT(*),MAX(sequence) FROM channel_authority",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if count != authority as i64 || count != high {
            return Err("evidence_invalid");
        }
        let observed: i64 = wd
            .query_row(
                "SELECT observed_at FROM channel_authority WHERE sequence=?1",
                [authority as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let lease: i64 = claims
            .query_row(
                "SELECT lease_until FROM la_assignment_terms WHERE assignment_id=?1",
                [&c.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let mut rebound = c.clone();
        rebound.permit_until = now
            .checked_add(1500)
            .ok_or("evidence_invalid")?
            .min(c.mandate_until)
            .min(lease.try_into().map_err(|_| "evidence_invalid")?)
            .min(
                u64::try_from(observed)
                    .map_err(|_| "evidence_invalid")?
                    .checked_add(1500)
                    .ok_or("evidence_invalid")?,
            )
            .min(resource.expires_at());
        if rebound.permit_until <= now {
            return Err("deadline_elapsed");
        }
        let wm = wroot.metadata().map_err(|_| "evidence_invalid")?;
        let cm = croot.metadata().map_err(|_| "evidence_invalid")?;
        let sequence: i64 = claims
            .query_row(
                "SELECT sequence FROM la_worker_cursor WHERE worker=?1 AND boot=?2",
                rusqlite::params![c.worker, c.boot],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let mut value = Self {
            body: ActivationBody {
                binding: binding.clone(),
                resource: resource.clone(),
                worker_dev: wm.dev(),
                worker_inode: wm.ino(),
                worker_state,
                controller_dev: cm.dev(),
                controller_inode: cm.ino(),
                controller_state: state,
                controller_head: head,
                authority_sequence: authority,
                issued_at: now,
                expires_at: rebound.permit_until,
            },
            original: c.clone(),
            rebound,
            handoff: handoff.digest()?,
            authority_history: transport_authority_digest(&wd, authority)?,
            worker_history: wh,
            controller_history: ch,
            service_history: sh,
            sequence: sequence.try_into().map_err(|_| "evidence_invalid")?,
            mac: [0; 32],
        };
        value.mac = value.signature(keys)?;
        Ok(value)
    }
    pub(super) fn verify_commands(&self) -> Result<(), &'static str> {
        let mut same = self.rebound.clone();
        same.permit_until = self.original.permit_until;
        if serde_json::to_vec(&same).map_err(|_| "evidence_invalid")?
            != serde_json::to_vec(&self.original).map_err(|_| "evidence_invalid")?
            || self.rebound.permit_until > self.original.mandate_until
            || self.rebound.permit_until
                > self
                    .body
                    .issued_at
                    .checked_add(1500)
                    .ok_or("evidence_invalid")?
            || self.rebound.permit_until != self.body.expires_at
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn verify_role(
        &self,
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        root: &std::fs::File,
        role: &str,
        domain: Option<&state_custody::Session>,
        now: u64,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        self.body.resource.verify(binding, keys, now)?;
        if self.body.binding != *binding
            || self.original.worker != binding.worker
            || self.original.boot != binding.worker_boot
            || self.body.issued_at > now
            || now >= self.body.expires_at
            || self.body.expires_at > self.rebound.permit_until
            || self.original.permit_until > self.original.mandate_until
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        self.verify_commands()?;
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        let (dev, ino, state) = match role {
            "worker" => (
                self.body.worker_dev,
                self.body.worker_inode,
                &self.body.worker_state,
            ),
            "controller" => (
                self.body.controller_dev,
                self.body.controller_inode,
                &self.body.controller_state,
            ),
            _ => return Err("evidence_invalid"),
        };
        if (m.dev(), m.ino()) != (dev, ino) || state_custody::state_digest(root)? != *state {
            return Err("evidence_invalid");
        }
        let name = if role == "worker" {
            "worker-channel.sqlite"
        } else {
            "controller-channel.sqlite"
        };
        let channel = super::la_store::open_pinned_readonly_database(root, name)?;
        let revision: i64 = channel
            .query_row("SELECT MAX(revision) FROM channel_checkpoints", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        let expected = if role == "worker" {
            &self.worker_history
        } else {
            &self.controller_history
        };
        if revision <= 0
            || checkpoint_bytes_digest(&channel, revision as u64, revision as u64)? != *expected
        {
            return Err("evidence_invalid");
        }
        if role == "worker"
            && transport_authority_digest(&channel, self.body.authority_sequence)?
                != self.authority_history
        {
            return Err("evidence_invalid");
        }
        if role == "controller" {
            if domain.ok_or("evidence_invalid")?.activation_anchor()?
                != (
                    self.body.controller_head.clone(),
                    self.body.controller_state.clone(),
                )
            {
                return Err("evidence_invalid");
            }
        } else {
            let db = super::la_store::open_pinned_readonly_database(root, "worker.sqlite")?;
            let absent: bool = db
                .query_row("SELECT NOT EXISTS(SELECT 1 FROM operations)", [], |r| {
                    r.get(0)
                })
                .map_err(|_| "evidence_invalid")?;
            let cursor: (String, String, i64, i64) = db
                .query_row(
                    "SELECT worker,boot,sequence,fence FROM reservation_session",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if !absent
                || cursor
                    != (
                        self.original.worker.clone(),
                        self.original.boot.clone(),
                        self.sequence as i64,
                        self.original.fence as i64,
                    )
            {
                return Err("transport_uncertain");
            }
        }
        Ok(())
    }
}
impl WorkerAdmission {
    fn check_operation(&self, operation: &WorkerOperation) -> Result<(), &'static str> {
        self.check()?;
        let current = self.0.lock().map_err(|_| "storage_unavailable")?;
        if let Some(scope) = &current.as_ref().ok_or("evidence_invalid")?.job_scope {
            match operation {
                WorkerOperation::Stage(c) | WorkerOperation::Start(c)
                    if &command_digest(c)? == scope => {}
                _ => return Err("evidence_invalid"),
            }
        }
        Ok(())
    }
    fn set_never_started(&self, cap: &NeverStartedPermit) -> Result<(), &'static str> {
        let mut current = self.0.lock().map_err(|_| "storage_unavailable")?;
        if current.is_some() || wall_now()? >= cap.body.expires_at {
            return Err("evidence_invalid");
        }
        *current = Some(AdmissionLease {
            issued_at: cap.body.issued_at,
            expires_at: cap.body.expires_at,
            job_scope: Some(command_digest(&cap.rebound)?),
        });
        Ok(())
    }
}
impl WorkerClient {
    pub(super) fn validate_never_started(
        &self,
        cap: &NeverStartedPermit,
        root: &std::fs::File,
        domain: &state_custody::Session,
    ) -> Result<(), &'static str> {
        cap.verify_role(
            &self.channel.binding,
            &self.keys,
            root,
            "controller",
            Some(domain),
            wall_now()?,
        )
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveredControllerAdmission {
    body: ActivationBody,
    handoff: String,
    cleanup: String,
    cleanup_ack: String,
    cleanup_consumed_at: u64,
    terminal: String,
    worker_anchor: SignedCheckpoint,
    worker_history: String,
    controller_anchor: SignedCheckpoint,
    controller_history: String,
    service_revision: u64,
    service_history: String,
    generation: u64,
    previous_boot: String,
    sequence: u64,
    fence: u64,
    occupancy: String,
    authority_history: String,
    process: serde_json::Value,
    controller_process: serde_json::Value,
    worker_pid: u64,
    controller_pid: u64,
    mac: [u8; 32],
}
impl RecoveredControllerAdmission {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut value = self.clone();
        value.mac = [0; 32];
        typed_mac(
            &keys.custody,
            b"diffuser-recovered-controller-admission/v1\0",
            &value,
        )
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    pub(super) fn binding(&self) -> &ChannelBinding {
        &self.body.binding
    }
    pub(super) fn cursor(&self) -> (&str, u64, u64, u64) {
        (
            &self.previous_boot,
            self.generation,
            self.sequence,
            self.fence,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds independent cleanup, both retained role histories, fresh resource and process evidence."
    )]
    pub(super) fn issue(
        resource: qualification::Certificate,
        h: &TransportEpochHandoff,
        certificate: &cleanup::Certificate,
        cleanup_ack: &serde_json::Value,
        worker: &std::fs::File,
        controller: &std::fs::File,
        worker_ledger: &CustodyLedger,
        controller_ledger: &CustodyLedger,
        service: &state_custody::Ledger,
        ready: &serde_json::Value,
        controller_ready: &serde_json::Value,
        controller_occupancy: &serde_json::Value,
        occupancy: &serde_json::Value,
        keys: &ChannelKeys,
        now: u64,
        expires: u64,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        let binding = &h.binding;
        h.verify_history(&keys.custody)?;
        resource.verify(binding, keys, now)?;
        // A consumed cleanup is historical evidence, not a fresh certificate
        // to consume again. Authenticate its exact durable bytes and the time
        // it was used within the ORIGINAL certificate window. Fresh successor
        // qualification/source/occupancy and this capability have their own
        // ordinary expiry; no old window, lease or permit is extended.
        let claims =
            super::la_store::open_pinned_readonly_database(controller, "lane_assignments.sqlite")?;
        let certificate_bytes = serde_json::to_vec(certificate).map_err(|_| "evidence_invalid")?;
        let cert_digest = hex::encode(Sha256::digest(&certificate_bytes));
        let (saved,consumed_at):(Vec<u8>,i64)=claims.query_row("SELECT certificate,released_at FROM la_assignment_cleanup_receipts WHERE assignment_id=?1 AND digest=?2",rusqlite::params![certificate.body.claim.assignment,cert_digest],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_| "evidence_invalid")?;
        let cleanup_consumed_at = u64::try_from(consumed_at).map_err(|_| "evidence_invalid")?;
        if saved != certificate_bytes || cleanup_consumed_at > now {
            return Err("evidence_invalid");
        }
        let cert = certificate.verify(binding, keys, controller, cleanup_consumed_at)?;
        if cert.claim.reconciliation.is_some()
            || cert.claim.boot != binding.worker_boot
            || cleanup_ack["released_now"] != true
            || cleanup_ack["certificate_digest"] != cert_digest
            || expires <= now
            || expires - now > 12000
            || expires > resource.expires_at()
            || worker_ledger.binding != *binding
            || controller_ledger.binding != *binding
            || worker_ledger.role != "worker"
            || controller_ledger.role != "controller"
            || worker_ledger.request_key != keys.reply
            || controller_ledger.request_key != keys.reply
            || worker_ledger.ack_key != keys.custody
            || controller_ledger.ack_key != keys.custody
        {
            return Err("evidence_invalid");
        }
        let wm = worker.metadata().map_err(|_| "evidence_invalid")?;
        let cm = controller.metadata().map_err(|_| "evidence_invalid")?;
        qualification::snapshot(
            occupancy,
            "w",
            &binding.executable_digest,
            false,
            Some(wm.dev()),
        )?;
        if occupancy["identity"]["starttime"].as_str().is_none()
            || ready["kind"] != "READY"
            || ready["role"] != "worker"
            || ready["boot_id"] != binding.worker_boot
            || ready["root_dev"] != wm.dev()
            || ready["root_inode"] != wm.ino()
            || ready["executable_sha256"] != binding.executable_digest
            || ready["policy_digest"] != binding.policy_digest
            || ready["process_seal"]["fork_errno"] != libc::EPERM
            || ready["process_seal"]["exec_errno"] != libc::EPERM
            || ready["process_seal"]["unshare_errno"] != libc::EPERM
            || ready["process_seal"]["no_new_privs"] != 1
            || ready["process_seal"]["mechanism"] != "seccomp-thread-only-tsync-v1"
            || ready["process_seal"]["architecture"] != "x86_64"
            || ready["process_seal"]["filter_sha256"]
                != "d08dcce79447d75446943abae0ad012a8fc3fa4dab11a06eb3593c7230d0c02c"
            || !occupancy["status"].as_str().is_some_and(|s| {
                ["NoNewPrivs:\t1", "Seccomp:\t2", "CapEff:\t0000000000000000"]
                    .iter()
                    .all(|line| s.lines().any(|v| v == *line))
            })
        {
            return Err("evidence_invalid");
        }
        verify_admission_process(
            controller_ready,
            controller_occupancy,
            "controller",
            binding,
            &cm,
        )?;
        verify_admission_process(ready, occupancy, "worker", binding, &wm)?;
        let (wa, _, wh) = worker_ledger.completed_anchor(worker)?;
        let (ca, _, ch) = controller_ledger.completed_anchor(controller)?;
        if wa.body.sequence <= h.worker.body.sequence
            || ca.body.sequence != wa.body.sequence
            || wa.body.sequence >= RPC_HISTORY_MAX
            || wa
                .body
                .revision
                .checked_add(2)
                .is_none_or(|r| r > CHECKPOINT_MAX)
            || ca
                .body
                .revision
                .checked_add(2)
                .is_none_or(|r| r > CHECKPOINT_MAX)
        {
            return Err("evidence_invalid");
        }
        let wd = super::la_store::open_pinned_readonly_database(worker, "worker-channel.sqlite")?;
        let cd = super::la_store::open_pinned_readonly_database(
            controller,
            "controller-channel.sqlite",
        )?;
        let claims =
            super::la_store::open_pinned_readonly_database(controller, "lane_assignments.sqlite")?;
        let state = super::la_store::open_pinned_readonly_database(worker, "worker.sqlite")?;
        super::la_worker::verify_session_history(&state, &keys.reply)?;
        verify_recovered_terminal(&claims, worker, binding, keys, h)?;
        let released:bool=claims.query_row("SELECT EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts WHERE assignment_id=?1 AND digest=?2) AND NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges) AND NOT EXISTS(SELECT 1 FROM la_assignments WHERE state!='closed')",rusqlite::params![cert.claim.assignment,cert_digest],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        let (old_boot,sequence,fence):(String,u64,u64)=claims.query_row("SELECT boot,sequence,(SELECT MAX(fence) FROM la_assignments WHERE worker=?1) FROM la_worker_cursor WHERE worker=?1",[&binding.worker],|r|Ok((r.get(0)?,u64::try_from(r.get::<_,i64>(1)?).map_err(|_|rusqlite::Error::InvalidQuery)?,u64::try_from(r.get::<_,i64>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?))).map_err(|_| "evidence_invalid")?;
        let generation = binding.controller_epoch;
        for (db, table) in [
            (&*state, "worker_controller_admissions"),
            (&*claims, "la_controller_admissions"),
        ] {
            let exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name=?1)",
                    [table],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            if exists {
                return Err("evidence_invalid");
            }
        }
        let cursor: (String, String, u64, u64) = state
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        u64::try_from(r.get::<_, i64>(2)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        u64::try_from(r.get::<_, i64>(3)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .map_err(|_| "evidence_invalid")?;
        if !released
            || cursor != (binding.worker.clone(), old_boot.clone(), sequence, fence)
            || old_boot != binding.worker_boot
            || sequence != cert.claim.sequence
            || fence != cert.claim.fence
            || generation != binding.controller_epoch
        {
            return Err("evidence_invalid");
        }
        let mut terminal = String::new();
        for seq in 1..=wa.body.sequence {
            let read = |db: &rusqlite::Connection| -> Result<(Vec<u8>, Vec<u8>), &'static str> {
                db.query_row(
                    "SELECT request,response FROM channel_log WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")
            };
            let (request, response) = read(&wd)?;
            if read(&cd)? != (request.clone(), response.clone()) {
                return Err("evidence_invalid");
            }
            let req: SignedRequest =
                serde_json::from_slice(&request).map_err(|_| "evidence_invalid")?;
            let rep: SignedResponse =
                serde_json::from_slice(&response).map_err(|_| "evidence_invalid")?;
            if !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &req.request)?
                    .ct_eq(&req.mac),
            ) || !bool::from(
                typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &rep.response)?
                    .ct_eq(&rep.mac),
            ) || rep.response.sequence != seq
                || rep.response.binding != req.request.binding
                || rep.response.request_digest
                    != hex::encode(Sha256::digest(
                        serde_json::to_vec(&req.request).map_err(|_| "evidence_invalid")?,
                    ))
            {
                return Err("evidence_invalid");
            }
            if seq == wa.body.sequence {
                let WorkerOperation::Close(c) = &req.request.operation else {
                    return Err("evidence_invalid");
                };
                let WorkerReply::Closed(r, m) = &rep.response.reply else {
                    return Err("evidence_invalid");
                };
                verify_close_receipt(&keys.reply, r, m)?;
                if c.assignment != cert.claim.assignment
                    || r.assignment != c.assignment
                    || r.sequence != cert.claim.sequence
                    || r.fence != cert.claim.fence
                    || req.request.binding != *binding
                {
                    return Err("evidence_invalid");
                }
                terminal = hex::encode(Sha256::digest(response));
            }
        }
        let (head, controller_state, service_history, revision, authority_sequence) =
            service.successor_anchor(controller, keys)?;
        let (count, high): (u64, u64) = wd
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM channel_authority",
                [],
                |r| {
                    Ok((
                        u64::try_from(r.get::<_, i64>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        u64::try_from(r.get::<_, i64>(1)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ))
                },
            )
            .map_err(|_| "evidence_invalid")?;
        if count != authority_sequence
            || high != count
            || authority_sequence <= h.authority_sequence
            || revision.checked_add(2).is_none_or(|r| r > 1025)
        {
            return Err("evidence_invalid");
        }
        let (ccount, chigh): (i64, i64) = claims
            .query_row(
                "SELECT COUNT(*),COALESCE(MAX(sequence),0) FROM la_authority_observations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if ccount != authority_sequence as i64 || chigh != ccount {
            return Err("evidence_invalid");
        }
        for seq in 1..=authority_sequence {
            let (body, frame): (Vec<u8>, Vec<u8>) = wd
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let (cbody, cmac): (Vec<u8>, Vec<u8>) = claims
                .query_row(
                    "SELECT body,mac FROM la_authority_observations WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let cmac: [u8; 32] = cmac.try_into().map_err(|_| "evidence_invalid")?;
            verify_authority_observation(&keys.authority, &cbody, &cmac)?;
            if body != cbody
                || verify_source_observation(
                    &keys.authority,
                    &transport_authority_binding(&wd, seq)?,
                    &frame,
                )? != body
            {
                return Err("evidence_invalid");
            }
            if seq == count {
                let v: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
                let observed = v["observed_at"].as_u64().ok_or("evidence_invalid")?;
                if v["sequence"] != count
                    || observed > now
                    || now - observed >= 1500
                    || verify_source_observation(&keys.authority, binding, &frame)? != body
                {
                    return Err("evidence_stale");
                }
            }
        }
        let body = ActivationBody {
            binding: binding.clone(),
            resource,
            worker_dev: wm.dev(),
            worker_inode: wm.ino(),
            worker_state: state_custody::state_digest(worker)?,
            controller_dev: cm.dev(),
            controller_inode: cm.ino(),
            controller_state,
            controller_head: head,
            authority_sequence,
            issued_at: now,
            expires_at: expires,
        };
        let mut value = Self {
            body,
            handoff: h.digest()?,
            cleanup: cert_digest,
            cleanup_consumed_at,
            cleanup_ack: hex::encode(Sha256::digest(
                serde_json::to_vec(cleanup_ack).map_err(|_| "evidence_invalid")?,
            )),
            terminal,
            worker_anchor: wa,
            worker_history: wh,
            controller_anchor: ca,
            controller_history: ch,
            service_revision: revision,
            service_history,
            generation,
            previous_boot: old_boot,
            sequence,
            fence,
            occupancy: hex::encode(Sha256::digest(
                serde_json::to_vec(occupancy).map_err(|_| "evidence_invalid")?,
            )),
            authority_history: transport_authority_digest(&wd, authority_sequence)?,
            process: occupancy["identity"].clone(),
            controller_process: controller_occupancy["identity"].clone(),
            worker_pid: ready["pid"].as_u64().ok_or("evidence_invalid")?,
            controller_pid: controller_ready["pid"].as_u64().ok_or("evidence_invalid")?,
            mac: [0; 32],
        };
        value.mac = value.signature(keys)?;
        if serde_json::to_vec(&value)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 12288
        {
            return Err("evidence_invalid");
        }
        Ok(value)
    }
    fn verify_role(
        &self,
        binding: &ChannelBinding,
        keys: &ChannelKeys,
        root: &std::fs::File,
        role: &str,
        domain: Option<&state_custody::Session>,
        now: u64,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        recovery_trace(
            "recovered_admission_verify_begin",
            serde_json::json!({"role":role,"now":now,"issued_at":self.body.issued_at,"expires_at":self.body.expires_at,"source_sequence":self.body.authority_sequence}),
        );
        self.body
            .resource
            .verify(binding, keys, now)
            .inspect_err(|code| {
                recovery_trace(
                    "recovered_admission_resource",
                    serde_json::json!({"role":role,"code":code}),
                )
            })?;
        if self.body.binding != *binding
            || self.body.issued_at > now
            || now >= self.body.expires_at
            || self.body.expires_at <= self.body.issued_at
            || self.body.expires_at - self.body.issued_at > 12000
            || self.body.expires_at > self.body.resource.expires_at()
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            recovery_trace(
                "recovered_admission_guard_1",
                serde_json::json!({"role":role,"now":now}),
            );
            return Err("evidence_invalid");
        }
        let (dev, ino, state, anchor, history) = match role {
            "worker" => (
                self.body.worker_dev,
                self.body.worker_inode,
                &self.body.worker_state,
                &self.worker_anchor,
                &self.worker_history,
            ),
            "controller" => (
                self.body.controller_dev,
                self.body.controller_inode,
                &self.body.controller_state,
                &self.controller_anchor,
                &self.controller_history,
            ),
            _ => return Err("evidence_invalid"),
        };
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        recovery_trace(
            "recovered_admission_state",
            serde_json::json!({"role":role,"expected":state,"actual":state_custody::state_digest(root).ok(),"expected_dev":dev,"actual_dev":m.dev(),"expected_inode":ino,"actual_inode":m.ino()}),
        );
        if (m.dev(), m.ino()) != (dev, ino)
            || state_custody::state_digest(root).inspect_err(|code| {
                recovery_trace(
                    "recovered_admission_state_read",
                    serde_json::json!({"role":role,"code":code}),
                )
            })? != *state
        {
            recovery_trace(
                "recovered_admission_guard_2",
                serde_json::json!({"role":role,"now":now}),
            );
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        verify_transport_chain(&db, anchor, &keys.reply, &keys.custody).inspect_err(|code| {
            recovery_trace(
                "recovered_admission_transport",
                serde_json::json!({"role":role,"code":code}),
            )
        })?;
        if transport_state_digest(&db, binding)? != anchor.body.state_digest
            || checkpoint_bytes_digest(&db, anchor.body.revision, anchor.body.revision)? != *history
        {
            recovery_trace(
                "recovered_admission_guard_3",
                serde_json::json!({"role":role,"now":now}),
            );
            return Err("evidence_invalid");
        }
        let (_, epochs) = transport_epochs(&db)?;
        let Some(TransportTransition::Controller(h)) = epochs.last() else {
            recovery_trace(
                "recovered_admission_guard_4",
                serde_json::json!({"role":role,"now":now}),
            );
            return Err("evidence_invalid");
        };
        if h.digest()? != self.handoff || h.binding != *binding {
            recovery_trace(
                "recovered_admission_guard_5",
                serde_json::json!({"role":role,"now":now}),
            );
            return Err("evidence_invalid");
        }
        {
            let proc =
                std::fs::read_to_string("/proc/self/stat").map_err(|_| "evidence_invalid")?;
            let start = proc
                .rsplit_once(") ")
                .and_then(|(_, s)| s.split_whitespace().nth(19))
                .ok_or("evidence_invalid")?;
            let (pid, identity) = if role == "worker" {
                (self.worker_pid, &self.process)
            } else {
                (self.controller_pid, &self.controller_process)
            };
            if u64::from(std::process::id()) != pid || identity["starttime"] != start {
                recovery_trace(
                    "recovered_admission_guard_6",
                    serde_json::json!({"role":role,"now":now}),
                );
                return Err("evidence_invalid");
            }
        }
        if role == "worker" {
            let state = super::la_store::open_pinned_readonly_database(root, "worker.sqlite")?;
            super::la_worker::verify_session_history(&state, &keys.reply)?;
            if transport_authority_digest(&db, self.body.authority_sequence)?
                != self.authority_history
            {
                recovery_trace(
                    "recovered_admission_guard_7",
                    serde_json::json!({"role":role,"now":now}),
                );
                return Err("evidence_invalid");
            }
            let (body, frame): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [self.body.authority_sequence as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if verify_source_observation(&keys.authority, binding, &frame)? != body {
                recovery_trace(
                    "recovered_admission_guard_8",
                    serde_json::json!({"role":role,"now":now}),
                );
                return Err("evidence_invalid");
            }
            let source: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
            let observed = source["observed_at"].as_u64().ok_or("evidence_invalid")?;
            recovery_trace(
                "recovered_admission_source_clock",
                serde_json::json!({"role":role,"consumer_now":now,"observed_at":observed,"age_ms":now.saturating_sub(observed),"source_sequence":self.body.authority_sequence}),
            );
            if observed > now || now - observed >= 1500 {
                recovery_trace(
                    "recovered_admission_guard_10",
                    serde_json::json!({"role":role,"now":now}),
                );
                return Err("evidence_stale");
            }
        } else {
            let (head, state) = domain
                .ok_or("evidence_invalid")?
                .activation_anchor()
                .inspect_err(|code| {
                    recovery_trace(
                        "recovered_admission_service_anchor",
                        serde_json::json!({"role":role,"code":code}),
                    )
                })?;
            let service =
                super::la_store::open_pinned_readonly_database(root, "service-custody.sqlite")?;
            if head != self.body.controller_head
                || state != self.body.controller_state
                || state_custody::successor_history(&service, self.service_revision)?
                    != self.service_history
            {
                recovery_trace(
                    "recovered_admission_guard_9",
                    serde_json::json!({"role":role,"now":now}),
                );
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
    fn acknowledgment(
        &self,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<ActivationAck, &'static str> {
        let activation_digest = self.digest()?;
        let mac = typed_mac(
            &keys.reply,
            b"diffuser-recovered-controller-admission-ack/v1\0",
            &(self.binding(), role, &activation_digest),
        )?;
        Ok(ActivationAck {
            binding: self.binding().clone(),
            role: role.into(),
            activation_digest,
            mac,
        })
    }
    pub(super) fn verify_ack(
        &self,
        role: &str,
        keys: &ChannelKeys,
        ack: &ActivationAck,
    ) -> Result<(), &'static str> {
        let expected = self.acknowledgment(role, keys)?;
        if ack.binding != expected.binding
            || ack.role != expected.role
            || ack.activation_digest != expected.activation_digest
            || !bool::from(expected.mac.ct_eq(&ack.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}

fn verify_admission_process(
    ready: &serde_json::Value,
    occupancy: &serde_json::Value,
    role: &str,
    binding: &ChannelBinding,
    root: &std::fs::Metadata,
) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt;
    qualification::snapshot(
        occupancy,
        if role == "worker" { "w" } else { "c" },
        &binding.executable_digest,
        false,
        Some(root.dev()),
    )?;
    let boot = if role == "worker" {
        &binding.worker_boot
    } else {
        &binding.controller_boot
    };
    let seal = &ready["process_seal"];
    if ready["kind"] != "READY"
        || ready["role"] != role
        || ready["boot_id"] != *boot
        || ready["root_dev"] != root.dev()
        || ready["root_inode"] != root.ino()
        || ready["executable_sha256"] != binding.executable_digest
        || ready["policy_digest"] != binding.policy_digest
        || ready["pid"].as_u64().is_none_or(|pid| pid == 0)
        || occupancy["identity"]["starttime"].as_str().is_none()
        || seal["fork_errno"] != libc::EPERM
        || seal["exec_errno"] != libc::EPERM
        || seal["unshare_errno"] != libc::EPERM
        || seal["no_new_privs"] != 1
        || seal["mechanism"] != "seccomp-thread-only-tsync-v1"
        || seal["architecture"] != "x86_64"
        || seal["filter_sha256"]
            != "d08dcce79447d75446943abae0ad012a8fc3fa4dab11a06eb3593c7230d0c02c"
        || !occupancy["status"].as_str().is_some_and(|s| {
            ["NoNewPrivs:\t1", "Seccomp:\t2", "CapEff:\t0000000000000000"]
                .iter()
                .all(|line| s.lines().any(|v| v == *line))
        })
    {
        return Err("evidence_invalid");
    }
    Ok(())
}

fn verify_recovered_terminal(
    claims: &rusqlite::Connection,
    root: &std::fs::File,
    binding: &ChannelBinding,
    keys: &ChannelKeys,
    h: &TransportEpochHandoff,
) -> Result<(), &'static str> {
    let (count, state, job): (i64, String, String) = claims
        .query_row("SELECT COUNT(*),state,id FROM la_jobs", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(|_| "evidence_invalid")?;
    if count != 1 {
        return Err("transport_uncertain");
    }
    if state == "succeeded" && h.never_started.as_ref().is_some_and(|c| c.job == job) {
        return verify_completed_worker_reconciliation(claims, root, binding, keys);
    }
    let (stop, mac) = h.settled_stop(keys)?.ok_or("transport_uncertain")?;
    verify_stop_receipt(&keys.reply, &stop, &mac)?;
    if state != "cancelled" || stop.job != job {
        return Err("transport_uncertain");
    }
    // The cancelled mode requires the exact P-retained stopped operation.
    let worker = super::la_store::open_pinned_readonly_database(root, "worker.sqlite")?;
    super::la_worker::verify_session_history(&worker, &keys.reply)?;
    let (command, mandate, report): (String, String, Option<String>) = claims.query_row("SELECT p.command,m.body,j.result_artifact FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_mandates m ON m.job=j.id WHERE j.id=?1", [&job], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_| "evidence_invalid")?;
    let c: InspectCommand = serde_json::from_str(&command).map_err(|_| "evidence_invalid")?;
    let m: super::la_auth::StoredMandate =
        serde_json::from_str(&mandate).map_err(|_| "evidence_invalid")?;
    let (saved, input, body, records): (String, String, Vec<u8>, i64) = worker.query_row("SELECT o.state,o.input_digest,m.body,(SELECT COUNT(*) FROM operations) FROM operations o JOIN worker_mandates m ON m.job=o.job WHERE o.op=?1 AND o.job=?2", rusqlite::params![c.operation,job], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_| "evidence_invalid")?;
    if command_digest(&c)? != stop.command_digest
        || m.draft.job != c.job
        || m.draft.operation != c.operation
        || m.draft.assignment != c.assignment
        || m.draft.worker != c.worker
        || m.draft.input_digest != c.input_digest
        || c.mandate_until != m.max_until
        || c.accepted_at != m.draft.accepted_at
        || c.operation != stop.operation
        || c.assignment != stop.assignment
        || c.fence != stop.fence
        || c.worker != binding.worker
        || c.boot != binding.worker_boot
        || saved != "stopped"
        || input != c.input_digest
        || body != mandate.as_bytes()
        || records != 1
        || report.is_some()
        || super::la_store::checked_mandate(&m.draft)? != m
    {
        return Err("evidence_invalid");
    }
    Ok(())
}

impl WorkerAdmission {
    fn validate_controller_admission(&self) -> Result<(), &'static str> {
        let current = self.0.lock().map_err(|_| "storage_unavailable")?;
        recovery_trace(
            "recovered_admission_lease",
            serde_json::json!({"present":current.is_some(),"scoped":current.as_ref().is_some_and(|a| a.job_scope.is_some()),"expires_at":current.as_ref().map(|a|a.expires_at)}),
        );
        if current.as_ref().is_some_and(|a| a.job_scope.is_none()) {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn set_controller_admission(
        &self,
        cap: &RecoveredControllerAdmission,
    ) -> Result<(), &'static str> {
        self.validate_controller_admission()?;
        if wall_now()? >= cap.body.expires_at {
            return Err("evidence_invalid");
        }
        *self.0.lock().map_err(|_| "storage_unavailable")? = Some(AdmissionLease {
            issued_at: cap.body.issued_at,
            expires_at: cap.body.expires_at,
            job_scope: None,
        });
        Ok(())
    }
}
impl WorkerClient {
    pub(super) fn validate_controller_admission(
        &self,
        cap: &RecoveredControllerAdmission,
        root: &std::fs::File,
        domain: &state_custody::Session,
    ) -> Result<(), &'static str> {
        self.channel.check()?;
        self.admission.validate_controller_admission()?;
        cap.verify_role(
            &self.channel.binding,
            &self.keys,
            root,
            "controller",
            Some(domain),
            wall_now()?,
        )
    }
    pub(super) fn finish_controller_admission(
        &self,
        cap: &RecoveredControllerAdmission,
    ) -> Result<ActivationAck, &'static str> {
        self.admission.set_controller_admission(cap)?;
        cap.acknowledgment("controller", &self.keys)
    }
}

impl WorkerClient {
    pub(super) fn verify_controller_admission_ack(
        &self,
        cap: &RecoveredControllerAdmission,
        ack: &ActivationAck,
    ) -> Result<(), &'static str> {
        cap.verify_ack("worker", &self.keys, ack)
    }
}

impl TransportEpochHandoff {
    pub(super) fn recovered_job_lifecycle(&self, keys: &ChannelKeys) -> Result<bool, &'static str> {
        Ok(self.never_started.is_some() || self.settled_stop(keys)?.is_some())
    }
}

/// Independently authenticated settlement of ONE entered operation after proved
/// execution-domain death. This is not a worker Stop, result, join, retry permit,
/// epoch transition, registration or activation. The original worker root is
/// retained byte-for-byte, including its started/uncertain marker and inputs.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerLossSettlement {
    kind: String,
    pub(super) binding: ChannelBinding,
    pub(super) command: InspectCommand,
    sequence: u64,
    request: String,
    controller: SignedCheckpoint,
    controller_ack: CheckpointAck,
    controller_history: String,
    worker: SignedCheckpoint,
    worker_ack: CheckpointAck,
    worker_history: String,
    controller_state: String,
    pub(super) worker_state: String,
    service: state_custody::WorkerServiceAnchor,
    authority_digest: String,
    authority_sequence: u64,
    death: serde_json::Value,
    survivors: serde_json::Value,
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}
impl WorkerLossSettlement {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut unsigned = self.clone();
        unsigned.mac = [0; 32];
        typed_mac(key, b"diffuser-entered-worker-loss/v1\0", &unsigned)
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    pub(super) fn verify_history(&self, keys: &ChannelKeys) -> Result<(), &'static str> {
        self.binding.validate()?;
        let signed: SignedRequest =
            serde_json::from_str(&self.request).map_err(|_| "evidence_invalid")?;
        if self.kind != "diffuser-entered-worker-loss/v1"
            || self.sequence == 0
            || self.sequence > RPC_HISTORY_MAX
            || self.controller.body.binding != self.binding
            || self.worker.body.binding != self.binding
            || self.controller.body.role != "controller"
            || self.worker.body.role != "worker"
            || self.controller.body.phase != "intent"
            || self.worker.body.phase != "complete"
            || self.controller.body.sequence != self.sequence
            || self.worker.body.sequence.checked_add(1) != Some(self.sequence)
            || self
                .controller
                .body
                .revision
                .checked_add(1)
                .is_none_or(|n| n > CHECKPOINT_MAX)
            || self.worker.body.owned_state.as_ref() != Some(&self.worker_state)
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 1500
            || signed.request.binding != self.binding
            || signed.request.sequence != self.sequence
            || !matches!(&signed.request.operation, WorkerOperation::Stop(c) if serde_json::to_vec(c).ok()==serde_json::to_vec(&self.command).ok())
            || self.command.worker != self.binding.worker
            || self.command.boot != self.binding.worker_boot
            || !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &signed.request)?
                    .ct_eq(&signed.mac),
            )
            || !bool::from(self.signature(&keys.custody)?.ct_eq(&self.mac))
            || [
                &self.controller_history,
                &self.worker_history,
                &self.controller_state,
                &self.worker_state,
                &self.authority_digest,
            ]
            .iter()
            .any(|h| h.len() != 64 || hex::decode(h).is_err())
            || self.authority_sequence == 0
            || self.authority_sequence > 128
            || self.death["kind"] != "W_KILLED"
            || self.death["signal"] != 9
            || self.death["pidfd_dead"] != true
            || self.death["rights"] != 0
            || self.death["execution_domain"]["quiescent"] != true
            || self.death["execution_domain"]["recursive"] != true
            || self.death["execution_domain"]["cgroup"] != self.death["identity"]["cgroup"]
            || self.death["keeper"] != self.survivors["keeper"]
            || self.death["survivors"] != self.survivors
            || self.death["identity"]["sha256"] != self.binding.executable_digest
            || self.death["seq"].as_u64().is_none_or(|n| n == 0 || n > 32)
            || self.death["nonce"]
                .as_str()
                .is_none_or(|n| n.len() != 64 || hex::decode(n).is_err())
        {
            return Err("evidence_invalid");
        }
        self.controller_ack
            .verify(&keys.custody, &self.controller)?;
        self.worker_ack.verify(&keys.custody, &self.worker)?;
        Ok(())
    }
    pub(super) fn consumption_deadline(&self) -> u64 {
        self.expires_at
    }
    pub(super) fn verify(&self, keys: &ChannelKeys, now: u64) -> Result<(), &'static str> {
        self.verify_history(keys)?;
        if now < self.issued_at || now >= self.expires_at {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Independent loss authority binds both histories, surviving roots, death domain and service custody."
    )]
    pub(super) fn prepare(
        controller: &CustodyLedger,
        worker: &CustodyLedger,
        service: &state_custody::Ledger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        initial: &serde_json::Value,
        death: &serde_json::Value,
        survivors: &serde_json::Value,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        if controller.role != "controller"
            || worker.role != "worker"
            || controller.binding != worker.binding
            || controller.pending_epoch.is_some()
            || worker.pending_epoch.is_some()
            || controller.ack_key != keys.custody
            || worker.ack_key != keys.custody
            || controller.request_key != keys.reply
            || worker.request_key != keys.reply
        {
            return Err("evidence_invalid");
        }
        qualification::snapshot(
            initial,
            "w",
            &controller.binding.executable_digest,
            true,
            Some(wroot.metadata().map_err(|_| "evidence_invalid")?.dev()),
        )?;
        if initial["identity"] != death["identity"] {
            return Err("evidence_invalid");
        }
        for role in ["controller", "keeper", "witness"] {
            let i = &survivors[role];
            if i["pid"].as_u64().is_none_or(|n| n == 0)
                || i["starttime"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_none_or(|n| n == 0)
                || i["cgroup"] == death["identity"]["cgroup"]
                || i["sha256"]
                    .as_str()
                    .is_none_or(|s| s.len() != 64 || hex::decode(s).is_err())
            {
                return Err("evidence_invalid");
            }
        }
        if survivors["controller"]["exe"] != "/worker-test"
            || survivors["controller"]["sha256"] != controller.binding.executable_digest
            || survivors["witness"]["exe"] != "/p-client"
            || survivors["witness"]["sha256"] != controller.binding.executable_digest
            || survivors["keeper"]["exe"] != "/stage/bridge"
            || survivors["controller"]["pid"] == survivors["keeper"]["pid"]
            || survivors["controller"]["pid"] == survivors["witness"]["pid"]
            || survivors["keeper"]["pid"] == survivors["witness"]["pid"]
        {
            return Err("evidence_invalid");
        }
        let (c, ca, ch) = controller.recovery_anchor(croot, true)?;
        let (w, wa, wh) = worker.completed_anchor(wroot)?;
        if w.body.sequence.checked_add(1) != Some(c.body.sequence) {
            return Err("transport_uncertain");
        }
        let anchor = service.worker_loss_anchor(croot)?;
        let cd =
            super::la_store::open_pinned_readonly_database(croot, "controller-channel.sqlite")?;
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        for seq in 1..c.body.sequence {
            let read =
                |db: &rusqlite::Connection| -> Result<(Vec<u8>, Vec<u8>, String), &'static str> {
                    db.query_row(
                        "SELECT request,response,digest FROM channel_log WHERE sequence=?1",
                        [seq as i64],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .map_err(|_| "evidence_invalid")
                };
            let cr = read(&cd)?;
            let wr = read(&wd)?;
            if cr.0 != wr.0 || cr.1 != wr.1 {
                return Err("evidence_invalid");
            }
            let request: SignedRequest =
                serde_json::from_slice(&cr.0).map_err(|_| "evidence_invalid")?;
            let response: SignedResponse =
                serde_json::from_slice(&wr.1).map_err(|_| "evidence_invalid")?;
            if !bool::from(
                typed_mac(
                    &keys.command,
                    b"diffuser-rpc-request/v1\0",
                    &request.request,
                )?
                .ct_eq(&request.mac),
            ) || !bool::from(
                typed_mac(
                    &keys.reply,
                    b"diffuser-rpc-response/v1\0",
                    &response.response,
                )?
                .ct_eq(&response.mac),
            ) || response.response.binding != request.request.binding
                || response.response.sequence != seq
                || response.response.request_digest != wr.2
            {
                return Err("evidence_invalid");
            }
        }
        let request: Vec<u8> = cd
            .query_row(
                "SELECT request FROM channel_log WHERE sequence=?1 AND response IS NULL",
                [c.body.sequence as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if service.worker_close_envelope()? != request {
            return Err("evidence_invalid");
        }
        let signed: SignedRequest =
            serde_json::from_slice(&request).map_err(|_| "evidence_invalid")?;
        let WorkerOperation::Stop(command) = signed.request.operation else {
            return Err("evidence_invalid");
        };
        let workerdb = super::la_store::open_pinned_readonly_database(wroot, "worker.sqlite")?;
        super::la_worker::verify_session_history(&workerdb, &keys.reply)?;
        let command_bytes = serde_json::to_vec(&command).map_err(|_| "evidence_invalid")?;
        let entered:bool=workerdb.query_row("SELECT EXISTS(SELECT 1 FROM operations o JOIN worker_inspect_commands c ON c.operation=o.op WHERE o.op=?1 AND o.job=?2 AND o.input_digest=?3 AND o.state='started' AND o.report IS NULL AND c.command_digest=?4) AND (SELECT COUNT(*) FROM operations)=1 AND NOT EXISTS(SELECT 1 FROM worker_result_receipts) AND NOT EXISTS(SELECT 1 FROM worker_stop_receipts)",rusqlite::params![command.operation,command.job,command.input_digest,Sha256::digest(&command_bytes).as_slice()],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if !entered {
            return Err("transport_uncertain");
        }
        // All source records and both role ACKs are verified by the service anchor.
        let authority_sequence = service.authority_sequence();
        let authority_digest = transport_authority_digest(&wd, authority_sequence)?;
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        for seq in 1..=authority_sequence {
            let (body, frame): (Vec<u8>, Vec<u8>) = wd
                .query_row(
                    "SELECT body,frame FROM channel_authority WHERE sequence=?1",
                    [seq as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let saved: Vec<u8> = claims
                .query_row(
                    "SELECT body FROM la_authority_observations WHERE sequence=?1",
                    [seq as i64],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            if body != saved
                || verify_source_observation(
                    &keys.authority,
                    &transport_authority_binding(&wd, seq)?,
                    &frame,
                )? != body
            {
                return Err("evidence_invalid");
            }
        }

        let value = Self {
            kind: "diffuser-entered-worker-loss/v1".into(),
            binding: controller.binding.clone(),
            command,
            sequence: c.body.sequence,
            request: String::from_utf8(request).map_err(|_| "evidence_invalid")?,
            controller: c,
            controller_ack: ca,
            controller_history: ch,
            worker: w,
            worker_ack: wa,
            worker_history: wh,
            controller_state: state_custody::state_digest(croot)?,
            worker_state: state_custody::state_digest(wroot)?,
            service: anchor,
            authority_digest,
            authority_sequence,
            death: death.clone(),
            survivors: survivors.clone(),
            issued_at: now,
            expires_at: now.checked_add(1500).ok_or("evidence_invalid")?,
            mac: [0; 32],
        };
        let mut value = value;
        value.mac = value.signature(&keys.custody)?;
        value.verify(keys, now)?;
        if serde_json::to_vec(&value)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 12288
        {
            return Err("evidence_invalid");
        }
        use std::io::Write;
        let mut file = super::la_artifacts::open_artifact(
            &controller.root,
            &format!("worker-loss-{:04}.json", value.sequence),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| "storage_unavailable")?;
        file.write_all(&serde_json::to_vec(&value).map_err(|_| "evidence_invalid")?)
            .and_then(|_| file.sync_all())
            .and_then(|_| controller.root.sync_all())
            .map_err(|_| "storage_unavailable")?;
        Ok(value)
    }
    pub(super) fn verify_controller(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify(keys, now)?;
        let db = super::la_store::open_pinned_readonly_database(root, "controller-channel.sqlite")?;
        if state_custody::state_digest(root)? != self.controller_state
            || transport_state_digest(&db, &self.binding)? != self.controller.body.state_digest
            || checkpoint_bytes_digest(
                &db,
                self.controller.body.revision,
                self.controller.body.revision,
            )? != self.controller_history
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, &self.controller, &keys.reply, &keys.custody)?;
        Ok(())
    }
}

impl WorkerClient {
    pub(super) fn settle_worker_loss(
        &mut self,
        cap: &WorkerLossSettlement,
        now: u64,
    ) -> Result<(), &'static str> {
        cap.verify_controller(&self.channel.root, &self.keys, now)?;
        if self.channel.binding != cap.binding {
            return Err("evidence_invalid");
        }
        self.service_custody
            .as_ref()
            .ok_or("evidence_invalid")?
            .verify_worker_loss(cap, &self.keys, now)?;
        // Fence execution before a mutation. No dead-worker reply is invented:
        // this response has a separate P signature and wire discriminant.
        cap.verify(&self.keys, wall_now()?)?;
        *self.admission.0.lock().map_err(|_| "storage_unavailable")? = None;
        let signed: SignedRequest =
            serde_json::from_str(&cap.request).map_err(|_| "evidence_invalid")?;
        self.channel.complete(
            cap.sequence,
            &rpc_content_digest(&signed.request)?,
            &serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?,
        )
    }
    pub(super) fn finish_worker_loss(
        &self,
        cap: &WorkerLossSettlement,
    ) -> Result<(), &'static str> {
        self.service_custody
            .as_ref()
            .ok_or("evidence_invalid")?
            .complete(cap.service.operation, &cap.digest()?)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerLossClose {
    pub(super) kind: String,
    pub(super) command: CloseCommand,
    pub(super) settlement: String,
}

impl cleanup::Certificate {
    /// Distinct dead-domain occupancy proof. No worker root or input is erased;
    /// a retained started marker is compatible only with this exact failed job.
    #[expect(
        clippy::too_many_arguments,
        reason = "Death-domain cleanup requires independent exact role and service custody plus current survivor observation."
    )]
    pub(super) fn inspect_worker_loss(
        cap: &WorkerLossSettlement,
        keys: &ChannelKeys,
        worker: &CustodyLedger,
        controller: &CustodyLedger,
        service: &state_custody::Ledger,
        wroot: &std::fs::File,
        croot: &std::fs::File,
        survivors: &serde_json::Value,
        now: u64,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        cap.verify_history(keys)?;
        let (_, _, history) = worker.completed_anchor(wroot)?;
        if worker.binding != cap.binding
            || worker.head != cap.worker.digest()?
            || history != cap.worker_history
            || state_custody::state_digest(wroot)? != cap.worker_state
            || survivors != &cap.survivors
        {
            return Err("evidence_invalid");
        }
        controller.completed_anchor(croot)?;
        if controller.binding != cap.binding {
            return Err("evidence_invalid");
        }
        service.worker_loss_cleanup_anchor(croot)?;
        let c = super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        let saved: Vec<u8> = c
            .query_row(
                "SELECT body FROM la_worker_loss_settlements WHERE job=?1",
                [&cap.command.job],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if saved != serde_json::to_vec(cap).map_err(|_| "evidence_invalid")? {
            return Err("evidence_invalid");
        }
        let claim = cleanup::claim_snapshot(&c, &cap.command.assignment)?;
        let close: Vec<u8> = c
            .query_row(
                "SELECT body FROM la_worker_loss_closes WHERE assignment_id=?1",
                [&claim.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let record: WorkerLossClose =
            serde_json::from_slice(&close).map_err(|_| "evidence_invalid")?;
        if record.kind != "diffuser-dead-domain-close/v1"
            || record.settlement != cap.digest()?
            || record.command.assignment != cap.command.assignment
            || record.command.boot != cap.binding.worker_boot
            || record.command.worker != cap.binding.worker
            || record.command.fence != cap.command.fence
            || Sha256::digest(&close).as_slice() != claim.stop_digest
        {
            return Err("evidence_invalid");
        }
        let wm = wroot.metadata().map_err(|_| "evidence_invalid")?;
        let cm = croot.metadata().map_err(|_| "evidence_invalid")?;
        let body = cleanup::Body {
            version: 2,
            binding: cap.binding.clone(),
            claim: claim.clone(),
            controller_root: (cm.dev(), cm.ino()),
            worker_root: (wm.dev(), wm.ino()),
            worker_state_digest: cap.worker_state.clone(),
            occupancy_digest: cap.digest()?,
            observed_at: now,
            expires_at: claim.certificate_expiry(&cap.binding, now)?,
        };
        let mac = typed_mac(&keys.custody, b"diffuser-cleanup-occupancy/v1\0", &body)?;
        let cert = Self {
            body,
            mac,
            loss: Some(Box::new(cap.clone())),
        };
        cert.verify(&cap.binding, keys, croot, now)?;
        Ok(cert)
    }
}

/// A distinct source reconciliation for surviving C after exact entered W loss.
/// It refreshes only the failed job's read/cancel/Close/cleanup authority. The
/// dead worker's source rows, acknowledged cursor and all execution clocks stay
/// unchanged. P retains full current survivor/occupancy observations separately.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerLossSource {
    kind: String,
    pub(super) binding: ChannelBinding,
    pub(super) job: String,
    pub(super) assignment: String,
    settlement: String,
    pub(super) mandate: super::la_auth::StoredMandate,
    pub(super) previous_sequence: u64,
    pub(super) frame: Vec<u8>,
    controller: SignedCheckpoint,
    controller_ack: CheckpointAck,
    controller_history: String,
    controller_state: String,
    service: (String, String, String, u64, u64),
    observation: serde_json::Value,
    survivors_digest: String,
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    mac: [u8; 32],
}
impl WorkerLossSource {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut unsigned = self.clone();
        unsigned.mac = [0; 32];
        typed_mac(key, b"diffuser-dead-worker-source/v1\0", &unsigned)
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(self).map_err(|_| "evidence_invalid")?,
        )))
    }
    pub(super) fn verify(&self, keys: &ChannelKeys, now: u64) -> Result<Vec<u8>, &'static str> {
        self.binding.validate()?;
        let canonical = verify_source_observation(&keys.authority, &self.binding, &self.frame)?;
        let body: serde_json::Value =
            serde_json::from_slice(&canonical).map_err(|_| "evidence_invalid")?;
        if self.kind != "diffuser-dead-worker-source/v1"
            || !bool::from(self.signature(&keys.custody)?.ct_eq(&self.mac))
            || self.previous_sequence == 0
            || self.previous_sequence >= 128
            || body["sequence"].as_u64() != self.previous_sequence.checked_add(1)
            || body["observed_at"].as_u64() != Some(self.issued_at)
            || self.issued_at > now
            || now >= self.expires_at
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 1500
            || self.observation["kind"] != "LOSS_REOBSERVED"
            || self.observation["pidfd_dead"] != true
            || self.observation["execution_domain"]["quiescent"] != true
            || self.observation["execution_domain"]["recursive"] != true
            || self.observation["rights"] != 0
            || self.observation["observed_at"].as_u64() != Some(self.issued_at)
            || self.observation["seq"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > 32)
            || self.controller.body.binding != self.binding
            || self.controller.body.role != "controller"
            || self.controller.body.phase != "complete"
            || self.service.1 != self.controller_state
            || self.service.4 != self.previous_sequence
            || self.service.3.checked_add(2).is_none_or(|n| n > 1025)
            || [
                &self.settlement,
                &self.controller_history,
                &self.controller_state,
                &self.survivors_digest,
            ]
            .iter()
            .any(|v| v.len() != 64 || hex::decode(v).is_err())
        {
            return Err("evidence_invalid");
        }
        self.controller_ack
            .verify(&keys.custody, &self.controller)?;
        Ok(canonical)
    }
    fn installed_loss(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
    ) -> Result<WorkerLossSettlement, &'static str> {
        let db = super::la_store::open_pinned_readonly_database(root, "lane_assignments.sqlite")?;
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT body FROM la_worker_loss_settlements WHERE job=?1 AND assignment_id=?2",
                rusqlite::params![self.job, self.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let loss: WorkerLossSettlement =
            serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        loss.verify_history(keys)?;
        let exact: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM la_jobs j JOIN la_reservations r ON r.assignment_id=j.assignment_id JOIN la_quota_charges q ON q.assignment_id=j.assignment_id JOIN la_job_outbox o ON o.job=j.id WHERE j.id=?1 AND j.state='failed' AND j.result_artifact IS NULL AND o.action='worker_lost_uncertain') AND NOT EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts WHERE assignment_id=?2)", rusqlite::params![self.job,self.assignment], |r| r.get(0)).map_err(|_| "evidence_invalid")?;
        if !exact
            || loss.digest()? != self.settlement
            || loss.binding != self.binding
            || loss.command.job != self.job
            || loss.command.assignment != self.assignment
            || self.observation["identity"] != loss.death["identity"]
            || self.observation["execution_domain"]["cgroup"]
                != loss.death["execution_domain"]["cgroup"]
            || self.observation["survivors"] != loss.survivors
            || self.observation["nonce"] != loss.death["nonce"]
            || self.observation["seq"].as_u64() <= loss.death["seq"].as_u64()
        {
            return Err("evidence_invalid");
        }
        Ok(loss)
    }
    pub(super) fn verify_controller(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Vec<u8>, &'static str> {
        let canonical = self.verify(keys, now)?;
        self.installed_loss(root, keys)?;
        let db = super::la_store::open_pinned_readonly_database(root, "controller-channel.sqlite")?;
        if state_custody::state_digest(root)? != self.controller_state
            || transport_state_digest(&db, &self.binding)? != self.controller.body.state_digest
            || checkpoint_bytes_digest(
                &db,
                self.controller.body.revision,
                self.controller.body.revision,
            )? != self.controller_history
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, &self.controller, &keys.reply, &keys.custody)?;
        let service_db =
            super::la_store::open_pinned_readonly_database(root, "service-custody.sqlite")?;
        let (f, a): (Vec<u8>, Vec<u8>) = service_db
            .query_row(
                "SELECT frame,ack FROM service_checkpoints WHERE revision=?1",
                [self.service.3 as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let f = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
        let a = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
        if state_custody::verified_anchor(root, &f, &a, keys)?
            != (self.service.0.clone(), self.service.1.clone())
            || state_custody::successor_history(&service_db, self.service.3)? != self.service.2
        {
            return Err("evidence_invalid");
        }
        Ok(canonical)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds exact surviving histories, current observations and retained dead-worker bytes."
    )]
    pub(super) fn prepare(
        loss: &WorkerLossSettlement,
        controller: &CustodyLedger,
        worker: &CustodyLedger,
        service: &state_custody::Ledger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        observation: &serde_json::Value,
        snapshots: &serde_json::Value,
        frame: Vec<u8>,
        keys: &ChannelKeys,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        loss.verify_history(keys)?;
        let (_, _, wh) = worker.completed_anchor(wroot)?;
        if controller.binding != loss.binding
            || worker.binding != loss.binding
            || worker.head != loss.worker.digest()?
            || wh != loss.worker_history
            || state_custody::state_digest(wroot)? != loss.worker_state
            || controller.pending_epoch.is_some()
            || worker.pending_epoch.is_some()
            || service.authority_sequence() != loss.authority_sequence
        {
            return Err("evidence_invalid");
        }
        for (role, name) in [("c", "controller"), ("k", "keeper"), ("p", "witness")] {
            let snap = &snapshots[name];
            qualification::snapshot(
                snap,
                role,
                &loss.binding.executable_digest,
                false,
                if role == "c" {
                    Some(croot.metadata().map_err(|_| "evidence_invalid")?.dev())
                } else {
                    None
                },
            )?;
            if snap["identity"] != loss.survivors[name] {
                return Err("evidence_invalid");
            }
        }
        if observation["occupancy"]
            .as_array()
            .is_none_or(|a| a.len() != 2)
        {
            return Err("evidence_invalid");
        }
        for (i, root) in [wroot, croot].into_iter().enumerate() {
            use std::os::fd::AsRawFd;
            let m = root.metadata().map_err(|_| "evidence_invalid")?;
            let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if unsafe { libc::fstatvfs(root.as_raw_fd(), st.as_mut_ptr()) } != 0 {
                return Err("evidence_invalid");
            }
            let st = unsafe { st.assume_init() };
            let occupancy = &observation["occupancy"][i];
            if occupancy["dev"].as_u64() != Some(m.dev())
                || occupancy["inode"].as_u64() != Some(m.ino())
                || occupancy["capacity"].as_u64() != Some(st.f_blocks * st.f_frsize)
                || occupancy["available"].as_u64() != Some(st.f_bavail * st.f_frsize)
                || st.f_blocks * st.f_frsize != 67108864
                || st.f_bavail == 0
            {
                return Err("evidence_invalid");
            }
        }
        let (c, ca, ch) = controller.completed_anchor(croot)?;
        let anchor = service.loss_source_anchor(croot)?;
        let now = observation["observed_at"]
            .as_u64()
            .ok_or("evidence_invalid")?;
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        let mandate: String = claims
            .query_row(
                "SELECT body FROM la_mandates WHERE job=?1",
                [&loss.command.job],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let mandate: super::la_auth::StoredMandate =
            serde_json::from_str(&mandate).map_err(|_| "evidence_invalid")?;
        if super::la_store::checked_mandate(&mandate.draft)? != mandate {
            return Err("evidence_invalid");
        }
        let mut value = Self {
            kind: "diffuser-dead-worker-source/v1".into(),
            binding: loss.binding.clone(),
            job: loss.command.job.clone(),
            assignment: loss.command.assignment.clone(),
            settlement: loss.digest()?,
            mandate,
            previous_sequence: service.authority_sequence(),
            frame,
            controller: c,
            controller_ack: ca,
            controller_history: ch,
            controller_state: state_custody::state_digest(croot)?,
            service: anchor,
            observation: observation.clone(),
            survivors_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(snapshots).map_err(|_| "evidence_invalid")?,
            )),
            issued_at: now,
            expires_at: now.checked_add(1500).ok_or("evidence_invalid")?,
            mac: [0; 32],
        };
        value.mac = value.signature(&keys.custody)?;
        value.verify_controller(croot, keys, wall_now()?)?;
        if serde_json::to_vec(&value)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 12288
        {
            return Err("evidence_invalid");
        }
        Ok(value)
    }
}

impl WorkerClient {
    pub(super) fn install_entered_loss_transport(
        &mut self,
        h: &WorkerLossReturn,
        address: std::net::SocketAddr,
        now: u64,
        scope: &(String, String),
        source_sequence: u64,
        domain_binding: &ChannelBinding,
    ) -> Result<serde_json::Value, &'static str> {
        h.verify(&self.keys.custody, now)?;
        let db = super::la_store::open_pinned_readonly_database(
            &self.channel.root,
            "controller-channel.sqlite",
        )?;
        let (req, res): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT request,response FROM channel_log WHERE sequence=?1",
                [h.high_water() as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let loss = h.verify_resolution(&req, &res, &self.keys.custody)?;
        if scope != &(loss.command.job.clone(), loss.command.assignment.clone())
            || source_sequence != h.authority_sequence + 1
            || domain_binding != &h.previous
        {
            return Err("evidence_invalid");
        }
        h.verify_role_root(&self.channel.root, "controller", &self.keys)?;
        if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || address.port() == 0
            || self
                .admission
                .0
                .lock()
                .map_err(|_| "storage_unavailable")?
                .is_some()
        {
            return Err("evidence_invalid");
        }
        self.channel.install_transition(
            &TransportTransition::EnteredLoss(Box::new(h.clone())),
            None,
            now,
        )?;
        self.address = address;
        let reply = self.call(WorkerOperation::Probe, &[])?;
        match reply {
            WorkerReply::Probe { worker_pid, .. } if worker_pid == h.returning.namespace_pid => Ok(
                serde_json::json!({"kind":"ENTERED_LOSS_TRANSPORT_RECONCILED","handoff":h.digest()?,"binding":h.binding,"first_rpc_sequence":h.high_water()+1,"worker_pid":worker_pid,"admitted":false}),
            ),
            _ => Err("evidence_invalid"),
        }
    }
}

impl WorkerLossReturn {
    /// Full current histories plus exact original prefixes and actual P-signed
    /// first-install clocks. Later checks cannot turn an expired FIRST use into
    /// a consumed transition. This grants no source/disposition/admission rights.
    pub(super) fn verify_installed_transport(
        &self,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify_history(&keys.custody)?;
        for (role, root) in [("worker", wroot), ("controller", croot)] {
            let (old, _, prefix, state) = self.anchor(role)?;
            let db = super::la_store::open_pinned_readonly_database(
                root,
                &format!("{role}-channel.sqlite"),
            )?;
            let (head, ack): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT frame,ack FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let head: SignedCheckpoint =
                serde_json::from_slice(&head).map_err(|_| "evidence_invalid")?;
            let ack: CheckpointAck =
                serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
            let (_, epochs) = transport_epochs(&db)?;
            if head.body.binding != self.binding
                || head.body.role != role
                || head.body.phase != "complete"
                || head.body.sequence < self.high_water() + 1
                || head.body.sequence > RPC_HISTORY_MAX
                || epochs.last().ok_or("evidence_invalid")?.digest()? != self.digest()?
                || transport_state_digest(&db, &self.binding)? != head.body.state_digest
                || checkpoint_bytes_digest(&db, head.body.revision, old.body.revision)? != prefix
                || state_custody::state_digest(root)? != state
            {
                return Err("evidence_invalid");
            }
            ack.verify(&keys.custody, &head)?;
            verify_transport_chain(&db, &head, &keys.reply, &keys.custody)?;
            let (installed, ack): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT frame,ack FROM channel_checkpoints WHERE revision=?1",
                    [(old.body.revision + 1) as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let installed: SignedCheckpoint =
                serde_json::from_slice(&installed).map_err(|_| "evidence_invalid")?;
            let ack: CheckpointAck =
                serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
            ack.verify(&keys.custody, &installed)?;
            let proof = ack.loss_consumption.as_ref().ok_or("evidence_invalid")?;
            let kind = if role == "worker" {
                "loss_worker"
            } else {
                "loss_controller"
            };
            proof.verify_window(
                &keys.custody,
                &self.digest()?,
                self.issued_at,
                self.expires_at,
                now,
            )?;
            if installed.body.binding != self.binding
                || installed.body.previous != old.digest()?
                || installed.body.sequence != self.high_water()
                || installed.body.phase != "handoff"
                || proof.kind != kind
                || proof.checkpoint != installed.digest()?
                || (role == "controller"
                    && proof.peer.as_ref().is_none_or(|p| p.kind != "loss_worker"))
            {
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn test_reopen_independent_ledgers(
        &self,
        controller: &CustodyLedger,
        worker: &CustodyLedger,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        self.verify_installed_transport(croot, wroot, keys, wall_now()?)?;
        for (ledger, root) in [(controller, croot), (worker, wroot)] {
            let (head, ack, _) = ledger.completed_anchor(root)?;
            let reopened = CustodyLedger::reopen(
                &ledger.root,
                &ledger.path,
                &head,
                &ack,
                keys.reply,
                keys.custody,
            )?;
            if reopened.head != ledger.head
                || reopened.binding != ledger.binding
                || reopened.revision != ledger.revision
            {
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
}

impl TransportJournal {
    fn loss_return_quarantine(&self) -> Result<(), &'static str> {
        self.check()?;
        if matches!(
            transport_epochs(&self.db)?.1.last(),
            Some(TransportTransition::EnteredLoss(_))
        ) {
            self.authenticated_loss_return_activation()?;
        }
        Ok(())
    }
}

#[cfg(test)]
impl WorkerLossReturn {
    pub(super) fn test_preinstall_guards(
        &self,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Vec<String>, &'static str> {
        self.verify(&keys.custody, now)?;
        self.verify_role_root(croot, "controller", keys)?;
        self.verify_role_root(wroot, "worker", keys)?;
        let mut guards = Vec::new();
        for field in [
            "worker_epoch",
            "worker_boot",
            "phase",
            "adjacency",
            "channel_headroom",
            "source_bound",
            "consumption_time",
            "full_prior_history",
        ] {
            recovery_trace(
                "loss_return_signed_probe_start",
                serde_json::json!({"field":field}),
            );
            let mut h = self.clone();
            match field {
                "worker_epoch" => h.binding.worker_epoch += 1,
                "worker_boot" => h.binding.worker_boot = h.previous.worker_boot.clone(),
                "phase" => h.controller.body.phase = "intent".into(),
                "adjacency" => h.worker.body.sequence -= 1,
                "channel_headroom" => h.worker.body.revision = CHECKPOINT_MAX - 2,
                "source_bound" => h.authority_sequence = 128,
                "consumption_time" => h.cleanup_consumed_at = h.issued_at + 1,
                "full_prior_history" => h.prior_epochs = "f".repeat(64),
                _ => unreachable!(),
            }
            // Reauthenticate changed anchors to reach the intended semantic guard.
            for head in [&mut h.controller, &mut h.worker] {
                head.mac = typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", &head.body)?;
            }
            h.controller_ack = CheckpointAck::new(&keys.custody, &h.controller)?;
            h.worker_ack = CheckpointAck::new(&keys.custody, &h.worker)?;
            h.mac = h.signature(&keys.custody)?;
            let refused = if field == "full_prior_history" {
                h.verify_history(&keys.custody)?;
                h.verify_role_root(wroot, "worker", keys).is_err()
            } else {
                h.verify_history(&keys.custody).is_err()
            };
            if !refused {
                return Err("evidence_invalid");
            }
            recovery_trace(
                "loss_return_signed_probe_end",
                serde_json::json!({"field":field,"refused":refused}),
            );
            guards.push(field.into());
        }
        if self.verify(&keys.custody, self.expires_at).is_ok() {
            return Err("evidence_invalid");
        }
        guards.push("expired_first_use".into());
        Ok(guards)
    }
}

#[cfg(test)]
impl WorkerLossReturn {
    pub(super) fn test_corrupt_resolution(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut cap: WorkerLossSettlement =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        if serde_json::to_vec(&cap).map_err(|_| "evidence_invalid")? != bytes {
            return Err("evidence_invalid");
        }
        cap.mac[0] ^= 1;
        serde_json::to_vec(&cap).map_err(|_| "evidence_invalid")
    }
}

/// Historical source resolution for ONE consumed entered loss. This does not
/// admit work or retire execution occupancy. In particular the W2 acknowledgment
/// below is never an ordinary SourceAck from the dead worker.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnteredLossSourceBridge {
    kind: String,
    returned: String,
    previous: ChannelBinding,
    binding: ChannelBinding,
    sequence: u64,
    prefix: String,
    historical: String,
    frame: String,
    controller_source_ack: SourceAck,
    settlement: String,
    cleanup: String,
    released_at: u64,
    worker: SignedCheckpoint,
    worker_history: String,
    controller: SignedCheckpoint,
    controller_history: String,
    service: (String, String, String, u64, u64),
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossSourceBridgeAck {
    bridge: String,
    role: String,
    binding: ChannelBinding,
    sequence: u64,
    mac: [u8; 32],
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossSourceBridgeCompletion {
    bridge: String,
    worker: LossSourceBridgeAck,
    controller: LossSourceBridgeAck,
    worker_observed_at: u64,
    controller_observed_at: u64,
    service: (String, String, String, u64, u64),
    mac: [u8; 32],
}
fn loss_bridge_table(db: &rusqlite::Connection) -> Result<bool, &'static str> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='channel_loss_source_bridge')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")
}
impl EnteredLossSourceBridge {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(key, b"diffuser-entered-loss-source-bridge/v1\0", &v)
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        value_digest(self)
    }
    fn returned(
        &self,
        db: &rusqlite::Connection,
        keys: &ChannelKeys,
    ) -> Result<WorkerLossReturn, &'static str> {
        let (_, epochs) = transport_epochs(db)?;
        let Some(TransportTransition::EnteredLoss(h)) = epochs.last() else {
            return Err("evidence_invalid");
        };
        self.verify_history(h, keys)?;
        Ok(*h.clone())
    }
    fn verify_history(&self, h: &WorkerLossReturn, keys: &ChannelKeys) -> Result<(), &'static str> {
        h.verify_history(&keys.custody)?;
        let body = verify_source_observation(&keys.authority, &h.previous, self.frame.as_bytes())?;
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
        verify_source_ack(
            &keys.reply,
            &h.previous,
            "controller",
            &body,
            &self.controller_source_ack,
        )?;
        if self.kind != "diffuser-entered-loss-source-bridge/v1"
            || self.returned != h.digest()?
            || self.previous != h.previous
            || self.binding != h.binding
            || self.sequence != h.authority_sequence + 1
            || self.sequence >= 128
            || self.prefix != h.worker_authority
            || self.historical != h.source_bridge
            || v["sequence"].as_u64() != Some(self.sequence)
            || self.controller_source_ack.sequence != self.sequence
            || self.settlement != h.resolution
            || self.cleanup != h.cleanup
            || self.released_at != h.cleanup_consumed_at
            || self.service != h.service
            || self.issued_at < self.released_at
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 1500
            || !bool::from(self.signature(&keys.custody)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        for (role, head, history) in [
            ("worker", &self.worker, &self.worker_history),
            ("controller", &self.controller, &self.controller_history),
        ] {
            if head.body.role != role
                || head.body.binding != self.binding
                || head.body.phase != "complete"
                || head.body.sequence != h.high_water() + 1
                || history.len() != 64
                || hex::decode(history).is_err()
            {
                return Err("evidence_invalid");
            }
            if !bool::from(
                typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", &head.body)?
                    .ct_eq(&head.mac),
            ) {
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
    fn fresh(&self, now: u64) -> Result<(), &'static str> {
        if now < self.issued_at || now >= self.expires_at {
            Err("evidence_invalid")
        } else {
            Ok(())
        }
    }
    fn verify_role(
        &self,
        root: &std::fs::File,
        role: &str,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.fresh(now)?;
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        let h = self.returned(&db, keys)?;
        let (head, history) = match role {
            "worker" => (&self.worker, &self.worker_history),
            "controller" => (&self.controller, &self.controller_history),
            _ => return Err("evidence_invalid"),
        };
        let (f, a): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if f != serde_json::to_vec(head).map_err(|_| "evidence_invalid")?
            || checkpoint_bytes_digest(&db, head.body.revision, head.body.revision)? != *history
            || transport_state_digest(&db, &self.binding)? != head.body.state_digest
            || state_custody::state_digest(root)? != *h.anchor(role)?.3
            || (role == "worker"
                && transport_authority_digest(&db, h.authority_sequence)? != self.prefix)
            || loss_bridge_table(&db)?
        {
            return Err("evidence_invalid");
        }
        let a: CheckpointAck = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
        a.verify(&keys.custody, head)?;
        verify_transport_chain(&db, head, &keys.reply, &keys.custody)?;
        // Prove actual original consumption from retained checkpoint ACKs,
        // without renewing its first-use interval or comparing a later root.
        h.verify_consumed_frontier(&db, role, keys, now)?;
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds exact transport/source/service histories and consumed release before fencing."
    )]
    pub(super) fn prepare(
        h: &WorkerLossReturn,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        controller: &CustodyLedger,
        worker: &CustodyLedger,
        service: &mut state_custody::Ledger,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Self, &'static str> {
        use std::io::Read;
        h.verify_installed_transport(croot, wroot, keys, now)?;
        let anchor = service.entered_loss_return_anchor(croot)?;
        if anchor != h.service {
            return Err("evidence_invalid");
        }
        let mut bytes = Vec::new();
        super::la_artifacts::open_artifact(
            &service.loss_return_root()?,
            &format!("service-authority-{:03}.json", h.authority_sequence + 1),
            libc::O_RDONLY,
        )
        .map_err(|_| "evidence_invalid")?
        .take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "evidence_invalid")?;
        if bytes.len() > 16384 || hex::encode(Sha256::digest(&bytes)) != h.source_bridge {
            return Err("evidence_invalid");
        }
        let (source, ack): (WorkerLossSource, SourceAck) =
            serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        let (wa, _, wh) = worker.completed_anchor(wroot)?;
        let (ca, _, ch) = controller.completed_anchor(croot)?;
        let mut v = Self {
            kind: "diffuser-entered-loss-source-bridge/v1".into(),
            returned: h.digest()?,
            previous: h.previous.clone(),
            binding: h.binding.clone(),
            sequence: h.authority_sequence + 1,
            prefix: h.worker_authority.clone(),
            historical: h.source_bridge.clone(),
            frame: String::from_utf8(source.frame).map_err(|_| "evidence_invalid")?,
            controller_source_ack: ack,
            settlement: h.resolution.clone(),
            cleanup: h.cleanup.clone(),
            released_at: h.cleanup_consumed_at,
            worker: wa,
            worker_history: wh,
            controller: ca,
            controller_history: ch,
            service: anchor,
            issued_at: now,
            expires_at: now.checked_add(1500).ok_or("evidence_invalid")?,
            mac: [0; 32],
        };
        v.mac = v.signature(&keys.custody)?;
        v.verify_role(wroot, "worker", keys, wall_now()?)?;
        v.verify_role(croot, "controller", keys, wall_now()?)?;
        service.prepare_entered_loss_source_bridge(croot, &v)?;
        Ok(v)
    }
    fn ack(&self, role: &str, keys: &ChannelKeys) -> Result<LossSourceBridgeAck, &'static str> {
        if !matches!(role, "worker" | "controller") {
            return Err("evidence_invalid");
        }
        let mut a = LossSourceBridgeAck {
            bridge: self.digest()?,
            role: role.into(),
            binding: self.binding.clone(),
            sequence: self.sequence,
            mac: [0; 32],
        };
        a.mac = typed_mac(
            &keys.reply,
            b"diffuser-entered-loss-source-bridge-role-ack/v1\0",
            &(&a.bridge, &a.role, &a.binding, a.sequence),
        )?;
        Ok(a)
    }
    fn verify_ack(
        &self,
        role: &str,
        keys: &ChannelKeys,
        ack: &LossSourceBridgeAck,
    ) -> Result<(), &'static str> {
        if serde_json::to_vec(&self.ack(role, keys)?).map_err(|_| "evidence_invalid")?
            != serde_json::to_vec(ack).map_err(|_| "evidence_invalid")?
        {
            return Err("evidence_invalid");
        };
        Ok(())
    }
    fn install(
        &self,
        channel: &mut TransportJournal,
        keys: &ChannelKeys,
        role: &str,
    ) -> Result<LossSourceBridgeAck, &'static str> {
        channel.check()?;
        self.verify_role(&channel.root, role, keys, wall_now()?)?;
        if channel.binding != self.binding {
            return Err("evidence_invalid");
        }
        let ack = self.ack(role, keys)?;
        let bytes = serde_json::to_vec(self).map_err(|_| "evidence_invalid")?;
        if bytes.len() > 12288 {
            return Err("evidence_invalid");
        }
        let tx = channel
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE channel_loss_source_bridge(sequence INTEGER PRIMARY KEY,body BLOB NOT NULL,ack BLOB NOT NULL,completion BLOB);").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO channel_loss_source_bridge VALUES(?1,?2,?3,NULL)",
            rusqlite::params![
                self.sequence as i64,
                bytes,
                serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.fresh(wall_now()?)?;
        Ok(ack)
    }
    fn installed_ack(
        &self,
        root: &std::fs::File,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<LossSourceBridgeAck, &'static str> {
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        self.returned(&db, keys)?;
        let (body, ack): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT body,ack FROM channel_loss_source_bridge WHERE sequence=?1",
                [self.sequence as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM channel_loss_source_bridge", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        if count != 1 || body != serde_json::to_vec(self).map_err(|_| "evidence_invalid")? {
            return Err("evidence_invalid");
        }
        let ack: LossSourceBridgeAck =
            serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
        self.verify_ack(role, keys, &ack)?;
        Ok(ack)
    }
    pub(super) fn complete(
        &self,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        service: &mut state_custody::Ledger,
        keys: &ChannelKeys,
    ) -> Result<LossSourceBridgeCompletion, &'static str> {
        service.complete_entered_loss_source_bridge(croot, wroot, self, keys)
    }
    pub(super) fn verify_complete(
        &self,
        croot: &std::fs::File,
        wroot: &std::fs::File,
        service: &mut state_custody::Ledger,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        let w = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        let c = super::la_store::open_pinned_readonly_database(croot, "controller-channel.sqlite")?;
        let (_, wc) = verified_loss_source_bridge(&w, keys)?.ok_or("evidence_invalid")?;
        let (_, cc) = verified_loss_source_bridge(&c, keys)?.ok_or("evidence_invalid")?;
        if value_digest(&wc)? != value_digest(&cc)? || wc.bridge != self.digest()? {
            return Err("evidence_invalid");
        }
        service.finish_entered_loss_source_bridge(self, &wc)?;
        Ok(())
    }
}
impl LossSourceBridgeCompletion {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(
            key,
            b"diffuser-entered-loss-source-bridge-consumed/v1\0",
            &v,
        )
    }
    fn verify(
        &self,
        cap: &EnteredLossSourceBridge,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        cap.verify_ack("worker", keys, &self.worker)?;
        cap.verify_ack("controller", keys, &self.controller)?;
        if self.bridge != cap.digest()?
            || self.worker_observed_at < cap.issued_at
            || self.controller_observed_at < self.worker_observed_at
            || self.controller_observed_at >= cap.expires_at
            || self.controller_observed_at > now
            || self.service.3 != cap.service.3 + 1
            || self.service.4 != cap.sequence
            || self.service.1 != cap.service.1
            || !bool::from(self.signature(&keys.custody)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        };
        Ok(())
    }
    fn install(
        &self,
        channel: &mut TransportJournal,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        channel.check()?;
        let bytes: Vec<u8> = channel
            .db
            .query_row("SELECT body FROM channel_loss_source_bridge", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        let cap: EnteredLossSourceBridge =
            serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        cap.returned(&channel.db, keys)?;
        self.verify(&cap, keys, wall_now()?)?;
        let role = channel.name.trim_end_matches("-channel.sqlite");
        let own: Vec<u8> = channel
            .db
            .query_row("SELECT ack FROM channel_loss_source_bridge", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        let ack: LossSourceBridgeAck =
            serde_json::from_slice(&own).map_err(|_| "evidence_invalid")?;
        cap.verify_ack(role, keys, &ack)?;
        let changed=channel.db.execute("UPDATE channel_loss_source_bridge SET completion=?1 WHERE sequence=?2 AND completion IS NULL",rusqlite::params![serde_json::to_vec(self).map_err(|_|"evidence_invalid")?,cap.sequence as i64]).map_err(|_|"storage_unavailable")?;
        if changed != 1 {
            return Err("evidence_invalid");
        };
        Ok(())
    }
}
fn verified_loss_source_bridge(
    db: &rusqlite::Connection,
    keys: &ChannelKeys,
) -> Result<Option<(EnteredLossSourceBridge, LossSourceBridgeCompletion)>, &'static str> {
    if !loss_bridge_table(db)? {
        return Ok(None);
    }
    let (sequence, bytes, ack, complete): (i64, Vec<u8>, Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT sequence,body,ack,completion FROM channel_loss_source_bridge",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|_| "evidence_invalid")?;
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM channel_loss_source_bridge", [], |r| {
            r.get(0)
        })
        .map_err(|_| "evidence_invalid")?;
    if count != 1 || bytes.len() > 12288 || ack.len() > 4096 || complete.len() > 4096 {
        return Err("evidence_invalid");
    }
    let cap: EnteredLossSourceBridge =
        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
    let h = cap.returned(db, keys)?;
    let (f, a): (Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT frame,ack FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| "evidence_invalid")?;
    let f: SignedCheckpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
    let a: CheckpointAck = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
    a.verify(&keys.custody, &f)?;
    if f.body.binding != h.binding || transport_state_digest(db, &h.binding)? != f.body.state_digest
    {
        return Err("evidence_invalid");
    };
    verify_transport_chain(db, &f, &keys.reply, &keys.custody)?;
    let completion: LossSourceBridgeCompletion =
        serde_json::from_slice(&complete).map_err(|_| "evidence_invalid")?;
    completion.verify(&cap, keys, wall_now()?)?;
    let role: String = db
        .query_row("SELECT role FROM channel_identity", [], |r| r.get(0))
        .map_err(|_| "evidence_invalid")?;
    let ack: LossSourceBridgeAck = serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
    cap.verify_ack(role.trim_end_matches("-channel.sqlite"), keys, &ack)?;
    if sequence != cap.sequence as i64 || cap.sequence != h.authority_sequence + 1 {
        return Err("evidence_invalid");
    }
    // Every logical history reader authenticates the entire old prefix too.
    h.verify_consumed_frontier(
        db,
        role.trim_end_matches("-channel.sqlite"),
        keys,
        wall_now()?,
    )?;
    let (frontier, prior) = if role == "worker-channel.sqlite" {
        (&cap.worker, &cap.worker_history)
    } else {
        (&cap.controller, &cap.controller_history)
    };
    let current: i64 = db
        .query_row("SELECT MAX(revision) FROM channel_checkpoints", [], |r| {
            r.get(0)
        })
        .map_err(|_| "evidence_invalid")?;
    let saved: Vec<u8> = db
        .query_row(
            "SELECT frame FROM channel_checkpoints WHERE revision=?1",
            [frontier.body.revision as i64],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    if saved != serde_json::to_vec(frontier).map_err(|_| "evidence_invalid")?
        || checkpoint_bytes_digest(
            db,
            u64::try_from(current).map_err(|_| "evidence_invalid")?,
            frontier.body.revision,
        )? != *prior
    {
        return Err("evidence_invalid");
    }
    if role == "worker-channel.sqlite"
        && ordinary_authority_prefix(db, h.authority_sequence)? != cap.prefix
    {
        return Err("evidence_invalid");
    }
    Ok(Some((cap, completion)))
}
fn ordinary_authority_prefix(
    db: &rusqlite::Connection,
    expected: u64,
) -> Result<String, &'static str> {
    let mut hash = Sha256::new();
    hash.update(b"diffuser-transport-authority-history/v1\0");
    for n in 1..=expected {
        let (time, body, frame): (i64, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT observed_at,body,frame FROM channel_authority WHERE sequence=?1",
                [n as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if n > 128 || body.len() > 12288 || frame.len() > 12288 {
            return Err("evidence_invalid");
        }
        hash.update((n as i64).to_be_bytes());
        hash.update(time.to_be_bytes());
        hash.update((body.len() as u64).to_be_bytes());
        hash.update(body);
        hash.update((frame.len() as u64).to_be_bytes());
        hash.update(frame);
    }
    Ok(hex::encode(hash.finalize()))
}
impl WorkerLossReturn {
    fn verify_consumed_frontier(
        &self,
        db: &rusqlite::Connection,
        role: &str,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.verify_history(&keys.custody)?;
        self.installed_resolution(db, &keys.custody)?;
        let (old, _, prefix, _) = self.anchor(role)?;
        let (f, a): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints WHERE revision=?1",
                [(old.body.revision + 1) as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let f: SignedCheckpoint = serde_json::from_slice(&f).map_err(|_| "evidence_invalid")?;
        let a: CheckpointAck = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
        a.verify(&keys.custody, &f)?;
        let p = a.loss_consumption.as_ref().ok_or("evidence_invalid")?;
        p.verify_window(
            &keys.custody,
            &self.digest()?,
            self.issued_at,
            self.expires_at,
            now,
        )?;
        let current: i64 = db
            .query_row("SELECT MAX(revision) FROM channel_checkpoints", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        if checkpoint_bytes_digest(
            db,
            u64::try_from(current).map_err(|_| "evidence_invalid")?,
            old.body.revision,
        )? != prefix
            || f.body.previous != old.digest()?
            || f.body.binding != self.binding
            || f.body.phase != "handoff"
            || f.body.sequence != self.high_water()
            || p.kind != format!("loss_{role}")
            || p.checkpoint != f.digest()?
        {
            return Err("evidence_invalid");
        };
        Ok(())
    }
}
impl WorkerRpc {
    pub(super) fn install_loss_source_bridge(
        &mut self,
        bytes: &[u8],
    ) -> Result<serde_json::Value, &'static str> {
        let cap: EnteredLossSourceBridge =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let ack = cap.install(&mut self.channel, &self.keys, "worker")?;
        Ok(serde_json::json!({"kind":"LOSS_SOURCE_BRIDGE_INSTALLED","ack":ack,"admitted":false}))
    }
    pub(super) fn complete_loss_source_bridge(
        &mut self,
        bytes: &[u8],
    ) -> Result<serde_json::Value, &'static str> {
        let complete: LossSourceBridgeCompletion =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        complete.install(&mut self.channel, &self.keys)?;
        Ok(
            serde_json::json!({"kind":"LOSS_SOURCE_BRIDGE_COMMITTED","digest":value_digest(&complete)?,"admitted":false}),
        )
    }
}
impl WorkerClient {
    pub(super) fn install_loss_source_bridge(
        &mut self,
        cap: &EnteredLossSourceBridge,
        domain: &state_custody::Session,
    ) -> Result<serde_json::Value, &'static str> {
        // Service handoff is deliberately consumed-loss/no-pending, separate
        // from completed-only worker_handoff's one pending Close predicate.
        cap.verify_role(&self.channel.root, "controller", &self.keys, wall_now()?)?;
        domain.install_loss_source_handoff(cap, &self.keys)?;
        let ack = cap.install(&mut self.channel, &self.keys, "controller")?;
        Ok(serde_json::json!({"kind":"LOSS_SOURCE_BRIDGE_INSTALLED","ack":ack,"admitted":false}))
    }
    pub(super) fn complete_loss_source_bridge(
        &mut self,
        bytes: &[u8],
    ) -> Result<serde_json::Value, &'static str> {
        let complete: LossSourceBridgeCompletion =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        complete.install(&mut self.channel, &self.keys)?;
        Ok(
            serde_json::json!({"kind":"LOSS_SOURCE_BRIDGE_COMMITTED","digest":value_digest(&complete)?,"admitted":false}),
        )
    }
    pub(super) fn verified_loss_source_binding(&self) -> Result<ChannelBinding, &'static str> {
        let (cap, _) =
            verified_loss_source_bridge(&self.channel.db, &self.keys)?.ok_or("evidence_invalid")?;
        Ok(cap.binding)
    }
}

// Ordinary rows retain their exact bytes. Only a completely consumed typed
// bridge contributes the historical missing sequence to logical source history.
type WorkerSourceRow = (i64, i64, Vec<u8>, Vec<u8>);
fn logical_worker_sources(
    db: &rusqlite::Connection,
    keys: &ChannelKeys,
) -> Result<Vec<WorkerSourceRow>, &'static str> {
    let bridge = verified_loss_source_bridge(db, keys)?;
    if bridge.is_none()
        && matches!(
            transport_epochs(db)?.1.last(),
            Some(TransportTransition::EnteredLoss(_))
        )
    {
        return Err("evidence_invalid");
    }

    let mut st=db.prepare("SELECT sequence,observed_at,body,frame FROM channel_authority ORDER BY sequence LIMIT 129").map_err(|_|"evidence_invalid")?;
    let mut rows: Vec<WorkerSourceRow> = st
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|_| "evidence_invalid")?
        .collect::<Result<_, _>>()
        .map_err(|_| "evidence_invalid")?;
    if let Some((cap, _)) = &bridge {
        if rows.iter().any(|r| r.0 == cap.sequence as i64) {
            return Err("evidence_invalid");
        }
        let body = verify_source_observation(&keys.authority, &cap.previous, cap.frame.as_bytes())?;
        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
        let t = v["observed_at"].as_i64().ok_or("evidence_invalid")?;
        rows.push((cap.sequence as i64, t, body, cap.frame.as_bytes().to_vec()));
        rows.sort_by_key(|r| r.0);
    }
    let mut time = 0;
    for (i, (seq, t, body, frame)) in rows.iter().enumerate() {
        if *seq != (i + 1) as i64
            || *seq > 128
            || *t < time
            || body.len() > 12288
            || frame.len() > 12288
            || verify_source_observation(
                &keys.authority,
                &transport_authority_binding(db, *seq as u64)?,
                frame,
            )? != *body
        {
            return Err("evidence_invalid");
        }
        let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| "evidence_invalid")?;
        if v["sequence"].as_i64() != Some(*seq) || v["observed_at"].as_i64() != Some(*t) {
            return Err("evidence_invalid");
        };
        time = *t;
    }
    Ok(rows)
}

#[cfg(test)]
impl EnteredLossSourceBridge {
    pub(super) fn test_guards(
        &self,
        h: &WorkerLossReturn,
        keys: &ChannelKeys,
    ) -> Result<Vec<String>, &'static str> {
        self.verify_history(h, keys)?;
        let mut passed = Vec::new();
        for field in [
            "return_digest",
            "historical_tuple",
            "old_source_prefix",
            "released_at",
            "settlement",
            "cleanup",
            "sequence",
            "service_anchor",
            "worker_epoch",
            "controller_source_ack",
        ] {
            let mut v = self.clone();
            match field {
                "return_digest" => v.returned = "f".repeat(64),
                "historical_tuple" => v.historical = "f".repeat(64),
                "old_source_prefix" => v.prefix = "f".repeat(64),
                "released_at" => v.released_at += 1,
                "settlement" => v.settlement = "f".repeat(64),
                "cleanup" => v.cleanup = "f".repeat(64),
                "sequence" => v.sequence += 1,
                "service_anchor" => v.service.0 = "f".repeat(64),
                "worker_epoch" => v.binding.worker_epoch += 1,
                "controller_source_ack" => v.controller_source_ack.mac[0] ^= 1,
                _ => unreachable!(),
            }
            v.mac = v.signature(&keys.custody)?;
            if v.verify_history(h, keys).is_ok() {
                return Err("evidence_invalid");
            };
            passed.push(field.into());
        }
        Ok(passed)
    }
    pub(super) fn test_corrupt_mac(&self) -> Self {
        let mut v = self.clone();
        v.mac[0] ^= 1;
        v
    }
    pub(super) fn test_no_role_bridge(
        root: &std::fs::File,
        role: &str,
    ) -> Result<bool, &'static str> {
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        Ok(!loss_bridge_table(&db)?)
    }
}

/// Complete protocol proof for C's ordinary source append. This authenticates
/// the original C-only tuple without overwriting it or inventing an old W ACK.
pub(super) fn verify_controller_loss_source_bridge(
    root: &std::fs::File,
    binding: &ChannelBinding,
    keys: &ChannelKeys,
) -> Result<(), &'static str> {
    let channel =
        super::la_store::open_pinned_readonly_database(root, "controller-channel.sqlite")?;
    let (cap, _) = verified_loss_source_bridge(&channel, keys)?.ok_or("evidence_invalid")?;
    if cap.binding != *binding {
        return Err("evidence_invalid");
    }
    let claims = super::la_store::open_pinned_readonly_database(root, "lane_assignments.sqlite")?;
    let bytes: Vec<u8> = claims
        .query_row(
            "SELECT body FROM la_worker_loss_sources WHERE sequence=?1",
            [cap.sequence as i64],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    let historical: WorkerLossSource =
        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
    let body = historical.verify(keys, historical.issued_at)?;
    let saved: Vec<u8> = claims
        .query_row(
            "SELECT body FROM la_authority_observations WHERE sequence=?1",
            [cap.sequence as i64],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    if historical.binding != cap.previous
        || historical.frame != cap.frame.as_bytes()
        || body != saved
        || hex::encode(Sha256::digest(
            serde_json::to_vec(&(historical, &cap.controller_source_ack))
                .map_err(|_| "evidence_invalid")?,
        )) != cap.historical
    {
        return Err("evidence_invalid");
    };
    Ok(())
}

/// Retires only the independently settled execution identity from LIVE
/// occupancy. Its original started row, reservation and retained input remain.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SpentLossDisposition {
    binding: ChannelBinding,
    returned: String,
    bridge: String,
    settlement: String,
    cleanup: String,
    released_at: u64,
    pub(super) command: InspectCommand,
    pub(super) previous_boot: String,
    pub(super) generation: u64,
    pub(super) sequence: u64,
    pub(super) fence: u64,
    pub(super) retained: String,
    pub(super) retained_bytes: u64,
    worker_state: String,
    controller_state: String,
    worker: SignedCheckpoint,
    worker_history: String,
    controller: SignedCheckpoint,
    controller_history: String,
    authority: u64,
    authority_history: String,
    service: (String, String, String, u64, u64),
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}
impl SpentLossDisposition {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(key, b"diffuser-spent-entered-loss-disposition/v1\0", &v)
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        value_digest(self)
    }
    pub(super) fn binding(&self) -> &ChannelBinding {
        &self.binding
    }
    fn verify_history(&self, root: &std::fs::File, keys: &ChannelKeys) -> Result<(), &'static str> {
        let db = super::la_store::open_pinned_readonly_database(root, "worker-channel.sqlite")?;
        let (bridge, complete) =
            verified_loss_source_bridge(&db, keys)?.ok_or("evidence_invalid")?;
        let h = bridge.returned(&db, keys)?;
        let response: Vec<u8> = db
            .query_row(
                "SELECT response FROM channel_log WHERE sequence=?1",
                [h.high_water() as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let loss: WorkerLossSettlement =
            serde_json::from_slice(&response).map_err(|_| "evidence_invalid")?;
        loss.verify_history(keys)?;
        if self.binding != h.binding
            || self.returned != h.digest()?
            || self.bridge != value_digest(&complete)?
            || self.settlement != h.resolution
            || self.cleanup != h.cleanup
            || self.released_at != h.cleanup_consumed_at
            || self.previous_boot != h.previous.worker_boot
            || self.generation != h.binding.worker_epoch
            || self.generation != h.previous.worker_epoch + 1
            || self.fence != loss.command.fence
            || self.command != loss.command
            || self.sequence == 0
            || self.sequence > 512
            || self.retained_bytes == 0
            || self.retained_bytes > RPC_INPUT_MAX as u64
            || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 1500
            || !bool::from(self.signature(&keys.custody)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn fresh(&self, now: u64) -> Result<(), &'static str> {
        if now < self.issued_at || now >= self.expires_at {
            Err("evidence_invalid")
        } else {
            Ok(())
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds independent release, all retained role histories, exact execution identity and current authority."
    )]
    pub(super) fn issue(
        h: &WorkerLossReturn,
        wroot: &std::fs::File,
        croot: &std::fs::File,
        worker: &CustodyLedger,
        controller: &CustodyLedger,
        service: &state_custody::Ledger,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<Self, &'static str> {
        let db = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        let (_, completion) = verified_loss_source_bridge(&db, keys)?.ok_or("evidence_invalid")?;
        let response: Vec<u8> = db
            .query_row(
                "SELECT response FROM channel_log WHERE sequence=?1",
                [h.high_water() as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let loss: WorkerLossSettlement =
            serde_json::from_slice(&response).map_err(|_| "evidence_invalid")?;
        loss.verify_history(keys)?;
        let w = super::la_store::open_pinned_readonly_database(wroot, "worker.sqlite")?;
        let c = super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        let (old_boot, seq, fence): (String, i64, i64) = w
            .query_row(
                "SELECT boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let exact:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM la_worker_cursor WHERE worker=?1 AND boot=?2 AND sequence=?3) AND EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts WHERE assignment_id=?4 AND digest=?5 AND released_at=?6) AND EXISTS(SELECT 1 FROM la_jobs WHERE id=?7 AND assignment_id=?4 AND state='failed' AND result_artifact IS NULL) AND NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges)",rusqlite::params![h.binding.worker,old_boot,seq,loss.command.assignment,h.cleanup,h.cleanup_consumed_at as i64,loss.command.job],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if !exact || old_boot != h.previous.worker_boot || fence != loss.command.fence as i64 {
            return Err("evidence_invalid");
        }
        let rows = logical_worker_sources(&db, keys)?;
        let authority = rows.last().ok_or("evidence_invalid")?.0 as u64;
        let (retained, retained_bytes) =
            super::la_worker::retained_loss_identity(&w, wroot, &loss.command)?;
        let (wa, _, wh) = worker.completed_anchor(wroot)?;
        let (ca, _, ch) = controller.completed_anchor(croot)?;
        let anchor = service.entered_loss_return_anchor(croot)?;
        if authority != anchor.4
            || authority <= h.authority_sequence + 1
            || wa.body.sequence != ca.body.sequence
        {
            return Err("evidence_invalid");
        }
        let mut v = Self {
            binding: h.binding.clone(),
            returned: h.digest()?,
            bridge: value_digest(&completion)?,
            settlement: h.resolution.clone(),
            cleanup: h.cleanup.clone(),
            released_at: h.cleanup_consumed_at,
            command: loss.command,
            previous_boot: old_boot,
            generation: h.binding.worker_epoch,
            sequence: u64::try_from(seq).map_err(|_| "evidence_invalid")?,
            fence: u64::try_from(fence).map_err(|_| "evidence_invalid")?,
            retained,
            retained_bytes,
            worker_state: state_custody::state_digest(wroot)?,
            controller_state: state_custody::state_digest(croot)?,
            worker: wa,
            worker_history: wh,
            controller: ca,
            controller_history: ch,
            authority,
            authority_history: value_digest(&rows)?,
            service: anchor,
            issued_at: now,
            expires_at: now.checked_add(1500).ok_or("evidence_invalid")?,
            mac: [0; 32],
        };
        v.mac = v.signature(&keys.custody)?;
        v.verify_before(wroot, "worker", keys, now)?;
        v.verify_before(croot, "controller", keys, now)?;
        Ok(v)
    }
    fn verify_before(
        &self,
        root: &std::fs::File,
        role: &str,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        self.fresh(now)?;
        if !bool::from(self.signature(&keys.custody)?.ct_eq(&self.mac)) {
            return Err("evidence_invalid");
        }
        let (anchor, history, state) = match role {
            "worker" => (&self.worker, &self.worker_history, &self.worker_state),
            "controller" => (
                &self.controller,
                &self.controller_history,
                &self.controller_state,
            ),
            _ => return Err("evidence_invalid"),
        };
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        let (f, a): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let a: CheckpointAck = serde_json::from_slice(&a).map_err(|_| "evidence_invalid")?;
        a.verify(&keys.custody, anchor)?;
        if f != serde_json::to_vec(anchor).map_err(|_| "evidence_invalid")?
            || checkpoint_bytes_digest(&db, anchor.body.revision, anchor.body.revision)? != *history
            || state_custody::state_digest(root)? != *state
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, anchor, &keys.reply, &keys.custody)?;
        if role == "worker" {
            self.verify_history(root, keys)?;
            self.verify_worker_identity(root, keys)?;
            let rows = logical_worker_sources(&db, keys)?;
            if value_digest(&rows)? != self.authority_history {
                return Err("evidence_invalid");
            };
            let last = rows.last().ok_or("evidence_invalid")?;
            if last.0 as u64 != self.authority
                || last.1 < 0
                || last.1 as u64 > now
                || now - last.1 as u64 >= 1500
            {
                return Err("evidence_stale");
            }
        }
        Ok(())
    }
    pub(super) fn verify_worker_identity(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        self.verify_history(root, keys)?;
        let db = super::la_store::open_pinned_readonly_database(root, "worker.sqlite")?;
        super::la_worker::verify_session_history(&db, &keys.reply)?;
        let cursor:(String,String,i64,i64,i64)=db.query_row("SELECT worker,boot,sequence,fence,(SELECT generation FROM worker_session_generations WHERE boot=?1) FROM worker_session_snapshots WHERE sequence=?2 AND boot=?1",rusqlite::params![self.previous_boot,self.sequence as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|_|"evidence_invalid")?;
        let high: i64 = db
            .query_row(
                "SELECT MAX(sequence) FROM worker_session_snapshots WHERE boot=?1",
                [&self.previous_boot],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if cursor
            != (
                self.binding.worker.clone(),
                self.previous_boot.clone(),
                self.sequence as i64,
                self.fence as i64,
                self.generation as i64 - 1,
            )
            || high != self.sequence as i64
        {
            return Err("evidence_invalid");
        }
        let (digest, bytes) = super::la_worker::retained_loss_identity(&db, root, &self.command)?;
        if digest != self.retained || bytes != self.retained_bytes {
            return Err("evidence_invalid");
        };
        Ok(())
    }
}

impl WorkerClient {
    pub(super) fn dispose_entered_loss(
        &mut self,
        cap: &SpentLossDisposition,
        domain: &state_custody::Session,
    ) -> Result<serde_json::Value, &'static str> {
        cap.verify_before(&self.channel.root, "controller", &self.keys, wall_now()?)?;
        let (head, state) = domain.activation_anchor()?;
        if (head, state) != (cap.service.0.clone(), cap.controller_state.clone())
            || domain.binding()? != cap.binding
        {
            return Err("evidence_invalid");
        }
        let op = domain.begin(&cap.digest()?)?;
        match self.call(
            WorkerOperation::DisposeEnteredLoss(Box::new(cap.clone())),
            &[],
        )? {
            WorkerReply::LossDisposed { disposition } if disposition == cap.digest()? => {
                domain.complete(op, &disposition)?;
                Ok(
                    serde_json::json!({"kind":"ENTERED_LOSS_DISPOSED","disposition":disposition,"admitted":false}),
                )
            }
            _ => Err("evidence_invalid"),
        }
    }
}

/// P records actual durable W disposition and C service consumption. This
/// witness has its own domain; it cannot satisfy source or admission predicates.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SpentLossConsumption {
    disposition: String,
    binding: ChannelBinding,
    worker: SignedCheckpoint,
    controller: SignedCheckpoint,
    service: (String, String, String, u64, u64),
    worker_observed_at: u64,
    controller_observed_at: u64,
    mac: [u8; 32],
}
impl SpentLossConsumption {
    fn signature(&self, key: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(key, b"diffuser-spent-entered-loss-consumed/v1\0", &v)
    }
    fn verify(
        &self,
        cap: &SpentLossDisposition,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        if self.disposition != cap.digest()?
            || self.binding != cap.binding
            || self.worker_observed_at < cap.issued_at
            || self.controller_observed_at < self.worker_observed_at
            || self.controller_observed_at >= cap.expires_at
            || self.controller_observed_at > now
            || self.worker.body.sequence != cap.worker.body.sequence + 1
            || self.controller.body.sequence != cap.controller.body.sequence + 1
            || self.service.3 != cap.service.3 + 2
            || self.service.4 != cap.authority
            || self.worker.body.binding != cap.binding
            || self.controller.body.binding != cap.binding
            || self.worker.body.phase != "complete"
            || self.controller.body.phase != "complete"
            || !bool::from(self.signature(&keys.custody)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        };
        Ok(())
    }
}
impl SpentLossDisposition {
    pub(super) fn witness_consumed(
        &self,
        wroot: &std::fs::File,
        croot: &std::fs::File,
        worker: &CustodyLedger,
        controller: &CustodyLedger,
        service: &state_custody::Ledger,
        keys: &ChannelKeys,
    ) -> Result<SpentLossConsumption, &'static str> {
        use std::io::Write;
        self.fresh(wall_now()?)?;
        self.verify_worker_identity(wroot, keys)?;
        let w = super::la_store::open_pinned_readonly_database(wroot, "worker.sqlite")?;
        let bytes: Vec<u8> = w
            .query_row(
                "SELECT body FROM worker_spent_losses WHERE operation=?1 AND assignment=?2",
                rusqlite::params![self.command.operation, self.command.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if bytes != serde_json::to_vec(self).map_err(|_| "evidence_invalid")? {
            return Err("evidence_invalid");
        }
        let (wa, _, _) = worker.completed_anchor(wroot)?;
        let wt = wall_now()?;
        let (ca, _, _) = controller.completed_anchor(croot)?;
        let anchor = service.entered_loss_return_anchor(croot)?;
        let ct = wall_now()?;
        for (role, root, head) in [("worker", wroot, &wa), ("controller", croot, &ca)] {
            let db = super::la_store::open_pinned_readonly_database(
                root,
                &format!("{role}-channel.sqlite"),
            )?;
            let (request, response): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT request,response FROM channel_log WHERE sequence=?1",
                    [head.body.sequence as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let request: SignedRequest =
                serde_json::from_slice(&request).map_err(|_| "evidence_invalid")?;
            let response: SignedResponse =
                serde_json::from_slice(&response).map_err(|_| "evidence_invalid")?;
            if !matches!(request.request.operation,WorkerOperation::DisposeEnteredLoss(ref c) if c.digest().ok()==self.digest().ok())
                || !matches!(response.response.reply,WorkerReply::LossDisposed{ref disposition} if disposition==&self.digest().unwrap_or_default())
            {
                return Err("evidence_invalid");
            }
            let old = if role == "worker" {
                &self.worker
            } else {
                &self.controller
            };
            let prefix = if role == "worker" {
                &self.worker_history
            } else {
                &self.controller_history
            };
            if checkpoint_bytes_digest(&db, head.body.revision, old.body.revision)? != *prefix {
                return Err("evidence_invalid");
            }
        }
        let sd = super::la_store::open_pinned_readonly_database(croot, "service-custody.sqlite")?;
        if state_custody::service_request_digest(&sd, anchor.3)?
            != (self.digest()?, Some(self.digest()?))
        {
            return Err("evidence_invalid");
        }
        let mut v = SpentLossConsumption {
            disposition: self.digest()?,
            binding: self.binding.clone(),
            worker: wa,
            controller: ca,
            service: anchor,
            worker_observed_at: wt,
            controller_observed_at: ct,
            mac: [0; 32],
        };
        v.mac = v.signature(&keys.custody)?;
        v.verify(self, keys, wall_now()?)?;
        let mut f = super::la_artifacts::open_artifact(
            &service.loss_return_root()?,
            &format!("spent-loss-consumed-{:04}.json", self.binding.worker_epoch),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| "evidence_invalid")?;
        f.write_all(&serde_json::to_vec(&v).map_err(|_| "evidence_invalid")?)
            .and_then(|_| f.sync_all())
            .map_err(|_| "storage_unavailable")?;
        service
            .loss_return_root()?
            .sync_all()
            .map_err(|_| "storage_unavailable")?;
        self.fresh(wall_now()?)?;
        Ok(v)
    }
    pub(super) fn verified_retirement(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
    ) -> Result<bool, &'static str> {
        let db = super::la_store::open_pinned_readonly_database(root, "worker-channel.sqlite")?;
        let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='channel_spent_loss_consumption')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if !table {
            return Ok(false);
        }
        let (body,count):(Vec<u8>,i64)=db.query_row("SELECT body,(SELECT COUNT(*) FROM channel_spent_loss_consumption) FROM channel_spent_loss_consumption WHERE disposition=?1",[self.digest()?],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|"evidence_invalid")?;
        if count != 1 || body.len() > 4096 {
            return Err("evidence_invalid");
        }
        let proof: SpentLossConsumption =
            serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
        proof.verify(self, keys, wall_now()?)?;
        let current: i64 = db
            .query_row("SELECT MAX(revision) FROM channel_checkpoints", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        let saved: Vec<u8> = db
            .query_row(
                "SELECT frame FROM channel_checkpoints WHERE revision=?1",
                [proof.worker.body.revision as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if saved != serde_json::to_vec(&proof.worker).map_err(|_| "evidence_invalid")?
            || current < proof.worker.body.revision as i64
        {
            return Err("evidence_invalid");
        };
        Ok(true)
    }
}
impl WorkerRpc {
    pub(super) fn commit_spent_loss(
        &mut self,
        bytes: &[u8],
    ) -> Result<serde_json::Value, &'static str> {
        self.channel.check()?;
        let proof: SpentLossConsumption =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        let cap = self.journal.spent_loss(&proof.disposition)?;
        cap.verify_worker_identity(&self.channel.root, &self.keys)?;
        proof.verify(&cap, &self.keys, wall_now()?)?;
        // This is the independently witnessed historical commit, never work or
        // admission. Missing/altered/time-invalid evidence retains live counts.
        let tx = self
            .channel
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE channel_spent_loss_consumption(disposition TEXT PRIMARY KEY,body BLOB NOT NULL)").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO channel_spent_loss_consumption VALUES(?1,?2)",
            rusqlite::params![proof.disposition, bytes],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        let occupancy = self.journal.verified_occupancy()?;
        if occupancy.live_reservations != 0
            || occupancy.live_operations != 0
            || occupancy.retained_bytes != cap.retained_bytes
        {
            return Err("evidence_invalid");
        }
        Ok(
            serde_json::json!({"kind":"SPENT_LOSS_COMMITTED","disposition":cap.digest()?,"live_reservations":occupancy.live_reservations,"live_operations":occupancy.live_operations,"retained_bytes":occupancy.retained_bytes,"admitted":false}),
        )
    }
}

#[cfg(test)]
impl SpentLossDisposition {
    pub(super) fn test_corrupt_mac(&self) -> Self {
        let mut v = self.clone();
        v.mac[0] ^= 1;
        v
    }
}
#[cfg(test)]
impl SpentLossConsumption {
    pub(super) fn test_corrupt_mac(&self) -> Self {
        let mut v = self.clone();
        v.mac[0] ^= 1;
        v
    }
}

#[cfg(test)]
mod loss_return_admission_tests {
    use super::*;

    #[test]
    fn distinct_loss_return_install_reply_has_its_own_wire_contract() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "kind": "LossReturnInstalled",
            "receipt": {"admission": "ab".repeat(32), "installed_at": 1000,
                        "mac": vec![7u8; 32]}
        }))
        .unwrap();
        let parsed = serde_json::from_slice::<WorkerReply>(&bytes);
        assert!(
            parsed.is_ok(),
            "distinct loss-return install reply must decode without a completed-only cast"
        );
        assert_eq!(
            serde_json::to_value(parsed.unwrap()).unwrap()["kind"],
            "LossReturnInstalled"
        );
    }
}

/// A distinct, quarantined entered-loss install. It grants no execution or
/// ordinary admission. Final activation separately consumes P's independently
/// fsynced global linearization and the exact completed-copy root transitions.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossReturnAdmission {
    binding: ChannelBinding,
    resource: qualification::Certificate,
    spent: SpentLossDisposition,
    consumed: SpentLossConsumption,
    worker: LossReturnRole,
    controller: LossReturnRole,
    service: (String, String, String, u64, u64),
    source_history: String,
    processes: LossReturnProcessPins,
    authority: LossReturnAuthority,
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LossReturnRole {
    device: u64,
    inode: u64,
    state: String,
    checkpoint: SignedCheckpoint,
    history: String,
    physical_bytes: u64,
    physical_manifest: String,
}
/// Fixed four-role observation, never an arbitrary role/path selector. Values
/// retain the existing bounded process-snapshot contracts in their entirety.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossReturnProcesses {
    worker_ready: serde_json::Value,
    controller_ready: serde_json::Value,
    worker: serde_json::Value,
    controller: serde_json::Value,
    parent: serde_json::Value,
    keeper: serde_json::Value,
    observed_at: u64,
}

// Unlike owned-state hashing, storage accounting includes transport/service
// SQLite, journals and retained histories. Both logical sizes and allocated
// blocks count; a tiny logical occupancy cannot erase retained physical input.
fn loss_return_physical(root: &std::fs::File) -> Result<(u64, String), &'static str> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    fn visit(
        root: &std::fs::File,
        prefix: &str,
        rows: &mut Vec<(String, u64, u64, u64, u64)>,
        total: &mut u64,
    ) -> Result<(), &'static str> {
        let mut names = std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))
            .map_err(|_| "evidence_invalid")?
            .take(257)
            .map(|e| e.map(|e| e.file_name()).map_err(|_| "evidence_invalid"))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        if names.len() > 256 {
            return Err("evidence_invalid");
        }
        for name in names {
            let name = name.to_str().ok_or("evidence_invalid")?;
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || rows.len() >= 256
            {
                return Err("evidence_invalid");
            }
            let f = super::la_artifacts::open_artifact(root, name, libc::O_RDONLY)
                .map_err(|_| "evidence_invalid")?;
            let m = f.metadata().map_err(|_| "evidence_invalid")?;
            if m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o022 != 0
                || (!m.is_dir() && (!m.is_file() || m.nlink() != 1))
            {
                return Err("evidence_invalid");
            }
            let path = format!("{prefix}{name}");
            let allocated = m.blocks().checked_mul(512).ok_or("evidence_invalid")?;
            *total = total
                .checked_add(m.len().max(allocated))
                .ok_or("evidence_invalid")?;
            rows.push((path.clone(), m.dev(), m.ino(), m.len(), allocated));
            if m.is_dir() {
                visit(&f, &format!("{path}/"), rows, total)?;
            }
        }
        Ok(())
    }
    let mut rows = Vec::new();
    let mut total = 0;
    visit(root, "", &mut rows, &mut total)?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err("evidence_invalid");
    }
    let stat = unsafe { stat.assume_init() };
    // One bounded new input plus conservative SQLite/history headroom. Resource
    // qualification still supplies all original per-role storage constraints.
    let required = total
        .checked_add(RPC_INPUT_MAX as u64)
        .and_then(|v| v.checked_add(1_048_576))
        .ok_or("evidence_invalid")?;
    if stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .is_none_or(|free| free < required)
    {
        return Err("evidence_invalid");
    }
    Ok((total, value_digest(&rows)?))
}
fn loss_return_reject(guard: &str, rejected: bool) -> bool {
    #[cfg(test)]
    recovery_trace(
        "loss_admission_actual_predicate",
        serde_json::json!({"guard":guard,"rejected":rejected}),
    );
    #[cfg(not(test))]
    let _ = guard;
    rejected
}
impl LossReturnAdmission {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(&keys.custody, b"diffuser-loss-return-admission/v1\0", &v)
    }
    pub(super) fn digest(&self) -> Result<String, &'static str> {
        value_digest(self)
    }
    pub(super) fn binding(&self) -> &ChannelBinding {
        &self.binding
    }
    pub(super) fn cursor(&self) -> (&str, u64, u64, u64) {
        (
            &self.spent.previous_boot,
            self.spent.generation,
            self.spent.sequence,
            self.spent.fence,
        )
    }
    pub(super) fn command(&self) -> &InspectCommand {
        &self.spent.command
    }
    pub(super) fn cleanup(&self) -> (&str, u64) {
        (&self.spent.cleanup, self.spent.released_at)
    }
    pub(super) fn verify_envelope(&self, keys: &ChannelKeys, now: u64) -> Result<(), &'static str> {
        self.binding.validate()?;
        // Authenticate this new domain before evaluating nested historical
        // counters. Altered unsigned JSON cannot reach old proof arithmetic.
        if serde_json::to_vec(self)
            .map_err(|_| "evidence_invalid")?
            .len()
            > 15360
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        self.authority
            .verify(self.service.4, now, self.expires_at)?;
        self.resource.verify(&self.binding, keys, now)?;
        self.consumed.verify(&self.spent, keys, now)?;
        if self.binding != self.spent.binding
            || self.consumed.binding != self.binding
            || self.binding.worker_epoch != 2
            || self.binding.controller_epoch != 1
            || self.spent.generation != 2
            || self.spent.sequence != 2
            || self.spent.fence != 1
            || self.spent.previous_boot == self.binding.worker_boot
            || self.spent.released_at == 0
            || self.spent.released_at > self.issued_at
            || self.consumed.controller_observed_at > self.issued_at
            || self.issued_at > now
            || now >= self.expires_at
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 1500
            || self.expires_at > self.resource.expires_at()
            || self.processes.observed_at > self.issued_at
            || now - self.processes.observed_at >= 1500
            || self.worker.checkpoint.body.binding != self.binding
            || self.controller.checkpoint.body.binding != self.binding
            || self.worker.checkpoint.body.role != "worker"
            || self.controller.checkpoint.body.role != "controller"
            || self.worker.checkpoint.body.phase != "complete"
            || self.controller.checkpoint.body.phase != "complete"
            || self.worker.checkpoint.body.sequence != 9
            || self.controller.checkpoint.body.sequence != 9
            || self
                .worker
                .checkpoint
                .body
                .revision
                .checked_add(2)
                .is_none_or(|n| n > CHECKPOINT_MAX)
            || self
                .controller
                .checkpoint
                .body
                .revision
                .checked_add(2)
                .is_none_or(|n| n > CHECKPOINT_MAX)
            || self.service.4 < 6
            || self.service.4 > 128
            || self.service.3.checked_add(6).is_none_or(|n| n > 1025)
            || self.worker.physical_bytes < self.spent.retained_bytes
            || self.spent.retained_bytes == 0
            || self.worker.physical_bytes == 0
            || self.controller.physical_bytes == 0
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn verify_role(
        &self,
        root: &std::fs::File,
        role: &str,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        self.verify_envelope(keys, now)?;
        let snapshot = match role {
            "worker" => &self.worker,
            "controller" => &self.controller,
            _ => return Err("evidence_invalid"),
        };
        let meta = root.metadata().map_err(|_| "evidence_invalid")?;
        if (meta.dev(), meta.ino()) != (snapshot.device, snapshot.inode)
            || state_custody::state_digest(root)? != snapshot.state
            || loss_return_physical(root)?
                != (snapshot.physical_bytes, snapshot.physical_manifest.clone())
        {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        let (frame, ack): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let ack: CheckpointAck = serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
        ack.verify(&keys.custody, &snapshot.checkpoint)?;
        if frame != serde_json::to_vec(&snapshot.checkpoint).map_err(|_| "evidence_invalid")?
            || checkpoint_bytes_digest(
                &db,
                snapshot.checkpoint.body.revision,
                snapshot.checkpoint.body.revision,
            )? != snapshot.history
            || transport_state_digest(&db, &self.binding)? != snapshot.checkpoint.body.state_digest
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, &snapshot.checkpoint, &keys.reply, &keys.custody)?;
        let (_, epochs) = transport_epochs(&db)?;
        let Some(TransportTransition::EnteredLoss(h)) = epochs.last() else {
            return Err("evidence_invalid");
        };
        h.verify_history(&keys.custody)?;
        if h.digest()? != self.spent.returned {
            return Err("evidence_invalid");
        }
        if role == "worker" {
            self.verify_retained_worker(root, keys)?;
            let rows = logical_worker_sources(&db, keys)?;
            let last = rows.last().ok_or("evidence_invalid")?;
            if value_digest(&rows)? != self.source_history
                || last.0 as u64 != self.service.4
                || last.1 < 0
                || last.1 as u64 > now
                || now - last.1 as u64 >= 1500
            {
                return Err("evidence_stale");
            }
        }
        Ok(())
    }
    pub(super) fn verify_retained_worker(
        &self,
        root: &std::fs::File,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        self.spent.verify_worker_identity(root, keys)?;
        if !self.spent.verified_retirement(root, keys)? {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_readonly_database(root, "worker-channel.sqlite")?;
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT body FROM channel_spent_loss_consumption WHERE disposition=?1",
                [self.spent.digest()?],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if bytes != serde_json::to_vec(&self.consumed).map_err(|_| "evidence_invalid")? {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    pub(super) fn worker_ack(
        &self,
        keys: &ChannelKeys,
        installed_at: u64,
    ) -> Result<[u8; 32], &'static str> {
        self.verify_envelope(keys, installed_at)?;
        typed_mac(
            &keys.reply,
            b"diffuser-loss-return-worker-install/v1\0",
            &(self.digest()?, installed_at),
        )
    }
    pub(super) fn verify_worker_ack(
        &self,
        keys: &ChannelKeys,
        installed_at: u64,
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        if !bool::from(self.worker_ack(keys, installed_at)?.ct_eq(mac)) {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    /// P's intent is exclusive and fsynced. The intent grants no admission;
    /// only separate authenticated final consumption may install a role lease.
    pub(super) fn persist_intent(
        &self,
        parent: &std::fs::File,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        self.verify_envelope(keys, wall_now()?)?;
        loss_return_write(parent, "loss-return-admission-intent.json", self)?;
        self.verify_envelope(keys, wall_now()?)
    }
}
fn loss_return_write<T: serde::Serialize>(
    root: &std::fs::File,
    name: &str,
    value: &T,
) -> Result<(), &'static str> {
    use std::io::Write;
    let bytes = serde_json::to_vec(value).map_err(|_| "evidence_invalid")?;
    if bytes.len() > RPC_JSON_MAX {
        return Err("evidence_invalid");
    }
    let mut f = super::la_artifacts::open_artifact(
        root,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )
    .map_err(|_| "evidence_invalid")?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .and_then(|_| root.sync_all())
        .map_err(|_| "storage_unavailable")
}

impl LossReturnAdmission {
    #[expect(
        clippy::too_many_arguments,
        reason = "P binds four current process observations and both complete durable role histories."
    )]
    pub(super) fn prepare(
        spent: &SpentLossDisposition,
        resource: qualification::Certificate,
        processes: LossReturnProcesses,
        wroot: &std::fs::File,
        croot: &std::fs::File,
        worker: &CustodyLedger,
        controller: &CustodyLedger,
        service: &state_custody::Ledger,
        keys: &ChannelKeys,
        authority: &super::lane_assignment::DiscoveryContext,
    ) -> Result<Self, &'static str> {
        use std::os::unix::fs::MetadataExt;
        let now = wall_now()?;
        let binding = spent.binding();
        resource.verify(binding, keys, now).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"resource"}),
            )
        })?;
        spent.verify_worker_identity(wroot, keys).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"retained_worker_identity"}),
            )
        })?;
        if !spent.verified_retirement(wroot, keys).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"retirement"}),
            )
        })? {
            return Err("evidence_invalid");
        }
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        let bytes: Vec<u8> = wd
            .query_row(
                "SELECT body FROM channel_spent_loss_consumption WHERE disposition=?1",
                [spent.digest()?],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let consumed: SpentLossConsumption =
            serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        consumed.verify(spent, keys, now).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"consumed_disposition"}),
            )
        })?;
        let (bridge, _) = verified_loss_source_bridge(&wd, keys)?.ok_or("evidence_invalid")?;
        let returned = bridge.returned(&wd, keys)?;
        let loss: Vec<u8> = wd
            .query_row(
                "SELECT response FROM channel_log WHERE sequence=?1",
                [returned.high_water() as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let loss: WorkerLossSettlement =
            serde_json::from_slice(&loss).map_err(|_| "evidence_invalid")?;
        loss.verify_history(keys).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"original_loss_history"}),
            )
        })?;
        let wm = wroot.metadata().map_err(|_| "evidence_invalid")?;
        let cm = croot.metadata().map_err(|_| "evidence_invalid")?;
        verify_admission_process(
            &processes.worker_ready,
            &processes.worker,
            "worker",
            binding,
            &wm,
        )
        .inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"worker_process"}),
            )
        })?;
        verify_admission_process(
            &processes.controller_ready,
            &processes.controller,
            "controller",
            binding,
            &cm,
        )
        .inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"controller_process"}),
            )
        })?;
        for (snapshot, role, old) in [
            (&processes.parent, "p", &loss.survivors["witness"]),
            (&processes.keeper, "k", &loss.survivors["keeper"]),
        ] {
            qualification::snapshot(snapshot, role, &binding.executable_digest, false, None)?;
            if &snapshot["identity"] != old {
                return Err("evidence_invalid");
            }
        }
        if processes.worker["identity"] != returned.returning.new_identity
            || processes.controller["identity"] != loss.survivors["controller"]
            || processes.worker_ready["pid"] != returned.returning.namespace_pid
            || processes.controller["status"]
                .as_str()
                .and_then(|v| v.lines().find_map(|l| l.strip_prefix("NSpid:")))
                .and_then(|v| v.split_whitespace().last())
                .and_then(|v| v.parse::<u64>().ok())
                != processes.controller_ready["pid"].as_u64()
            || loss_return_reject("observation_future", processes.observed_at > now)
            || loss_return_reject("observation_expired", now - processes.observed_at >= 1500)
        {
            return Err("evidence_invalid");
        }
        let rows = logical_worker_sources(&wd, keys)?;
        let last = rows.last().ok_or("evidence_invalid")?;
        if last.1 < 0 || last.1 as u64 > now || now - last.1 as u64 >= 1500 {
            return Err("evidence_stale");
        }
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        verify_loss_return_claims(&claims, spent)?;
        // Re-authenticate the consumed historical certificate at its ORIGINAL
        // release clock. The old strict pre-bridge verifier is unchanged.
        let certificate: Vec<u8> = claims
            .query_row(
                "SELECT certificate FROM la_assignment_cleanup_receipts WHERE assignment_id=?1",
                [&spent.command.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let certificate: cleanup::Certificate =
            serde_json::from_slice(&certificate).map_err(|_| "evidence_invalid")?;
        let original = certificate.verify(&returned.previous, keys, croot, spent.released_at)?;
        if loss_return_reject("original_certificate_version", original.version != 2)
            || loss_return_reject(
                "original_certificate_loss",
                certificate
                    .loss
                    .as_ref()
                    .is_none_or(|l| l.digest().ok() != Some(loss.digest().unwrap_or_default())),
            )
            || loss_return_reject(
                "original_certificate_assignment",
                original.claim.assignment != spent.command.assignment,
            )
            || loss_return_reject(
                "original_certificate_boot",
                original.claim.boot != spent.previous_boot,
            )
            || loss_return_reject(
                "original_certificate_fence",
                original.claim.fence != spent.fence,
            )
            || loss_return_reject(
                "original_certificate_sequence",
                original.claim.sequence != spent.sequence,
            )
            || loss_return_reject(
                "actual_loss_scope",
                authority.loss_scope.as_ref()
                    != Some(&(spent.command.job.clone(), spent.command.assignment.clone())),
            )
        {
            return Err("evidence_invalid");
        }
        let source_count: i64 = claims
            .query_row("SELECT COUNT(*) FROM la_authority_observations", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        if loss_return_reject("source_history_count", source_count != rows.len() as i64) {
            return Err("evidence_invalid");
        }
        for (sequence, _, body, _) in &rows {
            let (saved, mac): (Vec<u8>, Vec<u8>) = claims
                .query_row(
                    "SELECT body,mac FROM la_authority_observations WHERE sequence=?1",
                    [sequence],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let mac: [u8; 32] = mac.try_into().map_err(|_| "evidence_invalid")?;
            verify_authority_observation(&keys.authority, &saved, &mac)?;
            if saved != *body {
                return Err("evidence_invalid");
            }
        }
        let (wa, _, wh) = worker.completed_anchor(wroot).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"worker_completed_anchor"}),
            )
        })?;
        let (ca, _, ch) = controller.completed_anchor(croot).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"controller_completed_anchor"}),
            )
        })?;
        let anchor = service.entered_loss_return_anchor(croot).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"service_completed_anchor"}),
            )
        })?;
        if anchor.4 != last.0 as u64 || worker.binding != *binding || controller.binding != *binding
        {
            return Err("evidence_invalid");
        }
        let (wp, wdigest) = loss_return_physical(wroot).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"worker_physical"}),
            )
        })?;
        let (cp, cdigest) = loss_return_physical(croot).inspect_err(|_| {
            recovery_trace(
                "loss_admission_actual_refusal",
                serde_json::json!({"phase":"controller_physical"}),
            )
        })?;
        // Issue only after the expensive independent readbacks. All original
        // observation clocks remain unchanged and cap the first-use deadline.
        let now = wall_now()?;
        let expires_at = now
            .checked_add(1500)
            .ok_or("evidence_invalid")?
            .min(resource.expires_at())
            .min(
                processes
                    .observed_at
                    .checked_add(1500)
                    .ok_or("evidence_invalid")?,
            )
            .min(
                authority
                    .observed_at
                    .checked_add(1500)
                    .ok_or("evidence_invalid")?,
            )
            .min(
                (last.1 as u64)
                    .checked_add(1500)
                    .ok_or("evidence_invalid")?,
            );
        let mut cap = Self {
            binding: binding.clone(),
            resource,
            spent: spent.clone(),
            consumed,
            worker: LossReturnRole {
                device: wm.dev(),
                inode: wm.ino(),
                state: state_custody::state_digest(wroot)?,
                checkpoint: wa,
                history: wh,
                physical_bytes: wp,
                physical_manifest: wdigest,
            },
            controller: LossReturnRole {
                device: cm.dev(),
                inode: cm.ino(),
                state: state_custody::state_digest(croot)?,
                checkpoint: ca,
                history: ch,
                physical_bytes: cp,
                physical_manifest: cdigest,
            },
            service: anchor,
            source_history: value_digest(&rows)?,
            processes: LossReturnProcessPins::capture(&processes)?,
            authority: LossReturnAuthority::capture(authority),
            issued_at: now,
            expires_at,
            mac: [0; 32],
        };
        cap.mac = cap.signature(keys)?;
        cap.verify_role(wroot, "worker", keys, wall_now()?)
            .inspect_err(|_| {
                recovery_trace(
                    "loss_admission_actual_refusal",
                    serde_json::json!({"phase":"new_worker_role"}),
                )
            })?;
        cap.verify_role(croot, "controller", keys, wall_now()?)
            .inspect_err(|_| {
                recovery_trace(
                    "loss_admission_actual_refusal",
                    serde_json::json!({"phase":"new_controller_role"}),
                )
            })?;
        loss_return_write_processes(&service.loss_return_root()?, &processes)?;
        cap.persist_intent(&service.loss_return_root()?, keys)?;
        Ok(cap)
    }
}
pub(super) fn verify_loss_return_claims(
    db: &rusqlite::Connection,
    spent: &SpentLossDisposition,
) -> Result<(), &'static str> {
    let exact:bool=db.query_row("SELECT NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges) AND EXISTS(SELECT 1 FROM la_worker_cursor WHERE worker=?1 AND boot=?2 AND sequence=?3) AND (SELECT MAX(fence) FROM la_assignments WHERE worker=?1)=?4 AND EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts WHERE assignment_id=?5 AND digest=?6 AND released_at=?7) AND EXISTS(SELECT 1 FROM la_jobs WHERE id=?8 AND assignment_id=?5 AND state='failed' AND result_artifact IS NULL) AND (SELECT COUNT(*) FROM la_assignments)=1 AND (SELECT COUNT(*) FROM la_jobs)=1",rusqlite::params![spent.binding.worker,spent.previous_boot,spent.sequence as i64,spent.fence as i64,spent.command.assignment,spent.cleanup,spent.released_at as i64,spent.command.job],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
    if !exact {
        return Err("evidence_invalid");
    }
    let cert: Vec<u8> = db
        .query_row(
            "SELECT certificate FROM la_assignment_cleanup_receipts WHERE assignment_id=?1",
            [&spent.command.assignment],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    if hex::encode(Sha256::digest(cert)) != spent.cleanup {
        return Err("evidence_invalid");
    }
    Ok(())
}

impl WorkerClient {
    pub(super) fn install_loss_return(
        &mut self,
        cap: &LossReturnAdmission,
        claims: &mut super::la_store::ClaimStore,
        domain: &state_custody::Session,
    ) -> Result<serde_json::Value, &'static str> {
        cap.verify_role(&self.channel.root, "controller", &self.keys, wall_now()?)?;
        if domain.binding()? != cap.binding
            || domain.activation_anchor()? != (cap.service.0.clone(), cap.controller.state.clone())
        {
            return Err("evidence_invalid");
        }
        // This service intent remains outstanding if W or C installation fails.
        let operation = domain.begin(&cap.digest()?)?;
        let reply = self.call(WorkerOperation::AdmitLossReturn(Box::new(cap.clone())), &[])?;
        let WorkerReply::LossReturnInstalled {
            admission,
            installed_at,
            mac,
        } = reply
        else {
            return Err("evidence_invalid");
        };
        if admission != cap.digest()? {
            return Err("evidence_invalid");
        }
        cap.verify_worker_ack(&self.keys, installed_at, &mac)?;
        claims.install_loss_return(cap, &self.keys, installed_at, &mac, wall_now()?)?;
        domain.complete(operation, &cap.digest()?)?;
        cap.verify_envelope(&self.keys, wall_now()?)?;
        Ok(
            serde_json::json!({"kind":"LOSS_RETURN_INSTALLED_QUARANTINED","admission":cap.digest()?,"admitted":false}),
        )
    }
}

impl LossReturnAdmission {
    pub(super) fn verify_claims(&self, db: &rusqlite::Connection) -> Result<(), &'static str> {
        verify_loss_return_claims(db, &self.spent)
    }
    pub(super) fn verify_controller_store(
        &self,
        root: &std::fs::File,
        db: &rusqlite::Connection,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        if (m.dev(), m.ino()) != (self.controller.device, self.controller.inode)
            || state_custody::state_digest(root)? != self.controller.state
        {
            return Err("evidence_invalid");
        }
        self.verify_claims(db)
    }
    pub(super) fn controller_ack(
        &self,
        keys: &ChannelKeys,
        worker_at: u64,
        worker_ack: &[u8; 32],
        now: u64,
    ) -> Result<[u8; 32], &'static str> {
        self.verify_envelope(keys, now)?;
        self.verify_worker_ack(keys, worker_at, worker_ack)?;
        if worker_at > now {
            return Err("evidence_invalid");
        }
        typed_mac(
            &keys.reply,
            b"diffuser-loss-return-controller-install/v1\0",
            &(self.digest()?, worker_at, worker_ack, now),
        )
    }
}

/// P's whole-record completion is distinct from a W ACK and from activation.
/// It authenticates durable installs and the actual completed service operation.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossReturnCompletion {
    admission: String,
    binding: ChannelBinding,
    worker: SignedCheckpoint,
    controller: SignedCheckpoint,
    worker_history: String,
    controller_history: String,
    worker_installed_at: u64,
    worker_ack: [u8; 32],
    controller_installed_at: u64,
    controller_ack: [u8; 32],
    service: (String, String, String, u64, u64),
    worker_observed_at: u64,
    controller_observed_at: u64,
    mac: [u8; 32],
}
impl LossReturnCompletion {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(&keys.custody, b"diffuser-loss-return-completion/v1\0", &v)
    }
    fn verify(
        &self,
        cap: &LossReturnAdmission,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        // FIRST receipt of completion must retain current authority. Historical
        // install clocks never refresh this original capability's deadline.
        cap.verify_envelope(keys, now)?;
        cap.verify_worker_ack(keys, self.worker_installed_at, &self.worker_ack)?;
        let cack = cap.controller_ack(
            keys,
            self.worker_installed_at,
            &self.worker_ack,
            self.controller_installed_at,
        )?;
        if self.admission != cap.digest()?
            || self.binding != cap.binding
            || self.worker.body.binding != self.binding
            || self.controller.body.binding != self.binding
            || self.worker.body.role != "worker"
            || self.controller.body.role != "controller"
            || self.worker.body.phase != "complete"
            || self.controller.body.phase != "complete"
            || self.worker.body.sequence != 10
            || self.controller.body.sequence != 10
            || self.worker.body.revision != cap.worker.checkpoint.body.revision + 2
            || self.controller.body.revision != cap.controller.checkpoint.body.revision + 2
            || self.service.3 != cap.service.3 + 2
            || self.service.4 != cap.service.4
            || self.worker_installed_at > self.controller_installed_at
            || self.controller_installed_at > self.worker_observed_at
            || self.worker_observed_at > self.controller_observed_at
            || self.controller_observed_at > now
            || self.controller_observed_at >= cap.expires_at
            || !bool::from(cack.ct_eq(&self.controller_ack))
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}
impl LossReturnAdmission {
    pub(super) fn witness_installed(
        &self,
        wroot: &std::fs::File,
        croot: &std::fs::File,
        worker: &CustodyLedger,
        controller: &CustodyLedger,
        service: &state_custody::Ledger,
        keys: &ChannelKeys,
    ) -> Result<LossReturnCompletion, &'static str> {
        let now = wall_now()?;
        self.verify_envelope(keys, now)?;
        // Independently retain and reauthenticate the exact original current
        // process observation; this is not a new observation or a clock refresh.
        use std::io::Read;
        let mut bytes = Vec::new();
        super::la_artifacts::open_artifact(
            &service.loss_return_root()?,
            "loss-return-admission-processes.json",
            libc::O_RDONLY,
        )
        .map_err(|_| "evidence_invalid")?
        .take(RPC_INPUT_MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "evidence_invalid")?;
        if bytes.len() > RPC_INPUT_MAX {
            return Err("evidence_invalid");
        }
        let processes: LossReturnProcesses =
            serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        if LossReturnProcessPins::capture(&processes)? != self.processes {
            return Err("evidence_invalid");
        }
        self.verify_retained_worker(wroot, keys)?;
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker.sqlite")?;
        let cd = super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        let (wbytes,wt,wm):(Vec<u8>,i64,Vec<u8>)=wd.query_row("SELECT capability,installed_at,ack FROM worker_loss_return_installs WHERE admission=?1",[self.digest()?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"evidence_invalid")?;
        let (cbytes,cwt,cwm,ct,cm):(Vec<u8>,i64,Vec<u8>,i64,Vec<u8>)=cd.query_row("SELECT capability,worker_installed_at,worker_ack,installed_at,ack FROM la_loss_return_installs WHERE admission=?1",[self.digest()?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|_|"evidence_invalid")?;
        let saved = serde_json::to_vec(self).map_err(|_| "evidence_invalid")?;
        if wbytes != saved || cbytes != saved || wt != cwt || wm != cwm || wt < 0 || ct < 0 {
            return Err("evidence_invalid");
        }
        super::la_worker::verify_session_history(&wd, &keys.reply)?;
        let cursor: (String, String, i64, i64) = wd
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let c_cursor: (String, i64) = cd
            .query_row(
                "SELECT boot,sequence FROM la_worker_cursor WHERE worker=?1",
                [&self.binding.worker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if cursor
            != (
                self.binding.worker.clone(),
                self.binding.worker_boot.clone(),
                2,
                1,
            )
            || c_cursor != (self.binding.worker_boot.clone(), 2)
        {
            return Err("evidence_invalid");
        }
        let (wa, _, wh) = worker.completed_anchor(wroot)?;
        let wnow = wall_now()?;
        let (ca, _, ch) = controller.completed_anchor(croot)?;
        let anchor = service.entered_loss_return_anchor(croot)?;
        for (role, root, old, prefix, head) in [
            (
                "worker",
                wroot,
                &self.worker.checkpoint,
                &self.worker.history,
                &wa,
            ),
            (
                "controller",
                croot,
                &self.controller.checkpoint,
                &self.controller.history,
                &ca,
            ),
        ] {
            let db = super::la_store::open_pinned_readonly_database(
                root,
                &format!("{role}-channel.sqlite"),
            )?;
            if checkpoint_bytes_digest(&db, head.body.revision, old.body.revision)? != *prefix {
                return Err("evidence_invalid");
            }
            let (request, response): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT request,response FROM channel_log WHERE sequence=10",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let request: SignedRequest =
                serde_json::from_slice(&request).map_err(|_| "evidence_invalid")?;
            let response: SignedResponse =
                serde_json::from_slice(&response).map_err(|_| "evidence_invalid")?;
            if !matches!(&request.request.operation,WorkerOperation::AdmitLossReturn(cap) if cap.digest().ok()==Some(self.digest()?))
                || !matches!(&response.response.reply,WorkerReply::LossReturnInstalled{admission,installed_at,mac} if admission==&self.digest()? && *installed_at==wt as u64 && mac.as_slice()==wm.as_slice())
            {
                return Err("evidence_invalid");
            }
        }
        let sd = super::la_store::open_pinned_readonly_database(croot, "service-custody.sqlite")?;
        if state_custody::service_request_digest(&sd, anchor.3)?
            != (self.digest()?, Some(self.digest()?))
        {
            return Err("evidence_invalid");
        }
        let mut proof = LossReturnCompletion {
            admission: self.digest()?,
            binding: self.binding.clone(),
            worker: wa,
            controller: ca,
            worker_history: wh,
            controller_history: ch,
            worker_installed_at: wt as u64,
            worker_ack: wm.try_into().map_err(|_| "evidence_invalid")?,
            controller_installed_at: ct as u64,
            controller_ack: cm.try_into().map_err(|_| "evidence_invalid")?,
            service: anchor,
            worker_observed_at: wnow,
            controller_observed_at: wall_now()?,
            mac: [0; 32],
        };
        proof.mac = proof.signature(keys)?;
        proof.verify(self, keys, wall_now()?)?;
        loss_return_write(
            &service.loss_return_root()?,
            "loss-return-admission-completion.json",
            &proof,
        )?;
        proof.verify(self, keys, wall_now()?)?;
        Ok(proof)
    }
}

#[cfg(test)]
mod loss_return_component_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Private signed synthetic fixture: no actual P/process observation, no
    // NEW held claim, no runtime qualification or full historical-chain proof.
    fn fixture() -> (LossReturnAdmission, ChannelKeys, u64) {
        let now = wall_now().unwrap() - 100;
        let keys = ChannelKeys {
            command: [11; 32],
            reply: [12; 32],
            authority: [13; 32],
            custody: [14; 32],
        };
        let binding = ChannelBinding {
            worker: "worker_admission_01".into(),
            worker_boot: "b".repeat(64),
            controller_boot: "c".repeat(64),
            worker_epoch: 2,
            controller_epoch: 1,
            hardware_generation: 1,
            profile_epoch: 1,
            policy_digest: "d".repeat(64),
            source_digest: "e".repeat(64),
            executable_digest: "f".repeat(64),
        };
        let checkpoint = |role: &str, seq, revision| {
            let body = ChannelCheckpoint {
                binding: binding.clone(),
                role: role.into(),
                revision,
                previous: "1".repeat(64),
                sequence: seq,
                phase: "complete".into(),
                root_dev: 1,
                root_inode: 2,
                db_dev: 1,
                db_inode: 3,
                state_digest: "2".repeat(64),
                owned_state: Some("3".repeat(64)),
            };
            let mac = typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", &body).unwrap();
            SignedCheckpoint { body, mac }
        };
        #[derive(serde::Serialize)]
        struct ResourceBody {
            version: u32,
            binding: ChannelBinding,
            evidence: String,
            issued_at: u64,
            expires_at: u64,
        }
        let body = ResourceBody {
            version: 1,
            binding: binding.clone(),
            evidence: "4".repeat(64),
            issued_at: now - 100,
            expires_at: now + 10000,
        };
        let resource:qualification::Certificate=serde_json::from_value(serde_json::json!({"mac":typed_mac(&keys.custody,b"diffuser-resource-qualification/v1\0",&body).unwrap(),"body":body})).unwrap();
        let mut spent = SpentLossDisposition {
            binding: binding.clone(),
            returned: "5".repeat(64),
            bridge: "6".repeat(64),
            settlement: "7".repeat(64),
            cleanup: "8".repeat(64),
            released_at: now - 1000,
            command: InspectCommand {
                backend: None,
                worker: binding.worker.clone(),
                boot: "a".repeat(64),
                assignment: "assignment_old_001".into(),
                operation: "execution_old_001".into(),
                job: "job_retained_old_01".into(),
                fence: 1,
                input_digest: hex::encode(Sha256::digest(b"retained synthetic input")),
                accepted_at: now - 2000,
                mandate_until: now - 500,
                permit_until: now - 500,
            },
            previous_boot: "a".repeat(64),
            generation: 2,
            sequence: 2,
            fence: 1,
            retained: "9".repeat(64),
            retained_bytes: 45,
            worker_state: "1".repeat(64),
            controller_state: "2".repeat(64),
            worker: checkpoint("worker", 8, 16),
            worker_history: "3".repeat(64),
            controller: checkpoint("controller", 8, 16),
            controller_history: "4".repeat(64),
            authority: 6,
            authority_history: "5".repeat(64),
            service: ("6".repeat(64), "2".repeat(64), "7".repeat(64), 20, 6),
            issued_at: now - 30,
            expires_at: now + 1000,
            mac: [0; 32],
        };
        spent.mac = spent.signature(&keys.custody).unwrap();
        let mut consumed = SpentLossConsumption {
            disposition: spent.digest().unwrap(),
            binding: binding.clone(),
            worker: checkpoint("worker", 9, 18),
            controller: checkpoint("controller", 9, 18),
            service: ("8".repeat(64), "2".repeat(64), "9".repeat(64), 22, 6),
            worker_observed_at: now - 20,
            controller_observed_at: now - 10,
            mac: [0; 32],
        };
        consumed.mac = consumed.signature(&keys.custody).unwrap();
        let role = |name: &str| LossReturnRole {
            device: 1,
            inode: 2,
            state: "2".repeat(64),
            checkpoint: checkpoint(name, 9, 18),
            history: "3".repeat(64),
            physical_bytes: 65536,
            physical_manifest: "4".repeat(64),
        };
        let mut cap = LossReturnAdmission {
            binding: binding.clone(),
            resource,
            spent,
            consumed,
            worker: role("worker"),
            controller: role("controller"),
            service: ("8".repeat(64), "2".repeat(64), "9".repeat(64), 22, 6),
            source_history: "5".repeat(64),
            processes: LossReturnProcessPins::capture(&LossReturnProcesses {
                worker_ready: serde_json::json!({}),
                controller_ready: serde_json::json!({}),
                worker: serde_json::json!({}),
                controller: serde_json::json!({}),
                parent: serde_json::json!({}),
                keeper: serde_json::json!({}),
                observed_at: now,
            })
            .unwrap(),
            authority: synthetic_authority(now),
            issued_at: now,
            expires_at: now + 1400,
            mac: [0; 32],
        };
        cap.mac = cap.signature(&keys).unwrap();
        cap.verify_envelope(&keys, now).unwrap_or_else(|e| {
            panic!(
                "synthetic capsule bytes={} verification={e}",
                serde_json::to_vec(&cap).unwrap().len()
            )
        });
        (cap, keys, now)
    }
    fn synthetic_authority(now: u64) -> LossReturnAuthority {
        LossReturnAuthority {
            tenant: "tenant_synthetic_01".into(),
            project: "project_synthetic_01".into(),
            sequence: 6,
            observed_at: now,
            freshness_ms: 1500,
            grants: vec![LossReturnGrant {
                id: "grant_synthetic_01".into(),
                parent: None,
                tenant: "tenant_synthetic_01".into(),
                project: "project_synthetic_01".into(),
                actor: "actor_synthetic_001".into(),
                bearer_digest: [19; 32],
                scopes: super::super::lane_assignment::loss_return_required_scopes(),
                can_delegate: true,
                enabled: true,
                member: true,
                revoked: false,
                not_before: now - 1000,
                access_expires: now + 10000,
                run_until: now + 10000,
                execution_ceiling: now + 10000,
                audience: "diffuser".into(),
            }],
        }
    }
    fn completion(cap: &LossReturnAdmission, keys: &ChannelKeys, now: u64) -> LossReturnCompletion {
        let mut w = cap.worker.checkpoint.clone();
        w.body.sequence = 10;
        w.body.revision += 2;
        w.mac = typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", &w.body).unwrap();
        let mut c = cap.controller.checkpoint.clone();
        c.body.sequence = 10;
        c.body.revision += 2;
        c.mac = typed_mac(&keys.reply, b"diffuser-custody-checkpoint/v1\0", &c.body).unwrap();
        let wm = cap.worker_ack(keys, now + 1).unwrap();
        let cm = cap.controller_ack(keys, now + 1, &wm, now + 2).unwrap();
        let mut proof = LossReturnCompletion {
            admission: cap.digest().unwrap(),
            binding: cap.binding.clone(),
            worker: w,
            controller: c,
            worker_history: "a".repeat(64),
            controller_history: "b".repeat(64),
            worker_installed_at: now + 1,
            worker_ack: wm,
            controller_installed_at: now + 2,
            controller_ack: cm,
            service: (
                "c".repeat(64),
                "d".repeat(64),
                "e".repeat(64),
                cap.service.3 + 2,
                cap.service.4,
            ),
            worker_observed_at: now + 3,
            controller_observed_at: now + 4,
            mac: [0; 32],
        };
        proof.mac = proof.signature(keys).unwrap();
        proof
    }
    fn root(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "loss-return-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    // This fixture drives real channel begin/complete, independent P custody,
    // ClaimStore installation and completion consumption. Admission/resource/
    // historical cleanup are the disclosed synthetic fixture above; sequence10
    // is a Probe, so this is deliberately NOT full RPC10/install qualification.
    #[test]
    fn loss_return_final_guard_preserves_exact_original_grant_charges() {
        let (cap, _keys, _) = fixture();
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE la_worker_session_generations(worker TEXT,generation INTEGER,body BLOB); CREATE TABLE la_assignment_grant_charges(assignment_id TEXT,grant_id TEXT); CREATE TABLE la_assignments(id TEXT,project TEXT,actor TEXT,state TEXT);").unwrap();
        let saved = serde_json::to_vec(&cap).unwrap();
        db.execute(
            "INSERT INTO la_worker_session_generations VALUES(?1,2,?2)",
            rusqlite::params![cap.binding.worker, saved],
        )
        .unwrap();
        let g = &cap.authority.grants[0];
        db.execute(
            "INSERT INTO la_assignments VALUES(?1,?2,?3,'closed')",
            rusqlite::params![cap.spent.command.assignment, g.project, g.actor],
        )
        .unwrap();
        db.execute(
            "INSERT INTO la_assignment_grant_charges VALUES(?1,?2)",
            rusqlite::params![cap.spent.command.assignment, g.id],
        )
        .unwrap();
        assert!(loss_return_controller_generation_guard(&db,&cap,&saved).unwrap(),"retained authenticated original grant charge is required audit history, never an active capacity charge");
        db.execute(
            "INSERT INTO la_assignment_grant_charges VALUES(?1,'foreign_grant_0001')",
            [&cap.spent.command.assignment],
        )
        .unwrap();
        assert!(!loss_return_controller_generation_guard(&db, &cap, &saved).unwrap());
        db.execute("DELETE FROM la_assignment_grant_charges", [])
            .unwrap();
        assert!(!loss_return_controller_generation_guard(&db, &cap, &saved).unwrap());
    }

    struct ControllerCopyFixture {
        path: std::path::PathBuf,
        parent_path: std::path::PathBuf,
        root: std::fs::File,
        store: super::super::la_store::ClaimStore,
        cap: LossReturnAdmission,
        proof: LossReturnCompletion,
        keys: ChannelKeys,
        channel: TransportJournal,
        ledger: std::sync::Arc<std::sync::Mutex<CustodyLedger>>,
        domain: Option<std::sync::Arc<state_custody::Session>>,
        service_ledger: Option<std::sync::Arc<std::sync::Mutex<state_custody::Ledger>>>,
        service_fail_revision: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }
    fn controller_copy_fixture() -> ControllerCopyFixture {
        controller_copy_fixture_inner(false)
    }
    fn controller_copy_fixture_inner(with_service: bool) -> ControllerCopyFixture {
        use std::sync::{Arc, Mutex, Weak};
        let (mut cap, keys, now) = fixture();
        let path = root("copy-controller");
        let parent_path = root("copy-parent");
        let root = std::fs::File::open(&path).unwrap();
        let parent = std::fs::File::open(&parent_path).unwrap();
        let mut store =
            super::super::la_store::ClaimStore::open(&path.join("lane_assignments.sqlite"))
                .unwrap();
        let db = rusqlite::Connection::open(path.join("lane_assignments.sqlite")).unwrap();
        let certificate = b"synthetic historical certificate bytes; not runtime evidence";
        cap.spent.cleanup = hex::encode(Sha256::digest(certificate));
        cap.spent.mac = cap.spent.signature(&keys.custody).unwrap();
        cap.consumed.disposition = cap.spent.digest().unwrap();
        cap.consumed.mac = cap.consumed.signature(&keys.custody).unwrap();
        db.execute("INSERT INTO la_assignments VALUES(?1,'project_retained_01','actor_retained_001',?2,1,'closed')",rusqlite::params![cap.spent.command.assignment,cap.binding.worker]).unwrap();
        db.execute("INSERT INTO la_jobs VALUES(?1,?2,'project_retained_01','actor_retained_001','input_retained_001','failed',1,NULL)",rusqlite::params![cap.spent.command.job,cap.spent.command.assignment]).unwrap();
        db.execute(
            "INSERT INTO la_worker_cursor VALUES(?1,?2,2)",
            rusqlite::params![cap.binding.worker, cap.spent.previous_boot],
        )
        .unwrap();
        db.execute(
            "INSERT INTO la_assignment_cleanup_receipts VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                cap.spent.command.assignment,
                cap.spent.cleanup,
                certificate.as_slice(),
                cap.spent.released_at as i64
            ],
        )
        .unwrap();
        let ledger = Arc::new(Mutex::new(
            CustodyLedger::bootstrap(
                &parent,
                &parent_path,
                cap.binding.clone(),
                "controller",
                keys.reply,
                keys.custody,
            )
            .unwrap(),
        ));
        let holder = Arc::new(Mutex::new(None::<Weak<CustodyLink>>));
        let callback = holder.clone();
        let observed = ledger.clone();
        let observed_root = root.try_clone().unwrap();
        let link = CustodyLink::new(
            cap.binding.clone(),
            "controller",
            keys.reply,
            keys.custody,
            Box::new(move |bytes| {
                let frame = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
                let ack = observed
                    .lock()
                    .map_err(|_| "storage_unavailable")?
                    .observe(&observed_root, &frame)?;
                callback
                    .lock()
                    .map_err(|_| "storage_unavailable")?
                    .as_ref()
                    .ok_or("evidence_invalid")?
                    .upgrade()
                    .ok_or("evidence_invalid")?
                    .accept(&serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?)
            }),
        )
        .unwrap();
        *holder.lock().unwrap() = Some(Arc::downgrade(&link));
        let mut channel = TransportJournal::create(
            &root,
            &path,
            "controller-channel.sqlite",
            cap.binding.clone(),
        )
        .unwrap();
        channel.enable_custody(link).unwrap();
        let probe = |channel: &mut TransportJournal, seq| {
            let request = RpcRequest {
                version: 1,
                binding: cap.binding.clone(),
                sequence: seq,
                input_digest: hex::encode(Sha256::digest([])),
                input_bytes: 0,
                operation: WorkerOperation::Probe,
            };
            let digest = rpc_content_digest(&request).unwrap();
            let signed = SignedRequest {
                mac: typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &request).unwrap(),
                request,
            };
            channel
                .begin(seq, &digest, &serde_json::to_vec(&signed).unwrap())
                .unwrap();
            let response = RpcResponse {
                version: 1,
                binding: cap.binding.clone(),
                sequence: seq,
                request_digest: digest.clone(),
                reply: WorkerReply::Refused {
                    code: "evidence_invalid".into(),
                },
            };
            let signed = SignedResponse {
                mac: typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &response).unwrap(),
                response,
            };
            channel
                .complete(seq, &digest, &serde_json::to_vec(&signed).unwrap())
                .unwrap();
        };
        for seq in 1..=9 {
            probe(&mut channel, seq);
        }
        cap.controller.checkpoint = ledger.lock().unwrap().completed_anchor(&root).unwrap().0;
        cap.controller.history = checkpoint_bytes_digest(&channel.db, 18, 18).unwrap();
        let meta = root.metadata().unwrap();
        cap.controller.device = meta.dev();
        cap.controller.inode = meta.ino();
        cap.controller.state = state_custody::state_digest(&root).unwrap();
        let service_fail_revision = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (domain, service_ledger) = if with_service {
            let witness = Arc::new(Mutex::new(
                state_custody::Ledger::new(&parent, cap.binding.clone(), &keys).unwrap(),
            ));
            let weak = Arc::new(Mutex::new(None::<Weak<state_custody::Link>>));
            let callback = weak.clone();
            let observed = witness.clone();
            let actual_root = root.try_clone().unwrap();
            let fault = service_fail_revision.clone();
            let link = state_custody::Link::new(
                cap.binding.clone(),
                &keys,
                Box::new(move |bytes| {
                    let v: serde_json::Value =
                        serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
                    if v["body"]["revision"].as_u64()
                        == Some(fault.load(std::sync::atomic::Ordering::SeqCst))
                    {
                        return Err("storage_unavailable");
                    }
                    let frame = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
                    let ack = observed
                        .lock()
                        .map_err(|_| "storage_unavailable")?
                        .observe(&actual_root, &frame)?;
                    callback
                        .lock()
                        .map_err(|_| "storage_unavailable")?
                        .as_ref()
                        .ok_or("evidence_invalid")?
                        .upgrade()
                        .ok_or("evidence_invalid")?
                        .accept(&serde_json::to_vec(&ack).map_err(|_| "evidence_invalid")?)
                }),
            )
            .unwrap();
            *weak.lock().unwrap() = Some(Arc::downgrade(&link));
            let domain = state_custody::Session::create(&root, link).unwrap();
            let (head, state) = domain.activation_anchor().unwrap();
            let sd = super::super::la_store::open_pinned_readonly_database(
                &root,
                "service-custody.sqlite",
            )
            .unwrap();
            cap.service = (
                head,
                state,
                state_custody::successor_history(&sd, 1).unwrap(),
                1,
                cap.service.4,
            );
            (Some(domain), Some(witness))
        } else {
            (None, None)
        };
        cap.mac = cap.signature(&keys).unwrap();
        let at = wall_now().unwrap();
        let ack = cap.worker_ack(&keys, at).unwrap();
        let install_op = domain
            .as_ref()
            .map(|d| d.begin(&cap.digest().unwrap()).unwrap());
        store
            .install_loss_return(&cap, &keys, at, &ack, at)
            .unwrap();
        if let Some(op) = install_op {
            domain
                .as_ref()
                .unwrap()
                .complete(op, &cap.digest().unwrap())
                .unwrap();
        }
        // Repeat the production channel path after the actual quarantined C install.
        let request = RpcRequest {
            version: 1,
            binding: cap.binding.clone(),
            sequence: 10,
            input_digest: hex::encode(Sha256::digest([])),
            input_bytes: 0,
            operation: WorkerOperation::Probe,
        };
        let digest = rpc_content_digest(&request).unwrap();
        let signed = SignedRequest {
            mac: typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &request).unwrap(),
            request,
        };
        channel
            .begin(10, &digest, &serde_json::to_vec(&signed).unwrap())
            .unwrap();
        let response = RpcResponse {
            version: 1,
            binding: cap.binding.clone(),
            sequence: 10,
            request_digest: digest.clone(),
            reply: WorkerReply::Refused {
                code: "evidence_invalid".into(),
            },
        };
        let signed = SignedResponse {
            mac: typed_mac(&keys.reply, b"diffuser-rpc-response/v1\0", &response).unwrap(),
            response,
        };
        channel
            .complete(10, &digest, &serde_json::to_vec(&signed).unwrap())
            .unwrap();
        let mut proof = completion(&cap, &keys, now);
        proof.worker_installed_at = at;
        proof.worker_ack = ack;
        proof.controller_installed_at = at;
        proof.controller_ack = cap.controller_ack(&keys, at, &ack, at).unwrap();
        let (head, _, history) = ledger.lock().unwrap().completed_anchor(&root).unwrap();
        proof.controller = head;
        proof.controller_history = history;
        proof.service.1 = state_custody::state_digest(&root).unwrap();
        if let Some(d) = domain.as_ref() {
            let (head, state) = d.activation_anchor().unwrap();
            let sd = super::super::la_store::open_pinned_readonly_database(
                &root,
                "service-custody.sqlite",
            )
            .unwrap();
            proof.service = (
                head,
                state,
                state_custody::successor_history(&sd, 3).unwrap(),
                3,
                cap.service.4,
            );
        }
        proof.worker_observed_at = wall_now().unwrap();
        proof.controller_observed_at = wall_now().unwrap();
        proof.mac = proof.signature(&keys).unwrap();
        proof.verify_for(&cap, &keys).unwrap();
        drop(db);
        ControllerCopyFixture {
            path,
            parent_path,
            root,
            store,
            cap,
            proof,
            keys,
            channel,
            ledger,
            domain,
            service_ledger,
            service_fail_revision,
        }
    }
    #[test]
    fn loss_return_real_controller_completion_uses_service_owned_root() {
        let mut f = controller_copy_fixture();
        assert!(f.proof.controller.body.owned_state.is_none());
        let before = state_custody::state_digest(&f.root).unwrap();
        f.store
            .persist_loss_return_completion(&f.proof, &f.keys)
            .expect("exact service-owned controller completion must persist");
        let db = super::super::la_store::open_pinned_readonly_database(
            &f.root,
            "lane_assignments.sqlite",
        )
        .unwrap();
        let saved: Vec<u8> = db
            .query_row(
                "SELECT proof FROM la_loss_return_completions WHERE admission=?1",
                [f.cap.digest().unwrap()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(saved, serde_json::to_vec(&f.proof).unwrap());
        assert_ne!(before, state_custody::state_digest(&f.root).unwrap());
        let transition:bool=f.channel.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='channel_loss_return_copy')",[],|r|r.get(0)).unwrap();
        assert!(
            transition,
            "successful completion consumer must durably authenticate its changed root"
        );
        assert!(WorkerAdmission::default().check().is_err());
        drop(db);
        let ControllerCopyFixture {
            path,
            parent_path,
            root,
            store,
            channel,
            ledger,
            domain,
            service_ledger,
            ..
        } = f;
        drop((root, store, channel, ledger, domain, service_ledger));
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(parent_path).unwrap();
    }
    fn finish_controller_fixture(f: ControllerCopyFixture) {
        let ControllerCopyFixture {
            path,
            parent_path,
            root,
            store,
            channel,
            ledger,
            domain,
            service_ledger,
            ..
        } = f;
        drop((root, store, channel, ledger, domain, service_ledger));
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(parent_path).unwrap();
    }
    #[test]
    fn loss_return_real_service_completion_refuses_altered_service_history_before_copy() {
        let f = controller_copy_fixture_inner(true);
        let ControllerCopyFixture {
            path,
            parent_path,
            root,
            mut store,
            cap,
            proof,
            keys,
            channel,
            ledger,
            domain,
            service_ledger,
            ..
        } = f;
        let domain = domain.unwrap();
        let mut client =
            WorkerClient::new("127.0.0.1:1".parse().unwrap(), channel, keys.clone()).unwrap();
        let mut altered = proof.clone();
        altered.service.2 = "f".repeat(64);
        altered.mac = altered.signature(&keys).unwrap();
        altered.verify_for(&cap, &keys).unwrap();
        cap.verify_completion_role(&altered, &root, "controller", &keys)
            .unwrap();
        let before = state_custody::state_digest(&root).unwrap();
        let result = client.persist_loss_return_completion(
            &serde_json::to_vec(&altered).unwrap(),
            &mut store,
            &domain,
        );
        assert_eq!(
            result.err(),
            Some("evidence_invalid"),
            "the actual C/service consumer must authenticate the entire exact service history"
        );
        assert_eq!(before, state_custody::state_digest(&root).unwrap());
        assert_eq!(client.admission(), Err("evidence_invalid"));
        drop((root, store, client, ledger, domain, service_ledger));
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(parent_path).unwrap();
    }
    #[test]
    fn loss_return_real_service_completion_persists_actual_copy_and_service_custody_closed() {
        let f = controller_copy_fixture_inner(true);
        let ControllerCopyFixture {
            path,
            parent_path,
            root,
            mut store,
            cap,
            proof,
            keys,
            channel,
            ledger,
            domain,
            service_ledger,
            ..
        } = f;
        let domain = domain.unwrap();
        let mut client =
            WorkerClient::new("127.0.0.1:1".parse().unwrap(), channel, keys.clone()).unwrap();
        let result = client
            .persist_loss_return_completion(
                &serde_json::to_vec(&proof).unwrap(),
                &mut store,
                &domain,
            )
            .unwrap();
        assert_eq!(result["admitted"], false);
        let copy = LossReturnCopy::read(&root, "controller", &cap, &proof, &keys).unwrap();
        let anchor = domain.loss_return_completion_anchor().unwrap();
        assert_eq!(anchor.3, proof.service.3 + 2);
        assert_eq!(anchor.1, copy.after);
        let sd =
            super::super::la_store::open_pinned_readonly_database(&root, "service-custody.sqlite")
                .unwrap();
        let digest = value_digest(&proof).unwrap();
        assert_eq!(
            state_custody::service_request_digest(&sd, anchor.3).unwrap(),
            (digest.clone(), Some(digest))
        );
        let frame: Vec<u8> = sd
            .query_row(
                "SELECT frame FROM service_checkpoints WHERE revision=?1",
                [anchor.3 as i64],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            std::fs::read(parent_path.join(format!("service-state-{:04}.json", anchor.3))).unwrap(),
            frame
        );
        assert_eq!(client.admission(), Err("evidence_invalid"));
        // The service source in this fixture is NOT native qualification:
        // authority_sequence is zero, so P's genuine producer stays closed.
        assert_eq!(
            service_ledger
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .entered_loss_return_anchor(&root)
                .err(),
            Some("evidence_invalid")
        );
        drop((sd, root, store, client, ledger, domain, service_ledger));
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(parent_path).unwrap();
    }
    #[test]
    fn loss_return_real_copy_without_completed_service_stays_closed() {
        let f = controller_copy_fixture_inner(true);
        f.service_fail_revision
            .store(5, std::sync::atomic::Ordering::SeqCst);
        let ControllerCopyFixture {
            path,
            parent_path,
            root,
            mut store,
            cap,
            proof,
            keys,
            channel,
            ledger,
            domain,
            service_ledger,
            ..
        } = f;
        let domain = domain.unwrap();
        let mut client =
            WorkerClient::new("127.0.0.1:1".parse().unwrap(), channel, keys.clone()).unwrap();
        let result = client.persist_loss_return_completion(
            &serde_json::to_vec(&proof).unwrap(),
            &mut store,
            &domain,
        );
        assert_eq!(result.err(),Some("evidence_invalid"),"the real service link maps the injected completion ACK refusal to its exact typed code");
        println!("LOSS_RETURN_FAULT {{\"boundary\":\"C_copy_durable_before_service_completion_ACK\",\"code\":\"evidence_invalid\",\"admitted\":false}}");
        LossReturnCopy::read(&root, "controller", &cap, &proof, &keys).unwrap();
        assert_eq!(client.admission(), Err("evidence_invalid"));
        assert!(domain.loss_return_completion_anchor().is_err());
        assert!(!parent_path.join("service-state-0005.json").exists());
        let sd =
            super::super::la_store::open_pinned_readonly_database(&root, "service-custody.sqlite")
                .unwrap();
        let ack: Option<Vec<u8>> = sd
            .query_row(
                "SELECT ack FROM service_checkpoints WHERE revision=5",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(ack.is_none());
        assert_eq!(
            service_ledger
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .entered_loss_return_anchor(&root)
                .err(),
            Some("evidence_invalid")
        );
        drop((sd, root, store, client, ledger, domain, service_ledger));
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(parent_path).unwrap();
    }
    #[test]
    fn loss_return_real_first_completion_expiry_does_not_write_or_admit() {
        let mut f = controller_copy_fixture();
        let remaining = f.cap.expires_at.saturating_sub(wall_now().unwrap());
        std::thread::sleep(std::time::Duration::from_millis(remaining + 1));
        let before = std::fs::read(f.path.join("lane_assignments.sqlite")).unwrap();
        assert_eq!(
            f.store.persist_loss_return_completion(&f.proof, &f.keys),
            Err("evidence_invalid")
        );
        assert_eq!(
            before,
            std::fs::read(f.path.join("lane_assignments.sqlite")).unwrap()
        );
        assert_eq!(WorkerAdmission::default().check(), Err("evidence_invalid"));
        finish_controller_fixture(f);
    }
    #[test]
    fn loss_return_final_service_budget_reserves_separate_activation() {
        let (mut cap, keys, now) = fixture();
        cap.service.3 = 1020;
        cap.mac = cap.signature(&keys).unwrap();
        assert_eq!(
            cap.verify_envelope(&keys, now),
            Err("evidence_invalid"),
            "install + completion copy + final consumption need six service revisions"
        );
    }
    #[test]
    fn loss_return_real_completed_copy_rejects_tamper_foreign_root_history_and_interruption() {
        let mut f = controller_copy_fixture();
        f.store
            .persist_loss_return_completion(&f.proof, &f.keys)
            .unwrap();
        let copy = LossReturnCopy::read(&f.root, "controller", &f.cap, &f.proof, &f.keys).unwrap();
        assert_eq!(copy.before, f.proof.service.1);
        assert_eq!(copy.after, state_custody::state_digest(&f.root).unwrap());
        assert!(f
            .ledger
            .lock()
            .unwrap()
            .verify_completed_copy(&f.root, &f.cap, &f.proof, &f.keys)
            .is_ok());
        // Root and independently persisted P history have both actually run.
        let parent = std::fs::File::open(&f.parent_path).unwrap();
        let phead = loss_return_read_bytes(&parent, "controller-witness-0020.json", 4096).unwrap();
        assert_eq!(phead, serde_json::to_vec(&f.proof.controller).unwrap());
        for facet in 0..6 {
            let mut bad = copy.clone();
            match facet {
                0 => bad.before = "0".repeat(64),
                1 => bad.completion = "f".repeat(64),
                2 => bad.role = "worker".into(),
                3 => bad.binding.worker_boot = "a".repeat(64),
                4 => bad.consumed_at = f.cap.expires_at,
                5 => bad.checkpoint = "f".repeat(64),
                _ => unreachable!(),
            }
            bad.mac = bad.signature(&f.keys).unwrap();
            assert_eq!(
                bad.verify(&f.cap, &f.proof, "controller", &f.keys, wall_now().unwrap()),
                Err("evidence_invalid"),
                "signed copy facet {facet}"
            );
        }
        let foreign = root("copy-foreign");
        let foreign_root = std::fs::File::open(&foreign).unwrap();
        assert_eq!(
            LossReturnCopy::read(&foreign_root, "controller", &f.cap, &f.proof, &f.keys).err(),
            Some("evidence_invalid")
        );
        drop(foreign_root);
        std::fs::remove_dir_all(foreign).unwrap();
        // Same-size old checkpoint alteration reaches the full-history guard.
        let old: Vec<u8> = f
            .channel
            .db
            .query_row(
                "SELECT frame FROM channel_checkpoints WHERE revision=2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut changed = old.clone();
        let at = changed.iter().position(|b| *b == b'a').unwrap();
        changed[at] = b'b';
        f.channel
            .db
            .execute(
                "UPDATE channel_checkpoints SET frame=?1 WHERE revision=2",
                [&changed],
            )
            .unwrap();
        assert_eq!(
            LossReturnCopy::read(&f.root, "controller", &f.cap, &f.proof, &f.keys).err(),
            Some("evidence_invalid")
        );
        f.channel
            .db
            .execute(
                "UPDATE channel_checkpoints SET frame=?1 WHERE revision=2",
                [&old],
            )
            .unwrap();
        LossReturnCopy::read(&f.root, "controller", &f.cap, &f.proof, &f.keys).unwrap();
        // Actual independent P witness loss is distinct from a locally intact
        // completion/transport chain and must fail the P readback consumer.
        let name = "controller-witness-0019.json";
        let saved = loss_return_read_bytes(&parent, name, 4096).unwrap();
        std::fs::remove_file(f.parent_path.join(name)).unwrap();
        assert_eq!(
            f.ledger
                .lock()
                .unwrap()
                .verify_completed_copy(&f.root, &f.cap, &f.proof, &f.keys)
                .err(),
            Some("evidence_invalid")
        );
        {
            use std::io::Write;
            let mut file = super::super::la_artifacts::open_artifact(
                &parent,
                name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .unwrap();
            file.write_all(&saved).unwrap();
            file.sync_all().unwrap();
            parent.sync_all().unwrap();
        }
        f.ledger
            .lock()
            .unwrap()
            .verify_completed_copy(&f.root, &f.cap, &f.proof, &f.keys)
            .unwrap();
        // Changed owned bytes are not hidden by a valid old copy signature.
        std::fs::write(f.path.join("foreign-input"), b"foreign claim").unwrap();
        assert_eq!(
            LossReturnCopy::read(&f.root, "controller", &f.cap, &f.proof, &f.keys).err(),
            Some("evidence_invalid")
        );
        std::fs::remove_file(f.path.join("foreign-input")).unwrap();
        LossReturnCopy::read(&f.root, "controller", &f.cap, &f.proof, &f.keys).unwrap();
        // Simulate interruption AFTER the fsynced journal copy and BEFORE the
        // separate channel receipt. The completion is present; no admission is.
        f.channel
            .db
            .execute_batch("DROP TABLE channel_loss_return_copy")
            .unwrap();
        assert!(LossReturnCopy::saved_completion(&f.root, "controller", &f.proof).is_ok());
        assert_eq!(
            LossReturnCopy::read(&f.root, "controller", &f.cap, &f.proof, &f.keys).err(),
            Some("evidence_invalid")
        );
        assert_eq!(WorkerAdmission::default().check(), Err("evidence_invalid"));
        finish_controller_fixture(f);
    }
    // ONLY a signed-contract fixture. W/P global readback and W consumption
    // below are synthetic. They never open a barrier or establish runtime proof.
    fn synthetic_linearization(f: &ControllerCopyFixture) -> LossReturnLinearization {
        let c = LossReturnCopy::read(&f.root, "controller", &f.cap, &f.proof, &f.keys).unwrap();
        let (head, history, before) = LossReturnCopy::role(&f.proof, "worker").unwrap();
        let mut w = LossReturnCopy {
            admission: f.cap.digest().unwrap(),
            completion: value_digest(&f.proof).unwrap(),
            binding: f.cap.binding.clone(),
            role: "worker".into(),
            checkpoint: head.digest().unwrap(),
            history: history.into(),
            before: before.into(),
            after: "b".repeat(64),
            consumed_at: c.consumed_at,
            mac: [0; 32],
        };
        w.mac = w.signature(&f.keys).unwrap();
        let now = wall_now().unwrap();
        let mut value = LossReturnLinearization {
            admission: f.cap.digest().unwrap(),
            completion: value_digest(&f.proof).unwrap(),
            binding: f.cap.binding.clone(),
            worker: w,
            controller: c.clone(),
            service: (
                "a".repeat(64),
                c.after,
                "c".repeat(64),
                f.proof.service.3 + 2,
                f.proof.service.4,
            ),
            worker_storage: (65536, "d".repeat(64)),
            controller_storage: loss_return_physical(&f.root).unwrap(),
            processes: "e".repeat(64),
            process_observed_at: f.cap.processes.observed_at,
            worker_read_at: now,
            controller_read_at: now,
            issued_at: now,
            expires_at: f.cap.expires_at,
            mac: [0; 32],
        };
        value.mac = value.signature(&f.keys).unwrap();
        value.verify(&f.cap, &f.proof, &f.keys, now).unwrap();
        value
    }
    #[test]
    fn loss_return_distinct_global_contract_and_actual_final_consumer_refuse_unreturned_history() {
        let mut f = controller_copy_fixture();
        f.store
            .persist_loss_return_completion(&f.proof, &f.keys)
            .unwrap();
        let value = synthetic_linearization(&f);
        let now = wall_now().unwrap();
        let mut peer = LossReturnActivation {
            binding: value.binding.clone(),
            admission: value.admission.clone(),
            linearization: value.digest().unwrap(),
            role: "worker".into(),
            consumed_at: now,
            mac: [0; 32],
        };
        peer.mac = peer.signature(&f.keys).unwrap();
        peer.verify(&value, "worker", &f.keys, now).unwrap();
        let admission = WorkerAdmission::default();
        let before = state_custody::state_digest(&f.root).unwrap();
        // Every preceding local token/root/copy/MAC guard is valid. The REAL
        // consumer must reach the absent entered-loss transition and stay closed.
        assert_eq!(
            f.channel
                .consume_loss_return_final(&admission, &value, None, &f.keys)
                .err(),
            Some("evidence_invalid")
        );
        assert_eq!(admission.check(), Err("evidence_invalid"));
        assert_eq!(
            f.channel
                .consume_loss_return_final(&admission, &value, Some(&peer), &f.keys)
                .err(),
            Some("evidence_invalid")
        );
        assert_eq!(admission.check(), Err("evidence_invalid"));
        let active:bool=f.channel.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='channel_loss_return_activation')",[],|r|r.get(0)).unwrap();
        assert!(!active);
        assert_eq!(before, state_custody::state_digest(&f.root).unwrap());
        for facet in 0..9 {
            let mut bad = value.clone();
            match facet {
                0 => bad.service.3 -= 1,
                1 => bad.service.1 = "f".repeat(64),
                2 => bad.controller.role = "worker".into(),
                3 => bad.completion = "f".repeat(64),
                4 => bad.binding.source_digest = "a".repeat(64),
                5 => bad.expires_at += 1,
                6 => bad.worker_read_at = bad.issued_at + 1,
                7 => bad.process_observed_at = now - 1500,
                8 => bad.worker.consumed_at = bad.issued_at + 1,
                _ => unreachable!(),
            }
            // Re-sign all changed new-domain nested receipts; exercise semantic
            // guards rather than merely observing a stale top-level MAC.
            bad.worker.mac = bad.worker.signature(&f.keys).unwrap();
            bad.controller.mac = bad.controller.signature(&f.keys).unwrap();
            bad.mac = bad.signature(&f.keys).unwrap();
            assert_eq!(
                bad.verify(&f.cap, &f.proof, &f.keys, now),
                Err("evidence_invalid"),
                "global facet {facet}"
            );
        }
        assert_eq!(
            value.verify(&f.cap, &f.proof, &f.keys, value.expires_at),
            Err("evidence_invalid")
        );
        let mut unknown = serde_json::to_value(&value).unwrap();
        unknown["admitted"] = true.into();
        assert!(serde_json::from_value::<LossReturnLinearization>(unknown).is_err());
        assert!(serde_json::from_slice::<LossReturnLinearization>(
            &serde_json::to_vec(&f.proof).unwrap()
        )
        .is_err());
        assert!(
            serde_json::from_slice::<Activation>(&serde_json::to_vec(&value).unwrap()).is_err()
        );
        let mut wrong = value.clone();
        wrong.mac = typed_mac(
            &f.keys.custody,
            b"diffuser-loss-return-completion/v1\0",
            &wrong,
        )
        .unwrap();
        assert_eq!(
            wrong.verify(&f.cap, &f.proof, &f.keys, now),
            Err("evidence_invalid")
        );
        let mut peerbad = peer.clone();
        peerbad.role = "controller".into();
        peerbad.mac = peerbad.signature(&f.keys).unwrap();
        assert_eq!(
            peerbad.verify(&value, "worker", &f.keys, now),
            Err("evidence_invalid")
        );
        let final_packet =
            serde_json::to_vec(&serde_json::json!({"linearization":value,"worker":peer})).unwrap();
        let install=serde_json::to_vec(&serde_json::json!({"kind":"diffuser-loss-return-admission-install/v1","admission":f.cap})).unwrap();
        let request = RpcRequest {
            version: 1,
            binding: f.cap.binding.clone(),
            sequence: 10,
            input_digest: hex::encode(Sha256::digest([])),
            input_bytes: 0,
            operation: WorkerOperation::AdmitLossReturn(Box::new(f.cap.clone())),
        };
        let signed = SignedRequest {
            mac: typed_mac(&f.keys.command, b"diffuser-rpc-request/v1\0", &request).unwrap(),
            request,
        };
        let metadata = serde_json::to_vec(&signed).unwrap();
        println!("LOSS_RETURN_SYNTHETIC_POPULATED_BYTES install_control={} rpc10_metadata={} completion_control={} final_controller_control={} final_worker_control={}",install.len()+b"WLRETURN ".len(),metadata.len(),serde_json::to_vec(&f.proof).unwrap().len()+b"LACOMPLETE ".len(),final_packet.len()+b"WLRETURN LAACTIVATE ".len(),serde_json::to_vec(&value).unwrap().len()+b"LAACTIVATE ".len());
        assert!(install.len() + b"WLRETURN ".len() <= 16 * 1024);
        assert!(metadata.len() <= 65536);
        assert!(final_packet.len() + b"WLRETURN LAACTIVATE ".len() <= 16 * 1024);
        // Named file helper's actual fsync/readback is exercised with a clearly
        // synthetic token. This is NOT the full P producer's positive proof.
        let parent = std::fs::File::open(&f.parent_path).unwrap();
        loss_return_write(&parent, "synthetic-linearization-fsync.json", &value).unwrap();
        assert_eq!(
            loss_return_read_bytes(&parent, "synthetic-linearization-fsync.json", 65536).unwrap(),
            serde_json::to_vec(&value).unwrap()
        );
        assert_eq!(
            loss_return_write(&parent, "synthetic-linearization-fsync.json", &value),
            Err("evidence_invalid")
        );
        finish_controller_fixture(f);
    }
    #[test]
    fn synthetic_loss_return_domain_roundtrip_binding_and_no_old_mode_cast() {
        let (cap, keys, now) = fixture();
        let bytes = serde_json::to_vec(&cap).unwrap();
        let protected=serde_json::to_vec(&serde_json::json!({"kind":"diffuser-loss-return-admission-install/v1","admission":cap})).unwrap();
        assert!(protected.len() + b"WLRETURN ".len() < 16 * 1024);
        let decoded: LossReturnAdmission = serde_json::from_slice(&bytes).unwrap();
        decoded.verify_envelope(&keys, now).unwrap();
        assert!(serde_json::from_slice::<WorkerSuccessorAdmission>(&bytes).is_err());
        assert!(serde_json::from_slice::<RecoveredControllerAdmission>(&bytes).is_err());
        assert!(serde_json::from_slice::<NeverStartedPermit>(&bytes).is_err());
        assert!(serde_json::from_slice::<WorkerLossReturn>(&bytes).is_err());
        let mut unknown = serde_json::to_value(&cap).unwrap();
        unknown["admitted"] = true.into();
        assert!(serde_json::from_value::<LossReturnAdmission>(unknown).is_err());
        let mut overflow = cap.clone();
        overflow.spent.worker.body.sequence = u64::MAX;
        assert_eq!(
            overflow.verify_envelope(&keys, now),
            Err("evidence_invalid")
        );
        let mut other = cap.clone();
        other.binding.source_digest = "a".repeat(64);
        assert!(other.verify_envelope(&keys, now).is_err());
        let mut wrong = cap.clone();
        wrong.mac = typed_mac(
            &keys.custody,
            b"diffuser-worker-successor-admission/v1\0",
            &cap,
        )
        .unwrap();
        assert!(wrong.verify_envelope(&keys, now).is_err());
        let mut foreign = keys.clone();
        foreign.custody[0] ^= 1;
        assert!(cap.verify_envelope(&foreign, now).is_err());
        let op = WorkerOperation::AdmitLossReturn(Box::new(cap));
        assert_eq!(
            operation_target(&op).unwrap(),
            ("POST", "/v1/worker/rpc".into())
        );
        assert!(!op.needs_admission());
        let wire = serde_json::to_vec(&op).unwrap();
        let decoded: WorkerOperation = serde_json::from_slice(&wire).unwrap();
        assert_eq!(
            operation_target(&decoded).unwrap(),
            operation_target(&op).unwrap()
        );
        assert_eq!(
            serde_json::to_value(op).unwrap()["operation"],
            "AdmitLossReturn"
        );
    }
    #[test]
    fn synthetic_loss_return_original_clocks_and_adjacent_cursor_are_strict() {
        let (cap, keys, now) = fixture();
        assert!(cap.verify_envelope(&keys, now - 1).is_err());
        assert!(cap.verify_envelope(&keys, cap.expires_at).is_err());
        for facet in 0..8 {
            let mut bad = cap.clone();
            match facet {
                0 => bad.spent.generation = 3,
                1 => bad.spent.sequence = 3,
                2 => bad.spent.fence = 2,
                3 => bad.spent.previous_boot = bad.binding.worker_boot.clone(),
                4 => bad.binding.controller_epoch = 2,
                5 => bad.processes.observed_at = now - 1500,
                6 => bad.consumed.controller_observed_at = bad.spent.expires_at,
                7 => bad.spent.released_at = now + 1,
                _ => unreachable!(),
            }
            // Re-sign all affected domains so this reaches structural/time
            // predicates, not just the outer MAC.
            bad.spent.mac = bad.spent.signature(&keys.custody).unwrap();
            bad.consumed.disposition = bad.spent.digest().unwrap();
            bad.consumed.mac = bad.consumed.signature(&keys.custody).unwrap();
            bad.mac = bad.signature(&keys).unwrap();
            assert!(bad.verify_envelope(&keys, now).is_err(), "facet {facet}");
        }
        // Historical receipt authenticates at its original clocks even after
        // its own first-use deadline, while fresh admission still expires.
        assert!(cap.consumed.verify(&cap.spent, &keys, now + 5000).is_ok());
        assert!(cap.verify_envelope(&keys, now + 5000).is_err());
    }
    #[test]
    fn synthetic_loss_return_whole_completion_rejects_missing_altered_foreign_late_peer() {
        let (cap, keys, now) = fixture();
        let proof = completion(&cap, &keys, now);
        proof.verify(&cap, &keys, now + 4).unwrap();
        let bytes = serde_json::to_vec(&proof).unwrap();
        let parsed: LossReturnCompletion = serde_json::from_slice(&bytes).unwrap();
        parsed.verify(&cap, &keys, now + 4).unwrap();
        let mut missing = serde_json::to_value(&proof).unwrap();
        missing.as_object_mut().unwrap().remove("controller");
        assert!(serde_json::from_value::<LossReturnCompletion>(missing).is_err());
        for facet in 0..8 {
            let mut bad = proof.clone();
            match facet {
                0 => bad.controller.body.sequence = 9,
                1 => bad.service.3 -= 1,
                2 => bad.worker_installed_at = cap.expires_at,
                3 => bad.controller_observed_at = now - 1,
                4 => bad.binding.controller_boot = "a".repeat(64),
                5 => bad.controller_ack[0] ^= 1,
                6 => bad.worker_history = "f".repeat(64),
                7 => bad.worker_ack[0] ^= 1,
                _ => unreachable!(),
            }
            if facet != 6 {
                bad.mac = bad.signature(&keys).unwrap();
            }
            assert!(
                bad.verify(&cap, &keys, now + 4).is_err(),
                "completion facet {facet}"
            );
        }
        assert!(proof.verify(&cap, &keys, cap.expires_at).is_err());
        let worker_only = serde_json::json!({"admission":cap.digest().unwrap(),"installed_at":now+1,"mac":proof.worker_ack});
        assert!(serde_json::from_value::<LossReturnCompletion>(worker_only).is_err());
    }
    #[test]
    fn synthetic_loss_return_claimstore_installs_once_and_preserves_old_rows_and_clock() {
        let (mut cap, keys, now) = fixture();
        let path = root("claims");
        let mut store =
            super::super::la_store::ClaimStore::open(&path.join("lane_assignments.sqlite"))
                .unwrap();
        let db = rusqlite::Connection::open(path.join("lane_assignments.sqlite")).unwrap();
        let certificate = b"synthetic historical certificate bytes; not runtime evidence";
        cap.spent.cleanup = hex::encode(Sha256::digest(certificate));
        cap.spent.mac = cap.spent.signature(&keys.custody).unwrap();
        cap.consumed.disposition = cap.spent.digest().unwrap();
        cap.consumed.mac = cap.consumed.signature(&keys.custody).unwrap();
        db.execute("INSERT INTO la_assignments VALUES(?1,'project_retained_01','actor_retained_001',?2,1,'closed')",rusqlite::params![cap.spent.command.assignment,cap.binding.worker]).unwrap();
        db.execute("INSERT INTO la_jobs VALUES(?1,?2,'project_retained_01','actor_retained_001','input_retained_001','failed',1,NULL)",rusqlite::params![cap.spent.command.job,cap.spent.command.assignment]).unwrap();
        db.execute(
            "INSERT INTO la_worker_cursor VALUES(?1,?2,2)",
            rusqlite::params![cap.binding.worker, cap.spent.previous_boot],
        )
        .unwrap();
        db.execute(
            "INSERT INTO la_assignment_cleanup_receipts VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                cap.spent.command.assignment,
                cap.spent.cleanup,
                certificate.as_slice(),
                cap.spent.released_at as i64
            ],
        )
        .unwrap();
        let root = std::fs::File::open(&path).unwrap();
        let m = root.metadata().unwrap();
        cap.controller.device = m.dev();
        cap.controller.inode = m.ino();
        cap.controller.state = state_custody::state_digest(&root).unwrap();
        cap.mac = cap.signature(&keys).unwrap();
        let before = std::fs::read(path.join("lane_assignments.sqlite")).unwrap();
        let ack = cap.worker_ack(&keys, now + 1).unwrap();
        let mut bad = ack;
        bad[0] ^= 1;
        assert!(store
            .install_loss_return(&cap, &keys, now + 1, &bad, now + 2)
            .is_err());
        assert_eq!(
            std::fs::read(path.join("lane_assignments.sqlite")).unwrap(),
            before
        );
        assert!(store
            .install_loss_return(&cap, &keys, now + 1, &ack, cap.expires_at)
            .is_err());
        // Even a newly P-signed full root must not install generation two
        // beside an unexpected controller generation. This reaches the actual
        // ClaimStore consumer with valid signatures and current access.
        db.execute_batch("CREATE TABLE la_worker_session_generations(worker TEXT NOT NULL,generation INTEGER NOT NULL,body BLOB NOT NULL,PRIMARY KEY(worker,generation))").unwrap();
        db.execute(
            "INSERT INTO la_worker_session_generations VALUES(?1,3,?2)",
            rusqlite::params![cap.binding.worker, b"foreign-generation".as_slice()],
        )
        .unwrap();
        cap.controller.state = state_custody::state_digest(&root).unwrap();
        cap.mac = cap.signature(&keys).unwrap();
        let foreign_ack = cap.worker_ack(&keys, now + 1).unwrap();
        let foreign_before = std::fs::read(path.join("lane_assignments.sqlite")).unwrap();
        assert!(
            store
                .install_loss_return(&cap, &keys, now + 1, &foreign_ack, now + 2)
                .is_err(),
            "foreign controller generation must refuse before installing generation two"
        );
        assert_eq!(
            std::fs::read(path.join("lane_assignments.sqlite")).unwrap(),
            foreign_before
        );
        db.execute("DELETE FROM la_worker_session_generations", [])
            .unwrap();
        cap.controller.state = state_custody::state_digest(&root).unwrap();
        cap.mac = cap.signature(&keys).unwrap();
        let ack = cap.worker_ack(&keys, now + 1).unwrap();
        store
            .install_loss_return(&cap, &keys, now + 1, &ack, now + 2)
            .unwrap();
        let cursor: (String, i64) = db
            .query_row("SELECT boot,sequence FROM la_worker_cursor", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(cursor, (cap.binding.worker_boot.clone(), 2));
        let old:(String,Option<String>,Vec<u8>,i64)=db.query_row("SELECT j.state,j.result_artifact,c.certificate,c.released_at FROM la_jobs j JOIN la_assignment_cleanup_receipts c ON c.assignment_id=j.assignment_id",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(
            old,
            (
                "failed".into(),
                None,
                certificate.to_vec(),
                cap.spent.released_at as i64
            )
        );
        assert_eq!(store.counts().unwrap(), (0, 0, 0));
        let installed: Vec<u8> = db
            .query_row(
                "SELECT body FROM la_worker_session_generations WHERE generation=2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(installed, serde_json::to_vec(&cap).unwrap());
        assert!(store
            .install_loss_return(&cap, &keys, now + 1, &ack, now + 2)
            .is_err());
        drop(db);
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn synthetic_loss_return_current_access_membership_scopes_and_absolute_bounds() {
        let (cap, keys, now) = fixture();
        for facet in 0..9 {
            let mut bad = cap.clone();
            let g = &mut bad.authority.grants[0];
            match facet {
                0 => g.member = false,
                1 => g.enabled = false,
                2 => g.revoked = true,
                3 => g.scopes = 0,
                4 => g.access_expires = cap.expires_at - 1,
                5 => g.execution_ceiling = cap.expires_at - 1,
                6 => g.not_before = now + 1,
                7 => g.parent = Some(g.id.clone()),
                8 => bad.authority.sequence = 5,
                _ => unreachable!(),
            }
            bad.mac = bad.signature(&keys).unwrap();
            assert!(
                bad.verify_envelope(&keys, now).is_err(),
                "access facet {facet}"
            );
        }
    }
    #[test]
    fn synthetic_loss_return_worker_installer_requires_complete_original_retirement() {
        let (cap, keys, _) = fixture();
        let path = root("worker-refusal");
        let mut journal = super::super::la_worker::OperationJournal::bootstrap(
            &path.join("worker.sqlite"),
            "custody_retirement_01",
        )
        .unwrap();
        let session = super::super::la_worker::ReservationSession {
            worker: cap.binding.worker.clone(),
            boot: cap.binding.worker_boot.clone(),
            key: keys.reply,
        };
        let before = std::fs::read(path.join("worker.sqlite")).unwrap();
        assert_eq!(
            journal.install_loss_return_generation(&session, &cap, &keys),
            Err("evidence_invalid")
        );
        assert_eq!(std::fs::read(path.join("worker.sqlite")).unwrap(), before);
        drop(journal);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn synthetic_loss_return_partial_install_packets_cannot_activate_either_role() {
        let (cap, keys, now) = fixture();
        let path = root("partial");
        let root = std::fs::File::open(&path).unwrap();
        let proof = completion(&cap, &keys, now);
        let packets=[serde_json::to_vec(&cap).unwrap(),serde_json::to_vec(&WorkerReply::LossReturnInstalled{admission:cap.digest().unwrap(),installed_at:now+1,mac:proof.worker_ack}).unwrap(),serde_json::to_vec(&proof).unwrap(),serde_json::to_vec(&serde_json::json!({"admitted":true,"worker_ack":proof.worker_ack,"controller_ack":proof.controller_ack})).unwrap()];
        for role in ["worker", "controller"] {
            let admission = WorkerAdmission::default();
            for packet in &packets {
                assert!(admission
                    .install(packet, cap.binding(), &keys, &root, role, None)
                    .is_err());
                assert_eq!(admission.check(), Err("evidence_invalid"));
            }
        }
        let mut store =
            super::super::la_store::ClaimStore::open(&path.join("lane_assignments.sqlite"))
                .unwrap();
        let before = std::fs::read(path.join("lane_assignments.sqlite")).unwrap();
        assert!(store.persist_loss_return_completion(&proof, &keys).is_err());
        assert_eq!(
            std::fs::read(path.join("lane_assignments.sqlite")).unwrap(),
            before
        );
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn loss_return_physical_accounting_includes_sqlite_history_and_old_input() {
        let path = root("physical");
        for (name, size) in [
            ("worker.sqlite", 16384),
            ("worker-channel.sqlite", 8192),
            ("service-custody.sqlite", 8192),
            ("retained-input", 45),
            ("old-history.json", 512),
        ] {
            std::fs::write(path.join(name), vec![1; size]).unwrap();
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let root = std::fs::File::open(&path).unwrap();
        let (bytes, digest) = loss_return_physical(&root).unwrap();
        assert!(bytes > 32768 + 45 + 512);
        std::fs::write(path.join("worker-channel.sqlite"), vec![1; 16384]).unwrap();
        let (next, changed) = loss_return_physical(&root).unwrap();
        assert!(next > bytes);
        assert_ne!(changed, digest);
        std::fs::remove_dir_all(path).unwrap();
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LossReturnAuthority {
    tenant: String,
    project: String,
    sequence: u64,
    observed_at: u64,
    freshness_ms: u64,
    grants: Vec<LossReturnGrant>,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LossReturnGrant {
    id: String,
    parent: Option<String>,
    tenant: String,
    project: String,
    actor: String,
    bearer_digest: [u8; 32],
    scopes: u64,
    can_delegate: bool,
    enabled: bool,
    member: bool,
    revoked: bool,
    not_before: u64,
    access_expires: u64,
    run_until: u64,
    execution_ceiling: u64,
    audience: String,
}
impl LossReturnAuthority {
    fn capture(a: &super::lane_assignment::DiscoveryContext) -> Self {
        Self {
            tenant: a.tenant.clone(),
            project: a.project.clone(),
            sequence: a.observation_sequence,
            observed_at: a.observed_at,
            freshness_ms: a.freshness_ms,
            grants: a
                .grants
                .iter()
                .map(|g| LossReturnGrant {
                    id: g.id.clone(),
                    parent: g.parent.clone(),
                    tenant: g.tenant.clone(),
                    project: g.project.clone(),
                    actor: g.actor.clone(),
                    bearer_digest: g.bearer_digest,
                    scopes: g.scopes,
                    can_delegate: g.can_delegate,
                    enabled: g.enabled,
                    member: g.member,
                    revoked: g.revoked,
                    not_before: g.not_before,
                    access_expires: g.access_expires,
                    run_until: g.run_until,
                    execution_ceiling: g.execution_ceiling,
                    audience: g.audience.clone(),
                })
                .collect(),
        }
    }
    fn verify(&self, sequence: u64, now: u64, until: u64) -> Result<(), &'static str> {
        let scopes = super::lane_assignment::loss_return_required_scopes();
        if self.sequence != sequence
            || self.freshness_ms != 1500
            || self.observed_at > now
            || now - self.observed_at >= 1500
            || self.tenant.is_empty()
            || self.project.is_empty()
            || self.grants.is_empty()
            || self.grants.len() > 128
        {
            return Err("delegation_denied");
        }
        let mut ids = std::collections::BTreeSet::new();
        for g in &self.grants {
            if !ids.insert(&g.id)
                || !g.enabled
                || !g.member
                || g.revoked
                || g.tenant != self.tenant
                || g.project != self.project
                || g.audience != "diffuser"
                || g.not_before > now
                || g.access_expires < until
                || g.run_until < until
                || g.execution_ceiling < until
                || g.scopes & scopes != scopes
            {
                return Err("delegation_denied");
            }
            if let Some(parent) = &g.parent {
                let mut matches = self.grants.iter().filter(|p| &p.id == parent);
                let p = matches.next().ok_or("delegation_denied")?;
                if matches.next().is_some()
                    || !p.can_delegate
                    || g.scopes & !p.scopes != 0
                    || g.run_until > p.run_until
                    || g.execution_ceiling > p.execution_ceiling
                {
                    return Err("delegation_denied");
                }
            }
            let mut node = g;
            let mut chain = std::collections::BTreeSet::new();
            loop {
                if !chain.insert(&node.id) || chain.len() > 8 {
                    return Err("delegation_denied");
                }
                let Some(parent) = &node.parent else {
                    break;
                };
                node = self
                    .grants
                    .iter()
                    .find(|p| &p.id == parent)
                    .ok_or("delegation_denied")?;
            }
        }
        Ok(())
    }
}
impl LossReturnAdmission {
    pub(super) fn verify_current_authority(
        &self,
        a: &super::lane_assignment::DiscoveryContext,
    ) -> Result<(), &'static str> {
        let now = wall_now()?;
        self.authority
            .verify(self.service.4, now, self.expires_at)?;
        if self.authority != LossReturnAuthority::capture(a) {
            return Err("delegation_denied");
        }
        Ok(())
    }
}

impl LossReturnAdmission {
    pub(super) fn verify_completion_role(
        &self,
        proof: &LossReturnCompletion,
        root: &std::fs::File,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        proof.verify(self, keys, wall_now()?)?;
        let (head, history) = match role {
            "worker" => (&proof.worker, &proof.worker_history),
            "controller" => (&proof.controller, &proof.controller_history),
            _ => return Err("evidence_invalid"),
        };
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        let (frame, ack): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let ack: CheckpointAck = serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
        ack.verify(&keys.custody, head)?;
        if frame != serde_json::to_vec(head).map_err(|_| "evidence_invalid")?
            || checkpoint_bytes_digest(&db, head.body.revision, head.body.revision)? != *history
            || match role {
                "worker" => {
                    head.body.owned_state.as_ref() != Some(&state_custody::state_digest(root)?)
                }
                "controller" => {
                    head.body.owned_state.is_some()
                        || state_custody::state_digest(root)? != proof.service.1
                }
                _ => true,
            }
            || transport_state_digest(&db, &self.binding)? != head.body.state_digest
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, head, &keys.reply, &keys.custody)?;
        if role == "worker" {
            self.verify_retained_worker(root, keys)?;
        }
        Ok(())
    }
}
impl WorkerRpc {
    /// Protected completion persistence is deliberately separate from RPC10's
    /// install ACK. It leaves ordinary transport/WorkerAdmission closed.
    pub(super) fn persist_loss_return_completion(
        &mut self,
        bytes: &[u8],
    ) -> Result<serde_json::Value, &'static str> {
        if bytes.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        let proof: LossReturnCompletion =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        self.channel.check()?;
        self.journal
            .persist_loss_return_completion(&proof, &self.keys)?;
        Ok(serde_json::json!({"kind":"LOSS_RETURN_COMPLETION_PERSISTED","admitted":false}))
    }
}
impl WorkerClient {
    /// The C/service copy is also durable behind its existing barriers. P must
    /// still independently witness all three completed copies before activation.
    pub(super) fn persist_loss_return_completion(
        &mut self,
        bytes: &[u8],
        claims: &mut super::la_store::ClaimStore,
        domain: &state_custody::Session,
    ) -> Result<serde_json::Value, &'static str> {
        if bytes.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        let proof: LossReturnCompletion =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        self.channel.check()?;
        let cap = claims.load_loss_return_admission(proof.admission())?;
        proof.verify_for(&cap, &self.keys)?;
        cap.verify_completion_role(&proof, &self.channel.root, "controller", &self.keys)?;
        if domain.binding()? != proof.binding
            || domain.loss_return_completion_anchor()?
                != (
                    proof.service.0.clone(),
                    proof.service.1.clone(),
                    proof.service.2.clone(),
                    proof.service.3,
                )
        {
            return Err("evidence_invalid");
        }
        let digest = value_digest(&proof)?;
        let op = domain.begin(&digest)?;
        claims.persist_loss_return_completion(&proof, &self.keys)?;
        domain.complete(op, &digest)?;
        proof.verify_for(&cap, &self.keys)?;
        Ok(serde_json::json!({"kind":"LOSS_RETURN_COMPLETION_PERSISTED","admitted":false}))
    }
}
impl LossReturnCompletion {
    pub(super) fn admission(&self) -> &str {
        &self.admission
    }
    pub(super) fn verify_for(
        &self,
        cap: &LossReturnAdmission,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        self.verify(cap, keys, wall_now()?)
    }
}

impl LossReturnAdmission {
    pub(super) fn current_install_clock(&self, keys: &ChannelKeys) -> Result<u64, &'static str> {
        let now = wall_now()?;
        self.verify_envelope(keys, now)?;
        Ok(now)
    }
}

/// Compact exact commitments keep the existing 16KiB control frame. This
/// distinct capsule has a 15KiB maximum, leaving room for its fixed envelope. Full fixed-role observation bytes are fsynced at P before
/// the intent, rather than sending repeated mount/status/FD text over RPC10.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LossReturnProcessPins {
    worker: serde_json::Value,
    controller: serde_json::Value,
    parent: serde_json::Value,
    keeper: serde_json::Value,
    worker_ready: String,
    controller_ready: String,
    observations: String,
    observed_at: u64,
}
impl LossReturnProcessPins {
    fn capture(p: &LossReturnProcesses) -> Result<Self, &'static str> {
        Ok(Self {
            worker: p.worker["identity"].clone(),
            controller: p.controller["identity"].clone(),
            parent: p.parent["identity"].clone(),
            keeper: p.keeper["identity"].clone(),
            worker_ready: value_digest(&p.worker_ready)?,
            controller_ready: value_digest(&p.controller_ready)?,
            observations: value_digest(p)?,
            observed_at: p.observed_at,
        })
    }
}
fn loss_return_write_processes(
    root: &std::fs::File,
    processes: &LossReturnProcesses,
) -> Result<(), &'static str> {
    use std::io::Write;
    let bytes = serde_json::to_vec(processes).map_err(|_| "evidence_invalid")?;
    if bytes.len() > RPC_INPUT_MAX {
        return Err("evidence_invalid");
    }
    let mut f = super::la_artifacts::open_artifact(
        root,
        "loss-return-admission-processes.json",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )
    .map_err(|_| "evidence_invalid")?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .and_then(|_| root.sync_all())
        .map_err(|_| "storage_unavailable")
}

/// Authenticated transition for ONE exact completion-copy write. The receipt
/// lives in the excluded channel DB so that its post-root is not self-referential.
/// It grants no admission and cannot substitute for P's global linearization.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossReturnCopy {
    admission: String,
    completion: String,
    binding: ChannelBinding,
    role: String,
    checkpoint: String,
    history: String,
    before: String,
    after: String,
    consumed_at: u64,
    mac: [u8; 32],
}
impl LossReturnCopy {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(
            &keys.reply,
            b"diffuser-loss-return-completion-copy/v1\0",
            &v,
        )
    }
    fn role<'a>(
        proof: &'a LossReturnCompletion,
        role: &str,
    ) -> Result<(&'a SignedCheckpoint, &'a str, &'a str), &'static str> {
        match role {
            "worker" => Ok((
                &proof.worker,
                &proof.worker_history,
                proof
                    .worker
                    .body
                    .owned_state
                    .as_deref()
                    .ok_or("evidence_invalid")?,
            )),
            "controller" if proof.controller.body.owned_state.is_none() => Ok((
                &proof.controller,
                &proof.controller_history,
                &proof.service.1,
            )),
            _ => Err("evidence_invalid"),
        }
    }
    fn verify(
        &self,
        cap: &LossReturnAdmission,
        proof: &LossReturnCompletion,
        role: &str,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        proof.verify(cap, keys, now)?;
        let (head, history, before) = Self::role(proof, role)?;
        if self.admission != cap.digest()?
            || self.completion != value_digest(proof)?
            || self.binding != cap.binding
            || self.role != role
            || self.checkpoint != head.digest()?
            || self.history != history
            || self.before != before
            || self.after.len() != 64
            || hex::decode(&self.after).is_err()
            || self.before == self.after
            || self.consumed_at < proof.controller_observed_at
            || self.consumed_at > now
            || self.consumed_at >= cap.expires_at
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn saved_completion(
        root: &std::fs::File,
        role: &str,
        proof: &LossReturnCompletion,
    ) -> Result<(), &'static str> {
        let (database, query) = match role {
            "worker" => ("worker.sqlite", "SELECT length(proof),substr(proof,1,65537),(SELECT COUNT(*) FROM worker_loss_return_completions) FROM worker_loss_return_completions WHERE admission=?1"),
            "controller" => ("lane_assignments.sqlite", "SELECT length(proof),substr(proof,1,65537),(SELECT COUNT(*) FROM la_loss_return_completions) FROM la_loss_return_completions WHERE admission=?1"),
            _ => return Err("evidence_invalid"),
        };
        let db = super::la_store::open_pinned_readonly_database(root, database)?;
        let (length, saved, count): (i64, Vec<u8>, i64) = db
            .query_row(query, [proof.admission()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map_err(|_| "evidence_invalid")?;
        if count != 1
            || saved.len() > RPC_JSON_MAX
            || length != saved.len() as i64
            || saved != serde_json::to_vec(proof).map_err(|_| "evidence_invalid")?
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    /// Revalidate the exact old authenticated head and FULL history without
    /// pretending that its pre-copy owned root is the current post-copy root.
    fn verify_history(
        root: &std::fs::File,
        role: &str,
        cap: &LossReturnAdmission,
        proof: &LossReturnCompletion,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        use std::os::unix::fs::MetadataExt;
        let (head, history, _) = Self::role(proof, role)?;
        let original = match role {
            "worker" => &cap.worker,
            "controller" => &cap.controller,
            _ => return Err("evidence_invalid"),
        };
        let m = root.metadata().map_err(|_| "evidence_invalid")?;
        let name = format!("{role}-channel.sqlite");
        let file = super::la_artifacts::open_artifact(root, &name, libc::O_RDONLY)
            .map_err(|_| "evidence_invalid")?;
        let fm = file.metadata().map_err(|_| "evidence_invalid")?;
        if (m.dev(), m.ino()) != (original.device, original.inode)
            || (m.dev(), m.ino()) != (head.body.root_dev, head.body.root_inode)
            || (fm.dev(), fm.ino()) != (head.body.db_dev, head.body.db_inode)
        {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_readonly_database(root, &name)?;
        let (frame, ack): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT frame,ack FROM channel_checkpoints ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let ack: CheckpointAck = serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
        ack.verify(&keys.custody, head)?;
        if frame != serde_json::to_vec(head).map_err(|_| "evidence_invalid")?
            || checkpoint_bytes_digest(&db, head.body.revision, head.body.revision)? != history
            || checkpoint_bytes_digest(&db, head.body.revision, original.checkpoint.body.revision)?
                != original.history
            || transport_state_digest(&db, &cap.binding)? != head.body.state_digest
        {
            return Err("evidence_invalid");
        }
        verify_transport_chain(&db, head, &keys.reply, &keys.custody)
    }
    pub(super) fn record(
        root: &std::fs::File,
        role: &str,
        cap: &LossReturnAdmission,
        proof: &LossReturnCompletion,
        keys: &ChannelKeys,
    ) -> Result<Self, &'static str> {
        Self::saved_completion(root, role, proof)?;
        Self::verify_history(root, role, cap, proof, keys)?;
        let (head, history, before) = Self::role(proof, role)?;
        let mut copy = Self {
            admission: cap.digest()?,
            completion: value_digest(proof)?,
            binding: cap.binding.clone(),
            role: role.into(),
            checkpoint: head.digest()?,
            history: history.into(),
            before: before.into(),
            after: state_custody::state_digest(root)?,
            consumed_at: wall_now()?,
            mac: [0; 32],
        };
        copy.mac = copy.signature(keys)?;
        copy.verify(cap, proof, role, keys, wall_now()?)?;
        let db =
            super::la_store::open_pinned_database(root, &format!("{role}-channel.sqlite"), false)?;
        db.execute_batch(
            "CREATE TABLE channel_loss_return_copy(admission TEXT PRIMARY KEY,body BLOB NOT NULL)",
        )
        .map_err(|_| "evidence_invalid")?;
        db.execute(
            "INSERT INTO channel_loss_return_copy VALUES(?1,?2)",
            rusqlite::params![
                copy.admission,
                serde_json::to_vec(&copy).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        root.sync_all().map_err(|_| "storage_unavailable")?;
        Self::read(root, role, cap, proof, keys)
    }
    fn read(
        root: &std::fs::File,
        role: &str,
        cap: &LossReturnAdmission,
        proof: &LossReturnCompletion,
        keys: &ChannelKeys,
    ) -> Result<Self, &'static str> {
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        let (length,bytes,count): (i64,Vec<u8>,i64) = db.query_row("SELECT length(body),substr(body,1,4097),(SELECT COUNT(*) FROM channel_loss_return_copy) FROM channel_loss_return_copy WHERE admission=?1",[cap.digest()?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_| "evidence_invalid")?;
        if count != 1 || bytes.len() > 4096 || length != bytes.len() as i64 {
            return Err("evidence_invalid");
        }
        let copy: Self = serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        copy.verify(cap, proof, role, keys, wall_now()?)?;
        Self::saved_completion(root, role, proof)?;
        Self::verify_history(root, role, cap, proof, keys)?;
        if state_custody::state_digest(root)? != copy.after {
            return Err("evidence_invalid");
        }
        copy.verify(cap, proof, role, keys, wall_now()?)?;
        Ok(copy)
    }
}

/// P's independent, named GLOBAL completion linearization. A role ACK, an
/// installed receipt or either local copy can never be decoded as this type.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossReturnLinearization {
    admission: String,
    completion: String,
    binding: ChannelBinding,
    worker: LossReturnCopy,
    controller: LossReturnCopy,
    service: (String, String, String, u64, u64),
    worker_storage: (u64, String),
    controller_storage: (u64, String),
    processes: String,
    process_observed_at: u64,
    worker_read_at: u64,
    controller_read_at: u64,
    issued_at: u64,
    expires_at: u64,
    mac: [u8; 32],
}
impl LossReturnLinearization {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(
            &keys.custody,
            b"diffuser-loss-return-global-linearization/v1\0",
            &v,
        )
    }
    fn digest(&self) -> Result<String, &'static str> {
        value_digest(self)
    }
    fn verify(
        &self,
        cap: &LossReturnAdmission,
        proof: &LossReturnCompletion,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        proof.verify(cap, keys, now)?;
        self.worker
            .verify(cap, proof, "worker", keys, self.issued_at)?;
        self.controller
            .verify(cap, proof, "controller", keys, self.issued_at)?;
        if self.admission != cap.digest()?
            || self.completion != value_digest(proof)?
            || self.binding != cap.binding
            || self.service.3 != proof.service.3.checked_add(2).ok_or("evidence_invalid")?
            || self.service.3 > 1025
            || self.service.4 != proof.service.4
            || self.service.1 != self.controller.after
            || self.worker_read_at < self.worker.consumed_at
            || self.controller_read_at < self.controller.consumed_at
            || self.worker_read_at > self.controller_read_at
            || self.controller_read_at > self.issued_at
            || self.process_observed_at < cap.processes.observed_at
            || self.process_observed_at > self.issued_at
            || now
                .checked_sub(self.process_observed_at)
                .is_none_or(|age| age >= 1500)
            || self.issued_at > now
            || self.expires_at != cap.expires_at
            || now >= self.expires_at
            || self.worker_storage.0 < cap.spent.retained_bytes
            || self.controller_storage.0 == 0
            || [
                &self.processes,
                &self.worker_storage.1,
                &self.controller_storage.1,
                &self.service.0,
                &self.service.2,
            ]
            .iter()
            .any(|s| s.len() != 64 || hex::decode(s).is_err())
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}
fn loss_return_read_bytes(
    root: &std::fs::File,
    name: &str,
    max: usize,
) -> Result<Vec<u8>, &'static str> {
    use std::io::Read;
    let mut bytes = Vec::new();
    super::la_artifacts::open_artifact(root, name, libc::O_RDONLY)
        .map_err(|_| "evidence_invalid")?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "evidence_invalid")?;
    if bytes.len() > max {
        return Err("evidence_invalid");
    }
    Ok(bytes)
}
impl CustodyLedger {
    /// Exact P-owned witness history plus the newly authenticated root delta.
    /// The old completed_anchor/root-equality predicate remains unchanged.
    fn verify_completed_copy(
        &self,
        root: &std::fs::File,
        cap: &LossReturnAdmission,
        proof: &LossReturnCompletion,
        keys: &ChannelKeys,
    ) -> Result<LossReturnCopy, &'static str> {
        let copy = LossReturnCopy::read(root, &self.role, cap, proof, keys)?;
        let (head, _, _) = LossReturnCopy::role(proof, &self.role)?;
        if self.binding != cap.binding
            || self.request_key != keys.reply
            || self.ack_key != keys.custody
            || self.pending_epoch.is_some()
            || self.head != head.digest()?
            || self.revision != head.body.revision
            || self.owned_state != head.body.owned_state
        {
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{}-channel.sqlite", self.role),
        )?;
        let ack: Vec<u8> = db
            .query_row(
                "SELECT ack FROM channel_checkpoints WHERE revision=?1",
                [self.revision as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let ack: CheckpointAck = serde_json::from_slice(&ack).map_err(|_| "evidence_invalid")?;
        // Reopen only P's own immutable witness history, never the role journal.
        let reopened = Self::reopen(&self.root, &self.path, head, &ack, keys.reply, keys.custody)?;
        if reopened.head != self.head
            || reopened.revision != self.revision
            || reopened.role != self.role
        {
            return Err("evidence_invalid");
        }
        Ok(copy)
    }
}
fn loss_return_controller_generation_guard(
    claims: &rusqlite::Connection,
    cap: &LossReturnAdmission,
    saved: &[u8],
) -> Result<bool, &'static str> {
    use rusqlite::OptionalExtension;
    let generation: bool=claims.query_row("SELECT (SELECT COUNT(*) FROM la_worker_session_generations)=1 AND EXISTS(SELECT 1 FROM la_worker_session_generations WHERE worker=?1 AND generation=2 AND body=?2)",rusqlite::params![cap.binding.worker,saved],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
    if !generation {
        return Ok(false);
    }
    let owner: Option<(String, String, String)> = claims
        .query_row(
            "SELECT project,actor,state FROM la_assignments WHERE id=?1",
            [&cap.spent.command.assignment],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| "evidence_invalid")?;
    let Some((project, actor, state)) = owner else {
        return Ok(false);
    };
    if state != "closed" || project != cap.authority.project {
        return Ok(false);
    }
    // These rows are retained audit history, not active quota/reservations.
    // Bind the ENTIRE set to the original closed assignment and its exact
    // current authenticated actor-to-root grant lineage. Extra, foreign or
    // missing rows refuse; no row is deleted or rewritten to open admission.
    let mut leaves =
        cap.authority.grants.iter().filter(|g| {
            g.actor == actor && g.project == project && g.tenant == cap.authority.tenant
        });
    let Some(mut grant) = leaves.next() else {
        return Ok(false);
    };
    if leaves.next().is_some() {
        return Ok(false);
    }
    let mut expected = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if !seen.insert(&grant.id) || seen.len() > 8 {
            return Ok(false);
        }
        expected.push((cap.spent.command.assignment.clone(), grant.id.clone()));
        let Some(parent) = &grant.parent else {
            break;
        };
        let mut parents = cap.authority.grants.iter().filter(|g| &g.id == parent);
        let Some(next) = parents.next() else {
            return Ok(false);
        };
        if parents.next().is_some() {
            return Ok(false);
        }
        grant = next;
    }
    expected.sort();
    let actual = {
        let mut st=claims.prepare("SELECT assignment_id,grant_id FROM la_assignment_grant_charges ORDER BY assignment_id,grant_id").map_err(|_|"evidence_invalid")?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|_| "evidence_invalid")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "evidence_invalid")?;
        rows
    };
    #[cfg(test)]
    recovery_trace(
        "loss_final_actual_grant_lineage_guard",
        serde_json::json!({"generation":generation,"retained_rows":actual.len(),"expected_rows":expected.len(),"exact":actual==expected}),
    );
    Ok(actual == expected)
}

impl LossReturnAdmission {
    fn verify_final_processes(
        &self,
        p: &LossReturnProcesses,
        wroot: &std::fs::File,
        croot: &std::fs::File,
    ) -> Result<(), &'static str> {
        let now = wall_now()?;
        verify_admission_process(
            &p.worker_ready,
            &p.worker,
            "worker",
            &self.binding,
            &wroot.metadata().map_err(|_| "evidence_invalid")?,
        )?;
        verify_admission_process(
            &p.controller_ready,
            &p.controller,
            "controller",
            &self.binding,
            &croot.metadata().map_err(|_| "evidence_invalid")?,
        )?;
        for (snapshot, role, identity) in [
            (&p.parent, "p", &self.processes.parent),
            (&p.keeper, "k", &self.processes.keeper),
        ] {
            qualification::snapshot(snapshot, role, &self.binding.executable_digest, false, None)?;
            if &snapshot["identity"] != identity {
                return Err("evidence_invalid");
            }
        }
        if p.worker["identity"] != self.processes.worker
            || p.controller["identity"] != self.processes.controller
            || value_digest(&p.worker_ready)? != self.processes.worker_ready
            || value_digest(&p.controller_ready)? != self.processes.controller_ready
            || p.observed_at < self.processes.observed_at
            || p.observed_at > now
            || now - p.observed_at >= 1500
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    fn verify_completed_sources_and_claims(
        &self,
        wroot: &std::fs::File,
        croot: &std::fs::File,
        proof: &LossReturnCompletion,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        self.verify_retained_worker(wroot, keys)?;
        let wd = super::la_store::open_pinned_readonly_database(wroot, "worker-channel.sqlite")?;
        let rows = logical_worker_sources(&wd, keys)?;
        let last = rows.last().ok_or("evidence_invalid")?;
        let now = wall_now()?;
        if value_digest(&rows)? != self.source_history
            || last.0 as u64 != self.service.4
            || last.1 < 0
            || last.1 as u64 > now
            || now - last.1 as u64 >= 1500
        {
            return Err("evidence_stale");
        }
        let claims =
            super::la_store::open_pinned_readonly_database(croot, "lane_assignments.sqlite")?;
        let count: i64 = claims
            .query_row("SELECT COUNT(*) FROM la_authority_observations", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        if count != rows.len() as i64 {
            return Err("evidence_invalid");
        }
        for (sequence, _, body, _) in &rows {
            let (saved, mac): (Vec<u8>, Vec<u8>) = claims
                .query_row(
                    "SELECT body,mac FROM la_authority_observations WHERE sequence=?1",
                    [sequence],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let mac: [u8; 32] = mac.try_into().map_err(|_| "evidence_invalid")?;
            verify_authority_observation(&keys.authority, &saved, &mac)?;
            if saved != *body {
                return Err("evidence_invalid");
            }
        }
        let exact:bool=claims.query_row("SELECT NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges) AND EXISTS(SELECT 1 FROM la_worker_cursor WHERE worker=?1 AND boot=?2 AND sequence=2) AND (SELECT MAX(fence) FROM la_assignments WHERE worker=?1)=1 AND EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts WHERE assignment_id=?3 AND digest=?4 AND released_at=?5) AND EXISTS(SELECT 1 FROM la_jobs WHERE id=?6 AND assignment_id=?3 AND state='failed' AND result_artifact IS NULL) AND (SELECT COUNT(*) FROM la_assignments)=1 AND (SELECT COUNT(*) FROM la_jobs)=1",rusqlite::params![self.binding.worker,self.binding.worker_boot,self.spent.command.assignment,self.spent.cleanup,self.spent.released_at as i64,self.spent.command.job],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if !exact {
            return Err("evidence_invalid");
        }
        let certificate: Vec<u8> = claims
            .query_row(
                "SELECT certificate FROM la_assignment_cleanup_receipts WHERE assignment_id=?1",
                [&self.spent.command.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if hex::encode(Sha256::digest(&certificate)) != self.spent.cleanup {
            return Err("evidence_invalid");
        }
        let certificate: cleanup::Certificate =
            serde_json::from_slice(&certificate).map_err(|_| "evidence_invalid")?;
        let (bridge, _) = verified_loss_source_bridge(&wd, keys)?.ok_or("evidence_invalid")?;
        let returned = bridge.returned(&wd, keys)?;
        let original =
            certificate.verify(&returned.previous, keys, croot, self.spent.released_at)?;
        let loss: Vec<u8> = wd
            .query_row(
                "SELECT response FROM channel_log WHERE sequence=?1",
                [returned.high_water() as i64],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let loss: WorkerLossSettlement =
            serde_json::from_slice(&loss).map_err(|_| "evidence_invalid")?;
        loss.verify_history(keys)?;
        if original.version != 2
            || certificate
                .loss
                .as_ref()
                .is_none_or(|l| l.digest().ok() != Some(loss.digest().unwrap_or_default()))
            || original.claim.assignment != self.spent.command.assignment
            || original.claim.boot != self.spent.previous_boot
            || original.claim.sequence != self.spent.sequence
            || original.claim.fence != self.spent.fence
        {
            return Err("evidence_invalid");
        }
        let saved = serde_json::to_vec(self).map_err(|_| "evidence_invalid")?;
        let worker = super::la_store::open_pinned_readonly_database(wroot, "worker.sqlite")?;
        let (bytes,at,ack):(Vec<u8>,i64,Vec<u8>)=worker.query_row("SELECT capability,installed_at,ack FROM worker_loss_return_installs WHERE admission=?1",[self.digest()?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"evidence_invalid")?;
        let (cbytes,wat,wack,cat,cack):(Vec<u8>,i64,Vec<u8>,i64,Vec<u8>)=claims.query_row("SELECT capability,worker_installed_at,worker_ack,installed_at,ack FROM la_loss_return_installs WHERE admission=?1",[self.digest()?],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(|_|"evidence_invalid")?;
        super::la_worker::verify_session_history(&worker, &keys.reply)?;
        let exact_generation: bool = worker.query_row("SELECT (SELECT COUNT(*) FROM worker_session_generations)=2 AND EXISTS(SELECT 1 FROM worker_session_generations WHERE generation=2 AND worker=?1 AND boot=?2 AND sequence=2 AND fence=1 AND authority=?3) AND (SELECT COUNT(*) FROM operations)=1 AND (SELECT COUNT(*) FROM operations WHERE state='started' AND report IS NULL)=1 AND (SELECT COUNT(*) FROM worker_reservations)=1 AND (SELECT COUNT(*) FROM worker_reservations WHERE closed=0)=1",rusqlite::params![self.binding.worker,self.binding.worker_boot,self.digest()?],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        let exact_controller = loss_return_controller_generation_guard(&claims, self, &saved)?;
        if !exact_generation || !exact_controller {
            return Err("evidence_invalid");
        }
        let cursor: (String, String, i64, i64) = worker
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if bytes != saved
            || cbytes != saved
            || at != wat
            || ack != wack
            || at < 0
            || cat < 0
            || at as u64 != proof.worker_installed_at
            || cat as u64 != proof.controller_installed_at
            || ack.as_slice() != proof.worker_ack
            || cack.as_slice() != proof.controller_ack
            || cursor
                != (
                    self.binding.worker.clone(),
                    self.binding.worker_boot.clone(),
                    2,
                    1,
                )
        {
            return Err("evidence_invalid");
        }
        // Require exact installed RPC10 on BOTH independently retained histories.
        for (root, role) in [(wroot, "worker"), (croot, "controller")] {
            let db = super::la_store::open_pinned_readonly_database(
                root,
                &format!("{role}-channel.sqlite"),
            )?;
            let (request, response): (Vec<u8>, Vec<u8>) = db
                .query_row(
                    "SELECT request,response FROM channel_log WHERE sequence=10",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            let req: SignedRequest =
                serde_json::from_slice(&request).map_err(|_| "evidence_invalid")?;
            let res: SignedResponse =
                serde_json::from_slice(&response).map_err(|_| "evidence_invalid")?;
            if !bool::from(
                typed_mac(&keys.command, b"diffuser-rpc-request/v1\0", &req.request)?
                    .ct_eq(&req.mac),
            ) || !matches!(&req.request.operation,WorkerOperation::AdmitLossReturn(cap) if cap.digest().ok()==Some(self.digest()?))
                || !matches!(&res.response.reply,WorkerReply::LossReturnInstalled{admission,installed_at,mac} if admission==&self.digest()? && *installed_at==proof.worker_installed_at && mac==&proof.worker_ack)
            {
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "P independently rereads fixed W/C/service custody and genuine current process/authority observations."
    )]
    pub(super) fn linearize_completed(
        &self,
        wroot: &std::fs::File,
        croot: &std::fs::File,
        worker: &mut CustodyLedger,
        controller: &CustodyLedger,
        service: &state_custody::Ledger,
        keys: &ChannelKeys,
        authority: &super::lane_assignment::DiscoveryContext,
        processes: &LossReturnProcesses,
    ) -> Result<LossReturnLinearization, &'static str> {
        use std::os::unix::fs::MetadataExt;
        self.verify_envelope(keys, wall_now()?)?;
        self.verify_current_authority(authority)?;
        self.verify_final_processes(processes, wroot, croot)?;
        let parent = service.loss_return_root()?;
        let pm = parent.metadata().map_err(|_| "evidence_invalid")?;
        for root in [wroot, croot] {
            let m = root.metadata().map_err(|_| "evidence_invalid")?;
            if (pm.dev(), pm.ino()) == (m.dev(), m.ino()) {
                return Err("evidence_invalid");
            }
        }
        if loss_return_read_bytes(&parent, "loss-return-admission-intent.json", 15360)?
            != serde_json::to_vec(self).map_err(|_| "evidence_invalid")?
        {
            return Err("evidence_invalid");
        }
        let retained: LossReturnProcesses = serde_json::from_slice(&loss_return_read_bytes(
            &parent,
            "loss-return-admission-processes.json",
            RPC_INPUT_MAX,
        )?)
        .map_err(|_| "evidence_invalid")?;
        if LossReturnProcessPins::capture(&retained)? != self.processes {
            return Err("evidence_invalid");
        }
        let proof: LossReturnCompletion = serde_json::from_slice(&loss_return_read_bytes(
            &parent,
            "loss-return-admission-completion.json",
            RPC_JSON_MAX,
        )?)
        .map_err(|_| "evidence_invalid")?;
        proof.verify(self, keys, wall_now()?)?;
        let w = worker.verify_completed_copy(wroot, self, &proof, keys)?;
        let wt = wall_now()?;
        let c = controller.verify_completed_copy(croot, self, &proof, keys)?;
        let ct = wall_now()?;
        self.verify_completed_sources_and_claims(wroot, croot, &proof, keys)?;
        let anchor = service.entered_loss_return_anchor(croot)?;
        let sd = super::la_store::open_pinned_readonly_database(croot, "service-custody.sqlite")?;
        let digest = value_digest(&proof)?;
        if anchor.3 != proof.service.3.checked_add(2).ok_or("evidence_invalid")?
            || anchor.4 != proof.service.4
            || anchor.1 != c.after
            || state_custody::loss_return_completion_history(&sd, anchor.3, proof.service.3)?
                != proof.service.2
            || state_custody::service_request_digest(&sd, anchor.3)?
                != (digest.clone(), Some(digest))
        {
            return Err("evidence_invalid");
        }
        let mut value = LossReturnLinearization {
            admission: self.digest()?,
            completion: value_digest(&proof)?,
            binding: self.binding.clone(),
            worker: w,
            controller: c,
            service: anchor,
            worker_storage: loss_return_physical(wroot)?,
            controller_storage: loss_return_physical(croot)?,
            processes: value_digest(processes)?,
            process_observed_at: processes.observed_at,
            worker_read_at: wt,
            controller_read_at: ct,
            issued_at: wall_now()?,
            expires_at: self.expires_at,
            mac: [0; 32],
        };
        value.mac = value.signature(keys)?;
        value.verify(self, &proof, keys, wall_now()?)?;
        loss_return_write_final_processes(&parent, processes)?;
        // This exclusive file+directory fsync is the distinct global linearization
        // point. No token escapes and no role admission changes before it.
        loss_return_write(&parent, "loss-return-admission-linearization.json", &value)?;
        if loss_return_read_bytes(
            &parent,
            "loss-return-admission-linearization.json",
            RPC_JSON_MAX,
        )? != serde_json::to_vec(&value).map_err(|_| "evidence_invalid")?
        {
            return Err("evidence_invalid");
        }
        worker.verify_completed_copy(wroot, self, &proof, keys)?;
        controller.verify_completed_copy(croot, self, &proof, keys)?;
        if service.entered_loss_return_anchor(croot)? != value.service {
            return Err("evidence_invalid");
        }
        self.verify_current_authority(authority)?;
        value.verify(self, &proof, keys, wall_now()?)?;
        // Adopt ONLY this independently witnessed exact root delta for the next
        // ordinary worker intent. Historical checkpoint/root equality is intact.
        worker.owned_state = Some(value.worker.after.clone());
        Ok(value)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossReturnActivation {
    binding: ChannelBinding,
    admission: String,
    linearization: String,
    role: String,
    consumed_at: u64,
    mac: [u8; 32],
}
impl LossReturnActivation {
    fn signature(&self, keys: &ChannelKeys) -> Result<[u8; 32], &'static str> {
        let mut v = self.clone();
        v.mac = [0; 32];
        typed_mac(
            &keys.reply,
            b"diffuser-loss-return-final-consumption/v1\0",
            &v,
        )
    }
    fn verify(
        &self,
        value: &LossReturnLinearization,
        role: &str,
        keys: &ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        if !matches!(role, "worker" | "controller")
            || self.binding != value.binding
            || self.admission != value.admission
            || self.linearization != value.digest()?
            || self.role != role
            || self.consumed_at < value.issued_at
            || self.consumed_at >= value.expires_at
            || self.consumed_at > now
            || !bool::from(self.signature(keys)?.ct_eq(&self.mac))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LossReturnFinalConsumption {
    pub(super) linearization: LossReturnLinearization,
    worker: LossReturnActivation,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LossReturnActiveRecord {
    linearization: LossReturnLinearization,
    receipt: LossReturnActivation,
    worker: Option<LossReturnActivation>,
}
impl LossReturnAdmission {
    fn load_completed(
        root: &std::fs::File,
        role: &str,
        digest: &str,
    ) -> Result<(Self, LossReturnCompletion), &'static str> {
        let (database,query)=match role {
            "worker"=>("worker.sqlite","SELECT length(i.capability),substr(i.capability,1,15361),length(c.proof),substr(c.proof,1,65537) FROM worker_loss_return_installs i JOIN worker_loss_return_completions c ON c.admission=i.admission WHERE i.admission=?1"),
            "controller"=>("lane_assignments.sqlite","SELECT length(i.capability),substr(i.capability,1,15361),length(c.proof),substr(c.proof,1,65537) FROM la_loss_return_installs i JOIN la_loss_return_completions c ON c.admission=i.admission WHERE i.admission=?1"),
            _=>return Err("evidence_invalid"),
        };
        let db = super::la_store::open_pinned_readonly_database(root, database)?;
        let (cl, c, pl, p): (i64, Vec<u8>, i64, Vec<u8>) = db
            .query_row(query, [digest], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .map_err(|_| "evidence_invalid")?;
        if c.len() > 15360 || p.len() > RPC_JSON_MAX || cl != c.len() as i64 || pl != p.len() as i64
        {
            return Err("evidence_invalid");
        }
        let cap: Self = serde_json::from_slice(&c).map_err(|_| "evidence_invalid")?;
        let proof: LossReturnCompletion =
            serde_json::from_slice(&p).map_err(|_| "evidence_invalid")?;
        if cap.digest()? != digest || proof.admission() != digest {
            return Err("evidence_invalid");
        }
        Ok((cap, proof))
    }
}
impl LossReturnActiveRecord {
    fn verify_historical(
        &self,
        root: &std::fs::File,
        role: &str,
        keys: &ChannelKeys,
    ) -> Result<(), &'static str> {
        let (cap, proof) =
            LossReturnAdmission::load_completed(root, role, &self.linearization.admission)?;
        // Authenticate at the ORIGINAL final consumption clock, not wall_now.
        // Current admission, source and grant checks remain separate barriers.
        self.linearization
            .verify(&cap, &proof, keys, self.receipt.consumed_at)?;
        self.receipt
            .verify(&self.linearization, role, keys, self.receipt.consumed_at)?;
        match (role, &self.worker) {
            ("worker", None) => (),
            ("controller", Some(peer)) => peer.verify(
                &self.linearization,
                "worker",
                keys,
                self.receipt.consumed_at,
            )?,
            _ => return Err("evidence_invalid"),
        }
        let db = super::la_store::open_pinned_readonly_database(
            root,
            &format!("{role}-channel.sqlite"),
        )?;
        let (_, epochs) = transport_epochs(&db)?;
        let Some(TransportTransition::EnteredLoss(h)) = epochs.last() else {
            return Err("evidence_invalid");
        };
        h.verify_history(&keys.custody)?;
        if h.digest()? != cap.spent.returned || h.binding != self.linearization.binding {
            return Err("evidence_invalid");
        }
        let (head, history, _) = LossReturnCopy::role(&proof, role)?;
        let current: i64 = db
            .query_row("SELECT MAX(revision) FROM channel_checkpoints", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        let current = u64::try_from(current).map_err(|_| "evidence_invalid")?;
        if checkpoint_bytes_digest(&db, current, head.body.revision)? != history {
            return Err("evidence_invalid");
        }
        Ok(())
    }
}
impl TransportJournal {
    fn authenticated_loss_return_activation(&self) -> Result<(), &'static str> {
        let (link, _, _, _, _) = self.custody.as_ref().ok_or("evidence_invalid")?;
        let (length,bytes,count):(i64,Vec<u8>,i64)=self.db.query_row("SELECT length(body),substr(body,1,65537),(SELECT COUNT(*) FROM channel_loss_return_activation) FROM channel_loss_return_activation",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"evidence_invalid")?;
        if count != 1 || bytes.len() > RPC_JSON_MAX || length != bytes.len() as i64 {
            return Err("evidence_invalid");
        }
        let record: LossReturnActiveRecord =
            serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
        if record.linearization.binding != self.binding {
            return Err("evidence_invalid");
        }
        // Only the already protected reply/custody keys are used here. This
        // predicate neither authenticates new commands nor supplies authority.
        let keys = ChannelKeys {
            command: [0; 32],
            reply: link.request_key,
            authority: [0; 32],
            custody: link.ack_key,
        };
        record.verify_historical(&self.root, &link.role, &keys)
    }
    fn consume_loss_return_final(
        &mut self,
        admission: &WorkerAdmission,
        value: &LossReturnLinearization,
        worker: Option<&LossReturnActivation>,
        keys: &ChannelKeys,
    ) -> Result<LossReturnActivation, &'static str> {
        self.check()?;
        let role = self
            .custody
            .as_ref()
            .ok_or("evidence_invalid")?
            .0
            .role
            .clone();
        let (cap, proof) =
            LossReturnAdmission::load_completed(&self.root, &role, &value.admission)?;
        value.verify(&cap, &proof, keys, wall_now()?)?;
        let copy = LossReturnCopy::read(&self.root, &role, &cap, &proof, keys)?;
        let expected = match role.as_str() {
            "worker" => &value.worker,
            "controller" => &value.controller,
            _ => return Err("evidence_invalid"),
        };
        if value_digest(&copy)? != value_digest(expected)? || value.binding != self.binding {
            return Err("evidence_invalid");
        }
        if role == "worker" {
            if loss_return_physical(&self.root)? != value.worker_storage {
                return Err("evidence_invalid");
            }
            cap.verify_retained_worker(&self.root, keys)?;
            let rows = logical_worker_sources(&self.db, keys)?;
            let last = rows.last().ok_or("evidence_invalid")?;
            let now = wall_now()?;
            if value_digest(&rows)? != cap.source_history
                || last.1 < 0
                || last.1 as u64 > now
                || now - last.1 as u64 >= 1500
            {
                return Err("evidence_stale");
            }
        }
        let mut current = admission.0.lock().map_err(|_| "storage_unavailable")?;
        if current.is_some() {
            return Err("evidence_invalid");
        }
        let mut receipt = LossReturnActivation {
            binding: value.binding.clone(),
            admission: value.admission.clone(),
            linearization: value.digest()?,
            role: role.clone(),
            consumed_at: wall_now()?,
            mac: [0; 32],
        };
        receipt.mac = receipt.signature(keys)?;
        let record = LossReturnActiveRecord {
            linearization: value.clone(),
            receipt: receipt.clone(),
            worker: worker.cloned(),
        };
        record.verify_historical(&self.root, &role, keys)?;
        let bytes = serde_json::to_vec(&record).map_err(|_| "evidence_invalid")?;
        if bytes.len() > RPC_JSON_MAX {
            return Err("evidence_invalid");
        }
        self.db.execute_batch("CREATE TABLE channel_loss_return_activation(admission TEXT PRIMARY KEY,body BLOB NOT NULL)").map_err(|_|"evidence_invalid")?;
        self.db
            .execute(
                "INSERT INTO channel_loss_return_activation VALUES(?1,?2)",
                rusqlite::params![value.admission, bytes],
            )
            .map_err(|_| "storage_unavailable")?;
        self.root.sync_all().map_err(|_| "storage_unavailable")?;
        self.authenticated_loss_return_activation()?;
        value.verify(&cap, &proof, keys, wall_now()?)?;
        if state_custody::state_digest(&self.root)? != expected.after {
            return Err("evidence_invalid");
        }
        loss_return_physical(&self.root)?;
        value.verify(&cap, &proof, keys, wall_now()?)?;
        if role == "worker" {
            if !self.owned_state {
                return Err("evidence_invalid");
            }
            self.owned_digest = Some(expected.after.clone());
        }
        // The lease retains the original FIRST bound; consumption never renews
        // a source/resource/grant or a previous job's mandate/permit/lease.
        *current = Some(AdmissionLease {
            issued_at: receipt.consumed_at,
            expires_at: value.expires_at,
            job_scope: None,
        });
        Ok(receipt)
    }
}
impl WorkerRpc {
    pub(super) fn activate_loss_return(
        &mut self,
        bytes: &[u8],
    ) -> Result<LossReturnActivation, &'static str> {
        if bytes.len() > 16 * 1024 {
            return Err("evidence_invalid");
        }
        let value: LossReturnLinearization =
            serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
        if self.session.worker != value.binding.worker
            || self.session.boot != value.binding.worker_boot
            || self.session.key != self.keys.reply
        {
            return Err("evidence_invalid");
        }
        self.channel
            .consume_loss_return_final(&self.admission, &value, None, &self.keys)
    }
}
impl WorkerClient {
    pub(super) fn activate_loss_return(
        &mut self,
        request: &LossReturnFinalConsumption,
        domain: &state_custody::Session,
    ) -> Result<serde_json::Value, &'static str> {
        let value = &request.linearization;
        let (cap, proof) = LossReturnAdmission::load_completed(
            &self.channel.root,
            "controller",
            &value.admission,
        )?;
        value.verify(&cap, &proof, &self.keys, wall_now()?)?;
        request
            .worker
            .verify(value, "worker", &self.keys, wall_now()?)?;
        if domain.binding() != Ok(value.binding.clone())
            || domain.loss_return_completion_anchor()?
                != (
                    value.service.0.clone(),
                    value.controller.after.clone(),
                    value.service.2.clone(),
                    value.service.3,
                )
        {
            return Err("evidence_invalid");
        }
        if loss_return_physical(&self.channel.root)? != value.controller_storage {
            return Err("evidence_invalid");
        }
        let operation = domain.begin(&value.digest()?)?;
        let receipt = self.channel.consume_loss_return_final(
            &self.admission,
            value,
            Some(&request.worker),
            &self.keys,
        )?;
        // Any error after local persistence explicitly removes the memory lease.
        // No restart/replay path infers activation from that durable local row.
        let result = (|| {
            domain.complete(operation, &value_digest(&receipt)?)?;
            value.verify(&cap, &proof, &self.keys, wall_now()?)?;
            self.admission.check()?;
            Ok(serde_json::json!({"kind":"LOSS_RETURN_ACTIVATED","receipt":receipt}))
        })();
        if result.is_err() {
            *self.admission.0.lock().map_err(|_| "storage_unavailable")? = None;
        }
        result
    }
}

impl LossReturnLinearization {
    pub(super) fn admission(&self) -> &str {
        &self.admission
    }
}

fn loss_return_write_final_processes(
    root: &std::fs::File,
    processes: &LossReturnProcesses,
) -> Result<(), &'static str> {
    use std::io::Write;
    let bytes = serde_json::to_vec(processes).map_err(|_| "evidence_invalid")?;
    if bytes.len() > RPC_INPUT_MAX {
        return Err("evidence_invalid");
    }
    let mut f = super::la_artifacts::open_artifact(
        root,
        "loss-return-admission-final-processes.json",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )
    .map_err(|_| "evidence_invalid")?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .and_then(|_| root.sync_all())
        .map_err(|_| "storage_unavailable")
}

#[cfg(test)]
#[path = "la_backend_tests.rs"]
mod backend_tests;
