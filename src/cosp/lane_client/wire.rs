use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

/// Exact opaque wire value. Validation never rewrites a supplied identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);

impl Id {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(Error::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Id {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Error> {
        Self::new(value)
    }
}

impl From<Id> for String {
    fn from(value: Id) -> Self {
        value.0
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub tenant: Id,
    pub project: Id,
    pub actor: Id,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Unavailable,
    ReplyLost,
    ResponseLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidIdentifier,
    InvalidRequest,
    UnsupportedSelection,
    RequestLimit,
    ArtifactIntegrity,
    ReceiptIdentity,
    ReceiptStorage,
    ReceiptMissing,
    ReceiptConflict,
    ReceiptLimit,
    ReceiptUncertain,
    Transport(TransportError),
    UnexpectedResponse(StatusCode),
    Public(PublicError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(error) => {
                write!(f, "HTTP {} {}", error.status.as_u16(), error.code.as_str())
            }
            _ => write!(f, "{self:?}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Eq, PartialEq)]
pub struct PublicError {
    pub status: StatusCode,
    pub code: PublicCode,
    pub retry_action: RetryAction,
    pub request_id: Id,
    pub object_id: Option<Id>,
}

impl std::fmt::Debug for PublicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicError")
            .field("status", &self.status)
            .field("code", &self.code.as_str())
            .field("retry_action", &self.retry_action)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryAction {
    None,
    SameId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicCode {
    AuthRequired,
    AuthInvalid,
    ScopeDenied,
    DelegationDenied,
    QuotaExceeded,
    ObjectNotFound,
    LaneNotFound,
    IdempotencyConflict,
    CapacityUnavailable,
    StateConflict,
    ArtifactExpired,
    EvidenceStale,
    EvidenceInvalid,
    BodyTooLarge,
    MediaTypeUnsupported,
    ArtifactInvalid,
    ProviderUnconfigured,
    CapabilityUnavailable,
    RuntimeLimitExceeded,
    UnsupportedOperation,
    RoutingClosed,
    StorageUnavailable,
    ClockUntrusted,
    SchemaInvalid,
    VersionUnsupported,
    DuplicateMember,
    ConstraintUnresolved,
    IdempotencyRequired,
    RevisionConflict,
    DeadlineElapsed,
    InventoryUnavailable,
    TransportUncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LaneSchema {
    #[serde(rename = "diffuser-lane/v1")]
    V1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub schema_version: LaneSchema,
    pub queue_mode: QueuePolicy,
    pub lanes: Vec<Lane>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueuePolicy {
    Refuse,
    FairQueue,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    pub lane_id: String,
    pub capability: String,
    pub profile_id: String,
    pub accepting: bool,
    pub reason: String,
}

impl Discovery {
    /// Check the exact frozen v1 tuple. Discovery carries no profile revision
    /// field or capacity grant. The v1 mapping fixes the inspection revision.
    pub fn negotiate(
        &self,
        lane: &str,
        capability: &str,
        profile: &str,
        revision: &str,
    ) -> Result<&Lane, Error> {
        use super::{INSPECT_CAPABILITY, INSPECT_PROFILE, INSPECT_REVISION};
        if (capability, profile, revision)
            != (INSPECT_CAPABILITY, INSPECT_PROFILE, INSPECT_REVISION)
        {
            return Err(Error::UnsupportedSelection);
        }
        let mut selected = self.lanes.iter().filter(|entry| entry.lane_id == lane);
        let entry = selected.next().ok_or(Error::UnsupportedSelection)?;
        if selected.next().is_some()
            || entry.capability != capability
            || entry.profile_id != profile
        {
            return Err(Error::UnsupportedSelection);
        }
        Ok(entry)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErrorEnvelope {
    #[serde(rename = "schema_version")]
    _schema_version: LaneSchema,
    pub(super) error: WireError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireError {
    pub(super) code: PublicCode,
    pub(super) retry_action: RetryAction,
    pub(super) request_id: Id,
    #[serde(deserialize_with = "nullable")]
    pub(super) object_id: Option<Id>,
}

pub(super) fn nullable<'de, D: serde::Deserializer<'de>, V: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<V>, D::Error> {
    Option::deserialize(deserializer)
}

impl PublicCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthRequired => "auth_required",
            Self::AuthInvalid => "auth_invalid",
            Self::ScopeDenied => "scope_denied",
            Self::DelegationDenied => "delegation_denied",
            Self::QuotaExceeded => "quota_exceeded",
            Self::ObjectNotFound => "object_not_found",
            Self::LaneNotFound => "lane_not_found",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::CapacityUnavailable => "capacity_unavailable",
            Self::StateConflict => "state_conflict",
            Self::ArtifactExpired => "artifact_expired",
            Self::EvidenceStale => "evidence_stale",
            Self::EvidenceInvalid => "evidence_invalid",
            Self::BodyTooLarge => "body_too_large",
            Self::MediaTypeUnsupported => "media_type_unsupported",
            Self::ArtifactInvalid => "artifact_invalid",
            Self::ProviderUnconfigured => "provider_unconfigured",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::RuntimeLimitExceeded => "runtime_limit_exceeded",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::RoutingClosed => "routing_closed",
            Self::StorageUnavailable => "storage_unavailable",
            Self::ClockUntrusted => "clock_untrusted",
            Self::SchemaInvalid => "schema_invalid",
            Self::VersionUnsupported => "version_unsupported",
            Self::DuplicateMember => "duplicate_member",
            Self::ConstraintUnresolved => "constraint_unresolved",
            Self::IdempotencyRequired => "idempotency_required",
            Self::RevisionConflict => "revision_conflict",
            Self::DeadlineElapsed => "deadline_elapsed",
            Self::InventoryUnavailable => "inventory_unavailable",
            Self::TransportUncertain => "transport_uncertain",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ArtifactSchema {
    #[serde(rename = "diffuser-artifact/v1")]
    V1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Error> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::ArtifactIntegrity);
        }
        Ok(Self(value))
    }
}

impl From<Sha256Digest> for String {
    fn from(value: Sha256Digest) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Input,
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSource {
    CallerUpload,
    WorkerResult,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub schema_version: ArtifactSchema,
    pub tenant_id: Id,
    pub project_id: Id,
    pub owner_id: Id,
    pub actor_id: Id,
    pub initiator_id: Id,
    pub artifact_id: Id,
    pub version: u64,
    pub sha256: Sha256Digest,
    pub bytes: u64,
    pub media_type: String,
    pub kind: ArtifactKind,
    pub data_class: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub publication_state: String,
    #[serde(deserialize_with = "nullable")]
    pub assignment_id: Option<Id>,
    #[serde(deserialize_with = "nullable")]
    pub job_id: Option<Id>,
    pub provenance: ArtifactProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProvenance {
    pub source: ArtifactSource,
    pub authority_lineage: Vec<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUploaded {
    pub schema_version: LaneSchema,
    pub receipt_id: Id,
    pub request_id: Id,
    pub project_id: Id,
    pub object_type: String,
    pub object_id: Id,
    pub revision: u64,
    pub state: String,
    pub links: ArtifactLinks,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLinks {
    #[serde(rename = "self")]
    pub self_path: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedArtifact {
    pub metadata: ArtifactManifest,
    pub bytes: axum::body::Bytes,
}

impl std::fmt::Debug for VerifiedArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedArtifact")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acquire {
    pub schema_version: LaneSchema,
    pub capability: String,
    pub lane_id: String,
    pub profile_id: String,
    pub resource_id: Option<String>,
    pub provider_id: Option<String>,
    pub requested_hardware_description: Option<String>,
    pub resources: Resources,
    pub queue_policy: QueuePolicy,
    pub requested_lease_ms: u64,
    pub requested_tenure_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu_millicores: u64,
    pub ram_bytes: u64,
    pub storage_bytes: u64,
    pub gpu_domains: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub schema_version: LaneSchema,
    pub expected_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Renew {
    pub schema_version: LaneSchema,
    pub expected_revision: u64,
    pub requested_lease_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentState {
    Reserved,
    Assigned,
    Draining,
    Quarantined,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentAcquired {
    pub schema_version: LaneSchema,
    pub assignment_id: Id,
    pub state: AssignmentState,
    pub lease_expires_at: u64,
    pub hard_expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentView {
    pub schema_version: LaneSchema,
    pub assignment_id: Id,
    pub state: AssignmentState,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalState {
    Pending,
    Acknowledged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentRenewal {
    pub schema_version: LaneSchema,
    pub assignment_id: Id,
    pub revision: u64,
    /// Last acknowledged value reported by the service.
    pub lease_expires_at: u64,
    pub renewal_state: RenewalState,
}

impl AssignmentRenewal {
    /// An unacknowledged renewal contributes no new lease guarantee.
    pub fn acknowledged_lease(&self) -> Option<u64> {
        (self.renewal_state == RenewalState::Acknowledged).then_some(self.lease_expires_at)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentRelease {
    pub schema_version: LaneSchema,
    pub assignment_id: Id,
    pub state: AssignmentState,
}

impl AssignmentRelease {
    /// Only a verified 200/closed response establishes completed release.
    pub fn released(&self) -> bool {
        self.state == AssignmentState::Closed
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submit {
    pub schema_version: LaneSchema,
    pub client_job_id: Id,
    pub capability: String,
    pub profile_version: String,
    /// V1 submits exactly one immutable input.
    pub input_artifact_ids: [Id; 1],
    pub parameters: InspectParameters,
    pub max_runtime_ms: u64,
    pub disconnect_policy: DisconnectPolicy,
}

/// An explicit v2 request for the private CPU SHA-256 backend. The route,
/// assignment profile and response envelope are still the v1 ones.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CpuSubmit {
    schema_version: &'static str,
    client_job_id: Id,
    capability: &'static str,
    profile_version: &'static str,
    input_artifact_ids: [Id; 1],
    parameters: CpuParameters,
    max_runtime_ms: u64,
    disconnect_policy: DisconnectPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CpuParameters {
    backend: CpuBackend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CpuBackend {
    #[serde(rename = "cpu-private-sha256/v1")]
    PrivateSha256,
}

impl CpuSubmit {
    /// `input_artifact_id` names a previously uploaded private SHA-256 input
    /// envelope, not arbitrary bytes as in a v1 inspection request.
    pub fn new(
        client_job_id: Id,
        input_artifact_id: Id,
        max_runtime_ms: u64,
    ) -> Result<Self, Error> {
        if !(1..=i64::MAX as u64).contains(&max_runtime_ms) {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            schema_version: "diffuser-lane/v2",
            client_job_id,
            capability: super::INSPECT_CAPABILITY,
            profile_version: super::INSPECT_REVISION,
            input_artifact_ids: [input_artifact_id],
            parameters: CpuParameters {
                backend: CpuBackend::PrivateSha256,
            },
            max_runtime_ms,
            disconnect_policy: DisconnectPolicy::ContinueUntilJobDeadline,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectParameters {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisconnectPolicy {
    ContinueUntilJobDeadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Pending,
    Running,
    Stopping,
    Cancelled,
    Finalizing,
    Succeeded,
    // Protected terminal loss currently exposes this state outside the older schema.
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobAccepted {
    pub schema_version: LaneSchema,
    pub job_id: Id,
    pub assignment_id: Id,
    pub state: JobState,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobView {
    pub schema_version: LaneSchema,
    pub job_id: Id,
    pub assignment_id: Id,
    pub state: JobState,
    pub revision: u64,
    #[serde(deserialize_with = "nullable")]
    pub result_artifact_id: Option<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobCancellation {
    pub schema_version: LaneSchema,
    pub job_id: Id,
    pub state: JobState,
    pub revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectReport {
    pub schema_version: ArtifactSchema,
    pub capability: String,
    pub profile_id: String,
    pub profile_version: String,
    pub job_id: Id,
    pub sha256: Sha256Digest,
    pub bytes: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ResumedJob {
    pub job: JobView,
    pub result: Option<(VerifiedArtifact, InspectReport)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
pub enum CpuReportSchema {
    #[serde(rename = "diffuser-private-sha256-output/v1")]
    V1,
}

/// The private CPU backend's report, distinct from the v1 inspection report.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuReport {
    pub schema_version: CpuReportSchema,
    pub capability: String,
    pub backend: CpuBackend,
    pub job_id: Id,
    /// Digest and size of the uploaded input envelope (not the decoded data).
    pub sha256: Sha256Digest,
    pub bytes: u64,
    pub data_bytes: u64,
    pub rounds: u32,
    pub output_sha256: Sha256Digest,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ResumedCpuJob {
    pub job: JobView,
    pub result: Option<(VerifiedArtifact, CpuReport)>,
}
