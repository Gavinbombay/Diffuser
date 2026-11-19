//! Types for the single existing private CUDA add-one wire family.
use super::{
    AssignmentAcquired, Attempt, Client, DisconnectPolicy, Error, Id, JobAccepted, JobView,
    LaneSchema, Mutation, QueuePolicy, ReceiptStore, Sha256Digest, Transport, VerifiedArtifact,
};
use serde::{Deserialize, Serialize};

const CAPABILITY: &str = "compute.cuda.add-one/v1";
const PROFILE: &str = "cuda-private-add-one/v1";

/// Canonical physical CUDA device UUID. Never normalizes or resolves an ordinal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct CudaDeviceUuid(String);

impl CudaDeviceUuid {
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        let valid = value.strip_prefix("GPU-").is_some_and(|suffix| {
            suffix.len() == 36
                && suffix.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                })
        });
        if !valid {
            return Err(Error::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CudaDeviceUuid {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Error> {
        Self::new(value)
    }
}

/// Refuse-only acquire for exactly one device and the private CUDA profile.
/// The existing v1 route requires explicit null lane/resource/provider selectors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CudaAcquire {
    schema_version: LaneSchema,
    capability: &'static str,
    lane_id: Option<Id>,
    profile_id: &'static str,
    resource_id: Option<Id>,
    provider_id: Option<Id>,
    requested_hardware_description: Option<String>,
    resources: CudaResources,
    queue_policy: QueuePolicy,
    requested_lease_ms: u64,
    requested_tenure_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CudaResources {
    cpu_millicores: u64,
    ram_bytes: u64,
    storage_bytes: u64,
    gpu_domains: [CudaDeviceUuid; 1],
}

impl CudaAcquire {
    pub fn new(
        device_uuid: CudaDeviceUuid,
        cpu_millicores: u64,
        ram_bytes: u64,
        storage_bytes: u64,
        requested_lease_ms: u64,
        requested_tenure_ms: u64,
    ) -> Result<Self, Error> {
        if ![
            cpu_millicores,
            ram_bytes,
            storage_bytes,
            requested_lease_ms,
            requested_tenure_ms,
        ]
        .into_iter()
        .all(wire_positive)
        {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            schema_version: LaneSchema::V1,
            capability: CAPABILITY,
            lane_id: None,
            profile_id: PROFILE,
            resource_id: None,
            provider_id: None,
            requested_hardware_description: None,
            resources: CudaResources {
                cpu_millicores,
                ram_bytes,
                storage_bytes,
                gpu_domains: [device_uuid],
            },
            queue_policy: QueuePolicy::Refuse,
            requested_lease_ms,
            requested_tenure_ms,
        })
    }
}

/// An explicit caller selection; the existing route supports only add-one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CudaWorkload {
    AddOne,
}

/// V2 submit body on the existing v1 assignment jobs route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CudaSubmit {
    schema_version: &'static str,
    client_job_id: Id,
    capability: &'static str,
    profile_version: &'static str,
    input_artifact_ids: [Id; 1],
    parameters: CudaParameters,
    max_runtime_ms: u64,
    disconnect_policy: DisconnectPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct CudaParameters {
    backend: &'static str,
    device_uuid: CudaDeviceUuid,
    workload: CudaWorkload,
}

impl CudaSubmit {
    /// The artifact must contain the private CUDA input envelope for `workload`.
    /// Use the same explicitly chosen device as the acquire request.
    pub fn new(
        client_job_id: Id,
        input_artifact_id: Id,
        device_uuid: CudaDeviceUuid,
        workload: CudaWorkload,
        max_runtime_ms: u64,
    ) -> Result<Self, Error> {
        if !wire_positive(max_runtime_ms) {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            schema_version: "diffuser-lane/v2",
            client_job_id,
            capability: CAPABILITY,
            profile_version: "1",
            input_artifact_ids: [input_artifact_id],
            parameters: CudaParameters {
                backend: PROFILE,
                device_uuid,
                workload,
            },
            max_runtime_ms,
            disconnect_policy: DisconnectPolicy::ContinueUntilJobDeadline,
        })
    }
}

fn wire_positive(n: u64) -> bool {
    (1..=i64::MAX as u64).contains(&n)
}

/// Parsed only as part of verified CUDA job readback.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaReport {
    schema_version: String,
    capability: String,
    backend: String,
    pub job_id: Id,
    pub device_uuid: CudaDeviceUuid,
    pub workload: CudaWorkload,
    /// Digest and length of the input envelope, as reported by the worker.
    pub sha256: Sha256Digest,
    pub bytes: u64,
    pub values: [u8; 16],
}

#[derive(Debug, Eq, PartialEq)]
pub struct ResumedCudaJob {
    pub job: JobView,
    pub result: Option<(VerifiedArtifact, CudaReport)>,
}

impl<T: Transport> Client<T> {
    /// Request an assignment on the exact CUDA device. No discovery, fallback,
    /// routing enablement or automatic retry is performed.
    pub async fn acquire_cuda(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        body: &CudaAcquire,
    ) -> Result<AssignmentAcquired, Error> {
        self.acquire_typed(store, attempt, body).await
    }

    /// Submit the selected CUDA workload. Keep the original key and body for
    /// an explicit retry after an uncertain response.
    pub async fn submit_cuda(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        assignment: &Id,
        body: &CudaSubmit,
    ) -> Result<JobAccepted, Error> {
        self.submit_versioned(store, attempt, assignment, Mutation::CudaSubmit, body)
            .await
    }

    /// Use the saved submit receipt and exact original body to read back this
    /// job using GETs only. Artifact bytes and request/device/workload bindings
    /// are verified; no work is reissued or input bytes fetched.
    pub async fn resume_cuda_job(
        &self,
        store: &ReceiptStore,
        submit_key: &Id,
        body: &CudaSubmit,
    ) -> Result<ResumedCudaJob, Error> {
        let encoded = serde_json::to_vec(body).map_err(|_| Error::InvalidRequest)?;
        let (job, result) = self
            .resume_submitted(
                store,
                submit_key,
                Mutation::CudaSubmit,
                Some(Sha256Digest::of(&encoded)),
                |report: &CudaReport, job| {
                    &report.job_id == job
                        && report.schema_version == "diffuser-private-cuda-output/v1"
                        && report.capability == CAPABILITY
                        && report.backend == PROFILE
                        && report.device_uuid == body.parameters.device_uuid
                        && report.workload == body.parameters.workload
                        && (1..=128).contains(&report.bytes)
                        && report.values == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
                },
            )
            .await?;
        Ok(ResumedCudaJob { job, result })
    }
}
