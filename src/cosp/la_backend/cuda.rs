//! Wire and output contract for exactly one bounded CUDA workload. There is no
//! ordinary driver bootstrap here; the process binding is for trusted startup.
use super::Capability;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(in crate::cosp) const CAPABILITY: &str = "compute.cuda.add-one/v1";
pub(in crate::cosp) const PROFILE: &str = "cuda-private-add-one/v1";
const WORKLOAD: &str = "add_one";
const INPUT_SCHEMA: &str = "diffuser-private-cuda-input/v1";
pub(super) const OUTPUT_SCHEMA: &str = "diffuser-private-cuda-output/v1";
const MAX_INPUT: usize = 128;
const VERIFIED: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::cosp) struct DeviceUuid([u8; 40]);

impl DeviceUuid {
    pub(in crate::cosp) fn parse(value: &str) -> Option<Self> {
        let bytes: [u8; 40] = value.as_bytes().try_into().ok()?;
        (value.starts_with("GPU-")
            && bytes[4..].iter().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            }))
        .then_some(Self(bytes))
    }

    pub(in crate::cosp) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("validated ASCII UUID")
    }
}

impl Serialize for DeviceUuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for DeviceUuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value)
            .ok_or_else(|| serde::de::Error::custom("canonical physical CUDA UUID required"))
    }
}

pub(super) fn negotiate(parameters: &serde_json::Value) -> Result<Capability, &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Parameters {
        backend: String,
        device_uuid: DeviceUuid,
        workload: String,
    }
    let p: Parameters = serde_json::from_value(parameters.clone()).map_err(|_| "schema_invalid")?;
    if p.backend != PROFILE || p.workload != WORKLOAD {
        return Err("capability_unavailable");
    }
    Ok(Capability::CudaAddOne(p.device_uuid))
}

pub(super) fn validate_input(bytes: &[u8]) -> Result<(), &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        schema_version: String,
        workload: String,
    }
    if bytes.len() > MAX_INPUT {
        return Err("artifact_invalid");
    }
    let normalized =
        super::super::la_contract::canonical_json(bytes).map_err(|_| "artifact_invalid")?;
    let input: Input = serde_json::from_slice(&normalized).map_err(|_| "artifact_invalid")?;
    if input.schema_version != INPUT_SCHEMA || input.workload != WORKLOAD {
        return Err("artifact_invalid");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::cosp) struct Readback {
    device_uuid: DeviceUuid,
    workload: String,
    values: [u8; 16],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report<'a> {
    schema_version: &'a str,
    capability: &'a str,
    backend: &'a str,
    device_uuid: DeviceUuid,
    workload: &'a str,
    job_id: &'a str,
    sha256: &'a str,
    bytes: usize,
    values: [u8; 16],
}

pub(super) fn report(
    uuid: DeviceUuid,
    output: Readback,
    job: &str,
    digest: &str,
    bytes: usize,
) -> Result<Vec<u8>, &'static str> {
    if output.device_uuid != uuid || output.workload != WORKLOAD || output.values != VERIFIED {
        return Err("execution_uncertain");
    }
    serde_json::to_vec(&Report {
        schema_version: OUTPUT_SCHEMA,
        capability: CAPABILITY,
        backend: PROFILE,
        device_uuid: uuid,
        workload: WORKLOAD,
        job_id: job,
        sha256: digest,
        bytes,
        values: output.values,
    })
    .map_err(|_| "execution_uncertain")
}

pub(super) fn validate_report(
    bytes: &[u8],
    job: &str,
    digest: &str,
    input_size: Option<usize>,
    expected: Option<Capability>,
) -> Result<(), &'static str> {
    let report: Report<'_> = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
    if report.schema_version != OUTPUT_SCHEMA
        || report.capability != CAPABILITY
        || report.backend != PROFILE
        || expected.is_some_and(|selected| selected != Capability::CudaAddOne(report.device_uuid))
        || report.workload != WORKLOAD
        || report.job_id != job
        || report.sha256 != digest
        || !(1..=MAX_INPUT).contains(&report.bytes)
        || input_size.is_some_and(|n| report.bytes != n)
        || report.values != VERIFIED
    {
        return Err("evidence_invalid");
    }
    Ok(())
}

mod process;
#[cfg_attr(not(test), allow(unused_imports))]
pub(in crate::cosp) use process::CudaProcess;

#[cfg(test)]
mod launcher_tests;
