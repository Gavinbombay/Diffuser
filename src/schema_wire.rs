//! Wire field contracts. JSON Schema remains responsible for value constraints.
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn present<'de, D: serde::Deserializer<'de>>(input: D) -> Result<Value, D::Error> {
    Value::deserialize(input)
}

macro_rules! wire {
    ($name:ident { required { $($r:ident: $rt:ty),* $(,)? } optional { $($o:ident: $ot:ty),* $(,)? } }) => {
        #[allow(dead_code)]
        #[derive(Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct $name {
            $(#[serde(deserialize_with = "present")] $r: $rt,)*
            $(#[serde(skip_serializing_if = "Option::is_none")] $o: Option<$ot>,)*
        }
        #[cfg(test)]
        impl $name {
            const REQUIRED: &'static [&'static str] = &[$(stringify!($r)),*];
            const OPTIONAL: &'static [&'static str] = &[$(stringify!($o)),*];
        }
    };
}

wire!(JobSpec { required { spec: Value, job_id: Value, lane: Value, cartridge: Value, card_pref: Value, items: Value, seg_min: Value, deadline_min: Value, max_segs: Value, outputs: Value } optional { blend: Value, budget_cu: Value, cap_cu: Value, entry: Value, gpu_class: Value, gpu_min_vram_gb: Value, licence_checked_at: Value, licence_commercial: Value, licence_id: Value, r#use: Value } });

wire!(JobSpecItems { required { id: Value, args: Value } optional {  } });

wire!(CardState { required { schema_version: Value, card: Value, worker_id: Value, ts: Value, epoch: Value, state: Value, util: Value, watts: Value, vram_mb: Value, vram_total_mb: Value, ram_mb: Value, backends: Value, capacity: Value, busy: Value } optional { cu: Value, gpu_class: Value, job_id: Value, legacy: Value, proof_source: Value, seat: Value, segment: Value, self_probe: Value, session: Value, vram_gb: Value } });

wire!(CardStateCapacity { required { source: Value, at: Value, unknown: Value } optional {  } });

wire!(CardStateBusy { required { by: Value, r#ref: Value } optional {  } });

wire!(CardStateSeat { required { held: Value, by: Value } optional {  } });

wire!(CardStateSession { required { state: Value, id: Value, started_at: Value, last_poll_at: Value } optional {  } });

wire!(CardStateCu { required { balance: Value, floor: Value, at: Value } optional {  } });

wire!(CardStateSelfProbe { required { worker_id: Value, epoch: Value, util: Value, watts: Value, source: Value } optional {  } });

wire!(AgentPull { required { schema_version: Value, agent_id: Value, worker_id: Value, lanes: Value, wait_s: Value, state_epoch: Value } optional { gpu_class: Value, report: Value } });

wire!(AgentPullReport { required { lease_id: Value, job_id: Value, segment: Value, exit_code: Value, done_items: Value } optional { session_lost: Value } });

pub(crate) fn job_spec(value: &Value) -> bool {
    if serde_json::from_value::<JobSpec>(value.clone()).is_err() {
        return false;
    }
    if value["items"].as_array().is_none_or(|rows| {
        rows.iter()
            .any(|row| serde_json::from_value::<JobSpecItems>(row.clone()).is_err())
    }) {
        return false;
    }
    true
}

/// Canonical JSON object ordering after a typed, closed-field wire round trip.
pub(crate) fn normalize_job_spec(value: &Value) -> Result<Vec<u8>, &'static str> {
    if !job_spec(value) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let wire: JobSpec =
        serde_json::from_value(value.clone()).map_err(|_| crate::error_catalog::BAD_SPEC)?;
    let normalized = serde_json::to_value(wire).map_err(|_| crate::error_catalog::BAD_SPEC)?;
    serde_json::to_vec(&normalized).map_err(|_| crate::error_catalog::BAD_SPEC)
}

pub(crate) fn card_state(value: &Value) -> bool {
    if serde_json::from_value::<crate::card_state::WriterState>(value["state"].clone()).is_err() {
        return false;
    }
    if serde_json::from_value::<CardState>(value.clone()).is_err() {
        return false;
    }
    if value
        .get("capacity")
        .is_some_and(|row| serde_json::from_value::<CardStateCapacity>(row.clone()).is_err())
    {
        return false;
    }
    if value
        .get("busy")
        .is_some_and(|row| serde_json::from_value::<CardStateBusy>(row.clone()).is_err())
    {
        return false;
    }
    if value
        .get("seat")
        .is_some_and(|row| serde_json::from_value::<CardStateSeat>(row.clone()).is_err())
    {
        return false;
    }
    if value
        .get("session")
        .is_some_and(|row| serde_json::from_value::<CardStateSession>(row.clone()).is_err())
    {
        return false;
    }
    if value
        .get("cu")
        .is_some_and(|row| serde_json::from_value::<CardStateCu>(row.clone()).is_err())
    {
        return false;
    }
    if value
        .get("self_probe")
        .is_some_and(|row| serde_json::from_value::<CardStateSelfProbe>(row.clone()).is_err())
    {
        return false;
    }
    true
}

#[cfg(test)]
pub(crate) fn card_field_contracts() -> Vec<(
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
)> {
    vec![
        ("", CardState::REQUIRED, CardState::OPTIONAL),
        (
            "/properties/capacity",
            CardStateCapacity::REQUIRED,
            CardStateCapacity::OPTIONAL,
        ),
        (
            "/properties/busy",
            CardStateBusy::REQUIRED,
            CardStateBusy::OPTIONAL,
        ),
        (
            "/properties/seat",
            CardStateSeat::REQUIRED,
            CardStateSeat::OPTIONAL,
        ),
        (
            "/properties/session",
            CardStateSession::REQUIRED,
            CardStateSession::OPTIONAL,
        ),
        (
            "/properties/cu",
            CardStateCu::REQUIRED,
            CardStateCu::OPTIONAL,
        ),
        (
            "/properties/self_probe",
            CardStateSelfProbe::REQUIRED,
            CardStateSelfProbe::OPTIONAL,
        ),
    ]
}

pub(crate) fn agent_pull(value: &Value) -> bool {
    if serde_json::from_value::<AgentPull>(value.clone()).is_err() {
        return false;
    }
    if value
        .get("report")
        .is_some_and(|row| serde_json::from_value::<AgentPullReport>(row.clone()).is_err())
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    fn parity<T: serde::de::DeserializeOwned>(
        schema: &Value,
        required: &[&str],
        optional: &[&str],
    ) -> Result<(), String> {
        let names = |fields: &[&str]| {
            fields
                .iter()
                .map(|s| s.trim_start_matches("r#").to_string())
                .collect::<BTreeSet<_>>()
        };
        let required = names(required);
        let optional = names(optional);
        let actual_required: BTreeSet<String> = schema["required"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
            .unwrap_or_default();
        let actual_fields = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if required != actual_required
            || required.union(&optional).cloned().collect::<BTreeSet<_>>() != actual_fields
        {
            return Err("schema field drift".into());
        }
        let sample: Value = required
            .union(&optional)
            .map(|f| (f.clone(), Value::Bool(true)))
            .collect();
        assert!(serde_json::from_value::<T>(sample.clone()).is_ok());
        for field in required.union(&optional) {
            let mut missing = sample.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert_eq!(
                serde_json::from_value::<T>(missing).is_err(),
                required.contains(field),
                "{field}"
            );
        }
        let mut extra = sample;
        extra["planted_extra"] = Value::Bool(true);
        let accepts_extra = serde_json::from_value::<T>(extra).is_ok();
        if schema["additionalProperties"].as_bool().unwrap_or(true) != accepts_extra {
            return Err("additionalProperties drift".into());
        }
        Ok(())
    }
    #[test]
    fn job_spec_schema_parity() {
        let schema: Value = serde_json::from_str(include_str!("job-spec.schema.json")).unwrap();
        parity::<JobSpec>(&schema, JobSpec::REQUIRED, JobSpec::OPTIONAL).unwrap();
        parity::<JobSpecItems>(
            &schema["properties"]["items"]["items"],
            JobSpecItems::REQUIRED,
            JobSpecItems::OPTIONAL,
        )
        .unwrap();
    }
    #[test]
    fn card_state_schema_parity() {
        let schema: Value = serde_json::from_str(include_str!("card-state.schema.json")).unwrap();
        parity::<CardState>(&schema, CardState::REQUIRED, CardState::OPTIONAL).unwrap();
        parity::<CardStateCapacity>(
            &schema["properties"]["capacity"],
            CardStateCapacity::REQUIRED,
            CardStateCapacity::OPTIONAL,
        )
        .unwrap();
        parity::<CardStateBusy>(
            &schema["properties"]["busy"],
            CardStateBusy::REQUIRED,
            CardStateBusy::OPTIONAL,
        )
        .unwrap();
        parity::<CardStateSeat>(
            &schema["properties"]["seat"],
            CardStateSeat::REQUIRED,
            CardStateSeat::OPTIONAL,
        )
        .unwrap();
        parity::<CardStateSession>(
            &schema["properties"]["session"],
            CardStateSession::REQUIRED,
            CardStateSession::OPTIONAL,
        )
        .unwrap();
        parity::<CardStateCu>(
            &schema["properties"]["cu"],
            CardStateCu::REQUIRED,
            CardStateCu::OPTIONAL,
        )
        .unwrap();
        parity::<CardStateSelfProbe>(
            &schema["properties"]["self_probe"],
            CardStateSelfProbe::REQUIRED,
            CardStateSelfProbe::OPTIONAL,
        )
        .unwrap();
    }
    #[test]
    fn agent_pull_schema_parity() {
        let schema: Value = serde_json::from_str(include_str!("agent-pull.schema.json")).unwrap();
        parity::<AgentPull>(&schema, AgentPull::REQUIRED, AgentPull::OPTIONAL).unwrap();
        parity::<AgentPullReport>(
            &schema["properties"]["report"],
            AgentPullReport::REQUIRED,
            AgentPullReport::OPTIONAL,
        )
        .unwrap();
    }
    #[test]
    fn planted_schema_extra_field_fails() {
        let mut schema: Value = serde_json::from_str(include_str!("job-spec.schema.json")).unwrap();
        schema["properties"]["planted_extra"] = serde_json::json!({"type":"string"});
        assert_eq!(
            parity::<JobSpec>(&schema, JobSpec::REQUIRED, JobSpec::OPTIONAL).unwrap_err(),
            "schema field drift"
        );
        schema["properties"]
            .as_object_mut()
            .unwrap()
            .remove("planted_extra");
        schema["additionalProperties"] = Value::Bool(true);
        assert_eq!(
            parity::<JobSpec>(&schema, JobSpec::REQUIRED, JobSpec::OPTIONAL).unwrap_err(),
            "additionalProperties drift"
        );
    }
}

#[cfg(test)]
mod run37_normalization_tests {
    use super::*;

    fn examples() -> Vec<Value> {
        let schema: Value = serde_json::from_str(include_str!("job-spec.schema.json")).unwrap();
        let rows = schema["examples"].as_array().unwrap().clone();
        assert!(rows.len() >= 6);
        assert_eq!(
            rows.iter()
                .map(|row| row["lane"].as_str().unwrap())
                .collect::<std::collections::BTreeSet<_>>(),
            crate::LANES.iter().copied().collect()
        );
        rows
    }

    fn reordered(value: &Value, reverse: bool) -> String {
        match value {
            Value::Object(fields) => {
                let mut entries = fields.iter().collect::<Vec<_>>();
                if reverse {
                    entries.reverse();
                } else if entries.len() > 1 {
                    entries.rotate_left(1);
                }
                let content = entries
                    .into_iter()
                    .map(|(name, child)| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(name).unwrap(),
                            reordered(child, reverse)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{content}}}")
            }
            Value::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(|child| reordered(child, reverse))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            _ => serde_json::to_string(value).unwrap(),
        }
    }

    #[test]
    fn run37_w4_every_example_is_idempotent_and_closed() {
        for example in examples() {
            assert!(job_spec(&example));
            let once = normalize_job_spec(&example).unwrap();
            let parsed: Value = serde_json::from_slice(&once).unwrap();
            assert_eq!(normalize_job_spec(&parsed).unwrap(), once);
            assert_eq!(
                serde_json::to_vec(&parsed).unwrap(),
                once,
                "canonical object ordering"
            );
            let mut missing = example.clone();
            missing.as_object_mut().unwrap().remove("items");
            let mut extra = example.clone();
            extra["unexpected"] = true.into();
            let mut nested = example.clone();
            nested["items"][0]["unexpected"] = true.into();
            for invalid in [missing, extra, nested] {
                assert!(!job_spec(&invalid));
                let refused = normalize_job_spec(&invalid).unwrap_err();
                assert_eq!(refused, crate::error_catalog::BAD_SPEC);
                assert_eq!(
                    crate::error_catalog::lookup(None, refused).unwrap().code,
                    crate::error_catalog::BAD_SPEC
                );
            }
        }
    }

    #[test]
    fn run37_w4_every_example_ignores_object_field_order() {
        for example in examples() {
            let canonical = normalize_job_spec(&example).unwrap();
            for reverse in [false, true] {
                let raw = reordered(&example, reverse);
                assert_ne!(
                    raw.as_bytes(),
                    serde_json::to_vec(&example).unwrap(),
                    "fixture must actually change incoming order"
                );
                let shuffled: Value = serde_json::from_str(&raw).unwrap();
                assert_eq!(shuffled, example, "array order and values preserved");
                assert_eq!(normalize_job_spec(&shuffled).unwrap(), canonical);
                let again: Value =
                    serde_json::from_slice(&normalize_job_spec(&shuffled).unwrap()).unwrap();
                assert_eq!(normalize_job_spec(&again).unwrap(), canonical);
            }
        }
    }
}
