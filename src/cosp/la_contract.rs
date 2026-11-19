//! Strict request normalization, shared by future authenticated handlers.
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeMap, fmt};

const MAX_JSON: usize = 64 * 1024;
const MAX_DEPTH: usize = 32;

struct Strict(usize);
struct StrictVisitor(usize);
impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor(self.0))
    }
}
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded JSON value without floats or duplicate keys")
    }
    fn visit_bool<E: Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_u64<E: Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("schema_invalid"))
    }
    fn visit_str<E: Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(A::Error::custom("schema_invalid"));
        }
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Strict(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_DEPTH {
            return Err(A::Error::custom("schema_invalid"));
        }
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate_member"));
            }
            let value = map.next_value_seed(Strict(self.0 + 1))?;
            values.insert(key, value);
        }
        let mut object = Map::new();
        for (key, value) in values {
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

pub(super) fn canonical_json(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    if bytes.len() > MAX_JSON {
        return Err("body_too_large");
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = Strict(0).deserialize(&mut d).map_err(|e| {
        if e.to_string().contains("duplicate_member") {
            "duplicate_member"
        } else {
            "schema_invalid"
        }
    })?;
    d.end().map_err(|_| "schema_invalid")?;
    serde_json::to_vec(&value).map_err(|_| "schema_invalid")
}

/// Fixed S1 test-policy snapshot. The digest is computed from these values, not
/// accepted from the caller as evidence that the policy was installed.
#[derive(serde::Serialize)]
struct RuntimePolicy {
    policy_id: &'static str,
    queue_ms: u64,
    occupancy_freshness_ms: u64,
    admission_freshness_ms: u64,
    start_ms: u64,
    idle_ms: u64,
    lease_ms: u64,
    tenure_ms: u64,
    job_ms: u64,
    permit_window_ms: u64,
    renewal_ms: u64,
    worker_heartbeat_ms: u64,
    worker_loss_ms: u64,
    authority_observation_ms: u64,
    authority_freshness_ms: u64,
    grace_ms: u64,
    cleanup_ms: u64,
}

pub(super) fn policy_digest(id: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let policy = match id {
        "lab-proposal-v1" => RuntimePolicy {
            policy_id: "lab-proposal-v1",
            queue_ms: 120_000,
            occupancy_freshness_ms: 6_000,
            admission_freshness_ms: 3_600_000,
            start_ms: 30_000,
            idle_ms: 60_000,
            lease_ms: 120_000,
            tenure_ms: 600_000,
            job_ms: 10_000,
            permit_window_ms: 2_000,
            renewal_ms: 500,
            worker_heartbeat_ms: 2_000,
            worker_loss_ms: 6_000,
            authority_observation_ms: 2_000,
            authority_freshness_ms: 6_000,
            grace_ms: 2_000,
            cleanup_ms: 5_000,
        },
        "runtime-short-v1" => RuntimePolicy {
            policy_id: "runtime-short-v1",
            queue_ms: 120_000,
            occupancy_freshness_ms: 6_000,
            admission_freshness_ms: 3_600_000,
            start_ms: 2_000,
            idle_ms: 2_000,
            lease_ms: 4_000,
            tenure_ms: 12_000,
            job_ms: 8_000,
            permit_window_ms: 1_500,
            renewal_ms: 400,
            worker_heartbeat_ms: 400,
            worker_loss_ms: 1_200,
            authority_observation_ms: 400,
            authority_freshness_ms: 1_500,
            grace_ms: 500,
            cleanup_ms: 1_500,
        },
        _ => return None,
    };
    let encoded = serde_json::to_vec(&policy).ok()?;
    let canonical = canonical_json(&encoded).ok()?;
    Some(hex::encode(Sha256::digest(canonical)))
}
