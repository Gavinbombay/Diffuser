use super::{read, Failure, Result};
use serde_json::Value;
use std::path::Path;
pub fn value(p: impl AsRef<Path>) -> Result<Value> {
    serde_json::from_slice(&read(p)?).map_err(|_| Failure(70, "invalid_json"))
}
