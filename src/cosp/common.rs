use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
pub type Result<T> = std::result::Result<T, Failure>;
#[derive(Debug)]
pub struct Failure(pub i32, pub &'static str);
pub fn fail<T>(rc: i32, code: &'static str) -> Result<T> {
    Err(Failure(rc, code))
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn hash(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}
pub fn args() -> Vec<String> {
    std::env::args().skip(1).collect()
}
pub fn opt(a: &[String], name: &str) -> Option<String> {
    a.iter()
        .position(|s| s == name)
        .and_then(|i| a.get(i + 1))
        .cloned()
}
pub fn emit(r: Result<Value>) -> i32 {
    match r {
        Ok(v) => {
            println!("{v}");
            0
        }
        Err(Failure(rc, c)) => {
            println!(
                "{}",
                json!({"error":{"code":c,"retryable":false,"message":c,"request_id":format!("req_{}",now())}})
            );
            rc
        }
    }
}
pub fn read(p: impl AsRef<Path>) -> Result<Vec<u8>> {
    fs::read(p).map_err(|_| Failure(70, "file_unreadable"))
}
