use super::{fail, Failure, Result};
use serde_json::Value;
use std::{fs, path::Path};
pub fn atomic(p: &Path, data: &[u8]) -> Result<()> {
    let next = p.with_extension("new");
    fs::write(&next, data).map_err(|_| Failure(70, "write_failed"))?;
    fs::rename(next, p).map_err(|_| Failure(70, "rename_failed"))
}
pub fn db(path: &Path) -> Result<rusqlite::Connection> {
    let d = rusqlite::Connection::open(path).map_err(|_| Failure(70, "storage_unavailable"))?;
    d.busy_timeout(std::time::Duration::from_secs(10))
        .map_err(|_| Failure(70, "storage_unavailable"))?;
    d.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .map_err(|_| Failure(70, "storage_unavailable"))?;
    Ok(d)
}
pub fn client() -> Result<reqwest::blocking::Client> {
    lane_router::transport::private_http_client()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| Failure(75, "http_unavailable"))
}
pub fn http(method: &str, url: &str, payload: Option<&Value>, auth: Option<&str>) -> Result<Value> {
    let m = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| Failure(75, "http_unavailable"))?;
    let c = client()?;
    let mut r = c.request(m, url);
    if let Some(a) = auth {
        r = r.bearer_auth(a)
    }
    if let Some(p) = payload {
        r = r.json(p)
    }
    let r = r.send().map_err(|_| Failure(75, "upstream_unreachable"))?;
    if !r.status().is_success() {
        return fail(75, "upstream_refused");
    }
    r.json().map_err(|_| Failure(75, "upstream_invalid_json"))
}
