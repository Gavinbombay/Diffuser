//! Read-only preflight for the two existing protected startup paths.
//! A local match is not authority, a witness observation, or permission to serve.

use super::{common, la_contract, lane_assignment};
use sha2::{Digest, Sha256};
use std::{fs, io, io::Read, os::fd::AsRawFd};

pub(super) const SELECTOR: &str = "--check-private-cpu-startup";
const POLICY: &str = "runtime-short-v1";
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn executable_digest() -> io::Result<String> {
    // Hash the executing inode, not a path derived from argv or mutable cwd.
    let file = fs::File::open("/proc/self/exe")?;
    let mut digest = Sha256::new();
    let bytes = io::copy(&mut file.take(MAX_EXECUTABLE_BYTES + 1), &mut digest)?;
    if bytes == 0 || bytes > MAX_EXECUTABLE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(hex::encode(digest.finalize()))
}

pub(super) fn check(args: &[String]) -> common::Result<serde_json::Value> {
    let [selector, role, policy, executable] = args else {
        return common::fail(64, "private_cpu_check_usage");
    };
    if selector != SELECTOR || !is_sha256(policy) || !is_sha256(executable) {
        return common::fail(64, "private_cpu_check_usage");
    }
    let path = match role.as_str() {
        "controller" => "/job/service",
        "worker" => "/job/workerroot",
        _ => return common::fail(64, "private_cpu_check_usage"),
    };
    if la_contract::policy_digest(POLICY).as_ref() != Some(policy) {
        return common::fail(70, "startup_policy_mismatch");
    }
    let root =
        lane_assignment::open_startup_root(path).map_err(|code| common::Failure(70, code))?;
    let actual =
        executable_digest().map_err(|_| common::Failure(70, "startup_executable_unavailable"))?;
    if &actual != executable {
        return common::fail(70, "startup_executable_mismatch");
    }
    // Enumerate the pinned descriptor, without opening or reading any entry.
    let mut entries = fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))
        .map_err(|_| common::Failure(70, "startup_root_invalid"))?;
    match entries.next() {
        None => (),
        Some(Ok(_)) => return common::fail(70, "startup_root_not_fresh"),
        Some(Err(_)) => return common::fail(70, "startup_root_invalid"),
    }
    Ok(serde_json::json!({
        "status": "preflight_only", "role": role, "root": path,
        "policy_sha256": policy, "executable_sha256": actual
    }))
}
