#[path = "../cosp/common_lanes.rs"]
mod common;
#[path = "lanes_ctl_operator/mod.rs"]
mod operator;
use common::{Failure, Result};
use lane_router::lane_client::{Error as ClientError, Id, Identity, ReceiptStore};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
fn validate(root: &Path) -> Result<Value> {
    let data =
        common::read(root.join("BRIEF.md")).map_err(|_| Failure(61, "brief_stale_path_or_host"))?;
    let text = String::from_utf8_lossy(&data);
    if common::contains_banned_name(&text) {
        return common::fail(61, "brief_stale_path_or_host");
    }
    if !text.contains("0a")
        || !text.contains("ACK.md")
        || !text.contains("nuc")
        || regex::Regex::new(r"[A-Za-z]:\\").unwrap().is_match(&text)
    {
        return common::fail(61, "brief_stale_path_or_host");
    }
    let r = Command::new("python3")
        .arg("/srv/lanes/bin/qc_gate.py")
        .arg("check")
        .arg("--id")
        .arg(root.file_name().unwrap_or_default())
        .args(["--lane", "codex-main-nuc", "--dir"])
        .arg(root)
        .output()
        .map_err(|_| Failure(66, "qc_gate_blocked"))?;
    if !r.status.success() {
        return common::fail(66, "qc_gate_blocked");
    }
    Ok(json!({"valid":true,"brief_sha256":common::hash(data)}))
}
fn request(a: &[String], method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let socket = common::opt(a, "--socket").unwrap_or("/var/lib/uai-diffuser/control.sock".into());
    let client = reqwest::blocking::Client::builder()
        .unix_socket(socket)
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|_| Failure(75, "diffuser_unavailable"))?;
    let mut r = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        format!("http://localhost{path}"),
    );
    if let Some(b) = body {
        let ident = common::opt(a, "--idempotency-id")
            .unwrap_or_else(|| common::hash(format!("{path}\n{b}")));
        r = r.json(b).header("X-Idempotency-Id", ident);
    }
    let response = r.send().map_err(|_| Failure(75, "diffuser_unavailable"))?;
    let success = response.status().is_success();
    let reply: Value = response
        .json()
        .map_err(|_| Failure(75, "diffuser_invalid_reply"))?;
    if !success {
        println!("{reply}");
        return common::fail(74, "diffuser_refused");
    }
    Ok(reply)
}
fn publish(a: &[String]) -> Result<Value> {
    let bundle = PathBuf::from(common::opt(a, "--bundle").ok_or(Failure(64, "bundle_required"))?);
    common::publication_guard(&bundle)?;
    let manifest = common::value(bundle.join("manifest.json"))?;
    let id = manifest["bundle_id"]
        .as_str()
        .filter(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
        .ok_or(Failure(67, "bundle_invalid"))?;
    let scan = String::from_utf8(common::read(bundle.join("SCAN-RECEIPT.txt"))?)
        .map_err(|_| Failure(67, "scan_receipt_missing_or_nonzero"))?;
    if !["raw: 0", "unruled: 0", "namegrep: 0"]
        .iter()
        .all(|s| scan.contains(s))
    {
        return common::fail(67, "scan_receipt_missing_or_nonzero");
    }
    if manifest["scan_receipt_sha256"] != json!(common::hash(scan.as_bytes())) {
        return common::fail(67, "scan_receipt_missing_or_nonzero");
    }
    for row in manifest["items"]
        .as_array()
        .ok_or(Failure(67, "bundle_invalid"))?
    {
        let rel = row["rel_path"]
            .as_str()
            .ok_or(Failure(67, "bundle_invalid"))?;
        if Path::new(rel).is_absolute()
            || Path::new(rel)
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return common::fail(67, "bundle_invalid");
        }
        if common::hash(common::read(bundle.join(rel))?) != row["sha256"] {
            return common::fail(67, "bundle_digest_mismatch");
        }
    }
    let r = Command::new("sha256sum")
        .args(["-c", "--quiet", "SHA256SUMS"])
        .current_dir(&bundle)
        .output()
        .map_err(|_| Failure(67, "bundle_digest_mismatch"))?;
    if !r.status.success() {
        return common::fail(67, "bundle_digest_mismatch");
    }
    let dest = format!("/var/lib/uai-explorer/staged-bundles/{id}");
    let r = Command::new("ssh")
        .args([
            "-n",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "vps",
            "mkdir",
            "-p",
            &dest,
        ])
        .output()
        .map_err(|_| Failure(78, "explorer_auth_unavailable"))?;
    if !r.status.success() {
        return common::fail(78, "explorer_auth_unavailable");
    }
    let r = Command::new("rsync")
        .args(["-a", "--", "./", &format!("vps:{dest}/")])
        .current_dir(&bundle)
        .output()
        .map_err(|_| Failure(78, "explorer_auth_unavailable"))?;
    if !r.status.success() {
        return common::fail(78, "explorer_auth_unavailable");
    }
    let cmd = format!("cd {dest} && sha256sum -c --quiet SHA256SUMS");
    let r = Command::new("ssh")
        .args([
            "-n",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "vps",
            &cmd,
        ])
        .output()
        .map_err(|_| Failure(79, "explorer_readback_mismatch"))?;
    if !r.status.success() {
        return common::fail(79, "explorer_readback_mismatch");
    }
    // This is the single E-C receipt. No catalog mutation is attempted without custody.
    Ok(
        json!({"bundle_id":id,"bundle_sha256":common::hash(common::read(bundle.join("manifest.json"))?),"state":"staged_import_unverified","remote_path":dest,"remote_manifest_verified":true,"import_action":null,"import_action_verified":false,"slugs_verified":false}),
    )
}
fn diffuser(args: &[String]) -> Result<Value> {
    match args {
        [help] if help == "help" => Ok(json!({
            "commands": ["help", "receipt", "operator"],
            "operator_usage": "lanes-ctl diffuser operator help",
            "ordinary_service": "routing_closed",
            "receipt_usage": "lanes-ctl diffuser receipt <private-dir> <tenant-id> <project-id> <actor-id> <idempotency-key>"
        })),
        [command, directory, tenant, project, actor, key] if command == "receipt" => {
            let id = |value: &str| Id::new(value).map_err(|_| Failure(64, "invalid_identifier"));
            let identity = Identity {
                tenant: id(tenant)?,
                project: id(project)?,
                actor: id(actor)?,
            };
            let key = id(key)?;
            let receipt = ReceiptStore::open(directory)
                .and_then(|store| store.read(&identity, &key))
                .map_err(|error| match error {
                    ClientError::ReceiptIdentity => Failure(74, "receipt_identity_mismatch"),
                    ClientError::ReceiptMissing => Failure(74, "receipt_missing"),
                    _ => Failure(70, "receipt_storage_unavailable"),
                })?;
            Ok(json!({"identity": identity, "idempotency_key": key, "receipt": receipt}))
        }
        _ => common::fail(64, "diffuser_command_required"),
    }
}
fn run(a: &[String]) -> Result<Value> {
    match a.first().map(String::as_str) {
        Some("validate-brief") => validate(Path::new(
            a.get(1).ok_or(Failure(64, "job_directory_required"))?,
        )),
        Some("ack-check") => {
            let root = common::opt(a, "--job-root")
                .or_else(|| std::env::var("LANE_JOB_ROOT").ok())
                .ok_or(Failure(62, "ack_missing_or_stale"))?;
            common::ack_at(Path::new(&root), a.iter().any(|s| s == "--post"))
        }
        Some("explorer-publish") => publish(a),
        Some("diffuser") => diffuser(&a[1..]),
        Some("ready") => {
            let action = a
                .get(1)
                .map(String::as_str)
                .ok_or(Failure(64, "ready_action_required"))?;
            if action == "list" {
                return request(a, "GET", "/v1/build-lanes/ready", None);
            }
            let body = common::value(
                common::opt(a, "--request").ok_or(Failure(64, "request_file_required"))?,
            )?;
            let path = if action == "register" {
                "/v1/build-lanes/ready".into()
            } else {
                let id = common::opt(a, "--job-id").ok_or(Failure(64, "job_id_required"))?;
                if !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                {
                    return common::fail(64, "job_id_invalid");
                }
                if !matches!(action, "claim" | "complete") {
                    return common::fail(64, "ready_action_required");
                }
                format!("/v1/build-lanes/ready/{id}/{action}")
            };
            request(a, "POST", &path, Some(&body))
        }
        _ => common::fail(64, "command_required"),
    }
}
fn main() {
    if let Err(error) = common::ack() {
        std::process::exit(common::emit(Err(error)));
    }
    let args = common::args();
    let status = match args.as_slice() {
        [family, command, rest @ ..] if family == "diffuser" && command == "operator" => {
            operator::emit(operator::run(rest))
        }
        _ => common::emit(run(&args)),
    };
    std::process::exit(status);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bad_brief_is_refused() {
        assert_eq!(validate(Path::new("/nonexistent/cosp")).unwrap_err().0, 61);
    }
    #[test]
    fn unix_socket_unavailable_is_typed() {
        let a = vec!["--socket".into(), "/nonexistent/cosp.sock".into()];
        assert_eq!(
            request(&a, "GET", "/v1/build-lanes/ready", None)
                .unwrap_err()
                .0,
            75
        );
    }
}
