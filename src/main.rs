//! lane-router: shared service lanes (service-lane/v1). See /workspace/ops/SERVICE_LANES.md.
//! CLI:  lane-router workers --lane render-blender
//!       lane-router submit --spec job.json [--dry-run]
//!       lane-router status <job_id> | cancel <job_id> | reap
//!       lane-router serve --bind 127.0.0.1:17500   (loopback or 10.x LAN only; lane tokens by sha256 file)
//! Job types (render-blender): absent/"render" = frame range split across accepting workers (unchanged);
//! "bake-render" (2026-10-26) = one worker that advertises it, whole spec sent unchunked with job_id kept,
//! no retry, artifacts (subfolders allowed, e.g. baked/fluidcache/...) hard-linked into out/.
pub mod agent_pull;
mod artifact_routes;
mod card_state;
mod cartridge;
mod cartridge_registry;
#[cfg(test)]
#[path = "../tests/cite_check.rs"]
mod cite_check;
mod command_policy;
#[cfg(test)]
#[path = "../tests/conformance_b5.rs"]
mod conformance_b5;
#[cfg(test)]
#[path = "../tests/conformance_b6.rs"]
mod conformance_b6;
mod cosp;
mod cu_ledger;
mod deadline;
#[cfg(test)]
#[path = "../tests/deadline_remainder.rs"]
mod deadline_remainder;
#[cfg(test)]
#[path = "../tests/deadline_workers.rs"]
mod deadline_workers;
#[cfg(test)]
#[path = "../tests/decisions_fit.rs"]
mod decisions_fit;
mod dispatch_kinds;
mod error_catalog;
mod http_routes;
mod job_spec;
mod lane_bodies;
mod lane_gate;
mod log_redaction;
#[cfg(test)]
#[path = "../tests/log_surfaces.rs"]
mod log_surfaces;
#[cfg(test)]
#[path = "../tests/openapi_contract.rs"]
mod openapi_contract;
#[cfg(test)]
mod proof_row_tests;
#[cfg(test)]
#[path = "../tests/qc_minors.rs"]
mod qc_minors;
mod queue_policy;
mod render_admission;
mod request_boundary;
mod result_store;
#[cfg(test)]
mod route_wiring_tests;
mod runtime_limits;
mod schema_wire;
pub mod segment_lifecycle;
mod store;
#[cfg(test)]
mod test_process;
mod watchdog;
mod worker_process;
mod worker_registry;

use axum::{
    extract::{OriginalUri, Path as AxPath, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

const API: &str = "service-lane/v1";
const LANES: &[&str] = &[
    "render-blender",
    "tts",
    "stt",
    "diffusion-image",
    "diffusion-video",
    "music-sfx",
];
/// render-blender single Blender pin (ops call 2026-10-25 21:26 NDT; /workspace/ops/lanes/BLENDER_PIN.md).
const RB_CARTRIDGES: &[&str] = &["blender-4.5.14-cycles"];

mod engine;
use engine::*;
mod routes;
use routes::*;

#[cfg(test)]
mod contract_ref_tests;
#[cfg(test)]
mod pull_http_tests;

fn usage() -> i32 {
    eprintln!("usage: lane-router --check-policy FILE | worker-registry ACTION --state FILE | catalog-resolve --catalog FILE --lane L [--cartridge ID] [--job FILE] | cartridge-install --manifest FILE --directory DIR | cartridge-swap --lane L --manifest-sha256 HASH | workers --lane L | submit --spec job.json [--dry-run] | status ID | cancel ID | reap | serve --bind 127.0.0.1:17500");
    64
}

fn main() {
    cosp::maybe_private_helper();
    if std::env::args().next().is_some_and(|p| {
        std::path::Path::new(&p)
            .file_name()
            .is_some_and(|n| n == "uai-diffuser")
    }) {
        std::process::exit(cosp::main_cli());
    }
    let a: Vec<String> = std::env::args().skip(1).collect();
    let arg = |k: &str| {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1))
            .cloned()
    };
    if matches!(a.first().map(String::as_str), Some("serve" | "submit")) {
        if let Err(reason) = command_policy::startup() {
            eprintln!("{reason}");
            std::process::exit(1);
        }
    }
    let code = match a.first().map(String::as_str) {
        Some("--check-policy") => command_policy::check_cli(&a[1..]),
        Some("worker-registry") => match worker_registry::cli(&a[1..], clock_now()) {
            Ok(v) => {
                println!("{}", v);
                0
            }
            Err(code) => {
                println!(
                    "{}",
                    queue_policy::envelope(
                        code,
                        matches!(
                            code,
                            crate::error_catalog::STORAGE_UNAVAILABLE
                                | crate::error_catalog::SEATS_FULL
                                | crate::error_catalog::WORKER_STALE
                        )
                    )
                );
                1
            }
        },
        Some("catalog-resolve") => match cartridge_registry::cli(&a[1..]) {
            Ok(v) => {
                println!("{}", v);
                0
            }
            Err(code) => {
                println!(
                    "{}",
                    queue_policy::envelope(code, code == crate::error_catalog::PIN_UNSET)
                );
                1
            }
        },
        Some("cartridge-install") => match (arg("--manifest"), arg("--directory")) {
            (Some(m), Some(d)) => {
                match store::install(&base_dir().join("cartridges"), Path::new(&m), Path::new(&d)) {
                    Ok(hash) => {
                        println!("{hash}");
                        0
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        2
                    }
                }
            }
            _ => usage(),
        },
        Some("cartridge-swap") => match (arg("--lane"), arg("--manifest-sha256")) {
            (Some(lane), Some(hash)) => {
                match store::swap(&base_dir().join("cartridges"), &lane, &hash) {
                    Ok(()) => 0,
                    Err(e) => {
                        eprintln!("error: {e}");
                        2
                    }
                }
            }
            _ => usage(),
        },
        Some("workers") => {
            let lane = arg("--lane").unwrap_or("render-blender".into());
            match load_registry() {
                Ok(reg) => {
                    let v: Vec<Value> = reg
                        .iter()
                        .map(|w| worker_view(w, &lane, &HashMap::new()))
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({"lane": lane, "workers": v})).unwrap()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        Some("submit") => {
            let Some(p) = arg("--spec") else {
                std::process::exit(usage())
            };
            let b = match fs::read(&p) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {p}: {e}");
                    std::process::exit(2)
                }
            };
            let spec: Value = match serde_json::from_slice(&b) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: spec json: {e}");
                    std::process::exit(2)
                }
            };
            if spec["lane"].as_str().is_some_and(opened_lane) {
                let config = fs::read(base_dir().join("compat-routes.json"))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .unwrap_or(Value::Null);
                if config["lanes"][spec["lane"].as_str().unwrap()].as_bool() != Some(true) {
                    eprintln!("error: lane disabled");
                    std::process::exit(1);
                }
            }
            let mut spec = spec;
            if spec["lane"].as_str().is_some_and(opened_lane) {
                let config = fs::read(base_dir().join("compat-routes.json"))
                    .ok()
                    .and_then(|b| lane_gate::parse(&b).ok())
                    .unwrap_or(Value::Null);
                video_defaults(&mut spec);
                let admission = cartridge_registry::apply_config(&config, &mut spec)
                    .and_then(|()| {
                        runtime_limits::admit(
                            &mut spec,
                            &runtime_limits::Config::from_value(&config),
                        )
                    })
                    .map_err(str::to_owned)
                    .and_then(|()| select_manifest(&mut spec, &base_dir().join("cartridges")))
                    .and_then(|()| lane_gate::admit(&config, &spec).map_err(str::to_owned));
                if let Err(reason) = admission {
                    eprintln!("error: {reason}");
                    std::process::exit(1);
                }
            }
            let st: Shared = Arc::new(Mutex::new(JobTable::default()));
            let st2 = st.clone();
            // CLI cancel: SIGINT/SIGTERM forwarded to adapters via the cancel flag
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let jid = request_boundary::job_id(&spec);
            spec["job_id"] = json!(jid);
            if let Some(obj) = spec.as_object_mut() {
                obj.remove("cartridge_manifest_sha256");
            }
            let jid2 = jid.clone();
            std::thread::spawn(move || {
                rt.block_on(async move {
                    let mut term =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .unwrap();
                    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                    let _ = result_store::worker_log::emit(
                        &mut std::io::stderr().lock(),
                        b"cancel requested\n",
                        128,
                    );
                    let mut t = st2.lock().unwrap();
                    let now = (t.clock.unwrap_or(clock_now))();
                    if let Some(row) = t.jobs.get_mut(&jid2) {
                        let _ = deadline::cancel(row, now);
                    }
                    t.cancel.insert(jid2.clone());
                    for p in t.pids.get(&jid2).cloned().unwrap_or_default() {
                        sigterm(p);
                    }
                })
            });
            let dry = a.iter().any(|x| x == "--dry-run");
            let r = run_job(st, spec, b, dry);
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
            if r["state"] == "done" {
                0
            } else {
                1
            }
        }
        Some("results-gc") => {
            if let Some(root) = arg("--root") {
                let store =
                    result_store::Store::new(Path::new(&root), result_store::Config::default());
                match store.gc(clock_now(), !a.iter().any(|v| v == "--apply")) {
                    Ok(report) => {
                        println!("{report}");
                        0
                    }
                    Err(reason) => {
                        eprintln!("{reason}");
                        1
                    }
                }
            } else {
                eprintln!("results-gc requires --root");
                2
            }
        }
        Some("lane-gate") => {
            let action = a.get(1).map(String::as_str).unwrap_or("");
            let lane = if action == "check" {
                "-"
            } else {
                a.get(2).map(String::as_str).unwrap_or("")
            };
            if !lane_gate::valid_cli(&a[1..]) {
                eprintln!("usage: lane-gate check|enable|disable [lane] --pins file --state-dir directory");
                2
            } else {
                let result = lane_gate::execute(
                    action,
                    lane,
                    Path::new(&arg("--pins").unwrap()),
                    Path::new(&arg("--state-dir").unwrap()),
                    clock_now(),
                );
                match result {
                    Ok(v) => {
                        println!("{v}");
                        0
                    }
                    Err(code)
                        if matches!(
                            code,
                            crate::error_catalog::USAGE
                                | crate::error_catalog::PINS_UNREADABLE
                                | crate::error_catalog::STATE_CORRUPT
                                | crate::error_catalog::STATE_UNREADABLE
                                | crate::error_catalog::STATE_UNWRITABLE
                                | crate::error_catalog::AUDIT_UNWRITABLE
                        ) =>
                    {
                        eprintln!("{code}: failing closed");
                        2
                    }
                    Err(code) => {
                        println!(
                            "{}",
                            queue_policy::envelope(
                                code,
                                matches!(
                                    code,
                                    crate::error_catalog::MODEL_UNRESOLVED
                                        | crate::error_catalog::CARTRIDGE_PLACEHOLDER
                                        | crate::error_catalog::APPROVAL_MISSING
                                )
                            )
                        );
                        1
                    }
                }
            }
        }
        Some("status") | Some("cancel") => {
            let Some(id) = a.get(1) else {
                std::process::exit(usage())
            };
            match fs::read(jobs_dir().join(format!("{id}.json"))) {
                Ok(b) => {
                    let v: Value = serde_json::from_slice(&b).unwrap_or(Value::Null);
                    if a[0] == "cancel" {
                        let pid = v["router_pid"].as_u64().unwrap_or(0) as u32;
                        if pid > 0
                            && pid_alive(pid)
                            && matches!(v["state"].as_str(), Some("running" | "dispatching"))
                        {
                            sigterm(pid);
                            println!("SIGTERM sent to router pid {pid} (it forwards to adapters)");
                            0
                        } else {
                            println!("job not running");
                            1
                        }
                    } else {
                        println!("{}", serde_json::to_string_pretty(&v).unwrap());
                        0
                    }
                }
                Err(_) => {
                    eprintln!("no such job {id}");
                    2
                }
            }
        }
        Some("reap") => {
            println!("{}", json!({"reaped": reap()}));
            0
        }
        Some("serve") => {
            let bind = arg("--bind").unwrap_or("127.0.0.1:17500".into());
            let rt = tokio::runtime::Runtime::new().unwrap();
            match rt.block_on(serve(&bind)) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("error: {e}");
                    2
                }
            }
        }
        _ => usage(),
    };
    std::process::exit(code);
}

#[cfg(test)]
#[path = "../tests/main_tests.rs"]
mod tests;

#[cfg(test)]
mod fake_suite;

#[cfg(test)]
#[path = "../tests/coverage_gate.rs"]
mod coverage_gate;

#[cfg(test)]
#[path = "../tests/real_child_faults.rs"]
mod real_child_faults;

#[cfg(test)]
#[path = "../tests/cli_cancel.rs"]
mod cli_cancel;

#[cfg(test)]
#[path = "../tests/maintenance_guards.rs"]
mod maintenance_guards;

#[cfg(test)]
#[path = "../tests/run31_tables.rs"]
mod run31_tables;

#[cfg(test)]
#[path = "../tests/run31_tools.rs"]
mod run31_tools;

#[cfg(test)]
#[path = "../tests/run31_errors.rs"]
mod run31_errors;
