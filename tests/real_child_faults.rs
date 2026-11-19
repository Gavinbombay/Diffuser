//! Real worker faults exercise the shared supervision and bounded capture path.
use crate::*;
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicU64, Ordering};
static NOW: AtomicU64 = AtomicU64::new(1000);
fn clock() -> u64 {
    NOW.load(Ordering::SeqCst)
}

fn fault(name: &str, mode: &str) {
    if std::env::var_os("REAL_FAULT_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args(["--exact", &format!("real_child_faults::{name}"), "--quiet"])
            .env("REAL_FAULT_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    let _ = fault_once(mode);
}
fn fault_once(mode: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    NOW.store(1000, Ordering::SeqCst);
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let root = (0..1000)
        .find_map(|index| {
            let path = std::env::temp_dir().join(format!(
                "run26-real-fault-{}-{mode}-{index}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => Some(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => panic!("fault scratch directory: {error}"),
            }
        })
        .expect("fresh fault scratch directory");
    let script = root.join("worker.py");
    let ready = root.join("ready");
    fs::write(
        &script,
        r#"import os, pathlib, signal, sys
mode, ready = sys.argv[1:]
if mode == 'ignore':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
print('api_key = <TOKEN>;', file=sys.stderr, flush=True)
if mode == 'fork':
    leaf = os.fork()
    if leaf == 0:
        signal.pause()
        sys.exit(0)
    pathlib.Path(ready).write_text(str(leaf))
    sys.exit(7)
if mode == 'close':
    os.close(1)
    print('stdout closed', file=sys.stderr, flush=True)
if mode == 'overflow':
    sys.stdout.write('clean log line\n' * 10000)
    sys.stdout.write('api_key = <TOKEN>;\nlast line\n')
    sys.stdout.flush()
pathlib.Path(ready).write_text('ready')
if mode == 'ignore':
    signal.pause()
sys.exit(7)
"#,
    )
    .unwrap();
    let mut table = JobTable {
        clock: Some(clock),
        ..JobTable::default()
    };
    let mut row = queue_policy::admitted(
        &HashMap::new(),
        &json!({"job_id":"fixture","lane":"tts","timeout_min":1}),
        1000,
    );
    row["deadline_epoch"] = json!(1001);
    deadline::dispatch(&mut row, "worker-one", 1000).unwrap();
    deadline::accept(&mut row, 1000).unwrap();
    table.jobs.insert("fixture".into(), row);
    let shared = Arc::new(Mutex::new(table));
    let mut command = Command::new("python3");
    command
        .arg(&script)
        .args([mode])
        .arg(&ready)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_supervised(&shared, "fixture", &mut command).unwrap();
    let cap = 256;
    let capture = result_store::worker_log::Capture::start(&mut child, cap);
    for _ in 0..500 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    if !ready.exists() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("worker readiness missing");
    }
    if mode == "ignore" {
        NOW.store(1001, Ordering::SeqCst);
    }
    let completion = supervise_worker(
        &shared,
        "fixture",
        &mut child,
        Instant::now() + Duration::from_secs(2),
        Duration::from_millis(20),
    )
    .unwrap();
    assert!(child.try_wait().unwrap().is_some());
    let raw_rc = completion
        .status
        .code()
        .map(i64::from)
        .unwrap_or_else(|| -i64::from(completion.status.signal().unwrap()));
    assert_eq!(
        raw_rc,
        if mode == "ignore" {
            -i64::from(libc::SIGKILL)
        } else {
            7
        }
    );
    let log = root.join("worker.log");
    capture.finish(&log).unwrap();
    let text = fs::read_to_string(&log).unwrap();
    assert!(
        text.len() <= cap + 100,
        "unbounded worker log: {}",
        text.len()
    );
    assert!(!text.contains("<TOKEN>"));
    assert!(text.contains("[REDACTED_SECRET]"), "{text}");
    if mode == "overflow" {
        assert!(text.contains("last line"));
        assert!(text.contains("omitted"));
    }
    if mode == "close" {
        assert!(text.contains("stdout closed"));
    }
    if mode == "fork" {
        let leaf: i32 = fs::read_to_string(&ready).unwrap().parse().unwrap();
        let mut status = 0;
        let mut reaped = false;
        for _ in 0..500 {
            if unsafe { libc::waitpid(leaf, &mut status, libc::WNOHANG) } == leaf {
                reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(reaped, "descendant not reaped");
        assert!(libc::WIFSIGNALED(status));
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        assert_eq!(unsafe { libc::kill(leaf, 0) }, -1);
    }
    let mut table = shared.lock().unwrap();
    let row = table.jobs.get_mut("fixture").unwrap();
    assert_eq!(row["active_children"], 0);
    assert_eq!(row["attempts"][0]["reaped"], true);
    assert_eq!(row["attempts"][0]["raw_rc"], raw_rc);
    if mode == "ignore" {
        assert_eq!(row["state"], "timed_out");
        assert_eq!(row["attempts"][0]["rc"], 124);
    } else {
        deadline::report(row, 1, None, clock()).unwrap();
        assert_eq!(row["state"], "failed");
        assert_eq!(row["attempts"][0]["rc"], 1);
    }
    assert_eq!(row["attempts"].as_array().unwrap().len(), 1);
    assert_eq!(
        row["device_events"]["1"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| ["failed", "timed_out", "cancelled", "done"]
                .contains(&event["state"].as_str().unwrap_or("")))
            .count(),
        1
    );
    let settled = row.clone();
    assert!(deadline::report(row, 1, None, clock()).is_err());
    assert!(!deadline::expire(row, 2000));
    assert_eq!(*row, settled);
    drop(table);
    assert!(spawn_supervised(&shared, "fixture", &mut Command::new("/bin/true")).is_err());
    assert_eq!(shared.lock().unwrap().jobs["fixture"], settled);
    let output = (
        result_store::canonical(&settled),
        fs::read(&log).unwrap(),
        result_store::canonical(&result_store::runtime_manifest(&settled, clock())),
    );
    fs::remove_dir_all(root).unwrap();
    output
}
#[test]
fn worker_ignores_term() {
    fault("worker_ignores_term", "ignore");
}
#[test]
fn worker_forks_then_exits() {
    fault("worker_forks_then_exits", "fork");
}
#[test]
fn worker_closes_stdout_early() {
    fault("worker_closes_stdout_early", "close");
}
#[test]
fn worker_writes_past_h2_cap() {
    fault("worker_writes_past_h2_cap", "overflow");
}

fn repeat(name: &str, mode: &str) {
    if std::env::var_os("REAL_FAULT_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args(["--exact", &format!("real_child_faults::{name}"), "--quiet"])
            .env("REAL_FAULT_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    let first = fault_once(mode);
    let second = fault_once(mode);
    assert_eq!(first.0, second.0, "settlement differs for {mode}");
    assert_eq!(first.1, second.1, "capture differs for {mode}");
    assert_eq!(first.2, second.2, "manifest differs for {mode}");
    fs::create_dir_all(crate::test_process::target_dir()).unwrap();
    for (index, output) in [first, second].iter().enumerate() {
        for (kind, bytes) in [
            ("settlement.json", &output.0),
            ("worker.log", &output.1),
            ("manifest.json", &output.2),
        ] {
            fs::write(
                crate::test_process::target_dir()
                    .join(format!("run27-fault-{mode}-{index}-{kind}")),
                bytes,
            )
            .unwrap();
        }
    }
}
#[test]
fn deterministic_ignores_term() {
    repeat("deterministic_ignores_term", "ignore");
}
#[test]
fn deterministic_forks_then_exits() {
    repeat("deterministic_forks_then_exits", "fork");
}
#[test]
fn deterministic_closes_stdout_early() {
    repeat("deterministic_closes_stdout_early", "close");
}
#[test]
fn deterministic_writes_past_h2_cap() {
    repeat("deterministic_writes_past_h2_cap", "overflow");
}
