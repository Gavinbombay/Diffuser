use crate::*;
use std::sync::atomic::{AtomicU64, Ordering};
struct Scratch(PathBuf);
impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fold-deadline-remainder-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
    fn row(&self, id: &str) -> Value {
        let mut row = queue_policy::admitted(
            &HashMap::new(),
            &json!({"job_id":id,"lane":"tts","cartridge":"fixture","timeout_min":1,"cartridge_manifest_sha256":deadline::fingerprint(&json!({"fixture":true}))}),
            1000,
        );
        row["result_store_root"] = json!(self.0);
        row
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn queued_job_expires_without_worker() {
    static NOW: AtomicU64 = AtomicU64::new(1000);
    fn clock() -> u64 {
        NOW.load(Ordering::SeqCst)
    }
    let root = Scratch::new("queued");
    let mut table = JobTable::default();
    table.jobs.insert("queued".into(), root.row("queued"));
    let shared = Arc::new(Mutex::new(table));
    let waiting = shared.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        send.send(wait_for_turn(
            &waiting,
            "queued",
            queue_policy::Config {
                seats: 0,
                ..queue_policy::Config::default()
            },
            clock,
        ))
        .unwrap()
    });
    assert!(matches!(
        receive.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    NOW.store(1060, Ordering::SeqCst);
    assert!(!receive.recv_timeout(Duration::from_secs(2)).unwrap());
    handle.join().unwrap();
    let row = shared.lock().unwrap().jobs["queued"].clone();
    assert_eq!(row["state"], "timed_out");
    assert_eq!(row["attempts"][0]["worker"], "router");
    assert_eq!(row["attempts"][0]["rc"], 124);
    assert!(row["active_children"].is_null());
    let store = result_store::Store::new(&root.0, result_store::Config::default());
    assert_eq!(
        store.get_job("tts", "queued").unwrap()["state"],
        "timed_out"
    );
    assert!(root
        .0
        .join("lanes/tts/jobs/queued/attempts/1/device.json")
        .is_file());
}
#[test]
fn expiry_frees_seat_for_next() {
    fn clock() -> u64 {
        1060
    }
    let root = Scratch::new("seat");
    let mut table = JobTable::default();
    let mut blocker = root.row("blocker");
    deadline::dispatch(&mut blocker, "worker-one", 1000).unwrap();
    deadline::accept(&mut blocker, 1000).unwrap();
    let mut next = root.row("next");
    next["deadline_epoch"] = json!(1120);
    next["position"] = json!(1);
    table.jobs.insert("blocker".into(), blocker);
    table.jobs.insert("next".into(), next);
    let shared = Arc::new(Mutex::new(table));
    assert!(wait_for_turn(
        &shared,
        "next",
        queue_policy::Config::default(),
        clock
    ));
    let table = shared.lock().unwrap();
    assert_eq!(table.jobs["blocker"]["state"], "timed_out");
    assert_eq!(table.jobs["next"]["state"], "dispatching");
    assert_eq!(table.jobs["blocker"]["attempts"][0]["rc"], 124);
    assert!(root.0.join("lanes/tts/jobs/blocker/job.json").is_file());
}
fn adapter_case(expire: bool) {
    static NOW: AtomicU64 = AtomicU64::new(1000);
    fn clock() -> u64 {
        NOW.load(Ordering::SeqCst)
    }
    // Both modes use different processes because the injected clock is global.
    let root = Scratch::new("adapter");
    let script = root.0.join("adapter.py");
    fs::write(
        &script,
        if expire {
            "import time\ntime.sleep(30)\n"
        } else {
            "import sys\nsys.exit(7)\n"
        },
    )
    .unwrap();
    let spec = root.0.join("job.json");
    fs::write(&spec, "{}").unwrap();
    let mut table = JobTable {
        clock: Some(clock),
        ..JobTable::default()
    };
    let mut row = root.row("adapter");
    deadline::dispatch(&mut row, "worker-one", 1000).unwrap();
    deadline::accept(&mut row, 1000).unwrap();
    table.jobs.insert("adapter".into(), row);
    let shared = Arc::new(Mutex::new(table));
    let mut command = dispatch_kinds::command(
        dispatch_kinds::kind("adapter-tts").unwrap(),
        "unused",
        "worker-one",
        &json!({"entry":script}),
        &spec,
        &root.0.join("delivery"),
        60.0,
        false,
    )
    .unwrap();
    let mut child = spawn_supervised(&shared, "adapter", &mut command).unwrap();
    assert_eq!(shared.lock().unwrap().jobs["adapter"]["active_children"], 1);
    if expire {
        NOW.store(1060, Ordering::SeqCst);
    }
    let done = supervise_worker(
        &shared,
        "adapter",
        &mut child,
        Instant::now() + Duration::from_secs(2),
        Duration::from_millis(10),
    )
    .unwrap();
    assert!(child.try_wait().unwrap().is_some());
    let mut table = shared.lock().unwrap();
    let row = table.jobs.get_mut("adapter").unwrap();
    assert_eq!(row["active_children"], 0);
    assert_eq!(row["attempts"][0]["reaped"], true);
    if expire {
        assert_eq!(done.state, "timed_out");
        assert_eq!(row["state"], "timed_out");
        let settled = row.clone();
        assert!(!deadline::expire(row, 1120));
        assert!(deadline::report(row, 0, None, 1120).is_err());
        assert_eq!(*row, settled);
        drop(table);
        let before = shared.lock().unwrap().jobs["adapter"].clone();
        assert!(spawn_supervised(&shared, "adapter", &mut Command::new("/bin/true")).is_err());
        assert_eq!(shared.lock().unwrap().jobs["adapter"], before);
    } else {
        assert_eq!(done.status.code(), Some(7));
        assert_eq!(row["attempts"][0]["raw_rc"], 7);
        deadline::report(row, 1, None, 1000).unwrap();
        assert_eq!(row["state"], "failed");
    }
}
fn isolated(name: &str, expire: bool) {
    if std::env::var_os("REMAINDER_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args(["--exact", &format!("deadline_remainder::{name}"), "--quiet"])
            .env("REMAINDER_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    adapter_case(expire);
}
#[test]
fn adapter_child_supervised() {
    isolated("adapter_child_supervised", false);
}
#[test]
fn no_terminal_state_revisited_on_real_child() {
    isolated("no_terminal_state_revisited_on_real_child", true);
}

// REF A/glm-lanes-router-s02-deadline-ref-20261031/out/s02/tests/test_determinism.py:17,34,55.
fn child_determinism_scenario(mode: u8) -> (BTreeMap<PathBuf, Vec<u8>>, Vec<Value>, Value) {
    static NOW: AtomicU64 = AtomicU64::new(1000);
    fn clock() -> u64 {
        NOW.load(Ordering::SeqCst)
    }
    NOW.store(1000, Ordering::SeqCst);
    let root = Scratch::new("determinism");
    let spec =
        json!({"job_id":"deterministic-child","lane":"tts","cartridge":"fixture","timeout_min":1});
    let mut row = queue_policy::admitted(&HashMap::new(), &spec, clock());
    let mut snapshots = vec![result_store::snapshot(&row, clock())];
    deadline::dispatch(&mut row, "worker-one", clock()).unwrap();
    snapshots.push(result_store::snapshot(&row, clock()));
    deadline::accept(&mut row, clock()).unwrap();
    snapshots.push(result_store::snapshot(&row, clock()));
    let mut table = JobTable {
        clock: Some(clock),
        ..JobTable::default()
    };
    table.jobs.insert("deterministic-child".into(), row);
    let shared = Arc::new(Mutex::new(table));
    let mut command = Command::new(if mode == 0 {
        "/bin/false"
    } else {
        "/bin/sleep"
    });
    if mode != 0 {
        command.arg("30");
    }
    let mut child = spawn_supervised(&shared, "deterministic-child", &mut command).unwrap();
    if mode == 1 {
        NOW.store(1060, Ordering::SeqCst);
    }
    if mode == 2 {
        NOW.store(1005, Ordering::SeqCst);
        deadline::cancel(
            shared
                .lock()
                .unwrap()
                .jobs
                .get_mut("deterministic-child")
                .unwrap(),
            clock(),
        )
        .unwrap();
    }
    let completion = supervise_worker(
        &shared,
        "deterministic-child",
        &mut child,
        Instant::now() + Duration::from_secs(5),
        Duration::from_millis(20),
    )
    .unwrap();
    assert!(child.try_wait().unwrap().is_some());
    let mut table = shared.lock().unwrap();
    let row = table.jobs.get_mut("deterministic-child").unwrap();
    assert_eq!(row["active_children"], 0);
    assert_eq!(row["attempts"][0]["reaped"], true);
    if mode == 0 {
        assert_eq!(completion.status.code(), Some(1));
        deadline::report(row, 1, None, clock()).unwrap();
    }
    assert_eq!(
        row["state"],
        ["failed", "timed_out", "cancelled"][usize::from(mode)]
    );
    snapshots.push(result_store::snapshot(row, clock()));
    deadline::write_devices(&root.0, row).unwrap();
    result_store::publish_record(&root.0, row, clock()).unwrap();
    let store = result_store::Store::new(&root.0, result_store::Config::default());
    for (index, snapshot) in snapshots.iter().enumerate() {
        let mut snapshot = snapshot.clone();
        let id = format!("snapshot-{index}");
        snapshot["job_id"] = json!(id);
        store
            .put_job("tts", &id, &snapshot, &BTreeMap::new(), clock())
            .unwrap();
    }
    fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(&root.0, &root.0, &mut files);
    assert!(files.contains_key(Path::new("lanes/tts/jobs/deterministic-child/job.json")));
    assert!(files.contains_key(Path::new(
        "lanes/tts/jobs/deterministic-child/attempts/1/device.json"
    )));
    (files, snapshots, row.clone())
}
fn child_determinism_isolated(name: &str, check: impl FnOnce()) {
    if std::env::var_os("DETERMINISM_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args(["--exact", &format!("deadline_remainder::{name}"), "--quiet"])
            .env("DETERMINISM_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    check();
}
#[test]
fn real_child_same_clock_is_byte_identical() {
    child_determinism_isolated("real_child_same_clock_is_byte_identical", || {
        for mode in 0..3 {
            assert_eq!(
                child_determinism_scenario(mode),
                child_determinism_scenario(mode)
            );
        }
    });
}
#[test]
fn real_child_no_wall_clock_enters_run() {
    child_determinism_isolated("real_child_no_wall_clock_enters_run", || {
        let first = child_determinism_scenario(1);
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(first, child_determinism_scenario(1));
        assert_eq!(first.2["created_epoch"], 1000);
        assert_eq!(first.2["deadline_epoch"], 1060);
        for event in first.2["journal"].as_array().unwrap() {
            assert!([1000, 1060].contains(&event["at"].as_u64().unwrap()));
        }
    });
}
#[test]
fn real_child_live_and_terminal_snapshots_validate() {
    child_determinism_isolated("real_child_live_and_terminal_snapshots_validate", || {
        for mode in 0..3 {
            let (_, snapshots, row) = child_determinism_scenario(mode);
            assert_eq!(snapshots.len(), 4);
            for (snapshot, state) in snapshots.iter().zip([
                "queued",
                "dispatching",
                "running",
                row["state"].as_str().unwrap(),
            ]) {
                assert_eq!(snapshot.as_object().unwrap().len(), 17);
                assert_eq!(snapshot["state"], state);
                assert_eq!(snapshot["created_at"], "1970-01-01T00:16:40Z");
                assert_eq!(snapshot["deadline_at"], "1970-01-01T00:17:40Z");
            }
        }
    });
}
