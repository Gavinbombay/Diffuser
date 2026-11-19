use crate::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NOW: AtomicU64 = AtomicU64::new(100);
fn clock() -> u64 {
    NOW.load(Ordering::SeqCst)
}

fn run(name: &str, mode: u8) {
    if std::env::var_os("DEADLINE_WORKER_CHILD").is_none() {
        assert!(crate::test_process::command()
            .args(["--exact", &format!("deadline_workers::{name}"), "--quiet"])
            .env("DEADLINE_WORKER_CHILD", "1")
            .status()
            .unwrap()
            .success());
        return;
    }
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let root = std::env::temp_dir().join(format!("run23-deadline-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let script = root.join("worker.py");
    fs::write(&script, "import os, pathlib, sys, time\nif sys.argv[1] == 'exit': sys.exit(7)\nleaf = os.fork()\nif leaf == 0:\n    time.sleep(30)\nelse:\n    record = pathlib.Path(sys.argv[1])\n    pending = record.with_suffix('.pending')\n    pending.write_text(str(leaf))\n    pending.replace(record)\n    time.sleep(30)\n").unwrap();
    let mut table = JobTable {
        clock: Some(clock),
        ..JobTable::default()
    };
    let mut row = queue_policy::admitted(
        &HashMap::new(),
        &json!({"job_id":"fixture","lane":"tts"}),
        100,
    );
    row["deadline_epoch"] = json!(101);
    deadline::dispatch(&mut row, "worker-one", 100).unwrap();
    deadline::accept(&mut row, 100).unwrap();
    table.jobs.insert("fixture".into(), row);
    let shared = Arc::new(Mutex::new(table));
    let loops = if mode == 3 { 2 } else { 1 };
    for attempt in 0..loops {
        let leaf_path = root.join(format!("leaf-{attempt}"));
        let mut command = Command::new("python3");
        command.arg(&script);
        if mode >= 2 {
            command.arg("exit");
        } else {
            command.arg(&leaf_path);
        }
        let mut child = spawn_supervised(&shared, "fixture", &mut command).unwrap();
        assert_eq!(shared.lock().unwrap().jobs["fixture"]["active_children"], 1);
        if mode < 2 {
            for _ in 0..500 {
                if leaf_path.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(leaf_path.exists());
        }
        if mode == 0 {
            NOW.store(101, Ordering::SeqCst);
        }
        if mode == 1 {
            let mut table = shared.lock().unwrap();
            deadline::cancel(table.jobs.get_mut("fixture").unwrap(), 100).unwrap();
        }
        let completion = supervise_worker(
            &shared,
            "fixture",
            &mut child,
            Instant::now() + Duration::from_secs(5),
            Duration::from_millis(20),
        )
        .unwrap();
        assert!(child.try_wait().unwrap().is_some());
        let mut table = shared.lock().unwrap();
        let row = table.jobs.get_mut("fixture").unwrap();
        assert_eq!(row["active_children"], 0);
        assert_eq!(row["attempts"][attempt]["reaped"], true);
        if mode == 0 {
            assert_eq!(completion.state, "timed_out");
            assert_eq!(row["state"], "timed_out");
            assert_eq!(row["attempts"][attempt]["rc"], 124);
        } else if mode == 1 {
            assert_eq!(completion.state, "cancelled");
            assert_eq!(row["state"], "cancelled");
        } else {
            assert_eq!(completion.status.code(), Some(7));
            assert_eq!(row["attempts"][attempt]["raw_rc"], 7);
            deadline::report(
                row,
                1,
                (mode == 3 && attempt == 0).then_some("worker-two"),
                100,
            )
            .unwrap();
            assert_eq!(row["attempts"][attempt]["rc"], 1);
            if mode == 3 && attempt == 0 {
                deadline::accept(row, 100).unwrap();
            }
        }
        drop(table);
        if mode < 2 {
            let leaf: i32 = fs::read_to_string(&leaf_path).unwrap().parse().unwrap();
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(leaf, &mut status, 0) }, leaf);
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(unsafe { libc::kill(leaf, 0) }, -1);
        }
    }
    if mode == 3 {
        let mut table = shared.lock().unwrap();
        let row = table.jobs.get_mut("fixture").unwrap();
        assert_eq!(row["attempts"].as_array().unwrap().len(), 2);
        assert!(deadline::dispatch(row, "worker-three", 100).is_err());
        assert_eq!(row["attempts"].as_array().unwrap().len(), 2);
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn deadline_expiry_kills_group() {
    run("deadline_expiry_kills_group", 0);
}
#[test]
fn cancel_kills_group() {
    run("cancel_kills_group", 1);
}
#[test]
fn settle_from_reaped_exit() {
    run("settle_from_reaped_exit", 2);
}
#[test]
fn two_attempt_cap_holds_on_real_child() {
    run("two_attempt_cap_holds_on_real_child", 3);
}
