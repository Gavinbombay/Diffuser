use super::*;
use std::fs;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new(body: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "run22-worker-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("child.py"), body).unwrap();
        Self(root)
    }
    fn command(&self) -> Command {
        let mut cmd = Command::new("python3");
        cmd.arg(self.0.join("child.py")).current_dir(&self.0);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn finish(child: &mut Child) -> Completion {
    wait(
        child,
        Instant::now() + Duration::from_secs(5),
        Duration::from_millis(50),
        || false,
    )
    .unwrap()
}

#[test]
fn spawn_in_own_group() {
    let fixture = Fixture::new("import os\nassert os.getpgrp() == os.getpid()\n");
    let mut child = spawn(&mut fixture.command()).unwrap();
    assert!(finish(&mut child).status.success());
}

#[test]
fn timeout_kills_group() {
    // The parent reaps its child on TERM. Both ignore normal application work;
    // only signalling the whole group makes the parent's wait return.
    let fixture = Fixture::new("import os, signal, time\nchild = os.fork()\nif child == 0:\n    signal.signal(signal.SIGTERM, lambda *_: exit(0))\n    while True: time.sleep(1)\ndef stop(*_):\n    os.waitpid(child, 0)\n    exit(0)\nsignal.signal(signal.SIGTERM, stop)\nwith open('ready.tmp', 'w') as out: out.write(str(child))\nos.rename('ready.tmp', 'ready')\nwhile True: time.sleep(1)\n");
    let mut child = spawn(&mut fixture.command()).unwrap();
    let pid = child.id();
    let ready = fixture.0.join("ready");
    let until = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    let descendant: i32 = fs::read_to_string(ready).unwrap().parse().unwrap();
    let done = wait(
        &mut child,
        Instant::now() + Duration::from_millis(30),
        Duration::from_secs(1),
        || false,
    )
    .unwrap();
    assert_eq!(done.state, "timed_out");
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    assert_eq!(unsafe { libc::kill(descendant, 0) }, -1);
}

#[test]
fn no_leaked_fds() {
    let fixture = Fixture::new("import os, sys\ntry:\n    os.fstat(int(sys.argv[1]))\nexcept OSError:\n    exit(0)\nexit(1)\n");
    let file = fs::File::create(fixture.0.join("inherited")).unwrap();
    let fd = file.as_raw_fd();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    let mut cmd = fixture.command();
    cmd.arg(fd.to_string());
    let mut child = spawn(&mut cmd).unwrap();
    assert!(finish(&mut child).status.success());
}

#[test]
fn reaped_exit_code() {
    let fixture = Fixture::new("exit(23)\n");
    let mut child = spawn(&mut fixture.command()).unwrap();
    let pid = child.id();
    assert_eq!(finish(&mut child).status.code(), Some(23));
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn stdin_closed() {
    let fixture = Fixture::new("import sys\nassert sys.stdin.read() == ''\n");
    let mut child = spawn(&mut fixture.command()).unwrap();
    assert!(finish(&mut child).status.success());
}

#[test]
fn spawn_failure_propagates() {
    let fixture = Fixture::new("exit(0)\n");
    let err = spawn(&mut Command::new(fixture.0.join("absent"))).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn cancellation_kills_group() {
    let fixture = Fixture::new("import time\ntime.sleep(30)\n");
    let mut child = spawn(&mut fixture.command()).unwrap();
    let done = wait(
        &mut child,
        Instant::now() + Duration::from_secs(5),
        Duration::ZERO,
        || true,
    )
    .unwrap();
    assert_eq!(done.state, "cancelled");
    assert!(!done.status.success());
}

#[test]
fn forced_timeout_reaps_grandchild() {
    // Isolate the Linux subreaper flag from the surrounding suite. The helper
    // adopts and reaps the killed grandchild, rather than relying on PID 1.
    if std::env::var_os("RUN22_GROUP_HELPER").is_none() {
        let output = crate::test_process::command()
            .args([
                "--exact",
                "worker_process::tests::forced_timeout_reaps_grandchild",
                "--nocapture",
            ])
            .env("RUN22_GROUP_HELPER", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    let fixture = Fixture::new("import os, signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\nchild = os.fork()\nif child != 0:\n    with open('ready.tmp', 'w') as out: out.write(str(child))\n    os.rename('ready.tmp', 'ready')\nwhile True: time.sleep(1)\n");
    let mut child = spawn(&mut fixture.command()).unwrap();
    let pid = child.id();
    let ready = fixture.0.join("ready");
    let until = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    let descendant: i32 = fs::read_to_string(ready).unwrap().parse().unwrap();
    let done = wait(
        &mut child,
        Instant::now() + Duration::from_millis(20),
        Duration::from_millis(20),
        || false,
    )
    .unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(done.status.signal(), Some(libc::SIGKILL));
    assert_eq!(done.state, "timed_out");
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(descendant, &mut status, 0) },
        descendant
    );
    assert!(libc::WIFSIGNALED(status));
    assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    assert_eq!(unsafe { libc::kill(descendant, 0) }, -1);
}

#[test]
fn run34_worker_lifecycle_all_pairs() {
    use Event::*;
    use State::*;
    // Inert children stay entirely in process and perform no OS operations.
    struct InertChild {
        state: State,
    }
    let states = [
        Running,
        StoppingTimeout,
        StoppingCancel,
        Done,
        TimedOut,
        Cancelled,
        Failed,
    ];
    let events = [Poll, Deadline, Cancel, Exit, GraceElapsed, IoError];
    let allowed = [
        (Running, Poll, Running),
        (Running, Deadline, StoppingTimeout),
        (Running, Cancel, StoppingCancel),
        (Running, Exit, Done),
        (Running, IoError, Failed),
        (StoppingTimeout, Poll, StoppingTimeout),
        (StoppingCancel, Poll, StoppingCancel),
        (StoppingTimeout, IoError, Failed),
        (StoppingCancel, IoError, Failed),
        (StoppingTimeout, Exit, TimedOut),
        (StoppingTimeout, GraceElapsed, TimedOut),
        (StoppingCancel, Exit, Cancelled),
        (StoppingCancel, GraceElapsed, Cancelled),
    ];
    let mut checked = 0;
    for before in states {
        for event in events {
            let mut child = InertChild { state: before };
            let result = transition(&mut child.state, event);
            if let Some((_, _, after)) =
                allowed.iter().find(|(s, e, _)| *s == before && *e == event)
            {
                assert_eq!(result, Ok(()), "{before:?}/{event:?}");
                assert_eq!(child.state, *after);
            } else {
                assert_eq!(
                    result,
                    Err(crate::error_catalog::ILLEGAL_TRANSITION),
                    "{before:?}/{event:?}"
                );
                assert!(crate::error_catalog::lookup(None, result.unwrap_err()).is_some());
                assert_eq!(child.state, before);
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 42);
}

#[test]
fn run36_v4_worker_submodule_terminal_refusals_preserve_child() {
    use Event::*;
    use State::*;
    let files: std::collections::BTreeSet<_> =
        fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/worker_process"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
    assert_eq!(
        files,
        std::collections::BTreeSet::from(["tests.rs".to_owned()])
    );
    // This test file documents terminal event refusal. Inert records perform no
    // spawn, signal, wait, clock, socket or filesystem operation on a child.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct InertChild {
        state: State,
        completion: Option<&'static str>,
        writes: usize,
        signals: usize,
    }
    let paths: &[(&[Event], State, &str)] = &[
        (&[Exit], Done, "done"),
        (&[Deadline, GraceElapsed], TimedOut, "timed_out"),
        (&[Cancel, Exit], Cancelled, "cancelled"),
        (&[IoError], Failed, "failed"),
    ];
    let mut refusals = 0;
    for (events, terminal, outcome) in paths {
        let mut child = InertChild {
            state: Running,
            completion: None,
            writes: 0,
            signals: 0,
        };
        for event in *events {
            transition(&mut child.state, *event).unwrap();
        }
        assert_eq!(child.state, *terminal);
        child.completion = Some(outcome);
        let before = child.clone();
        for event in [Poll, Deadline, Cancel, Exit, GraceElapsed, IoError] {
            let reason = transition(&mut child.state, event).unwrap_err();
            assert_eq!(reason, crate::error_catalog::ILLEGAL_TRANSITION);
            assert_eq!(
                crate::error_catalog::lookup(None, reason).unwrap().code,
                crate::error_catalog::ILLEGAL_TRANSITION
            );
            assert_eq!(
                child, before,
                "terminal child changed on {terminal:?}/{event:?}"
            );
            refusals += 1;
        }
    }
    assert_eq!(refusals, 24);
}
