use super::{super as backend, *};
use crate::cosp::la_worker::OperationJournal;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

// Neutral child: no driver, devices, sockets, credentials, or test authority.
// Faults are compiled into the fixture, not selected via the launcher API.
const CHILD: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
int main(int argc, char **argv) {
    static const char *pin = "GPU-457abb57-787f-5cf6-9ed5-d720030b93f5";
    if (argc != 2 || strcmp(argv[1], pin) || environ[0]) return 21;
    for (int fd = 3; fd < 64; ++fd) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 22;
    }
    if (CASE == 1) { write(1, "!", 1); for (;;) pause(); }
    if (CASE == 2) { for (;;) pause(); }
    if (write(1, "R", 1) != 1) return 23;
    char ch;
    if (read(0, &ch, 1) != 1 || ch != 'G' || read(0, &ch, 1) != 0) return 24;
    if (CASE == 3) return 6;
    if (CASE == 4) { for (int i = 0; i < 257; ++i) putchar(' '); return 0; }
    if (CASE == 5) { for (;;) pause(); }
    printf("{\"device_uuid\":\"%s\",\"workload\":\"add_one\",\"values\":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]}\n",
           CASE == 6 ? "GPU-00000000-0000-0000-0000-000000000001" : pin);
    return 0;
}
"#;
const PIN: &str = "GPU-457abb57-787f-5cf6-9ed5-d720030b93f5";
const OTHER: &str = "GPU-00000000-0000-0000-0000-000000000001";
const ADDRESS_SPACE: u64 = 16 * 1024 * 1024;
const INPUT: &[u8] = br#"{"schema_version":"diffuser-private-cuda-input/v1","workload":"add_one"}"#;

struct Scratch(PathBuf);
impl Scratch {
    fn new(case: &str) -> Self {
        let path = std::env::temp_dir().join(format!("cuda-neutral-{}-{case}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn child(&self, case: u8) -> (File, [u8; 32]) {
        let src = self.0.join("child.c");
        let exe = self.0.join(format!("child-{case}"));
        fs::write(&src, CHILD).unwrap();
        assert!(Command::new("/usr/bin/cc")
            .args(["-Wall", "-Wextra", "-Werror", &format!("-DCASE={case}")])
            .arg(src)
            .arg("-o")
            .arg(&exe)
            .status()
            .unwrap()
            .success());
        let digest = Sha256::digest(fs::read(&exe).unwrap()).into();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o500)).unwrap();
        (File::open(&exe).unwrap(), digest)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn launch(artifact: File, digest: [u8; 32]) -> Result<CudaProcess, &'static str> {
    CudaProcess::launch_verified(
        artifact,
        digest,
        DeviceUuid::parse(PIN).unwrap(),
        ADDRESS_SPACE,
    )
}
fn require_joined(pid: u32) {
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "child {pid} was not reaped"
    );
    println!("neutral_exact_child_reaped pid={pid}");
}

#[test]
fn neutral_verified_child_hands_off_to_protected_journal() {
    let scratch = Scratch::new("handoff");
    let (fd, hash) = scratch.child(0);
    // Retarget the original pathname to a different executable. The bound
    // descriptor must still launch the originally verified child.
    fs::rename(scratch.0.join("child-0"), scratch.0.join("child-original")).unwrap();
    fs::copy("/usr/bin/false", scratch.0.join("child-0")).unwrap();
    let helper = launch(fd, hash).expect("verified neutral child must become ready");
    let pid = helper.pid();
    let cap = Capability::CudaAddOne(DeviceUuid::parse(PIN).unwrap());
    let mut journal =
        OperationJournal::bootstrap(&scratch.0.join("worker.db"), "neutral-local").unwrap();
    journal.attach_backend(Box::new(helper)).unwrap();
    assert_eq!(journal.backend_ready(cap), Ok(()));
    assert_eq!(
        journal.backend_ready(Capability::CudaAddOne(DeviceUuid::parse(OTHER).unwrap())),
        Err("capability_unavailable")
    );
    drop(journal);
    require_joined(pid);
    println!("neutral_journal_handoff=ready wrong_uuid=capability_unavailable unused_child=reaped");
}

#[test]
fn neutral_verified_child_arms_once_and_checks_status_and_report() {
    let scratch = Scratch::new("protocol");
    let cap = Capability::CudaAddOne(DeviceUuid::parse(PIN).unwrap());
    for case in [0, 3, 4, 5, 6] {
        let (fd, hash) = scratch.child(case);
        let helper = launch(fd, hash).expect("neutral child must reach ready before armed fault");
        let pid = helper.pid();
        let answer = backend::execute(
            Box::new(helper),
            cap,
            INPUT,
            "neutral",
            &"0".repeat(64),
            Instant::now() + Duration::from_millis(if case == 5 { 80 } else { 2000 }),
            &|| false,
        );
        if case == 0 {
            let bytes = answer.unwrap();
            backend::validate_report(
                &bytes,
                "neutral",
                &"0".repeat(64),
                Some(INPUT.len()),
                Some(cap),
            )
            .unwrap();
            println!(
                "neutral_checked_report_sha256={}",
                hex::encode(Sha256::digest(bytes))
            );
        } else {
            assert_eq!(answer.unwrap_err(), "execution_uncertain");
            println!("neutral_fault_case={case} execution_uncertain");
        }
        require_joined(pid);
    }
}

#[test]
fn neutral_verified_child_refuses_bad_identity_or_readiness() {
    let scratch = Scratch::new("refusal");
    let (fd, mut hash) = scratch.child(0);
    hash[0] ^= 1;
    assert_eq!(launch(fd, hash).err(), Some("capability_unavailable"));
    for case in [1, 2] {
        let (fd, hash) = scratch.child(case);
        assert_eq!(launch(fd, hash).err(), Some("capability_unavailable"));
    }
    assert!(fs::read_to_string("/proc/thread-self/children")
        .unwrap()
        .trim()
        .is_empty());
    println!("neutral_identity_or_readiness=capability_unavailable no_children");
}
