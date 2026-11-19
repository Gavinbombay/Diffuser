//! Real CLI signals exercise startup, worker reaping and terminal publication.
use crate::*;
fn check(signal: &str) {
    let output = Command::new("python3")
        .args(["tools/cli-cancel.py", signal])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: Value = serde_json::from_slice(
        &fs::read(crate::test_process::target_dir().join(format!("run28-cli-{signal}.json")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(evidence["result"], "PASS");
    let line = evidence["cancel_log"].as_str().unwrap();
    assert_eq!(line.lines().count(), 1);
    assert!(line.len() <= 128);
    assert_eq!(log_redaction::line(line), line);
}
#[test]
fn sigint_cli_settles_once_and_reaps_real_child() {
    check("int");
}
#[test]
fn sigterm_cli_settles_once_and_reaps_real_child() {
    check("term");
}
