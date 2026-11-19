//! Every shipped Python tool runs clean and planted fixtures as a real process.
use crate::*;
fn fixture(tool: &str) {
    let mut evidence = Vec::new();
    for (kind, accepted) in [("clean", true), ("planted", false)] {
        let output = Command::new("python3")
            .args([tool, "--fixture-test", kind])
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            accepted,
            "{tool} {kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if !accepted {
            assert!(!String::from_utf8_lossy(&output.stdout).contains("PASS"));
        }
        evidence.push(json!({"fixture":kind,"exit":output.status.code(),"accepted":accepted}));
    }
    let name = Path::new(tool).file_stem().unwrap().to_str().unwrap();
    fs::write(
        crate::test_process::target_dir().join(format!("run31-q4-{name}.json")),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
}
#[test]
fn run31_tool_coverage_gate() {
    fixture("tools/coverage-gate.py");
}
#[test]
fn run31_tool_test_suite() {
    fixture("tools/test-suite.py");
}
#[test]
fn run31_harness_accounting_regressions() {
    let output = Command::new("python3")
        .args(["tools/test-suite.py", "--self-test", "accounting"])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "harness accounting regressions: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"vector_count\": 53"));
}
#[test]
fn run31_tool_cli_cancel() {
    fixture("tools/cli-cancel.py");
}
#[test]
fn run31_tool_run28_audit() {
    fixture("tools/run28-audit.py");
}
#[test]
fn run31_tool_run29_audit() {
    fixture("tools/run29-audit.py");
}
#[test]
fn run31_tool_run30_audit() {
    fixture("tools/run30-audit.py");
}
#[test]
fn run31_tool_name_scan() {
    fixture("tools/name-scan.py");
}
