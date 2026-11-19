use crate::*;
fn mutation(case: &str) {
    let output = Command::new("python3")
        .args(["tools/coverage-gate.py", "--self-test", case])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn coverage_gate_rejects_undeclared_and_unexercised_status() {
    mutation("status");
}
#[test]
fn coverage_gate_rejects_unused_and_unreachable_catalog_code() {
    mutation("unused");
}

fn timing_check(case: &str) {
    let output = Command::new("python3")
        .args(["tools/test-suite.py", "--self-test", case])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn harness_timing_rejects_empty_group() {
    timing_check("empty");
}
#[test]
fn harness_timing_report_has_every_group() {
    timing_check("report");
}
#[test]
fn harness_timing_delta_names_groups_missing_from_either_run() {
    timing_check("delta");
}
