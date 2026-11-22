//! Bidirectional code parity with diagnostics naming every orphan.
use crate::*;
use std::collections::BTreeSet;
#[cfg(feature = "contract-docs")]
fn parity(text: &str) -> Result<usize, String> {
    let catalog = error_catalog::TABLE
        .iter()
        .filter(|entry| !entry.code.is_empty())
        .map(|entry| entry.code.to_string())
        .collect::<BTreeSet<_>>();
    let rows = text
        .lines()
        .filter(|line| line.starts_with("| "))
        .filter_map(|line| line.split('|').nth(2))
        .map(str::trim)
        .filter(|code| !matches!(*code, "Error code" | "---" | "none"))
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let missing = catalog.difference(&rows).cloned().collect::<Vec<_>>();
    let orphan = rows.difference(&catalog).cloned().collect::<Vec<_>>();
    if !missing.is_empty() || !orphan.is_empty() {
        Err(format!(
            "missing documentation: {missing:?}; orphan documentation: {orphan:?}"
        ))
    } else {
        Ok(catalog.len())
    }
}
#[cfg(feature = "contract-docs")]
#[test]
fn run31_real_error_docs_match_catalog() {
    let count = parity(include_str!("../docs/ERRORS.md")).unwrap();
    assert!(count > 0);
    fs::write(
        crate::test_process::target_dir().join("run31-q5-parity.json"),
        serde_json::to_vec_pretty(&json!({"result":"PASS","catalog_codes":count})).unwrap(),
    )
    .unwrap();
}
#[cfg(feature = "contract-docs")]
#[test]
fn run31_planted_error_doc_orphans_are_named() {
    let text = include_str!("../docs/ERRORS.md");
    let error = parity(&format!(
        "{text}\n| in-process | planted-orphan | [R] | [R] |\n"
    ))
    .unwrap_err();
    assert!(
        error.contains("orphan documentation: [\"planted-orphan\"]"),
        "{error}"
    );
    let missing = text
        .lines()
        .filter(|line| {
            !(line.starts_with("| ")
                && line
                    .split('|')
                    .nth(2)
                    .is_some_and(|code| code.trim() == error_catalog::BAD_SPEC))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let error = parity(&missing).unwrap_err();
    assert!(error.contains(error_catalog::BAD_SPEC), "{error}");
    assert!(error.starts_with("missing documentation:"));
}
