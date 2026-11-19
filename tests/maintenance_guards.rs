//! Maintenance evidence is checked alongside behavior by the full suite.
use crate::*;

fn tool_check(tool: &str, case: &str) {
    let output = Command::new("python3")
        .args([tool, "--self-test", case])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tool check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn name_scan_planted_match_prints_count_only() {
    tool_check("tools/name-scan.py", "planted");
}

#[test]
fn name_scan_clean_tree_prints_zero() {
    tool_check("tools/name-scan.py", "clean");
}

fn missing_allows(file: &str, source: &str, notes: &str) -> Vec<String> {
    let attributes = regex::Regex::new(r"(?s)#\s*\[\s*allow\s*\((.*?)\)\s*\]").unwrap();
    let lints = regex::Regex::new(r"clippy\s*::\s*([A-Za-z_0-9]+)").unwrap();
    let mut missing = Vec::new();
    for attribute in attributes.captures_iter(source) {
        for lint in lints.captures_iter(&attribute[1]) {
            let required = format!("CLIPPY-ALLOW {file} clippy::{}:", &lint[1]);
            if !notes.lines().any(|line| {
                line.strip_prefix(&required)
                    .is_some_and(|reason| !reason.trim().is_empty())
            }) {
                missing.push(format!("{file} clippy::{}", &lint[1]));
            }
        }
    }
    missing
}

#[test]
fn clippy_allows_require_file_and_lint_justifications() {
    fn visit(path: &Path, notes: &str, missing: &mut Vec<String>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, notes, missing);
            } else if path.extension().is_some_and(|value| value == "rs") {
                missing.extend(missing_allows(
                    path.to_str().unwrap(),
                    &fs::read_to_string(&path).unwrap(),
                    notes,
                ));
            }
        }
    }
    let notes = fs::read_to_string("FOLD-NOTES.md").unwrap();
    let mut missing = Vec::new();
    visit(Path::new("src"), &notes, &mut missing);
    assert!(
        missing.is_empty(),
        "Clippy allows without justification: {missing:?}"
    );
    let source = "#[allow(clippy::example, clippy::other)] fn fixture() {}";
    assert_eq!(
        missing_allows("src/planted.rs", source, ""),
        [
            "src/planted.rs clippy::example",
            "src/planted.rs clippy::other"
        ]
    );
    let notes = "CLIPPY-ALLOW src/planted.rs clippy::example: fixture reason\nCLIPPY-ALLOW src/planted.rs clippy::other: fixture reason";
    assert!(missing_allows("src/planted.rs", source, notes).is_empty());
    assert_eq!(
        missing_allows(
            "src/planted.rs",
            source,
            "CLIPPY-ALLOW src/planted.rs clippy::example: "
        )
        .len(),
        2
    );
}

fn ledger_rows(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines().filter(|line| line.starts_with("| RUN")) {
        let fields: Vec<_> = line.split('|').map(str::trim).collect();
        if fields.len() != 6
            || !fields[1]
                .strip_prefix("RUN")
                .and_then(|run| run.parse::<u32>().ok())
                .is_some_and(|run| run >= 23)
            || fields[2].is_empty()
            || !fields[3].starts_with("CONT_REPORT.md:")
            || fields[4].is_empty()
        {
            return Err(format!("invalid ledger row: {line}"));
        }
        let identity = (fields[1].to_owned(), fields[4].replace("&#124;", "|"));
        if !seen.insert(identity.clone()) {
            return Err(format!("duplicate ledger note: {line}"));
        }
        rows.push(identity);
    }
    if rows.is_empty() {
        return Err("empty ledger".into());
    }
    Ok(rows)
}

fn report_notes(report: &str) -> HashSet<(String, String)> {
    let mut expected = HashSet::new();
    // The historical headings begin at RUN21 and occur once per run.
    for (index, block) in report
        .split("## NOTES-TO-UPDATE\n")
        .skip(1)
        .enumerate()
        .skip(2)
    {
        let run = format!("RUN{}", index + 21);
        for line in block.lines().filter(|line| !line.trim().is_empty()) {
            if let Some(note) = line.strip_prefix("- ") {
                expected.insert((run.clone(), note.to_owned()));
            } else if let Some((_, note)) = line
                .split_once(" | ")
                .filter(|(_, note)| note.starts_with(&format!("{run} ")))
            {
                expected.insert((run.clone(), note.to_owned()));
            } else {
                break;
            }
        }
    }
    expected
}

fn check_ledger(ledger: &str, report: &str) -> Result<(), String> {
    let actual = ledger_rows(ledger)?.into_iter().collect::<HashSet<_>>();
    let expected = report_notes(report);
    let mut missing = expected
        .difference(&actual)
        .map(|(run, note)| format!("{run}: {note}"))
        .collect::<Vec<_>>();
    missing.sort();
    if !missing.is_empty() {
        return Err(format!("missing ledger entries: {}", missing.join("; ")));
    }
    let mut extra = actual.difference(&expected).cloned().collect::<Vec<_>>();
    extra.sort();
    if !extra.is_empty() {
        return Err(format!("ledger entries without source: {extra:?}"));
    }
    Ok(())
}

#[test]
fn notes_ledger_rows_have_section_run_and_complete_source_entries() {
    let ledger = fs::read_to_string("docs/NOTES-TO-UPDATE.md").unwrap();
    let rows = ledger_rows(&ledger).unwrap();
    let report = fs::read_to_string("CONT_REPORT.md").unwrap();
    let blocks: Vec<_> = report.split("## NOTES-TO-UPDATE\n").skip(1).collect();
    assert!(blocks.len() >= 9);
    let expected = report_notes(&report);
    check_ledger(&ledger, &report).unwrap();
    assert_eq!(rows.into_iter().collect::<HashSet<_>>(), expected);
    assert_eq!(
        expected
            .iter()
            .map(|row| row.0.as_str())
            .collect::<HashSet<_>>()
            .len(),
        blocks.len() - 2
    );
    assert!(fs::read_to_string("README.md")
        .unwrap()
        .contains("docs/NOTES-TO-UPDATE.md"));
    for bad in [
        "| RUN23 | | CONT_REPORT.md:1 | note |",
        "| RUN | section | CONT_REPORT.md:1 | note |",
        "",
    ] {
        assert!(ledger_rows(bad).is_err(), "accepted bad ledger: {bad}");
    }
    let first = ledger
        .lines()
        .find(|line| line.starts_with("| RUN"))
        .unwrap();
    assert!(ledger_rows(&format!("{ledger}\n{first}")).is_err());
}

#[test]
fn notes_ledger_missing_entry_names_run_and_note() {
    let ledger = fs::read_to_string("docs/NOTES-TO-UPDATE.md").unwrap();
    let report = fs::read_to_string("CONT_REPORT.md").unwrap();
    let heading = "## NOTES-TO-UPDATE\n";
    let start = report.rfind(heading).unwrap() + heading.len();
    let mut planted = report.clone();
    planted.insert_str(start, "\n- [R] missing ledger entry\n");
    let error = check_ledger(&ledger, &planted).unwrap_err();
    assert!(error.contains("RUN29: [R] missing ledger entry"), "{error}");
    assert!(check_ledger(&ledger, &report).is_ok());
}

fn invalid_manifest_paths(manifest: &str, contents: &str) -> Vec<String> {
    contents
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let path = line
                .split_once(char::is_whitespace)
                .map(|(_, path)| path.trim_start().trim_start_matches('*'))
                .unwrap_or("");
            let normalized = path.replace('\\', "/");
            let invalid = normalized.is_empty()
                || normalized.starts_with('/')
                || normalized.as_bytes().get(1) == Some(&b':')
                || normalized
                    .split('/')
                    .any(|part| ["..", "proof", "registry.json", "token-sha"].contains(&part));
            invalid.then(|| format!("{manifest}:{}: invalid manifest path {path}", index + 1))
        })
        .collect()
}

#[test]
fn manifest_path_guard_rejects_planted_bad_entries() {
    for path in [
        "/[R]",
        "../[R]",
        "docs/../[R]",
        "proof/[R]",
        "registry.json",
        "nested/registry.json",
        "token-sha/[R]",
        "nested/proof/[R]",
        "C:\\[R]",
        "nested\\..\\[R]",
    ] {
        let bad = format!("[R]  {path}\n");
        let errors = invalid_manifest_paths("SHA256SUMS.run-planted", &bad);
        assert_eq!(errors.len(), 1, "accepted {path}");
        assert!(errors[0].contains(path));
        assert!(errors[0].starts_with("SHA256SUMS.run-planted:1:"));
    }
    assert!(invalid_manifest_paths("SHA256SUMS.run-planted", "[R]  docs/example.md\n").is_empty());
}

#[test]
fn manifest_path_guard_accepts_every_shipped_manifest() {
    let mut manifests = fs::read_dir(".")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("SHA256SUMS.run")
        })
        .collect::<Vec<_>>();
    manifests.sort();
    assert!(!manifests.is_empty());
    let mut errors = Vec::new();
    for path in manifests {
        // Only the manifest is read. Entries are strings, never opened.
        errors.extend(invalid_manifest_paths(
            path.file_name().unwrap().to_str().unwrap(),
            &fs::read_to_string(&path).unwrap(),
        ));
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

fn run30_accepted_cli_flags() -> std::collections::BTreeSet<String> {
    let main = fs::read_to_string("src/main.rs").unwrap();
    let body = main
        .split_once("fn main() {")
        .unwrap()
        .1
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    let direct = regex::Regex::new(r#"(?:arg\(\s*|==\s*|Some\(\s*)"(--[a-z][a-z0-9-]*)""#).unwrap();
    let delegated = regex::Regex::new(r#"get\(\s*"(--[a-z][a-z0-9-]*)""#).unwrap();
    let mut accepted = direct
        .captures_iter(body)
        .map(|c| c[1].to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    for (name, marker) in [
        ("src/worker_registry.rs", "pub fn cli("),
        ("src/cartridge_registry.rs", "pub fn cli("),
    ] {
        assert!(body.contains(if name.contains("worker_registry") {
            "worker_registry::cli"
        } else {
            "cartridge_registry::cli"
        }));
        let source = fs::read_to_string(name).unwrap();
        let parser = source
            .split_once(marker)
            .unwrap()
            .1
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        accepted.extend(delegated.captures_iter(parser).map(|c| c[1].to_owned()));
    }
    assert!(!accepted.is_empty());
    accepted
}

fn run30_cli_drift(
    accepted: &std::collections::BTreeSet<String>,
    readme: &str,
) -> Result<(), String> {
    let worker = regex::Regex::new(r"(?s)<!-- worker-cli -->.*?<!-- /worker-cli -->").unwrap();
    let readme = worker.replace_all(readme, "");
    let flags = regex::Regex::new(r"--[a-z][a-z0-9-]*").unwrap();
    let documented = flags
        .find_iter(&readme)
        .map(|m| m.as_str().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let missing: Vec<_> = accepted.difference(&documented).cloned().collect();
    let unknown: Vec<_> = documented.difference(accepted).cloned().collect();
    if missing.is_empty() && unknown.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "README missing flags: {missing:?}; README unknown flags: {unknown:?}"
        ))
    }
}

#[test]
fn run30_real_readme_matches_accepted_cli_flags() {
    run30_cli_drift(
        &run30_accepted_cli_flags(),
        &fs::read_to_string("README.md").unwrap(),
    )
    .unwrap();
}

#[test]
fn run30_planted_readme_flag_fails_naming_drift() {
    let accepted = run30_accepted_cli_flags();
    let readme = fs::read_to_string("README.md").unwrap();
    let extra = format!("{readme}\n`--planted-option`\n");
    assert!(run30_cli_drift(&accepted, &extra)
        .unwrap_err()
        .contains("--planted-option"));
    let missing = readme.replace("--manifest-sha256", "manifest digest");
    assert!(run30_cli_drift(&accepted, &missing)
        .unwrap_err()
        .contains("--manifest-sha256"));
    let mut changed_source = accepted;
    changed_source.insert("--planted-source-option".into());
    assert!(run30_cli_drift(&changed_source, &readme)
        .unwrap_err()
        .contains("--planted-source-option"));
}
