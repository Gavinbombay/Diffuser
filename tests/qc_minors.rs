use crate::*;
#[test]
fn qc_cartridge_non_string_lane_refused() {
    for lane in [json!([]), json!({}), json!(1), json!(false), Value::Null] {
        assert_eq!(
            cartridge_registry::job_shape(&json!({"api":API,"lane":lane}), "tts"),
            Err(error_catalog::BAD_SPEC)
        );
    }
}
#[test]
fn qc_multiple_refusals_have_explicit_lane_then_size_precedence() {
    let malformed = vec![b'{'; dispatch_kinds::Config::default().body_max + 1];
    assert_eq!(
        request_boundary::load(&malformed, Some("unknown")),
        Err(error_catalog::UNKNOWN_LANE)
    );
    assert_eq!(
        request_boundary::load(b"{", Some("unknown")),
        Err(error_catalog::UNKNOWN_LANE)
    );
    assert_eq!(
        request_boundary::load(&malformed, Some("tts")),
        Err(error_catalog::REQUEST_TOO_LARGE)
    );
}
#[test]
fn qc_unknown_limits_lane_fails_closed() {
    for lane in [json!("unknown"), Value::Null, json!([])] {
        assert_eq!(
            runtime_limits::enforce(
                &json!({"lane":lane}),
                &json!({}),
                |_| panic!("must refuse before reading"),
                &runtime_limits::Config::default()
            ),
            Err(error_catalog::CEILING_UNKNOWN)
        );
    }
}
#[test]
fn qc_dispatch_outcome_precedence_is_pinned() {
    let device = json!({"state":"timed_out","timed_out":true,"rc":124});
    assert_eq!(
        dispatch_kinds::map_attempt(0, &device, &Value::Null, true, None),
        ("timed_out".into(), 124, None)
    );
    let result = json!({"api":API,"job_id":"fixture","state":"failed","attempts":[{"state":"failed","rc":1,"reason":"fixture-failure"}]});
    assert_eq!(
        dispatch_kinds::map_attempt(0, &device, &result, true, None),
        ("failed".into(), 1, Some("fixture-failure".into()))
    );
    assert_eq!(
        dispatch_kinds::map_attempt(2, &json!({"state":"failed"}), &Value::Null, true, None).0,
        "failed"
    );
    assert_eq!(
        dispatch_kinds::map_attempt(2, &json!({"state":"failed"}), &Value::Null, false, None).0,
        "refused"
    );
}
fn positive_cite(value: &str) -> Option<(&str, &str)> {
    value
        .rsplit_once(':')
        .filter(|(path, n)| !path.is_empty() && n.parse::<usize>().is_ok_and(|line| line > 0))
}
fn valid_table(text: &str) -> bool {
    let rows: Vec<_> = text
        .lines()
        .filter(|line| {
            line.starts_with('|')
                && !line.starts_with("| QC file:line")
                && !line.starts_with("| ---")
        })
        .collect();
    !rows.is_empty()
        && rows.iter().all(|line| {
            let cells: Vec<_> = line.split('|').map(str::trim).collect();
            if cells.len() != 6
                || !["closed-in-fold", "fixed-now", "not-in-fold"].contains(&cells[3])
            {
                return false;
            }
            if positive_cite(cells[1]).is_none() {
                return false;
            }
            let Some((file, n)) = positive_cite(cells[2]) else {
                return false;
            };
            let path = Path::new(file);
            if path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
                || !(file.starts_with("src/")
                    || file.starts_with("tests/")
                    || file.starts_with("docs/")
                    || ["README.md", "CONTRACT-5820.md", "FOLD-NOTES.md"].contains(&file))
            {
                return false;
            }
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
                .is_ok_and(|content| n.parse::<usize>().unwrap() <= content.lines().count())
        })
}
#[cfg(feature = "contract-docs")]
#[test]
fn qc_minor_rows_require_status_and_both_citations() {
    let table = include_str!("../docs/QC-MINORS.md");
    assert!(valid_table(table));
    assert!(!valid_table(&table.replacen("| fixed-now |", "| |", 1)));
    assert!(
        table
            .lines()
            .filter(|line| line.starts_with("| A/") && line.contains("| fixed-now |"))
            .count()
            >= 4
    );
}

#[cfg(feature = "contract-docs")]
#[test]
fn qc_minor_dispositions_are_closed_and_explain_absent_subjects() {
    let table = include_str!("../docs/QC-MINORS.md");
    for line in table.lines().filter(|line| line.starts_with("| A/")) {
        let cells: Vec<_> = line.split('|').map(str::trim).collect();
        assert!(
            ["closed-in-fold", "fixed-now", "not-in-fold"].contains(&cells[3]),
            "unresolved QC row: {}",
            cells[1]
        );
        assert!(!cells[4].is_empty(), "missing disposition: {}", cells[1]);
        if cells[3] == "not-in-fold" {
            assert!(
                cells[4].contains("absent"),
                "absent subject needs a reason: {}",
                cells[1]
            );
        }
    }
}

#[cfg(feature = "contract-docs")]
#[test]
fn qc_guard_refuses_missing_status_and_either_citation() {
    let valid = "| A/fixture/QC.md:1 | src/main.rs:1 | closed-in-fold | checked |";
    assert!(valid_table(include_str!("../docs/QC-MINORS.md")));
    assert!(valid_table(valid));
    for (before, after) in [
        ("closed-in-fold", ""),
        ("A/fixture/QC.md:1", ""),
        ("src/main.rs:1", ""),
        ("QC.md:1", "QC.md:0"),
        ("closed-in-fold", "open"),
    ] {
        assert!(
            !valid_table(&valid.replace(before, after)),
            "accepted missing status/cite: {before}"
        );
        assert!(
            !valid_table(&format!("{valid}\n{}", valid.replace(before, after))),
            "malformed row hidden among valid rows: {before}"
        );
    }
}
#[test]
fn qc_guard_refuses_fold_citations_outside_file_bounds() {
    let valid = "| A/fixture/QC.md:1 | src/main.rs:1 | fixed-now | checked |";
    let lines = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
        .unwrap()
        .lines()
        .count();
    assert!(valid_table(
        &valid.replace("src/main.rs:1", &format!("src/main.rs:{lines}"))
    ));
    for cite in [
        format!("src/main.rs:{}", lines + 1),
        "src/main.rs:0".into(),
        "src/missing.rs:1".into(),
        "../src/main.rs:1".into(),
    ] {
        assert!(
            !valid_table(&valid.replace("src/main.rs:1", &cite)),
            "accepted invalid fold cite: {cite}"
        );
    }
}
