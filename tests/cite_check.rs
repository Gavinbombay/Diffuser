//! Range-check fold cites and available accepted references without changing them.
use crate::*;
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"_./~+-".contains(&b)
}
fn citations(text: &str) -> Vec<(String, usize, usize)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for at in 0..bytes.len() {
        if bytes[at] != b':' || !bytes.get(at + 1).is_some_and(u8::is_ascii_digit) {
            continue;
        }
        let mut start = at;
        while start > 0 && path_byte(bytes[start - 1]) {
            start -= 1;
        }
        let path = &text[start..at];
        if !path.contains('.') || !path.bytes().any(|b| b.is_ascii_alphabetic()) {
            continue;
        }
        let mut cursor = at + 1;
        loop {
            let begin = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                cursor += 1;
            }
            let first = text[begin..cursor].parse::<usize>().unwrap_or(0);
            let mut last = first;
            if bytes.get(cursor) == Some(&b'-') {
                cursor += 1;
                let begin = cursor;
                while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                    cursor += 1;
                }
                last = text[begin..cursor].parse::<usize>().unwrap_or(0);
            }
            found.push((path.to_owned(), first, last));
            if bytes.get(cursor) != Some(&b',')
                || !bytes.get(cursor + 1).is_some_and(u8::is_ascii_digit)
            {
                break;
            }
            cursor += 1;
        }
    }
    found
}
fn check(root: &Path, accepted: &Path, text: &str) -> Result<(usize, usize), Vec<String>> {
    let mut checked = 0;
    let mut skipped = 0;
    let mut failures = Vec::new();
    for (path, first, last) in citations(text) {
        let target = if let Some(rest) = path.strip_prefix("A/") {
            let job = rest.split('/').next().unwrap_or("");
            if job.starts_with("agy-")
                || ["-b7-01", "-b7-02", "-b7-03", "-b7-05", "-b7-12"]
                    .iter()
                    .any(|s| job.contains(s))
            {
                failures.push(format!("excluded reference {path}:{first}"));
                continue;
            }
            let p = accepted.join(rest);
            if !p.is_file() {
                skipped += 1;
                continue;
            }
            p
        } else {
            let relative = path.strip_prefix("F/").unwrap_or(&path);
            if !(relative.starts_with("src/")
                || relative.starts_with("tests/")
                || relative.starts_with("docs/")
                || ["README.md", "CONTRACT-5820.md", "FOLD-NOTES.md"].contains(&relative))
            {
                continue;
            }
            if relative.split('/').any(|s| s == "..") {
                failures.push(format!("unsafe cite {path}:{first}"));
                continue;
            }
            root.join(relative)
        };
        checked += 1;
        match fs::read_to_string(target) {
            Ok(s) if first > 0 && last >= first && s.lines().count() >= last => {}
            _ => failures.push(format!("invalid cite {path}:{first}-{last}")),
        }
    }
    if failures.is_empty() {
        Ok((checked, skipped))
    } else {
        Err(failures)
    }
}
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
#[test]
fn cite_check_real_fold_documents() {
    let root = root();
    let accepted = std::env::var_os("LANE_ACCEPTED_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("../../../srv/lanes-inbox/accepted"));
    let mut total = 0;
    let mut skipped = 0;
    assert!(
        fs::read_to_string(root.join("src/main.rs"))
            .unwrap()
            .lines()
            .count()
            < 600
    );
    let mut documents: Vec<PathBuf> = ["CONTRACT-5820.md", "README.md", "FOLD-NOTES.md"]
        .into_iter()
        .map(PathBuf::from)
        .collect();
    documents.extend(
        fs::read_dir(root.join("docs"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|s| s == "md")),
    );
    for file in documents {
        let (count, missing) = check(
            &root,
            &accepted,
            &fs::read_to_string(root.join(&file)).unwrap(),
        )
        .unwrap_or_else(|bad| panic!("{}: {bad:?}", file.display()));
        total += count;
        skipped += missing;
    }
    assert!(total > 10);
    println!("cites checked {total}; unavailable A cites skipped {skipped}");
}
#[test]
fn cite_check_planted_bad_cite_in_temp_copy_fails() {
    let tmp = std::env::temp_dir().join(format!("fold-cites-{}", std::process::id()));
    fs::create_dir_all(tmp.join("src")).unwrap();
    fs::write(tmp.join("src/example.rs"), "one\ntwo\n").unwrap();
    let mut text = fs::read_to_string(root().join("README.md")).unwrap();
    text.push_str("\nsrc/example.rs:1-3\n");
    fs::write(tmp.join("README.md"), &text).unwrap();
    let error = check(&tmp, &tmp.join("absent"), &text).unwrap_err();
    assert!(error.iter().any(|s| s.contains("src/example.rs:1-3")));
    assert!(check(&tmp, &tmp, "src/missing.rs:1").is_err());
    fs::remove_dir_all(tmp).unwrap();
}
#[test]
fn cite_check_ranges_and_unavailable_reference_count() {
    assert_eq!(
        citations("src/example.rs:2-4,6 A/missing/out/NOTE.md:1"),
        vec![
            ("src/example.rs".into(), 2, 4),
            ("src/example.rs".into(), 6, 6),
            ("A/missing/out/NOTE.md".into(), 1, 1)
        ]
    );
    assert_eq!(
        check(
            &root(),
            &crate::test_process::target_dir().join("absent-reference-root"),
            "A/missing/out/NOTE.md:1"
        ),
        Ok((0, 1))
    );
    assert!(check(&root(), &root(), "src/main.rs:0").is_err());
    assert!(check(&root(), &root(), "src/main.rs:3-2").is_err());
}

// Unlike the historical audit, this gate skips no path prefix or missing file.
fn strict_check(
    root: &Path,
    accepted: &Path,
    vendor: &Path,
    text: &str,
) -> Result<usize, Vec<String>> {
    let mut failures = Vec::new();
    let cites = citations(text);
    for (path, first, last) in &cites {
        let relative = path.strip_prefix("F/").unwrap_or(path);
        let unsafe_path = Path::new(relative).is_absolute()
            || relative.split('/').any(|part| {
                matches!(
                    part,
                    ".." | "proof" | "token-sha" | "registry.json" | "specs" | "kit" | "stalled"
                )
            });
        let target = if let Some(rest) = path.strip_prefix("A/") {
            accepted.join(rest)
        } else if let Some(rest) = path.strip_prefix("V/") {
            vendor.join(rest)
        } else {
            root.join(relative)
        };
        if unsafe_path
            || fs::read_to_string(target)
                .ok()
                .is_none_or(|source| *first == 0 || last < first || *last > source.lines().count())
        {
            failures.push(format!("{path}:{first}-{last}"));
        }
    }
    if failures.is_empty() {
        Ok(cites.len())
    } else {
        Err(failures)
    }
}
// Reference roots (spine r5 same-job resume): one env root,
// default the custodian read-only tree. accepted = $ROOT/accepted, vendor = $ROOT/vendor-src/codex-8801b9a8a6c6.
fn refs_root() -> PathBuf {
    std::env::var_os("DIFFUSER_REFS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/srv/lanes/refs/diffuser-20261113"))
}
#[test]
fn run28_every_cite_in_required_documents_exists_and_is_in_bounds() {
    let root = root();
    let refs = refs_root();
    let accepted = refs.join("accepted");
    let vendor = refs.join("vendor-src/codex-8801b9a8a6c6");
    let mut failures = Vec::new();
    let mut count = 0;
    for document in ["FOLD-NOTES.md", "docs/ERRORS.md", "docs/CONFORMANCE-B6.md"] {
        match strict_check(
            &root,
            &accepted,
            &vendor,
            &fs::read_to_string(root.join(document)).unwrap(),
        ) {
            Ok(n) => {
                assert!(n > 0, "no cites in {document}");
                count += n;
            }
            Err(bad) => failures.extend(bad.into_iter().map(|cite| format!("{document}: {cite}"))),
        }
    }
    assert!(
        failures.is_empty(),
        "invalid cites:\n{}",
        failures.join("\n")
    );
    assert!(count > 1000);
}
#[test]
fn run28_planted_bad_cites_name_every_failure() {
    let root = std::env::temp_dir().join(format!("run28-cites-{}", std::process::id()));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/example.rs"), "one\ntwo\n").unwrap();
    let bad = strict_check(
        &root,
        &root,
        &root,
        "src/example.rs:3 src/missing.rs:1 other.txt:9 src/example.rs:0 src/example.rs:2-1",
    )
    .unwrap_err();
    assert_eq!(
        bad,
        [
            "src/example.rs:3-3",
            "src/missing.rs:1-1",
            "other.txt:9-9",
            "src/example.rs:0-0",
            "src/example.rs:2-1"
        ]
    );
    assert_eq!(
        strict_check(&root, &root, &root, "src/example.rs:1-2"),
        Ok(1)
    );
    fs::remove_dir_all(root).unwrap();
}
// RETIRED-UNRECOVERABLE (DIV-010): the fold build log behind the one
// FOLD-NOTES cite of target/run31-startup.log (sha256 2470caa8a6d7) is gone; it is never regenerated.
// The marker must stay in FOLD-NOTES.md and the path must never come back as a live cite.
#[test]
fn run31_startup_log_cite_is_retired_unrecoverable() {
    let notes = fs::read_to_string(root().join("FOLD-NOTES.md")).unwrap();
    assert!(
        notes.contains("target/run31-startup.log [RETIRED-UNRECOVERABLE"),
        "retired marker missing"
    );
    assert!(
        !citations(&notes)
            .iter()
            .any(|(path, _, _)| path == "target/run31-startup.log"),
        "retired cite target/run31-startup.log is live again"
    );
}
