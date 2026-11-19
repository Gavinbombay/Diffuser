use super::*;
use crate::*;
#[test]
fn catalog_document_rows_equal_const_table() {
    let doc = include_str!("../docs/ERRORS.md");
    let rows: Vec<_> = doc
        .lines()
        .filter(|s| s.starts_with("| ") && !s.starts_with("| HTTP") && !s.starts_with("| ---"))
        .collect();
    assert_eq!(rows.len(), TABLE.len());
    for (row, entry) in rows.iter().zip(TABLE) {
        assert!(row.contains(entry.code));
        assert!(row.contains(entry.reason.replace('|', "/").as_str()));
        assert!(row.contains(entry.source));
        assert!(row.contains(
            &entry
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "in-process".into())
        ));
    }
}
#[test]
fn catalog_sources_resolve_and_tuples_are_unique() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut seen = HashSet::new();
    for e in TABLE {
        assert!(seen.insert((e.status, e.code, e.reason)), "duplicate {e:?}");
        let (path, line) = e.source.rsplit_once(':').unwrap();
        let line = line.parse::<usize>().unwrap();
        assert!(
            line > 0 && fs::read_to_string(root.join(path)).unwrap().lines().count() >= line,
            "{}",
            e.source
        );
    }
}
fn lex_end(data: &[u8], at: usize) -> usize {
    if data[at..].starts_with(b"//") {
        return data[at..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| at + n)
            .unwrap_or(data.len());
    }
    if data[at..].starts_with(b"/*") {
        let mut pos = at + 2;
        let mut depth = 1;
        while pos < data.len() && depth > 0 {
            if data[pos..].starts_with(b"/*") {
                depth += 1;
                pos += 2;
            } else if data[pos..].starts_with(b"*/") {
                depth -= 1;
                pos += 2;
            } else {
                pos += 1;
            }
        }
        return pos;
    }
    let mut pos = at;
    if data[pos..].starts_with(b"br") {
        pos += 2;
    } else if data[pos] == b'r' {
        pos += 1;
    }
    if pos > at {
        let marks = pos;
        while data.get(pos) == Some(&b'#') {
            pos += 1;
        }
        if data.get(pos) == Some(&b'"') {
            let count = pos - marks;
            pos += 1;
            while pos < data.len() {
                if data[pos] == b'"' && (0..count).all(|n| data.get(pos + 1 + n) == Some(&b'#')) {
                    return pos + 1 + count;
                }
                pos += 1;
            }
            return pos;
        }
    }
    if data[at] == b'"' {
        let mut pos = at + 1;
        while pos < data.len() {
            if data[pos] == b'\\' {
                pos += 2;
            } else if data[pos] == b'"' {
                return pos + 1;
            } else {
                pos += 1;
            }
        }
        return pos.min(data.len());
    }
    if data[at] == b'\'' {
        if data.get(at + 2) == Some(&b'\'') {
            return at + 3;
        }
        if data.get(at + 1) == Some(&b'\\') && data.get(at + 3) == Some(&b'\'') {
            return at + 4;
        }
    }
    at
}
pub(crate) fn production(source: &str) -> String {
    let data = source.as_bytes();
    let mut out = data.to_vec();
    let mut at = 0;
    while at < data.len() {
        let next = lex_end(data, at);
        if next > at {
            if data[at..].starts_with(b"//") || data[at..].starts_with(b"/*") {
                for b in &mut out[at..next] {
                    if *b != b'\n' {
                        *b = b' ';
                    }
                }
            }
            at = next;
            continue;
        }
        if data[at..].starts_with(b"#[cfg(test)]") {
            let start = at;
            at += 12;
            while at < data.len() {
                let next = lex_end(data, at);
                if next > at {
                    at = next;
                    continue;
                }
                if data[at] == b';' {
                    at += 1;
                    break;
                }
                if data[at] == b'{' {
                    let mut depth = 1;
                    at += 1;
                    while at < data.len() && depth > 0 {
                        let next = lex_end(data, at);
                        if next > at {
                            at = next;
                            continue;
                        }
                        if data[at] == b'{' {
                            depth += 1;
                        }
                        if data[at] == b'}' {
                            depth -= 1;
                        }
                        at += 1;
                    }
                    break;
                }
                at += 1;
            }
            for b in &mut out[start..at] {
                if *b != b'\n' {
                    *b = b' ';
                }
            }
        } else {
            at += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
fn codes_in_source(source: &str) -> HashSet<String> {
    let source = production(source);
    let data = source.as_bytes();
    let mut found = HashSet::new();
    let mut at = 0;
    while at < data.len() {
        let end = lex_end(data, at);
        if data[at] == b'"' && end > at + 1 {
            let value = &source[at + 1..end - 1];
            let prefix: String = source[..at]
                .chars()
                .rev()
                .take(100)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .filter(|c| !c.is_whitespace())
                .collect();
            let producer = [
                "crate::error_catalog::reason(",
                "Err(",
                ".ok_or(",
                "failure(",
                "returnSome(",
                ".push(",
                "\"code\":",
                "\"error_code\":",
                "code:",
                "self.reason=Some(",
            ]
            .iter()
            .any(|p| prefix.ends_with(p))
                || ((prefix.ends_with('|'))
                    && (prefix.contains("map_err(") || prefix.contains("ok_or_else(")));
            if producer
                && !value.is_empty()
                && value.as_bytes()[0].is_ascii_alphabetic()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphabetic() || b.is_ascii_digit() || b"_-".contains(&b))
            {
                found.insert(value.to_owned());
            }
        }
        at = if end > at { end } else { at + 1 };
    }
    found
}
#[test]
fn catalog_grep_no_production_error_code_missing() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let listed: HashSet<_> = TABLE.iter().map(|e| e.code).collect();
    let mut missing = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|s| s != "rs")
            || path.file_name().unwrap() == "fake_suite.rs"
            || path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("_tests.rs")
        {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        if path.file_name().unwrap() != "error_catalog.rs" {
            for (line, value) in bare_codes(&source) {
                missing.push(format!("bare {value} in {}:{line}", path.display()));
            }
        }
        for code in codes_in_source(&source) {
            if !listed.contains(code.as_str()) {
                missing.push(format!("{code} in {}", path.display()));
            }
        }
    }
    assert!(missing.is_empty(), "unlisted codes: {missing:?}");
    assert!(!listed.contains("catalog-planted-unlisted"));
    assert!(codes_in_source("Err(\"catalog-planted-unlisted\")")
        .iter()
        .any(|code| !listed.contains(code.as_str())));
}

fn bare_codes(source: &str) -> Vec<(usize, String)> {
    let source = production(source);
    let data = source.as_bytes();
    let listed: HashSet<_> = TABLE
        .iter()
        .map(|e| e.code)
        .filter(|s| !s.is_empty())
        .collect();
    let mut found = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let end = lex_end(data, at);
        if data[at] == b'"' && end > at + 1 {
            let value = &source[at + 1..end - 1];
            if listed.contains(value) {
                found.push((
                    source[..at].bytes().filter(|b| *b == b'\n').count() + 1,
                    value.into(),
                ));
            }
        }
        at = end.max(at + 1);
    }
    found
}
#[test]
fn catalog_bare_literal_scan_rejects_known_codes_in_any_context() {
    for source in [
        "reason(\"bad-spec\")",
        "match code { \"bad-spec\" => 1, _ => 0 }",
        "let reason = \"bad-spec\";",
        "json!({\"code\":\"bad-spec\"})",
    ] {
        assert_eq!(bare_codes(source), vec![(1, BAD_SPEC.into())]);
    }
    assert!(bare_codes("// bad-spec\nlet reason = crate::error_catalog::BAD_SPEC;").is_empty());
}
fn enum_codes(value: &Value, doc: &Value, found: &mut HashSet<String>) {
    if let Some(reference) = value["$ref"].as_str() {
        enum_codes(doc.pointer(&reference[1..]).unwrap(), doc, found);
        return;
    }
    if let Some(properties) = value["properties"].as_object() {
        for (field, definition) in properties {
            if ["code", "error_code"].contains(&field.as_str()) {
                if let Some(values) = definition["enum"].as_array() {
                    found.extend(values.iter().map(|v| v.as_str().unwrap().to_owned()));
                } else {
                    panic!("machine-code field without enum: {definition}");
                }
            } else {
                enum_codes(definition, doc, found);
            }
        }
    }
    for combiner in ["anyOf", "oneOf", "allOf"] {
        if let Some(values) = value[combiner].as_array() {
            for v in values {
                enum_codes(v, doc, found);
            }
        }
    }
}
#[test]
fn catalog_openapi_error_enums_equal_route_catalog() {
    let doc: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
    for (path, ops) in doc["paths"].as_object().unwrap() {
        for (method, op) in ops.as_object().unwrap() {
            let mut found = HashSet::new();
            for (status, response) in op["responses"].as_object().unwrap() {
                if status.parse::<u16>().unwrap() >= 400 {
                    enum_codes(
                        &response["content"]["application/json"]["schema"],
                        &doc,
                        &mut found,
                    );
                }
            }
            assert_eq!(
                found,
                route_codes(path).iter().map(|s| s.to_string()).collect(),
                "{method} {path}"
            );
        }
    }
}
#[test]
fn catalog_route_codes_are_registered_and_subdirectories_have_no_bare_codes() {
    assert_eq!(
        canonical_code("unknown worker diagnostic"),
        ARTIFACT_MISMATCH
    );
    for entry in TABLE.iter().filter(|entry| !entry.code.is_empty()) {
        assert_eq!(canonical_code(entry.code), entry.code);
    }
    let listed: HashSet<_> = TABLE.iter().map(|e| e.code).collect();
    for (path, _) in http_routes::ROUTES {
        assert!(route_codes(path).iter().all(|code| listed.contains(code)));
    }
    fn visit(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path);
            } else if path.extension().is_some_and(|s| s == "rs")
                && path.file_name().unwrap() != "error_catalog.rs"
            {
                assert!(
                    bare_codes(&fs::read_to_string(&path).unwrap()).is_empty(),
                    "{}",
                    path.display()
                );
            }
        }
    }
    visit(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
}
#[test]
fn catalog_every_code_exercised_by_real_paths() {
    let root = std::env::temp_dir().join(format!("fold-catalog-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let output = crate::test_process::command()
        .args([
            "--quiet",
            "--test-threads=1",
            "--skip",
            "catalog_every_code_exercised_by_real_paths",
        ])
        .env("FOLD_CATALOG_CAPTURE", &root)
        .output()
        .unwrap();
    fs::write(
        crate::test_process::target_dir().join("run21-catalog-child.log"),
        &output.stdout,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "catalog exercise suite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut exercised = HashSet::new();
    let mut evidence = BTreeMap::<String, HashSet<String>>::new();
    for file in fs::read_dir(&root).unwrap() {
        for row in fs::read_to_string(file.unwrap().path()).unwrap().lines() {
            let (code, test) = row.split_once('\t').unwrap();
            exercised.insert(code.to_owned());
            evidence
                .entry(code.to_owned())
                .or_default()
                .insert(test.to_owned());
        }
    }
    fs::write(
        crate::test_process::target_dir().join("run21-error-coverage.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    fs::remove_dir_all(root).unwrap();
    let missing: Vec<_> = TABLE
        .iter()
        .map(|e| e.code)
        .filter(|c| !exercised.contains(if c.is_empty() { "_message" } else { c }))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    assert!(missing.is_empty(), "unexercised catalog codes: {missing:?}");
}

#[test]
fn catalog_rare_failures_use_real_gate_adapter_and_pull_paths() {
    let root = std::env::temp_dir().join(format!("fold-catalog-probes-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let pins: Value =
        serde_json::from_str(include_str!("fixtures/b6-04w2/pins.example.json")).unwrap();
    fs::create_dir(root.join(".state.new")).unwrap();
    assert_eq!(
        lane_gate::call("disable", "tts", &pins, &root, 1790000000),
        Err("state-unwritable")
    );
    assert_eq!(
        lane_gate::call("check", "-", &pins, &root, u64::MAX),
        Err("clock-unavailable")
    );
    let row = dispatch_kinds::kind("adapter-tts").unwrap();
    assert_eq!(
        dispatch_kinds::command(
            row,
            "fixture",
            "fixture",
            &json!({}),
            &root,
            &root,
            1.0,
            false
        )
        .unwrap_err(),
        "adapter-entry-unset"
    );
    assert_eq!(
        dispatch_kinds::command(
            row,
            "fixture",
            "fixture",
            &json!({}),
            &root,
            &root,
            1.0,
            true
        )
        .unwrap_err(),
        "adapter-dry-run-unsupported"
    );
    let mut lifecycle = segment_lifecycle::Lifecycle::new(5);
    assert!(lifecycle.assign("lease-123".into(), 9.0, 5.0));
    assert!(lifecycle.report("lease-123", 0, 1, false, &[]));
    assert_eq!(lifecycle.reason.as_deref(), Some("segment-failed"));
    let b = segment_lifecycle::Boundary {
        root: &root,
        job_id: "fixture",
        ts: "2026-09-21T14:13:20Z",
        balance: 9.0,
        floor: 5.0,
        gpu_class: "any",
    };
    assert_eq!(
        JobTable::default()
            .agent_pull_transaction(
                &json!({}),
                &json!({}),
                1790000000,
                &b,
                "lease-123",
                "2026-09-21T14:14:20Z"
            )
            .unwrap(),
        Err("invalid-request")
    );
    fs::remove_dir_all(root).unwrap();
}
