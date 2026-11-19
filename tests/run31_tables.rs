//! Adjacent limit values through the production admission and decoder functions.
use crate::*;

fn declared(status: u16) {
    let doc: Value = serde_json::from_str(include_str!("../docs/openapi.json")).unwrap();
    assert!(
        doc["paths"]["/v1/lanes/{lane}/jobs"]["post"]["responses"]
            .get(status.to_string())
            .is_some(),
        "undeclared status {status}"
    );
}
fn render() -> Value {
    json!({"lane":"render-blender","blend":"/scene.blend","out":"/render-output","frames":"1-6"})
}
#[test]
fn run31_render_limit_table() {
    let mut rows = Vec::new();
    for (field, edges, bake) in [
        (
            "timeout_min",
            vec![
                (0, false),
                (1, true),
                (2, true),
                (359, true),
                (360, true),
                (361, false),
            ],
            false,
        ),
        (
            "script_timeout_min",
            vec![
                (-1, false),
                (0, true),
                (1, true),
                (719, true),
                (720, true),
                (721, false),
            ],
            false,
        ),
        (
            "bake_timeout_min",
            vec![
                (-1, false),
                (0, true),
                (1, true),
                (719, true),
                (720, true),
                (721, false),
            ],
            false,
        ),
        (
            "script_timeout_min",
            vec![
                (-1, false),
                (0, false),
                (1, true),
                (719, true),
                (720, true),
                (721, false),
            ],
            true,
        ),
        (
            "bake_timeout_min",
            vec![
                (-1, false),
                (0, false),
                (1, true),
                (719, true),
                (720, true),
                (721, false),
            ],
            true,
        ),
    ] {
        for (number, accepted) in edges {
            let mut spec = render();
            if bake {
                spec["type"] = json!("bake-render");
            }
            spec[field] = json!(number);
            rows.push((format!("{field}={number} bake={bake}"), spec, accepted));
        }
    }
    for (field, sizes) in [
        (
            "script",
            vec![
                (0, false),
                (1, true),
                (2, true),
                (4095, true),
                (4096, true),
                (4097, false),
            ],
        ),
        (
            "job_id",
            vec![
                (0, false),
                (1, true),
                (2, true),
                (63, true),
                (64, true),
                (65, false),
            ],
        ),
        ("prefer", vec![(4, true), (5, true), (6, false)]),
        (
            "steps",
            vec![(0, false), (1, true), (2, true), (3, true), (4, false)],
        ),
        (
            "frames",
            vec![
                (0, false),
                (1, true),
                (2, true),
                (999, true),
                (1000, true),
                (1001, false),
            ],
        ),
    ] {
        for (size, accepted) in sizes {
            let mut spec = render();
            spec[field] = match field {
                "prefer" => json!((0..size).map(|n| format!("worker-{n}")).collect::<Vec<_>>()),
                "steps" => json!(["script", "bake", "render", "extra"][..size].to_vec()),
                "frames" => {
                    spec["type"] = json!("bake-render");
                    json!(vec![1; size])
                }
                _ => json!("x".repeat(size)),
            };
            rows.push((format!("{field} size={size}"), spec, accepted));
        }
    }
    // The frame list cap applies to both supported list representations.
    for (size, accepted) in [(999, true), (1000, true), (1001, false)] {
        let mut spec = render();
        spec["type"] = json!("bake-render");
        spec["frames"] = json!(vec!["1"; size].join(","));
        rows.push((format!("frame string size={size}"), spec, accepted));
    }
    // Limits count Unicode characters rather than UTF-8 bytes.
    for (size, accepted) in [(4095, true), (4096, true), (4097, false)] {
        let mut spec = render();
        spec["script"] = json!("界".repeat(size));
        rows.push((format!("unicode script size={size}"), spec, accepted));
    }
    assert_eq!(rows.len(), 62);
    let mut evidence = Vec::new();
    for (label, spec, accepted) in rows {
        let result = render_admission::body(&spec);
        let expected = if accepted {
            Ok(())
        } else {
            Err(error_catalog::BAD_SPEC)
        };
        assert_eq!(result, expected, "{label}");
        let status = result
            .as_ref()
            .err()
            .map(|code| request_boundary::status(code, "render-blender").as_u16())
            .unwrap_or(202);
        assert_eq!(status, if accepted { 202 } else { 400 });
        declared(status);
        if let Err(code) = result {
            assert!(error_catalog::TABLE.iter().any(|entry| entry.code == code));
        }
        evidence.push(json!({"row":label,"status":status,"code":result.err()}));
    }
    fs::write(
        crate::test_process::target_dir().join("run31-q3-render.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
}

#[test]
fn run31_request_boundary_limit_table() {
    let mut evidence = Vec::new();
    for lane in ["render-blender", "tts"] {
        for (size, expected) in [
            (65535, Ok(())),
            (65536, Ok(())),
            (65537, Err(error_catalog::REQUEST_TOO_LARGE)),
        ] {
            let mut raw = serde_json::to_vec(&json!({"lane":lane})).unwrap();
            raw.resize(size, b' ');
            let result = request_boundary::load(&raw, Some(lane)).map(|_| ());
            assert_eq!(result, expected, "{lane} bytes={size}");
            let status = result
                .as_ref()
                .err()
                .map(|code| request_boundary::status(code, lane).as_u16())
                .unwrap_or(202);
            assert_eq!(status, if size > 65536 { 413 } else { 202 });
            declared(status);
            evidence.push(json!({"lane":lane,"bytes":size,"status":status,"code":result.err()}));
        }
        for (size, accepted) in [
            (0, false),
            (1, true),
            (2, true),
            (63, true),
            (64, true),
            (65, false),
        ] {
            let raw = serde_json::to_vec(&json!({"lane":lane,"job_id":"x".repeat(size)})).unwrap();
            let result = request_boundary::load(&raw, Some(lane)).map(|_| ());
            assert_eq!(
                result,
                if accepted {
                    Ok(())
                } else {
                    Err(error_catalog::BAD_SPEC)
                }
            );
            let status = result
                .as_ref()
                .err()
                .map(|code| request_boundary::status(code, lane).as_u16())
                .unwrap_or(202);
            assert_eq!(status, if accepted { 202 } else { 400 });
            declared(status);
            evidence.push(json!({"lane":lane,"id_bytes":size,"status":status,"code":result.err()}));
        }
        let result = request_boundary::load(b"{", Some(lane)).unwrap_err();
        assert_eq!(result, error_catalog::BAD_JSON);
        let status = request_boundary::status(result, lane).as_u16();
        assert_eq!(status, if lane == "tts" { 422 } else { 400 });
        declared(status);
        evidence.push(json!({"lane":lane,"case":"malformed JSON","status":status,"code":result}));
    }
    assert_eq!(evidence.len(), 20);
    for row in &evidence {
        if let Some(code) = row["code"].as_str() {
            assert!(error_catalog::TABLE.iter().any(|entry| entry.code == code));
        }
    }
    fs::write(
        crate::test_process::target_dir().join("run31-q3-boundary.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
}
