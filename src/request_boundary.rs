//! Common bounded, strict request decoding before lane-specific admission.
use serde_json::Value;

pub fn load(raw: &[u8], lane_arg: Option<&str>) -> Result<Value, &'static str> {
    if lane_arg.is_some_and(|lane| !crate::LANES.contains(&lane)) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    if raw.len() > crate::dispatch_kinds::Config::default().body_max {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::REQUEST_TOO_LARGE,
        ));
    }
    let v = crate::lane_gate::parse(raw)
        .map_err(|_| crate::error_catalog::reason(crate::error_catalog::BAD_JSON))?;
    if !v.is_object() || v.get("api").is_some_and(|a| a != crate::API) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    if v.get("lane").is_some_and(|v| !v.is_string()) {
        return Err(crate::error_catalog::reason(crate::error_catalog::BAD_SPEC));
    }
    let lane = v["lane"]
        .as_str()
        .or(lane_arg)
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::UNKNOWN_LANE))?;
    if lane_arg.is_some_and(|a| a != lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::LANE_MISMATCH,
        ));
    }
    if !crate::LANES.contains(&lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        ));
    }
    crate::dispatch_kinds::validate_job(&v.clone().with_lane(lane))?;
    Ok(v)
}
trait WithLane {
    fn with_lane(self, lane: &str) -> Self;
}
impl WithLane for Value {
    fn with_lane(mut self, lane: &str) -> Self {
        self["lane"] = lane.into();
        self
    }
}

pub fn job_id(spec: &Value) -> String {
    spec["job_id"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| format!("rb-{}", crate::stamp()))
}

pub fn status(code: &str, lane: &str) -> axum::http::StatusCode {
    if code == crate::error_catalog::REQUEST_TOO_LARGE {
        axum::http::StatusCode::PAYLOAD_TOO_LARGE
    } else if code == crate::error_catalog::BAD_JSON && crate::opened_lane(lane) {
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    } else {
        axum::http::StatusCode::BAD_REQUEST
    }
}

#[cfg(test)]
mod run37_boundary_tests {
    use super::*;
    use crate::error_catalog as catalog;
    use serde_json::json;

    #[test]
    fn run37_w2_load_refusals_and_job_ids() {
        let rows: &[(&str, &[u8], Option<&str>, &str)] = &[
            ("missing lane", br#"{}"#, None, catalog::UNKNOWN_LANE),
            (
                "lane mismatch",
                br#"{"lane":"tts"}"#,
                Some("stt"),
                catalog::LANE_MISMATCH,
            ),
            ("non object", br#"[]"#, Some("tts"), catalog::BAD_SPEC),
            ("bad JSON", br#"{"#, Some("tts"), catalog::BAD_JSON),
        ];
        assert_eq!(rows.len(), 4);
        for (label, raw, lane, expected) in rows {
            assert_eq!(load(raw, *lane), Err(*expected), "{label}");
            assert_eq!(
                catalog::lookup(None, expected).unwrap().code,
                *expected,
                "{label}"
            );
        }
        let generated = job_id(&json!({}));
        assert!(generated.starts_with("rb-"));
        assert!(regex::Regex::new(r"^rb-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$")
            .unwrap()
            .is_match(&generated));
        assert_eq!(job_id(&json!({"job_id":""})), "");
        assert_eq!(job_id(&json!({"job_id":"job-valid"})), "job-valid");
    }

    #[test]
    fn run37_w2_status_catalog_and_docs_table() {
        let rows = [
            (catalog::REQUEST_TOO_LARGE, "render-blender", 413),
            (catalog::REQUEST_TOO_LARGE, "tts", 413),
            (catalog::BAD_JSON, "render-blender", 400),
            (catalog::BAD_JSON, "tts", 422),
            (catalog::BAD_JSON, "stt", 422),
            (catalog::BAD_JSON, "diffusion-image", 422),
            (catalog::BAD_JSON, "diffusion-video", 422),
            (catalog::BAD_JSON, "music-sfx", 422),
            (catalog::BAD_SPEC, "tts", 400),
            (catalog::UNKNOWN_LANE, "tts", 400),
            (catalog::LANE_MISMATCH, "tts", 400),
        ];
        // Keep the explicit status cases exhaustive when the implementation grows.
        let source = include_str!("request_boundary.rs");
        let function = source
            .split("pub fn status(")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let matched = regex::Regex::new(r"crate::error_catalog::([A-Z_]+)")
            .unwrap()
            .captures_iter(function)
            .map(|row| row[1].to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            matched,
            ["BAD_JSON".to_owned(), "REQUEST_TOO_LARGE".to_owned()]
                .into_iter()
                .collect()
        );
        let docs = include_str!("../docs/ERRORS.md");
        for (code, lane, expected) in rows {
            assert_eq!(status(code, lane).as_u16(), expected, "{code}/{lane}");
            assert_eq!(catalog::lookup(None, code).unwrap().code, code);
            assert!(
                docs.lines()
                    .any(|line| line
                        == format!(" | request-boundary | {code} | {lane} | {expected} |")),
                "missing documented mapping {code}/{lane}"
            );
        }
    }
}
