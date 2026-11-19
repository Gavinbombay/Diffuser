//! Recommendations remain pending. These tests pin the current fold.
use crate::*;
fn enforce(spec: Value, manifest: Value) -> Result<(), &'static str> {
    runtime_limits::enforce(
        &spec,
        &manifest,
        |name| {
            Ok(if name.ends_with(".wav") {
                conformance_b6::descriptor(
                    &json!({"kind":"wav","channels":1,"rate":44100,"width":2,"frames":1}),
                )
            } else {
                vec![1]
            })
        },
        &runtime_limits::Config::default(),
    )
}
#[test]
fn d1_flac_stems_currently_fail_closed() {
    assert_eq!(
        enforce(
            json!({"lane":"music-sfx","duration_seconds":30}),
            json!({"artifacts":[{"path":"audio.wav"}]})
        ),
        Ok(())
    );
    assert_eq!(
        enforce(
            json!({"lane":"music-sfx","duration_seconds":30}),
            json!({"artifacts":[{"path":"audio.wav"},{"path":"stems/one.flac"}]})
        ),
        Err("output-unreadable")
    );
    // Name grammar still allows FLAC; this is a measurement refusal, not removal.
    assert!(result_store::allowed_artifact(
        "music-sfx",
        "stems/one.flac"
    ));
}
#[test]
fn d2_eight_artifact_default_and_nine_fail_closed() {
    assert_eq!(runtime_limits::Config::default().max_artifacts, 8);
    let rows: Vec<_> = (1..=9)
        .map(|n| json!({"path":format!("frame_{n:04}.png")}))
        .collect();
    assert_eq!(
        enforce(
            json!({"lane":"diffusion-video","frames":48}),
            json!({"artifacts":rows})
        ),
        Err("artifact-count-exceeded")
    );
}
#[test]
fn d3_declared_manifest_frames_are_measured() {
    let spec = json!({"lane":"diffusion-video","frames":48});
    assert_eq!(
        enforce(
            spec.clone(),
            json!({"artifacts":[{"path":"out.mp4"}],"frames":48})
        ),
        Ok(())
    );
    assert_eq!(
        enforce(spec.clone(), json!({"artifacts":[{"path":"out.mp4"}]})),
        Err("frame-count-unknowable")
    );
    assert_eq!(
        enforce(
            spec,
            json!({"artifacts":[{"path":"frame_0001.png"}],"frames":48})
        ),
        Err("frame-count-inconsistent")
    );
}
#[test]
fn d4_artifact_mismatch_keeps_specific_attempt_reason() {
    let row = json!({"job_id":"fixture","lane":"diffusion-video","state":"failed","error":{"code":"artifact-mismatch","retryable":false},"reason":"output-over-ceiling","chunks":[{"worker":"fixture"}]});
    let snap = result_store::snapshot(&row, 1790000000);
    assert_eq!(snap["error"]["code"], "artifact-mismatch");
    assert_eq!(snap["attempts"][0]["reason"], "output-over-ceiling");
}
#[test]
fn d5_failed_merge_nonretryable_unresolved_and_done_clean() {
    let mut row = json!({"job_id":"fixture","lane":"tts","state":"failed","error":{"code":"artifact-mismatch","retryable":true},"artifacts":[{"path":"speech.wav"}]});
    let snap = result_store::snapshot(&row, 1790000000);
    assert_eq!(snap["error"]["retryable"], false);
    assert_eq!(snap["cleanup"], "unresolved");
    assert_eq!(snap["artifacts"], json!([]));
    assert!(snap["manifest"].is_null());
    row["state"] = json!("done");
    row["error"] = Value::Null;
    assert_eq!(result_store::snapshot(&row, 1790000000)["cleanup"], "clean");
}
#[test]
fn d6_under_delivery_keeps_one_sided_ceiling() {
    assert_eq!(
        enforce(
            json!({"lane":"diffusion-video","frames":480}),
            json!({"artifacts":[{"path":"frame_0001.png"},{"path":"frame_0002.png"}],"frames":2})
        ),
        Ok(())
    );
    assert_eq!(
        enforce(
            json!({"lane":"diffusion-video","frames":480}),
            json!({"artifacts":[],"frames":0})
        ),
        Err("output-missing")
    );
}
