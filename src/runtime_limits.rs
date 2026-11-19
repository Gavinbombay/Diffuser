//! Admission ceilings and fail-closed merge measurements.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

pub const TTS_SECONDS: u64 = 300; // unit: seconds
pub const SAMPLE_RATE: u64 = 24000; // unit: hertz
pub const VIDEO_FRAMES: u64 = 48; // unit: frames
pub const MAX_ARTIFACTS: usize = 8; // unit: artifacts
pub const MUSIC_SECONDS_MIN: u64 = 1; // unit: seconds
pub const MUSIC_SECONDS_MAX: u64 = 300; // unit: seconds
pub const VIDEO_FRAMES_MIN: u64 = 2; // unit: frames
pub const VIDEO_FRAMES_MAX: u64 = 480; // unit: frames
pub const SAMPLE_RATES: &[u64] = &[16000, 22050, 24000, 44100, 48000]; // unit: hertz

#[cfg(test)]
#[path = "runtime_limit_docs.rs"]
mod doc_tests;

#[derive(Debug)]
pub struct Config {
    pub tts_seconds: u64,
    pub sample_rate: u64,
    pub video_frames: u64,
    pub max_artifacts: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            tts_seconds: TTS_SECONDS,
            sample_rate: SAMPLE_RATE,
            video_frames: VIDEO_FRAMES,
            max_artifacts: MAX_ARTIFACTS,
        }
    }
}
impl Config {
    pub fn from_value(v: &Value) -> Self {
        let d = Self::default();
        Self {
            tts_seconds: v["runtime_limits"]["tts_seconds"]
                .as_u64()
                .filter(|n| *n > 0)
                .unwrap_or(d.tts_seconds),
            ..d
        }
    }
}
pub fn admit(spec: &mut Value, cfg: &Config) -> Result<(), &'static str> {
    match spec["lane"].as_str() {
        Some("tts") => {
            if spec.get("sample_rate").is_none() {
                spec["sample_rate"] = json!(cfg.sample_rate);
            }
            if !spec["sample_rate"]
                .as_u64()
                .is_some_and(|n| SAMPLE_RATES.contains(&n))
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::SAMPLE_RATE_MISMATCH,
                ));
            }
            spec["max_output_seconds"] = json!(cfg.tts_seconds);
        }
        Some("music-sfx") => {
            if !spec["duration_seconds"]
                .as_u64()
                .is_some_and(|n| (MUSIC_SECONDS_MIN..=MUSIC_SECONDS_MAX).contains(&n))
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::CEILING_UNKNOWN,
                ));
            }
        }
        Some("diffusion-video") => {
            if spec.get("frames").is_none() {
                spec["frames"] = json!(cfg.video_frames);
            }
            if !spec["frames"]
                .as_u64()
                .is_some_and(|n| (VIDEO_FRAMES_MIN..=VIDEO_FRAMES_MAX).contains(&n))
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::CEILING_UNKNOWN,
                ));
            }
        }
        Some("render-blender" | "stt" | "diffusion-image") => {}
        _ => {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::CEILING_UNKNOWN,
            ))
        }
    }
    Ok(())
}
fn u32le(data: &[u8], at: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::OUTPUT_UNREADABLE))?
            .try_into()
            .unwrap(),
    ))
}
fn u16le(data: &[u8], at: usize) -> Result<u16, &'static str> {
    Ok(u16::from_le_bytes(
        data.get(at..at + 2)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::OUTPUT_UNREADABLE))?
            .try_into()
            .unwrap(),
    ))
}
fn wav(data: &[u8], expected: Option<u64>, limit: u64) -> Result<(), &'static str> {
    if data.get(..4) != Some(b"RIFF") || data.get(8..12) != Some(b"WAVE") {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::OUTPUT_UNREADABLE,
        ));
    }
    let mut pos = 12usize;
    let mut format = None;
    while pos.checked_add(8).is_some_and(|end| end <= data.len()) {
        let size = u32le(data, pos + 4)? as usize;
        let start = pos + 8;
        if &data[pos..pos + 4] == b"fmt " {
            if size < 16
                || start.checked_add(size).is_none_or(|end| end > data.len())
                || u16le(data, start)? != 1
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::OUTPUT_UNREADABLE,
                ));
            }
            let channels = u16le(data, start + 2)? as u64;
            let rate = u32le(data, start + 4)? as u64;
            let bits = u16le(data, start + 14)? as u64;
            if channels == 0 || rate == 0 || bits == 0 || !bits.is_multiple_of(8) {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::OUTPUT_UNREADABLE,
                ));
            }
            let block = channels * (bits / 8);
            if u16le(data, start + 12)? as u64 != block
                || u32le(data, start + 8)? as u64 != rate * block
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::OUTPUT_UNREADABLE,
                ));
            }
            format = Some((rate, block));
        } else if &data[pos..pos + 4] == b"data" {
            let (rate, block) = format.ok_or_else(|| {
                crate::error_catalog::reason(crate::error_catalog::OUTPUT_UNREADABLE)
            })?;
            if start.checked_add(size).is_none_or(|end| end > data.len())
                || !(size as u64).is_multiple_of(block)
            {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::OUTPUT_TRUNCATED,
                ));
            }
            let frames = size as u64 / block;
            if frames == 0 {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::OUTPUT_EMPTY,
                ));
            }
            if expected.is_some_and(|want| want != rate) {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::SAMPLE_RATE_MISMATCH,
                ));
            }
            if frames as u128 > limit as u128 * rate as u128 {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::OUTPUT_OVER_CEILING,
                ));
            }
            return Ok(());
        }
        pos = start
            .checked_add(size)
            .and_then(|n| n.checked_add(size % 2))
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::OUTPUT_UNREADABLE))?;
    }
    Err(crate::error_catalog::reason(
        crate::error_catalog::OUTPUT_UNREADABLE,
    ))
}
pub fn enforce(
    spec: &Value,
    manifest: &Value,
    mut read: impl FnMut(&str) -> Result<Vec<u8>, String>,
    cfg: &Config,
) -> Result<(), &'static str> {
    let lane = spec["lane"]
        .as_str()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::CEILING_UNKNOWN))?;
    if !crate::LANES.contains(&lane) {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::CEILING_UNKNOWN,
        ));
    }
    if lane == "tts" && cfg.tts_seconds == 0 {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::CEILING_UNKNOWN,
        ));
    }
    let arts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::OUTPUT_MISSING))?;
    if arts.is_empty() {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::OUTPUT_MISSING,
        ));
    }
    if arts.len() > cfg.max_artifacts {
        return Err(crate::error_catalog::reason(
            crate::error_catalog::ARTIFACT_COUNT_EXCEEDED,
        ));
    }
    let mut seen = HashSet::new();
    for art in arts {
        let path = art["path"]
            .as_str()
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::OUTPUT_UNREADABLE))?;
        if !seen.insert(path) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::DUPLICATE_ARTIFACT,
            ));
        }
    }
    let ceiling = match lane {
        "tts" => Some(
            spec["max_output_seconds"]
                .as_u64()
                .unwrap_or(cfg.tts_seconds),
        ),
        "music-sfx" => Some(
            spec["duration_seconds"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    crate::error_catalog::reason(crate::error_catalog::CEILING_UNKNOWN)
                })?,
        ),
        _ => None,
    };
    if let Some(limit) = ceiling {
        let required = if lane == "tts" {
            "speech.wav"
        } else {
            "audio.wav"
        };
        if !seen.contains(required) {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::OUTPUT_MISSING,
            ));
        }
        let mut paths: Vec<_> = seen.iter().copied().collect();
        paths.sort();
        for path in paths {
            if path.ends_with(".flac") {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::OUTPUT_UNREADABLE,
                ));
            }
            if path.ends_with(".wav") {
                wav(
                    &read(path).map_err(|_| {
                        crate::error_catalog::reason(crate::error_catalog::OUTPUT_UNREADABLE)
                    })?,
                    if lane == "tts" {
                        spec["sample_rate"].as_u64()
                    } else {
                        None
                    },
                    limit,
                )?;
            }
        }
    }
    if lane == "diffusion-video" {
        let limit = spec["frames"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or_else(|| crate::error_catalog::reason(crate::error_catalog::CEILING_UNKNOWN))?;
        let numbered: HashSet<u64> = seen
            .iter()
            .filter_map(|p| p.strip_prefix("frame_")?.strip_suffix(".png")?.parse().ok())
            .collect();
        let declared = manifest
            .get("frames")
            .map(|v| {
                v.as_u64().ok_or_else(|| {
                    crate::error_catalog::reason(crate::error_catalog::FRAME_COUNT_UNKNOWABLE)
                })
            })
            .transpose()?;
        let count = match (declared, numbered.len()) {
            (None, 0) => {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::FRAME_COUNT_UNKNOWABLE,
                ))
            }
            (Some(n), 0) => n,
            (None, n) => n as u64,
            (Some(a), b) if a == b as u64 => a,
            _ => {
                return Err(crate::error_catalog::reason(
                    crate::error_catalog::FRAME_COUNT_INCONSISTENT,
                ))
            }
        };
        if count > limit {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::OUTPUT_OVER_CEILING,
            ));
        }
    }
    for art in arts {
        let path = art["path"].as_str().unwrap();
        let data = read(path)
            .map_err(|_| crate::error_catalog::reason(crate::error_catalog::OUTPUT_UNREADABLE))?;
        if art
            .get("sha256")
            .is_some_and(|v| v.as_str() != Some(hex::encode(Sha256::digest(&data)).as_str()))
            || art
                .get("bytes")
                .is_some_and(|v| v.as_u64() != Some(data.len() as u64))
        {
            return Err(crate::error_catalog::reason(
                crate::error_catalog::HASH_MISMATCH,
            ));
        }
    }
    Ok(())
}
pub fn merged(
    spec: &Value,
    root: &Path,
    arts: &[Value],
    parts: &[Value],
) -> Result<(), &'static str> {
    let mut manifest = json!({"artifacts":arts});
    if parts.len() == 1 {
        if let Some(part) = parts[0]["part_dir"].as_str() {
            if let Ok(data) = std::fs::read(root.join(part).join("manifest.json")) {
                if let Ok(v) = serde_json::from_slice::<Value>(&data) {
                    if let Some(frames) = v.get("frames") {
                        manifest["frames"] = frames.clone();
                    }
                }
            }
        }
    }
    enforce(
        spec,
        &manifest,
        |path| std::fs::read(root.join(path)).map_err(|e| e.to_string()),
        &Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn audio(frames: u32, rate: u32) -> Vec<u8> {
        let bytes = frames * 2;
        let mut v = Vec::new();
        v.extend(b"RIFF");
        v.extend((36 + bytes).to_le_bytes());
        v.extend(b"WAVEfmt ");
        v.extend(16u32.to_le_bytes());
        v.extend(1u16.to_le_bytes());
        v.extend(1u16.to_le_bytes());
        v.extend(rate.to_le_bytes());
        v.extend((rate * 2).to_le_bytes());
        v.extend(2u16.to_le_bytes());
        v.extend(16u16.to_le_bytes());
        v.extend(b"data");
        v.extend(bytes.to_le_bytes());
        v.resize(44 + bytes as usize, 0);
        v
    }
    fn check(
        spec: Value,
        files: Vec<(&str, Vec<u8>)>,
        frames: Option<Value>,
    ) -> Result<(), &'static str> {
        let arts: Vec<_> = files
            .iter()
            .map(|(p, d)| json!({"path":p,"bytes":d.len(),"sha256":hex::encode(Sha256::digest(d))}))
            .collect();
        let mut m = json!({"artifacts":arts});
        if let Some(n) = frames {
            m["frames"] = n;
        }
        enforce(
            &spec,
            &m,
            |p| {
                files
                    .iter()
                    .find(|(name, _)| *name == p)
                    .map(|(_, d)| d.clone())
                    .ok_or("absent".into())
            },
            &Config::default(),
        )
    }
    fn tts() -> Value {
        json!({"lane":"tts","sample_rate":16000})
    }
    fn music() -> Value {
        json!({"lane":"music-sfx","duration_seconds":30})
    }
    #[test]
    fn defaults() {
        let c = Config::from_value(&json!({}));
        assert_eq!(
            (
                c.tts_seconds,
                c.sample_rate,
                c.video_frames,
                c.max_artifacts
            ),
            (300, 24000, 48, 8)
        );
    }
    #[test]
    fn tts_at_ceiling() {
        assert_eq!(
            check(tts(), vec![("speech.wav", audio(300 * 16000, 16000))], None),
            Ok(())
        );
    }
    #[test]
    fn tts_one_sample_over() {
        assert_eq!(
            check(
                tts(),
                vec![("speech.wav", audio(300 * 16000 + 1, 16000))],
                None
            ),
            Err(crate::error_catalog::OUTPUT_OVER_CEILING)
        );
    }
    #[test]
    fn tts_under_ceiling() {
        assert_eq!(
            check(tts(), vec![("speech.wav", audio(32000, 16000))], None),
            Ok(())
        );
    }
    #[test]
    fn tts_zero_length() {
        assert_eq!(
            check(tts(), vec![("speech.wav", audio(0, 16000))], None),
            Err(crate::error_catalog::OUTPUT_EMPTY)
        );
    }
    #[test]
    fn tts_bad_header() {
        assert_eq!(
            check(tts(), vec![("speech.wav", b"bad".to_vec())], None),
            Err(crate::error_catalog::OUTPUT_UNREADABLE)
        );
    }
    #[test]
    fn tts_bad_header_fmt() {
        let mut d = audio(10, 16000);
        d[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            check(tts(), vec![("speech.wav", d)], None),
            Err(crate::error_catalog::OUTPUT_UNREADABLE)
        );
    }
    #[test]
    fn tts_truncated() {
        let mut d = audio(10, 16000);
        d.pop();
        assert_eq!(
            check(tts(), vec![("speech.wav", d)], None),
            Err(crate::error_catalog::OUTPUT_TRUNCATED)
        );
    }
    #[test]
    fn tts_truncated_oversold() {
        let mut d = audio(10, 16000);
        d[40..44].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(
            check(tts(), vec![("speech.wav", d)], None),
            Err(crate::error_catalog::OUTPUT_TRUNCATED)
        );
    }
    #[test]
    fn tts_rate_mismatch() {
        assert_eq!(
            check(tts(), vec![("speech.wav", audio(10, 24000))], None),
            Err(crate::error_catalog::SAMPLE_RATE_MISMATCH)
        );
    }
    fn mismatch(sha_only: bool) {
        let d = audio(10, 16000);
        let other = audio(11, 16000);
        let m = json!({"artifacts":[{"path":"speech.wav","bytes":if sha_only {d.len()}else{other.len()},"sha256":hex::encode(Sha256::digest(&other))}]});
        assert_eq!(
            enforce(&tts(), &m, |_| Ok(d.clone()), &Config::default()),
            Err(crate::error_catalog::HASH_MISMATCH)
        );
    }
    #[test]
    fn tts_hash_mismatch() {
        mismatch(false);
    }
    #[test]
    fn tts_hash_mismatch_sha() {
        mismatch(true);
    }
    #[test]
    fn tts_missing_artifact() {
        assert_eq!(
            check(tts(), vec![("other.wav", audio(10, 16000))], None),
            Err(crate::error_catalog::OUTPUT_MISSING)
        );
    }
    #[test]
    fn music_at_ceiling() {
        assert_eq!(
            check(
                music(),
                vec![
                    ("audio.wav", audio(30 * 44100, 44100)),
                    ("stems/drums.wav", audio(30 * 44100, 44100)),
                    ("stems/bass.wav", audio(2 * 44100, 44100))
                ],
                None
            ),
            Ok(())
        );
    }
    #[test]
    fn music_one_sample_over() {
        assert_eq!(
            check(
                music(),
                vec![("audio.wav", audio(30 * 44100 + 1, 44100))],
                None
            ),
            Err(crate::error_catalog::OUTPUT_OVER_CEILING)
        );
    }
    #[test]
    fn music_stem_over() {
        assert_eq!(
            check(
                music(),
                vec![
                    ("audio.wav", audio(30 * 44100, 44100)),
                    ("stems/drums.wav", audio(31 * 44100, 44100))
                ],
                None
            ),
            Err(crate::error_catalog::OUTPUT_OVER_CEILING)
        );
    }
    #[test]
    fn music_zero_length() {
        assert_eq!(
            check(music(), vec![("audio.wav", audio(0, 44100))], None),
            Err(crate::error_catalog::OUTPUT_EMPTY)
        );
    }
    #[test]
    fn music_no_ceiling() {
        assert_eq!(
            check(
                json!({"lane":"music-sfx"}),
                vec![("audio.wav", audio(1, 44100))],
                None
            ),
            Err(crate::error_catalog::CEILING_UNKNOWN)
        );
    }
    fn video(declared: Option<Value>, paths: &[&str]) -> Result<(), &'static str> {
        check(
            json!({"lane":"diffusion-video","frames":48}),
            paths.iter().map(|p| (*p, b"media".to_vec())).collect(),
            declared,
        )
    }
    #[test]
    fn video_at_admitted_frames() {
        assert_eq!(video(Some(json!(48)), &["video.mp4"]), Ok(()));
    }
    #[test]
    fn video_one_frame_over() {
        assert_eq!(
            video(Some(json!(49)), &["video.mp4"]),
            Err(crate::error_catalog::OUTPUT_OVER_CEILING)
        );
    }
    #[test]
    fn video_frames_undeclared() {
        assert_eq!(
            video(None, &["video.mp4"]),
            Err(crate::error_catalog::FRAME_COUNT_UNKNOWABLE)
        );
    }
    #[test]
    fn video_frames_disagree() {
        assert_eq!(
            video(
                Some(json!(6)),
                &[
                    "frame_0000.png",
                    "frame_0001.png",
                    "frame_0002.png",
                    "frame_0003.png",
                    "frame_0004.png",
                    "frame_0005.png",
                    "frame_0006.png"
                ]
            ),
            Err(crate::error_catalog::FRAME_COUNT_INCONSISTENT)
        );
    }
    #[test]
    fn video_frames_as_artifacts() {
        assert_eq!(
            video(
                None,
                &[
                    "frame_0000.png",
                    "frame_0001.png",
                    "frame_0002.png",
                    "frame_0003.png",
                    "frame_0004.png",
                    "frame_0005.png"
                ]
            ),
            Ok(())
        );
    }
    #[test]
    fn video_no_admitted_frames() {
        assert_eq!(
            check(
                json!({"lane":"diffusion-video"}),
                vec![("video.mp4", b"media".to_vec())],
                Some(json!(48))
            ),
            Err(crate::error_catalog::CEILING_UNKNOWN)
        );
    }
    #[test]
    fn image_passes_through() {
        assert_eq!(
            check(
                json!({"lane":"diffusion-image"}),
                vec![("image.png", b"image".to_vec())],
                None
            ),
            Ok(())
        );
    }
    #[test]
    fn image_empty_merge() {
        assert_eq!(
            check(json!({"lane":"diffusion-image"}), vec![], None),
            Err(crate::error_catalog::OUTPUT_MISSING)
        );
    }
    #[test]
    fn unknown_lane() {
        assert_eq!(
            check(json!({"lane":"unknown"}), vec![("out.bin", vec![1])], None),
            Err(crate::error_catalog::CEILING_UNKNOWN)
        );
    }
    #[test]
    fn missing_lane() {
        assert_eq!(
            check(json!({}), vec![("out.bin", vec![1])], None),
            Err(crate::error_catalog::CEILING_UNKNOWN)
        );
    }
    #[test]
    fn flac_stem_fails_closed() {
        assert_eq!(
            check(
                music(),
                vec![("audio.wav", audio(1, 44100)), ("stems/one.flac", vec![1])],
                None
            ),
            Err(crate::error_catalog::OUTPUT_UNREADABLE)
        );
    }
    #[test]
    fn duplicate_paths_refused() {
        assert_eq!(
            check(
                tts(),
                vec![
                    ("speech.wav", audio(1, 16000)),
                    ("speech.wav", audio(1, 16000))
                ],
                None
            ),
            Err(crate::error_catalog::DUPLICATE_ARTIFACT)
        );
    }
    #[test]
    fn over_eight_artifacts_refused() {
        assert_eq!(
            video(
                None,
                &[
                    "frame_0.png",
                    "frame_1.png",
                    "frame_2.png",
                    "frame_3.png",
                    "frame_4.png",
                    "frame_5.png",
                    "frame_6.png",
                    "frame_7.png",
                    "frame_8.png"
                ]
            ),
            Err(crate::error_catalog::ARTIFACT_COUNT_EXCEEDED)
        );
    }
    #[test]
    fn admission_persists_defaults() {
        let mut s = json!({"lane":"tts"});
        admit(&mut s, &Config::default()).unwrap();
        assert_eq!(s["max_output_seconds"], 300);
        assert_eq!(s["sample_rate"], 24000);
        let mut v = json!({"lane":"diffusion-video"});
        admit(&mut v, &Config::default()).unwrap();
        assert_eq!(v["frames"], 48);
    }
}
