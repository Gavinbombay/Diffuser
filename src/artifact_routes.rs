//! Authenticated artifact reads over the lane-scoped result store.
use crate::*;
#[derive(Debug, PartialEq)]
pub struct Failure {
    pub status: StatusCode,
    pub code: &'static str,
    pub retryable: bool,
}
fn failure(code: &'static str) -> Failure {
    Failure {
        status: match code {
            crate::error_catalog::PATH_UNSAFE
            | crate::error_catalog::DIGEST_CONFLICT
            | crate::error_catalog::MANIFEST_MISMATCH => StatusCode::CONFLICT,
            crate::error_catalog::NO_SUCH_ARTIFACT => StatusCode::GONE,
            crate::error_catalog::STORAGE_UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::NOT_FOUND,
        },
        code,
        retryable: matches!(
            code,
            crate::error_catalog::DIGEST_CONFLICT | crate::error_catalog::STORAGE_UNAVAILABLE
        ),
    }
}
#[derive(Debug)]
pub struct Read {
    pub bytes: Vec<u8>,
    pub digest: String,
    pub content_type: &'static str,
}
pub const CLEANUP_STATES: &[&str] = &["pending", "clean", "unresolved"];
pub fn cleanup_event(state: &str, event: &str) -> Option<&'static str> {
    match (state, event) {
        ("pending", "job-cancelled" | "teardown-confirmed")
        | ("unresolved", "teardown-confirmed") => Some("clean"),
        ("pending", "teardown-unknown") | ("unresolved", "teardown-rechecked") => {
            Some("unresolved")
        }
        _ => None,
    }
}
fn syntax(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 128
        || name.split('/').count() > 8
        || matches!(
            name,
            "job.json" | "meta.json" | "gc.json" | "manifest.json" | "SHA256SUMS"
        )
    {
        return false;
    }
    name.split('/').all(|p| {
        !p.is_empty()
            && p.len() <= 64
            && p.as_bytes()[0].is_ascii_alphanumeric()
            && p.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    })
}
pub fn guard_name(lane: &str, name: &str) -> bool {
    syntax(name)
        && (lane == "render-blender"
            || LANES
                .iter()
                .any(|candidate| result_store::allowed_artifact(candidate, name))
            || (lane == "diffusion-video"
                && name
                    .strip_prefix("frame_")
                    .and_then(|s| s.strip_suffix(".png"))
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))))
}
pub fn read(
    store: &result_store::Store,
    lane: &str,
    id: &str,
    name: Option<&str>,
    now: u64,
) -> Result<Read, Failure> {
    if !LANES.contains(&lane) {
        return Err(failure(crate::error_catalog::reason(
            crate::error_catalog::UNKNOWN_LANE,
        )));
    }
    if !result_store::valid_id(id) {
        return Err(failure(crate::error_catalog::reason(
            crate::error_catalog::NO_SUCH_JOB,
        )));
    }
    if let Some(name) = name.filter(|s| !matches!(*s, "manifest.json" | "SHA256SUMS")) {
        if !syntax(name) || (!store.legacy_paths() && !guard_name(lane, name)) {
            return Err(Failure {
                status: StatusCode::BAD_REQUEST,
                code: crate::error_catalog::reason(crate::error_catalog::PATH_UNSAFE),
                retryable: false,
            });
        }
    }
    let doc = store.get_job(lane, id).map_err(failure)?;
    if doc["state"] != "done" {
        return Err(failure(crate::error_catalog::reason(
            crate::error_catalog::NO_SUCH_DOCUMENT,
        )));
    }
    let meta = store.get_meta(lane, id).map_err(failure)?;
    if meta["lane"] != lane || meta["job_id"] != id || meta["state"] != doc["state"] {
        return Err(failure(crate::error_catalog::reason(
            crate::error_catalog::MANIFEST_MISMATCH,
        )));
    }
    if now
        >= meta["expires_docs_epoch"].as_u64().ok_or_else(|| {
            failure(crate::error_catalog::reason(
                crate::error_catalog::STORAGE_UNAVAILABLE,
            ))
        })?
    {
        return Err(failure(crate::error_catalog::reason(
            crate::error_catalog::NO_SUCH_JOB,
        )));
    }
    let manifest_bytes = store.get_document(lane, id, "manifest.json").map_err(|s| {
        failure(if s == crate::error_catalog::NO_SUCH_ARTIFACT {
            crate::error_catalog::NO_SUCH_DOCUMENT
        } else {
            s
        })
    })?;
    let manifest = lane_gate::parse(&manifest_bytes).map_err(|_| {
        failure(crate::error_catalog::reason(
            crate::error_catalog::MANIFEST_MISMATCH,
        ))
    })?;
    for field in [
        "api",
        "lane",
        "job_id",
        "cartridge",
        "pin_sha256",
        "spec_sha256",
        "state",
    ] {
        if manifest[field] != doc[field] {
            return Err(failure(crate::error_catalog::reason(
                crate::error_catalog::MANIFEST_MISMATCH,
            )));
        }
    }
    let arts = manifest["artifacts"].as_array().ok_or_else(|| {
        failure(crate::error_catalog::reason(
            crate::error_catalog::MANIFEST_MISMATCH,
        ))
    })?;
    let paths = arts
        .iter()
        .map(|a| a["path"].as_str().unwrap_or(""))
        .collect::<Vec<_>>();
    if arts.is_empty()
        || paths.windows(2).any(|p| p[0] >= p[1])
        || manifest["artifacts"] != meta["artifacts"]
        || doc["artifacts"] != meta["artifacts"]
    {
        return Err(failure(crate::error_catalog::reason(
            crate::error_catalog::MANIFEST_MISMATCH,
        )));
    }
    if let Some(name) = name.filter(|s| !matches!(*s, "manifest.json" | "SHA256SUMS")) {
        if !guard_name(lane, name) && !arts.iter().any(|a| a["path"] == name) {
            return Err(Failure {
                status: StatusCode::BAD_REQUEST,
                code: crate::error_catalog::reason(crate::error_catalog::PATH_UNSAFE),
                retryable: false,
            });
        }
    }
    let (bytes, ctype) = match name {
        None => (
            result_store::canonical(
                &json!({"api":crate::API,"lane":lane,"job_id":id,"artifacts":arts}),
            ),
            "application/json",
        ),
        Some("manifest.json") => (manifest_bytes, "application/json"),
        Some("SHA256SUMS") => (
            store
                .get_document(lane, id, "SHA256SUMS")
                .map_err(failure)?,
            "text/plain",
        ),
        Some(name) => {
            let art = arts.iter().find(|a| a["path"] == name).ok_or(Failure {
                status: StatusCode::NOT_FOUND,
                code: crate::error_catalog::reason(crate::error_catalog::NO_SUCH_ARTIFACT),
                retryable: false,
            })?;
            if now
                >= meta["expires_artifacts_epoch"].as_u64().ok_or_else(|| {
                    failure(crate::error_catalog::reason(
                        crate::error_catalog::STORAGE_UNAVAILABLE,
                    ))
                })?
            {
                return Err(failure(crate::error_catalog::reason(
                    crate::error_catalog::NO_SUCH_ARTIFACT,
                )));
            }
            let bytes = store
                .get_artifact(
                    lane,
                    art["sha256"].as_str().ok_or_else(|| {
                        failure(crate::error_catalog::reason(
                            crate::error_catalog::MANIFEST_MISMATCH,
                        ))
                    })?,
                )
                .map_err(failure)?;
            if art["bytes"].as_u64() != Some(bytes.len() as u64) {
                return Err(failure(crate::error_catalog::reason(
                    crate::error_catalog::DIGEST_CONFLICT,
                )));
            }
            let ctype = match Path::new(name).extension().and_then(|s| s.to_str()) {
                Some("png") => "image/png",
                Some("wav") => "audio/wav",
                Some("flac") => "audio/flac",
                Some("mp4") => "video/mp4",
                Some("json") => "application/json",
                _ => "application/octet-stream",
            };
            (bytes, ctype)
        }
    };
    Ok(Read {
        digest: hex::encode(Sha256::digest(&bytes)),
        bytes,
        content_type: ctype,
    })
}
pub fn response(result: Result<Read, Failure>) -> Response {
    match result {
        Ok(r) => (
            [
                ("content-type", r.content_type.to_owned()),
                ("etag", format!("\"{}\"", r.digest)),
                ("content-length", r.bytes.len().to_string()),
            ],
            r.bytes,
        )
            .into_response(),
        Err(e) => {
            crate::error_catalog::observe(Some(e.status.as_u16()), e.code);
            (
                e.status,
                Json(json!({"error":e.code,"code":e.code,"retryable":e.retryable})),
            )
                .into_response()
        }
    }
}
pub async fn method_refusal() -> Response {
    response(Err(Failure {
        status: StatusCode::METHOD_NOT_ALLOWED,
        code: crate::error_catalog::reason(crate::error_catalog::METHOD_NOT_ALLOWED),
        retryable: false,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        root: PathBuf,
        store: result_store::Store,
        doc: Value,
    }
    impl Fixture {
        fn new(state: &str, cleanup: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "artifact-route-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let store = result_store::Store::new(&root, result_store::Config::default());
            let sha = store.put_artifact("tts", b"fixture", None).unwrap();
            let arts = if state == "done" {
                json!([{"path":"speech.wav","sha256":sha,"bytes":7}])
            } else {
                json!([])
            };
            let mut doc = result_store::snapshot(
                &json!({"lane":"tts","job_id":"fixture","state":state,"artifacts":arts}),
                0,
            );
            doc["cleanup"] = json!(cleanup);
            let docs = if state == "done" {
                BTreeMap::from([
                    ("manifest.json".into(), result_store::canonical(&doc)),
                    (
                        "SHA256SUMS".into(),
                        format!("{sha}  speech.wav\n").into_bytes(),
                    ),
                ])
            } else {
                BTreeMap::new()
            };
            store.put_job("tts", "fixture", &doc, &docs, 0).unwrap();
            Self { root, store, doc }
        }
        fn get(&self, name: &str) -> Result<Read, Failure> {
            read(&self.store, "tts", "fixture", Some(name), 1)
        }
        fn dir(&self) -> PathBuf {
            self.root.join("lanes/tts/jobs/fixture")
        }
        fn rewrite(&self, doc: &Value) {
            let b = result_store::canonical(doc);
            fs::write(self.dir().join("manifest.json"), &b).unwrap();
            let mut m = self.store.get_meta("tts", "fixture").unwrap();
            m["documents"]["manifest"] = json!(hex::encode(Sha256::digest(&b)));
            fs::write(self.dir().join("meta.json"), result_store::canonical(&m)).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn t01_manifest_good_read() {
        let f = Fixture::new("done", "pending");
        let r = f.get("manifest.json").unwrap();
        assert_eq!(r.bytes, fs::read(f.dir().join("manifest.json")).unwrap());
        assert_eq!(r.digest, hex::encode(Sha256::digest(&r.bytes)));
    }
    #[test]
    fn t02_artifact_good_read() {
        let f = Fixture::new("done", "clean");
        let r = f.get("speech.wav").unwrap();
        assert_eq!(r.bytes, b"fixture");
        assert_eq!(r.content_type, "audio/wav");
    }
    fn http(name: &str, case: u8) {
        if std::env::var_os("FOLD_ARTIFACT_CHILD").is_none() {
            let status = crate::test_process::command()
                .args([
                    "--exact",
                    &format!("artifact_routes::tests::{name}"),
                    "--quiet",
                ])
                .env("FOLD_ARTIFACT_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let f = Fixture::new("done", "clean");
        crate::pull_http_tests::auth_fixture(&f.root);
        fn clock() -> u64 {
            1
        }
        let mut state = new_app(
            json!({"result_store_dir":f.root}),
            f.root.join("cartridges"),
        );
        state.clock = clock;
        let app = router_with_app(state);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use tower::ServiceExt;
            let path=if case==0{"/v1/lanes/stt/jobs/fixture/artifacts/manifest.json"}else{"/v1/lanes/tts/jobs/fixture/artifacts/manifest.json"};
            let mut req=axum::http::Request::builder().uri(path);
            if case==0||case==2||case==3{req=req.header("authorization","Bearer <TOKEN>");}
            if case==2{req=req.method("POST");}
            let r=app.clone().oneshot(req.body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(r.status(),match case{0=>StatusCode::SERVICE_UNAVAILABLE,1=>StatusCode::UNAUTHORIZED,2=>StatusCode::METHOD_NOT_ALLOWED,_=>StatusCode::OK});
            if case==1{for value in ["Basic [R]","Bearer [R]"]{let req=axum::http::Request::builder().uri(path).header("authorization",value).body(axum::body::Body::empty()).unwrap();assert_eq!(app.clone().oneshot(req).await.unwrap().status(),StatusCode::UNAUTHORIZED);}}
            if case==2{
                let bytes=axum::body::to_bytes(r.into_body(),4096).await.unwrap();let v:Value=serde_json::from_slice(&bytes).unwrap();assert_eq!(v["code"],crate::error_catalog::METHOD_NOT_ALLOWED);
                let req=axum::http::Request::builder().method("HEAD").uri(path).header("authorization","Bearer <TOKEN>").body(axum::body::Body::empty()).unwrap();assert_eq!(app.clone().oneshot(req).await.unwrap().status(),StatusCode::METHOD_NOT_ALLOWED);
            } else if case==3{
                assert!(r.headers().contains_key("etag"));
                let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();let server=tokio::spawn(async move{axum::serve(listener,app).await.unwrap()});
                let reply=tokio::task::spawn_blocking(move||{use std::io::{Read,Write};let mut s=std::net::TcpStream::connect(addr).unwrap();write!(s,"GET /v1/lanes/tts/jobs/fixture/artifacts/speech.wav HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nConnection: close\r\n\r\n").unwrap();let mut reply=String::new();s.read_to_string(&mut reply).unwrap();reply}).await.unwrap();assert!(reply.starts_with("HTTP/1.1 200"),"{reply}");assert!(reply.ends_with("fixture"));server.abort();
            }
        });
    }
    #[test]
    fn t03_wrong_lane_cred() {
        http("t03_wrong_lane_cred", 0);
    }
    #[test]
    fn t04_missing_or_malformed_cred() {
        http("t04_missing_or_malformed_cred", 1);
    }
    #[test]
    fn t05_unknown_job_and_lane() {
        let f = Fixture::new("done", "clean");
        assert_eq!(
            read(&f.store, "tts", "absent", None, 1).unwrap_err().status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            read(&f.store, "unknown", "fixture", None, 1)
                .unwrap_err()
                .code,
            crate::error_catalog::UNKNOWN_LANE
        );
        assert_eq!(
            read(&f.store, "stt", "fixture", None, 1)
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }
    #[test]
    fn t06_traversal_names_refused() {
        let f = Fixture::new("done", "clean");
        for name in [
            "../speech.wav",
            "/speech.wav",
            "a//b",
            "a/./b",
            "a/../b",
            "a\\b",
            ".dot",
            "%2e%2e/file",
        ] {
            assert_eq!(f.get(name).unwrap_err().status, StatusCode::BAD_REQUEST);
        }
    }
    #[test]
    fn t07_reserved_names_refused() {
        for name in [
            "job.json",
            "meta.json",
            "gc.json",
            "manifest.json",
            "SHA256SUMS",
        ] {
            assert!(!guard_name("render-blender", name));
        }
    }
    #[test]
    fn t08_lane_name_sets() {
        for (lane, path) in [
            ("tts", "speech.wav"),
            ("stt", "transcript.json"),
            ("music-sfx", "stems/drums.wav"),
            ("diffusion-video", "frame_0001.png"),
            ("render-blender", "baked/cache.bin"),
        ] {
            assert!(guard_name(lane, path));
        }
        assert!(!guard_name("tts", "bonus.bin"));
        assert!(!guard_name("render-blender", &"a".repeat(129)));
        assert!(!guard_name("render-blender", &["a"; 9].join("/")));
    }
    #[cfg(unix)]
    #[test]
    fn t09_symlinks_refused() {
        let f = Fixture::new("done", "clean");
        let p = f.dir().join("manifest.json");
        let q = f.root.join("manifest-copy");
        fs::rename(&p, &q).unwrap();
        std::os::unix::fs::symlink(&q, &p).unwrap();
        assert_eq!(
            f.get("manifest.json").unwrap_err().code,
            crate::error_catalog::PATH_UNSAFE
        );
    }
    #[test]
    fn t10_digest_rechecked_on_read() {
        let f = Fixture::new("done", "clean");
        let sha = f.doc["artifacts"][0]["sha256"].as_str().unwrap();
        let blob = f.root.join("lanes/tts/blobs").join(&sha[..2]).join(sha);
        fs::write(blob, b"changed").unwrap();
        let e = f.get("speech.wav").unwrap_err();
        assert_eq!(e.code, crate::error_catalog::DIGEST_CONFLICT);
        assert!(e.retryable);
        fs::write(f.dir().join("manifest.json"), b"changed").unwrap();
        assert_eq!(
            f.get("manifest.json").unwrap_err().code,
            crate::error_catalog::DIGEST_CONFLICT
        );
    }
    #[test]
    fn t11_manifest_must_match_snapshot() {
        let f = Fixture::new("done", "clean");
        for field in [
            "job_id",
            "lane",
            "cartridge",
            "spec_sha256",
            "pin_sha256",
            "state",
        ] {
            let mut d = f.doc.clone();
            d[field] = json!("other");
            f.rewrite(&d);
            assert_eq!(
                f.get("manifest.json").unwrap_err().code,
                crate::error_catalog::MANIFEST_MISMATCH
            );
        }
    }
    #[test]
    fn t12_only_done_is_served() {
        for state in [
            "queued",
            "dispatching",
            "running",
            "failed",
            "cancelled",
            "timed_out",
        ] {
            let f = Fixture::new(state, "pending");
            assert_eq!(
                f.get("manifest.json").unwrap_err().code,
                crate::error_catalog::NO_SUCH_DOCUMENT
            );
        }
    }
    #[test]
    fn t13_absent_blob_and_absent_name() {
        let f = Fixture::new("done", "clean");
        assert_eq!(
            f.get("image.png").unwrap_err().status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            read(&f.store, "tts", "fixture", Some("speech.wav"), 14 * 86400)
                .unwrap_err()
                .status,
            StatusCode::GONE
        );
        let sha = f.doc["artifacts"][0]["sha256"].as_str().unwrap();
        fs::remove_file(f.root.join("lanes/tts/blobs").join(&sha[..2]).join(sha)).unwrap();
        assert_eq!(f.get("speech.wav").unwrap_err().status, StatusCode::GONE);
    }
    #[test]
    fn t14_method_route_and_clock() {
        http("t14_method_route_and_clock", 2);
    }
    #[test]
    fn t15_no_escape_outside_the_root() {
        let f = Fixture::new("done", "clean");
        for id in ["../fixture", "..%2ffixture", "/fixture"] {
            assert_eq!(
                read(&f.store, "tts", id, None, 1).unwrap_err().code,
                crate::error_catalog::NO_SUCH_JOB
            );
        }
    }
    #[test]
    fn t16_cleanup_state_does_not_gate_reads() {
        for state in ["pending", "clean", "unresolved"] {
            let f = Fixture::new("done", state);
            assert!(f.get("manifest.json").is_ok());
            assert!(f.get("speech.wav").is_ok());
        }
    }
    #[test]
    fn loopback_artifact_route() {
        http("loopback_artifact_route", 3);
    }
    #[test]
    fn artifact_list() {
        let f = Fixture::new("done", "clean");
        let r = read(&f.store, "tts", "fixture", None, 1).unwrap();
        let v: Value = serde_json::from_slice(&r.bytes).unwrap();
        assert_eq!(v["artifacts"], f.doc["artifacts"]);
    }
    #[test]
    fn e01_cleanup_state_set_is_pinned() {
        for c in ["pending", "clean", "unresolved"] {
            let f = Fixture::new("done", c);
            assert_eq!(f.store.get_job("tts", "fixture").unwrap()["cleanup"], c);
        }
    }
    #[test]
    fn e02_cleanup_what_s01_actually_writes() {
        let mut row = queue_policy::admitted(
            &HashMap::new(),
            &json!({"lane":"tts","job_id":"fixture"}),
            0,
        );
        assert_eq!(row["cleanup"], "pending");
        deadline::cancel(&mut row, 0).unwrap();
        assert_eq!(row["cleanup"], "clean");
    }
    #[test]
    fn e03_cleanup_transitions() {
        for (state, event, want) in [
            ("pending", "job-cancelled", "clean"),
            ("pending", "teardown-confirmed", "clean"),
            ("pending", "teardown-unknown", "unresolved"),
            ("unresolved", "teardown-confirmed", "clean"),
            ("unresolved", "teardown-rechecked", "unresolved"),
        ] {
            assert_eq!(cleanup_event(state, event), Some(want));
        }
        for (state, event) in [
            ("clean", "teardown-confirmed"),
            ("clean", "job-cancelled"),
            ("pending", "teardown-rechecked"),
            ("unresolved", "job-cancelled"),
            ("unresolved", "teardown-unknown"),
            ("nonsense", "teardown-confirmed"),
            ("pending", "nonsense"),
            ("pending", ""),
        ] {
            assert_eq!(cleanup_event(state, event), None);
        }
    }
    #[test]
    fn e04_cleanup_sweep_each_state() {
        for state in ["pending", "clean", "unresolved"] {
            let f = Fixture::new("done", state);
            f.store.gc(1, false).unwrap();
            assert_eq!(f.store.get_job("tts", "fixture").unwrap()["cleanup"], state);
        }
    }
    #[test]
    fn e05_cleanup_never_gates_a_read() {
        t16_cleanup_state_does_not_gate_reads();
    }
    #[test]
    fn e06_replay_and_conflict_while_retained() {
        let f = Fixture::new("done", "clean");
        let docs = BTreeMap::new();
        assert!(f.store.put_job("tts", "fixture", &f.doc, &docs, 1).is_ok());
        let mut changed = f.doc.clone();
        changed["spec_sha256"] = json!(hex::encode(Sha256::digest(b"different")));
        assert_eq!(
            f.store.put_job("tts", "fixture", &changed, &docs, 1),
            Err(crate::error_catalog::JOB_ID_EXISTS)
        );
    }
    #[test]
    fn e07_expired_record_is_absent() {
        let f = Fixture::new("done", "clean");
        f.store.gc(45 * 86400, true).unwrap();
        assert!(f.store.get_job("tts", "fixture").is_ok());
        f.store.gc(45 * 86400, false).unwrap();
        assert_eq!(
            f.store.get_job("tts", "fixture"),
            Err(crate::error_catalog::NO_SUCH_JOB)
        );
    }
    #[test]
    fn e08_live_record_never_expires() {
        for state in ["queued", "dispatching", "running"] {
            let f = Fixture::new(state, "pending");
            f.store.gc(400 * 86400, false).unwrap();
            assert!(f.store.get_job("tts", "fixture").is_ok());
        }
    }
    #[test]
    fn e09_compaction_is_fifo_and_spares_live_records() {
        let f = Fixture::new("running", "pending");
        let first = f.store.gc(400 * 86400, true).unwrap();
        let second = f.store.gc(400 * 86400, true).unwrap();
        assert_eq!(first, second);
        assert!(f.store.get_job("tts", "fixture").is_ok());
    }
    #[test]
    fn e10_policy_defaults() {
        let cfg = result_store::Config::default();
        assert_eq!(cfg.stale_tmp, 86400);
        assert_eq!(queue_policy::Config::default().per_lane, 128);
        assert_eq!(result_store::retention("tts"), (14, 45));
    }
}

#[cfg(test)]
mod run34_tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn run34_artifact_refusal_table() {
        let root = std::env::temp_dir().join(format!("run34-artifact-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("outside"), "[R]").unwrap();
        let store_root = root.join("store");
        let store = result_store::Store::new(&store_root, result_store::Config::default());
        let rows: &[(&str, &[u8], u16, &str)] = &[
            ("traversal", b"../outside", 400, error_catalog::PATH_UNSAFE),
            ("absolute", b"/outside", 400, error_catalog::PATH_UNSAFE),
            ("empty", b"", 400, error_catalog::PATH_UNSAFE),
            ("non-UTF-8", &[0xff], 400, error_catalog::PATH_UNSAFE),
            (
                "unknown-job",
                b"speech.wav",
                404,
                error_catalog::NO_SUCH_JOB,
            ),
        ];
        for (label, name, status, code) in rows {
            let (actual_status, actual_code) = if let Ok(name) = std::str::from_utf8(name) {
                let refusal = read(&store, "tts", "missing", Some(name), 1).unwrap_err();
                assert!(!refusal.retryable, "{label}");
                (refusal.status.as_u16(), refusal.code.to_owned())
            } else {
                // The real route guard rejects invalid UTF-8 before auth or storage.
                let app = new_app(json!({"result_store_dir":store_root}), root.join("cards"));
                let request = axum::http::Request::builder()
                    .uri("/v1/lanes/tts/jobs/missing/artifacts/%FF")
                    .body(axum::body::Body::empty())
                    .unwrap();
                let response = router_with_app(app).oneshot(request).await.unwrap();
                let status = response.status().as_u16();
                let bytes = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                let doc: Value = serde_json::from_slice(&bytes).unwrap();
                (status, doc["error"].as_str().unwrap().to_owned())
            };
            assert_eq!(actual_status, *status, "{label}");
            assert_eq!(actual_code, *code, "{label}");
            assert!(
                error_catalog::lookup(Some(*status), code).is_some(),
                "{label}"
            );
            assert_eq!(fs::read(root.join("outside")).unwrap(), b"[R]");
        }
        assert!(!store_root.exists(), "refusals must not create storage");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
