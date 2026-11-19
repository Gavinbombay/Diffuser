use super::*;
use std::io::{Read, Write};

const NOW: u64 = 1793459400;
fn fixed_clock() -> u64 {
    NOW
}

fn run_case(name: &str, case: u8) {
    if std::env::var_os("PULL_HTTP_CHILD").is_none() {
        let status = crate::test_process::command()
            .args(["--exact", &format!("pull_http_tests::{name}"), "--quiet"])
            .env("PULL_HTTP_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = std::env::temp_dir().join(format!("pull-http-{}-{case}", std::process::id()));
    fs::create_dir_all(root.join("cards")).unwrap();
    auth_fixture(&root);
    fs::write(
        root.join("workers.cfg"),
        serde_json::to_vec(&json!({"workers":[{"id":"colab-l4","lanes":["tts"],"enabled":true}]}))
            .unwrap(),
    )
    .unwrap();
    fs::write(root.join("floor"), "5").unwrap();
    std::env::set_var("LANE_REGISTRY", root.join("workers.cfg"));
    std::env::set_var("LANE_TOKEN_SHA_DIR", root.join("auth"));
    let mut card: Value = serde_json::from_slice(include_bytes!(
        "../tests/fixtures/card-state/colab-l4-state.json"
    ))
    .unwrap();
    card["state"] = json!("idle");
    card["busy"] = json!({"by":"none","ref":null});
    card["seat"] = json!({"held":false,"by":""});
    card["session"]["state"] = json!("none");
    card["cu"]["balance"] = json!(9.0);
    let mut checked = card.clone();
    checked["stale"] = json!(false);
    assert_eq!(
        card_state::colab_proof(&checked, Some("colab-l4"), NOW),
        Ok("router-probe")
    );
    let card_path = root.join("cards/colab-l4-state.json");
    fs::write(&card_path, serde_json::to_vec(&card).unwrap()).unwrap();
    let table = Arc::new(Mutex::new(JobTable::default()));
    table.lock().unwrap().enqueue_agent(json!({"job_id":"job-123","max_segs":if case == 4 {1} else {5},"lane":"tts","gpu_class":"l4"}), 9.0);
    let app = App {
        st: table.clone(),
        compat: json!({"card_state_dir":root.join("cards"),"cu_floor_path":root.join("floor"),"jobs_dir":root.join("jobs")}),
        store_root: root.join("store"),
        cards: Arc::new(Mutex::new(HashMap::new())),
        clock: fixed_clock,
    };
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router_with_app(app)).await.unwrap() });
        async fn pull(addr: SocketAddr, body: Value) -> Value {
            tokio::task::spawn_blocking(move || {
                let body = body.to_string(); let mut stream = std::net::TcpStream::connect(addr).unwrap();
                write!(stream, "POST /v1/agent/pull HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer <TOKEN>\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                let mut response = String::new(); stream.read_to_string(&mut response).unwrap();
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
            }).await.unwrap()
        }
        let mut request = json!({"schema_version":"agent-pull/v1","agent_id":"agent-123","worker_id":"colab-l4","lanes":["tts"],"wait_s":1,"state_epoch":NOW});
        let mut current;
        if case == 5 {
            let mut other = request.clone(); other["agent_id"] = json!("agent-456");
            let (first, second) = tokio::join!(pull(addr, request), pull(addr, other));
            assert_eq!([first["status"].as_str(), second["status"].as_str()].iter().filter(|s| **s == Some("assigned")).count(), 1);
            assert_eq!(table.lock().unwrap().jobs.values().filter(|j| j["state"] == "leased").count(), 1);
        } else {
            current = pull(addr, request.clone()).await;
            assert_eq!(current["status"], "assigned");
            if case == 1 { card["cu"]["balance"] = json!(5.1); fs::write(&card_path, serde_json::to_vec(&card).unwrap()).unwrap(); }
            let repeats = if case == 2 { 3 } else { 1 };
            for i in 0..repeats {
                request["report"] = json!({"job_id":"job-123","lease_id":current["lease_id"],"segment":current["segment"],"exit_code":if case == 0 {0} else {75},"session_lost":case == 3,"done_items":["one","one"]});
                current = pull(addr, request.clone()).await;
                if case == 2 || case == 3 { assert_eq!(current["status"], "assigned"); assert_eq!(current["resume_count"], i + 1); }
            }
            if case == 2 || case == 3 {
                assert_eq!(current["done_items"], json!(["one"]));
                request["report"] = json!({"job_id":"job-123","lease_id":current["lease_id"],"segment":current["segment"],"exit_code":0,"done_items":["one"]});
                assert_eq!(pull(addr, request).await["status"], "empty");
            }
            let jobs = table.lock().unwrap(); assert_eq!(jobs.jobs.len(), 1);
            assert_eq!(jobs.jobs["job-123"]["state"], match case {1 => "floor-stopped", 4 => "failed", _ => "done"});
            if case == 4 { assert_eq!(jobs.jobs["job-123"]["reason"], crate::error_catalog::MAX_SEGS_EXCEEDED); }
        }
        server.abort();
    });
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn agent_pull_assigns_then_completes() {
    run_case("agent_pull_assigns_then_completes", 0);
}
#[test]
fn floor_stops_at_boundary_never_under() {
    run_case("floor_stops_at_boundary_never_under", 1);
}
#[test]
fn exit75_three_times_then_done_one_record_three_resumes() {
    run_case("exit75_three_times_then_done_one_record_three_resumes", 2);
}
#[test]
fn lost_session_resume_same_job_id_no_dup_items() {
    run_case("lost_session_resume_same_job_id_no_dup_items", 3);
}
#[test]
fn max_segs_exceeded_failed_with_reason() {
    run_case("max_segs_exceeded_failed_with_reason", 4);
}
#[test]
fn two_agents_never_same_job() {
    run_case("two_agents_never_same_job", 5);
}

// Shared by the in-process reference tests; keep one fixture definition here.
pub(super) fn auth_fixture(root: &Path) {
    fs::create_dir_all(root.join("auth")).unwrap();
    fs::write(
        root.join("auth/tts.sha256"),
        hex::encode(Sha256::digest(b"<TOKEN>")),
    )
    .unwrap();
    std::env::set_var("LANE_TOKEN_SHA_DIR", root.join("auth"));
}
