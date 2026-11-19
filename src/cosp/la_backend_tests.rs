//! Private loopback family. The only synthetic inputs are the fixture grants
//! and bootstrap admission. Process occupancy and all persisted lifecycle
//! commitments are observed and authenticated at their real consumers.
use super::*;
use crate::cosp::{la_artifacts, la_backend, la_store, la_tests, la_worker, lane_assignment};
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::{DirBuilderExt, MetadataExt},
            net::{UnixListener, UnixStream},
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};
use tower::ServiceExt;

const ACTOR_BASE: &str = "/v1/diffuser/projects/project_12345678";
const CASE_VAR: &str = "DIFFUSER_TYPED_FAMILY_CHILD";
const ROOT_VAR: &str = "DIFFUSER_TYPED_FAMILY_ROOT";
const SOURCE_VAR: &str = "DIFFUSER_TYPED_FAMILY_SOURCE";
const CHILD_TEST: &str = "cosp::la_adapter::backend_tests::private_worker";
const BODY: &[u8] =
    br#"{"schema_version":"diffuser-private-sha256-input/v1","data_hex":"616263","rounds":3}"#;
const CAP: la_backend::Capability = la_backend::Capability::PrivateSha256;

fn dir(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

fn file_digest(path: impl AsRef<Path>) -> String {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    io::copy(&mut file, &mut hash).unwrap();
    hex::encode(hash.finalize())
}

fn keys() -> ChannelKeys {
    // Deliberately fixture-only, separate command/reply/P-source/P-custody domains.
    ChannelKeys {
        command: [91; 32],
        reply: [92; 32],
        authority: [93; 32],
        custody: [94; 32],
    }
}

fn binding(source: String, executable: String) -> ChannelBinding {
    ChannelBinding {
        worker: "worker_private_cpu".into(),
        worker_boot: "9".repeat(64),
        controller_boot: "8".repeat(64),
        worker_epoch: 1,
        controller_epoch: 1,
        hardware_generation: 1,
        profile_epoch: 1,
        policy_digest: super::super::la_contract::policy_digest("runtime-short-v1").unwrap(),
        source_digest: source,
        executable_digest: executable,
    }
}

fn session(binding: &ChannelBinding) -> la_worker::ReservationSession {
    la_worker::ReservationSession {
        worker: binding.worker.clone(),
        boot: binding.worker_boot.clone(),
        key: keys().reply,
    }
}

fn lab_lease() -> WorkerAdmission {
    let now = wall_now().unwrap();
    WorkerAdmission(Arc::new(Mutex::new(Some(AdmissionLease {
        issued_at: now,
        expires_at: now + 12_000,
        job_scope: None,
    }))))
}

fn send<T: serde::Serialize>(socket: &mut UnixStream, value: &T) -> io::Result<()> {
    serde_json::to_writer(&mut *socket, value)?;
    socket.write_all(b"\n")
}

fn receive<T: serde::de::DeserializeOwned>(reader: &mut BufReader<UnixStream>) -> io::Result<T> {
    let mut bytes = Vec::new();
    reader.take(65_537).read_until(b'\n', &mut bytes)?;
    if bytes.last() != Some(&b'\n') {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn connection(stream: UnixStream) -> BufReader<UnixStream> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    BufReader::new(stream)
}

fn path_identity(pid: u32) -> io::Result<(u64, u64)> {
    let metadata = fs::metadata(format!("/proc/{pid}/exe"))?;
    Ok((metadata.dev(), metadata.ino()))
}

#[derive(Debug, serde::Serialize)]
struct ProcessIdentity {
    pid: u32,
    starttime: u64,
    parent: u32,
    executable_inode: (u64, u64),
    cgroup: String,
    limits: String,
    status: Vec<String>,
    descendants: Vec<u32>,
}

fn identity(pid: u32) -> io::Result<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<&str> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let mut descendants = Vec::new();
    for thread in fs::read_dir(format!("/proc/{pid}/task"))? {
        for child in fs::read_to_string(thread?.path().join("children"))?.split_whitespace() {
            descendants.push(child.parse::<u32>().unwrap());
        }
    }
    descendants.sort_unstable();
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?
        .lines()
        .filter(|value| {
            [
                "VmRSS:",
                "VmHWM:",
                "Threads:",
                "NoNewPrivs:",
                "Seccomp:",
                "CapEff:",
            ]
            .iter()
            .any(|key| value.starts_with(key))
        })
        .map(str::to_owned)
        .collect();
    Ok(ProcessIdentity {
        pid,
        starttime: fields[19].parse().unwrap(),
        parent: fields[1].parse().unwrap(),
        executable_inode: path_identity(pid)?,
        cgroup: fs::read_to_string(format!("/proc/{pid}/cgroup"))?,
        limits: fs::read_to_string(format!("/proc/{pid}/limits"))?,
        status,
        descendants,
    })
}

fn pin(pid: u32) -> OwnedFd {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn signal(fd: &OwnedFd, number: i32) {
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                number,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
}

fn dead(fd: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut poll, 1, 0) == 1 && poll.revents & libc::POLLIN != 0 }
}

fn exited(pid: u32) {
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "owned process {pid} was not joined"
    );
}

fn write_evidence(case: &str, value: &Value) {
    if let Some(path) = std::env::var_os("DIFFUSER_TYPED_PROOF_DIR") {
        let path = PathBuf::from(path).join(format!("typed-family-{case}.json"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        serde_json::to_writer_pretty(&mut file, value).unwrap();
        file.sync_all().unwrap();
    }
    println!("TYPED_PRIVATE_FAMILY {case}: {value}");
}

#[test]
fn private_worker() {
    let Ok(case) = std::env::var(CASE_VAR) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT_VAR).unwrap());
    let path = root.join("worker");
    let role = la_artifacts::open_owned_root(&path).unwrap();
    let binding = binding(
        std::env::var(SOURCE_VAR).unwrap(),
        file_digest("/proc/self/exe"),
    );
    let keys = keys();
    let witness_socket = Arc::new(Mutex::new(connection(
        UnixStream::connect(root.join("witness")).unwrap(),
    )));
    let slot = Arc::new(Mutex::new(None::<std::sync::Weak<CustodyLink>>));
    let weak = slot.clone();
    let link = CustodyLink::new(
        binding.clone(),
        "worker",
        keys.reply,
        keys.custody,
        Box::new(move |frame| {
            let mut wire = witness_socket.lock().map_err(|_| "storage_unavailable")?;
            wire.get_mut()
                .write_all(frame)
                .and_then(|_| wire.get_mut().write_all(b"\n"))
                .map_err(|_| "control_invalid")?;
            let ack: CheckpointAck = receive(&mut wire).map_err(|_| "control_invalid")?;
            weak.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap()
                .accept(&serde_json::to_vec(&ack).unwrap())
        }),
    )
    .unwrap();
    *slot.lock().unwrap() = Some(Arc::downgrade(&link));
    let mut channel =
        TransportJournal::create(&role, &path, "worker-channel.sqlite", binding.clone()).unwrap();
    channel.enable_custody(link).unwrap();
    let mut journal = la_worker::OperationJournal::bootstrap(
        &path.join("worker.sqlite"),
        "private_family_custody",
    )
    .unwrap();
    let resume = Arc::new(AtomicBool::new(false));
    let (entered, events) = std::sync::mpsc::sync_channel(1);
    let mut helper_pin = None;
    let helper = if case == "legacy" {
        None
    } else if case.starts_with("cuda-") {
        let capability = cuda_route_tests::case_pin(&case);
        let trace = File::create(root.join("cuda-driver.trace")).unwrap();
        match la_backend::cuda::CudaProcess::launch(
            &root.join("cuda-helper"),
            trace,
            capability,
            cuda_route_tests::case_mode(&case),
        ) {
            Ok(helper) => {
                let pid = helper.pid();
                helper_pin = Some(Arc::new(pin(pid)));
                journal.attach_backend(Box::new(helper)).unwrap();
                Some(pid)
            }
            Err("capability_unavailable") => None,
            Err(code) => panic!("unexpected CUDA fixture startup: {code}"),
        }
    } else {
        let mut helper = la_backend::PrivateProcess::launch().unwrap();
        let helper_pid = helper.pid();
        helper_pin = Some(Arc::new(pin(helper_pid)));
        if [
            "cancel",
            "result_wins_cancel",
            "running_loss",
            "permit_expiry",
        ]
        .contains(&case.as_str())
        {
            helper.pause = Some(la_backend::FixturePause {
                entered,
                resume: resume.clone(),
            });
        }
        journal.attach_backend(Box::new(helper)).unwrap();
        Some(helper_pid)
    };
    let w_state = Arc::new(Mutex::new(WorkerRpc {
        journal,
        session: session(&binding),
        channel,
        keys: keys.clone(),
        admission: lab_lease(),
    }));
    {
        let mut w = w_state.lock().unwrap();
        w.channel.owned_state = true;
        w.channel.owned_digest = Some(state_custody::state_digest(&role).unwrap());
    }

    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let addr = socket.local_addr().unwrap();
    let mut control = connection(UnixStream::connect(root.join("control")).unwrap());
    let seal = la_worker::seal_fixture_role().unwrap();
    let control_state = w_state.clone();
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let control_task = std::thread::spawn(move || {
        send(
            control.get_mut(),
            &json!({"port":addr.port(),"helper":helper,"worker":std::process::id(),"seal":seal}),
        )
        .unwrap();
        loop {
            let command: Value = receive(&mut control).unwrap();
            let value = match command["op"].as_str().unwrap() {
                "source" => {
                    let bytes: Vec<u8> = serde_json::from_value(command["frame"].clone()).unwrap();
                    let ack = control_state.lock().unwrap().observe(&bytes).unwrap();
                    json!(ack)
                }
                "entered" => json!(events.try_recv().ok()),
                "continue" => {
                    resume.store(true, Ordering::SeqCst);
                    json!(true)
                }
                "shutdown" => {
                    send(control.get_mut(), &json!(true)).unwrap();
                    shutdown.send(()).unwrap();
                    break;
                }
                _ => panic!("unknown fixed fixture message"),
            };
            send(control.get_mut(), &value).unwrap();
        }
    });
    let dropped = Arc::new(AtomicBool::new(false));
    let router = worker_rpc_router(
        InventoryContext {
            bearer_digest: [0; 32],
            worker_id: binding.worker,
            boot_id: binding.worker_boot,
            hardware_generation: 1,
            profile_epoch: 1,
        },
        w_state,
    )
    .layer(from_fn(move |req: Request, next: Next| {
        let case = case.clone();
        let dropped = dropped.clone();
        let helper = helper_pin.clone();
        async move {
            let response = next.run(req).await;
            let (parts, body) = response.into_parts();
            let bytes = to_bytes(body, 65_536).await.unwrap();
            if let Ok(reply) = serde_json::from_slice::<SignedResponse>(&bytes) {
                if case == "before_start"
                    && matches!(reply.response.reply, WorkerReply::Staged { .. })
                {
                    signal(helper.as_ref().unwrap(), libc::SIGKILL);
                    let until = Instant::now() + Duration::from_millis(250);
                    while !dead(helper.as_ref().unwrap()) && Instant::now() < until {
                        std::thread::yield_now();
                    }
                    assert!(dead(helper.as_ref().unwrap()));
                }
                if case == "lost_reply"
                    && matches!(reply.response.reply, WorkerReply::Result(..))
                    && !dropped.swap(true, Ordering::SeqCst)
                {
                    eprintln!(
                        "TYPED_FIXTURE_DROPPED_DURABLE_REPLY sequence={}",
                        reply.response.sequence
                    );
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
            }
            Response::from_parts(parts, Body::from(bytes))
        }
    }));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let listener = tokio::net::TcpListener::from_std(socket).unwrap();
            axum::serve(listener, router)
                .with_graceful_shutdown(async { stopped.await.unwrap() })
                .await
                .unwrap();
        });
    control_task.join().unwrap();
}

struct Managed(Child);
impl Drop for Managed {
    fn drop(&mut self) {
        if self.0.try_wait().ok() == Some(None) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn listen(path: &Path) -> UnixListener {
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn accept(listener: &UnixListener, child: &mut Managed) -> BufReader<UnixStream> {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return connection(stream),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                assert_eq!(
                    child.0.try_wait().unwrap(),
                    None,
                    "private worker exited at startup"
                );
                assert!(Instant::now() < deadline, "private worker startup expired");
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(err) => panic!("{err}"),
        }
    }
}

fn worker_limits(cmd: &mut Command) {
    unsafe {
        cmd.pre_exec(|| {
            for (resource, amount) in [
                (libc::RLIMIT_CPU, 6),
                (libc::RLIMIT_AS, 536_870_912),
                (libc::RLIMIT_FSIZE, 1_048_576),
                (libc::RLIMIT_CORE, 0),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: amount,
                    rlim_max: amount,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn ctl(wire: &mut BufReader<UnixStream>, value: &Value) -> Value {
    send(wire.get_mut(), value).unwrap();
    receive(wire).unwrap()
}

fn await_entry(wire: &mut BufReader<UnixStream>, pid: u32) {
    let until = Instant::now() + Duration::from_millis(350);
    loop {
        let reported = ctl(wire, &json!({"op":"entered"}));
        if reported.as_u64() == Some(u64::from(pid)) {
            return;
        }
        assert!(
            Instant::now() < until,
            "the private helper never completed its first real round"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn attach_transport_witness(
    channel: &mut TransportJournal,
    binding: &ChannelBinding,
    role: &File,
    custody: &File,
    path: &Path,
) {
    let keys = keys();
    let ledger = Arc::new(Mutex::new(
        CustodyLedger::bootstrap(
            custody,
            path,
            binding.clone(),
            "controller",
            keys.reply,
            keys.custody,
        )
        .unwrap(),
    ));
    let role = role.try_clone().unwrap();
    let slot = Arc::new(Mutex::new(None::<std::sync::Weak<CustodyLink>>));
    let weak = slot.clone();
    let link = CustodyLink::new(
        binding.clone(),
        "controller",
        keys.reply,
        keys.custody,
        Box::new(move |frame| {
            let frame: SignedCheckpoint = serde_json::from_slice(frame).unwrap();
            let ack = ledger.lock().unwrap().observe(&role, &frame)?;
            weak.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap()
                .accept(&serde_json::to_vec(&ack).unwrap())
        }),
    )
    .unwrap();
    *slot.lock().unwrap() = Some(Arc::downgrade(&link));
    channel.enable_custody(link).unwrap();
}

fn attach_service_witness(
    binding: &ChannelBinding,
    role: &File,
    custody: &File,
) -> (
    Arc<state_custody::Session>,
    Arc<Mutex<state_custody::Ledger>>,
) {
    let keys = keys();
    let ledger = Arc::new(Mutex::new(
        state_custody::Ledger::new(custody, binding.clone(), &keys).unwrap(),
    ));
    let independent = ledger.clone();
    let observer_root = role.try_clone().unwrap();
    let slot = Arc::new(Mutex::new(None::<std::sync::Weak<state_custody::Link>>));
    let weak = slot.clone();
    let link = state_custody::Link::new(
        binding.clone(),
        &keys,
        Box::new(move |frame| {
            let frame: state_custody::Checkpoint = serde_json::from_slice(frame).unwrap();
            let ack = independent
                .lock()
                .unwrap()
                .observe(&observer_root, &frame)?;
            weak.lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap()
                .accept(&serde_json::to_vec(&ack).unwrap())
        }),
    )
    .unwrap();
    *slot.lock().unwrap() = Some(Arc::downgrade(&link));
    (state_custody::Session::create(role, link).unwrap(), ledger)
}

#[path = "la_fixture_http.rs"]
mod fixture_http;

#[derive(Clone)]
struct Client {
    tcp: Option<fixture_http::TcpClient>,
    app: Option<Router>,
    token: String,
}
impl Client {
    async fn call(
        &self,
        method: &str,
        path: &str,
        key: &str,
        value: impl serde::Serialize,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(format!("{ACTOR_BASE}{path}"))
            .header("authorization", format!("Bearer {}", self.token))
            .header("idempotency-key", key)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap();
        let (status, _, bytes) = self.send(request).await;
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn send(&self, req: Request) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        if let Some(tcp) = &self.tcp {
            return tcp.send(req).await;
        }
        let response = self.app.clone().unwrap().oneshot(req).await.unwrap();
        let (parts, body) = response.into_parts();
        (
            parts.status,
            parts.headers,
            to_bytes(body, 65_536).await.unwrap().to_vec(),
        )
    }

    async fn upload(&self, key: &str, input: &[u8]) -> String {
        let request = Request::builder()
            .method("POST")
            .uri(format!("{ACTOR_BASE}/artifacts"))
            .header("authorization", format!("Bearer {}", self.token))
            .header("idempotency-key", key)
            .header("content-type", "application/octet-stream")
            .header("x-diffuser-schema", "diffuser-artifact/v1")
            .header("x-content-sha256", hex::encode(Sha256::digest(input)))
            .body(Body::from(input.to_vec()))
            .unwrap();
        let (status, _, bytes) = self.send(request).await;
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["object_id"].as_str().unwrap().to_owned()
    }

    async fn artifact(&self, id: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let request = Request::builder()
            .uri(format!("{ACTOR_BASE}/artifacts/{id}/content"))
            .header("authorization", format!("Bearer {}", self.token))
            .body(Body::empty())
            .unwrap();
        self.send(request).await
    }
}

fn submit(input: &str, legacy: bool) -> Value {
    json!({
        "schema_version": if legacy { "diffuser-lane/v1" } else { "diffuser-lane/v2" },
        "client_job_id": "private_typed_job01",
        "capability": "artifact.inspect.sha256/v1",
        "profile_version": "1",
        "input_artifact_ids": [input],
        "parameters": if legacy { json!({}) } else { json!({"backend":"cpu-private-sha256/v1"}) },
        "max_runtime_ms":4000,
        "disconnect_policy":"continue_until_job_deadline"
    })
}

fn worker_counts(root: &File) -> (i64, i64, i64, i64) {
    let db = la_store::open_pinned_readonly_database(root, "worker.sqlite").unwrap();
    db.query_row("SELECT (SELECT COUNT(*) FROM operations WHERE state!='stopped'),(SELECT COUNT(*) FROM worker_result_receipts),(SELECT COUNT(*) FROM worker_stop_receipts),(SELECT COUNT(*) FROM worker_cleanup_receipts)",[],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap()
}

struct Family {
    root: Root,
    control: BufReader<UnixStream>,
    child: Managed,
    w_id: ProcessIdentity,
    w_pin: OwnedFd,
    h_id: Option<ProcessIdentity>,
    h_pin: Option<OwnedFd>,
    witness: Option<std::thread::JoinHandle<()>>,
    binding: ChannelBinding,
    w_root: File,
    c_root: File,
    p_root: File,
    custody: Arc<state_custody::Session>,
    ledger: Arc<Mutex<state_custody::Ledger>>,
    claims: Arc<Mutex<la_store::ClaimStore>>,
    authority: lane_assignment::SharedAuthority,
    service_worker: Arc<Mutex<lane_assignment::ServiceWorker>>,
    client: Client,
    foreign: Client,
    sequence: u64,
    address: std::net::SocketAddr,
    grant_expiry: u64,
}

impl Family {
    fn start(case: &str) -> Self {
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let base =
            std::env::temp_dir().join(format!("p3-{}-{}", std::process::id(), wall_now().unwrap()));
        dir(&base);
        let root = Root(base);
        if case.starts_with("cuda-") {
            cuda_route_tests::build_helper(&root.0);
        }
        let source = std::env::var_os("DIFFUSER_TYPED_PROOF_DIR")
            .map(PathBuf::from)
            .map(|p| {
                let source: std::collections::BTreeMap<String, String> =
                    serde_json::from_slice(&fs::read(p.join("source-before.json")).unwrap())
                        .unwrap();
                hex::encode(Sha256::digest(serde_json::to_vec(&source).unwrap()))
            })
            .unwrap_or_else(|| hex::encode(Sha256::digest(include_bytes!("la_backend.rs"))));
        let binding = binding(source.clone(), file_digest("/proc/self/exe"));
        let w_path = root.0.join("worker");
        let c_path = root.0.join("controller");
        let p_path = root.0.join("custody");
        for path in [&w_path, &c_path, &p_path] {
            dir(path);
        }
        let w_root = la_artifacts::open_owned_root(&w_path).unwrap();
        let c_root = la_artifacts::open_owned_root(&c_path).unwrap();
        let p_root = la_artifacts::open_owned_root(&p_path).unwrap();
        let wit = listen(&root.0.join("witness"));
        let control = listen(&root.0.join("control"));
        let mut cmd = Command::new("/proc/self/exe");
        cmd.args(["--exact", CHILD_TEST, "--nocapture"])
            .env_clear()
            .env(CASE_VAR, case)
            .env(ROOT_VAR, &root.0)
            .env(SOURCE_VAR, &source)
            .stdin(Stdio::null());
        worker_limits(&mut cmd);
        let mut child = Managed(cmd.spawn().unwrap());
        let keys = keys();
        let mut wire = accept(&wit, &mut child);
        let observed = w_root.try_clone().unwrap();
        let mut transport_witness = CustodyLedger::bootstrap(
            &p_root,
            &p_path,
            binding.clone(),
            "worker",
            keys.reply,
            keys.custody,
        )
        .unwrap();
        let witness = std::thread::spawn(move || loop {
            let frame: SignedCheckpoint = match receive(&mut wire) {
                Ok(frame) => frame,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => panic!("owned worker witness failed: {err}"),
            };
            let ack = transport_witness.observe(&observed, &frame).unwrap();
            send(wire.get_mut(), &ack).unwrap();
        });
        let mut control = accept(&control, &mut child);
        let ready: Value = receive(&mut control).unwrap();
        assert_eq!(ready["worker"], child.0.id());
        let w_id = identity(child.0.id()).unwrap();
        let w_pin = pin(w_id.pid);
        assert_eq!(w_id.parent, std::process::id());
        assert_eq!(
            w_id.executable_inode,
            path_identity(std::process::id()).unwrap()
        );
        assert_eq!(
            w_id.cgroup,
            fs::read_to_string("/proc/self/cgroup").unwrap()
        );
        assert_eq!(ready["seal"]["fork_errno"], libc::EPERM);
        assert_eq!(ready["seal"]["exec_errno"], libc::EPERM);
        let h_id = ready["helper"]
            .as_u64()
            .map(|pid| identity(pid as u32).unwrap());
        let h_pin = h_id.as_ref().map(|h| pin(h.pid));
        if let Some(h) = &h_id {
            assert_eq!(h.parent, w_id.pid);
            assert_eq!(h.cgroup, w_id.cgroup);
            if case.starts_with("cuda-") {
                let metadata = fs::metadata(root.0.join("cuda-helper")).unwrap();
                assert_eq!(h.executable_inode, (metadata.dev(), metadata.ino()));
            } else {
                assert_eq!(h.executable_inode, w_id.executable_inode);
            }
            assert!(h.descendants.is_empty());
            assert!(h.status.iter().any(|line| line == "NoNewPrivs:\t1"));
            assert!(h.status.iter().any(|line| line == "Seccomp:\t2"));
            assert!(h
                .limits
                .lines()
                .any(|line| line.starts_with("Max address space ") && line.contains("16777216")));
            assert!(h
                .limits
                .lines()
                .any(|line| line.split_whitespace().collect::<Vec<_>>()
                    == ["Max", "cpu", "time", "1", "1", "seconds"]));
            assert_eq!(w_id.descendants, [h.pid]);
        }
        let port = ready["port"].as_u64().unwrap() as u16;
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let now = wall_now().unwrap();
        let (mut authority, human, leaf) = la_tests::fixture_discovery_context(now);
        let grant_expiry = now + if case == "auth_expiry" { 350 } else { 60_000 };
        authority.freshness_ms = 1500;
        for grant in &mut authority.grants {
            grant.scopes = 2047;
            grant.access_expires = grant_expiry;
        }
        let authority = Arc::new(RwLock::new(authority));
        let artifacts = la_artifacts::ArtifactStore::open(&c_path).unwrap();
        let claims = Arc::new(Mutex::new(
            la_store::ClaimStore::open(&c_path.join("lane_assignments.sqlite")).unwrap(),
        ));
        let mut channel = TransportJournal::create(
            &c_root,
            &c_path,
            "controller-channel.sqlite",
            binding.clone(),
        )
        .unwrap();
        attach_transport_witness(&mut channel, &binding, &c_root, &p_root, &p_path);
        let (custody, ledger) = attach_service_witness(&binding, &c_root, &p_root);
        let rpc = WorkerClient::new(address, channel, keys)
            .unwrap()
            .with_protected_admission(lab_lease())
            .with_protected_backend(Some(if case.starts_with("cuda-") {
                la_backend::Capability::CudaAddOne(cuda_route_tests::case_pin(case))
            } else {
                CAP
            }))
            .with_service_custody(custody.clone());
        let (routes, worker) = lane_assignment::protected_service_router(
            authority.clone(),
            artifacts,
            claims.clone(),
            rpc,
            session(&binding),
        );
        let app = crate::cosp::api_with_namespace(
            crate::cosp::Spine {
                root: root.0.clone(),
                edge: false,
                worker_ports: [0, 0],
                admin: false,
                sequence: Arc::new(Mutex::new(0)),
            },
            lane_assignment::witnessed_namespace(routes, custody.clone()),
        );
        Self {
            root,
            control,
            child,
            w_id,
            w_pin,
            h_id,
            h_pin,
            witness: Some(witness),
            binding,
            w_root,
            c_root,
            p_root,
            custody,
            ledger,
            claims,
            authority,
            service_worker: worker,
            client: Client {
                tcp: None,
                app: Some(app.clone()),
                token: leaf,
            },
            foreign: Client {
                tcp: None,
                app: Some(app),
                token: human,
            },
            sequence: 0,
            address,
            grant_expiry,
        }
    }

    fn refresh(&mut self, revoked: &[&str]) {
        self.sequence += 1;
        let bytes = serde_json::to_vec(&json!({
            "schema_version":"diffuser-authority-observation/v1",
            "sequence":self.sequence, "observed_at":wall_now().unwrap(), "revoked":revoked
        }))
        .unwrap();
        let keys = keys();
        let frame = sign_source_observation(&keys.authority, &self.binding, &bytes).unwrap();
        self.ledger
            .lock()
            .unwrap()
            .record_authority(&frame)
            .unwrap();
        let worker: SourceAck = serde_json::from_value(ctl(
            &mut self.control,
            &json!({"op":"source", "frame":frame}),
        ))
        .unwrap();
        let controller = lane_assignment::apply_witnessed_protected_source_observation(
            &self.authority,
            &self.claims,
            &self.binding,
            &keys,
            &frame,
            Some(&self.service_worker),
            &self.custody,
        )
        .unwrap();
        self.ledger
            .lock()
            .unwrap()
            .observe_authority(&frame, &controller, &worker)
            .unwrap();
    }

    fn h_wait_death(&self) {
        let until = Instant::now() + Duration::from_millis(500);
        while !dead(self.h_pin.as_ref().unwrap()) {
            assert!(Instant::now() < until, "exact private child remained live");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn kill(&mut self) -> Option<Value> {
        signal(&self.w_pin, libc::SIGKILL);
        let result = self.child.0.wait().unwrap();
        assert_eq!(result.signal(), Some(libc::SIGKILL));
        exited(self.w_id.pid);
        if self.h_pin.is_some() {
            self.h_wait_death();
        }
        let helper_signal = self.reap_adopted();
        self.witness.take().unwrap().join().unwrap();
        helper_signal
    }

    fn reap_adopted(&self) -> Option<Value> {
        let h = self.h_id.as_ref()?;
        let mut status = 0;
        let result = unsafe { libc::waitpid(h.pid as i32, &mut status, libc::WNOHANG) };
        if result < 0 {
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            return None;
        }
        if result == 0 {
            signal(self.h_pin.as_ref().unwrap(), libc::SIGKILL);
            assert_eq!(
                unsafe { libc::waitpid(h.pid as i32, &mut status, 0) },
                h.pid as i32
            );
        }
        exited(h.pid);
        if libc::WIFSIGNALED(status) {
            Some(json!({"signal":libc::WTERMSIG(status)}))
        } else {
            assert!(libc::WIFEXITED(status));
            Some(json!({"exit_code":libc::WEXITSTATUS(status)}))
        }
    }

    fn shutdown(&mut self) {
        assert_eq!(ctl(&mut self.control, &json!({"op":"shutdown"})), true);
        assert!(self.child.0.wait().unwrap().success());
        exited(self.w_id.pid);
        if let Some(h) = &self.h_id {
            exited(h.pid);
        }
        self.witness.take().unwrap().join().unwrap();
    }

    fn counts(&self) -> (i64, i64, i64) {
        self.claims.lock().unwrap().counts().unwrap()
    }

    fn cleanup(&self, assignment: &str) -> (cleanup::Certificate, Value, Value) {
        assert!(!dead(&self.w_pin));
        let current = identity(self.w_id.pid).unwrap();
        assert_eq!(current.starttime, self.w_id.starttime);
        assert_eq!(current.executable_inode, self.w_id.executable_inode);
        assert_eq!(current.cgroup, self.w_id.cgroup);
        assert_eq!(current.limits, self.w_id.limits);
        assert!(current.descendants.is_empty());
        if let Some(h) = &self.h_id {
            assert!(dead(self.h_pin.as_ref().unwrap()));
            exited(h.pid);
        }
        let snapshot = json!({
            "profile":"private-loopback-cpu-fixture/v1",
            "worker":current,
            "original_helper":self.h_id,
            "zero_descendants":true,
        });
        let keys = keys();
        let certificate = cleanup::Certificate::inspect_fixture_witnessed_state(
            &self.binding,
            &keys,
            &self.w_root,
            &self.c_root,
            &self.p_root,
            &self.root.0.join("custody"),
            &json!(self.w_id),
            &snapshot,
            assignment,
            wall_now().unwrap(),
            None,
        )
        .unwrap();
        let frame = serde_json::to_vec(&certificate).unwrap();
        let mut record = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.root.0.join("custody/typed-cleanup-certificate.json"))
            .unwrap();
        record.write_all(&frame).unwrap();
        record.sync_all().unwrap();
        self.p_root.sync_all().unwrap();
        let first = lane_assignment::apply_witnessed_cleanup(
            &self.claims,
            &self.binding,
            &keys,
            &frame,
            &self.custody,
        )
        .unwrap();
        let replay = lane_assignment::apply_witnessed_cleanup(
            &self.claims,
            &self.binding,
            &keys,
            &frame,
            &self.custody,
        )
        .unwrap();
        assert_eq!(first["released_now"], true);
        assert_eq!(replay["released_now"], false);
        assert_eq!(first["certificate_digest"], replay["certificate_digest"]);
        (certificate, first, replay)
    }

    fn replay_exact_worker_result(&self, operation: &str) -> Value {
        let w =
            la_store::open_pinned_readonly_database(&self.w_root, "worker-channel.sqlite").unwrap();
        let mut rows = w.prepare("SELECT request,response FROM channel_log WHERE response IS NOT NULL ORDER BY sequence").unwrap();
        let pairs = rows
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .unwrap();
        for result in pairs {
            let (req, response) = result.unwrap();
            let reply: SignedResponse = serde_json::from_slice(&response).unwrap();
            if !matches!(reply.response.reply, WorkerReply::Result(_, ref r, _) if r.operation == operation)
            {
                continue;
            }
            let request: SignedRequest = serde_json::from_slice(&req).unwrap();
            let mut frame = (req.len() as u32).to_be_bytes().to_vec();
            frame.extend(req);
            let again = rpc_http(self.address, &request.request.operation, &frame).unwrap();
            assert_eq!(again, response);
            return json!({
                "signed_request_sha256":hex::encode(Sha256::digest(&frame[4..])),
                "signed_reply_sha256":hex::encode(Sha256::digest(&response)),
                "sequence":reply.response.sequence,
                "reply":reply.response.reply,
            });
        }
        panic!("missing exact retained signed result");
    }
}

impl Drop for Family {
    fn drop(&mut self) {
        if self.witness.is_some() {
            if !dead(&self.w_pin) {
                signal(&self.w_pin, libc::SIGKILL);
            }
            let _ = self.child.0.wait();
            self.reap_adopted();
            let _ = self.witness.take().unwrap().join();
        }
    }
}

const CASES: &[&str] = &[
    "legacy",
    "normal",
    "lost_reply",
    "cancel",
    "result_wins_cancel",
    "permit_expiry",
    "before_start",
    "running_loss",
    "after_result_loss",
    "before_cleanup",
    "auth_expiry",
    "revoked",
];

async fn family_case(case: &str) {
    let legacy = case == "legacy";
    let mut f = Family::start(case);
    f.refresh(&[]);
    let acquire = json!({"schema_version":"diffuser-lane/v1","capability":"artifact.inspect.sha256/v1","lane_id":null,"profile_id":null,"resource_id":null,"provider_id":null,"requested_hardware_description":null,"resources":{"cpu_millicores":1000,"ram_bytes":16777216,"storage_bytes":2097152,"gpu_domains":[]},"queue_policy":"refuse","requested_lease_ms":4000,"requested_tenure_ms":12000});
    let payload = if legacy {
        b"legacy ordinary process payload".as_slice()
    } else {
        BODY
    };
    let input = f.client.upload("private_input_00001", payload).await;
    let (status, assignment) = f
        .client
        .call("POST", "/assignments", "private_acquire_001", acquire)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{assignment}");
    assert_eq!(assignment["state"], "assigned");
    let assignment = assignment["assignment_id"].as_str().unwrap();
    let submit_path = format!("/assignments/{assignment}/jobs");
    let release_path = format!("/assignments/{assignment}/release");
    let request = submit(&input, legacy);
    let mut observations = json!({
        "case":case, "source":f.binding.source_digest, "executable_sha256":f.binding.executable_digest,
        "worker_start":f.w_id, "helper_start":f.h_id,
        "delegated_ephemeral_fixture_grants":true, "bootstrap_lease_fixture_only":true,
        "current_qualification_claimed":false,
    });

    if case == "normal" {
        let (status, denied) = f
            .foreign
            .call("POST", &submit_path, "private_foreign_001", request.clone())
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{denied}");
        assert_eq!(denied["error"]["code"], "object_not_found");
        let mut denied_codes = vec![denied["error"]["code"].clone()];
        for (facets, code) in [
            (
                json!({"backend":"https://invalid.invalid/v1"}),
                "capability_unavailable",
            ),
            (
                json!({"backend":"cpu-private-sha256/v1","argv":["/bin/false"]}),
                "schema_invalid",
            ),
            (json!({"backend":true}), "schema_invalid"),
            (json!({}), "schema_invalid"),
        ] {
            let mut changed = request.clone();
            changed["parameters"] = facets;
            let (_, denied) = f
                .client
                .call("POST", &submit_path, "private_invalid_001", changed)
                .await;
            assert_eq!(denied["error"]["code"], code, "{denied}");
            denied_codes.push(denied["error"]["code"].clone());
        }
        let valid_input: Value = serde_json::from_slice(BODY).unwrap();
        for (index, (field, value)) in [
            ("schema_version", json!("unexpected/v1")),
            ("data_hex", json!("AB")),
            ("rounds", json!(262145)),
            ("path", json!("/fixture")),
        ]
        .into_iter()
        .enumerate()
        {
            let mut bad_input = valid_input.clone();
            bad_input[field] = value;
            let artifact = f
                .client
                .upload(
                    &format!("private_bad_input_{index}"),
                    &serde_json::to_vec(&bad_input).unwrap(),
                )
                .await;
            let mut changed = request.clone();
            changed["input_artifact_ids"] = json!([artifact]);
            let (status, denied) = f
                .client
                .call("POST", &submit_path, "private_invalid_002", changed)
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(denied["error"]["code"], "artifact_invalid", "{denied}");
            denied_codes.push(denied["error"]["code"].clone());
        }
        assert_eq!(worker_counts(&f.w_root), (0, 0, 0, 0));
        assert_eq!(f.claims.lock().unwrap().job_history_count().unwrap(), 0);
        observations["negative_codes"] = json!(denied_codes);
        f.refresh(&[]);
    }
    if matches!(case, "auth_expiry" | "revoked") {
        if case == "auth_expiry" {
            let remaining = f.grant_expiry.saturating_sub(wall_now().unwrap());
            std::thread::sleep(Duration::from_millis(remaining + 2));
        } else {
            f.refresh(&["grant_leaf123456"]);
        }
        let (status, denied) = f
            .client
            .call("POST", &submit_path, "private_submit_0001", request)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{denied}");
        assert_eq!(denied["error"]["code"], "auth_invalid", "{denied}");
        assert_eq!(worker_counts(&f.w_root).0, 0);
        assert_eq!(f.claims.lock().unwrap().job_history_count().unwrap(), 0);
        observations["public_refusal"] = denied;
        observations["work_entries"] = json!(0);
        f.shutdown();
        write_evidence(case, &observations);
        return;
    }

    let (status, submitted) = f
        .client
        .call("POST", &submit_path, "private_submit_0001", request.clone())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{submitted}");
    let job = submitted["job_id"].as_str().unwrap();
    let job_path = format!("/jobs/{job}");
    let cancel_path = format!("{job_path}/cancel");
    let command = f.claims.lock().unwrap().job_permit_command(job).unwrap();
    assert_eq!(command.backend, (!legacy).then_some(CAP));
    let cancel =
        json!({"schema_version":"diffuser-lane/v1", "expected_revision":submitted["revision"]});
    observations["command"] = json!(command);
    observations["first_submit"] = submitted.clone();

    if matches!(
        case,
        "cancel" | "result_wins_cancel" | "running_loss" | "permit_expiry"
    ) {
        assert_eq!(submitted["state"], "running");
        let pid = f.h_id.as_ref().unwrap().pid;
        await_entry(&mut f.control, pid);
        let running = identity(pid).unwrap();
        assert_eq!(running.starttime, f.h_id.as_ref().unwrap().starttime);
        assert_eq!(running.parent, f.w_id.pid);
        assert!(running.descendants.is_empty());
        assert!(!dead(f.h_pin.as_ref().unwrap()));
        assert_eq!(worker_counts(&f.w_root), (1, 0, 0, 0));
        observations["first_hash_observed"] = json!(running);
        if case == "result_wins_cancel" {
            assert_eq!(ctl(&mut f.control, &json!({"op":"continue"})), true);
            f.h_wait_death();
        } else if case == "permit_expiry" {
            let remaining = command.permit_until.saturating_sub(wall_now().unwrap());
            std::thread::sleep(Duration::from_millis(remaining + 2));
            f.h_wait_death();
            exited(pid);
            assert_eq!(worker_counts(&f.w_root), (1, 0, 0, 0));
            f.refresh(&[]);
        } else if case == "running_loss" {
            let exit = f.kill().expect("independently joined adopted helper");
            assert!(
                exit["signal"] == libc::SIGKILL || exit["exit_code"] == 70,
                "parent death must close the helper via its death signal or pipe EOF: {exit}"
            );
            observations["adopted_helper_exit"] = exit;
            let (status, denied) = f
                .client
                .call("POST", &cancel_path, "private_cancel_001", cancel)
                .await;
            observations["cancel_after_death"] = json!({"http":status.as_u16(),"body":denied});
            assert_eq!(worker_counts(&f.w_root), (1, 0, 0, 0));
            assert_eq!(f.counts().0, 1);
            assert_eq!(f.counts().1, 1);
            observations["worker_counts"] = json!(worker_counts(&f.w_root));
            observations["held_claims_quota"] = json!(f.counts());
            write_evidence(case, &observations);
            return;
        } else {
            let (status, denied) = f
                .foreign
                .call("POST", &cancel_path, "private_foreign_002", cancel.clone())
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{denied}");
            assert_eq!(denied["error"]["code"], "object_not_found");
            assert!(!dead(f.h_pin.as_ref().unwrap()));
        }
    }

    let cancelled = matches!(case, "before_start" | "cancel" | "permit_expiry");
    let terminal = if cancelled || case == "result_wins_cancel" {
        let (status, cancelled) = f
            .client
            .call("POST", &cancel_path, "private_cancel_001", cancel.clone())
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{cancelled}");
        cancelled
    } else {
        let (status, view) = f.client.call("GET", &job_path, "", Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{view}");
        view
    };
    let state = if cancelled { "cancelled" } else { "succeeded" };
    let until = Instant::now() + Duration::from_millis(350);
    let mut terminal = terminal;
    while terminal["state"] != state && Instant::now() < until {
        let (status, view) = f.client.call("GET", &job_path, "", Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{view}");
        terminal = view;
    }
    assert_eq!(terminal["state"], state, "{terminal}");
    observations["terminal"] = terminal.clone();
    if let Some(h) = &f.h_id {
        assert!(dead(f.h_pin.as_ref().unwrap()));
        exited(h.pid);
    }
    let output = if cancelled {
        assert_eq!(
            worker_counts(&f.w_root),
            (i64::from(case != "before_start"), 0, 1, 0)
        );
        None
    } else {
        assert_eq!(worker_counts(&f.w_root), (1, 1, 0, 0));
        let (_, view) = f.client.call("GET", &job_path, "", Value::Null).await;
        let output = view["result_artifact_id"].as_str().unwrap().to_owned();
        let (status, headers, bytes) = f.client.artifact(&output).await;
        assert_eq!(status, StatusCode::OK);
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(headers["etag"], format!("\"{digest}\""));
        let report: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report["sha256"], hex::encode(Sha256::digest(payload)));
        if !legacy {
            assert_eq!(report["backend"], "cpu-private-sha256/v1");
            assert_eq!(
                report["output_sha256"],
                hex::encode(Sha256::digest(Sha256::digest(Sha256::digest(b"abc"))))
            );
            assert_eq!(report["rounds"], 3);
        }
        let exact = f.replay_exact_worker_result(&command.operation);
        assert_eq!(worker_counts(&f.w_root), (1, 1, 0, 0));
        observations["exact_signed_replay"] = exact;
        observations["artifact_sha256"] = json!(digest);
        observations["artifact"] = report;
        let (foreign_status, _, denied) = f.foreign.artifact(&output).await;
        assert_eq!(foreign_status, StatusCode::NOT_FOUND);
        assert_eq!(
            serde_json::from_slice::<Value>(&denied).unwrap()["error"]["code"],
            "object_not_found"
        );
        Some((output, bytes))
    };

    if case == "normal" {
        let mut new_request = request.clone();
        new_request["client_job_id"] = "private_no_fallback".into();
        let (status, denied) = f
            .client
            .call("POST", &submit_path, "private_next_typed01", new_request)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{denied}");
        assert_eq!(denied["error"]["code"], "capability_unavailable");
        assert_eq!(f.claims.lock().unwrap().job_history_count().unwrap(), 1);
        assert_eq!(worker_counts(&f.w_root), (1, 1, 0, 0));
        observations["unavailable_no_fallback"] = denied;
    }
    if case == "after_result_loss" {
        assert_eq!(f.kill(), None);
        assert_eq!(f.counts().0, 1);
        assert_eq!(f.counts().1, 1);
    }
    let (status, retry) = f
        .client
        .call("POST", &submit_path, "private_submit_0001", request)
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{retry}");
    assert_eq!(retry["job_id"], job);
    assert_eq!(retry["state"], state);
    assert_eq!(
        worker_counts(&f.w_root).0,
        i64::from(case != "before_start")
    );

    if case != "after_result_loss" {
        f.refresh(&[]);
        let (status, assignment_view) = f
            .client
            .call(
                "GET",
                &format!("/assignments/{assignment}"),
                "",
                Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{assignment_view}");
        let release = json!({"schema_version":"diffuser-lane/v1","expected_revision":assignment_view["revision"]});
        let (status, closed) = f
            .client
            .call("POST", &release_path, "private_release_001", release)
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{closed}");
        assert_eq!(f.counts().0, 1);
        assert_eq!(f.counts().1, 1);
        assert!(f
            .claims
            .lock()
            .unwrap()
            .assignment_stop_recorded(assignment)
            .unwrap());
        observations["close"] = closed;
        observations["held_after_close"] = json!(f.counts());
        if case == "before_cleanup" {
            assert_eq!(f.kill(), None);
            assert_eq!(f.counts().0, 1);
            assert_eq!(f.counts().1, 1);
            observations["no_occupancy_authority_after_death"] = json!(dead(&f.w_pin));
        } else {
            let (certificate, first, replay) = f.cleanup(assignment);
            assert_eq!(f.counts(), (0, 0, 0));
            observations["cleanup_certificate"] = json!(certificate);
            observations["cleanup_commit"] = first;
            observations["cleanup_replay"] = replay;
            if case == "normal" {
                assert_eq!(f.kill(), None);
            } else {
                f.shutdown();
            }
        }
    }
    if let Some((output, expected)) = output {
        let (status, _, bytes) = f.client.artifact(&output).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, expected);
        observations["readback_after_worker_exit"] = json!(true);
    }
    observations["worker_counts"] = json!(worker_counts(&f.w_root));
    observations["claims_quota_outbox"] = json!(f.counts());
    write_evidence(case, &observations);
}

#[tokio::test]
async fn private_family() {
    match std::env::var("DIFFUSER_TYPED_PROOF_CASE") {
        Ok(case) => {
            assert!(CASES.contains(&case.as_str()));
            family_case(&case).await;
        }
        Err(_) => {
            for case in CASES {
                eprintln!("private CPU case {case}");
                family_case(case).await;
            }
        }
    }
}

#[path = "la_cuda_route_tests.rs"]
mod cuda_route_tests;

#[path = "la_cpu_product_loopback.rs"]
mod cpu_product_loopback;
