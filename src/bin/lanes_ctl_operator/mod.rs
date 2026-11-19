//! Explicit operator access to an already provisioned, trusted local endpoint.
use axum::{
    body::Bytes,
    http::{header, HeaderValue, Method, Request, Response},
};
use lane_router::lane_client as sdk;
use sdk::{
    Attempt, Client, CudaAcquire, CudaDeviceUuid, CudaSubmit, CudaWorkload, Error, Id, Identity,
    LaneSchema, ReceiptStore, Revision, TransportError,
};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::{self, Read},
    net::SocketAddrV4,
    os::unix::fs::OpenOptionsExt,
    time::Duration,
};
use zeroize::Zeroizing;

pub enum Failure {
    Local(i32, &'static str),
    Sdk(Error),
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Sdk(error)
    }
}
type Result<T> = std::result::Result<T, Failure>;
const USAGE: Failure = Failure::Local(64, "operator_usage");

pub fn emit(result: Result<Value>) -> i32 {
    let (exit, code) = match result {
        Ok(value) => {
            println!("{value}");
            return 0;
        }
        Err(Failure::Local(exit, code)) => (exit, code),
        Err(Failure::Sdk(Error::Public(error))) => {
            eprintln!(
                "{}",
                json!({"error": {"code":error.code.as_str(), "http_status":error.status.as_u16(),
                "retry_action":error.retry_action,"request_id":error.request_id,"object_id":error.object_id}})
            );
            return 74;
        }
        Err(Failure::Sdk(error)) => match error {
            Error::InvalidIdentifier => (64, "invalid_identifier"),
            Error::InvalidRequest => (64, "invalid_request"),
            Error::UnsupportedSelection => (64, "unsupported_selection"),
            Error::RequestLimit => (64, "request_limit"),
            Error::ReceiptIdentity => (74, "receipt_identity_mismatch"),
            Error::ReceiptMissing => (74, "receipt_missing"),
            Error::ReceiptConflict => (74, "receipt_conflict"),
            Error::ReceiptLimit => (74, "receipt_limit"),
            Error::ReceiptUncertain => (74, "receipt_uncertain"),
            Error::ReceiptStorage => (70, "receipt_storage_unavailable"),
            Error::ArtifactIntegrity => (74, "artifact_integrity"),
            Error::UnexpectedResponse(_) => (74, "unexpected_response"),
            Error::Transport(TransportError::Unavailable) => (75, "transport_unavailable"),
            Error::Transport(TransportError::ReplyLost) => (75, "reply_lost"),
            Error::Transport(TransportError::ResponseLimit) => (75, "response_limit"),
            Error::Public(_) => unreachable!(),
        },
    };
    eprintln!("{}", json!({"error":{"code":code}}));
    exit
}

struct LocalHttp {
    address: SocketAddrV4,
    identity: Identity,
    authorization: Option<HeaderValue>,
    http: reqwest::Client,
}

impl sdk::Transport for LocalHttp {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    async fn send(
        &self,
        request: Request<Bytes>,
        limits: sdk::ResponseLimits,
    ) -> std::result::Result<Response<Bytes>, TransportError> {
        let (mut parts, body) = request.into_parts();
        if parts.uri.scheme().is_some()
            || parts.uri.authority().is_some()
            || parts.uri.query().is_some()
            || !matches!(parts.method, Method::GET | Method::POST)
            || parts.headers.contains_key(header::AUTHORIZATION)
            || parts.headers.contains_key(header::HOST)
            || !(parts
                .uri
                .path()
                .starts_with(&format!("/v1/diffuser/projects/{}/", self.identity.project))
                || (parts.method == Method::GET && parts.uri.path() == "/v1/diffuser/discovery"))
        {
            return Err(TransportError::Unavailable);
        }
        if let Some(value) = &self.authorization {
            parts.headers.insert(header::AUTHORIZATION, value.clone());
        }
        let post = parts.method == Method::POST;
        let interrupted = if post {
            TransportError::ReplyLost
        } else {
            TransportError::Unavailable
        };
        let mut response = self
            .http
            .request(
                parts.method,
                format!("http://{}{}", self.address, parts.uri),
            )
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_connect() {
                    TransportError::Unavailable
                } else {
                    interrupted
                }
            })?;
        let status = response.status();
        let version = response.version();
        let headers = response.headers().clone();
        let cap = limits.for_status(status);
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| interrupted)? {
            if chunk.len() > cap - bytes.len() {
                return Err(TransportError::ResponseLimit);
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut reply = Response::new(bytes.into());
        *reply.status_mut() = status;
        *reply.version_mut() = version;
        *reply.headers_mut() = headers;
        Ok(reply)
    }
}

fn endpoint(value: &str) -> Result<SocketAddrV4> {
    let address = value
        .parse::<SocketAddrV4>()
        .map_err(|_| Failure::Local(64, "invalid_endpoint"))?;
    if *address.ip() != std::net::Ipv4Addr::LOCALHOST
        || address.port() == 0
        || address.to_string() != value
    {
        return Err(Failure::Local(64, "invalid_endpoint"));
    }
    Ok(address)
}

fn bearer() -> Result<HeaderValue> {
    const CAP: usize = 8192;
    let mut bytes = Zeroizing::new(b"Bearer ".to_vec());
    let prefix = bytes.len();
    let error = || Failure::Local(64, "invalid_bearer_stdin");
    io::stdin()
        .lock()
        .take((CAP + 3) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| error())?;
    if bytes.ends_with(b"\r\n") {
        let length = bytes.len() - 2;
        bytes.truncate(length);
    } else if bytes.ends_with(b"\n") {
        bytes.pop();
    }
    if !(1..=CAP).contains(&(bytes.len() - prefix))
        || !bytes[prefix..].iter().all(u8::is_ascii_graphic)
    {
        return Err(error());
    }
    let mut value = HeaderValue::from_bytes(&bytes).map_err(|_| error())?;
    value.set_sensitive(true);
    Ok(value)
}

fn id(s: &str) -> Result<Id> {
    Ok(Id::new(s)?)
}
fn integer(s: &str, min: u64) -> Result<u64> {
    if s.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(n) = s.parse::<u64>() {
            if (min..=i64::MAX as u64).contains(&n) {
                return Ok(n);
            }
        }
    }
    Err(Failure::Local(64, "invalid_integer"))
}

fn input(path: &str) -> Result<Bytes> {
    let unavailable = || Failure::Local(70, "input_unreadable");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| unavailable())?;
    if !file.metadata().map_err(|_| unavailable())?.is_file() {
        return Err(unavailable());
    }
    let mut bytes = Vec::new();
    file.take((sdk::ARTIFACT_MAX + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.is_empty() || bytes.len() > sdk::ARTIFACT_MAX {
        return Err(Error::RequestLimit.into());
    }
    Ok(bytes.into())
}

struct Mutation {
    store: ReceiptStore,
    key: Id,
    retry: bool,
}
impl Mutation {
    fn new(dir: &str, mode: &str, key: &str) -> Result<Self> {
        let retry = match mode {
            "start" => false,
            "retry" => true,
            _ => return Err(USAGE),
        };
        Ok(Self {
            key: id(key)?,
            store: ReceiptStore::open(dir)?,
            retry,
        })
    }
    fn attempt(&self) -> Attempt<'_> {
        if self.retry {
            Attempt::Retry(&self.key)
        } else {
            Attempt::Start(&self.key)
        }
    }
}

fn cuda_submit(
    name: &str,
    artifact: &str,
    runtime: &str,
    uuid: &str,
    workload: &str,
) -> Result<CudaSubmit> {
    if workload != "add_one" {
        return Err(Failure::Local(64, "unsupported_workload"));
    }
    Ok(CudaSubmit::new(
        id(name)?,
        id(artifact)?,
        CudaDeviceUuid::new(uuid)?,
        CudaWorkload::AddOne,
        integer(runtime, 1)?,
    )?)
}

fn manifest(value: &sdk::ArtifactManifest) -> Value {
    json!({"artifact_id":value.artifact_id,"sha256":value.sha256,"bytes":value.bytes,
        "media_type":value.media_type,"assignment_id":value.assignment_id,"job_id":value.job_id,
        "kind":value.kind,"expires_at":value.expires_at})
}

fn result_view(job: sdk::JobView, artifact: Option<sdk::VerifiedArtifact>) -> Result<Value> {
    let result = artifact
        .map(|artifact| {
            // The SDK has already verified the exact bytes and the family-specific report.
            let report: Value =
                serde_json::from_slice(&artifact.bytes).map_err(|_| Error::ArtifactIntegrity)?;
            Ok::<_, Error>(json!({"metadata":manifest(&artifact.metadata),"report":report}))
        })
        .transpose()?;
    Ok(json!({"job":job,"result":result}))
}

async fn execute(client: Client<LocalHttp>, args: &[&str]) -> Result<Value> {
    Ok(match args {
        ["discover"] => {
            let d = client.discover().await?;
            let lanes = d
                .lanes
                .into_iter()
                .map(|l| {
                    json!({"lane_id":l.lane_id,"capability":l.capability,
                "profile_id":l.profile_id,"accepting":l.accepting,"reason":l.reason})
                })
                .collect::<Vec<_>>();
            json!({"schema_version":d.schema_version,"queue_mode":d.queue_mode,"lanes":lanes})
        }
        ["assignment", assignment] => json!(client.assignment(&id(assignment)?).await?),
        ["job", job] => json!(client.job(&id(job)?).await?),
        ["artifact", artifact] => {
            let value = client.artifact_content(&id(artifact)?).await?;
            json!({"metadata":manifest(&value.metadata),"content_hex":hex::encode(value.bytes)})
        }
        ["upload", dir, mode, key, path] => {
            let bytes = input(path)?;
            let m = Mutation::new(dir, mode, key)?;
            let u = client.upload(&m.store, m.attempt(), bytes).await?;
            json!({"schema_version":u.schema_version,"receipt_id":u.receipt_id,"request_id":u.request_id,
                "project_id":u.project_id,"object_type":u.object_type,"object_id":u.object_id,"revision":u.revision,"state":u.state})
        }
        [command @ ("cpu-acquire" | "cuda-acquire"), dir, mode, key, pin, cpu, ram, storage, lease, tenure] =>
        {
            let (cpu, ram, storage, lease, tenure) = (
                integer(cpu, 1)?,
                integer(ram, 1)?,
                integer(storage, 1)?,
                integer(lease, 1)?,
                integer(tenure, 1)?,
            );
            let m = Mutation::new(dir, mode, key)?;
            let response = if *command == "cpu-acquire" {
                let body = sdk::Acquire {
                    schema_version: LaneSchema::V1,
                    capability: sdk::INSPECT_CAPABILITY.into(),
                    lane_id: id(pin)?.into(),
                    profile_id: sdk::INSPECT_PROFILE.into(),
                    resource_id: None,
                    provider_id: None,
                    requested_hardware_description: None,
                    resources: sdk::Resources {
                        cpu_millicores: cpu,
                        ram_bytes: ram,
                        storage_bytes: storage,
                        gpu_domains: vec![],
                    },
                    queue_policy: sdk::QueuePolicy::Refuse,
                    requested_lease_ms: lease,
                    requested_tenure_ms: tenure,
                };
                client.acquire(&m.store, m.attempt(), &body).await?
            } else {
                let body =
                    CudaAcquire::new(CudaDeviceUuid::new(*pin)?, cpu, ram, storage, lease, tenure)?;
                client.acquire_cuda(&m.store, m.attempt(), &body).await?
            };
            json!(response)
        }
        ["cpu-submit", dir, mode, key, assignment, name, artifact, runtime] => {
            let body = sdk::CpuSubmit::new(id(name)?, id(artifact)?, integer(runtime, 1)?)?;
            let m = Mutation::new(dir, mode, key)?;
            json!(
                client
                    .submit_cpu(&m.store, m.attempt(), &id(assignment)?, &body)
                    .await?
            )
        }
        ["cuda-submit", dir, mode, key, assignment, name, artifact, runtime, uuid, workload] => {
            let body = cuda_submit(name, artifact, runtime, uuid, workload)?;
            let m = Mutation::new(dir, mode, key)?;
            json!(
                client
                    .submit_cuda(&m.store, m.attempt(), &id(assignment)?, &body)
                    .await?
            )
        }
        ["cpu-resume", dir, key] => {
            let resumed = client
                .resume_cpu_job(&ReceiptStore::open(dir)?, &id(key)?)
                .await?;
            return result_view(resumed.job, resumed.result.map(|(artifact, _)| artifact));
        }
        ["cuda-resume", dir, key, name, artifact, runtime, uuid, workload] => {
            let body = cuda_submit(name, artifact, runtime, uuid, workload)?;
            let resumed = client
                .resume_cuda_job(&ReceiptStore::open(dir)?, &id(key)?, &body)
                .await?;
            return result_view(resumed.job, resumed.result.map(|(artifact, _)| artifact));
        }
        [command @ ("cancel" | "release"), dir, mode, key, target, revision] => {
            let target = id(target)?;
            let body = Revision {
                schema_version: LaneSchema::V1,
                expected_revision: integer(revision, 0)?,
            };
            let m = Mutation::new(dir, mode, key)?;
            if *command == "cancel" {
                json!(client.cancel(&m.store, m.attempt(), &target, &body).await?)
            } else {
                json!(
                    client
                        .release(&m.store, m.attempt(), &target, &body)
                        .await?
                )
            }
        }
        _ => return Err(USAGE),
    })
}

pub fn run(args: &[String]) -> Result<Value> {
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    if args == ["help"] {
        return Ok(
            json!({"usage":"lanes-ctl diffuser operator 127.0.0.1:PORT TENANT PROJECT ACTOR AUTH COMMAND [ARGS]",
            "auth":["bearer-stdin (existing scoped bearer, finish with EOF)", "anonymous (discover only)"],
            "commands":["discover","assignment ASSIGNMENT","job JOB","artifact ARTIFACT",
                "upload DIR MODE KEY INPUT_FILE",
                "cpu-acquire DIR MODE KEY LANE CPU_MILLICORES RAM_BYTES STORAGE_BYTES LEASE_MS TENURE_MS",
                "cuda-acquire DIR MODE KEY GPU_UUID CPU_MILLICORES RAM_BYTES STORAGE_BYTES LEASE_MS TENURE_MS",
                "cpu-submit DIR MODE KEY ASSIGNMENT CLIENT_JOB INPUT_ARTIFACT RUNTIME_MS",
                "cuda-submit DIR MODE KEY ASSIGNMENT CLIENT_JOB INPUT_ARTIFACT RUNTIME_MS GPU_UUID add_one",
                "cpu-resume DIR SUBMIT_KEY", "cuda-resume DIR SUBMIT_KEY CLIENT_JOB INPUT_ARTIFACT RUNTIME_MS GPU_UUID add_one",
                "cancel DIR MODE KEY JOB REVISION","release DIR MODE KEY ASSIGNMENT REVISION"],
            "mode":["start","retry (exact same intent/key)"], "receipt_directory":"caller-owned dedicated mode 0700",
            "transport":"trusted explicit IPv4 loopback only; no proxies, redirects or automatic retry"}),
        );
    }
    let [address, tenant, project, actor, auth, command @ ..] = args.as_slice() else {
        return Err(USAGE);
    };
    if command.is_empty() {
        return Err(USAGE);
    }
    let address = endpoint(address)?;
    let identity = Identity {
        tenant: id(tenant)?,
        project: id(project)?,
        actor: id(actor)?,
    };
    let authorization = match *auth {
        "anonymous" if command == ["discover"] => None,
        "bearer-stdin" => Some(bearer()?),
        _ => return Err(USAGE),
    };
    let http = reqwest::Client::builder()
        .http1_only()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| Failure::Local(75, "transport_unavailable"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Failure::Local(75, "transport_unavailable"))?;
    runtime.block_on(execute(
        Client::new(LocalHttp {
            address,
            identity,
            authorization,
            http,
        }),
        command,
    ))
}
