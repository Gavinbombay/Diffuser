// Test-only synthetic identity adapter for the actual private Axum router.
use super::*;
use axum::{
    body::{to_bytes, Bytes},
    http::{header, HeaderValue},
};
use lane_router::lane_client::*;

struct FixtureTransport {
    app: Router,
    identity: Identity,
    authorization: Option<HeaderValue>,
    requests: Arc<Mutex<Vec<Recorded>>>,
    request_edit: Option<Box<RequestEdit>>,
    response_edit: Option<Box<ResponseEdit>>,
}

impl Transport for FixtureTransport {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    async fn send(
        &self,
        mut request: WireRequest,
        limits: ResponseLimits,
    ) -> std::result::Result<axum::http::Response<Bytes>, TransportError> {
        if let Some(edit) = &self.request_edit {
            edit(&mut request);
        }
        assert!(!request.headers().contains_key(header::AUTHORIZATION));
        let method = request.method().clone();
        let path = request.uri().to_string();
        let headers = request.headers().clone();
        let payload = request.body().clone();
        let mut request = request.map(Body::from);
        if let Some(value) = &self.authorization {
            request
                .headers_mut()
                .insert(header::AUTHORIZATION, value.clone());
        }
        let (parts, body) = self
            .app
            .clone()
            .oneshot(request)
            .await
            .unwrap()
            .into_parts();
        let bytes = to_bytes(body, limits.for_status(parts.status))
            .await
            .map_err(|_| TransportError::ResponseLimit)?;
        let response_type = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.requests.lock().unwrap().push(Recorded {
            method,
            path,
            headers,
            body: payload,
            status: parts.status,
            response_type,
            response_body: bytes.clone(),
        });
        let mut response = axum::http::Response::from_parts(parts, bytes);
        if let Some(edit) = &self.response_edit {
            edit(&mut response)?;
        }
        Ok(response)
    }
}

fn fixture_identity() -> Identity {
    Identity {
        tenant: id("tenant_123456789"),
        project: id("project_12345678"),
        actor: id("agent_1234567890"),
    }
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn fixture_header(token: &str) -> HeaderValue {
    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    value.set_sensitive(true);
    value
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn spine(root: PathBuf) -> Spine {
    Spine {
        root,
        edge: false,
        worker_ports: [0, 0],
        admin: false,
        sequence: Arc::new(Mutex::new(0)),
    }
}

fn public(error: Error, status: StatusCode, code: PublicCode) {
    let Error::Public(error) = error else {
        panic!("expected public error, got {error:?}");
    };
    assert_eq!((error.status, error.code), (status, code));
}

#[tokio::test]
async fn discovery_uses_fixture_authority_and_negotiates_the_exact_v1_selection() {
    let (authority, _, agent) = fixture_discovery_context(now_ms());
    let app = api_with_namespace(
        spine(std::env::temp_dir()),
        super::super::lane_assignment::injected_router(authority),
    );
    let transport = |authorization| FixtureTransport {
        app: app.clone(),
        identity: fixture_identity(),
        authorization,
        requests: Arc::default(),
        request_edit: None,
        response_edit: None,
    };
    let client = Client::new(transport(Some(fixture_header(&agent))));
    let discovery = client.discover().await.unwrap();
    let lane = discovery
        .negotiate(
            "lane_cpu_inspect",
            "artifact.inspect.sha256/v1",
            "cpu-artifact-inspect/v1",
            "1",
        )
        .unwrap();
    assert!(!lane.accepting);
    assert_eq!(
        discovery.negotiate(
            "lane_cpu_inspect",
            "artifact.inspect.sha256/v1",
            "cpu-artifact-inspect/v1",
            "2"
        ),
        Err(Error::UnsupportedSelection)
    );
    let error = Client::new(transport(None)).discover().await.unwrap_err();
    assert!(!format!("{discovery:?} {error:?} {client:?}").contains(&agent));
    public(error, StatusCode::UNAUTHORIZED, PublicCode::AuthRequired);
}

struct PrivateRoot(PathBuf);

impl PrivateRoot {
    fn new() -> Self {
        let mut nonce = [0u8; 16];
        assert_eq!(
            unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) },
            nonce.len() as isize
        );
        let root = std::env::temp_dir().join(format!("lane-client-{}", hex::encode(nonce)));
        private_dir(&root);
        Self(root)
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn private_dir(path: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

type WireRequest = axum::http::Request<Bytes>;
type WireResponse = axum::http::Response<Bytes>;
type RequestEdit = dyn Fn(&mut WireRequest) + Send + Sync;
type ResponseEdit =
    dyn Fn(&mut WireResponse) -> std::result::Result<(), TransportError> + Send + Sync;

#[derive(Clone)]
#[cfg_attr(not(feature = "contract-docs"), allow(dead_code))]
struct Recorded {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Bytes,
    status: StatusCode,
    response_type: String,
    response_body: Bytes,
}

struct Fixture {
    app: Router,
    agent: zeroize::Zeroizing<String>,
    root: PrivateRoot,
    work_entries: Arc<Mutex<Vec<(String, String)>>>,
}

impl Fixture {
    fn new() -> Self {
        Self::with_worker(None)
    }

    // Bounded, in-process CPU fixture. No server socket or worker process.
    fn with_worker(execute: Option<bool>) -> Self {
        Self::with_backend(execute, false)
    }

    fn with_backend(execute: Option<bool>, typed: bool) -> Self {
        use super::super::{la_artifacts, la_backend, la_store, la_worker, lane_assignment};
        let root = PrivateRoot::new();
        let service = root.0.join("service");
        private_dir(&service);
        let (mut authority, _, agent) = fixture_discovery_context(now_ms());
        for grant in &mut authority.grants {
            grant.scopes = 2047;
        }
        let artifacts = la_artifacts::ArtifactStore::open(&service).unwrap();
        let work_entries = Arc::new(Mutex::new(Vec::new()));
        let namespace = match execute {
            Some(execute) => {
                let worker = root.0.join("worker");
                private_dir(&worker);
                let mut journal = la_worker::OperationJournal::bootstrap(
                    &worker.join("worker.sqlite"),
                    "custody_12345678",
                )
                .unwrap();
                if typed {
                    let entries = work_entries.clone();
                    journal
                        .observe_work_entry(Arc::new(move |operation, job| {
                            entries.lock().unwrap().push((operation.into(), job.into()));
                            Ok(())
                        }))
                        .unwrap();
                    journal
                        .attach_backend(Box::new(la_backend::PrivateProcess::launch().unwrap()))
                        .unwrap();
                }
                lane_assignment::fixture_worker_router(
                    Arc::new(std::sync::RwLock::new(authority)),
                    artifacts,
                    la_store::ClaimStore::open(&service.join("claims.sqlite")).unwrap(),
                    journal,
                    la_worker::ReservationSession {
                        worker: "worker_123456789".into(),
                        boot: "boot_12345678901".into(),
                        key: [42; 32],
                    },
                    execute,
                )
            }
            None => lane_assignment::injected_service_router(authority, artifacts),
        };
        let app = api_with_namespace(spine(root.0.clone()), namespace);
        Self {
            app,
            agent: zeroize::Zeroizing::new(agent),
            root,
            work_entries,
        }
    }

    fn claims(&self) -> super::super::la_store::ClaimStore {
        super::super::la_store::ClaimStore::open(&self.root.0.join("service/claims.sqlite"))
            .unwrap()
    }

    fn row_count(&self, sql: &str) -> i64 {
        count_rows(&self.root.0.join("service/claims.sqlite"), sql)
    }

    fn worker_row_count(&self, sql: &str) -> i64 {
        count_rows(&self.root.0.join("worker/worker.sqlite"), sql)
    }

    fn transport(&self) -> FixtureTransport {
        FixtureTransport {
            app: self.app.clone(),
            identity: fixture_identity(),
            authorization: Some(fixture_header(&self.agent)),
            requests: Arc::default(),
            request_edit: None,
            response_edit: None,
        }
    }

    fn journal(&self, name: &str) -> ReceiptStore {
        let dir = self.root.0.join(name);
        private_dir(&dir);
        ReceiptStore::open(dir).unwrap()
    }
}

fn count_rows(path: &Path, sql: &str) -> i64 {
    rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap()
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

#[tokio::test]
async fn immutable_artifact_requests_reach_the_router_and_verify_content() {
    let fixture = Fixture::new();
    let journal = fixture.journal("receipts");
    let transport = fixture.transport();
    let requests = transport.requests.clone();
    let client = Client::new(transport);
    let payload = Bytes::from_static(b"small synthetic artifact\0");
    let key = id("upload_fixture_001");
    let uploaded = client
        .upload(&journal, Attempt::Start(&key), payload.clone())
        .await
        .unwrap();
    let metadata = client.artifact_metadata(&uploaded.object_id).await.unwrap();
    let verified = client.artifact_content(&uploaded.object_id).await.unwrap();
    assert_eq!(verified.bytes, payload);
    assert_eq!(verified.metadata, metadata);
    assert_eq!(metadata.bytes, payload.len() as u64);
    assert_eq!(metadata.sha256, Sha256Digest::of(&payload));
    assert_eq!(metadata.actor_id, fixture_identity().actor);
    assert_eq!(metadata.project_id, fixture_identity().project);
    let saved = journal.read(&fixture_identity(), &key).unwrap();
    assert!(saved.returned.is_some());
    let receipts = fs::read_to_string(fixture.root.0.join("receipts/journal.json")).unwrap();
    let diagnostic = format!("{client:?} {verified:?} {uploaded:?} {saved:?}");
    assert!(!receipts.contains(fixture.agent.as_str()));
    assert!(!diagnostic.contains(fixture.agent.as_str()));
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    let artifact_path = format!(
        "/v1/diffuser/projects/project_12345678/artifacts/{}",
        uploaded.object_id
    );
    assert_eq!(
        requests[0].path,
        "/v1/diffuser/projects/project_12345678/artifacts"
    );
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(requests[0].status, StatusCode::CREATED);
    assert_eq!(requests[0].headers["idempotency-key"], key.as_str());
    assert_eq!(
        requests[0].headers["x-diffuser-schema"],
        "diffuser-artifact/v1"
    );
    assert_eq!(
        requests[0].headers["x-content-sha256"],
        metadata.sha256.as_str()
    );
    assert_eq!(
        requests[0].headers[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        requests[0].headers[header::CONTENT_LENGTH]
            .to_str()
            .unwrap(),
        payload.len().to_string()
    );
    assert_eq!(requests[0].body, payload);
    assert_eq!(requests[1].path, artifact_path);
    assert_eq!(requests[2].path, artifact_path);
    assert_eq!(requests[3].path, format!("{artifact_path}/content"));
    for request in &requests[1..] {
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.status, StatusCode::OK);
        assert!(request.headers.is_empty());
        assert!(request.body.is_empty());
    }
}

#[tokio::test]
async fn artifact_single_faults_and_cross_project_reach_exact_boundaries() {
    let fixture = Fixture::new();
    let journal = fixture.journal("receipts");
    let payload = Bytes::from_static(b"synthetic boundary baseline");
    for (index, (edit, status, code)) in [
        (
            (|r: &mut WireRequest| {
                r.headers_mut().insert(
                    "x-diffuser-schema",
                    HeaderValue::from_static("diffuser-artifact/v2"),
                )
            }) as fn(&mut WireRequest) -> Option<HeaderValue>,
            StatusCode::BAD_REQUEST,
            PublicCode::VersionUnsupported,
        ),
        (
            |r| {
                let body = Bytes::from(vec![0; ARTIFACT_MAX + 1]);
                r.headers_mut().insert(
                    "x-content-sha256",
                    HeaderValue::from_str(Sha256Digest::of(&body).as_str()).unwrap(),
                );
                *r.body_mut() = body;
                r.headers_mut().remove(header::CONTENT_LENGTH)
            },
            StatusCode::PAYLOAD_TOO_LARGE,
            PublicCode::BodyTooLarge,
        ),
        (
            |r| {
                r.headers_mut().insert(
                    "x-content-sha256",
                    HeaderValue::from_static(
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    ),
                )
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            PublicCode::ArtifactInvalid,
        ),
        (
            |r| {
                r.headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from_static("1"))
            },
            StatusCode::UNPROCESSABLE_ENTITY,
            PublicCode::ArtifactInvalid,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut transport = fixture.transport();
        transport.request_edit = Some(Box::new(move |r| {
            edit(r);
        }));
        let key = id(&format!("fault_fixture_{index:03}"));
        let error = Client::new(transport)
            .upload(&journal, Attempt::Start(&key), payload.clone())
            .await
            .unwrap_err();
        assert!(!format!("{error:?} {error}").contains(fixture.agent.as_str()));
        public(error, status, code);
    }

    let mut foreign = fixture.transport();
    foreign.request_edit = Some(Box::new(|r| {
        *r.uri_mut() = "/v1/diffuser/projects/foreign_project_01/artifacts"
            .parse()
            .unwrap();
    }));
    let key = id("foreign_upload_01");
    public(
        Client::new(foreign)
            .upload(&journal, Attempt::Start(&key), payload.clone())
            .await
            .unwrap_err(),
        StatusCode::NOT_FOUND,
        PublicCode::ObjectNotFound,
    );
    let mut foreign = fixture.transport();
    foreign.identity.project = id("foreign_project_01");
    let requests = foreign.requests.clone();
    assert_eq!(
        Client::new(foreign)
            .upload(&journal, Attempt::Retry(&key), payload.clone())
            .await,
        Err(Error::ReceiptIdentity)
    );
    assert!(requests.lock().unwrap().is_empty());
    let mut unauthenticated = fixture.transport();
    unauthenticated.authorization = None;
    public(
        Client::new(unauthenticated)
            .artifact_metadata(&id("missing_artifact_01"))
            .await
            .unwrap_err(),
        StatusCode::UNAUTHORIZED,
        PublicCode::AuthRequired,
    );
    for bad in [
        "../../elsewhere_123",
        "https://host/path",
        "encoded%2fpath_012",
        " padded_value_012 ",
    ] {
        assert_eq!(Id::new(bad), Err(Error::InvalidIdentifier));
    }
}

#[tokio::test]
async fn artifact_content_refuses_corruption_truncation_and_bad_counts() {
    let fixture = Fixture::new();
    let journal = fixture.journal("receipts");
    let original = Bytes::from_static(b"synthetic");
    let uploaded = Client::new(fixture.transport())
        .upload(
            &journal,
            Attempt::Start(&id("upload_fixture_001")),
            original.clone(),
        )
        .await
        .unwrap();
    for case in 0..4 {
        let mut transport = fixture.transport();
        transport.response_edit = Some(Box::new(move |response| {
            let is_content = response.headers()[header::CONTENT_TYPE] == "application/octet-stream";
            match case {
                0 if is_content => *response.body_mut() = Bytes::from_static(b"corrupted"),
                1 if is_content => *response.body_mut() = Bytes::from_static(b"syntheti"),
                2 if !is_content => {
                    let mut manifest: Value = serde_json::from_slice(response.body()).unwrap();
                    manifest["bytes"] = json!(10);
                    *response.body_mut() = serde_json::to_vec(&manifest).unwrap().into();
                }
                3 if !is_content => {
                    let mut manifest: Value = serde_json::from_slice(response.body()).unwrap();
                    manifest["sha256"] =
                        json!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                    *response.body_mut() = serde_json::to_vec(&manifest).unwrap().into();
                }
                _ => return Ok(()),
            }
            // Model a complete HTTP frame with corrupt payload/metadata.
            let length = response.body().len();
            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
            Ok(())
        }));
        assert_eq!(
            Client::new(transport)
                .artifact_content(&uploaded.object_id)
                .await,
            Err(Error::ArtifactIntegrity),
            "case {case}",
        );
    }
}

fn acquire_body() -> Acquire {
    Acquire {
        schema_version: LaneSchema::V1,
        capability: INSPECT_CAPABILITY.into(),
        lane_id: "lane_cpu_inspect".into(),
        profile_id: INSPECT_PROFILE.into(),
        resource_id: None,
        provider_id: None,
        requested_hardware_description: None,
        resources: Resources {
            cpu_millicores: 1000,
            ram_bytes: 16 * 1024 * 1024,
            storage_bytes: 2 * 1024 * 1024,
            gpu_domains: vec![],
        },
        queue_policy: QueuePolicy::Refuse,
        requested_lease_ms: 10_000,
        requested_tenure_ms: 60_000,
    }
}

#[tokio::test]
async fn assignment_acquire_read_renew_and_release_parse_the_current_routes() {
    let fixture = Fixture::with_worker(Some(false));
    let journal = fixture.journal("receipts");
    let transport = fixture.transport();
    let requests = transport.requests.clone();
    let client = Client::new(transport);
    let acquired = client
        .acquire(
            &journal,
            Attempt::Start(&id("fixture_acquire_01")),
            &acquire_body(),
        )
        .await
        .unwrap();
    assert_eq!(acquired.state, AssignmentState::Assigned);
    let assignment = &acquired.assignment_id;
    let view = client.assignment(assignment).await.unwrap();
    assert_eq!(view.revision, 0);
    assert_eq!(view.state, AssignmentState::Assigned);
    let renew = Renew {
        schema_version: LaneSchema::V1,
        expected_revision: view.revision,
        requested_lease_ms: 20_000,
    };
    let renewed = client
        .renew(
            &journal,
            Attempt::Start(&id("fixture_renew_001")),
            assignment,
            &renew,
        )
        .await
        .unwrap();
    assert!(renewed.acknowledged_lease().unwrap() > acquired.lease_expires_at);
    assert_eq!(renewed.revision, 1);

    let release = Revision {
        schema_version: LaneSchema::V1,
        expected_revision: renewed.revision,
    };
    let key = id("fixture_release_01");
    for attempt in [Attempt::Start(&key), Attempt::Retry(&key)] {
        let response = client
            .release(&journal, attempt, assignment, &release)
            .await
            .unwrap();
        assert_eq!(response.state, AssignmentState::Draining);
        assert!(!response.released());
    }
    let held = client.assignment(assignment).await.unwrap();
    assert_eq!(held.state, AssignmentState::Draining);
    let counts = fixture.claims().counts().unwrap();
    assert_eq!((counts.0, counts.1), (1, 1));
    assert!(fixture
        .claims()
        .assignment_stop_recorded(assignment.as_str())
        .unwrap());
    assert_eq!(
        fixture.row_count("SELECT COUNT(*) FROM la_close_intents"),
        1
    );
    let requests = requests.lock().unwrap();
    let path = format!("/v1/diffuser/projects/project_12345678/assignments/{assignment}");
    assert_json_request(
        &requests[0],
        "/v1/diffuser/projects/project_12345678/assignments",
        "fixture_acquire_01",
        StatusCode::ACCEPTED,
        &json!({
            "schema_version": "diffuser-lane/v1", "capability": "artifact.inspect.sha256/v1",
            "lane_id": "lane_cpu_inspect", "profile_id": "cpu-artifact-inspect/v1",
            "resource_id": null, "provider_id": null, "requested_hardware_description": null,
            "resources": {"cpu_millicores": 1000, "ram_bytes": 16777216, "storage_bytes": 2097152, "gpu_domains": []},
            "queue_policy": "refuse", "requested_lease_ms": 10000, "requested_tenure_ms": 60000
        }),
    );
    assert_get(&requests[1], &path, StatusCode::OK);
    assert_json_request(
        &requests[2],
        &format!("{path}/renew"),
        "fixture_renew_001",
        StatusCode::OK,
        &json!({
            "schema_version": "diffuser-lane/v1", "expected_revision": 0, "requested_lease_ms": 20000
        }),
    );
    for request in &requests[3..5] {
        assert_json_request(
            request,
            &format!("{path}/release"),
            key.as_str(),
            StatusCode::ACCEPTED,
            &json!({
                "schema_version": "diffuser-lane/v1", "expected_revision": 1
            }),
        );
    }
    assert_get(&requests[5], &path, StatusCode::OK);
}

fn assert_json_request(record: &Recorded, path: &str, key: &str, status: StatusCode, body: &Value) {
    assert_eq!(record.path, path);
    assert_eq!(record.method, Method::POST);
    assert_eq!(record.headers["idempotency-key"], key);
    assert_eq!(record.headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(record.status, status);
    assert_eq!(
        &serde_json::from_slice::<Value>(&record.body).unwrap(),
        body
    );
}

fn assert_get(record: &Recorded, path: &str, status: StatusCode) {
    assert_eq!(record.path, path);
    assert_eq!(record.method, Method::GET);
    assert_eq!(record.status, status);
    assert!(record.headers.is_empty());
    assert!(record.body.is_empty());
}

fn json_request_edit(request: &mut WireRequest, edit: impl FnOnce(&mut Value)) {
    let mut body: Value = serde_json::from_slice(request.body()).unwrap();
    edit(&mut body);
    *request.body_mut() = serde_json::to_vec(&body).unwrap().into();
    let length = request.body().len();
    request
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
}

#[tokio::test]
async fn assignment_refusals_reach_auth_schema_limits_and_explicit_selection() {
    let fixture = Fixture::with_worker(Some(false));
    let journal = fixture.journal("receipts");
    let missing = id("missing_fixture_01");
    let mut transport = fixture.transport();
    transport.authorization = None;
    let client = Client::new(transport);
    let revision = Revision {
        schema_version: LaneSchema::V1,
        expected_revision: 0,
    };
    public(
        client.assignment(&missing).await.unwrap_err(),
        StatusCode::UNAUTHORIZED,
        PublicCode::AuthRequired,
    );
    public(
        client
            .release(
                &journal,
                Attempt::Start(&id("unauth_release_01")),
                &missing,
                &revision,
            )
            .await
            .unwrap_err(),
        StatusCode::UNAUTHORIZED,
        PublicCode::AuthRequired,
    );
    public(
        Client::new(fixture.transport())
            .assignment(&missing)
            .await
            .unwrap_err(),
        StatusCode::NOT_FOUND,
        PublicCode::ObjectNotFound,
    );

    type RequestFault = (fn(&mut WireRequest), StatusCode, PublicCode);
    let faults: [RequestFault; 3] = [
        (
            |request| {
                json_request_edit(request, |json| {
                    json.as_object_mut().unwrap().remove("profile_id");
                })
            },
            StatusCode::BAD_REQUEST,
            PublicCode::SchemaInvalid,
        ),
        (
            |request| {
                json_request_edit(request, |json| {
                    json["schema_version"] = json!("diffuser-lane/v2");
                })
            },
            StatusCode::BAD_REQUEST,
            PublicCode::VersionUnsupported,
        ),
        (
            |request| {
                let mut too_big = request.body().to_vec();
                too_big.resize(JSON_MAX + 1, b' ');
                *request.body_mut() = too_big.into();
                request
                    .headers_mut()
                    .insert(header::CONTENT_LENGTH, HeaderValue::from(JSON_MAX + 1));
            },
            StatusCode::PAYLOAD_TOO_LARGE,
            PublicCode::BodyTooLarge,
        ),
    ];
    for (index, (edit, status, code)) in faults.into_iter().enumerate() {
        let mut transport = fixture.transport();
        transport.request_edit = Some(Box::new(edit));
        let key = id(&format!("fault_acquire_{index:03}"));
        let error = Client::new(transport)
            .acquire(&journal, Attempt::Start(&key), &acquire_body())
            .await
            .unwrap_err();
        public(error, status, code);
    }

    let mut choices = [
        (
            acquire_body(),
            StatusCode::UNPROCESSABLE_ENTITY,
            PublicCode::ProviderUnconfigured,
        ),
        (
            acquire_body(),
            StatusCode::NOT_FOUND,
            PublicCode::LaneNotFound,
        ),
        (
            acquire_body(),
            StatusCode::UNPROCESSABLE_ENTITY,
            PublicCode::CapabilityUnavailable,
        ),
        (
            acquire_body(),
            StatusCode::NOT_IMPLEMENTED,
            PublicCode::UnsupportedOperation,
        ),
    ];
    choices[0].0.provider_id = Some("colab".into());
    choices[1].0.resource_id = Some("explicit_missing_device".into());
    choices[2]
        .0
        .resources
        .gpu_domains
        .push("gpu_explicit_unavailable".into());
    choices[3].0.queue_policy = QueuePolicy::FairQueue;
    for (index, (choice, status, code)) in choices.into_iter().enumerate() {
        let key = id(&format!("pinned_choice_{index:03}"));
        let client = Client::new(fixture.transport());
        public(
            client
                .acquire(&journal, Attempt::Start(&key), &choice)
                .await
                .unwrap_err(),
            status,
            code,
        );
    }
    assert_eq!(fixture.claims().counts().unwrap(), (0, 0, 0));
}

#[tokio::test]
async fn pending_renewal_does_not_extend_guarantee() {
    let fixture = Fixture::with_worker(Some(false));
    let journal = fixture.journal("receipts");
    let client = Client::new(fixture.transport());
    let acquired = client
        .acquire(
            &journal,
            Attempt::Start(&id("fixture_acquire_01")),
            &acquire_body(),
        )
        .await
        .unwrap();
    let renew = Renew {
        schema_version: LaneSchema::V1,
        expected_revision: 0,
        requested_lease_ms: 20_000,
    };
    let mut transport = fixture.transport();
    // Inject a correctly shaped pending reply at the consumer boundary.
    // The real handler above this overlay actually acknowledges the renewal.
    transport.response_edit = Some(Box::new(|response| {
        let mut body: Value = serde_json::from_slice(response.body()).unwrap();
        body["renewal_state"] = json!("pending");
        replace_json_reply(response, &body);
        *response.status_mut() = StatusCode::ACCEPTED;
        Ok(())
    }));
    let result = Client::new(transport)
        .renew(
            &journal,
            Attempt::Start(&id("pending_renewal_01")),
            &acquired.assignment_id,
            &renew,
        )
        .await
        .unwrap();
    assert_eq!(result.renewal_state, RenewalState::Pending);
    assert_eq!(result.acknowledged_lease(), None);
}

fn replace_json_reply(response: &mut WireResponse, body: &Value) {
    *response.body_mut() = serde_json::to_vec(body).unwrap().into();
    let len = response.body().len();
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
}

fn submit_body(input: Id) -> Submit {
    Submit {
        schema_version: LaneSchema::V1,
        client_job_id: id("client_job_001AbC"),
        capability: INSPECT_CAPABILITY.into(),
        profile_version: INSPECT_REVISION.into(),
        input_artifact_ids: [input],
        parameters: InspectParameters {},
        max_runtime_ms: 4_000,
        disconnect_policy: DisconnectPolicy::ContinueUntilJobDeadline,
    }
}

async fn upload_and_acquire(
    client: &Client<FixtureTransport>,
    journal: &ReceiptStore,
    input: Bytes,
) -> (Id, Id) {
    let artifact = client
        .upload(journal, Attempt::Start(&id("fixture_upload_001")), input)
        .await
        .unwrap();
    let assignment = client
        .acquire(
            journal,
            Attempt::Start(&id("fixture_acquire_01")),
            &acquire_body(),
        )
        .await
        .unwrap();
    assert_eq!(assignment.state, AssignmentState::Assigned);
    (artifact.object_id, assignment.assignment_id)
}

#[cfg(feature = "contract-docs")]
#[tokio::test]
async fn sdk_v2_cpu_lost_reply_reconnects_and_verifies_once() {
    let fixture = Fixture::with_backend(Some(true), true);
    let journal = fixture.journal("typed-receipts");
    let input = Bytes::from_static(
        br#"{"schema_version":"diffuser-private-sha256-input/v1","data_hex":"616263","rounds":2}"#,
    );
    let client = Client::new(fixture.transport());
    let (artifact_id, assignment) = upload_and_acquire(&client, &journal, input.clone()).await;
    let job_id = id("typed_client_job_01");
    let key = id("typed_cpu_submit_01");
    let body = CpuSubmit::new(job_id.clone(), artifact_id.clone(), 4000).unwrap();
    for invalid in [0, i64::MAX as u64 + 1] {
        assert_eq!(
            CpuSubmit::new(job_id.clone(), artifact_id.clone(), invalid),
            Err(Error::InvalidRequest)
        );
    }
    let mut transport = fixture.transport();
    let first = transport.requests.clone();
    let sent_key = key.clone();
    let at_send = ReceiptStore::open(fixture.root.0.join("typed-receipts")).unwrap();
    transport.request_edit = Some(Box::new(move |request| {
        let receipt = at_send.read(&fixture_identity(), &sent_key).unwrap();
        assert!(receipt.returned.is_none());
        assert_eq!(receipt.intent.body_sha256, Sha256Digest::of(request.body()));
    }));
    transport.response_edit = Some(Box::new(|response| {
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let job: JobAccepted = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(job.state, JobState::Succeeded);
        Err(TransportError::ReplyLost)
    }));
    let client = Client::new(transport);
    assert_eq!(
        client
            .submit_cpu(&journal, Attempt::Start(&key), &assignment, &body)
            .await,
        Err(Error::Transport(TransportError::ReplyLost))
    );
    let assert_once = || {
        assert_eq!(fixture.claims().job_history_count().unwrap(), 1);
        assert_eq!(fixture.work_entries.lock().unwrap().len(), 1);
        for table in [
            "operations",
            "worker_inspect_commands",
            "worker_result_receipts",
        ] {
            assert_eq!(
                fixture.worker_row_count(&format!("SELECT COUNT(*) FROM {table}")),
                1
            );
        }
        assert_eq!(
            fixture.worker_row_count("SELECT COUNT(*) FROM operations WHERE state='complete'"),
            1
        );
    };
    assert_once();
    drop(client);
    drop(journal);

    let journal = ReceiptStore::open(fixture.root.0.join("typed-receipts")).unwrap();
    let transport = fixture.transport();
    let replay = transport.requests.clone();
    let client = Client::new(transport);
    assert_eq!(
        client.resume_cpu_job(&journal, &key).await,
        Err(Error::ReceiptUncertain)
    );
    assert_eq!(
        client.resume_job(&journal, &key).await,
        Err(Error::ReceiptConflict)
    );
    let different = CpuSubmit::new(job_id, artifact_id.clone(), 4001).unwrap();
    assert_eq!(
        client
            .submit_cpu(&journal, Attempt::Retry(&key), &assignment, &different)
            .await,
        Err(Error::ReceiptConflict)
    );
    let legacy = submit_body(artifact_id.clone());
    assert_eq!(
        client
            .submit(&journal, Attempt::Retry(&key), &assignment, &legacy)
            .await,
        Err(Error::ReceiptConflict)
    );
    assert_eq!(
        client
            .submit(
                &journal,
                Attempt::Start(&id("legacy_submit_new01")),
                &assignment,
                &legacy
            )
            .await,
        Err(Error::ReceiptConflict)
    );
    assert!(replay.lock().unwrap().is_empty());
    let accepted = client
        .submit_cpu(&journal, Attempt::Retry(&key), &assignment, &body)
        .await
        .unwrap();
    {
        let first = first.lock().unwrap();
        let replay = replay.lock().unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(replay.len(), 1);
        assert_eq!(first[0].body, replay[0].body);
        assert_eq!(first[0].response_body, replay[0].response_body);
        let mut golden: Value = serde_json::from_str(include_str!(
            "../../docs/cosp/lane-client-cpu-v2.golden.json"
        ))
        .unwrap();
        golden["input_artifact_ids"][0] = json!(artifact_id);
        assert_json_request(
            &replay[0],
            &format!("/v1/diffuser/projects/project_12345678/assignments/{assignment}/jobs"),
            key.as_str(),
            StatusCode::ACCEPTED,
            &golden,
        );
    }
    assert_once();
    drop(client);
    drop(journal);

    let journal = ReceiptStore::open(fixture.root.0.join("typed-receipts")).unwrap();
    let mut corrupt = fixture.transport();
    corrupt.response_edit = Some(Box::new(|response| {
        if response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v == "application/octet-stream")
        {
            let mut bytes = response.body().to_vec();
            bytes[0] ^= 1;
            *response.body_mut() = bytes.into();
        }
        Ok(())
    }));
    assert_eq!(
        Client::new(corrupt).resume_cpu_job(&journal, &key).await,
        Err(Error::ArtifactIntegrity)
    );
    assert_eq!(
        journal
            .read(&fixture_identity(), &key)
            .unwrap()
            .returned
            .unwrap()
            .result_artifact_id,
        None
    );
    let transport = fixture.transport();
    let readback = transport.requests.clone();
    let resumed = Client::new(transport)
        .resume_cpu_job(&journal, &key)
        .await
        .unwrap();
    assert_eq!(resumed.job.job_id, accepted.job_id);
    assert_eq!(
        fixture.work_entries.lock().unwrap()[0].1,
        accepted.job_id.as_str()
    );
    let (artifact, report) = resumed.result.unwrap();
    assert_eq!(report.job_id, accepted.job_id);
    assert_eq!(report.sha256, Sha256Digest::of(&input));
    assert_eq!(report.bytes, input.len() as u64);
    assert_eq!((report.data_bytes, report.rounds), (3, 2));
    let first_digest = hex::decode(Sha256Digest::of(b"abc").as_str()).unwrap();
    assert_eq!(report.output_sha256, Sha256Digest::of(&first_digest));
    assert_eq!(artifact.metadata.sha256, Sha256Digest::of(&artifact.bytes));
    assert_eq!(artifact.metadata.bytes, artifact.bytes.len() as u64);
    let output = &artifact.metadata.artifact_id;
    assert_eq!(
        journal
            .read(&fixture_identity(), &key)
            .unwrap()
            .returned
            .unwrap()
            .result_artifact_id
            .as_ref(),
        Some(output)
    );
    let readback = readback.lock().unwrap();
    assert_eq!(readback.len(), 3);
    let prefix = "/v1/diffuser/projects/project_12345678";
    assert_get(
        &readback[0],
        &format!("{prefix}/jobs/{}", accepted.job_id),
        StatusCode::OK,
    );
    assert_get(
        &readback[1],
        &format!("{prefix}/artifacts/{output}"),
        StatusCode::OK,
    );
    assert_get(
        &readback[2],
        &format!("{prefix}/artifacts/{output}/content"),
        StatusCode::OK,
    );
    assert_once();
}

#[tokio::test]
async fn sdk_v2_cpu_refuses_unavailable_backend_without_downgrade() {
    // Exactly the same assignment and input accept a legacy inspection. The
    // explicit CPU v2 submission must instead fail on backend admission.
    let fixture = Fixture::with_worker(Some(true));
    let journal = fixture.journal("cpu-unavailable");
    let client = Client::new(fixture.transport());
    let (input, assignment) = upload_and_acquire(&client, &journal, Bytes::from_static(
        br#"{"schema_version":"diffuser-private-sha256-input/v1","data_hex":"616263","rounds":2}"#,
    )).await;
    let transport = fixture.transport();
    let captured = transport.requests.clone();
    let client = Client::new(transport);
    let key = id("cpu_unavailable_001");
    let body = CpuSubmit::new(id("sdk_cpu_unavail_job"), input.clone(), 4000).unwrap();
    public(
        client
            .submit_cpu(&journal, Attempt::Start(&key), &assignment, &body)
            .await
            .unwrap_err(),
        StatusCode::UNPROCESSABLE_ENTITY,
        PublicCode::CapabilityUnavailable,
    );
    {
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let request: Value = serde_json::from_slice(&captured[0].body).unwrap();
        assert_eq!(request["schema_version"], "diffuser-lane/v2");
        assert_eq!(request["parameters"]["backend"], "cpu-private-sha256/v1");
    }
    assert_eq!(fixture.claims().job_history_count().unwrap(), 0);
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations"),
        0
    );
    assert!(journal
        .read(&fixture_identity(), &key)
        .unwrap()
        .returned
        .is_none());
    let legacy = fixture.journal("legacy-only");
    let key = id("legacy_submit_key01");
    let accepted = client
        .submit(
            &legacy,
            Attempt::Start(&key),
            &assignment,
            &submit_body(input),
        )
        .await
        .unwrap();
    assert_eq!(accepted.state, JobState::Succeeded);
    let before = captured.lock().unwrap().len();
    assert_eq!(
        client.resume_cpu_job(&legacy, &key).await,
        Err(Error::ReceiptConflict)
    );
    assert_eq!(captured.lock().unwrap().len(), before);
    let raw: Value = serde_json::from_slice(
        &std::fs::read(fixture.root.0.join("legacy-only/journal.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(raw.as_object().unwrap().len(), 3);
    assert_eq!(raw["version"], "diffuser-client-receipts/v1");
    assert_eq!(
        raw["records"][key.as_str()]["intent"]["operation"],
        "submit"
    );
}

#[tokio::test]
async fn lost_submit_reply_reconnects_same_key_and_read_only_result_without_second_execution() {
    let fixture = Fixture::with_worker(Some(true));
    let journal = Arc::new(fixture.journal("receipts"));
    let input = Bytes::from_static(b"one bounded CPU inspection\0");
    let client = Client::new(fixture.transport());
    let (artifact_id, assignment_id) = upload_and_acquire(&client, &journal, input.clone()).await;
    drop(client);
    let body = submit_body(artifact_id.clone());
    let key = id("fixture_submit_001");
    let observed = Arc::new(Mutex::new(None));
    let mut transport = fixture.transport();
    let (at_handler, sent_key) = (journal.clone(), key.clone());
    transport.request_edit = Some(Box::new(move |request| {
        let saved = at_handler.read(&fixture_identity(), &sent_key).unwrap();
        assert!(saved.returned.is_none());
        assert_eq!(saved.intent.operation, Operation::Submit);
        assert_eq!(saved.intent.body_sha256, Sha256Digest::of(request.body()));
    }));
    let server_job = observed.clone();
    transport.response_edit = Some(Box::new(move |response| {
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let job: JobAccepted = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(job.state, JobState::Succeeded);
        *server_job.lock().unwrap() = Some(job.job_id);
        Err(TransportError::ReplyLost)
    }));
    let client = Client::new(transport);
    assert_eq!(
        client
            .submit(&journal, Attempt::Start(&key), &assignment_id, &body)
            .await,
        Err(Error::Transport(TransportError::ReplyLost))
    );
    let uncertain = journal.read(&fixture_identity(), &key).unwrap();
    assert_eq!(uncertain.intent.target_id.as_ref(), Some(&assignment_id));
    assert!(uncertain.returned.is_none());
    assert_eq!(fixture.claims().job_history_count().unwrap(), 1);
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations"),
        1
    );
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations WHERE state='complete'"),
        1
    );
    drop(client);
    drop(journal);

    let journal = ReceiptStore::open(fixture.root.0.join("receipts")).unwrap();
    let reconnect = fixture.transport();
    let requests = reconnect.requests.clone();
    let client = Client::new(reconnect);
    assert_eq!(
        client.resume_job(&journal, &key).await,
        Err(Error::ReceiptUncertain)
    );
    let mut different_body = body.clone();
    different_body.max_runtime_ms += 1;
    assert_eq!(
        client
            .submit(
                &journal,
                Attempt::Retry(&key),
                &assignment_id,
                &different_body
            )
            .await,
        Err(Error::ReceiptConflict)
    );
    let mut replacement = body.clone();
    replacement.client_job_id = id("different_job_001");
    assert_eq!(
        client
            .submit(
                &journal,
                Attempt::Start(&id("new_submit_key_001")),
                &assignment_id,
                &replacement
            )
            .await,
        Err(Error::ReceiptConflict)
    );
    assert_eq!(
        client
            .submit(
                &journal,
                Attempt::Retry(&id("unknown_key_00001")),
                &assignment_id,
                &body
            )
            .await,
        Err(Error::ReceiptMissing)
    );
    assert_eq!(
        client
            .release(
                &journal,
                Attempt::Retry(&key),
                &assignment_id,
                &Revision {
                    schema_version: LaneSchema::V1,
                    expected_revision: 0,
                }
            )
            .await,
        Err(Error::ReceiptConflict)
    );
    assert!(requests.lock().unwrap().is_empty());

    let recovered = client
        .submit(&journal, Attempt::Retry(&key), &assignment_id, &body)
        .await
        .unwrap();
    assert_eq!(Some(recovered.job_id.clone()), *observed.lock().unwrap());
    let saved = journal
        .read(&fixture_identity(), &key)
        .unwrap()
        .returned
        .unwrap();
    assert_eq!(saved.object_id, recovered.job_id);
    assert_eq!(saved.assignment_id.as_ref(), Some(&assignment_id));
    assert_eq!(fixture.claims().job_history_count().unwrap(), 1);
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations"),
        1
    );
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations WHERE state='complete'"),
        1
    );
    assert_json_request(
        &requests.lock().unwrap()[0],
        &format!("/v1/diffuser/projects/project_12345678/assignments/{assignment_id}/jobs"),
        key.as_str(),
        StatusCode::ACCEPTED,
        &json!({
            "schema_version": "diffuser-lane/v1", "client_job_id": "client_job_001AbC",
            "capability": "artifact.inspect.sha256/v1", "profile_version": "1",
            "input_artifact_ids": [artifact_id], "parameters": {}, "max_runtime_ms": 4000,
            "disconnect_policy": "continue_until_job_deadline"
        }),
    );
    drop(client);
    drop(journal);

    let journal = ReceiptStore::open(fixture.root.0.join("receipts")).unwrap();
    let readback = fixture.transport();
    let requests = readback.requests.clone();
    let client = Client::new(readback);
    let resumed = client.resume_job(&journal, &key).await.unwrap();
    assert_eq!(resumed.job.job_id, recovered.job_id);
    let (artifact, report) = resumed.result.unwrap();
    assert_eq!(report.job_id, recovered.job_id);
    assert_eq!(report.sha256, Sha256Digest::of(&input));
    assert_eq!(report.bytes, input.len() as u64);
    assert_eq!(artifact.metadata.sha256, Sha256Digest::of(&artifact.bytes));
    assert_eq!(artifact.metadata.bytes, artifact.bytes.len() as u64);
    assert_eq!(
        journal
            .read(&fixture_identity(), &key)
            .unwrap()
            .returned
            .unwrap()
            .result_artifact_id,
        Some(artifact.metadata.artifact_id.clone())
    );
    let job = &recovered.job_id;
    let output = &artifact.metadata.artifact_id;
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_get(
        &requests[0],
        &format!("/v1/diffuser/projects/project_12345678/jobs/{job}"),
        StatusCode::OK,
    );
    assert_get(
        &requests[1],
        &format!("/v1/diffuser/projects/project_12345678/artifacts/{output}"),
        StatusCode::OK,
    );
    assert_get(
        &requests[2],
        &format!("/v1/diffuser/projects/project_12345678/artifacts/{output}/content"),
        StatusCode::OK,
    );
    assert_eq!(fixture.claims().job_history_count().unwrap(), 1);
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations"),
        1
    );
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations WHERE state='complete'"),
        1
    );
}

#[tokio::test]
async fn cancel_is_not_release_and_exact_release_replay_records_one_close_while_held() {
    let fixture = Fixture::with_worker(Some(false));
    let journal = fixture.journal("receipts");
    let transport = fixture.transport();
    let requests = transport.requests.clone();
    let client = Client::new(transport);
    let (artifact, assignment) =
        upload_and_acquire(&client, &journal, Bytes::from_static(b"pending input")).await;
    let job = client
        .submit(
            &journal,
            Attempt::Start(&id("fixture_submit_001")),
            &assignment,
            &submit_body(artifact),
        )
        .await
        .unwrap();
    assert_eq!(job.state, JobState::Pending);
    let pending = client.job(&job.job_id).await.unwrap();
    let revision = Revision {
        schema_version: LaneSchema::V1,
        expected_revision: pending.revision,
    };
    let result = client
        .cancel(
            &journal,
            Attempt::Start(&id("fixture_cancel_001")),
            &job.job_id,
            &revision,
        )
        .await
        .unwrap();
    assert_eq!(result.state, JobState::Cancelled);
    let held = client.assignment(&assignment).await.unwrap();
    assert_eq!(held.state, AssignmentState::Assigned);
    assert_eq!(
        fixture.row_count("SELECT COUNT(*) FROM la_close_intents"),
        0
    );
    assert_eq!(fixture.claims().counts().unwrap().0, 1);
    let revision = Revision {
        schema_version: LaneSchema::V1,
        expected_revision: held.revision,
    };
    let release = id("fixture_release_01");
    for attempt in [Attempt::Start(&release), Attempt::Retry(&release)] {
        let result = client
            .release(&journal, attempt, &assignment, &revision)
            .await
            .unwrap();
        assert_eq!(result.state, AssignmentState::Draining);
        assert!(!result.released());
    }
    let claims = fixture.claims();
    let counts = claims.counts().unwrap();
    assert_eq!((counts.0, counts.1), (1, 1));
    assert_eq!(
        fixture.row_count("SELECT COUNT(*) FROM la_close_intents"),
        1
    );
    assert_eq!(
        fixture.row_count("SELECT COUNT(*) FROM la_assignment_cleanup_receipts"),
        0
    );
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM worker_close_receipts"),
        1
    );
    assert_eq!(
        fixture.worker_row_count(
            "SELECT COUNT(*) FROM operations WHERE state IN ('started','complete','cancelled')"
        ),
        0
    );
    let requests = requests.lock().unwrap();
    assert_json_request(
        &requests[4],
        &format!(
            "/v1/diffuser/projects/project_12345678/jobs/{}/cancel",
            job.job_id
        ),
        "fixture_cancel_001",
        StatusCode::ACCEPTED,
        &json!({"schema_version": "diffuser-lane/v1", "expected_revision": 0}),
    );
}

#[tokio::test]
async fn job_refusals_preserve_auth_order_and_do_not_fall_back_to_revision_one() {
    let fixture = Fixture::with_worker(Some(false));
    let journal = fixture.journal("receipts");
    let client = Client::new(fixture.transport());
    let (input, assignment) =
        upload_and_acquire(&client, &journal, Bytes::from_static(b"refusal input")).await;
    let baseline = submit_body(input);
    let mut transport = fixture.transport();
    transport.authorization = None;
    let no_auth = Client::new(transport);
    let missing = id("missing_assignment1");
    public(
        no_auth
            .submit(
                &journal,
                Attempt::Start(&id("unauth_submit_001")),
                &missing,
                &baseline,
            )
            .await
            .unwrap_err(),
        StatusCode::UNAUTHORIZED,
        PublicCode::AuthRequired,
    );
    let other_journal = fixture.journal("profile-refusal");
    let mut future = baseline.clone();
    future.profile_version = "2".into();
    public(
        client
            .submit(
                &other_journal,
                Attempt::Start(&id("future_submit_001")),
                &assignment,
                &future,
            )
            .await
            .unwrap_err(),
        StatusCode::UNPROCESSABLE_ENTITY,
        PublicCode::CapabilityUnavailable,
    );
    let missing_job = id("missing_job_00001");
    public(
        no_auth.job(&missing_job).await.unwrap_err(),
        StatusCode::UNAUTHORIZED,
        PublicCode::AuthRequired,
    );
    public(
        client.job(&missing_job).await.unwrap_err(),
        StatusCode::NOT_FOUND,
        PublicCode::ObjectNotFound,
    );
    assert_eq!(fixture.claims().job_history_count().unwrap(), 0);
    assert_eq!(
        fixture.worker_row_count("SELECT COUNT(*) FROM operations"),
        0
    );
}

#[cfg(feature = "contract-docs")]
#[tokio::test]
async fn frozen_v1_golden_transcript_matches_actual_cpu_workflow() {
    let golden: Value =
        serde_json::from_str(include_str!("../../docs/cosp/lane-client-v1.golden.json")).unwrap();
    let sources = [
        (
            "docs/cosp/lane-assignment.openapi.json",
            include_bytes!("../../docs/cosp/lane-assignment.openapi.json").as_slice(),
        ),
        (
            "docs/cosp/lane-assignment.schema.json",
            include_bytes!("../../docs/cosp/lane-assignment.schema.json").as_slice(),
        ),
        (
            "docs/cosp/lane-assignment-errors.json",
            include_bytes!("../../docs/cosp/lane-assignment-errors.json").as_slice(),
        ),
        (
            "src/cosp/lane_assignment.rs",
            include_bytes!("lane_assignment.rs").as_slice(),
        ),
        (
            "src/cosp/la_auth.rs",
            include_bytes!("la_auth.rs").as_slice(),
        ),
    ];
    assert_eq!(
        golden["source_sha256"].as_object().unwrap().len(),
        sources.len()
    );
    for (path, bytes) in sources {
        assert_eq!(
            golden["source_sha256"][path],
            Sha256Digest::of(bytes).as_str(),
            "{path}"
        );
    }
    let catalog: Value = serde_json::from_slice(include_bytes!(
        "../../docs/cosp/lane-assignment-errors.json"
    ))
    .unwrap();
    for entry in catalog["errors"].as_array().unwrap() {
        let code: PublicCode = serde_json::from_value(entry["code"].clone()).unwrap();
        assert_eq!(entry["code"], code.as_str());
    }

    let fixture = Fixture::with_worker(Some(true));
    let store = fixture.journal("receipts");
    let transport = fixture.transport();
    let requests = transport.requests.clone();
    let client = Client::new(transport);
    let discovery = client.discover().await.unwrap();
    assert!(
        !discovery
            .negotiate(
                "lane_cpu_inspect",
                INSPECT_CAPABILITY,
                INSPECT_PROFILE,
                INSPECT_REVISION
            )
            .unwrap()
            .accepting
    );
    let bytes = Bytes::from_static(b"golden-v1-input\n");
    let input = client
        .upload(
            &store,
            Attempt::Start(&id("golden_upload_001")),
            bytes.clone(),
        )
        .await
        .unwrap()
        .object_id;
    assert_eq!(client.artifact_content(&input).await.unwrap().bytes, bytes);
    let acquired = client
        .acquire(
            &store,
            Attempt::Start(&id("golden_acquire_01")),
            &acquire_body(),
        )
        .await
        .unwrap();
    let assignment = acquired.assignment_id;
    let view = client.assignment(&assignment).await.unwrap();
    assert_eq!(view.state, AssignmentState::Assigned);
    let renewed = client
        .renew(
            &store,
            Attempt::Start(&id("golden_renew_0001")),
            &assignment,
            &Renew {
                schema_version: LaneSchema::V1,
                expected_revision: view.revision,
                requested_lease_ms: 20_000,
            },
        )
        .await
        .unwrap();
    assert!(renewed.acknowledged_lease().unwrap() > acquired.lease_expires_at);

    let submit = id("golden_submit_001");
    let accepted = client
        .submit(
            &store,
            Attempt::Start(&submit),
            &assignment,
            &submit_body(input.clone()),
        )
        .await
        .unwrap();
    let resumed = client.resume_job(&store, &submit).await.unwrap();
    let (output, report) = resumed.result.unwrap();
    assert_eq!(report.sha256, Sha256Digest::of(&bytes));
    assert_eq!(report.bytes, bytes.len() as u64);
    client
        .cancel(
            &store,
            Attempt::Start(&id("golden_cancel_001")),
            &accepted.job_id,
            &Revision {
                schema_version: LaneSchema::V1,
                expected_revision: resumed.job.revision,
            },
        )
        .await
        .unwrap();
    let key = id("golden_release_01");
    let release = Revision {
        schema_version: LaneSchema::V1,
        expected_revision: renewed.revision,
    };
    for attempt in [Attempt::Start(&key), Attempt::Retry(&key)] {
        assert!(!client
            .release(&store, attempt, &assignment, &release)
            .await
            .unwrap()
            .released());
    }
    let mut unavailable = acquire_body();
    unavailable.provider_id = Some("colab".into());
    public(
        client
            .acquire(
                &store,
                Attempt::Start(&id("golden_refusal_01")),
                &unavailable,
            )
            .await
            .unwrap_err(),
        StatusCode::UNPROCESSABLE_ENTITY,
        PublicCode::ProviderUnconfigured,
    );

    let ids = [
        (&input, "$input"),
        (&assignment, "$assignment"),
        (&accepted.job_id, "$job"),
        (&output.metadata.artifact_id, "$output"),
    ];
    let captured: Vec<_> = requests
        .lock()
        .unwrap()
        .iter()
        .map(|row| wire_row(row, &ids))
        .collect();
    assert_eq!(json!(captured), golden["wire"]);
    println!("{}", serde_json::to_string(&captured).unwrap());
}

#[cfg(feature = "contract-docs")]
fn wire_row(row: &Recorded, ids: &[(&Id, &str)]) -> Value {
    let normalize = |text: &str| {
        ids.iter().fold(text.to_owned(), |text, (id, label)| {
            text.replace(id.as_str(), label)
        })
    };
    let headers: std::collections::BTreeMap<_, _> = row
        .headers
        .iter()
        .map(|(name, value)| {
            let value = value.to_str().unwrap();
            if *name == header::CONTENT_LENGTH {
                assert_eq!(value.parse::<usize>().unwrap(), row.body.len());
                (name.as_str(), "<body-bytes>")
            } else {
                (name.as_str(), value)
            }
        })
        .collect();
    let body = match row
        .headers
        .get(header::CONTENT_TYPE)
        .map(|value| value.to_str().unwrap())
    {
        Some("application/json") => {
            serde_json::from_str(&normalize(std::str::from_utf8(&row.body).unwrap())).unwrap()
        }
        Some("application/octet-stream") => {
            json!({"bytes": row.body.len(), "sha256": Sha256Digest::of(&row.body)})
        }
        None => Value::Null,
        media => panic!("unexpected transcript request media {media:?}"),
    };
    let mut summary = serde_json::Map::new();
    if row.response_type == "application/json" {
        let reply: Value = serde_json::from_slice(&row.response_body).unwrap();
        for field in [
            "schema_version",
            "queue_mode",
            "object_type",
            "state",
            "kind",
            "renewal_state",
        ] {
            if let Some(value) = reply.get(field) {
                summary.insert(field.into(), value.clone());
            }
        }
        if let Some(error) = reply.get("error") {
            summary.insert("code".into(), error["code"].clone());
            summary.insert("retry_action".into(), error["retry_action"].clone());
        }
    }
    json!({
        "method": row.method.as_str(), "path": normalize(&row.path),
        "request_headers": headers, "request_body": body, "status": row.status.as_u16(),
        "response_type": row.response_type, "response": summary
    })
}

#[tokio::test]
async fn client_bounds_requests_and_rejects_malformed_or_oversized_replies() {
    let fixture = Fixture::new();
    let store = fixture.journal("receipts");
    let transport = fixture.transport();
    let requests = transport.requests.clone();
    let client = Client::new(transport);
    let key = id("limit_fixture_001");
    assert_eq!(
        client
            .upload(
                &store,
                Attempt::Start(&key),
                Bytes::from(vec![0; ARTIFACT_MAX + 1]),
            )
            .await,
        Err(Error::RequestLimit)
    );
    let mut oversized = acquire_body();
    oversized.requested_hardware_description = Some("a".repeat(JSON_MAX));
    assert_eq!(
        client
            .acquire(&store, Attempt::Start(&key), &oversized)
            .await,
        Err(Error::RequestLimit)
    );
    assert!(requests.lock().unwrap().is_empty());
    assert_eq!(
        store.read(&fixture_identity(), &key),
        Err(Error::ReceiptMissing)
    );
    let artifact = client
        .upload(&store, Attempt::Start(&key), Bytes::from_static(b"test"))
        .await
        .unwrap()
        .object_id;
    let mut malformed = fixture.transport();
    malformed.response_edit = Some(Box::new(|response| {
        let mut metadata: Value = serde_json::from_slice(response.body()).unwrap();
        metadata["artifact_id"] = json!(format!(" {}", metadata["artifact_id"].as_str().unwrap()));
        replace_json_reply(response, &metadata);
        Ok(())
    }));
    assert_eq!(
        Client::new(malformed).artifact_metadata(&artifact).await,
        Err(Error::UnexpectedResponse(StatusCode::OK))
    );

    let mut large = fixture.transport();
    large.authorization = None;
    large.response_edit = Some(Box::new(|response| {
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let mut body = response.body().to_vec();
        body.resize(JSON_MAX + 1, b' ');
        *response.body_mut() = body.into();
        Ok(())
    }));
    assert_eq!(
        Client::new(large).artifact_metadata(&artifact).await,
        Err(Error::Transport(TransportError::ResponseLimit))
    );
}

#[path = "sdk_cpu_loopback.rs"]
mod sdk_cpu_loopback;
