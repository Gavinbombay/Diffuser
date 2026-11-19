//! Client for the existing private Diffuser assignment namespace, including
//! explicit typed private CPU and bounded CUDA operations.
use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode},
};
use receipts::Mutation;
use serde::de::DeserializeOwned;
use std::{future::Future, io};
use wire::ErrorEnvelope;

mod cuda;
mod receipts;
mod wire;
pub use cuda::*;
pub use receipts::*;
pub use wire::*;

pub const LANE_SCHEMA: &str = "diffuser-lane/v1";
pub const ARTIFACT_SCHEMA: &str = "diffuser-artifact/v1";
pub const INSPECT_CAPABILITY: &str = "artifact.inspect.sha256/v1";
pub const INSPECT_PROFILE: &str = "cpu-artifact-inspect/v1";
pub const INSPECT_REVISION: &str = "1";
pub const JSON_MAX: usize = 65_536;
pub const ARTIFACT_MAX: usize = 1_048_576;
pub const REPORT_MAX: usize = 4_096;

/// Apply these limits while receiving the body, before handing it to the client.
#[derive(Clone, Copy)]
pub struct ResponseLimits {
    success: usize,
}

impl ResponseLimits {
    pub fn for_status(self, status: StatusCode) -> usize {
        if status.is_success() {
            self.success
        } else {
            JSON_MAX
        }
    }
}

/// An in-process binding to the existing private namespace. The adapter owns
/// authority and destination selection and must enforce the cap while reading
/// responses, including errors. It must not redirect or retry requests.
pub trait Transport {
    fn identity(&self) -> &Identity;
    fn send(
        &self,
        request: Request<Bytes>,
        limits: ResponseLimits,
    ) -> impl Future<Output = Result<Response<Bytes>, TransportError>> + Send;
}

pub struct Client<T> {
    transport: T,
    identity: Identity,
}

impl<T> std::fmt::Debug for Client<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        let identity = transport.identity().clone();
        Self {
            transport,
            identity,
        }
    }

    pub async fn discover(&self) -> Result<Discovery, Error> {
        self.json(
            Request::get("/v1/diffuser/discovery")
                .body(Bytes::new())
                .unwrap(),
            &[StatusCode::OK],
        )
        .await
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub async fn upload(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        input: Bytes,
    ) -> Result<ArtifactUploaded, Error> {
        if input.len() > ARTIFACT_MAX {
            return Err(Error::RequestLimit);
        }
        let mut request = Request::post(self.project_path("/artifacts"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, input.len())
            .header("x-diffuser-schema", ARTIFACT_SCHEMA)
            .header("x-content-sha256", Sha256Digest::of(&input).as_str())
            .body(input)
            .expect("fixed route and validated headers");
        let key =
            self.mutation_intent(store, attempt, Operation::Upload.into(), None, &mut request)?;
        let published: ArtifactUploaded = self.json(request, &[StatusCode::CREATED]).await?;
        if published.project_id != self.identity().project
            || published.object_type != "artifact"
            || published.revision != 1
            || published.state != "published"
            || published.links.self_path != self.artifact_path(&published.object_id)
        {
            return Err(Error::UnexpectedResponse(StatusCode::CREATED));
        }
        let mut returned = Returned::object(published.object_id.clone());
        returned.receipt_id = Some(published.receipt_id.clone());
        store.finish(
            self.identity(),
            &key,
            StatusCode::CREATED.as_u16(),
            returned,
        )?;
        Ok(published)
    }

    pub async fn artifact_metadata(&self, artifact: &Id) -> Result<ArtifactManifest, Error> {
        let metadata: ArtifactManifest = self
            .json(get(self.artifact_path(artifact)), &[StatusCode::OK])
            .await?;
        let identity = self.identity();
        if &metadata.artifact_id != artifact
            || metadata.project_id != identity.project
            || metadata.tenant_id != identity.tenant
            || metadata.owner_id != identity.actor
            || metadata.actor_id != identity.actor
            || metadata.version != 1
            || metadata.media_type != "application/octet-stream"
            || metadata.data_class != "synthetic"
            || metadata.publication_state != "published"
            || metadata.provenance.authority_lineage.is_empty()
            || metadata.created_at >= metadata.expires_at
        {
            return Err(Error::UnexpectedResponse(StatusCode::OK));
        }
        let bound = match (
            metadata.kind,
            metadata.provenance.source,
            &metadata.assignment_id,
            &metadata.job_id,
        ) {
            (ArtifactKind::Input, ArtifactSource::CallerUpload, None, None) => ARTIFACT_MAX,
            (ArtifactKind::Output, ArtifactSource::WorkerResult, Some(_), Some(_)) => REPORT_MAX,
            _ => return Err(Error::UnexpectedResponse(StatusCode::OK)),
        };
        if metadata.bytes > bound as u64 {
            return Err(Error::ArtifactIntegrity);
        }
        Ok(metadata)
    }

    /// Fetch metadata and the fixed content route and return bytes only after
    /// verifying the immutable ID, media type, ETag, length and SHA-256.
    pub async fn artifact_content(&self, artifact: &Id) -> Result<VerifiedArtifact, Error> {
        self.verified_content(self.artifact_metadata(artifact).await?)
            .await
    }

    async fn verified_content(
        &self,
        metadata: ArtifactManifest,
    ) -> Result<VerifiedArtifact, Error> {
        let bound = match metadata.kind {
            ArtifactKind::Input => ARTIFACT_MAX,
            ArtifactKind::Output => REPORT_MAX,
        };
        let response = self
            .exchange(
                get(format!(
                    "{}/content",
                    self.artifact_path(&metadata.artifact_id)
                )),
                &[StatusCode::OK],
                bound,
            )
            .await?;
        let bytes = response.body();
        let etag = format!("\"{}\"", metadata.sha256.as_str());
        if header_value(response.headers(), header::CONTENT_TYPE)
            != Some("application/octet-stream")
            || header_value(response.headers(), header::ETAG) != Some(etag.as_str())
            || bytes.len() as u64 != metadata.bytes
            || Sha256Digest::of(bytes) != metadata.sha256
        {
            return Err(Error::ArtifactIntegrity);
        }
        Ok(VerifiedArtifact {
            metadata,
            bytes: response.into_body(),
        })
    }

    pub async fn acquire(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        body: &Acquire,
    ) -> Result<AssignmentAcquired, Error> {
        self.acquire_typed(store, attempt, body).await
    }

    async fn acquire_typed(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        body: &impl serde::Serialize,
    ) -> Result<AssignmentAcquired, Error> {
        let (request, key) = self.json_mutation(
            store,
            attempt,
            Operation::Acquire,
            None,
            self.project_path("/assignments"),
            body,
        )?;
        let status = StatusCode::ACCEPTED;
        let reply: AssignmentAcquired = self.json(request, &[status]).await?;
        if reply.lease_expires_at > reply.hard_expires_at || reply.hard_expires_at > i64::MAX as u64
        {
            return Err(Error::UnexpectedResponse(status));
        }
        store.finish(
            self.identity(),
            &key,
            status.as_u16(),
            Returned::object(reply.assignment_id.clone()),
        )?;
        Ok(reply)
    }

    pub async fn assignment(&self, assignment: &Id) -> Result<AssignmentView, Error> {
        let status = StatusCode::OK;
        let reply: AssignmentView = self
            .json(get(self.assignment_path(assignment)), &[status])
            .await?;
        if &reply.assignment_id != assignment || reply.revision > i64::MAX as u64 {
            return Err(Error::UnexpectedResponse(status));
        }
        Ok(reply)
    }

    pub async fn renew(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        assignment: &Id,
        body: &Renew,
    ) -> Result<AssignmentRenewal, Error> {
        let (request, key) = self.json_mutation(
            store,
            attempt,
            Operation::Renew,
            Some(assignment),
            format!("{}/renew", self.assignment_path(assignment)),
            body,
        )?;
        let (status, reply): (_, AssignmentRenewal) = self
            .json_reply(request, &[StatusCode::OK, StatusCode::ACCEPTED])
            .await?;
        let consistent = matches!(
            (status, reply.renewal_state),
            (StatusCode::OK, RenewalState::Acknowledged)
                | (StatusCode::ACCEPTED, RenewalState::Pending)
        );
        if !consistent
            || &reply.assignment_id != assignment
            || reply.revision > i64::MAX as u64
            || reply.lease_expires_at > i64::MAX as u64
        {
            return Err(Error::UnexpectedResponse(status));
        }
        store.finish(
            self.identity(),
            &key,
            status.as_u16(),
            Returned::object(reply.assignment_id.clone()),
        )?;
        Ok(reply)
    }

    pub async fn release(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        assignment: &Id,
        body: &Revision,
    ) -> Result<AssignmentRelease, Error> {
        let (request, key) = self.json_mutation(
            store,
            attempt,
            Operation::Release,
            Some(assignment),
            format!("{}/release", self.assignment_path(assignment)),
            body,
        )?;
        let (status, reply): (_, AssignmentRelease) = self
            .json_reply(request, &[StatusCode::OK, StatusCode::ACCEPTED])
            .await?;
        let consistent = matches!(
            (status, reply.state),
            (StatusCode::OK, AssignmentState::Closed)
                | (
                    StatusCode::ACCEPTED,
                    AssignmentState::Draining | AssignmentState::Quarantined
                )
        );
        if !consistent || &reply.assignment_id != assignment {
            return Err(Error::UnexpectedResponse(status));
        }
        store.finish(
            self.identity(),
            &key,
            status.as_u16(),
            Returned::object(reply.assignment_id.clone()),
        )?;
        Ok(reply)
    }

    pub async fn submit(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        assignment: &Id,
        body: &Submit,
    ) -> Result<JobAccepted, Error> {
        self.submit_versioned(store, attempt, assignment, Operation::Submit.into(), body)
            .await
    }

    /// Submit the explicitly selected v2 CPU operation via the existing job
    /// route. No discovery inference, downgrade, or automatic retry occurs.
    /// Retain `body` and the original key to retry an uncertain reply.
    pub async fn submit_cpu(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        assignment: &Id,
        body: &CpuSubmit,
    ) -> Result<JobAccepted, Error> {
        self.submit_versioned(store, attempt, assignment, Mutation::CpuSubmit, body)
            .await
    }

    async fn submit_versioned(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        assignment: &Id,
        mutation: Mutation,
        body: &impl serde::Serialize,
    ) -> Result<JobAccepted, Error> {
        let (request, key) = self.json_mutation(
            store,
            attempt,
            mutation,
            Some(assignment),
            format!("{}/jobs", self.assignment_path(assignment)),
            body,
        )?;
        let status = StatusCode::ACCEPTED;
        let reply: JobAccepted = self.json(request, &[status]).await?;
        if &reply.assignment_id != assignment || reply.revision > i64::MAX as u64 {
            return Err(Error::UnexpectedResponse(status));
        }
        let mut returned = Returned::object(reply.job_id.clone());
        returned.assignment_id = Some(reply.assignment_id.clone());
        store.finish(self.identity(), &key, status.as_u16(), returned)?;
        Ok(reply)
    }

    pub async fn job(&self, job: &Id) -> Result<JobView, Error> {
        let status = StatusCode::OK;
        let reply: JobView = self.json(get(self.job_path(job)), &[status]).await?;
        if &reply.job_id != job
            || reply.revision > i64::MAX as u64
            || (reply.state == JobState::Succeeded) != reply.result_artifact_id.is_some()
        {
            return Err(Error::UnexpectedResponse(status));
        }
        Ok(reply)
    }

    pub async fn cancel(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        job: &Id,
        body: &Revision,
    ) -> Result<JobCancellation, Error> {
        let (request, key) = self.json_mutation(
            store,
            attempt,
            Operation::Cancel,
            Some(job),
            format!("{}/cancel", self.job_path(job)),
            body,
        )?;
        let status = StatusCode::ACCEPTED;
        let reply: JobCancellation = self.json(request, &[status]).await?;
        if &reply.job_id != job || reply.revision > i64::MAX as u64 {
            return Err(Error::UnexpectedResponse(status));
        }
        store.finish(
            self.identity(),
            &key,
            status.as_u16(),
            Returned::object(reply.job_id.clone()),
        )?;
        Ok(reply)
    }

    /// Reconnect by the returned IDs of a saved submit. Only GETs go to the
    /// service. If the reply was lost before its ID was saved, the caller
    /// may explicitly retry the exact original submit under the same key.
    pub async fn resume_job(
        &self,
        store: &ReceiptStore,
        submit_key: &Id,
    ) -> Result<ResumedJob, Error> {
        let (job, result) = self
            .resume_submitted(
                store,
                submit_key,
                Operation::Submit.into(),
                None,
                |report: &InspectReport, job| {
                    &report.job_id == job
                        && report.capability == INSPECT_CAPABILITY
                        && report.profile_id == INSPECT_PROFILE
                        && report.profile_version == INSPECT_REVISION
                        && report.bytes <= ARTIFACT_MAX as u64
                },
            )
            .await?;
        Ok(ResumedJob { job, result })
    }

    /// Read only the saved v2 CPU job and verify its immutable result, if any.
    /// This authenticates the result artifact against route metadata; it does
    /// not reexecute the computation or compare against caller input bytes.
    pub async fn resume_cpu_job(
        &self,
        store: &ReceiptStore,
        submit_key: &Id,
    ) -> Result<ResumedCpuJob, Error> {
        let (job, result) = self
            .resume_submitted(
                store,
                submit_key,
                Mutation::CpuSubmit,
                None,
                |report: &CpuReport, job| {
                    // Schema, backend and both digest encodings are checked by parsing.
                    &report.job_id == job
                        && report.capability == INSPECT_CAPABILITY
                        && (1..=1024).contains(&report.bytes)
                        && (1..=256).contains(&report.data_bytes)
                        && (1..=262_144).contains(&report.rounds)
                },
            )
            .await?;
        Ok(ResumedCpuJob { job, result })
    }

    async fn resume_submitted<R: DeserializeOwned>(
        &self,
        store: &ReceiptStore,
        submit_key: &Id,
        mutation: Mutation,
        body_sha256: Option<Sha256Digest>,
        valid: impl FnOnce(&R, &Id) -> bool,
    ) -> Result<(JobView, Option<(VerifiedArtifact, R)>), Error> {
        let receipt = store.read_submit(self.identity(), submit_key, mutation)?;
        if body_sha256.is_some_and(|digest| digest != receipt.intent.body_sha256) {
            return Err(Error::ReceiptConflict);
        }
        let saved = receipt.returned.ok_or(Error::ReceiptUncertain)?;
        let job = self.job(&saved.object_id).await?;
        if Some(&job.assignment_id) != saved.assignment_id.as_ref()
            || saved
                .result_artifact_id
                .as_ref()
                .is_some_and(|artifact| Some(artifact) != job.result_artifact_id.as_ref())
        {
            return Err(Error::UnexpectedResponse(StatusCode::OK));
        }
        let result = if let Some(artifact_id) = &job.result_artifact_id {
            let metadata = self.artifact_metadata(artifact_id).await?;
            if metadata.kind != ArtifactKind::Output
                || metadata.job_id.as_ref() != Some(&job.job_id)
                || metadata.assignment_id.as_ref() != Some(&job.assignment_id)
            {
                return Err(Error::ArtifactIntegrity);
            }
            let artifact = self.verified_content(metadata).await?;
            let report =
                serde_json::from_slice(&artifact.bytes).map_err(|_| Error::ArtifactIntegrity)?;
            if !valid(&report, &job.job_id) {
                return Err(Error::ArtifactIntegrity);
            }
            store.remember_result(self.identity(), submit_key, &job.job_id, artifact_id)?;
            Some((artifact, report))
        } else {
            None
        };
        Ok((job, result))
    }

    fn job_path(&self, job: &Id) -> String {
        self.project_path(&format!("/jobs/{job}"))
    }

    fn assignment_path(&self, assignment: &Id) -> String {
        self.project_path(&format!("/assignments/{assignment}"))
    }

    fn json_mutation(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        operation: impl Into<Mutation>,
        target: Option<&Id>,
        path: String,
        body: &impl serde::Serialize,
    ) -> Result<(Request<Bytes>, Id), Error> {
        let mut encoded = BoundedJson::default();
        serde_json::to_writer(&mut encoded, body).map_err(|error| {
            if error.io_error_kind() == Some(io::ErrorKind::FileTooLarge) {
                Error::RequestLimit
            } else {
                Error::InvalidRequest
            }
        })?;
        let body = encoded.0;
        let mut request = Request::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, body.len())
            .body(Bytes::from(body))
            .expect("fixed route and validated headers");
        let key = self.mutation_intent(store, attempt, operation.into(), target, &mut request)?;
        Ok((request, key))
    }

    fn mutation_intent(
        &self,
        store: &ReceiptStore,
        attempt: Attempt<'_>,
        mutation: Mutation,
        target_id: Option<&Id>,
        request: &mut Request<Bytes>,
    ) -> Result<Id, Error> {
        let key = store.begin(
            self.identity(),
            attempt,
            mutation,
            target_id.cloned(),
            Sha256Digest::of(request.body()),
        )?;
        request.headers_mut().insert(
            "idempotency-key",
            HeaderValue::from_str(key.as_str()).expect("validated idempotency key"),
        );
        Ok(key)
    }

    fn project_path(&self, path: &str) -> String {
        format!("/v1/diffuser/projects/{}{path}", self.identity().project)
    }

    fn artifact_path(&self, artifact: &Id) -> String {
        self.project_path(&format!("/artifacts/{artifact}"))
    }

    async fn json<R: DeserializeOwned>(
        &self,
        request: Request<Bytes>,
        expected: &[StatusCode],
    ) -> Result<R, Error> {
        self.json_reply(request, expected)
            .await
            .map(|(_, body)| body)
    }

    async fn json_reply<R: DeserializeOwned>(
        &self,
        request: Request<Bytes>,
        expected: &[StatusCode],
    ) -> Result<(StatusCode, R), Error> {
        let response = self.exchange(request, expected, JSON_MAX).await?;
        let status = response.status();
        if header_value(response.headers(), header::CONTENT_TYPE) != Some("application/json") {
            return Err(Error::UnexpectedResponse(status));
        }
        let body = serde_json::from_slice(response.body())
            .map_err(|_| Error::UnexpectedResponse(status))?;
        Ok((status, body))
    }

    async fn exchange(
        &self,
        request: Request<Bytes>,
        expected: &[StatusCode],
        success_limit: usize,
    ) -> Result<Response<Bytes>, Error> {
        let limits = ResponseLimits {
            success: success_limit,
        };
        let response = self
            .transport
            .send(request, limits)
            .await
            .map_err(Error::Transport)?;
        let status = response.status();
        if response.body().len() > limits.for_status(status) {
            return Err(Error::Transport(TransportError::ResponseLimit));
        }
        if response.headers().contains_key(header::CONTENT_LENGTH)
            && header_value(response.headers(), header::CONTENT_LENGTH)
                .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|value| value.parse::<usize>().ok())
                != Some(response.body().len())
        {
            return Err(Error::UnexpectedResponse(status));
        }
        if expected.contains(&status) {
            return Ok(response);
        }
        if !(status.is_client_error() || status.is_server_error())
            || header_value(response.headers(), header::CONTENT_TYPE) != Some("application/json")
        {
            return Err(Error::UnexpectedResponse(status));
        }
        let envelope: ErrorEnvelope = serde_json::from_slice(response.body())
            .map_err(|_| Error::UnexpectedResponse(status))?;
        Err(Error::Public(PublicError {
            status,
            code: envelope.error.code,
            retry_action: envelope.error.retry_action,
            request_id: envelope.error.request_id,
            object_id: envelope.error.object_id,
        }))
    }
}

fn header_value(headers: &HeaderMap, name: axum::http::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}

fn get(path: impl AsRef<str>) -> Request<Bytes> {
    Request::get(path.as_ref())
        .body(Bytes::new())
        .expect("fixed route and validated identifiers")
}

#[derive(Default)]
struct BoundedJson(Vec<u8>);

impl io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > JSON_MAX - self.0.len() {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
