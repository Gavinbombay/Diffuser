//! Bounded byte inspection. Admission and durable operation fencing are separate gates.
use super::la_backend::{self, Capability};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Instant;

const MAX_INPUT: usize = 1024 * 1024;
const MAX_OPERATIONS: i64 = 32;

fn valid_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryReport {
    schema_version: String,
    sha256: String,
    bytes: u64,
    capability: String,
    profile_id: String,
    profile_version: String,
    job_id: String,
}

fn validate_history(db: &rusqlite::Connection) -> Result<(), &'static str> {
    let mut statement = db
        .prepare("SELECT substr(op,1,129),substr(job,1,129),substr(input_digest,1,65),substr(state,1,16),length(report),length(CAST(op AS BLOB)),length(CAST(job AS BLOB)),length(CAST(input_digest AS BLOB)),length(CAST(state AS BLOB)) FROM operations")
        .map_err(|_| "evidence_invalid")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(|_| "evidence_invalid")?;
    let mut count = 0i64;
    for row in rows {
        let (op, job, digest, state, report_len, op_len, job_len, digest_len, state_len) =
            row.map_err(|_| "evidence_invalid")?;
        count += 1;
        if count > MAX_OPERATIONS
            || !valid_id(&op)
            || !valid_id(&job)
            || i64::try_from(op.len()).ok() != Some(op_len)
            || i64::try_from(job.len()).ok() != Some(job_len)
            || i64::try_from(digest.len()).ok() != Some(digest_len)
            || i64::try_from(state.len()).ok() != Some(state_len)
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("evidence_invalid");
        }
        match (state.as_str(), report_len) {
            ("started" | "stopped" | "cancelled", None) => (),
            ("complete", Some(length)) if (1..=4096).contains(&length) => {
                let report: Vec<u8> = db
                    .query_row("SELECT report FROM operations WHERE op=?1", [&op], |row| {
                        row.get(0)
                    })
                    .map_err(|_| "evidence_invalid")?;
                if report.len() != length as usize {
                    return Err("evidence_invalid");
                }
                let normalized =
                    super::la_contract::canonical_json(&report).map_err(|_| "evidence_invalid")?;
                if la_backend::is_typed_report(&normalized) {
                    la_backend::validate_report(&normalized, &job, &digest, None, None)?;
                    continue;
                }
                let report: HistoryReport =
                    serde_json::from_slice(&normalized).map_err(|_| "evidence_invalid")?;
                if report.schema_version != "diffuser-artifact/v1"
                    || report.sha256 != digest
                    || report.bytes > MAX_INPUT as u64
                    || report.capability != "artifact.inspect.sha256/v1"
                    || report.profile_id != "cpu-artifact-inspect/v1"
                    || report.profile_version != "1"
                    || report.job_id != job
                {
                    return Err("evidence_invalid");
                }
            }
            _ => return Err("evidence_invalid"),
        }
    }
    Ok(())
}

pub(super) fn inspect(
    input: &mut impl Read,
    job_id: &str,
    deadline: Instant,
    cancelled: impl Fn() -> bool,
) -> Result<Vec<u8>, &'static str> {
    let mut hash = Sha256::new();
    let mut count = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if cancelled() || Instant::now() >= deadline {
            return Err("stopped");
        }
        let n = input.read(&mut buffer).map_err(|_| "input_unavailable")?;
        if cancelled() || Instant::now() >= deadline {
            return Err("stopped");
        }
        if n == 0 {
            break;
        }
        count = count.checked_add(n).ok_or("artifact_invalid")?;
        if count > MAX_INPUT {
            return Err("artifact_invalid");
        }
        hash.update(&buffer[..n]);
    }
    if cancelled() || Instant::now() >= deadline {
        return Err("stopped");
    }
    let report = serde_json::json!({
        "schema_version": "diffuser-artifact/v1",
        "sha256": hex::encode(hash.finalize()),
        "bytes": count,
        "capability": "artifact.inspect.sha256/v1",
        "profile_id": "cpu-artifact-inspect/v1",
        "profile_version": "1",
        "job_id": job_id,
    });
    let result = serde_json::to_vec(&report).map_err(|_| "artifact_invalid")?;
    if result.len() > 4096 {
        return Err("artifact_invalid");
    }
    if cancelled() || Instant::now() >= deadline {
        return Err("stopped");
    }
    Ok(result)
}

/// An unexposed execution journal. A caller must first enforce the full worker
/// admission, fence, permit and authority checks; the journal is not admission.
type WorkEntryObserver = dyn Fn(&str, &str) -> Result<(), &'static str> + Send + Sync;
pub(super) struct OperationJournal {
    work_entry: Option<std::sync::Arc<WorkEntryObserver>>,
    occupancy_keys: Option<Box<super::la_adapter::ChannelKeys>>,
    running: Option<Box<RunningInspection>>,
    backend: Option<Box<dyn la_backend::Binding>>,
    db: super::la_store::PinnedDb,
    lock: std::fs::File,
    root: std::fs::File,
    root_path: std::path::PathBuf,
    quarantined: std::cell::Cell<bool>,
}

fn open_worker_lock(root: &std::fs::File, create: bool) -> Result<std::fs::File, &'static str> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let flags = libc::O_RDWR
        | if create {
            libc::O_CREAT | libc::O_EXCL
        } else {
            0
        };
    let file = super::la_artifacts::open_artifact(root, ".worker-lock", flags)
        .map_err(|_| "evidence_invalid")?;
    let meta = file.metadata().map_err(|_| "evidence_invalid")?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err("evidence_invalid");
    }
    if create {
        file.sync_all()
            .and_then(|_| root.sync_all())
            .map_err(|_| "storage_unavailable")?;
    }
    Ok(file)
}

fn worker_lock_matches(root: &std::fs::File, lock: &std::fs::File) -> bool {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let Ok(meta) = lock.metadata() else {
        return false;
    };
    let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            c".worker-lock".as_ptr(),
            current.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return false;
    }
    let current = unsafe { current.assume_init() };
    meta.is_file()
        && meta.nlink() == 1
        && meta.uid() == unsafe { libc::geteuid() }
        && meta.mode() & 0o777 == 0o600
        && current.st_mode & libc::S_IFMT == libc::S_IFREG
        && current.st_mode & 0o777 == 0o600
        && current.st_uid == unsafe { libc::geteuid() }
        && current.st_nlink == 1
        && current.st_dev == meta.dev()
        && current.st_ino == meta.ino()
}

fn worker_root(
    path: &std::path::Path,
) -> Result<(std::fs::File, std::path::PathBuf, String), &'static str> {
    let parent = path
        .parent()
        .filter(|p| p.is_absolute())
        .ok_or("storage_unavailable")?;
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or("storage_unavailable")?;
    let root = super::la_artifacts::open_owned_root(parent).map_err(|_| "storage_unavailable")?;
    Ok((root, parent.to_path_buf(), name.to_owned()))
}
fn worker_quarantined(root: &std::fs::File) -> Result<bool, &'static str> {
    use std::os::fd::AsRawFd;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            c".worker-quarantine".as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(true);
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err("storage_unavailable")
    }
}
fn mark_worker_quarantine(root: &std::fs::File) -> Result<(), &'static str> {
    use std::io::Write;
    let mut marker = match super::la_artifacts::open_artifact(
        root,
        ".worker-quarantine",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    ) {
        Ok(marker) => marker,
        Err(_) if worker_quarantined(root)? => return Ok(()),
        Err(_) => return Err("storage_unavailable"),
    };
    marker
        .write_all(b"worker-custody-uncertain-v1\n")
        .and_then(|_| marker.sync_all())
        .map_err(|_| "storage_unavailable")?;
    root.sync_all().map_err(|_| "storage_unavailable")
}

impl OperationJournal {
    pub(super) fn bootstrap(path: &std::path::Path, custody: &str) -> Result<Self, &'static str> {
        let (root, root_path, name) = worker_root(path)?;
        Self::bootstrap_at(&root, &root_path, &name, custody)
    }

    fn bootstrap_at(
        root: &std::fs::File,
        root_path: &std::path::Path,
        name: &str,
        custody: &str,
    ) -> Result<Self, &'static str> {
        if custody.is_empty() {
            return Err("evidence_invalid");
        }
        let root = root.try_clone().map_err(|_| "storage_unavailable")?;
        let root_path = root_path.to_path_buf();
        if !super::la_store::claim_root_matches(&root, &root_path) {
            let _ = mark_worker_quarantine(&root);
            return Err("storage_unavailable");
        }
        if worker_quarantined(&root)? {
            return Err("evidence_invalid");
        }
        let lock = open_worker_lock(&root, true)?;
        use std::os::unix::fs::MetadataExt;
        let lock_meta = lock.metadata().map_err(|_| "evidence_invalid")?;
        let lock_dev = i64::try_from(lock_meta.dev()).map_err(|_| "evidence_invalid")?;
        let lock_ino = i64::try_from(lock_meta.ino()).map_err(|_| "evidence_invalid")?;
        let file = super::la_artifacts::open_artifact(
            &root,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| "storage_unavailable")?;
        file.sync_all().map_err(|_| "storage_unavailable")?;
        root.sync_all().map_err(|_| "storage_unavailable")?;
        let db = super::la_store::open_pinned_database(&root, name, false)?;
        if !super::la_store::claim_root_matches(&root, &root_path)
            || !worker_lock_matches(&root, &lock)
        {
            let _ = mark_worker_quarantine(&root);
            return Err("storage_unavailable");
        }
        db.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE identity (custody TEXT NOT NULL, lock_dev INTEGER NOT NULL, lock_ino INTEGER NOT NULL); CREATE TABLE operations (op TEXT PRIMARY KEY, job TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL, report BLOB); CREATE TABLE reservation_session (worker TEXT NOT NULL, boot TEXT NOT NULL, sequence INTEGER NOT NULL, fence INTEGER NOT NULL); CREATE TABLE worker_session_generations (generation INTEGER PRIMARY KEY, worker TEXT NOT NULL, boot TEXT NOT NULL UNIQUE, sequence INTEGER NOT NULL, fence INTEGER NOT NULL, authority TEXT NOT NULL, mac BLOB NOT NULL); CREATE TABLE worker_session_snapshots (sequence INTEGER PRIMARY KEY, assignment TEXT NOT NULL, generation INTEGER NOT NULL, worker TEXT NOT NULL, boot TEXT NOT NULL, fence INTEGER NOT NULL, event TEXT NOT NULL, proof BLOB NOT NULL, mac BLOB NOT NULL); CREATE TABLE worker_reservations (assignment_id TEXT PRIMARY KEY, operation TEXT NOT NULL UNIQUE, fence INTEGER NOT NULL, command_digest BLOB NOT NULL, sequence INTEGER NOT NULL UNIQUE, lease_until INTEGER NOT NULL, hard_until INTEGER NOT NULL, revision INTEGER NOT NULL, closed INTEGER NOT NULL); CREATE TABLE worker_inspect_commands (operation TEXT PRIMARY KEY, command_digest BLOB NOT NULL, sequence INTEGER NOT NULL UNIQUE); CREATE TABLE worker_result_receipts (operation TEXT PRIMARY KEY, digest TEXT NOT NULL, byte_count INTEGER NOT NULL, sequence INTEGER NOT NULL UNIQUE); CREATE TABLE worker_renewals (operation TEXT PRIMARY KEY, digest BLOB NOT NULL, sequence INTEGER NOT NULL UNIQUE); CREATE TABLE worker_stop_receipts (operation TEXT PRIMARY KEY, command_digest BLOB NOT NULL, sequence INTEGER NOT NULL UNIQUE); CREATE TABLE worker_close_receipts (operation TEXT PRIMARY KEY, command_digest BLOB NOT NULL, sequence INTEGER NOT NULL UNIQUE); CREATE TABLE worker_input_assignments (operation TEXT PRIMARY KEY, assignment TEXT NOT NULL); CREATE TABLE worker_cleanup_receipts (assignment TEXT PRIMARY KEY, operation TEXT NOT NULL, fence INTEGER NOT NULL, sequence INTEGER NOT NULL); CREATE TABLE worker_inputs (operation TEXT PRIMARY KEY, command_digest BLOB NOT NULL, input_digest TEXT NOT NULL, content TEXT NOT NULL); CREATE TABLE worker_assignment_terms (assignment TEXT PRIMARY KEY, body BLOB NOT NULL); CREATE TABLE worker_mandates (job TEXT PRIMARY KEY, body BLOB NOT NULL);")
            .map_err(|_| "storage_unavailable")?;
        db.execute(
            "INSERT INTO identity VALUES (?1,?2,?3)",
            rusqlite::params![custody, lock_dev, lock_ino],
        )
        .map_err(|_| "storage_unavailable")?;
        if !super::la_store::claim_root_matches(&root, &root_path)
            || !worker_lock_matches(&root, &lock)
        {
            let _ = mark_worker_quarantine(&root);
            return Err("storage_unavailable");
        }
        Ok(Self {
            work_entry: None,
            occupancy_keys: None,
            running: None,
            backend: None,
            db,
            lock,
            root,
            root_path,
            quarantined: std::cell::Cell::new(false),
        })
    }

    /// `expected_starts` must come from an independent trusted custody record.
    /// This is only a partial rollback check, not full worker readiness proof.
    pub(super) fn reopen(
        path: &std::path::Path,
        custody: &str,
        expected_starts: u64,
    ) -> Result<Self, &'static str> {
        // The legacy partial check cannot establish stopped-tombstone history.
        Self::reopen_checked(path, custody, expected_starts, expected_starts)
    }

    /// Both high-water counts must be independently supplied by trusted custody.
    pub(super) fn reopen_checked(
        path: &std::path::Path,
        custody: &str,
        expected_starts: u64,
        expected_records: u64,
    ) -> Result<Self, &'static str> {
        let (root, root_path, name) = worker_root(path).map_err(|_| "evidence_invalid")?;
        if worker_quarantined(&root).map_err(|_| "evidence_invalid")? {
            return Err("evidence_invalid");
        }
        let lock = open_worker_lock(&root, false)?;
        use std::os::unix::fs::MetadataExt;
        let lock_meta = lock.metadata().map_err(|_| "evidence_invalid")?;
        let file =
            super::la_artifacts::open_artifact(&root, &name, libc::O_RDONLY | libc::O_NONBLOCK)
                .map_err(|_| {
                    let _ = mark_worker_quarantine(&root);
                    "evidence_invalid"
                })?;
        if !file
            .metadata()
            .map_err(|_| {
                let _ = mark_worker_quarantine(&root);
                "evidence_invalid"
            })?
            .is_file()
        {
            let _ = mark_worker_quarantine(&root);
            return Err("evidence_invalid");
        }
        let db = super::la_store::open_pinned_database(&root, &name, false).map_err(|_| {
            let _ = mark_worker_quarantine(&root);
            "evidence_invalid"
        })?;
        if !super::la_store::claim_root_matches(&root, &root_path)
            || !worker_lock_matches(&root, &lock)
        {
            let _ = mark_worker_quarantine(&root);
            return Err("evidence_invalid");
        }
        // Keep integrity, high-water and row validation on one SQLite view.
        db.execute_batch("PRAGMA synchronous=FULL; BEGIN DEFERRED;")
            .map_err(|_| {
                let _ = mark_worker_quarantine(&root);
                "evidence_invalid"
            })?;
        let integrity: String = db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(|_| {
                let _ = mark_worker_quarantine(&root);
                "evidence_invalid"
            })?;
        let (stored, lock_dev, lock_ino, identities): (String, i64, i64, i64) = db
            .query_row(
                "SELECT custody,lock_dev,lock_ino,(SELECT COUNT(*) FROM identity) FROM identity",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| {
                let _ = mark_worker_quarantine(&root);
                "evidence_invalid"
            })?;
        let (records, starts, invalid): (i64,i64,i64) = db.query_row("SELECT COUNT(*),COALESCE(SUM(state IN ('started','complete','cancelled')),0),COALESCE(SUM(state NOT IN ('started','complete','stopped','cancelled') OR (state='complete' AND report IS NULL) OR (state!='complete' AND report IS NOT NULL)),0) FROM operations", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_| { let _ = mark_worker_quarantine(&root); "evidence_invalid" })?;
        if integrity != "ok" {
            let _ = mark_worker_quarantine(&root);
            return Err("evidence_invalid");
        }
        if identities != 1 || invalid != 0 || records > MAX_OPERATIONS {
            let _ = mark_worker_quarantine(&root);
            return Err("evidence_invalid");
        }
        if stored != custody
            || u64::try_from(lock_dev).ok() != Some(lock_meta.dev())
            || u64::try_from(lock_ino).ok() != Some(lock_meta.ino())
            || !worker_lock_matches(&root, &lock)
            || u64::try_from(starts).ok() != Some(expected_starts)
            || u64::try_from(records).ok() != Some(expected_records)
        {
            if u64::try_from(lock_dev).ok() != Some(lock_meta.dev())
                || u64::try_from(lock_ino).ok() != Some(lock_meta.ino())
                || !worker_lock_matches(&root, &lock)
            {
                let _ = mark_worker_quarantine(&root);
            }
            return Err("evidence_invalid");
        }
        if validate_history(&db).is_err() {
            let _ = mark_worker_quarantine(&root);
            return Err("evidence_invalid");
        }
        db.execute_batch("COMMIT;").map_err(|_| {
            let _ = mark_worker_quarantine(&root);
            "evidence_invalid"
        })?;
        if !super::la_store::claim_root_matches(&root, &root_path)
            || !worker_lock_matches(&root, &lock)
        {
            let _ = mark_worker_quarantine(&root);
            return Err("evidence_invalid");
        }
        Ok(Self {
            work_entry: None,
            occupancy_keys: None,
            running: None,
            backend: None,
            db,
            lock,
            root,
            root_path,
            quarantined: std::cell::Cell::new(false),
        })
    }

    fn checked_occupancy(&self) -> Result<VerifiedExecutionOccupancy, &'static str> {
        let occupancy =
            verified_execution_occupancy(&self.db, &self.root, self.occupancy_keys.as_deref())?;
        if self.quarantined.get() || worker_quarantined(&self.root)? {
            self.quarantined.set(true);
            return Err("storage_unavailable");
        }
        if !super::la_store::claim_root_matches(&self.root, &self.root_path)
            || !worker_lock_matches(&self.root, &self.lock)
        {
            self.quarantined.set(true);
            let _ = mark_worker_quarantine(&self.root);
            return Err("storage_unavailable");
        }
        Ok(occupancy)
    }

    fn check_root(&self) -> Result<(), &'static str> {
        self.checked_occupancy().map(|_| ())
    }

    /// Authenticate the ENTIRE installed disposition/consumption/retained set
    /// on this call before any selected ID can grant work or readback authority.
    /// Historical identity/occupancy reconstruction and raw entry counts do not
    /// use this guard: they return no execution, result, permit or cleanup right.
    fn guard_ids(
        &self,
        boundary: &'static str,
        assignments: &[&str],
        operations: &[&str],
        jobs: &[&str],
    ) -> Result<(), &'static str> {
        let occupancy = self.checked_occupancy()?;
        if assignments
            .iter()
            .any(|id| occupancy.retired_assignments.contains(*id))
            || operations.iter().any(|id| {
                occupancy.retired_operations.contains(*id)
                    || occupancy.retired_reserve_operations.contains(*id)
            })
            || jobs.iter().any(|id| occupancy.retired_jobs.contains(*id))
        {
            #[cfg(test)]
            RETIRED_REFUSAL.with(|last| last.set(Some(boundary)));
            let _ = boundary;
            return Err("evidence_invalid");
        }
        Ok(())
    }

    fn enter_inspection(
        &mut self,
        op: &str,
        job: &str,
        input: &[u8],
        expected_digest: &str,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> Result<Option<Vec<u8>>, &'static str> {
        self.guard_ids("enter_inspection", &[], &[op], &[job])?;
        self.check_root()?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        if input.len() > MAX_INPUT || !valid_id(op) || !valid_id(job) {
            return Err("artifact_invalid");
        }
        if expected_digest.len() != 64
            || !expected_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("artifact_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let existing: Option<(String, String, String, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT job,input_digest,state,report FROM operations WHERE op=?1",
                [op],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old_job, old_digest, state, report)) = existing {
            if old_job != job || old_digest != expected_digest {
                return Err("idempotency_conflict");
            }
            // A retry never reruns the task, but the supplied bytes still
            // must match the immutable input binding.
            if hex::encode(Sha256::digest(input)) != expected_digest {
                return Err("artifact_invalid");
            }
            return match state.as_str() {
                "complete" => report.map(Some).ok_or("storage_unavailable"),
                "stopped" | "cancelled" => Err("stopped"),
                _ => Err("execution_uncertain"),
            };
        }
        if cancelled() || Instant::now() >= deadline {
            return Err("stopped");
        }
        let records: i64 = tx
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .map_err(|_| "storage_unavailable")?;
        if records >= MAX_OPERATIONS {
            return Err("storage_unavailable");
        }
        // Input transfer must have bound these bytes to the requested digest
        // before a task start is recorded. A mismatch creates no start marker.
        let mut input_hash = Sha256::new();
        for chunk in input.chunks(64 * 1024) {
            if cancelled() || Instant::now() >= deadline {
                return Err("stopped");
            }
            input_hash.update(chunk);
        }
        if cancelled() || Instant::now() >= deadline {
            return Err("stopped");
        }
        if hex::encode(input_hash.finalize()) != expected_digest {
            return Err("artifact_invalid");
        }
        tx.execute(
            "INSERT INTO operations (op,job,input_digest,state) VALUES (?1,?2,?3,'started')",
            params![op, job, expected_digest],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(None)
    }

    pub(super) fn inspect_once(
        &mut self,
        op: &str,
        job: &str,
        input: &[u8],
        expected_digest: &str,
        deadline: Instant,
        cancelled: impl Fn() -> bool,
    ) -> Result<Vec<u8>, &'static str> {
        self.guard_ids("inspect_once", &[], &[op], &[job])?;
        if let Some(report) =
            self.enter_inspection(op, job, input, expected_digest, deadline, &cancelled)?
        {
            return Ok(report);
        }
        // This durable marker deliberately precedes the first hashing read. A
        // crash in the gap is uncertain and must never trigger recomputation.
        if let Some(observe) = &self.work_entry {
            observe(op, job)?;
        }
        self.check_root()?;
        #[cfg(test)]
        if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").is_ok_and(|v| v.starts_with("running-")) {
            // Deterministic fault barrier after the real durable entry, within
            // the original permit and resource bounds.
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let mut bytes = input;
        let report = inspect(&mut bytes, job, deadline, cancelled)?;
        self.publish_inspection(op, expected_digest, &report)?;
        Ok(report)
    }

    fn publish_inspection(
        &mut self,
        op: &str,
        expected_digest: &str,
        report: &[u8],
    ) -> Result<(), &'static str> {
        self.guard_ids("publish_inspection", &[], &[op], &[])?;
        use rusqlite::params;
        let parsed: serde_json::Value =
            serde_json::from_slice(report).map_err(|_| "artifact_invalid")?;
        if parsed["sha256"].as_str() != Some(expected_digest) {
            return Err("artifact_invalid");
        }
        self.check_root()?;
        let changed = self
            .db
            .execute(
                "UPDATE operations SET state='complete',report=?2 WHERE op=?1 AND state='started'",
                params![op, report],
            )
            .map_err(|_| "storage_unavailable")?;
        if changed != 1 {
            return Err("storage_unavailable");
        }
        self.check_root()?;
        Ok(())
    }

    /// Protected construction may observe actual work entry, after the durable
    /// marker and before computation. Observation failure retains uncertainty;
    /// a retry cannot emit another entry or repeat the work.
    pub(super) fn observe_work_entry(
        &mut self,
        observer: std::sync::Arc<WorkEntryObserver>,
    ) -> Result<(), &'static str> {
        self.check_root()?;
        if self.work_entry.is_some() {
            return Err("evidence_invalid");
        }
        self.work_entry = Some(observer);
        Ok(())
    }

    pub(super) fn start_count(&self, op: &str) -> Result<u64, &'static str> {
        self.check_root()?;
        let count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM operations WHERE op=?1 AND state IN ('started','complete','cancelled')",
                [op],
                |r| r.get(0),
            )
            .map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        u64::try_from(count).map_err(|_| "storage_unavailable")
    }
}

/// Independent worker-local stop signal. It grants no admission by itself.
pub(super) struct PermitTimer {
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    state: std::sync::Arc<(std::sync::Mutex<PermitTimerState>, std::sync::Condvar)>,
    hard: std::time::Instant,
    thread: Option<std::thread::JoinHandle<()>>,
}
struct PermitTimerState {
    deadline: std::time::Instant,
    closed: bool,
}
impl PermitTimer {
    pub(super) fn new(
        deadline: std::time::Instant,
        hard: std::time::Instant,
    ) -> Result<Self, &'static str> {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Condvar, Mutex,
        };
        if deadline <= std::time::Instant::now() || deadline > hard {
            return Err("deadline_elapsed");
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let state = Arc::new((
            Mutex::new(PermitTimerState {
                deadline,
                closed: false,
            }),
            Condvar::new(),
        ));
        let thread_stopped = stopped.clone();
        let thread_state = state.clone();
        let thread = std::thread::Builder::new()
            .name("la-permit-timer".into())
            .spawn(move || {
                let (lock, wake) = &*thread_state;
                let mut state = match lock.lock() {
                    Ok(state) => state,
                    Err(_) => {
                        thread_stopped.store(true, Ordering::SeqCst);
                        return;
                    }
                };
                loop {
                    let now = std::time::Instant::now();
                    if state.closed || now >= state.deadline {
                        state.closed = true;
                        thread_stopped.store(true, Ordering::SeqCst);
                        return;
                    }
                    let remaining = state.deadline.saturating_duration_since(now);
                    match wake.wait_timeout(state, remaining) {
                        Ok((next, _)) => state = next,
                        Err(_) => {
                            thread_stopped.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                }
            })
            .map_err(|_| "startup_unavailable")?;
        Ok(Self {
            stopped,
            state,
            hard,
            thread: Some(thread),
        })
    }
    fn deadline(&self) -> Result<Instant, &'static str> {
        self.state
            .0
            .lock()
            .map(|state| state.deadline)
            .map_err(|_| "execution_uncertain")
    }
    pub(super) fn stop_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.stopped.clone()
    }
    /// Signal this operation only; successful signalling is not cleanup proof.
    pub(super) fn stop(&self) -> Result<(), &'static str> {
        use std::sync::atomic::Ordering;
        self.stopped.store(true, Ordering::SeqCst);
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().map_err(|_| "storage_unavailable")?;
        state.closed = true;
        wake.notify_all();
        Ok(())
    }
    pub(super) fn is_stopped(&self) -> bool {
        use std::sync::atomic::Ordering;
        if self.stopped.load(Ordering::SeqCst) {
            return true;
        }
        let (lock, wake) = &*self.state;
        match lock.lock() {
            Ok(mut state) => {
                if state.closed || std::time::Instant::now() >= state.deadline {
                    state.closed = true;
                    self.stopped.store(true, Ordering::SeqCst);
                    wake.notify_all();
                    true
                } else {
                    false
                }
            }
            Err(_) => {
                self.stopped.store(true, Ordering::SeqCst);
                true
            }
        }
    }
    pub(super) fn renew(&self, deadline: std::time::Instant) -> Result<(), &'static str> {
        use std::sync::atomic::Ordering;
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().map_err(|_| {
            self.stopped.store(true, Ordering::SeqCst);
            "deadline_elapsed"
        })?;
        if state.closed
            || self.stopped.load(Ordering::SeqCst)
            || std::time::Instant::now() >= state.deadline
        {
            state.closed = true;
            self.stopped.store(true, Ordering::SeqCst);
            wake.notify_all();
            return Err("deadline_elapsed");
        }
        if deadline <= state.deadline || deadline > self.hard {
            return Err("deadline_elapsed");
        }
        state.deadline = deadline;
        wake.notify_all();
        Ok(())
    }
}
impl Drop for PermitTimer {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.stopped.store(true, Ordering::SeqCst);
        let (lock, wake) = &*self.state;
        if let Ok(mut state) = lock.lock() {
            state.closed = true;
        }
        wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl OperationJournal {
    /// The caller must authenticate the job-local stop. An existing start marker
    /// remains uncertain until the real computation is stopped and inspected.
    pub(super) fn stop_before_start(
        &mut self,
        op: &str,
        job: &str,
        digest: &str,
    ) -> Result<(), &'static str> {
        self.guard_ids("stop_before_start", &[], &[op], &[job])?;
        self.check_root()?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        if !valid_id(op)
            || !valid_id(job)
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("artifact_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let existing: Option<(String, String, String)> = tx
            .query_row(
                "SELECT job,input_digest,state FROM operations WHERE op=?1",
                [op],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old_job, old_digest, state)) = existing {
            if old_job != job || old_digest != digest {
                return Err("idempotency_conflict");
            }
            return match state.as_str() {
                "stopped" => Ok(()),
                "started" => Err("execution_uncertain"),
                _ => Err("state_conflict"),
            };
        }
        let records: i64 = tx
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))
            .map_err(|_| "storage_unavailable")?;
        if records >= MAX_OPERATIONS {
            return Err("storage_unavailable");
        }
        tx.execute(
            "INSERT INTO operations(op,job,input_digest,state) VALUES (?1,?2,?3,'stopped')",
            params![op, job, digest],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        Ok(())
    }
}

impl OperationJournal {
    /// Admission, operation identity and durable permit authenticity must be
    /// checked before entering this private execution primitive.
    pub(super) fn inspect_permitted(
        &mut self,
        op: &str,
        job: &str,
        input: &[u8],
        digest: &str,
        job_deadline: Instant,
        permit: &PermitTimer,
    ) -> Result<Vec<u8>, &'static str> {
        self.guard_ids("inspect_permitted", &[], &[op], &[job])?;
        self.inspect_once(op, job, input, digest, job_deadline, || permit.is_stopped())
    }
}

/// Parsed only from the trusted fixture pipe. No bearer is persisted or logged.
#[cfg(test)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapAuthority {
    service_bearer: String,
    worker_id: String,
    boot_id: String,
    hardware_generation: u64,
    profile_epoch: u64,
    #[serde(default)]
    channel: Option<super::la_adapter::ProtectedChannelBootstrap>,
}

#[cfg(test)]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapCustody {
    mode: String,
    worker_id: String,
    store_id: String,
    root_dev: u64,
    root_inode: u64,
    expected_starts: u64,
    expected_records: u64,
    #[serde(default)]
    worker_handoff: Option<Box<super::la_adapter::WorkerEpochHandoff>>,
    #[serde(default)]
    loss_return: Option<Box<super::la_adapter::WorkerLossReturn>>,
}

#[cfg(test)]
pub(super) struct WorkerBootstrap {
    pub(super) bearer_digest: [u8; 32],
    pub(super) worker_id: String,
    pub(super) boot_id: String,
    pub(super) hardware_generation: u64,
    pub(super) profile_epoch: u64,
    pub(super) store_id: String,
    root_dev: u64,
    root_inode: u64,
    recovery_counts: Option<(u64, u64)>,
    pub(super) worker_handoff: Option<Box<super::la_adapter::WorkerEpochHandoff>>,
    pub(super) loss_return: Option<Box<super::la_adapter::WorkerLossReturn>>,
    pub(super) channel: Option<super::la_adapter::ProtectedChannelBootstrap>,
}

#[cfg(test)]
pub(super) fn validate_bootstrap(
    authority: serde_json::Value,
    custody: serde_json::Value,
) -> Result<WorkerBootstrap, &'static str> {
    use zeroize::Zeroize;
    let mut authority: BootstrapAuthority =
        serde_json::from_value(authority).map_err(|_| "child_config_invalid")?;
    let custody: BootstrapCustody = match serde_json::from_value(custody) {
        Ok(value) => value,
        Err(_) => {
            authority.service_bearer.zeroize();
            return Err("child_config_invalid");
        }
    };
    let hex64 = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && value.bytes().any(|b| b != b'0')
    };
    let id = |value: &str| {
        (16..=128).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    let valid = hex64(&authority.service_bearer)
        && hex64(&authority.boot_id)
        && id(&authority.worker_id)
        && authority.hardware_generation > 0
        && authority.profile_epoch > 0
        && (custody.mode == "bootstrap" || custody.mode == "recover")
        && custody.worker_id == authority.worker_id
        && hex64(&custody.store_id)
        && custody.root_dev > 0
        && custody.root_inode > 0
        && custody.expected_starts <= custody.expected_records
        && custody.expected_records <= MAX_OPERATIONS as u64
        && (custody.mode != "bootstrap"
            || (custody.expected_starts == 0 && custody.expected_records == 0));
    let bearer_digest: [u8; 32] = Sha256::digest(authority.service_bearer.as_bytes()).into();
    authority.service_bearer.zeroize();
    if !valid || (custody.worker_handoff.is_some() && custody.loss_return.is_some()) {
        return Err("child_config_invalid");
    }
    if let Some(channel) = &authority.channel {
        channel.validate(&authority.worker_id, &authority.boot_id, None)?;
        if authority.hardware_generation != channel.binding.hardware_generation
            || authority.profile_epoch != channel.binding.profile_epoch
        {
            return Err("child_config_invalid");
        }
    }
    Ok(WorkerBootstrap {
        worker_handoff: custody.worker_handoff,
        loss_return: custody.loss_return,
        channel: authority.channel.take(),
        bearer_digest,
        worker_id: authority.worker_id,
        boot_id: authority.boot_id,
        hardware_generation: authority.hardware_generation,
        profile_epoch: authority.profile_epoch,
        store_id: custody.store_id,
        root_dev: custody.root_dev,
        root_inode: custody.root_inode,
        recovery_counts: (custody.mode == "recover")
            .then_some((custody.expected_starts, custody.expected_records)),
    })
}

#[cfg(test)]
impl WorkerBootstrap {
    pub(super) fn is_recovery(&self) -> bool {
        self.recovery_counts.is_some()
    }
    /// The protected fixture supplies independent custody counts for recovery.
    /// Neither bootstrap nor this partial recovery check grants admission.
    pub(super) fn initialize_journal(
        &self,
        root: &std::fs::File,
        path: &std::path::Path,
    ) -> Result<OperationJournal, &'static str> {
        if let Some((starts, records)) = self.recovery_counts {
            if let Some(channel) = &self.channel {
                let keys = channel.validate(&self.worker_id, &self.boot_id, None)?;
                if let Some(loss) = &self.loss_return {
                    if loss.binding() != &channel.binding
                        || loss.high_water() != channel.expected_high_water
                    {
                        return Err("evidence_invalid");
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "clock_untrusted")?
                        .as_millis() as u64;
                    loss.verify_worker_root(root, &keys, now)?;
                } else {
                    let handoff = self.worker_handoff.as_ref().ok_or("evidence_invalid")?;
                    if handoff.binding() != &channel.binding
                        || handoff.high_water() != channel.expected_high_water
                    {
                        return Err("evidence_invalid");
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "clock_untrusted")?
                        .as_millis() as u64;
                    handoff.verify_worker_root(root, &keys, now)?;
                }
            } else if self.worker_handoff.is_some() || self.loss_return.is_some() {
                return Err("evidence_invalid");
            }
            self.reopen_with_custody_counts(root, path, starts, records)
        } else {
            if self.worker_handoff.is_some() || self.loss_return.is_some() {
                return Err("evidence_invalid");
            }
            let identity = serde_json::json!({"worker_id":self.worker_id,"store_id":self.store_id,"root_dev":self.root_dev,"root_inode":self.root_inode}).to_string();
            OperationJournal::bootstrap_at(root, path, "worker.sqlite", &identity)
        }
    }

    pub(super) fn reopen_with_custody_counts(
        &self,
        root: &std::fs::File,
        path: &std::path::Path,
        starts: u64,
        records: u64,
    ) -> Result<OperationJournal, &'static str> {
        let identity = serde_json::json!({"worker_id":self.worker_id,"store_id":self.store_id,"root_dev":self.root_dev,"root_inode":self.root_inode}).to_string();
        super::la_tests::WORKER_STORE_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let journal = OperationJournal::reopen_checked(
            &path.join("worker.sqlite"),
            &identity,
            starts,
            records,
        )?;
        use std::os::unix::fs::MetadataExt;
        let expected = root.metadata().map_err(|_| "evidence_invalid")?;
        let actual = journal.root.metadata().map_err(|_| "evidence_invalid")?;
        if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino())
            || !super::la_store::claim_root_matches(root, path)
        {
            return Err("evidence_invalid");
        }
        Ok(journal)
    }

    /// Check the pinned object, not a repeated path. Trusted P still verifies
    /// its independent expected root tuple and all resource gates separately.
    pub(super) fn validate_new_root(&self, root: &std::fs::File) -> Result<(), &'static str> {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let meta = root.metadata().map_err(|_| "startup_root_invalid")?;
        if (meta.dev(), meta.ino()) != (self.root_dev, self.root_inode) {
            return Err("startup_root_invalid");
        }
        if self.recovery_counts.is_none() {
            let mut entries = std::fs::read_dir(format!("/proc/self/fd/{}", root.as_raw_fd()))
                .map_err(|_| "startup_root_invalid")?;
            if entries.next().is_some() {
                return Err("evidence_invalid");
            }
        }
        Ok(())
    }
}

/// Serve only the injected internal worker router. The caller supplies the
/// already-bound isolated listener, validated context and shutdown future.
pub(super) async fn serve_inventory(
    listener: tokio::net::TcpListener,
    context: super::la_adapter::InventoryContext,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), &'static str> {
    axum::serve(listener, super::la_adapter::inventory_router(context))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|_| "startup_unavailable")
}

/// The protected worker bootstrap owns these values. Possession of a supplied
/// key is not itself proof of protected-channel custody or resource admission.
pub(super) struct ReservationSession {
    pub(super) worker: String,
    pub(super) boot: String,
    pub(super) key: [u8; 32],
}

impl OperationJournal {
    /// Authenticate and durably deduplicate the exact reserve command before
    /// producing a sequenced receipt. No job is started by this operation.
    pub(super) fn reserve_authenticated(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::ReserveCommand,
        mac: &[u8; 32],
    ) -> Result<(super::la_adapter::WorkerReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "reserve_authenticated",
            &[&command.assignment],
            &[&command.operation],
            &[],
        )?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        self.check_root()?;
        let digest = super::la_adapter::verify_reserve_command(&session.key, command, mac)?;
        if ![
            &session.worker,
            &session.boot,
            &command.assignment,
            &command.operation,
        ]
        .iter()
        .all(|id| valid_id(id))
            || command.worker != session.worker
            || command.boot != session.boot
            || command.fence == 0
            || command.fence > i64::MAX as u64
            || command.lease_until > i64::MAX as u64
            || command.hard_until > i64::MAX as u64
            || command.lease_until > command.hard_until
        {
            return Err("evidence_invalid");
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if now >= command.lease_until {
            return Err("deadline_elapsed");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        verify_session_history(&tx, &session.key)?;
        let existing: Option<(String,i64,Vec<u8>,i64)> = tx.query_row(
            "SELECT operation,fence,command_digest,sequence FROM worker_reservations WHERE assignment_id=?1",
            [&command.assignment], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))
        ).optional().map_err(|_| "storage_unavailable")?;
        let sequence = if let Some((operation, fence, old_digest, sequence)) = existing {
            if operation != command.operation
                || fence != command.fence as i64
                || old_digest.as_slice() != digest
            {
                return Err("idempotency_conflict");
            }
            sequence
        } else {
            let cursor: Option<(String, String, i64, i64)> = tx
                .query_row(
                    "SELECT worker,boot,sequence,fence FROM reservation_session",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()
                .map_err(|_| "storage_unavailable")?;
            let sequence = if let Some((worker, boot, sequence, fence)) = cursor {
                if worker != session.worker || boot != session.boot || command.fence as i64 <= fence
                {
                    return Err("evidence_invalid");
                }
                sequence.checked_add(1).ok_or("storage_unavailable")?
            } else {
                1
            };
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM worker_reservations", [], |r| r.get(0))
                .map_err(|_| "storage_unavailable")?;
            // Retain all eight assignment histories. A new reservation can
            // follow a locally fenced terminal history, but never an open or
            // uncertain operation. C still retains its claim until independent
            // cleanup/occupancy proof; this is not a service capacity release.
            let occupancy =
                verified_execution_occupancy(&tx, &self.root, self.occupancy_keys.as_deref())?;
            if count >= 8 || occupancy.live_reservations != 0 || occupancy.live_operations != 0 {
                return Err("capacity_unavailable");
            }
            let generations: i64 = tx
                .query_row("SELECT COUNT(*) FROM worker_session_generations", [], |r| {
                    r.get(0)
                })
                .map_err(|_| "evidence_invalid")?;
            if generations == 0 {
                if count != 0 || sequence != 1 {
                    return Err("evidence_invalid");
                }
                append_session_generation(&tx, session, 1, 0, 0, "genesis")?;
            }
            tx.execute("DELETE FROM reservation_session", [])
                .map_err(|_| "storage_unavailable")?;
            tx.execute(
                "INSERT INTO reservation_session VALUES (?1,?2,?3,?4)",
                params![session.worker, session.boot, sequence, command.fence as i64],
            )
            .map_err(|_| "storage_unavailable")?;
            tx.execute(
                "INSERT INTO worker_reservations VALUES (?1,?2,?3,?4,?5,?6,?7,0,0)",
                params![
                    command.assignment,
                    command.operation,
                    command.fence as i64,
                    digest.as_slice(),
                    sequence,
                    command.lease_until as i64,
                    command.hard_until as i64
                ],
            )
            .map_err(|_| "storage_unavailable")?;
            append_session_snapshot(&tx, session, &command.assignment, sequence)?;
            sequence
        };
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        let receipt = super::la_adapter::WorkerReceipt {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            fence: command.fence,
            sequence: u64::try_from(sequence).map_err(|_| "storage_unavailable")?,
            operation: command.operation.clone(),
            assignment: command.assignment.clone(),
            action: "reserved".into(),
            lease_until: command.lease_until,
            hard_until: command.hard_until,
        };
        let signature = super::la_adapter::sign_receipt(&session.key, &receipt)?;
        Ok((receipt, signature))
    }
}

impl OperationJournal {
    /// Execute only an authenticated command for the currently fenced
    /// reservation. The independent local timer never extends on controller
    /// silence, and the operation journal prevents a second start.
    pub(super) fn inspect_authenticated(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        mac: &[u8; 32],
        input: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.guard_ids(
            "inspect_authenticated",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        let (hard, timer) = self.authenticate_inspection(session, command, mac)?;
        if command.backend.is_some() {
            return Err("capability_unavailable");
        }
        self.inspect_permitted(
            &command.operation,
            &command.job,
            input,
            &command.input_digest,
            hard,
            &timer,
        )
    }
}

impl OperationJournal {
    fn authenticate_inspection(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        mac: &[u8; 32],
    ) -> Result<(Instant, PermitTimer), &'static str> {
        self.guard_ids(
            "authenticate_inspection",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::{params, TransactionBehavior};
        self.check_root()?;
        verify_session_history(&self.db, &session.key)?;
        let command_digest = super::la_adapter::verify_start_command(&session.key, command, mac)?;
        if command.worker != session.worker
            || command.boot != session.boot
            || ![&command.assignment, &command.operation, &command.job]
                .iter()
                .all(|v| valid_id(v))
            || command.fence == 0
            || command.fence > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let mono = Instant::now();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if command.accepted_at > now
            || command.mandate_until <= now
            || command.permit_until <= now
            || command.permit_until > command.mandate_until
            || command.mandate_until
                > command
                    .accepted_at
                    .checked_add(10_000)
                    .ok_or("deadline_elapsed")?
            || command.permit_until > now.checked_add(2_000).ok_or("deadline_elapsed")?
        {
            return Err("deadline_elapsed");
        }
        let hard = mono
            .checked_add(std::time::Duration::from_millis(
                command.mandate_until - now,
            ))
            .ok_or("clock_untrusted")?;
        let until = mono
            .checked_add(std::time::Duration::from_millis(command.permit_until - now))
            .ok_or("clock_untrusted")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM worker_reservations r JOIN reservation_session s ON s.fence=r.fence WHERE r.assignment_id=?1 AND r.fence=?2 AND s.worker=?3 AND s.boot=?4 AND r.lease_until>=?5 AND r.lease_until>?6 AND r.closed=0)",
            params![command.assignment,command.fence as i64,session.worker,session.boot,command.permit_until as i64,now as i64], |r| r.get(0)
        ).map_err(|_| "storage_unavailable")?;
        if !reserved {
            return Err("evidence_invalid");
        }
        let old = effective_worker_command(&tx, &command.operation)?;
        match old {
            Some(old) if old.as_slice() == command_digest => (),
            Some(_) => return Err("idempotency_conflict"),
            None => return Err("evidence_invalid"),
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        let timer = PermitTimer::new(until, hard)?;
        Ok((hard, timer))
    }
}

impl OperationJournal {
    /// Durable stop-before-start tombstone. An already-started operation stays
    /// uncertain; this method does not assert that running work was stopped.
    pub(super) fn stop_authenticated_before_start(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        self.guard_ids(
            "stop_authenticated_before_start",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::params;
        self.check_root()?;
        super::la_adapter::verify_stop_command(&session.key, command, mac)?;
        if command.worker != session.worker
            || command.boot != session.boot
            || command.fence == 0
            || command.fence > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let reserved: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM worker_reservations r JOIN reservation_session s ON s.fence=r.fence WHERE r.assignment_id=?1 AND r.fence=?2 AND s.worker=?3 AND s.boot=?4 AND r.closed=0)",
            params![command.assignment,command.fence as i64,session.worker,session.boot], |r| r.get(0)
        ).map_err(|_| "storage_unavailable")?;
        if !reserved {
            return Err("evidence_invalid");
        }
        self.stop_before_start(&command.operation, &command.job, &command.input_digest)
    }
}

impl OperationJournal {
    /// Persist a worker-local permit before acknowledging it; this does not
    /// start work. A changed command cannot reuse its operation identity.
    pub(super) fn accept_inspect_permit(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        mac: &[u8; 32],
    ) -> Result<(super::la_adapter::PermitReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "accept_inspect_permit",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        self.check_root()?;
        verify_session_history(&self.db, &session.key)?;
        let digest = super::la_adapter::verify_inspect_command(&session.key, command, mac)?;
        if command.worker != session.worker
            || command.boot != session.boot
            || command.fence == 0
            || command.fence > i64::MAX as u64
            || ![&command.assignment, &command.operation, &command.job]
                .iter()
                .all(|v| valid_id(v))
        {
            return Err("evidence_invalid");
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if command.accepted_at > now
            || command.permit_until <= now
            || command.permit_until > command.mandate_until
            || command.mandate_until
                > command
                    .accepted_at
                    .checked_add(10_000)
                    .ok_or("deadline_elapsed")?
            || command.permit_until > now.checked_add(2_000).ok_or("deadline_elapsed")?
        {
            return Err("deadline_elapsed");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let cursor: Option<(String, String, i64, i64)> = tx
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let (worker, boot, last, fence) = cursor.ok_or("evidence_invalid")?;
        let reserved: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM worker_reservations WHERE assignment_id=?1 AND fence=?2 AND lease_until>=?3 AND lease_until>?4 AND closed=0)",params![command.assignment,command.fence as i64,command.permit_until as i64,now as i64],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if worker != session.worker
            || boot != session.boot
            || fence != command.fence as i64
            || !reserved
        {
            return Err("evidence_invalid");
        }
        let old: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT command_digest,sequence FROM worker_inspect_commands WHERE operation=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let sequence = if let Some((old, sequence)) = old {
            if old.as_slice() != digest {
                return Err("idempotency_conflict");
            }
            sequence
        } else {
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM worker_inspect_commands", [], |r| {
                    r.get(0)
                })
                .map_err(|_| "storage_unavailable")?;
            if count >= MAX_OPERATIONS {
                return Err("capacity_unavailable");
            }
            let sequence = last.checked_add(1).ok_or("storage_unavailable")?;
            tx.execute(
                "INSERT INTO worker_inspect_commands VALUES (?1,?2,?3)",
                params![command.operation, digest.as_slice(), sequence],
            )
            .map_err(|_| "storage_unavailable")?;
            tx.execute("UPDATE reservation_session SET sequence=?1", [sequence])
                .map_err(|_| "storage_unavailable")?;
            append_session_snapshot(&tx, session, &command.assignment, sequence)?;
            sequence
        };
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if after < now || after >= command.permit_until {
            return Err("deadline_elapsed");
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        let receipt = super::la_adapter::PermitReceipt {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            fence: command.fence,
            sequence: u64::try_from(sequence).map_err(|_| "storage_unavailable")?,
            assignment: command.assignment.clone(),
            operation: command.operation.clone(),
            job: command.job.clone(),
            command_digest: hex::encode(digest),
            permit_until: command.permit_until,
        };
        let signature = super::la_adapter::sign_permit_receipt(&session.key, &receipt)?;
        Ok((receipt, signature))
    }
}

impl OperationJournal {
    /// Compute using the authenticated start and issue a signed receipt for the
    /// durable report. Receipt retries return the same sequence and bytes.
    pub(super) fn inspect_with_receipt(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        start_mac: &[u8; 32],
        input: &[u8],
    ) -> Result<(Vec<u8>, super::la_adapter::ResultReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "inspect_with_receipt",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        let report = self.inspect_authenticated(session, command, start_mac, input)?;
        self.inspection_receipt(session, command, report)
    }
    fn inspection_receipt(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        report: Vec<u8>,
    ) -> Result<(Vec<u8>, super::la_adapter::ResultReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "inspection_receipt",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        if command.backend.is_some() {
            la_backend::validate_report(
                &report,
                &command.job,
                &command.input_digest,
                None,
                command.backend,
            )?;
        }
        let report_digest = hex::encode(Sha256::digest(&report));
        self.check_root()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT digest,byte_count,sequence FROM worker_result_receipts WHERE operation=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let sequence = if let Some((digest, count, sequence)) = old {
            if digest != report_digest || usize::try_from(count).ok() != Some(report.len()) {
                return Err("evidence_invalid");
            }
            sequence
        } else {
            let (worker, boot, last, fence): (String, String, i64, i64) = tx
                .query_row(
                    "SELECT worker,boot,sequence,fence FROM reservation_session",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .map_err(|_| "storage_unavailable")?;
            if worker != session.worker
                || boot != session.boot
                || u64::try_from(fence).ok() != Some(command.fence)
            {
                return Err("evidence_invalid");
            }
            let sequence = last.checked_add(1).ok_or("storage_unavailable")?;
            tx.execute(
                "INSERT INTO worker_result_receipts VALUES (?1,?2,?3,?4)",
                params![
                    command.operation,
                    report_digest,
                    report.len() as i64,
                    sequence
                ],
            )
            .map_err(|_| "storage_unavailable")?;
            tx.execute("UPDATE reservation_session SET sequence=?1", [sequence])
                .map_err(|_| "storage_unavailable")?;
            append_session_snapshot(&tx, session, &command.assignment, sequence)?;
            sequence
        };
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        let receipt = super::la_adapter::ResultReceipt {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            fence: command.fence,
            sequence: u64::try_from(sequence).map_err(|_| "storage_unavailable")?,
            assignment: command.assignment.clone(),
            operation: command.operation.clone(),
            job: command.job.clone(),
            report_digest,
            report_bytes: report.len() as u64,
        };
        let signature = super::la_adapter::sign_result_receipt(&session.key, &receipt)?;
        Ok((report, receipt, signature))
    }
}

impl OperationJournal {
    /// Worker-local lease extension; no work permit is extended by this call.
    pub(super) fn renew_authenticated(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::RenewCommand,
        mac: &[u8; 32],
    ) -> Result<(super::la_adapter::RenewReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "renew_authenticated",
            &[&command.assignment],
            &[&command.operation],
            &[],
        )?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        self.check_root()?;
        let digest = super::la_adapter::verify_renew_command(&session.key, command, mac)?;
        if command.worker != session.worker
            || command.boot != session.boot
            || !valid_id(&command.assignment)
            || !valid_id(&command.operation)
            || command.fence == 0
            || command.fence > i64::MAX as u64
            || command.revision == 0
            || command.revision > i64::MAX as u64
            || command.previous_until > i64::MAX as u64
            || command.requested_until > i64::MAX as u64
            || command.requested_until <= command.previous_until
        {
            return Err("evidence_invalid");
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if now >= command.previous_until {
            return Err("deadline_elapsed");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let (worker, boot, last, fence): (String, String, i64, i64) = tx
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if worker != session.worker
            || boot != session.boot
            || u64::try_from(fence).ok() != Some(command.fence)
        {
            return Err("evidence_invalid");
        }
        let old: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT digest,sequence FROM worker_renewals WHERE operation=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let sequence = if let Some((old, seq)) = old {
            if old.as_slice() != digest {
                return Err("idempotency_conflict");
            }
            seq
        } else {
            let state:Option<(i64,i64,i64)>=tx.query_row("SELECT lease_until,hard_until,revision FROM worker_reservations WHERE assignment_id=?1 AND fence=?2 AND closed=0",params![command.assignment,command.fence as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|"storage_unavailable")?;
            let (lease, hard, revision) = state.ok_or("evidence_invalid")?;
            if u64::try_from(lease).ok() != Some(command.previous_until)
                || u64::try_from(hard)
                    .ok()
                    .is_none_or(|v| command.requested_until > v)
                || revision.checked_add(1) != Some(command.revision as i64)
            {
                return Err("evidence_invalid");
            }
            let seq = last.checked_add(1).ok_or("storage_unavailable")?;
            tx.execute(
                "UPDATE worker_reservations SET lease_until=?2,revision=?3 WHERE assignment_id=?1",
                params![
                    command.assignment,
                    command.requested_until as i64,
                    command.revision as i64
                ],
            )
            .map_err(|_| "storage_unavailable")?;
            tx.execute(
                "INSERT INTO worker_renewals VALUES (?1,?2,?3)",
                params![command.operation, digest.as_slice(), seq],
            )
            .map_err(|_| "storage_unavailable")?;
            tx.execute("UPDATE reservation_session SET sequence=?1", [seq])
                .map_err(|_| "storage_unavailable")?;
            append_session_snapshot(&tx, session, &command.assignment, seq)?;
            seq
        };
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if after < now || after >= command.previous_until {
            return Err("deadline_elapsed");
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        let receipt = super::la_adapter::RenewReceipt {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: command.assignment.clone(),
            fence: command.fence,
            operation: command.operation.clone(),
            revision: command.revision,
            sequence: u64::try_from(sequence).map_err(|_| "storage_unavailable")?,
            previous_until: command.previous_until,
            acknowledged_until: command.requested_until,
        };
        let mac = super::la_adapter::sign_renew_receipt(&session.key, &receipt)?;
        Ok((receipt, mac))
    }
}

impl OperationJournal {
    /// Sign only a durable pre-entry tombstone or an entered task whose actual
    /// join published cancellation. Missing owners/markers remain uncertain.
    pub(super) fn stop_with_receipt(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        mac: &[u8; 32],
    ) -> Result<(super::la_adapter::StopReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "stop_with_receipt",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        super::la_adapter::verify_stop_command(&session.key, command, mac)?;
        self.authenticate_running_command(session, command)?;
        if let Some(task) = &self.running {
            if task.command.operation == command.operation {
                #[cfg(test)]
                if std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                    .is_ok_and(|v| v.starts_with("running-"))
                {
                    use std::io::Write;
                    let at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "clock_untrusted")?
                        .as_millis() as u64;
                    println!(
                        "DIFFUSER_LA_CHILD_V1 {}",
                        serde_json::json!({"kind":"STOP_SIGNALLED","operation":command.operation,"job":command.job,"worker_boot":command.boot,"pid":std::process::id(),"observed_at":at,"permit_until":command.permit_until,"task_exists":true})
                    );
                    std::io::stdout().flush().map_err(|_| "control_invalid")?;
                }
                task.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let until = Instant::now() + std::time::Duration::from_millis(10);
        while self
            .running
            .as_ref()
            .is_some_and(|t| !t.thread.is_finished())
            && Instant::now() < until
        {
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        self.reap_inspection()?;
        let (state, _) = self.authenticated_status(session, command)?;
        if state != "cancelled" {
            self.stop_authenticated_before_start(session, command, mac)?;
        } else {
            super::la_adapter::verify_stop_command(&session.key, command, mac)?;
        }
        let digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?).into();
        self.check_root()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let existing: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT command_digest,sequence FROM worker_stop_receipts WHERE operation=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let sequence = if let Some((old, seq)) = existing {
            if old.as_slice() != digest {
                return Err("idempotency_conflict");
            }
            seq
        } else {
            let (worker, boot, last, fence): (String, String, i64, i64) = tx
                .query_row(
                    "SELECT worker,boot,sequence,fence FROM reservation_session",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if worker != session.worker
                || boot != session.boot
                || u64::try_from(fence).ok() != Some(command.fence)
            {
                return Err("evidence_invalid");
            }
            let seq = last.checked_add(1).ok_or("storage_unavailable")?;
            tx.execute(
                "INSERT INTO worker_stop_receipts VALUES (?1,?2,?3)",
                params![command.operation, digest.as_slice(), seq],
            )
            .map_err(|_| "storage_unavailable")?;
            tx.execute("UPDATE reservation_session SET sequence=?1", [seq])
                .map_err(|_| "storage_unavailable")?;
            append_session_snapshot(&tx, session, &command.assignment, seq)?;
            seq
        };
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        let receipt = super::la_adapter::StopReceipt {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: command.assignment.clone(),
            fence: command.fence,
            sequence: u64::try_from(sequence).map_err(|_| "storage_unavailable")?,
            operation: command.operation.clone(),
            job: command.job.clone(),
            command_digest: hex::encode(digest),
        };
        let mac = super::la_adapter::sign_stop_receipt(&session.key, &receipt)?;
        Ok((receipt, mac))
    }
}

impl OperationJournal {
    /// Fence further worker commands after every local operation is terminal.
    /// This proves a worker tombstone only, not external process cleanup.
    pub(super) fn close_authenticated(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::CloseCommand,
        mac: &[u8; 32],
    ) -> Result<(super::la_adapter::CloseReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "close_authenticated",
            &[&command.assignment],
            &[&command.operation],
            &[],
        )?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        self.check_root()?;
        let digest = super::la_adapter::verify_close_command(&session.key, command, mac)?;
        if command.worker != session.worker
            || command.boot != session.boot
            || !valid_id(&command.assignment)
            || !valid_id(&command.operation)
            || command.fence == 0
            || command.fence > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let (worker, boot, last, fence): (String, String, i64, i64) = tx
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        if worker != session.worker
            || boot != session.boot
            || u64::try_from(fence).ok() != Some(command.fence)
        {
            return Err("evidence_invalid");
        }
        let existing: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT command_digest,sequence FROM worker_close_receipts WHERE operation=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let sequence = if let Some((old, seq)) = existing {
            if old.as_slice() != digest {
                return Err("idempotency_conflict");
            }
            seq
        } else {
            if verified_execution_occupancy(&tx, &self.root, self.occupancy_keys.as_deref())?
                .live_operations
                != 0
            {
                return Err("execution_uncertain");
            }
            let changed=tx.execute("UPDATE worker_reservations SET closed=1 WHERE assignment_id=?1 AND fence=?2 AND closed=0",params![command.assignment,command.fence as i64]).map_err(|_|"storage_unavailable")?;
            if changed != 1 {
                return Err("state_conflict");
            }
            let seq = last.checked_add(1).ok_or("storage_unavailable")?;
            tx.execute(
                "INSERT INTO worker_close_receipts VALUES (?1,?2,?3)",
                params![command.operation, digest.as_slice(), seq],
            )
            .map_err(|_| "storage_unavailable")?;
            tx.execute("UPDATE reservation_session SET sequence=?1", [seq])
                .map_err(|_| "storage_unavailable")?;
            append_session_snapshot(&tx, session, &command.assignment, seq)?;
            seq
        };
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        self.cleanup_fenced_inputs(command, sequence)?;
        let receipt = super::la_adapter::CloseReceipt {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: command.assignment.clone(),
            fence: command.fence,
            operation: command.operation.clone(),
            sequence: u64::try_from(sequence).map_err(|_| "storage_unavailable")?,
        };
        let mac = super::la_adapter::sign_close_receipt(&session.key, &receipt)?;
        Ok((receipt, mac))
    }
}

impl OperationJournal {
    /// Persist the authenticated input under the bounded worker root. The
    /// operation and digest are immutable; transfer never creates a start.
    pub(super) fn stage_authenticated_input(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        mac: &[u8; 32],
        input: &[u8],
    ) -> Result<(), &'static str> {
        self.guard_ids(
            "stage_authenticated_input",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::{params, OptionalExtension, TransactionBehavior};
        self.check_root()?;
        verify_session_history(&self.db, &session.key)?;
        let digest = super::la_adapter::verify_stage_command(&session.key, command, mac)?;
        if command.worker != session.worker
            || command.boot != session.boot
            || command.fence == 0
            || command.fence > i64::MAX as u64
            || !valid_id(&command.assignment)
            || !valid_id(&command.operation)
            || !valid_id(&command.job)
        {
            return Err("evidence_invalid");
        }
        if input.len() > MAX_INPUT || hex::encode(Sha256::digest(input)) != command.input_digest {
            return Err("artifact_invalid");
        }
        let mono = Instant::now();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        let remaining = command
            .permit_until
            .checked_sub(now)
            .filter(|v| *v > 0)
            .ok_or("deadline_elapsed")?;
        let deadline = mono
            .checked_add(std::time::Duration::from_millis(remaining))
            .ok_or("clock_untrusted")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let permitted:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM worker_inspect_commands i JOIN worker_reservations r ON r.assignment_id=?2 JOIN reservation_session s ON s.fence=r.fence WHERE i.operation=?1 AND r.fence=?4 AND r.closed=0 AND r.lease_until>=?5 AND s.worker=?6 AND s.boot=?7)",params![command.operation,command.assignment,digest.as_slice(),command.fence as i64,command.permit_until as i64,session.worker,session.boot],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if !permitted
            || effective_worker_command(&tx, &command.operation)?.as_deref()
                != Some(digest.as_slice())
        {
            return Err("evidence_invalid");
        }
        let old: Option<(Vec<u8>, String, String)> = tx
            .query_row(
                "SELECT command_digest,input_digest,content FROM worker_inputs WHERE operation=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old_command, old_digest, old_content)) = old {
            if !rebound_staged_command(&tx, &command.operation, &old_command, &digest)?
                || old_digest != command.input_digest
                || read_staged_file(&self.root, &old_content, &command.input_digest)? != input
            {
                return Err("idempotency_conflict");
            }
        } else {
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM worker_inputs", [], |r| r.get(0))
                .map_err(|_| "storage_unavailable")?;
            if count >= MAX_OPERATIONS {
                return Err("capacity_unavailable");
            }
            let name = staged_file_name(&command.operation);
            use std::io::Write;
            match super::la_artifacts::open_artifact(
                &self.root,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            ) {
                Ok(mut file) => {
                    for chunk in input.chunks(64 * 1024) {
                        if Instant::now() >= deadline {
                            return Err("deadline_elapsed");
                        }
                        file.write_all(chunk).map_err(|_| "storage_unavailable")?;
                    }
                    file.sync_all()
                        .and_then(|_| self.root.sync_all())
                        .map_err(|_| "storage_unavailable")?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A crash between file fsync and row commit may leave this
                    // exact immutable file. It never authorizes execution.
                    if read_staged_file(&self.root, &name, &command.input_digest)? != input {
                        return Err("evidence_invalid");
                    }
                }
                Err(_) => return Err("storage_unavailable"),
            }
            tx.execute(
                "INSERT INTO worker_inputs VALUES (?1,?2,?3,?4)",
                params![
                    command.operation,
                    digest.as_slice(),
                    command.input_digest,
                    name
                ],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        tx.execute(
            "INSERT INTO worker_input_assignments VALUES (?1,?2) ON CONFLICT(operation) DO NOTHING",
            params![command.operation, command.assignment],
        )
        .map_err(|_| "storage_unavailable")?;
        let bound: String = tx
            .query_row(
                "SELECT assignment FROM worker_input_assignments WHERE operation=?1",
                [&command.operation],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if bound != command.assignment {
            return Err("evidence_invalid");
        }
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|v| u64::try_from(v.as_millis()).ok())
            .ok_or("clock_untrusted")?;
        if after < now || after >= command.permit_until || Instant::now() >= deadline {
            return Err("deadline_elapsed");
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()
    }

    /// Re-read staged bytes from the worker journal and compute only the exact
    /// permitted operation; supplied bytes are not trusted as worker output.
    pub(super) fn inspect_staged(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        start_mac: &[u8; 32],
    ) -> Result<(Vec<u8>, super::la_adapter::ResultReceipt, [u8; 32]), &'static str> {
        self.guard_ids(
            "inspect_staged",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        let input = self.staged_inspection_input(session, command, start_mac)?;
        self.inspect_with_receipt(session, command, start_mac, &input)
    }
}

impl OperationJournal {
    fn staged_inspection_input(
        &self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
        start_mac: &[u8; 32],
    ) -> Result<Vec<u8>, &'static str> {
        self.guard_ids(
            "staged_inspection_input",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::OptionalExtension;
        self.check_root()?;
        verify_session_history(&self.db, &session.key)?;
        let digest = super::la_adapter::verify_start_command(&session.key, command, start_mac)?;
        let row: Option<(Vec<u8>, String, String)> = self
            .db
            .query_row(
                "SELECT command_digest,input_digest,content FROM worker_inputs WHERE operation=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let (stored, input_digest, name) = row.ok_or("input_unavailable")?;
        if !rebound_staged_command(&self.db, &command.operation, &stored, &digest)?
            || input_digest != command.input_digest
            || name != staged_file_name(&command.operation)
        {
            return Err("evidence_invalid");
        }
        let input = read_staged_file(&self.root, &name, &input_digest)?;
        Ok(input)
    }
}

impl OperationJournal {
    /// Signed-channel observation of this exact immutable command. A missing
    /// record is an observation, not proof that cleanup made capacity reusable.
    pub(super) fn authenticated_status(
        &self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
    ) -> Result<(String, u64), &'static str> {
        self.guard_ids(
            "authenticated_status",
            &[&command.assignment],
            &[&command.operation],
            &[&command.job],
        )?;
        use rusqlite::{params, OptionalExtension};
        self.check_root()?;
        if command.worker != session.worker
            || command.boot != session.boot
            || !valid_id(&command.operation)
            || !valid_id(&command.job)
        {
            return Err("evidence_invalid");
        }
        let expected = Sha256::digest(serde_json::to_vec(command).map_err(|_| "evidence_invalid")?);
        let stored = effective_worker_command(&self.db, &command.operation)?;
        if let Some(stored) = stored {
            if stored.as_slice() != expected.as_slice() {
                return Err("evidence_invalid");
            }
        }
        let state: Option<(String, String, String)> = self
            .db
            .query_row(
                "SELECT job,input_digest,state FROM operations WHERE op=?1",
                [&command.operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let reserved:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM worker_reservations WHERE assignment_id=?1 AND fence=?2)",params![command.assignment,i64::try_from(command.fence).map_err(|_|"evidence_invalid")?],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if !reserved {
            return Err("evidence_invalid");
        }
        let starts = self.start_count(&command.operation)?;
        match state {
            Some((job, digest, state)) if job == command.job && digest == command.input_digest => {
                Ok((state, starts))
            }
            None => Ok(("never_seen".into(), starts)),
            _ => Err("evidence_invalid"),
        }
    }
}

impl Drop for ReservationSession {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

/// Lifecycle callers use one normal interface. Only synthetic in-process tests
/// can construct the local backend; real injected C owns a private HTTP client.
pub(super) enum WorkerConnection {
    #[cfg(test)]
    Local(OperationJournal),
    Remote(Box<super::la_adapter::WorkerClient>),
}
impl WorkerConnection {
    pub(super) fn private_cuda_backend(&self) -> Option<Capability> {
        match self {
            #[cfg(test)]
            Self::Local(_) => None,
            Self::Remote(client) => client.private_cuda_backend(),
        }
    }

    pub(super) fn negotiate_backend(&mut self, capability: Capability) -> Result<(), &'static str> {
        #[cfg(test)]
        if let Self::Local(journal) = self {
            return journal.backend_ready(capability);
        }
        // An older peer can refuse the new RPC. Keep the original typed
        // selection closed and preserve the ordered transport's uncertainty.
        match self.reply(super::la_adapter::WorkerOperation::Backend(capability), &[]) {
            Ok(super::la_adapter::WorkerReply::Backend(ready)) if ready == capability => Ok(()),
            _ => Err("capability_unavailable"),
        }
    }

    pub(super) fn admission(&self) -> Result<(), &'static str> {
        match self {
            #[cfg(test)]
            Self::Local(_) => Ok(()),
            Self::Remote(c) => c.admission(),
        }
    }
    fn reply(
        &mut self,
        operation: super::la_adapter::WorkerOperation,
        input: &[u8],
    ) -> Result<super::la_adapter::WorkerReply, &'static str> {
        let typed = operation.typed_backend();
        match self {
            Self::Remote(c) => match c.call(operation, input)? {
                super::la_adapter::WorkerReply::Refused { code } => Err(match code.as_str() {
                    "capability_unavailable" if typed => "capability_unavailable",
                    "execution_uncertain" if typed => "execution_uncertain",
                    "deadline_elapsed" => "deadline_elapsed",
                    "capacity_unavailable" => "capacity_unavailable",
                    "idempotency_conflict" => "idempotency_conflict",
                    "transport_uncertain" => "transport_uncertain",
                    "storage_unavailable" => "storage_unavailable",
                    _ => "evidence_invalid",
                }),
                reply => Ok(reply),
            },
            #[cfg(test)]
            Self::Local(_) => Err("evidence_invalid"),
        }
    }
    pub(super) fn stage_authenticated_input(
        &mut self,
        s: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
        m: &[u8; 32],
        input: &[u8],
    ) -> Result<(), &'static str> {
        #[cfg(test)]
        if let Self::Local(j) = self {
            return j.stage_authenticated_input(s, c, m, input);
        }
        let digest = super::la_adapter::verify_stage_command(&s.key, c, m)?;
        match self.reply(super::la_adapter::WorkerOperation::Stage(c.clone()), input)? {
            super::la_adapter::WorkerReply::Staged {
                operation,
                command_digest,
                input_digest,
                input_bytes,
            } if operation == c.operation
                && command_digest == hex::encode(digest)
                && input_digest == c.input_digest
                && input_bytes == input.len() as u64 =>
            {
                Ok(())
            }
            _ => Err("evidence_invalid"),
        }
    }
    pub(super) fn inspect_staged(
        &mut self,
        s: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
        m: &[u8; 32],
    ) -> Result<(Vec<u8>, super::la_adapter::ResultReceipt, [u8; 32]), &'static str> {
        #[cfg(test)]
        if let Self::Local(j) = self {
            if c.backend.is_none() {
                return j.inspect_staged(s, c, m);
            }
        }
        super::la_adapter::verify_start_command(&s.key, c, m)?;
        let reply = match self {
            #[cfg(test)]
            Self::Local(j) => j.start_inspection(s, c)?,
            Self::Remote(_) => {
                self.reply(super::la_adapter::WorkerOperation::Start(c.clone()), &[])?
            }
        };
        match reply {
            super::la_adapter::WorkerReply::Result(b, r, m) if b.len() <= 4096 => {
                super::la_adapter::verify_result_receipt(&s.key, &r, &m)?;
                Ok((b, r, m))
            }
            super::la_adapter::WorkerReply::Status {
                operation,
                state,
                starts: 1,
            } if operation == c.operation && state == "started" => Err("work_running"),
            _ => Err("evidence_invalid"),
        }
    }

    pub(super) fn fetch_inspection(
        &mut self,
        _session: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
    ) -> Result<super::la_adapter::WorkerReply, &'static str> {
        if c.backend.is_some() {
            match self {
                #[cfg(test)]
                Self::Local(j) => return j.inspection_reply(_session, c),
                Self::Remote(client) => {
                    if let Some(reply) = client.retry_pending_inspection(c)? {
                        return Ok(reply);
                    }
                }
            }
        }
        self.reply(super::la_adapter::WorkerOperation::Fetch(c.clone()), &[])
    }
}

macro_rules! connection_method {
    ($method:ident,$command:ty,$verify:ident,$operation:ident,$reply:ident,$receipt:ty,$verify_receipt:ident) => {
        impl WorkerConnection {
            pub(super) fn $method(
                &mut self,
                s: &ReservationSession,
                c: &$command,
                m: &[u8; 32],
            ) -> Result<($receipt, [u8; 32]), &'static str> {
                #[cfg(test)]
                if let Self::Local(j) = self {
                    return j.$method(s, c, m);
                }
                super::la_adapter::$verify(&s.key, c, m)?;
                match self.reply(
                    super::la_adapter::WorkerOperation::$operation(c.clone()),
                    &[],
                )? {
                    super::la_adapter::WorkerReply::$reply(r, m) => {
                        super::la_adapter::$verify_receipt(&s.key, &r, &m)?;
                        Ok((r, m))
                    }
                    _ => Err("evidence_invalid"),
                }
            }
        }
    };
}

connection_method!(
    stop_with_receipt,
    super::la_adapter::InspectCommand,
    verify_stop_command,
    Stop,
    Stopped,
    super::la_adapter::StopReceipt,
    verify_stop_receipt
);
connection_method!(
    renew_authenticated,
    super::la_adapter::RenewCommand,
    verify_renew_command,
    Renew,
    Renewed,
    super::la_adapter::RenewReceipt,
    verify_renew_receipt
);
connection_method!(
    close_authenticated,
    super::la_adapter::CloseCommand,
    verify_close_command,
    Close,
    Closed,
    super::la_adapter::CloseReceipt,
    verify_close_receipt
);

/// Seal a controlled fixture role after its fixed executable and namespace/root
/// custody have been established. TSYNC covers existing threads; future threads
/// inherit it. No process creation, exec, namespace change or mount mutation can
/// occur after this point. Thread creation remains available to timers/HTTP.
/// This is process-local qualification plumbing, never host policy installation.
#[cfg(target_arch = "x86_64")]
pub(super) fn seal_fixture_role() -> Result<serde_json::Value, &'static str> {
    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    const LOAD: u16 = 0x20;
    const EQ: u16 = 0x15;
    const SET: u16 = 0x45;
    const RET: u16 = 0x06;
    const ALLOW: u32 = 0x7fff0000;
    const ERRNO: u32 = 0x00050000;
    const KILL: u32 = 0x80000000;
    let mut filter = vec![
        stmt(LOAD, 4),
        jump(EQ, 0xc000003e, 1, 0),
        stmt(RET, KILL),
        stmt(LOAD, 0),
        jump(SET, 0x40000000, 0, 1),
        stmt(RET, ERRNO | libc::EPERM as u32),
    ];
    for number in [
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_ptrace,
        libc::SYS_process_vm_writev,
        libc::SYS_open_by_handle_at,
        libc::SYS_bpf,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
    ] {
        filter.push(jump(EQ, number as u32, 0, 1));
        filter.push(stmt(RET, ERRNO | libc::EPERM as u32));
    }
    // libc falls back to clone with visible flags on ENOSYS. Never accept the
    // opaque clone3 argument structure as proof of a thread-only operation.
    filter.push(jump(EQ, libc::SYS_clone3 as u32, 0, 1));
    filter.push(stmt(RET, ERRNO | libc::ENOSYS as u32));
    filter.push(jump(EQ, libc::SYS_clone as u32, 0, 6));
    filter.push(stmt(LOAD, 16));
    filter.push(jump(SET, libc::CLONE_THREAD as u32, 1, 0));
    filter.push(stmt(RET, ERRNO | libc::EPERM as u32));
    let namespace_flags = (libc::CLONE_NEWCGROUP
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWUSER
        | libc::CLONE_NEWUTS) as u32;
    filter.push(jump(SET, namespace_flags, 0, 1));
    filter.push(stmt(RET, ERRNO | libc::EPERM as u32));
    filter.push(stmt(RET, ALLOW));
    filter.push(stmt(RET, ALLOW));
    let mut digest = Sha256::new();
    for instruction in &filter {
        digest.update(instruction.code.to_le_bytes());
        digest.update([instruction.jt, instruction.jf]);
        digest.update(instruction.k.to_le_bytes());
    }
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).map_err(|_| "evidence_invalid")?,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::syscall(libc::SYS_seccomp, 1, 1, &program) } != 0
    {
        return Err("resource_unqualified");
    }
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    // Negative observations are made only in this job-owned role. Unexpected
    // fork success exits/reaps the bounded probe child before failing closed.
    let fork = unsafe { libc::syscall(libc::SYS_fork) };
    if fork == 0 {
        unsafe { libc::_exit(101) }
    }
    if fork > 0 {
        unsafe { libc::waitpid(fork as i32, std::ptr::null_mut(), 0) };
        return Err("resource_unqualified");
    }
    let fork_errno = std::io::Error::last_os_error().raw_os_error();
    let unshare = unsafe { libc::syscall(libc::SYS_unshare, 0) };
    let unshare_errno = std::io::Error::last_os_error().raw_os_error();
    let exec = unsafe {
        libc::syscall(
            libc::SYS_execve,
            c"/nonexistent-job-seal-probe".as_ptr(),
            std::ptr::null::<*const libc::c_char>(),
            std::ptr::null::<*const libc::c_char>(),
        )
    };
    let exec_errno = std::io::Error::last_os_error().raw_os_error();
    if no_new_privs != 1
        || fork_errno != Some(libc::EPERM)
        || unshare != -1
        || unshare_errno != Some(libc::EPERM)
        || exec != -1
        || exec_errno != Some(libc::EPERM)
    {
        return Err("resource_unqualified");
    }
    Ok(
        serde_json::json!({"mechanism":"seccomp-thread-only-tsync-v1","architecture":"x86_64","filter_sha256":hex::encode(digest.finalize()),"no_new_privs":no_new_privs,"fork_errno":fork_errno,"unshare_errno":unshare_errno,"exec_errno":exec_errno}),
    )
}
#[cfg(not(target_arch = "x86_64"))]
pub(super) fn seal_fixture_role() -> Result<serde_json::Value, &'static str> {
    Err("resource_unqualified")
}

impl WorkerConnection {
    pub(super) fn bind_assignment_terms(
        &mut self,
        assignment: &str,
        terms: &super::la_store::AssignmentTerms,
    ) -> Result<(), &'static str> {
        match self {
            Self::Remote(c) => c.bind_assignment_terms(assignment, terms),
            #[cfg(test)]
            Self::Local(_) => Ok(()),
        }
    }
    pub(super) fn bind_mandate(
        &mut self,
        mandate: super::la_auth::StoredMandate,
    ) -> Result<(), &'static str> {
        match self {
            Self::Remote(c) => c.bind_mandate(mandate),
            #[cfg(test)]
            Self::Local(_) => Ok(()),
        }
    }
    pub(super) fn reserve_authenticated(
        &mut self,
        s: &ReservationSession,
        c: &super::la_adapter::ReserveCommand,
        m: &[u8; 32],
    ) -> Result<(super::la_adapter::WorkerReceipt, [u8; 32]), &'static str> {
        #[cfg(test)]
        if let Self::Local(j) = self {
            return j.reserve_authenticated(s, c, m);
        }
        super::la_adapter::verify_reserve_command(&s.key, c, m)?;
        match self {
            Self::Remote(client) => match client.reserve(c)? {
                super::la_adapter::WorkerReply::Reserved(r, m) => {
                    super::la_adapter::verify_receipt(&s.key, &r, &m)?;
                    Ok((r, m))
                }
                _ => Err("evidence_invalid"),
            },
            #[cfg(test)]
            Self::Local(_) => unreachable!(),
        }
    }
    pub(super) fn accept_inspect_permit(
        &mut self,
        s: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
        m: &[u8; 32],
    ) -> Result<(super::la_adapter::PermitReceipt, [u8; 32]), &'static str> {
        #[cfg(test)]
        if let Self::Local(j) = self {
            return j.accept_inspect_permit(s, c, m);
        }
        super::la_adapter::verify_inspect_command(&s.key, c, m)?;
        match self {
            Self::Remote(client) => match client.permit(c)? {
                super::la_adapter::WorkerReply::Permitted(r, m) => {
                    super::la_adapter::verify_permit_receipt(&s.key, &r, &m)?;
                    Ok((r, m))
                }
                _ => Err("evidence_invalid"),
            },
            #[cfg(test)]
            Self::Local(_) => unreachable!(),
        }
    }
}

impl OperationJournal {
    pub(super) fn bind_assignment_terms(
        &mut self,
        c: &super::la_adapter::ReserveCommand,
        terms: &super::la_store::AssignmentTerms,
    ) -> Result<(), &'static str> {
        self.guard_ids(
            "bind_assignment_terms",
            &[&c.assignment],
            &[&c.operation],
            &[],
        )?;
        use rusqlite::OptionalExtension;
        self.check_root()?;
        if terms.cpu_millicores != 1000
            || terms.memory_bytes != 16777216
            || terms.storage_bytes != 2097152
            || terms.accepted_at >= terms.lease_until
            || terms.lease_until != c.lease_until
            || terms.hard_until != c.hard_until
            || terms.lease_until > terms.hard_until
        {
            return Err("evidence_invalid");
        }
        let body = serde_json::to_vec(terms).map_err(|_| "evidence_invalid")?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM worker_assignment_terms WHERE assignment=?1",
                [&c.assignment],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some(old) = old {
            if old != body {
                return Err("evidence_invalid");
            }
        } else {
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM worker_assignment_terms", [], |r| {
                    r.get(0)
                })
                .map_err(|_| "storage_unavailable")?;
            if count >= 8 {
                return Err("capacity_unavailable");
            }
            tx.execute(
                "INSERT INTO worker_assignment_terms VALUES (?1,?2)",
                rusqlite::params![c.assignment, body],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()
    }
    pub(super) fn bind_worker_mandate(
        &mut self,
        s: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
        m: &super::la_auth::StoredMandate,
    ) -> Result<(), &'static str> {
        self.guard_ids(
            "bind_worker_mandate",
            &[&c.assignment],
            &[&c.operation],
            &[&c.job],
        )?;
        use rusqlite::OptionalExtension;
        self.check_root()?;
        if super::la_store::checked_mandate(&m.draft)? != *m {
            return Err("evidence_invalid");
        }
        Self::mandate_matches(s, c, m)?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let terms: Vec<u8> = tx
            .query_row(
                "SELECT body FROM worker_assignment_terms WHERE assignment=?1",
                [&c.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let terms: super::la_store::AssignmentTerms =
            serde_json::from_slice(&terms).map_err(|_| "evidence_invalid")?;
        if (
            m.draft.cpu_millicores,
            m.draft.memory_bytes,
            m.draft.storage_bytes,
            m.draft.assignment_hard,
        ) != (
            terms.cpu_millicores,
            terms.memory_bytes,
            terms.storage_bytes,
            terms.hard_until,
        ) {
            return Err("evidence_invalid");
        }
        let bytes = serde_json::to_vec(m).map_err(|_| "evidence_invalid")?;
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM worker_mandates WHERE job=?1",
                [&c.job],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some(old) = old {
            if old != bytes {
                return Err("evidence_invalid");
            }
        } else {
            let count: i64 = tx
                .query_row("SELECT COUNT(*) FROM worker_mandates", [], |r| r.get(0))
                .map_err(|_| "storage_unavailable")?;
            if count >= 32 {
                return Err("capacity_unavailable");
            }
            tx.execute(
                "INSERT INTO worker_mandates VALUES (?1,?2)",
                rusqlite::params![c.job, bytes],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()
    }
    fn mandate_matches(
        s: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
        m: &super::la_auth::StoredMandate,
    ) -> Result<(), &'static str> {
        let d = &m.draft;
        if c.worker != s.worker
            || c.boot != s.boot
            || d.worker != c.worker
            || d.assignment != c.assignment
            || d.operation != c.operation
            || d.job != c.job
            || d.input_digest != c.input_digest
            || d.profile != Capability::mandate_profile(c.backend)
            || d.accepted_at != c.accepted_at
            || m.max_until != c.mandate_until
            || c.permit_until > m.max_until
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }
    pub(super) fn worker_mandate(
        &self,
        s: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
    ) -> Result<super::la_auth::StoredMandate, &'static str> {
        self.guard_ids(
            "worker_mandate",
            &[&c.assignment],
            &[&c.operation],
            &[&c.job],
        )?;
        self.check_root()?;
        let body: Vec<u8> = self
            .db
            .query_row(
                "SELECT body FROM worker_mandates WHERE job=?1",
                [&c.job],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if body.len() > 16384 {
            return Err("evidence_invalid");
        }
        let m: super::la_auth::StoredMandate =
            serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
        if super::la_store::checked_mandate(&m.draft)? != m {
            return Err("evidence_invalid");
        }
        Self::mandate_matches(s, c, &m)?;
        Ok(m)
    }
}

fn staged_file_name(operation: &str) -> String {
    format!(
        "input-{}",
        hex::encode(Sha256::digest(operation.as_bytes()))
    )
}
fn read_staged_file(
    root: &std::fs::File,
    name: &str,
    digest: &str,
) -> Result<Vec<u8>, &'static str> {
    use std::os::unix::fs::MetadataExt;
    if name.len() != 70
        || !name.starts_with("input-")
        || !name[6..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("evidence_invalid");
    }
    let file = super::la_artifacts::open_artifact(root, name, libc::O_RDONLY)
        .map_err(|_| "input_unavailable")?;
    let metadata = file.metadata().map_err(|_| "evidence_invalid")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_INPUT as u64
    {
        return Err("evidence_invalid");
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input_unavailable")?;
    if bytes.len() as u64 != metadata.len()
        || bytes.len() > MAX_INPUT
        || hex::encode(Sha256::digest(&bytes)) != digest
    {
        return Err("evidence_invalid");
    }
    Ok(bytes)
}

impl OperationJournal {
    /// Cleanup follows the durable assignment fence. A crash before the final
    /// marker leaves the claim held and the same deletion safely retryable.
    /// Report/mandate/input metadata remain immutable audit history.
    fn cleanup_fenced_inputs(
        &mut self,
        command: &super::la_adapter::CloseCommand,
        sequence: i64,
    ) -> Result<(), &'static str> {
        self.guard_ids(
            "cleanup_fenced_inputs",
            &[&command.assignment],
            &[&command.operation],
            &[],
        )?;
        use std::os::fd::AsRawFd;
        self.check_root()?;
        let rows = {
            let mut statement = self.db.prepare("SELECT i.operation,i.content,i.input_digest,a.assignment FROM worker_inputs i JOIN worker_input_assignments a ON a.operation=i.operation").map_err(|_| "storage_unavailable")?;
            let rows = statement
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                })
                .map_err(|_| "storage_unavailable")?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "storage_unavailable")?;
            if rows.len() > MAX_OPERATIONS as usize {
                return Err("evidence_invalid");
            }
            rows
        };
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM worker_inputs", [], |r| r.get(0))
            .map_err(|_| "storage_unavailable")?;
        if count != rows.len() as i64 {
            return Err("evidence_invalid");
        }
        let occupancy =
            verified_execution_occupancy(&self.db, &self.root, self.occupancy_keys.as_deref())?;
        if occupancy.retired_assignments.contains(&command.assignment) {
            return Err("evidence_invalid");
        }
        for (op, name, input_digest, assignment) in rows {
            if assignment != command.assignment {
                continue;
            }
            if !valid_id(&op) || name != staged_file_name(&op) {
                return Err("evidence_invalid");
            }
            // Only an exact known immutable input can be removed. ENOENT is
            // valid after the fence because deletion may precede a crash.
            match super::la_artifacts::open_artifact(&self.root, &name, libc::O_RDONLY) {
                Ok(_) => {
                    read_staged_file(&self.root, &name, &input_digest)?;
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(_) => return Err("storage_unavailable"),
            }
            let name = std::ffi::CString::new(name).map_err(|_| "evidence_invalid")?;
            if unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err("storage_unavailable");
            }
        }
        self.root.sync_all().map_err(|_| "storage_unavailable")?;
        self.db.execute("INSERT INTO worker_cleanup_receipts VALUES (?1,?2,?3,?4) ON CONFLICT(assignment) DO NOTHING", rusqlite::params![command.assignment,command.operation,command.fence as i64,sequence]).map_err(|_| "storage_unavailable")?;
        self.check_root()
    }
}

// A mutable cursor is only the current session. These authenticated rows retain
// every generation and every assignment receipt; no recovery infers missing rows.
fn generation_mac(
    key: &[u8; 32],
    generation: i64,
    worker: &str,
    boot: &str,
    sequence: i64,
    fence: i64,
    authority: &str,
) -> Result<[u8; 32], &'static str> {
    super::la_adapter::typed_mac(
        key,
        b"diffuser-worker-session-generation/v1\0",
        &(generation, worker, boot, sequence, fence, authority),
    )
}
fn append_session_generation(
    db: &rusqlite::Connection,
    session: &ReservationSession,
    generation: i64,
    sequence: i64,
    fence: i64,
    authority: &str,
) -> Result<(), &'static str> {
    let mac = generation_mac(
        &session.key,
        generation,
        &session.worker,
        &session.boot,
        sequence,
        fence,
        authority,
    )?;
    db.execute(
        "INSERT INTO worker_session_generations VALUES(?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![
            generation,
            session.worker,
            session.boot,
            sequence,
            fence,
            authority,
            mac.as_slice()
        ],
    )
    .map_err(|_| "evidence_invalid")?;
    Ok(())
}
fn session_event(
    db: &rusqlite::Connection,
    sequence: i64,
) -> Result<(String, Vec<u8>), &'static str> {
    let mut st=db.prepare("SELECT 'reserve',command_digest FROM worker_reservations WHERE sequence=?1 UNION ALL SELECT 'permit',command_digest FROM worker_inspect_commands WHERE sequence=?1 UNION ALL SELECT 'result',CAST(digest AS BLOB) FROM worker_result_receipts WHERE sequence=?1 UNION ALL SELECT 'renew',digest FROM worker_renewals WHERE sequence=?1 UNION ALL SELECT 'stop',command_digest FROM worker_stop_receipts WHERE sequence=?1 UNION ALL SELECT 'close',command_digest FROM worker_close_receipts WHERE sequence=?1").map_err(|_| "evidence_invalid")?;
    let mut rows = st
        .query_map([sequence], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|_| "evidence_invalid")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "evidence_invalid")?;
    for (seq, proof) in rebound_events(db)? {
        if seq == sequence {
            rows.push(("rebound_permit".into(), proof));
        }
    }
    if rows.len() != 1 {
        return Err("evidence_invalid");
    }
    rows.pop().ok_or("evidence_invalid")
}
fn append_session_snapshot(
    db: &rusqlite::Connection,
    session: &ReservationSession,
    assignment: &str,
    sequence: i64,
) -> Result<(), &'static str> {
    let (worker, boot, last, fence): (String, String, i64, i64) = db
        .query_row(
            "SELECT worker,boot,sequence,fence FROM reservation_session",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|_| "evidence_invalid")?;
    let generation: i64 = db
        .query_row(
            "SELECT generation FROM worker_session_generations WHERE worker=?1 AND boot=?2",
            rusqlite::params![worker, boot],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    let (event, proof) = session_event(db, sequence)?;
    if worker != session.worker
        || boot != session.boot
        || last != sequence
        || !(1..=512).contains(&sequence)
    {
        return Err("evidence_invalid");
    }
    let mac = super::la_adapter::typed_mac(
        &session.key,
        b"diffuser-worker-session-snapshot/v1\0",
        &(
            sequence, assignment, generation, &worker, &boot, fence, &event, &proof,
        ),
    )?;
    db.execute(
        "INSERT INTO worker_session_snapshots VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![
            sequence,
            assignment,
            generation,
            worker,
            boot,
            fence,
            event,
            proof,
            mac.as_slice()
        ],
    )
    .map_err(|_| "evidence_invalid")?;
    Ok(())
}
pub(super) fn verify_session_history(
    db: &rusqlite::Connection,
    key: &[u8; 32],
) -> Result<(), &'static str> {
    use rusqlite::OptionalExtension;
    use subtle::ConstantTimeEq;
    let cursor: Option<(String, String, i64, i64)> = db
        .query_row(
            "SELECT worker,boot,sequence,fence FROM reservation_session",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(|_| "evidence_invalid")?;
    let generations: i64 = db
        .query_row("SELECT COUNT(*) FROM worker_session_generations", [], |r| {
            r.get(0)
        })
        .map_err(|_| "evidence_invalid")?;
    let snapshots: i64 = db
        .query_row("SELECT COUNT(*) FROM worker_session_snapshots", [], |r| {
            r.get(0)
        })
        .map_err(|_| "evidence_invalid")?;
    let events:i64=db.query_row("SELECT (SELECT COUNT(*) FROM worker_reservations)+(SELECT COUNT(*) FROM worker_inspect_commands)+(SELECT COUNT(*) FROM worker_result_receipts)+(SELECT COUNT(*) FROM worker_renewals)+(SELECT COUNT(*) FROM worker_stop_receipts)+(SELECT COUNT(*) FROM worker_close_receipts)",[],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
    if cursor.is_none() {
        return if generations == 0 && snapshots == 0 && events == 0 {
            Ok(())
        } else {
            Err("evidence_invalid")
        };
    }
    let cursor = cursor.ok_or("evidence_invalid")?;
    if !(1..=9).contains(&generations)
        || snapshots != cursor.2
        || events + rebound_events(db)?.len() as i64 != snapshots
        || !(1..=512).contains(&snapshots)
    {
        return Err("evidence_invalid");
    }
    let last_fence: i64 = db
        .query_row(
            "SELECT fence FROM worker_session_snapshots WHERE sequence=?1",
            [snapshots],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    if last_fence != cursor.3 {
        return Err("evidence_invalid");
    }
    let mut previous = None;
    for generation in 1..=generations {
        let (worker,boot,sequence,fence,authority,mac):(String,String,i64,i64,String,Vec<u8>)=db.query_row("SELECT worker,boot,sequence,fence,authority,mac FROM worker_session_generations WHERE generation=?1",[generation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).map_err(|_| "evidence_invalid")?;
        let expected =
            generation_mac(key, generation, &worker, &boot, sequence, fence, &authority)?;
        if !bool::from(expected.as_slice().ct_eq(&mac))
            || !valid_id(&worker)
            || !valid_id(&boot)
            || (generation == 1 && (sequence != 0 || fence != 0 || authority != "genesis"))
            || (generation > 1
                && (sequence <= 0
                    || fence <= 0
                    || authority.len() != 64
                    || hex::decode(&authority).is_err()))
        {
            return Err("evidence_invalid");
        }
        if let Some((prior_worker, prior_boot, prior_sequence, prior_fence)) = previous {
            if worker != prior_worker
                || boot == prior_boot
                || sequence <= prior_sequence
                || fence <= prior_fence
            {
                return Err("evidence_invalid");
            }
            let (w, b, f): (String, String, i64) = db
                .query_row(
                    "SELECT worker,boot,fence FROM worker_session_snapshots WHERE sequence=?1",
                    [sequence],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(|_| "evidence_invalid")?;
            if (w, b, f) != (prior_worker, prior_boot, fence) {
                return Err("evidence_invalid");
            }
        }
        if generation == generations
            && (worker != cursor.0 || boot != cursor.1 || sequence > cursor.2 || fence > cursor.3)
        {
            return Err("evidence_invalid");
        }
        previous = Some((worker, boot, sequence, fence));
    }
    for sequence in 1..=snapshots {
        let (assignment,generation,worker,boot,fence,event,proof,mac):(String,i64,String,String,i64,String,Vec<u8>,Vec<u8>)=db.query_row("SELECT assignment,generation,worker,boot,fence,event,proof,mac FROM worker_session_snapshots WHERE sequence=?1",[sequence],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).map_err(|_| "evidence_invalid")?;
        let expected = super::la_adapter::typed_mac(
            key,
            b"diffuser-worker-session-snapshot/v1\0",
            &(
                sequence,
                &assignment,
                generation,
                &worker,
                &boot,
                fence,
                &event,
                &proof,
            ),
        )?;
        let valid:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM worker_session_generations WHERE generation=?1 AND worker=?2 AND boot=?3 AND sequence<?4 AND fence<?5) AND NOT EXISTS(SELECT 1 FROM worker_session_generations WHERE generation>?1 AND sequence<?4)",rusqlite::params![generation,worker,boot,sequence,fence],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        if !valid || !bool::from(expected.as_slice().ct_eq(&mac)) || session_event(db,sequence)?!=(event,proof) || !db.query_row("SELECT EXISTS(SELECT 1 FROM worker_reservations WHERE assignment_id=?1 AND fence=?2)",rusqlite::params![assignment,fence],|r|r.get::<_,bool>(0)).map_err(|_| "evidence_invalid")? { return Err("evidence_invalid"); }
    }
    Ok(())
}

impl OperationJournal {
    pub(super) fn install_successor_generation(
        &mut self,
        session: &ReservationSession,
        cap: &super::la_adapter::WorkerSuccessorAdmission,
    ) -> Result<(), &'static str> {
        self.check_root()?;
        if cap.binding().worker != session.worker || cap.binding().worker_boot != session.boot {
            return Err("evidence_invalid");
        }
        let (old_boot, generation, sequence, fence) = cap.cursor();
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        verify_session_history(&tx, &session.key)?;
        let current: (String, String, i64, i64) = tx
            .query_row(
                "SELECT worker,boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(|_| "evidence_invalid")?;
        let next: i64 = tx
            .query_row(
                "SELECT MAX(generation)+1 FROM worker_session_generations",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let terminal:bool=tx.query_row("SELECT NOT EXISTS(SELECT 1 FROM worker_reservations WHERE closed=0) AND NOT EXISTS(SELECT 1 FROM operations WHERE state='started')",[],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        if current
            != (
                session.worker.clone(),
                old_boot.into(),
                sequence as i64,
                fence as i64,
            )
            || next != generation as i64
            || !terminal
        {
            return Err("evidence_invalid");
        }
        append_session_generation(
            &tx,
            session,
            generation as i64,
            sequence as i64,
            fence as i64,
            &cap.digest()?,
        )?;
        tx.execute("UPDATE reservation_session SET boot=?1", [&session.boot])
            .map_err(|_| "storage_unavailable")?;
        verify_session_history(&tx, &session.key)?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()
    }
}

impl OperationJournal {
    pub(super) fn rebound_never_started(
        &mut self,
        session: &ReservationSession,
        cap: &super::la_adapter::NeverStartedPermit,
    ) -> Result<(super::la_adapter::PermitReceipt, [u8; 32]), &'static str> {
        use rusqlite::params;
        self.check_root()?;
        verify_session_history(&self.db, &session.key)?;
        cap.verify_commands()?;
        let c = &cap.rebound;
        self.guard_ids(
            "rebound_never_started",
            &[&c.assignment, &cap.original.assignment],
            &[&c.operation, &cap.original.operation],
            &[&c.job, &cap.original.job],
        )?;
        let original_digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&cap.original).map_err(|_| "evidence_invalid")?)
                .into();
        self.worker_mandate(session, c)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "clock_untrusted")?
            .as_millis() as u64;
        if now >= c.permit_until {
            return Err("deadline_elapsed");
        }
        let digest = super::la_adapter::verify_inspect_command(
            &session.key,
            c,
            &super::la_adapter::sign_inspect_command(&session.key, c)?,
        )?;
        let bytes = serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?;
        let proof: [u8; 32] = Sha256::digest(&bytes).into();
        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS worker_rebound_permits(operation TEXT PRIMARY KEY,command_digest BLOB NOT NULL,sequence INTEGER NOT NULL UNIQUE,proof BLOB NOT NULL,body BLOB NOT NULL);").map_err(|_| "storage_unavailable")?;
        let valid:bool=tx.query_row("SELECT NOT EXISTS(SELECT 1 FROM operations) AND (SELECT COUNT(*) FROM worker_rebound_permits)<8 AND EXISTS(SELECT 1 FROM worker_inspect_commands i JOIN worker_reservations r ON r.assignment_id=?2 JOIN reservation_session s ON s.fence=r.fence WHERE i.operation=?1 AND i.command_digest=?3 AND r.closed=0 AND r.fence=?4 AND s.worker=?5 AND s.boot=?6 AND r.lease_until>=?7)",params![c.operation,c.assignment,original_digest.as_slice(),c.fence as i64,session.worker,session.boot,c.permit_until as i64],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        if !valid {
            return Err("transport_uncertain");
        }
        let sequence: i64 = tx
            .query_row("SELECT sequence+1 FROM reservation_session", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        tx.execute(
            "INSERT INTO worker_rebound_permits VALUES(?1,?2,?3,?4,?5)",
            params![
                c.operation,
                digest.as_slice(),
                sequence,
                proof.as_slice(),
                bytes
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.execute("UPDATE reservation_session SET sequence=?1", [sequence])
            .map_err(|_| "storage_unavailable")?;
        append_session_snapshot(&tx, session, &c.assignment, sequence)?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        let receipt = super::la_adapter::PermitReceipt {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            fence: c.fence,
            sequence: sequence.try_into().map_err(|_| "evidence_invalid")?,
            assignment: c.assignment.clone(),
            operation: c.operation.clone(),
            job: c.job.clone(),
            command_digest: hex::encode(digest),
            permit_until: c.permit_until,
        };
        let mac = super::la_adapter::sign_permit_receipt(&session.key, &receipt)?;
        Ok((receipt, mac))
    }
}
fn rebound_events(db: &rusqlite::Connection) -> Result<Vec<(i64, Vec<u8>)>, &'static str> {
    let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_rebound_permits')",[],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
    if !table {
        return Ok(Vec::new());
    }
    let mut st = db
        .prepare("SELECT sequence,proof,body,command_digest,operation FROM worker_rebound_permits ORDER BY sequence LIMIT 9")
        .map_err(|_| "evidence_invalid")?;
    let mut result = Vec::new();
    for row in st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })
        .map_err(|_| "evidence_invalid")?
    {
        let (sequence, proof, body, command, operation) = row.map_err(|_| "evidence_invalid")?;
        if result.len() >= 8 || body.len() > 12288 || Sha256::digest(&body).as_slice() != proof {
            return Err("evidence_invalid");
        }
        let cap: super::la_adapter::NeverStartedPermit =
            serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
        cap.verify_commands()?;
        let actual: [u8; 32] =
            Sha256::digest(serde_json::to_vec(&cap.rebound).map_err(|_| "evidence_invalid")?)
                .into();
        if actual.as_slice() != command || cap.rebound.operation != operation {
            return Err("evidence_invalid");
        }
        if serde_json::to_vec(&cap).map_err(|_| "evidence_invalid")? != body {
            return Err("evidence_invalid");
        }
        result.push((sequence, proof));
    }
    Ok(result)
}

fn effective_worker_command(
    db: &rusqlite::Connection,
    operation: &str,
) -> Result<Option<Vec<u8>>, &'static str> {
    use rusqlite::OptionalExtension;
    rebound_events(db)?;
    let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_rebound_permits')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
    if table {
        let row: Option<Vec<u8>> = db
            .query_row(
                "SELECT command_digest FROM worker_rebound_permits WHERE operation=?1",
                [operation],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "evidence_invalid")?;
        if row.is_some() {
            return Ok(row);
        }
    }
    db.query_row(
        "SELECT command_digest FROM worker_inspect_commands WHERE operation=?1",
        [operation],
        |r| r.get(0),
    )
    .optional()
    .map_err(|_| "evidence_invalid")
}
fn rebound_staged_command(
    db: &rusqlite::Connection,
    operation: &str,
    stored: &[u8],
    expected: &[u8],
) -> Result<bool, &'static str> {
    use rusqlite::OptionalExtension;
    if stored == expected {
        return Ok(true);
    }
    let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_rebound_permits')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
    if !table {
        return Ok(false);
    }
    rebound_events(db)?;
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT body FROM worker_rebound_permits WHERE operation=?1",
            [operation],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| "evidence_invalid")?;
    let Some(bytes) = bytes else { return Ok(false) };
    let cap: super::la_adapter::NeverStartedPermit =
        serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
    let old: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&cap.original).map_err(|_| "evidence_invalid")?).into();
    let new: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&cap.rebound).map_err(|_| "evidence_invalid")?).into();
    Ok(old.as_slice() == stored && new.as_slice() == expected)
}

impl OperationJournal {
    pub(super) fn install_controller_admission(
        &mut self,
        session: &ReservationSession,
        cap: &super::la_adapter::RecoveredControllerAdmission,
    ) -> Result<(), &'static str> {
        self.check_root()?;
        let (boot, generation, sequence, fence) = cap.cursor();
        if cap.binding().worker != session.worker
            || cap.binding().worker_boot != session.boot
            || boot != session.boot
        {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        verify_session_history(&tx, &session.key)?;
        let safe: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM reservation_session WHERE worker=?1 AND boot=?2 AND sequence=?3 AND fence=?4) AND NOT EXISTS(SELECT 1 FROM worker_reservations WHERE closed=0) AND NOT EXISTS(SELECT 1 FROM operations WHERE state='started') AND NOT EXISTS(SELECT 1 FROM sqlite_master WHERE name='worker_controller_admissions')", rusqlite::params![session.worker,session.boot,sequence as i64,fence as i64], |r|r.get(0)).map_err(|_| "evidence_invalid")?;
        if !safe || generation != cap.binding().controller_epoch {
            return Err("evidence_invalid");
        }
        tx.execute_batch("CREATE TABLE worker_controller_admissions(generation INTEGER PRIMARY KEY,capability BLOB NOT NULL UNIQUE);").map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO worker_controller_admissions VALUES(?1,?2)",
            rusqlite::params![
                generation as i64,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()
    }
}

#[cfg(test)]
static FIXTURE_ENTRY_RELEASED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
pub(super) fn release_fixture_entry() -> Result<(), &'static str> {
    if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").as_deref() != Ok("running-completion-wins") {
        return Err("control_invalid");
    }
    FIXTURE_ENTRY_RELEASED.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

struct RunningInspection {
    command: super::la_adapter::InspectCommand,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<Result<Vec<u8>, &'static str>>,
}

impl OperationJournal {
    /// The protected worker bootstrap owns this hook. No RPC or request can
    /// attach a backend or arm a process.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn attach_backend(
        &mut self,
        mut backend: Box<dyn la_backend::Binding>,
    ) -> Result<(), &'static str> {
        self.check_root()?;
        if self.backend.is_some() || self.running.is_some() {
            return Err("state_conflict");
        }
        backend.ready(backend.capability())?;
        self.backend = Some(backend);
        Ok(())
    }

    pub(super) fn backend_ready(&mut self, capability: Capability) -> Result<(), &'static str> {
        let binding = self.backend.as_mut().ok_or("capability_unavailable")?;
        if binding.capability() != capability {
            return Err("capability_unavailable");
        }
        binding.ready(capability)
    }

    /// An interrupted signed RPC can read an exact durable result. A marker
    /// without terminal bytes remains held and may never launch a new task.
    pub(super) fn retained_typed_result(
        &mut self,
        session: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
    ) -> Result<super::la_adapter::WorkerReply, &'static str> {
        self.authenticate_running_command(session, c)?;
        self.worker_mandate(session, c)?;
        if c.backend.is_none() || self.authenticated_status(session, c)?.0 != "complete" {
            return Err("transport_uncertain");
        }
        self.inspection_reply(session, c)
    }

    fn authenticate_running_command(
        &self,
        session: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
    ) -> Result<(), &'static str> {
        self.guard_ids(
            "authenticate_running_command",
            &[&c.assignment],
            &[&c.operation],
            &[&c.job],
        )?;
        use rusqlite::OptionalExtension;
        self.check_root()?;
        verify_session_history(&self.db, &session.key)?;
        let digest = Sha256::digest(serde_json::to_vec(c).map_err(|_| "evidence_invalid")?);
        let stored = effective_worker_command(&self.db, &c.operation)?;
        if stored.is_some_and(|v| v.as_slice() != digest.as_slice()) {
            return Err("evidence_invalid");
        }
        let row: Option<(String, i64, i64)> = self
            .db
            .query_row(
                "SELECT assignment_id,fence,closed FROM worker_reservations WHERE assignment_id=?1",
                [&c.assignment],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if c.worker != session.worker
            || c.boot != session.boot
            || c.fence == 0
            || !matches!(row, Some((ref a, f, 0)) if a == &c.assignment && u64::try_from(f).ok() == Some(c.fence))
        {
            return Err("evidence_invalid");
        }
        Ok(())
    }

    /// One task, at most MAX_INPUT bytes, one original permit timer. The task
    /// never owns SQLite or publishes results. The journal remains the writer.
    pub(super) fn start_inspection(
        &mut self,
        session: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
    ) -> Result<super::la_adapter::WorkerReply, &'static str> {
        self.guard_ids(
            "start_inspection",
            &[&c.assignment],
            &[&c.operation],
            &[&c.job],
        )?;
        self.authenticate_running_command(session, c)?;
        self.reap_inspection()?;
        if let Some(task) = &self.running {
            return if task.command == *c {
                self.inspection_reply(session, c)
            } else {
                Err("capacity_unavailable")
            };
        }
        let mac = super::la_adapter::sign_start_command(&session.key, c)?;
        let input = self.staged_inspection_input(session, c, &mac)?;
        let (hard, timer) = self.authenticate_inspection(session, c, &mac)?;
        if let Some(capability) = c.backend {
            if self.authenticated_status(session, c)?.0 != "never_seen" {
                return self.inspection_reply(session, c);
            }
            capability.validate_input(&input)?;
            self.backend_ready(capability)?;
        }
        let deadline = timer.deadline()?;
        if let Some(report) =
            self.enter_inspection(&c.operation, &c.job, &input, &c.input_digest, hard, || {
                timer.is_stopped()
            })?
        {
            let (b, r, m) = self.inspection_receipt(session, c, report)?;
            return Ok(super::la_adapter::WorkerReply::Result(b, r, m));
        }
        let backend = if c.backend.is_some() {
            self.backend.take()
        } else {
            None
        };
        let cancel = timer.stop_flag();
        let task_cancel = cancel.clone();
        let observer = self.work_entry.clone();
        let command = c.clone();
        let thread = std::thread::Builder::new()
            .name("la-inspection".into())
            .spawn(move || {
                if let Some(observe) = observer {
                    observe(&command.operation, &command.job)?;
                }
                #[cfg(test)]
                if std::env::var("DIFFUSER_LA_RESOURCE_PROBE")
                    .is_ok_and(|v| v.starts_with("running-"))
                {
                    while !FIXTURE_ENTRY_RELEASED.load(std::sync::atomic::Ordering::SeqCst)
                        && !timer.is_stopped()
                    {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                let result = if let Some(capability) = command.backend {
                    la_backend::execute(
                        backend.ok_or("execution_uncertain")?,
                        capability,
                        &input,
                        &command.job,
                        &command.input_digest,
                        deadline,
                        &|| timer.is_stopped(),
                    )
                } else {
                    inspect(&mut input.as_slice(), &command.job, hard, || {
                        timer.is_stopped()
                    })
                };
                // Drop joins the independent permit timer before this task exits.
                drop(timer);
                result
            })
            .map_err(|_| "startup_unavailable")?;
        self.running = Some(Box::new(RunningInspection {
            command: c.clone(),
            cancel: task_cancel,
            thread,
        }));
        // A bounded fast path preserves synchronous completion for small work.
        // It never waits for the operation's full lifetime under the RPC lock.
        let until = Instant::now() + std::time::Duration::from_millis(10);
        while self
            .running
            .as_ref()
            .is_some_and(|t| !t.thread.is_finished())
            && Instant::now() < until
        {
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        self.inspection_reply(session, c)
    }

    fn reap_inspection(&mut self) -> Result<(), &'static str> {
        self.check_root()?;
        if let Some(task) = &self.running {
            self.guard_ids(
                "reap_inspection",
                &[&task.command.assignment],
                &[&task.command.operation],
                &[&task.command.job],
            )?;
        }
        if !self
            .running
            .as_ref()
            .is_some_and(|t| t.thread.is_finished())
        {
            return Ok(());
        }
        let task = self.running.take().ok_or("execution_uncertain")?;
        let result = task.thread.join().map_err(|_| "execution_uncertain")?;
        self.check_root()?;
        let settled = match result {
            Ok(report) => self.publish_inspection(
                &task.command.operation,
                &task.command.input_digest,
                &report,
            ),
            Err("stopped") => {
                let changed = self.db.execute("UPDATE operations SET state='cancelled' WHERE op=?1 AND job=?2 AND input_digest=?3 AND state='started' AND report IS NULL", rusqlite::params![task.command.operation,task.command.job,task.command.input_digest]).map_err(|_| "storage_unavailable")?;
                if changed != 1 {
                    return Err("execution_uncertain");
                }
                self.check_root()
            }
            Err(code) => Err(code), // marker retained; no proof of safe terminal state
        };
        settled?;
        #[cfg(test)]
        if std::env::var("DIFFUSER_LA_RESOURCE_PROBE").is_ok_and(|v| v.starts_with("running-")) {
            use std::io::Write;
            println!(
                "DIFFUSER_LA_CHILD_V1 {}",
                serde_json::json!({"kind":"WORK_QUIESCED","operation":task.command.operation,"job":task.command.job,"worker_boot":task.command.boot,"pid":std::process::id(),"task_joined":true,"original_permit_until":task.command.permit_until})
            );
            std::io::stdout().flush().map_err(|_| "control_invalid")?;
        }
        Ok(())
    }

    pub(super) fn inspection_reply(
        &mut self,
        session: &ReservationSession,
        c: &super::la_adapter::InspectCommand,
    ) -> Result<super::la_adapter::WorkerReply, &'static str> {
        self.guard_ids(
            "inspection_reply",
            &[&c.assignment],
            &[&c.operation],
            &[&c.job],
        )?;
        self.authenticate_running_command(session, c)?;
        self.reap_inspection()?;
        let (state, starts) = self.authenticated_status(session, c)?;
        match state.as_str() {
            "complete" => {
                let report = self
                    .db
                    .query_row(
                        "SELECT report FROM operations WHERE op=?1",
                        [&c.operation],
                        |r| r.get(0),
                    )
                    .map_err(|_| "storage_unavailable")?;
                let (b, r, m) = self.inspection_receipt(session, c, report)?;
                Ok(super::la_adapter::WorkerReply::Result(b, r, m))
            }
            "stopped" | "cancelled" => {
                let mac = super::la_adapter::sign_stop_command(&session.key, c)?;
                let (r, m) = self.stop_with_receipt(session, c, &mac)?;
                Ok(super::la_adapter::WorkerReply::Stopped(r, m))
            }
            "started" if c.backend.is_some() && self.running.is_none() => {
                Err("execution_uncertain")
            }
            _ => Ok(super::la_adapter::WorkerReply::Status {
                operation: c.operation.clone(),
                state,
                starts,
            }),
        }
    }

    pub(super) fn running_command(&self) -> Option<super::la_adapter::InspectCommand> {
        self.running.as_ref().map(|t| t.command.clone())
    }
    pub(super) fn signal_running_stop(&self) {
        if let Some(task) = &self.running {
            task.cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
impl Drop for OperationJournal {
    fn drop(&mut self) {
        self.signal_running_stop();
        if let Some(task) = self.running.take() {
            let _ = task.thread.join();
        }
    }
}

#[cfg(test)]
mod running_tests {
    use super::*;

    fn fixture() -> (
        std::path::PathBuf,
        OperationJournal,
        ReservationSession,
        super::super::la_adapter::InspectCommand,
        std::sync::mpsc::SyncSender<()>,
    ) {
        use super::super::la_adapter::*;
        let root = std::env::temp_dir().join(format!(
            "la-running-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let mut journal =
            OperationJournal::bootstrap(&root.join("worker.sqlite"), "custody_running_1234")
                .unwrap();
        let session = ReservationSession {
            worker: "worker_running_1234".into(),
            boot: "boot_running_12345".into(),
            key: [37; 32],
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let reserve = ReserveCommand {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: "assignment_run_1234".into(),
            operation: "reservation_run_123".into(),
            fence: 1,
            lease_until: now + 4000,
            hard_until: now + 6000,
        };
        journal
            .reserve_authenticated(
                &session,
                &reserve,
                &sign_reserve_command(&session.key, &reserve).unwrap(),
            )
            .unwrap();
        let c = InspectCommand {
            backend: None,
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: reserve.assignment,
            operation: "operation_running12".into(),
            job: "job_running_123456".into(),
            fence: 1,
            input_digest: hex::encode(Sha256::digest(b"bounded actual work")),
            accepted_at: now,
            mandate_until: now + 4000,
            permit_until: now + 1500,
        };
        journal
            .accept_inspect_permit(
                &session,
                &c,
                &sign_inspect_command(&session.key, &c).unwrap(),
            )
            .unwrap();
        journal
            .stage_authenticated_input(
                &session,
                &c,
                &sign_stage_command(&session.key, &c).unwrap(),
                b"bounded actual work",
            )
            .unwrap();
        let (release, gate) = std::sync::mpsc::sync_channel(1);
        let gate = std::sync::Mutex::new(gate);
        journal
            .observe_work_entry(std::sync::Arc::new(move |_, _| {
                gate.lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(1))
                    .map_err(|_| "control_invalid")
            }))
            .unwrap();
        (root, journal, session, c, release)
    }

    #[test]
    fn running_stop_needs_actual_join_and_exact_authenticated_command() {
        use super::super::la_adapter::*;
        let (root, mut journal, session, c, release) = fixture();
        assert!(matches!(
            journal.start_inspection(&session, &c).unwrap(),
            WorkerReply::Status { starts: 1, .. }
        ));
        assert_eq!(journal.start_count(&c.operation).unwrap(), 1);
        assert!(journal.stop_with_receipt(&session, &c, &[0; 32]).is_err());
        let mut changed = c.clone();
        changed.permit_until += 1;
        assert!(journal
            .stop_with_receipt(
                &session,
                &changed,
                &sign_stop_command(&session.key, &changed).unwrap()
            )
            .is_err());
        assert!(!journal
            .running
            .as_ref()
            .unwrap()
            .cancel
            .load(std::sync::atomic::Ordering::SeqCst));
        let mac = sign_stop_command(&session.key, &c).unwrap();
        assert_eq!(
            journal.stop_with_receipt(&session, &c, &mac).err(),
            Some("execution_uncertain")
        );
        assert_eq!(
            journal.authenticated_status(&session, &c).unwrap(),
            ("started".into(), 1)
        );
        let receipts: i64 = journal
            .db
            .query_row("SELECT COUNT(*) FROM worker_stop_receipts", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(receipts, 0, "a cancellation flag is not terminal proof");
        release.send(()).unwrap();
        while !journal.running.as_ref().unwrap().thread.is_finished() {
            std::thread::yield_now();
        }
        let (receipt, signature) = journal.stop_with_receipt(&session, &c, &mac).unwrap();
        verify_stop_receipt(&session.key, &receipt, &signature).unwrap();
        assert_eq!(
            journal.authenticated_status(&session, &c).unwrap(),
            ("cancelled".into(), 1)
        );
        let (again, again_mac) = journal.stop_with_receipt(&session, &c, &mac).unwrap();
        assert_eq!(receipt.sequence, again.sequence);
        assert_eq!(signature, again_mac);
        assert!(journal.start_inspection(&session, &c).is_err());
        assert_eq!(journal.start_count(&c.operation).unwrap(), 1);
        drop(journal);
        let reopened = OperationJournal::reopen_checked(
            &root.join("worker.sqlite"),
            "custody_running_1234",
            1,
            1,
        )
        .unwrap();
        verify_session_history(&reopened.db, &session.key).unwrap();
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_task_wins_stop_and_keeps_exact_durable_result() {
        use super::super::la_adapter::*;
        let (root, mut journal, session, c, release) = fixture();
        assert!(matches!(
            journal.start_inspection(&session, &c).unwrap(),
            WorkerReply::Status { starts: 1, .. }
        ));
        release.send(()).unwrap();
        while !journal.running.as_ref().unwrap().thread.is_finished() {
            std::thread::yield_now();
        }
        assert_eq!(
            journal
                .stop_with_receipt(&session, &c, &sign_stop_command(&session.key, &c).unwrap())
                .err(),
            Some("state_conflict")
        );
        let WorkerReply::Result(report, receipt, mac) =
            journal.inspection_reply(&session, &c).unwrap()
        else {
            panic!("completed report lost to Stop");
        };
        verify_result_receipt(&session.key, &receipt, &mac).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&report).unwrap()["sha256"],
            c.input_digest
        );
        let receipts: i64 = journal
            .db
            .query_row("SELECT COUNT(*) FROM worker_stop_receipts", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(receipts, 0);
        assert_eq!(journal.start_count(&c.operation).unwrap(), 1);
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod session_history_tests {
    use super::*;
    #[test]
    fn assignment_session_snapshots_survive_next_fence_and_missing_history_cannot_authorize() {
        let root = std::env::temp_dir().join(format!(
            "la-session-history-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let mut journal =
            OperationJournal::bootstrap(&root.join("worker.sqlite"), "custody_12345678").unwrap();
        let session = ReservationSession {
            worker: "worker_123456789".into(),
            boot: "boot_12345678901".into(),
            key: [42; 32],
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let reserve = super::super::la_adapter::ReserveCommand {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: "assignment_12345".into(),
            operation: "reservation_12345".into(),
            fence: 7,
            lease_until: now + 60000,
            hard_until: now + 60000,
        };
        let (receipt, signature) = journal
            .reserve_authenticated(
                &session,
                &reserve,
                &super::super::la_adapter::sign_reserve_command(&session.key, &reserve).unwrap(),
            )
            .unwrap();
        let close = super::super::la_adapter::CloseCommand {
            worker: session.worker.clone(),
            boot: session.boot.clone(),
            assignment: reserve.assignment.clone(),
            operation: "close_assignment_12345".into(),
            fence: 7,
        };
        journal
            .close_authenticated(
                &session,
                &close,
                &super::super::la_adapter::sign_close_command(&session.key, &close).unwrap(),
            )
            .unwrap();
        let second = super::super::la_adapter::ReserveCommand {
            assignment: "assignment_23456".into(),
            operation: "reservation_23456".into(),
            fence: 8,
            ..reserve.clone()
        };
        journal
            .reserve_authenticated(
                &session,
                &second,
                &super::super::la_adapter::sign_reserve_command(&session.key, &second).unwrap(),
            )
            .unwrap();
        verify_session_history(&journal.db, &session.key).unwrap();
        let old:(String,String,i64,i64)=journal.db.query_row("SELECT worker,boot,sequence,fence FROM worker_session_snapshots WHERE assignment=?1 AND event='close'",[&reserve.assignment],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(old, (session.worker.clone(), session.boot.clone(), 2, 7));
        super::super::la_adapter::verify_receipt(&session.key, &receipt, &signature).unwrap();
        let new_session = ReservationSession {
            worker: session.worker.clone(),
            boot: "boot_23456789012".into(),
            key: session.key,
        };
        let foreign = super::super::la_adapter::ReserveCommand {
            boot: new_session.boot.clone(),
            assignment: "assignment_34567".into(),
            operation: "reservation_34567".into(),
            fence: 9,
            ..second
        };
        assert!(journal
            .reserve_authenticated(
                &new_session,
                &foreign,
                &super::super::la_adapter::sign_reserve_command(&session.key, &foreign).unwrap()
            )
            .is_err());
        // A row count and a valid current cursor cannot recreate erased authority.
        journal
            .db
            .execute("DELETE FROM worker_session_snapshots WHERE sequence=1", [])
            .unwrap();
        assert_eq!(
            verify_session_history(&journal.db, &session.key),
            Err("evidence_invalid")
        );
        let before: i64 = journal
            .db
            .query_row("SELECT COUNT(*) FROM worker_reservations", [], |r| r.get(0))
            .unwrap();
        assert!(journal
            .reserve_authenticated(
                &session,
                &reserve,
                &super::super::la_adapter::sign_reserve_command(&session.key, &reserve).unwrap()
            )
            .is_err());
        assert_eq!(
            journal
                .db
                .query_row("SELECT COUNT(*) FROM worker_reservations", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            before
        );
        drop(journal);
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Full retained identity, including the actual immutable input bytes and
/// physical inode. Later assignments cannot replace these audit records.
pub(super) fn retained_loss_identity(
    db: &rusqlite::Connection,
    root: &std::fs::File,
    command: &super::la_adapter::InspectCommand,
) -> Result<(String, u64), &'static str> {
    let (digest, bytes, _) = retained_loss_identity_with_reserve(db, root, command)?;
    Ok((digest, bytes))
}
fn retained_loss_identity_with_reserve(
    db: &rusqlite::Connection,
    root: &std::fs::File,
    c: &super::la_adapter::InspectCommand,
) -> Result<(String, u64, String), &'static str> {
    use std::os::unix::fs::MetadataExt;
    let operation: (String, String, String, Option<Vec<u8>>) = db
        .query_row(
            "SELECT job,input_digest,state,report FROM operations WHERE op=?1",
            [&c.operation],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|_| "evidence_invalid")?;
    let reservation:(String,i64,Vec<u8>,i64,i64,i64,i64,i64)=db.query_row("SELECT operation,fence,command_digest,sequence,lease_until,hard_until,revision,closed FROM worker_reservations WHERE assignment_id=?1",[&c.assignment],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).map_err(|_|"evidence_invalid")?;
    let permit: (Vec<u8>, i64) = db
        .query_row(
            "SELECT command_digest,sequence FROM worker_inspect_commands WHERE operation=?1",
            [&c.operation],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| "evidence_invalid")?;
    let input:(Vec<u8>,String,String,String)=db.query_row("SELECT i.command_digest,i.input_digest,i.content,a.assignment FROM worker_inputs i JOIN worker_input_assignments a ON a.operation=i.operation WHERE i.operation=?1",[&c.operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|_|"evidence_invalid")?;
    let mandate: Vec<u8> = db
        .query_row(
            "SELECT body FROM worker_mandates WHERE job=?1",
            [&c.job],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    let terms: Vec<u8> = db
        .query_row(
            "SELECT body FROM worker_assignment_terms WHERE assignment=?1",
            [&c.assignment],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    let bytes = read_staged_file(root, &input.2, &input.1)?;
    let meta = super::la_artifacts::open_artifact(root, &input.2, libc::O_RDONLY)
        .map_err(|_| "evidence_invalid")?
        .metadata()
        .map_err(|_| "evidence_invalid")?;
    let command = serde_json::to_vec(c).map_err(|_| "evidence_invalid")?;
    if operation
        != (
            c.job.clone(),
            c.input_digest.clone(),
            "started".into(),
            None,
        )
        || reservation.1 != c.fence as i64
        || reservation.7 != 0
        || input.1 != c.input_digest
        || input.3 != c.assignment
        || input.2 != staged_file_name(&c.operation)
        || permit.0 != sha2::Sha256::digest(&command).as_slice()
        || input.0 != permit.0
        || bytes.is_empty()
    {
        return Err("evidence_invalid");
    }
    let terminal:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM worker_result_receipts WHERE operation=?1) OR EXISTS(SELECT 1 FROM worker_stop_receipts WHERE operation=?1) OR EXISTS(SELECT 1 FROM worker_cleanup_receipts WHERE assignment=?2)",rusqlite::params![c.operation,c.assignment],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
    if terminal {
        return Err("evidence_invalid");
    }
    let reserve_operation = reservation.0.clone();
    let retained = super::la_adapter::value_digest(&(
        operation,
        reservation,
        permit,
        input,
        mandate,
        terms,
        (
            meta.dev(),
            meta.ino(),
            meta.blocks(),
            bytes.len(),
            hex::encode(sha2::Sha256::digest(&bytes)),
        ),
    ))?;
    Ok((retained, bytes.len() as u64, reserve_operation))
}
pub(super) struct VerifiedExecutionOccupancy {
    pub(super) live_reservations: usize,
    pub(super) live_operations: usize,
    pub(super) retained_bytes: u64,
    retired_operations: std::collections::BTreeSet<String>,
    retired_assignments: std::collections::BTreeSet<String>,
    retired_reserve_operations: std::collections::BTreeSet<String>,
    retired_jobs: std::collections::BTreeSet<String>,
}
pub(super) fn verified_execution_occupancy(
    db: &rusqlite::Connection,
    root: &std::fs::File,
    keys: Option<&super::la_adapter::ChannelKeys>,
) -> Result<VerifiedExecutionOccupancy, &'static str> {
    let mut v = VerifiedExecutionOccupancy {
        live_reservations: 0,
        live_operations: 0,
        retained_bytes: 0,
        retired_operations: Default::default(),
        retired_assignments: Default::default(),
        retired_reserve_operations: Default::default(),
        retired_jobs: Default::default(),
    };
    let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_spent_losses')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
    if table {
        let keys = keys.ok_or("evidence_invalid")?;
        let mut installed_assignments = std::collections::BTreeSet::new();
        let mut installed_operations = std::collections::BTreeSet::new();
        let mut installed_jobs = std::collections::BTreeSet::new();
        let mut st=db.prepare("SELECT operation,assignment,body FROM worker_spent_losses ORDER BY operation LIMIT 9").map_err(|_|"evidence_invalid")?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| "evidence_invalid")?;
        for (i, row) in rows.enumerate() {
            let (op, assignment, bytes) = row.map_err(|_| "evidence_invalid")?;
            if i >= 8 || bytes.len() > 12288 {
                return Err("evidence_invalid");
            }
            let cap: super::la_adapter::SpentLossDisposition =
                serde_json::from_slice(&bytes).map_err(|_| "evidence_invalid")?;
            cap.verify_worker_identity(root, keys)?;
            let (digest, count, reserve_operation) =
                retained_loss_identity_with_reserve(db, root, &cap.command)?;
            if op != cap.command.operation
                || assignment != cap.command.assignment
                || digest != cap.retained
                || count != cap.retained_bytes
                || serde_json::to_vec(&cap).map_err(|_| "evidence_invalid")? != bytes
            {
                return Err("evidence_invalid");
            }
            // Conflicting installed identities fail the whole derivation, even
            // if a different row has not yet been independently consumed.
            if !valid_id(&reserve_operation)
                || !installed_assignments.insert(assignment.clone())
                || !installed_jobs.insert(cap.command.job.clone())
                || !installed_operations.insert(op.clone())
                || (reserve_operation != op
                    && !installed_operations.insert(reserve_operation.clone()))
            {
                return Err("evidence_invalid");
            }
            if cap.verified_retirement(root, keys)? {
                v.retired_operations.insert(op);
                v.retired_assignments.insert(assignment);
                v.retired_reserve_operations.insert(reserve_operation);
                v.retired_jobs.insert(cap.command.job.clone());
            }
            v.retained_bytes = v
                .retained_bytes
                .checked_add(count)
                .ok_or("evidence_invalid")?;
        }
    }
    let mut st=db.prepare("SELECT assignment_id FROM worker_reservations WHERE closed=0 ORDER BY assignment_id LIMIT 9").map_err(|_|"evidence_invalid")?;
    for (i, row) in st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|_| "evidence_invalid")?
        .enumerate()
    {
        let id = row.map_err(|_| "evidence_invalid")?;
        if i >= 8 {
            return Err("evidence_invalid");
        };
        if !v.retired_assignments.contains(&id) {
            v.live_reservations += 1
        }
    }
    let mut st = db
        .prepare("SELECT op FROM operations WHERE state='started' ORDER BY op LIMIT 33")
        .map_err(|_| "evidence_invalid")?;
    for (i, row) in st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|_| "evidence_invalid")?
        .enumerate()
    {
        let id = row.map_err(|_| "evidence_invalid")?;
        if i >= 32 {
            return Err("evidence_invalid");
        };
        if !v.retired_operations.contains(&id) {
            v.live_operations += 1
        }
    }
    Ok(v)
}
impl OperationJournal {
    pub(super) fn install_spent_loss(
        &mut self,
        cap: &super::la_adapter::SpentLossDisposition,
        keys: &super::la_adapter::ChannelKeys,
    ) -> Result<(), &'static str> {
        self.bind_occupancy_keys(keys)?;
        self.check_root()?;
        cap.verify_worker_identity(&self.root, keys)?;
        let (digest, bytes) = retained_loss_identity(&self.db, &self.root, &cap.command)?;
        if digest != cap.retained || bytes != cap.retained_bytes {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS worker_spent_losses(operation TEXT PRIMARY KEY,assignment TEXT NOT NULL UNIQUE,body BLOB NOT NULL)").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO worker_spent_losses VALUES(?1,?2,?3)",
            rusqlite::params![
                cap.command.operation,
                cap.command.assignment,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()
    }
    pub(super) fn bind_occupancy_keys(
        &mut self,
        keys: &super::la_adapter::ChannelKeys,
    ) -> Result<(), &'static str> {
        if self.occupancy_keys.as_ref().is_some_and(|old| {
            old.custody != keys.custody
                || old.reply != keys.reply
                || old.command != keys.command
                || old.authority != keys.authority
        }) {
            return Err("evidence_invalid");
        };
        self.occupancy_keys = Some(Box::new(keys.clone()));
        Ok(())
    }
}

impl OperationJournal {
    pub(super) fn spent_loss(
        &self,
        digest: &str,
    ) -> Result<super::la_adapter::SpentLossDisposition, &'static str> {
        self.check_root()?;
        let mut st = self
            .db
            .prepare("SELECT body FROM worker_spent_losses LIMIT 9")
            .map_err(|_| "evidence_invalid")?;
        for (i, row) in st
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|_| "evidence_invalid")?
            .enumerate()
        {
            let body = row.map_err(|_| "evidence_invalid")?;
            if i >= 8 || body.len() > 12288 {
                return Err("evidence_invalid");
            };
            let cap: super::la_adapter::SpentLossDisposition =
                serde_json::from_slice(&body).map_err(|_| "evidence_invalid")?;
            if cap.digest()? == digest {
                return Ok(cap);
            }
        }
        Err("evidence_invalid")
    }
    pub(super) fn verified_occupancy(&self) -> Result<VerifiedExecutionOccupancy, &'static str> {
        self.check_root()?;
        verified_execution_occupancy(&self.db, &self.root, self.occupancy_keys.as_deref())
    }
}

#[cfg(test)]
std::thread_local! {
    static RETIRED_REFUSAL: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// Fixture-only probes on the REAL installed/consumed disposition. They do not
/// open admission, synthesize another running task or claim, or mutate old rows.
#[cfg(test)]
impl OperationJournal {
    pub(super) fn test_retired_lookup_probes(
        &mut self,
        session: &ReservationSession,
        command: &super::la_adapter::InspectCommand,
    ) -> Result<serde_json::Value, &'static str> {
        use super::la_adapter as a;
        let before = a::state_custody::state_digest(&self.root)?;
        let occupancy = self.checked_occupancy()?;
        if occupancy.live_operations != 0
            || occupancy.live_reservations != 0
            || !occupancy.retired_jobs.contains(&command.job)
        {
            return Err("evidence_invalid");
        }
        let reserve: (String,i64,i64,Vec<u8>) = self.db.query_row(
            "SELECT operation,lease_until,hard_until,command_digest FROM worker_reservations WHERE assignment_id=?1",
            [&command.assignment], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))
        ).map_err(|_| "evidence_invalid")?;
        let reserve_command = a::ReserveCommand {
            worker: command.worker.clone(),
            boot: command.boot.clone(),
            assignment: command.assignment.clone(),
            operation: reserve.0.clone(),
            fence: command.fence,
            lease_until: reserve.1.try_into().map_err(|_| "evidence_invalid")?,
            hard_until: reserve.2.try_into().map_err(|_| "evidence_invalid")?,
        };
        let reserve_mac = a::sign_reserve_command(&session.key, &reserve_command)?;
        if a::verify_reserve_command(&session.key, &reserve_command, &reserve_mac)?.as_slice()
            != reserve.3
        {
            return Err("evidence_invalid");
        }
        let terms: Vec<u8> = self
            .db
            .query_row(
                "SELECT body FROM worker_assignment_terms WHERE assignment=?1",
                [&command.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let terms = serde_json::from_slice::<super::la_store::AssignmentTerms>(&terms)
            .map_err(|_| "evidence_invalid")?;
        let mandate: Vec<u8> = self
            .db
            .query_row(
                "SELECT body FROM worker_mandates WHERE job=?1",
                [&command.job],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let mandate = serde_json::from_slice::<super::la_auth::StoredMandate>(&mandate)
            .map_err(|_| "evidence_invalid")?;
        let input = read_staged_file(
            &self.root,
            &staged_file_name(&command.operation),
            &command.input_digest,
        )?;
        let start = a::sign_start_command(&session.key, command)?;
        let stage = a::sign_stage_command(&session.key, command)?;
        let stop = a::sign_stop_command(&session.key, command)?;
        let permit = a::sign_inspect_command(&session.key, command)?;
        let close = a::CloseCommand {
            worker: command.worker.clone(),
            boot: command.boot.clone(),
            assignment: command.assignment.clone(),
            fence: command.fence,
            operation: reserve.0.clone(),
        };
        let close_mac = a::sign_close_command(&session.key, &close)?;
        let renewal = a::RenewCommand {
            worker: command.worker.clone(),
            boot: command.boot.clone(),
            assignment: command.assignment.clone(),
            fence: command.fence,
            operation: reserve.0.clone(),
            revision: 1,
            previous_until: reserve_command.lease_until,
            requested_until: reserve_command.lease_until + 1,
        };
        let renewal_mac = a::sign_renew_command(&session.key, &renewal)?;
        let mut probes = Vec::new();
        macro_rules! refused {
            ($name:literal,$call:expr) => {{
                RETIRED_REFUSAL.with(|last| last.set(None));
                if $call.err() != Some("evidence_invalid")
                    || RETIRED_REFUSAL.with(|last| last.get()) != Some($name)
                {
                    return Err("evidence_invalid");
                }
                probes.push($name);
            }};
        }
        // Each ID facet independently reaches the authenticated set guard.
        self.guard_ids(
            "unrelated_ids",
            &["assignment_retired_probe_new"],
            &["operation_retired_probe_new"],
            &["job_retired_probe_new"],
        )?;
        refused!(
            "assignment_facet",
            self.guard_ids("assignment_facet", &[&command.assignment], &[], &[])
        );
        refused!(
            "reserve_operation_facet",
            self.guard_ids("reserve_operation_facet", &[], &[&reserve.0], &[])
        );
        refused!(
            "execution_operation_facet",
            self.guard_ids("execution_operation_facet", &[], &[&command.operation], &[])
        );
        refused!(
            "job_facet",
            self.guard_ids("job_facet", &[], &[], &[&command.job])
        );
        refused!(
            "bind_assignment_terms",
            self.bind_assignment_terms(&reserve_command, &terms)
        );
        refused!(
            "reserve_authenticated",
            self.reserve_authenticated(session, &reserve_command, &reserve_mac)
        );
        refused!(
            "bind_worker_mandate",
            self.bind_worker_mandate(session, command, &mandate)
        );
        refused!("worker_mandate", self.worker_mandate(session, command));
        refused!(
            "accept_inspect_permit",
            self.accept_inspect_permit(session, command, &permit)
        );
        refused!(
            "stage_authenticated_input",
            self.stage_authenticated_input(session, command, &stage, &input)
        );
        refused!(
            "staged_inspection_input",
            self.staged_inspection_input(session, command, &start)
        );
        refused!(
            "authenticate_inspection",
            self.authenticate_inspection(session, command, &start)
        );
        refused!(
            "authenticate_running_command",
            self.authenticate_running_command(session, command)
        );
        refused!(
            "inspect_authenticated",
            self.inspect_authenticated(session, command, &start, &input)
        );
        refused!(
            "inspect_with_receipt",
            self.inspect_with_receipt(session, command, &start, &input)
        );
        refused!(
            "inspect_staged",
            self.inspect_staged(session, command, &start)
        );
        refused!("start_inspection", self.start_inspection(session, command));
        refused!(
            "enter_inspection",
            self.enter_inspection(
                &command.operation,
                &command.job,
                &input,
                &command.input_digest,
                Instant::now() + std::time::Duration::from_millis(50),
                || false
            )
        );
        refused!(
            "inspect_once",
            self.inspect_once(
                &command.operation,
                &command.job,
                &input,
                &command.input_digest,
                Instant::now() + std::time::Duration::from_millis(50),
                || false
            )
        );
        let report = serde_json::to_vec(&serde_json::json!({"sha256":command.input_digest}))
            .map_err(|_| "evidence_invalid")?;
        refused!(
            "publish_inspection",
            self.publish_inspection(&command.operation, &command.input_digest, &report)
        );
        refused!(
            "inspection_receipt",
            self.inspection_receipt(session, command, report)
        );
        refused!(
            "authenticated_status",
            self.authenticated_status(session, command)
        );
        refused!("inspection_reply", self.inspection_reply(session, command));
        refused!(
            "stop_before_start",
            self.stop_before_start(&command.operation, &command.job, &command.input_digest)
        );
        refused!(
            "stop_authenticated_before_start",
            self.stop_authenticated_before_start(session, command, &stop)
        );
        refused!(
            "stop_with_receipt",
            self.stop_with_receipt(session, command, &stop)
        );
        refused!(
            "renew_authenticated",
            self.renew_authenticated(session, &renewal, &renewal_mac)
        );
        refused!(
            "close_authenticated",
            self.close_authenticated(session, &close, &close_mac)
        );
        refused!(
            "cleanup_fenced_inputs",
            self.cleanup_fenced_inputs(&close, 1)
        );
        if a::state_custody::state_digest(&self.root)? != before
            || self.start_count(&command.operation)? != 1
        {
            return Err("evidence_invalid");
        }
        Ok(
            serde_json::json!({"kind":"RETIRED_LOOKUP_PROBES","probes":probes,"unrelated_ids_guard_passed":true,"complete_retained_state_unchanged":true,"raw_old_entries":1,"old_input_bytes":input.len(),"reserve_operation_distinct":reserve.0!=command.operation,"reserve_digest_matches_original":true,"live_operations":0,"live_reservations":0,"NEW_claim_held":false,"admitted":false,"not_complete_NEW_claim_replay_proof":true}),
        )
    }
}

impl OperationJournal {
    /// Entered-loss generation installation is separate from terminal cleanup.
    /// Raw started/open rows survive; only the independently retired identity
    /// can pass this consumer. No WorkerAdmission is installed here.
    pub(super) fn install_loss_return_generation(
        &mut self,
        session: &ReservationSession,
        cap: &super::la_adapter::LossReturnAdmission,
        keys: &super::la_adapter::ChannelKeys,
    ) -> Result<u64, &'static str> {
        self.check_root()?;
        let installed_at = cap.current_install_clock(keys)?;
        cap.verify_retained_worker(&self.root, keys)?;
        if cap.binding().worker != session.worker
            || cap.binding().worker_boot != session.boot
            || session.key != keys.reply
        {
            return Err("evidence_invalid");
        }
        let occupancy = self.checked_occupancy()?;
        if occupancy.live_reservations != 0 || occupancy.live_operations != 0 {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let (old_boot, generation, sequence, fence) = cap.cursor();
        append_loss_return_generation(
            &tx,
            session,
            (old_boot, generation, sequence, fence),
            &cap.digest()?,
        )?;
        tx.execute_batch("CREATE TABLE worker_loss_return_installs(admission TEXT PRIMARY KEY,capability BLOB NOT NULL,installed_at INTEGER NOT NULL,ack BLOB NOT NULL)")
            .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO worker_loss_return_installs VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                cap.digest()?,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?,
                installed_at as i64,
                cap.worker_ack(keys, installed_at)?.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        self.check_root()?;
        cap.current_install_clock(keys)?;
        Ok(installed_at)
    }
}

fn append_loss_return_generation(
    tx: &rusqlite::Transaction<'_>,
    session: &ReservationSession,
    cursor: (&str, u64, u64, u64),
    authority: &str,
) -> Result<(), &'static str> {
    let (old_boot, generation, sequence, fence) = cursor;
    verify_session_history(tx, &session.key)?;
    let current: (String, String, i64, i64) = tx
        .query_row(
            "SELECT worker,boot,sequence,fence FROM reservation_session",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|_| "evidence_invalid")?;
    let next: i64 = tx
        .query_row(
            "SELECT MAX(generation)+1 FROM worker_session_generations",
            [],
            |r| r.get(0),
        )
        .map_err(|_| "evidence_invalid")?;
    let raw:(i64,i64,i64)=tx.query_row("SELECT (SELECT COUNT(*) FROM operations WHERE state='started'),(SELECT COUNT(*) FROM worker_reservations WHERE closed=0),(SELECT COUNT(*) FROM worker_reservations)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"evidence_invalid")?;
    if generation != 2
        || sequence != 2
        || fence != 1
        || next != 2
        || old_boot == session.boot
        || current != (session.worker.clone(), old_boot.into(), 2, 1)
        || raw != (1, 1, 1)
        || authority.len() != 64
        || hex::decode(authority).is_err()
    {
        return Err("evidence_invalid");
    }
    append_session_generation(tx, session, 2, 2, 1, authority)?;
    if tx
        .execute(
            "UPDATE reservation_session SET boot=?1 WHERE boot=?2",
            rusqlite::params![session.boot, old_boot],
        )
        .map_err(|_| "storage_unavailable")?
        != 1
    {
        return Err("evidence_invalid");
    }
    verify_session_history(tx, &session.key)
}

#[cfg(test)]
mod loss_return_generation_tests {
    use super::super::la_adapter::*;
    use super::*;

    #[test]
    fn synthetic_loss_return_adjacent_transaction_preserves_raw_entered_history_and_bytes() {
        // Executes the actual mutation primitive with real journal commands and
        // retained bytes. It is not P history/process qualification or admission.
        let path = std::env::temp_dir().join(format!(
            "loss-return-worker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        let mut j =
            OperationJournal::bootstrap(&path.join("worker.sqlite"), "custody_admission_01")
                .unwrap();
        let old = ReservationSession {
            worker: "worker_admission_01".into(),
            boot: "a".repeat(64),
            key: [12; 32],
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let reserve = ReserveCommand {
            worker: old.worker.clone(),
            boot: old.boot.clone(),
            assignment: "assignment_old_001".into(),
            operation: "reservation_old_001".into(),
            fence: 1,
            lease_until: now + 4000,
            hard_until: now + 6000,
        };
        j.reserve_authenticated(
            &old,
            &reserve,
            &sign_reserve_command(&old.key, &reserve).unwrap(),
        )
        .unwrap();
        let input = [b'x'; 45];
        let c = InspectCommand {
            backend: None,
            worker: old.worker.clone(),
            boot: old.boot.clone(),
            assignment: reserve.assignment.clone(),
            operation: "execution_old_001".into(),
            job: "job_retained_old_01".into(),
            fence: 1,
            input_digest: hex::encode(Sha256::digest(input)),
            accepted_at: now,
            mandate_until: now + 4000,
            permit_until: now + 1500,
        };
        j.accept_inspect_permit(&old, &c, &sign_inspect_command(&old.key, &c).unwrap())
            .unwrap();
        j.stage_authenticated_input(&old, &c, &sign_stage_command(&old.key, &c).unwrap(), &input)
            .unwrap();
        j.enter_inspection(
            &c.operation,
            &c.job,
            &input,
            &c.input_digest,
            Instant::now() + std::time::Duration::from_secs(1),
            || false,
        )
        .unwrap();
        let before = |db: &rusqlite::Connection| {
            let mut s=db.prepare("SELECT sequence,assignment,generation,worker,boot,fence,event,proof,mac FROM worker_session_snapshots ORDER BY sequence").unwrap();
            s.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, Vec<u8>>(7)?,
                    r.get::<_, Vec<u8>>(8)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        };
        let snapshots = before(&j.db);
        let generation: Vec<u8> =
            j.db.query_row(
                "SELECT mac FROM worker_session_generations WHERE generation=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let new = ReservationSession {
            worker: old.worker.clone(),
            boot: "b".repeat(64),
            key: old.key,
        };
        for cursor in [
            (old.boot.as_str(), 3, 2, 1),
            (old.boot.as_str(), 2, 3, 1),
            (old.boot.as_str(), 2, 2, 2),
            (new.boot.as_str(), 2, 2, 1),
        ] {
            let tx =
                j.db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
            assert!(append_loss_return_generation(&tx, &new, cursor, &"a".repeat(64)).is_err());
            drop(tx);
            verify_session_history(&j.db, &old.key).unwrap();
            assert_eq!(before(&j.db), snapshots);
        }
        {
            let tx =
                j.db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
            append_loss_return_generation(&tx, &new, (&old.boot, 2, 2, 1), &"a".repeat(64))
                .unwrap();
            tx.commit().unwrap();
        }
        verify_session_history(&j.db, &new.key).unwrap();
        assert_eq!(before(&j.db), snapshots);
        assert_eq!(
            j.db.query_row(
                "SELECT mac FROM worker_session_generations WHERE generation=1",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
            generation
        );
        let cursor: (String, i64, i64) =
            j.db.query_row(
                "SELECT boot,sequence,fence FROM reservation_session",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(cursor, (new.boot.clone(), 2, 1));
        let raw:(i64,i64)=j.db.query_row("SELECT (SELECT COUNT(*) FROM operations WHERE state='started'),(SELECT COUNT(*) FROM worker_reservations WHERE closed=0)",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(raw, (1, 1));
        assert_eq!(
            read_staged_file(&j.root, &staged_file_name(&c.operation), &c.input_digest).unwrap(),
            input
        );
        let tx =
            j.db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
        assert!(
            append_loss_return_generation(&tx, &new, (&old.boot, 2, 2, 1), &"a".repeat(64))
                .is_err()
        );
        drop(tx);
        drop(j);
        std::fs::remove_dir_all(path).unwrap();
    }
}

impl OperationJournal {
    pub(super) fn persist_loss_return_completion(
        &mut self,
        proof: &super::la_adapter::LossReturnCompletion,
        keys: &super::la_adapter::ChannelKeys,
    ) -> Result<(), &'static str> {
        self.check_root()?;
        let saved: Vec<u8> = self
            .db
            .query_row(
                "SELECT capability FROM worker_loss_return_installs WHERE admission=?1",
                [proof.admission()],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let cap: super::la_adapter::LossReturnAdmission =
            serde_json::from_slice(&saved).map_err(|_| "evidence_invalid")?;
        proof.verify_for(&cap, keys)?;
        cap.verify_completion_role(proof, &self.root, "worker", keys)?;
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE worker_loss_return_completions(admission TEXT PRIMARY KEY,proof BLOB NOT NULL)").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO worker_loss_return_completions VALUES(?1,?2)",
            rusqlite::params![
                proof.admission(),
                serde_json::to_vec(proof).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        super::la_adapter::LossReturnCopy::record(&self.root, "worker", &cap, proof, keys)?;
        self.check_root()?;
        cap.current_install_clock(keys)?;
        Ok(())
    }
}
