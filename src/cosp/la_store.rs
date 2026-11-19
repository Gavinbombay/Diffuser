//! Internal reservation transaction. Callers must authenticate and validate all
//! policy, inventory, quotas and worker evidence before reaching this primitive.
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

type PermitAckRow = (i64, i64, i64, Option<i64>, Option<i64>, bool);
type RenewalAckRow = (String, bool, String, i64, i64, String, String, i64);

fn checked_wall_since(previous: u64) -> Result<u64, &'static str> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| u64::try_from(v.as_millis()).ok())
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or("clock_untrusted")?;
    if now < previous {
        return Err("clock_untrusted");
    }
    Ok(now)
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AssignmentTerms {
    pub(super) cpu_millicores: u64,
    pub(super) memory_bytes: u64,
    pub(super) storage_bytes: u64,
    pub(super) accepted_at: u64,
    pub(super) lease_until: u64,
    pub(super) hard_until: u64,
}

pub(super) struct ClaimStore {
    db: PinnedDb,
    root: std::fs::File,
    root_path: PathBuf,
    lock: std::fs::File,
    quarantined: std::cell::Cell<bool>,
}

struct ClaimLock(std::fs::File);
impl Drop for ClaimLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn claim_lock(file: &std::fs::File) -> Result<ClaimLock, &'static str> {
    use std::os::fd::AsRawFd;
    let file = file.try_clone().map_err(|_| "storage_unavailable")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(ClaimLock(file));
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EWOULDBLOCK)
            || std::time::Instant::now() >= deadline
        {
            return Err("storage_unavailable");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn claim_marker_present(root: &std::fs::File) -> Result<bool, &'static str> {
    use std::os::fd::AsRawFd;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            c".claim-quarantine".as_ptr(),
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
fn mark_claim_quarantine(root: &std::fs::File) -> Result<(), &'static str> {
    use std::{
        io::Write,
        os::fd::{AsRawFd, FromRawFd},
    };
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c".claim-quarantine".as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return if claim_marker_present(root)? {
            Ok(())
        } else {
            Err("storage_unavailable")
        };
    }
    let mut marker = unsafe { std::fs::File::from_raw_fd(fd) };
    marker
        .write_all(b"claim-custody-uncertain-v1\n")
        .and_then(|_| marker.sync_all())
        .map_err(|_| "storage_unavailable")?;
    root.sync_all().map_err(|_| "storage_unavailable")
}
pub(super) fn claim_root_matches(root: &std::fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(current) = super::la_artifacts::open_owned_root(path) else {
        return false;
    };
    let (Ok(a), Ok(b)) = (root.metadata(), current.metadata()) else {
        return false;
    };
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}
fn open_claim_lock(root: &std::fs::File) -> Result<std::fs::File, &'static str> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c".claim-lock".as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("storage_unavailable");
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    if !file
        .metadata()
        .map_err(|_| "storage_unavailable")?
        .is_file()
    {
        return Err("storage_unavailable");
    }
    Ok(file)
}
fn valid_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
pub(super) fn reservation_operation(id: &str, fence: i64) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"diffuser-reservation-operation-v1\0");
    hash.update((id.len() as u64).to_be_bytes());
    hash.update(id.as_bytes());
    hash.update(fence.to_be_bytes());
    format!("reserve_{}", hex::encode(hash.finalize()))
}

impl ClaimStore {
    pub(super) fn open(path: &Path) -> Result<Self, &'static str> {
        let parent = path
            .parent()
            .filter(|p| p.is_absolute())
            .ok_or("storage_unavailable")?;
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or("storage_unavailable")?;
        let root =
            super::la_artifacts::open_owned_root(parent).map_err(|_| "storage_unavailable")?;
        let lock = open_claim_lock(&root)?;
        let guard = claim_lock(&lock)?;
        if claim_marker_present(&root)? {
            return Err("storage_unavailable");
        }
        let db = open_pinned_database(&root, name, true)?;
        if !claim_root_matches(&root, parent) {
            let _ = mark_claim_quarantine(&root);
            return Err("storage_unavailable");
        }
        db.busy_timeout(Duration::from_secs(3))
            .map_err(|_| "storage_unavailable")?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS la_assignments (id TEXT PRIMARY KEY, project TEXT NOT NULL, actor TEXT NOT NULL, worker TEXT NOT NULL, fence INTEGER NOT NULL, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS la_reservations (domain TEXT PRIMARY KEY, assignment_id TEXT NOT NULL UNIQUE REFERENCES la_assignments(id));
            CREATE TABLE IF NOT EXISTS la_quota_charges (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), project TEXT NOT NULL, actor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS la_assignment_grant_charges (assignment_id TEXT NOT NULL REFERENCES la_assignments(id), grant_id TEXT NOT NULL, PRIMARY KEY(assignment_id,grant_id));
            CREATE TABLE IF NOT EXISTS la_assignment_terms (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), cpu INTEGER NOT NULL, memory INTEGER NOT NULL, storage INTEGER NOT NULL, accepted INTEGER NOT NULL, lease_until INTEGER NOT NULL, hard_until INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS la_assignment_revisions (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), revision INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS la_assignment_release_keys (project TEXT NOT NULL, actor TEXT NOT NULL, idem_key TEXT NOT NULL, assignment_id TEXT NOT NULL REFERENCES la_assignments(id), expected_revision INTEGER NOT NULL, PRIMARY KEY(project,actor,idem_key));
            CREATE TABLE IF NOT EXISTS la_assignment_renewals (project TEXT NOT NULL, actor TEXT NOT NULL, idem_key TEXT NOT NULL, assignment_id TEXT NOT NULL REFERENCES la_assignments(id), expected_revision INTEGER NOT NULL, requested_ms INTEGER NOT NULL, operation TEXT NOT NULL UNIQUE, command TEXT NOT NULL, acknowledged INTEGER NOT NULL, PRIMARY KEY(project,actor,idem_key));
            CREATE TABLE IF NOT EXISTS la_authority_observations (sequence INTEGER PRIMARY KEY, observed_at INTEGER NOT NULL, body BLOB NOT NULL, mac BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS la_outbox (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), action TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS la_idempotency (project TEXT NOT NULL, actor TEXT NOT NULL, operation TEXT NOT NULL, idem_key TEXT NOT NULL, fingerprint TEXT NOT NULL, assignment_id TEXT NOT NULL REFERENCES la_assignments(id), PRIMARY KEY(project,actor,operation,idem_key));
            CREATE TABLE IF NOT EXISTS la_mandates (job TEXT PRIMARY KEY, body TEXT NOT NULL, digest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS la_close_intents (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), first_reason TEXT NOT NULL, requested_at INTEGER NOT NULL, stop_operation TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS la_assignment_cleanup_receipts (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), digest TEXT NOT NULL, certificate BLOB NOT NULL, released_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS la_assignment_stop_receipts (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), receipt_digest BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS la_permits (job TEXT PRIMARY KEY REFERENCES la_mandates(job), lease_ack INTEGER NOT NULL, ack_until INTEGER NOT NULL, ack_revision INTEGER NOT NULL, pending_revision INTEGER, pending_until INTEGER, closed INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS la_worker_receipts (worker TEXT NOT NULL, boot TEXT NOT NULL, sequence INTEGER NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(worker,boot,sequence));
            CREATE TABLE IF NOT EXISTS la_worker_cursor (worker TEXT PRIMARY KEY, boot TEXT NOT NULL, sequence INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS la_reservation_authorizations (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), worker TEXT NOT NULL, boot TEXT NOT NULL, fence INTEGER NOT NULL, operation TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS la_reservation_operations (assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id), operation TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS la_jobs (id TEXT PRIMARY KEY, assignment_id TEXT NOT NULL REFERENCES la_assignments(id), project TEXT NOT NULL, actor TEXT NOT NULL, input_artifact TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, result_artifact TEXT);
            CREATE TABLE IF NOT EXISTS la_job_idempotency (project TEXT NOT NULL, actor TEXT NOT NULL, idem_key TEXT NOT NULL, fingerprint TEXT NOT NULL, job TEXT NOT NULL REFERENCES la_jobs(id), PRIMARY KEY(project,actor,idem_key));
            CREATE TABLE IF NOT EXISTS la_client_jobs (project TEXT NOT NULL, actor TEXT NOT NULL, client_job_id TEXT NOT NULL, fingerprint TEXT NOT NULL, job TEXT NOT NULL REFERENCES la_jobs(id), PRIMARY KEY(project,actor,client_job_id));
            CREATE TABLE IF NOT EXISTS la_job_outbox (job TEXT PRIMARY KEY REFERENCES la_jobs(id), operation TEXT NOT NULL UNIQUE, action TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS la_job_permit_intents (job TEXT PRIMARY KEY REFERENCES la_jobs(id), command TEXT NOT NULL, digest TEXT NOT NULL, permit_until INTEGER NOT NULL, acknowledged INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS la_job_results (job TEXT PRIMARY KEY REFERENCES la_jobs(id), output_id TEXT NOT NULL UNIQUE, report_digest TEXT NOT NULL, receipt_digest BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS la_job_grant_charges (job TEXT NOT NULL REFERENCES la_jobs(id), grant_id TEXT NOT NULL, PRIMARY KEY(job,grant_id));
            CREATE TABLE IF NOT EXISTS la_job_cancel_keys (project TEXT NOT NULL, actor TEXT NOT NULL, idem_key TEXT NOT NULL, job TEXT NOT NULL REFERENCES la_jobs(id), expected_revision INTEGER NOT NULL, PRIMARY KEY(project,actor,idem_key));")
            .map_err(|_| "storage_unavailable")?;
        drop(guard);
        Ok(Self {
            db,
            root,
            root_path: parent.to_path_buf(),
            lock,
            quarantined: std::cell::Cell::new(false),
        })
    }

    fn guard(&self) -> Result<ClaimLock, &'static str> {
        if self.quarantined.get() {
            return Err("storage_unavailable");
        }
        let guard = claim_lock(&self.lock)?;
        if claim_marker_present(&self.root)? {
            self.quarantined.set(true);
            return Err("storage_unavailable");
        }
        if !claim_root_matches(&self.root, &self.root_path) {
            self.quarantined.set(true);
            let _ = mark_claim_quarantine(&self.root);
            return Err("storage_unavailable");
        }
        Ok(guard)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
    )]
    pub(super) fn reserve(
        &mut self,
        id: &str,
        project: &str,
        actor: &str,
        key: &str,
        fingerprint: &str,
        worker: &str,
        fence: i64,
    ) -> Result<String, &'static str> {
        self.reserve_inner(
            id,
            project,
            actor,
            key,
            fingerprint,
            worker,
            Some(fence),
            &[],
            None,
            None,
        )
    }

    /// Claim the single S1 seat and charge the complete authenticated lineage
    /// in one immediate transaction. `lineage` is root through leaf; the caller
    /// must hold its authority observation stable across this transaction.
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit claim identity and authorization terms."
    )]
    pub(super) fn reserve_scoped(
        &mut self,
        id: &str,
        project: &str,
        actor: &str,
        key: &str,
        fingerprint: &str,
        worker: &str,
        lineage: &[String],
        deadline: (u64, std::time::Instant),
        terms: &AssignmentTerms,
    ) -> Result<String, &'static str> {
        if lineage.is_empty()
            || lineage.len() > 3
            || lineage.iter().any(|id| !valid_id(id))
            || lineage
                .iter()
                .enumerate()
                .any(|(i, id)| lineage[..i].contains(id))
        {
            return Err("delegation_denied");
        }
        if [
            terms.cpu_millicores,
            terms.memory_bytes,
            terms.storage_bytes,
        ]
        .contains(&0)
            || [
                terms.cpu_millicores,
                terms.memory_bytes,
                terms.storage_bytes,
                terms.accepted_at,
                terms.lease_until,
                terms.hard_until,
            ]
            .iter()
            .any(|v| *v > i64::MAX as u64)
            || terms.lease_until <= terms.accepted_at
            || terms.hard_until < terms.lease_until
        {
            return Err("schema_invalid");
        }
        self.reserve_inner(
            id,
            project,
            actor,
            key,
            fingerprint,
            worker,
            None,
            lineage,
            Some(deadline),
            Some(terms),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Shared transactional claim implementation."
    )]
    fn reserve_inner(
        &mut self,
        id: &str,
        project: &str,
        actor: &str,
        key: &str,
        fingerprint: &str,
        worker: &str,
        requested_fence: Option<i64>,
        lineage: &[String],
        deadline: Option<(u64, std::time::Instant)>,
        terms: Option<&AssignmentTerms>,
    ) -> Result<String, &'static str> {
        let _guard = self.guard()?;
        if ![id, project, actor, key, worker]
            .iter()
            .all(|v| valid_id(v))
            || requested_fence.is_some_and(|fence| fence <= 0)
            || fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("schema_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        if let Some((wall_deadline, monotonic_deadline)) = deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|v| u64::try_from(v.as_millis()).ok())
                .ok_or("clock_untrusted")?;
            if now >= wall_deadline || std::time::Instant::now() >= monotonic_deadline {
                return Err("evidence_stale");
            }
        }
        let old: Option<(String,String)> = tx.query_row("SELECT fingerprint,assignment_id FROM la_idempotency WHERE project=?1 AND actor=?2 AND operation='acquire' AND idem_key=?3", params![project,actor,key], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_| "storage_unavailable")?;
        if let Some((old_fingerprint, old_id)) = old {
            if !lineage.is_empty() {
                let charges: Vec<String> = {
                    let mut statement=tx.prepare("SELECT grant_id FROM la_assignment_grant_charges WHERE assignment_id=?1 ORDER BY grant_id").map_err(|_|"storage_unavailable")?;
                    let values = statement
                        .query_map([&old_id], |r| r.get(0))
                        .map_err(|_| "storage_unavailable")?
                        .collect::<Result<_, _>>()
                        .map_err(|_| "storage_unavailable")?;
                    values
                };
                let mut expected = lineage.to_vec();
                expected.sort();
                if charges != expected {
                    return Err("delegation_denied");
                }
            }
            return if old_fingerprint == fingerprint {
                Ok(old_id)
            } else {
                Err("idempotency_conflict")
            };
        }
        let fence = match requested_fence {
            Some(fence) => fence,
            None => {
                let last: i64 = tx
                    .query_row(
                        "SELECT COALESCE(MAX(fence),0) FROM la_assignments WHERE worker=?1",
                        [worker],
                        |r| r.get(0),
                    )
                    .map_err(|_| "storage_unavailable")?;
                last.checked_add(1)
                    .filter(|v| *v > 0)
                    .ok_or("storage_unavailable")?
            }
        };
        if !lineage.is_empty() {
            let (actor_count, project_count): (i64, i64) = tx.query_row(
                "SELECT COALESCE(SUM(q.actor=?2),0),COALESCE(SUM(q.project=?1),0) FROM la_quota_charges q JOIN la_reservations r ON r.assignment_id=q.assignment_id",
                params![project, actor], |r| Ok((r.get(0)?, r.get(1)?))
            ).map_err(|_| "storage_unavailable")?;
            if actor_count >= 1 || project_count >= 2 {
                return Err("quota_exceeded");
            }
            for grant in lineage {
                let used: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM la_assignment_grant_charges c JOIN la_reservations r ON r.assignment_id=c.assignment_id WHERE c.grant_id=?1)", [grant], |r| r.get(0)).map_err(|_| "storage_unavailable")?;
                if used {
                    return Err("quota_exceeded");
                }
            }
        }
        let occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM la_reservations WHERE domain='cpu-artifact-inspect')",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "storage_unavailable")?;
        if occupied {
            return Err("capacity_unavailable");
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM la_assignments", [], |r| r.get(0))
            .map_err(|_| "storage_unavailable")?;
        if count >= 8 {
            return Err("storage_unavailable");
        }
        tx.execute(
            "INSERT INTO la_assignments VALUES (?1,?2,?3,?4,?5,'reserved')",
            params![id, project, actor, worker, fence],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_reservations VALUES ('cpu-artifact-inspect',?1)",
            [id],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_quota_charges VALUES (?1,?2,?3)",
            params![id, project, actor],
        )
        .map_err(|_| "storage_unavailable")?;
        if let Some(terms) = terms {
            tx.execute("INSERT INTO la_assignment_revisions VALUES (?1,0)", [id])
                .map_err(|_| "storage_unavailable")?;
            tx.execute(
                "INSERT INTO la_assignment_terms VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id,
                    terms.cpu_millicores as i64,
                    terms.memory_bytes as i64,
                    terms.storage_bytes as i64,
                    terms.accepted_at as i64,
                    terms.lease_until as i64,
                    terms.hard_until as i64
                ],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        for grant in lineage {
            tx.execute(
                "INSERT INTO la_assignment_grant_charges VALUES (?1,?2)",
                params![id, grant],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        tx.execute("INSERT INTO la_outbox VALUES (?1,'reserve')", [id])
            .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_reservation_operations VALUES (?1,?2)",
            params![id, reservation_operation(id, fence)],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_idempotency VALUES (?1,?2,'acquire',?3,?4,?5)",
            params![project, actor, key, fingerprint, id],
        )
        .map_err(|_| "storage_unavailable")?;
        if let Some((wall_deadline, monotonic_deadline)) = deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|v| u64::try_from(v.as_millis()).ok())
                .ok_or("clock_untrusted")?;
            if now >= wall_deadline || std::time::Instant::now() >= monotonic_deadline {
                return Err("evidence_stale");
            }
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(id.to_owned())
    }
    pub(super) fn assignment_terms(
        &self,
        project: &str,
        actor: &str,
        id: &str,
    ) -> Result<AssignmentTerms, &'static str> {
        let _guard = self.guard()?;
        let row: Option<(i64,i64,i64,i64,i64,i64)> = self.db.query_row("SELECT t.cpu,t.memory,t.storage,t.accepted,t.lease_until,t.hard_until FROM la_assignment_terms t JOIN la_assignments a ON a.id=t.assignment_id WHERE a.project=?1 AND a.actor=?2 AND a.id=?3", params![project,actor,id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))
            .optional().map_err(|_| "storage_unavailable")?;
        let (cpu, memory, storage, accepted, lease, hard) = row.ok_or("object_not_found")?;
        let convert = |v| u64::try_from(v).map_err(|_| "storage_unavailable");
        Ok(AssignmentTerms {
            cpu_millicores: convert(cpu)?,
            memory_bytes: convert(memory)?,
            storage_bytes: convert(storage)?,
            accepted_at: convert(accepted)?,
            lease_until: convert(lease)?,
            hard_until: convert(hard)?,
        })
    }

    pub(super) fn assignment_view(
        &self,
        project: &str,
        actor: &str,
        id: &str,
    ) -> Result<(String, i64), &'static str> {
        let _guard = self.guard()?;
        self.db
            .query_row(
                "SELECT state,fence FROM la_assignments WHERE project=?1 AND actor=?2 AND id=?3",
                params![project, actor, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?
            .ok_or("object_not_found")
    }

    pub(super) fn counts(&self) -> Result<(i64, i64, i64), &'static str> {
        let _guard = self.guard()?;
        self.db.query_row("SELECT (SELECT COUNT(*) FROM la_reservations), (SELECT COUNT(*) FROM la_quota_charges), (SELECT COUNT(*) FROM la_outbox)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_| "storage_unavailable")
    }
    pub(super) fn state(&self, id: &str) -> Result<String, &'static str> {
        let _guard = self.guard()?;
        self.db
            .query_row("SELECT state FROM la_assignments WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .map_err(|_| "object_not_found")
    }
    /// Only an already authenticated and fully validated worker receipt may call this.
    pub(super) fn ack(&mut self, id: &str, worker: &str, fence: i64) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let changed = self.db.execute("UPDATE la_assignments SET state='assigned' WHERE id=?1 AND worker=?2 AND fence=?3 AND state='reserved'", params![id,worker,fence]).map_err(|_| "storage_unavailable")?;
        if changed != 1 {
            return Err("state_conflict");
        }
        Ok(())
    }
}

pub(super) fn checked_mandate(
    draft: &super::la_auth::MandateDraft,
) -> Result<super::la_auth::StoredMandate, &'static str> {
    let ids = [
        &draft.tenant,
        &draft.project,
        &draft.actor,
        &draft.initiator,
        &draft.lineage,
        &draft.assignment,
        &draft.job,
        &draft.operation,
        &draft.worker,
    ];
    if !ids.iter().all(|id| valid_id(id))
        || !draft.chain.iter().all(|g| valid_id(&g.id))
        || draft.input_digest.len() != 64
        || !draft
            .input_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !super::la_backend::Capability::known_mandate_profile(&draft.profile)
        || !matches!(
            draft.policy.as_str(),
            "lab-proposal-v1" | "runtime-short-v1"
        )
        || draft.cpu_millicores != 1000
        || draft.memory_bytes == 0
        || draft.memory_bytes > 16 * 1024 * 1024
        || draft.storage_bytes == 0
        || draft.storage_bytes > 2 * 1024 * 1024
    {
        return Err("schema_invalid");
    }
    let chain: Vec<_> = draft
        .chain
        .iter()
        .map(|g| super::la_auth::GrantBounds {
            id: &g.id,
            parent: g.parent.as_deref(),
            run_until: Some(g.run_until),
            execution_ceiling: Some(g.execution_ceiling),
        })
        .collect();
    let max_until = super::la_auth::mandate_limit(
        draft.accepted_at,
        draft.runtime_ms,
        draft.assignment_hard,
        draft.project_ceiling,
        &chain,
    )?;
    Ok(super::la_auth::StoredMandate {
        draft: draft.clone(),
        max_until,
    })
}

fn decode_mandate(
    job: &str,
    body: &str,
    digest: &str,
) -> Result<super::la_auth::StoredMandate, &'static str> {
    use sha2::{Digest, Sha256};
    if hex::encode(Sha256::digest(body.as_bytes())) != digest {
        return Err("storage_unavailable");
    }
    let stored: super::la_auth::StoredMandate =
        serde_json::from_str(body).map_err(|_| "storage_unavailable")?;
    if stored.draft.job != job || checked_mandate(&stored.draft).ok().as_ref() != Some(&stored) {
        return Err("storage_unavailable");
    }
    Ok(stored)
}

impl ClaimStore {
    /// Only called after the complete caller, scope, freshness and quota checks.
    /// This primitive is not yet integrated into the job admission transaction.
    pub(super) fn save_mandate(
        &mut self,
        draft: &super::la_auth::MandateDraft,
    ) -> Result<super::la_auth::StoredMandate, &'static str> {
        let _guard = self.guard()?;
        use sha2::{Digest, Sha256};
        let stored = checked_mandate(draft)?;
        let body = serde_json::to_string(&stored).map_err(|_| "storage_unavailable")?;
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT body,digest FROM la_mandates WHERE job=?1",
                [&draft.job],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old_body, old_digest)) = old {
            let previous = decode_mandate(&draft.job, &old_body, &old_digest)?;
            return if previous == stored {
                Ok(previous)
            } else {
                Err("idempotency_conflict")
            };
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM la_mandates", [], |r| r.get(0))
            .map_err(|_| "storage_unavailable")?;
        if count >= 32 {
            return Err("storage_unavailable");
        }
        tx.execute(
            "INSERT INTO la_mandates VALUES (?1,?2,?3)",
            params![draft.job, body, digest],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(stored)
    }
    pub(super) fn load_mandate(
        &self,
        job: &str,
    ) -> Result<super::la_auth::StoredMandate, &'static str> {
        let _guard = self.guard()?;
        self.load_mandate_unlocked(job)
    }
    fn load_mandate_unlocked(
        &self,
        job: &str,
    ) -> Result<super::la_auth::StoredMandate, &'static str> {
        let row: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT body,digest FROM la_mandates WHERE job=?1",
                [job],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let (body, digest) = row.ok_or("object_not_found")?;
        decode_mandate(job, &body, &digest)
    }
}

impl ClaimStore {
    /// Starts closure of a reserved or assigned record and retains its hold.
    /// Authentication and authorization precede this internal primitive. It is
    /// not yet safe for active jobs until job closure expansion is integrated.
    pub(super) fn drain(
        &mut self,
        id: &str,
        project: &str,
        actor: &str,
        reason: &str,
        now: u64,
    ) -> Result<String, &'static str> {
        let _guard = self.guard()?;
        if ![id, project, actor].iter().all(|v| valid_id(v))
            || now > i64::MAX as u64
            || !matches!(
                reason,
                "released"
                    | "revoked"
                    | "lease_expired"
                    | "hard_expired"
                    | "start_expired"
                    | "idle_expired"
            )
        {
            return Err("schema_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM la_assignments WHERE id=?1 AND project=?2 AND actor=?3",
                params![id, project, actor],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        match state.as_deref() {
            None => return Err("object_not_found"),
            Some(crate::error_catalog::DRAINING) => {
                return tx
                    .query_row(
                        "SELECT first_reason FROM la_close_intents WHERE assignment_id=?1",
                        [id],
                        |r| r.get(0),
                    )
                    .map_err(|_| "storage_unavailable");
            }
            Some("reserved" | "assigned") => (),
            _ => return Err("state_conflict"),
        }
        let changed=tx.execute("UPDATE la_assignments SET state='draining' WHERE id=?1 AND state IN ('reserved','assigned')",[id]).map_err(|_| "storage_unavailable")?;
        if changed != 1 {
            return Err("state_conflict");
        }
        let stop_operation = format!("stop:{id}");
        tx.execute(
            "INSERT INTO la_close_intents VALUES (?1,?2,?3,?4)",
            params![id, reason, now as i64, stop_operation],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(reason.to_owned())
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct PermitView {
    pub(super) acknowledged_until: u64,
    pub(super) pending_until: Option<u64>,
    pub(super) revision: u64,
    pub(super) closed: bool,
}
impl ClaimStore {
    /// The initial receipt and all future ACKs must be authenticated and
    /// matched to the complete worker/boot/fence tuple by the caller. These
    /// persistence primitives are not yet connected to worker admission.
    pub(super) fn begin_permit(
        &mut self,
        job: &str,
        acknowledged: u64,
        lease_ack: u64,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let mandate = self.load_mandate_unlocked(job)?;
        if acknowledged <= mandate.draft.accepted_at
            || acknowledged > mandate.max_until
            || acknowledged > lease_ack
            || lease_ack > mandate.draft.assignment_hard
            || lease_ack > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<(i64, i64)> = tx
            .query_row(
                "SELECT ack_until,lease_ack FROM la_permits WHERE job=?1",
                [job],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old_ack, old_lease)) = old {
            return if u64::try_from(old_ack).ok() == Some(acknowledged)
                && u64::try_from(old_lease).ok() == Some(lease_ack)
            {
                Ok(())
            } else {
                Err("idempotency_conflict")
            };
        }
        tx.execute(
            "INSERT INTO la_permits VALUES (?1,?2,?3,0,NULL,NULL,0)",
            params![job, lease_ack as i64, acknowledged as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }

    /// Call only after checking current inclusive-chain authority, freshness,
    /// revocation, current worker identity and writer epoch.
    pub(super) fn propose_permit(
        &mut self,
        job: &str,
        now: u64,
        lease_intent: u64,
        window: u64,
        observed_at: u64,
        freshness: u64,
    ) -> Result<u64, &'static str> {
        let _guard = self.guard()?;
        let mandate = self.load_mandate_unlocked(job)?;
        if now > i64::MAX as u64 || lease_intent > mandate.draft.assignment_hard {
            return Err("deadline_elapsed");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let row:Option<(i64,i64,i64,Option<i64>,bool)> = tx.query_row("SELECT ack_until,lease_ack,ack_revision,pending_until,closed FROM la_permits WHERE job=?1",[job],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|_| "storage_unavailable")?;
        let (ack, lease, revision, pending, closed) = row.ok_or("object_not_found")?;
        if closed {
            return Err("state_conflict");
        }
        let ack = u64::try_from(ack).map_err(|_| "storage_unavailable")?;
        let lease = u64::try_from(lease).map_err(|_| "storage_unavailable")?;
        if now >= ack.min(lease).min(mandate.max_until) {
            tx.execute("UPDATE la_permits SET closed=1,pending_revision=NULL,pending_until=NULL WHERE job=?1", [job]).map_err(|_| "storage_unavailable")?;
            tx.commit().map_err(|_| "storage_unavailable")?;
            return Err("deadline_elapsed");
        }
        if pending.is_some() {
            return Err("state_conflict");
        }
        let revision = revision.checked_add(1).ok_or("storage_unavailable")?;
        let deadline = match super::la_auth::proposed_permit(
            now,
            ack.min(lease).min(mandate.max_until),
            mandate.max_until,
            lease_intent,
            window,
            observed_at,
            freshness,
            false,
        ) {
            Ok(deadline) => deadline,
            Err(error) => {
                tx.execute("UPDATE la_permits SET closed=1,pending_revision=NULL,pending_until=NULL WHERE job=?1",[job]).map_err(|_| "storage_unavailable")?;
                tx.commit().map_err(|_| "storage_unavailable")?;
                return Err(error);
            }
        };
        tx.execute("UPDATE la_permits SET pending_revision=?2,pending_until=?3 WHERE job=?1 AND closed=0 AND pending_until IS NULL",params![job,revision,deadline as i64]).map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(deadline)
    }

    pub(super) fn acknowledge_permit(
        &mut self,
        job: &str,
        revision: u64,
        until: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let mandate = self.load_mandate_unlocked(job)?;
        if [revision, until, now].iter().any(|x| *x > i64::MAX as u64) {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let row:Option<PermitAckRow> = tx.query_row("SELECT ack_until,lease_ack,ack_revision,pending_revision,pending_until,closed FROM la_permits WHERE job=?1",[job],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|_| "storage_unavailable")?;
        let (ack, lease, old_rev, pending_rev, pending_until, closed) =
            row.ok_or("object_not_found")?;
        if closed {
            return Err("state_conflict");
        }
        let ack = u64::try_from(ack).map_err(|_| "storage_unavailable")?;
        let lease = u64::try_from(lease).map_err(|_| "storage_unavailable")?;
        if now >= ack.min(lease).min(mandate.max_until) {
            tx.execute("UPDATE la_permits SET closed=1,pending_revision=NULL,pending_until=NULL WHERE job=?1",[job]).map_err(|_| "storage_unavailable")?;
            tx.commit().map_err(|_| "storage_unavailable")?;
            return Err("deadline_elapsed");
        }
        if pending_rev.is_none()
            && pending_until.is_none()
            && u64::try_from(old_rev).ok() == Some(revision)
            && ack == until
        {
            return Ok(());
        }
        if pending_rev.and_then(|v| u64::try_from(v).ok()) != Some(revision)
            || pending_until.and_then(|v| u64::try_from(v).ok()) != Some(until)
            || until <= now
            || until > mandate.max_until
            || until > lease
        {
            return Err("evidence_invalid");
        }
        tx.execute("UPDATE la_permits SET ack_until=?2,ack_revision=?3,pending_revision=NULL,pending_until=NULL WHERE job=?1 AND closed=0",params![job,until as i64,revision as i64]).map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
    pub(super) fn close_permit(&mut self, job: &str) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let changed=self.db.execute("UPDATE la_permits SET closed=1,pending_revision=NULL,pending_until=NULL WHERE job=?1",[job]).map_err(|_| "storage_unavailable")?;
        if changed != 1 {
            return Err("object_not_found");
        }
        Ok(())
    }
    pub(super) fn permit_view(&self, job: &str) -> Result<PermitView, &'static str> {
        let _guard = self.guard()?;
        let row: Option<(i64, Option<i64>, i64, bool)> = self
            .db
            .query_row(
                "SELECT ack_until,pending_until,ack_revision,closed FROM la_permits WHERE job=?1",
                [job],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let (ack, pending, revision, closed) = row.ok_or("object_not_found")?;
        Ok(PermitView {
            acknowledged_until: u64::try_from(ack).map_err(|_| "storage_unavailable")?,
            pending_until: pending
                .map(u64::try_from)
                .transpose()
                .map_err(|_| "storage_unavailable")?,
            revision: u64::try_from(revision).map_err(|_| "storage_unavailable")?,
            closed,
        })
    }
}

/// A connection and the directory descriptor used by every SQLite path.
/// Field order keeps the descriptor alive until the connection is closed.
pub(super) struct PinnedDb {
    connection: rusqlite::Connection,
    _directory: std::fs::File,
}
impl std::ops::Deref for PinnedDb {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}
impl std::ops::DerefMut for PinnedDb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

// The bundled SQLite Unix VFS normally canonicalizes all symlinks in
// xFullPathname, turning /proc/self/fd/N back into a mutable pathname. Its
// xOpen uses O_NOFOLLOW on the final component. Preserve the proc-fd prefix
// instead, while delegating all I/O and locking to that same Unix VFS.
unsafe extern "C" fn pinned_full_pathname(
    _vfs: *mut rusqlite::ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    output_size: std::ffi::c_int,
    output: *mut std::ffi::c_char,
) -> std::ffi::c_int {
    if name.is_null() || output.is_null() || output_size <= 0 {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    }
    let input = unsafe { std::ffi::CStr::from_ptr(name) }.to_bytes();
    let Some(rest) = input.strip_prefix(b"/proc/self/fd/") else {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    };
    let Some(slash) = rest.iter().position(|b| *b == b'/') else {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    };
    let (digits, tail) = rest.split_at(slash);
    let file = &tail[1..];
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || file.is_empty()
        || file.len() > 128
        || file == b"."
        || file == b".."
        || !file
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || input
            .len()
            .checked_add(1)
            .is_none_or(|n| n > output_size as usize)
    {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    }
    let Ok(fd) = std::str::from_utf8(digits)
        .unwrap_or("")
        .parse::<libc::c_int>()
    else {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), output.cast::<u8>(), input.len());
        *output.add(input.len()) = 0;
    }
    rusqlite::ffi::SQLITE_OK
}

// SQLite may ask the VFS for an unnamed temporary file. This worker boundary
// has no outside-root scratch allowance, so refuse it rather than letting the
// Unix VFS choose a host temp directory.
unsafe extern "C" fn pinned_open(
    vfs: *mut rusqlite::ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    file: *mut rusqlite::ffi::sqlite3_file,
    flags: std::ffi::c_int,
    output_flags: *mut std::ffi::c_int,
) -> std::ffi::c_int {
    let mut validated = [0i8; 512];
    if unsafe {
        pinned_full_pathname(
            vfs,
            name,
            validated.len() as std::ffi::c_int,
            validated.as_mut_ptr(),
        )
    } != rusqlite::ffi::SQLITE_OK
    {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    }
    let original = unsafe { rusqlite::ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
    if original.is_null() {
        return rusqlite::ffi::SQLITE_CANTOPEN;
    }
    match unsafe { (*original).xOpen } {
        Some(open) => unsafe { open(vfs, name, file, flags, output_flags) },
        None => rusqlite::ffi::SQLITE_CANTOPEN,
    }
}

fn register_pinned_vfs() -> bool {
    static REGISTERED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *REGISTERED.get_or_init(|| unsafe {
        let name = c"diffuser-owned-root-v1";
        if !rusqlite::ffi::sqlite3_vfs_find(name.as_ptr()).is_null() {
            return false;
        }
        let original = rusqlite::ffi::sqlite3_vfs_find(c"unix".as_ptr());
        if original.is_null() {
            return false;
        }
        let mut vfs = Box::new(*original);
        vfs.pNext = std::ptr::null_mut();
        vfs.zName = name.as_ptr();
        vfs.xFullPathname = Some(pinned_full_pathname);
        vfs.xOpen = Some(pinned_open);
        let raw = Box::into_raw(vfs);
        if rusqlite::ffi::sqlite3_vfs_register(raw, 0) == rusqlite::ffi::SQLITE_OK {
            true
        } else {
            drop(Box::from_raw(raw));
            false
        }
    })
}

pub(super) fn open_pinned_database(
    root: &std::fs::File,
    name: &str,
    create: bool,
) -> Result<PinnedDb, &'static str> {
    use std::os::fd::AsRawFd;
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        || !register_pinned_vfs()
    {
        return Err("storage_unavailable");
    }
    let directory = root.try_clone().map_err(|_| "storage_unavailable")?;
    if !directory
        .metadata()
        .map_err(|_| "storage_unavailable")?
        .is_dir()
    {
        return Err("storage_unavailable");
    }
    let path = format!("/proc/self/fd/{}/{name}", directory.as_raw_fd());
    let mut flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
    if create {
        flags |= rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
    }
    let connection =
        rusqlite::Connection::open_with_flags_and_vfs(path, flags, "diffuser-owned-root-v1")
            .map_err(|_| "storage_unavailable")?;
    Ok(PinnedDb {
        connection,
        _directory: directory,
    })
}

impl ClaimStore {
    /// Called only for a validated, genuinely empty new controller root.
    pub(super) fn bootstrap_controller_identity(
        &mut self,
        store_id: &str,
        root_dev: u64,
        root_inode: u64,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        if store_id.len() != 64
            || !store_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || root_dev == 0
            || root_inode == 0
            || root_dev > i64::MAX as u64
            || root_inode > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_controller_identity (store_id TEXT PRIMARY KEY, root_dev INTEGER NOT NULL, root_inode INTEGER NOT NULL, writer_epoch INTEGER NOT NULL);").map_err(|_|"storage_unavailable")?;
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM la_controller_identity", [], |r| {
                r.get(0)
            })
            .map_err(|_| "storage_unavailable")?;
        if count != 0 {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO la_controller_identity VALUES (?1,?2,?3,1)",
            params![store_id, root_dev as i64, root_inode as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    /// Called inside a recovered service-custody operation. The capability
    /// authenticates the prior store incarnation and exact adjacent epoch.
    /// Claims, charges, mandates, fences and result rows are never rewritten.
    pub(super) fn recover_controller_identity(
        &mut self,
        recovery: &super::la_adapter::ControllerReadbackRecovery,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let epoch = recovery.binding().controller_epoch;
        if epoch < 2 || epoch > i64::MAX as u64 {
            return Err("evidence_invalid");
        }
        let changed=tx.execute("UPDATE la_controller_identity SET writer_epoch=?2 WHERE store_id=?1 AND writer_epoch=?3 AND root_dev=?4 AND root_inode=?5",
            params![recovery.store_id(),epoch as i64,(epoch-1) as i64,recovery.service().root_dev as i64,recovery.service().root_inode as i64]).map_err(|_|"storage_unavailable")?;
        if changed != 1 {
            return Err("evidence_invalid");
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_controller_recoveries(epoch INTEGER PRIMARY KEY,boot TEXT NOT NULL,handoff TEXT NOT NULL);").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_controller_recoveries VALUES (?1,?2,?3)",
            params![
                epoch as i64,
                recovery.binding().controller_boot,
                recovery.digest()?
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }

    /// Authenticate and consume the exact reservation receipt in the same
    /// transaction as the assignment transition. A duplicate is accepted only
    /// if its complete authenticated payload matches the durable receipt.
    pub(super) fn acknowledge_reservation_receipt(
        &mut self,
        key: &[u8; 32],
        expected_worker: &str,
        expected_boot: &str,
        expected_operation: &str,
        receipt: &super::la_adapter::WorkerReceipt,
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        let digest = super::la_adapter::verify_receipt(key, receipt, mac)?;
        if ![
            &receipt.worker,
            &receipt.boot,
            &receipt.operation,
            &receipt.assignment,
        ]
        .iter()
        .all(|v| valid_id(v))
            || receipt.worker != expected_worker
            || receipt.boot != expected_boot
            || receipt.operation != expected_operation
            || receipt.action != "reserved"
            || receipt.fence == 0
            || receipt.fence > i64::MAX as u64
            || receipt.sequence == 0
            || receipt.sequence > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM la_worker_receipts WHERE worker=?1 AND boot=?2 AND sequence=?3",
                params![receipt.worker, receipt.boot, receipt.sequence as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some(old) = old {
            return if old.as_slice() == digest {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        }
        let cursor: Option<(String, i64)> = tx
            .query_row(
                "SELECT boot,sequence FROM la_worker_cursor WHERE worker=?1",
                [&receipt.worker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        match cursor {
            None if receipt.sequence == 1 => (),
            Some((boot, seq))
                if boot == receipt.boot && seq.checked_add(1) == Some(receipt.sequence as i64) => {}
            _ => return Err("evidence_invalid"),
        }
        let terms: Option<(i64, i64)> = tx
            .query_row(
                "SELECT lease_until,hard_until FROM la_assignment_terms WHERE assignment_id=?1",
                [&receipt.assignment],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((lease, hard)) = terms {
            if u64::try_from(lease).ok() != Some(receipt.lease_until)
                || u64::try_from(hard).ok() != Some(receipt.hard_until)
                || checked_wall_since(0)? >= receipt.lease_until
            {
                return Err("evidence_invalid");
            }
        }
        let operation_matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM la_reservation_operations WHERE assignment_id=?1 AND operation=?2)", params![receipt.assignment,receipt.operation], |r| r.get(0)).map_err(|_| "storage_unavailable")?;
        if !operation_matches {
            return Err("evidence_invalid");
        }
        let changed = tx.execute(
            "UPDATE la_assignments SET state='assigned' WHERE id=?1 AND worker=?2 AND fence=?3 AND state='reserved'",
            params![receipt.assignment, receipt.worker, receipt.fence as i64]
        ).map_err(|_| "storage_unavailable")?;
        if changed != 1 {
            return Err("state_conflict");
        }
        tx.execute(
            "INSERT INTO la_worker_receipts VALUES (?1,?2,?3,?4)",
            params![
                receipt.worker,
                receipt.boot,
                receipt.sequence as i64,
                digest.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute("INSERT INTO la_worker_cursor VALUES (?1,?2,?3) ON CONFLICT(worker) DO UPDATE SET sequence=excluded.sequence",
            params![receipt.worker, receipt.boot, receipt.sequence as i64])
            .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_reservation_authorizations VALUES (?1,?2,?3,?4,?5)",
            params![
                receipt.assignment,
                receipt.worker,
                receipt.boot,
                receipt.fence as i64,
                receipt.operation
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "DELETE FROM la_outbox WHERE assignment_id=?1 AND action='reserve'",
            [&receipt.assignment],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct JobView {
    pub(super) id: String,
    pub(super) assignment: String,
    pub(super) input_artifact: String,
    pub(super) state: String,
    pub(super) revision: i64,
    pub(super) result_artifact: Option<String>,
}

impl ClaimStore {
    /// Atomically persists a pending job, immutable mandate, idempotency
    /// binding, inclusive grant charges and start outbox. This never starts a
    /// worker or grants a permit; a separately verified receipt is required.
    pub(super) fn create_pending_job(
        &mut self,
        draft: &super::la_auth::MandateDraft,
        input_artifact: &str,
        key: &str,
        fingerprint: &str,
    ) -> Result<String, &'static str> {
        self.create_pending_job_inner(draft, input_artifact, key, fingerprint, None, None, None)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Submission binds authority, idempotency and worker permit."
    )]
    pub(super) fn create_pending_job_authorized(
        &mut self,
        draft: &super::la_auth::MandateDraft,
        input_artifact: &str,
        key: &str,
        fingerprint: &str,
        deadline: (u64, std::time::Instant),
        command: &super::la_adapter::InspectCommand,
        client_job_id: &str,
    ) -> Result<String, &'static str> {
        self.create_pending_job_inner(
            draft,
            input_artifact,
            key,
            fingerprint,
            Some(deadline),
            Some(command),
            Some(client_job_id),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Job transaction binds mandate, request and permit fields."
    )]
    fn create_pending_job_inner(
        &mut self,
        draft: &super::la_auth::MandateDraft,
        input_artifact: &str,
        key: &str,
        fingerprint: &str,
        deadline: Option<(u64, std::time::Instant)>,
        command: Option<&super::la_adapter::InspectCommand>,
        client_job_id: Option<&str>,
    ) -> Result<String, &'static str> {
        use sha2::{Digest, Sha256};
        if !valid_id(input_artifact)
            || !valid_id(key)
            || client_job_id.is_some_and(|id| !valid_id(id))
            || fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("schema_invalid");
        }
        let mandate = checked_mandate(draft)?;
        let body = serde_json::to_string(&mandate).map_err(|_| "storage_unavailable")?;
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        if let Some((wall, mono)) = deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|v| u64::try_from(v.as_millis()).ok())
                .ok_or("clock_untrusted")?;
            if now >= wall || std::time::Instant::now() >= mono {
                return Err("evidence_stale");
            }
        }
        let old: Option<(String,String)> = tx.query_row(
            "SELECT fingerprint,job FROM la_job_idempotency WHERE project=?1 AND actor=?2 AND idem_key=?3",
            params![draft.project,draft.actor,key], |r| Ok((r.get(0)?,r.get(1)?))
        ).optional().map_err(|_| "storage_unavailable")?;
        if let Some((old_fingerprint, job)) = old {
            if deadline.is_some() {
                let charges: Vec<String> = {
                    let mut statement=tx.prepare("SELECT grant_id FROM la_job_grant_charges WHERE job=?1 ORDER BY grant_id").map_err(|_|"storage_unavailable")?;
                    let values = statement
                        .query_map([&job], |r| r.get(0))
                        .map_err(|_| "storage_unavailable")?
                        .collect::<Result<_, _>>()
                        .map_err(|_| "storage_unavailable")?;
                    values
                };
                let mut expected: Vec<_> = draft.chain.iter().map(|g| g.id.clone()).collect();
                expected.sort();
                if charges != expected {
                    return Err("delegation_denied");
                }
            }
            return if old_fingerprint == fingerprint {
                Ok(job)
            } else {
                Err("idempotency_conflict")
            };
        }
        if let Some(client_id) = client_job_id {
            let old:Option<(String,String)>=tx.query_row("SELECT fingerprint,job FROM la_client_jobs WHERE project=?1 AND actor=?2 AND client_job_id=?3",params![draft.project,draft.actor,client_id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|"storage_unavailable")?;
            if let Some((old_fingerprint, job)) = old {
                if old_fingerprint != fingerprint {
                    return Err("idempotency_conflict");
                }
                let charges: Vec<String> = {
                    let mut statement=tx.prepare("SELECT grant_id FROM la_job_grant_charges WHERE job=?1 ORDER BY grant_id").map_err(|_|"storage_unavailable")?;
                    let values = statement
                        .query_map([&job], |r| r.get(0))
                        .map_err(|_| "storage_unavailable")?
                        .collect::<Result<_, _>>()
                        .map_err(|_| "storage_unavailable")?;
                    values
                };
                let mut expected: Vec<_> = draft.chain.iter().map(|g| g.id.clone()).collect();
                expected.sort();
                if charges != expected {
                    return Err("delegation_denied");
                }
                tx.execute(
                    "INSERT INTO la_job_idempotency VALUES (?1,?2,?3,?4,?5)",
                    params![draft.project, draft.actor, key, fingerprint, job],
                )
                .map_err(|_| "storage_unavailable")?;
                if let Some((wall, mono)) = deadline {
                    if checked_wall_since(draft.accepted_at)? >= wall
                        || std::time::Instant::now() >= mono
                    {
                        return Err("evidence_stale");
                    }
                }
                tx.commit().map_err(|_| "storage_unavailable")?;
                return Ok(job);
            }
        }
        let assigned: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM la_assignments a JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.worker=a.worker AND r.fence=a.fence WHERE a.id=?1 AND a.project=?2 AND a.actor=?3 AND a.worker=?4 AND a.state='assigned')",
            params![draft.assignment,draft.project,draft.actor,draft.worker], |r| r.get(0)
        ).map_err(|_| "storage_unavailable")?;
        if !assigned {
            return Err("state_conflict");
        }
        if deadline.is_some() {
            let terms: Option<(i64,i64,i64,i64,i64)> = tx.query_row("SELECT cpu,memory,storage,lease_until,hard_until FROM la_assignment_terms WHERE assignment_id=?1", [&draft.assignment], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|_| "storage_unavailable")?;
            let (cpu, memory, storage, lease, hard) = terms.ok_or("evidence_invalid")?;
            let command = command.ok_or("evidence_invalid")?;
            let worker_binding: Option<(String,i64)> = tx.query_row("SELECT boot,fence FROM la_reservation_authorizations WHERE assignment_id=?1 AND worker=?2",params![draft.assignment,draft.worker],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_| "storage_unavailable")?;
            let (boot, fence) = worker_binding.ok_or("evidence_invalid")?;
            if command.worker != draft.worker
                || command.boot != boot
                || u64::try_from(fence).ok() != Some(command.fence)
                || command.assignment != draft.assignment
                || command.job != draft.job
                || command.operation != draft.operation
                || command.input_digest != draft.input_digest
                || draft.profile != super::la_backend::Capability::mandate_profile(command.backend)
                || command.accepted_at != draft.accepted_at
                || command.mandate_until != mandate.max_until
                || command.permit_until <= draft.accepted_at
                || command.permit_until > mandate.max_until
                || command.permit_until > u64::try_from(lease).map_err(|_| "evidence_invalid")?
                || command.permit_until > deadline.ok_or("evidence_invalid")?.0
                || command.permit_until
                    > draft
                        .accepted_at
                        .checked_add(2_000)
                        .ok_or("deadline_elapsed")?
            {
                return Err("evidence_invalid");
            }
            if u64::try_from(cpu).ok() != Some(draft.cpu_millicores)
                || u64::try_from(memory).ok() != Some(draft.memory_bytes)
                || u64::try_from(storage).ok() != Some(draft.storage_bytes)
                || u64::try_from(hard).ok() != Some(draft.assignment_hard)
                || u64::try_from(lease)
                    .ok()
                    .is_none_or(|v| draft.accepted_at >= v)
            {
                return Err("evidence_invalid");
            }
            let mut statement = tx.prepare("SELECT grant_id FROM la_assignment_grant_charges WHERE assignment_id=?1 ORDER BY grant_id").map_err(|_| "storage_unavailable")?;
            let charges = statement
                .query_map([&draft.assignment], |r| r.get::<_, String>(0))
                .map_err(|_| "storage_unavailable")?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "storage_unavailable")?;
            let mut expected: Vec<_> = draft.chain.iter().map(|g| g.id.clone()).collect();
            expected.sort();
            if charges != expected {
                return Err("delegation_denied");
            }
        }
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM la_jobs", [], |r| r.get(0))
            .map_err(|_| "storage_unavailable")?;
        if count >= 32 {
            return Err("capacity_unavailable");
        }
        let busy: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM la_jobs WHERE assignment_id=?1 AND state IN ('pending','running','stopping'))", [&draft.assignment], |r| r.get(0))
            .map_err(|_| "storage_unavailable")?;
        if busy {
            return Err("capacity_unavailable");
        }
        tx.execute(
            "INSERT INTO la_jobs VALUES (?1,?2,?3,?4,?5,'pending',0,NULL)",
            params![
                draft.job,
                draft.assignment,
                draft.project,
                draft.actor,
                input_artifact
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_mandates VALUES (?1,?2,?3)",
            params![draft.job, body, digest],
        )
        .map_err(|_| "storage_unavailable")?;
        if let Some(command) = command {
            let encoded = serde_json::to_string(command).map_err(|_| "storage_unavailable")?;
            let digest = hex::encode(Sha256::digest(encoded.as_bytes()));
            tx.execute(
                "INSERT INTO la_job_permit_intents VALUES (?1,?2,?3,?4,0)",
                params![draft.job, encoded, digest, command.permit_until as i64],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        for grant in &draft.chain {
            tx.execute(
                "INSERT INTO la_job_grant_charges VALUES (?1,?2)",
                params![draft.job, grant.id],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        tx.execute(
            "INSERT INTO la_job_outbox VALUES (?1,?2,'start')",
            params![draft.job, draft.operation],
        )
        .map_err(|_| "storage_unavailable")?;
        if let Some(client_id) = client_job_id {
            tx.execute(
                "INSERT INTO la_client_jobs VALUES (?1,?2,?3,?4,?5)",
                params![
                    draft.project,
                    draft.actor,
                    client_id,
                    fingerprint,
                    draft.job
                ],
            )
            .map_err(|_| "storage_unavailable")?;
        }
        tx.execute(
            "INSERT INTO la_job_idempotency VALUES (?1,?2,?3,?4,?5)",
            params![draft.project, draft.actor, key, fingerprint, draft.job],
        )
        .map_err(|_| "storage_unavailable")?;
        if let Some((wall, mono)) = deadline {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|v| u64::try_from(v.as_millis()).ok())
                .ok_or("clock_untrusted")?;
            if now >= wall || std::time::Instant::now() >= mono {
                return Err("evidence_stale");
            }
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(draft.job.clone())
    }

    pub(super) fn job_view(
        &self,
        project: &str,
        actor: &str,
        id: &str,
    ) -> Result<JobView, &'static str> {
        let _guard = self.guard()?;
        self.db.query_row("SELECT id,assignment_id,input_artifact,state,revision,result_artifact FROM la_jobs WHERE project=?1 AND actor=?2 AND id=?3",
            params![project,actor,id], |r| Ok(JobView { id:r.get(0)?, assignment:r.get(1)?, input_artifact:r.get(2)?, state:r.get(3)?, revision:r.get(4)?, result_artifact:r.get(5)? }))
            .optional().map_err(|_| "storage_unavailable")?.ok_or("object_not_found")
    }
}

impl ClaimStore {
    /// Record a stop intent without releasing capacity. The worker must
    /// acknowledge stop before any reservation or charge can be released.
    pub(super) fn request_job_stop(
        &mut self,
        project: &str,
        actor: &str,
        job: &str,
        key: &str,
        revision: u64,
    ) -> Result<(), &'static str> {
        if ![project, actor, job, key].iter().all(|v| valid_id(v)) || revision > i64::MAX as u64 {
            return Err("schema_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<(String,i64)> = tx.query_row(
            "SELECT job,expected_revision FROM la_job_cancel_keys WHERE project=?1 AND actor=?2 AND idem_key=?3",
            params![project,actor,key], |r| Ok((r.get(0)?,r.get(1)?))
        ).optional().map_err(|_| "storage_unavailable")?;
        if let Some((old_job, old_revision)) = old {
            return if old_job == job && old_revision == revision as i64 {
                Ok(())
            } else {
                Err("idempotency_conflict")
            };
        }
        let row: Option<(String, i64)> = tx
            .query_row(
                "SELECT state,revision FROM la_jobs WHERE project=?1 AND actor=?2 AND id=?3",
                params![project, actor, job],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        let (state, current) = row.ok_or("object_not_found")?;
        if current != revision as i64 {
            return Err("state_conflict");
        }
        if matches!(
            state.as_str(),
            "finalizing" | "succeeded" | "cancelled" | "failed"
        ) {
            tx.execute(
                "INSERT INTO la_job_cancel_keys VALUES (?1,?2,?3,?4,?5)",
                params![project, actor, key, job, revision as i64],
            )
            .map_err(|_| "storage_unavailable")?;
            return tx.commit().map_err(|_| "storage_unavailable");
        }
        if !matches!(state.as_str(), "pending" | "running") {
            return Err("state_conflict");
        }
        let next = current.checked_add(1).ok_or("storage_unavailable")?;
        tx.execute(
            "UPDATE la_jobs SET state='stopping', revision=?2 WHERE id=?1",
            params![job, next],
        )
        .map_err(|_| "storage_unavailable")?;
        let changed = tx
            .execute("UPDATE la_job_outbox SET action='stop' WHERE job=?1", [job])
            .map_err(|_| "storage_unavailable")?;
        if changed != 1 {
            return Err("storage_unavailable");
        }
        tx.execute(
            "INSERT INTO la_job_cancel_keys VALUES (?1,?2,?3,?4,?5)",
            params![project, actor, key, job, revision as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    /// Read back the exact immutable permit intent. It confers no start right
    /// until its worker acknowledgement has been authenticated and committed.
    pub(super) fn job_permit_command(
        &self,
        job: &str,
    ) -> Result<super::la_adapter::InspectCommand, &'static str> {
        use sha2::{Digest, Sha256};
        let _guard = self.guard()?;
        let (body, digest): (String, String) = self
            .db
            .query_row(
                "SELECT command,digest FROM la_job_permit_intents WHERE job=?1",
                [job],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?
            .ok_or("object_not_found")?;
        if hex::encode(Sha256::digest(body.as_bytes())) != digest {
            return Err("evidence_invalid");
        }
        serde_json::from_str(&body).map_err(|_| "evidence_invalid")
    }

    /// Consume only the authenticated exact worker permit receipt and its next
    /// sequence. A closed job or late ACK cannot establish start authority.
    pub(super) fn acknowledge_job_permit(
        &mut self,
        key: &[u8; 32],
        receipt: &super::la_adapter::PermitReceipt,
        mac: &[u8; 32],
        now: u64,
    ) -> Result<(), &'static str> {
        let digest = super::la_adapter::verify_permit_receipt(key, receipt, mac)?;
        if receipt.sequence == 0
            || receipt.sequence > i64::MAX as u64
            || receipt.fence == 0
            || receipt.fence > i64::MAX as u64
            || now > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let row: Option<(String,i64,bool,String,String,i64,String)> = tx.query_row(
            "SELECT p.digest,p.permit_until,p.acknowledged,j.state,a.worker,a.fence,r.boot FROM la_job_permit_intents p JOIN la_jobs j ON j.id=p.job JOIN la_assignments a ON a.id=j.assignment_id JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.fence=a.fence AND r.worker=a.worker JOIN la_job_outbox o ON o.job=j.id WHERE p.job=?1 AND j.assignment_id=?2 AND o.operation=?3",
            params![receipt.job,receipt.assignment,receipt.operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))
        ).optional().map_err(|_|"storage_unavailable")?;
        let (command_digest, until, ack, state, worker, fence, boot) =
            row.ok_or("evidence_invalid")?;
        if command_digest != receipt.command_digest
            || u64::try_from(until).ok() != Some(receipt.permit_until)
            || worker != receipt.worker
            || boot != receipt.boot
            || u64::try_from(fence).ok() != Some(receipt.fence)
        {
            return Err("evidence_invalid");
        }
        let prior: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM la_worker_receipts WHERE worker=?1 AND boot=?2 AND sequence=?3",
                params![receipt.worker, receipt.boot, receipt.sequence as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some(prior) = prior {
            return if prior.as_slice() == digest && ack {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        }
        if state != "pending" || checked_wall_since(now)? >= receipt.permit_until {
            return Err("deadline_elapsed");
        }
        let cursor: Option<(String, i64)> = tx
            .query_row(
                "SELECT boot,sequence FROM la_worker_cursor WHERE worker=?1",
                [&receipt.worker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if !matches!(cursor,Some((ref boot,last)) if boot==&receipt.boot && last.checked_add(1)==Some(receipt.sequence as i64))
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO la_worker_receipts VALUES (?1,?2,?3,?4)",
            params![
                receipt.worker,
                receipt.boot,
                receipt.sequence as i64,
                digest.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_worker_cursor SET sequence=?2 WHERE worker=?1",
            params![receipt.worker, receipt.sequence as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_job_permit_intents SET acknowledged=1 WHERE job=?1",
            [&receipt.job],
        )
        .map_err(|_| "storage_unavailable")?;
        if checked_wall_since(now)? >= receipt.permit_until {
            return Err("deadline_elapsed");
        }
        tx.commit().map_err(|_| "storage_unavailable")
    }

    /// The close-vs-send CAS: a committed stop wins over dispatch. After this
    /// transition a crash is uncertain and cannot authorize a second start.
    pub(super) fn claim_job_start(&mut self, job: &str, now: u64) -> Result<(), &'static str> {
        if now > i64::MAX as u64 {
            return Err("clock_untrusted");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let changed = tx.execute("UPDATE la_jobs SET state='running',revision=revision+1 WHERE id=?1 AND state='pending' AND EXISTS (SELECT 1 FROM la_job_permit_intents p WHERE p.job=la_jobs.id AND p.acknowledged=1 AND p.permit_until>?2) AND EXISTS (SELECT 1 FROM la_job_outbox o WHERE o.job=la_jobs.id AND o.action='start') AND EXISTS (SELECT 1 FROM la_assignments a WHERE a.id=la_jobs.assignment_id AND a.state='assigned')",params![job,now as i64]).map_err(|_|"storage_unavailable")?;
        if changed != 1 {
            return Err("state_conflict");
        }
        tx.execute(
            "UPDATE la_job_outbox SET action='sent' WHERE job=?1 AND action='start'",
            [job],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    /// Verify the worker terminal receipt and report against the immutable
    /// mandate, and commit finalizing before artifact publication.
    #[expect(
        clippy::too_many_arguments,
        reason = "Result verification binds each independently authenticated field."
    )]
    pub(super) fn record_job_result(
        &mut self,
        key: &[u8; 32],
        receipt: &super::la_adapter::ResultReceipt,
        mac: &[u8; 32],
        report: &[u8],
        input_bytes: usize,
        output_id: &str,
        now: u64,
    ) -> Result<(), &'static str> {
        use sha2::{Digest, Sha256};
        let receipt_digest = super::la_adapter::verify_result_receipt(key, receipt, mac)?;
        if !valid_id(output_id)
            || report.len() > 4096
            || receipt.report_bytes != report.len() as u64
            || receipt.report_digest != hex::encode(Sha256::digest(report))
            || receipt.sequence == 0
            || receipt.sequence > i64::MAX as u64
            || receipt.fence == 0
            || receipt.fence > i64::MAX as u64
            || now > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let normalized =
            super::la_contract::canonical_json(report).map_err(|_| "evidence_invalid")?;
        let _guard = self.guard()?;
        let mandate = self.load_mandate_unlocked(&receipt.job)?;
        if now >= mandate.max_until {
            return Err("evidence_invalid");
        }
        if let Some(backend) =
            super::la_backend::Capability::from_mandate_profile(&mandate.draft.profile)?
        {
            super::la_backend::validate_report(
                &normalized,
                &receipt.job,
                &mandate.draft.input_digest,
                Some(input_bytes),
                Some(backend),
            )?;
        } else {
            let parsed: serde_json::Value =
                serde_json::from_slice(&normalized).map_err(|_| "evidence_invalid")?;
            if !parsed.as_object().is_some_and(|object| object.len() == 7)
                || parsed["schema_version"] != "diffuser-artifact/v1"
                || parsed["job_id"] != receipt.job
                || parsed["sha256"] != mandate.draft.input_digest
                || parsed["capability"] != "artifact.inspect.sha256/v1"
                || parsed["profile_id"] != "cpu-artifact-inspect/v1"
                || parsed["profile_version"] != "1"
                || input_bytes > 1_048_576
                || parsed["bytes"].as_u64() != Some(input_bytes as u64)
            {
                return Err("evidence_invalid");
            }
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let row:Option<(String,String,i64,String,String)> = tx.query_row("SELECT j.state,a.worker,a.fence,r.boot,o.action FROM la_jobs j JOIN la_assignments a ON a.id=j.assignment_id JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.worker=a.worker AND r.fence=a.fence JOIN la_job_outbox o ON o.job=j.id WHERE j.id=?1 AND j.assignment_id=?2 AND o.operation=?3",params![receipt.job,receipt.assignment,receipt.operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|_|"storage_unavailable")?;
        let (state, worker, fence, boot, action) = row.ok_or("evidence_invalid")?;
        if worker != receipt.worker
            || boot != receipt.boot
            || u64::try_from(fence).ok() != Some(receipt.fence)
        {
            return Err("evidence_invalid");
        }
        let previous: Option<(String, String, Vec<u8>)> = tx
            .query_row(
                "SELECT output_id,report_digest,receipt_digest FROM la_job_results WHERE job=?1",
                [&receipt.job],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old_output, old_report, old_receipt)) = previous {
            return if old_output == output_id
                && old_report == receipt.report_digest
                && old_receipt.as_slice() == receipt_digest
            {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        }
        if !((state == "running" && action == "sent") || (state == "stopping" && action == "stop"))
        {
            return Err("state_conflict");
        }
        let permit = effective_job_permit_until(&tx, &receipt.job)?;
        if checked_wall_since(now)? >= u64::try_from(permit).map_err(|_| "evidence_invalid")? {
            return Err("deadline_elapsed");
        }
        let cursor: Option<(String, i64)> = tx
            .query_row(
                "SELECT boot,sequence FROM la_worker_cursor WHERE worker=?1",
                [&receipt.worker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if !matches!(cursor,Some((ref boot,last)) if boot==&receipt.boot && last.checked_add(1)==Some(receipt.sequence as i64))
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO la_worker_receipts VALUES (?1,?2,?3,?4)",
            params![
                receipt.worker,
                receipt.boot,
                receipt.sequence as i64,
                receipt_digest.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_worker_cursor SET sequence=?2 WHERE worker=?1",
            params![receipt.worker, receipt.sequence as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_job_results VALUES (?1,?2,?3,?4)",
            params![
                receipt.job,
                output_id,
                receipt.report_digest,
                receipt_digest.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute("UPDATE la_jobs SET state='finalizing',revision=revision+1 WHERE id=?1 AND state IN ('running','stopping')",[&receipt.job]).map_err(|_|"storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }

    /// Called after immutable output publication and a scoped integrity read.
    pub(super) fn publish_job_result(
        &mut self,
        job: &str,
        output: &str,
        digest: &str,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let changed=tx.execute("UPDATE la_jobs SET state='succeeded',revision=revision+1,result_artifact=?2 WHERE id=?1 AND state='finalizing' AND EXISTS (SELECT 1 FROM la_job_results r WHERE r.job=la_jobs.id AND r.output_id=?2 AND r.report_digest=?3)",params![job,output,digest]).map_err(|_|"storage_unavailable")?;
        if changed != 1 {
            return Err("state_conflict");
        }
        tx.execute(
            "UPDATE la_job_outbox SET action='complete' WHERE job=?1",
            [job],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    pub(super) fn assignment_revision(
        &self,
        project: &str,
        actor: &str,
        assignment: &str,
    ) -> Result<i64, &'static str> {
        let _guard = self.guard()?;
        self.db.query_row("SELECT r.revision FROM la_assignment_revisions r JOIN la_assignments a ON a.id=r.assignment_id WHERE a.project=?1 AND a.actor=?2 AND a.id=?3",params![project,actor,assignment],|r|r.get(0)).optional().map_err(|_|"storage_unavailable")?.ok_or("object_not_found")
    }

    /// Commit the assignment close barrier and all dependent job stop intents
    /// together. Capacity and charges remain held until separately proved safe.
    pub(super) fn request_assignment_release(
        &mut self,
        project: &str,
        actor: &str,
        assignment: &str,
        key: &str,
        revision: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        if ![project, actor, assignment, key]
            .iter()
            .all(|v| valid_id(v))
            || revision > i64::MAX as u64
            || now > i64::MAX as u64
        {
            return Err("schema_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old:Option<(String,i64)>=tx.query_row("SELECT assignment_id,expected_revision FROM la_assignment_release_keys WHERE project=?1 AND actor=?2 AND idem_key=?3",params![project,actor,key],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|"storage_unavailable")?;
        if let Some((old_id, old_revision)) = old {
            return if old_id == assignment && old_revision == revision as i64 {
                Ok(())
            } else {
                Err("idempotency_conflict")
            };
        }
        let row:Option<(String,i64)>=tx.query_row("SELECT a.state,r.revision FROM la_assignments a JOIN la_assignment_revisions r ON r.assignment_id=a.id WHERE a.project=?1 AND a.actor=?2 AND a.id=?3",params![project,actor,assignment],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|"storage_unavailable")?;
        let (state, current) = row.ok_or("object_not_found")?;
        if current != revision as i64 || !matches!(state.as_str(), "reserved" | "assigned") {
            return Err("state_conflict");
        }
        let next = current.checked_add(1).ok_or("storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_close_intents VALUES (?1,'released',?2,?3)",
            params![assignment, now as i64, format!("release_{assignment}")],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_assignments SET state='draining' WHERE id=?1",
            [assignment],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_assignment_revisions SET revision=?2 WHERE assignment_id=?1",
            params![assignment, next],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_outbox VALUES (?1,'stop') ON CONFLICT(assignment_id) DO UPDATE SET action='stop'",
            [assignment],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute("UPDATE la_job_outbox SET action='stop' WHERE job IN (SELECT id FROM la_jobs WHERE assignment_id=?1 AND state IN ('pending','running'))",[assignment]).map_err(|_|"storage_unavailable")?;
        tx.execute("UPDATE la_jobs SET state='stopping',revision=revision+1 WHERE assignment_id=?1 AND state IN ('pending','running')",[assignment]).map_err(|_|"storage_unavailable")?;
        tx.execute("UPDATE la_permits SET closed=1,pending_revision=NULL,pending_until=NULL WHERE job IN (SELECT id FROM la_jobs WHERE assignment_id=?1)",[assignment]).map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_assignment_release_keys VALUES (?1,?2,?3,?4,?5)",
            params![project, actor, key, assignment, revision as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    /// Record the requested lease separately from the last acknowledged
    /// lease. A retry retrieves the same command, never a fresh extension.
    #[expect(
        clippy::too_many_arguments,
        reason = "Renewal binds scoped authority, exact command and expiry."
    )]
    pub(super) fn request_assignment_renewal(
        &mut self,
        project: &str,
        actor: &str,
        key: &str,
        requested_ms: u64,
        command: &super::la_adapter::RenewCommand,
        lineage: &[String],
        deadline: (u64, std::time::Instant),
        now: u64,
    ) -> Result<super::la_adapter::RenewCommand, &'static str> {
        if ![project, actor, key, &command.assignment, &command.operation]
            .iter()
            .all(|v| valid_id(v))
            || requested_ms == 0
            || [
                requested_ms,
                command.revision,
                command.fence,
                command.previous_until,
                command.requested_until,
                now,
            ]
            .iter()
            .any(|v| *v > i64::MAX as u64)
            || command.revision == 0
            || command.fence == 0
        {
            return Err("schema_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let observed = checked_wall_since(now)?;
        if observed >= deadline.0 || std::time::Instant::now() >= deadline.1 {
            return Err("evidence_stale");
        }
        let owned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM la_assignments WHERE id=?1 AND project=?2 AND actor=?3)",params![command.assignment,project,actor],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if !owned {
            return Err("object_not_found");
        }
        let mut statement = tx.prepare("SELECT grant_id FROM la_assignment_grant_charges WHERE assignment_id=?1 ORDER BY grant_id").map_err(|_|"storage_unavailable")?;
        let charges = statement
            .query_map([&command.assignment], |r| r.get::<_, String>(0))
            .map_err(|_| "storage_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "storage_unavailable")?;
        let mut expected = lineage.to_vec();
        expected.sort();
        if expected.is_empty() || expected.len() > 3 || charges != expected {
            return Err("delegation_denied");
        }
        drop(statement);
        let old:Option<(String,i64,i64,String)>=tx.query_row("SELECT assignment_id,expected_revision,requested_ms,command FROM la_assignment_renewals WHERE project=?1 AND actor=?2 AND idem_key=?3",params![project,actor,key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|_|"storage_unavailable")?;
        if let Some((id, revision, old_ms, body)) = old {
            return if id == command.assignment
                && revision.checked_add(1) == Some(command.revision as i64)
                && old_ms == requested_ms as i64
            {
                serde_json::from_str(&body).map_err(|_| "evidence_invalid")
            } else {
                Err("idempotency_conflict")
            };
        }
        let binding:Option<(String,i64,String,String,i64,i64,i64)>=tx.query_row("SELECT a.state,r.revision,a.worker,b.boot,a.fence,t.lease_until,t.hard_until FROM la_assignments a JOIN la_assignment_revisions r ON r.assignment_id=a.id JOIN la_assignment_terms t ON t.assignment_id=a.id JOIN la_reservation_authorizations b ON b.assignment_id=a.id AND b.worker=a.worker AND b.fence=a.fence WHERE a.id=?1 AND a.project=?2 AND a.actor=?3",params![command.assignment,project,actor],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(|_|"storage_unavailable")?;
        let (state, revision, worker, boot, fence, lease, hard) =
            binding.ok_or("object_not_found")?;
        if state != "assigned"
            || revision.checked_add(1) != Some(command.revision as i64)
            || worker != command.worker
            || boot != command.boot
            || u64::try_from(fence).ok() != Some(command.fence)
            || u64::try_from(lease).ok() != Some(command.previous_until)
            || command.previous_until <= observed
            || command.requested_until <= command.previous_until
            || u64::try_from(hard)
                .ok()
                .is_none_or(|v| command.requested_until > v)
        {
            return Err("state_conflict");
        }
        let busy:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM la_assignment_renewals WHERE assignment_id=?1 AND acknowledged=0)",[&command.assignment],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if busy {
            return Err("state_conflict");
        }
        let body = serde_json::to_string(command).map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_assignment_renewals VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0)",
            params![
                project,
                actor,
                key,
                command.assignment,
                revision,
                requested_ms as i64,
                command.operation,
                body
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute("INSERT INTO la_outbox VALUES (?1,'renew') ON CONFLICT(assignment_id) DO UPDATE SET action='renew'",[&command.assignment]).map_err(|_|"storage_unavailable")?;
        if checked_wall_since(now)? >= deadline.0 || std::time::Instant::now() >= deadline.1 {
            return Err("evidence_stale");
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(command.clone())
    }

    /// Advance the service lease only after the exact authenticated worker ACK,
    /// before the previous safe lease expires and while the assignment is open.
    pub(super) fn acknowledge_assignment_renewal(
        &mut self,
        key: &[u8; 32],
        receipt: &super::la_adapter::RenewReceipt,
        mac: &[u8; 32],
        now: u64,
    ) -> Result<(), &'static str> {
        let digest = super::la_adapter::verify_renew_receipt(key, receipt, mac)?;
        if receipt.sequence == 0
            || receipt.sequence > i64::MAX as u64
            || receipt.revision == 0
            || receipt.revision > i64::MAX as u64
            || receipt.fence == 0
            || receipt.fence > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let row:Option<RenewalAckRow>=tx.query_row("SELECT n.command,n.acknowledged,a.state,r.revision,t.lease_until,a.worker,b.boot,a.fence FROM la_assignment_renewals n JOIN la_assignments a ON a.id=n.assignment_id JOIN la_assignment_revisions r ON r.assignment_id=a.id JOIN la_assignment_terms t ON t.assignment_id=a.id JOIN la_reservation_authorizations b ON b.assignment_id=a.id WHERE n.operation=?1 AND n.assignment_id=?2",params![receipt.operation,receipt.assignment],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(|_|"storage_unavailable")?;
        let (body, ack, state, revision, lease, worker, boot, fence) =
            row.ok_or("evidence_invalid")?;
        let cmd: super::la_adapter::RenewCommand =
            serde_json::from_str(&body).map_err(|_| "evidence_invalid")?;
        if cmd.worker != receipt.worker
            || cmd.boot != receipt.boot
            || cmd.fence != receipt.fence
            || cmd.operation != receipt.operation
            || cmd.assignment != receipt.assignment
            || cmd.revision != receipt.revision
            || cmd.previous_until != receipt.previous_until
            || cmd.requested_until != receipt.acknowledged_until
            || worker != receipt.worker
            || boot != receipt.boot
            || u64::try_from(fence).ok() != Some(receipt.fence)
        {
            return Err("evidence_invalid");
        }
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM la_worker_receipts WHERE worker=?1 AND boot=?2 AND sequence=?3",
                params![receipt.worker, receipt.boot, receipt.sequence as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some(old) = old {
            return if ack && old.as_slice() == digest {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        }
        if state != "assigned"
            || revision.checked_add(1) != Some(receipt.revision as i64)
            || u64::try_from(lease).ok() != Some(receipt.previous_until)
            || checked_wall_since(now)? >= receipt.previous_until
        {
            return Err("deadline_elapsed");
        }
        let cursor: Option<(String, i64)> = tx
            .query_row(
                "SELECT boot,sequence FROM la_worker_cursor WHERE worker=?1",
                [&receipt.worker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if !matches!(cursor,Some((ref boot,last)) if boot==&receipt.boot && last.checked_add(1)==Some(receipt.sequence as i64))
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO la_worker_receipts VALUES (?1,?2,?3,?4)",
            params![
                receipt.worker,
                receipt.boot,
                receipt.sequence as i64,
                digest.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_worker_cursor SET sequence=?2 WHERE worker=?1",
            params![receipt.worker, receipt.sequence as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_assignment_terms SET lease_until=?2 WHERE assignment_id=?1",
            params![receipt.assignment, receipt.acknowledged_until as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_assignment_revisions SET revision=?2 WHERE assignment_id=?1",
            params![receipt.assignment, receipt.revision as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_assignment_renewals SET acknowledged=1 WHERE operation=?1",
            [&receipt.operation],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "DELETE FROM la_outbox WHERE assignment_id=?1 AND action='renew'",
            [&receipt.assignment],
        )
        .map_err(|_| "storage_unavailable")?;
        if checked_wall_since(now)? >= receipt.previous_until {
            return Err("deadline_elapsed");
        }
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    /// Append an authenticated observation without allowing sequence gaps,
    /// rollback, or replacement. Key custody and upstream identity are external.
    pub(super) fn append_authority_observation(
        &mut self,
        key: &[u8; 32],
        bytes: &[u8],
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        self.append_authority_observation_inner(key, bytes, mac, None, None)
    }
    fn append_authority_observation_inner(
        &mut self,
        key: &[u8; 32],
        bytes: &[u8],
        mac: &[u8; 32],
        loss: Option<(
            &super::la_adapter::WorkerLossSource,
            &super::la_adapter::ChannelKeys,
        )>,
        bridge: Option<(
            &super::la_adapter::ChannelBinding,
            &super::la_adapter::ChannelKeys,
        )>,
    ) -> Result<(), &'static str> {
        if self.has_loss_source()? {
            let (binding, keys) = bridge.ok_or("evidence_invalid")?;
            super::la_adapter::verify_controller_loss_source_bridge(&self.root, binding, keys)?;
        } else if bridge.is_some() {
            return Err("evidence_invalid");
        }

        let canonical =
            super::la_contract::canonical_json(bytes).map_err(|_| "evidence_invalid")?;
        super::la_adapter::verify_authority_observation(key, &canonical, mac)?;
        let value: serde_json::Value =
            serde_json::from_slice(&canonical).map_err(|_| "evidence_invalid")?;
        let sequence = value
            .get("sequence")
            .and_then(|v| v.as_u64())
            .filter(|v| *v > 0 && *v <= i64::MAX as u64)
            .ok_or("evidence_invalid")?;
        let observed = value
            .get("observed_at")
            .and_then(|v| v.as_u64())
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or("evidence_invalid")?;
        if value.get("schema_version").and_then(|v| v.as_str())
            != Some("diffuser-authority-observation/v1")
            || value.get("revoked").and_then(|v| v.as_array()).is_none()
        {
            return Err("evidence_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let (count,last_seq,last_time):(i64,i64,i64)=tx.query_row("SELECT COUNT(*),COALESCE(MAX(sequence),0),COALESCE(MAX(observed_at),0) FROM la_authority_observations",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|_|"storage_unavailable")?;
        if count >= 128
            || last_seq.checked_add(1) != Some(sequence as i64)
            || observed < last_time as u64
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO la_authority_observations VALUES (?1,?2,?3,?4)",
            params![sequence as i64, observed as i64, canonical, mac.as_slice()],
        )
        .map_err(|_| "storage_unavailable")?;
        // A revocation cannot become visible while an affected assignment
        // still admits starts. The append, close barriers and stop outboxes
        // share this transaction; grants remain charged until verified cleanup.
        for revoked in value["revoked"].as_array().ok_or("evidence_invalid")? {
            let grant = revoked
                .as_str()
                .filter(|s| valid_id(s))
                .ok_or("evidence_invalid")?;
            let affected = {
                let mut statement=tx.prepare("SELECT a.id FROM la_assignments a JOIN la_assignment_grant_charges c ON c.assignment_id=a.id WHERE c.grant_id=?1 AND a.state IN ('reserved','assigned') ORDER BY a.id").map_err(|_| "storage_unavailable")?;
                let rows = statement
                    .query_map([grant], |r| r.get::<_, String>(0))
                    .map_err(|_| "storage_unavailable")?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| "storage_unavailable")?;
                rows
            };
            for assignment in affected {
                close_assignment_transaction(&tx, &assignment, "revoked", observed)?;
            }
        }
        if let Some((cap, keys)) = loss {
            tx.execute_batch("CREATE TABLE la_worker_loss_sources(sequence INTEGER PRIMARY KEY,job TEXT UNIQUE NOT NULL REFERENCES la_jobs(id),body BLOB NOT NULL)").map_err(|_| "storage_unavailable")?;
            tx.execute(
                "INSERT INTO la_worker_loss_sources VALUES(?1,?2,?3)",
                params![
                    sequence as i64,
                    cap.job,
                    serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?
                ],
            )
            .map_err(|_| "evidence_invalid")?;
            cap.verify(keys, checked_wall_since(cap.issued_at)?)?;
        }
        tx.commit().map_err(|_| "storage_unavailable")
    }

    /// The expected sequence must be supplied by independent protected custody;
    /// a database's own maximum cannot establish that it was not rolled back.
    pub(super) fn authority_observations(
        &self,
        key: &[u8; 32],
        expected_sequence: u64,
    ) -> Result<Vec<Vec<u8>>, &'static str> {
        let _guard = self.guard()?;
        let mut statement = self
            .db
            .prepare("SELECT sequence,body,mac FROM la_authority_observations ORDER BY sequence")
            .map_err(|_| "storage_unavailable")?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|_| "storage_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "storage_unavailable")?;
        if rows.len() > 128 || rows.len() as u64 != expected_sequence {
            return Err("evidence_invalid");
        }
        let mut output = Vec::with_capacity(rows.len());
        for (index, (sequence, body, mac)) in rows.into_iter().enumerate() {
            if sequence != index as i64 + 1 {
                return Err("evidence_invalid");
            }
            let mac: [u8; 32] = mac.try_into().map_err(|_| "evidence_invalid")?;
            super::la_adapter::verify_authority_observation(key, &body, &mac)?;
            output.push(body);
        }
        Ok(output)
    }
}

impl ClaimStore {
    /// A worker tombstone receipt resolves only the matching stop intent; the
    /// assignment's reservation and quota charges remain held.
    pub(super) fn acknowledge_job_stop(
        &mut self,
        key: &[u8; 32],
        receipt: &super::la_adapter::StopReceipt,
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        let digest = super::la_adapter::verify_stop_receipt(key, receipt, mac)?;
        if receipt.sequence == 0
            || receipt.sequence > i64::MAX as u64
            || receipt.fence == 0
            || receipt.fence > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let row:Option<(String,String,String,i64,String,String)>=tx.query_row("SELECT j.state,p.digest,a.worker,a.fence,r.boot,o.action FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_assignments a ON a.id=j.assignment_id JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.worker=a.worker AND r.fence=a.fence JOIN la_job_outbox o ON o.job=j.id WHERE j.id=?1 AND j.assignment_id=?2 AND o.operation=?3",params![receipt.job,receipt.assignment,receipt.operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|_|"storage_unavailable")?;
        let (state, command_digest, worker, fence, boot, action) = row.ok_or("evidence_invalid")?;
        if command_digest != receipt.command_digest
            || worker != receipt.worker
            || boot != receipt.boot
            || u64::try_from(fence).ok() != Some(receipt.fence)
        {
            return Err("evidence_invalid");
        }
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM la_worker_receipts WHERE worker=?1 AND boot=?2 AND sequence=?3",
                params![receipt.worker, receipt.boot, receipt.sequence as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some(old) = old {
            return if old.as_slice() == digest && state == "cancelled" {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        }
        if state != "stopping" || action != "stop" {
            return Err("state_conflict");
        }
        let cursor: Option<(String, i64)> = tx
            .query_row(
                "SELECT boot,sequence FROM la_worker_cursor WHERE worker=?1",
                [&receipt.worker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if !matches!(cursor,Some((ref boot,last)) if boot==&receipt.boot && last.checked_add(1)==Some(receipt.sequence as i64))
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO la_worker_receipts VALUES (?1,?2,?3,?4)",
            params![
                receipt.worker,
                receipt.boot,
                receipt.sequence as i64,
                digest.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_worker_cursor SET sequence=?2 WHERE worker=?1",
            params![receipt.worker, receipt.sequence as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute("UPDATE la_jobs SET state='cancelled',revision=revision+1 WHERE id=?1 AND state='stopping'",[&receipt.job]).map_err(|_|"storage_unavailable")?;
        tx.execute(
            "UPDATE la_job_outbox SET action='stopped' WHERE job=?1",
            [&receipt.job],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    pub(super) fn stopping_job_commands(
        &self,
        assignment: &str,
    ) -> Result<Vec<super::la_adapter::InspectCommand>, &'static str> {
        use sha2::{Digest, Sha256};
        let _guard = self.guard()?;
        let mut statement=self.db.prepare("SELECT p.command,p.digest FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id WHERE j.assignment_id=?1 AND j.state='stopping' ORDER BY j.id").map_err(|_|"storage_unavailable")?;
        let rows = statement
            .query_map([assignment], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|_| "storage_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "storage_unavailable")?;
        let mut commands = Vec::with_capacity(rows.len());
        for (body, digest) in rows {
            if hex::encode(Sha256::digest(body.as_bytes())) != digest {
                return Err("evidence_invalid");
            }
            commands.push(serde_json::from_str(&body).map_err(|_| "evidence_invalid")?);
        }
        Ok(commands)
    }
    pub(super) fn assignment_close_command(
        &self,
        project: &str,
        actor: &str,
        assignment: &str,
    ) -> Result<super::la_adapter::CloseCommand, &'static str> {
        let _guard = self.guard()?;
        self.db.query_row("SELECT a.worker,r.boot,a.id,a.fence,c.stop_operation FROM la_assignments a JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.worker=a.worker AND r.fence=a.fence JOIN la_close_intents c ON c.assignment_id=a.id WHERE a.project=?1 AND a.actor=?2 AND a.id=?3 AND a.state='draining' AND NOT EXISTS (SELECT 1 FROM la_assignment_stop_receipts s WHERE s.assignment_id=a.id) AND NOT EXISTS (SELECT 1 FROM la_jobs j WHERE j.assignment_id=a.id AND j.state IN ('pending','running','stopping','finalizing'))",params![project,actor,assignment],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,String>(4)?)))
            .optional().map_err(|_|"storage_unavailable")?.ok_or("state_conflict").and_then(|(worker,boot,assignment,fence,operation)|Ok(super::la_adapter::CloseCommand {worker,boot,assignment,fence:u64::try_from(fence).map_err(|_|"evidence_invalid")?,operation}))
    }
    /// A signed worker stop is recorded but cannot free capacity; a separate
    /// fresh safe-occupancy and cleanup proof is still required.
    pub(super) fn acknowledge_assignment_stop(
        &mut self,
        key: &[u8; 32],
        receipt: &super::la_adapter::CloseReceipt,
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        let digest = super::la_adapter::verify_close_receipt(key, receipt, mac)?;
        if receipt.sequence == 0
            || receipt.sequence > i64::MAX as u64
            || receipt.fence == 0
            || receipt.fence > i64::MAX as u64
        {
            return Err("evidence_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM la_assignments a JOIN la_reservation_authorizations r ON r.assignment_id=a.id AND r.worker=a.worker AND r.fence=a.fence JOIN la_close_intents c ON c.assignment_id=a.id WHERE a.id=?1 AND a.worker=?2 AND a.fence=?3 AND a.state='draining' AND r.boot=?4 AND c.stop_operation=?5 AND NOT EXISTS (SELECT 1 FROM la_jobs j WHERE j.assignment_id=a.id AND j.state IN ('pending','running','stopping','finalizing')))",params![receipt.assignment,receipt.worker,receipt.fence as i64,receipt.boot,receipt.operation],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if !valid {
            return Err("state_conflict");
        }
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT receipt_digest FROM la_assignment_stop_receipts WHERE assignment_id=?1",
                [&receipt.assignment],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some(old) = old {
            return if old.as_slice() == digest {
                Ok(())
            } else {
                Err("evidence_invalid")
            };
        }
        let cursor: Option<(String, i64)> = tx
            .query_row(
                "SELECT boot,sequence FROM la_worker_cursor WHERE worker=?1",
                [&receipt.worker],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if !matches!(cursor,Some((ref boot,last)) if boot==&receipt.boot && last.checked_add(1)==Some(receipt.sequence as i64))
        {
            return Err("evidence_invalid");
        }
        tx.execute(
            "INSERT INTO la_worker_receipts VALUES (?1,?2,?3,?4)",
            params![
                receipt.worker,
                receipt.boot,
                receipt.sequence as i64,
                digest.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_worker_cursor SET sequence=?2 WHERE worker=?1",
            params![receipt.worker, receipt.sequence as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_assignment_stop_receipts VALUES (?1,?2)",
            params![receipt.assignment, digest.as_slice()],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    pub(super) fn assignment_stop_recorded(&self, assignment: &str) -> Result<bool, &'static str> {
        let _guard = self.guard()?;
        self.db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM la_assignment_stop_receipts WHERE assignment_id=?1)",
                [assignment],
                |r| r.get(0),
            )
            .map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    pub(super) fn job_history_count(&self) -> Result<i64, &'static str> {
        let _guard = self.guard()?;
        self.db
            .query_row("SELECT COUNT(*) FROM la_jobs", [], |r| r.get(0))
            .map_err(|_| "storage_unavailable")
    }
}

/// Trusted P can observe a pinned finite child root without obtaining a writer
/// or canonicalizing its out-of-view descriptor into a mutable host path.
pub(super) fn open_pinned_readonly_database(
    root: &std::fs::File,
    name: &str,
) -> Result<PinnedDb, &'static str> {
    use std::os::fd::AsRawFd;
    if !matches!(
        name,
        "worker-channel.sqlite"
            | "controller-channel.sqlite"
            | "service-custody.sqlite"
            | "worker.sqlite"
            | "lane_assignments.sqlite"
    ) || !register_pinned_vfs()
    {
        return Err("evidence_invalid");
    }
    let directory = root.try_clone().map_err(|_| "storage_unavailable")?;
    let path = format!("/proc/self/fd/{}/{name}", directory.as_raw_fd());
    let connection = rusqlite::Connection::open_with_flags_and_vfs(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        "diffuser-owned-root-v1",
    )
    .map_err(|_| "evidence_invalid")?;
    connection
        .execute_batch("PRAGMA query_only=ON;")
        .map_err(|_| "evidence_invalid")?;
    Ok(PinnedDb {
        connection,
        _directory: directory,
    })
}

impl ClaimStore {
    /// Only protected P's independently observed certificate can reach this
    /// transaction. Terminal jobs and retained audit rows never release claims.
    /// Only an authenticated exact pending-close handoff can open this bounded
    /// recovery cleanup window. The original close timestamp/fence is retained.
    pub(super) fn record_recovered_close(
        &mut self,
        handoff: &super::la_adapter::TransportEpochHandoff,
        keys: &super::la_adapter::ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        let (receipt, window) = handoff
            .recovered_close_window(&self.root, keys, now)?
            .ok_or("evidence_invalid")?;
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let epoch: i64 = tx
            .query_row("SELECT writer_epoch FROM la_controller_identity", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        if epoch != window.binding.controller_epoch as i64 {
            return Err("evidence_invalid");
        }
        let claim = super::la_adapter::cleanup::claim_snapshot(&tx, &receipt.assignment)?;
        if claim.worker != receipt.worker
            || claim.boot != receipt.boot
            || claim.fence != receipt.fence
            || claim.sequence != receipt.sequence
            || claim.operation != receipt.operation
            || hex::encode(&claim.stop_digest) != window.receipt_digest
        {
            return Err("evidence_invalid");
        }
        let bytes = serde_json::to_vec(&window).map_err(|_| "evidence_invalid")?;
        if bytes.len() > 4096 {
            return Err("evidence_invalid");
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_close_reconciliations(assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id),body BLOB NOT NULL);").map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_close_reconciliations VALUES(?1,?2)",
            params![receipt.assignment, bytes],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
    pub(super) fn record_worker_return_close(
        &mut self,
        handoff: &super::la_adapter::WorkerEpochHandoff,
        keys: &super::la_adapter::ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        let (receipt, window) = handoff.close_window(keys, now)?;
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let epoch: i64 = tx
            .query_row("SELECT writer_epoch FROM la_controller_identity", [], |r| {
                r.get(0)
            })
            .map_err(|_| "evidence_invalid")?;
        if epoch != window.binding.controller_epoch as i64 {
            return Err("evidence_invalid");
        }
        let claim = super::la_adapter::cleanup::claim_snapshot(&tx, &receipt.assignment)?;
        if claim.worker != receipt.worker
            || claim.boot != receipt.boot
            || claim.fence != receipt.fence
            || claim.sequence != receipt.sequence
            || claim.operation != receipt.operation
            || hex::encode(&claim.stop_digest) != window.receipt_digest
        {
            return Err("evidence_invalid");
        }
        let bytes = serde_json::to_vec(&window).map_err(|_| "evidence_invalid")?;
        if bytes.len() > 4096 {
            return Err("evidence_invalid");
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_close_reconciliations(assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id),body BLOB NOT NULL);").map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_close_reconciliations VALUES(?1,?2)",
            params![receipt.assignment, bytes],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
    pub(super) fn release_cleaned_assignment(
        &mut self,
        binding: &super::la_adapter::ChannelBinding,
        keys: &super::la_adapter::ChannelKeys,
        certificate: &super::la_adapter::cleanup::Certificate,
        now: u64,
    ) -> Result<bool, &'static str> {
        use sha2::{Digest, Sha256};
        let _guard = self.guard()?;
        let bytes = serde_json::to_vec(certificate).map_err(|_| "evidence_invalid")?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let old: Option<(String,Vec<u8>,i64)> = tx
            .query_row(
                "SELECT digest,certificate,released_at FROM la_assignment_cleanup_receipts WHERE assignment_id=?1",
                [certificate.assignment()],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            )
            .optional()
            .map_err(|_| "storage_unavailable")?;
        if let Some((old, saved, released_at)) = old {
            // An exact committed replay reads its historical receipt only.
            // Authenticate the original consumption time and complete signed
            // bytes; never consume a certificate late or open another window.
            let released_at = u64::try_from(released_at).map_err(|_| "evidence_invalid")?;
            if old != digest || saved != bytes || released_at > now {
                return Err("evidence_invalid");
            }
            certificate.verify(binding, keys, &self.root, released_at)?;
            return Ok(false);
        }
        let body = certificate.verify(binding, keys, &self.root, now)?;
        if super::la_adapter::cleanup::claim_snapshot(&tx, &body.claim.assignment)? != body.claim {
            #[cfg(test)]
            super::la_adapter::recovery_trace(
                "cleanup_live_claim_mismatch",
                serde_json::json!({"now":now}),
            );
            return Err("evidence_invalid");
        }
        let assignment = &body.claim.assignment;
        let changed = tx
            .execute(
                "UPDATE la_assignments SET state='closed' WHERE id=?1 AND state IN ('draining','quarantined')",
                [assignment],
            )
            .map_err(|_| "storage_unavailable")?;
        let reservation = tx
            .execute(
                "DELETE FROM la_reservations WHERE assignment_id=?1",
                [assignment],
            )
            .map_err(|_| "storage_unavailable")?;
        let quota = tx
            .execute(
                "DELETE FROM la_quota_charges WHERE assignment_id=?1",
                [assignment],
            )
            .map_err(|_| "storage_unavailable")?;
        if changed != 1 || reservation != 1 || quota != 1 {
            return Err("evidence_invalid");
        }
        tx.execute(
            "UPDATE la_assignment_revisions SET revision=revision+1 WHERE assignment_id=?1",
            [assignment],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute("DELETE FROM la_outbox WHERE assignment_id=?1", [assignment])
            .map_err(|_| "storage_unavailable")?;
        // Grant charges, idempotency, fence high-water, close cause, permits,
        // terminal receipts and artifact bindings remain audit history.
        tx.execute(
            "INSERT INTO la_assignment_cleanup_receipts VALUES (?1,?2,?3,?4)",
            params![
                assignment,
                digest,
                bytes,
                i64::try_from(now).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        let commit_now = checked_wall_since(now)?;
        #[cfg(test)]
        super::la_adapter::recovery_trace(
            "cleanup_commit_clock",
            serde_json::json!({"received_now":now,"commit_now":commit_now}),
        );
        certificate.verify(binding, keys, &self.root, commit_now)?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(true)
    }
}

/// Commit an assignment barrier and stop expansion together. This function
/// never releases a reservation or rewrites a terminal execution result.
fn close_assignment_transaction(
    tx: &rusqlite::Transaction<'_>,
    assignment: &str,
    reason: &str,
    now: u64,
) -> Result<(), &'static str> {
    let changed=tx.execute("UPDATE la_assignments SET state='draining' WHERE id=?1 AND state IN ('reserved','assigned')",[assignment]).map_err(|_| "storage_unavailable")?;
    if changed == 0 {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO la_close_intents VALUES (?1,?2,?3,?4)",
        params![
            assignment,
            reason,
            now as i64,
            format!("close_{assignment}")
        ],
    )
    .map_err(|_| "storage_unavailable")?;
    tx.execute(
        "UPDATE la_assignment_revisions SET revision=revision+1 WHERE assignment_id=?1",
        [assignment],
    )
    .map_err(|_| "storage_unavailable")?;
    tx.execute("INSERT INTO la_outbox VALUES (?1,'stop') ON CONFLICT(assignment_id) DO UPDATE SET action='stop'",[assignment]).map_err(|_| "storage_unavailable")?;
    tx.execute("UPDATE la_job_outbox SET action='stop' WHERE job IN (SELECT id FROM la_jobs WHERE assignment_id=?1 AND state IN ('pending','running'))",[assignment]).map_err(|_| "storage_unavailable")?;
    tx.execute("UPDATE la_jobs SET state='stopping',revision=revision+1 WHERE assignment_id=?1 AND state IN ('pending','running')",[assignment]).map_err(|_| "storage_unavailable")?;
    tx.execute("UPDATE la_permits SET closed=1,pending_revision=NULL,pending_until=NULL WHERE job IN (SELECT id FROM la_jobs WHERE assignment_id=?1)",[assignment]).map_err(|_| "storage_unavailable")?;
    Ok(())
}

impl ClaimStore {
    /// Protected-source ticks close explicit acknowledged lease/hard bounds.
    /// Cleanup timeout quarantines and retains every reservation and charge.
    pub(super) fn tick_assignment_closures(
        &mut self,
        binding: &super::la_adapter::ChannelBinding,
        now: u64,
    ) -> Result<(), &'static str> {
        if now > i64::MAX as u64 {
            return Err("clock_untrusted");
        }
        let cleanup = super::la_adapter::cleanup::deadline_ms(binding)?;
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let rows = {
            let mut s=tx.prepare("SELECT a.id,t.lease_until,t.hard_until FROM la_assignments a JOIN la_assignment_terms t ON t.assignment_id=a.id WHERE a.worker=?1 AND a.state IN ('reserved','assigned') ORDER BY a.id").map_err(|_| "storage_unavailable")?;
            let rows = s
                .query_map([&binding.worker], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|_| "storage_unavailable")?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "storage_unavailable")?;
            rows
        };
        for (id, lease, hard) in rows {
            if lease < 0 || hard < lease {
                return Err("evidence_invalid");
            }
            let reason = if now >= hard as u64 {
                Some("hard_expired")
            } else if now >= lease as u64 {
                Some("lease_expired")
            } else {
                None
            };
            if let Some(reason) = reason {
                close_assignment_transaction(&tx, &id, reason, now)?;
            }
        }
        let oldest = now.saturating_sub(cleanup);
        if now >= cleanup {
            tx.execute("UPDATE la_assignment_revisions SET revision=revision+1 WHERE assignment_id IN (SELECT a.id FROM la_assignments a JOIN la_close_intents c ON c.assignment_id=a.id WHERE a.worker=?1 AND a.state='draining' AND c.requested_at<=?2)",params![binding.worker,oldest as i64]).map_err(|_| "storage_unavailable")?;
            tx.execute("UPDATE la_assignments SET state='quarantined' WHERE worker=?1 AND state='draining' AND id IN (SELECT assignment_id FROM la_close_intents WHERE requested_at<=?2)",params![binding.worker,oldest as i64]).map_err(|_| "storage_unavailable")?;
        }
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    pub(super) fn ready_for_cleanup_assignments(
        &self,
        worker: &str,
    ) -> Result<Vec<String>, &'static str> {
        let _guard = self.guard()?;
        let mut s = self
            .db
            .prepare(
                "SELECT a.id FROM la_assignments a                  WHERE a.worker=?1 AND a.state='draining'                  AND EXISTS(SELECT 1 FROM la_assignment_stop_receipts r WHERE r.assignment_id=a.id)                  AND NOT EXISTS(SELECT 1 FROM la_assignment_cleanup_receipts c WHERE c.assignment_id=a.id)                  ORDER BY a.id",
            )
            .map_err(|_| "storage_unavailable")?;
        let rows = s
            .query_map([worker], |r| r.get(0))
            .map_err(|_| "storage_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "storage_unavailable")?;
        Ok(rows)
    }
    pub(super) fn snapshot_for_cleanup(
        &self,
        assignment: &str,
    ) -> Result<super::la_adapter::cleanup::Claim, &'static str> {
        let _guard = self.guard()?;
        super::la_adapter::cleanup::claim_snapshot(&self.db, assignment)
    }
    pub(super) fn draining_assignment_owners(
        &self,
        worker: &str,
    ) -> Result<Vec<(String, String, String)>, &'static str> {
        let _guard = self.guard()?;
        let mut s=self.db.prepare("SELECT a.project,a.actor,a.id FROM la_assignments a WHERE a.worker=?1 AND a.state='draining' AND NOT EXISTS(SELECT 1 FROM la_assignment_stop_receipts r WHERE r.assignment_id=a.id) ORDER BY a.id").map_err(|_| "storage_unavailable")?;
        let rows = s
            .query_map([worker], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|_| "storage_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "storage_unavailable")?;
        Ok(rows)
    }
}

impl ClaimStore {
    /// Retained immutable permit commands for read-only live-W reconciliation.
    /// Loading this list grants neither a new permit nor dispatch authority.
    pub(super) fn reconciliation_commands(
        &self,
    ) -> Result<Vec<super::la_adapter::InspectCommand>, &'static str> {
        let jobs = {
            let _guard = self.guard()?;
            let mut st = self
                .db
                .prepare("SELECT id FROM la_jobs ORDER BY id LIMIT 33")
                .map_err(|_| "evidence_invalid")?;
            let values = st
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|_| "evidence_invalid")?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "evidence_invalid")?;
            if values.len() > 32 {
                return Err("evidence_invalid");
            }
            values
        };
        jobs.iter()
            .map(|job| self.job_permit_command(job))
            .collect()
    }
}

impl ClaimStore {
    /// Exact retained-key lookup for a completed request. This performs no claim,
    /// permit, mandate, outbox, quota or idempotency-alias mutation.
    pub(super) fn completed_job_retry(
        &self,
        project: &str,
        actor: &str,
        assignment: &str,
        key: &str,
        fingerprint: &str,
        lineage: &[String],
    ) -> Result<JobView, &'static str> {
        self.existing_job_retry(project, actor, assignment, key, fingerprint, lineage, None)
    }

    /// Typed live retries also recognize an exact client job ID and pending
    /// original work. They never insert an alias or repeat an execution.
    #[expect(
        clippy::too_many_arguments,
        reason = "Each independent retry binding is required."
    )]
    pub(super) fn existing_job_retry(
        &self,
        project: &str,
        actor: &str,
        assignment: &str,
        key: &str,
        fingerprint: &str,
        lineage: &[String],
        live_client_id: Option<&str>,
    ) -> Result<JobView, &'static str> {
        if ![project, actor, assignment, key].into_iter().all(valid_id)
            || fingerprint.len() != 64
            || hex::decode(fingerprint).is_err()
        {
            return Err("schema_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|_| "storage_unavailable")?;
        let owned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM la_assignments WHERE id=?1 AND project=?2 AND actor=?3)",params![assignment,project,actor],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if !owned {
            return Err("object_not_found");
        }
        let old:Option<(String,String)>=tx.query_row("SELECT fingerprint,job FROM la_job_idempotency WHERE project=?1 AND actor=?2 AND idem_key=?3",params![project,actor,key],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_|"storage_unavailable")?;
        let (saved, job) = match (old, live_client_id) {
            (Some(row), _) => row,
            (None, Some(id)) if valid_id(id) => tx.query_row(
                "SELECT fingerprint,job FROM la_client_jobs WHERE project=?1 AND actor=?2 AND client_job_id=?3",
                params![project,actor,id], |r|Ok((r.get(0)?,r.get(1)?)),
            ).optional().map_err(|_| "storage_unavailable")?.ok_or("routing_closed")?,
            _ => return Err("routing_closed"),
        };
        if saved != fingerprint {
            return Err("idempotency_conflict");
        }
        let mut st = tx
            .prepare("SELECT grant_id FROM la_job_grant_charges WHERE job=?1 ORDER BY grant_id")
            .map_err(|_| "storage_unavailable")?;
        let charged = st
            .query_map([&job], |r| r.get::<_, String>(0))
            .map_err(|_| "storage_unavailable")?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "storage_unavailable")?;
        let mut expected = lineage.to_vec();
        expected.sort();
        if charged != expected {
            return Err("delegation_denied");
        }
        drop(st);
        let view:JobView=tx.query_row("SELECT id,assignment_id,input_artifact,state,revision,result_artifact FROM la_jobs WHERE id=?1 AND project=?2 AND actor=?3 AND assignment_id=?4",params![job,project,actor,assignment],|r|Ok(JobView{id:r.get(0)?,assignment:r.get(1)?,input_artifact:r.get(2)?,state:r.get(3)?,revision:r.get(4)?,result_artifact:r.get(5)?})).optional().map_err(|_|"storage_unavailable")?.ok_or("object_not_found")?;
        let published: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM la_job_results WHERE job=?1 AND output_id=?2)",
                params![job, view.result_artifact],
                |r| r.get(0),
            )
            .map_err(|_| "storage_unavailable")?;
        if (live_client_id.is_none() || view.state == "succeeded")
            && (view.state != "succeeded" || view.result_artifact.is_none() || !published)
        {
            return Err("routing_closed");
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(view)
    }
}

impl ClaimStore {
    pub(super) fn install_worker_successor(
        &mut self,
        cap: &super::la_adapter::WorkerSuccessorAdmission,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let (old_boot, generation, sequence, fence) = cap.cursor();
        let binding = cap.binding();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let safe:bool=tx.query_row("SELECT NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges) AND NOT EXISTS(SELECT 1 FROM la_assignments WHERE state!='closed') AND EXISTS(SELECT 1 FROM la_worker_cursor WHERE worker=?1 AND boot=?2 AND sequence=?3) AND (SELECT MAX(fence) FROM la_assignments WHERE worker=?1)=?4",params![binding.worker,old_boot,sequence as i64,fence as i64],|r|r.get(0)).map_err(|_| "evidence_invalid")?;
        if !safe {
            return Err("evidence_invalid");
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_worker_session_generations(worker TEXT NOT NULL,generation INTEGER NOT NULL,body BLOB NOT NULL,PRIMARY KEY(worker,generation))").map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_worker_session_generations VALUES(?1,?2,?3)",
            params![
                binding.worker,
                generation as i64,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.execute(
            "UPDATE la_worker_cursor SET boot=?2 WHERE worker=?1",
            params![binding.worker, binding.worker_boot],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    /// A new adjacent-epoch receipt consumes a separate, exact rebound record.
    /// Original permit/mandate/outbox identities and absolute times stay intact.
    pub(super) fn claim_never_started_rebound(
        &mut self,
        cap: &super::la_adapter::NeverStartedPermit,
        key: &[u8; 32],
        r: &super::la_adapter::PermitReceipt,
        mac: &[u8; 32],
        now: u64,
    ) -> Result<(), &'static str> {
        use sha2::{Digest, Sha256};
        let digest = super::la_adapter::verify_permit_receipt(key, r, mac)?;
        cap.verify_commands()?;
        let c = &cap.rebound;
        let original = serde_json::to_string(&cap.original).map_err(|_| "evidence_invalid")?;
        let command = serde_json::to_string(c).map_err(|_| "evidence_invalid")?;
        if r.worker != c.worker
            || r.boot != c.boot
            || r.assignment != c.assignment
            || r.fence != c.fence
            || r.operation != c.operation
            || r.job != c.job
            || r.permit_until != c.permit_until
            || r.command_digest != hex::encode(Sha256::digest(command.as_bytes()))
            || now >= c.permit_until
        {
            return Err("evidence_invalid");
        }
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_job_rebound_permits(job TEXT PRIMARY KEY,capability TEXT NOT NULL UNIQUE,receipt BLOB NOT NULL,sequence INTEGER NOT NULL,claimed_at INTEGER NOT NULL,command TEXT NOT NULL,digest TEXT NOT NULL,permit_until INTEGER NOT NULL);").map_err(|_| "storage_unavailable")?;
        let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_job_outbox o ON o.job=j.id JOIN la_assignments a ON a.id=j.assignment_id JOIN la_reservation_authorizations z ON z.assignment_id=a.id JOIN la_worker_cursor w ON w.worker=a.worker AND w.boot=z.boot WHERE j.id=?1 AND j.assignment_id=?2 AND a.state='assigned' AND a.worker=?3 AND z.boot=?4 AND a.fence=?5 AND p.command=?6 AND p.acknowledged=1 AND o.operation=?7 AND ((j.state='pending' AND o.action='start') OR (j.state='running' AND o.action='sent')) AND w.sequence+1=?8 AND NOT EXISTS(SELECT 1 FROM la_close_intents x WHERE x.assignment_id=a.id))",params![c.job,c.assignment,c.worker,c.boot,c.fence as i64,original,c.operation,r.sequence as i64],|row|row.get(0)).map_err(|_| "evidence_invalid")?;
        if !valid {
            return Err("state_conflict");
        }
        tx.execute(
            "INSERT INTO la_job_rebound_permits VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                c.job,
                cap.digest()?,
                digest.as_slice(),
                r.sequence as i64,
                now as i64,
                command,
                r.command_digest,
                c.permit_until as i64
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.execute(
            "INSERT INTO la_worker_receipts VALUES(?1,?2,?3,?4)",
            params![r.worker, r.boot, r.sequence as i64, digest.as_slice()],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_worker_cursor SET sequence=?2 WHERE worker=?1",
            params![r.worker, r.sequence as i64],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.execute("UPDATE la_jobs SET state='running',revision=revision+1 WHERE id=?1 AND state='pending'",[&c.job]).map_err(|_| "storage_unavailable")?;
        tx.execute(
            "UPDATE la_job_outbox SET action='sent' WHERE job=?1 AND action='start'",
            [&c.job],
        )
        .map_err(|_| "storage_unavailable")?;
        if checked_wall_since(now)? >= c.permit_until {
            return Err("deadline_elapsed");
        }
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

fn effective_job_permit_until(db: &rusqlite::Connection, job: &str) -> Result<i64, &'static str> {
    use sha2::{Digest, Sha256};
    let (original,until):(String,i64)=db.query_row("SELECT command,permit_until FROM la_job_permit_intents WHERE job=?1 AND acknowledged=1",[job],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|"evidence_invalid")?;
    let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='la_job_rebound_permits')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
    if !table {
        return Ok(until);
    }
    let row: Option<(String, String, i64)> = db
        .query_row(
            "SELECT command,digest,permit_until FROM la_job_rebound_permits WHERE job=?1",
            [job],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| "evidence_invalid")?;
    let Some((command, digest, expiry)) = row else {
        return Ok(until);
    };
    let old: super::la_adapter::InspectCommand =
        serde_json::from_str(&original).map_err(|_| "evidence_invalid")?;
    let mut new: super::la_adapter::InspectCommand =
        serde_json::from_str(&command).map_err(|_| "evidence_invalid")?;
    if hex::encode(Sha256::digest(command.as_bytes())) != digest
        || new.permit_until != u64::try_from(expiry).map_err(|_| "evidence_invalid")?
        || new.permit_until > old.mandate_until
    {
        return Err("evidence_invalid");
    }
    new.permit_until = old.permit_until;
    if serde_json::to_vec(&new).map_err(|_| "evidence_invalid")?
        != serde_json::to_vec(&old).map_err(|_| "evidence_invalid")?
    {
        return Err("evidence_invalid");
    }
    Ok(expiry)
}

impl ClaimStore {
    pub(super) fn terminal_release_eligible(&self, assignment: &str) -> Result<bool, &'static str> {
        let _guard = self.guard()?;
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM la_assignments WHERE id=?1) AND NOT EXISTS(SELECT 1 FROM la_jobs WHERE assignment_id=?1 AND state NOT IN ('succeeded','cancelled'))", [assignment], |r|r.get(0)).map_err(|_| "evidence_invalid")
    }
    pub(super) fn install_controller_admission(
        &mut self,
        cap: &super::la_adapter::RecoveredControllerAdmission,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let (boot, generation, sequence, fence) = cap.cursor();
        let b = cap.binding();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let safe: bool = tx.query_row("SELECT NOT EXISTS(SELECT 1 FROM la_reservations) AND NOT EXISTS(SELECT 1 FROM la_quota_charges) AND NOT EXISTS(SELECT 1 FROM la_assignments WHERE state!='closed') AND EXISTS(SELECT 1 FROM la_worker_cursor WHERE worker=?1 AND boot=?2 AND sequence=?3) AND (SELECT MAX(fence) FROM la_assignments WHERE worker=?1)=?4 AND (SELECT writer_epoch FROM la_controller_identity)=?5 AND NOT EXISTS(SELECT 1 FROM sqlite_master WHERE name='la_controller_admissions')", params![b.worker,boot,sequence as i64,fence as i64,generation as i64], |r|r.get(0)).map_err(|_| "evidence_invalid")?;
        if !safe || generation != b.controller_epoch {
            return Err("evidence_invalid");
        }
        tx.execute_batch("CREATE TABLE la_controller_admissions(generation INTEGER PRIMARY KEY,capability BLOB NOT NULL UNIQUE);").map_err(|_| "storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_controller_admissions VALUES(?1,?2)",
            params![
                generation as i64,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
}

impl ClaimStore {
    /// A P loss capability terminates the client job as failed/uncertain. It
    /// never synthesizes a worker receipt, advances a worker cursor or releases
    /// a reservation. Interrupted consumption remains behind pending custody.
    pub(super) fn record_worker_loss(
        &mut self,
        cap: &super::la_adapter::WorkerLossSettlement,
        keys: &super::la_adapter::ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        cap.verify(keys, now)?;
        let _guard = self.guard()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let c = &cap.command;
        let exact:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM la_jobs j JOIN la_job_permit_intents p ON p.job=j.id JOIN la_job_outbox o ON o.job=j.id JOIN la_assignments a ON a.id=j.assignment_id JOIN la_reservation_authorizations r ON r.assignment_id=a.id JOIN la_reservations h ON h.assignment_id=a.id JOIN la_quota_charges q ON q.assignment_id=a.id WHERE j.id=?1 AND j.assignment_id=?2 AND j.state='stopping' AND j.result_artifact IS NULL AND o.operation=?3 AND o.action='stop' AND p.command=?4 AND a.worker=?5 AND a.fence=?6 AND r.boot=?7 AND a.state IN ('assigned','draining') AND NOT EXISTS(SELECT 1 FROM la_job_results WHERE job=j.id))",params![c.job,c.assignment,c.operation,serde_json::to_string(c).map_err(|_|"evidence_invalid")?,c.worker,c.fence as i64,c.boot],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if !exact {
            return Err("evidence_invalid");
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_worker_loss_settlements(job TEXT PRIMARY KEY REFERENCES la_jobs(id),assignment_id TEXT UNIQUE NOT NULL,body BLOB NOT NULL); CREATE TABLE IF NOT EXISTS la_worker_loss_closes(assignment_id TEXT PRIMARY KEY REFERENCES la_assignments(id),body BLOB NOT NULL);").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_worker_loss_settlements VALUES(?1,?2,?3)",
            params![
                c.job,
                c.assignment,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        if tx.execute("UPDATE la_jobs SET state='failed',revision=revision+1 WHERE id=?1 AND state='stopping'",[&c.job]).map_err(|_|"storage_unavailable")?!=1 {return Err("evidence_invalid");}
        tx.execute(
            "UPDATE la_job_outbox SET action='worker_lost_uncertain' WHERE job=?1",
            [&c.job],
        )
        .map_err(|_| "storage_unavailable")?;
        cap.verify(keys, checked_wall_since(now)?)?;
        tx.commit().map_err(|_| "storage_unavailable")
    }
    /// The ordinary release route creates its original Close intent first.
    /// Its distinct death-domain close record does not impersonate W's cursor.
    pub(super) fn close_lost_worker(
        &mut self,
        command: &super::la_adapter::CloseCommand,
    ) -> Result<bool, &'static str> {
        let _guard = self.guard()?;
        let exists:bool=self.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='la_worker_loss_settlements')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if !exists {
            return Ok(false);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        let cap: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM la_worker_loss_settlements WHERE assignment_id=?1",
                [&command.assignment],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| "evidence_invalid")?;
        let Some(cap) = cap else {
            return Ok(false);
        };
        let cap: super::la_adapter::WorkerLossSettlement =
            serde_json::from_slice(&cap).map_err(|_| "evidence_invalid")?;
        let c = &cap.command;
        let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM la_assignments a JOIN la_close_intents i ON i.assignment_id=a.id JOIN la_reservation_authorizations r ON r.assignment_id=a.id JOIN la_worker_cursor w ON w.worker=a.worker AND w.boot=r.boot WHERE a.id=?1 AND a.state='draining' AND a.worker=?2 AND a.fence=?3 AND r.boot=?4 AND i.stop_operation=?5 AND (SELECT COUNT(*) FROM la_jobs WHERE assignment_id=a.id)=1 AND EXISTS(SELECT 1 FROM la_jobs j JOIN la_job_outbox o ON o.job=j.id WHERE j.id=?6 AND j.assignment_id=a.id AND j.state='failed' AND j.result_artifact IS NULL AND o.action='worker_lost_uncertain'))",params![command.assignment,command.worker,command.fence as i64,command.boot,command.operation,c.job],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if !valid
            || command.worker != c.worker
            || command.boot != c.boot
            || command.fence != c.fence
        {
            return Err("evidence_invalid");
        }
        let record = super::la_adapter::WorkerLossClose {
            kind: "diffuser-dead-domain-close/v1".into(),
            command: command.clone(),
            settlement: cap.digest()?,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| "evidence_invalid")?;
        tx.execute(
            "INSERT INTO la_worker_loss_closes VALUES(?1,?2) ON CONFLICT(assignment_id) DO NOTHING",
            params![command.assignment, bytes],
        )
        .map_err(|_| "evidence_invalid")?;
        let saved: Vec<u8> = tx
            .query_row(
                "SELECT body FROM la_worker_loss_closes WHERE assignment_id=?1",
                [&command.assignment],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if saved != bytes {
            return Err("evidence_invalid");
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        Ok(true)
    }
}

impl ClaimStore {
    pub(super) fn record_loss_source(
        &mut self,
        cap: &super::la_adapter::WorkerLossSource,
        keys: &super::la_adapter::ChannelKeys,
        now: u64,
    ) -> Result<(), &'static str> {
        let body = cap.verify(keys, now)?;
        let mac = super::la_adapter::sign_authority_observation(&keys.authority, &body);
        self.append_authority_observation_inner(
            &keys.authority,
            &body,
            &mac,
            Some((cap, keys)),
            None,
        )
    }

    pub(super) fn has_loss_source(&self) -> Result<bool, &'static str> {
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='la_worker_loss_sources')", [], |r| r.get(0)).map_err(|_| "evidence_invalid")
    }
}

impl ClaimStore {
    pub(super) fn append_loss_return_authority_observation(
        &mut self,
        binding: &super::la_adapter::ChannelBinding,
        keys: &super::la_adapter::ChannelKeys,
        bytes: &[u8],
        mac: &[u8; 32],
    ) -> Result<(), &'static str> {
        self.append_authority_observation_inner(
            &keys.authority,
            bytes,
            mac,
            None,
            Some((binding, keys)),
        )
    }
}

impl ClaimStore {
    /// Installs only the new cursor and exact W ACK under the distinct domain.
    /// The old failed job, cleanup certificate/time and all old rows survive.
    pub(super) fn install_loss_return(
        &mut self,
        cap: &super::la_adapter::LossReturnAdmission,
        keys: &super::la_adapter::ChannelKeys,
        worker_installed_at: u64,
        worker_ack: &[u8; 32],
        now: u64,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let now = checked_wall_since(now)?;
        cap.verify_envelope(keys, now)?;
        cap.verify_worker_ack(keys, worker_installed_at, worker_ack)?;
        cap.verify_controller_store(&self.root, &self.db)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        cap.verify_claims(&tx)?;
        let generations:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='la_worker_session_generations')",[],|r|r.get(0)).map_err(|_|"evidence_invalid")?;
        if generations {
            let rows: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM la_worker_session_generations",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| "evidence_invalid")?;
            if rows != 0 {
                return Err("evidence_invalid");
            }
        }
        let b = cap.binding();
        let (_, generation, _, _) = cap.cursor();
        tx.execute_batch("CREATE TABLE IF NOT EXISTS la_worker_session_generations(worker TEXT NOT NULL,generation INTEGER NOT NULL,body BLOB NOT NULL,PRIMARY KEY(worker,generation)); CREATE TABLE la_loss_return_installs(admission TEXT PRIMARY KEY,capability BLOB NOT NULL,worker_installed_at INTEGER NOT NULL,worker_ack BLOB NOT NULL,installed_at INTEGER NOT NULL,ack BLOB NOT NULL)").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_worker_session_generations VALUES(?1,?2,?3)",
            params![
                b.worker,
                generation as i64,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "evidence_invalid")?;
        let ack = cap.controller_ack(keys, worker_installed_at, worker_ack, now)?;
        tx.execute(
            "INSERT INTO la_loss_return_installs VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                cap.digest()?,
                serde_json::to_vec(cap).map_err(|_| "evidence_invalid")?,
                worker_installed_at as i64,
                worker_ack.as_slice(),
                now as i64,
                ack.as_slice()
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        let (old_boot, _, sequence, _) = cap.cursor();
        if tx
            .execute(
                "UPDATE la_worker_cursor SET boot=?1 WHERE worker=?2 AND boot=?3 AND sequence=?4",
                params![b.worker_boot, b.worker, old_boot, sequence as i64],
            )
            .map_err(|_| "storage_unavailable")?
            != 1
        {
            return Err("evidence_invalid");
        }
        tx.commit().map_err(|_| "storage_unavailable")?;
        cap.current_install_clock(keys)?;
        Ok(())
    }
}

impl ClaimStore {
    pub(super) fn persist_loss_return_completion(
        &mut self,
        proof: &super::la_adapter::LossReturnCompletion,
        keys: &super::la_adapter::ChannelKeys,
    ) -> Result<(), &'static str> {
        let _guard = self.guard()?;
        let saved: Vec<u8> = self
            .db
            .query_row(
                "SELECT capability FROM la_loss_return_installs WHERE admission=?1",
                [proof.admission()],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        let cap: super::la_adapter::LossReturnAdmission =
            serde_json::from_slice(&saved).map_err(|_| "evidence_invalid")?;
        proof.verify_for(&cap, keys)?;
        cap.verify_completion_role(proof, &self.root, "controller", keys)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        tx.execute_batch("CREATE TABLE la_loss_return_completions(admission TEXT PRIMARY KEY,proof BLOB NOT NULL)").map_err(|_|"storage_unavailable")?;
        tx.execute(
            "INSERT INTO la_loss_return_completions VALUES(?1,?2)",
            params![
                proof.admission(),
                serde_json::to_vec(proof).map_err(|_| "evidence_invalid")?
            ],
        )
        .map_err(|_| "storage_unavailable")?;
        tx.commit().map_err(|_| "storage_unavailable")?;
        super::la_adapter::LossReturnCopy::record(&self.root, "controller", &cap, proof, keys)?;
        cap.current_install_clock(keys)?;
        Ok(())
    }
}

impl ClaimStore {
    pub(super) fn load_loss_return_admission(
        &self,
        digest: &str,
    ) -> Result<super::la_adapter::LossReturnAdmission, &'static str> {
        let _guard = self.guard()?;
        let saved: Vec<u8> = self
            .db
            .query_row(
                "SELECT capability FROM la_loss_return_installs WHERE admission=?1",
                [digest],
                |r| r.get(0),
            )
            .map_err(|_| "evidence_invalid")?;
        if saved.len() > 15360 {
            return Err("evidence_invalid");
        }
        let cap: super::la_adapter::LossReturnAdmission =
            serde_json::from_slice(&saved).map_err(|_| "evidence_invalid")?;
        if cap.digest()? != digest {
            return Err("evidence_invalid");
        }
        Ok(cap)
    }
}
