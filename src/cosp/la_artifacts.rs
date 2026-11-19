//! Private immutable artifact storage; callers must authorize before invoking it.
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
};

const MAX_INPUT: usize = 1024 * 1024;
const MAX_ARTIFACTS: i64 = 32;
type ManifestRow = (
    String,
    i64,
    i64,
    i64,
    String,
    Option<String>,
    Option<String>,
);

fn valid_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub(super) fn open_owned_root(path: &Path) -> std::io::Result<fs::File> {
    if !path.is_absolute() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/")?;
    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(name) => {
                let name = std::ffi::CString::new(name.as_bytes())
                    .map_err(|_| std::io::ErrorKind::InvalidInput)?;
                // Walk every ancestor relative to the previously opened fd.
                let fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                current = unsafe { fs::File::from_raw_fd(fd) };
            }
            _ => return Err(std::io::ErrorKind::InvalidInput.into()),
        }
    }
    Ok(current)
}

pub(super) fn open_artifact(
    directory: &fs::File,
    id: &str,
    flags: i32,
) -> std::io::Result<fs::File> {
    let name = std::ffi::CString::new(id).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    // id is a single validated component; the held directory fd prevents a
    // parent path replacement from redirecting this operation.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

// All store instances take the same nonblocking lock. A durable intent is
// written before staging, and is retained after an ambiguous failure or crash.
struct ArtifactLock(fs::File);
impl ArtifactLock {
    fn acquire(file: &fs::File) -> Result<Self, &'static str> {
        let file = file.try_clone().map_err(|_| "storage_unavailable")?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("storage_unavailable");
        }
        Ok(Self(file))
    }
}
impl Drop for ArtifactLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn intent_present(root: &fs::File) -> Result<bool, &'static str> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            c".artifact-intent".as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err("storage_unavailable")
    }
}
fn begin_intent(root: &fs::File) -> Result<(), &'static str> {
    let mut marker = open_artifact(
        root,
        ".artifact-intent",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )
    .map_err(|_| "storage_unavailable")?;
    marker
        .write_all(b"artifact-publication-pending-v1\n")
        .and_then(|_| marker.sync_all())
        .map_err(|_| "storage_unavailable")?;
    root.sync_all().map_err(|_| "storage_unavailable")
}
fn finish_intent(root: &fs::File) -> Result<(), &'static str> {
    if unsafe { libc::unlinkat(root.as_raw_fd(), c".artifact-intent".as_ptr(), 0) } != 0 {
        return Err("storage_unavailable");
    }
    root.sync_all().map_err(|_| "storage_unavailable")
}

#[derive(Debug)]
pub(super) struct ArtifactManifest {
    pub(super) id: String,
    pub(super) tenant: String,
    pub(super) project: String,
    pub(super) actor: String,
    pub(super) initiator: Option<String>,
    pub(super) lineage: Option<Vec<String>>,
    pub(super) digest: String,
    pub(super) bytes: u64,
    pub(super) created: u64,
    pub(super) expires: u64,
    pub(super) kind: String,
    pub(super) assignment: Option<String>,
    pub(super) job: Option<String>,
}

#[derive(Clone, Copy)]
struct UploadBinding<'a> {
    key: &'a str,
    fingerprint: &'a str,
    initiator: &'a str,
    lineage: &'a [String],
    authorized_at: u64,
    valid_until: u64,
    monotonic_until: std::time::Instant,
    expiry_error: &'static str,
}

fn check_upload_deadline(binding: Option<UploadBinding<'_>>) -> Result<(), &'static str> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or("clock_untrusted")?;
    if now < binding.authorized_at {
        return Err("clock_untrusted");
    }
    if now >= binding.valid_until || std::time::Instant::now() >= binding.monotonic_until {
        return Err(binding.expiry_error);
    }
    Ok(())
}

pub(super) struct ArtifactStore {
    db: super::la_store::PinnedDb,
    root_handle: fs::File,
    root_path: PathBuf,
    lock_handle: fs::File,
    directory_handle: fs::File,
    uncertain: bool,
}

impl ArtifactStore {
    pub(super) fn open(root: &Path) -> Result<Self, &'static str> {
        let root_handle = open_owned_root(root).map_err(|_| "storage_unavailable")?;
        let lock_handle =
            open_artifact(&root_handle, ".artifact-lock", libc::O_RDWR | libc::O_CREAT)
                .map_err(|_| "storage_unavailable")?;
        if !lock_handle
            .metadata()
            .map_err(|_| "storage_unavailable")?
            .is_file()
        {
            return Err("storage_unavailable");
        }
        let guard = ArtifactLock::acquire(&lock_handle)?;
        if intent_present(&root_handle)? {
            return Err("storage_unavailable");
        }
        let name = c"artifacts";
        let created = unsafe { libc::mkdirat(root_handle.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err("storage_unavailable");
        }
        let directory_handle = open_artifact(
            &root_handle,
            "artifacts",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .map_err(|_| "storage_unavailable")?;
        let db =
            super::la_store::open_pinned_database(&root_handle, "lane_assignments.sqlite", true)?;
        let reopened = open_owned_root(root).map_err(|_| "storage_unavailable")?;
        let pinned_meta = root_handle.metadata().map_err(|_| "storage_unavailable")?;
        let reopened_meta = reopened.metadata().map_err(|_| "storage_unavailable")?;
        if pinned_meta.dev() != reopened_meta.dev() || pinned_meta.ino() != reopened_meta.ino() {
            return Err("storage_unavailable");
        }
        db.busy_timeout(std::time::Duration::from_secs(3))
            .map_err(|_| "storage_unavailable")?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS la_artifacts (
            id TEXT PRIMARY KEY, tenant TEXT NOT NULL, project TEXT NOT NULL, actor TEXT NOT NULL,
            digest TEXT NOT NULL, byte_count INTEGER NOT NULL, created INTEGER NOT NULL,
            expires INTEGER NOT NULL, kind TEXT NOT NULL, assignment_id TEXT, job_id TEXT,
            quarantined INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS la_artifact_provenance (
            artifact_id TEXT PRIMARY KEY REFERENCES la_artifacts(id),
            initiator TEXT NOT NULL, lineage TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS la_artifact_idempotency (
            tenant TEXT NOT NULL, project TEXT NOT NULL, actor TEXT NOT NULL,
            idem_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
            artifact_id TEXT NOT NULL REFERENCES la_artifacts(id),
            PRIMARY KEY(tenant,project,actor,idem_key)
        );",
        )
        .map_err(|_| "storage_unavailable")?;
        // Retain ambiguous files and refuse readiness until custody reconciles
        // the filesystem and committed metadata. Do not delete history.
        let mut recorded = std::collections::BTreeSet::new();
        {
            let mut statement = db
                .prepare("SELECT id FROM la_artifacts")
                .map_err(|_| "storage_unavailable")?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|_| "storage_unavailable")?;
            for row in rows {
                let id = row.map_err(|_| "storage_unavailable")?;
                if !valid_id(&id)
                    || !recorded.insert(id)
                    || recorded.len() > 2 * MAX_ARTIFACTS as usize
                {
                    return Err("storage_unavailable");
                }
            }
        }
        let invalid: i64 = db.query_row("SELECT COUNT(*) FROM (SELECT kind,COUNT(*) AS n FROM la_artifacts GROUP BY kind) WHERE kind NOT IN ('input','output') OR n>?1",[MAX_ARTIFACTS],|r|r.get(0)).map_err(|_|"storage_unavailable")?;
        if invalid != 0 {
            return Err("storage_unavailable");
        }
        let mut present = std::collections::BTreeSet::new();
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory_handle.as_raw_fd()))
            .map_err(|_| "storage_unavailable")?
        {
            let entry = entry.map_err(|_| "storage_unavailable")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "storage_unavailable")?;
            if !valid_id(&name)
                || !entry
                    .file_type()
                    .map_err(|_| "storage_unavailable")?
                    .is_file()
                || !present.insert(name)
                || present.len() > 2 * MAX_ARTIFACTS as usize
            {
                return Err("storage_unavailable");
            }
        }
        if recorded != present {
            return Err("storage_unavailable");
        }
        drop(guard);
        Ok(Self {
            db,
            root_handle,
            root_path: root.to_path_buf(),
            lock_handle,
            directory_handle,
            uncertain: false,
        })
    }

    fn directory_matches(&self) -> bool {
        let Ok(current_root) = open_owned_root(&self.root_path) else {
            return false;
        };
        let (Ok(expected), Ok(current)) = (self.root_handle.metadata(), current_root.metadata())
        else {
            return false;
        };
        if (expected.dev(), expected.ino()) != (current.dev(), current.ino()) {
            return false;
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                self.root_handle.as_raw_fd(),
                c"artifacts".as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return false;
        }
        let stat = unsafe { stat.assume_init() };
        let Ok(handle) = self.directory_handle.metadata() else {
            return false;
        };
        (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
            && stat.st_dev == handle.dev()
            && stat.st_ino == handle.ino()
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
    )]
    pub(super) fn put_input(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        bytes: &[u8],
        digest: &str,
        created: u64,
        expires: u64,
    ) -> Result<(), &'static str> {
        self.put(
            tenant, project, actor, id, None, None, bytes, digest, created, expires, None,
        )
        .map(|_| ())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
    )]
    fn put(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        assignment: Option<&str>,
        job: Option<&str>,
        bytes: &[u8],
        digest: &str,
        created: u64,
        expires: u64,
        idempotency: Option<UploadBinding<'_>>,
    ) -> Result<String, &'static str> {
        let _guard = ArtifactLock::acquire(&self.lock_handle)?;
        if self.uncertain || !self.directory_matches() {
            self.uncertain = true;
            if !intent_present(&self.root_handle).unwrap_or(true) {
                let _ = begin_intent(&self.root_handle);
            }
            return Err("storage_unavailable");
        }
        if intent_present(&self.root_handle)? {
            self.uncertain = true;
            return Err("storage_unavailable");
        }
        let kind = if assignment.is_some() && job.is_some() {
            "output"
        } else if assignment.is_none() && job.is_none() {
            "input"
        } else {
            return Err("artifact_invalid");
        };
        if ![tenant, project, actor, id].iter().all(|v| valid_id(v))
            || assignment.is_some_and(|v| !valid_id(v))
            || job.is_some_and(|v| !valid_id(v))
            || bytes.len() > if kind == "input" { MAX_INPUT } else { 4096 }
            || digest != hex::encode(Sha256::digest(bytes))
            || expires <= created
            || expires > i64::MAX as u64
        {
            return Err("artifact_invalid");
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "storage_unavailable")?;
        // SQLite may have waited on another writer after HTTP authorization.
        check_upload_deadline(idempotency)?;
        if let Some(UploadBinding {
            key,
            fingerprint,
            initiator,
            lineage,
            ..
        }) = idempotency
        {
            if !valid_id(initiator)
                || lineage.is_empty()
                || lineage.len() > 3
                || !lineage.iter().all(|id| valid_id(id))
                || kind != "input"
                || !valid_id(key)
                || fingerprint.len() != 64
                || !fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("schema_invalid");
            }
            let old: Option<(String, String)> = tx.query_row(
                "SELECT fingerprint,artifact_id FROM la_artifact_idempotency WHERE tenant=?1 AND project=?2 AND actor=?3 AND idem_key=?4",
                params![tenant, project, actor, key], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(|_| "storage_unavailable")?;
            if let Some((old_fingerprint, old_id)) = old {
                return if old_fingerprint == fingerprint {
                    Ok(old_id)
                } else {
                    Err("idempotency_conflict")
                };
            }
        }
        let count: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM la_artifacts WHERE kind=?1",
                [kind],
                |r| r.get(0),
            )
            .map_err(|_| "storage_unavailable")?;
        if count >= MAX_ARTIFACTS {
            return Err("storage_unavailable");
        }
        if begin_intent(&self.root_handle).is_err() {
            self.uncertain = true;
            return Err("storage_unavailable");
        }
        let mut file = match open_artifact(
            &self.directory_handle,
            id,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => file,
            Err(_) => {
                self.uncertain = true;
                return Err("storage_unavailable");
            }
        };
        let result = (|| {
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "storage_unavailable")?;
            self.directory_handle
                .sync_all()
                .map_err(|_| "storage_unavailable")?;
            tx.execute("INSERT INTO la_artifacts (id,tenant,project,actor,digest,byte_count,created,expires,kind,assignment_id,job_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)", params![id, tenant, project, actor, digest, bytes.len() as i64, created as i64, expires as i64, kind, assignment, job]).map_err(|_| "storage_unavailable")?;
            if let Some(UploadBinding {
                key,
                fingerprint,
                initiator,
                lineage,
                ..
            }) = idempotency
            {
                let lineage = serde_json::to_string(lineage).map_err(|_| "storage_unavailable")?;
                tx.execute(
                    "INSERT INTO la_artifact_provenance VALUES (?1,?2,?3)",
                    params![id, initiator, lineage],
                )
                .map_err(|_| "storage_unavailable")?;
                tx.execute(
                    "INSERT INTO la_artifact_idempotency VALUES (?1,?2,?3,?4,?5,?6)",
                    params![tenant, project, actor, key, fingerprint, id],
                )
                .map_err(|_| "storage_unavailable")?;
            }
            // If staging consumed the authority horizon, retain the durable
            // intent and fail closed instead of committing a stale mutation.
            check_upload_deadline(idempotency)?;
            tx.commit().map_err(|_| "storage_unavailable")
        })();
        // A failed commit can be ambiguous. Preserve the staged file so a later
        // recovery pass can reconcile it; never delete possibly committed bytes.
        if result.is_err() || !self.directory_matches() {
            self.uncertain = true;
            return Err("storage_unavailable");
        }
        if finish_intent(&self.root_handle).is_err() {
            self.uncertain = true;
            return Err("storage_unavailable");
        }
        result.map(|_| id.to_owned())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
    )]
    pub(super) fn put_input_idempotent(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        bytes: &[u8],
        digest: &str,
        created: u64,
        expires: u64,
        key: &str,
        fingerprint: &str,
        initiator: &str,
        lineage: &[String],
        authorized_at: u64,
        valid_until: u64,
        monotonic_until: std::time::Instant,
        expiry_error: &'static str,
    ) -> Result<String, &'static str> {
        self.put(
            tenant,
            project,
            actor,
            id,
            None,
            None,
            bytes,
            digest,
            created,
            expires,
            Some(UploadBinding {
                key,
                fingerprint,
                initiator,
                lineage,
                authorized_at,
                valid_until,
                monotonic_until,
                expiry_error,
            }),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "This internal API keeps distinct contract fields explicit and does not itself grant authority."
    )]
    pub(super) fn put_output(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        assignment: &str,
        job: &str,
        bytes: &[u8],
        digest: &str,
        created: u64,
        expires: u64,
    ) -> Result<(), &'static str> {
        self.put(
            tenant,
            project,
            actor,
            id,
            Some(assignment),
            Some(job),
            bytes,
            digest,
            created,
            expires,
            None,
        )
        .map(|_| ())
    }
    /// The caller must authenticate before this scoped lookup. Bytes are
    /// verified on every read, and integrity failure quarantines the record.
    pub(super) fn read_manifest_and_content(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        now: u64,
    ) -> Result<(ArtifactManifest, Vec<u8>), &'static str> {
        if ![tenant, project, actor, id].iter().all(|v| valid_id(v)) {
            return Err("object_not_found");
        }
        let (digest, count, created, expires, kind, assignment, job) = {
            let _guard = ArtifactLock::acquire(&self.lock_handle)?;
            if self.uncertain || !self.directory_matches() || intent_present(&self.root_handle)? {
                self.uncertain = true;
                return Err("storage_unavailable");
            }
            let row: Option<ManifestRow> = self.db.query_row(
                "SELECT digest,byte_count,created,expires,kind,assignment_id,job_id FROM la_artifacts WHERE id=?1 AND tenant=?2 AND project=?3 AND actor=?4",
                params![id, tenant, project, actor],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
            ).optional().map_err(|_| "storage_unavailable")?;
            row.ok_or("object_not_found")?
        };
        if !matches!(kind.as_str(), "input" | "output") {
            return Err("artifact_invalid");
        }
        let bytes = self.read(tenant, project, actor, id, now, &kind)?;
        let provenance: Option<(String, String)> = {
            let _guard = ArtifactLock::acquire(&self.lock_handle)?;
            if self.uncertain || !self.directory_matches() || intent_present(&self.root_handle)? {
                self.uncertain = true;
                return Err("storage_unavailable");
            }
            self.db
                .query_row(
                    "SELECT initiator,lineage FROM la_artifact_provenance WHERE artifact_id=?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|_| "storage_unavailable")?
        };
        let (initiator, lineage) = if let Some((initiator, lineage)) = provenance {
            let lineage: Vec<String> =
                serde_json::from_str(&lineage).map_err(|_| "artifact_invalid")?;
            if !valid_id(&initiator)
                || lineage.is_empty()
                || lineage.len() > 3
                || !lineage.iter().all(|id| valid_id(id))
            {
                return Err("artifact_invalid");
            }
            (Some(initiator), Some(lineage))
        } else {
            (None, None)
        };
        let record = ArtifactManifest {
            id: id.to_owned(),
            tenant: tenant.to_owned(),
            project: project.to_owned(),
            actor: actor.to_owned(),
            initiator,
            lineage,
            digest,
            bytes: u64::try_from(count).map_err(|_| "artifact_invalid")?,
            created: u64::try_from(created).map_err(|_| "artifact_invalid")?,
            expires: u64::try_from(expires).map_err(|_| "artifact_invalid")?,
            kind,
            assignment,
            job,
        };
        Ok((record, bytes))
    }

    pub(super) fn read_output(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        now: u64,
    ) -> Result<Vec<u8>, &'static str> {
        self.read(tenant, project, actor, id, now, "output")
    }
    pub(super) fn read_input(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        now: u64,
    ) -> Result<Vec<u8>, &'static str> {
        self.read(tenant, project, actor, id, now, "input")
    }
    fn read(
        &mut self,
        tenant: &str,
        project: &str,
        actor: &str,
        id: &str,
        now: u64,
        kind: &str,
    ) -> Result<Vec<u8>, &'static str> {
        if ![tenant, project, actor, id].iter().all(|v| valid_id(v)) {
            return Err("object_not_found");
        }
        let _guard = ArtifactLock::acquire(&self.lock_handle)?;
        if self.uncertain || !self.directory_matches() {
            self.uncertain = true;
            if !intent_present(&self.root_handle).unwrap_or(true) {
                let _ = begin_intent(&self.root_handle);
            }
            return Err("storage_unavailable");
        }
        if intent_present(&self.root_handle)? {
            self.uncertain = true;
            return Err("storage_unavailable");
        }
        let record: Option<(String, i64, i64, bool)> = self.db.query_row(
            "SELECT digest,byte_count,expires,quarantined FROM la_artifacts WHERE id=?1 AND tenant=?2 AND project=?3 AND actor=?4 AND kind=?5",
            params![id,tenant,project,actor,kind], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional().map_err(|_| "storage_unavailable")?;
        let (digest, count, expires, quarantined) = record.ok_or("object_not_found")?;
        if quarantined {
            return Err("artifact_invalid");
        }
        let expires = u64::try_from(expires).map_err(|_| "artifact_invalid")?;
        let count = u64::try_from(count).map_err(|_| "artifact_invalid")?;
        if now >= expires {
            return Err("artifact_expired");
        }
        let bytes = (|| {
            let file = open_artifact(
                &self.directory_handle,
                id,
                libc::O_RDONLY | libc::O_NONBLOCK,
            )
            .map_err(|_| "artifact_invalid")?;
            let meta = file.metadata().map_err(|_| "artifact_invalid")?;
            if !meta.is_file() || meta.len() > MAX_INPUT as u64 || meta.len() != count {
                return Err("artifact_invalid");
            }
            let mut bytes = Vec::with_capacity(meta.len() as usize);
            file.take((MAX_INPUT + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "artifact_invalid")?;
            if u64::try_from(bytes.len()).ok() != Some(count)
                || hex::encode(Sha256::digest(&bytes)) != digest
            {
                return Err("artifact_invalid");
            }
            Ok(bytes)
        })();
        if bytes.is_err() {
            if begin_intent(&self.root_handle).is_err() {
                self.uncertain = true;
                return Err("storage_unavailable");
            }
            if self
                .db
                .execute("UPDATE la_artifacts SET quarantined=1 WHERE id=?1", [id])
                .is_err()
                || finish_intent(&self.root_handle).is_err()
            {
                self.uncertain = true;
                return Err("storage_unavailable");
            }
        }
        if !self.directory_matches() {
            self.uncertain = true;
            if !intent_present(&self.root_handle).unwrap_or(true) {
                let _ = begin_intent(&self.root_handle);
            }
            return Err("storage_unavailable");
        }
        bytes
    }
}
