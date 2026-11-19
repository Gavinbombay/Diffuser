//! A private, crash-safe journal for one workflow and at most one submitted job.
use super::{Error, Id, Identity, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

const JOURNAL: &str = "journal.json";
const MAX_ENTRIES: usize = 64;
const JOURNAL_MAX: usize = 65_536;

#[derive(Clone, Copy, Debug)]
pub enum Attempt<'a> {
    /// An explicit new operation reserves this key before sending.
    Start(&'a Id),
    /// Requires an existing intent for this exact operation and body.
    Retry(&'a Id),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Upload,
    Acquire,
    Renew,
    Release,
    Submit,
    Cancel,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mutation {
    Legacy(Operation),
    CpuSubmit,
    CudaSubmit,
}

impl Mutation {
    fn operation(self) -> Operation {
        match self {
            Self::Legacy(operation) => operation,
            Self::CpuSubmit | Self::CudaSubmit => Operation::Submit,
        }
    }
}

impl From<Operation> for Mutation {
    fn from(operation: Operation) -> Self {
        Self::Legacy(operation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub operation: Operation,
    pub target_id: Option<Id>,
    pub body_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Returned {
    /// The generated or already existing object ID returned by the API.
    pub object_id: Id,
    pub assignment_id: Option<Id>,
    pub receipt_id: Option<Id>,
    /// Populated by successful readback of a verified job result.
    pub result_artifact_id: Option<Id>,
}

impl Returned {
    pub(super) fn object(object_id: Id) -> Self {
        Self {
            object_id,
            assignment_id: None,
            receipt_id: None,
            result_artifact_id: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub intent: Intent,
    /// Absent until a successful reply with validated IDs is committed.
    pub returned: Option<Returned>,
    /// The HTTP status of the most recent validated mutation reply.
    pub http_status: Option<u16>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: JournalVersion,
    identity: Identity,
    records: BTreeMap<Id, Receipt>,
    // One submit per journal. Omit this for legacy journals to preserve their
    // exact disk representation and the public Receipt/Operation API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cpu_submit_key: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cuda_submit_key: Option<Id>,
}

impl Journal {
    fn mutation(&self, key: &Id, operation: Operation) -> Mutation {
        if self.cpu_submit_key.as_ref() == Some(key) {
            Mutation::CpuSubmit
        } else if self.cuda_submit_key.as_ref() == Some(key) {
            Mutation::CudaSubmit
        } else {
            Mutation::Legacy(operation)
        }
    }
}

#[derive(Serialize, Deserialize)]
enum JournalVersion {
    #[serde(rename = "diffuser-client-receipts/v1")]
    V1,
}

pub struct ReceiptStore {
    directory: File,
}

impl ReceiptStore {
    /// Open an existing dedicated directory owned by this UID, mode 0700.
    /// The directory must be on a local filesystem supporting flock, rename
    /// and fsync. Its descriptors pin it for each transaction.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let directory = open_directory(path.as_ref(), libc::O_NOFOLLOW)?;
        Ok(Self { directory })
    }

    pub fn read(&self, identity: &Identity, key: &Id) -> Result<Receipt, Error> {
        let dir = self.lock(false)?;
        let journal = load(&dir, identity)?;
        journal
            .records
            .get(key)
            .cloned()
            .ok_or(Error::ReceiptMissing)
    }

    pub(super) fn read_submit(
        &self,
        identity: &Identity,
        key: &Id,
        mutation: Mutation,
    ) -> Result<Receipt, Error> {
        let dir = self.lock(false)?;
        let journal = load(&dir, identity)?;
        let receipt = journal.records.get(key).ok_or(Error::ReceiptMissing)?;
        if receipt.intent.operation != Operation::Submit
            || journal.mutation(key, receipt.intent.operation) != mutation
        {
            return Err(Error::ReceiptConflict);
        }
        Ok(receipt.clone())
    }

    pub(super) fn begin(
        &self,
        identity: &Identity,
        attempt: Attempt<'_>,
        mutation: Mutation,
        target_id: Option<Id>,
        body_sha256: Sha256Digest,
    ) -> Result<Id, Error> {
        let intent = Intent {
            operation: mutation.operation(),
            target_id,
            body_sha256,
        };
        let dir = self.lock(true)?;
        let mut journal = load(&dir, identity)?;
        let key = match attempt {
            Attempt::Start(key) => {
                if journal.records.contains_key(key) {
                    return Err(Error::ReceiptConflict);
                }
                if intent.operation == Operation::Submit
                    && journal
                        .records
                        .values()
                        .any(|r| r.intent.operation == Operation::Submit)
                {
                    return Err(Error::ReceiptConflict);
                }
                if journal.records.len() >= MAX_ENTRIES {
                    return Err(Error::ReceiptLimit);
                }
                journal.records.insert(
                    key.clone(),
                    Receipt {
                        intent,
                        returned: None,
                        http_status: None,
                    },
                );
                match mutation {
                    Mutation::CpuSubmit => journal.cpu_submit_key = Some(key.clone()),
                    Mutation::CudaSubmit => journal.cuda_submit_key = Some(key.clone()),
                    Mutation::Legacy(_) => (),
                }
                save(&dir, &journal)?;
                key
            }
            Attempt::Retry(key) => {
                let existing = journal.records.get(key).ok_or(Error::ReceiptMissing)?;
                if existing.intent != intent
                    || journal.mutation(key, existing.intent.operation) != mutation
                {
                    return Err(Error::ReceiptConflict);
                }
                // Also cover a prior attempt that observed an fsync failure
                // after the intent rename.
                dir.sync_all().map_err(|_| Error::ReceiptStorage)?;
                key
            }
        };
        Ok(key.clone())
    }

    pub(super) fn finish(
        &self,
        identity: &Identity,
        key: &Id,
        status: u16,
        mut returned: Returned,
    ) -> Result<(), Error> {
        let dir = self.lock(true)?;
        let mut journal = load(&dir, identity)?;
        let receipt = journal.records.get_mut(key).ok_or(Error::ReceiptMissing)?;
        if let Some(old) = &receipt.returned {
            if old.object_id != returned.object_id
                || old.assignment_id != returned.assignment_id
                || old.receipt_id != returned.receipt_id
            {
                return Err(Error::ReceiptConflict);
            }
            returned.result_artifact_id = old.result_artifact_id.clone();
        }
        receipt.returned = Some(returned);
        receipt.http_status = Some(status);
        save(&dir, &journal)
    }

    pub(super) fn remember_result(
        &self,
        identity: &Identity,
        key: &Id,
        job: &Id,
        artifact: &Id,
    ) -> Result<(), Error> {
        let dir = self.lock(true)?;
        let mut journal = load(&dir, identity)?;
        let receipt = journal.records.get_mut(key).ok_or(Error::ReceiptMissing)?;
        if receipt.intent.operation != Operation::Submit {
            return Err(Error::ReceiptConflict);
        }
        let returned = receipt.returned.as_mut().ok_or(Error::ReceiptUncertain)?;
        if &returned.object_id != job {
            return Err(Error::ReceiptConflict);
        }
        match &returned.result_artifact_id {
            Some(previous) if previous == artifact => return Ok(()),
            Some(_) => return Err(Error::ReceiptConflict),
            None => returned.result_artifact_id = Some(artifact.clone()),
        }
        save(&dir, &journal)
    }

    fn lock(&self, write: bool) -> Result<File, Error> {
        // Each transaction needs its own open file description for flock,
        // including simultaneous calls on the same ReceiptStore.
        let dir = open_directory(&descriptor_path(&self.directory), 0)?;
        let mode = if write { libc::LOCK_EX } else { libc::LOCK_SH };
        loop {
            if unsafe { libc::flock(dir.as_raw_fd(), mode) } == 0 {
                return Ok(dir);
            }
            if std::io::Error::last_os_error().kind() != ErrorKind::Interrupted {
                return Err(Error::ReceiptStorage);
            }
        }
    }
}

fn descriptor_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn open_directory(path: &Path, flags: i32) -> Result<File, Error> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | flags)
        .open(path)
        .map_err(|_| Error::ReceiptStorage)?;
    let meta = dir.metadata().map_err(|_| Error::ReceiptStorage)?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
        return Err(Error::ReceiptStorage);
    }
    Ok(dir)
}

fn load(dir: &File, identity: &Identity) -> Result<Journal, Error> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(descriptor_path(dir).join(JOURNAL))
    {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(Journal {
                version: JournalVersion::V1,
                identity: identity.clone(),
                records: BTreeMap::new(),
                cpu_submit_key: None,
                cuda_submit_key: None,
            })
        }
        Err(_) => return Err(Error::ReceiptStorage),
    };
    let meta = file.metadata().map_err(|_| Error::ReceiptStorage)?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
    {
        return Err(Error::ReceiptStorage);
    }
    let mut bytes = Vec::new();
    file.take(JOURNAL_MAX as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::ReceiptStorage)?;
    if bytes.len() > JOURNAL_MAX {
        return Err(Error::ReceiptLimit);
    }
    let journal: Journal = serde_json::from_slice(&bytes).map_err(|_| Error::ReceiptStorage)?;
    if journal.identity != *identity {
        return Err(Error::ReceiptIdentity);
    }
    if journal.records.len() > MAX_ENTRIES {
        return Err(Error::ReceiptLimit);
    }
    let typed_keys = [&journal.cpu_submit_key, &journal.cuda_submit_key];
    if typed_keys.iter().filter(|key| key.is_some()).count() > 1
        || typed_keys
            .into_iter()
            .filter_map(Option::as_ref)
            .any(|key| {
                !journal
                    .records
                    .get(key)
                    .is_some_and(|receipt| receipt.intent.operation == Operation::Submit)
            })
    {
        return Err(Error::ReceiptStorage);
    }
    Ok(journal)
}

fn save(dir: &File, journal: &Journal) -> Result<(), Error> {
    let bytes = serde_json::to_vec(journal).map_err(|_| Error::ReceiptStorage)?;
    if bytes.len() > JOURNAL_MAX {
        return Err(Error::ReceiptLimit);
    }
    let mut random = [0u8; 16];
    if unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) }
        != random.len() as isize
    {
        return Err(Error::ReceiptStorage);
    }
    let path = descriptor_path(dir);
    let temp = path.join(format!(".receipt-{}", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| Error::ReceiptStorage)?;
    let result = (|| {
        // Enforce 0600 even if the caller uses an unusually restrictive umask.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path.join(JOURNAL))?;
        dir.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|_| Error::ReceiptStorage)
}
