//! Staged cartridge publication. Dispatch integration is not yet complete.
use crate::cartridge::{self, Cartridge};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

static STORE_LOCK: Mutex<()> = Mutex::new(());

static NEXT: AtomicU64 = AtomicU64::new(0);

fn staging(root: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    loop {
        let path = root.join(format!(
            ".stage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn sync_tree(path: &Path) -> Result<(), String> {
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            sync_tree(&entry.path())?;
        } else if ty.is_file() {
            fs::File::open(entry.path())
                .and_then(|f| f.sync_all())
                .map_err(|e| e.to_string())?;
        } else {
            return Err("non-regular staging entry".into());
        }
    }
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

fn sync_dir(path: &Path) -> Result<(), String> {
    fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Opening a store keeps no cached pointer or unpublished version state.
pub struct Store {
    root: PathBuf,
}
impl Store {
    pub fn open(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
        }
    }
    pub fn active_version(&self, lane: &str) -> Result<(PathBuf, PathBuf, String), String> {
        if !crate::LANES.contains(&lane) {
            return Err(crate::error_catalog::UNKNOWN_LANE.into());
        }
        let hash = fs::read_to_string(self.root.join("active").join(lane))
            .map_err(|_| crate::error_catalog::STATE_UNREADABLE.to_owned())?;
        self.version(lane, &hash)
    }
    /// Read a pinned immutable record, including earlier published versions.
    /// Integrity failure never changes the active pointer or another record.
    pub fn version(&self, lane: &str, hash: &str) -> Result<(PathBuf, PathBuf, String), String> {
        if !crate::LANES.contains(&lane) {
            return Err(crate::error_catalog::UNKNOWN_LANE.into());
        }
        if !valid_digest(hash) {
            return Err(crate::error_catalog::BAD_DIGEST.into());
        }
        let version = self.root.join("versions").join(hash);
        let manifest = version.join("manifest.json");
        let data =
            fs::read(&manifest).map_err(|_| crate::error_catalog::STATE_UNREADABLE.to_owned())?;
        if digest(&data) != hash {
            return Err(crate::error_catalog::HASH_MISMATCH.into());
        }
        let cart: Cartridge = serde_json::from_slice(&data)
            .map_err(|_| crate::error_catalog::STATE_CORRUPT.to_owned())?;
        if cart.lane != lane {
            return Err(crate::error_catalog::LANE_MISMATCH.into());
        }
        cartridge::verify(&cart, &version.join("files"))
            .map_err(|_| crate::error_catalog::MANIFEST_MISMATCH.to_owned())?;
        Ok((manifest, version.join("files"), hash.to_owned()))
    }
}

pub fn active_version(root: &Path, lane: &str) -> Result<(PathBuf, PathBuf, String), String> {
    Store::open(root).active_version(lane)
}

pub fn install(root: &Path, manifest: &Path, source: &Path) -> Result<String, String> {
    #[cfg(test)]
    {
        install_inner(root, manifest, source, false)
    }
    #[cfg(not(test))]
    {
        install_inner(root, manifest, source)
    }
}

fn install_inner(
    root: &Path,
    manifest: &Path,
    source: &Path,
    #[cfg(test)] interrupt: bool,
) -> Result<String, String> {
    let _guard = STORE_LOCK.lock().unwrap();
    let data = fs::read(manifest).map_err(|e| e.to_string())?;
    let cart: Cartridge = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    cartridge::verify(&cart, source)?;
    let hash = digest(&data);
    let versions = root.join("versions");
    fs::create_dir_all(&versions).map_err(|e| e.to_string())?;
    let stage = staging(&root.join("staging"))?;
    let files = stage.join("files");
    fs::create_dir(&files).map_err(|e| e.to_string())?;
    for name in cart.files.keys() {
        let target = files.join(name);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(source.join(name), target).map_err(|e| e.to_string())?;
    }
    cartridge::verify(&cart, &files)?;
    fs::write(stage.join("manifest.json"), &data).map_err(|e| e.to_string())?;
    sync_tree(&stage)?;
    sync_dir(&root.join("staging"))?;
    #[cfg(test)]
    if interrupt {
        return Err("simulated interruption before version rename".into());
    }
    fs::rename(&stage, versions.join(&hash)).map_err(|e| e.to_string())?;
    sync_dir(&versions)?;
    sync_dir(&root.join("staging"))?;
    sync_dir(root)?;
    Ok(hash)
}

pub fn swap(root: &Path, lane: &str, hash: &str) -> Result<(), String> {
    #[cfg(test)]
    {
        swap_inner(root, lane, hash, false)
    }
    #[cfg(not(test))]
    {
        swap_inner(root, lane, hash)
    }
}

fn swap_inner(
    root: &Path,
    lane: &str,
    hash: &str,
    #[cfg(test)] interrupt: bool,
) -> Result<(), String> {
    let _guard = STORE_LOCK.lock().unwrap();
    if !crate::LANES.contains(&lane) || !valid_digest(hash) {
        return Err("invalid lane or manifest digest".into());
    }
    Store::open(root).version(lane, hash)?;
    let active = root.join("active");
    fs::create_dir_all(&active).map_err(|e| e.to_string())?;
    let stage = staging(&root.join("staging"))?;
    let pointer = stage.join("pointer");
    fs::write(&pointer, hash).map_err(|e| e.to_string())?;
    sync_tree(&stage)?;
    sync_dir(&root.join("staging"))?;
    #[cfg(test)]
    if interrupt {
        return Err("simulated interruption before pointer rename".into());
    }
    fs::rename(pointer, active.join(lane)).map_err(|e| e.to_string())?;
    fs::remove_dir(&stage).map_err(|e| e.to_string())?;
    sync_dir(&active)?;
    sync_dir(&root.join("staging"))?;
    sync_dir(root)
}

/// Compatibility configuration: store.staging_grace_secs, default one hour.
pub struct Config {
    pub staging_grace: Duration,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            staging_grace: Duration::from_secs(3600),
        }
    }
}
impl Config {
    pub fn from_value(value: &Value) -> Self {
        Self {
            staging_grace: value["store"]["staging_grace_secs"]
                .as_u64()
                .map(Duration::from_secs)
                .unwrap_or(Self::default().staging_grace),
        }
    }
}

fn staging_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(".stage-") else {
        return false;
    };
    let Some((pid, sequence)) = rest.split_once('-') else {
        return false;
    };
    [pid, sequence]
        .iter()
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

// Check each component before resolving or traversing. A symlink anywhere in
// a candidate tree refuses the entire removal, including links to this root.
fn no_symlinks(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if fs::symlink_metadata(ancestor)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("symlink refused".into());
        }
    }
    Ok(())
}
fn regular_tree(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("symlink refused".into());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
            regular_tree(&entry.map_err(|e| e.to_string())?.path())?;
        }
    } else if !metadata.is_file() {
        return Err("non-regular entry refused".into());
    }
    Ok(())
}
fn collect_references(value: &Value, references: &mut HashSet<String>) {
    match value {
        Value::String(text) => {
            references.insert(text.clone());
        }
        Value::Array(rows) => {
            for row in rows {
                collect_references(row, references);
            }
        }
        Value::Object(row) => {
            for field in row.values() {
                collect_references(field, references);
            }
        }
        _ => {}
    }
}

fn cleanup_candidate(
    root: &Path,
    candidate: &Path,
    references: &HashSet<String>,
    config: &Config,
    now: SystemTime,
    log: &mut impl FnMut(&str),
) -> Result<bool, String> {
    no_symlinks(candidate)?;
    let resolved_root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let resolved = fs::canonicalize(candidate).map_err(|e| e.to_string())?;
    if resolved.parent() != Some(resolved_root.as_path()) {
        return Err("outside staging root refused".into());
    }
    let name = candidate
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("non-UTF8 name refused")?;
    if !staging_name(name)
        || !fs::symlink_metadata(candidate)
            .map_err(|e| e.to_string())?
            .is_dir()
    {
        return Ok(false);
    }
    regular_tree(candidate)?;
    let mut identities = vec![
        name.to_owned(),
        candidate.to_string_lossy().into_owned(),
        resolved.to_string_lossy().into_owned(),
    ];
    // Jobs normally pin a digest. Protect staged copies of that version too.
    if let Ok(data) = fs::read(candidate.join("manifest.json")) {
        identities.push(digest(&data));
    }
    if let Ok(pointer) = fs::read_to_string(candidate.join("pointer")) {
        identities.push(pointer);
    }
    if references.iter().any(|reference| {
        identities.iter().any(|identity| {
            reference == identity || Path::new(reference).starts_with(Path::new(identity))
        })
    }) {
        return Ok(false);
    }
    let age = now
        .duration_since(
            fs::symlink_metadata(candidate)
                .map_err(|e| e.to_string())?
                .modified()
                .map_err(|e| e.to_string())?,
        )
        .unwrap_or_default();
    if age <= config.staging_grace {
        return Ok(false);
    }
    fs::remove_dir_all(candidate).map_err(|e| e.to_string())?;
    log(&format!(
        "removed path={name} age_secs={} reason=abandoned-unreferenced-staging",
        age.as_secs()
    ));
    Ok(true)
}

/// Deletes only immediate staging children. Published versions are never GC'd.
/// Call with the job-table lock held, including persisted job records on restart.
pub fn cleanup(
    root: &Path,
    jobs: &[Value],
    config: &Config,
    now: SystemTime,
    mut log: impl FnMut(&str),
) {
    let _guard = STORE_LOCK.lock().unwrap();
    let stage_root = root.join("staging");
    if fs::symlink_metadata(&stage_root).is_err() {
        return;
    }
    if let Err(reason) = no_symlinks(&stage_root) {
        log(&format!("refused staging root: {reason}"));
        return;
    }
    let mut references = HashSet::new();
    for job in jobs {
        collect_references(job, &mut references);
    }
    let active = root.join("active");
    if fs::symlink_metadata(&active).is_ok() {
        let read_active = || -> Result<Vec<String>, String> {
            no_symlinks(&active)?;
            let mut rows = Vec::new();
            for entry in fs::read_dir(&active).map_err(|e| e.to_string())? {
                let path = entry.map_err(|e| e.to_string())?.path();
                no_symlinks(&path)?;
                if path.is_file() {
                    rows.push(fs::read_to_string(path).map_err(|e| e.to_string())?);
                }
            }
            Ok(rows)
        };
        match read_active() {
            Ok(rows) => references.extend(rows),
            Err(reason) => {
                log(&format!(
                    "refused cleanup: unreadable active references: {reason}"
                ));
                return;
            }
        }
    }
    let entries = match fs::read_dir(&stage_root) {
        Ok(entries) => entries,
        Err(reason) => {
            log(&format!("refused staging root: {reason}"));
            return;
        }
    };
    for entry in entries {
        match entry {
            Ok(entry) => {
                if let Err(reason) = cleanup_candidate(
                    &stage_root,
                    &entry.path(),
                    &references,
                    config,
                    now,
                    &mut log,
                ) {
                    log(&format!("refused path={:?}: {reason}", entry.file_name()));
                }
            }
            Err(reason) => log(&format!("refused staging entry: {reason}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct CleanupFixture {
        root: PathBuf,
        stage: PathBuf,
    }
    impl CleanupFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "store-cleanup-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let stage = staging(&root.join("staging")).unwrap();
            fs::write(stage.join("marker"), "[R]").unwrap();
            Self { root, stage }
        }
        fn run(&self, jobs: &[Value], elapsed: u64) -> Vec<String> {
            let mut events = Vec::new();
            let now = fs::metadata(&self.stage).unwrap().modified().unwrap()
                + Duration::from_secs(elapsed);
            cleanup(&self.root, jobs, &Config::default(), now, |event| {
                events.push(event.to_owned())
            });
            events
        }
    }
    impl Drop for CleanupFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
    #[test]
    fn staging_grace_default_reads_one_hour() {
        assert_eq!(
            Config::from_value(&json!({})).staging_grace,
            Duration::from_secs(3600)
        );
        assert_eq!(
            Config::from_value(&json!({"store":{"staging_grace_secs":90}})).staging_grace,
            Duration::from_secs(90)
        );
    }
    #[test]
    fn staging_pattern_mismatch_kept() {
        let fixture = CleanupFixture::new();
        for name in [
            ".stage-no-1",
            ".stage-1-",
            ".stage-1-2-extra",
            "stage-1-2",
            ".stage--2",
        ] {
            fs::create_dir(fixture.root.join("staging").join(name)).unwrap();
        }
        fixture.run(&[], 7200);
        for name in [
            ".stage-no-1",
            ".stage-1-",
            ".stage-1-2-extra",
            "stage-1-2",
            ".stage--2",
        ] {
            assert!(fixture.root.join("staging").join(name).is_dir());
        }
    }
    #[test]
    fn staging_referenced_dir_kept() {
        let fixture = CleanupFixture::new();
        for state in ["queued", "running", "leased"] {
            assert!(fixture.run(&[json!({"state":state,"spec":{"cartridge_directory":fixture.stage.join("files")}})], 7200).is_empty());
            assert!(fixture.stage.exists());
        }
        fs::create_dir(fixture.root.join("active")).unwrap();
        fs::write(
            fixture.root.join("active/render-blender"),
            fixture.stage.to_str().unwrap(),
        )
        .unwrap();
        assert!(fixture.run(&[], 7200).is_empty());
        assert!(fixture.stage.exists());
    }
    #[test]
    fn staging_younger_than_grace_kept() {
        let fixture = CleanupFixture::new();
        assert!(fixture.run(&[], 3599).is_empty());
        assert!(fixture.run(&[], 3600).is_empty());
        assert!(fixture.stage.exists());
    }
    #[test]
    fn staging_symlink_refused() {
        use std::os::unix::fs::symlink;
        let fixture = CleanupFixture::new();
        let outside = fixture.root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("marker"), "[R]").unwrap();
        let link = fixture.root.join("staging/.stage-999-1");
        symlink(&outside, &link).unwrap();
        symlink(&outside, fixture.stage.join("nested")).unwrap();
        let events = fixture.run(&[], 7200);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.contains("symlink refused"))
                .count(),
            2
        );
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(outside.join("marker")).unwrap(), b"[R]");
        assert!(fixture.stage.exists());
    }
    #[test]
    fn staging_outside_root_refused() {
        let fixture = CleanupFixture::new();
        let outside = fixture.root.join(".stage-999-2");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("marker"), "[R]").unwrap();
        let result = cleanup_candidate(
            &fixture.root.join("staging"),
            &outside,
            &HashSet::new(),
            &Config::default(),
            SystemTime::now() + Duration::from_secs(7200),
            &mut |_| panic!("outside removal logged"),
        );
        assert_eq!(result.unwrap_err(), "outside staging root refused");
        fixture.run(&[], 7200);
        assert_eq!(fs::read(outside.join("marker")).unwrap(), b"[R]");
    }
    #[test]
    fn staging_qualifying_removed_and_logged() {
        let fixture = CleanupFixture::new();
        let name = fixture.stage.file_name().unwrap().to_str().unwrap();
        let events = fixture.run(&[], 7200);
        assert!(!fixture.stage.exists());
        assert_eq!(
            events,
            vec![format!(
                "removed path={name} age_secs=7200 reason=abandoned-unreferenced-staging"
            )]
        );
    }

    struct CrashFixture {
        temp: CleanupFixture,
        manifest: PathBuf,
        source: PathBuf,
        previous: String,
    }
    impl CrashFixture {
        fn new() -> Self {
            let temp = CleanupFixture::new();
            let source = temp.root.join("source");
            fs::create_dir(&source).unwrap();
            let manifest = temp.root.join("input.json");
            let mut fixture = Self {
                temp,
                manifest,
                source,
                previous: String::new(),
            };
            fixture.write(b"abc");
            fixture.previous =
                install(&fixture.temp.root, &fixture.manifest, &fixture.source).unwrap();
            swap(&fixture.temp.root, "render-blender", &fixture.previous).unwrap();
            fixture
        }
        fn write(&self, bytes: &[u8]) -> String {
            fs::write(self.source.join("weights"), bytes).unwrap();
            let data = serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":bytes.len(),"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":digest(bytes)}})).unwrap();
            fs::write(&self.manifest, &data).unwrap();
            digest(&data)
        }
        fn restart(&self) -> Store {
            Store::open(&self.temp.root)
        }
        fn assert_previous(&self, store: &Store) {
            let (_, files, hash) = store.active_version("render-blender").unwrap();
            assert_eq!(hash, self.previous);
            assert_eq!(fs::read(files.join("weights")).unwrap(), b"abc");
            assert_eq!(
                fs::read_to_string(self.temp.root.join("active/render-blender")).unwrap(),
                self.previous
            );
        }
    }
    fn run34_recovery(truncated: bool) {
        let fixture = CrashFixture::new();
        let root = &fixture.temp.root;
        fixture.write(b"def");
        let second = install(root, &fixture.manifest, &fixture.source).unwrap();
        swap(root, "render-blender", &second).unwrap();
        fixture.write(b"ghi");
        let damaged = install(root, &fixture.manifest, &fixture.source).unwrap();
        let path = root.join("versions").join(&damaged).join("manifest.json");
        let mut bytes = fs::read(&path).unwrap();
        if truncated {
            bytes.truncate(bytes.len() / 2);
        } else {
            let mut doc: Value = serde_json::from_slice(&bytes).unwrap();
            doc["size_bytes"] = json!(4);
            bytes = serde_json::to_vec(&doc).unwrap();
        }
        fs::write(&path, &bytes).unwrap();
        fn inventory(
            root: &Path,
            dir: &Path,
            out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
        ) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                assert!(!entry.file_type().unwrap().is_symlink());
                if entry.file_type().unwrap().is_dir() {
                    inventory(root, &entry.path(), out);
                } else {
                    out.insert(
                        entry.path().strip_prefix(root).unwrap().to_owned(),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        let mut before = std::collections::BTreeMap::new();
        inventory(root, root, &mut before);
        let store = fixture.restart();
        let refusal = store.version("render-blender", &damaged).unwrap_err();
        assert_eq!(refusal, crate::error_catalog::HASH_MISMATCH);
        assert!(crate::error_catalog::lookup(None, &refusal).is_some());
        assert_eq!(swap(root, "render-blender", &damaged).unwrap_err(), refusal);
        assert_eq!(store.active_version("render-blender").unwrap().2, second);
        for (hash, content) in [(&fixture.previous, b"abc"), (&second, b"def")] {
            let (_, files, actual) = store.version("render-blender", hash).unwrap();
            assert_eq!(&actual, hash);
            assert!(files.starts_with(root));
            assert_eq!(fs::read(files.join("weights")).unwrap(), content);
        }
        let mut after = std::collections::BTreeMap::new();
        inventory(root, root, &mut after);
        assert_eq!(before, after, "refusal and recovery must not write");
    }
    #[test]
    fn run34_store_truncated_record_preserves_earlier_records() {
        run34_recovery(true);
    }
    #[test]
    fn run34_store_checksum_mismatch_preserves_earlier_records() {
        run34_recovery(false);
    }

    #[test]
    fn store_crash_before_staging_rename_keeps_previous_pointer() {
        let fixture = CrashFixture::new();
        let next = fixture.write(b"def");
        let before = fixture.restart();
        assert_eq!(
            install_inner(&fixture.temp.root, &fixture.manifest, &fixture.source, true)
                .unwrap_err(),
            "simulated interruption before version rename"
        );
        drop(before);
        fixture.assert_previous(&fixture.restart());
        assert!(!fixture.temp.root.join("versions").join(next).exists());
        assert!(fs::read_dir(fixture.temp.root.join("staging"))
            .unwrap()
            .any(|entry| entry.unwrap().path().join("manifest.json").is_file()));
    }
    #[test]
    fn store_crash_before_pointer_rename_keeps_previous_pointer() {
        let fixture = CrashFixture::new();
        let next = fixture.write(b"def");
        install(&fixture.temp.root, &fixture.manifest, &fixture.source).unwrap();
        let before = fixture.restart();
        assert_eq!(
            swap_inner(&fixture.temp.root, "render-blender", &next, true).unwrap_err(),
            "simulated interruption before pointer rename"
        );
        drop(before);
        fixture.assert_previous(&fixture.restart());
        assert!(fs::read_dir(fixture.temp.root.join("staging"))
            .unwrap()
            .any(|entry| {
                fs::read_to_string(entry.unwrap().path().join("pointer"))
                    .ok()
                    .as_deref()
                    == Some(&next)
            }));
        swap(&fixture.temp.root, "render-blender", &next).unwrap();
        assert_eq!(
            fixture
                .restart()
                .active_version("render-blender")
                .unwrap()
                .2,
            next
        );
    }
    #[test]
    fn store_restart_ignores_half_published_version() {
        let fixture = CrashFixture::new();
        let next = fixture.write(b"def");
        assert!(
            install_inner(&fixture.temp.root, &fixture.manifest, &fixture.source, true).is_err()
        );
        let incomplete = fixture.temp.root.join("versions").join(&next);
        fs::create_dir(&incomplete).unwrap();
        fs::copy(&fixture.manifest, incomplete.join("manifest.json")).unwrap();
        let restarted = fixture.restart();
        fixture.assert_previous(&restarted);
        assert!(swap(&fixture.temp.root, "render-blender", &next).is_err());
        fixture.assert_previous(&fixture.restart());
        // Even a corrupt pointer cannot expose the incomplete version.
        fs::write(fixture.temp.root.join("active/render-blender"), &next).unwrap();
        assert!(fixture.restart().active_version("render-blender").is_err());
    }
    #[test]
    fn store_cleanup_never_removes_job_referenced_version() {
        let fixture = CrashFixture::new();
        let next = fixture.write(b"def");
        assert!(
            install_inner(&fixture.temp.root, &fixture.manifest, &fixture.source, true).is_err()
        );
        let staged = fs::read_dir(fixture.temp.root.join("staging"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.join("manifest.json").is_file())
            .unwrap();
        let staged_manifest = staged.join("manifest.json");
        let jobs = [
            json!({"state":"queued","spec":{"cartridge_manifest_sha256":next}}),
            json!({"state":"running","cartridge_manifest_sha256":fixture.previous}),
        ];
        let now = SystemTime::now() + Duration::from_secs(7200);
        cleanup(&fixture.temp.root, &jobs, &Config::default(), now, |_| {});
        assert!(staged_manifest.is_file());
        install(&fixture.temp.root, &fixture.manifest, &fixture.source).unwrap();
        swap(&fixture.temp.root, "render-blender", &next).unwrap();
        cleanup(&fixture.temp.root, &jobs, &Config::default(), now, |_| {});
        assert!(staged_manifest.is_file());
        assert!(fixture
            .temp
            .root
            .join("versions")
            .join(&fixture.previous)
            .join("manifest.json")
            .is_file());
        assert!(fixture
            .temp
            .root
            .join("versions")
            .join(&next)
            .join("files/weights")
            .is_file());
        assert_eq!(
            fixture
                .restart()
                .active_version("render-blender")
                .unwrap()
                .2,
            next
        );
        // The digest in an active pointer also protects a staged duplicate.
        cleanup(&fixture.temp.root, &[], &Config::default(), now, |_| {});
        assert!(staged_manifest.is_file());
    }

    #[test]
    fn interruptions_preserve_previous_active_version() {
        let root = std::env::temp_dir().join(format!(
            "lane-interrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        let manifest = root.join("input.json");
        let write_fixture = |bytes: &[u8]| {
            fs::write(source.join("weights"), bytes).unwrap();
            let data = serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":bytes.len(),"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":digest(bytes)}})).unwrap();
            fs::write(&manifest, &data).unwrap();
            digest(&data)
        };
        let store = root.join("store");
        let previous = write_fixture(b"abc");
        install(&store, &manifest, &source).unwrap();
        swap(&store, "render-blender", &previous).unwrap();
        let next = write_fixture(b"def");
        assert!(install_inner(&store, &manifest, &source, true).is_err());
        assert!(!store.join("versions").join(&next).exists());
        assert_eq!(
            active_version(&store, "render-blender").unwrap().2,
            previous
        );
        install(&store, &manifest, &source).unwrap();
        assert!(swap_inner(&store, "render-blender", &next, true).is_err());
        assert_eq!(
            active_version(&store, "render-blender").unwrap().2,
            previous
        );
    }
    #[test]
    fn concurrent_installs_publish_complete_version() {
        let root = crate::test_process::target_dir().join(format!(
            "install-concurrent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("weights"), b"abc").unwrap();
        let manifest = root.join("input.json");
        let data = serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":digest(b"abc")}})).unwrap();
        fs::write(&manifest, &data).unwrap();
        let store = root.join("store");
        let results = std::thread::scope(|scope| {
            let a = scope.spawn(|| install(&store, &manifest, &source));
            let b = scope.spawn(|| install(&store, &manifest, &source));
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let hash = digest(&data);
        swap(&store, "render-blender", &hash).unwrap();
        assert_eq!(active_version(&store, "render-blender").unwrap().2, hash);
    }
    #[test]
    fn install_swap_and_failed_swap_preserves_pointer() {
        let root = std::env::temp_dir().join(format!(
            "lane-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("weights"), b"abc").unwrap();
        let manifest = root.join("input.json");
        fs::write(&manifest, serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":digest(b"abc")}})).unwrap()).unwrap();
        let store = root.join("store");
        let hash = install(&store, &manifest, &source).unwrap();
        swap(&store, "render-blender", &hash).unwrap();
        let (selected, files, selected_hash) = active_version(&store, "render-blender").unwrap();
        assert_eq!(selected_hash, hash);
        assert_eq!(
            selected,
            store.join("versions").join(&hash).join("manifest.json")
        );
        assert_eq!(files, store.join("versions").join(&hash).join("files"));
        assert!(active_version(&store, "../invalid").is_err());
        assert_eq!(
            fs::read_to_string(store.join("active/render-blender")).unwrap(),
            hash
        );
        fs::write(
            store.join("versions").join(&hash).join("files/weights"),
            b"xyz",
        )
        .unwrap();
        assert!(swap(&store, "render-blender", &hash).is_err());
        assert_eq!(
            fs::read_to_string(store.join("active/render-blender")).unwrap(),
            hash
        );
    }
    #[test]
    fn publication_failure_preserves_pointer() {
        let root = std::env::temp_dir().join(format!(
            "lane-store-fail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("weights"), b"abc").unwrap();
        let manifest = root.join("input.json");
        fs::write(&manifest, serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":digest(b"abc")}})).unwrap()).unwrap();
        let store = root.join("store");
        let hash = install(&store, &manifest, &source).unwrap();
        swap(&store, "render-blender", &hash).unwrap();
        // A nonempty destination prevents publication without relying on permissions.
        assert!(install(&store, &manifest, &source).is_err());
        assert_eq!(
            fs::read_to_string(store.join("active/render-blender")).unwrap(),
            hash
        );
        assert!(swap(&store, "render-blender", &"0".repeat(64)).is_err());
        assert_eq!(
            fs::read_to_string(store.join("active/render-blender")).unwrap(),
            hash
        );
    }

    #[test]
    fn concurrent_swaps_leave_complete_pointer() {
        let root = crate::test_process::target_dir().join(format!(
            "store-concurrent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("weights"), b"abc").unwrap();
        let manifest = root.join("input.json");
        fs::write(&manifest, serde_json::to_vec(&json!({"id":"blender-4.5.14-cycles","lane":"render-blender","size_bytes":3,"min_vram_mb":1,"min_ram_mb":1,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{"weights":digest(b"abc")}})).unwrap()).unwrap();
        let store = root.join("store");
        let hash = install(&store, &manifest, &source).unwrap();
        std::thread::scope(|scope| {
            let a = scope.spawn(|| swap(&store, "render-blender", &hash));
            let b = scope.spawn(|| swap(&store, "render-blender", &hash));
            a.join().unwrap().unwrap();
            b.join().unwrap().unwrap();
        });
        assert_eq!(active_version(&store, "render-blender").unwrap().2, hash);
    }
}
