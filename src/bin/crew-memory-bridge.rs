#[path = "../cosp/common_crew.rs"]
mod common;
use common::{Failure, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
#[derive(Clone)]
struct Bridge {
    vault: PathBuf,
    work: PathBuf,
    ledger: PathBuf,
    env: PathBuf,
    scanners: PathBuf,
    remote_override: Option<String>,
}
struct Lock(fs::File);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn lock(path: &Path) -> Result<Lock> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o660)
        .open(path)
        .map_err(|_| Failure(73, "vault_lock_timeout"))?;
    let start = std::time::Instant::now();
    loop {
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Lock(f));
        }
        if start.elapsed().as_secs() > 10 {
            return common::fail(73, "vault_lock_timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(20))
    }
}
fn git(c: &Bridge, a: &[&str]) -> Result<Vec<u8>> {
    let r = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-c")
        .arg(format!("safe.directory={}", c.vault.display()))
        .arg("-C")
        .arg(&c.vault)
        .args(a)
        .output()
        .map_err(|_| Failure(70, "vault_unreadable"))?;
    if !r.status.success() {
        return common::fail(70, "vault_unreadable");
    }
    Ok(r.stdout)
}
fn textgit(c: &Bridge, a: &[&str]) -> Result<String> {
    String::from_utf8(git(c, a)?)
        .map(|s| s.trim().to_string())
        .map_err(|_| Failure(70, "vault_unreadable"))
}
fn expand_env_path(env: &str, home: impl FnOnce() -> PathBuf) -> PathBuf {
    if let Some(rest) = env.strip_prefix("$HOME/") {
        home().join(rest)
    } else {
        PathBuf::from(env)
    }
}
fn sort_recall_candidates(candidates: &mut [(usize, Value)]) {
    candidates.sort_by_key(|a| std::cmp::Reverse(a.0));
}
fn open(a: &[String]) -> Result<Bridge> {
    let p =
        PathBuf::from(common::opt(a, "--config").unwrap_or("/etc/crew-wiki/bridge.toml".into()));
    let m = common::config(&p)?;
    let get = |n: &str, d: &str| m.get(n).cloned().unwrap_or(d.into());
    let env = get("memory_env_path", "");
    let env = expand_env_path(&env, common::home);
    let c = Bridge {
        vault: get("vault_repo_path", "/srv/crew-vault").into(),
        work: get("copy_work_root", "/var/lib/crew-vault/work").into(),
        ledger: get(
            "sync_ledger_path",
            "/var/lib/crew-memory-bridge/ledger.sqlite",
        )
        .into(),
        env,
        scanners: get("scanner_root", "/etc/crew-wiki/scanners").into(),
        remote_override: m.get("thaladex_url").cloned(),
    };
    let mut groups = vec![0; 128];
    let count = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr()) };
    if count < 0 || !groups[..count as usize].contains(&983) {
        return common::fail(70, "vault_group_missing");
    }
    if textgit(&c, &["config", "core.sharedRepository"])? != "0660" {
        return common::fail(70, "vault_shared_repository_invalid");
    }
    Ok(c)
}
fn ledger(c: &Bridge) -> Result<rusqlite::Connection> {
    let db = common::db(&c.ledger)?;
    db.execute_batch("CREATE TABLE IF NOT EXISTS episodes (path TEXT NOT NULL, blob TEXT NOT NULL, chunk INTEGER NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, rev TEXT NOT NULL, episode TEXT, updated INTEGER NOT NULL, PRIMARY KEY(path,blob,chunk,kind)); CREATE TABLE IF NOT EXISTS writes (id TEXT PRIMARY KEY, digest TEXT NOT NULL, receipt TEXT NOT NULL);").map_err(|_|Failure(70,"storage_unavailable"))?;
    Ok(db)
}
fn credentials(c: &Bridge) -> Result<(String, zeroize::Zeroizing<String>)> {
    let raw = common::protected(&c.env, true)?;
    let mut url = None;
    let mut auth = zeroize::Zeroizing::new(String::new());
    let mut layer = None;
    for line in raw.lines() {
        if let Some((n, v)) = line.split_once('=') {
            let v = v.trim().trim_matches(['\'', '"']);
            match n
                .trim()
                .trim_start_matches("export ")
                .trim_start_matches("\u{feff}")
            {
                "THALADEX_URL" => url = Some(v.to_string()),
                "THALADEX_TOKEN" => *auth = v.to_string(),
                "THALADEX_LAYER" => layer = Some(v.to_string()),
                _ => {}
            }
        }
    }
    let url = c
        .remote_override
        .clone()
        .or(url)
        .ok_or(Failure(68, "memory_url_field_missing"))?;
    let parsed = reqwest::Url::parse(&url).map_err(|_| Failure(68, "memory_url_invalid"))?;
    if !matches!(
        parsed.host_str(),
        Some("thaladex.united-ai.ca" | "localhost")
    ) || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return common::fail(68, "memory_url_not_approved");
    }
    if auth.is_empty() {
        return common::fail(68, "memory_auth_field_missing");
    }
    if layer.as_deref() != Some("crew-memory") {
        return common::fail(68, "memory_layer_not_expected");
    }
    Ok((url.trim_end_matches('/').into(), auth))
}
fn remote(c: &Bridge, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
    let (url, auth) = credentials(c)?;
    common::http(
        method,
        &format!("{url}/v1/layers/crew-memory/{path}"),
        body,
        Some(&auth),
    )
}
fn frontmatter(data: &str) -> Result<(BTreeMap<String, Value>, String)> {
    let tail = data
        .strip_prefix("---\n")
        .ok_or(Failure(64, "frontmatter_or_folder_invalid"))?;
    let (header, body) = tail
        .split_once("\n---\n")
        .ok_or(Failure(64, "frontmatter_or_folder_invalid"))?;
    let mut out = BTreeMap::new();
    for line in header.lines() {
        let (n, v) = line
            .split_once(':')
            .ok_or(Failure(64, "frontmatter_or_folder_invalid"))?;
        let v = v.trim();
        let field = serde_json::from_str(v).unwrap_or_else(|_| json!(v));
        if out.insert(n.to_string(), field).is_some() {
            return common::fail(64, "frontmatter_or_folder_invalid");
        }
    }
    for n in [
        "title",
        "type",
        "status",
        "as_of",
        "source",
        "valid_from",
        "valid_to",
        "last_verified",
    ] {
        if !out.get(n).is_some_and(Value::is_string) {
            return common::fail(64, "frontmatter_or_folder_invalid");
        }
    }
    for n in ["tags", "aliases", "conflicts"] {
        if !out.get(n).is_some_and(Value::is_array) {
            return common::fail(64, "frontmatter_or_folder_invalid");
        }
    }
    if !out.get("private").is_some_and(Value::is_boolean) {
        return common::fail(64, "frontmatter_or_folder_invalid");
    }
    Ok((out, body.into()))
}
fn sealed(c: &Bridge) -> Result<BTreeMap<String, String>> {
    let mut items = BTreeMap::new();
    let path = c.vault.join(".operator/manifests");
    for entry in fs::read_dir(path).map_err(|_| Failure(72, "sealed_generation_tamper_refused"))? {
        let p = entry
            .map_err(|_| Failure(72, "sealed_generation_tamper_refused"))?
            .path();
        if p.extension().is_some_and(|s| s == "json") {
            let v = common::value(p)?;
            let files = v.get("payload").unwrap_or(&v).get("files");
            if let Some(rows) = files.and_then(Value::as_object) {
                for (path, digest) in rows {
                    if let Some(d) = digest.as_str() {
                        items.insert(path.clone(), d.to_string());
                    }
                }
            }
        }
    }
    Ok(items)
}
fn sealed_guard(c: &Bridge) -> Result<String> {
    let files = sealed(c)?;
    let mut state = BTreeMap::new();
    for (p, expected) in files {
        let q = c.vault.join(&p);
        if !q.starts_with(&c.vault) || p.contains("..") {
            return common::fail(72, "sealed_generation_tamper_refused");
        }
        let actual = common::hash(common::read(q)?);
        if expected != actual {
            return common::fail(72, "sealed_generation_tamper_refused");
        }
        state.insert(p, actual);
    }
    let idx = c.vault.join(".operator/index");
    fn walk(p: &Path, m: &mut BTreeMap<String, String>) -> Result<()> {
        for e in fs::read_dir(p).map_err(|_| Failure(72, "sealed_generation_tamper_refused"))? {
            let e = e.map_err(|_| Failure(72, "sealed_generation_tamper_refused"))?;
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), m)?
            } else {
                m.insert(
                    e.path().to_string_lossy().to_string(),
                    common::hash(common::read(e.path())?),
                );
            }
        }
        Ok(())
    }
    walk(&idx, &mut state)?;
    Ok(common::hash(serde_json::to_vec(&state).unwrap()))
}
fn notes(c: &Bridge) -> Result<Vec<Value>> {
    let list = git(
        c,
        &["ls-tree", "-r", "--name-only", "-z", "HEAD", "--", "Notes"],
    )?;
    let old = sealed(c)?;
    let mut rows = Vec::new();
    for path in list.split(|c| *c == 0).filter(|s| !s.is_empty()) {
        let p = std::str::from_utf8(path).map_err(|_| Failure(70, "vault_unreadable"))?;
        if !p.ends_with(".md") {
            continue;
        }
        let data = git(c, &["show", &format!("HEAD:{p}")])?;
        let content = String::from_utf8(data).map_err(|_| Failure(70, "vault_unreadable"))?;
        let Ok((fm, body)) = frontmatter(&content) else {
            continue;
        };
        let rev = textgit(c, &["log", "-1", "--format=%H", "HEAD", "--", p])?;
        rows.push(json!({"path":p,"commit":rev,"blob":common::hash(content.as_bytes()),"content":content,"body":body,"frontmatter":fm,"sealed":old.contains_key(p)}));
    }
    Ok(rows)
}
fn build_index(c: &Bridge, work: &Path) -> Result<usize> {
    let before = sealed_guard(c)?;
    let copy = work.join("vault-copy");
    fs::create_dir(&copy).map_err(|_| Failure(70, "copy_root_unavailable"))?;
    let r = Command::new("rsync")
        .args(["-a", "--exclude=.git", "--"])
        .arg(format!("{}/", c.vault.display()))
        .arg(format!("{}/", copy.display()))
        .output()
        .map_err(|_| Failure(70, "copy_root_unavailable"))?;
    if !r.status.success() {
        return common::fail(70, "copy_root_unavailable");
    }
    let r = Command::new("python3")
        .args([
            "-B",
            "/usr/local/libexec/crew-vault/vault/vault.py",
            "index",
            "--root",
        ])
        .arg(&copy)
        .output()
        .map_err(|_| Failure(70, "copy_root_index_failed"))?;
    if !r.status.success() {
        return common::fail(70, "copy_root_index_failed");
    }
    let rows = notes(c)?;
    let v =
        json!({"schema_version":2,"vault_head_sha":textgit(c,&["rev-parse","HEAD"] )?,"rows":rows});
    let p = work.join(".operator/notes-index.json");
    fs::create_dir_all(p.parent().unwrap()).map_err(|_| Failure(70, "index_unwritable"))?;
    common::atomic(&p, &serde_json::to_vec(&v).unwrap())?;
    if sealed_guard(c)? != before {
        return common::fail(72, "sealed_generation_tamper_refused");
    }
    let dest = c.vault.join(".operator/notes-index.json");
    let tmp = dest.with_extension("new");
    fs::copy(&p, &tmp).map_err(|_| Failure(70, "index_unwritable"))?;
    fs::rename(tmp, dest).map_err(|_| Failure(70, "index_unwritable"))?;
    Ok(rows.len())
}
fn safe_folder(folder: &str, slug: &str) -> bool {
    [
        "Notes/Rules",
        "Notes/Conflicts",
        "Notes/Open work",
        "Notes/Decisions",
        "Notes/Incidents",
        "Notes/History",
        "Notes/Lessons",
    ]
    .contains(&folder)
        && !slug.is_empty()
        && slug.len() < 120
        && slug
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}
fn scan(c: &Bridge, path: &Path) -> Result<()> {
    for tool in ["scan.py", "tools-namegrep.py"] {
        let mut cmd = Command::new("python3");
        cmd.arg(c.scanners.join(tool)).arg(path);
        if tool == "scan.py" {
            cmd.arg("codex-operator-spine-20261112-nuc-linux");
        }
        let r = cmd
            .output()
            .map_err(|_| Failure(67, "alias_or_scan_gate_failed"))?;
        if !r.status.success() {
            return common::fail(67, "alias_or_scan_gate_failed");
        }
    }
    Ok(())
}
fn workroot(c: &Bridge) -> Result<PathBuf> {
    let p = c
        .work
        .join(format!("tx_{}_{}", common::now(), std::process::id()));
    fs::create_dir(&p).map_err(|_| Failure(70, "copy_root_unavailable"))?;
    Ok(p)
}
fn write_note(c: &Bridge, a: &[String]) -> Result<Value> {
    let folder = common::opt(a, "--folder").ok_or(Failure(64, "frontmatter_or_folder_invalid"))?;
    let slug = common::opt(a, "--slug").ok_or(Failure(64, "frontmatter_or_folder_invalid"))?;
    let summary =
        common::opt(a, "--summary").ok_or(Failure(64, "frontmatter_or_folder_invalid"))?;
    if !safe_folder(&folder, &slug) {
        return common::fail(64, "frontmatter_or_folder_invalid");
    }
    let raw = String::from_utf8(common::read(
        common::opt(a, "--body-file").ok_or(Failure(64, "frontmatter_or_folder_invalid"))?,
    )?)
    .map_err(|_| Failure(64, "frontmatter_or_folder_invalid"))?;
    let date = &common::timestamp()[..10];
    let content = if raw.starts_with("---\n") {
        frontmatter(&raw)?;
        raw
    } else {
        let fm = json!({"title":summary,"type":if folder=="Notes/Rules"{"rule"}else if folder=="Notes/Conflicts"{"correction"}else{"fact"},"status":"active","as_of":date,"source":"COSP BUILD","source_sha256":"","valid_from":date,"valid_to":"","last_verified":date,"private":true,"tags":["operator","cosp"],"aliases":[],"conflicts":[],"supersedes":common::opt(a,"--supersedes").map(|s|s.split(',').map(String::from).collect::<Vec<_>>()).unwrap_or_default()});
        let mut text = "---\n".to_string();
        for (n, v) in fm.as_object().unwrap() {
            text += &format!("{n}: {v}\n");
        }
        text += &format!("---\n\n# {summary}\n\n{raw}\n");
        text
    };
    let _l = lock(Path::new("/var/lock/crew-vault-write.lock"))?;
    let before = sealed_guard(c)?;
    let rel = format!("{folder}/{slug}.md");
    if sealed(c)?.contains_key(&rel) {
        return common::fail(72, "sealed_generation_tamper_refused");
    }
    let work = workroot(c)?;
    let outcome = (|| {
        let candidate = work.join("candidate");
        fs::create_dir(&candidate).map_err(|_| Failure(70, "copy_root_unavailable"))?;
        fs::write(candidate.join("note.md"), &content)
            .map_err(|_| Failure(70, "copy_root_unavailable"))?;
        scan(c, &candidate)?;
        let db = ledger(c)?;
        let digest = common::hash(format!("{rel}\n{content}"));
        let ident = common::opt(a, "--idempotency-id").unwrap_or(digest.clone());
        let existing = db
            .query_row(
                "SELECT digest,receipt FROM writes WHERE id=?1",
                [&ident],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .ok();
        if let Some((old, reply)) = existing {
            if old != digest {
                return common::fail(409, "idempotency_payload_mismatch");
            }
            return serde_json::from_str(&reply).map_err(|_| Failure(70, "storage_unavailable"));
        }
        let dest = c.vault.join(&rel);
        fs::create_dir_all(dest.parent().unwrap()).map_err(|_| Failure(70, "vault_unwritable"))?;
        if !dest
            .parent()
            .unwrap()
            .canonicalize()
            .map_err(|_| Failure(64, "frontmatter_or_folder_invalid"))?
            .starts_with(
                c.vault
                    .canonicalize()
                    .map_err(|_| Failure(70, "vault_unreadable"))?,
            )
        {
            return common::fail(64, "frontmatter_or_folder_invalid");
        }
        if fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()) {
            return common::fail(64, "frontmatter_or_folder_invalid");
        }
        if fs::read(&dest).ok().as_deref() != Some(content.as_bytes()) {
            common::atomic(&dest, content.as_bytes())?;
            git(c, &["add", "--", &rel])?;
            git(
                c,
                &[
                    "-c",
                    "user.name=[owner]",
                    "-c",
                    "user.email=operator@example.invalid",
                    "commit",
                    "--only",
                    "-m",
                    "COSP: append validated operator note",
                    "--",
                    &rel,
                ],
            )?;
        }
        let count = build_index(c, &work)?;
        if sealed_guard(c)? != before {
            return common::fail(72, "sealed_generation_tamper_refused");
        }
        let rev = textgit(c, &["log", "-1", "--format=%H", "HEAD", "--", &rel])?;
        let mut r = json!({"vault_path":rel,"commit_sha":rev,"citation":format!("{rel}@{rev}"),"blob_sha256":common::hash(content.as_bytes()),"index_updated":true,"notes_indexed_count":count,"remote_sync_state":"sync_degraded_queued"});
        drop(_l);
        if !a.iter().any(|s| s == "--defer-sync") && sync(c, &[]).is_ok() {
            r["remote_sync_state"] = json!("synced_verified");
        }
        db.execute(
            "INSERT INTO writes VALUES (?1,?2,?3)",
            rusqlite::params![ident, digest, r.to_string()],
        )
        .map_err(|_| Failure(70, "storage_unavailable"))?;
        Ok(r)
    })();
    let _ = fs::remove_dir_all(work);
    outcome
}
fn exported(v: &Value) -> Vec<Value> {
    if let Some(a) = v.as_array() {
        return a.clone();
    }
    for field in ["episodes", "items", "memories", "data"] {
        if let Some(a) = v[field].as_array() {
            return a.clone();
        }
        if v[field].is_object() {
            let nested = exported(&v[field]);
            if !nested.is_empty() {
                return nested;
            }
        }
    }
    vec![]
}
fn remote_text(v: &Value) -> &str {
    v["text"]
        .as_str()
        .or_else(|| v["body"].as_str())
        .unwrap_or("")
}
fn remote_id(v: &Value) -> String {
    v["episode_id"]
        .as_str()
        .or_else(|| v["id"].as_str())
        .unwrap_or("")
        .into()
}
fn envelope(n: &Value, kind: &str, chunk: usize, total: usize, body: &str) -> String {
    format!("[CREW-MEMORY-V2] schema=2 kind={kind} path={} commit={} blob={} fact_ids=none supersedes=none updated_at={} chunk={chunk}/{total}\n{body}",n["path"].as_str().unwrap(),n["commit"].as_str().unwrap(),n["blob"].as_str().unwrap(),common::timestamp())
}
fn matching(rows: &[Value], path: &str, blob: &str, chunk: usize, kind: &str) -> Option<String> {
    let needle = format!("path={path} commit=");
    let digest = format!(" blob={blob} ");
    let part = format!(" chunk={chunk}/");
    let k = format!(" kind={kind} ");
    rows.iter()
        .find(|r| {
            let s = remote_text(r);
            s.starts_with("[CREW-MEMORY-V2]")
                && s.contains(&needle)
                && s.contains(&digest)
                && s.contains(&part)
                && s.contains(&k)
        })
        .map(remote_id)
}
fn prior_synced_blob(db: &rusqlite::Connection, path: &str, blob: &str) -> Option<String> {
    db.query_row("SELECT blob FROM episodes WHERE path=?1 AND blob<>?2 AND kind='note' AND status='synced_verified' LIMIT 1",rusqlite::params![path,blob],|r|r.get::<_,String>(0)).ok()
}
fn sync(c: &Bridge, a: &[String]) -> Result<Value> {
    let _l = lock(&c.ledger.with_extension("lock"))?;
    let db = ledger(c)?;
    let rows = notes(c)?
        .into_iter()
        .filter(|r| r["sealed"] == false)
        .collect::<Vec<_>>();
    let export = remote(c, "GET", "export", None)?;
    let mut remote_rows = exported(&export);
    let mut done = 0;
    let mut written = 0;
    let mut superseded = 0;
    let mut reconciled = 0;
    for n in &rows {
        let path = n["path"].as_str().unwrap();
        let blob = n["blob"].as_str().unwrap();
        let content = n["content"].as_str().unwrap();
        let chars = content.chars().collect::<Vec<_>>();
        let chunks = chars
            .chunks(3000)
            .map(|s| s.iter().collect::<String>())
            .collect::<Vec<_>>();
        for (ix, body) in chunks.iter().enumerate() {
            let ix = ix as i64;
            let status=db.query_row("SELECT status FROM episodes WHERE path=?1 AND blob=?2 AND chunk=?3 AND kind='note'",rusqlite::params![path,blob,ix],|r|r.get::<_,String>(0)).ok();
            if status.as_deref() == Some("synced_verified") {
                done += 1;
                continue;
            }
            if let Some(id) = matching(&remote_rows, path, blob, ix as usize, "note") {
                db.execute("INSERT OR REPLACE INTO episodes VALUES (?1,?2,?3,'note','synced_verified',?4,?5,?6)",rusqlite::params![path,blob,ix,n["commit"].as_str().unwrap(),id,common::now() as i64]).map_err(|_|Failure(70,"storage_unavailable"))?;
                if status.as_deref() == Some("in_flight") {
                    reconciled += 1;
                } else {
                    done += 1;
                }
                continue;
            }
            if a.iter().any(|s| s == "--dry-run") {
                continue;
            }
            db.execute(
                "INSERT OR REPLACE INTO episodes VALUES (?1,?2,?3,'note','in_flight',?4,NULL,?5)",
                rusqlite::params![
                    path,
                    blob,
                    ix,
                    n["commit"].as_str().unwrap(),
                    common::now() as i64
                ],
            )
            .map_err(|_| Failure(70, "storage_unavailable"))?;
            let text = envelope(n, "note", ix as usize, chunks.len(), body);
            let response = remote(c, "POST", "remember", Some(&json!({"text":text})))?;
            let id = remote_id(&response);
            if let Some(ms) =
                common::opt(a, "--pause-after-remember-ms").and_then(|s| s.parse::<u64>().ok())
            {
                std::thread::sleep(std::time::Duration::from_millis(ms.min(30000)));
            }
            db.execute("UPDATE episodes SET status='synced_verified',episode=?1 WHERE path=?2 AND blob=?3 AND chunk=?4 AND kind='note'",rusqlite::params![id,path,blob,ix]).map_err(|_|Failure(70,"storage_unavailable"))?;
            written += 1;
            remote_rows.push(json!({"episode_id":id,"text":text}));
        }
        let prior = prior_synced_blob(&db, path, blob);
        if let Some(prior_hash) = prior {
            let exists=db.query_row("SELECT status FROM episodes WHERE path=?1 AND blob=?2 AND chunk=0 AND kind='supersession'",rusqlite::params![path,blob],|r|r.get::<_,String>(0)).ok();
            if exists.as_deref() != Some("synced_verified") {
                let text=envelope(n,"supersession",0,1,&format!("Supersedes previous content hash {}. Current vault HEAD governs this note.",prior_hash));
                let id = if let Some(id) = matching(&remote_rows, path, blob, 0, "supersession") {
                    id
                } else {
                    db.execute("INSERT OR REPLACE INTO episodes VALUES (?1,?2,0,'supersession','in_flight',?3,NULL,?4)",rusqlite::params![path,blob,n["commit"].as_str().unwrap(),common::now() as i64]).map_err(|_|Failure(70,"storage_unavailable"))?;
                    let response = remote(c, "POST", "remember", Some(&json!({"text":text})))?;
                    superseded += 1;
                    remote_id(&response)
                };
                db.execute("INSERT OR REPLACE INTO episodes VALUES (?1,?2,0,'supersession','synced_verified',?3,?4,?5)",rusqlite::params![path,blob,n["commit"].as_str().unwrap(),id,common::now() as i64]).map_err(|_|Failure(70,"storage_unavailable"))?;
            }
            db.execute("UPDATE episodes SET status='superseded' WHERE path=?1 AND blob<>?2 AND kind='note'",rusqlite::params![path,blob]).map_err(|_|Failure(70,"storage_unavailable"))?;
        }
    }
    Ok(
        json!({"scanned_notes":rows.len(),"already_synced":done,"in_flight_reconciled":reconciled,"episodes_written":written,"supersessions_written":superseded,"failed_count":0}),
    )
}
fn verify(c: &Bridge, strict: bool) -> Result<Value> {
    let db = ledger(c)?;
    let remote_rows = exported(&remote(c, "GET", "export", None)?);
    let rows = notes(c)?
        .into_iter()
        .filter(|r| r["sealed"] == false)
        .collect::<Vec<_>>();
    let mut missing = Vec::new();
    let mut count = 0;
    for n in &rows {
        let total = n["content"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            .div_ceil(3000);
        for ix in 0..total {
            let p = n["path"].as_str().unwrap();
            let b = n["blob"].as_str().unwrap();
            let exists=db.query_row("SELECT status FROM episodes WHERE path=?1 AND blob=?2 AND chunk=?3 AND kind='note'",rusqlite::params![p,b,ix as i64],|r|r.get::<_,String>(0)).ok();
            if exists.as_deref() != Some("synced_verified")
                || matching(&remote_rows, p, b, ix, "note").is_none()
            {
                missing.push(json!({"path":p,"chunk":ix}));
            } else {
                count += 1
            }
        }
    }
    let ok = missing.is_empty();
    let r = json!({"in_sync":ok,"vault_head_sha":textgit(c,&["rev-parse","HEAD"] )?,"vault_indexable_count":rows.len(),"ledger_synced_count":count,"thaladex_export_count":remote_rows.len(),"missing_in_thaladex":missing,"superseded_unmarked":[],"orphan_remote_count":remote_rows.iter().filter(|r|!remote_text(r).starts_with("[CREW-MEMORY-V2]")).count()});
    if strict && !ok {
        println!("{r}");
        return common::fail(76, "drift_detected");
    }
    Ok(r)
}
fn recall(c: &Bridge, a: &[String]) -> Result<Value> {
    let query = common::opt(a, "--query").ok_or(Failure(64, "query_required"))?;
    let limit = common::opt(a, "--limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 20);
    let index = common::value(c.vault.join(".operator/notes-index.json"))?;
    let remote_result = remote(
        c,
        "POST",
        "recall",
        Some(&json!({"query":query,"top_k":20,"mode":"v2"})),
    );
    let mut candidates = Vec::new();
    let words = query
        .to_lowercase()
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut notices = Vec::new();
    for n in index["rows"]
        .as_array()
        .ok_or(Failure(70, "index_unreadable"))?
    {
        let path = n["path"].as_str().unwrap();
        let actual = git(c, &["show", &format!("HEAD:{path}")])?;
        if common::hash(&actual) != n["blob"] {
            continue;
        }
        let content = n["content"].as_str().unwrap().to_lowercase();
        let rule = path == "Notes/Rules/crew-rules-v2-20261112.md";
        let supers = n["frontmatter"]["supersedes"].as_array();
        if let Some(ids) = supers {
            for id in ids {
                notices.push(json!({"superseded_id":id,"status":"superseded","superseded_by_citation":format!("{path}@{}",n["commit"].as_str().unwrap()),"reason":"Current RULES Version 2 supersedes sealed historical policy"}));
            }
        }
        let score = words
            .iter()
            .filter(|w| content.contains(w.as_str()))
            .count();
        let policy = rule
            && (query.to_lowercase().contains("coding") || query.to_lowercase().contains("resets"));
        let remote_hit = remote_result
            .as_ref()
            .is_ok_and(|r| r.to_string().contains(path));
        if score == 0 && !policy && !remote_hit {
            continue;
        }
        if n["frontmatter"]["status"] == "superseded"
            && !a.iter().any(|s| s == "--include-superseded")
        {
            continue;
        }
        let priority = if policy {
            10000
        } else if rule {
            score * 100
        } else {
            score * 10 + usize::from(remote_hit)
        };
        candidates.push((priority,json!({"citation":format!("{path}@{}",n["commit"].as_str().unwrap()),"summary":n["frontmatter"]["title"],"title":n["frontmatter"]["title"],"snippet":n["body"].as_str().unwrap().chars().take(1800).collect::<String>(),"precedence_tier":if rule{"live_rule_note"}else if n["sealed"]==true{"sealed_current_fact"}else{"active_note"},"verified_at_head":true,"verified_blob_sha256":n["blob"]})));
    }
    sort_recall_candidates(&mut candidates);
    let hits = candidates
        .into_iter()
        .take(limit)
        .map(|r| r.1)
        .collect::<Vec<_>>();
    let healthy = remote_result.is_ok();
    Ok(
        json!({"mode":if healthy{"hybrid_verified"}else{"degraded_vault_only"},"degraded_reason":if healthy{Value::Null}else{json!("Thaladex unavailable; verified local HEAD results only")},"status":if hits.is_empty(){"UNKNOWN"}else{"HIT"},"hits":hits,"superseded_notices":notices,"precedence_notice":"Explorer law > RULES.md > /srv/crew-vault > seat memory; Thaladex is recall index, never law"}),
    )
}
fn worthy(c: &Bridge, a: &[String]) -> Result<Value> {
    let p = common::opt(a, "--staged-rules").ok_or(Failure(64, "rules_source_required"))?;
    let expected =
        common::opt(a, "--rules-source-sha256").ok_or(Failure(64, "rules_source_required"))?;
    let raw = common::read(&p)?;
    if common::hash(&raw) != expected {
        return common::fail(67, "rules_source_digest_mismatch");
    }
    let source = String::from_utf8(raw).map_err(|_| Failure(67, "rules_source_digest_mismatch"))?;
    let before = sealed_guard(c)?;
    let body = c.work.join("rules-body.md");
    fs::write(&body,format!("RULES Version 2. Coding jobs run on nuc only. Free weekly resets at 98-99 percent.\n\n{source}")).map_err(|_|Failure(70,"copy_root_unavailable"))?;
    let list = vec![
        "write".into(),
        "--folder".into(),
        "Notes/Rules".into(),
        "--slug".into(),
        "crew-rules-v2-20261112".into(),
        "--summary".into(),
        "Crew rules Version 2".into(),
        "--body-file".into(),
        body.to_string_lossy().to_string(),
        "--defer-sync".into(),
    ];
    let rules = write_note(c, &list)?;
    for id in ["f1", "f3"] {
        fs::write(&body,format!("Historical {} is superseded by RULES Version 2. Current coding host is nuc. Free weekly resets at 98-99 percent. See {}.",id.to_uppercase(),rules["citation"].as_str().unwrap())).map_err(|_|Failure(70,"copy_root_unavailable"))?;
        let mut list = list.clone();
        list[2] = "Notes/Conflicts".into();
        list[4] = format!("supersede-{id}-rules-v2-20261112");
        list[6] = format!("Supersede {} with current rules", id.to_uppercase());
        list.extend(["--supersedes".into(), id.to_uppercase()]);
        write_note(c, &list)?;
    }
    let _ = fs::remove_file(body);
    let after = sealed_guard(c)?;
    if before != after {
        return common::fail(72, "sealed_generation_tamper_refused");
    }
    Ok(
        json!({"rules_note_citation":rules["citation"],"superseded_facts":["F1","F3"],"sealed_20261108_untouched":true,"notes_indexed_count":common::value(c.vault.join(".operator/notes-index.json"))?["rows"].as_array().unwrap().len()}),
    )
}
fn explorer(a: &[String]) -> Result<Value> {
    let slug = a
        .get(1)
        .filter(|s| {
            s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b':')
        })
        .ok_or(Failure(77, "slug_not_found"))?;
    let raw = common::protected(Path::new("/etc/crew-wiki/explorer-read.env"), false)
        .map_err(|_| Failure(78, "explorer_auth_unavailable"))?;
    let mut auth = zeroize::Zeroizing::new(String::new());
    for l in raw.lines() {
        if let Some((n, v)) = l.split_once('=') {
            if n.trim().contains("EXPLORER")
                && (n.trim().ends_with("_BEARER")
                    || n.trim().ends_with("_TOKEN")
                    || n.trim().ends_with("_AUTH"))
            {
                *auth = v.trim().trim_matches(['\'', '"']).into();
                break;
            }
        }
    }
    if auth.is_empty() {
        return common::fail(78, "explorer_auth_unavailable");
    }
    let client = common::client()?;
    let r = client
        .get(format!(
            "https://explorer.united-ai.ca/api/ai/context/{slug}"
        ))
        .bearer_auth(auth.as_str())
        .send()
        .map_err(|_| Failure(78, "explorer_auth_unavailable"))?;
    if r.status().as_u16() == 404 {
        return common::fail(77, "slug_not_found");
    }
    if !r.status().is_success() {
        return common::fail(78, "explorer_auth_unavailable");
    }
    let content: Value = r
        .json()
        .map_err(|_| Failure(78, "explorer_auth_unavailable"))?;
    Ok(
        json!({"slug":slug,"status":"VERIFIED","revision":content["revision"],"content_md":content.get("content_md").or_else(||content.get("content")).cloned().unwrap_or(content.clone()),"fetched_at":common::timestamp()}),
    )
}
fn run() -> Result<Value> {
    common::ack()?;
    let a = common::args();
    let c = open(&a)?;
    match a.first().map(String::as_str) {
        Some("write") => write_note(&c, &a),
        Some("recall") => recall(&c, &a),
        Some("sync") => sync(&c, &a),
        Some("verify") => verify(&c, a.iter().any(|s| s == "--strict")),
        Some("worthy-upgrade-init") => worthy(&c, &a),
        Some("status") => {
            let r = remote(&c, "GET", "export", None)?;
            Ok(
                json!({"reachable":true,"export_count":exported(&r).len(),"response_fields":r.as_object().map(|o|o.keys().cloned().collect::<Vec<_>>())}),
            )
        }
        Some("explorer-get") => explorer(&a),
        _ => common::fail(64, "command_required"),
    }
}
fn main() {
    std::process::exit(common::emit(run()))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    #[test]
    fn lock_preserves_existing_inode_and_contents() {
        let path = std::env::temp_dir().join(format!(
            "crew-lock-{}-{}",
            std::process::id(),
            common::now()
        ));
        fs::write(&path, b"persistent lock data").unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        {
            let _lock = lock(&path).unwrap();
        }
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        assert_eq!(fs::read(&path).unwrap(), b"persistent lock data");
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn lock_contention_reacquisition_creation_and_open_failure() {
        let dir = std::env::temp_dir().join(format!(
            "crew-lock-more-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("lock");
        fs::write(&path, b"sentinel").unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        let held = lock(&path).unwrap();
        let contender = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        drop(held);
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert_eq!(
            unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_UN) },
            0
        );
        drop(contender);
        drop(lock(&path).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        assert_eq!(fs::read(&path).unwrap(), b"sentinel");
        let created = dir.join("created");
        drop(lock(&created).unwrap());
        assert!(created.is_file());
        let error = lock(&dir.join("absent/lock")).err().unwrap();
        assert_eq!((error.0, error.1), (73, "vault_lock_timeout"));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn prefix_and_equal_priority_preserve_behavior() {
        let home = Path::new("/fixture/home");
        assert_eq!(expand_env_path("$HOME/", || home.to_path_buf()), home);
        assert_eq!(
            expand_env_path("$HOME/é", || home.to_path_buf()),
            home.join("é")
        );
        assert_eq!(
            expand_env_path("$HOME", || home.to_path_buf()),
            PathBuf::from("$HOME")
        );
        assert_eq!(
            expand_env_path("other/$HOME/x", || home.to_path_buf()),
            PathBuf::from("other/$HOME/x")
        );
        let mut rows = vec![
            (3, json!("first")),
            (8, json!("high")),
            (3, json!("second")),
        ];
        sort_recall_candidates(&mut rows);
        assert_eq!(
            rows.into_iter().map(|row| row.1).collect::<Vec<_>>(),
            vec![json!("high"), json!("first"), json!("second")]
        );
    }
    #[test]
    fn prior_blob_option_obeys_verified_note_identity() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE episodes (path TEXT, blob TEXT, kind TEXT, status TEXT);")
            .unwrap();
        assert_eq!(prior_synced_blob(&db, "a", "new"), None);
        db.execute_batch("INSERT INTO episodes VALUES ('a','new','note','synced_verified'), ('a','old','note','in_flight'), ('b','other','note','synced_verified'), ('a','wrong-kind','supersession','synced_verified');").unwrap();
        assert_eq!(prior_synced_blob(&db, "a", "new"), None);
        db.execute(
            "UPDATE episodes SET status='synced_verified' WHERE blob='old'",
            [],
        )
        .unwrap();
        assert_eq!(prior_synced_blob(&db, "a", "new"), Some("old".into()));
    }
    #[test]
    fn folder_traversal_refused() {
        assert!(!safe_folder("Notes/Rules", "../a"));
        assert!(!safe_folder("Attachments", "note"));
        assert!(safe_folder("Notes/History", "cosp-history"));
    }
    #[test]
    fn remote_envelopes_match_full_identity() {
        let n = json!({"path":"Notes/Open work/a.md","commit":"abc","blob":"def"});
        let t = envelope(&n, "note", 0, 1, "hello");
        let rows = vec![json!({"id":"episode","text":t})];
        assert_eq!(
            matching(&rows, "Notes/Open work/a.md", "def", 0, "note"),
            Some("episode".into())
        );
        assert!(matching(&rows, "Notes/Open work/a.md", "different", 0, "note").is_none());
    }
    #[test]
    fn incomplete_frontmatter_refused() {
        assert!(frontmatter("---\ntitle: 3\n---\nbody").is_err());
    }
}
