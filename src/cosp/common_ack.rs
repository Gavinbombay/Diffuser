use super::{fail, hash, read, Failure, Result};
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
/// Staged rule inputs, relative to the job root. Set `DIFFUSER_ACK_INPUTS` to
/// use another directory.
fn inputs(root: &Path) -> PathBuf {
    root.join(
        std::env::var_os("DIFFUSER_ACK_INPUTS")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "stage/INPUTS/rules".into()),
    )
}
pub fn ack_at(root: &Path, post: bool) -> Result<Value> {
    let p = root.join("out/evidence/ACK.md");
    let staged = inputs(root);
    let b = read(&p).map_err(|_| Failure(62, "ack_missing_or_stale"))?;
    let s = String::from_utf8_lossy(&b);
    for name in ["RULES.md", "CONNECT.md"] {
        let d = read(staged.join(name)).map_err(|_| Failure(62, "ack_missing_or_stale"))?;
        if !s.contains(&hash(&d)) {
            return fail(62, "ack_missing_or_stale");
        }
        if name == "RULES.md" {
            let txt = String::from_utf8_lossy(&d);
            let line = txt
                .lines()
                .find(|l| l.contains("Version "))
                .ok_or(Failure(62, "ack_missing_or_stale"))?;
            if !s.contains(line) {
                return fail(62, "ack_missing_or_stale");
            }
        }
    }
    let at = fs::metadata(&p)
        .map_err(|_| Failure(62, "ack_missing_or_stale"))?
        .modified()
        .unwrap();
    let mut earliest = None;
    fn walk(p: &Path, a: &Path, t: &mut Option<SystemTime>) -> Result<()> {
        for e in fs::read_dir(p).map_err(|_| Failure(70, "output_unreadable"))? {
            let e = e.map_err(|_| Failure(70, "output_unreadable"))?;
            let q = e.path();
            if e.file_type()
                .map_err(|_| Failure(70, "output_unreadable"))?
                .is_dir()
            {
                walk(&q, a, t)?
            } else if q != a {
                let m = e.metadata().unwrap().modified().unwrap();
                *t = Some(t.map_or(m, |o| o.min(m)));
            }
        }
        Ok(())
    }
    if post {
        walk(&root.join("out"), &p, &mut earliest)?;
        if earliest.is_some_and(|e| e < at) {
            return fail(63, "ack_written_after_work");
        }
    }
    Ok(
        json!({"ack_verified":true,"rules_staged_sha256":hash(read(staged.join("RULES.md"))?),"connect_staged_sha256":hash(read(staged.join("CONNECT.md"))?),"pre_work_verified":post,"job_id":root.file_name().and_then(|n|n.to_str()),"rules_version_line":String::from_utf8_lossy(&read(staged.join("RULES.md"))?).lines().find(|l|l.contains("Version ")).map(str::to_string),"ack_ctime_epoch":fs::metadata(&p).map_err(|_|Failure(62,"ack_missing_or_stale"))?.ctime(),"earliest_other_out_epoch":earliest.map(|t|t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()),"ack_proof_source":"current job ACK"}),
    )
}
