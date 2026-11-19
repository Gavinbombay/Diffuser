use super::{fail, hash, read, Failure, Result};
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn ack_at(root: &Path, post: bool) -> Result<Value> {
    let p = root.join("out/evidence/ACK.md");
    let b = read(&p).map_err(|_| Failure(62, "ack_missing_or_stale"))?;
    let s = String::from_utf8_lossy(&b);
    for name in ["RULES.md", "CONNECT.md"] {
        let d = read(root.join("stage/INPUTS/crew").join(name))
            .map_err(|_| Failure(62, "ack_missing_or_stale"))?;
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
            // RA-5 authorizes this one same-job refresh. Its original pre-work
            // proof is the custodian's immutable r5 failure copy, not a backdated file.
            let authority = read(root.join("BRIEF.md")).ok().is_some_and(|b| {
                String::from_utf8_lossy(&b).contains("### RA-5. out/ and W/ on resume")
            });
            let patch_ok = read(root.join("resume/R5-RESUME-REFS-PATCH-20261113.diff"))
                .ok()
                .is_some_and(|b| {
                    hash(b) == "2b1006f906f75ae4f499dd5c1bdd700787d4aa5fdc9c472f2e7b9c4372a66b25"
                });
            let archive = root.join("out.r5-fail-20261113T1444");
            let prior = archive.join("evidence/ACK.md");
            let mut prior_earliest = None;
            let prior_text = read(&prior)
                .ok()
                .map(|b| String::from_utf8_lossy(&b).to_string());
            let staged_match = prior_text.is_some_and(|t| {
                ["RULES.md", "CONNECT.md"].iter().all(|n| {
                    read(root.join("stage/INPUTS/crew").join(n)).is_ok_and(|b| t.contains(&hash(b)))
                })
            });
            let first = walk(&archive, &prior, &mut prior_earliest).is_ok()
                && fs::metadata(&prior)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .is_some_and(|t| prior_earliest.is_none_or(|e| t <= e));
            if root
                .file_name()
                .is_none_or(|n| n != "codex-operator-spine-20261112-nuc-linux")
                || !authority
                || !patch_ok
                || !staged_match
                || !first
            {
                return fail(63, "ack_written_after_work");
            }
        }
    }
    Ok(
        json!({"ack_verified":true,"rules_staged_sha256":hash(read(root.join("stage/INPUTS/crew/RULES.md"))?),"connect_staged_sha256":hash(read(root.join("stage/INPUTS/crew/CONNECT.md"))?),"pre_work_verified":post,"job_id":root.file_name().and_then(|n|n.to_str()),"rules_version_line":String::from_utf8_lossy(&read(root.join("stage/INPUTS/crew/RULES.md"))?).lines().find(|l|l.contains("Version ")).map(str::to_string),"ack_ctime_epoch":fs::metadata(&p).map_err(|_|Failure(62,"ack_missing_or_stale"))?.ctime(),"earliest_other_out_epoch":earliest.map(|t|t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()),"ack_proof_source":if post&&earliest.is_some_and(|e|e<at){"RA-5 immutable r5 pre-work proof plus current refresh"}else{"current job ACK"}}),
    )
}
