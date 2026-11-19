use super::{fail, hash, Failure, Result};
use std::{fs, path::Path};
/// Enforce the brief's content rules before copying any publication payload.
/// Official scan receipts alone do not cover these additional source constraints.
pub fn publication_guard(root: &Path) -> Result<()> {
    const SHORT: &[&str] = &[
        "21acb73a915f047af8b30af7b967133e022491b0efd6552029aa43f87988a83e",
        "ec6f049478046f72becb006a2339202eae93911281dd610a7c869adec1ba3297",
    ];
    const LONG: &[&str] = &["795b104abe3e4134960ca245ded0e617f162c751209347b7f003bc35e062f43e"];
    let home_pattern = regex::Regex::new(r"/home/[A-Za-z0-9_.-]+").unwrap();
    let ipv4_pattern = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    fn walk(p: &Path, home_pattern: &regex::Regex, ipv4_pattern: &regex::Regex) -> Result<()> {
        for entry in fs::read_dir(p).map_err(|_| Failure(67, "alias_or_scan_gate_failed"))? {
            let entry = entry.map_err(|_| Failure(67, "alias_or_scan_gate_failed"))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|_| Failure(67, "alias_or_scan_gate_failed"))?;
            if kind.is_symlink()
                || path.extension().is_some_and(|s| s == "env")
                || path.file_name().is_some_and(|s| s == ".git")
            {
                return fail(67, "alias_or_scan_gate_failed");
            }
            if kind.is_dir() {
                walk(&path, home_pattern, ipv4_pattern)?;
                continue;
            }
            let text =
                fs::read_to_string(&path).map_err(|_| Failure(67, "alias_or_scan_gate_failed"))?;
            let folded = text.to_lowercase();
            for (width, pins) in [(7, SHORT), (9, LONG)] {
                if folded
                    .as_bytes()
                    .windows(width)
                    .any(|b| pins.contains(&hash(b).as_str()))
                {
                    return fail(67, "alias_or_scan_gate_failed");
                }
            }
            if home_pattern.is_match(&text) {
                return fail(67, "alias_or_scan_gate_failed");
            }
            for m in ipv4_pattern.find_iter(&text) {
                if let Ok(addr) = m.as_str().parse::<std::net::Ipv4Addr>() {
                    let o = addr.octets();
                    if !matches!(&o[..3], [192, 0, 2] | [198, 51, 100] | [203, 0, 113]) {
                        return fail(67, "alias_or_scan_gate_failed");
                    }
                }
            }
        }
        Ok(())
    }
    walk(root, &home_pattern, &ipv4_pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn tree() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "publication-guard-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn publication_guard_keeps_path_and_address_rejections() {
        let root = tree();
        let file = root.join("payload.txt");
        fs::write(&file, "ordinary text").unwrap();
        assert!(publication_guard(&root).is_ok());
        fs::write(&file, "local path /home/operator").unwrap();
        assert_eq!(publication_guard(&root).unwrap_err().0, 67);
        fs::write(&file, "documentation address 203.0.113.7").unwrap();
        assert!(publication_guard(&root).is_ok());
        fs::write(&file, "private address 10.20.30.40").unwrap();
        assert_eq!(publication_guard(&root).unwrap_err().0, 67);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publication_guard_keeps_alias_and_env_rejections() {
        let root = tree();
        let file = root.join("payload.txt");
        fs::write(&file, "ordinary text").unwrap();
        fs::write(root.join("blocked.env"), "ordinary text").unwrap();
        assert_eq!(publication_guard(&root).unwrap_err().0, 67);
        fs::remove_file(root.join("blocked.env")).unwrap();
        std::os::unix::fs::symlink(&file, root.join("alias.txt")).unwrap();
        assert_eq!(publication_guard(&root).unwrap_err().0, 67);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn nested_publication_rules_keep_failure_identity() {
        let root = tree();
        let nested = root.join("one/two");
        fs::create_dir_all(&nested).unwrap();
        let file = nested.join("payload.txt");
        let refusal = |root: &Path| {
            let error = publication_guard(root).unwrap_err();
            assert_eq!((error.0, error.1), (67, "alias_or_scan_gate_failed"));
        };
        for content in [
            "192.0.2.1",
            "198.51.100.2",
            "203.0.113.3",
            "999.999.999.999",
        ] {
            fs::write(&file, content).unwrap();
            assert!(publication_guard(&root).is_ok());
        }
        for content in ["nested /home/operator", "nested 10.20.30.40"] {
            fs::write(&file, content).unwrap();
            refusal(&root);
        }
        fs::write(&file, [0xff]).unwrap();
        refusal(&root);
        fs::write(&file, "safe").unwrap();
        fs::create_dir(nested.join(".git")).unwrap();
        refusal(&root);
        fs::remove_dir_all(root).unwrap();
    }
}
