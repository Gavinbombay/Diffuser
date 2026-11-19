use super::{fail, read, Failure, Result};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
pub fn config(path: &Path) -> Result<BTreeMap<String, String>> {
    let data = String::from_utf8(read(path)?).map_err(|_| Failure(70, "config_invalid"))?;
    let mut r = BTreeMap::new();
    for l in data.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (n, v) = l.split_once('=').ok_or(Failure(70, "config_invalid"))?;
        let v = v.trim();
        if !v.starts_with('"') || !v.ends_with('"') {
            return fail(70, "config_invalid");
        }
        r.insert(n.trim().to_string(), v[1..v.len() - 1].to_string());
    }
    Ok(r)
}
pub fn protected(path: &Path, strict_parent: bool) -> Result<zeroize::Zeroizing<String>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Failure(68, "credential_env_missing_or_bad_mode"))?;
    let meta = f
        .metadata()
        .map_err(|_| Failure(68, "credential_env_missing_or_bad_mode"))?;
    let allowed = if strict_parent {
        meta.mode() & 0o077 == 0
    } else {
        meta.mode() & 0o037 == 0
    };
    if !meta.is_file() || !allowed {
        return fail(68, "credential_env_missing_or_bad_mode");
    }
    if strict_parent
        && fs::metadata(
            path.parent()
                .ok_or(Failure(68, "credential_env_missing_or_bad_mode"))?,
        )
        .map_err(|_| Failure(68, "credential_env_missing_or_bad_mode"))?
        .mode()
            & 0o077
            != 0
    {
        return fail(68, "credential_env_missing_or_bad_mode");
    }
    let mut data = zeroize::Zeroizing::new(String::new());
    f.read_to_string(&mut data)
        .map_err(|_| Failure(68, "credential_env_missing_or_bad_mode"))?;
    Ok(data)
}
pub fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
}
