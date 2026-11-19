//! Local cartridge integrity and resource checks.
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

#[derive(Debug, Deserialize)]
pub struct Cartridge {
    pub id: String,
    #[serde(alias = "capability")]
    pub lane: String,
    pub size_bytes: u64,
    pub min_vram_mb: u64,
    pub min_ram_mb: u64,
    pub required_backend: String,
    pub license_id: String,
    pub license_accepted: bool,
    #[serde(default)]
    pub license_commercial: bool,
    #[allow(dead_code)]
    #[serde(default)]
    pub license_url: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    pub license_checked_at: Option<String>,
    pub files: BTreeMap<String, String>,
}

fn collect(root: &Path, dir: &Path, found: &mut BTreeSet<String>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let ty = entry.file_type().map_err(|e| e.to_string())?;
        if ty.is_dir() {
            collect(root, &path, found)?;
        } else if ty.is_file() {
            let name = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("non-UTF-8 path")?
                .to_owned();
            found.insert(name);
        } else {
            return Err(format!("non-regular cartridge entry: {}", path.display()));
        }
    }
    Ok(())
}

pub fn verify(c: &Cartridge, root: &Path) -> Result<(), String> {
    if c.id.is_empty()
        || !super::LANES.contains(&c.lane.as_str())
        || c.license_id.is_empty()
        || !c.license_accepted
        || c.required_backend.is_empty()
        || c.files.is_empty()
    {
        return Err("invalid cartridge or license not accepted".into());
    }
    let mut found = BTreeSet::new();
    collect(root, root, &mut found)?;
    let mut size = 0u64;
    for (name, hash) in &c.files {
        if name.is_empty()
            || Path::new(name)
                .components()
                .any(|x| !matches!(x, Component::Normal(_)))
            || hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!("invalid file entry: {name}"));
        }
        if !found.remove(name) {
            return Err(format!("missing cartridge file: {name}"));
        }
        let path = root.join(name);
        size = size
            .checked_add(fs::metadata(&path).map_err(|e| e.to_string())?.len())
            .ok_or("size overflow")?;
        if super::sha256_file(&path).map_err(|e| e.to_string())? != *hash {
            return Err(format!("cartridge hash mismatch: {name}"));
        }
    }
    if !found.is_empty() {
        return Err(format!("unlisted cartridge files: {found:?}"));
    }
    if size != c.size_bytes {
        return Err("cartridge size mismatch".into());
    }
    Ok(())
}

pub fn compatible(c: &Cartridge, worker_id: &str, caps: &Value) -> Result<(), String> {
    if worker_id == "b70" && c.required_backend.eq_ignore_ascii_case("cuda") {
        return Err("CUDA unavailable on b70".into());
    }
    let vram = caps["vram_mb"].as_u64().ok_or("worker VRAM unknown")?;
    let ram = caps["ram_mb"].as_u64().ok_or("worker RAM unknown")?;
    if vram < c.min_vram_mb {
        return Err("insufficient VRAM".into());
    }
    if ram < c.min_ram_mb {
        return Err("insufficient RAM".into());
    }
    if !caps["backends"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(&c.required_backend)))
    {
        return Err("backend unavailable".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn commercial_metadata_is_optional_for_existing_manifests() {
        let old = json!({"id":"fixture","lane":"tts","size_bytes":1,"min_vram_mb":0,"min_ram_mb":0,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{}});
        let c: Cartridge = serde_json::from_value(old).unwrap();
        assert!(!c.license_commercial);
        assert!(c.license_url.is_none());
        assert!(c.license_checked_at.is_none());
        let c: Cartridge = serde_json::from_value(json!({"id":"fixture","lane":"tts","size_bytes":1,"min_vram_mb":0,"min_ram_mb":0,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"license_commercial":true,"license_url":"[R]","license_checked_at":"2026-10-31T00:00:00Z","files":{}})).unwrap();
        assert!(c.license_commercial);
        assert_eq!(c.license_url.as_deref(), Some("[R]"));
        assert_eq!(
            c.license_checked_at.as_deref(),
            Some("2026-10-31T00:00:00Z")
        );
    }
    fn cart() -> Cartridge {
        Cartridge {
            id: "blender-4.5.14-cycles".into(),
            lane: "render-blender".into(),
            size_bytes: 3,
            min_vram_mb: 8,
            min_ram_mb: 16,
            required_backend: "cuda".into(),
            license_id: "test-license".into(),
            license_accepted: true,
            license_commercial: false,
            license_url: None,
            license_checked_at: None,
            files: BTreeMap::from([(
                "weights".into(),
                hex::encode(super::super::Sha256::digest(b"abc")),
            )]),
        }
    }
    use sha2::Digest;
    #[test]
    fn rejects_symlink_and_traversal_entries() {
        use std::os::unix::fs::symlink;
        let root = crate::test_process::target_dir().join(format!(
            "lane-cart-edge-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("weights"), b"abc").unwrap();
        symlink("weights", root.join("link")).unwrap();
        assert!(verify(&cart(), &root).unwrap_err().contains("non-regular"));
        let separate = root.join("separate");
        fs::create_dir(&separate).unwrap();
        let mut invalid = cart();
        invalid.files = BTreeMap::from([(
            "../weights".into(),
            hex::encode(super::super::Sha256::digest(b"abc")),
        )]);
        assert!(verify(&invalid, &separate)
            .unwrap_err()
            .contains("invalid file entry"));
    }
    #[test]
    fn integrity_and_license() {
        let root = crate::test_process::target_dir().join(format!(
            "lane-cart-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("weights"), b"abc").unwrap();
        let mut c = cart();
        assert!(verify(&c, &root).is_ok());
        c.license_accepted = false;
        assert!(verify(&c, &root).unwrap_err().contains("license"));
        c.license_accepted = true;
        fs::write(root.join("weights"), b"xyz").unwrap();
        assert!(verify(&c, &root).unwrap_err().contains("hash mismatch"));
        fs::write(root.join("weights"), b"abc").unwrap();
        fs::write(root.join("extra"), b"x").unwrap();
        assert!(verify(&c, &root).unwrap_err().contains("unlisted"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn unknown_capacity_fails_closed() {
        let c = cart();
        for caps in [
            json!({}),
            json!({"vram_mb":-1,"ram_mb":16,"backends":["cuda"]}),
            json!({"vram_mb":8.5,"ram_mb":16,"backends":["cuda"]}),
            json!({"vram_mb":8,"ram_mb":-1,"backends":["cuda"]}),
            json!({"vram_mb":8,"ram_mb":16,"backends":"cuda"}),
        ] {
            assert!(compatible(&c, "w", &caps).is_err());
        }
    }
    #[test]
    fn resources() {
        let c = cart();
        assert!(compatible(
            &c,
            "b70",
            &json!({"vram_mb":100,"ram_mb":100,"backends":["cuda"]})
        )
        .unwrap_err()
        .contains("b70"));
        assert!(compatible(
            &c,
            "w",
            &json!({"vram_mb":7,"ram_mb":100,"backends":["cuda"]})
        )
        .unwrap_err()
        .contains("VRAM"));
        assert!(compatible(
            &c,
            "w",
            &json!({"vram_mb":8,"ram_mb":15,"backends":["cuda"]})
        )
        .unwrap_err()
        .contains("RAM"));
        assert!(compatible(
            &c,
            "w",
            &json!({"vram_mb":8,"ram_mb":16,"backends":["cpu"]})
        )
        .unwrap_err()
        .contains("backend"));
        assert!(compatible(
            &c,
            "w",
            &json!({"vram_mb":8,"ram_mb":16,"backends":["cuda"]})
        )
        .is_ok());
    }
}

#[cfg(test)]
mod run35_u2 {
    use super::*;
    use crate::{error_catalog, store};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "fold-run35-cart-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn visit(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                assert!(!entry.file_type().unwrap().is_symlink());
                if path.is_dir() {
                    visit(root, &path, files);
                } else {
                    files.insert(
                        path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                        fs::read(&path).unwrap(),
                    );
                }
            }
        }
        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    fn plant(root: &Path, file: &str, lane: &str) -> String {
        let manifest = serde_json::json!({"id":"fixture","lane":lane,"size_bytes":3,"min_vram_mb":0,"min_ram_mb":0,"required_backend":"cpu","license_id":"fixture","license_accepted":true,"files":{file:hex::encode(Sha256::digest(b"abc"))}});
        let data = serde_json::to_vec(&manifest).unwrap();
        let pin = hex::encode(Sha256::digest(&data));
        let version = root.join("versions").join(&pin);
        fs::create_dir_all(version.join("files")).unwrap();
        fs::write(version.join("files/weights"), b"abc").unwrap();
        fs::write(version.join("manifest.json"), data).unwrap();
        pin
    }

    #[test]
    fn run35_u2_load_refusals_table() {
        let temp = TempRoot::new();
        let root = &temp.0;
        let valid = plant(root, "weights", "tts");
        let escape = plant(root, "../outside", "tts");
        let unknown = plant(root, "weights", "unknown");
        fs::write(root.join("outside"), b"unchanged").unwrap();
        let mismatch = hex::encode(Sha256::digest(b"mismatched manifest"));
        fs::create_dir_all(root.join("versions").join(&mismatch)).unwrap();
        fs::copy(
            root.join("versions").join(&valid).join("manifest.json"),
            root.join("versions").join(&mismatch).join("manifest.json"),
        )
        .unwrap();
        let missing = hex::encode(Sha256::digest(b"missing manifest"));
        let rows = [
            (
                "missing manifest",
                "tts",
                missing.as_str(),
                error_catalog::STATE_UNREADABLE,
            ),
            (
                "pin mismatch",
                "tts",
                mismatch.as_str(),
                error_catalog::HASH_MISMATCH,
            ),
            (
                "escaping file",
                "tts",
                escape.as_str(),
                error_catalog::MANIFEST_MISMATCH,
            ),
            (
                "unknown lane kind",
                "unknown",
                unknown.as_str(),
                error_catalog::UNKNOWN_LANE,
            ),
            ("unsafe pin", "tts", "../outside", error_catalog::BAD_DIGEST),
            (
                "lane mismatch",
                "stt",
                valid.as_str(),
                error_catalog::LANE_MISMATCH,
            ),
        ];
        assert!(rows.len() >= 4);
        let before = snapshot(root);
        for (label, lane, pin, code) in rows {
            assert_eq!(
                store::Store::open(root).version(lane, pin).unwrap_err(),
                code,
                "{label}"
            );
            assert_eq!(error_catalog::lookup(None, code).unwrap().code, code);
            assert_eq!(snapshot(root), before, "{label}");
        }
    }

    #[test]
    fn run35_u2_valid_planted_load() {
        let temp = TempRoot::new();
        let root = &temp.0;
        let pin = plant(root, "weights", "tts");
        let before = snapshot(root);
        let (manifest, files, loaded) = store::Store::open(root).version("tts", &pin).unwrap();
        assert!(manifest.starts_with(root) && files.starts_with(root));
        assert_eq!(loaded, pin);
        let cart: Cartridge = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
        assert_eq!((cart.id.as_str(), cart.lane.as_str()), ("fixture", "tts"));
        assert_eq!(fs::read(files.join("weights")).unwrap(), b"abc");
        verify(&cart, &files).unwrap();
        assert_eq!(snapshot(root), before);
    }
}
