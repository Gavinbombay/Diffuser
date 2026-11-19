//! Test subprocesses execute private copies that outlive a rebuild or unlink.
use std::fs;
use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Helper {
    command: Command,
    root: PathBuf,
}
impl Helper {
    pub fn copy(source: &Path) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "fold-test-helper-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let result = (|| {
            let path = root.join("helper");
            let source = if source == Path::new("/proc/self/exe") {
                PathBuf::from(format!("/proc/{}/exe", std::process::id()))
            } else {
                source.to_owned()
            };
            // A separate process owns the writer. Concurrent forks in this
            // process cannot inherit it and keep the helper text file busy.
            if !Command::new("cp")
                .arg("--reflink=auto")
                .arg("--")
                .arg(source)
                .arg(&path)
                .status()?
                .success()
            {
                return Err(io::Error::other("copy test executable failed"));
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            Ok(Self {
                command: Command::new(path),
                root: root.clone(),
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(root);
        }
        result
    }
}
impl Deref for Helper {
    type Target = Command;
    fn deref(&self) -> &Command {
        &self.command
    }
}
impl DerefMut for Helper {
    fn deref_mut(&mut self) -> &mut Command {
        &mut self.command
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
pub fn command() -> Helper {
    // This handle stays available even when Cargo has removed the original path.
    Helper::copy(Path::new("/proc/self/exe")).expect("copy running test executable")
}
#[test]
fn helper_survives_source_path_removed() {
    if std::env::var_os("HELPER_UNLINK_CHILD").is_some() {
        return;
    }
    let held = command();
    let source = PathBuf::from(held.get_program());
    let mut independent = Helper::copy(&source).unwrap();
    fs::remove_file(&source).unwrap();
    assert!(!source.exists());
    assert!(independent
        .args([
            "--exact",
            "test_process::helper_survives_source_path_removed",
            "--quiet"
        ])
        .env("HELPER_UNLINK_CHILD", "1")
        .status()
        .unwrap()
        .success());
}

/// Resolve Cargo's output directory without assuming a source-local build tree.
pub fn target_dir() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = if let Some(value) = std::env::var_os("CARGO_TARGET_DIR") {
        let value = PathBuf::from(value);
        if value.is_absolute() {
            value
        } else {
            root.join(value)
        }
    } else {
        let output = Command::new("cargo")
            .args([
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--offline",
            ])
            .current_dir(root)
            .output()
            .expect("cargo metadata");
        assert!(output.status.success(), "cargo metadata failed");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        PathBuf::from(value["target_directory"].as_str().unwrap())
    };
    fs::create_dir_all(&path).unwrap();
    path
}
