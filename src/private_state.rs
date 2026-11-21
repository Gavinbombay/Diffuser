use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) struct PrivateDir {
    path: PathBuf,
    dir: File,
    owner: u32,
}

fn unsafe_path() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe private state path")
}

fn fd_path(dir: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

impl PrivateDir {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(unsafe_path());
        }
        let path = std::path::absolute(path)?;
        let owner = unsafe { libc::geteuid() };
        let mut dir = open_dir(Path::new("/"))?;
        for part in path.components().skip(1) {
            let Component::Normal(name) = part else {
                return Err(unsafe_path());
            };
            dir = open_dir(&fd_path(&dir).join(name))?;
            let meta = dir.metadata()?;
            // A sticky directory protects entries owned by root or the service.
            if (meta.uid() != 0 && meta.uid() != owner)
                || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0)
            {
                return Err(unsafe_path());
            }
        }
        Self::check_dir(&dir, owner)?;
        Ok(Self { path, dir, owner })
    }

    fn check_dir(dir: &File, owner: u32) -> io::Result<()> {
        let meta = dir.metadata()?;
        if meta.uid() == owner && meta.mode() & 0o7777 == 0o700 {
            Ok(())
        } else {
            Err(unsafe_path())
        }
    }

    pub(crate) fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let rel = if path.is_absolute() {
            path.strip_prefix(&self.path).map_err(|_| unsafe_path())?
        } else {
            path.strip_prefix(".").unwrap_or(path)
        };
        let mut parts = rel.components().peekable();
        let mut dir = self.dir.try_clone()?;
        Self::check_dir(&dir, self.owner)?;
        while let Some(Component::Normal(name)) = parts.next() {
            let entry = fd_path(&dir).join(name);
            if parts.peek().is_some() {
                dir = open_dir(&entry)?;
                Self::check_dir(&dir, self.owner)?;
                continue;
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(entry)?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != self.owner
                || meta.mode() & 0o7777 != 0o600
                || meta.nlink() != 1
            {
                return Err(unsafe_path());
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            return Ok(bytes);
        }
        Err(unsafe_path())
    }

    pub(crate) fn replace(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut parts = Path::new(name).components();
        if !matches!((parts.next(), parts.next()), (Some(Component::Normal(part)), None) if part == name)
        {
            return Err(unsafe_path());
        }
        Self::check_dir(&self.dir, self.owner)?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = fd_path(&self.dir);
        let tmp = dir.join(format!(
            ".{name}.tmp.{}.{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let result = file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|_| file.write_all(bytes))
            .and_then(|_| file.sync_all())
            .and_then(|_| fs::rename(&tmp, dir.join(name)));
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
}

#[cfg(test)]
pub(crate) fn fixture_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(test)]
pub(crate) fn fixture_file(path: &Path, data: impl AsRef<[u8]>) {
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn private_read_checks_the_open_file_and_every_directory() {
        let ancestor = std::env::temp_dir().join(format!("private-state-{}", std::process::id()));
        let root = ancestor.join("root");
        let nested = root.join("nested");
        fixture_dir(&ancestor);
        fixture_dir(&root);
        fixture_dir(&nested);
        let file = nested.join("snapshot");
        fixture_file(&file, b"trusted");
        let dir = PrivateDir::open(&root).unwrap();
        assert_eq!(dir.read(&file).unwrap(), b"trusted");
        assert_eq!(dir.read(Path::new("nested/snapshot")).unwrap(), b"trusted");
        assert_eq!(
            dir.read(Path::new("./nested/snapshot")).unwrap(),
            b"trusted"
        );
        assert!(dir.read(Path::new("nested/../nested/snapshot")).is_err());
        symlink(&nested, root.join("redirect")).unwrap();
        assert!(dir.read(Path::new("redirect/snapshot")).is_err());
        fs::hard_link(&file, root.join("alias")).unwrap();
        assert!(dir.read(&file).is_err());
        fs::remove_file(root.join("alias")).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(dir.read(&file).is_err());
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(PrivateDir::open(&root).is_err());
        fs::remove_dir_all(ancestor).unwrap();
    }
}
