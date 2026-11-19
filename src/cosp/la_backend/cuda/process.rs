use super::{super::Binding, Capability, DeviceUuid, Readback};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::FileExt, process::CommandExt},
    },
    process::{Child, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

const WARP_UUID: &str = "GPU-457abb57-787f-5cf6-9ed5-d720030b93f5";
const WARP_SHA256: [u8; 32] = [
    0x2b, 0x28, 0x13, 0xc1, 0x99, 0x22, 0xd0, 0x99, 0xd8, 0x3a, 0x46, 0x92, 0x1f, 0x1e, 0x59, 0x84,
    0x6e, 0x78, 0x96, 0x51, 0xfe, 0x1f, 0x97, 0x05, 0x6f, 0x82, 0xc5, 0x5f, 0x4f, 0x10, 0x44, 0x96,
];
const UNAVAILABLE: &str = "capability_unavailable";
const MAX_ELF_BYTES: u64 = 1024 * 1024;

// One child owns this readiness gate and the single work exchange. The journal
// remains responsible for authorization, result custody and release evidence.
pub(in crate::cosp) struct CudaProcess {
    child: Child,
    output: ChildStdout,
    pin: DeviceUuid,
    joined: bool,
}

impl CudaProcess {
    /// For future trusted W bootstrap only, before process sealing. The caller
    /// must already own the artifact fd and the qualified execution domain,
    /// including its driver/interpreter, device scope and spawning thread.
    /// This function neither authenticates a worker nor grants admission.
    #[allow(dead_code)] // No ordinary startup caller is authorized yet.
    pub(in crate::cosp) fn launch_native(
        artifact: File,
        expected_sha256: [u8; 32],
        pin: DeviceUuid,
        address_space_bytes: u64,
    ) -> Result<Self, &'static str> {
        if expected_sha256 != WARP_SHA256 || pin.as_str() != WARP_UUID {
            return Err(UNAVAILABLE);
        }
        // The read-only executable mount is necessary, not sufficient: trusted
        // startup must also control the backing store and all writable aliases.
        let mut mount = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(artifact.as_raw_fd(), mount.as_mut_ptr()) } != 0
            || unsafe { mount.assume_init() }.f_flag & (libc::ST_RDONLY | libc::ST_NOEXEC)
                != libc::ST_RDONLY
        {
            return Err(UNAVAILABLE);
        }
        Self::launch_verified(artifact, expected_sha256, pin, address_space_bytes)
    }

    /// Protected startup native CUDA launcher for any configured qualified GPU
    /// via its exact configured GPU UUID. Enforces exact ELF
    /// SHA-256 verification, finite nonzero address-space cap, `/proc/self/fd`
    /// execution with `env_clear()`, and optional read-only mount enforcement.
    pub(in crate::cosp) fn launch_native_configured(
        artifact: File,
        expected_sha256: [u8; 32],
        pin: DeviceUuid,
        address_space_bytes: u64,
        cpu_secs: u64,
        ready_timeout_ms: i32,
        require_ro_mount: bool,
    ) -> Result<Self, &'static str> {
        if matches!(address_space_bytes, 0 | libc::RLIM_INFINITY)
            || cpu_secs == 0
            || ready_timeout_ms <= 0
        {
            return Err(UNAVAILABLE);
        }
        if require_ro_mount {
            let mut mount = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if unsafe { libc::fstatvfs(artifact.as_raw_fd(), mount.as_mut_ptr()) } != 0
                || unsafe { mount.assume_init() }.f_flag & (libc::ST_RDONLY | libc::ST_NOEXEC)
                    != libc::ST_RDONLY
            {
                return Err(UNAVAILABLE);
            }
        }
        verify_image(&artifact, expected_sha256).map_err(|_| UNAVAILABLE)?;
        let mut cmd = Command::new(format!("/proc/self/fd/{}", artifact.as_raw_fd()));
        cmd.env_clear();
        Self::spawn_with_limits(
            cmd,
            Stdio::null(),
            pin,
            address_space_bytes,
            cpu_secs,
            ready_timeout_ms,
        )
    }

    pub(super) fn launch_verified(
        artifact: File,
        expected_sha256: [u8; 32],
        pin: DeviceUuid,
        address_space_bytes: u64,
    ) -> Result<Self, &'static str> {
        if matches!(address_space_bytes, 0 | libc::RLIM_INFINITY) {
            return Err(UNAVAILABLE);
        }
        verify_image(&artifact, expected_sha256).map_err(|_| UNAVAILABLE)?;
        // Resolve this descriptor in the child before CLOEXEC closes it. No
        // original pathname is reopened and no descriptor survives into ELF.
        let mut cmd = Command::new(format!("/proc/self/fd/{}", artifact.as_raw_fd()));
        cmd.env_clear();
        Self::spawn(cmd, Stdio::null(), pin, address_space_bytes)
    }

    #[cfg(test)]
    pub(in crate::cosp) fn launch(
        binary: &std::path::Path,
        trace: File,
        pin: DeviceUuid,
        mode: &'static str,
    ) -> Result<Self, &'static str> {
        let mut cmd = Command::new(binary);
        cmd.env_clear().env("CUDA_FIXTURE_CASE", mode);
        Self::spawn(cmd, trace.into(), pin, 16 * 1024 * 1024)
    }

    fn spawn(
        cmd: Command,
        stderr: Stdio,
        pin: DeviceUuid,
        address_space_bytes: u64,
    ) -> Result<Self, &'static str> {
        Self::spawn_with_limits(cmd, stderr, pin, address_space_bytes, 1, 1000)
    }

    fn spawn_with_limits(
        mut cmd: Command,
        stderr: Stdio,
        pin: DeviceUuid,
        address_space_bytes: u64,
        cpu_secs: u64,
        ready_timeout_ms: i32,
    ) -> Result<Self, &'static str> {
        let parent = std::process::id();
        cmd.arg(pin.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr);
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() as u32 != parent
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::syscall(
                        libc::SYS_close_range,
                        3u32,
                        u32::MAX,
                        libc::CLOSE_RANGE_CLOEXEC,
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                for (resource, limit) in [
                    (libc::RLIMIT_CPU, cpu_secs),
                    (libc::RLIMIT_AS, address_space_bytes),
                    (libc::RLIMIT_FSIZE, 16 * 1024),
                    (libc::RLIMIT_CORE, 0),
                ] {
                    let bounds = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(resource, &bounds) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|_| "capability_unavailable")?;
        let output = child.stdout.take().expect("piped stdout");
        let mut process = Self {
            child,
            output,
            pin,
            joined: false,
        };
        let fd = process.output.as_raw_fd();
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut ready = [0];
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } != 0
            || unsafe { libc::poll(&mut poll, 1, ready_timeout_ms) } != 1
            || poll.revents != libc::POLLIN
            || process.output.read_exact(&mut ready).is_err()
            || ready != [b'R']
        {
            return Err("capability_unavailable");
        }
        process.ready(process.capability())?;
        Ok(process)
    }

    #[cfg(test)]
    pub(in crate::cosp) fn pid(&self) -> u32 {
        self.child.id()
    }
}

// The verified descriptor stays open across spawn, so path replacement cannot
// switch the executable. Immutability of its backing inode is a prerequisite
// of the calling startup (the neutral fixture owns its own backing inode).
fn verify_image(artifact: &File, expected_sha256: [u8; 32]) -> io::Result<()> {
    let meta = artifact.metadata()?;
    if !meta.is_file() || !(1..=MAX_ELF_BYTES).contains(&meta.len()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; meta.len() as usize];
    artifact.read_exact_at(&mut bytes, 0)?;
    if !bytes.starts_with(b"\x7fELF") || Sha256::digest(&bytes)[..] != expected_sha256 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

impl Drop for CudaProcess {
    fn drop(&mut self) {
        if !self.joined {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Binding for CudaProcess {
    fn capability(&self) -> Capability {
        Capability::CudaAddOne(self.pin)
    }

    fn ready(&mut self, capability: Capability) -> Result<(), &'static str> {
        if capability != self.capability()
            || self.child.stdin.is_none()
            || self.child.try_wait().ok() != Some(None)
        {
            return Err("capability_unavailable");
        }
        Ok(())
    }

    fn execute_cuda(
        mut self: Box<Self>,
        deadline: Instant,
        stop: &dyn Fn() -> bool,
    ) -> Result<Readback, &'static str> {
        if stop() || Instant::now() >= deadline {
            return Err("stopped");
        }
        let mut stdin = self.child.stdin.take().ok_or("execution_uncertain")?;
        stdin.write_all(b"G").map_err(|_| "execution_uncertain")?;
        drop(stdin);
        loop {
            // After arming, neither a timeout nor a killed process certifies
            // accelerator cleanup. Leave the existing started marker held.
            if stop() || Instant::now() >= deadline {
                return Err("execution_uncertain");
            }
            if let Some(status) = self.child.try_wait().map_err(|_| "execution_uncertain")? {
                self.joined = true;
                if !status.success() {
                    return Err("execution_uncertain");
                }
                break;
            }
            std::thread::sleep(Duration::from_micros(250));
        }
        let mut bytes = Vec::new();
        self.output
            .by_ref()
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| "execution_uncertain")?;
        if bytes.len() > 256 || stop() || Instant::now() >= deadline {
            return Err("execution_uncertain");
        }
        serde_json::from_slice(&bytes).map_err(|_| "execution_uncertain")
    }

    fn execute(
        self: Box<Self>,
        _: &super::super::Input,
        _: Instant,
        _: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], &'static str> {
        Err("execution_uncertain")
    }
}
