//! Fixed private typed backends. The worker owns the journal, permits and receipts.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub(super) mod cuda;

pub(super) const CAPABILITY: &str = "artifact.inspect.sha256/v1";
pub(super) const TYPED_SUBMIT: &str = "diffuser-lane/v2";
const INPUT_SCHEMA: &str = "diffuser-private-sha256-input/v1";
const OUTPUT_SCHEMA: &str = "diffuser-private-sha256-output/v1";
const PRIVATE_PROFILE: &str = "cpu-private-sha256/v1";
const LEGACY_PROFILE: &str = "cpu-artifact-inspect";
const ENTRY: &str = "--private-cosp-sha256-v1";
const MAX_DATA: usize = 256;
const MAX_INPUT: usize = 1024;
const MAX_ROUNDS: u32 = 262_144;
const READY: u8 = b'R';
const STARTED: u8 = b'S';
const CONTINUE: u8 = b'G';

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(super) enum Capability {
    #[serde(rename = "cpu-private-sha256/v1")]
    PrivateSha256,
    #[serde(rename = "cuda-private-add-one/v1")]
    CudaAddOne(cuda::DeviceUuid),
}

impl Capability {
    pub(super) fn mandate_profile(value: Option<Self>) -> String {
        match value {
            None => LEGACY_PROFILE.into(),
            Some(Self::PrivateSha256) => PRIVATE_PROFILE.into(),
            Some(Self::CudaAddOne(uuid)) => format!("{}/{}", cuda::PROFILE, uuid.as_str()),
        }
    }

    pub(super) fn from_mandate_profile(profile: &str) -> Result<Option<Self>, &'static str> {
        match profile {
            LEGACY_PROFILE => Ok(None),
            PRIVATE_PROFILE => Ok(Some(Self::PrivateSha256)),
            _ => profile
                .strip_prefix(cuda::PROFILE)
                .and_then(|rest| rest.strip_prefix('/'))
                .and_then(cuda::DeviceUuid::parse)
                .map(|uuid| Some(Self::CudaAddOne(uuid)))
                .ok_or("evidence_invalid"),
        }
    }

    pub(super) fn known_mandate_profile(profile: &str) -> bool {
        Self::from_mandate_profile(profile).is_ok()
    }

    pub(super) fn public_capability(value: Option<Self>) -> &'static str {
        match value {
            Some(Self::CudaAddOne(_)) => cuda::CAPABILITY,
            _ => CAPABILITY,
        }
    }

    pub(super) fn validate_input(self, bytes: &[u8]) -> Result<(), &'static str> {
        match self {
            Self::PrivateSha256 => Input::parse(bytes).map(drop),
            Self::CudaAddOne(_) => cuda::validate_input(bytes),
        }
    }
}

pub(super) fn negotiate(
    schema: &str,
    parameters: &serde_json::Value,
) -> Result<Option<Capability>, &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TypedParameters {
        backend: String,
    }
    match schema {
        "diffuser-lane/v1" if parameters.as_object().is_some_and(|v| v.is_empty()) => Ok(None),
        "diffuser-lane/v1" => Err("schema_invalid"),
        TYPED_SUBMIT if parameters["backend"] == cuda::PROFILE => {
            cuda::negotiate(parameters).map(Some)
        }
        TYPED_SUBMIT => {
            let parsed: TypedParameters =
                serde_json::from_value(parameters.clone()).map_err(|_| "schema_invalid")?;
            match parsed.backend.as_str() {
                PRIVATE_PROFILE => Ok(Some(Capability::PrivateSha256)),
                _ => Err("capability_unavailable"),
            }
        }
        _ => Err("version_unsupported"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputEnvelope {
    schema_version: String,
    data_hex: String,
    rounds: u32,
}

pub(super) struct Input {
    data: Vec<u8>,
    rounds: u32,
}

impl Input {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_INPUT {
            return Err("artifact_invalid");
        }
        let canonical =
            super::la_contract::canonical_json(bytes).map_err(|_| "artifact_invalid")?;
        let envelope: InputEnvelope =
            serde_json::from_slice(&canonical).map_err(|_| "artifact_invalid")?;
        if envelope.schema_version != INPUT_SCHEMA
            || !(1..=MAX_ROUNDS).contains(&envelope.rounds)
            || !(2..=2 * MAX_DATA).contains(&envelope.data_hex.len())
            || !envelope
                .data_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("artifact_invalid");
        }
        let data = hex::decode(envelope.data_hex).map_err(|_| "artifact_invalid")?;
        Ok(Self {
            data,
            rounds: envelope.rounds,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report<'a> {
    schema_version: &'a str,
    capability: &'a str,
    backend: Capability,
    job_id: &'a str,
    sha256: &'a str,
    bytes: usize,
    data_bytes: usize,
    rounds: u32,
    output_sha256: String,
}

pub(super) fn is_typed_report(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|report| {
        matches!(
            report["schema_version"].as_str(),
            Some(OUTPUT_SCHEMA | cuda::OUTPUT_SCHEMA)
        )
    })
}

pub(super) fn validate_report(
    bytes: &[u8],
    job: &str,
    digest: &str,
    input_size: Option<usize>,
    expected: Option<Capability>,
) -> Result<(), &'static str> {
    let cuda_report = serde_json::from_slice::<serde_json::Value>(bytes)
        .is_ok_and(|report| report["schema_version"] == cuda::OUTPUT_SCHEMA);
    if cuda_report || matches!(expected, Some(Capability::CudaAddOne(_))) {
        return cuda::validate_report(bytes, job, digest, input_size, expected);
    }
    let report: Report<'_> = serde_json::from_slice(bytes).map_err(|_| "evidence_invalid")?;
    if report.schema_version != OUTPUT_SCHEMA
        || report.capability != CAPABILITY
        || report.backend != Capability::PrivateSha256
        || report.job_id != job
        || report.sha256 != digest
        || !(1..=MAX_INPUT).contains(&report.bytes)
        || input_size.is_some_and(|expected| report.bytes != expected)
        || !(1..=MAX_DATA).contains(&report.data_bytes)
        || !(1..=MAX_ROUNDS).contains(&report.rounds)
        || report.output_sha256.len() != 64
        || !report
            .output_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("evidence_invalid");
    }
    Ok(())
}

/// Attached by trusted worker bootstrap before the existing process seal.
/// Availability is advisory. Only the journal can admit and enter an operation.
pub(super) trait Binding: Send {
    fn capability(&self) -> Capability {
        Capability::PrivateSha256
    }

    fn execute_cuda(
        self: Box<Self>,
        _deadline: Instant,
        _stop: &dyn Fn() -> bool,
    ) -> Result<cuda::Readback, &'static str> {
        Err("execution_uncertain")
    }

    fn ready(&mut self, capability: Capability) -> Result<(), &'static str>;

    /// Return a digest or "stopped" only after the exact work process and
    /// its execution domain have been joined. Loss of proof is uncertain.
    fn execute(
        self: Box<Self>,
        input: &Input,
        deadline: Instant,
        stop: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], &'static str>;
}

pub(super) fn execute(
    binding: Box<dyn Binding>,
    capability: Capability,
    input: &[u8],
    job: &str,
    digest: &str,
    deadline: Instant,
    stop: &dyn Fn() -> bool,
) -> Result<Vec<u8>, &'static str> {
    if binding.capability() != capability {
        return Err("execution_uncertain");
    }
    if let Capability::CudaAddOne(uuid) = capability {
        cuda::validate_input(input)?;
        let output = binding.execute_cuda(deadline, stop)?;
        return cuda::report(uuid, output, job, digest, input.len());
    }
    let envelope = Input::parse(input)?;
    let output = binding.execute(&envelope, deadline, stop)?;
    serde_json::to_vec(&Report {
        schema_version: OUTPUT_SCHEMA,
        capability: CAPABILITY,
        backend: Capability::PrivateSha256,
        job_id: job,
        sha256: digest,
        bytes: input.len(),
        data_bytes: envelope.data.len(),
        rounds: envelope.rounds,
        output_sha256: hex::encode(output),
    })
    .map_err(|_| "execution_uncertain")
}

/// One child, started before W's process seal, only after a trusted bootstrap
/// selects this binding. No request can choose the executable, arguments or
/// environment. The child gets a bounded stdin frame and returns only a digest.
pub(super) struct PrivateProcess {
    child: Child,
    output: File,
    joined: bool,
    #[cfg(test)]
    pub(super) pause: Option<FixturePause>,
}

#[cfg(test)]
pub(super) struct FixturePause {
    pub(super) entered: std::sync::mpsc::SyncSender<u32>,
    pub(super) resume: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl PrivateProcess {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn launch() -> Result<Self, &'static str> {
        let parent = std::process::id();
        let mut cmd = Command::new("/proc/self/exe");
        cmd.env_clear().stdin(Stdio::piped());
        #[cfg(not(test))]
        cmd.arg(ENTRY).stdout(Stdio::piped()).stderr(Stdio::null());
        #[cfg(test)]
        cmd.args([
            "--exact",
            "cosp::la_backend::private_helper_entry",
            "--nocapture",
        ])
        .env("DIFFUSER_PRIVATE_HELPER_TEST", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        // Before exec, prevent leakage of custody/store FDs and arrange for
        // the kernel to kill the private child if the owning worker dies.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() as u32 != parent
                    || libc::syscall(
                        libc::SYS_close_range,
                        3u32,
                        u32::MAX,
                        libc::CLOSE_RANGE_CLOEXEC,
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|_| "capability_unavailable")?;
        #[cfg(not(test))]
        let output: OwnedFd = child.stdout.take().expect("piped stdout").into();
        #[cfg(test)]
        let output: OwnedFd = child.stderr.take().expect("piped stderr").into();
        let mut process = Self {
            child,
            output: File::from(output),
            joined: false,
            #[cfg(test)]
            pause: None,
        };
        let mut poll = libc::pollfd {
            fd: process.output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let mut ready = [0];
        if unsafe { libc::poll(&mut poll, 1, 1000) } != 1
            || process.output.read_exact(&mut ready).is_err()
            || ready != [READY]
            || unsafe { libc::fcntl(poll.fd, libc::F_SETFL, libc::O_NONBLOCK) } != 0
        {
            return Err("capability_unavailable");
        }
        process.ready(Capability::PrivateSha256)?;
        Ok(process)
    }

    #[cfg(test)]
    pub(super) fn pid(&self) -> u32 {
        self.child.id()
    }

    fn kill_and_join(&mut self) -> Result<Option<std::process::ExitStatus>, &'static str> {
        let signalled = self.child.kill().is_ok();
        let status = self.child.wait().map_err(|_| "execution_uncertain")?;
        self.joined = true;
        Ok(signalled.then_some(status))
    }

    fn result(&mut self, deadline: Instant) -> Result<[u8; 32], &'static str> {
        if Instant::now() >= deadline {
            return Err("stopped");
        }
        let mut output = [0; 32];
        self.output
            .read_exact(&mut output)
            .map_err(|_| "execution_uncertain")?;
        let mut extra = [0];
        if self.output.read(&mut extra).ok() != Some(0) {
            return Err("execution_uncertain");
        }
        Ok(output)
    }
}

impl Drop for PrivateProcess {
    fn drop(&mut self) {
        if !self.joined {
            let _ = self.kill_and_join();
        }
    }
}

impl Binding for PrivateProcess {
    fn ready(&mut self, capability: Capability) -> Result<(), &'static str> {
        if capability != Capability::PrivateSha256
            || self.child.try_wait().ok() != Some(None)
            || self.child.stdin.is_none()
        {
            return Err("capability_unavailable");
        }
        Ok(())
    }

    fn execute(
        mut self: Box<Self>,
        input: &Input,
        deadline: Instant,
        stop: &dyn Fn() -> bool,
    ) -> Result<[u8; 32], &'static str> {
        let mut send_continue = self.child.stdin.take();
        let mut entered = false;
        if !stop() && Instant::now() < deadline {
            let stdin = send_continue.as_mut().ok_or("execution_uncertain")?;
            // All writes are below PIPE_BUF. The child is initially blocked
            // reading this pipe and cannot retain it in another process.
            let mut frame = Vec::with_capacity(6 + input.data.len());
            frame.extend(input.rounds.to_be_bytes());
            frame.extend((input.data.len() as u16).to_be_bytes());
            frame.extend(&input.data);
            stdin.write_all(&frame).map_err(|_| "execution_uncertain")?;
        }
        loop {
            if !entered {
                let mut signal = [0];
                match self.output.read(&mut signal) {
                    Ok(1) if signal == [STARTED] => {
                        entered = true;
                        #[cfg(test)]
                        if let Some(pause) = &self.pause {
                            pause
                                .entered
                                .try_send(self.child.id())
                                .map_err(|_| "execution_uncertain")?;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => (),
                    Ok(0) => (),
                    _ => return Err("execution_uncertain"),
                }
            }
            if let Some(status) = self.child.try_wait().map_err(|_| "execution_uncertain")? {
                self.joined = true;
                return if status.success() && entered {
                    self.result(deadline)
                } else {
                    Err("execution_uncertain")
                };
            }
            if stop() || Instant::now() >= deadline {
                let status = self.kill_and_join()?;
                return match status {
                    Some(status) if status.signal() == Some(libc::SIGKILL) => Err("stopped"),
                    Some(status) if status.success() && entered => self.result(deadline),
                    _ => Err("execution_uncertain"),
                };
            }
            #[cfg(test)]
            let paused = self
                .pause
                .as_ref()
                .is_some_and(|p| !p.resume.load(std::sync::atomic::Ordering::SeqCst));
            #[cfg(not(test))]
            let paused = false;
            if entered && !paused {
                if let Some(mut input) = send_continue.take() {
                    input
                        .write_all(&[CONTINUE])
                        .map_err(|_| "execution_uncertain")?;
                }
            }
            std::thread::sleep(Duration::from_micros(250));
        }
    }
}

fn restrict_helper() -> io::Result<()> {
    for (resource, value) in [
        (libc::RLIMIT_CPU, 1),
        (libc::RLIMIT_AS, 16 * 1024 * 1024),
        (libc::RLIMIT_CORE, 0),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    let stmt = |code, k| libc::sock_filter {
        code,
        k,
        jt: 0,
        jf: 0,
    };
    let equals = |k| libc::sock_filter {
        code: 0x15,
        k,
        jt: 0,
        jf: 1,
    };
    const RETURN: u16 = 0x06;
    const ALLOW: u32 = 0x7fff0000;
    const DENY: u32 = 0x00050000 | libc::EPERM as u32;
    let mut filter = vec![
        stmt(0x20, 4), // seccomp_data.arch
        libc::sock_filter {
            code: 0x15,
            k: 0xc000003e,
            jt: 1,
            jf: 0,
        },
        stmt(RETURN, 0x80000000),
        stmt(0x20, 0), // seccomp_data.nr
    ];
    for syscall in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_futex,
        libc::SYS_munmap,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_rt_sigreturn,
    ] {
        filter.extend([equals(syscall as u32), stmt(RETURN, ALLOW)]);
    }
    filter.push(stmt(RETURN, DENY));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::syscall(libc::SYS_seccomp, 1, 1, &program) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn helper(output_fd: i32) -> io::Result<()> {
    // The only executable entry always owns these standard descriptors.
    let mut input = unsafe { File::from_raw_fd(libc::STDIN_FILENO) };
    let mut output = unsafe { File::from_raw_fd(output_fd) };
    restrict_helper()?;
    output.write_all(&[READY])?;
    let mut header = [0; 6];
    input.read_exact(&mut header)?;
    let rounds = u32::from_be_bytes(header[..4].try_into().expect("fixed header"));
    let count = u16::from_be_bytes([header[4], header[5]]) as usize;
    if !(1..=MAX_DATA).contains(&count) || !(1..=MAX_ROUNDS).contains(&rounds) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut data = [0; MAX_DATA];
    input.read_exact(&mut data[..count])?;
    let mut digest = Sha256::digest(&data[..count]);
    output.write_all(&[STARTED])?;
    let mut next = [0];
    input.read_exact(&mut next)?;
    if next != [CONTINUE] || input.read(&mut next)? != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    for _ in 1..rounds {
        digest = Sha256::digest(digest);
    }
    output.write_all(&digest)
}

pub(crate) fn maybe_private_helper() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() == Some(std::ffi::OsStr::new(ENTRY)) {
        let ok = args.next().is_none() && helper(libc::STDOUT_FILENO).is_ok();
        std::process::exit(if ok { 0 } else { 70 });
    }
}

#[test]
fn private_helper_entry() {
    if std::env::var_os("DIFFUSER_PRIVATE_HELPER_TEST").is_some() {
        let ok = helper(libc::STDERR_FILENO).is_ok();
        std::process::exit(if ok { 0 } else { 70 });
    }
}
