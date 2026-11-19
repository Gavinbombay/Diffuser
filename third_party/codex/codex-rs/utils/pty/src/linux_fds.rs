//! Linux descriptor cleanup after fork, using only stack storage and syscalls.
//! Stdio and explicitly preserved FDs remain usable. CLOEXEC keeps Rust's
//! spawn-error channel alive until exec succeeds. Cleanup is best-effort:
//! failures do not prevent launch and may leave unrelated descriptors inherited.

// RUN22 modification: the original best-effort policy above is tightened to
// return cleanup errors to the worker spawn hook, preventing exec with leaked FDs.
use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;

pub(crate) fn close_inherited_fds_except(preserved_fds: &[RawFd]) -> io::Result<()> {
    // Mark rather than close: std::process still needs its CLOEXEC error
    // pipe if exec fails. Do not alter flags on explicitly preserved FDs.
    let mut first = 3_u32;
    loop {
        // The keep-list need not be sorted. Walking its gaps leaves each kept
        // FD's flags untouched, without allocating a sorted copy after fork.
        let next = preserved_fds
            .iter()
            .copied()
            .filter_map(|fd| u32::try_from(fd).ok())
            .filter(|&fd| fd >= first)
            .min();
        let last = next.map_or(u32::MAX, |fd| fd - 1);
        if first <= last
        // SAFETY: close_range has no pointers and changes only this child's FDs.
        && unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first,
                last,
                libc::CLOSE_RANGE_CLOEXEC,
            )
        } != 0
        {
            break;
        }
        match next {
            Some(fd) => first = fd + 1,
            None => return Ok(()),
        }
    }
    // Older kernels (or seccomp policies) may reject close_range. Read
    // this child's descriptor table without libc's allocating DIR API.
    // Return an error if the fallback also fails. Logging
    // here could allocate or lock after fork; writing to child stderr may block.
    close_from_proc(preserved_fds)
}

fn mark_cloexec(fd: RawFd, preserved_fds: &[RawFd]) -> io::Result<()> {
    if fd <= libc::STDERR_FILENO || preserved_fds.contains(&fd) {
        return Ok(());
    }
    // SAFETY: fcntl operates on the child's descriptors without allocating.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC == 0 {
        // SAFETY: only adds CLOEXEC; existing flags and the descriptor remain intact.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn close_from_proc(preserved_fds: &[RawFd]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    // Open after fork: a proc directory opened in the parent would enumerate
    // the parent's changing descriptor table instead of this child's snapshot.
    // SAFETY: the path is NUL-terminated and open does not allocate.
    let raw = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a new owned descriptor; dropping it only calls close.
    let directory = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut buffer = [0_u8; 4096];
    loop {
        // SAFETY: getdents64 writes at most buffer.len() bytes into stack storage.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count == -1 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            return Ok(());
        }
        let mut entries = &buffer[..count as usize];
        // Linux getdents64 records have two 64-bit fields, a u16 record length,
        // one type byte, then the NUL-terminated name (independent of libc ABI).
        while !entries.is_empty() {
            if entries.len() < 20 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid descriptor directory entry",
                ));
            }
            let length = u16::from_ne_bytes([entries[16], entries[17]]) as usize;
            if length < 20 || length > entries.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid descriptor directory entry",
                ));
            }
            if let Some(fd) = CStr::from_bytes_until_nul(&entries[19..length])
                .ok()
                .and_then(|name| name.to_str().ok())
                .and_then(|name| name.parse::<RawFd>().ok())
            {
                // Abort worker exec if any inherited descriptor cannot be marked.
                mark_cloexec(fd, preserved_fds)?;
            }
            entries = &entries[length..];
        }
    }
}
