#!/usr/bin/env python3
"""Diffuser exec adapter for headless Blender 4.5.16 LTS jobs (render.blender.exec/v1).

Trust boundary: invoked solely by Diffuser's HMAC-authenticated local fleet worker
for operator-authorized jobs on configured GPU workers.
"""

import base64
import binascii
import hashlib
import json
import math
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time

PINNED_BLENDER_PATHS = (
    "/opt/blender/blender-4.5.16-linux-x64/blender",
    "/usr/local/blender/blender-4.5.16-linux-x64/blender",
)
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_STDIN_BYTES = 24 * 1024 * 1024
MAX_SCRIPT_BYTES = 256 * 1024
MAX_FILES = 4
MAX_TOTAL_FILE_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_FSIZE_BYTES = 32 * 1024 * 1024
MAX_ARGS = 32
MAX_ARG_LEN = 256
MAX_TAIL_CHARS = 8192
MIN_TIMEOUT_SECS = 10
MAX_TIMEOUT_SECS = 840


def fail(code: str, message: str, extra: dict | None = None) -> None:
    out = {"ok": False, "error_code": code, "error": message}
    if extra:
        out.update(extra)
    sys.stdout.write(json.dumps(out) + "\n")
    sys.exit(0)


def validate_safe_name(name: object, label: str) -> str:
    if not isinstance(name, str) or not SAFE_NAME_RE.match(name) or ".." in name:
        fail("invalid_filename", f"{label} must be a safe single filename segment")
    return name


def resolve_blender_bin() -> str:
    for path in PINNED_BLENDER_PATHS:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and os.access(path, os.X_OK):
            return path
    fail("blender_not_found", "pinned Blender 4.5.16 LTS binary not found")
    return ""


def read_regular_from_dirfd(dir_fd: int, name: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(name, flags, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("output artifact is not a regular file")
        if st.st_size > max_bytes:
            raise ValueError("output artifact exceeds byte limit")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("output artifact exceeds byte limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_log_tail(path: str, max_chars: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return ""
        read_len = min(st.st_size, max_chars * 4)
        if st.st_size > read_len:
            os.lseek(fd, st.st_size - read_len, os.SEEK_SET)
        data = os.read(fd, read_len)
        return data.decode("utf-8", errors="replace")[-max_chars:]
    finally:
        os.close(fd)


def kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def child_setup() -> None:
    os.setsid()
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FSIZE_BYTES, MAX_FSIZE_BYTES))


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        fail("stdin_too_large", "request payload exceeds 24 MiB limit")
    try:
        req = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        fail("invalid_json", f"could not parse JSON input: {exc}")
    if not isinstance(req, dict):
        fail("invalid_input", "request must be a JSON object")

    script_b64 = req.get("script_b64")
    if not isinstance(script_b64, str) or not script_b64.strip():
        fail("missing_script", "script_b64 is required")
    try:
        script_bytes = base64.b64decode(script_b64, validate=True)
    except (binascii.Error, ValueError):
        fail("invalid_script_b64", "script_b64 is not valid base64")
    if len(script_bytes) == 0 or len(script_bytes) > MAX_SCRIPT_BYTES:
        fail("script_size_limit", "decoded script must be 1..262144 bytes")
    if b"\x00" in script_bytes:
        fail("invalid_script", "script contains NUL bytes")
    try:
        script_bytes.decode("utf-8")
    except UnicodeDecodeError:
        fail("invalid_script_utf8", "script must be valid UTF-8")

    raw_args = req.get("args", [])
    if not isinstance(raw_args, list) or len(raw_args) > MAX_ARGS:
        fail("invalid_args", f"args must be a list of at most {MAX_ARGS} strings")
    safe_args: list[str] = []
    for item in raw_args:
        if not isinstance(item, str) or len(item) > MAX_ARG_LEN or "\x00" in item:
            fail("invalid_arg_item", "each arg must be a string <= 256 chars with no NUL bytes")
        safe_args.append(item)

    timeout_raw = req.get("timeout_secs", 300)
    if isinstance(timeout_raw, bool) or not isinstance(timeout_raw, (int, float)) or not math.isfinite(timeout_raw):
        fail("invalid_timeout", "timeout_secs must be a finite number")
    timeout_secs = max(MIN_TIMEOUT_SECS, min(MAX_TIMEOUT_SECS, int(timeout_raw)))

    files_in = req.get("files_in", [])
    if not isinstance(files_in, list) or len(files_in) > MAX_FILES:
        fail("invalid_files_in", f"files_in must be a list of at most {MAX_FILES} items")

    files_out_req = req.get("files_out", [])
    if not isinstance(files_out_req, list) or len(files_out_req) > MAX_FILES:
        fail("invalid_files_out", f"files_out must be a list of at most {MAX_FILES} filenames")
    wanted_out = [validate_safe_name(name, "files_out") for name in files_out_req]

    blender_bin = resolve_blender_bin()

    with tempfile.TemporaryDirectory(prefix="diffuser-blender-") as workdir:
        os.chmod(workdir, 0o700)
        in_dir = os.path.join(workdir, "in")
        out_dir = os.path.join(workdir, "out")
        os.mkdir(in_dir, 0o700)
        os.mkdir(out_dir, 0o700)

        out_dir_fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            total_in = 0
            seen_in: set[str] = set()
            for entry in files_in:
                if not isinstance(entry, dict):
                    fail("invalid_files_in_entry", "each files_in item must be an object")
                name = validate_safe_name(entry.get("name"), "files_in.name")
                if name in seen_in:
                    fail("duplicate_input_file", f"duplicate input filename: {name}")
                seen_in.add(name)
                b64 = entry.get("b64")
                if not isinstance(b64, str):
                    fail("invalid_files_in_b64", f"missing base64 for {name}")
                try:
                    data = base64.b64decode(b64, validate=True)
                except (binascii.Error, ValueError):
                    fail("invalid_files_in_b64", f"invalid base64 for {name}")
                total_in += len(data)
                if total_in > MAX_TOTAL_FILE_BYTES:
                    fail("input_size_limit", "total decoded files_in exceeds 16 MiB")
                dest = os.path.join(in_dir, name)
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, data)
                finally:
                    os.close(fd)

            script_path = os.path.join(workdir, "job.py")
            fd = os.open(script_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, script_bytes)
            finally:
                os.close(fd)

            stdout_log = os.path.join(workdir, "stdout.log")
            stderr_log = os.path.join(workdir, "stderr.log")
            out_fd = os.open(stdout_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            err_fd = os.open(stderr_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

            cmd = [
                blender_bin,
                "--background",
                "--factory-startup",
                "--python-exit-code",
                "1",
                "--python",
                script_path,
                "--",
                "--in-dir",
                in_dir,
                "--out-dir",
                out_dir,
                *safe_args,
            ]
            env = {
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": workdir,
                "TMPDIR": workdir,
            }
            if "CUDA_VISIBLE_DEVICES" in os.environ:
                env["CUDA_VISIBLE_DEVICES"] = os.environ["CUDA_VISIBLE_DEVICES"]

            t0 = time.monotonic()
            timed_out = False
            output_capped = False
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=out_fd,
                    stderr=err_fd,
                    cwd=workdir,
                    env=env,
                    preexec_fn=child_setup,
                    close_fds=True,
                )
            finally:
                os.close(out_fd)
                os.close(err_fd)

            try:
                deadline = t0 + timeout_secs
                while True:
                    rc = proc.poll()
                    try:
                        if os.path.getsize(stdout_log) + os.path.getsize(stderr_log) > MAX_LOG_BYTES:
                            output_capped = True
                            kill_process_group(proc.pid)
                            break
                    except OSError:
                        pass
                    if rc is not None:
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        kill_process_group(proc.pid)
                        break
                    time.sleep(0.1)
            finally:
                # Always terminate any surviving descendants in the job process group before reaping
                kill_process_group(proc.pid)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

            # Post-exit final log size check
            try:
                if os.path.getsize(stdout_log) + os.path.getsize(stderr_log) > MAX_LOG_BYTES:
                    output_capped = True
            except OSError:
                pass

            duration_secs = round(time.monotonic() - t0, 3)
            stdout_tail = read_log_tail(stdout_log, MAX_TAIL_CHARS)
            stderr_tail = read_log_tail(stderr_log, MAX_TAIL_CHARS)

            if output_capped:
                fail(
                    "output_limit_exceeded",
                    f"Blender job output exceeded {MAX_LOG_BYTES} bytes",
                    {
                        "duration_secs": duration_secs,
                        "stdout_tail": stdout_tail,
                        "stderr_tail": stderr_tail,
                    },
                )

            if timed_out:
                fail(
                    "timeout",
                    f"Blender job exceeded {timeout_secs}s timeout",
                    {
                        "duration_secs": duration_secs,
                        "stdout_tail": stdout_tail,
                        "stderr_tail": stderr_tail,
                    },
                )

            if proc.returncode != 0:
                fail(
                    "blender_failed",
                    f"Blender exited with code {proc.returncode}",
                    {
                        "exit_code": proc.returncode,
                        "duration_secs": duration_secs,
                        "stdout_tail": stdout_tail,
                        "stderr_tail": stderr_tail,
                    },
                )

            files_out = []
            total_out = 0
            for name in wanted_out:
                try:
                    remaining = MAX_TOTAL_FILE_BYTES - total_out
                    data = read_regular_from_dirfd(out_dir_fd, name, remaining)
                except FileNotFoundError:
                    fail("missing_output_file", f"expected output file not found: {name}")
                except Exception as exc:
                    fail("invalid_output_file", f"could not read output file {name}: {exc}")
                total_out += len(data)
                files_out.append(
                    {
                        "name": name,
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "b64": base64.b64encode(data).decode("ascii"),
                    }
                )

            sys.stdout.write(
                json.dumps(
                    {
                        "ok": True,
                        "exit_code": 0,
                        "blender_bin": blender_bin,
                        "duration_secs": duration_secs,
                        "files_out": files_out,
                        "stdout_tail": stdout_tail,
                        "stderr_tail": stderr_tail,
                    }
                )
                + "\n"
            )
        finally:
            os.close(out_dir_fd)


if __name__ == "__main__":
    main()
