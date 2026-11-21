"""Fail-closed lifecycle for Colab seats sharing one account."""

import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from artifacts import ArtifactError, Artifacts, GUEST_ARTIFACTS, MAX_FILE_BYTES, MAX_TOTAL_BYTES
from presets import CU_FLOOR, LANE_ID, LaneConfig, PRESETS, account_limit, lane_id
from secure_io import (
    JsonSizeError, TEMP_FLAGS, directory, load_json, open_regular, read_json, unlink_regular, write_json,
)

CONTROL_TIMEOUT = 10
DEFAULT_TIMEOUT = 180
MAX_CLI_OUTPUT = 256 * 1024
JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
GENERATION = re.compile(r"[0-9a-f]{12}")
NUMBERED_INTENT = re.compile(r"seat-(0|[1-9][0-9]{0,9})\.intent\.json")
BALANCE = re.compile(
    r"(?:Current )?balance: ([+-]?[0-9]{1,24}(?:\.[0-9]{1,12})?)(?: compute units| CU)?",
    re.IGNORECASE,
)
EMPTY_SESSIONS = "[colab] No active sessions found on server."
SESSION_ROW = re.compile(
    r"\[(?P<name>[^\[\]\r\n]+)\] [^\s|]+ \| Hardware: (?P<gpu>[A-Za-z0-9][A-Za-z0-9_-]{0,63})"
    r" \| Shape: (?:Standard|High-RAM) \| Variant: (?:DEFAULT|GPU|TPU)"
)
PRUNED = re.compile(r"\[colab\] Pruned [1-9][0-9]* stale local session\(s\)\.")
PROBE_COMMAND = (
    "nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader"
)


@dataclass
class CliResult:
    stdout: str
    returncode: int
    has_stderr: bool


class Refusal(Exception):
    pass


@contextlib.contextmanager
def cancellation():
    received = None

    def remember(signum, _frame):
        nonlocal received
        received = signum

    previous = {signum: signal.signal(signum, remember)
                for signum in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield lambda: received is not None
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def exists(path):
    try:
        with directory(path.parent) as parent:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def make_state_dir(path):
    with directory(path, create=True, private=True):
        pass


def directory_entries(path, *, private=True):
    try:
        with directory(path, private=private) as fd:
            return sorted(os.listdir(fd))
    except FileNotFoundError:
        return []


write_state = write_json


def state_directory(root=None):
    return Path(root or os.environ.get(
        "DIFFUSER_COLAB_STATE_DIR", "/var/lib/diffuser-colab",
    )).absolute()


def lane_directory(root, name):
    try:
        with directory(root) as parent:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)


def intent_paths(path):
    return [path / name for name in directory_entries(path) if (
        name == "active_intent.json" or NUMBERED_INTENT.fullmatch(name)
    )]


def read_intent(path):
    data = read_json(path)
    if not isinstance(data, dict):
        raise ValueError("invalid intent object")
    return data


def owner_alive(pid):
    if type(pid) is not int or not 0 < pid <= 2**31 - 1:
        raise ValueError("invalid owner PID")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


@contextlib.contextmanager
def locked_file(path, deadline=None, cancelled=lambda: False):
    with directory(path.parent) as parent:
        fd = open_regular(parent, path.name, os.O_CREAT | os.O_RDWR | os.O_NONBLOCK
                          | os.O_NOFOLLOW | os.O_CLOEXEC, private=True)
    try:
        while True:
            if cancelled():
                raise Refusal("interrupted")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if deadline is None:
                    raise Refusal("seat_busy") from None
                if time.monotonic() >= deadline:
                    raise Refusal("account_lock_timeout") from None
                time.sleep(0.02)
        yield fd
    finally:
        # Closing lets a surviving CLI process retain its inherited lock.
        os.close(fd)


def account_lock(root, deadline, cancelled=lambda: False):
    directory = root / "_account"
    make_state_dir(root)
    make_state_dir(directory)
    return locked_file(directory / "account.lock", deadline, cancelled)


@contextlib.contextmanager
def seat_lock(state_dir, index):
    with contextlib.ExitStack() as stack:
        locks = []
        if index == 0:
            locks.append(stack.enter_context(locked_file(state_dir / "seat.lock")))
        locks.append(stack.enter_context(locked_file(state_dir / f"seat-{index}.lock")))
        yield tuple(locks)


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


def drain_group(child, grace=0.2, kill_wait=1.0):
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, kill_wait)):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, sig)
        deadline = time.monotonic() + wait
        while True:
            child.poll()
            if not group_exists(child.pid):
                return
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
    raise Refusal("cli_unreaped")


class Engine:
    def __init__(self, config, colab_bin=None, state_root=None):
        self.config = config
        self.colab_bin = os.fspath(colab_bin or os.environ.get(
            "DIFFUSER_COLAB_BIN", "/opt/colab-cli-venv/bin/colab"
        ))
        self.state_root = state_directory(state_root)
        self.state_dir = self.state_root / lane_id(config.lane_id)
        self.intent_path = self.state_dir / "active_intent.json"
        self.quarantine_path = self.state_dir / "quarantine.json"
        self.account_config = self.state_root / "_account" / "cli-sessions.json"
        self.cli_config = self.account_config
        self.floor = max(CU_FLOOR, config.min_cu_floor)
        self.seat_fds = ()
        self.account_fd = None

    def run_cli(self, args, deadline, cancelled, cli_config=None, file_limit=None):
        config_path = cli_config or self.cli_config
        argv = [self.colab_bin, "--config", str(config_path), *args]
        if "pay" in argv:
            raise Refusal("purchase_forbidden")
        if cancelled():
            raise Refusal("interrupted")
        if time.monotonic() >= deadline:
            raise Refusal("timeout")

        try:
            with directory(config_path.parent, create=True, private=True) as parent:
                try:
                    os.close(open_regular(parent, config_path.name, private=True))
                except FileNotFoundError:
                    pass
            held_fds = self.seat_fds
            if self.account_fd is not None:
                held_fds += (self.account_fd,)
            if file_limit is not None:
                argv = [sys.executable, "-c", (
                    "import os, resource, sys; "
                    "limit = int(sys.argv[1]); "
                    "resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit)); "
                    "os.execvp(sys.argv[2], sys.argv[2:])"
                ), str(file_limit), *argv]
            child = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, pass_fds=held_fds, umask=0o077,
            )
        except (OSError, ValueError):
            raise Refusal("cli_unavailable") from None

        output = bytearray()
        captured = 0
        has_stderr = False
        try:
            with child.stdout, child.stderr, selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                selector.register(child.stderr, selectors.EVENT_READ)
                while selector.get_map() or child.poll() is None:
                    if cancelled():
                        raise Refusal("interrupted")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Refusal("timeout")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        captured += len(chunk)
                        if captured > MAX_CLI_OUTPUT:
                            raise Refusal("cli_output_limit")
                        if key.fileobj is child.stderr:
                            has_stderr = True
                        else:
                            output.extend(chunk)
            return CliResult(output.decode("utf-8", errors="replace"), child.returncode, has_stderr)
        finally:
            # The session leader may already have exited while descendants remain.
            if child.returncode is None or group_exists(child.pid):
                drain_group(child)
            with directory(config_path.parent) as parent:
                try:
                    os.close(open_regular(parent, config_path.name, private=True))
                except FileNotFoundError:
                    pass

    def control(self, args, cancelled, cli_config=None, deadline=math.inf):
        return self.run_cli(
            args, min(deadline, time.monotonic() + CONTROL_TIMEOUT), cancelled, cli_config,
        )

    def usage(self, cancelled, cli_config=None, deadline=math.inf):
        try:
            result = self.control(["usage"], cancelled, cli_config, deadline)
        except Refusal as exc:
            if str(exc) in ("interrupted", "purchase_forbidden", "cli_unreaped"):
                raise
            raise Refusal("usage_unavailable") from None
        matches = [BALANCE.fullmatch(line.strip()) for line in result.stdout.splitlines()
                   if re.match(r"\s*(?:Current )?balance\s*:", line, re.IGNORECASE)]
        if result.returncode or result.has_stderr or len(matches) != 1 or matches[0] is None:
            raise Refusal("usage_unavailable")
        balance = Decimal(matches[0][1])
        if not math.isfinite(float(balance)):
            raise Refusal("usage_unavailable")
        return balance

    def sessions(self, cancelled, cli_config=None, deadline=math.inf):
        try:
            result = self.control(["sessions"], cancelled, cli_config, deadline)
        except Refusal as exc:
            if str(exc) in ("interrupted", "purchase_forbidden", "cli_unreaped"):
                raise
            raise Refusal("sessions_unavailable") from None
        if result.returncode or result.has_stderr:
            raise Refusal("sessions_unavailable")
        update_prefixes = (
            "[colab] A new version of Colab CLI is available:",
            "[colab] You can run 'colab update",
            "[colab] Run 'colab update'",
            "[colab] Run 'pip install --upgrade google-colab-cli'",
            "[colab] To silence this check,",
        )
        lines = [
            line.strip() for line in result.stdout.splitlines()
            if line.strip() and not line.strip().startswith(update_prefixes)
        ]
        if lines and PRUNED.fullmatch(lines[0]):
            lines.pop(0)
        if lines == [EMPTY_SESSIONS]:
            return {}, 0
        if not lines:
            raise Refusal("sessions_ambiguous")
        named = {}
        anonymous = 0
        for line in lines:
            row = SESSION_ROW.fullmatch(line)
            if row is None:
                raise Refusal("sessions_ambiguous")
            name, gpu = row["name"], row["gpu"]
            if name == "?":
                anonymous += 1
            elif name in named or name == "colab":
                raise Refusal("sessions_ambiguous")
            else:
                named[name] = gpu
        return named, anonymous

    def accepting(self):
        try:
            path = self.state_dir / "OWNER-GO.json"
            marker = read_json(path)
        except FileNotFoundError:
            return self.config.accepting
        except (OSError, ValueError, RecursionError):
            return False
        return isinstance(marker, dict) and marker.get("unparked") is True

    def status(self, cancelled):
        cfg = self.config
        accepting = self.accepting()
        result = {
            "ok": True, "lane_id": cfg.lane_id, "accepting": accepting, "parked": not accepting,
            "quarantined": exists(self.quarantine_path), "active_intent": bool(intent_paths(self.state_dir)),
            "allowed_gpus": list(cfg.allowed_gpus), "gpu_default": cfg.allowed_gpus[0],
            "min_cu_floor": self.floor, "max_cu_per_job": cfg.max_cu_per_job,
            "max_seats": cfg.max_seats, "max_account_vms": account_limit(cfg.max_account_vms),
            "max_walltime_secs": cfg.max_walltime_secs, "cu_balance": None, "session_count": None,
        }
        errors = {}
        # The pinned CLI updates session metadata during listing. Use scratch state for status.
        with tempfile.TemporaryDirectory() as scratch:
            cli_config = Path(scratch) / "sessions.json"
            try:
                result["cu_balance"] = float(self.usage(cancelled, cli_config))
            except Refusal as exc:
                errors["usage"] = str(exc)
            try:
                named, anonymous = self.sessions(cancelled, cli_config)
                result["session_count"] = len(named) + anonymous
            except Refusal as exc:
                errors["sessions"] = str(exc)
        if errors:
            result.update(ok=False, error=next(iter(errors.values())), checks=errors)
        return result

    def parameters(self, request, action):
        cfg = self.config
        gpu = request.get("gpu", cfg.allowed_gpus[0])
        if isinstance(gpu, str) and gpu.strip().upper() in {name.upper() for name in cfg.forbidden_gpus}:
            raise Refusal("gpu_forbidden_for_train" if cfg.legacy_seat else "gpu_forbidden")
        if not isinstance(gpu, str) or gpu not in cfg.allowed_gpus:
            raise Refusal("gpu_not_allowed")

        timeout = request.get("timeout_secs", min(DEFAULT_TIMEOUT, cfg.max_walltime_secs))
        if type(timeout) is not int or not 1 <= timeout <= cfg.max_walltime_secs:
            raise Refusal("invalid_timeout_secs")
        max_cu = request.get("max_cu", cfg.max_cu_per_job)
        if type(max_cu) not in (int, float) or not 0 < max_cu <= cfg.max_cu_per_job:
            raise Refusal("invalid_max_cu")

        command = request.get("command") if action == "exec" else None
        if action == "exec":
            if not isinstance(command, str) or not command.strip() or "\x00" in command:
                raise Refusal("invalid_command")
        job_id = os.environ.get("DIFFUSER_JOB_ID") or request.get("job_id", uuid.uuid4().hex[:12])
        if not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id):
            raise Refusal("invalid_job_id")
        return gpu, timeout, max_cu, command, job_id

    def session_name(self, job_id, generation):
        return f"diffuser-{self.config.lane_id}-{job_id}-{generation}"

    @contextlib.contextmanager
    def account_guard(self, deadline, cancelled=lambda: False):
        with account_lock(self.state_root, deadline, cancelled) as fd:
            self.account_fd = fd
            try:
                yield
            finally:
                self.account_fd = None

    def check_account_capacity(self):
        count = 0
        limit = account_limit(self.config.max_account_vms)
        for name in directory_entries(self.state_root):
            directory = self.state_root / name
            if not LANE_ID.fullmatch(directory.name):
                continue
            # Ignore unrelated entries while rejecting symlinked lane directories.
            if not lane_directory(self.state_root, name):
                continue
            paths = intent_paths(directory)
            if directory == self.state_dir and len(paths) >= self.config.max_seats:
                raise Refusal("seat_busy")
            count += len(paths)
            for path in paths:
                try:
                    other_limit = read_intent(path).get("max_account_vms")
                except (ValueError, OSError, RecursionError):
                    continue
                if type(other_limit) is int and other_limit > 0:
                    limit = min(limit, other_limit)
        if count >= limit:
            raise Refusal("account_capacity_reached")
        return limit

    def recovery_target(self, require_pid=False):
        intent = read_intent(self.intent_path)
        if require_pid and "owner_pid" not in intent:
            raise Refusal("owner_pid_missing")
        if "owner_pid" in intent:
            if owner_alive(intent.get("owner_pid")):
                raise Refusal("owner_alive")
        job_id = intent["job_id"]
        generation = intent["generation"]
        session = intent["session_name"]
        store = intent.get("cli_store")
        if not (
            intent["lane_id"] == self.config.lane_id and JOB_ID.fullmatch(job_id)
            and GENERATION.fullmatch(generation) and session == self.session_name(job_id, generation)
            and store in (None, "account")
        ):
            raise ValueError("invalid intent ownership")
        self.cli_config = self.account_config if store == "account" else (
            self.state_dir / "cli-sessions.json"
        )
        return session

    def recover(self):
        try:
            session = self.recovery_target(require_pid=self.intent_path.name != "active_intent.json")
        except Refusal as exc:
            if str(exc) == "owner_alive":
                raise Refusal("seat_busy") from None
            return self.quarantine(None, None, [str(exc)])
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            return self.quarantine(None, None, ["intent_invalid"])
        return self.cleanup(session)

    def session_records(self):
        stores = dict.fromkeys((self.account_config, self.cli_config))
        for attempt in range(4):
            try:
                records = {}
                for store in stores:
                    try:
                        data = read_json(store)
                    except FileNotFoundError:
                        continue
                    if not isinstance(data, dict) or records.keys() & data.keys():
                        raise ValueError("invalid session metadata")
                    records.update(data)
                return records
            except (OSError, ValueError, RecursionError):
                if attempt == 3:
                    raise Refusal("sessions_unavailable") from None
                time.sleep(0.02)

    def account_sessions(self, cancelled, deadline=math.inf, records=None):
        # Listing can rewrite session state. Give it a snapshot so it cannot overwrite
        # another seat's kernel metadata while that seat is executing.
        if records is None:
            records = self.session_records()
        with tempfile.TemporaryDirectory() as scratch:
            snapshot = Path(scratch) / "sessions.json"
            if records:
                write_state(snapshot, records)
            return self.sessions(cancelled, snapshot, deadline)

    def quarantine(self, session, leaked, reasons):
        result = {
            "ok": False, "error": "cleanup_quarantined", "session_name": session,
            "cleanup_verified": False, "leaked_owned_sessions": leaked,
        }
        try:
            write_state(self.quarantine_path, {
                "lane_id": self.config.lane_id, "created_at": datetime.now(timezone.utc).isoformat(),
                **result, "reasons": reasons,
            })
        except OSError:
            # The existing intent still blocks reuse until cleanup can be proven.
            result["quarantine_persisted"] = False
        return result

    def cleanup(self, session, work_child_unreaped=False):
        try:
            with self.account_guard(time.monotonic() + 2 * CONTROL_TIMEOUT):
                return self.cleanup_locked(session, work_child_unreaped)
        except (Refusal, OSError):
            return self.quarantine(session, None, ["cleanup_lock_unavailable"])

    def cleanup_locked(self, session, work_child_unreaped=False):
        def ignore_cancellation():
            return False

        reasons = ["work_child_unreaped"] if work_child_unreaped else []
        records = None
        with contextlib.suppress(Refusal):
            # Retain the endpoint mapping in case the provider still lists it after stop.
            records = self.session_records()
        try:
            result = self.control(["stop", "-s", session], ignore_cancellation)
            if result.returncode or result.has_stderr:
                reasons.append("stop_failed")
        except (Refusal, OSError):
            reasons.append("stop_failed")

        leaked = None
        try:
            named, anonymous = self.account_sessions(ignore_cancellation, records=records)
            if session in named:
                leaked = 1
                reasons.append("owned_session_live")
            if anonymous:
                reasons.append("anonymous_sessions")
            elif leaked is None:
                leaked = 0
        except Refusal as exc:
            reasons.append(str(exc))
        except OSError:
            reasons.append("sessions_unavailable")
        if not reasons:
            try:
                unlink_regular(self.intent_path)
                return {"cleanup_verified": True, "leaked_owned_sessions": 0}
            except OSError:
                reasons.append("intent_release_failed")
        return self.quarantine(session, leaked, reasons)

    def execute_remote(self, session, gpu, command, deadline, cancelled, uploads=(), downloads=()):
        marker = "DIFFUSER_" + uuid.uuid4().hex
        # Verify the guest GPU before executing the workload. The provider listing also
        # confirms the literal SKU, including G4, whose guest model name may differ.
        script = f"""
import csv, hashlib, json, os, re, stat, subprocess, threading

marker = {marker!r}
requested = {gpu!r}
command = {command!r}
denied = {tuple(name.upper() for name in self.config.forbidden_gpus)!r}
known = {tuple(PRESETS)!r}
uploads = {uploads!r}
downloads = {downloads!r}
receipt = {{"gpu_observed": None, "exit_code": None, "error": None}}
{GUEST_ARTIFACTS if uploads or downloads else ""}
# Drain guest output in fixed-size chunks while retaining only a preview.
def run_guest(argv, shell=False):
    read_fd, write_fd = os.pipe()
    preview = bytearray()

    def drain():
        with os.fdopen(read_fd, "rb") as stream:
            for chunk in iter(lambda: stream.read(8192), b""):
                preview.extend(chunk[:8193 - len(preview)])

    reader = threading.Thread(target=drain)
    reader.start()
    try:
        result = subprocess.run(
            argv, shell=shell, stdin=subprocess.DEVNULL, stdout=write_fd,
            stderr=subprocess.DEVNULL,
        )
    finally:
        os.close(write_fd)
        reader.join()
    return result.returncode, preview

try:
    status, probe_data = run_guest({PROBE_COMMAND.split()!r})
    if status or len(probe_data) > 8192:
        raise ValueError
    devices = list(csv.reader(probe_data.decode().splitlines(), skipinitialspace=True))
    if not devices or any(len(row) != 3 or not all(row) for row in devices):
        raise ValueError
    names = [row[0].strip() for row in devices]
    receipt["gpu_observed"] = names[0]
    receipt["gpu_memory"] = devices[0][1]
    receipt["driver_version"] = devices[0][2]
    model_parts = [set(re.findall(r"[A-Z0-9_-]+", name.upper())) for name in names]
    guest_skus = [set(re.findall(r"\\b(?:G4|L4|T4|H100|A100)\\b", name.upper())) for name in names]
    expected_skus = ({{requested}}, set()) if requested == "G4" else ({{requested}},)
    if any(parts.intersection(denied) for parts in model_parts + guest_skus) or (
        requested in known and any(sku not in expected_skus for sku in guest_skus)
    ):
        receipt["error"] = "gpu_mismatch"
    elif command is not None:
        receipt["exit_code"], preview = run_guest(command, shell=True)
        if not receipt["exit_code"]:
            receipt["stdout"] = preview[:8192].decode("utf-8", errors="replace").rstrip("\\n")
        if receipt["exit_code"]:
            receipt["error"] = "command_failed"
except (OSError, ValueError, subprocess.CalledProcessError):
    receipt["error"] = "gpu_probe_failed" if receipt["gpu_observed"] is None else "command_failed"
if receipt["error"] is None and (uploads or downloads):
    try:
        for path in uploads:
            prepare_upload(path)
        remaining = {MAX_TOTAL_BYTES}
        outputs = []
        for path in downloads:
            output = verify_output(path, min(remaining, {MAX_FILE_BYTES}))
            outputs.append(output)
            remaining -= output["bytes"]
        receipt["artifact_metadata"] = outputs
    except (OSError, ValueError):
        receipt["error"] = "guest_artifact_invalid"
print("\\n" + marker + json.dumps(receipt), flush=True)
"""
        with tempfile.TemporaryDirectory(prefix="diffuser-colab-exec-") as scratch:
            script_file = Path(scratch) / "exec.py"
            with directory(script_file.parent, private=True) as parent:
                fd = open_regular(parent, script_file.name, TEMP_FLAGS, private=True)
                with os.fdopen(fd, "w", encoding="utf-8") as file:
                    file.write(script)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refusal("timeout")
            result = self.run_cli(
                ["exec", "-s", session, "-f", str(script_file), "--timeout", str(remaining)],
                deadline, cancelled,
            )
        if result.returncode or result.has_stderr:
            raise Refusal("command_failed")
        lines = result.stdout.splitlines()
        receipts = [line for line in lines if line.startswith(marker)]
        if len(receipts) != 1:
            raise Refusal("exec_result_unavailable")
        try:
            payload = json.loads(receipts[0][len(marker):])
            error = payload["error"]
            exit_code = payload["exit_code"]
            if error not in (None, "gpu_mismatch", "gpu_probe_failed", "command_failed",
                             "guest_artifact_invalid"):
                raise ValueError
            if exit_code is not None and type(exit_code) is not int:
                raise ValueError
            receipt = {"error": error, "exit_code": exit_code}
            for key, pattern in (
                ("gpu_observed", r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,95}"),
                ("gpu_memory", r"[0-9]{1,12} MiB"),
                ("driver_version", r"[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}"),
            ):
                value = payload.get(key)
                receipt[key] = value if isinstance(value, str) and re.fullmatch(pattern, value) else None
            if error is None and (not receipt["gpu_observed"] or exit_code != (0 if command else None)):
                raise ValueError
            if error is None and downloads:
                metadata = payload["artifact_metadata"]
                if not isinstance(metadata, list) or len(metadata) != len(downloads):
                    raise ValueError
                total = 0
                for entry in metadata:
                    if not isinstance(entry, dict) or entry.keys() != {"bytes", "sha256"}:
                        raise ValueError
                    size = entry["bytes"]
                    if (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                            or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
                        raise ValueError
                    total += size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError
                receipt["artifact_metadata"] = metadata
        except (ValueError, TypeError, KeyError, RecursionError):
            raise Refusal("exec_result_unavailable") from None
        if error is None:
            stdout = payload.get("stdout", "")
            if not isinstance(stdout, str):
                raise Refusal("exec_result_unavailable")
            receipt["stdout"] = compact_output(stdout)
        return receipt

    def allocate(self, params, cancelled, artifacts, scratch):
        gpu, timeout, max_cu, command, job_id = params
        deadline = time.monotonic() + timeout

        def check_deadline():
            if cancelled():
                raise Refusal("interrupted")
            if time.monotonic() >= deadline:
                raise Refusal("timeout")

        if scratch is not None:
            artifacts.prepare(scratch, check_deadline)
        generation = uuid.uuid4().hex[:12]
        session = self.session_name(job_id, generation)
        result = {
            "ok": False, "gpu_requested": gpu, "gpu_observed": None, "cu_before": None,
            "cu_after": None, "cu_delta": None, "max_cu": max_cu, "session_name": session,
        }
        self.cli_config = self.account_config
        balance = None
        reserving = False
        try:
            with self.account_guard(deadline, cancelled):
                self.require_accepting()
                limit = self.check_account_capacity()
                balance = self.usage(cancelled, deadline=deadline)
                if balance < Decimal(str(self.floor)):
                    raise Refusal("cu_below_floor")
                check_deadline()
                result["cu_before"] = float(balance)
                started_at = datetime.now(timezone.utc).isoformat()
                intent = {
                    "lane_id": self.config.lane_id, "job_id": job_id, "generation": generation,
                    "session_name": session, "created_at": started_at, "started_at": started_at,
                    "gpu": gpu, "owner_pid": os.getpid(), "max_account_vms": limit,
                    "cli_store": "account",
                }
                reserving = True
                write_state(self.intent_path, intent)
                new = self.run_cli(["new", "-s", session, "--gpu", gpu], deadline, cancelled)
                if new.returncode:
                    raise Refusal("allocation_failed")
                named, _ = self.account_sessions(cancelled, deadline)
                if named.get(session) != gpu:
                    raise Refusal("gpu_mismatch" if session in named else "allocation_unverified")
            if artifacts.uploads:
                prepared = self.execute_remote(
                    session, gpu, None, deadline, cancelled,
                    uploads=[remote for _, remote in artifacts.uploads],
                )
                if prepared["error"]:
                    raise Refusal(prepared["error"])
                for index, (_, remote) in enumerate(artifacts.uploads):
                    upload = self.run_cli(
                        ["upload", "-s", session, str(scratch / f"in-{index}"), f"content/{remote}"],
                        deadline, cancelled,
                    )
                    if upload.returncode or upload.has_stderr:
                        raise Refusal("artifact_upload_failed")
                    unlink_regular(scratch / f"in-{index}")
            remote = self.execute_remote(
                session, gpu, command, deadline, cancelled,
                downloads=[remote for _, remote in artifacts.downloads],
            )
            metadata = remote.pop("artifact_metadata", [])
            result.update(remote)
            if remote["error"] is None:
                remaining_download = MAX_TOTAL_BYTES
                if artifacts.downloads:
                    result["files_out"] = []
                for index, ((local, path), expected) in enumerate(zip(artifacts.downloads, metadata)):
                    pending = scratch / f"out-{index}"
                    download = self.run_cli(
                        ["download", "-s", session, f"content/{path}", str(pending)],
                        deadline, cancelled, file_limit=min(remaining_download, MAX_FILE_BYTES),
                    )
                    if download.returncode or download.has_stderr:
                        raise Refusal("artifact_download_failed")
                    verified = artifacts.publish(pending, local, expected, check_deadline)
                    unlink_regular(pending)
                    remaining_download -= verified["bytes"]
                    result["files_out"].append({"local": local, "remote": path, **verified})
                result["ok"] = True
                del result["error"]
        except ArtifactError as exc:
            result.update(ok=False, error=str(exc))
        except Refusal as exc:
            if not reserving:
                raise
            result.update(ok=False, error=str(exc))
        except (OSError, ValueError):
            if not reserving:
                raise
            result.update(ok=False, error="adapter_io_error")
        finally:
            if reserving and exists(self.intent_path):
                result.update(self.cleanup(session, result.get("error") == "cli_unreaped"))
            elif reserving:
                result.update(cleanup_verified=False, leaked_owned_sessions=None)

        try:
            after = self.usage(lambda: False)
            delta = balance - after
            result.update(cu_after=float(after), cu_delta=float(delta))
            if result["ok"] and delta > Decimal(str(max_cu)):
                result.update(ok=False, error="cu_budget_exceeded")
        except Refusal:
            if result["ok"]:
                result.update(ok=False, error="usage_unavailable")
        if cancelled() and result.get("error") != "cleanup_quarantined":
            result.update(ok=False, error="interrupted")
        if not result["ok"]:
            result.pop("stdout", None)
        if "stdout" in result and result.get("files_out") and len(json.dumps(result)) > 3600:
            result["stdout"] = "[output truncated]"
        return result

    def require_accepting(self):
        if exists(self.quarantine_path):
            raise Refusal("lane_quarantined")
        if not self.accepting():
            raise Refusal("lane_parked")

    def allocation_request(self, request, action, cancelled):
        self.require_accepting()
        params = self.parameters(request, action)
        if action != "exec" and ("files_in" in request or "files_out" in request):
            raise Refusal("artifacts_require_exec")
        artifacts = Artifacts(request, self.state_dir)
        make_state_dir(self.state_root)
        make_state_dir(self.state_dir)
        for index in range(self.config.max_seats):
            try:
                with seat_lock(self.state_dir, index) as self.seat_fds:
                    self.require_accepting()
                    numbered = self.state_dir / f"seat-{index}.intent.json"
                    legacy = self.state_dir / "active_intent.json"
                    for path in ((legacy, numbered) if index == 0 else (numbered,)):
                        if exists(path):
                            self.intent_path = path
                            recovered = self.recover()
                            if not recovered["cleanup_verified"]:
                                return recovered
                    self.intent_path = legacy if index == 0 and self.config.legacy_seat else numbered
                    with artifacts.stage() as scratch:
                        return self.allocate(params, cancelled, artifacts, scratch)
            except Refusal as exc:
                if str(exc) != "seat_busy":
                    raise
            finally:
                self.seat_fds = ()
        raise Refusal("seat_busy")

    def handle(self, request, cancelled):
        try:
            if not isinstance(request, dict):
                raise Refusal("invalid_request")
            action = request.get("action")
            if action in ("status", "health"):
                return self.status(cancelled)
            if action not in ("probe", "exec"):
                raise Refusal("invalid_action")
            return {"lane_id": self.config.lane_id, **self.allocation_request(request, action, cancelled)}
        except (Refusal, ArtifactError) as exc:
            return {"ok": False, "lane_id": self.config.lane_id, "error": str(exc)}
        except OSError:
            return {"ok": False, "lane_id": self.config.lane_id, "error": "state_unavailable"}
        except ValueError:
            return {"ok": False, "lane_id": self.config.lane_id, "error": "invalid_configuration"}


def compact_output(output):
    # The fleet worker drains its stdout pipe only after the child exits.
    if len(json.dumps(output)) <= 1500:
        return output
    return output[:120] + "\n[output truncated]"


def main(config):
    with cancellation() as cancelled:
        try:
            request = load_json(sys.stdin.buffer)
        except JsonSizeError:
            receipt = {"ok": False, "lane_id": config.lane_id, "error": "request_size_limit"}
        except (OSError, ValueError, RecursionError):
            receipt = {"ok": False, "lane_id": config.lane_id, "error": "invalid_json"}
        else:
            receipt = Engine(config).handle(request, cancelled)
        print(json.dumps(receipt, allow_nan=False), flush=True)
