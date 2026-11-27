#!/usr/bin/env python3
"""Diffuser gaming-laptop idle-lane guard.

Quiet to the gamer, loud to the fleet.

Poll a laptop for game processes and non-Diffuser GPU load. On the first hit,
drain the fleet worker so the controller stops scheduling jobs, and stop the
local ``uai-diffuser --fleet-worker`` process when one is configured. After
continuous idle for ``idle_cooldown_secs``, start that process again (it
enrolls itself) or POST ``/v1/fleet/workers/enroll`` when ``reenroll`` is set.

Python 3 standard library only. Linux, WSL2, and Windows.
"""

from __future__ import annotations

import argparse
import csv
import errno
import io
import json
import logging
import os
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

LOG = logging.getLogger("gamer_idle_guard")
LOG.addHandler(logging.NullHandler())

ACTIVE_FOR_FLEET = "ACTIVE_FOR_FLEET"
GAMER_ACTIVE = "GAMER_ACTIVE"
COOLDOWN = "COOLDOWN"

DRAIN_BODY = b"{}"
TOKEN_MAX_BYTES = 4096
RESPONSE_MAX_BYTES = 65536
ENROLL_MAX_BYTES = 65536
STATE_VERSION = 1

DEFAULT_WATCHLIST = (
    "steam",
    "cs2",
    "cyberpunk",
    "eldenring",
    "baldursgate",
    "valorant",
    "helldivers",
    "gamescope",
    "wine64-preloader",
)
DEFAULT_DIFFUSER_MARKERS = (
    "uai-diffuser",
    "diffuser",
    "fleet-worker",
)
# Always-on desktop and driver helpers. A game process is not in this list.
# Thresholds still apply when no Diffuser job is on the GPU.
DEFAULT_GPU_IGNORE = (
    "xorg",
    "xwayland",
    "gnome-shell",
    "mutter",
    "kwin",
    "plasmashell",
    "sway",
    "hyprland",
    "dwm.exe",
    "explorer.exe",
    "csrss.exe",
    "sihost.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "textinputhost.exe",
    "applicationframehost.exe",
    "systemsettings.exe",
    "nvcontainer",
    "nvidia-smi",
    "nvsphelper",
    "amdow",
    "radeonsoftware",
)

GPU_QUERY = (
    "--query-gpu=utilization.gpu,memory.used,memory.total",
    "--format=csv,noheader,nounits",
)
APPS_QUERY = (
    "--query-apps=pid,process_name,used_gpu_memory",
    "--format=csv,noheader,nounits",
)
COMPUTE_APPS_QUERY = (
    "--query-compute-apps=pid,process_name,used_gpu_memory",
    "--format=csv,noheader,nounits",
)

_WORKER_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_HEX_RE = re.compile(r"[0-9a-f]+\Z")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_ENROLL_SECRET_KEYS = frozenset(
    {"token", "bearer", "enroll_bearer", "authorization", "password", "secret"}
)
_ENROLL_REQUIRED = (
    "host",
    "rpc_url",
    "rpc_secret_hex",
    "rpc_session",
    "cpu_millicores",
    "ram_bytes",
    "vram_bytes",
    "capabilities",
)
_ALLOWED_KEYS = frozenset(
    {
        "comment",
        "worker_id",
        "controller_url",
        "token_file",
        "token_env",
        "poll_interval_secs",
        "idle_cooldown_secs",
        "busy_util_pct",
        "busy_vram_mib",
        "http_timeout_secs",
        "nvidia_smi_timeout_secs",
        "nvidia_smi_bin",
        "process_watchlist",
        "diffuser_process_markers",
        "gpu_process_ignore",
        "worker_command",
        "worker_pid_file",
        "stop_timeout_secs",
        "reenroll",
        "state_file",
    }
)


class GuardError(Exception):
    """Expected guard failure with a message safe to print."""


class ConfigError(GuardError):
    """Config, token, or URL rejected."""


class InsecureControllerUrl(ConfigError):
    """Controller URL is not HTTPS and is not a loopback HTTP origin."""


class FleetHttpError(GuardError):
    """Controller call failed. The message never includes the bearer token."""


@dataclass(frozen=True)
class Config:
    worker_id: str
    controller_url: str
    token_file: str | None
    token_env: str | None
    poll_interval_secs: float
    idle_cooldown_secs: float
    busy_util_pct: float
    busy_vram_mib: float
    http_timeout_secs: float
    nvidia_smi_timeout_secs: float
    nvidia_smi_bin: str
    process_watchlist: tuple[str, ...]
    diffuser_process_markers: tuple[str, ...]
    gpu_process_ignore: tuple[str, ...]
    worker_command: tuple[str, ...]
    worker_pid_file: str | None
    stop_timeout_secs: float
    reenroll_json: str | None
    state_file: str | None

    def __repr__(self) -> str:
        enroll = "set" if self.reenroll_json else "unset"
        return (
            f"Config(worker_id={self.worker_id!r}, "
            f"controller_url={self.controller_url!r}, reenroll={enroll})"
        )


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    names: tuple[str, ...]


@dataclass(frozen=True)
class GpuApp:
    pid: int
    name: str
    memory_mib: float


@dataclass(frozen=True)
class GpuSnapshot:
    util_pct: float | None
    memory_used_mib: float | None
    apps: tuple[GpuApp, ...]


@dataclass(frozen=True)
class Sample:
    procs: tuple[Proc, ...]
    gpu: GpuSnapshot | None
    process_list_ok: bool


@dataclass(frozen=True)
class CommandResult:
    code: int
    stdout: str
    stderr: str


def validate_controller_url(url: str) -> str:
    """Accept HTTPS origins, and HTTP only for loopback."""
    if not isinstance(url, str) or not url.strip():
        raise InsecureControllerUrl("controller_url is missing")
    raw = url.strip()
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InsecureControllerUrl("controller_url must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise InsecureControllerUrl("controller_url must not embed credentials")
    host = parsed.hostname
    if not host:
        raise InsecureControllerUrl("controller_url is missing a host")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise InsecureControllerUrl("controller_url must be an origin with no path or query")
    if scheme == "http" and host.lower() not in _LOOPBACK_HOSTS:
        raise InsecureControllerUrl(
            "HTTP is allowed only for 127.0.0.1, localhost, or ::1; use HTTPS"
        )
    return raw.rstrip("/")


def _number(raw: object, name: str, default: float, lo: float, hi: float) -> float:
    if raw is None:
        raw = default
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ConfigError(f"{name} must be a number")
    value = float(raw)
    if value < lo or value > hi:
        raise ConfigError(f"{name} must be between {lo:g} and {hi:g}")
    return value


def _string_tuple(
    value: object,
    name: str,
    *,
    min_items: int,
    max_items: int,
    min_len: int,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list of strings")
    if len(value) > max_items:
        raise ConfigError(f"{name} has too many entries")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(f"{name} must be a list of strings")
        text = item.strip()
        if len(text) < min_len or len(text) > 128:
            raise ConfigError(f"{name} entries must be {min_len} to 128 characters")
        if any(ord(ch) < 32 for ch in text):
            raise ConfigError(f"{name} entry contains control characters")
        out.append(text)
    if len(out) < min_items:
        raise ConfigError(f"{name} needs at least {min_items} entries")
    return tuple(out)


def _optional_text(raw: object, name: str) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ConfigError(f"{name} must be a string")
    text = raw.strip()
    if not text:
        return None
    if "\x00" in text:
        raise ConfigError(f"{name} contains a NUL")
    return text


def _command(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError("worker_command must be a list of strings")
    if not value:
        return ()
    if len(value) > 32:
        raise ConfigError("worker_command has too many arguments")
    out: list[str] = []
    for arg in value:
        if not isinstance(arg, str) or arg == "" or "\x00" in arg or len(arg) > 4096:
            raise ConfigError("worker_command must be non-empty strings")
        out.append(arg)
    return tuple(out)


def _validate_reenroll(body: object, worker_id: str) -> str:
    if not isinstance(body, dict):
        raise ConfigError("reenroll must be a JSON object")
    lowered = {str(key).lower() for key in body}
    if lowered & _ENROLL_SECRET_KEYS:
        raise ConfigError("reenroll must not carry a bearer token; the guard sends that header itself")
    missing = [key for key in _ENROLL_REQUIRED if key not in body]
    if missing:
        raise ConfigError("reenroll is missing: " + ", ".join(missing))
    if "worker_id" in body and body["worker_id"] != worker_id:
        raise ConfigError("reenroll.worker_id must match worker_id")
    host = body["host"]
    rpc_url = body["rpc_url"]
    secret = body["rpc_secret_hex"]
    session = body["rpc_session"]
    if not isinstance(host, str) or not host.strip():
        raise ConfigError("reenroll.host must be a non-empty string")
    if not isinstance(rpc_url, str) or not rpc_url.strip():
        raise ConfigError("reenroll.rpc_url must be a non-empty string")
    if not isinstance(secret, str) or len(secret) < 32 or not _HEX_RE.fullmatch(secret.lower()):
        raise ConfigError("reenroll.rpc_secret_hex must be at least 32 hex characters")
    if not isinstance(session, str) or len(session) != 32 or not _HEX_RE.fullmatch(session.lower()):
        raise ConfigError("reenroll.rpc_session must be 32 hex characters")
    for key in ("cpu_millicores", "ram_bytes", "vram_bytes"):
        number = body[key]
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise ConfigError(f"reenroll.{key} must be a non-negative integer")
    if not isinstance(body["capabilities"], list):
        raise ConfigError("reenroll.capabilities must be a list")
    if "gpus" in body and not isinstance(body["gpus"], list):
        raise ConfigError("reenroll.gpus must be a list")
    payload = dict(body)
    payload.pop("worker_id", None)
    payload.setdefault("gpus", [])
    try:
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ConfigError("reenroll is not JSON serializable") from exc
    if len(encoded) > ENROLL_MAX_BYTES:
        raise ConfigError("reenroll payload is too large")
    return encoded.decode("utf-8")


def config_from_mapping(raw: object) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("config must be a JSON object")
    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError("unknown config keys: " + ", ".join(unknown))
    worker_id = raw.get("worker_id")
    if not isinstance(worker_id, str) or not _WORKER_ID_RE.fullmatch(worker_id):
        raise ConfigError(
            "worker_id must be 1 to 64 characters: letters, digits, dot, underscore, hyphen"
        )
    controller_url = validate_controller_url(str(raw.get("controller_url", "")))
    file_path = _optional_text(raw.get("token_file"), "token_file")
    env_name = _optional_text(raw.get("token_env"), "token_env")
    if env_name is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
        raise ConfigError("token_env must be an environment variable name")
    if file_path is None and env_name is None:
        raise ConfigError("set token_file or token_env")
    watch = raw.get("process_watchlist", list(DEFAULT_WATCHLIST))
    markers = raw.get("diffuser_process_markers", list(DEFAULT_DIFFUSER_MARKERS))
    ignore = raw.get("gpu_process_ignore", list(DEFAULT_GPU_IGNORE))
    command = _command(raw.get("worker_command"))
    reenroll_raw = raw.get("reenroll", None)
    reenroll_json = None if reenroll_raw is None else _validate_reenroll(reenroll_raw, worker_id)
    if command and reenroll_json is not None:
        raise ConfigError("choose worker_command or reenroll, and only one of them")
    if not command and reenroll_json is None:
        raise ConfigError("set worker_command or reenroll so the guard can return the worker to the fleet")
    pid_file = _optional_text(raw.get("worker_pid_file"), "worker_pid_file")
    state_file = _optional_text(raw.get("state_file"), "state_file")
    if command and pid_file is None:
        raise ConfigError("worker_pid_file is required when worker_command is set")
    paths = [path for path in (file_path, pid_file, state_file) if path]
    if len({os.path.abspath(path) for path in paths}) != len(paths):
        raise ConfigError("token_file, worker_pid_file, and state_file must be different paths")
    binary = _optional_text(raw.get("nvidia_smi_bin"), "nvidia_smi_bin") or "nvidia-smi"
    if any(ord(ch) < 32 for ch in binary):
        raise ConfigError("nvidia_smi_bin contains control characters")
    return Config(
        worker_id=worker_id,
        controller_url=controller_url,
        token_file=file_path,
        token_env=env_name,
        poll_interval_secs=_number(raw.get("poll_interval_secs"), "poll_interval_secs", 3, 0.5, 120),
        idle_cooldown_secs=_number(raw.get("idle_cooldown_secs"), "idle_cooldown_secs", 180, 0, 86400),
        busy_util_pct=_number(raw.get("busy_util_pct"), "busy_util_pct", 25, 1, 100),
        busy_vram_mib=_number(raw.get("busy_vram_mib"), "busy_vram_mib", 1500, 1, 1048576),
        http_timeout_secs=_number(raw.get("http_timeout_secs"), "http_timeout_secs", 5, 1, 30),
        nvidia_smi_timeout_secs=_number(
            raw.get("nvidia_smi_timeout_secs"), "nvidia_smi_timeout_secs", 2, 0.5, 15
        ),
        nvidia_smi_bin=binary,
        process_watchlist=_string_tuple(watch, "process_watchlist", min_items=1, max_items=128, min_len=3),
        diffuser_process_markers=_string_tuple(
            markers, "diffuser_process_markers", min_items=1, max_items=64, min_len=3
        ),
        gpu_process_ignore=_string_tuple(
            ignore, "gpu_process_ignore", min_items=0, max_items=128, min_len=3
        ),
        worker_command=command,
        worker_pid_file=pid_file,
        stop_timeout_secs=_number(raw.get("stop_timeout_secs"), "stop_timeout_secs", 10, 1, 120),
        reenroll_json=reenroll_json,
        state_file=state_file,
    )


def load_config(path: str) -> Config:
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config is not valid JSON: line {exc.lineno}") from None
    return config_from_mapping(raw)


def _token_is_header_safe(token: str) -> bool:
    if not token or len(token) > TOKEN_MAX_BYTES:
        return False
    if not token.isascii():
        return False
    return all(33 <= ord(ch) <= 126 for ch in token)


def read_token_file(path: str) -> str:
    """Read a bearer token from a regular 0600 file. Never include it in errors."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise ConfigError(f"token file not found: {path}") from None
        raise ConfigError("token file cannot be opened") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError("token file must be a regular file")
        if os.name != "nt":
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o077:
                raise ConfigError(f"token file must be mode 0600 (no group or other access): {path}")
            if not mode & stat.S_IRUSR:
                raise ConfigError("token file is not readable by its owner")
        blob = os.read(fd, TOKEN_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(blob) > TOKEN_MAX_BYTES:
        raise ConfigError("token file is too large")
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("token file is not valid text") from None
    token = text.lstrip("\ufeff").strip()
    if not _token_is_header_safe(token):
        raise ConfigError("token file contents are not a single token")
    return token


def read_token_env(name: str) -> str:
    value = os.environ.get(name, "")
    value = value.strip()
    if not _token_is_header_safe(value):
        raise ConfigError(f"environment variable {name} is missing or not a single token")
    return value


def read_configured_token(config: Config) -> str:
    """File wins when ``token_file`` is set. Environment is the fallback."""
    if config.token_file:
        return read_token_file(config.token_file)
    if config.token_env:
        return read_token_env(config.token_env)
    raise ConfigError("set token_file or token_env")


def parse_metric(text: str) -> float | None:
    cleaned = text.strip()
    if not cleaned or cleaned.startswith("[") or cleaned.upper() in {"N/A", "NA"}:
        return None
    number: list[str] = []
    for char in cleaned:
        if char.isdigit() or char in ".-":
            number.append(char)
            continue
        if number:
            break
    if not number or number == ["-"] or number == ["."]:
        return None
    try:
        return float("".join(number))
    except ValueError:
        return None


def parse_gpu_csv(text: str) -> tuple[float | None, float | None]:
    """Max utilization and max memory.used (MiB) across GPUs."""
    utils: list[float] = []
    memories: list[float] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or "utilization" in raw.lower():
            continue
        parts = [part.strip() for part in raw.split(",")]
        if len(parts) < 2:
            continue
        util = parse_metric(parts[0])
        memory = parse_metric(parts[1])
        if util is not None and util >= 0:
            utils.append(util)
        if memory is not None and memory >= 0:
            memories.append(memory)
    return (max(utils) if utils else None, max(memories) if memories else None)


def parse_app_csv(text: str) -> tuple[GpuApp, ...]:
    apps: list[GpuApp] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.lower().startswith("pid"):
            continue
        parts = [part.strip() for part in raw.split(",")]
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        memory = parse_metric(parts[-1]) or 0.0
        name = ",".join(parts[1:-1]).strip()
        if pid > 0 and name:
            apps.append(GpuApp(pid=pid, name=name[:256], memory_mib=max(0.0, memory)))
        if len(apps) >= 64:
            break
    return tuple(apps)


def parse_windows_process_table(text: str) -> list[Proc]:
    """Parse ``pid<TAB>ppid<TAB>name<TAB>command`` lines."""
    found: list[Proc] = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        name = parts[2].strip()
        command = parts[3].strip() if len(parts) > 3 else ""
        names = tuple(item for item in (name, command) if item)
        if pid > 0 and names:
            found.append(Proc(pid=pid, ppid=max(0, ppid), names=names))
    return found


def parse_tasklist_csv(text: str) -> list[Proc]:
    found: list[Proc] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        name = row[0].strip()
        try:
            pid = int(row[1])
        except ValueError:
            continue
        if pid > 0 and name:
            found.append(Proc(pid=pid, ppid=0, names=(name,)))
    return found


def _hidden_window_kwargs() -> dict[str, object]:
    if os.name != "nt":
        return {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return {"creationflags": flags}


def run_command(argv: list[str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            **_hidden_window_kwargs(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return CommandResult(1, "", "")
    stdout = completed.stdout.decode("utf-8", "replace")
    stderr = completed.stderr.decode("utf-8", "replace")[:400]
    return CommandResult(completed.returncode, stdout, stderr)


class SubprocessRunner:
    def run(self, argv: list[str], timeout: float) -> CommandResult:
        return run_command(argv, timeout)


def linux_process_source() -> list[Proc]:
    found: list[Proc] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        raise GuardError("process list unavailable") from None
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        base = os.path.join("/proc", entry)
        try:
            with open(os.path.join(base, "status"), encoding="utf-8", errors="replace") as handle:
                status = handle.read(8192)
            with open(os.path.join(base, "comm"), encoding="utf-8", errors="replace") as handle:
                comm = handle.read(256).strip()
            with open(os.path.join(base, "cmdline"), "rb") as handle:
                raw = handle.read(4096)
        except OSError:
            continue
        ppid = 0
        for line in status.splitlines():
            if line.startswith("PPid:"):
                pieces = line.split()
                if len(pieces) == 2 and pieces[1].isdigit():
                    ppid = int(pieces[1])
                break
        command = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        names = tuple(item for item in (comm, command) if item)
        if names:
            found.append(Proc(pid=pid, ppid=ppid, names=names))
        if len(found) >= 5000:
            break
    return found


def windows_process_source() -> list[Proc]:
    script = (
        "Get-CimInstance Win32_Process | "
        "ForEach-Object { '{0}`t{1}`t{2}`t{3}' -f "
        "$_.ProcessId, $_.ParentProcessId, $_.Name, $_.CommandLine }"
    )
    listed = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        5,
    )
    if listed.code == 0 and listed.stdout.strip():
        return parse_windows_process_table(listed.stdout)[:5000]
    fallback = run_command(["tasklist", "/FO", "CSV", "/NH"], 5)
    return parse_tasklist_csv(fallback.stdout)[:5000]


def default_process_source() -> list[Proc]:
    if os.name == "nt":
        return windows_process_source()
    return linux_process_source()


class NvidiaProbe:
    def __init__(
        self,
        config: Config,
        runner: SubprocessRunner | None = None,
        process_source=None,
    ) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()
        self.process_source = process_source or default_process_source
        self._apps_kind = "apps"
        self._warned: set[str] = set()

    def _warn(self, key: str) -> None:
        if key in self._warned:
            return
        self._warned.add(key)
        LOG.warning("%s unavailable; gamer detection is degraded", key)

    def _query_gpu(self) -> GpuSnapshot | None:
        binary = self.config.nvidia_smi_bin
        timeout = self.config.nvidia_smi_timeout_secs
        gpu = self.runner.run([binary, *GPU_QUERY], timeout)
        if gpu.code != 0:
            self._warn("nvidia-smi gpu query")
            return None
        util, memory = parse_gpu_csv(gpu.stdout)
        if self._apps_kind == "apps":
            apps = self.runner.run([binary, *APPS_QUERY], timeout)
            if apps.code != 0:
                self._apps_kind = "compute"
                apps = self.runner.run([binary, *COMPUTE_APPS_QUERY], timeout)
        else:
            apps = self.runner.run([binary, *COMPUTE_APPS_QUERY], timeout)
        if apps.code != 0:
            self._warn("nvidia-smi process query")
            app_list: tuple[GpuApp, ...] = ()
        else:
            app_list = parse_app_csv(apps.stdout)
        return GpuSnapshot(util_pct=util, memory_used_mib=memory, apps=app_list)

    def sample(self) -> Sample:
        ok = True
        try:
            procs = tuple(self.process_source())
        except Exception:
            self._warn("process-list")
            procs = ()
            ok = False
        if len(procs) > 5000:
            procs = procs[:5000]
        try:
            gpu = self._query_gpu()
        except Exception:
            self._warn("nvidia-smi")
            gpu = None
        return Sample(procs=procs, gpu=gpu, process_list_ok=ok)


def _names_hit(names: tuple[str, ...] | str, needles: tuple[str, ...]) -> bool:
    haystacks = (names,) if isinstance(names, str) else names
    cleaned = [needle.lower() for needle in needles if len(needle.strip()) >= 3]
    for hay in haystacks:
        low = hay.lower()
        for needle in cleaned:
            if needle in low:
                return True
    return False


def _diffuser_pids(procs: tuple[Proc, ...], markers: tuple[str, ...], roots: set[int]) -> set[int]:
    seeds = set(roots)
    children: dict[int, list[int]] = {}
    for proc in procs:
        children.setdefault(proc.ppid, []).append(proc.pid)
        if _names_hit(proc.names, markers):
            seeds.add(proc.pid)
    found = set(seeds)
    stack = list(seeds)
    while stack:
        pid = stack.pop()
        for child in children.get(pid, []):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def classify_activity(sample: Sample, config: Config, root_pids: set[int]) -> list[str]:
    """Reasons the machine is busy for a gamer. Empty means idle."""
    reasons: list[str] = []
    if not sample.process_list_ok:
        reasons.append("process-list-unavailable")
    diffuser = _diffuser_pids(sample.procs, config.diffuser_process_markers, set(root_pids))
    seen: set[str] = set()
    for proc in sample.procs:
        if proc.pid in diffuser:
            continue
        for name in proc.names:
            low = name.lower()
            for term in config.process_watchlist:
                key = term.lower()
                if len(key) < 3 or key in seen or key not in low:
                    continue
                reasons.append(f"process:{term}")
                seen.add(key)
                break
    gpu = sample.gpu
    if gpu is None:
        return reasons
    diffuser_job = False
    foreign: list[str] = []
    for app in gpu.apps:
        if app.pid in diffuser or _names_hit(app.name, config.diffuser_process_markers):
            diffuser_job = True
            continue
        if _names_hit(app.name, config.gpu_process_ignore):
            continue
        foreign.append(app.name)
    if foreign:
        shown = ",".join(name[:80] for name in foreign[:4])
        reasons.append(f"gpu-foreign:{shown}")
    if not diffuser_job:
        if gpu.util_pct is not None and gpu.util_pct >= config.busy_util_pct:
            reasons.append(f"gpu-util:{gpu.util_pct:g}")
        if gpu.memory_used_mib is not None and gpu.memory_used_mib >= config.busy_vram_mib:
            reasons.append(f"gpu-vram:{gpu.memory_used_mib:g}")
    return reasons


def _fmt_reasons(reasons: list[str]) -> str:
    clipped = [reason.replace("\n", " ")[:120] for reason in reasons[:8]]
    return ", ".join(clipped)[:300]


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so the bearer token cannot follow Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise FleetHttpError("controller redirect blocked")


def build_fleet_opener() -> urllib.request.OpenerDirector:
    """HTTPS with default certificate checks, no redirects, no environment proxy.

    ``ProxyHandler({})`` replaces the default handler that would read
    ``HTTP_PROXY``. An empty mapping installs no proxy methods, so the bearer
    token is sent only to the controller.
    """
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirects())


def urllib_send(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        request.add_header(key, value)
    opener = build_fleet_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(RESPONSE_MAX_BYTES)
            code = getattr(response, "status", None) or response.getcode()
    except FleetHttpError:
        raise
    except urllib.error.HTTPError as exc:
        raise FleetHttpError(f"controller HTTP {exc.code}") from None
    except Exception:
        raise FleetHttpError("controller request failed") from None
    if code < 200 or code >= 300:
        raise FleetHttpError(f"controller HTTP {code}")
    return int(code), payload


class HttpFleetClient:
    """Drain and enroll against the Diffuser fleet controller.

    ``fleet.rs`` registers ``POST /v1/fleet/workers/{worker_id}/drain``, which
    sets ``status`` to ``draining``. ``POST /v1/fleet/workers/enroll`` sets
    ``status`` back to ``active``. Heartbeat updates telemetry and leaves
    ``status`` unchanged. The router does not register an undrain path.
    """

    def __init__(self, config: Config, send=None, token_loader=None) -> None:
        self.config = config
        self.base = validate_controller_url(config.controller_url)
        self._send = send or urllib_send
        self._load_auth = token_loader or (lambda: read_configured_token(config))

    def _url(self, path: str) -> str:
        validate_controller_url(self.base)
        return self.base + path

    def _post(self, url: str, body: bytes) -> None:
        value = self._load_auth()
        if not _token_is_header_safe(value):
            raise FleetHttpError("fleet token is missing")
        headers = {
            "Authorization": "Bearer " + value,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "gamer-idle-guard",
        }
        timeout = min(30.0, max(1.0, float(self.config.http_timeout_secs)))
        code, _payload = self._send("POST", url, headers, body, timeout)
        if code < 200 or code >= 300:
            raise FleetHttpError(f"controller HTTP {code}")

    def drain(self) -> None:
        worker = urllib.parse.quote(self.config.worker_id, safe="")
        self._post(self._url(f"/v1/fleet/workers/{worker}/drain"), DRAIN_BODY)

    def enroll(self) -> None:
        if not self.config.reenroll_json:
            raise ConfigError("reenroll is not configured")
        payload = json.loads(self.config.reenroll_json)
        payload["worker_id"] = self.config.worker_id
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > ENROLL_MAX_BYTES:
            raise ConfigError("reenroll payload is too large")
        self._post(self._url("/v1/fleet/workers/enroll"), body)


def worker_identity_needles(command: tuple[str, ...]) -> tuple[str, ...]:
    """Substrings that must all appear in a pid's command line before we signal it."""
    if not command:
        return ()
    exe = os.path.basename(command[0]).lower()
    extras = [
        os.path.basename(part).lower()
        for part in command[1:]
        if part and not part.startswith("-")
    ]
    if extras:
        return (exe, extras[-1])
    return (exe,)


def read_cmdline(pid: int) -> str:
    if os.name == "nt":
        script = (
            f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"
        )
        result = run_command(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            5,
        )
        return result.stdout.strip() if result.code == 0 else ""
    path = os.path.join("/proc", str(int(pid)), "cmdline")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(4096)
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def pid_alive(pid: int) -> bool:
    if pid <= 1:
        return False
    if os.name == "nt":
        result = run_command(["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"], 5)
        return str(int(pid)) in result.stdout
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def default_signal_pid(pid: int, gentle: bool) -> None:
    if os.name == "nt":
        argv = ["taskkill", "/PID", str(int(pid)), "/T"]
        if not gentle:
            argv.insert(1, "/F")
        run_command(argv, 10)
        return
    sig = signal.SIGTERM if gentle else signal.SIGKILL
    try:
        os.killpg(pid, sig)
        return
    except OSError:
        pass
    try:
        os.kill(pid, sig)
    except OSError:
        return


def _write_private(path: str, data: bytes) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class SubprocessWorker:
    """Start and stop the local fleet worker. Never signals an unrelated pid."""

    def __init__(
        self,
        config: Config,
        *,
        popen=None,
        alive=None,
        cmdline_of=None,
        signal_pid=None,
        sleep=None,
        clock=None,
    ) -> None:
        if not config.worker_command:
            raise ConfigError("worker_command is empty")
        self.command = config.worker_command
        self.pid_file = config.worker_pid_file
        self.stop_timeout = config.stop_timeout_secs
        self.needles = worker_identity_needles(self.command)
        self._popen = popen or subprocess.Popen
        self._alive_fn = alive or pid_alive
        self._cmdline_of = cmdline_of or read_cmdline
        self._signal_pid = signal_pid or default_signal_pid
        self._sleep = sleep or time.sleep
        self._clock = clock or time.monotonic
        self._child = None

    def root_pids(self) -> set[int]:
        pids: set[int] = set()
        if self._child is not None and self._child.poll() is None and self._child.pid:
            pids.add(self._child.pid)
        pid = self._read_pid()
        if pid and self._cmdline_matches(pid):
            pids.add(pid)
        return pids

    def is_running(self) -> bool:
        if self._child is not None and self._child.poll() is None:
            return True
        pid = self._read_pid()
        if pid is None:
            return False
        return bool(self._alive_fn(pid) and self._cmdline_matches(pid))

    def start(self) -> None:
        if self.is_running():
            return
        argv = list(self.command)
        kwargs: dict[str, object] = {"stdin": subprocess.DEVNULL, "start_new_session": True}
        kwargs.update(_hidden_window_kwargs())
        self._child = self._popen(argv, **kwargs)
        if self.pid_file and self._child.pid:
            _write_private(self.pid_file, f"{int(self._child.pid)}\n".encode("ascii"))

    def stop(self) -> None:
        targets = self._targets()
        if not targets:
            return
        for pid in targets:
            self._signal_pid(pid, True)
        self._wait_until_dead(targets)
        for pid in targets:
            if self._alive_fn(pid):
                self._signal_pid(pid, False)
        if self._child is not None and self._child.pid not in targets:
            pass
        elif self._child is not None and not self._alive_fn(self._child.pid):
            self._child = None
        elif self._child is not None and self._child.poll() is not None:
            self._child = None
        self._clear_pidfile(targets)

    def _targets(self) -> list[int]:
        pids: list[int] = []
        if self._child is not None and self._child.poll() is None and self._child.pid:
            pids.append(int(self._child.pid))
        file_pid = self._read_pid()
        if file_pid and file_pid not in pids:
            if self._cmdline_matches(file_pid):
                pids.append(file_pid)
            elif self._alive_fn(file_pid):
                LOG.warning(
                    "pid file points at pid %s but the command line is not the fleet worker; left it alone",
                    file_pid,
                )
        return pids

    def _wait_until_dead(self, pids: list[int]) -> None:
        interval = 0.1
        steps = max(1, int(self.stop_timeout / interval) + 1)
        for _ in range(steps):
            if all(not self._alive_fn(pid) for pid in pids):
                return
            self._sleep(interval)

    def _cmdline_matches(self, pid: int) -> bool:
        if not self.needles:
            return False
        try:
            command = self._cmdline_of(pid).lower()
        except Exception:
            return False
        return all(needle in command for needle in self.needles)

    def _read_pid(self) -> int | None:
        if not self.pid_file or not os.path.exists(self.pid_file):
            return None
        try:
            with open(self.pid_file, encoding="utf-8") as handle:
                text = handle.read(64).strip()
            pid = int(text)
        except (OSError, ValueError):
            return None
        if pid <= 1 or pid >= 2**31 or pid == os.getpid():
            return None
        return pid

    def _clear_pidfile(self, targets: list[int]) -> None:
        if not self.pid_file or not os.path.exists(self.pid_file):
            return
        current = self._read_pid()
        if current is None or current in targets or not self._alive_fn(current):
            try:
                os.remove(self.pid_file)
            except OSError:
                return


def _state_file_readable(path: str) -> bool:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return False
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            LOG.warning("ignoring state file with loose permissions")
            return False
        return True
    finally:
        os.close(fd)


class Guard:
    """Hysteresis state machine. Entry to GAMER_ACTIVE is immediate."""

    def __init__(
        self,
        config: Config,
        probe: NvidiaProbe,
        controller: HttpFleetClient,
        worker: SubprocessWorker | None = None,
        clock=None,
        wall_clock=None,
    ) -> None:
        self.config = config
        self.probe = probe
        self.controller = controller
        self.worker = worker
        self.clock = clock or time.monotonic
        self.wall_clock = wall_clock or time.time
        self.state = ACTIVE_FOR_FLEET
        self._cooldown_started: float | None = None
        self._cooldown_wall: float | None = None
        self._restore()

    def tick(self) -> str:
        try:
            sample = self.probe.sample()
            reasons = classify_activity(sample, self.config, self._roots())
        except Exception:
            LOG.error("probe failed: %s", "ProbeError")
            return self.state
        if reasons:
            self._to_gamer(reasons)
            return self.state
        if self.state == GAMER_ACTIVE:
            self._to_cooldown()
            return self.state
        if self.state == COOLDOWN:
            self._cooldown_idle()
            return self.state
        self._ensure_worker_running()
        return self.state

    def run(self, once: bool = False, sleep=None) -> str:
        sleeper = sleep or time.sleep
        stop = {"flag": False}

        def _stop(_signum, _frame) -> None:
            stop["flag"] = True

        previous = []
        for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
            if sig is None:
                continue
            try:
                previous.append((sig, signal.signal(sig, _stop)))
            except (OSError, ValueError):
                continue
        try:
            while not stop["flag"]:
                self.tick()
                if once or stop["flag"]:
                    return self.state
                sleeper(self.config.poll_interval_secs)
            return self.state
        finally:
            for sig, handler in previous:
                signal.signal(sig, handler)

    def _roots(self) -> set[int]:
        if self.worker is None:
            return set()
        try:
            return set(self.worker.root_pids())
        except Exception:
            return set()

    def _to_gamer(self, reasons: list[str]) -> None:
        if self.state != GAMER_ACTIVE:
            LOG.info("state %s -> %s (%s)", self.state, GAMER_ACTIVE, _fmt_reasons(reasons))
        else:
            LOG.debug("gamer still active (%s)", _fmt_reasons(reasons))
        self.state = GAMER_ACTIVE
        self._cooldown_started = None
        self._cooldown_wall = None
        self._persist()
        self._hold()

    def _to_cooldown(self) -> None:
        self.state = COOLDOWN
        self._cooldown_started = self.clock()
        self._cooldown_wall = float(self.wall_clock())
        LOG.info(
            "state %s -> %s (idle, waiting %.0fs)",
            GAMER_ACTIVE,
            COOLDOWN,
            self.config.idle_cooldown_secs,
        )
        self._persist()
        self._hold()

    def _cooldown_idle(self) -> None:
        if self._cooldown_started is None:
            self._cooldown_started = self.clock()
            self._cooldown_wall = float(self.wall_clock())
            self._persist()
        elapsed = self.clock() - self._cooldown_started
        if elapsed >= self.config.idle_cooldown_secs:
            if self._enable():
                self.state = ACTIVE_FOR_FLEET
                self._cooldown_started = None
                self._cooldown_wall = None
                LOG.info("state %s -> %s", COOLDOWN, ACTIVE_FOR_FLEET)
                self._persist()
                return
            LOG.warning("re-enable failed; staying in %s", COOLDOWN)
        self._hold()

    def _ensure_worker_running(self) -> None:
        if self.worker is None or self.worker.is_running():
            return
        try:
            self.worker.start()
            LOG.info("fleet worker started")
        except Exception:
            LOG.error("fleet worker start failed: %s", "StartError")

    def _hold(self) -> None:
        try:
            self.controller.drain()
        except GuardError as exc:
            LOG.warning("drain failed: %s", exc)
        except Exception:
            LOG.warning("drain failed: %s", "DrainError")
        if self.worker is None:
            return
        try:
            self.worker.stop()
        except Exception:
            LOG.warning("worker stop failed: %s", "StopError")

    def _enable(self) -> bool:
        try:
            if self.worker is not None:
                self.worker.start()
            if self.config.reenroll_json is not None:
                self.controller.enroll()
            return True
        except GuardError as exc:
            LOG.warning("re-enable failed: %s", exc)
            return False
        except Exception:
            LOG.warning("re-enable failed: %s", "EnableError")
            return False

    def _persist(self) -> None:
        path = self.config.state_file
        if not path:
            return
        payload = {
            "version": STATE_VERSION,
            "state": self.state,
            "cooldown_started_wall": self._cooldown_wall,
        }
        try:
            _write_private(path, json.dumps(payload, sort_keys=True).encode("utf-8") + b"\n")
        except OSError:
            LOG.warning("state file not written")

    def _restore(self) -> None:
        path = self.config.state_file
        if not path or not os.path.exists(path) or not _state_file_readable(path):
            return
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            LOG.warning("state file ignored")
            return
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            LOG.warning("state file ignored")
            return
        state = data.get("state")
        if state not in {ACTIVE_FOR_FLEET, GAMER_ACTIVE, COOLDOWN}:
            LOG.warning("state file ignored")
            return
        self.state = state
        wall = data.get("cooldown_started_wall")
        if state == COOLDOWN and isinstance(wall, (int, float)) and not isinstance(wall, bool):
            self._cooldown_wall = float(wall)
            elapsed = max(0.0, float(self.wall_clock()) - float(wall))
            self._cooldown_started = self.clock() - elapsed
            LOG.info("restored %s with %.0fs already idle", COOLDOWN, elapsed)
        elif state == GAMER_ACTIVE:
            LOG.info("restored %s", GAMER_ACTIVE)


def build_guard(config: Config) -> Guard:
    probe = NvidiaProbe(config)
    controller = HttpFleetClient(config)
    worker = SubprocessWorker(config) if config.worker_command else None
    return Guard(config, probe, controller, worker)


def check_ready(config: Config) -> None:
    """Validate the URL and load the token. Do not print the token."""
    validate_controller_url(config.controller_url)
    read_configured_token(config)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Keep a gaming laptop quiet for the player and available to the Diffuser fleet when idle."
    )
    parser.add_argument("--config", required=True, help="Path to the JSON config")
    parser.add_argument("--once", action="store_true", help="Run a single poll and exit")
    parser.add_argument("--check", action="store_true", help="Validate the config and token, then exit")
    try:
        args = parser.parse_args(argv)
        config = load_config(args.config)
        if args.check:
            check_ready(config)
            print("config ok")
            return 0
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        guard = build_guard(config)
        guard.run(once=args.once)
        return 0
    except GuardError as exc:
        print(f"gamer-idle-guard: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(
            f"gamer-idle-guard: {exc.strerror or 'os error'}: {exc.filename or ''}",
            file=sys.stderr,
        )
        return 2
    except Exception:
        print("gamer-idle-guard: failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
