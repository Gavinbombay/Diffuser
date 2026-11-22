#!/usr/bin/env python3
"""Cross-platform Python 3 stdlib Diffuser Fleet Worker (Windows / Linux).

Designed to run under gamer_idle_guard.py on a gaming PC or laptop. Enrolls with
Diffuser over loopback/HTTPS, reports live nvidia-smi VRAM and utilization on
every heartbeat, verifies Diffuser v2 HMAC-SHA256 signed RPCs with bounded
replay protection, and executes real hardware AV1/HEVC/H.264 NVENC encode
benchmarks alongside GPU probe and SHA-256 capabilities.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
import signal
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

MAX_RPC_BODY_BYTES = 2 * 1024 * 1024
MAX_CONCURRENT_REQUESTS = 8
REQUEST_SOCKET_TIMEOUT_SECS = 10.0
MAX_REPLAY_ENTRIES = 4096
REPLAY_WINDOW_MS = 120_000
MAX_FUTURE_SKEW_MS = 30_000
JOB_ID_RE = re.compile(r"^fjob_[0-9a-f]{32}$")
HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
ALLOWED_CODECS = frozenset({"av1_nvenc", "hevc_nvenc", "h264_nvenc"})
ALLOWED_PRESETS = frozenset({"p1", "p2", "p3", "p4", "p5", "p6", "p7"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects_disabled", headers, fp)


def validate_controller_url(raw: str) -> str:
    parsed = urllib.parse.urlparse(raw.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError("controller_url scheme must be http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("controller_url must not contain credentials, query, or fragment")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("controller_url missing hostname")
    if parsed.scheme == "http" and host not in LOOPBACK_HOSTS:
        raise ValueError("plain http controller_url is allowed only on loopback")
    return raw.strip().rstrip("/")


def validate_bind_host(host: str) -> str:
    h = host.strip().lower()
    if h in LOOPBACK_HOSTS:
        return h
    try:
        if ipaddress.ip_address(h).is_loopback:
            return h
    except ValueError:
        pass
    raise ValueError("bind_host must be a loopback address")


def sign_rpc_v2(secret_hex: str, body: bytes) -> str:
    key = hashlib.sha256(secret_hex.encode("utf-8")).digest()
    return hmac.new(key, b"diffuser-fleet-rpc/v2\0" + body, hashlib.sha256).hexdigest()


def verify_rpc_v2(secret_hex: str, body: bytes, sig_hex: str) -> bool:
    if not isinstance(sig_hex, str) or len(sig_hex.strip()) != 64:
        return False
    expected = sign_rpc_v2(secret_hex, body)
    return hmac.compare_digest(expected, sig_hex.strip().lower())


class BoundedReplayCache:
    """Bounded timestamp-window replay guard that fails closed at capacity."""

    def __init__(self, max_entries: int = MAX_REPLAY_ENTRIES, window_ms: int = REPLAY_WINDOW_MS):
        self.max_entries = max_entries
        self.window_ms = window_ms
        self._seen: dict[str, int] = {}
        self._high_water_ms = 0
        self._lock = threading.Lock()

    def consume(self, job_id: str, issued_at_ms: int, now_ms: int) -> str | None:
        if not JOB_ID_RE.fullmatch(job_id):
            return "rpc_identity_invalid"
        if not isinstance(issued_at_ms, int) or isinstance(issued_at_ms, bool):
            return "rpc_timestamp_invalid"
        with self._lock:
            if now_ms < self._high_water_ms - MAX_FUTURE_SKEW_MS:
                return "rpc_timestamp_invalid"
            if now_ms > self._high_water_ms:
                self._high_water_ms = now_ms
            if issued_at_ms > now_ms + MAX_FUTURE_SKEW_MS:
                return "rpc_timestamp_invalid"
            if now_ms - issued_at_ms > self.window_ms:
                return "rpc_timestamp_invalid"
            cutoff = now_ms - self.window_ms
            expired = [k for k, ts in self._seen.items() if ts < cutoff]
            for k in expired:
                del self._seen[k]
            if job_id in self._seen:
                return "rpc_replayed"
            if len(self._seen) >= self.max_entries:
                return "rpc_replay_cache_full"
            self._seen[job_id] = issued_at_ms
            return None


def query_gpus(nvidia_smi_bin: str = "nvidia-smi"):
    try:
        out = subprocess.check_output(
            [
                nvidia_smi_bin,
                "--query-gpu=uuid,name,memory.total,memory.free,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            text=True,
            timeout=3,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return [], [], None, None
    gpus = []
    live = []
    total_free = 0
    max_util = 0
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5:
            continue
        uuid, name, tot_mib, free_mib, util = parts[:5]
        try:
            tot_b = int(tot_mib) * 1024 * 1024
            free_b = int(free_mib) * 1024 * 1024
            u = max(0, min(100, int(util)))
        except ValueError:
            continue
        gpus.append({"uuid": uuid, "name": name, "vram_bytes": tot_b})
        live.append({
            "uuid": uuid,
            "memory_free_bytes": free_b,
            "memory_total_bytes": tot_b,
            "util_pct": u,
        })
        total_free += free_b
        max_util = max(max_util, u)
    return gpus, live, (total_free if live else None), (max_util if live else None)


def validate_nvenc_params(inp: dict) -> tuple[dict | None, str | None]:
    if not isinstance(inp, dict):
        return None, "invalid_input"
    codec = str(inp.get("codec", "av1_nvenc")).strip()
    if codec not in ALLOWED_CODECS:
        return None, "unsupported_codec"
    preset = str(inp.get("preset", "p4")).strip()
    if preset not in ALLOWED_PRESETS:
        return None, "unsupported_preset"
    try:
        width = int(inp.get("width", 1920))
        height = int(inp.get("height", 1080))
        fps = int(inp.get("fps", 60))
        duration_secs = int(inp.get("duration_secs", 5))
    except (TypeError, ValueError):
        return None, "invalid_numeric_param"
    if not (256 <= width <= 3840 and width % 2 == 0):
        return None, "invalid_width"
    if not (256 <= height <= 2160 and height % 2 == 0):
        return None, "invalid_height"
    if not (15 <= fps <= 60):
        return None, "invalid_fps"
    if not (1 <= duration_secs <= 30):
        return None, "invalid_duration_secs"
    return {
        "codec": codec,
        "preset": preset,
        "width": width,
        "height": height,
        "fps": fps,
        "duration_secs": duration_secs,
    }, None


def run_nvenc_bench(ffmpeg_bin: str, inp: dict, timeout_secs: int = 90) -> dict:
    params, err = validate_nvenc_params(inp)
    if err or params is None:
        return {"ok": False, "error": err or "invalid_input", "cleanup_ok": True}
    null_sink = "NUL" if os.name == "nt" else "/dev/null"
    fmt = "ivf" if params["codec"] == "av1_nvenc" else "null"
    argv = [
        ffmpeg_bin,
        "-hide_banner",
        "-y",
        "-f", "lavfi",
        "-i", f"testsrc2=size={params['width']}x{params['height']}:rate={params['fps']}:duration={params['duration_secs']}",
        "-c:v", params["codec"],
        "-preset", params["preset"],
        "-f", fmt,
        null_sink,
    ]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_secs,
            check=False,
        )
    except FileNotFoundError:
        return {"ok": False, "error": "ffmpeg_not_found", "cleanup_ok": True}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "nvenc_timeout", "cleanup_ok": True}
    elapsed = round(time.monotonic() - t0, 3)
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "nvenc_failed",
            "exit_code": proc.returncode,
            "cleanup_ok": True,
        }
    total_frames = params["fps"] * params["duration_secs"]
    encode_fps = round(total_frames / max(elapsed, 0.001), 1)
    return {
        "ok": True,
        "output": {
            "codec": params["codec"],
            "preset": params["preset"],
            "resolution": f"{params['width']}x{params['height']}",
            "source_fps": params["fps"],
            "duration_secs": params["duration_secs"],
            "frames_encoded": total_frames,
            "elapsed_secs": elapsed,
            "encode_fps": encode_fps,
        },
        "cleanup_ok": True,
    }


def make_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())


def load_worker_config(path: str) -> dict:
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    cfg["controller_url"] = validate_controller_url(cfg["controller_url"])
    cfg["bind_host"] = validate_bind_host(cfg.get("bind_host", "127.0.0.1"))
    cfg["bind_port"] = int(cfg["bind_port"])
    if not (1024 <= cfg["bind_port"] <= 65535):
        raise ValueError("bind_port must be 1024..65535")
    if not HEX_SECRET_RE.fullmatch(str(cfg.get("rpc_secret_hex", ""))):
        raise ValueError("rpc_secret_hex must be 32..128 hex chars")
    return cfg


def build_handler(cfg: dict, rpc_session: str, replay: BoundedReplayCache, nvidia_smi_bin: str, ffmpeg_bin: str):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _reply(self, code: int, payload: dict) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:
            if self.path != "/v1/fleet-worker/run":
                self._reply(404, {"ok": False, "error": "not_found", "cleanup_ok": True})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._reply(400, {"ok": False, "error": "invalid_content_length", "cleanup_ok": True})
                return
            if length <= 0 or length > MAX_RPC_BODY_BYTES:
                self._reply(413, {"ok": False, "error": "body_too_large", "cleanup_ok": True})
                return
            body = self.rfile.read(length)
            sig = self.headers.get("x-diffuser-signature", "")
            if not verify_rpc_v2(cfg["rpc_secret_hex"], body, sig):
                self._reply(401, {"ok": False, "error": "invalid_signature", "cleanup_ok": True})
                return
            try:
                req = json.loads(body.decode("utf-8"))
            except Exception:
                self._reply(400, {"ok": False, "error": "invalid_json", "cleanup_ok": True})
                return
            if not isinstance(req, dict) or req.get("rpc_session") != rpc_session:
                self._reply(401, {"ok": False, "error": "rpc_identity_invalid", "cleanup_ok": True})
                return
            err = replay.consume(str(req.get("job_id", "")), req.get("issued_at_ms"), int(time.time() * 1000))
            if err is not None:
                code = 409 if err == "rpc_replayed" else (503 if err == "rpc_replay_cache_full" else 401)
                self._reply(code, {"ok": False, "error": err, "cleanup_ok": True})
                return

            cap = req.get("capability")
            inp = req.get("input") or {}
            if cap == "tool.a15.gpu-probe/v1":
                g, lv, lf, gu = query_gpus(nvidia_smi_bin)
                self._reply(200, {
                    "ok": True,
                    "output": {
                        "host": cfg.get("host", "windows-node"),
                        "gpus": g,
                        "gpus_live": lv,
                        "live_vram_free_bytes": lf,
                        "gpu_util_pct": gu,
                    },
                    "cleanup_ok": True,
                })
            elif cap == "tool.cpu.sha256/v1":
                text = str(inp.get("text", ""))
                if len(text) > 1_000_000:
                    self._reply(400, {"ok": False, "error": "input_too_large", "cleanup_ok": True})
                    return
                self._reply(200, {
                    "ok": True,
                    "output": {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()},
                    "cleanup_ok": True,
                })
            elif cap == "media.nvenc.encode-bench/v1":
                self._reply(200, run_nvenc_bench(ffmpeg_bin, inp))
            else:
                self._reply(200, {"ok": False, "error": "capability_not_found", "cleanup_ok": True})

    return Handler


class BoundedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        max_concurrent: int = MAX_CONCURRENT_REQUESTS,
        request_timeout: float = REQUEST_SOCKET_TIMEOUT_SECS,
    ):
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self.request_timeout = request_timeout
        super().__init__(server_address, RequestHandlerClass)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            request.settimeout(self.request_timeout)
            t = threading.Thread(
                target=self.process_request_thread,
                args=(request, client_address),
                daemon=True,
            )
            t.start()
        except Exception:
            self._slots.release()
            self.shutdown_request(request)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: windows_fleet_worker.py <config.json>", file=sys.stderr)
        return 2
    cfg = load_worker_config(sys.argv[1])
    tok = Path(cfg["token_file"]).read_text(encoding="utf-8").strip()
    nvidia_smi_bin = str(cfg.get("nvidia_smi_bin", "nvidia-smi"))
    ffmpeg_bin = str(cfg.get("ffmpeg_bin", "ffmpeg"))
    rpc_session = secrets.token_hex(16)
    replay = BoundedReplayCache()
    stop_event = threading.Event()
    opener = make_opener()

    gpus, _live, _lf, _gu = query_gpus(nvidia_smi_bin)
    vram_total = sum(g["vram_bytes"] for g in gpus)
    first_uuid = gpus[0]["uuid"] if gpus else None

    capabilities = [
        {"capability": "tool.a15.gpu-probe/v1", "kind": "exec", "gpu_uuid": first_uuid, "timeout_secs": 30},
        {"capability": "tool.cpu.sha256/v1", "kind": "exec", "gpu_uuid": None, "timeout_secs": 30},
        {"capability": "media.nvenc.encode-bench/v1", "kind": "exec", "gpu_uuid": first_uuid, "timeout_secs": 120},
    ]

    handler_cls = build_handler(cfg, rpc_session, replay, nvidia_smi_bin, ffmpeg_bin)
    srv = BoundedHTTPServer((cfg["bind_host"], cfg["bind_port"]), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def post_ctrl(path: str, payload: dict) -> bytes:
        req = urllib.request.Request(
            cfg["controller_url"] + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(req, timeout=8) as resp:
            return resp.read()

    enroll_body = {
        "worker_id": cfg["worker_id"],
        "host": cfg.get("host", "windows-node"),
        "rpc_url": cfg["advertise_url"],
        "rpc_secret_hex": cfg["rpc_secret_hex"],
        "rpc_session": rpc_session,
        "cpu_millicores": int(cfg.get("cpu_millicores", 8000)),
        "ram_bytes": int(cfg.get("ram_bytes", 8 * 1024 * 1024 * 1024)),
        "vram_bytes": vram_total,
        "gpus": gpus,
        "capabilities": capabilities,
    }
    post_ctrl("/v1/fleet/workers/enroll", enroll_body)
    print(f"windows_fleet_worker enrolled {cfg['worker_id']} on {cfg['bind_host']}:{cfg['bind_port']}", flush=True)

    def _stop(*_):
        stop_event.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while not stop_event.is_set():
        _g, lv, lf, gu = query_gpus(nvidia_smi_bin)
        try:
            post_ctrl(f"/v1/fleet/workers/{cfg['worker_id']}/heartbeat", {
                "live_vram_free_bytes": lf,
                "gpu_util_pct": gu,
                "gpus_live": lv,
            })
        except Exception as exc:
            print(f"heartbeat warn: {type(exc).__name__}", file=sys.stderr, flush=True)
        stop_event.wait(10.0)

    srv.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
