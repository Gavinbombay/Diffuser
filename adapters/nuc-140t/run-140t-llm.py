#!/usr/bin/env python3
"""Diffuser exec adapter for the qualified NUC Arc 140T Vulkan profiles."""

import ctypes
import fcntl
import http.client
import json
import os
from pathlib import Path
import queue
import select
import signal
import socket
import stat
import subprocess
import sys
import threading
import time


ENGINE = "/opt/diffuser-140t/bin/llama-server"
MODELS = {
    "30b": "/opt/diffuser-140t/models/gguf-30b/Qwen3-30B-A3B-Instruct-2507-Q4_K_M.gguf",
    "4b": "/opt/diffuser-140t/models/gguf-4b/Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
}
HOST, PORT = "127.0.0.1", 18081
FLAGS = (
    "-ngl", "99", "--jinja", "--slots", "--no-context-shift",
    "-c", "16384", "-np", "1", "-t", "3", "-tb", "3",
    "-fa", "off", "-ctk", "f16", "-ctv", "f16",
    "-b", "2048", "-ub", "512", "--cache-reuse", "256",
)
INFER = "infer.llm.140t/v1"
CONTROL = "gpu.140t.control/v1"
THERMAL_LIMIT = 90.0
POLL = 0.25
IDLE_SECS = 60
STARTUP_SECS = 120
STOP_SECS = 3
CLEANUP_RESERVE = 8
DEFAULT_TIMEOUT = 240
MAX_TIMEOUT = 600
MAX_INPUT = 1024 * 1024
MAX_RESPONSE = 128 * 1024
STATE_DIR = Path(f"/tmp/diffuser-140t-{os.getuid()}")


class AdapterError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def error_receipt(exc):
    return {"ok": False, "error_code": exc.code, "error": str(exc)}


def command(profile):
    return ["/usr/bin/taskset", "-c", "6-13", ENGINE, "-m", MODELS[profile],
            "--host", HOST, "--port", str(PORT), *FLAGS]


def engine_env():
    # Do not inherit worker credentials, proxy settings or GGML tuning flags.
    env = {key: os.environ[key] for key in ("HOME", "USER", "LANG") if key in os.environ}
    env.update(PATH="/usr/bin:/bin", VK_DRIVER_FILES="/usr/share/vulkan/icd.d/intel_icd.json",
               MESA_SHADER_CACHE_DIR="/var/cache/diffuser-140t/mesa")
    return env


def package_temp(thermal=Path("/sys/class/thermal"), hwmon=Path("/sys/class/hwmon")):
    readings = []

    def read_sensor(path):
        try:
            value = int(path.read_text().strip()) / 1000
            if -20 <= value <= 150:
                readings.append(value)
        except (OSError, ValueError):
            pass

    for zone in thermal.glob("thermal_zone*"):
        try:
            if (zone / "type").read_text().strip() == "x86_pkg_temp":
                read_sensor(zone / "temp")
        except OSError:
            continue
    for device in hwmon.glob("hwmon*"):
        try:
            if (device / "name").read_text().strip() != "coretemp":
                continue
            for label in device.glob("temp*_label"):
                if label.read_text().strip().startswith("Package id "):
                    read_sensor(label.with_name(label.name.replace("_label", "_input")))
        except OSError:
            continue
    return max(readings) if readings else None


def check_thermal():
    temp = package_temp()
    if temp is None:
        raise AdapterError("thermal_unavailable", "CPU package temperature unavailable")
    if temp >= THERMAL_LIMIT:
        raise AdapterError("thermal_limit", "CPU package temperature reached 90 C")
    return temp


def encode(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode() + b"\n"


def decode(raw):
    def bad_constant(_):
        raise ValueError("non-finite number")

    try:
        return json.loads(raw, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise AdapterError("invalid_json", "expected valid JSON") from None


def invalid(message):
    raise AdapterError("invalid_input", message)


def validate(req, capability=None):
    if not isinstance(req, dict):
        invalid("request must be an object")
    action = req.get("action", "infer")
    if action not in ("infer", "status", "park"):
        invalid("action must be infer, status or park")
    if capability not in (None, INFER, CONTROL):
        invalid("unsupported capability")
    if (capability == CONTROL and action == "infer") or (capability == INFER and action != "infer"):
        invalid("action does not match capability")
    timeout = req.get("timeout_secs", DEFAULT_TIMEOUT)
    if type(timeout) is not int or not 1 <= timeout <= MAX_TIMEOUT:
        invalid("timeout_secs must be an integer from 1 to 600")
    if action != "infer":
        if req.keys() - {"action", "timeout_secs"}:
            invalid("control action has unsupported fields")
        return action, None, None, timeout
    profile = req.get("profile", "30b")
    if not isinstance(profile, str) or profile not in MODELS:
        invalid("profile must be 30b or 4b")
    optional = {"temperature", "top_p", "seed", "stop", "tools", "tool_choice", "response_format"}
    if req.keys() - ({"action", "profile", "prompt", "messages", "max_tokens", "timeout_secs"} | optional):
        invalid("unsupported inference field")
    if ("prompt" in req) == ("messages" in req):
        invalid("provide exactly one of prompt or messages")
    messages = req.get("messages", [{"role": "user", "content": req.get("prompt")}])
    if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
        invalid("messages must contain 1 to 128 entries")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in ("system", "user", "assistant", "tool"):
            invalid("invalid message role")
        if message.keys() - {"role", "content", "tool_calls", "tool_call_id", "name"}:
            invalid("unsupported message field")
        content = message.get("content")
        if not isinstance(content, str) and not (content is None and message.get("role") == "assistant"
                                                and isinstance(message.get("tool_calls"), list)):
            invalid("message content must be text")
    count = req.get("max_tokens", 256)
    if type(count) is not int or not 1 <= count <= 4096:
        invalid("max_tokens must be an integer from 1 to 4096")
    for key, upper in (("temperature", 2), ("top_p", 1)):
        if key in req:
            value = req[key]
            if type(value) not in (int, float) or not 0 <= value <= upper:
                invalid(f"invalid {key}")
    if "seed" in req and (type(req["seed"]) is not int or not 0 <= req["seed"] < 2**32):
        invalid("invalid seed")
    if "stop" in req:
        stop = req["stop"]
        if not (isinstance(stop, str) or isinstance(stop, list) and len(stop) <= 8
                and all(isinstance(item, str) for item in stop)):
            invalid("invalid stop sequences")
    if "tools" in req and not isinstance(req["tools"], list):
        invalid("tools must be a list")
    if "tool_choice" in req and not isinstance(req["tool_choice"], (str, dict)):
        invalid("invalid tool_choice")
    if "response_format" in req and not isinstance(req["response_format"], dict):
        invalid("response_format must be an object")
    payload = {"messages": messages, "max_tokens": count, "stream": False}
    payload.update({key: req[key] for key in optional if key in req})
    return action, profile, payload, timeout


def http_json(path, payload=None, timeout=2):
    # Fixed loopback destination, no proxy, redirects or credentials.
    conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        conn.request("GET" if payload is None else "POST", path,
                     body=None if payload is None else encode(payload),
                     headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        if res.status != 200:
            raise AdapterError("engine_http", f"engine returned HTTP {res.status}")
        body = res.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise AdapterError("response_too_large", "engine response exceeded byte limit")
        value = decode(body)
        if not isinstance(value, dict):
            raise AdapterError("engine_response", "engine response must be an object")
        return value
    finally:
        conn.close()


def disconnected(client):
    return bool(select.select([client], [], [], 0)[0]) and not client.recv(1, socket.MSG_PEEK)


def port_available():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Match normal server restart behavior after connections enter TIME_WAIT.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((HOST, PORT))
        except OSError:
            return False
    return True



def owns_listener(pid, proc_root=Path("/proc")):
    """Check that the fixed IPv4 listening socket belongs to this child."""
    process = proc_root / str(pid)
    address = f"{socket.inet_aton(HOST)[::-1].hex().upper()}:{PORT:04X}"
    try:
        inodes = set()
        for row in (process / "net/tcp").read_text().splitlines()[1:]:
            fields = row.split()
            if len(fields) >= 10 and fields[1] == address and fields[3] == "0A":
                inodes.add(f"socket:[{fields[9]}]")
        if not inodes:
            return False
        for fd in (process / "fd").iterdir():
            try:
                if os.readlink(fd) in inodes:
                    return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def launch_engine(profile):
    if not os.access(ENGINE, os.X_OK) or not os.path.isfile(MODELS[profile]):
        raise AdapterError("engine_missing", "qualified binary or model file unavailable")
    if not port_available():
        raise AdapterError("port_in_use", "loopback port 18081 is already owned by another listener")
    # The wrapper sets a Linux parent-death signal before exec. The resulting
    # process is the qualified taskset/llama-server, owned only by this supervisor.
    return subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--engine",
                             str(os.getpid()), profile], env=engine_env(),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, close_fds=True)


def engine_child(parent, profile):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        return 1
    argv = command(profile)
    os.execv(argv[0], argv)


class Supervisor:
    def __init__(self):
        self.proc = None
        self.profile = None
        self.ready = False
        self.last_used = time.monotonic()
        self.stopping = False

    def stop(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=STOP_SECS)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=STOP_SECS)
            self.proc = None
        self.profile = None
        self.ready = False

    def live(self):
        return self.proc is not None and self.proc.poll() is None

    def guard(self, deadline, client):
        check_thermal()
        if self.stopping or disconnected(client):
            raise AdapterError("cancelled", "request cancelled")
        if time.monotonic() >= deadline:
            raise AdapterError("timeout", "request deadline exceeded")
        if not self.live():
            raise AdapterError("engine_exited", "owned engine exited")

    def monitored(self, operation, deadline, client):
        # The sole engine owner continues checking temperature while HTTP blocks.
        result = queue.Queue(1)

        def worker():
            try:
                result.put((True, operation()))
            except Exception as exc:
                result.put((False, exc))

        thread = threading.Thread(target=worker, daemon=True)
        self.guard(deadline, client)
        thread.start()
        try:
            while True:
                self.guard(deadline, client)
                try:
                    success, value = result.get(timeout=POLL)
                except queue.Empty:
                    continue
                thread.join()  # Result was queued; the thread has no more work.
                self.guard(deadline, client)
                if success:
                    return value
                raise value
        finally:
            # If a guard interrupted HTTP, retire the supervisor rather than
            # allow an old request thread to reach a newly loaded model.
            if thread.is_alive():
                self.stopping = True

    def wake(self, profile, deadline, client):
        check_thermal()
        if self.live() and self.profile == profile and self.ready:
            return
        self.stop()
        check_thermal()
        if self.stopping or disconnected(client):
            raise AdapterError("cancelled", "request cancelled")
        if time.monotonic() >= deadline:
            raise AdapterError("timeout", "request deadline exceeded")
        self.proc = launch_engine(profile)
        self.profile = profile
        startup_deadline = min(deadline, time.monotonic() + STARTUP_SECS)
        while True:
            self.guard(startup_deadline, client)
            if not owns_listener(self.proc.pid):
                time.sleep(POLL)
                continue
            try:
                health = self.monitored(lambda: http_json("/health"), startup_deadline, client)
                if health.get("status") == "ok":
                    self.ready = True
                    return
            except (OSError, http.client.HTTPException):
                pass
            except AdapterError as exc:
                if exc.code != "engine_http":
                    raise
            time.sleep(POLL)

    def handle(self, request, deadline, client):
        action, profile, payload, _ = validate(request)
        if self.stopping:
            raise AdapterError("cancelled", "supervisor is stopping")
        if action == "park":
            self.stop()
            return self.status()
        if action == "status":
            return self.status()
        try:
            self.wake(profile, deadline, client)
            if not owns_listener(self.proc.pid):
                raise AdapterError("engine_listener", "owned engine no longer owns the loopback listener")
            response = self.monitored(
                lambda: http_json("/v1/chat/completions", payload,
                                  timeout=max(1, deadline - time.monotonic())), deadline, client)
            if not isinstance(response.get("choices"), list) or not response["choices"]:
                raise AdapterError("engine_response", "engine returned no completion choices")
            self.last_used = time.monotonic()
            return {"ok": True, "profile": profile, "response": response}
        except BaseException:
            self.stop()
            raise

    def status(self):
        temp = package_temp()
        if not self.live() or temp is None or temp >= THERMAL_LIMIT:
            self.stop()
        return {"ok": True, "state": "ready" if self.ready else "parked",
                "profile": self.profile, "package_temp_c": temp,
                "thermal_ok": temp is not None and temp < THERMAL_LIMIT}

    def idle_tick(self):
        if self.proc is None:
            return
        try:
            check_thermal()
            if not self.live() or time.monotonic() - self.last_used >= IDLE_SECS:
                self.stop()
        except AdapterError:
            self.stop()


def state_paths():
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    st = STATE_DIR.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise AdapterError("state_permissions", "adapter state directory must be private and owned by worker")
    return STATE_DIR / "control.sock", STATE_DIR / "request.lock"


def lock_file(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        os.close(fd)
        raise AdapterError("state_permissions", "adapter lock must be private and owned by worker")
    return fd


def receive_line(conn, limit):
    data = bytearray()
    while len(data) <= limit:
        chunk = conn.recv(min(65536, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if data.endswith(b"\n"):
            if len(data) <= limit:
                return decode(data)
            break
    raise AdapterError("protocol_error", "missing or oversized adapter message")


def serve(listener_fd):
    manager = Supervisor()
    signal.signal(signal.SIGTERM, lambda *_: setattr(manager, "stopping", True))
    signal.signal(signal.SIGINT, lambda *_: setattr(manager, "stopping", True))
    with socket.socket(fileno=listener_fd) as listener:
        listener.settimeout(POLL)
        try:
            while not manager.stopping:
                manager.idle_tick()
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    # Once parked, exit under the same lock used by clients so a
                    # new request cannot connect to a supervisor that is exiting.
                    if manager.proc is None:
                        _, lock_path = state_paths()
                        fd = lock_file(lock_path)
                        try:
                            try:
                                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            except BlockingIOError:
                                continue
                            listener.close()
                            return
                        finally:
                            os.close(fd)
                    continue
                with client:
                    client.settimeout(2)
                    try:
                        envelope = receive_line(client, MAX_INPUT * 6)
                        receipt = manager.handle(envelope["request"], envelope["deadline"], client)
                    except AdapterError as exc:
                        receipt = error_receipt(exc)
                    except (OSError, http.client.HTTPException, ValueError, KeyError, TypeError):
                        receipt = error_receipt(AdapterError("engine_unavailable", "adapter or engine I/O failed"))
                    if manager.stopping:
                        listener.close()
                    try:
                        client.sendall(encode(receipt))
                    except (OSError, ValueError, RecursionError):
                        manager.stop()
        finally:
            manager.stop()


def connect_supervisor(path, wake):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(path))
        return client
    except (FileNotFoundError, ConnectionRefusedError):
        client.close()
        if not wake:
            return None
    except BaseException:
        client.close()
        raise
    check_thermal()
    # Caller holds the cross-process request lock. Never unlink a live listener.
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):
            raise AdapterError("state_permissions", "unexpected state socket path")
        path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--supervise", str(listener.fileno())],
                         pass_fds=(listener.fileno(),), start_new_session=True, env=engine_env(),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(path))
            return client
        except BaseException:
            client.close()
            raise


def execute(req, capability=None, outer_timeout=None):
    action, _, _, budget = validate(req, capability)
    if outer_timeout is not None:
        budget = min(budget, outer_timeout - CLEANUP_RESERVE)
    if budget <= 0:
        raise AdapterError("timeout", "worker budget leaves no time for cleanup")
    deadline = time.monotonic() + budget
    path, lock_path = state_paths()
    fd = lock_file(lock_path)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AdapterError("busy", "another 140T request is active") from None
        # A hot request is also sent to an existing supervisor so it can park.
        client = connect_supervisor(path, wake=action == "infer")
        if client is None:
            return Supervisor().status()
        with client:
            client.settimeout(max(1, deadline - time.monotonic() + STOP_SECS * 2))
            client.sendall(encode({"request": req, "deadline": deadline}))
            return receive_line(client, MAX_RESPONSE * 6)
    finally:
        os.close(fd)


def output_receipt(receipt):
    raw = encode(receipt)
    # The fleet worker waits for process exit before draining the stdout pipe.
    # Never block on a receipt larger than that pipe's actual capacity.
    try:
        capacity = fcntl.fcntl(sys.stdout.fileno(), fcntl.F_GETPIPE_SZ)
    except OSError:
        capacity = MAX_RESPONSE
    if len(raw) > capacity:
        raw = encode(error_receipt(AdapterError("response_too_large", "receipt exceeds worker stdout capacity")))
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise AdapterError("input_too_large", "request exceeds byte limit")
        timeout = os.environ.get("DIFFUSER_TIMEOUT_SECS")
        receipt = execute(decode(raw), os.environ.get("DIFFUSER_CAPABILITY"),
                          None if timeout is None else int(timeout))
    except AdapterError as exc:
        receipt = error_receipt(exc)
    except (OSError, ValueError, TypeError, RuntimeError):
        receipt = error_receipt(AdapterError("adapter_unavailable", "adapter I/O or configuration failed"))
    output_receipt(receipt)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--supervise":
        serve(int(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "--engine":
        sys.exit(engine_child(int(sys.argv[2]), sys.argv[3]))
    elif len(sys.argv) == 1:
        main()
    else:
        sys.exit(2)
