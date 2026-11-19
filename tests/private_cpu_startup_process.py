"""Process checks for the built uai-diffuser; invoke inside private namespaces."""

import hashlib
import http.client
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


BINARY = pathlib.Path(sys.argv[1]).resolve(strict=True)
ROLE = sys.argv[2]
ROOT = pathlib.Path({"controller": "/job/service", "worker": "/job/workerroot"}[ROLE])
FLAG = "--check-private-cpu-startup"
# Wire names and limits come from the existing runtime-short-v1 policy.
POLICY = {
    "policy_id": "runtime-short-v1", "queue_ms": 120000,
    "occupancy_freshness_ms": 6000, "admission_freshness_ms": 3600000,
    "start_ms": 2000, "idle_ms": 2000, "lease_ms": 4000,
    "tenure_ms": 12000, "job_ms": 8000, "permit_window_ms": 1500,
    "renewal_ms": 400, "worker_heartbeat_ms": 400, "worker_loss_ms": 1200,
    "authority_observation_ms": 400, "authority_freshness_ms": 1500,
    "grace_ms": 500, "cleanup_ms": 1500,
}
POLICY_DIGEST = hashlib.sha256(json.dumps(POLICY, separators=(",", ":"), sort_keys=True).encode()).hexdigest()
with BINARY.open("rb") as binary:
    EXEC_DIGEST = hashlib.file_digest(binary, "sha256").hexdigest()
ARGS = [FLAG, ROLE, POLICY_DIGEST, EXEC_DIGEST]


def check(label, args, status, expected):
    run = subprocess.run([BINARY, *args], capture_output=True, timeout=4, check=False)
    row = {"case": label, "role": ROLE, "status": run.returncode,
           "stdout": run.stdout.decode(), "stderr": run.stderr.decode()}
    print(json.dumps(row), flush=True)
    assert run.returncode == status, row
    payload = json.loads(run.stdout)
    assert not run.stderr, row
    assert (payload["error"]["code"] if status else payload) == expected, row


def check_default():
    with tempfile.TemporaryDirectory(prefix="cpu-default-") as state:
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        with subprocess.Popen([BINARY, "--state-dir", state, "--bind", f"localhost:{port}"]) as server:
            try:
                deadline = time.monotonic() + 4
                while True:
                    if server.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError(f"default listener not ready: {server.poll()}")
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
                    try:
                        conn.request("GET", "/v1/diffuser/discovery")
                        response = conn.getresponse()
                        body = json.loads(response.read())
                        break
                    except ConnectionRefusedError:
                        time.sleep(0.025)
                    finally:
                        conn.close()
                assert response.status == 503 and body["error"]["code"] == "routing_closed", body
                print(json.dumps({"case": "default_discovery", "status": response.status, "body": body}))
                sdk = subprocess.run([sys.argv[4], str(port)], capture_output=True, timeout=3, check=False)
                print(json.dumps({"case": "sdk_probe_process", "status": sdk.returncode,
                                  "stdout": sdk.stdout.decode(), "stderr": sdk.stderr.decode()}))
                assert sdk.returncode == 0 and not sdk.stderr
                assert json.loads(sdk.stdout) == {"case": "sdk_discovery", "status": 503,
                                                 "code": "routing_closed"}
            finally:
                if server.poll() is None:
                    server.terminate()
                    server.wait(timeout=3)
            with socket.socket() as probe:
                probe.settimeout(0.5)
                assert probe.connect_ex(("127.0.0.1", port)) != 0
            print(json.dumps({"case": "default_teardown", "returncode": server.returncode, "listener_gone": True}))


# Including a nonlocal legacy bind makes the missing selector fail promptly on
# the base instead of booting the legacy listener and timing out.
check("mixed_options", ARGS + ["--bind", "127.0.0.1:0"], 64, "private_cpu_check_usage")
if sys.argv[3] == "missing":
    check("missing_root", ARGS, 70, "startup_root_invalid")
    sys.exit(0)
assert not any(ROOT.iterdir())
check("fresh_root", ARGS, 0, {"status": "preflight_only", "role": ROLE, "root": str(ROOT),
                              "policy_sha256": POLICY_DIGEST, "executable_sha256": EXEC_DIGEST})
assert not any(ROOT.iterdir())
check("unknown_role", [FLAG, "claim_client", POLICY_DIGEST, EXEC_DIGEST], 64, "private_cpu_check_usage")
check("policy_mismatch", [FLAG, ROLE, "0" * 64, EXEC_DIGEST], 70, "startup_policy_mismatch")
check("executable_mismatch", [FLAG, ROLE, POLICY_DIGEST, "0" * 64], 70, "startup_executable_mismatch")
check("state_dir_not_accepted", ARGS + ["--state-dir", str(ROOT)], 64, "private_cpu_check_usage")
ROOT.chmod(0o755)
try:
    check("nonprivate_root", ARGS, 70, "startup_root_invalid")
finally:
    ROOT.chmod(0o700)
marker = ROOT / "occupancy"
marker.write_bytes(b"must not change")
try:
    check("occupied_root", ARGS, 70, "startup_root_not_fresh")
    assert list(ROOT.iterdir()) == [marker] and marker.read_bytes() == b"must not change"
finally:
    marker.unlink()
if ROLE == "controller":
    check_default()
assert not any(ROOT.iterdir())
