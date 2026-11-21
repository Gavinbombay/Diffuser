from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

ADAPTER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ADAPTER_DIR))
import colab_l4
import colab_train
from artifacts import ArtifactError, Artifacts
from engine import Engine, Refusal, read_intent, seat_lock, write_state
from secure_io import MAX_JSON_BYTES


FAKE_COLAB = r"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

root = Path(os.environ["FAKE_COLAB_ROOT"])
options = json.loads((root / "options.json").read_text())
live = root / "live.json"
args = sys.argv[1:]
assert args[:1] == ["--config"], args
config = Path(args[1])
args = args[2:]
with (root / "calls.jsonl").open("a") as log:
    print(json.dumps(args), file=log)

action = args[0]
owned = json.loads(live.read_text()) if live.exists() else {}
tracked = json.loads(config.read_text()) if config.exists() else {}

def save(path, payload):
    pending = path.with_name(f"{path.name}.{os.getpid()}")
    pending.write_text(json.dumps(payload))
    pending.replace(path)

def next_count(name):
    path = root / name
    count = int(path.read_text()) if path.exists() else 0
    count += 1
    path.write_text(str(count))
    return count

def guest(name):
    return root / "guests" / name

if action == "usage":
    marker = root / "stopped"
    stopped = marker.exists()
    marker.unlink(missing_ok=True)
    if options.get("usage_fail") or stopped and options.get("after_fail"):
        sys.exit(2)
    balances = options.get("usage_balances")
    if isinstance(balances, list) and balances:
        balance = balances[min(next_count("usage_count") - 1, len(balances) - 1)]
    else:
        balance = options.get("after", "248.75") if stopped else options.get("before", "250.00")
    with (root / "usage_marks").open("a") as marks:
        marks.write(f"{time.monotonic():.6f} {balance}{chr(10)}")
    print(options.get("usage_output", f"Current balance: {balance} compute units"))
    print("Usage rate: 0.00/hr")
    print("Active assignments: 0")
elif action == "sessions":
    stopped = (root / "stopped").exists()
    mode = options.get("post_stop") if stopped else options.get("pre_stop")
    if mode == "failed":
        sys.exit(2)
    if mode == "ambiguous":
        print("[colab] No active sessions found on server.")
        print("The assignment listing was incomplete.")
        sys.exit(0)
    if mode == "blank":
        sys.exit(0)
    if mode == "stderr":
        print("[colab] No active sessions found on server.")
        print("Could not authenticate", file=sys.stderr)
        sys.exit(0)
    if options.get("update_banner"):
        print("[colab] A new version of Colab CLI is available: 99.0")
        print("[colab] Run 'pip install --upgrade google-colab-cli'")
        print("[colab] To silence this check, change your settings.")
    rows = {**options.get("foreign", {}), **owned}
    reveal_on = options.get("reveal_owned_session_on_call")
    if reveal_on is not None and next_count("sessions_count") == reveal_on:
        state = Path(os.environ["DIFFUSER_COLAB_STATE_DIR"])
        intents = [json.loads(path.read_text()) for pattern in ("*/active_intent.json", "*/seat-*.intent.json")
                   for path in state.glob(pattern)]
        for intent in intents:
            rows[intent["session_name"]] = intent.get("gpu", "L4")
    if mode == "anonymous":
        rows["?"] = "L4"
    if not rows:
        print("[colab] No active sessions found on server.")
    for index, (name, gpu) in enumerate(rows.items(), 1):
        if name in owned and name not in tracked:
            name = "?"
        print(f"[{name}] endpoint{index} | Hardware: {gpu} | Shape: Standard | Variant: GPU")
elif action == "new":
    assert args[1] == "-s" and args[3] == "--gpu", args
    name, gpu = args[2], args[4]
    state = Path(os.environ["DIFFUSER_COLAB_STATE_DIR"])
    intents = [json.loads(path.read_text()) for pattern in ("*/active_intent.json", "*/seat-*.intent.json")
               for path in state.glob(pattern)]
    intent, = [intent for intent in intents if intent["session_name"] == name]
    assert intent["session_name"] == name and intent["gpu"] == gpu, intent
    assert name == "diffuser-{lane_id}-{job_id}-{generation}".format(**intent)
    assert intent["created_at"] == intent["started_at"]
    assert intent["owner_pid"] == os.getppid()
    (root / "intent_seen.json").write_text(json.dumps(intent))
    with (root / "new_marks").open("a") as marks:
        marks.write(f"{time.monotonic():.6f}\n")
    failures = options.get("transient_new_failures", 0)
    seen_path = root / "transient_new_count"
    seen = int(seen_path.read_text()) if seen_path.exists() else 0
    if seen < failures:
        seen_path.write_text(str(seen + 1))
        sys.exit(3)
    (root / "stopped").unlink(missing_ok=True)
    owned[name] = options.get("provider_gpu", gpu)
    save(live, owned)
    tracked[name] = {"name": name}
    save(config, tracked)
    guest(name).mkdir(parents=True)
    if options.get("new_fail"):
        sys.exit(3)
elif action == "exec":
    assert args[1] == "-s" and args[2] in owned, args
    assert args[3] == "-f" and args[5] == "--timeout" and float(args[6]) > 0, args
    if options.get("cli_diagnostic"):
        print(options["cli_diagnostic"], flush=True)
    if options.get("exec_fail"):
        sys.exit(4)
    if options.get("exec_silent"):
        sys.exit(0)
    if options.get("exec_hang"):
        (root / "exec_ready").touch()
        time.sleep(30)
    if options.get("exec_wait"):
        (root / "exec_ready").touch()
        (root / f"ready-{args[2]}").touch()
        deadline = time.monotonic() + 12
        while not (root / "exec_release").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
    env = dict(os.environ, FAKE_GPU=options.get("guest_gpu", owned[args[2]]))
    sys.exit(subprocess.call([sys.executable, args[4]], env=env, cwd=guest(args[2])))
elif action == "upload":
    assert args[1] == "-s" and args[2] in owned, args
    assert args[4].startswith("content/"), args
    shutil.copyfile(args[3], guest(args[2]) / args[4][8:])
elif action == "download":
    assert args[1] == "-s" and args[2] in owned, args
    assert args[3].startswith("content/"), args
    source = guest(args[2]) / args[3][8:]
    if options.get("corrupt_download"):
        Path(args[4]).write_bytes(b"x" * source.stat().st_size)
    else:
        shutil.copyfile(source, args[4])
elif action == "stop":
    assert args[1] == "-s" and args[2] not in options.get("foreign", {}), args
    (root / "stopped").touch()
    if not options.get("stop_survives"):
        owned.pop(args[2], None)
        save(live, owned)
        tracked.pop(args[2], None)
        save(config, tracked)
    if options.get("stop_hang"):
        time.sleep(30)
    if options.get("stop_fail"):
        sys.exit(5)
else:
    raise AssertionError(f"Unexpected command {args}")
"""


class ColabAdaptersTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.fixture = Path(self.temp.name)
        self.bin = self.fixture / "colab"
        self.bin.write_text(f"#!{sys.executable}\n" + FAKE_COLAB, encoding="utf-8")
        self.bin.chmod(0o755)
        smi = self.fixture / "nvidia-smi"
        smi.write_text(
            "#!/bin/sh\n"
            "[ \"$*\" = '--query-gpu=name,memory.total,driver_version --format=csv,noheader' ] || exit 2\n"
            "printf 'NVIDIA %s, 23034 MiB, 550.54.15\\n' \"$FAKE_GPU\"\n",
            encoding="utf-8",
        )
        smi.chmod(0o755)
        self.state_root = self.fixture / "state"
        self.l4 = self.state_root / "colab-l4"
        self.train = self.state_root / "colab-train"
        self.env = {
            "FAKE_COLAB_ROOT": str(self.fixture),
            "DIFFUSER_COLAB_BIN": str(self.bin),
            "DIFFUSER_COLAB_STATE_DIR": str(self.state_root),
            "DIFFUSER_COLAB_MAX_ACCOUNT_VMS": "2",
            "DIFFUSER_JOB_ID": "",
            "PATH": str(self.fixture) + os.pathsep + os.environ["PATH"],
        }
        self.options()

    def options(self, **kwargs):
        (self.fixture / "options.json").write_text(json.dumps(kwargs), encoding="utf-8")
        for name in ("transient_new_count", "usage_count", "sessions_count", "usage_marks", "new_marks"):
            (self.fixture / name).unlink(missing_ok=True)

    def calls(self):
        log = self.fixture / "calls.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def actions(self):
        return [args[0] for args in self.calls()]

    def unpark(self, marker=None):
        self.train.mkdir(parents=True, exist_ok=True)
        (self.train / "OWNER-GO.json").write_text(
            json.dumps({"unparked": True} if marker is None else marker), encoding="utf-8",
        )

    def invoke(self, request, lane="l4", raw=None, **env):
        completed = subprocess.run(
            [str(ADAPTER_DIR / f"colab_{lane}.py")],
            input=json.dumps(request) if raw is None else raw, text=True, capture_output=True,
            env={**os.environ, **self.env, **env}, timeout=8,
        )
        return self.parse(completed.returncode, completed.stdout, completed.stderr)

    def parse(self, returncode, stdout, stderr):
        self.assertEqual(returncode, 0, stderr)
        self.assertEqual(stderr, "")
        self.assertEqual(len(stdout.splitlines()), 1)
        receipt = json.loads(stdout)
        self.assertIsInstance(receipt, dict)
        return receipt

    def assert_clean(self, result):
        self.assertTrue(result["cleanup_verified"], result)
        self.assertEqual(result["leaked_owned_sessions"], 0)
        self.assertEqual(self.calls()[-3], ["stop", "-s", result["session_name"]])
        self.assertEqual(self.calls()[-2:], [["sessions"], ["usage"]])
        directory = self.state_root / result["lane_id"]
        self.assertFalse((directory / "active_intent.json").exists())
        self.assertEqual(list(directory.glob("seat-*.intent.json")), [])

    def test_pay_is_refused_at_subprocess_boundary(self):
        engine = Engine(colab_l4.CONFIG, self.bin, self.state_root)
        for args in (["pay"], ["usage", "pay"], ["status", "--", "pay"]):
            with self.subTest(args=args), self.assertRaisesRegex(Refusal, "^purchase_forbidden$"):
                engine.run_cli(args, time.monotonic() + 1, lambda: False)
        self.assertEqual(self.calls(), [])

    def test_low_balance_and_unavailable_usage_block_allocation(self):
        for options, error in (
            ({"before": "199.99"}, "cu_below_floor"),
            ({"usage_output": "Current balance: unknown"}, "usage_unavailable"),
            ({"usage_output": "Current balance: 250.00 CU\nBalance: 1 CU"}, "usage_unavailable"),
            ({"usage_output": "Current balance: 250.0.1 CU"}, "usage_unavailable"),
            ({"usage_fail": True}, "usage_unavailable"),
        ):
            with self.subTest(options=options):
                self.options(**options)
                self.assertEqual(self.invoke({"action": "probe"})["error"], error)
        self.assertEqual(self.actions(), ["usage"] * 5)
        self.assertFalse((self.l4 / "active_intent.json").exists())

    def test_configured_floor_cannot_lower_hard_floor_and_can_raise_it(self):
        with patch.dict(os.environ, self.env):
            for floor, balance in ((10.0, "199.99"), (275.0, "274.99")):
                with self.subTest(floor=floor):
                    self.options(before=balance)
                    engine = Engine(replace(colab_l4.CONFIG, min_cu_floor=floor))
                    self.assertEqual(
                        engine.handle({"action": "probe"}, lambda: False)["error"], "cu_below_floor",
                    )
        self.assertEqual(self.actions(), ["usage", "usage"])

    def test_budget_and_timeout_ceilings_and_invalid_values(self):
        self.unpark()
        for lane, cap, walltime in (("l4", 30, 5400), ("train", 100, 21600)):
            for key, error, values in (
                ("max_cu", "invalid_max_cu", [cap + 0.01, -1, 0, None, True, "2", 10**100]),
                ("timeout_secs", "invalid_timeout_secs", [walltime + 1, -1, 0, None, True, 1.5, "180"]),
            ):
                for value in values:
                    with self.subTest(lane=lane, field=key, value=value):
                        self.assertEqual(self.invoke({"action": "probe", key: value}, lane)["error"], error)
        self.assertEqual(self.calls(), [])
        for lane, cap, walltime in (("l4", 30, 5400), ("train", 100, 21600)):
            with self.subTest(lane=lane):
                self.assertTrue(self.invoke(
                    {"action": "probe", "max_cu": cap, "timeout_secs": walltime}, lane,
                )["ok"])

    def test_train_is_parked_until_literal_owner_go_and_forbids_l4_t4(self):
        health = self.invoke({"action": "health"}, "train")
        self.assertTrue(health["ok"])
        self.assertTrue(health["parked"])
        self.assertFalse(health["accepting"])
        self.assertEqual(health["allowed_gpus"], ["G4", "H100", "A100"])
        self.assertFalse(self.state_root.exists())
        self.assertEqual(self.invoke({"action": "probe"}, "train")["error"], "lane_parked")
        self.unpark({"unparked": 1})
        self.assertEqual(self.invoke({"action": "exec"}, "train")["error"], "lane_parked")
        self.unpark()
        status = self.invoke({"action": "status"}, "train")
        self.assertTrue(status["accepting"])
        self.assertFalse(status["parked"])
        for gpu in ("L4", "T4", "l4", " t4 "):
            with self.subTest(gpu=gpu):
                self.assertEqual(self.invoke({"action": "probe", "gpu": gpu}, "train")["error"],
                                 "gpu_forbidden_for_train")
        self.assertEqual(self.actions(), ["usage", "sessions", "usage", "sessions"])
        for gpu in ("G4", "H100", "A100"):
            with self.subTest(gpu=gpu):
                self.options(guest_gpu="RTX PRO 6000" if gpu == "G4" else gpu)
                result = self.invoke({"action": "probe", "gpu": gpu}, "train")
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["gpu_requested"], gpu)
                self.assert_clean(result)

    def test_probe_records_intent_before_new_and_leaves_foreign_names_alone(self):
        foreign = {"another-session": "T4", "diffuser-colab-l4-foreign-deadbeefcafe": "L4"}
        self.options(before="200.00", after="198.75", foreign=foreign)
        result = self.invoke({"action": "probe", "timeout_secs": 180}, DIFFUSER_JOB_ID="fleet-job")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["lane_id"], "colab-l4")
        self.assertEqual(result["gpu_requested"], "L4")
        self.assertEqual(result["gpu_observed"], "NVIDIA L4")
        self.assertEqual((result["cu_before"], result["cu_after"], result["cu_delta"]), (200, 198.75, 1.25))
        self.assertEqual(self.actions(), ["usage", "new", "sessions", "exec", "stop", "sessions", "usage"])
        intent = json.loads((self.fixture / "intent_seen.json").read_text())
        self.assertEqual(intent["job_id"], "fleet-job")
        self.assertEqual(intent["session_name"], result["session_name"])
        self.assert_clean(result)

    def test_exec_returns_remote_output_and_cleanup_receipt(self):
        result = self.invoke({"action": "exec", "command": "printf 'remote output\\n'"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["stdout"].strip(), "remote output")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["cu_delta"], 1.25)
        self.assert_clean(result)

    def test_exec_output_fits_fleet_worker_pipe(self):
        command = "printf '%04000d' 0"
        result = self.invoke({"action": "exec", "command": command})
        self.assertTrue(result["ok"], result)
        self.assertIn("[output truncated]", result["stdout"])
        self.assertLess(len(json.dumps(result)), 4096)

    def test_no_gpu_fallback_and_workload_does_not_run_on_wrong_gpu(self):
        workload_output = self.fixture / "workload-ran"
        command = f"touch {shlex.quote(str(workload_output))}"
        for options in ({"provider_gpu": "CPU"}, {"guest_gpu": "T4"}):
            with self.subTest(options=options):
                self.options(**options)
                result = self.invoke({"action": "exec", "command": command})
                self.assertEqual(result["error"], "gpu_mismatch")
                self.assertFalse(workload_output.exists())
                self.assert_clean(result)

    def test_command_errors_and_timeouts_still_clean_up(self):
        for options, command, timeout, error in (
            ({}, "exit 7", 180, "command_failed"),
            ({"exec_fail": True}, "true", 180, "command_failed"),
            ({"exec_silent": True}, "true", 180, "exec_result_unavailable"),
            ({"exec_hang": True}, "true", 1, "timeout"),
            ({"new_fail": True}, "true", 180, "allocation_failed"),
        ):
            with self.subTest(options=options, timeout=timeout):
                self.options(**options)
                result = self.invoke({"action": "exec", "command": command, "timeout_secs": timeout})
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["error"], error)
                self.assert_clean(result)

    def test_cu_overage_and_missing_post_job_usage_cannot_report_success(self):
        self.options(after="219.99")
        result = self.invoke({"action": "probe"})
        self.assertEqual(result["error"], "cu_budget_exceeded")
        self.assertEqual(result["cu_delta"], 30.01)
        self.assert_clean(result)
        self.options(after_fail=True)
        result = self.invoke({"action": "probe"})
        self.assertEqual(result["error"], "usage_unavailable")
        self.assertIsNone(result["cu_after"])
        self.assert_clean(result)

    def test_cleanup_failures_override_success_and_quarantine(self):
        for options, leaked, reason in (
            ({"post_stop": "ambiguous"}, None, "sessions_ambiguous"),
            ({"post_stop": "blank"}, None, "sessions_ambiguous"),
            ({"post_stop": "failed"}, None, "sessions_unavailable"),
            ({"post_stop": "stderr"}, None, "sessions_unavailable"),
            ({"post_stop": "anonymous"}, None, "anonymous_sessions"),
            ({"stop_survives": True}, 1, "owned_session_live"),
            ({"stop_fail": True}, 0, "stop_failed"),
        ):
            with self.subTest(options=options):
                self.options(**options)
                result = self.invoke({"action": "probe"})
                self.assertEqual(result["gpu_observed"], "NVIDIA L4")
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], "cleanup_quarantined")
                self.assertFalse(result["cleanup_verified"])
                self.assertEqual(result["leaked_owned_sessions"], leaked)
                marker = self.l4 / "quarantine.json"
                self.assertIn(reason, json.loads(marker.read_text())["reasons"])
                intent = self.l4 / "active_intent.json"
                self.assertTrue(intent.exists())
                calls = self.calls()
                self.assertEqual(self.invoke({"action": "probe"})["error"], "lane_quarantined")
                self.assertEqual(self.invoke({"action": "exec"})["error"], "lane_quarantined")
                self.assertEqual(self.calls(), calls)
                self.options()
                status = self.invoke({"action": "status"})
                self.assertTrue(status["ok"])
                self.assertTrue(status["quarantined"])
                self.assertTrue(status["active_intent"])
                self.assertEqual(self.calls()[len(calls):], [["usage"], ["sessions"]])
                marker.unlink()
                self.assertTrue(self.invoke({"action": "probe"})["ok"])
                self.assertEqual(self.calls()[len(calls) + 2], ["stop", "-s", result["session_name"]])
                self.assertFalse(intent.exists())

    def test_invalid_stale_intent_never_stops_a_foreign_name(self):
        self.l4.mkdir(parents=True)
        (self.l4 / "active_intent.json").write_text(json.dumps({
            "lane_id": "colab-l4", "job_id": "job", "generation": "0123456789ab",
            "session_name": "foreign",
        }))
        result = self.invoke({"action": "probe"})
        self.assertEqual(result["error"], "cleanup_quarantined")
        self.assertEqual(self.calls(), [])
        self.assertTrue((self.l4 / "quarantine.json").exists())

    def test_stop_timeout_still_checks_sessions_and_quarantines(self):
        self.options(stop_hang=True)
        with patch.dict(os.environ, self.env), patch("engine.CONTROL_TIMEOUT", 0.6):
            engine = Engine(colab_l4.CONFIG)
            result = engine.handle({"action": "probe"}, lambda: False)
        self.assertEqual(result["error"], "cleanup_quarantined")
        self.assertEqual(result["leaked_owned_sessions"], 0)
        self.assertEqual(self.actions()[-3:], ["stop", "sessions", "usage"])

    def test_surviving_cli_child_holds_seat_after_forced_adapter_kill(self):
        self.options(exec_wait=True)
        ready = self.fixture / "exec_ready"
        release = self.fixture / "exec_release"
        with subprocess.Popen(
            [str(ADAPTER_DIR / "colab_l4.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, **self.env}, text=True,
        ) as child:
            try:
                child.stdin.write('{"action":"probe"}')
                child.stdin.close()
                deadline = time.monotonic() + 5
                while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                child.kill()
                child.wait(timeout=5)
                calls = self.calls()
                self.assertEqual(self.invoke({"action": "probe"})["error"], "seat_busy")
                self.assertEqual(self.calls(), calls)
                intent = json.loads((self.l4 / "active_intent.json").read_text())
            finally:
                release.touch()
                if child.poll() is None:
                    child.kill()
        self.options()
        deadline = time.monotonic() + 5
        while True:
            result = self.invoke({"action": "probe"})
            if result.get("error") != "seat_busy" or time.monotonic() >= deadline:
                break
        self.assertTrue(result["ok"], result)
        self.assertEqual(self.calls()[len(calls)], ["stop", "-s", intent["session_name"]])
        self.assert_clean(result)

    def test_signal_cleanup_and_single_seat_during_exec(self):
        self.options(exec_hang=True, foreign={"other-session": "L4"})
        ready = self.fixture / "exec_ready"
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                ready.unlink(missing_ok=True)
                with subprocess.Popen(
                    [str(ADAPTER_DIR / "colab_l4.py")],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, **self.env}, text=True,
                ) as child:
                    try:
                        child.stdin.write('{"action":"exec","command":"true"}')
                        child.stdin.close()
                        child.stdin = None
                        deadline = time.monotonic() + 5
                        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(ready.exists())
                        calls = self.calls()
                        self.assertEqual(self.invoke({"action": "probe"})["error"], "seat_busy")
                        self.assertEqual(self.calls(), calls)
                        child.send_signal(signum)
                        stdout, stderr = child.communicate(timeout=5)
                        result = self.parse(child.returncode, stdout, stderr)
                    finally:
                        if child.poll() is None:
                            child.kill()
                            child.communicate(timeout=5)
                self.assertEqual(result["error"], "interrupted")
                self.assert_clean(result)

    def test_invalid_input_still_uses_one_object_and_zero_exit(self):
        for raw in ("", "{", "null", '{"action":"probe","max_cu":NaN}'):
            with self.subTest(raw=raw):
                result = self.invoke(None, raw=raw)
                self.assertFalse(result["ok"])
        self.assertEqual(self.calls(), [])

    def worker(self, lane="gpu", gpus="T4", *flags):
        return [str(ADAPTER_DIR / "colab_worker.py"), "--lane", lane, "--gpus", gpus, *flags]

    def worker_request(self, request, lane="gpu", gpus="T4", *flags, **env):
        process = subprocess.run(
            self.worker(lane, gpus, *flags), input=json.dumps(request), text=True,
            capture_output=True, env={**os.environ, **self.env, **env}, timeout=8,
        )
        return self.parse(process.returncode, process.stdout, process.stderr)

    def ctl(self, *args, expected=0):
        process = subprocess.run(
            [str(ADAPTER_DIR / "colab_ctl.py"), *map(str, args)], text=True,
            capture_output=True, env={**os.environ, **self.env}, timeout=8,
        )
        self.assertEqual(process.returncode, expected, process.stderr)
        self.assertEqual(process.stderr, "")
        return json.loads(process.stdout)

    @contextmanager
    def start_worker(self, command, **env):
        with subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env={**os.environ, **self.env, **env},
        ) as child:
            try:
                child.stdin.write('{"action":"probe"}')
                child.stdin.close()
                child.stdin = None
                yield child
            finally:
                (self.fixture / "exec_release").touch()
                try:
                    child.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate(timeout=5)

    def wait_for_seat(self, lane, index):
        path = self.state_root / lane / f"seat-{index}.intent.json"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if path.exists():
                intent = json.loads(path.read_text())
                if (self.fixture / f"ready-{intent['session_name']}").exists():
                    return intent
            time.sleep(0.01)
        self.fail(f"Seat {index} in {lane} did not enter exec")

    def finish_worker(self, child):
        stdout, stderr = child.communicate(timeout=5)
        return self.parse(child.returncode, stdout, stderr)

    def test_generic_gpu_catalog_and_custom_passthrough(self):
        self.options(update_banner=True)
        for gpu, max_cu, walltime in (("T4", 30, 5400), ("A100", 100, 21600),
                                      ("CUSTOM_SKU", 30, 5400), ("next-gen", 30, 5400)):
            with self.subTest(gpu=gpu):
                status = self.worker_request({"action": "status"}, "gpu", gpu)
                self.assertTrue(status["ok"], status)
                self.assertEqual((status["max_cu_per_job"], status["max_walltime_secs"]), (max_cu, walltime))
                result = self.worker_request({"action": "probe"}, "gpu", gpu)
                self.assertTrue(result["ok"], result)
                self.assertEqual((result["gpu_requested"], result["gpu_observed"]), (gpu, f"NVIDIA {gpu}"))
                self.assert_clean(result)
        presets = self.ctl("list-presets")
        self.assertEqual(set(presets), {"T4", "L4", "A100", "H100", "G4"})
        self.assertEqual(presets["T4"]["capability"], "colab.t4.exec/v1")
        self.assertGreater(presets["G4"]["vram_gib"], 0)

    def test_generic_park_denylist_and_validation(self):
        flags = ("--forbid-gpus", "L4,T4", "--parked")
        self.assertEqual(self.worker_request({"action": "probe"}, "gpu", "L4,A100", *flags)["error"],
                         "lane_parked")
        self.ctl("unpark", "--lane", "gpu")
        self.assertEqual(
            self.worker_request({"action": "probe", "gpu": " t4 "}, "gpu", "L4,A100", *flags)["error"],
            "gpu_forbidden",
        )
        self.assertEqual(self.calls(), [])
        result = self.worker_request({"action": "probe"}, "gpu", "L4,A100", *flags)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["gpu_requested"], "A100")
        self.ctl("park", "--lane", "gpu")
        self.assertEqual(self.worker_request({"action": "probe"})["error"], "lane_parked")
        for command in (
            self.worker("../bad"), self.worker("gpu", "T4,,A100"),
            self.worker("gpu", "T4", "--forbid-gpus", "T4"),
            self.worker("gpu", "T4", "--min-cu-floor", "199.99"),
            self.worker("gpu", "T4", "--max-cu", "inf"),
            self.worker("gpu", "T4", "--max-walltime", "0"),
            self.worker("gpu", "T4", "--max-seats", "-1"),
            self.worker("gpu", "T4", "--max-account-vms", "0"),
            self.worker("gpu", "T4", "--idle-timeout", "0"),
        ):
            with self.subTest(command=command):
                result = subprocess.run(command, input='{"action":"probe"}', capture_output=True, text=True,
                                        env={**os.environ, **self.env}, timeout=8)
                self.assertEqual(result.returncode, 2)

    def test_account_cap_across_concurrent_lanes(self):
        self.options(exec_wait=True)
        with self.start_worker(self.worker("first", "T4")) as first:
            with self.start_worker(self.worker("second", "A100")) as second:
                first_intent = self.wait_for_seat("first", 0)
                second_intent = self.wait_for_seat("second", 0)
                self.assertEqual((first_intent["owner_pid"], second_intent["owner_pid"]), (first.pid, second.pid))
                self.assertNotEqual(first_intent["session_name"], second_intent["session_name"])
                self.assertEqual(self.worker_request({"action": "probe"}, "third")["error"],
                                 "account_capacity_reached")
                self.assertEqual(self.actions().count("new"), 2)
                self.assertTrue((self.state_root / "_account" / "account.lock").exists())
                (self.fixture / "exec_release").touch()
                for child in (first, second):
                    receipt = self.finish_worker(child)
                    self.assertTrue(receipt["ok"], receipt)
                    self.assertTrue(receipt["cleanup_verified"], receipt)
        self.assertEqual(json.loads((self.fixture / "live.json").read_text()), {})

    def test_account_cap_environment_and_explicit_flag(self):
        self.options(exec_wait=True)
        with self.start_worker(self.worker("one"), DIFFUSER_COLAB_MAX_ACCOUNT_VMS="1") as child:
            self.wait_for_seat("one", 0)
            result = self.worker_request({"action": "probe"}, "two", "A100", "--max-account-vms", "4")
            self.assertEqual(result["error"], "account_capacity_reached")
            self.assertEqual(self.actions().count("new"), 1)
            (self.fixture / "exec_release").touch()
            self.assertTrue(self.finish_worker(child)["ok"])
        result = self.worker_request(
            {"action": "probe"}, "two", "A100", "--max-account-vms", "2",
            DIFFUSER_COLAB_MAX_ACCOUNT_VMS="invalid",
        )
        self.assertTrue(result["ok"], result)

    def test_two_seats_and_legacy_seat_zero_are_isolated(self):
        flags = ("--max-seats", "2")
        command = self.worker("colab-l4", "L4", *flags)
        self.options(exec_wait=True)
        with self.start_worker(command) as first:
            self.wait_for_seat("colab-l4", 0)
            self.assertEqual(self.invoke({"action": "probe"})["error"], "seat_busy")
            with self.start_worker(command) as second:
                self.wait_for_seat("colab-l4", 1)
                self.assertEqual(self.worker_request({"action": "probe"}, "colab-l4", "L4", *flags)["error"],
                                 "seat_busy")
                self.assertEqual(self.actions().count("new"), 2)
                (self.fixture / "exec_release").touch()
                for child in (first, second):
                    receipt = self.finish_worker(child)
                    self.assertTrue(receipt["ok"], receipt)
                    self.assertTrue(receipt["cleanup_verified"], receipt)
        self.assertTrue((self.l4 / "seat-1.lock").exists())
        self.assertEqual(list(self.l4.glob("*.intent.json")), [])

    def test_upload_and_verified_download_precede_vm_stop(self):
        root = self.state_root / "gpu" / "artifacts"
        root.mkdir(parents=True)
        data = b"abc\x00\xff"
        (root / "input.bin").write_bytes(data)
        result = self.worker_request({
            "action": "exec", "command": "mkdir -p output && cp input/setup.bin output/result.bin",
            "files_in": [{"local": str(root / "input.bin"), "remote": "input/setup.bin"}],
            "files_out": [{"remote": "output/result.bin", "local": "results/result.bin"}],
        })
        self.assertTrue(result["ok"], result)
        self.assertEqual((root / "results/result.bin").read_bytes(), data)
        self.assertEqual(result["files_out"], [{
            "local": "results/result.bin", "remote": "output/result.bin",
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        }])
        self.assertEqual(self.actions(), ["usage", "new", "sessions", "exec", "upload", "exec",
                                          "download", "stop", "sessions", "usage"])
        self.assert_clean(result)

    def test_artifact_traversal_symlinks_and_limits_are_rejected(self):
        root = self.state_root / "gpu" / "artifacts"
        root.mkdir(parents=True)
        (root / "link").symlink_to(self.fixture, target_is_directory=True)
        with (root / "big").open("wb") as stream:
            stream.truncate(64 * 1024**2 + 1)
        for field, local, remote, error in (
            ("files_in", "../options.json", "good", "invalid_artifact_path"),
            ("files_out", "good", "dir/../bad", "invalid_artifact_path"),
            ("files_out", "good", "/tmp/file", "invalid_artifact_path"),
            ("files_out", "link/options.json", "good", "artifact_path_unavailable"),
            ("files_in", "link/options.json", "good", "artifact_path_unavailable"),
            ("files_in", "big", "good", "artifact_size_limit"),
        ):
            with self.subTest(field=field, local=local, remote=remote):
                result = self.worker_request({
                    "action": "exec", "command": "true", field: [{"local": local, "remote": remote}],
                })
                self.assertEqual(result["error"], error)
        result = self.worker_request({"action": "exec", "command": "true", "files_out": [{}] * 5})
        self.assertEqual(result["error"], "invalid_files_out")
        self.assertEqual(self.calls(), [])

    def test_guest_symlink_and_corrupt_download_keep_previous_artifact(self):
        root = self.state_root / "gpu" / "artifacts"
        root.mkdir(parents=True)
        local = root / "result"
        local.write_bytes(b"previous")
        for command, error, download in (
            ("ln -s /etc/passwd output", "guest_artifact_invalid", False),
            ("printf 'abc' > output", "artifact_digest_mismatch", True),
        ):
            with self.subTest(error=error):
                self.options(corrupt_download=download)
                offset = len(self.actions())
                result = self.worker_request({
                    "action": "exec", "command": command,
                    "files_out": [{"remote": "output", "local": local.name}],
                })
                self.assertEqual(result["error"], error)
                self.assertEqual("download" in self.actions()[offset:], download)
                self.assertEqual(local.read_bytes(), b"previous")
                self.assert_clean(result)

    def test_ctl_config_lifecycle_and_secret_redaction(self):
        config = self.fixture / "fleet-worker-colab.json"
        source = self.fixture / "existing.json"
        bearer, rpc_val = "private-enrollment-material", "private-rpc-material"
        source.write_text(json.dumps({"enroll_bearer": bearer, "rpc_secret_hex": rpc_val}))
        self.ctl("init", "--config", config, "--from-worker", source)
        original = json.loads(config.read_text())
        self.assertEqual(original["enroll_bearer"], bearer)
        self.assertNotEqual(original["rpc_secret_hex"], rpc_val)
        other = {"capability": "http.other", "adapter": {"kind": "http", "url": "http://localhost"}}
        original.update(profiles=[other], extra={"preserve": True}, rpc_secret_hex=rpc_val)
        config.write_text(json.dumps(original))
        config.chmod(0o644)
        self.ctl("add-lane", "--config", config, "--lane", "mixed", "--gpus", "T4,CUSTOM_SKU",
                 "--forbid-gpus", "T4", "--parked", "--max-seats", "2", "--timeout-secs", "240")
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        first = json.loads(config.read_text())
        self.assertEqual(first["profiles"][0], other)
        self.assertEqual(first["profiles"][1]["adapter"]["command"][0], str(ADAPTER_DIR / "colab_worker.py"))
        self.assertEqual(first["extra"], original["extra"])
        self.assertEqual((first["enroll_bearer"], first["rpc_secret_hex"]), (bearer, rpc_val))
        listing = self.ctl("list-lanes", "--config", config)
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["capability"], "colab.mixed.exec/v1")
        self.assertEqual(listing[0]["gpus"], ["CUSTOM_SKU"])
        self.assertEqual(listing[0]["max_seats"], 2)
        self.assertNotIn(bearer, json.dumps(listing))
        self.assertNotIn(rpc_val, json.dumps(listing))
        self.ctl("add-lane", "--config", config, "--lane", "mixed", "--gpus", "H100",
                 "--capability", "custom.cap")
        listing = self.ctl("list-lanes", "--config", config)
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["gpus"], ["H100"])
        self.assertEqual(listing[0]["capability"], "custom.cap")
        self.assertEqual(self.ctl("remove-lane", "--config", config, "--lane", "mixed")["removed"], 1)
        self.assertEqual(self.ctl("list-lanes", "--config", config), [])
        self.assertEqual(json.loads(config.read_text())["profiles"], [other])
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def ctl_failure(self, *args):
        process = subprocess.run(
            [str(ADAPTER_DIR / "colab_ctl.py"), *map(str, args)], text=True,
            capture_output=True, env={**os.environ, **self.env}, timeout=8,
        )
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(process.stdout, "")
        return process.stderr

    def test_stdin_json_byte_limit_applies_to_every_entrypoint(self):
        request = '{"action":"probe","padding":"' + 'é' * (MAX_JSON_BYTES // 2) + '"}'
        for command in (self.worker(), [str(ADAPTER_DIR / "colab_l4.py")],
                        [str(ADAPTER_DIR / "colab_train.py")]):
            with self.subTest(command=command):
                process = subprocess.run(
                    command, input=request.encode(), capture_output=True,
                    env={**os.environ, **self.env}, timeout=8,
                )
                result = self.parse(process.returncode, process.stdout.decode(), process.stderr.decode())
                self.assertEqual(result["error"], "request_size_limit")
        boundary = '{"action":"status"}'
        result = self.invoke(None, raw=boundary.ljust(MAX_JSON_BYTES))
        self.assertTrue(result["ok"])
        self.assertEqual(self.actions(), ["usage", "sessions"])

    def test_config_cap_shape_permissions_and_sanitized_errors(self):
        canary = "LEAK_CANARY_9a36"
        path = self.fixture / canary / "fleet-worker-colab.json"
        self.ctl("init", "--config", path)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.with_suffix(".json.lock").stat().st_mode), 0o600)
        for raw, error in (
            (b" " * (MAX_JSON_BYTES + 1), "JSON size limit exceeded"),
            (json.dumps({"profiles": [canary]}).encode(), "invalid or unavailable"),
            (('{"enroll_bearer":"' + canary).encode(), "invalid or unavailable"),
            (b"[]", "invalid or unavailable"),
        ):
            with self.subTest(error=error):
                path.write_bytes(raw)
                message = self.ctl_failure("list-lanes", "--config", path)
                self.assertIn(error, message)
                self.assertNotIn(canary, message)
        for args in (("list-lanes", "--config", path, "--" + canary),
                     ("add-lane", "--config", path, "--lane", canary, "--gpus", "L4",
                      "--max-seats", canary), (canary,)):
            self.assertNotIn(canary, self.ctl_failure(*args))
        path.write_text(json.dumps({
            "enroll_bearer": canary,
            "rpc_secret_hex": "<test-rpc>",
            "profiles": [{
                "capability": "custom." + canary,
                "adapter": {"kind": "exec", "command": self.worker(gpus="<test-rpc>")},
            }],
        }))
        listed = json.dumps(self.ctl("list-lanes", "--config", path))
        self.assertNotIn(canary, listed)
        self.assertNotIn("<test-rpc>", listed)

    def test_config_state_and_lock_symlinks_are_rejected(self):
        target = self.fixture / "outside"
        target.mkdir()
        original = target / "config.json"
        original.write_text('{"profiles":[]}')
        original.chmod(0o644)
        parent_link = self.fixture / "parent-link"
        parent_link.symlink_to(target, target_is_directory=True)
        config_link = self.fixture / "config-link.json"
        config_link.symlink_to(original)
        for path in (config_link, parent_link / original.name):
            with self.subTest(path=path):
                self.ctl_failure("list-lanes", "--config", path)
                self.ctl_failure("init", "--config", path)
        self.assertEqual(stat.S_IMODE(original.stat().st_mode), 0o644)
        self.ctl_failure("unpark", "--lane", "colab-l4", "--state-dir", parent_link / "state")
        self.assertFalse((target / "state").exists())
        self.assertEqual(self.invoke({"action": "probe"},
                                     DIFFUSER_COLAB_STATE_DIR=str(parent_link / "state"))["error"],
                         "state_unavailable")
        self.l4.mkdir(parents=True)
        for name in ("OWNER-GO.json", "quarantine.json", "active_intent.json", "seat.lock"):
            link = self.l4 / name
            link.symlink_to(original)
            try:
                with self.subTest(name=name):
                    if name == "OWNER-GO.json":
                        self.assertEqual(self.invoke({"action": "probe"})["error"], "lane_parked")
                        self.ctl_failure("unpark", "--lane", "colab-l4")
                    elif name == "quarantine.json":
                        self.assertEqual(self.invoke({"action": "probe"})["error"], "lane_quarantined")
                        self.ctl_failure("clear-quarantine", "--lane", "colab-l4")
                    elif name == "active_intent.json":
                        with self.assertRaises(OSError):
                            read_intent(link)
                    else:
                        self.assertEqual(self.invoke({"action": "probe"})["error"], "state_unavailable")
                    self.assertTrue(link.is_symlink())
            finally:
                link.unlink()
        self.assertEqual(original.read_text(), '{"profiles":[]}')
        self.assertEqual(self.calls(), [])

    def test_private_state_and_artifact_modes(self):
        root = self.l4 / "artifacts"
        root.mkdir(parents=True)
        for path in (self.state_root, self.l4, root):
            path.chmod(0o755)
        self.ctl("unpark", "--lane", "colab-l4")
        self.options(stop_fail=True)
        result = self.invoke({
            "action": "exec", "command": "printf data > output",
            "files_out": [{"remote": "output", "local": "nested/output"}],
        })
        self.assertEqual(result["error"], "cleanup_quarantined")
        for path in (self.state_root, self.l4, root, root / "nested", self.state_root / "_account"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700, path.name)
        for path in (root / "nested/output", self.l4 / "OWNER-GO.json", self.l4 / "quarantine.json",
                     self.l4 / "active_intent.json", self.l4 / "seat.lock", self.l4 / "seat-0.lock",
                     self.state_root / "_account/account.lock",
                     self.state_root / "_account/cli-sessions.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path.name)

    def test_artifact_paths_are_pinned_during_upload_and_publish(self):
        root = self.l4 / "artifacts"
        nested = root / "nested"
        nested.mkdir(parents=True)
        (nested / "input").write_bytes(b"safe upload")
        outside = self.fixture / "outside"
        outside.mkdir()
        (outside / "input").write_bytes(b"private")
        (outside / "output").write_bytes(b"untouched")
        saved = root / "saved"

        def swap_parent():
            if not saved.exists():
                nested.rename(saved)
                nested.symlink_to(outside, target_is_directory=True)

        request = {
            "files_in": [{"local": "nested/input", "remote": "input"}],
            "files_out": [{"local": "nested/output", "remote": "output"}],
        }
        artifacts = Artifacts(request, self.l4)
        with artifacts.stage() as scratch:
            artifacts.prepare(scratch, swap_parent)
            self.assertEqual((scratch / "in-0").read_bytes(), b"safe upload")
            self.assertEqual(stat.S_IMODE((scratch / "in-0").stat().st_mode), 0o600)
            nested.unlink()
            saved.rename(nested)
            incoming = scratch / "out-0"
            incoming.write_bytes(b"verified")
            metadata = {"bytes": 8, "sha256": hashlib.sha256(b"verified").hexdigest()}
            with self.assertRaisesRegex(ArtifactError, "^artifact_publish_failed$"):
                artifacts.publish(incoming, "nested/output", metadata, swap_parent)
            self.assertFalse((saved / "output").exists())
            self.assertEqual(list(saved.glob(".download-*")), [])
            self.assertEqual((outside / "output").read_bytes(), b"untouched")
            self.assertEqual((outside / "input").read_bytes(), b"private")
            nested.unlink()
            saved.rename(nested)
            destination = nested / "output"
            destination.write_bytes(b"previous")

            def swap_destination():
                if not destination.is_symlink():
                    destination.unlink()
                    destination.symlink_to(outside / "output")

            with self.assertRaisesRegex(ArtifactError, "^invalid_artifact_path$"):
                artifacts.publish(incoming, "nested/output", metadata, swap_destination)
            self.assertTrue(destination.is_symlink())
            self.assertEqual((outside / "output").read_bytes(), b"untouched")
            (nested / "input").unlink()
            (nested / "input").symlink_to(outside / "input")
            with self.assertRaisesRegex(ArtifactError, "^artifact_path_unavailable$"):
                Artifacts({"files_in": request["files_in"]}, self.l4).prepare(scratch, lambda: None)

    def test_upload_total_cap_and_atomic_state_validation(self):
        root = self.l4 / "artifacts"
        root.mkdir(parents=True)
        for name in ("first", "second"):
            (root / name).write_bytes(b"123")
        files = [{"local": name, "remote": name} for name in ("first", "second")]
        with patch("artifacts.MAX_TOTAL_BYTES", 5):
            self.assertEqual(self.invoke_artifact_prepare(files), "artifact_size_limit")
        target = self.l4 / "active_intent.json"
        target.write_text('{"existing":true}')
        with self.assertRaisesRegex(ValueError, "json_size_limit"):
            write_state(target, {"body": "a" * MAX_JSON_BYTES})
        self.assertEqual(read_intent(target), {"existing": True})
        self.assertEqual(list(self.l4.glob(".pending-*")), [])

    def invoke_artifact_prepare(self, files):
        artifacts = Artifacts({"files_in": files}, self.l4)
        with artifacts.stage() as scratch:
            with self.assertRaises(ArtifactError) as error:
                artifacts.prepare(scratch, lambda: None)
        return str(error.exception)

    def test_download_size_and_total_caps_run_before_transfer(self):
        files = [{"remote": name, "local": name} for name in ("first", "second")]
        command = "printf 123 > first; printf 456 > second"
        engine = Engine(colab_l4.CONFIG, self.bin, self.state_root)
        for file_limit, total_limit in ((2, 100), (4, 5)):
            with self.subTest(file_limit=file_limit, total_limit=total_limit):
                offset = len(self.actions())
                with patch.dict(os.environ, self.env), patch("engine.MAX_FILE_BYTES", file_limit), \
                        patch("engine.MAX_TOTAL_BYTES", total_limit):
                    result = engine.handle(
                        {"action": "exec", "command": command, "files_out": files}, lambda: False,
                    )
                self.assertEqual(result["error"], "guest_artifact_invalid")
                self.assertNotIn("download", self.actions()[offset:])
                self.assert_clean(result)

    def test_cli_capture_caps_stdout_and_stderr_without_leaking(self):
        canary_txt = "RAW_CANARY_VALUE"
        for fd in (1, 2):
            script = self.fixture / f"flood-{fd}"
            script.write_text(f"#!{sys.executable}\nimport os\nwhile True: os.write({fd}, {canary_txt.encode()!r} * 1024)\n")
            script.chmod(0o755)
            engine = Engine(colab_l4.CONFIG, script, self.state_root)
            with self.assertRaisesRegex(Refusal, "^cli_output_limit$"):
                engine.run_cli(["usage"], time.monotonic() + 4, lambda: False)
        self.options(cli_diagnostic=canary_txt)
        result = self.invoke({"action": "exec", "command": "printf safe"})
        self.assertEqual(result["stdout"], "safe")
        self.assertNotIn(canary_txt, json.dumps(result))
        result = self.invoke({"action": "exec", "command": f"printf {canary_txt}; echo {canary_txt} >&2; exit 1"})
        self.assertEqual(result["error"], "command_failed")
        self.assertNotIn(canary_txt, json.dumps(result))

    def test_timeout_drains_group_after_session_leader_exits(self):
        script = self.fixture / "group"
        pids = self.fixture / "pids"
        script.write_text(f"""#!{sys.executable}
import os
import signal
import time

pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open({str(pids)!r}, "w") as stream:
        stream.write(f"{{os.getpgrp()}} {{os.getpid()}}")
    time.sleep(30)
os._exit(0)
""")
        script.chmod(0o755)
        engine = Engine(colab_l4.CONFIG, script, self.state_root)
        with patch("engine.os.killpg", wraps=os.killpg) as killpg:
            with self.assertRaisesRegex(Refusal, "^timeout$"):
                engine.run_cli(["usage"], time.monotonic() + 0.8, lambda: False)
        pgid, pid = map(int, pids.read_text().split())
        signals = [args[1] for args, _ in killpg.call_args_list if args[0] == pgid and args[1]]
        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
        with self.assertRaises(ProcessLookupError):
            os.killpg(pgid, 0)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def seed_intent(self, lane, name, pid, generation="0123456789ab", store="account"):
        directory = self.state_root / lane
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        session = f"diffuser-{lane}-task-{generation}"
        intent = {"lane_id": lane, "job_id": "task", "generation": generation,
                  "session_name": session, "started_at": "2026-01-01T00:00:00+00:00"}
        if pid is not None:
            intent["owner_pid"] = pid
        if store is not None:
            intent["cli_store"] = store
        path.write_text(json.dumps(intent))
        cli_dir = self.state_root / "_account" if store == "account" else directory
        cli_dir.mkdir(exist_ok=True)
        for file, entry in ((cli_dir / "cli-sessions.json", {"name": session}),
                            (self.fixture / "live.json", "L4")):
            data = json.loads(file.read_text()) if file.exists() else {}
            data[session] = entry
            file.write_text(json.dumps(data))
        return path, session

    def dead_pid(self):
        with subprocess.Popen([sys.executable, "-c", "pass"]) as process:
            process.wait(timeout=5)
            return process.pid

    def test_reaper_skips_live_legacy_unknown_and_foreign(self):
        orphan_path, orphan = self.seed_intent("dead", "seat-1.intent.json", self.dead_pid())
        live_path, live = self.seed_intent("live", "active_intent.json", os.getpid())
        legacy_path, legacy = self.seed_intent("legacy", "active_intent.json", None, store=None)
        # The legacy fixture is also named in this account's provider view.
        account_config = self.state_root / "_account" / "cli-sessions.json"
        records = json.loads(account_config.read_text())
        account_config.write_text(json.dumps({**records, legacy: {"name": legacy}}))
        self.options(foreign={"foreign": "T4", "diffuser-dead-foreign-deadbeefcafe": "A100"},
                     update_banner=True)
        dry = self.ctl("reap", "--state-dir", self.state_root, "--dry-run")
        self.assertEqual({item["status"] for item in dry["intents"]},
                         {"orphan", "owner_alive", "owner_pid_missing"})
        self.assertEqual(self.calls(), [])
        self.assertTrue(orphan_path.exists())
        self.assertFalse((orphan_path.parent / "seat-1.lock").exists())
        result = self.ctl("reap", "--state-dir", self.state_root)
        self.assertEqual(result["cleaned"], 1)
        self.assertFalse(orphan_path.exists())
        self.assertTrue(live_path.exists())
        self.assertTrue(legacy_path.exists())
        self.assertEqual(self.calls(), [["stop", "-s", orphan], ["sessions"]])
        self.assertEqual(set(json.loads((self.fixture / "live.json").read_text())), {live, legacy})

    def test_reaper_respects_seat_lock_and_quarantines_failed_stop(self):
        path, name = self.seed_intent("dead", "seat-0.intent.json", self.dead_pid())
        with seat_lock(path.parent, 0):
            result = self.ctl("reap")
            self.assertEqual(result["intents"][0]["status"], "seat_busy")
            self.assertEqual(self.calls(), [])
        self.options(stop_survives=True)
        result = self.ctl("reap", expected=1)
        self.assertEqual(result["quarantined"], 1)
        self.assertEqual(self.calls(), [["stop", "-s", name], ["sessions"]])
        self.assertTrue(path.exists())
        marker = path.parent / "quarantine.json"
        self.assertIn("owned_session_live", json.loads(marker.read_text())["reasons"])
        self.assertEqual(self.worker_request({"action": "probe"}, "dead")["error"], "lane_quarantined")
        self.ctl("clear-quarantine", "--lane", "dead")
        self.assertFalse(marker.exists())
        self.assertTrue(path.exists())
        self.options()
        self.assertEqual(self.ctl("reap")["cleaned"], 1)
        self.assertFalse(path.exists())

    def test_reaper_rejects_intent_with_forged_session_name(self):
        path, _ = self.seed_intent("forged", "seat-0.intent.json", self.dead_pid())
        value = json.loads(path.read_text())
        path.write_text(json.dumps({**value, "session_name": "foreign"}))
        self.options(foreign={"foreign": "L4"})
        result = self.ctl("reap", expected=1)
        self.assertEqual(result["intents"][0]["status"], "intent_invalid")
        self.assertEqual(self.calls(), [])

    def test_orphan_retains_account_reservation_until_verified_cleanup(self):
        path, orphan = self.seed_intent("old", "seat-0.intent.json", self.dead_pid())
        flags = ("--max-account-vms", "1")
        self.assertEqual(self.worker_request({"action": "probe"}, "gpu", "T4", *flags)["error"],
                         "account_capacity_reached")
        self.assertEqual(self.calls(), [])
        self.options(post_stop="anonymous")
        self.assertEqual(self.ctl("reap", expected=1)["quarantined"], 1)
        self.assertEqual(self.calls(), [["stop", "-s", orphan], ["sessions"]])
        self.assertTrue(path.exists())
        self.assertEqual(self.worker_request({"action": "probe"}, "gpu", "T4", *flags)["error"],
                         "account_capacity_reached")
        self.options()
        self.assertEqual(self.ctl("reap")["cleaned"], 1)
        result = self.worker_request({"action": "probe"}, "gpu", "T4", *flags)
        self.assertTrue(result["ok"], result)
        self.assertFalse(path.exists())

    def test_idle_watchdog_aborts_silence_and_allows_progress(self):
        stalled = self.invoke({
            "action": "exec", "command": "sleep 30", "timeout_secs": 30, "idle_timeout_secs": 1,
        })
        self.assertEqual(stalled["error"], "idle_timeout")
        self.assert_clean(stalled)
        self.assertFalse((self.fixture / "live.json").exists() and json.loads(
            (self.fixture / "live.json").read_text()
        ))
        started = time.monotonic()
        active = self.invoke({
            "action": "exec",
            "command": "python3 -c 'import sys,time\n"
                       "for i in range(8):\n"
                       " print(i, flush=True)\n"
                       " sys.stderr.write(str(i)+\"\\n\")\n"
                       " sys.stderr.flush()\n"
                       " time.sleep(0.25)'",
            "timeout_secs": 30,
            "idle_timeout_secs": 1,
        })
        elapsed = time.monotonic() - started
        self.assertTrue(active["ok"], active)
        self.assertGreaterEqual(elapsed, 1.2)
        self.assert_clean(active)
        stderr_only = self.invoke({
            "action": "exec",
            "command": "python3 -c 'import sys,time\n"
                       "for i in range(8):\n"
                       " sys.stderr.write(str(i)+\"\\n\")\n"
                       " sys.stderr.flush()\n"
                       " time.sleep(0.25)'",
            "timeout_secs": 30,
            "idle_timeout_secs": 1,
        })
        self.assertTrue(stderr_only["ok"], stderr_only)
        self.assert_clean(stderr_only)
        offset = len(self.actions())
        invalid = self.invoke({"action": "exec", "command": "true", "idle_timeout_secs": "900"})
        self.assertEqual(invalid["error"], "invalid_idle_timeout_secs")
        self.assertEqual(self.actions()[offset:], [])
        status = self.invoke({"action": "status"})
        self.assertEqual(status["idle_timeout_secs"], 900)
        clamped = self.invoke({"action": "status"}, DIFFUSER_COLAB_IDLE_TIMEOUT_SECS="99999")
        self.assertEqual(clamped["idle_timeout_secs"], 5400)
        configured = self.worker_request({"action": "status"}, "gpu", "L4", "--idle-timeout", "30")
        self.assertEqual(configured["idle_timeout_secs"], 30)

    def test_transient_allocation_retries_once_then_fails_closed(self):
        from engine import interruptible_sleep

        delay = {"DIFFUSER_COLAB_ALLOC_RETRY_DELAY_SECS": "0.05"}
        self.options(transient_new_failures=1)
        offset = len(self.actions())
        result = self.invoke({"action": "exec", "command": "true", "timeout_secs": 60}, **delay)
        self.assertTrue(result["ok"], result)
        self.assert_clean(result)
        news = [call for call in self.calls()[offset:] if call[0] == "new"]
        self.assertEqual(len(news), 2)
        self.assertNotEqual(news[0][2], news[1][2])
        self.assertEqual(news[1][2], result["session_name"])
        marks = [float(line) for line in (self.fixture / "new_marks").read_text().splitlines()]
        self.assertGreaterEqual(marks[-1] - marks[-2], 0.05)
        self.assertFalse(json.loads((self.fixture / "live.json").read_text()))
        intent = json.loads((self.fixture / "intent_seen.json").read_text())
        self.assertEqual(intent["session_name"], result["session_name"])
        self.assertEqual(intent["created_at"], intent["started_at"])

        self.options(transient_new_failures=4)
        offset = len(self.actions())
        failed = self.invoke({"action": "exec", "command": "true", "timeout_secs": 60}, **delay)
        self.assertEqual(failed["error"], "allocation_failed")
        self.assert_clean(failed)
        failed_news = [call for call in self.calls()[offset:] if call[0] == "new"]
        self.assertEqual(len(failed_news), 2)
        self.assertEqual(json.loads((self.fixture / "live.json").read_text()), {})

        self.options(new_fail=True)
        offset = len(self.actions())
        owned = self.invoke({"action": "exec", "command": "true", "timeout_secs": 60}, **delay)
        self.assertEqual(owned["error"], "allocation_failed")
        self.assertEqual([call[0] for call in self.calls()[offset:]].count("new"), 1)
        self.assert_clean(owned)

        self.options(transient_new_failures=1)
        offset = len(self.actions())
        tight = self.invoke({"action": "exec", "command": "true", "timeout_secs": 5})
        self.assertEqual(tight["error"], "allocation_failed")
        self.assertEqual([call[0] for call in self.calls()[offset:]].count("new"), 1)
        self.assert_clean(tight)

        flag = {"stop": False}

        def cancel():
            return flag["stop"]

        def flip():
            time.sleep(0.05)
            flag["stop"] = True

        import threading
        threading.Thread(target=flip).start()
        started = time.monotonic()
        with self.assertRaisesRegex(Refusal, "^interrupted$"):
            interruptible_sleep(5, time.monotonic() + 10, cancel)
        self.assertLess(time.monotonic() - started, 1)

    def test_retry_refuses_when_balance_drops_below_floor_during_backoff(self):
        delay = {"DIFFUSER_COLAB_ALLOC_RETRY_DELAY_SECS": "0.05"}
        self.options(
            transient_new_failures=1,
            usage_balances=["250.00", "250.00", "199.00", "199.00"],
        )
        offset = len(self.actions())
        result = self.invoke({"action": "exec", "command": "true", "timeout_secs": 60}, **delay)
        self.assertEqual(result["error"], "cu_below_floor")
        self.assert_clean(result)
        actions = self.actions()[offset:]
        self.assertEqual(actions[:5], ["usage", "new", "sessions", "usage", "usage"])
        self.assertEqual(actions.count("new"), 1)
        new_at = float((self.fixture / "new_marks").read_text().splitlines()[0])
        usage_rows = (self.fixture / "usage_marks").read_text().splitlines()
        recheck_at, recheck_balance = usage_rows[2].split()
        self.assertEqual(recheck_balance, "199.00")
        self.assertGreaterEqual(float(recheck_at) - new_at, 0.05)
        self.assertEqual(result["cu_before"], 250.0)

    def test_retry_refuses_when_owned_session_appears_during_backoff(self):
        delay = {"DIFFUSER_COLAB_ALLOC_RETRY_DELAY_SECS": "0.05"}
        self.options(transient_new_failures=1, reveal_owned_session_on_call=2)
        offset = len(self.actions())
        result = self.invoke({"action": "exec", "command": "true", "timeout_secs": 60}, **delay)
        self.assertEqual(result["error"], "allocation_failed")
        self.assert_clean(result)
        actions = self.actions()[offset:]
        self.assertEqual(
            actions,
            ["usage", "new", "sessions", "usage", "usage", "sessions", "stop", "sessions", "usage"],
        )
        self.assertEqual(actions.count("new"), 1)
        new_at = float((self.fixture / "new_marks").read_text().splitlines()[0])
        usage_rows = (self.fixture / "usage_marks").read_text().splitlines()
        recheck_at = float(usage_rows[2].split()[0])
        self.assertGreaterEqual(recheck_at - new_at, 0.05)


if __name__ == "__main__":
    unittest.main()
