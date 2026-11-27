import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "adapter", Path(__file__).resolve().parents[1] / "run-140t-llm.py")
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class ValidationTests(unittest.TestCase):
    def test_default_prompt(self):
        action, profile, body, timeout = adapter.validate({"prompt": "hello"}, adapter.INFER)
        self.assertEqual((action, profile, timeout), ("infer", "30b", 240))
        self.assertEqual(body, {"messages": [{"role": "user", "content": "hello"}],
                                "max_tokens": 256, "stream": False})

    def test_4b_messages_tools_and_format(self):
        req = {"profile": "4b", "messages": [{"role": "user", "content": "hello"}],
               "temperature": 0.2, "max_tokens": 100, "seed": 4, "top_p": 0.8,
               "tools": [{"type": "function", "function": {"name": "lookup"}}],
               "tool_choice": "auto", "response_format": {"type": "json_object"}, "stop": ["end"]}
        _, profile, body, _ = adapter.validate(req)
        self.assertEqual(profile, "4b")
        self.assertEqual(body, {k: v for k, v in req.items() if k != "profile"} | {"stream": False})

    def test_control_routing(self):
        for action in ("status", "park"):
            self.assertEqual(adapter.validate({"action": action}, adapter.CONTROL)[:3], (action, None, None))
            with self.assertRaises(adapter.AdapterError):
                adapter.validate({"action": action}, adapter.INFER)
        with self.assertRaises(adapter.AdapterError):
            adapter.validate({"prompt": "hi"}, adapter.CONTROL)

    def test_invalid_requests(self):
        for req in (None, [], {}, {"action": "wake"}, {"action": "park", "profile": "4b"},
                    {"prompt": []}, {"prompt": "x", "messages": []}, {"prompt": "x", "stream": True},
                    {"prompt": "x", "profile": []}, {"prompt": "x", "profile": "other"},
                    {"prompt": "x", "max_tokens": True}, {"prompt": "x", "max_tokens": 4097},
                    {"prompt": "x", "temperature": float("nan")}, {"prompt": "x", "top_p": 2},
                    {"prompt": "x", "seed": -1}, {"prompt": "x", "stop": [1]},
                    {"prompt": "x", "tools": {}}, {"prompt": "x", "tool_choice": 1},
                    {"prompt": "x", "response_format": []}, {"prompt": "x", "timeout_secs": 0},
                    {"messages": [{"role": "user", "content": [{"type": "image_url"}]}]},
                    {"messages": [{"role": "invalid", "content": "x"}]},
                    {"messages": [{"role": "user", "content": "x", "extra": 1}]}):
            with self.subTest(req=req), self.assertRaises(adapter.AdapterError):
                adapter.validate(req)

    def test_bad_json(self):
        for raw in (b"{", b"\xff", b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(adapter.AdapterError):
                adapter.decode(raw)


class QualifiedConfigTests(unittest.TestCase):
    def test_exact_command_for_both_profiles(self):
        for profile, model in (("30b", "gguf-30b/Qwen3-30B-A3B-Instruct-2507-Q4_K_M.gguf"),
                               ("4b", "gguf-4b/Qwen3-4B-Instruct-2507-Q4_K_M.gguf")):
            self.assertEqual(adapter.command(profile), [
                "/usr/bin/taskset", "-c", "6-13", "/opt/diffuser-140t/bin/llama-server",
                "-m", "/opt/diffuser-140t/models/" + model, "--host", "127.0.0.1", "--port", "18081",
                "-ngl", "99", "--jinja", "--slots", "--no-context-shift", "-c", "16384", "-np", "1",
                "-t", "3", "-tb", "3", "-fa", "off", "-ctk", "f16", "-ctv", "f16",
                "-b", "2048", "-ub", "512", "--cache-reuse", "256"])

    def test_env_is_qualified_and_isolated(self):
        with patch.dict(os.environ, {"GGML_VK_FORCE_XE_FA": "1", "HTTP_PROXY": "unused",
                                    "DIFFUSER_RPC_SECRET": "placeholder"}, clear=True):
            env = adapter.engine_env()
        self.assertEqual(env["VK_DRIVER_FILES"], "/usr/share/vulkan/icd.d/intel_icd.json")
        self.assertEqual(env["MESA_SHADER_CACHE_DIR"], "/var/cache/diffuser-140t/mesa")
        self.assertEqual(set(env), {"PATH", "VK_DRIVER_FILES", "MESA_SHADER_CACHE_DIR"})

    def test_ownership_requires_matching_listening_socket(self):
        with tempfile.TemporaryDirectory() as tmp:
            process = Path(tmp) / "123"
            (process / "net").mkdir(parents=True)
            (process / "fd").mkdir()
            (process / "net/tcp").write_text(
                "header\n"
                f"0: 0100007F:{adapter.PORT:04X} 00000000:0000 0A 0:0 0:0 0 0 0 987\n"
            )
            (process / "fd/3").symlink_to("socket:[123]")
            self.assertFalse(adapter.owns_listener(123, Path(tmp)))
            (process / "fd/4").symlink_to("socket:[987]")
            self.assertTrue(adapter.owns_listener(123, Path(tmp)))
            self.assertFalse(adapter.owns_listener(456, Path(tmp)))

    @patch.object(adapter.subprocess, "Popen")
    @patch.object(adapter, "port_available", return_value=False)
    @patch.object(adapter.os.path, "isfile", return_value=True)
    @patch.object(adapter.os, "access", return_value=True)
    def test_external_port_is_never_adopted(self, _, __, ___, popen):
        with self.assertRaisesRegex(adapter.AdapterError, "already owned"):
            adapter.launch_engine("30b")
        popen.assert_not_called()

    @patch.object(adapter.subprocess, "Popen")
    @patch.object(adapter, "port_available", return_value=True)
    @patch.object(adapter.os.path, "isfile", return_value=True)
    @patch.object(adapter.os, "access", return_value=True)
    def test_launch_only_owned_engine(self, _, __, ___, popen):
        adapter.launch_engine("4b")
        args, kwargs = popen.call_args
        self.assertEqual(args[0][-3:], ["--engine", str(os.getpid()), "4b"])
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertTrue(kwargs["close_fds"])


class ThermalTests(unittest.TestCase):
    def test_reads_package_max_not_gpu_or_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            zone = root / "thermal_zone0"
            zone.mkdir()
            (zone / "type").write_text("x86_pkg_temp\n")
            (zone / "temp").write_text("85000\n")
            device = root / "hwmon0"
            device.mkdir()
            (device / "name").write_text("coretemp")
            (device / "temp1_label").write_text("Package id 0")
            (device / "temp1_input").write_text("91000")
            (device / "temp2_label").write_text("Core 0")
            (device / "temp2_input").write_text("100000")
            self.assertEqual(adapter.package_temp(root, root), 91)
            (device / "temp1_input").write_text("bad")
            self.assertEqual(adapter.package_temp(root, root), 85)
            (zone / "temp").unlink()
            self.assertIsNone(adapter.package_temp(root, root))

    def test_threshold_and_missing_sensor(self):
        for value, code in ((90, "thermal_limit"), (105, "thermal_limit"), (None, "thermal_unavailable")):
            with patch.object(adapter, "package_temp", return_value=value), self.assertRaises(adapter.AdapterError) as cm:
                adapter.check_thermal()
            self.assertEqual(cm.exception.code, code)
        with patch.object(adapter, "package_temp", return_value=89.999):
            self.assertEqual(adapter.check_thermal(), 89.999)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.manager = adapter.Supervisor()
        self.client, self.peer = socket.socketpair()
        self.addCleanup(self.client.close)
        self.addCleanup(self.peer.close)
        self.deadline = time.monotonic() + 10
        self.proc = Mock()
        self.proc.poll.return_value = None
        self.temp = self.enterContext(patch.object(adapter, "package_temp", return_value=50))
        self.launch = self.enterContext(patch.object(adapter, "launch_engine", return_value=self.proc))
        self.owns = self.enterContext(patch.object(adapter, "owns_listener", return_value=True))
        self.http = self.enterContext(patch.object(adapter, "http_json", side_effect=self.response))

    def response(self, path, *args, **kwargs):
        return {"status": "ok"} if path == "/health" else {"choices": [{"message": {"content": "hello"}}]}

    def infer(self, **kwargs):
        return self.manager.handle({"prompt": "hello", **kwargs}, self.deadline, self.client)

    def test_auto_wake_reuse_and_explicit_park(self):
        self.assertEqual(self.manager.status()["state"], "parked")
        self.assertTrue(self.infer()["ok"])
        self.assertEqual(self.manager.status()["state"], "ready")
        self.assertTrue(self.infer()["ok"])
        self.launch.assert_called_once_with("30b")
        self.assertEqual(self.http.call_count, 3)
        result = self.manager.handle({"action": "park"}, self.deadline, self.client)
        self.assertEqual(result["state"], "parked")
        self.proc.terminate.assert_called_once()
        self.proc.wait.assert_called_once_with(timeout=adapter.STOP_SECS)

    def test_switch_profile_stops_owned_process(self):
        self.infer()
        second = Mock()
        second.poll.return_value = None
        self.launch.return_value = second
        self.assertEqual(self.infer(profile="4b")["profile"], "4b")
        self.proc.terminate.assert_called_once()
        second.terminate.assert_not_called()
        self.assertEqual(self.manager.profile, "4b")

    def test_idle_park(self):
        self.infer()
        self.manager.idle_tick()
        self.proc.terminate.assert_not_called()
        self.manager.last_used -= adapter.IDLE_SECS
        self.manager.idle_tick()
        self.proc.terminate.assert_called_once()
        self.assertEqual(self.manager.status()["state"], "parked")

    def test_preflight_hot_or_missing_never_launches(self):
        for value in (90, None):
            self.temp.return_value = value
            with self.assertRaises(adapter.AdapterError):
                self.infer()
        self.launch.assert_not_called()
        self.http.assert_not_called()

    def test_heat_during_startup_aborts(self):
        self.temp.side_effect = [50, 50, 90]
        with self.assertRaises(adapter.AdapterError) as cm:
            self.infer()
        self.assertEqual(cm.exception.code, "thermal_limit")
        self.proc.terminate.assert_called_once()
        self.http.assert_not_called()

    def test_heat_during_completion_aborts_even_if_http_returns(self):
        self.infer()
        def hot_response(*args, **kwargs):
            self.temp.return_value = 90
            return {"choices": [{}]}
        self.http.side_effect = hot_response
        with self.assertRaises(adapter.AdapterError) as cm:
            self.infer()
        self.assertEqual(cm.exception.code, "thermal_limit")
        self.proc.terminate.assert_called_once()

    def test_thermal_trip_while_http_is_blocked(self):
        self.infer()
        entered = threading.Event()
        release = threading.Event()
        def blocked_response(*args, **kwargs):
            entered.set()
            self.temp.return_value = 90
            release.wait(2)
            return {"choices": [{}]}
        self.http.side_effect = blocked_response
        try:
            with patch.object(adapter, "POLL", 0.005), self.assertRaises(adapter.AdapterError) as cm:
                self.infer()
            self.assertTrue(entered.is_set())
            self.assertEqual(cm.exception.code, "thermal_limit")
            self.assertTrue(self.manager.stopping)
            self.proc.terminate.assert_called_once()
        finally:
            release.set()

    def test_hot_idle_parks(self):
        self.infer()
        self.temp.return_value = 90
        self.manager.idle_tick()
        self.proc.terminate.assert_called_once()
        self.assertFalse(self.manager.status()["thermal_ok"])

    def test_lost_listener_prevents_request_to_unowned_endpoint(self):
        self.infer()
        self.owns.return_value = False
        calls = self.http.call_count
        with self.assertRaises(adapter.AdapterError) as cm:
            self.infer()
        self.assertEqual(cm.exception.code, "engine_listener")
        self.assertEqual(self.http.call_count, calls)
        self.proc.terminate.assert_called_once()

    def test_http_failure_parks(self):
        self.infer()
        self.http.side_effect = OSError("private diagnostics")
        with self.assertRaises(OSError):
            self.infer()
        self.proc.terminate.assert_called_once()

    def test_timeout_and_disconnected_client_do_not_launch(self):
        self.deadline = time.monotonic() - 1
        with self.assertRaises(adapter.AdapterError) as cm:
            self.infer()
        self.assertEqual(cm.exception.code, "timeout")
        self.deadline = time.monotonic() + 10
        self.peer.close()
        with self.assertRaises(adapter.AdapterError) as cm:
            self.infer()
        self.assertEqual(cm.exception.code, "cancelled")
        self.launch.assert_not_called()

    def test_cancel_warm_engine(self):
        self.infer()
        self.peer.close()
        with self.assertRaises(adapter.AdapterError) as cm:
            self.infer()
        self.assertEqual(cm.exception.code, "cancelled")
        self.proc.terminate.assert_called_once()

    def test_engine_exit(self):
        self.proc.poll.return_value = 1
        with self.assertRaises(adapter.AdapterError) as cm:
            self.infer()
        self.assertEqual(cm.exception.code, "engine_exited")
        self.proc.terminate.assert_not_called()

    def test_stop_escalates_only_own_process(self):
        self.manager.proc = self.proc
        self.proc.wait.side_effect = [subprocess.TimeoutExpired("llama", 3), 0]
        self.manager.stop()
        self.proc.terminate.assert_called_once()
        self.proc.kill.assert_called_once()
        self.assertIsNone(self.manager.proc)


class HttpAndExecTests(unittest.TestCase):
    @patch.object(adapter.http.client, "HTTPConnection")
    def test_http_loopback_json_and_close(self, connection):
        conn = connection.return_value
        response = conn.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"choices": [{}]}'
        self.assertEqual(adapter.http_json("/v1/chat/completions", {"stream": False}), {"choices": [{}]})
        connection.assert_called_once_with("127.0.0.1", 18081, timeout=2)
        self.assertEqual(conn.request.call_args.args[:2], ("POST", "/v1/chat/completions"))
        conn.close.assert_called_once()

    @patch.object(adapter.http.client, "HTTPConnection")
    def test_http_error_omits_diagnostics(self, connection):
        response = connection.return_value.getresponse.return_value
        response.status = 503
        with self.assertRaises(adapter.AdapterError) as cm:
            adapter.http_json("/health")
        self.assertEqual(cm.exception.code, "engine_http")
        response.read.assert_not_called()
        connection.return_value.close.assert_called_once()

    @patch.object(adapter.http.client, "HTTPConnection")
    def test_oversized_engine_response(self, connection):
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.read.return_value = b"x" * (adapter.MAX_RESPONSE + 1)
        with self.assertRaises(adapter.AdapterError) as cm:
            adapter.http_json("/health")
        self.assertEqual(cm.exception.code, "response_too_large")

    def test_status_and_park_do_not_spawn(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(adapter, "STATE_DIR", Path(tmp)), \
                patch.object(adapter.subprocess, "Popen") as popen, patch.object(adapter, "package_temp", return_value=50):
            for action in ("status", "park"):
                self.assertEqual(adapter.execute({"action": action}, adapter.CONTROL)["state"], "parked")
            popen.assert_not_called()

    def test_hot_cold_wake_does_not_spawn_supervisor(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(adapter, "STATE_DIR", Path(tmp)), \
                patch.object(adapter.subprocess, "Popen") as popen, patch.object(adapter, "package_temp", return_value=90):
            with self.assertRaises(adapter.AdapterError) as cm:
                adapter.execute({"prompt": "hello"})
            self.assertEqual(cm.exception.code, "thermal_limit")
            popen.assert_not_called()

    def test_supervisor_ipc_wake_reuse_idle_exit_and_restart(self):
        threads = []
        children = []
        errors = []
        def supervisor_thread(args, **kwargs):
            fd = os.dup(kwargs["pass_fds"][0])
            def run():
                try:
                    adapter.serve(fd)
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            threads.append(thread)
            return Mock()
        def engine(profile):
            child = Mock()
            child.poll.return_value = None
            children.append(child)
            return child
        def response(path, *args, **kwargs):
            return {"status": "ok"} if path == "/health" else {"choices": [{}]}
        with tempfile.TemporaryDirectory() as tmp, patch.object(adapter, "STATE_DIR", Path(tmp)), \
                patch.object(adapter.signal, "signal"), patch.object(adapter, "package_temp", return_value=50), \
                patch.object(adapter, "launch_engine", side_effect=engine), \
                patch.object(adapter, "owns_listener", return_value=True), \
                patch.object(adapter, "http_json", side_effect=response), \
                patch.object(adapter.subprocess, "Popen", side_effect=supervisor_thread), \
                patch.object(adapter, "IDLE_SECS", 0.15), patch.object(adapter, "POLL", 0.01):
            try:
                self.assertTrue(adapter.execute({"prompt": "hi"})["ok"])
                self.assertEqual(adapter.execute({"action": "status"})["state"], "ready")
                self.assertTrue(adapter.execute({"prompt": "again"})["ok"])
                self.assertEqual(len(children), 1)
                threads[0].join(2)
                self.assertFalse(threads[0].is_alive())
                children[0].terminate.assert_called_once()
                self.assertEqual(adapter.execute({"action": "status"})["state"], "parked")
                self.assertTrue(adapter.execute({"profile": "4b", "prompt": "hi"})["ok"])
                self.assertEqual(len(children), 2)
                self.assertEqual(adapter.execute({"action": "park"})["state"], "parked")
                children[1].terminate.assert_called_once()
            finally:
                for thread in threads:
                    thread.join(2)
            self.assertEqual(errors, [])
            self.assertTrue(all(not thread.is_alive() for thread in threads))

    def test_lock_serializes_clients(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(adapter, "STATE_DIR", Path(tmp)):
            _, lock = adapter.state_paths()
            fd = adapter.lock_file(lock)
            try:
                adapter.fcntl.flock(fd, adapter.fcntl.LOCK_EX | adapter.fcntl.LOCK_NB)
                with self.assertRaises(adapter.AdapterError) as cm:
                    adapter.execute({"prompt": "hello"})
                self.assertEqual(cm.exception.code, "busy")
            finally:
                os.close(fd)

    def test_insecure_state_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(adapter, "STATE_DIR", Path(tmp)):
            os.chmod(tmp, 0o755)
            with self.assertRaises(adapter.AdapterError) as cm:
                adapter.state_paths()
            self.assertEqual(cm.exception.code, "state_permissions")

    def test_deadline_reserves_cleanup(self):
        with self.assertRaises(adapter.AdapterError) as cm:
            adapter.execute({"prompt": "hello"}, outer_timeout=8)
        self.assertEqual(cm.exception.code, "timeout")
        with tempfile.TemporaryDirectory() as tmp, patch.object(adapter, "STATE_DIR", Path(tmp)), \
                patch.object(adapter, "connect_supervisor") as connect, patch.object(adapter, "receive_line", return_value={"ok": True}):
            client = connect.return_value
            before = time.monotonic()
            self.assertTrue(adapter.execute({"prompt": "hello"}, outer_timeout=30)["ok"])
            envelope = json.loads(client.sendall.call_args.args[0])
            self.assertAlmostEqual(envelope["deadline"], before + 22, delta=1)

    def test_protocol_line_limit(self):
        first, second = socket.socketpair()
        with first, second:
            second.sendall(b'{"ok":true}\n')
            self.assertEqual(adapter.receive_line(first, 32), {"ok": True})
            second.sendall(b"x" * 11)
            with self.assertRaises(adapter.AdapterError):
                adapter.receive_line(first, 10)

    def test_receipt_cannot_overfill_worker_pipe(self):
        stdout = Mock()
        stdout.buffer = io.BytesIO()
        with patch.object(adapter.sys, "stdout", stdout), patch.object(adapter.fcntl, "fcntl", return_value=4096):
            adapter.output_receipt({"ok": True, "response": "x" * 5000})
        self.assertEqual(json.loads(stdout.buffer.getvalue())["error_code"], "response_too_large")

    def test_main_invalid_json_single_receipt(self):
        stdin = Mock()
        stdin.buffer = io.BytesIO(b"not json")
        with patch.object(adapter.sys, "stdin", stdin), patch.object(adapter, "output_receipt") as output:
            adapter.main()
        self.assertEqual(output.call_args.args[0]["error_code"], "invalid_json")


if __name__ == "__main__":
    unittest.main()
