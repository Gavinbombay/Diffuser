#!/usr/bin/env python3
"""Unit tests for the Diffuser gamer idle-lane guard.

nvidia-smi, the process list, the clock, and the HTTP controller are fakes.
"""

from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import io
import json
import logging
import os
import stat
import tempfile
from urllib.parse import urlunsplit
import unittest
import urllib.request
from unittest.mock import patch

import gamer_idle_guard as guard

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = str(Path(__file__).resolve().parents[1] / "config.example.json")
TOKEN = "dummy-worker-auth-fixture"
SECRET = bytes(range(32)).hex()
SESSION = "fedcba9876543210" * 2


class Clock:
    def __init__(self) -> None:
        self.mono = 1000.0
        self.wall_s = 1_700_000_000.0

    def monotonic(self) -> float:
        return self.mono

    def wall(self) -> float:
        return self.wall_s

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall_s += seconds


class ProcList:
    def __init__(self) -> None:
        self.procs: list[guard.Proc] = []
        self.error: BaseException | None = None

    def __call__(self) -> list[guard.Proc]:
        if self.error is not None:
            raise self.error
        return list(self.procs)


class FakeNvidia:
    def __init__(self) -> None:
        self.gpu_csv = "0, 120, 8188\n"
        self.apps_csv = ""
        self.compute_csv = ""
        self.gpu_rc = 0
        self.apps_rc = 0
        self.calls: list[str] = []

    def run(self, argv, timeout):
        text = " ".join(argv)
        self.calls.append(text)
        if "--query-gpu=" in text:
            return guard.CommandResult(self.gpu_rc, self.gpu_csv, "")
        if "--query-compute-apps=" in text:
            return guard.CommandResult(0, self.compute_csv, "")
        if "--query-apps=" in text:
            return guard.CommandResult(self.apps_rc, self.apps_csv, "")
        return guard.CommandResult(1, "", "unexpected")


class RecordingSend:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.status = 200

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout,
            }
        )
        if self.status >= 400:
            raise guard.FleetHttpError(f"controller HTTP {self.status}")
        return self.status, b'{"ok":true}'


class FakeWorker:
    def __init__(self) -> None:
        self.running = True
        self.events: list[str] = []
        self.pid_value = 50

    def is_running(self) -> bool:
        return self.running

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.events.append("start")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        self.events.append("stop")

    def root_pids(self) -> set[int]:
        if self.running:
            return {self.pid_value}
        return set()


class FakePopen:
    def __init__(self, args, **kwargs) -> None:
        self.args = args
        self.kwargs = kwargs
        self.pid = 321
        self._rc = None

    def poll(self):
        return self._rc


def enroll_body() -> dict:
    return {
        "host": "a15",
        "rpc_url": "http://127.0.0.1:9",
        "rpc_secret_hex": SECRET,
        "rpc_session": SESSION,
        "cpu_millicores": 16000,
        "ram_bytes": 32 * 1024**3,
        "vram_bytes": 8 * 1024**3,
        "gpus": [],
        "capabilities": [],
    }


def make_config(**overrides):
    raw = {
        "worker_id": "a15-rtx4060",
        "controller_url": "https://diffuser.invalid",
        "token_env": "EXAMPLE_DIFFUSER_ADMIN_TOKEN",
        "reenroll": enroll_body(),
    }
    raw.update(overrides)
    return guard.config_from_mapping(raw)


class GuardTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.logs = io.StringIO()
        self.handler = logging.StreamHandler(self.logs)
        self.handler.setFormatter(logging.Formatter("%(message)s"))
        self.log = logging.getLogger("gamer_idle_guard")
        self.log.addHandler(self.handler)
        self.log.setLevel(logging.DEBUG)
        self._prop = self.log.propagate
        self.log.propagate = False

    def tearDown(self) -> None:
        self.log.removeHandler(self.handler)
        self.log.propagate = self._prop
        self.handler.close()

    def assert_secret_free(self) -> None:
        text = self.logs.getvalue()
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(SECRET, text)
        self.assertNotIn(SESSION, text)


class ConfigAndSecurityTests(GuardTestCase):
    def test_example_config_matches_laptop_defaults(self) -> None:
        config = guard.load_config(EXAMPLE)
        self.assertEqual(config.worker_id, "a15-rtx4060")
        self.assertTrue(config.controller_url.startswith("https://"))
        self.assertEqual(config.poll_interval_secs, 3)
        self.assertEqual(config.idle_cooldown_secs, 180)
        self.assertEqual(config.busy_util_pct, 25)
        self.assertEqual(config.busy_vram_mib, 1500)
        self.assertEqual(config.http_timeout_secs, 5)
        for term in (
            "steam",
            "cs2",
            "cyberpunk",
            "eldenring",
            "baldursgate",
            "valorant",
            "helldivers",
            "gamescope",
            "wine64-preloader",
        ):
            self.assertIn(term, config.process_watchlist)
        self.assertIn("dwm.exe", config.gpu_process_ignore)
        self.assertIn("xorg", config.gpu_process_ignore)
        self.assertIsNone(config.reenroll_json)
        self.assertIn("--fleet-worker", config.worker_command)
        self.assertTrue(any("uai-diffuser" in part for part in config.worker_command))
        self.assertIsNotNone(config.state_file)
        self.assertIsNotNone(config.token_file)

    def test_rejects_both_or_neither_enable_path(self) -> None:
        with self.assertRaises(guard.ConfigError):
            make_config(worker_command=["/usr/local/bin/uai-diffuser", "--fleet-worker", "a.json"],
                        worker_pid_file="/tmp/worker.pid")
        with self.assertRaises(guard.ConfigError):
            make_config(reenroll=None)

    def test_timeout_bounds(self) -> None:
        with self.assertRaises(guard.ConfigError):
            make_config(http_timeout_secs=0)
        with self.assertRaises(guard.ConfigError):
            make_config(http_timeout_secs=31)

    def test_https_enforcement_on_remote_urls(self) -> None:
        rejected = [
            "http://gpu.example.com",
            'http://controller.example.invalid:8080',
            "http://198.51.100.1.20",
            "http://[2001:db8::1]",
            "ftp://127.0.0.1",
            urlunsplit(('http', f"{'dummy-user'}:{'dummy-pass'}@127.0.0.1", '', '', '')),
            urlunsplit(('https', f"{'dummy-user'}:{'dummy-pass'}@diffuser.invalid", '', '', '')),
            "http://127.0.0.1.example.com",
            "http://127.0.0.2",
            "http://127.0.0.1:8080/v1/fleet",
        ]
        for url in rejected:
            with self.subTest(url=url):
                with self.assertRaises(guard.InsecureControllerUrl):
                    guard.validate_controller_url(url)

        allowed = [
            "https://gpu.example.com",
            "https://gpu.example.com:8443",
            "https://diffuser.invalid",
            "http://127.0.0.1:8080",
            "http://127.0.0.1",
            "http://localhost",
            "http://LOCALHOST:5820",
            "http://[::1]:8080",
        ]
        for url in allowed:
            with self.subTest(url=url):
                send = RecordingSend()
                config = make_config(controller_url=url)
                client = guard.HttpFleetClient(config, send=send, token_loader=lambda: TOKEN)
                client.drain()
                self.assertEqual(len(send.calls), 1)
                self.assertEqual(send.calls[0]["method"], "POST")
                self.assertTrue(send.calls[0]["url"].endswith("/v1/fleet/workers/a15-rtx4060/drain"))
                self.assertTrue(send.calls[0]["url"].startswith(guard.validate_controller_url(url)))
                self.assertEqual(send.calls[0]["headers"]["Authorization"], "Bearer " + TOKEN)
                self.assertEqual(send.calls[0]["body"], b"{}")
                self.assertGreaterEqual(send.calls[0]["timeout"], 1)
                self.assertLessEqual(send.calls[0]["timeout"], 30)
                self.assert_secret_free()

    def test_remote_http_does_not_build_a_client(self) -> None:
        send = RecordingSend()
        with self.assertRaises(guard.InsecureControllerUrl):
            make_config(controller_url='http://controller.example.invalid:8443')
        self.assertEqual(send.calls, [])

    def test_token_file_must_be_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fleet.token")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(TOKEN + "\n")
            os.chmod(path, 0o640)
            with self.assertRaises(guard.ConfigError) as caught:
                guard.read_token_file(path)
            self.assertNotIn(TOKEN, str(caught.exception))
            self.assertIn("0600", str(caught.exception))
            os.chmod(path, 0o600)
            self.assertEqual(guard.read_token_file(path), TOKEN)
            os.chmod(path, 0o644)
            with self.assertRaises(guard.ConfigError):
                guard.read_token_file(path)

    def test_windows_skips_posix_mode_bits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fleet.token")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(TOKEN + "\n")
            os.chmod(path, 0o644)
            with patch("gamer_idle_guard.os.name", "nt"):
                self.assertEqual(guard.read_token_file(path), TOKEN)

    def test_token_env_and_file_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fleet.token")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("file-token-value-0600\n")
            os.chmod(path, 0o600)
            config = make_config(token_file=path, token_env="EXAMPLE_DIFFUSER_ADMIN_TOKEN")
            with patch.dict(os.environ, {"EXAMPLE_DIFFUSER_ADMIN_TOKEN": "dummy-env-auth-fixture"}, clear=False):
                self.assertEqual(guard.read_configured_token(config), "file-token-value-0600")
                env_only = make_config(token_file=None, token_env="EXAMPLE_DIFFUSER_ADMIN_TOKEN")
                self.assertEqual(guard.read_configured_token(env_only), "dummy-env-auth-fixture")

    def test_opener_disables_proxies_and_redirects(self) -> None:
        env = {
            "http_proxy": "http://proxy.example:8080",
            "https_proxy": "http://proxy.example:8080",
            "HTTP_PROXY": "http://proxy.example:8080",
            "HTTPS_PROXY": "http://proxy.example:8080",
        }
        with patch.dict(os.environ, env, clear=False):
            opener = guard.build_fleet_opener()
            default = urllib.request.build_opener()
        ours = [item for item in opener.handlers if isinstance(item, urllib.request.ProxyHandler)]
        stock = [item for item in default.handlers if isinstance(item, urllib.request.ProxyHandler)]
        redirects = [
            item for item in opener.handlers if isinstance(item, urllib.request.HTTPRedirectHandler)
        ]
        self.assertEqual(ours, [])
        self.assertEqual(len(stock), 1)
        self.assertIn("proxy.example", str(stock[0].proxies))
        self.assertEqual(len(redirects), 1)
        self.assertIsInstance(redirects[0], guard.RejectRedirects)
        with self.assertRaises(guard.FleetHttpError) as caught:
            redirects[0].redirect_request(None, None, 302, "Found", {}, "https://evil.example/steal")
        self.assertNotIn("evil.example", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_cli_check_hides_token_and_once_polls_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            auth_path = os.path.join(tmp, "fleet.token")
            config_path = os.path.join(tmp, "gamer.json")
            with open(auth_path, "w", encoding="utf-8") as handle:
                handle.write(TOKEN + "\n")
            os.chmod(auth_path, 0o600)
            raw = {
                "worker_id": "a15-rtx4060",
                "controller_url": "https://diffuser.invalid",
                "token_file": auth_path,
                "reenroll": enroll_body(),
            }
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(raw, handle)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                code = guard.main(["--config", config_path, "--check"])
            self.assertEqual(code, 0)
            self.assertIn("config ok", stdout.getvalue())
            self.assertNotIn(TOKEN, stdout.getvalue())
            self.assertNotIn(TOKEN, stderr.getvalue())
            self.assertNotIn(SECRET, stdout.getvalue() + stderr.getvalue())

            ticks: list[bool] = []

            class Stub:
                def run(self, once: bool = False, sleep=None) -> str:
                    ticks.append(once)
                    return guard.ACTIVE_FOR_FLEET

            with patch("gamer_idle_guard.build_guard", return_value=Stub()):
                code = guard.main(["--config", config_path, "--once"])
            self.assertEqual(code, 0)
            self.assertEqual(ticks, [True])

            loose = os.path.join(tmp, "loose.token")
            with open(loose, "w", encoding="utf-8") as handle:
                handle.write(TOKEN + "\n")
            os.chmod(loose, 0o644)
            raw["token_file"] = loose
            loose_cfg = os.path.join(tmp, "loose.json")
            with open(loose_cfg, "w", encoding="utf-8") as handle:
                json.dump(raw, handle)
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                code = guard.main(["--config", loose_cfg, "--check"])
            self.assertEqual(code, 2)
            self.assertNotIn(TOKEN, stderr.getvalue())
            self.assertIn("0600", stderr.getvalue())


class ActivityTests(GuardTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.clock = Clock()
        self.procs = ProcList()
        self.nvidia = FakeNvidia()
        self.http = RecordingSend()
        self.config = make_config()
        self.probe = guard.NvidiaProbe(self.config, runner=self.nvidia, process_source=self.procs)
        self.client = guard.HttpFleetClient(self.config, send=self.http, token_loader=lambda: TOKEN)
        self.worker = None
        self.guard = guard.Guard(
            self.config,
            self.probe,
            self.client,
            worker=None,
            clock=self.clock.monotonic,
            wall_clock=self.clock.wall,
        )

    def _use_worker_mode(self, worker: FakeWorker | None = None) -> FakeWorker:
        worker = worker or FakeWorker()
        config = make_config(
            reenroll=None,
            worker_command=[
                "/usr/local/bin/uai-diffuser",
                "--fleet-worker",
                "/home/operator/.config/diffuser/a15-worker.json",
            ],
            worker_pid_file="/home/operator/.local/state/diffuser/a15-fleet-worker.pid",
        )
        self.config = config
        self.probe = guard.NvidiaProbe(config, runner=self.nvidia, process_source=self.procs)
        self.client = guard.HttpFleetClient(config, send=self.http, token_loader=lambda: TOKEN)
        self.worker = worker
        self.guard = guard.Guard(
            config,
            self.probe,
            self.client,
            worker=worker,
            clock=self.clock.monotonic,
            wall_clock=self.clock.wall,
        )
        return worker

    def set_idle(self) -> None:
        self.procs.procs = [guard.Proc(1, 0, ("systemd",))]
        self.nvidia.gpu_rc = 0
        self.nvidia.apps_rc = 0
        self.nvidia.gpu_csv = "0, 120, 8188\n"
        self.nvidia.apps_csv = ""

    def set_game(self, name: str = "cs2.exe") -> None:
        self.procs.procs = [guard.Proc(42, 1, (name, f"/games/{name}"))]
        self.nvidia.gpu_csv = "0, 120, 8188\n"
        self.nvidia.apps_csv = ""

    def drain_calls(self) -> list[dict]:
        return [call for call in self.http.calls if call["url"].endswith("/drain")]

    def enroll_calls(self) -> list[dict]:
        return [call for call in self.http.calls if call["url"].endswith("/enroll")]

    def test_instant_drain_on_game_launch(self) -> None:
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(self.http.calls, [])
        for name in ("cs2", "CS2.exe", "Cyberpunk2077.exe", "wine64-preloader", "gamescope"):
            with self.subTest(name=name):
                self.http.calls.clear()
                self.guard.state = guard.ACTIVE_FOR_FLEET
                self.set_game(name)
                self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
                self.assertEqual(len(self.drain_calls()), 1)
                self.assertEqual(self.enroll_calls(), [])
                self.assertEqual(self.drain_calls()[0]["method"], "POST")
                self.assertEqual(
                    self.drain_calls()[0]["url"],
                    "https://diffuser.invalid/v1/fleet/workers/a15-rtx4060/drain",
                )
                self.assertEqual(self.drain_calls()[0]["headers"]["Authorization"], "Bearer " + TOKEN)
                self.assert_secret_free()

    def test_instant_drain_on_gpu_util_spike(self) -> None:
        self.set_idle()
        self.nvidia.gpu_csv = "24, 120, 8188\n"
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(self.drain_calls(), [])
        self.nvidia.gpu_csv = "25, 120, 8188\n"
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertEqual(len(self.drain_calls()), 1)
        self.assertEqual(self.enroll_calls(), [])

    def test_instant_drain_on_gpu_vram_spike(self) -> None:
        self.set_idle()
        self.nvidia.gpu_csv = "1, 1499, 8188\n"
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.nvidia.gpu_csv = "1, 1500, 8188\n"
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertEqual(len(self.drain_calls()), 1)
        self.assertEqual(self.enroll_calls(), [])

    def test_foreign_gpu_process_drains_at_low_util(self) -> None:
        self.set_idle()
        self.nvidia.gpu_csv = "3, 80, 8188\n"
        self.nvidia.apps_csv = "77, Helldivers2.exe, 80\n"
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertEqual(len(self.drain_calls()), 1)
        self.assert_secret_free()

    def test_diffuser_job_does_not_count_as_gamer_load(self) -> None:
        self.procs.procs = [
            guard.Proc(50, 1, ("uai-diffuser", "/usr/local/bin/uai-diffuser --fleet-worker a15.json")),
            guard.Proc(60, 50, ("python", "python train.py --note cyberpunk")),
        ]
        self.nvidia.gpu_csv = "99, 7000, 8188\n"
        self.nvidia.apps_csv = "60, python, 7000\n"
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(self.http.calls, [])
        # A game beside the fleet job still drains on the same poll.
        self.procs.procs.append(guard.Proc(70, 1, ("cs2.exe",)))
        self.nvidia.apps_csv = "60, python, 7000\n70, cs2.exe, 500\n"
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertEqual(len(self.drain_calls()), 1)

    def test_desktop_compositor_alone_stays_with_the_fleet(self) -> None:
        self.set_idle()
        self.nvidia.gpu_csv = "2, 300, 8188\n"
        self.nvidia.apps_csv = "8, dwm.exe, 180\n12, explorer.exe, 90\n"
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(self.http.calls, [])
        self.nvidia.gpu_csv = "2, 2000, 8188\n"
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)

    def test_hysteresis_cooldown_prevents_flapping(self) -> None:
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.set_game("cs2.exe")
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.clock.advance(179)
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.assertEqual(self.enroll_calls(), [])
        # A blip during the wait returns to gamer and the 180s starts over.
        self.set_game("eldenring.exe")
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertEqual(self.enroll_calls(), [])
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.clock.advance(179)
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.assertEqual(self.enroll_calls(), [])
        self.clock.advance(1)
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(len(self.enroll_calls()), 1)
        body = json.loads(self.enroll_calls()[0]["body"].decode("utf-8"))
        self.assertEqual(body["worker_id"], "a15-rtx4060")
        self.assertEqual(self.enroll_calls()[0]["url"], "https://diffuser.invalid/v1/fleet/workers/enroll")
        self.assert_secret_free()

    def test_reenable_after_clean_cooldown(self) -> None:
        self.set_game("valorant.exe")
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.clock.advance(180)
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(len(self.enroll_calls()), 1)
        self.assertGreaterEqual(len(self.drain_calls()), 1)
        # The completing poll enrolls and does not drain in the same breath.
        self.assertTrue(self.http.calls[-1]["url"].endswith("/enroll"))
        self.assertEqual(self.http.calls[-1]["headers"]["Authorization"], "Bearer " + TOKEN)
        self.assert_secret_free()

    def test_http_error_retries_without_logging_token(self) -> None:
        self.set_game("baldursgate3.exe")
        self.http.status = 503
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertIn("controller HTTP 503", self.logs.getvalue())
        self.assert_secret_free()
        self.http.status = 200
        self.set_idle()
        self.guard.tick()
        self.clock.advance(180)
        self.http.status = 503
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.http.status = 200
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertGreaterEqual(len(self.enroll_calls()), 1)
        self.assertTrue(self.http.calls[-1]["url"].endswith("/enroll"))
        self.assert_secret_free()

    def test_worker_restarts_only_after_clean_cooldown(self) -> None:
        worker = self._use_worker_mode()
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(worker.events, [])
        self.set_game("helldivers2.exe")
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertEqual(worker.events, ["stop"])
        self.assertEqual(self.enroll_calls(), [])
        self.assertGreaterEqual(len(self.drain_calls()), 1)
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.clock.advance(179)
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.assertEqual(worker.events, ["stop"])
        self.set_game("steam")
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.clock.advance(180)
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(worker.events, ["stop", "start"])
        self.assertEqual(self.enroll_calls(), [])

    def test_boot_starts_a_stopped_worker_when_idle(self) -> None:
        worker = FakeWorker()
        worker.running = False
        self._use_worker_mode(worker)
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.ACTIVE_FOR_FLEET)
        self.assertEqual(worker.events, ["start"])
        self.assertEqual(self.drain_calls(), [])

    def test_process_list_failure_fails_quiet(self) -> None:
        self.set_idle()
        self.procs.error = OSError("unread")
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)
        self.assertEqual(len(self.drain_calls()), 1)
        self.procs.error = None
        self.set_idle()
        self.assertEqual(self.guard.tick(), guard.COOLDOWN)
        self.assertEqual(self.enroll_calls(), [])

    def test_restart_during_cooldown_does_not_enable_early(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "state.json")
            config = make_config(state_file=state)
            probe = guard.NvidiaProbe(config, runner=self.nvidia, process_source=self.procs)
            client = guard.HttpFleetClient(config, send=self.http, token_loader=lambda: TOKEN)
            first = guard.Guard(
                config,
                probe,
                client,
                clock=self.clock.monotonic,
                wall_clock=self.clock.wall,
            )
            self.set_game("cs2.exe")
            self.assertEqual(first.tick(), guard.GAMER_ACTIVE)
            self.set_idle()
            self.assertEqual(first.tick(), guard.COOLDOWN)
            self.clock.advance(30)
            mode = stat.S_IMODE(os.stat(state).st_mode)
            if os.name != "nt":
                self.assertEqual(mode & 0o077, 0)
            later_http = RecordingSend()
            later = guard.Guard(
                config,
                probe,
                guard.HttpFleetClient(config, send=later_http, token_loader=lambda: TOKEN),
                clock=self.clock.monotonic,
                wall_clock=self.clock.wall,
            )
            self.assertEqual(later.state, guard.COOLDOWN)
            self.assertEqual(later.tick(), guard.COOLDOWN)
            self.assertEqual(
                [call for call in later_http.calls if call["url"].endswith("/enroll")],
                [],
            )
            self.clock.advance(150)
            self.assertEqual(later.tick(), guard.ACTIVE_FOR_FLEET)
            enrolls = [call for call in later_http.calls if call["url"].endswith("/enroll")]
            self.assertEqual(len(enrolls), 1)

    def test_nvidia_smi_parser_and_compute_fallback(self) -> None:
        util, memory = guard.parse_gpu_csv("10, 200, 8188\n80, 400, 2048\n[N/A], 5, 8188\n")
        self.assertEqual(util, 80)
        self.assertEqual(memory, 400)
        apps = guard.parse_app_csv("4242, /usr/bin/gamescope, 1700\n")
        self.assertEqual(apps[0].pid, 4242)
        self.assertIn("gamescope", apps[0].name)
        self.set_idle()
        self.nvidia.apps_rc = 1
        self.nvidia.compute_csv = "9, python, 10\n"
        self.nvidia.gpu_csv = "1, 10, 8188\n"
        sample = self.probe.sample()
        self.assertIsNotNone(sample.gpu)
        assert sample.gpu is not None
        self.assertEqual(sample.gpu.apps[0].name, "python")
        self.assertTrue(any("--query-apps=" in call for call in self.nvidia.calls))
        self.assertTrue(any("--query-compute-apps=" in call for call in self.nvidia.calls))
        self.nvidia.calls.clear()
        self.probe.sample()
        self.assertFalse(any("--query-apps=" in call for call in self.nvidia.calls))
        self.assertTrue(any("--query-compute-apps=" in call for call in self.nvidia.calls))

    def test_multi_gpu_uses_the_busiest_card(self) -> None:
        self.set_idle()
        self.nvidia.gpu_csv = "4, 100, 8188\n40, 200, 8188\n"
        self.assertEqual(self.guard.tick(), guard.GAMER_ACTIVE)


class ProcessAndWorkerTests(GuardTestCase):
    def test_windows_process_table_and_tasklist(self) -> None:
        table = "4242\t100\tcs2.exe\tC:\\Games\\cs2.exe -novid\n200\t4242\thelper.exe\t\n"
        procs = guard.parse_windows_process_table(table)
        self.assertEqual(procs[0].pid, 4242)
        self.assertEqual(procs[0].ppid, 100)
        self.assertIn("cs2.exe", procs[0].names[0])
        self.assertIn("cs2.exe", procs[0].names[1])
        listed = '"cs2.exe","4242","Console","1","100,000 K"\n'
        parsed = guard.parse_tasklist_csv(listed)
        self.assertEqual(parsed[0].pid, 4242)
        self.assertEqual(parsed[0].names, ("cs2.exe",))

    def test_stop_leaves_an_unrelated_pid_alone(self) -> None:
        signals: list[tuple[int, bool]] = []
        with tempfile.TemporaryDirectory() as tmp:
            pid_file = os.path.join(tmp, "worker.pid")
            with open(pid_file, "w", encoding="utf-8") as handle:
                handle.write("99\n")
            config = make_config(
                reenroll=None,
                worker_command=[
                    "/usr/local/bin/uai-diffuser",
                    "--fleet-worker",
                    "/home/operator/.config/diffuser/a15-worker.json",
                ],
                worker_pid_file=pid_file,
                stop_timeout_secs=1,
            )
            worker = guard.SubprocessWorker(
                config,
                alive=lambda _pid: True,
                cmdline_of=lambda _pid: "python unrelated.py",
                signal_pid=lambda pid, gentle: signals.append((pid, gentle)),
                sleep=lambda _seconds: None,
            )
            worker.stop()
            self.assertEqual(signals, [])
            self.assertTrue(os.path.exists(pid_file))

    def test_stop_signals_a_matching_worker_and_start_is_idempotent(self) -> None:
        signals: list[tuple[int, bool]] = []
        alive = {"up": True}
        created: list[FakePopen] = []

        def popen(args, **kwargs):
            proc = FakePopen(args, **kwargs)
            created.append(proc)
            return proc

        def mark(pid, gentle):
            signals.append((pid, gentle))
            if gentle:
                alive["up"] = False

        with tempfile.TemporaryDirectory() as tmp:
            pid_file = os.path.join(tmp, "worker.pid")
            with open(pid_file, "w", encoding="utf-8") as handle:
                handle.write("77\n")
            config = make_config(
                reenroll=None,
                worker_command=[
                    "/usr/local/bin/uai-diffuser",
                    "--fleet-worker",
                    "/home/operator/.config/diffuser/a15-worker.json",
                ],
                worker_pid_file=pid_file,
                stop_timeout_secs=1,
            )
            worker = guard.SubprocessWorker(
                config,
                popen=popen,
                alive=lambda _pid: alive["up"],
                cmdline_of=lambda _pid: (
                    "/usr/local/bin/uai-diffuser --fleet-worker "
                    "/home/operator/.config/diffuser/a15-worker.json"
                ),
                signal_pid=mark,
                sleep=lambda _seconds: None,
            )
            worker.stop()
            self.assertEqual(signals, [(77, True)])
            self.assertFalse(os.path.exists(pid_file))
            alive["up"] = False
            worker.start()
            worker.start()
            self.assertEqual(len(created), 1)
            self.assertNotIn("shell", created[0].kwargs)
            self.assertTrue(created[0].kwargs.get("start_new_session"))
            self.assertEqual(created[0].args[1], "--fleet-worker")
            with open(pid_file, encoding="utf-8") as handle:
                written = handle.read().strip()
            self.assertEqual(written, "321")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(pid_file).st_mode) & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
