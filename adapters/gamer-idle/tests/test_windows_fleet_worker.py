"""Unit tests for windows_fleet_worker.py security and NVENC validation."""

from __future__ import annotations

import json
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import windows_fleet_worker as wfw


class WorkerSecurityTests(unittest.TestCase):
    def test_controller_url_enforces_https_off_loopback(self):
        self.assertEqual(wfw.validate_controller_url("http://127.0.0.1:5820/"), "http://127.0.0.1:5820")
        self.assertEqual(wfw.validate_controller_url("https://fleet.example/"), "https://fleet.example")
        with self.assertRaises(ValueError):
            wfw.validate_controller_url("http://fleet.example:5820")
        with self.assertRaises(ValueError):
            wfw.validate_controller_url("https://user:pass@fleet.example")

    def test_bind_host_loopback_only(self):
        self.assertEqual(wfw.validate_bind_host("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(ValueError):
            wfw.validate_bind_host("0.0.0.0")

    def test_replay_cache_freshness_replay_and_capacity_fail_closed(self):
        cache = wfw.BoundedReplayCache(max_entries=2, window_ms=60_000)
        now = 1_000_000
        j1 = "fjob_" + "a" * 32
        j2 = "fjob_" + "b" * 32
        j3 = "fjob_" + "c" * 32
        self.assertIsNone(cache.consume(j1, now, now))
        self.assertEqual(cache.consume(j1, now, now), "rpc_replayed")
        self.assertEqual(cache.consume(j2, now - 70_000, now), "rpc_timestamp_invalid")
        self.assertEqual(cache.consume(j2, now + 40_000, now), "rpc_timestamp_invalid")
        self.assertIsNone(cache.consume(j2, now, now))
        self.assertEqual(cache.consume(j3, now, now), "rpc_replay_cache_full")
        self.assertEqual(cache.consume("bad-id", now, now), "rpc_identity_invalid")

    def test_nvenc_param_validation_rejects_injection(self):
        ok, err = wfw.validate_nvenc_params({"codec": "av1_nvenc", "width": 1920, "height": 1080, "fps": 60, "duration_secs": 5, "preset": "p4"})
        self.assertIsNone(err)
        self.assertEqual(ok["codec"], "av1_nvenc")
        for bad in [
            {"codec": "av1_nvenc; calc.exe"},
            {"preset": "p9"},
            {"width": 99999},
            {"duration_secs": 120},
            {"fps": 240},
        ]:
            _, err = wfw.validate_nvenc_params(bad)
            self.assertIsNotNone(err)

    def test_signed_http_rpc_accepts_fresh_and_rejects_tampered_or_replayed(self):
        secret = "0123456789abcdef" * 4
        session = "f" * 32
        cfg = {"rpc_secret_hex": secret, "host": "test-a15"}
        replay = wfw.BoundedReplayCache()
        handler_cls = wfw.build_handler(cfg, session, replay, "nvidia-smi", "ffmpeg")
        srv = wfw.http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            body = json.dumps({
                "job_id": "fjob_" + "1" * 32,
                "rpc_session": session,
                "issued_at_ms": int(time.time() * 1000),
                "capability": "tool.cpu.sha256/v1",
                "input": {"text": "hello"},
            }).encode("utf-8")
            sig = wfw.sign_rpc_v2(secret, body)
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/fleet-worker/run",
                data=body,
                headers={"Content-Type": "application/json", "x-diffuser-signature": sig},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(data["ok"])
            self.assertEqual(len(data["output"]["sha256"]), 64)

            # Replay must return 409
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 409)

            # Bad signature must return 401
            bad_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/fleet-worker/run",
                data=body,
                headers={"Content-Type": "application/json", "x-diffuser-signature": "0" * 64},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx2:
                urllib.request.urlopen(bad_req, timeout=5)
            self.assertEqual(ctx2.exception.code, 401)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_nvenc_bench_mocked_success(self):
        class DummyProc:
            returncode = 0
            stdout = ""
            stderr = ""
        with patch("windows_fleet_worker.subprocess.run", return_value=DummyProc()):
            res = wfw.run_nvenc_bench("ffmpeg", {"codec": "av1_nvenc", "duration_secs": 4, "fps": 60})
        self.assertTrue(res["ok"])
        self.assertEqual(res["output"]["codec"], "av1_nvenc")
        self.assertEqual(res["output"]["frames_encoded"], 240)


    def test_bounded_server_caps_concurrency_and_times_out_idle_clients(self):
        import socket
        secret = "0123456789abcdef" * 4
        cfg = {"rpc_secret_hex": secret, "host": "test-a15"}
        handler_cls = wfw.build_handler(cfg, "f" * 32, wfw.BoundedReplayCache(), "nvidia-smi", "ffmpeg")
        srv = wfw.BoundedHTTPServer(("127.0.0.1", 0), handler_cls, max_concurrent=1, request_timeout=0.2)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            s1 = socket.create_connection(("127.0.0.1", port), timeout=2)
            time.sleep(0.05)
            # Second concurrent idle connection must be closed immediately without acquiring a slot
            s2 = socket.create_connection(("127.0.0.1", port), timeout=2)
            s2.settimeout(1.0)
            self.assertEqual(s2.recv(16), b"")
            s2.close()
            # First idle connection must be closed once request_timeout (0.2s) elapses
            s1.settimeout(1.5)
            self.assertEqual(s1.recv(16), b"")
            s1.close()
            # Slot must be released cleanly so a new connection can proceed
            time.sleep(0.05)
            self.assertTrue(srv._slots.acquire(blocking=False))
            srv._slots.release()
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
