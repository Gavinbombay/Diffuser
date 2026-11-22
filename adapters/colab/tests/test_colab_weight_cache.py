"""Tests for the Imagination Studio Colab Drive weight cache helper."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "colab_weight_cache.sh"
FALLBACK = (
    "[cache] Drive unavailable or <45GB free; falling back to ephemeral "
    "local storage with HF_HUB_DISABLE_XET=1"
)
MODEL_DIRS = ("diffusion_models", "text_encoders", "vae", "loras")
KB_PER_GB = 1024 * 1024


def _gb_kb(gb):
    return gb * KB_PER_GB


class ColabWeightCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="colab-cache-"))
        self.addCleanup(self._rm_tmp)

    def _rm_tmp(self):
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _write_executable(self, path: Path, body: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def _mock_df(self, avail_kb: int) -> Path:
        """df -Pk mock. Filesystem name includes a space so column 4 is wrong."""
        bin_dir = self.tmp / "bin"
        # Capacity field anchors parsing. A naive $4 read sees "0", not avail.
        body = (
            "#!/bin/sh\n"
            'echo "Filesystem 1024-blocks Used Available Capacity Mounted on"\n'
            'echo "My Drive 1000000000 0 %d 1%% ${2:-.}"\n' % avail_kb
        )
        self._write_executable(bin_dir / "df", body)
        return bin_dir

    def _mock_sleep(self, log_path: Path) -> Path:
        bin_dir = self.tmp / "bin"
        body = (
            "#!/bin/sh\n"
            "printf '%s\\n' \"$1\" >> \"" + str(log_path) + "\"\n"
            "exit 0\n"
        )
        self._write_executable(bin_dir / "sleep", body)
        return bin_dir

    def _env(self, **overrides):
        env = os.environ.copy()
        env.pop("HF_HOME", None)
        env.pop("HF_HUB_DISABLE_XET", None)
        for key, value in overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = str(value)
        return env

    def _source(self, env):
        body = (
            'source "%s"\n'
            'printf "XET=%%s\\n" "${HF_HUB_DISABLE_XET-}"\n'
            'printf "HF_HOME=%%s\\n" "${HF_HOME-}"\n' % SCRIPT
        )
        return subprocess.run(
            ["bash", "-c", body],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def _parse_exports(self, stdout):
        found = {}
        for line in stdout.splitlines():
            if line.startswith("XET="):
                found["XET"] = line.split("=", 1)[1]
            elif line.startswith("HF_HOME="):
                found["HF_HOME"] = line.split("=", 1)[1]
        return found

    def test_drive_ready_creates_cache_symlinks_and_exports(self):
        drive = self.tmp / "drive"
        comfy = self.tmp / "studio" / "ComfyUI" / "models"
        cache = drive / "weight-cache"
        drive.mkdir()
        vae = comfy / "vae"
        diffusion = comfy / "diffusion_models"
        vae.mkdir(parents=True)
        diffusion.mkdir(parents=True)
        (diffusion / "fasth3.safetensors").write_bytes(b"checkpoint")
        (vae / "keep.bin").write_bytes(b"local-keep")
        (vae / "extra.bin").write_bytes(b"extra")
        # Cache already holds keep.bin. Local copy must be parked, not deleted.
        cached_vae = cache / "comfy-models" / "vae"
        cached_vae.mkdir(parents=True)
        (cached_vae / "keep.bin").write_bytes(b"cache-keep")

        bin_dir = self._mock_df(_gb_kb(45))
        env = self._env(
            PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            DIFFUSER_DRIVE_ROOT=drive,
            CACHE_ROOT=cache,
            COMFY_MODELS_DIR=comfy,
            MIN_FREE_GB=45,
        )
        first = self._source(env)
        self.assertEqual(
            first.returncode,
            0,
            msg=f"stdout={first.stdout!r} stderr={first.stderr!r}",
        )
        exports = self._parse_exports(first.stdout)
        self.assertEqual(exports.get("XET"), "1")
        self.assertEqual(exports.get("HF_HOME"), str(cache / "hf-cache"))
        self.assertNotIn(FALLBACK, first.stdout)
        self.assertTrue((cache / "comfy-models").is_dir())
        self.assertTrue((cache / "hf-cache").is_dir())

        for name in MODEL_DIRS:
            link = comfy / name
            target = cache / "comfy-models" / name
            self.assertTrue(target.is_dir(), name)
            self.assertTrue(link.is_symlink(), name)
            self.assertEqual(os.path.realpath(link), os.path.realpath(target))

        self.assertEqual(
            (cache / "comfy-models" / "diffusion_models" / "fasth3.safetensors").read_bytes(),
            b"checkpoint",
        )
        self.assertEqual((cached_vae / "keep.bin").read_bytes(), b"cache-keep")
        self.assertEqual((cached_vae / "extra.bin").read_bytes(), b"extra")
        self.assertEqual((cached_vae / "keep.bin.local").read_bytes(), b"local-keep")
        self.assertFalse((vae / "keep.bin").exists() and not (comfy / "vae").is_symlink())

        second = self._source(env)
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        self.assertEqual((cached_vae / "keep.bin").read_bytes(), b"cache-keep")
        self.assertEqual(
            (cache / "comfy-models" / "diffusion_models" / "fasth3.safetensors").read_bytes(),
            b"checkpoint",
        )
        self.assertFalse((cached_vae / "keep.bin.local.1").exists())

    def test_drive_absent_falls_back_without_error(self):
        drive = self.tmp / "missing-drive"
        comfy = self.tmp / "comfy-models"
        cache = self.tmp / "should-not-exist"
        marker_parent = comfy / "diffusion_models"
        marker_parent.mkdir(parents=True)
        marker = marker_parent / "stay.safetensors"
        marker.write_bytes(b"stay")

        # df would report plenty of room if the script skipped the mount check.
        bin_dir = self._mock_df(_gb_kb(200))
        env = self._env(
            PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            DIFFUSER_DRIVE_ROOT=drive,
            CACHE_ROOT=cache,
            COMFY_MODELS_DIR=comfy,
        )
        result = self._source(env)
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn(FALLBACK, result.stdout)
        exports = self._parse_exports(result.stdout)
        self.assertEqual(exports.get("XET"), "1")
        self.assertEqual(exports.get("HF_HOME"), "")
        self.assertFalse(cache.exists())
        self.assertFalse(drive.exists())
        self.assertFalse(marker_parent.is_symlink())
        self.assertEqual(marker.read_bytes(), b"stay")

    def test_drive_low_space_falls_back_without_error(self):
        drive = self.tmp / "drive"
        comfy = self.tmp / "comfy-models"
        cache = drive / "weight-cache"
        drive.mkdir()
        marker_parent = comfy / "loras"
        marker_parent.mkdir(parents=True)
        marker = marker_parent / "stay.safetensors"
        marker.write_bytes(b"stay")

        bin_dir = self._mock_df(_gb_kb(45) - 1)
        env = self._env(
            PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            DIFFUSER_DRIVE_ROOT=drive,
            CACHE_ROOT=cache,
            COMFY_MODELS_DIR=comfy,
            MIN_FREE_GB=45,
        )
        result = self._source(env)
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn(FALLBACK, result.stdout)
        exports = self._parse_exports(result.stdout)
        self.assertEqual(exports.get("XET"), "1")
        self.assertEqual(exports.get("HF_HOME"), "")
        self.assertFalse(cache.exists())
        self.assertFalse(marker_parent.is_symlink())
        self.assertEqual(marker.read_bytes(), b"stay")

    def test_run_setup_with_retry_succeeds_after_two_transient_failures(self):
        work = self.tmp / "work"
        work.mkdir()
        count_path = self.tmp / "attempts"
        args_path = self.tmp / "args"
        sleep_log = self.tmp / "sleeps"
        count_path.write_text("0")
        oneshot = work / "oneshot-setup-spark.sh"
        oneshot_body = """#!/bin/bash
printf '%s\\n' "$*" >> "{args}"
n=$(cat "{count}")
n=$((n + 1))
printf '%s\\n' "$n" > "{count}"
if [ "$n" -le 2 ]; then
  echo 'transient Hugging Face error: 503 Service Unavailable' >&2
  exit 1
fi
echo ready
exit 0
""".format(args=args_path, count=count_path)
        self._write_executable(oneshot, oneshot_body)
        bin_dir = self._mock_sleep(sleep_log)
        env = self._env(
            PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            DIFFUSER_DRIVE_ROOT=self.tmp / "no-drive",
            CACHE_ROOT=self.tmp / "unused-cache",
            COMFY_MODELS_DIR=self.tmp / "unused-comfy",
            CACHE_RETRY_ATTEMPTS=4,
            CACHE_RETRY_BACKOFF_SEC=60,
        )
        body = (
            'source "%s"\n'
            'cd "%s"\n'
            "run_setup_with_retry\n" % (SCRIPT, work)
        )
        result = subprocess.run(
            ["bash", "-c", body],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn("ready", result.stdout)
        self.assertEqual(count_path.read_text().strip(), "3")
        self.assertEqual(
            [line for line in args_path.read_text().splitlines() if line],
            ["--no-render", "--no-render", "--no-render"],
        )
        self.assertEqual(sleep_log.read_text().splitlines(), ["60", "60"])
        self.assertIn(FALLBACK, result.stdout)


if __name__ == "__main__":
    unittest.main()
