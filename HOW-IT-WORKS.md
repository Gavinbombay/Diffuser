# Diffuser — Plain-English Guide (HOW-IT-WORKS)

## Overview and Purpose

Diffuser (`uai-diffuser` / `lanes-ctl`) is a strict, auditable resource router for CPU and NVIDIA CUDA compute. When tools, scripts, or AI agents need compute, Diffuser solves three operational risks:

1. **Wrong hardware**: Callers request an exact lane or exact GPU UUID (`GPU-...`). Diffuser refuses unavailable selections (`422 capability_unavailable`) instead of silently substituting another device.
2. **Duplicate work on retries**: Callers submit with a stable `Idempotency-Key`. Retries return the original job instead of running duplicate compute, and result artifacts remain durably readable after worker exit.
3. **Unsafe reuse after crashes**: Releasing an assignment moves it to `draining` until the independent custody witness verifies quiescent worker state and commits a signed cleanup certificate (`draining -> closed`).

## Step-by-Step Flow

1. **Discover**: An authenticated caller runs `lanes-ctl diffuser operator ... discover` against `:5820`. Unconfigured controllers fail closed (`503 routing_closed`).
2. **Upload**: The caller uploads an input payload and receives a content-addressed `artifact_id`.
3. **Acquire**: The caller reserves an exact CPU lane (`lane_cpu_inspect`) or exact CUDA GPU UUID (`GPU-...`). Unavailable devices are refused (`422 capability_unavailable`) rather than substituted.
4. **Submit**: The caller submits with a stable `Idempotency-Key`. Retries return the original job instead of running duplicate compute.
5. **Readback**: The caller reads and verifies the output artifact digest, which remains durable even after worker exit.
6. **Release & Witnessed Cleanup**: Releasing transitions the assignment to `draining`. The controller witness fetches signed `/protected/cleanup-evidence` from the quiescent worker and commits `apply_witnessed_cleanup` (`draining -> closed`), freeing capacity for the next job.

## Runtime Location

- **Controller service**: `uai-diffuser.service` on your controller host (`localhost:5820`, admin socket `/var/lib/uai-diffuser/control.sock`, state `/var/lib/uai-diffuser`, protected config `/etc/diffuser/controller.json`, fleet config `/etc/diffuser/fleet.json`).
- **CPU & GPU fleet workers**: Any number of local or remote `uai-diffuser --fleet-worker <config.json>` daemons (loopback or SSH-tunneled), plus optional protected single-worker daemons (`--worker-config`).
- **Native CUDA helpers**: Deterministic zero-toolkit `libcuda.so.1` helper (`native/cuda/add_one.cpp`) compiled on any Linux NVIDIA host and connected locally or over encrypted SSH loopback tunnels (`ssh -L` / `-R`).
- **Binaries & Source**: `/usr/local/bin/uai-diffuser`, `/usr/local/bin/lanes-ctl`, active repo `/srv/diffuser`, public repo `Gavinbombay/Diffuser`.

## Health and Logs

- **HTTP health checks**: `curl -sS http://127.0.0.1:5820/health` and `curl -sS http://127.0.0.1:5820/v1/health` return JSON service and lane status.
- **Authenticated discovery**: `lanes-ctl diffuser operator 127.0.0.1:5820 <TENANT> <PROJECT> <ACTOR> bearer-stdin discover` (passing the scoped bearer on stdin).
- **Systemd status & logs**:
  - `systemctl status uai-diffuser.service diffuser-cpu-worker.service`
  - `journalctl -u uai-diffuser.service -u diffuser-cpu-worker.service -n 100 --no-pager`

## Failure Modes

- **Unconfigured protected startup (`503 routing_closed`, CLI exit `74`)**: Ordinary startup without `--protected-config` intentionally fails closed on `/v1/diffuser/*`. Provide a valid `0600` protected config and restart.
- **Stale authority observation (`412 evidence_stale`)**: Authority freshness is strictly bounded (`<= 1500 ms`). Check that the worker is reachable on `worker_addr` so `/protected/source-observation` succeeds.
- **Uncertain teardown / stuck `draining`**: If a worker crashes or fails cleanup before committing `/protected/cleanup-evidence`, Diffuser intentionally keeps the assignment held (`draining`) rather than reusing dirty capacity. Inspect worker logs, verify no stray child processes remain, and restart the worker cleanly.
- **Wrong GPU UUID or missing driver (`422 capability_unavailable`)**: Verify `nvidia-smi -L` matches the configured `device_uuid` and the helper ELF SHA-256 matches `helper_sha256`.
