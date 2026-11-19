---
name: diffuser-onboard
description: Guide an AI agent to onboard any new host, CPU/GPU accelerator, or pluggable tool/service (exec or http) into a live Diffuser fleet controller in one flow.
---

# Diffuser Worker & Capability Onboarding Skill

Use this skill when adding a new machine, GPU, or tool (Blender, Whisper, Ollama, ComfyUI, native CUDA helper, etc.) to Diffuser.

## Steps

1. **Inspect Target Hardware**
   - Run `nvidia-smi --query-gpu=uuid,name,memory.total --format=csv,noheader,nounits` (if NVIDIA GPU present) and note CPU/RAM.
2. **Author `fleet-worker.json` (mode `0600`)**
   - Set unique `worker_id`, `host`, loopback `bind` (e.g. `127.0.0.1:5835`), `advertise_url`, `controller_url` (`http://127.0.0.1:5820`), `enroll_bearer`, and a fresh 64-hex `rpc_secret_hex`.
   - Declare one or more `profiles` using either:
     - `adapter.kind = "exec"`: `command`, `timeout_secs`, optional `gpu_uuid` (automatically injects `CUDA_VISIBLE_DEVICES`, `DIFFUSER_JOB_ID`, `DIFFUSER_CAPABILITY`, reads JSON on stdin, returns JSON on stdout).
     - `adapter.kind = "http"`: `url`, `method`, `timeout_secs` (forwards JSON payload to a local HTTP service like Ollama/ComfyUI/embeddings).
3. **Establish Encrypted Tunnel (for remote LAN/laptop hosts)**
   - Run `ssh -N -L 127.0.0.1:<worker_port>:127.0.0.1:<worker_port> -R 127.0.0.1:5820:127.0.0.1:5820 <host>` so both worker enrollment/heartbeats and controller->worker RPC travel over SSH loopback.
4. **Launch Worker & Verify Enrollment**
   - Start `uai-diffuser --fleet-worker /path/to/fleet-worker.json`.
   - Call `GET /v1/fleet/workers` (or MCP `fleet_list_workers`) and confirm `"alive": true, "accepting": true` with the expected GPU UUIDs and capabilities.
5. **Run a Smoke Job**
   - Submit one idempotent smoke job via `POST /v1/fleet/jobs` (or MCP `fleet_submit_job`) and confirm `state == "succeeded"` and `capacity_released == true`.
