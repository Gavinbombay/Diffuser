---
name: diffuser-caller
description: Guide an AI agent to discover live Diffuser fleet capabilities, submit idempotent CPU/GPU jobs with exact GPU pinning, and verify durable output digests.
---

# Diffuser Fleet Caller Skill

## Core Rules

1. **Discover First**: Call `GET /v1/fleet/discover` (or MCP `fleet_discover`) with your scoped Bearer token. Never hardcode hostnames or assume a GPU is available.
2. **Always Pass `Idempotency-Key`**: Every `POST /v1/fleet/jobs` (or MCP `fleet_submit_job`) requires a stable `Idempotency-Key`. Retries return the original job without duplicating compute.
3. **Pin Exact GPUs When Required**: Pass `pin_gpu_uuid` (`GPU-...`) when targeting a specific card. Diffuser returns `422 capability_unavailable` rather than silently substituting another device.
4. **Verify Durable Readback**: Check `output_sha256` on the response or via `GET /v1/fleet/jobs/{job_id}` (`fleet_get_job`).
