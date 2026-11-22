# Security Audit Summary (Diffuser)

## Verdict: CLEAN PASS

- **Audit Framework**: Cloudflare Security Audit Skill (`cloudflare/security-audit-skill`, 6-phase standard profile, vendored Node validators)
- **Independent Auditor**: Codex Luna (`gpt-6-luna`, `reasoning effort: high`)
- **Remediation**: Codex Sol (`gpt-6.2-sol`, `reasoning effort: high`), independently re-audited by Codex Luna
- **Final Counts**: `0` confirmed vulnerabilities, `0` open `needs_validation` leads
- **Validator Status**: `validate-findings.cjs` exit `0` (`PASS`), `validate-coverage-ledger.cjs` exit `0` (`PASS`)

## Coverage

- **100% active source coverage**: 87 Rust files (`src/`), 2 native C++ files (`native/`), and 9 Google Colab fleet adapter Python files (`adapters/colab/`), with `0` deferred active units.
- **Offline verification in isolated `bwrap` sandbox**: 93 focused Rust security regression tests passed + 39/39 Colab adapter tests passed (`0` failed).

## Closed Hardening Leads

All six leads identified during the full high-effort pass were remediated and independently verified closed:

1. **Fleet worker RPC replay freshness**: Signed worker RPC requests now bind a per-start session ID, timestamp freshness window, and single-use random job ID; workers consume IDs before execution and reject stale or replayed requests.
2. **Fleet worker RPC cleartext transport**: Enrollment and dispatch require HTTPS for remote worker URLs, allowing plain HTTP only on explicit loopback addresses (`127.0.0.1`, `::1`, `localhost`).
3. **Memory bridge cleartext bearer transport**: Remote bridge URLs require HTTPS with loopback-only HTTP exception, proxy discovery disabled, and redirects disabled. (The memory bridge binary has since been removed from this repository.)
4. **Loopback ready-queue disclosure**: `GET` and `HEAD` inspection routes require the `0600` Unix admin control socket with peer UID verification; TCP listener has admin routes disabled.
5. **Colab snapshot state trust**: Snapshot reads enforce a service-owned `0700` directory and `0600` regular single-link file alongside schema, freshness, and probe checks.
6. **Watchdog backlog permissions**: Backlog, standing entries, and job specs are read through a service-owned private spool rejecting unsafe ownership, modes, symlinks, and path traversal.

## Colab Adapter Security Controls (`adapters/colab/`)

- Descriptor-relative `O_NOFOLLOW | O_CLOEXEC` file and directory I/O with symlink-swap race protection.
- Unconditional subprocess block on `colab pay`, hard minimum compute-unit floor (`>= 200 CU`), per-job CU and walltime ceilings, and account-wide VM concurrency coordination.
- Durable PID-stamped intent written before VM allocation, automatic VM shutdown on every exit/error/timeout/signal, owned-only session cleanup, and fail-closed lane quarantine on ambiguous cleanup.
- Strict 256 KiB JSON and CLI output caps, bounded artifact transfers with SHA-256 verification before VM shutdown, and `TERM` + `KILL` + `ESRCH` process-group reaping.

## Async Fleet Router Delta Audit (2026-11-21)

- **Scope**: `src/cosp/fleet.rs` and `src/bin/lanes-ctl.rs` (async job execution `"async": true`, `GET /v1/fleet/jobs/{job_id}`, MCP `fleet_get_job`, 6-hour profile timeout ceiling).
- **Auditor**: Codex Luna (`gpt-6-luna`, `reasoning effort: high`).
- **Closed findings**: Zero-resource async capacity bypass (enforced 100 millicores + 64 MiB minima and atomic 16-job per-actor/project in-flight cap), synchronous disconnect capacity leak (unified cancellation-independent background dispatch with oneshot reply), and synchronous `lanes-ctl` omitted-timeout client wait alignment (`21660 s`).
- **Result**: `0` open confirmed findings, `0` open `needs_validation`, `9/9` fleet tests passing in isolated `bwrap` sandbox, both Node validators exit `0`.

## Production Hardening v2 Delta Audit (2026-11-21)

- **Scope**: `src/cosp/fleet.rs` (live `nvidia-smi` free-VRAM + `gpu_util_pct` heartbeat telemetry, per-GPU `gpus_live` freshness, external-load steering) and `adapters/colab/` (idle progress watchdog `idle_timeout_secs`, transient `allocation_failed` single retry with post-backoff re-admission).
- **Auditor**: Codex Luna (`gpt-6-luna`, `reasoning effort: high`), 4-iteration delta verification.
- **Closed findings**: Post-backoff Colab retry state race (`recheck_retry_admission` verifies CU balance/floor, active sessions, and VM cap after backoff), aggregate-only exact-pin admission (`PinnedLiveFree::NoReport` fails closed for exact pins with positive VRAM minimums), and stale per-GPU telemetry reuse on omitted heartbeats (`handle_heartbeat` clears `gpus_live_json` when omitted).
- **Result**: `CLEAN_PASS` (`0` open confirmed findings, `0` open `needs_validation`, `12/12` fleet tests + `43/43` Colab adapter tests passing, both Node validators exit `0`).

## Adapters v3 Delta Audit (2026-11-22)

- **Scope**: `adapters/colab/colab_weight_cache.sh`, `adapters/colab/tests/test_colab_weight_cache.py`, `adapters/gamer-idle/gamer_idle_guard.py`, `adapters/gamer-idle/config.example.json`, `adapters/gamer-idle/README.md`, and `adapters/gamer-idle/tests/test_gamer_idle_guard.py`.
- **Auditor**: Codex Luna (`gpt-6-luna`, `reasoning effort: high`).
- **Result**: `CLEAN_PASS` (`0` open confirmed findings, `0` open `needs_validation`, `32/32` unit tests passing in isolated `bwrap` sandbox, both Node validators exit `0`).
