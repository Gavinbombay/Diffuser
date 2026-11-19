# How Diffuser Works (Plain-English Guide)

## What problem Diffuser solves

When AI agents, scripts, or local services need compute — whether a quick CPU check or a real NVIDIA GPU job — sending work directly to a machine creates three risks:

1. **Wrong hardware**: A job meant for a specific GPU silently lands on the wrong card or falls back to CPU.
2. **Duplicate work on retries**: A dropped connection causes a client to retry and accidentally run the same expensive job twice.
3. **Unsafe reuse after a crash**: A GPU job fails mid-cleanup, and the router hands that dirty GPU to the next caller before cleanup is actually confirmed.

Diffuser solves all three by acting as a strict, auditable traffic controller between callers and workers.

## The lifecycle of a job

1. **Discover**: An authenticated caller asks Diffuser what lanes and capabilities exist. If protected routing has not been explicitly configured, Diffuser refuses cleanly (`503 routing_closed`).
2. **Upload**: The caller uploads its input payload. Diffuser stores it durably and returns a content-addressed artifact ID.
3. **Acquire**: The caller requests a lease for an exact lane or exact GPU UUID (`GPU-...`). Diffuser checks the caller's grant, reserves capacity on the matching worker, and refuses if that exact device is unavailable.
4. **Submit (with an idempotency key)**: The caller submits the job with a stable key. If the caller retries with the same key, Diffuser returns the existing job instead of starting a second run.
5. **Read back durably**: Once the worker finishes, Diffuser stores the verified result artifact. Even if the worker exits afterward, the caller can still read and verify the result digest.
6. **Release**: When the caller releases the assignment, Diffuser transitions it to `draining` and tracks cleanup through its custody ledger so uncertain teardowns keep capacity held rather than reusing it prematurely.

## How CPU and GPU workers stay isolated

- **CPU workers** launch a dedicated helper child process with closed extra file descriptors and parent-death cleanup.
- **GPU workers** open a compiled native CUDA helper (`native/cuda/add_one.cpp`), verify its exact SHA-256 digest on the open file descriptor, launch it via `/proc/self/fd` with an empty environment, confirm it binds the exact requested GPU UUID via `libcuda.so.1`, and return a typed result report.
