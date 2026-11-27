# NUC Intel Arc 140T Diffuser adapter

Linux Python 3 stdlib adapter for the qualified NUC iGPU. It uses the canonical
`/opt/diffuser-140t/bin/llama-server` (llama.cpp b12675, commit
`c212d25ad`) and the two qualified GGUFs under `/opt/diffuser-140t/models/`.
Install the pinned engine and model files at the documented paths and provision
`/var/cache/diffuser-140t/mesa` writable by the worker account. No alternate
engine or tuning flags are selected at runtime. Validate this configuration on
your own hardware before enrollment.

## Enroll a configured Intel Arc 140T worker

Append these two objects to the existing `profiles` array in the worker's
configuration through the normal operator-managed enrollment procedure. This
is a JSON fragment of the fleet worker config, not a replacement for the
existing profiles or credentials. Adjust the example installation path to your
checkout. No enrollment or service change is made by
this adapter. Use your existing worker ID; `example-140t-worker` is illustrative.

```json
{
  "worker_id": "example-140t-worker",
  "profiles": [
    {
      "capability": "infer.llm.140t/v1",
      "description": "Intel Arc 140T Vulkan Qwen3 30B-A3B or 4B inference",
      "adapter": {
        "kind": "exec",
        "command": ["/usr/bin/python3", "/opt/diffuser/adapters/nuc-140t/run-140t-llm.py"],
        "timeout_secs": 600
      }
    },
    {
      "capability": "gpu.140t.control/v1",
      "description": "Intel Arc 140T local inference status and park",
      "adapter": {
        "kind": "exec",
        "command": ["/usr/bin/python3", "/opt/diffuser/adapters/nuc-140t/run-140t-llm.py"],
        "timeout_secs": 30
      }
    }
  ]
}
```

Use `vram_bytes: 0` for the integrated GPU and retain any existing capabilities. The integrated
GPU uses shared host memory, not dedicated NVIDIA VRAM. Route via the capability
and worker ID, without `min_vram_bytes` or `pin_gpu_uuid` constraints. The worker
account must have access to the Vulkan render device, pinned binary, model
files and Mesa cache directory; no root access is needed.

## Request and receipt

Diffuser sends the `input` object to stdin and reads one JSON receipt from
stdout. Check `output.ok` in the Diffuser worker response, even when the outer
worker receipt is successful. The default action is `infer`, default profile
is `30b` and default generation limit is 256 tokens.

```json
{"capability":"infer.llm.140t/v1","timeout_secs":300,"input":{"prompt":"Explain Vulkan in one sentence.","max_tokens":128}}
```

```json
{"capability":"infer.llm.140t/v1","input":{"profile":"4b","messages":[{"role":"user","content":"Summarize this in one sentence."}],"max_tokens":128,"temperature":0.2}}
```

```json
{"capability":"gpu.140t.control/v1","input":{"action":"status"}}
```

```json
{"capability":"gpu.140t.control/v1","input":{"action":"park"}}
```

A successful inference returns `{"ok":true,"profile":"30b","response":{...}}`
where `response` is the llama.cpp OpenAI-compatible chat completion object.
Provide either `prompt` (text) or `messages` (text chat, including tool turns),
not both. Supported optional parameters are `max_tokens` (1 to 4096),
`temperature`, `top_p`, `seed`, `stop`, `tools`, `tool_choice`, `response_format`
and `timeout_secs` (1 to 600, default 240). Tools are only described to the
model; the adapter does not execute them. Context is fixed at 16384 tokens,
including generation. Streaming, arbitrary engine arguments, models, URLs,
multimodal content and request-selected environment variables are unsupported.
The adapter reserves 8 seconds of the actual `DIFFUSER_TIMEOUT_SECS` budget for
cleanup, with a maximum 120 seconds for cold readiness. It limits input to 1 MiB
and engine response to 128 KiB. A receipt must also fit the actual worker stdout
pipe (the worker drains it only after exit); oversized receipts return
`response_too_large`, not partial JSON. Use shorter generations if needed.

## Lifecycle and coexistence

- The first inference auto-wakes the model. A same-profile request reuses the
  warm server. A different profile first cleanly parks the old model, then
  starts the requested one. The exact canonical invocation uses `taskset -c
  6-13`, `127.0.0.1:18081`, `-ngl 99 --jinja --slots --no-context-shift`,
  `-fa off -ctk f16 -ctv f16 -c 16384 -np 1 -t 3 -tb 3 -b 2048 -ub 512
  --cache-reuse 256`, the pinned Intel Vulkan ICD and Mesa cache directory.
- A private per-worker-UID local supervisor owns the engine child and parks
  it after 60 seconds of inactivity. It exits once parked. A per-UID Unix
  socket and nonblocking lock under `/tmp/diffuser-140t-<uid>/` serialize
  requests across both capabilities; directory mode is 0700. Concurrent
  inference or control returns `busy`; retry after the active request ends.
- `status` does not wake a server. It returns the adapter-owned state
  (`ready` or `parked`), profile, package temperature and `thermal_ok`.
  `park` is idempotent and stops only the supervisor's own child. An unrelated
  listener on port 18081 is never adopted or stopped. A cold wake with that
  port occupied returns `port_in_use`. Linux socket ownership is checked
  before health probing and before submitting inference.
- CPU package temperature is read from `x86_pkg_temp` and `coretemp` package
  labels (highest valid reading). Inference fails closed if no reading exists
  or if the temperature is at least 90 C. Temperature and cancellation are
  checked roughly every 250 ms during startup, inference and warm idle.
  Thermal trips, failed inference, cancellation and timeout stop the owned
  process. Clean stop uses SIGTERM, with SIGKILL only if it does not exit in
  3 seconds. A Linux parent-death signal also protects against an abruptly
  killed supervisor. No changes to CPU power policy, GPU drivers, live
  Diffuser config or unrelated services are performed.
- The HTTP connection uses only the fixed loopback endpoint and cannot follow
  redirects or proxies. Child processes do not inherit worker credentials or
  unqualified tuning variables. Raw server output and internal exceptions are
  not forwarded. Error receipts have `ok:false`, `error_code` and `error`.

## Verify locally without starting the engine

```sh
python3 -B -m unittest discover -s adapters/nuc-140t/tests -v
```

Run from the repository root. These tests mock engine startup, HTTP and
temperature sensors. Enrollment and live hardware validation are separate
operator actions.
