# Design Notes (Diffuser)

Diffuser separates **routing authority**, **durable custody**, and **pluggable execution** into distinct boundaries:

1. **Fail-closed controller**: Unconfigured protected routes refuse requests (`503 routing_closed`) rather than falling back to local execution.
2. **Exact capability and device pinning**: Callers request an explicit capability and optional GPU UUID (`GPU-...`); unavailable devices return `422 capability_unavailable` with zero silent substitution.
3. **Idempotent durable execution**: Stable `Idempotency-Key` values prevent duplicate compute on retries, and output artifacts remain readable and digest-verified after worker exit.
4. **Witnessed teardown and custody**: Releasing an assignment transitions it to `draining` until independent cleanup evidence is verified (`draining -> closed`).
5. **Pluggable fleet workers**: Local CPU, remote CUDA (over encrypted SSH loopback tunnels or HTTPS), and optional Google Colab GPU adapters (`adapters/colab/`) share one authenticated, replay-protected fleet protocol.
