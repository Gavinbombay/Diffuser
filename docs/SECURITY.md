# Security Policy (Diffuser)

## Supported Version

Security fixes target the latest commit on `main`.

## Reporting a Vulnerability

Please report suspected security issues privately to the repository maintainer rather than opening a public issue with exploit details. Include the affected file paths, reproduction preconditions, and impact assessment.

## Trust Boundaries

- **Admin & control sockets**: Loopback HTTP and `0600` Unix control sockets are trusted local operator surfaces.
- **Worker RPC**: Remote worker URLs require HTTPS (`127.0.0.1` / `::1` / `localhost` loopback HTTP exception); signed RPC requests enforce per-start session binding, timestamp freshness, and single-use replay rejection.
- **Google Colab adapters (`adapters/colab/`)**: Operator-managed `0600` CLI credentials live outside the repository; the adapter blocks `colab pay`, enforces a hard minimum compute-unit floor (`>= 200 CU`), stops owned VMs on all exits, and fails closed into lane quarantine if cleanup verification is ambiguous.

See [`../AUDIT.md`](../AUDIT.md) for the latest Cloudflare Security Audit record (`CLEAN PASS`).
