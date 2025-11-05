# Getting started

This guide covers installation, local execution, and configuration for the Ghidra MCPd server.

## Install

Use Python 3.10+ and create an isolated environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
```

The bridge depends on Ghidra's headless components through the bundled plugin. No additional system packages are required for basic usage.

## Run

Launch the deterministic ASGI app with Uvicorn:

```bash
uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000
```

The server exposes REST endpoints under `/api/*.json`, `/openapi.json`, server-sent events on `/sse`, and session state via `/state`. Clients should wait for readiness before issuing `/messages` calls; premature traffic receives HTTP 425 with `{"error":"mcp_not_ready"}`.

Batch-oriented tools (`disassemble_batch`, `read_words`, `search_scalars_with_context`) are available once the SSE bridge reports ready. When running against large programs, favor these endpoints to reduce token churn compared to issuing many single-address calls.

## Configuration

Set environment variables before starting the server to adjust safety limits and auditing:

- `GHIDRA_MCP_ENABLE_WRITES` (default `false`)
  - Disable or enable write operations globally. When `false` or when requests include `dry_run=true`, write handlers perform no mutations.
- `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` (default `2`)
  - Caps the number of writes a single call may perform. Surpassing the cap raises `SafetyLimitExceeded`.
- `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` (default `256`)
  - Applies to batch endpoints and search windows, including `search_scalars_with_context`. Values above the limit raise `SafetyLimitExceeded` to preserve deterministic token budgets.
- `GHIDRA_MCP_AUDIT_LOG`
  - Optional filesystem path for JSONL write audits. When unset, successful writes are not logged.
- `BRIDGE_OPTIONAL_ADAPTERS`
  - Comma-separated list of optional Ghidra adapters to enable. Unknown entries fail fast at startup.

For reproducibility, copy `.env.sample` to `.env`, edit values, and load via `export $(cat .env | xargs)` (or a shell equivalent) prior to launching Uvicorn.

## Token efficiency notes

Ghidra MCPd keeps responses compact by enforcing deterministic schema envelopes (`{"ok":bool,"data":object|null,"errors":[]}`) and predictable limits. In typical analysis sessions, combining `disassemble_batch` with contextual search reduces total request tokens by roughly 70% (example: ~80k tokens before batching → ~25k after). Actual savings depend on program size and client prompting, but the enforced caps above protect against unbounded payloads.
