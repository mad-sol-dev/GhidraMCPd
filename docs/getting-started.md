# Getting started

This guide covers installation, local execution, and configuration for the Ghidra MCPd server.

## Install

Use Python 3.10+ and create an isolated environment:

```bash
python -m venv .venv
source .venv/bin/activate
# install the runtime dependencies only
python -m pip install -r requirements.txt
# optionally install development/test dependencies
python -m pip install -r requirements-dev.txt
```

The bridge depends on Ghidra's headless components through the bundled plugin. No additional system packages are required for basic usage.

## Run

Launch the deterministic ASGI app with Uvicorn:

```bash
uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000
```

The server exposes REST endpoints under `/api/*.json`, `/openapi.json`, server-sent events on `/sse`, and session state via `/state`. Clients should wait for readiness before issuing `/messages` calls; premature traffic receives HTTP 425 with `{"error":"mcp_not_ready"}`.

Batch-oriented tools (`disassemble_batch`, `read_words`, `search_scalars_with_context`) are available once the SSE bridge reports ready. When running against large programs, favor these endpoints to reduce token churn compared to issuing many single-address calls.

## Stdio mode

The repository still ships the legacy helper for console-first workflows or
environments where SSE/Web transports are blocked. Use it after completing the
same Python prerequisites (`python -m pip install -r requirements.txt` etc.).

Launch the helper by pointing it at your Ghidra Bridge URL and selecting a
transport:

```bash
python scripts/bridge_stdio.py --ghidra-server http://127.0.0.1:8080/ --transport stdio
```

- `--transport stdio` starts the MCP server in-process and speaks JSON-RPC over
  stdio (no `/sse`, `/messages`, or shim). This matches the classic CLI used
  before the Uvicorn-based server and is ideal for local smoke tests.
- `--transport sse` spins up the same MCP server but also boots an OpenWebUI shim
  (controlled by `--shim-host/--shim-port`) and forwards HTTP traffic to
  `/sse`, `/messages`, and `/state`. Use it when integrating with OpenWebUI or
  other SSE-aware clients.

Switch transports at runtime by re-running the command with the desired flag.
Other CLI options (`--mcp-host`, `--mcp-port`, and `--debug`) remain identical
between modes so you can keep a single `.env`/script and only toggle
`--transport` depending on your client.

## Configuration

Set environment variables before starting the server to adjust safety limits, auditing and endpoint targets:
- `GHIDRA_SERVER_URL` (default `http://127.0.0.1:8080/`)
  - Base URL (including trailing slash) for the Ghidra Java plugin.  The Python bridge uses this to communicate with Ghidra.  Override this if your plugin is running on a different host or port.
- `GHIDRA_MCP_ENABLE_WRITES` (default `false`)
  - Disable or enable write operations globally. When `false` or when requests include `dry_run=true`, write handlers perform no mutations.
- `GHIDRA_MCP_ENABLE_PROJECT_REBASE` (default `false`)
  - Enables `/api/project_rebase.json` to mutate the program image base when `dry_run=false` and the request includes `confirm=true`. Without the flag, the endpoint only reports what would change.
- `GHIDRA_MCP_AUDIT_LOG`
  - Optional filesystem path for JSONL write audits. When unset, successful writes are not logged.
- `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` (default `2`)
  - Caps the number of writes a single call may perform. Surpassing the cap raises `SafetyLimitExceeded`.
- `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` (default `256`)
  - Applies to batch endpoints and search windows, including `search_scalars_with_context`. Values above the limit raise `SafetyLimitExceeded` to preserve deterministic token budgets.
- `GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY` (default `strict`)
  - Governs mid-session program switching. `strict` returns errors once program-scoped tools have run; `soft` allows the change with warnings and confirmation guidance.
- `BRIDGE_OPTIONAL_ADAPTERS`
  - Comma-separated list of optional Ghidra adapters to enable. Unknown entries fail fast at startup.

For reproducibility, copy `.env.sample` to `.env`, edit values, and load via `export $(cat .env | xargs)` (or a shell equivalent) prior to launching Uvicorn.

> **Batch caps**
> - Search windows, compact string listings, and disassembly batches default to **256** items via `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`.
> - Write operations default to **2** mutations per request via `GHIDRA_MCP_MAX_WRITES_PER_REQUEST`.
> - Override the limits by setting the environment variables (or updating your `.env`) before starting the server.

### Batch limits (defaults)

The bridge enforces deterministic caps on batch-style operations to keep token usage predictable. All of the following limits default to `GHIDRA_MCP_MAX_ITEMS_PER_BATCH = 256` and raise `SafetyLimitExceeded` when exceeded (see the [error reference](troubleshooting.md#error-reference) for envelope details):

| Operation | Capped dimension | Default | Override |
| --- | --- | --- | --- |
| `disassemble_batch` | Addresses per request | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`
| `read_words` | Words per request | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`
| `search_strings`, `search_imports`, `search_exports`, `search_xrefs_to`, `strings_compact` | Window size (`page * limit` for search APIs, `offset + limit` for compact listings) | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`
| `search_scalars_with_context` | Matches returned | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`

Set the environment variable before starting the server to raise the ceiling, for example:

```bash
GHIDRA_MCP_MAX_ITEMS_PER_BATCH=512 uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000
```

Watch for repeated `SafetyLimitExceeded` responses to confirm the new cap is sufficient for your workload.

## Token efficiency notes

Ghidra MCPd keeps responses compact by enforcing deterministic schema envelopes (`{"ok":bool,"data":object|null,"errors":[]}`) and predictable limits. In typical analysis sessions, combining `disassemble_batch` with contextual search reduces total request tokens by roughly 70% (example: ~80k tokens before batching → ~25k after). Actual savings depend on program size and client prompting, but the enforced caps above protect against unbounded payloads.
