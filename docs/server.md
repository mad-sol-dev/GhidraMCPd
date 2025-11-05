# Server operations

## Streaming & readiness

Ghidra MCPd exposes a single server-sent events stream at `GET /sse`. Exactly one connection is permitted at a time. A second `GET /sse` while an active stream is open returns **HTTP 409 Conflict** and logs the existing connection identifier. Attempting to `POST /sse` responds with **HTTP 405 Method Not Allowed** and `{"allow":"GET"}`.

Clients must establish the SSE stream before using `/messages`. Until both the bridge and session are ready, `/messages` responds with **HTTP 425 Too Early** and `{"error":"mcp_not_ready"}`. After receiving the initial readiness event, resume message traffic. When reconnecting, allow the previous stream to close and back off at least 500–1000 ms between retries to avoid immediate 409 responses.

## Observability

Poll `GET /state` to view live diagnostics:

- `bridge_ready`: boolean indicating that the Python bridge has initialised.
- `session_ready`: boolean showing the MCP session is available for tool calls.
- `active_sse`: connection identifier or `null` when idle.
- `counters`: per-endpoint usage counters, including batch operations and limit guards.
- `limit_hits`: list of safety limit triggers (e.g., batch caps, write guards).

Throttle polling to at least every 500 ms to avoid log spam. The same endpoint reflects write-guard status and can be scraped for observability dashboards.

## Limits & write-guards

Write operations are guarded by deterministic envelopes and configuration flags:

- `ENABLE_WRITES`: bound to `GHIDRA_MCP_ENABLE_WRITES`. When `false`, write routes short-circuit and return `ok=false` with errors.
- `dry_run`: per-request override that forces non-destructive execution even when writes are enabled.
- `SafetyLimitExceeded`: error raised when batch sizes, search windows, or write counts exceed configured caps (e.g., `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`, `GHIDRA_MCP_MAX_WRITES_PER_REQUEST`). Limit hits populate `/state.limit_hits` for downstream monitoring.

Keep writes idempotent and monitor `/state` for repeated limit violations to fine-tune batch sizes or adjust configuration within safe bounds.
