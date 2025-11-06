# Server operations

## Streaming & readiness

Ghidra MCPd exposes a single server-sent events stream at `GET /sse`. Exactly one connection is permitted at a time. A second `GET /sse` while an active stream is open returns **HTTP 409 Conflict** and logs the existing connection identifier. Attempting to `POST /sse` responds with **HTTP 405 Method Not Allowed** and `{"allow":"GET"}`. See the [error reference](troubleshooting.md#error-reference) for a quick matrix of the relevant status codes.

Clients must establish the SSE stream before using `/messages`. Until both the bridge and session are ready, `/messages` responds with **HTTP 425 Too Early** and `{"error":"mcp_not_ready"}`. After receiving the initial readiness event, resume message traffic. When reconnecting, allow the previous stream to close and back off at least 500-1000 ms between retries to avoid immediate 409 responses.

### Reconnect backoff example

The snippet below shows one way to retry the SSE stream with backoff and jitter. The loop tolerates transient `409`/`405` responses while the previous stream winds down and caps retries at five seconds.

```python
import random
import time

import requests

SSE_URL = "http://127.0.0.1:8000/sse"

backoff = 0.5  # seconds
max_backoff = 5.0

while True:
    response = requests.get(SSE_URL, stream=True, timeout=30)
    if response.status_code == 200:
        break  # stream established

    if response.status_code in {405, 409}:
        jitter = random.uniform(0.0, 0.5)
        sleep_for = min(max_backoff, backoff + jitter)
        time.sleep(sleep_for)
        backoff = min(max_backoff, backoff * 1.5)
        continue

    response.raise_for_status()

for line in response.iter_lines():
    print(line)
```

The server continues delivering exactly one SSE stream at a time; clients should only run a single copy of the loop.

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
