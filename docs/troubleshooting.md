# Troubleshooting

## Error reference

All REST responses share the deterministic envelope shown below. Successful calls set `ok=true` and populate `data`, while errors populate `errors[]` with `code` and `message` entries for downstream tooling.

```json
{
  "ok": false,
  "data": null,
  "errors": [
    {
      "code": "SAFETY_LIMIT",
      "message": "strings.search.window limit exceeded: attempted 400 > allowed 256"
    }
  ]
}
```

See the table below for concrete error codes and HTTP status guidance.

| Name | When it appears | Example payload / status |
| --- | --- | --- |
| `mcp_not_ready` | `POST /messages` before the SSE stream and session finish initialising | `425 Too Early` with `{"error":"mcp_not_ready"}` |
| SSE single-stream guard | Second `GET /sse` while another stream is open, or non-GET method | `409 Conflict` (duplicate stream) or `405 Method Not Allowed` with `{"allow":"GET"}` |
| `SAFETY_LIMIT` | Batch/search window or write count exceeds configured caps (`GHIDRA_MCP_MAX_ITEMS_PER_BATCH`, `GHIDRA_MCP_MAX_WRITES_PER_REQUEST`) | `400 Bad Request` envelope: `{"ok":false,"errors":[{"code":"SAFETY_LIMIT","message":"strings.search.window limit exceeded: attempted 400 > allowed 256"}]}` |
| `INVALID_ARGUMENT` | Request parameters fail validation (negative offsets, non-integer limits, malformed hex) | `400 Bad Request` envelope with `code="INVALID_ARGUMENT"` |
| `SCHEMA_INVALID` | JSON body violates schema (missing required fields, unexpected keys) | `400 Bad Request` envelope with `code="SCHEMA_INVALID"` |
| `WRITE_DISABLED_DRY_RUN` | Write attempted while writes are disabled or `dry_run=false` without permission | `400 Bad Request` envelope: `{"ok":false,"errors":[{"code":"WRITE_DISABLED_DRY_RUN","message":"Writes are disabled while dry_run is false."}]}` |
| `WRITE_VERIFY_FAILED` | Ghidra could not confirm a rename/comment during jump-table processing | `200 OK` with `data.errors` containing `"WRITE_VERIFY_FAILED"` |
| `TOOL_BINDING_MISSING` | Jump-table slot read failed (adapter missing backing data) | `200 OK` with `data.errors` containing `"TOOL_BINDING_MISSING"` |
| `ARM_INSTRUCTION` | Jump-table slot contains instruction sentinel (no branch target) | `200 OK` with `data.errors` containing `"ARM_INSTRUCTION"` |
| `OUT_OF_RANGE` | Jump-table target falls outside `code_min`/`code_max` bounds | `200 OK` with `data.errors` containing `"OUT_OF_RANGE"` |
| `NO_FUNCTION_AT_TARGET` | Jump-table target lacks a defined function symbol | `200 OK` with `data.errors` containing `"NO_FUNCTION_AT_TARGET"` |

Refer back to this table when interpreting the examples below or cross-checking logs.

## Quick checks

- **409 on `/sse`**: By design there is only one active SSE stream. See [SSE readiness guidance](server.md#streaming--readiness) and the [error reference](#error-reference) before reconnecting.
- **425 on `/messages`**: The bridge or session is still initialising. Wait for the readiness event on `/sse` or poll `/state` until `bridge_ready` and `session_ready` are true.
- **Noisy `CancelledError` on shutdown**: Benign cancellation traces may appear while the server closes background tasks. They are filtered in current builds but can surface if an ASGI server terminates abruptly.
- **Adapter error**: Unknown optional adapter values raise fast failures. Verify `BRIDGE_OPTIONAL_ADAPTERS` names against supported architectures.

## SSE Connection Error (409 Conflict) — detailed guide

### Symptom

MCP clients (e.g., AiderDesk) log messages such as:

- `SSE error: Non-200 status code (409)`
- `Error invoking remote method 'load-mcp-server-tools'`

### Root cause

The Ghidra Java plugin does not support parallel operations. Ghidra MCPd enforces a single active SSE connection to prevent concurrent access that could corrupt state. A second `GET /sse` request therefore returns 409 while the first stream remains active.

### Common scenarios

#### Task switching in clients

Switching contexts rapidly can leave the old SSE stream closing while a new one starts.

Server logs typically show:

```
INFO: 127.0.0.1:44026 - "GET /sse HTTP/1.1" 200 OK
INFO: 127.0.0.1:48446 - "GET /sse HTTP/1.1" 409 Conflict
INFO: 127.0.0.1:57816 - "GET /sse HTTP/1.1" 200 OK
```

#### MCP server reloads

Restarting a client-side MCP manager can trigger reconnect attempts before the bridge cleans up the earlier connection.

### Resolution

1. Allow 500–1000 ms backoff before retrying and wait for the prior connection to close. Streaming best practices are detailed in [Server operations](server.md#streaming--readiness).
2. Confirm idle state:
   ```bash
   curl http://127.0.0.1:8000/state | jq '.active_sse'
   ```
   A null value indicates the bridge is ready for a new stream.
3. Reconnect once `/state.active_sse` is `null` or readiness events arrive on the SSE stream.

### Prevention

- Ensure clients close SSE connections gracefully before spinning up a new one.
- Space reconnection attempts to avoid overlapping `GET /sse` calls.
- Monitor `/state.limit_hits` for repeated connection churn.

### Manual recovery

If a client remains stuck, restart the server:

```bash
python -m uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000
```

## `425 Too Early` on `/messages`

### Symptom

Requests to `/messages` return HTTP 425 with body `{"error":"mcp_not_ready"}`.

### Root cause

The SSE stream has not finished initialising or the Ghidra bridge is still loading. Until both readiness flags are true, the server gates message traffic.

### Resolution

1. Establish the SSE connection and wait for the readiness event.
2. Alternatively poll `/state` and confirm:
   ```bash
   curl http://127.0.0.1:8000/state | jq '{bridge_ready, session_ready}'
   ```
   Both values must be `true` before `/messages` accepts requests.
3. After readiness, resume normal MCP messaging.

## Handling shutdown `CancelledError`

The server cancels background tasks when stopping. Uvicorn may still log `asyncio.CancelledError` traces during shutdown, especially if the process receives `SIGINT` or `SIGTERM`. These messages are expected and safe to ignore unless accompanied by stack traces indicating failed cleanup.
