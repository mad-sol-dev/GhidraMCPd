# SSE Behavior

- **Single active connection**: second `GET /sse` returns **409** by design.
- `POST /sse` → **405** with `{"error":"method_not_allowed","allow":"GET"}`.
- `/messages` gates on readiness; premature calls return **425** `{ "error":"mcp_not_ready" }`.

Use `/state` to observe `active_sse`, readiness, and counters. See also `observability.md`.
