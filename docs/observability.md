# Observability & Limits

- `/state`: diagnostics (`bridge_ready`, `session_ready`, `active_sse`, counters).
- Limits: request/batch/time limits enforced; writes audited when enabled.
- Polling tip: throttle `/state` polling to ≥500ms to avoid log spam.
