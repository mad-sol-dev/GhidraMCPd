# Observability & Limits

- `/state`: diagnostics (`bridge_ready`, `session_ready`, `ready`, `active_sse`, `connects`, `last_init_ts`).
- Limits: request/batch/time limits enforced; writes audited when enabled.
- Polling tip: throttle `/state` polling to ≥500ms to avoid log spam.
