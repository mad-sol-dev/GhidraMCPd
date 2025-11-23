# Observability & Limits

- `/state`: diagnostics (`bridge_ready`, `session_ready`, `ready`, `active_sse`, `connects`, `last_init_ts`).
- Limits: request/batch/time limits enforced; writes audited when enabled.
- Polling tip: throttle `/state` polling to ≥500ms to avoid log spam.

## Audit log entries

When `GHIDRA_MCP_AUDIT_LOG` is set, deterministic write endpoints emit JSONL entries for
both successful and rejected attempts (including dry-runs and disabled writes). Each line
includes:

- `timestamp` and `category` (e.g., `memory.write_bytes`, `datatypes.update`, `project.rebase`).
- Request context fields (`request_id`, `request`, `context.path`) populated by the active
  request scope when available.
- `parameters` reflecting the caller inputs (addresses, paths, confirmation flags, etc.).
- `dry_run`, `writes_enabled`, and operation-specific `controls` (such as `rebases_enabled`).
- A `result` block capturing `ok`, `errors`, `notes`, and outcome-specific flags
  (e.g., `written`, `rebased`).

Entries are appended to the configured JSONL file in the order requests are processed so
that dry-run checks, disabled writes, and successful mutations share a consistent audit
surface.
