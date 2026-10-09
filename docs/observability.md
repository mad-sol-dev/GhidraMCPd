# Observability & Limits

- `/state`: diagnostics (`bridge_ready`, `session_ready`, `ready`, `active_sse`, `connects`, `last_init_ts`).
- Limits: request/batch/time limits enforced; writes audited when enabled.
- Polling tip: throttle `/state` polling to ≥500ms to avoid log spam.

## Audit log entries

When `GHIDRA_MCP_AUDIT_LOG` is set, the data-type write endpoints emit JSONL entries for
both successful and rejected attempts. Renames, comments and JT/MMIO annotations are not
audited yet ({R.28}); renames and comments made through `rename_function`/`set_comment` do
appear in `list_mutations` (including dry-runs and disabled writes). Each line
includes:

- `timestamp` and `category` (`datatypes.create`, `datatypes.update`, `datatypes.delete`).
- Request context fields (`request_id`, `request`, `context.path`) populated by the active
  request scope when available.
- `parameters` reflecting the caller inputs (kind, path, fields).
- `dry_run`, `writes_enabled`, and operation-specific `controls`.
- A `result` block capturing `ok`, `errors`, `notes`, and outcome-specific flags
  (`written`).

Entries are appended to the configured JSONL file in the order requests are processed so
that dry-run checks, disabled writes, and successful mutations share a consistent audit
surface.
