# Configuration

Set via environment variables:

- `GHIDRA_MCP_ENABLE_WRITES` (default: `false`)
  Write endpoints honor this flag. When `false` or when requests pass `dry_run=true`, no writes occur.

- `GHIDRA_MCP_AUDIT_LOG`
  Optional filesystem path for JSONL write audits. When unset, successful writes are not recorded.

- `GHIDRA_MCP_MAX_WRITES_PER_REQUEST`
  Hard limit of writes any single request may perform.

- `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`
  Bound for batch payload sizes across deterministic endpoints.

- `BRIDGE_OPTIONAL_ADAPTERS` (e.g., `"x86,i386"`)
  Enables optional architecture adapters. Unknown names raise a descriptive error at startup.

Place local defaults in `.env.sample` → `.env` and load them before running the bridge.
