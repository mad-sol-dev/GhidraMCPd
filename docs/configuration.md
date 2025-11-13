# Configuration

Set via environment variables:

- `GHIDRA_SERVER_URL` (default: `http://127.0.0.1:8080/`)
  Base URL (including trailing slash) for the Ghidra HTTP plugin consumed by the bridge client.

- `GHIDRA_MCP_ENABLE_WRITES` (default: `false`)
  Enables deterministic write tools (rename/comment). When `false` or when requests pass
  `dry_run=true`, no writes occur.

- `GHIDRA_MCP_ENABLE_PROJECT_REBASE` (default: `false`)
  Gates the project rebase tools that modify checked-out workspaces. Keep disabled unless
  you understand the workflow impact.

- `GHIDRA_MCP_AUDIT_LOG` (default: unset)
  Optional filesystem path for JSONL write audits. When unset, successful writes are not
  recorded.

- `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` (default: `2`)
  Hard limit of writes any single request may perform.

- `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` (default: `256`)
  Bound for batch payload sizes across deterministic endpoints.

- `BRIDGE_OPTIONAL_ADAPTERS` (default: unset, e.g., `"x86,i386"`)
  Enables optional architecture adapters. Unknown names raise a descriptive error at startup.

Place local defaults in `.env.sample` → `.env` and load them before running the bridge.
