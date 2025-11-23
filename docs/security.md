# Security and safety guard rails

## Write-capable operations (as implemented in code)
- **Memory writes**: `bridge/features/memory.py::write_bytes` calls `client.write_bytes` only when `dry_run` is `False` and `writes_enabled` is `True`; otherwise it only returns notes/errors.
- **Data type mutations**: `create_datatype`, `update_datatype`, and `delete_datatype` in `bridge/features/datatypes.py` gate writes on both `dry_run=False` and `writes_enabled=True` before invoking GhidraClient operations (create/update/delete) and `record_write_attempt()`.
- **Jump-table annotations**: `bridge/features/jt.py::slot_process` performs `rename_function` and `set_decompiler_comment` only if the slot check succeeds, `dry_run` is `False`, and `writes_enabled` is `True`; it records each write attempt.
- **MMIO annotations**: `bridge/features/mmio.py::annotate` enforces a batch limit, then calls `set_disassembly_comment` per sample only when `dry_run=False` and `writes_enabled=True`.
- **Project rebasing**: `bridge/features/project.py::rebase_project` attempts `client.rebase_program` only if `dry_run` is `False`, `writes_enabled` is `True`, `rebases_enabled` is `True`, and `confirm` is `True`; otherwise it returns notes/errors without issuing the upstream call.

## Guard rails in the code
- **Default read-only mode**: `ENABLE_WRITES` defaults to `False` (from `GHIDRA_MCP_ENABLE_WRITES`), and `MAX_WRITES_PER_REQUEST` defaults to `2`; `MAX_ITEMS_PER_BATCH` defaults to `256` for batch-sensitive features.
- **Per-request write counting**: `record_write_attempt()` enforces `MAX_WRITES_PER_REQUEST` and raises `SafetyLimitExceeded` when the limit is exceeded.
- **Batch size enforcement**: `enforce_batch_limit()` enforces `MAX_ITEMS_PER_BATCH`, raising `SafetyLimitExceeded` when exceeded (e.g., in `mmio.annotate`).
- **Dry-run defaults**: Write-capable feature functions default `dry_run` to `True`, causing them to report planned actions without issuing writes.
- **Project rebase opt-in**: `ENABLE_PROJECT_REBASE` defaults to `False` and must be set (and `confirm=True`) before a rebase call can proceed.
- **Confirm blocking at the client**: The Ghidra client refuses upstream requests that include `confirm=true`, preventing direct bypass of confirmation checks.
- **Single SSE connection**: The guarded SSE app returns `SSE_CONFLICT` when a second client connects while another SSE session is active.

## Usage recommendations (interpretation)
- Enable `GHIDRA_MCP_ENABLE_WRITES` only when you intentionally need mutations; all write-capable functions honor `writes_enabled`, so leaving it unset keeps the bridge read-only.
- Keep `dry_run` at its default `True` until you have reviewed the planned changes (memory writes, data types, JT/MMIO annotations); switching to `False` is what triggers actual writes when writes are enabled.
- Turn on `GHIDRA_MCP_ENABLE_PROJECT_REBASE` only for deliberate rebasing scenarios and run `project_rebase` with `dry_run` first; rebasing also requires `confirm=True` in addition to writes being enabled.
- Avoid raising `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` or `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` unless you truly need larger operations; these limits are the guard rails enforced by `record_write_attempt()` and `enforce_batch_limit()`.

## Whitelisted Bridge Calls & Adapters

The bridge enforces a whitelist of allowed Ghidra operations (GET/POST) defined in `bridge/ghidra/whitelist.py`; only these
 endpoints can be invoked upstream. Optional architecture adapters (e.g., `x86`) can be enabled via `BRIDGE_OPTIONAL_ADAPTERS`
 to extend functionality while still honoring the whitelist.
