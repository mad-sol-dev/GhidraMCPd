# MMIO Endpoint

## `mmio_annotate`

Annotates addresses for memory-mapped IO while respecting write guards:

- Requires explicit `addresses` and `annotation` payloads.
- Honors `dry_run` to preview changes without writes.
- When writes execute, they are limited by `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` and logged if `GHIDRA_MCP_AUDIT_LOG` is configured.
