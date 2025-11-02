# MMIO Endpoint

## `mmio_annotate`

Annotates addresses for memory-mapped IO while respecting write guards:

- Requires explicit `addresses` and `annotation` payloads.
- Honors `dry_run` to preview changes without writes.
- When writes execute, they are limited by `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` and logged if `GHIDRA_MCP_AUDIT_LOG` is configured.

## Response Format

**Request:**
```json
{
  "function_addr": "0x0002df2c",
  "dry_run": true,
  "max_samples": 4
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "function": "0x0002df2c",
    "reads": 10,
    "writes": 9,
    "bitwise_or": 2,
    "bitwise_and": 1,
    "toggles": 0,
    "annotated": 0,
    "samples": [
      {
        "addr": "0x0002df30",
        "op": "READ",
        "target": "0x00000018",
        "address_abs": "0x00000018"
      },
      {
        "addr": "0x0002df34",
        "op": "OR",
        "target": "0x00004000",
        "address_abs": "0x00004000"
      }
    ],
    "notes": ["dry-run requested: annotations were not applied"]
  },
  "errors": []
}
```

### Fields

- `addr`: instruction address where the operation occurs
- `op`: operation type (READ, WRITE, OR, AND, TOGGLE)
- `target`: immediate value extracted from the instruction
- `address_abs`: **absolute address** for the operation
  - If `target` is a valid address (non-zero), uses `target`
  - Otherwise falls back to `addr` (the instruction address)
- `annotated`: number of comments actually written (0 when `dry_run: true`)
- `notes`: array of informational messages

### Limits

- `max_samples`: max 8 (default), caps the number of sample operations returned
- Write operations require `dry_run: false` and `GHIDRA_MCP_ENABLE_WRITES=1`
