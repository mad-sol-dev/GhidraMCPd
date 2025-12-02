# Ghidra MCPd API reference

_Source: bridge/tests/golden/data/openapi_snapshot.json — Ghidra MCP Bridge API v1.0.0_

## Overview

All endpoints use the envelope `{ok, data|null, errors[]}` with error entries shaped as `{status, code, message, recovery[]}` plus strict JSON schemas.

- `POST /api/search_strings.json`
- `POST /api/search_functions.json`
- `POST /api/search_imports.json`
- `POST /api/search_exports.json`
- `POST /api/search_xrefs_to.json`
- `POST /api/search_scalars.json`
- `POST /api/list_functions_in_range.json`
- `POST /api/find_in_function.json`
- `POST /api/disassemble_at.json`
- `POST /api/read_bytes.json`
- `POST /api/write_bytes.json`
- `POST /api/jt_slot_check.json`
- `POST /api/jt_scan.json`
- `POST /api/strings_compact.json`
- `POST /api/mmio_annotate.json`
- `POST /api/analyze_function_complete.json`
- `GET /api/project_info.json`

See the sections below for parameters and invariants.

> OpenAPI: `GET /openapi.json`
> **Conventions:** `data.total` is an integer; `data.page` is **1-based** on search endpoints.

## Search endpoints

### Common semantics

- **Server-side filtering first** (no information loss), then pagination.
- Responses unify on: `query`, `total`, `page` (1-based), `limit`, `items`, `has_more`.

### Strings

`POST /api/search_strings.json`

```json
{ "query": "memcpy", "limit": 50, "page": 1 }
```

### Functions / Imports / Exports / Xrefs

Same shape; each filters in its domain. See OpenAPI for item fields.

### Scalars

`POST /api/search_scalars.json`

Search for immediate/constant values in code.

**Request:**
```json
{ "value": "0xB0000084", "limit": 100, "page": 1 }
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "query": "0xB0000084",
    "total": 42,
    "page": 1,
    "limit": 100,
    "items": [
      {
        "address": "0x0020A1C0",
        "value": "0xB0000084",
        "function": "init_board",
        "context": "LDR R0, =0xB0000084"
      }
    ],
    "has_more": false
  },
  "errors": []
}
```

- `value`: hex string (0x...) or integer
- `limit`: max 500
- `page`: 1-based pagination
- `has_more`: true when another page exists (`page * limit < total`)

### Functions in range

`POST /api/list_functions_in_range.json`

List all functions within an address range.

**Request:**
```json
{ "address_min": "0x00000000", "address_max": "0x00001000", "limit": 200, "page": 1 }
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "total": 12,
    "page": 1,
    "limit": 200,
    "items": [
      {
        "name": "Reset",
        "address": "0x00000000",
        "size": 3
      }
    ]
  },
  "errors": []
}
```

- `address_min`, `address_max`: hex strings (inclusive range)
- `size`: optional, number of addresses in function body
- `limit`: max 500

### Find in function

`POST /api/find_in_function.json` (MCP tool: `find_in_function`)

Search for text patterns within a function's disassembly or decompilation.

**Request:**
```json
{
  "address": "0x00401000",
  "query": "0x251",
  "mode": "both",
  "regex": false,
  "case_sensitive": false,
  "context_lines": 3,
  "limit": 50
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "address": "0x00401000",
    "query": "0x251",
    "mode": "both",
    "regex": false,
    "case_sensitive": false,
    "matches": {
      "disassembly": [
        {
          "line_number": 42,
          "address": "0x00401028",
          "matched_text": "MOV R0, #0x251",
          "context": {
            "before": ["...", "..."],
            "match": "MOV R0, #0x251",
            "after": ["...", "..."]
          }
        }
      ],
      "decompile": [
        {
          "line_number": 15,
          "matched_text": "offset = 0x251;",
          "context": {
            "before": ["void init() {", "  int offset;"],
            "match": "  offset = 0x251;",
            "after": ["  configure(offset);", "}"]
          }
        }
      ]
    },
    "summary": {
      "total_matches": 2,
      "disassembly_matches": 1,
      "decompile_matches": 1,
      "truncated": false
    }
  },
  "errors": []
}
```

Parameters:
- `address`: Function address (hex string, required)
- `query`: Search string or regex pattern (required)
- `mode`: Search in `"disasm"`, `"decompile"`, or `"both"` (default: `"both"`)
- `regex`: Treat query as regex pattern (default: `false`)
- `case_sensitive`: Perform case-sensitive search (default: `false`)
- `context_lines`: Lines before/after match to include (0-16, default: 3)
- `limit`: Max matches per mode (1-200, default: 50)

**Use cases:**
- Find all references to a specific offset/constant within a function
- Search for register usage in disassembly (e.g., `"R7"`, `"SP"`)
- Find variable names in decompiled code
- Regex search for instruction patterns (e.g., `r"BL\s+0x[0-9A-Fa-f]+"`)

**Token efficiency:** Server-side search returns only matches with context windows, avoiding the need to transfer entire function listings.

### Disassemble at

`POST /api/disassemble_at.json`

Disassemble N instructions starting at an address.

**Request:**
```json
{ "address": "0x00000000", "count": 16 }
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "items": [
      {
        "address": "0x00000000",
        "bytes": "DBF021E3",
        "text": "msr cpsr_c,#0xdb"
      }
    ]
  },
  "errors": []
}
```

- `count`: max 128, default 16
- `bytes`: uppercase hex string of instruction bytes

### Read bytes

`POST /api/read_bytes.json`

Read raw bytes from memory.

**Request:**
```json
{ "address": "0x00000000", "length": 16 }
```

**Response:**
```json
{
"ok": true,
"data": {
  "address": "0x00000000",
  "length": 16,
  "encoding": "base64",
  "data": "2/Ah4zTQn+XX8CHjMNCf5Q==",
  "literal": "\xDB\xF0!\xE35\x10\x9F\xE5\xD7\xF0!\xE30\xD0\x9F\xE5"
},
"errors": []
}
```

- `length`: max 4096 bytes
- `encoding`: always "base64"
- `data`: Base64-encoded bytes
- `literal`: Optional raw byte string (Latin-1 safe) when `include_literals: true` is requested

### Wildcard queries

The following endpoints support wildcard queries (return all items without filtering):
- `search_functions`: use `query: "*"` or `query: ""`

`search_xrefs_to` accepts optional query strings (normalized before forwarding). Leave the query empty or wildcard to return all matches.

All search endpoints enforce the shared batch window cap (`page * limit <= 256` by default). Oversized windows return `413 Payload Too Large` so callers can retry with a smaller page or limit.

## String endpoints

### `strings_compact`

Returns a compact listing of program strings with deterministic ordering:

- Items contain `addr`, `s`, and `refs` counts with optional full `literal` text.
- Results are bounded by `limit` and always include `total` metadata.
- Empty strings are omitted; ASCII/UTF-16 variants are normalized to UTF-8 output.
- When Ghidra bindings do not implement `list_strings_compact`, the bridge falls back to `list_strings` or a wildcard `search_strings("")` call before applying `offset`/`limit`. Some environments may still return an empty catalog if upstream discovery is unavailable.
- Set `include_literals: true` to include the full normalized literal (without truncation) alongside the compact `s` preview.

### `search_strings`

See [Search endpoints](#search-endpoints) for shared pagination semantics. Query terms are matched server-side with no client-side filtering. Set `include_literals: true` to ask for full normalized string contents in addition to the compact snippet, which stays capped at 120 characters.

## Xref endpoints

### `search_xrefs_to`

Search for references pointing to a target address:

- Accepts `target`, `limit`, and `page` parameters plus a required **empty** `query` string. Non-empty queries return `400 Bad Request` because filtering is not supported upstream.
- Results include caller/callee metadata plus reference kinds and repeat the `target_address` on each item for clarity.
- Pagination mirrors other search endpoints with deterministic totals (`has_more` flips to `false` on the last page).
- Oversized windows (`page * limit` over the configured maximum, default `256`) fail fast with `413 Payload Too Large` so callers can retry with a smaller batch.

## Jump-table endpoints

### `jt_slot_check`

Validates a single pointer as ARM/Thumb (or none), enforcing `[code_min, code_max)`.

**Tip — Deriving CODE_MIN/MAX:** fetch segments from the plugin and choose the `.text`/code bounds.

### `jt_scan`

Batch over many slots; invariants:

- `summary.total == len(items)`
- `summary.valid + summary.invalid == summary.total`

## MMIO endpoint

### `mmio_annotate`

Annotates addresses for memory-mapped IO while respecting write guards:

- Requires explicit `addresses` and `annotation` payloads.
- Honors `dry_run` to preview changes without writes.
- When writes execute, they are limited by `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` and logged if `GHIDRA_MCP_AUDIT_LOG` is configured.

#### Response format

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

##### Fields

- `addr`: instruction address where the operation occurs
- `op`: operation type (READ, WRITE, OR, AND, TOGGLE)
- `target`: immediate value extracted from the instruction
- `address_abs`: **absolute address** for the operation
  - If `target` is a valid address (non-zero), uses `target`
  - Otherwise falls back to `addr` (the instruction address)
- `annotated`: number of comments actually written (0 when `dry_run: true`)
- `notes`: array of informational messages

##### Limits

- `max_samples`: max 8 (default), caps the number of sample operations returned
- Write operations require `dry_run: false` and `GHIDRA_MCP_ENABLE_WRITES=1`

## Data-type management API

The bridge exposes helper endpoints for creating, updating, and deleting structures and unions inside the active Ghidra program. All endpoints share the same safety model used elsewhere in the bridge: write operations are disabled by default, calls honour the per-request write counters, and every response is wrapped in the standard envelope returned by the API gateway.

Each route accepts a JSON payload that describes the type to manipulate and responds with a stable summary of the operation that was attempted. When `dry_run` is set to `true` (the default) no writes are forwarded to the Ghidra plugin. Clearing `dry_run` requires the server to be started with `GHIDRA_MCP_ENABLE_WRITES=1` and still consumes one write token from the current request scope.

### POST `/api/datatypes/create.json`

Create a new structure or union in the active project. The request schema is `datatypes_create.request.v1.json`.

```json
{
  "kind": "structure",
  "name": "Widget",
  "category": "/structs",
  "fields": [
    {"name": "id", "type": "uint32", "offset": 0, "length": 4},
    {"name": "flags", "type": "uint16", "offset": 4, "length": 2}
  ],
  "dry_run": false
}
```

Responses conform to `datatypes_create.v1.json` and always include the computed path, the normalised field list, and the inferred size (when available). During a dry run the `written` flag remains `false` and a note describing the simulated operation is included.

### POST `/api/datatypes/update.json`

Update an existing structure or union in-place. The request schema is `datatypes_update.request.v1.json` and requires the fully-qualified data-type path plus the new field definitions. Response envelopes follow `datatypes_update.v1.json` and echo the final layout reported by the plugin (or the requested layout if the plugin returned no additional metadata).

### POST `/api/datatypes/delete.json`

Delete a structure or union by path. The request schema is `datatypes_delete.request.v1.json` and the response schema is `datatypes_delete.v1.json`. Successful deletes set `written` to `true` and return the canonicalised `kind` and `path`. Dry runs add notes explaining that no data types were removed.

### Safety limits

All three routes share the standard per-request write guard. Each successful write consumes a single token and will raise an error if the configured limit is exceeded. The bridge will also reject attempts to proceed while writes are disabled, returning `WRITE_DISABLED` in the response envelope.

## `/api/analyze_function_complete.json`

### POST

**Summary:** analyze_function_route

#### Request body
- Declares: `http://json-schema.org/draft-07/schema#`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | string | Yes | pattern=^(0x)?[0-9a-fA-F]+$ |
| `fields` | array<string> | No |  |
| `fmt` | string | No | enum=['json'] |
| `max_result_tokens` | integer | No | min=0 |
| `options` | object | No |  |

```json
{
  "address": "string",
  "fields": [
    "function"
  ],
  "fmt": "json",
  "max_result_tokens": 0,
  "options": {
    "callgraph": {
      "limit": 0
    },
    "decompile": {
      "enabled": false,
      "max_lines": 0
    },
    "disasm": {
      "after": 0,
      "before": 0,
      "max_instructions": 0
    },
    "strings": {
      "limit": 0,
      "max_cstring_len": 0
    },
    "xrefs": {
      "inbound_limit": 0,
      "outbound_limit": 0
    }
  }
}
```

#### Responses
- `200` — Successful Response
  - Declares: `http://json-schema.org/draft-07/schema#`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `address` | string | Yes |  |
  | `callgraph` | object | No |  |
  | `decompile` | object | No |  |
  | `disasm` | object | No |  |
  | `features` | object | No |  |
  | `function` | object | No |  |
  | `meta` | object | Yes |  |
  | `strings` | object | No |  |
  | `xrefs` | object | No |  |

  ```json
  {
    "address": "string",
    "callgraph": {
      "callees": [
        {
          "address": "string",
          "name": "string",
          "type": "string"
        }
      ],
      "callers": [
        {
          "name": "string",
          "site": "string",
          "type": "string"
        }
      ]
    },
    "decompile": {
      "enabled": false,
      "error": "string",
      "lines": 0,
      "snippet": "string",
      "truncated": false
    },
    "disasm": {
      "after": 0,
      "before": 0,
      "center_index": 0,
      "max_instructions": 0,
      "total_instructions": 0,
      "truncated": false,
      "window": [
        {
          "address": "string",
          "bytes": "string",
          "is_target": false,
          "text": "string"
        }
      ]
    },
    "features": {
      "call_count": 0,
      "instruction_count": 0,
      "notes": [
        "string"
      ],
      "size_bytes": 0,
      "string_reference_count": 0,
      "xrefs_inbound_count": 0,
      "xrefs_outbound_count": 0
    },
    "function": {
      "address": "string",
      "comment": "string",
      "entry_point": "string",
      "name": "string",
      "range": {
        "end": "string",
        "start": "string"
      },
      "signature": "string"
    },
    "meta": {
      "estimate_tokens": 0,
      "fields": [
        "string"
      ],
      "fmt": "string",
      "max_result_tokens": 0,
      "truncated": false
    },
    "strings": {
      "items": [
        {
          "address": "string",
          "length": 0,
          "literal": "string",
          "source": "string"
        }
      ],
      "limit": 0,
      "source": "string"
    },
    "xrefs": {
      "inbound": [
        {
          "address": "string",
          "context": "string",
          "function": "string",
          "type": "string"
        }
      ],
      "outbound": [
        {
          "context": "string",
          "from_address": "string",
          "name": "string",
          "to_address": "string",
          "type": "string"
        }
      ],
      "summary": {
        "inbound": 0,
        "outbound": 0
      }
    }
  }
  ```

## `/api/capabilities.json`

### GET

**Summary:** capabilities

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:capabilities.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `endpoints` | array<object> | Yes |  |

  ```json
  {
    "endpoints": [
      {
        "budget_hint": "small",
        "category": "overview",
        "description": "string",
        "method": "string",
        "path": "string"
      }
    ]
  }
  ```

### HEAD

**Summary:** capabilities

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:capabilities.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `endpoints` | array<object> | Yes |  |

  ```json
  {
    "endpoints": [
      {
        "budget_hint": "small",
        "category": "overview",
        "description": "string",
        "method": "string",
        "path": "string"
      }
    ]
  }
  ```

## `/api/collect.json`

### POST

**Summary:** collect_route

#### Request body
- Schema ID: `urn:schema:collect.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `metadata` | object | No |  |
| `projects` | array<object> | No |  |
| `queries` | array<object> | No |  |
| `result_budget` | object | No |  |

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:collect.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `meta` | object | No |  |
  | `projects` | array<object> | No |  |
  | `queries` | array<object> | Yes |  |

  ```json
  {
    "meta": "\u2026",
    "projects": [
      "\u2026"
    ],
    "queries": [
      "\u2026"
    ]
  }
  ```

##### Query object

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | Yes | minLength=1 |
| `op` | string | Yes | minLength=1 |
| `params` | object | No | default={} |
| `result_budget` | object | No | See Result budget object |
| `max_result_tokens` | integer|null | No | min=0 |
| `metadata` | object | No | echoed in response |

##### Project object

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | Yes | minLength=1 |
| `queries` | array<query> | Yes | 1-256 entries |
| `result_budget` | object | No | See Result budget object |
| `metadata` | object | No | echoed in response |
| `ghidra_url` | string | No | alternate server base URL |
| `base_url` | string | No | legacy alias for ghidra_url |

##### Result budget object

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `max_result_tokens` | integer|null | No | min=0; null for unlimited |
| `mode` | string | No | enum=['auto_trim', 'strict']; default='auto_trim' |

#### Supported `op` values

- `disassemble_at` — Disassemble instructions at a single address. Required: address (hex). Optional: count (default 16).

  ```json
  {
    "id": "head",
    "op": "disassemble_at",
    "params": {
      "address": "0x401000",
      "count": 8
    }
  }
  ```

- `disassemble_batch` — Disassemble multiple addresses in one call. Required: addresses (array of hex strings). Optional: count (default 16).

  ```json
  {
    "id": "epilogue",
    "op": "disassemble_batch",
    "params": {
      "addresses": [
        "0x401000",
        "0x401020"
      ],
      "count": 4
    }
  }
  ```

- `read_bytes` — Read a raw byte window. Required: address (hex). Optional: length in bytes (default 64).

  ```json
  {
    "id": "bytes",
    "op": "read_bytes",
    "params": {
      "address": "0x401000",
      "length": 32
    }
  }
  ```

- `read_words` — Read machine words. Required: address (hex). Optional: count (default 1).

  ```json
  {
    "id": "words",
    "op": "read_words",
    "params": {
      "address": "0x401000",
      "count": 2
    }
  }
  ```

- `search_strings` — Search string literals. Required: query substring. Optional: limit (default 100) and page (default 1).

  ```json
  {
    "id": "long-strings",
    "op": "search_strings",
    "params": {
      "query": "init",
      "limit": 25
    }
  }
  ```

- `strings_compact` — List compact string summaries. Required: limit (>0). Optional: offset (default 0).

  ```json
  {
    "id": "strings",
    "op": "strings_compact",
    "params": {
      "limit": 100,
      "offset": 0
    }
  }
  ```

- `string_xrefs` — Lookup cross-references to a string. Required: string_addr (hex). Optional: limit (default 50).

  ```json
  {
    "id": "string-xrefs",
    "op": "string_xrefs",
    "params": {
      "string_addr": "0x500123",
      "limit": 10
    }
  }
  ```

- `search_imports` — Search imported symbols. Required: query substring. Optional: limit (default 100) and page (default 1).

  ```json
  {
    "id": "imports",
    "op": "search_imports",
    "params": {
      "query": "socket",
      "limit": 10
    }
  }
  ```

- `search_exports` — Search exported symbols. Required: query substring. Optional: limit (default 100) and page (default 1).

  ```json
  {
    "id": "exports",
    "op": "search_exports",
    "params": {
      "query": "init",
      "limit": 10
    }
  }
  ```

- `search_functions` — Search functions with optional ranking. Optional params: query text, limit/page (defaults 100/1), context_lines (0-16). Use rank='simple' with optional k, or resume_cursor for pagination (not both).

  ```json
  {
    "id": "init-funcs",
    "op": "search_functions",
    "params": {
      "query": "init",
      "limit": 20,
      "context_lines": 2
    }
  }
  ```

- `search_xrefs_to` — Search inbound references to an address. Required: address (hex). Optional: query, limit (default 100), page (default 1).

  ```json
  {
    "id": "xref",
    "op": "search_xrefs_to",
    "params": {
      "address": "0x401050",
      "limit": 50
    }
  }
  ```

- `search_scalars` — Search scalar values. Required: value (int or hex string). Optional: query label, limit/page (defaults 50/1), resume_cursor.

  ```json
  {
    "id": "scalars",
    "op": "search_scalars",
    "params": {
      "value": "0xDEADBEEF",
      "limit": 10
    }
  }
  ```

- `search_scalars_with_context` — Search scalars and include annotated disassembly context. Required: value. Optional: context_lines (0-16, default 4) and limit (default 25).

  ```json
  {
    "id": "scalar-context",
    "op": "search_scalars_with_context",
    "params": {
      "value": "0x8040123",
      "context_lines": 3
    }
  }
  ```

#### Example requests

**Search init functions & long strings**

```json
{
  "queries": [
    {
      "id": "init-funcs",
      "op": "search_functions",
      "params": {
        "query": "init",
        "limit": 20,
        "context_lines": 2
      },
      "result_budget": {
        "max_result_tokens": 600
      }
    },
    {
      "id": "long-strings",
      "op": "search_strings",
      "params": {
        "query": "initialization complete",
        "limit": 50
      }
    }
  ],
  "result_budget": {
    "max_result_tokens": 1500,
    "mode": "auto_trim"
  },
  "metadata": {
    "request": "search init functions & long strings"
  }
}
```

**Xref lookup + batch disassembly**

```json
{
  "queries": [
    {
      "id": "xref-to-target",
      "op": "search_xrefs_to",
      "params": {
        "address": "0x401050",
        "limit": 25
      }
    }
  ],
  "projects": [
    {
      "id": "linux-build",
      "ghidra_url": "http://ghidra.example.local:13100/",
      "queries": [
        {
          "id": "batch-disasm",
          "op": "disassemble_batch",
          "params": {
            "addresses": [
              "0x401050",
              "0x401060"
            ],
            "count": 8
          }
        }
      ],
      "result_budget": {
        "mode": "strict",
        "max_result_tokens": 800
      }
    }
  ],
  "result_budget": {
    "max_result_tokens": 2000
  }
}
```

## `/api/current_program.json`

### GET

**Summary:** current_program

#### Responses
- `200` — Successful Response
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `domain_file_id` | string | Yes |  |
  | `locked` | boolean | Yes |  |
  | `warnings` | array<string> | No |  |

  ```json
  {
    "domain_file_id": "string",
    "locked": false,
    "warnings": [
      "string"
    ]
  }
  ```

### HEAD

**Summary:** current_program

#### Responses
- `200` — Successful Response
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `domain_file_id` | string | Yes |  |
  | `locked` | boolean | Yes |  |
  | `warnings` | array<string> | No |  |

  ```json
  {
    "domain_file_id": "string",
    "locked": false,
    "warnings": [
      "string"
    ]
  }
  ```

## `/api/datatypes/create.json`

### POST

**Summary:** create_route

#### Request body
- Schema ID: `urn:schema:datatypes-create.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `category` | string | Yes |  |
| `dry_run` | boolean | No | default=True |
| `fields` | array<object> | Yes |  |
| `kind` | string | Yes | enum=['structure', 'union'] |
| `name` | string | Yes |  |

```json
{
  "category": "string",
  "dry_run": true,
  "fields": [
    "\u2026"
  ],
  "kind": "structure",
  "name": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:datatypes-create.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `datatype` | object | Yes |  |
  | `dry_run` | boolean | Yes |  |
  | `errors` | array<string> | Yes |  |
  | `kind` | string | Yes | enum=['structure', 'union'] |
  | `notes` | array<string> | Yes |  |
  | `path` | string | Yes | pattern=^/.* |
  | `transport_error` | object | No |  |
  | `written` | boolean | Yes |  |

  ```json
  {
    "datatype": {
      "category": "string",
      "fields": [
        "\u2026"
      ],
      "kind": "structure",
      "name": "string",
      "path": "string",
      "size": 0
    },
    "dry_run": false,
    "errors": [
      "string"
    ],
    "kind": "structure",
    "notes": [
      "string"
    ],
    "path": "string",
    "transport_error": {
      "reason": "string",
      "retryable": false,
      "status": 0
    },
    "written": false
  }
  ```

## `/api/datatypes/delete.json`

### POST

**Summary:** delete_route

#### Request body
- Schema ID: `urn:schema:datatypes-delete.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `dry_run` | boolean | No | default=True |
| `kind` | string | Yes | enum=['structure', 'union'] |
| `path` | string | Yes | pattern=^/.* |

```json
{
  "dry_run": true,
  "kind": "structure",
  "path": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:datatypes-delete.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `datatype` | object | Yes |  |
  | `dry_run` | boolean | Yes |  |
  | `errors` | array<string> | Yes |  |
  | `kind` | string | Yes | enum=['structure', 'union'] |
  | `notes` | array<string> | Yes |  |
  | `path` | string | Yes | pattern=^/.* |
  | `transport_error` | object | No |  |
  | `written` | boolean | Yes |  |

  ```json
  {
    "datatype": {
      "kind": "structure",
      "path": "string"
    },
    "dry_run": false,
    "errors": [
      "string"
    ],
    "kind": "structure",
    "notes": [
      "string"
    ],
    "path": "string",
    "transport_error": {
      "reason": "string",
      "retryable": false,
      "status": 0
    },
    "written": false
  }
  ```

## `/api/datatypes/update.json`

### POST

**Summary:** update_route

#### Request body
- Schema ID: `urn:schema:datatypes-update.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `dry_run` | boolean | No | default=True |
| `fields` | array<object> | Yes |  |
| `kind` | string | Yes | enum=['structure', 'union'] |
| `path` | string | Yes | pattern=^/.* |

```json
{
  "dry_run": true,
  "fields": [
    "\u2026"
  ],
  "kind": "structure",
  "path": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:datatypes-update.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `datatype` | object | Yes |  |
  | `dry_run` | boolean | Yes |  |
  | `errors` | array<string> | Yes |  |
  | `kind` | string | Yes | enum=['structure', 'union'] |
  | `notes` | array<string> | Yes |  |
  | `path` | string | Yes | pattern=^/.* |
  | `transport_error` | object | No |  |
  | `written` | boolean | Yes |  |

  ```json
  {
    "datatype": {
      "category": "string",
      "fields": [
        "\u2026"
      ],
      "kind": "structure",
      "name": "string",
      "path": "string",
      "size": 0
    },
    "dry_run": false,
    "errors": [
      "string"
    ],
    "kind": "structure",
    "notes": [
      "string"
    ],
    "path": "string",
    "transport_error": {
      "reason": "string",
      "retryable": false,
      "status": 0
    },
    "written": false
  }
  ```

## `/api/disassemble_at.json`

### POST

**Summary:** disassemble_at_route

#### Request body
- Schema ID: `urn:schema:disassemble-at.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `count` | integer | No | default=16, min=1, max=128 |

```json
{
  "address": "0x0",
  "count": 16
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:disassemble-at.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `items` | array<object> | Yes |  |

  ```json
  {
    "items": [
      {
        "address": "0x0",
        "bytes": "string",
        "text": "string"
      }
    ]
  }
  ```

## `/api/health.json`

### GET

**Summary:** health_route

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:health.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `ghidra` | object | Yes |  |
  | `service` | string | Yes |  |
  | `writes_enabled` | boolean | Yes |  |

  ```json
  {
    "ghidra": {
      "base_url": "string",
      "error": "string",
      "reachable": false,
      "status_code": 0
    },
    "service": "string",
    "writes_enabled": false
  }
  ```

### HEAD

**Summary:** health_route

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:health.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `ghidra` | object | Yes |  |
  | `service` | string | Yes |  |
  | `writes_enabled` | boolean | Yes |  |

  ```json
  {
    "ghidra": {
      "base_url": "string",
      "error": "string",
      "reachable": false,
      "status_code": 0
    },
    "service": "string",
    "writes_enabled": false
  }
  ```

## `/api/jt_scan.json`

### POST

**Summary:** jt_scan_route

#### Request body
- Schema ID: `urn:schema:jt-scan.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `arch` | string | No |  |
| `code_max` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `code_min` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `count` | integer | Yes | min=1, max=256 |
| `jt_base` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `start` | integer | Yes | min=0 |

```json
{
  "arch": "string",
  "code_max": "0x0",
  "code_min": "0x0",
  "count": 0,
  "jt_base": "0x0",
  "start": 0
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:jt-scan.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `items` | array<object> | Yes |  |
  | `range` | object | Yes |  |
  | `summary` | object | Yes |  |

  ```json
  {
    "items": [
      "\u2026"
    ],
    "range": {
      "count": 0,
      "start": 0
    },
    "summary": {
      "invalid": 0,
      "total": 0,
      "valid": 0
    }
  }
  ```

## `/api/jt_slot_check.json`

### POST

**Summary:** jt_slot_check_route

#### Request body
- Schema ID: `urn:schema:jt-slot-check.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `arch` | string | No |  |
| `code_max` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `code_min` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `jt_base` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `slot_index` | integer | Yes | min=0 |

```json
{
  "arch": "string",
  "code_max": "0x0",
  "code_min": "0x0",
  "jt_base": "0x0",
  "slot_index": 0
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:jt-slot-check.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `errors` | array<string> | Yes |  |
  | `mode` | string | Yes | enum=['ARM', 'Thumb', 'none'] |
  | `notes` | array<string> | No |  |
  | `raw` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
  | `slot` | integer | Yes | min=0 |
  | `slot_addr` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
  | `target` | object | Yes |  |

  ```json
  {
    "errors": [
      "string"
    ],
    "mode": "ARM",
    "notes": [
      "string"
    ],
    "raw": "0x0",
    "slot": 0,
    "slot_addr": "0x0",
    "target": "0x0"
  }
  ```

## `/api/jt_slot_process.json`

### POST

**Summary:** jt_slot_process_route

#### Request body
- Schema ID: `urn:schema:jt-slot-process.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `arch` | string | No |  |
| `code_max` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `code_min` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `comment` | string | No |  |
| `dry_run` | boolean | No |  |
| `jt_base` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `rename_pattern` | string | No |  |
| `slot_index` | integer | Yes | min=0 |

```json
{
  "arch": "string",
  "code_max": "0x0",
  "code_min": "0x0",
  "comment": "string",
  "dry_run": false,
  "jt_base": "0x0",
  "rename_pattern": "string",
  "slot_index": 0
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:jt-slot-process.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `errors` | array<string> | Yes |  |
  | `mode` | string | Yes | enum=['ARM', 'Thumb', 'none'] |
  | `notes` | array<string> | No |  |
  | `raw` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
  | `slot` | integer | Yes | min=0 |
  | `slot_addr` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
  | `target` | object | Yes |  |
  | `verify` | object | Yes |  |
  | `writes` | object | Yes |  |

  ```json
  {
    "errors": [
      "string"
    ],
    "mode": "ARM",
    "notes": [
      "string"
    ],
    "raw": "0x0",
    "slot": 0,
    "slot_addr": "0x0",
    "target": "0x0",
    "verify": {
      "comment_present": false,
      "name": "string"
    },
    "writes": {
      "comment_set": false,
      "renamed": false
    }
  }
  ```

## `/api/list_functions_in_range.json`

### POST

**Summary:** list_functions_in_range_route

#### Request body
- Schema ID: `urn:schema:list-functions-in-range.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address_max` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `address_min` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `limit` | integer | No | default=200, min=1, max=500 |
| `page` | integer | No | default=1, min=1 |

```json
{
  "address_max": "0x0",
  "address_min": "0x0",
  "limit": 200,
  "page": 1
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:list-functions-in-range.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `has_more` | boolean | Yes |  |
  | `items` | array<object> | Yes |  |
  | `limit` | integer | Yes | min=1 |
  | `page` | integer | Yes | min=1 |
  | `query` | string | Yes |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "has_more": false,
    "items": [
      {
        "address": "0x0",
        "name": "string",
        "size": 0
      }
    ],
    "limit": 0,
    "page": 0,
    "query": "string",
    "total": 0
  }
  ```

## `/api/mmio_annotate.json`

### POST

**Summary:** mmio_annotate_route

#### Request body
- Schema ID: `urn:schema:mmio-annotate.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `dry_run` | boolean | No |  |
| `function_addr` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `max_samples` | integer | No | min=1, max=256 |

```json
{
  "dry_run": false,
  "function_addr": "0x0",
  "max_samples": 0
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:mmio-annotate.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `annotated` | integer | Yes | min=0 |
  | `bitwise_and` | integer | Yes | min=0 |
  | `bitwise_or` | integer | Yes | min=0 |
  | `function` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
  | `notes` | array<string> | No |  |
  | `reads` | integer | Yes | min=0 |
  | `samples` | array<object> | Yes |  |
  | `toggles` | integer | Yes | min=0 |
  | `writes` | integer | Yes | min=0 |

  ```json
  {
    "annotated": 0,
    "bitwise_and": 0,
    "bitwise_or": 0,
    "function": "0x0",
    "notes": [
      "string"
    ],
    "reads": 0,
    "samples": [
      {
        "addr": "0x0",
        "address_abs": "0x0",
        "op": "READ",
        "target": "0x0"
      }
    ],
    "toggles": 0,
    "writes": 0
  }
  ```

## `/api/project_info.json`

### GET

**Summary:** project_info

#### Responses
- `200` — Successful Response
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `compiler_spec_id` | string | Yes |  |
  | `entry_points` | array<string> | Yes |  |
  | `executable_format` | string | No |  |
  | `executable_md5` | string | No |  |
  | `executable_path` | string | No |  |
  | `executable_sha256` | string | No |  |
  | `exports_count` | integer | Yes | min=0 |
  | `image_base` | string | Yes |  |
  | `imports_count` | integer | Yes | min=0 |
  | `language_id` | string | Yes |  |
  | `memory_blocks` | array<object> | Yes |  |
  | `program_name` | string | Yes |  |

  ```json
  {
    "compiler_spec_id": "string",
    "entry_points": [
      "string"
    ],
    "executable_format": "string",
    "executable_md5": "string",
    "executable_path": "string",
    "executable_sha256": "string",
    "exports_count": 0,
    "image_base": "string",
    "imports_count": 0,
    "language_id": "string",
    "memory_blocks": [
      {
        "end": "string",
        "initialized": false,
        "length": 0,
        "loaded": false,
        "name": "string",
        "rwx": "string",
        "start": "string"
      }
    ],
    "program_name": "string"
  }
  ```

### HEAD

**Summary:** project_info

#### Responses
- `200` — Successful Response
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `compiler_spec_id` | string | Yes |  |
  | `entry_points` | array<string> | Yes |  |
  | `executable_format` | string | No |  |
  | `executable_md5` | string | No |  |
  | `executable_path` | string | No |  |
  | `executable_sha256` | string | No |  |
  | `exports_count` | integer | Yes | min=0 |
  | `image_base` | string | Yes |  |
  | `imports_count` | integer | Yes | min=0 |
  | `language_id` | string | Yes |  |
  | `memory_blocks` | array<object> | Yes |  |
  | `program_name` | string | Yes |  |

  ```json
  {
    "compiler_spec_id": "string",
    "entry_points": [
      "string"
    ],
    "executable_format": "string",
    "executable_md5": "string",
    "executable_path": "string",
    "executable_sha256": "string",
    "exports_count": 0,
    "image_base": "string",
    "imports_count": 0,
    "language_id": "string",
    "memory_blocks": [
      {
        "end": "string",
        "initialized": false,
        "length": 0,
        "loaded": false,
        "name": "string",
        "rwx": "string",
        "start": "string"
      }
    ],
    "program_name": "string"
  }
  ```

## `/api/project_overview.json`

### GET

**Summary:** project_overview

#### Responses
- `200` — Successful Response
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `files` | array<object> | Yes |  |

  ```json
  {
    "files": [
      {
        "domain_file_id": "string",
        "name": "string",
        "path": "string",
        "size": 0,
        "type": "string"
      }
    ]
  }
  ```

### HEAD

**Summary:** project_overview

#### Responses
- `200` — Successful Response
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `files` | array<object> | Yes |  |

  ```json
  {
    "files": [
      {
        "domain_file_id": "string",
        "name": "string",
        "path": "string",
        "size": 0,
        "type": "string"
      }
    ]
  }
  ```

## `/api/project_rebase.json`

### POST

**Summary:** project_rebase

#### Request body
- Schema ID: `urn:schema:project-rebase.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `confirm` | boolean | No | default=False |
| `dry_run` | boolean | No | default=True |
| `new_base` | string | Yes | pattern=^(0x)?[0-9a-fA-F]+$ |

```json
{
  "confirm": false,
  "dry_run": true,
  "new_base": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:project-rebase.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `dry_run` | boolean | Yes |  |
  | `errors` | array<string> | Yes |  |
  | `notes` | array<string> | Yes |  |
  | `offset` | string | Yes | pattern=^-?0x[0-9a-fA-F]+$ |
  | `previous_base` | string | Yes | pattern=^-?0x[0-9a-fA-F]+$ |
  | `project_info` | object | Yes |  |
  | `rebased` | boolean | Yes |  |
  | `requested_base` | string | Yes | pattern=^-?0x[0-9a-fA-F]+$ |

  ```json
  {
    "dry_run": false,
    "errors": [
      "string"
    ],
    "notes": [
      "string"
    ],
    "offset": "string",
    "previous_base": "string",
    "project_info": {},
    "rebased": false,
    "requested_base": "string"
  }
  ```

## `/api/read_bytes.json`

### POST

**Summary:** read_bytes_route

#### Request body
- Schema ID: `urn:schema:read-bytes.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `include_literals` | boolean | No | default=False |
| `length` | integer | Yes | min=1, max=4096 |

```json
{
  "address": "0x0",
  "include_literals": false,
  "length": 0
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:read-bytes.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `address` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
  | `data` | string | Yes |  |
  | `encoding` | string | Yes | enum=['base64'] |
  | `length` | integer | Yes | min=0 |
  | `literal` | string | No |  |

  ```json
  {
    "address": "0x0",
    "data": "string",
    "encoding": "base64",
    "length": 0,
    "literal": "string"
  }
  ```

## `/api/search_exports.json`

### POST

**Summary:** search_exports_route

#### Request body
- Schema ID: `search_exports.request.v1.json`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | integer | No | default=100, min=1, max=1000 |
| `page` | integer | No | default=1, min=1 |
| `query` | string | Yes |  |

```json
{
  "limit": 100,
  "page": 1,
  "query": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `search_exports.v1.json`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `has_more` | boolean | Yes |  |
  | `items` | array<object> | Yes |  |
  | `limit` | integer | Yes | min=1 |
  | `page` | integer | Yes | min=1 |
  | `query` | string | Yes |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "has_more": false,
    "items": [
      {
        "address": "0x0",
        "name": "string"
      }
    ],
    "limit": 0,
    "page": 0,
    "query": "string",
    "total": 0
  }
  ```

## `/api/search_functions.json`

### POST

**Summary:** search_functions_route

#### Request body
- Schema ID: `search_functions.request.v1.json`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `context_lines` | integer | No | default=0, min=0, max=16 |
| `cursor` | string | No |  |
| `k` | integer | No | min=1 |
| `limit` | integer | No | default=100, min=1, max=500 |
| `page` | integer | No | default=1, min=1 |
| `query` | string | Yes |  |
| `rank` | string | No | enum=['simple'] |
| `resume_cursor` | string | No |  |

```json
{
  "context_lines": 0,
  "cursor": "string",
  "k": 0,
  "limit": 100,
  "page": 1,
  "query": "string",
  "rank": "simple",
  "resume_cursor": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `search_functions.v1.json`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `cursor` | string | No |  |
  | `has_more` | boolean | Yes |  |
  | `items` | array<object> | Yes |  |
  | `limit` | integer | Yes | min=1 |
  | `page` | integer | Yes | min=1 |
  | `query` | string | Yes |  |
  | `resume_cursor` | string | No |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "cursor": "string",
    "has_more": false,
    "items": [
      {
        "address": "0x0",
        "context": {
          "disassembly": [
            {
              "address": "\u2026",
              "bytes": "\u2026",
              "text": "\u2026"
            }
          ],
          "window": {
            "after": 0,
            "before": 0,
            "center": "0x0"
          }
        },
        "name": "string"
      }
    ],
    "limit": 0,
    "page": 0,
    "query": "string",
    "resume_cursor": "string",
    "total": 0
  }
  ```

## `/api/search_imports.json`

### POST

**Summary:** search_imports_route

#### Request body
- Schema ID: `search_imports.request.v1.json`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | integer | No | default=100, min=1, max=1000 |
| `page` | integer | No | default=1, min=1 |
| `query` | string | Yes |  |

```json
{
  "limit": 100,
  "page": 1,
  "query": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `search_imports.v1.json`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `has_more` | boolean | Yes |  |
  | `items` | array<object> | Yes |  |
  | `limit` | integer | Yes | min=1 |
  | `page` | integer | Yes | min=1 |
  | `query` | string | Yes |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "has_more": false,
    "items": [
      {
        "address": "0x0",
        "name": "string"
      }
    ],
    "limit": 0,
    "page": 0,
    "query": "string",
    "total": 0
  }
  ```

## `/api/search_scalars.json`

### POST

**Summary:** search_scalars_route

#### Request body
- Schema ID: `urn:schema:search-scalars.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `cursor` | string | No |  |
| `limit` | integer | No | default=100, min=1, max=500 |
| `page` | integer | No | default=1, min=1 |
| `resume_cursor` | string | No |  |
| `value` | object | Yes |  |

```json
{
  "cursor": "string",
  "limit": 100,
  "page": 1,
  "resume_cursor": "string",
  "value": "0x0"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:search-scalars.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `cursor` | string | No |  |
  | `has_more` | boolean | Yes |  |
  | `items` | array<object> | Yes |  |
  | `limit` | integer | Yes | min=1 |
  | `page` | integer | Yes | min=1 |
  | `query` | string | Yes |  |
  | `resume_cursor` | string | No |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "cursor": "string",
    "has_more": false,
    "items": [
      {
        "address": "0x0",
        "context": "string",
        "function": "string",
        "value": "0x0"
      }
    ],
    "limit": 0,
    "page": 0,
    "query": "string",
    "resume_cursor": "string",
    "total": 0
  }
  ```

## `/api/search_strings.json`

### POST

**Summary:** search_strings_route

#### Request body
- Schema ID: `urn:schema:search-strings.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `include_literals` | boolean | No | default=False |
| `limit` | integer | No | min=1 |
| `page` | integer | No | min=1 |
| `query` | string | Yes |  |

```json
{
  "include_literals": false,
  "limit": 0,
  "page": 0,
  "query": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:search-strings.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `has_more` | boolean | Yes |  |
  | `items` | array<object> | Yes |  |
  | `limit` | integer | Yes | min=1 |
  | `page` | integer | Yes | min=1 |
  | `query` | string | Yes |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "has_more": false,
    "items": [
      "\u2026"
    ],
    "limit": 0,
    "page": 0,
    "query": "string",
    "total": 0
  }
  ```

## `/api/search_xrefs_to.json`

### POST

**Summary:** search_xrefs_to_route

#### Request body
- Schema ID: `search_xrefs_to.request.v1.json`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `limit` | integer | No | default=100, min=1, max=1000 |
| `page` | integer | No | default=1, min=1 |
| `query` | string | Yes | default='' |

```json
{
  "address": "0x0",
  "limit": 100,
  "page": 1,
  "query": ""
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `search_xrefs_to.v1.json`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `has_more` | boolean | Yes |  |
  | `items` | array<object> | Yes |  |
  | `limit` | integer | Yes | min=1 |
  | `page` | integer | Yes | min=1 |
  | `query` | string | Yes |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "has_more": false,
    "items": [
      {
        "context": "string",
        "from_address": "0x0",
        "target_address": "0x0"
      }
    ],
    "limit": 0,
    "page": 0,
    "query": "string",
    "total": 0
  }
  ```

## `/api/select_program.json`

### POST

**Summary:** select_program

#### Request body
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `domain_file_id` | string | Yes |  |

```json
{
  "domain_file_id": "string"
}
```

#### Responses
- `200` — Successful Response
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `domain_file_id` | string | Yes |  |
  | `locked` | boolean | Yes |  |
  | `warnings` | array<string> | No |  |

  ```json
  {
    "domain_file_id": "string",
    "locked": false,
    "warnings": [
      "string"
    ]
  }
  ```

## `/api/string_xrefs.json`

### POST

**Summary:** string_xrefs_route

#### Request body
- Schema ID: `urn:schema:string-xrefs.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | integer | No | min=1, max=256 |
| `string_addr` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |

```json
{
  "limit": 0,
  "string_addr": "0x0"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:string-xrefs.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `callers` | array<object> | Yes |  |
  | `count` | integer | Yes | min=0 |
  | `string` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |

  ```json
  {
    "callers": [
      {
        "addr": "0x0",
        "arg_index": 0,
        "context": "string",
        "hint": "string"
      }
    ],
    "count": 0,
    "string": "0x0"
  }
  ```

## `/api/strings_compact.json`

### POST

**Summary:** strings_compact_route

#### Request body
- Schema ID: `urn:schema:strings-compact.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `include_literals` | boolean | No | default=False |
| `limit` | integer | Yes | min=0 |
| `offset` | integer | No | min=0 |

```json
{
  "include_literals": false,
  "limit": 0,
  "offset": 0
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:strings-compact.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `items` | array<object> | Yes |  |
  | `total` | integer | Yes | min=0 |

  ```json
  {
    "items": [
      {
        "addr": "0x0",
        "literal": "string",
        "refs": 0,
        "s": "string"
      }
    ],
    "total": 0
  }
  ```

## `/api/write_bytes.json`

### POST

**Summary:** write_bytes_route

#### Request body
- Schema ID: `urn:schema:write-bytes.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
| `data` | string | Yes |  |
| `dry_run` | boolean | No | default=True |
| `encoding` | string | No | default='base64', enum=['base64'] |

```json
{
  "address": "0x0",
  "data": "string",
  "dry_run": true,
  "encoding": "base64"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:write-bytes.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `address` | string | Yes | pattern=^0x[0-9a-fA-F]+$ |
  | `dry_run` | boolean | Yes |  |
  | `errors` | array<string> | Yes |  |
  | `length` | integer | Yes | min=0 |
  | `notes` | array<string> | Yes |  |
  | `written` | boolean | Yes |  |

  ```json
  {
    "address": "0x0",
    "dry_run": false,
    "errors": [
      "string"
    ],
    "length": 0,
    "notes": [
      "string"
    ],
    "written": false
  }
  ```

## `/state`

### GET

**Summary:** state

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:state.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `active_sse` | string | Yes |  |
  | `bridge_ready` | boolean | Yes |  |
  | `connects` | integer | Yes | min=0 |
  | `last_init_ts` | string | Yes |  |
  | `ready` | boolean | Yes |  |
  | `session_ready` | boolean | Yes |  |

  ```json
  {
    "active_sse": "string",
    "bridge_ready": false,
    "connects": 0,
    "last_init_ts": "string",
    "ready": false,
    "session_ready": false
  }
  ```

### HEAD

**Summary:** state

#### Responses
- `200` — Successful Response
  - Schema ID: `urn:schema:state.v1`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  | Field | Type | Required | Notes |
  | --- | --- | --- | --- |
  | `active_sse` | string | Yes |  |
  | `bridge_ready` | boolean | Yes |  |
  | `connects` | integer | Yes | min=0 |
  | `last_init_ts` | string | Yes |  |
  | `ready` | boolean | Yes |  |
  | `session_ready` | boolean | Yes |  |

  ```json
  {
    "active_sse": "string",
    "bridge_ready": false,
    "connects": 0,
    "last_init_ts": "string",
    "ready": false,
    "session_ready": false
  }
  ```
