# Ghidra MCPd API reference

_Source: bridge/tests/golden/data/openapi_snapshot.json — Ghidra MCP Bridge API v1.0.0_

## `/api/disassemble_at.json`

### POST

**Summary:** disassemble_at_route

## `/api/health.json`

### GET

**Summary:** health_route

### HEAD

**Summary:** health_route

## `/api/project_info.json`

### GET

**Summary:** project_info

#### Responses
- `200` — Successful Response
  - Schema ID: `project_info.v1.json`
  - Declares: `https://json-schema.org/draft/2020-12/schema`

  ```json
  {
    "program_name": "stub_program",
    "executable_path": "/opt/programs/stub_program.bin",
    "executable_md5": "0123456789abcdef0123456789abcdef",
    "executable_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "executable_format": "ELF",
    "image_base": "0x00100000",
    "language_id": "ARM:LE:32:v7",
    "compiler_spec_id": "default",
    "entry_points": [
      "0x00100000"
    ],
    "memory_blocks": [
      {
        "name": ".text",
        "start": "0x00100000",
        "end": "0x0010ffff",
        "length": 65536,
        "rwx": "r-x",
        "loaded": true,
        "initialized": true
      }
    ],
    "imports_count": 24,
    "exports_count": 24
  }
  ```

### HEAD

**Summary:** project_info

## `/api/jt_scan.json`

### POST

**Summary:** jt_scan_route

## `/api/jt_slot_check.json`

### POST

**Summary:** jt_slot_check_route

## `/api/jt_slot_process.json`

### POST

**Summary:** jt_slot_process_route

## `/api/list_functions_in_range.json`

### POST

**Summary:** list_functions_in_range_route

## `/api/mmio_annotate.json`

### POST

**Summary:** mmio_annotate_route

#### Request body
- Schema ID: `mmio_annotate.request.v1.json`

```json
{
  "function_addr": "0x00007000",
  "dry_run": true,
  "max_samples": 4
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `mmio_annotate.v1.json`

  ```json
  {
    "function": "0x00007000",
    "annotated": 2,
    "samples": [
      {
        "address": "0x00007008",
        "comment": "write32: base=0x40010000 offset=0x20"
      }
    ],
    "notes": [
      "dry-run: no comments written"
    ]
  }
  ```

## `/api/analyze_function_complete.json`

### POST

**Summary:** analyze_function_complete_route

#### Request body
- Schema ID: `analyze_function_complete.request.v1.json`

```json
{
  "address": "0x00102004",
  "fields": [
    "function",
    "disasm",
    "decompile",
    "xrefs",
    "callgraph",
    "strings",
    "features"
  ],
  "options": {
    "disasm": {"before": 8, "after": 8},
    "xrefs": {"inbound_limit": 32, "outbound_limit": 32},
    "strings": {"limit": 6},
    "decompile": {"max_lines": 80}
  }
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `analyze_function_complete.v1.json`

  ```json
  {
    "address": "0x00102004",
    "function": {
      "name": "sub_102004",
      "entry_point": "0x00102004",
      "address": "0x00102004",
      "signature": "int sub_102004(void)",
      "comment": "initial",
      "range": {
        "start": "0x00102004",
        "end": "0x0010201f"
      }
    },
    "disasm": {
      "before": 8,
      "after": 8,
      "max_instructions": 48,
      "window": [
        {
          "address": "0x00102004",
          "bytes": "PUSH",
          "text": "PUSH {r4, lr}",
          "is_target": true
        },
        {
          "address": "0x00102008",
          "bytes": "BL",
          "text": "BL jump_table_target",
          "is_target": false
        }
      ],
      "total_instructions": 12,
      "center_index": 0,
      "truncated": false
    },
    "decompile": {
      "enabled": true,
      "snippet": "int sub_102004(void)\n{\n    return 0;\n}",
      "lines": 4,
      "truncated": false,
      "error": null
    },
    "xrefs": {
      "inbound": [
        {
          "address": "0x00005000",
          "type": "CALL",
          "function": "caller_one",
          "context": "00005000 in caller_one [CALL]"
        }
      ],
      "outbound": [
        {
          "from_address": "0x00102008",
          "to_address": "0x00006000",
          "name": "target",
          "type": "BL",
          "context": "BL target"
        }
      ],
      "summary": {
        "inbound": 1,
        "outbound": 1
      }
    },
    "callgraph": {
      "callers": [
        {"name": "caller_one", "site": "0x00005000", "type": "CALL"}
      ],
      "callees": [
        {"name": "target", "address": "0x00006000", "type": "BL"}
      ]
    },
    "strings": {
      "items": [
        {
          "address": "0x00200000",
          "source": "0x0010200C",
          "literal": "Diagnostic mode enabled",
          "length": 25
        }
      ],
      "limit": 6,
      "source": "disassembly_literals"
    },
    "features": {
      "instruction_count": 12,
      "call_count": 1,
      "string_reference_count": 1,
      "xrefs_inbound_count": 1,
      "xrefs_outbound_count": 1,
      "size_bytes": 28,
      "notes": []
    },
    "meta": {
      "fields": [
        "callgraph",
        "decompile",
        "disasm",
        "features",
        "function",
        "strings",
        "xrefs"
      ],
      "fmt": "json",
      "max_result_tokens": null,
      "estimate_tokens": 112,
      "truncated": false
    }
  }
  ```

## `/api/read_bytes.json`

### POST

**Summary:** read_bytes_route

## `/api/search_exports.json`

### POST

**Summary:** search_exports_route

#### Request body
- Schema ID: `search_exports.request.v1.json`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | integer | No | default=100, min=1, max=1000 |
| `offset` | integer | No | default=0, min=0 |
| `query` | string | Yes |  |

```json
{
  "limit": 100,
  "offset": 0,
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
| `limit` | integer | No | default=100, min=1, max=500 |
| `offset` | integer | No | default=0, min=0 |
| `query` | string | Yes |  |

```json
{
  "limit": 100,
  "offset": 0,
  "query": "string"
}
```

#### Responses
- `200` — Successful Response
  - Schema ID: `search_functions.v1.json`
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

## `/api/search_imports.json`

### POST

**Summary:** search_imports_route

#### Request body
- Schema ID: `search_imports.request.v1.json`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | integer | No | default=100, min=1, max=1000 |
| `offset` | integer | No | default=0, min=0 |
| `query` | string | Yes |  |

```json
{
  "limit": 100,
  "offset": 0,
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

## `/api/search_strings.json`

### POST

**Summary:** search_strings_route

#### Request body
- Schema ID: `urn:schema:search-strings.request.v1`
- Declares: `https://json-schema.org/draft/2020-12/schema`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `limit` | integer | No | min=1 |
| `offset` | integer | No | min=0 |
| `query` | string | Yes |  |

```json
{
  "limit": 0,
  "offset": 0,
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

## `/api/string_xrefs.json`

### POST

**Summary:** string_xrefs_route

## `/api/strings_compact.json`

### POST

**Summary:** strings_compact_route

## `/state`

### GET

**Summary:** state

### HEAD

**Summary:** state
