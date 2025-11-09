# Ghidra MCPd API reference

_Source: bridge/tests/golden/data/openapi_snapshot.json — Ghidra MCP Bridge API v1.0.0_

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

## `/api/disassemble_at.json`

### POST

**Summary:** disassemble_at_route

## `/api/health.json`

### GET

**Summary:** health_route

### HEAD

**Summary:** health_route

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
