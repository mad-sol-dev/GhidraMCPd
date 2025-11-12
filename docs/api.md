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
| `length` | integer | Yes | min=1, max=4096 |

```json
{
  "address": "0x0",
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

  ```json
  {
  "address": "0x0",
  "data": "string",
  "encoding": "base64",
  "length": 0
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
| `cursor` | string | No |  |
| `k` | integer | No | min=1 |
| `limit` | integer | No | default=100, min=1, max=500 |
| `page` | integer | No | default=1, min=1 |
| `query` | string | Yes |  |
| `rank` | string | No | enum=['simple'] |
| `resume_cursor` | string | No |  |

```json
{
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
| `limit` | integer | No | min=1 |
| `page` | integer | No | min=1 |
| `query` | string | Yes |  |

```json
{
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
| `query` | string | Yes |  |

```json
{
  "address": "0x0",
  "limit": 100,
  "page": 1,
  "query": "string"
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
| `limit` | integer | Yes | min=1 |
| `offset` | integer | No | min=0 |

```json
{
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
