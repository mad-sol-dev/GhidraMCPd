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
