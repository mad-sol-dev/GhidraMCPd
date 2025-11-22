# Search Endpoints

## Common semantics

- **Server-side filtering first** (no information loss), then pagination.
- Responses unify on: `query`, `total`, `page` (1-based), `limit`, `items`, `has_more`.

## Strings

`POST /api/search_strings.json`

```json
{ "query": "memcpy", "limit": 50, "page": 1 }
```

## Functions / Imports / Exports / Xrefs

Same shape; each filters in its domain. See OpenAPI for item fields.

## Scalars

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

## Functions in Range

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

## Disassemble At

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

## Read Bytes

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

## Wildcard Queries

The following endpoints support wildcard queries (return all items without filtering):
- `search_functions`: use `query: "*"` or `query: ""`

`search_xrefs_to` now requires a non-empty `query` string. Requests with empty or
wildcard queries are rejected with `400` to encourage intentional filtering.
