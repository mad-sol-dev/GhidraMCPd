# Search Endpoints

## Common semantics

- **Server-side filtering first** (no information loss), then pagination.
- Responses unify on: `query`, `total`, `page` (1-based), `limit`, `items`.

## Strings

`POST /api/search_strings.json`

```json
{ "query": "memcpy", "limit": 50, "page": 1 }
```

## Functions / Imports / Exports / Xrefs

Same shape; each filters in its domain. See OpenAPI for item fields.
