# API Reference

All endpoints use the envelope `{ok, data|null, errors[]}` and strict JSON schemas.

- `POST /api/search_strings.json`
- `POST /api/search_functions.json`
- `POST /api/search_imports.json`
- `POST /api/search_exports.json`
- `POST /api/search_xrefs_to.json`
- `POST /api/jt_slot_check.json`
- `POST /api/jt_scan.json`
- `POST /api/strings_compact.json`
- `POST /api/mmio_annotate.json`

See dedicated pages for parameters and invariants.

> OpenAPI: `GET /openapi.json`  
> **Conventions:** `data.total` is an integer; `data.page` is **1-based** on search endpoints.
