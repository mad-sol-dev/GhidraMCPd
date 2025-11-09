# API Reference

All endpoints use the envelope `{ok, data|null, errors[]}` and strict JSON schemas.

- `POST /api/search_strings.json`
- `POST /api/search_functions.json`
- `POST /api/search_imports.json`
- `POST /api/search_exports.json`
- `POST /api/search_xrefs_to.json`
- `POST /api/search_scalars.json`
- `POST /api/list_functions_in_range.json`
- `POST /api/disassemble_at.json`
- `POST /api/read_bytes.json`
- `POST /api/jt_slot_check.json`
- `POST /api/jt_scan.json`
- `POST /api/strings_compact.json`
- `POST /api/mmio_annotate.json`
- `GET /api/project_info.json`

See dedicated pages for parameters and invariants.

> OpenAPI: `GET /openapi.json`  
> **Conventions:** `data.total` is an integer; `data.page` is **1-based** on search endpoints.
