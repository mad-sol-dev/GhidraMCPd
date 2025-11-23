# Xref Endpoints

## `search_xrefs_to`

Search for references pointing to a target address:

- Accepts `target`, `limit`, and `page` parameters plus a required **empty** `query` string. Non-empty queries return `400 Bad Request` because filtering is not supported upstream.
- Results include caller/callee metadata plus reference kinds and repeat the `target_address` on each item for clarity.
- Pagination mirrors other search endpoints with deterministic totals (`has_more` flips to `false` on the last page).
- Oversized windows (`page * limit` over the configured maximum, default `256`) fail fast with `413 Payload Too Large` so callers can retry with a smaller batch.
