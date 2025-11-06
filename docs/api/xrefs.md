# Xref Endpoints

## `search_xrefs_to`

Search for references pointing to a target address:

- Accepts `target`, `limit`, and `page` parameters.
- Results include caller/callee metadata plus reference kinds and repeat the `target_address` on each item for clarity.
- Pagination mirrors other search endpoints with deterministic totals (`has_more` flips to `false` on the last page).
