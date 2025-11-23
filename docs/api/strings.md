# Strings Endpoints

## `strings_compact`

Returns a compact listing of program strings with deterministic ordering:

- Items contain `addr`, `s`, `length`, and encoding metadata.
- Results are bounded by `limit` and always include `total`/`page` metadata.
- Empty strings are omitted; ASCII/UTF-16 variants are normalized to UTF-8 output.
- Set `include_literals: true` to include the full normalized literal (without truncation) alongside the compact `s` preview.

## `search_strings`

See [Search](search.md) for shared pagination semantics. Query terms are matched server-side with no client-side filtering.
Set `include_literals: true` to ask for full normalized string contents in addition to the compact snippet, which stays capped at 120 characters.
