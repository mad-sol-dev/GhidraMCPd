# Overview

The bridge provides a deterministic, LLM-friendly API over the Ghidra plugin:

- **Strict envelopes**: every response is `{ ok, data|null, errors[] }`.
- **Schemas & tests**: contract + golden tests guard drift.
- **Batching & pagination**: search endpoints expose 1-based `page`, `has_more`, and resume cursors (totals remain when determinable).
- **Safety**: write paths disabled by default; `dry_run` supported.

Use this when you need reliable, paginated, and schema-validated access to program analysis data.

## Current status snapshot

- **Delivered**: project metadata endpoint, composite function dossier, unified error envelopes, deterministic search pagination (with totals/1-based pages) and query/has_more metadata across range listings, SSE guardrails, MCP batch helpers for disassembly/memory/search, the multi-query collector (`POST /api/collect.json`) with request-level result budgeting and multi-program project lanes, opt-in function ranking with `rank=simple` + `k` prefiltering, `include_literals` support for memory and string search endpoints, a five-minute search cache keyed by `{program_digest, query, pagination}`, and the write/rebase/datatypes surfaces (`/api/write_bytes.json`, `/api/project_rebase.json`, `/api/datatypes/*`) behind dry-run aware safety checks.
- **Queued backlog**: {R.2} enhanced ranking/context windows, {R.4} expanded write/rebase/datatypes audit logging, {R.5} CORS/origin whitelists, {R.6} Docker/CI packaging, {R.7} MCP tool UX docs — see `.plan/TODO.md` for bucketed priority.
- **Ongoing**: compact listings continue to expose offset-based slicing while parity polish is scheduled under the backlog above.
