# Overview

The bridge provides a deterministic, LLM-friendly API over the Ghidra plugin:

- **Strict envelopes**: every response is `{ ok, data|null, errors[] }`.
- **Schemas & tests**: contract + golden tests guard drift.
- **Batching & pagination**: search endpoints return full totals and 1-based `page`.
- **Safety**: write paths disabled by default; `dry_run` supported.

Use this when you need reliable, paginated, and schema-validated access to program analysis data.

## Current status snapshot

- **Delivered**: project metadata endpoint, composite function dossier, unified error envelopes, deterministic search pagination (with totals/1-based pages) and query/has_more metadata across range listings, SSE guardrails, MCP batch helpers for disassembly/memory/search, the multi-query collector (`POST /api/collect.json`) with request-level result budgeting, and opt-in function ranking with `rank=simple` + `k` prefiltering.
- **In progress**: compact listings continue to expose offset-based slicing.
- **Planned**: cursor streaming/resume support and a 5-minute short-term cache per `{digest,query}`.
