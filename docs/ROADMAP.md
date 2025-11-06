# Roadmap: from data bridge to a token‑efficient analysis server

This document tracks where Ghidra MCPd is today and what comes next. The original problem statement (filter after paginate, high token spend, unclear readiness) has been addressed in Phase 1. The next phases focus on ranking, payload reduction, and developer ergonomics.

## Executive summary

* Historical issue: many list endpoints filtered after pagination. That produced incomplete searches and pushed cost to the LLM.
* Current state: search‑before‑paginate exists for the major entities, batch operations and context‑aware tools are available, and streaming/readiness semantics are explicit. API docs can be generated from the live OpenAPI.
* Next steps: unify response metadata across all search endpoints, add optional relevance scoring, and harden performance and DX.

---

## Status snapshot

* [x] Server‑side search endpoints for major entities

  * strings, functions, imports, exports, xrefs, scalars
* [x] Batch operations

  * `disassemble_batch`, `read_words`
* [x] Context‑aware search

  * `search_scalars_with_context` with server‑side windowing
* [x] Deterministic envelopes and strict schemas

  * `{ok, data, errors[]}`, JSON Schema with `additionalProperties: false`
* [x] Streaming and readiness semantics

  * single active `GET /sse` (second returns 409), `POST /sse` returns 405, early calls may return 425 until session is ready
* [x] Observability and guard rails

  * `/state` readiness and counters, safety limits, write guards (`ENABLE_WRITES`, `dry_run`)
* [x] API documentation generator

  * `scripts/gen_api_md.py` renders `docs/api.md` from `/openapi.json`
* [ ] Response‑level metadata

  * ensure consistent `total` and introduce `has_more` across all search endpoints
* [ ] Lightweight relevance scoring

  * optional `score` field and stable ordering, with an `explain` toggle for debugging

---

## Phase 1 – complete and to be finalized

Goal: make server responses correct, discoverable, and cheap without changing the plugin fundamentals.

1. Search‑before‑paginate model

* Implemented for key entities (strings, functions, imports, exports, xrefs, scalars).
* Follow ups:

  * Normalize response metadata across all search endpoints: `query`, `total`, `page` (1‑based), `limit`, `items`.
  * Add `has_more` for simple forward pagination and document the contract in `docs/api.md`.

2. Batch and windowing

* Implemented (`disassemble_batch`, `read_words`, windowed scalar search).
* Follow ups:

  * Enforce clear batch caps in configuration and document defaults in `docs/getting-started.md`.

3. Deterministic contracts and limits

* Implemented (envelopes, safety limits).
* Follow ups:

  * Consolidate error type documentation and link from troubleshooting and server docs.

4. Streaming and readiness

* Implemented (single SSE, readiness gate).
* Follow ups:

  * Add a short client example for reconnect backoff to `docs/server.md`.

---

## Phase 2 – relevance and payload reduction

Goal: return only what a client likely needs, in a ranked and auditable form.

* Relevance scoring (optional)

  * Add `score` when a query is present. Provide `rank` options: `none` (default), `simple` (term frequency and proximity), `strict` (deterministic tie‑breaking).
  * Keep off by default to preserve baseline determinism.

* Explain mode (optional)

  * `explain=true` adds a minimal `why` object per item for debugging and tests.
  * Hard size caps so explain cannot grow payloads unbounded.

* Sampling and caps

  * `top_k` and `tail_k` for large match sets.
  * Document interaction with `limit`, `offset`, `total`, and `has_more`.

---

## Phase 3 – performance and ops

Goal: keep latency and cost low at scale while staying predictable.

* Cache common lookups (LRU or TTL) with explicit invalidation hooks.
* Expose metrics counters for batch sizes, skipped items, and limit hits in `/state`.
* Backpressure and rate limits for chatty clients, with clear error messages.

---

## Phase 4 – developer experience

Goal: make integration and debugging straightforward.

* Thin client helpers

  * Minimal CLI or Python helper that opens SSE, waits for readiness, and calls tools.
* Examples

  * 2 to 3 short end‑to‑end examples under `examples/` showing search -> batch read -> disassemble window.
* Docs automation

  * CI step that regenerates `docs/api.md` from `/openapi.json` and fails on drift.

---

## Compatibility and versioning

* OpenAPI for core fields is currently frozen to avoid churn. Additive changes are allowed. Removing or renaming fields requires a minor version bump.
* If relevance scoring is enabled by default in the future, ship a minor bump and provide a `rank=none` escape hatch.

---

## Appendix – endpoint coverage checklist

This table tracks search metadata and future relevance hooks.

| Endpoint                          | Search before paginate | `total` field | `has_more` field | scoring/explain |
| --------------------------------- | ---------------------- | ------------- | ---------------- | --------------- |
| /api/search_strings.json          | yes                    | yes           | planned          | planned         |
| /api/search_functions.json        | yes                    | yes           | planned          | planned         |
| /api/search_imports.json          | yes                    | yes           | planned          | planned         |
| /api/search_exports.json          | yes                    | yes           | planned          | planned         |
| /api/search_xrefs_to.json         | yes                    | yes           | planned          | planned         |
| /api/search_scalars.json          | yes                    | yes           | planned          | planned         |
| /api/list_functions_in_range.json | partial                | n/a           | n/a              | n/a             |

Notes:

* `total` and `page` already appear in responses for the search endpoints above; add `has_more` for clarity and consistency.
* Non‑search endpoints like `disassemble_at.json` are not applicable for these fields.

