# Roadmap (focused on LLM efficiency)

## Phase 1 – Correctness & consistency (now)
- ✅ GET /api/project_info.json
- ✅ Unify search metadata ({query,total,page,limit,has_more,items}, page=1-based) — `list_functions_in_range` now aligned; compact listings continue to rely on offsets
- ✅ Unified error schema + enums
- OpenAPI snapshots drift-free

## Phase 2 – Fewer Round Trips (Composite & Collector)
- ✅ POST /api/analyze_function_complete.json (read-only, server-side aggregation)
- ✅ POST /api/collect.json (multi-query collector for multiple read-only sub-ops)
- ✅ Result budgeting (server-side): `max_result_tokens`, `result_budget.mode=auto_trim|strict`
  - **auto_trim:** 200 OK, per-subop envelope flagged with `truncated=true`, `estimate_tokens`, and budgeting notes.
  - **strict:** 413 RESULT_TOO_LARGE response with recovery hints (reduce fields/limit/k).

## Phase 3 – Relevance & Scaling
- ✅ rank=simple & k (opt-in)
- ✅ Cursor streaming for large sets (cursor/resume plumbing + docs/tests)
- ✅ 5-minute short-term cache per {digest,query}
- ✅ Batch project analysis lanes (multi-program collector envelopes)

## Post-Phase 3 – Delivery & Hardening

### Recently completed
- ✅ `/api/write_bytes.json` end-to-end write support with dry-run safety guardrails — gated by `GHIDRA_MCP_ENABLE_WRITES` and capped via `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` (see [getting started](docs/getting-started.md#configuration)).
- ✅ `/api/project_rebase.json` activation path, including `confirm=true` handshake and `GHIDRA_MCP_ENABLE_PROJECT_REBASE` opt-in (documented in [getting started](docs/getting-started.md#configuration)).
- ✅ `/api/datatypes/*` surfacing for structure/enum introspection alongside deterministic pagination (see [API reference](docs/api.md)).

### Upcoming milestones
- Search ranking & context tuning
  - Adjustable ranking strategies and context windows, with explicit `rank` + `k` defaults spelled out in [docs/api.md](docs/api.md), and batch-size guardrails tied to `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` (see [getting started](docs/getting-started.md#batch-limits-defaults)).
- Deployment hardening
  - Official Docker image & origin whitelist support (`GHIDRA_MCP_ALLOWED_ORIGINS`) documented alongside TLS/reverse-proxy recipes in [docs/getting-started.md](docs/getting-started.md) and [README.md](../README.md).
- LLM-facing usability
  - Surface batching helpers (`include_literals`, composite search envelopes) inside client recipes with updated token budgeting notes referencing [docs/getting-started.md](docs/getting-started.md#batch-limits-defaults).
- Audit logging & observability
  - Expand JSONL emitters beyond `GHIDRA_MCP_AUDIT_LOG`, including per-endpoint counters and batch-orchestration traces for `/api/write_bytes.json`, `/api/project_rebase.json`, and `/api/datatypes/*`.

## Principles
- Defaults remain compatible; new features are opt-in.
- Deterministic sorting & stable envelopes.
- Cost control is **server-side** – clients/LLMs do not need to predict anything.
