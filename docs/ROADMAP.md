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
- Cursor streaming for large sets (pending — no cursor/resume plumbing yet)
- 5-minute short-term cache per {digest,query}

## Principles
- Defaults remain compatible; new features are opt-in.
- Deterministic sorting & stable envelopes.
- Cost control is **server-side** – clients/LLMs do not need to predict anything.
