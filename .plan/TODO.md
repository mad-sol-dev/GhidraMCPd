# Ghidra MCP – TODO (authoritative)

> Goal: LLM-friendly, token-efficient server. Fewer round trips through Composite Ops and Multi-Query Collector.
> Standards: 1-based `page`, `has_more`, deterministic sorting, strict envelope `{ok,data,errors[]}`.

## NOW
- [ ] D.1 GET /api/project_info.json (read-only)
  DoD: LanguageID, CompilerSpec, ImageBase, Entry, Memory-Blocks(+rwx), Imports/Exports-Counts; sort by start; Unit/Contract/Golden.
- [ ] D.2 POST /api/analyze_function_complete.json (read-only)
  DoD: Aggregates Disasm(±N), Strings(xN), Xrefs in/out, Callers/Callees(r1), feature sketch; `fields`, `fmt`, `max_result_tokens`; deterministic order; tests+Golden.
- [ ] D.3 Unify search metadata
  DoD: All search endpoints return {query,total,page,limit,has_more,items}; 1-based `page`; edge case tests (0/limit/last).

## NEXT
- [ ] D.4 POST /api/collect.json (multi-query collector, read-only)
  DoD: `queries[]` (multiple sub-ops) in one call; shortened by budget if necessary; each sub-result with its own envelope; tests.
- [ ] D.5 Error schema + enums
  DoD: `errors[]` entries = {status, code, message, recovery[]}; Enums: INVALID_REQUEST, RESULT_TOO_LARGE, NOT_READY, SSE_CONFLICT, TOO_MANY_REQUESTS, INTERNAL, UNAVAILABLE; Golden examples.
- [ ] D.6 Result budgeting (server-side)
  DoD: `max_result_tokens` (hard), `result_budget.mode=auto_trim|strict`; Response carries `estimate_tokens`, `truncated`, `resume_cursor?`; Docs+tests.

## LATER
- [ ] D.7 rank=simple & k (heuristic prefilter, opt-in)
- [ ] D.8 Cursor streaming for very large sets
- [ ] D.9 5-min short-term cache per {digest,query}

## Invariants
- CI green (Unit/Contract/Golden), OpenAPI drift-free.
- Breaking defaults only via minor bump.
