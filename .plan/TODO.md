# Ghidra MCP – TODO (authoritative)

> Goal: LLM-friendly, token-efficient server. Fewer round trips through Composite Ops and Multi-Query Collector.
> Standards: 1-based `page`, `has_more`, deterministic sorting, strict envelope `{ok,data,errors[]}`.

## NOW
- {D.3} Unify search metadata
  DoD: All search endpoints return {query,total,page,limit,has_more,items}; 1-based `page`; edge case tests (0/limit/last).

## NEXT
- {D.4} POST /api/collect.json (multi-query collector, read-only)
  DoD: `queries[]` (multiple sub-ops) in one call; shortened by budget if necessary; each sub-result with its own envelope; tests.
- {D.6} Result budgeting (server-side)
  DoD: `max_result_tokens` (hard), `result_budget.mode=auto_trim|strict`; Response carries `estimate_tokens`, `truncated`, `resume_cursor?`; Docs+tests.

## LATER
- {D.7} rank=simple & k (heuristic prefilter, opt-in)
- {D.8} Cursor streaming for very large sets
- {D.9} 5-min short-term cache per {digest,query}

## DONE
- [x] {D.1} GET /api/project_info.json (read-only) — deterministic metadata envelope, contract/unit coverage, docs snapshot updated.
- [x] {D.2} POST /api/analyze_function_complete.json (read-only) — composite dossier (`fields`, `fmt`, `max_result_tokens`, disasm/decompile/xrefs/callgraph/strings/features) with deterministic ordering, unit/contract/golden coverage, docs updated.
- [x] {D.5} Error schema + enums — unified error envelope `{status,code,message,recovery[]}`, updated docs, contract/unit/golden coverage.

## Invariants
- CI green (Unit/Contract/Golden), OpenAPI drift-free.
- Breaking defaults only via minor bump.
