# Ghidra MCP – TODO (authoritative)

> Goal: LLM-friendly, token-efficient server. Fewer round trips through Composite Ops and Multi-Query Collector.
> Standards: 1-based `page`, `has_more`, deterministic sorting, strict envelope `{ok,data,errors[]}`.

## NOW
- _None (tracking downstream follow-ups)._ 

## NEXT
- _None (blocked on later roadmap items)._ 

## LATER
- {D.7} rank=simple & k (heuristic prefilter, opt-in)
- {D.8} Cursor streaming for very large sets — revert to todo until cursor/resume plumbing lands
- {D.9} 5-min short-term cache per {digest,query}

## DONE
- [x] {D.1} GET /api/project_info.json (read-only) — deterministic metadata envelope, contract/unit coverage, docs snapshot updated.
- [x] {D.2} POST /api/analyze_function_complete.json (read-only) — composite dossier (`fields`, `fmt`, `max_result_tokens`, disasm/decompile/xrefs/callgraph/strings/features) with deterministic ordering, unit/contract/golden coverage, docs updated.
- [x] {D.5} Error schema + enums — unified error envelope `{status,code,message,recovery[]}`, updated docs, contract/unit/golden coverage.
- [x] {D.3} Unify search metadata — {query,total,page,limit,has_more,items} now consistent across list/search endpoints (range + pagination edge cases covered).
- [x] {D.4} POST /api/collect.json — multi-query collector with per-subop envelopes, request budgeting, docs/tests updated.
- [x] {T-202511-018} Sync roadmap + plan docs with audit — ROADMAP.md updated, `.plan` statuses aligned, overview captures current capabilities.
- [x] {D.6} Result budgeting — request/query `max_result_tokens`, auto-trim (200) vs strict (413) enforcement, coverage + docs refreshed.
- [x] OpenAPI renderer fixed — gen_api_md.py handles 3.1 unions/combinators, docs regenerated.
- [x] Maven deps via GHIDRA_DIR — CI downloads Ghidra, pom.xml uses GHIDRA_DIR system paths, docs note local build.

## Invariants
- CI green (Unit/Contract/Golden), OpenAPI drift-free.
- Breaking defaults only via minor bump.
