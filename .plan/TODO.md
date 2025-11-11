# Ghidra MCP – TODO (authoritative)

> Goal: LLM-friendly, token-efficient server. Fewer round trips through Composite Ops and Multi-Query Collector.
> Standards: 1-based `page`, `has_more`, deterministic sorting, strict envelope `{ok,data,errors[]}`.

## NOW
- {R.1} Batch project analysis lanes for multi-program dossiers
- {R.2} Enhanced search ranking + expanded context windows

## NEXT
- {R.3} `include_literals` plumbing across read/search APIs
- {R.4} Expanded audit logging for write/rebase/datatypes flows

## LATER
- {R.5} CORS/origin whitelist controls for bridge endpoints
- {R.6} Docker images + CI packaging handoff
- {R.7} MCP tool UX docs (flows, screenshots, failure drills)

## DONE
- [x] {D.1} GET /api/project_info.json (read-only) — deterministic metadata envelope, contract/unit coverage, docs snapshot updated.
- [x] {D.2} POST /api/analyze_function_complete.json (read-only) — composite dossier (`fields`, `fmt`, `max_result_tokens`, disasm/decompile/xrefs/callgraph/strings/features) with deterministic ordering, unit/contract/golden coverage, docs updated.
- [x] {D.5} Error schema + enums — unified error envelope `{status,code,message,recovery[]}`, updated docs, contract/unit/golden coverage.
- [x] {D.3} Unify search metadata — {query,total,page,limit,has_more,items} now consistent across list/search endpoints (range + pagination edge cases covered).
- [x] {D.4} POST /api/collect.json — multi-query collector with per-subop envelopes, request budgeting, docs/tests updated.
- [x] {T-202511-018} Sync roadmap + plan docs with audit — ROADMAP.md updated, `.plan` statuses aligned, overview captures current capabilities.
- [x] {D.6} Result budgeting — request/query `max_result_tokens`, auto-trim (200) vs strict (413) enforcement, coverage + docs refreshed.
- [x] {D.7} rank=simple & k — heuristic prefilter enabled as opt-in, stable ordering, docs/tests added.
- [x] {D.8} Cursor streaming for very large sets — cursor/resume plumbing landed with docs/tests.
- [x] {D.9} 5-min short-term cache per {digest,query}.
- [x] OpenAPI renderer fixed — gen_api_md.py handles 3.1 unions/combinators, docs regenerated.
- [x] Maven deps via GHIDRA_DIR — CI downloads Ghidra, pom.xml uses GHIDRA_DIR system paths, docs note local build.

## Invariants
- CI green (Unit/Contract/Golden), OpenAPI drift-free.
- Breaking defaults only via minor bump.
