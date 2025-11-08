# TODO (authoritative)

Goal: Streamlined composite operations and batch collector improvements for an LLM-friendly server.

## NOW

- [ ] D.1 GET /api/project_info.json — expose read-only program metadata (LanguageID, CompilerSpec, ImageBase, Entry, Memory Blocks with permissions, import/export counts) sorted by start; cover unit, contract, and golden tests.
- [ ] D.2 POST /api/analyze_function_complete.json — aggregate disassembly windows, strings, inbound/outbound xrefs, immediate callers/callees, and feature sketch with deterministic ordering and coverage for `fields`, `fmt`, `max_result_tokens` options plus tests/goldens.
- [ ] D.3 Unify search metadata — ensure every search endpoint returns `{query,total,page,limit,has_more,items}` with 1-based page numbering and edge-case coverage (zero, limit boundaries, last page).

## NEXT

- [ ] D.4 POST /api/collect.json — implement multi-query collector accepting `queries[]`, honoring budget-driven truncation, and returning per-sub-operation envelopes with regression tests.
- [ ] D.5 Error schema and enums — define `errors[]` entries `{status, code, message, recovery[]}` with enums `INVALID_REQUEST`, `RESULT_TOO_LARGE`, `NOT_READY`, `SSE_CONFLICT`, `TOO_MANY_REQUESTS`, `INTERNAL`, `UNAVAILABLE`; provide golden examples.
- [ ] D.6 Result budgeting — enforce `max_result_tokens` (hard cap) with `result_budget.mode=auto_trim|strict`; responses should report `estimate_tokens`, `truncated`, optional `resume_cursor`; document and test behavior.

## LATER

- [ ] D.7 rank=simple & k heuristic prefilter (opt-in mode).
- [ ] D.8 Cursor streaming for very large result sets.
- [ ] D.9 Five-minute short-term cache keyed by {digest, query}.

## Invariants

- CI remains green across unit, contract, and golden suites with no OpenAPI drift.
- Breaking default changes require a minor version bump.
