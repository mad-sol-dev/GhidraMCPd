# Ghidra MCP – TODO (authoritative)

> Goal: LLM-friendly, token-efficient server. Fewer round trips through Composite Ops and Multi-Query Collector.
> Standards: 1-based `page`, `has_more`, deterministic sorting, strict envelope `{ok,data,errors[]}`.

## NOW
- {R.15} MCP tool smoke-test script against reference firmware (project_info/overview, strings, scalars, MMIO, bytes/words)
- {R.16} Unit-test expansion for new project/analysis tools and invalid-parameter paths

Recommended next focus: advance {R.15}/{R.16} coverage so smoke tests and invalid-parameter paths are stable before expanding tool flows.

## NEXT
- {R.9} Firmware-set workflows (boot→app→res prompts, swap-back guidance)
- {R.11} LLM recipes on existing tools (string→xrefs→disasm, scalar→MMIO→annotate, region→functions→analyze)
- {R.12} Write-path utilities (rename_function/set_comment/apply_label) with dry-run + env gate + error codes
- {R.13} Extension ZIP packaging + install checklist + CI/script smoke-test hook
- {R.17} AGENTS.md guidance for ghidra-bridge usage and prompting defaults
- {R.18} Cookbook snippets for USB/update/boot/MMIO workflows using MCP tools only

## LATER
- {R.5} CORS/origin whitelist controls for bridge endpoints
- {R.6} Docker images + CI packaging handoff
- {R.7} MCP tool UX docs (flows, screenshots, failure drills)
- {R.14} Ghidra version-compat matrix (min vs. latest, mock-based type checks)
- {R.19} Cross-binary analysis (BOOT⇄APP links, firmware diffing)
- {R.20} Controlled Ghidra action automation (auto-analysis, mark-as-library) with confirmations

## DONE
- [x] {R.10} Clarify `strings_compact` population and error contracts (incl. `search_xrefs_to` empty-query behavior)
- [x] {R.8} Program selection helpers (`select_program`, `get_current_program`) to anchor analysis tools on the active Ghidra program
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
- [x] {R.1} Batch project analysis lanes for multi-program dossiers — collector lanes span multiple Ghidra projects with deterministic envelopes and docs/tests.
- [x] {R.2} Enhanced search ranking + expanded context windows — function search supports opt-in context windows with deterministic ordering coverage across unit/contract/golden suites.
- [x] {R.3} `include_literals` plumbing across memory and string search endpoints.
- [x] {R.4} Expanded audit logging for write/rebase/datatypes flows.
- [x] {T-202511-019} Refresh roadmap and .plan with navigation/context/backlog alignment.

## Invariants
- CI green (Unit/Contract/Golden), OpenAPI drift-free.
- Breaking defaults only via minor bump.
