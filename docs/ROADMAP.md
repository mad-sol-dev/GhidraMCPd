# Roadmap (LLM-first focus)

## Current capabilities
- ✅ Core program metadata and firmware set visibility via `/api/project_info.json` and `/api/project_overview.json`, including schema validation and contract/unit coverage.
- ✅ Composite and budgeting flows: `/api/analyze_function_complete.json`, `/api/collect.json`, cursor streaming, request budgeting with auto-trim/strict enforcement, and short-term caching for deterministic multi-query runs.
- ✅ Guarded write support: `/api/write_bytes.json` and `/api/project_rebase.json` are behind explicit environment gates; datatype introspection endpoints are live; the MMIO annotator stays dry-run unless writes are enabled.
- ✅ Literal-inclusive memory and string search: `include_literals` plumbing is available across memory reads and string search requests so callers can pull bytes/strings in one pass when needed.
- ✅ Expanded audit logging on gated operations: write/rebase/datatype flows emit structured audit entries that capture caller context, parameters, gating state, and outcomes for better observability.

## A. Program navigation & context
- ✅ Solidify `project_overview`
  - Tool is shipped and exercised; remaining work is UX/prompt guidance so LLMs reliably use the firmware-set context they receive.
- ✅ Explicit program selection as global context
  - MCP endpoints `select_program(domain_file_id: str)` and `get_current_program()` track the active program per session/requestor with mid-session switch gating.
- ✅ CodeBrowser navigation support
  - MCP endpoint `goto_address(address: str)` moves the CodeBrowser cursor to a specified address, centering it on screen for visibility. Enables programmatic navigation during analysis workflows.
- ◻ Explicit dirty-state handling when switching programs
  - Gate `open_program` with a pre-switch dirty check so callers cannot silently discard edits when moving between programs.
  - Surface explicit write-path endpoints (`/save_program` and `/discard_program_changes`) with warnings that LLMs should avoid destructive actions without user consent.
  - Extend `/open_program` with `on_dirty=error|save|discard` flags (default `error`) to align with readiness gating work and keep dirty-state decisions explicit.
- ◻ Firmware-set workflows
  - Define standard prompts/recipes for boot→app→res investigations (e.g., reset vectors in BOOT, update handlers in APP, resource container checks in RES). **Planning needed:** how to expose these as reusable flows for agents.

## B. ghidra-bridge tooling
- ✅ Round out tool landscape
  - `strings_compact` now falls back to `search_strings("")` with documented limitations, and `search_xrefs_to` errors clearly when queries are non-empty.
- ✅ Text search within functions (`find_in_function`)
  - Server-side pattern matching in disassembly/decompilation with regex support, case sensitivity options, and configurable context windows around matches.
- ◻ Token/character-based result limits
  - Current `analyze_function_complete` truncates by line count (max 500), which can cut mid-block. Consider adding `max_chars` or `max_tokens` options to avoid abrupt truncation and better align with LLM token budgets.
- ◻ High-level analysis recipes on existing tools
  - Formalize LLM-side "String → Xrefs → Disasm," "Scalar → MMIO → mmio_annotate_compact," and "Region → list_functions_in_range → analyze_function_complete" workflows. Future: optional MCP meta-tools that package these.
- ◻ Write-path hygiene (rename/comments/labels)
  - Build small gated write tools such as `rename_function`, `set_comment`, or `apply_label`, each with dry-run options, explicit error codes, and clear docs about `GHIDRA_MCP_ENABLE_WRITES` requirements.

## C. GhidraMCP plugin & packaging
- ✅ Single-port multi-context server (R.21) (NOW)
  - Java plugin now uses a singleton HTTP server shared across Project Manager and CodeBrowser contexts.
  - FrontEnd can start the server without blocking later CodeBrowser launches, with request routing to the active tool.
  - Global operations such as `open_program` are handled even when no program context is available.
- ◻ Data type lookup caching (R.22)
  - Cache type-name lookups per DataTypeManager with safe invalidation and a single fallback scan for misses to speed repeated resolutions.
- ◻ Open-program readiness gating (R.23)
  - Track IDLE/LOADING/READY states through open/auto-analysis and expose a cheap status check so the bridge can defer heavy calls until READY.
- ◻ Extension ZIP packaging story
  - Beyond the Maven-built `GhidraMCP.jar`, produce a reproducible Extension ZIP (proper layout + `extension.properties` + JAR) and installation checklist. CI/script should fetch Ghidra (11.4.2), build the plugin, emit the ZIP, and run a minimal smoke test (`project_info`, etc.).
- ◻ Early detection of Ghidra version incompatibilities
  - Establish a small test matrix (e.g., minimum supported vs. latest Ghidra) and at least one unit test that mocks Ghidra APIs to ensure type compatibility, guarding against namespace clashes like `java.util.function.Function` vs. `ghidra.program.model.listing.Function`.

## D. Tests & quality net
- ✅ MCP tool smoke tests (NOW)
  - Deterministic stub-backed smoke test (`scripts/mcp_smoke_test.py`) exercises `project_info`, `project_overview`, `search_strings`, `search_functions`, `search_scalars_with_context`, `mmio_annotate_compact`, `read_bytes`, and `read_words` against the bundled reference firmware with CI automation.
- ✅ Unit tests for new tools and error cases (NOW)
  - Expanded unit suite covers additional project/analysis tools plus negative parameter and limit paths (e.g., scalars, strings, MMIO, collect, program selection), enforcing schema validation alongside contract/golden coverage.

## E. Documentation & UX
- ◻ AGENTS.md / “How to talk to ghidra-bridge”
  - Capture recommended tool sequencing (start with `project_info`/`project_overview`; strings via `search_strings` → `string_xrefs_compact`/`search_xrefs_to`; IO via `search_scalars_with_context` → `disassemble_at` → `mmio_annotate_compact`; eventually `select_program`).
- ◻ User-facing cookbooks
  - Curate markdown snippets for recurring asks (USB handlers, update/flash paths, bootloader reset-to-main walks, MMIO register surveys) that rely solely on ghidra-bridge tools.
- ◻ Port 8080 error response cleanup (R.24)
  - Settle on consistent text/JSON conventions for plugin 8080 errors, keep bridge parsing tolerant but deterministic, and document the finalized behavior alongside readBytes/readBytesBase64 expectations.

## F. Future bets
- ◻ Cross-binary analyses
  - Map interactions between BOOT and APP or compare firmware revisions (function graph diffs, cross-image references).
- ◻ More Ghidra action automation
  - Carefully gated automation hooks for actions like auto-analysis or marking functions as libraries, with explicit confirmations to avoid destructive edits.
