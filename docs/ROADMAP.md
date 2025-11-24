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
- ◻ Firmware-set workflows
  - Define standard prompts/recipes for boot→app→res investigations (e.g., reset vectors in BOOT, update handlers in APP, resource container checks in RES). **Planning needed:** how to expose these as reusable flows for agents.

## B. ghidra-bridge tooling
- ✅ Round out tool landscape
  - `strings_compact` now falls back to `search_strings("")` with documented limitations, and `search_xrefs_to` errors clearly when queries are non-empty.
- ◻ High-level analysis recipes on existing tools
  - Formalize LLM-side “String → Xrefs → Disasm,” “Scalar → MMIO → mmio_annotate_compact,” and “Region → list_functions_in_range → analyze_function_complete” workflows. Future: optional MCP meta-tools that package these.
- ◻ Write-path hygiene (rename/comments/labels)
  - Build small gated write tools such as `rename_function`, `set_comment`, or `apply_label`, each with dry-run options, explicit error codes, and clear docs about `GHIDRA_MCP_ENABLE_WRITES` requirements.

## C. GhidraMCP plugin & packaging
- ◻ Single-port multi-context server (R.21) (NOW)
  - Refactor Java plugin to use a singleton HTTP server instance shared across Ghidra tools.
  - Allow FrontEnd (Project Manager) to start the server without blocking subsequent CodeBrowser instances.
  - Dispatch requests to the active tool instance or handle global actions (like `open_program`) directly.
- ◻ Extension ZIP packaging story
  - Beyond the Maven-built `GhidraMCP.jar`, produce a reproducible Extension ZIP (proper layout + `extension.properties` + JAR) and installation checklist. CI/script should fetch Ghidra (11.4.2), build the plugin, emit the ZIP, and run a minimal smoke test (`project_info`, etc.).
- ◻ Early detection of Ghidra version incompatibilities
  - Establish a small test matrix (e.g., minimum supported vs. latest Ghidra) and at least one unit test that mocks Ghidra APIs to ensure type compatibility, guarding against namespace clashes like `java.util.function.Function` vs. `ghidra.program.model.listing.Function`.

## D. Tests & quality net
- ◻ MCP tool smoke tests (NOW)
  - Automate the manual snippets used so far into a smoke-test script (Python/Shell) that exercises `project_info`, `project_overview`, `search_strings`, `search_functions`, `search_scalars_with_context`, `mmio_annotate_compact`, `read_bytes`, and `read_words` against a test firmware with “what good looks like” assertions.
- ◻ Unit tests for new tools and error cases (NOW)
  - Extend the `project_overview`-style unit coverage to additional project/analysis tools, including negative cases (invalid parameters, large limits) and schema validation paths.

## E. Documentation & UX
- ◻ AGENTS.md / “How to talk to ghidra-bridge”
  - Capture recommended tool sequencing (start with `project_info`/`project_overview`; strings via `search_strings` → `string_xrefs_compact`/`search_xrefs_to`; IO via `search_scalars_with_context` → `disassemble_at` → `mmio_annotate_compact`; eventually `select_program`).
- ◻ User-facing cookbooks
  - Curate markdown snippets for recurring asks (USB handlers, update/flash paths, bootloader reset-to-main walks, MMIO register surveys) that rely solely on ghidra-bridge tools.

## F. Future bets
- ◻ Cross-binary analyses
  - Map interactions between BOOT and APP or compare firmware revisions (function graph diffs, cross-image references).
- ◻ More Ghidra action automation
  - Carefully gated automation hooks for actions like auto-analysis or marking functions as libraries, with explicit confirmations to avoid destructive edits.
