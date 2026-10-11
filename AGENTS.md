# Working in this repository

GhidraMCPd: an MCP server (Python bridge, `bridge/`) in front of a Ghidra plugin (Java,
`src/main/java/com/lauriewired/`). The bridge talks to the plugin over HTTP on
`127.0.0.1:8080`. Human docs start at `README.md`; the design rules are in
`docs/design.md`.

## Commands

```bash
.venv/bin/python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden   # all offline tests
.venv/bin/python -m pytest -q bridge/tests/live            # against a running Ghidra, read-only
GHIDRA_DIR=/path/to/ghidra_11.4.2_PUBLIC mvn -Drevision="$(scripts/plugin_version.sh)" package   # plugin
.venv/bin/python scripts/reference_run.py --expect-fingerprint baseline/fingerprint.json        # cost measurement
.venv/bin/python scripts/measure_schema_cost.py            # schema base; keep under 8500 tokens
```

After changing tool docstrings or plugin routes, regenerate `docs/reference/` (commands in
`docs/development.md`); a test fails otherwise.

## Rules

1. **Failure is not absence.** A plugin read answered `NOT_FOUND`/`UNMAPPED` is "not
   there" (`None`, empty). Every other failure raises `UpstreamFailed` and becomes an error
   envelope. Never turn a failure into an empty result, and never report a cut list as
   complete (`has_more`/`truncated`).
2. **Plugin and bridge move together.** The bridge accepts exactly API 3
   (`REQUIRED_PLUGIN_API`, plugin `API_LEVEL`); change both in one commit when the answer
   convention changes. A plugin change is live only after build, install and a Ghidra
   restart; `curl http://127.0.0.1:8080/plugin_version` shows what runs.
3. **Stubs answer like the plugin.** Mock plugins go through `bridge/tests/plugin_http.py`.
   A stub that returns a shape the plugin never sends hides bugs; check the Java source.
4. **Strict schemas.** Responses follow `bridge/api/schemas/` with
   `additionalProperties: false`; a new field needs the schema and the golden snapshots
   (`UPDATE_SNAPSHOTS=1 UPDATE_GOLDEN_SNAPSHOTS=1`).
5. **Docstrings are the model's documentation.** Every tool says what it is not for and
   every parameter its range, within the schema budget.
6. **Writes stay guarded.** Writing tools default to `dry_run=True`; real writes need
   `GHIDRA_MCP_ENABLE_WRITES=true`. The test suite forces writes off itself.
7. **Endpoint aliases are real routes.** Every name in the client's candidate lists must
   exist in the plugin (`bridge/tests/unit/test_plugin_routes.py`).

## The open Ghidra program

Live checks run against a frozen copy of the ZK-Inkjet project, the baseline for
measurements. Read-only probes are fine. A write test is agreed with the maintainer
first and undone in Ghidra (Ctrl+Z, no save), then confirmed via `/check_dirty_state`. An
auto-analysis changes the copy as well; it is reset by closing without saving.

## Plan

Tasks in `.plan/` (`TODO.md`, `DONE.md`, `tasks.manifest.json`, `state.json`); commit
messages carry the task ID; `python3 bin/plan_check.py` must pass. The working log is
`docs/notes/ghidramcpd-rework.md` (German); its last hand-off section says what is open.
