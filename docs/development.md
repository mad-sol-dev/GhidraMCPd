# Development

## Tests

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden
```

- `bridge/tests/unit` -- features and tools against stub clients and mock plugins.
- `bridge/tests/contract` -- the bridge HTTP routes against a stub client.
- `bridge/tests/golden` -- the OpenAPI snapshot and recorded HTTP answers. After an
  intended change: `UPDATE_SNAPSHOTS=1 UPDATE_GOLDEN_SNAPSHOTS=1 pytest bridge/tests/golden`,
  then read the diff.
- `bridge/tests/live` -- against a running Ghidra; see below.

The suite sets `GHIDRA_MCP_ENABLE_WRITES=false` itself: python-dotenv finds the
repository's `.env` from a worktree too, and a test run that merely happens not to write
is no protection.

### Stubs answer like the plugin

Several bugs survived because stubs answered in shapes the plugin never sends. Mock
plugins go through `bridge/tests/plugin_http.py`: `plugin_transport` adds the API header,
`plugin_error` builds a failure, `plugin_cursor` and `function_search_page` page and
refuse cursors the way the plugin does. Source tests hold the Java side to the same
rules (no error prose, API level equal to the bridge's, flags as booleans).

### Generated pages

`docs/reference/` is generated and checked:

| Page | From | Command |
|---|---|---|
| `tools.md` | tool docstrings | `python scripts/gen_tools_md.py > docs/reference/tools.md` |
| `plugin-api.md` | plugin source, bridge whitelist | `python scripts/gen_plugin_routes_md.py > docs/reference/plugin-api.md` |
| `http-api.md` | OpenAPI snapshot | `python scripts/gen_api_md.py bridge/tests/golden/data/openapi_snapshot.json > docs/reference/http-api.md` |

The first two are compared by `bridge/tests/unit/test_generated_docs.py`, the third by CI.

## Live checks

`bridge/tests/live/` runs against a Ghidra serving the reference program (a frozen copy
of the ZK-Inkjet project, identified by SHA-256) and skips when none is reachable or the
plugin speaks another API level. Everything there reads or runs as a dry run.

The frozen copy is the baseline for measurements, so it must not change:

- Read-only probes are fine.
- A real write test is agreed first, then undone in Ghidra (Ctrl+Z, no save) and confirmed
  with `/check_dirty_state` and a read-back. Count the undo steps: Ghidra accepts some
  writes one expects to fail (a rename to an existing name).
- An auto-analysis changes the copy too. Reset by closing the program without saving.

### Reference run

```bash
.venv/bin/python scripts/reference_run.py --expect-fingerprint baseline/fingerprint.json
.venv/bin/python scripts/usage_report.py runs/reference_run.jsonl
```

40 fixed read-only calls, one usage line each. Logs go to `runs/` (ignored by git);
`baseline/` holds the checked-in comparison points and is replaced only with
`--overwrite-baseline`. `scripts/measure_schema_cost.py` measures the schema base; keep it
under 8 500 tokens.

## The plugin

Java, `src/main/java/com/lauriewired/`. Build as in [setup](setup.md#build); with tests:

```bash
GHIDRA_DIR=/path/to/ghidra_11.4.2_PUBLIC mvn -Drevision="$(scripts/plugin_version.sh)" package
```

Commit before building a version that will be installed: on a clean tree the version is
`<base>.<N>` (N = commits touching `src/` or `pom.xml`), otherwise it gets a `-dev` suffix.
The `version=` line in `extension.properties` stays the Ghidra version; Ghidra refuses the
extension otherwise. `scripts/build_local.sh` builds the same ZIP with only a JDK.

A plugin change reaches a running Ghidra only through install and restart. When the
answer convention changes, raise `API_LEVEL` in the plugin and `REQUIRED_PLUGIN_API` in
the bridge together; install the plugin first, then restart bridges.

## Plan

Tasks live in `.plan/`: `TODO.md` (open), `DONE.md` (finished, with commit), and
`tasks.manifest.json`/`state.json` (machine-readable). `python3 bin/plan_check.py` checks
them, CI runs it. `.plan/sync_state.sh` fills in commits for tasks that have none and
leaves recorded ones alone. Commit messages carry the task ID.

## CI

`.github/workflows/build.yml`, on pull requests: plan check, unit tests, the `http-api.md`
drift check, and the Maven package (without tests) when Java changes.
