# MCP smoke test

Use the deterministic smoke test to exercise the core MCP tools against the bundled reference firmware (`bridge/tests/fixtures/reference.bin`). The script drives the stubbed MCP server over stdio and checks that each tool returns data matching the known layout.

## Running locally

```bash
python scripts/mcp_smoke_test.py
```

The helper will start `scripts/reference_mcp_server.py` with the reference firmware and call:

- `project_info`
- `project_overview`
- `search_strings` (query: `boot`)
- `search_functions`
- `search_scalars_with_context`
- `mmio_annotate_compact`
- `read_bytes`
- `read_words`

A healthy run prints PASS for each tool and exits zero. Example output:

```
Connected to ReferenceMCPServer 0.0.0
[PASS] project_info
[PASS] project_overview
[PASS] search_strings
[PASS] search_functions
[PASS] search_scalars_with_context
[PASS] mmio_annotate_compact
[PASS] read_bytes
[PASS] read_words
All smoke tests passed.
```

Pass `--server-script` or `--firmware` if you want to point the smoke test at a different stub server or fixture.

## Automation

The smoke test runs in CI via `.github/workflows/build.yml` so regressions against the reference firmware are caught automatically.
