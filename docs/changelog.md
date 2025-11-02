# Changelog

## Unreleased

- Removed the legacy `bridge_mcp_ghidra.py` script; use the uvicorn factory entrypoint.
- Added deterministic write audit logging with JSONL output and unit coverage.
- Introduced jump-table golden snapshots and stricter contract tests for deterministic endpoints.
- Added mocked Ghidra integration tests to exercise happy/error/timeout flows.
- Implemented a parse-only orchestrator aggregator that ignores prior chatter.
- Refactored documentation into modular `/docs` pages linked from a lean README.
