# Ghidra MCPd - token-efficient MCP server for Ghidra

Deterministic MCP server for the Ghidra plugin focused on lowering token spend while keeping schemas stable and auditable.

> **Status:** Experimental • **Provenance:** this repository’s code is almost entirely AI-generated (Codex / AiderDesk) • Use at your own risk - contributions welcome.
> **Credit:** Fork of **GhidraMCP** - thanks to **Laurie Wired** for the original project and inspiration.

## Motivation

Bridging Ghidra through MCP can be API-expensive when clients emit many small calls. Ghidra MCPd batches high-volume tasks and adds server-side context windows so typical reverse-engineering sessions drop from roughly 80k tokens to ~25k (scenario-dependent, ...and GPT5's wild halucination), reducing latency and cost while preserving deterministic envelopes.

## Highlights

* Batch ops: `disassemble_batch`, `read_words`
* Context search: `search_scalars_with_context` (server-side windowing)
* Deterministic envelopes & schemas (`{ok,data,errors[]}`, `additionalProperties:false`)
* Guard rails: write-guards (`ENABLE_WRITES`, `dry_run`), safety limits, observability via `/state`
* Tested: contract, golden (OpenAPI/HTTP parity), unit

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000
```

## Build the Ghidra extension

Populate `lib/` with the required Ghidra jars, then run Maven:

```bash
python scripts/fetch_ghidra_jars.py
mvn -DskipTests package
```

If you already have a local Ghidra checkout, you can still point Maven at it directly:

```bash
export GHIDRA_DIR=/path/to/ghidra_*_PUBLIC && mvn -DskipTests package
```

The build produces `target/GhidraMCP-1.0-SNAPSHOT.jar`.

**Installation:**

1. Copy the JAR to Ghidra's Extensions directory:
   ```bash
   cp target/GhidraMCP-1.0-SNAPSHOT.jar $GHIDRA_INSTALL_DIR/Extensions/Ghidra/
   ```

2. Or use Ghidra's GUI: **File → Install Extensions** and select the JAR file.

3. Restart Ghidra to load the extension.

## Advanced start

Run the server and verify deterministic behavior:

```bash
curl -sS http://localhost:8000/openapi.json | jq '.info.title'
# → 200 JSON ("Ghidra MCP Bridge API")

curl -iN http://localhost:8000/sse
# keep this stream open (HTTP/1.1 200)

curl -i http://localhost:8000/sse
# → HTTP/1.1 409 Conflict (single active SSE)

curl -i -X POST http://localhost:8000/sse
# → HTTP/1.1 405 Method Not Allowed + {"allow":"GET"}

curl -i http://localhost:8000/messages
# before readiness → HTTP/1.1 425 Too Early + {"error":"mcp_not_ready"}
```

## API index

* `/api/search_strings.json`
* `/api/strings_compact.json`
* `/api/string_xrefs.json`
* `/api/search_imports.json`
* `/api/search_exports.json`
* `/api/search_functions.json`
* `/api/search_xrefs_to.json`
* `/api/search_scalars.json`
* `/api/list_functions_in_range.json`
* `/api/disassemble_at.json`
* `/api/read_bytes.json`
* `/api/jt_slot_check.json`
* `/api/jt_slot_process.json`
* `/api/jt_scan.json`
* `/api/mmio_annotate.json`
* `/api/analyze_function_complete.json`
* `/api/health.json`

See the generated reference in [docs/api.md](docs/api.md).

## Documentation

* [Getting started](docs/getting-started.md)
* [Server operations](docs/server.md)
* [Troubleshooting](docs/troubleshooting.md)
* [Development workflow](docs/development.md)

## Status

This repo is maintained with a deterministic plan. See [Development](docs/development.md) for the `.plan/` workflow.

---

## Acknowledgments & Provenance (details)

This repository’s code is almost entirely AI-generated (Codex, AiderDesk). Human role: planning, prompting, review, tests, and documentation. Fork of GhidraMCP — many thanks to Laurie Wired for the foundation and inspiration. Provided as-is; community review and contributions are welcome.
