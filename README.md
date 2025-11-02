# Ghidra MCP – Deterministic Bridge

Deterministic, testable HTTP+MCP layer over the Ghidra plugin with strict schemas, batching, and write guards.

- 🚦 **Deterministic** JSON envelopes for all endpoints
- 🔍 **Rich search** across strings, functions, imports/exports, xrefs
- 🧪 **Contract & golden** tests for stability
- 🔐 **Write guards** (`ENABLE_WRITES`, `dry_run`) + observability

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt

# Run (factory app)
uvicorn bridge.app:create_app --factory --port 8081

# Smoke
bash bin/smoke.sh
```

## MCP Tools

> The MCP tool implementations create and close their own `GhidraClient` instances. Tool
> signatures never expose a `client` parameter.

## Documentation

* [Overview](docs/overview.md)
* [Quickstart](docs/quickstart.md)
* [Configuration](docs/configuration.md)
* [API Reference (Index)](docs/api/index.md)
* [SSE Behavior](docs/sse.md)
* [Observability](docs/observability.md)
* [Development](docs/development.md)
* [Troubleshooting](docs/troubleshooting.md)

> OpenAPI: `GET /openapi.json` (served by the app)

## Status

This repo is maintained with a deterministic plan. See [Development](docs/development.md) for the `.plan/` workflow.
