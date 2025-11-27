# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GhidraMCPd is a token-efficient MCP (Model Context Protocol) server that bridges Ghidra reverse engineering tool with AI assistants. It exposes Ghidra's capabilities through a deterministic HTTP/SSE API and MCP tools, focusing on reducing token costs through batch operations and server-side context assembly.

**Key Architecture:**
- **Python Bridge** (`bridge/`): FastMCP server with HTTP/SSE transports
- **Ghidra Plugin** (`src/main/java/`): Java plugin that embeds an HTTP server in Ghidra
- **Two-tier communication**: AI client ↔ Python bridge (MCP/SSE) ↔ Ghidra plugin (HTTP)

## Development Commands

### Python Development

```bash
# Setup virtual environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # for tests

# Run bridge server (SSE transport)
uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000

# Run bridge server (stdio transport for CLI clients)
python scripts/bridge_stdio.py --transport stdio

# Run all tests (unit, contract, golden)
python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden

# Run specific test file
python -m pytest bridge/tests/contract/test_safeguards.py

# Verify MCP tools over stdio
python scripts/verify_mcp_tools.py --ghidra-server-url http://127.0.0.1:8080/

# Run deterministic smoke test (uses stub fixture, no Ghidra needed)
python scripts/mcp_smoke_test.py
```

### Java/Ghidra Extension Development

```bash
# Fetch Ghidra JARs (if not using GHIDRA_DIR)
python scripts/fetch_ghidra_jars.py

# Build extension (Docker - recommended)
./scripts/build_docker.sh

# Build extension (local Maven)
export GHIDRA_DIR=/path/to/ghidra_11.4.2_PUBLIC  # optional
mvn -DskipTests package
mvn package  # with tests

# Output: target/GhidraMCP-1.3.0.zip

# Docker cache workaround (if version doesn't update):
docker build --no-cache -f Dockerfile.build .
```

**Install in Ghidra:**
1. File → Install Extensions → select ZIP from `target/`
2. Restart Ghidra
3. File → Configure → Developer/Configure → check "GhidraMCP" to activate

## Architecture Details

### Bridge Server Architecture

**Entry point**: `bridge/app.py`
- `create_app()`: Factory that returns Starlette app with FastMCP + HTTP API routes
- `MCP_SERVER`: Global FastMCP instance that registers MCP tools
- Single SSE connection enforced via `BridgeState` with connection tracking

**Transports**:
- **SSE** (Server-Sent Events): `/sse` endpoint for web clients, enforces single active connection
- **Stdio**: Direct JSON-RPC over stdin/stdout for CLI clients (no HTTP layer)

**Feature modules** (`bridge/features/`):
Each feature module (e.g., `analyze.py`, `strings.py`, `memory.py`) implements domain-specific operations that are registered as both:
- HTTP routes in `bridge/api/routes/`
- MCP tools in `bridge/api/tools.py`

**GhidraClient** (`bridge/ghidra/client.py`):
- HTTP client wrapper around Ghidra plugin's endpoints
- Endpoint resolver pattern: tries multiple candidate names for backward compatibility
- Whitelist validation for program interactions
- Connection pooling via httpx

### Request/Response Flow

```
AI Client → /sse (SSE stream) → FastMCP → MCP Tools → GhidraClient → Ghidra Plugin (HTTP) → Ghidra API
                                                                                            ↓
AI Client ← SSE events ← FastMCP ← envelope{ok, data, errors} ← JSON response ← HTTP ← Ghidra
```

**Envelope structure**: All responses use `{ok: bool, data: any, errors: []}` with strict JSON schemas in `bridge/api/schemas/`

### Program Context Management

**Program selection** (`bridge/utils/program_context.py`):
- Tracks which program is active per session
- Policy enforcement: `strict` (hard error on switch) vs `soft` (warning + allow)
- Auto-open programs when first accessed by MCP tools
- Validates program readiness via `ProgramStatusTracker` in Java plugin

### Java Plugin Architecture

**Main class**: `src/main/java/com/lauriewired/GhidraMCPPlugin.java`
- Embeds `com.sun.net.httpserver.HttpServer` on port 8080 (configurable)
- Implements `ProgramCapable` interface for multi-window program tracking
- `PluginContextRegistry`: Manages multiple Ghidra tool windows, promotes active context
- `SharedHttpServerState`: Singleton HTTP server shared across plugin instances

**Key patterns**:
- Routes registered once globally via `ROUTES_REGISTERED` atomic flag
- Plugin delegates to shared server, multiple instances coordinate via registry
- `ProgramStatusTracker`: Tracks program open/ready state, gates operations requiring analysis
- `CursorPager`: Deterministic pagination with cursor-based resumption

## API Design Principles

1. **Batch over round-trips**: Use `collect` endpoint, `disassemble_batch`, `read_words` for multiple operations
2. **Server-side context**: `search_scalars_with_context` includes disassembly window to avoid follow-up calls
3. **Deterministic pagination**: Stable cursors, fixed limits, totals don't change mid-pagination
4. **Strict schemas**: `additionalProperties: false` for LLM-friendly, diff-able responses
5. **Write guards**: Writes disabled by default, require `GHIDRA_MCP_ENABLE_WRITES=true`, audit logging

## Environment Configuration

Copy `.env.sample` to `.env` and adjust:
- `GHIDRA_SERVER_URL`: Ghidra plugin HTTP endpoint (default: `http://127.0.0.1:8080/`)
- `GHIDRA_MCP_ENABLE_WRITES`: Enable write operations (rename, comment) - keep disabled unless auditing
- `GHIDRA_MCP_ENABLE_PROJECT_REBASE`: Enable program rebasing operations
- `GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY`: `strict` or `soft` for mid-session program switching

## Testing Strategy

**Test hierarchy**:
- `bridge/tests/unit/`: Fast unit tests, use stub/fixture client
- `bridge/tests/contract/`: Contract tests verifying API behavior (may require Ghidra instance)
- `bridge/tests/golden/`: Golden tests comparing OpenAPI snapshot vs HTTP endpoints

**Fixtures**: `bridge/tests/fixtures/reference.bin` - minimal firmware for deterministic tests

## Plan-Driven Development

This repo uses a `.plan/` workflow for deterministic task tracking:
- `.plan/TODO.md`: Active tasks
- `.plan/DONE.md`: Completed tasks with dates
- `.plan/tasks.manifest.json`: Machine-readable task state
- `.plan/sync_state.sh`: Helper to keep manifest/TODO/DONE in sync

**Workflow**: Read TODO → work task → commit with task ID → run sync_state.sh → move to DONE

## Architecture-Specific Adapters

`bridge/adapters/`: Optional architecture-specific disassembly helpers
- `arm_thumb.py`: ARM/Thumb mode detection
- `x86.py`: x86 operand parsing
- `fallback.py`: Default passthrough adapter
- Enable via `BRIDGE_OPTIONAL_ADAPTERS` env var (comma-separated, e.g., "x86,arm_thumb")

## Key Files Reference

- `bridge/app.py`: Main application factory, SSE connection management
- `bridge/api/tools.py`: MCP tool registration (71KB, extensive tool definitions)
- `bridge/ghidra/client.py`: HTTP client to Ghidra plugin (51KB, endpoint resolution)
- `bridge/features/`: Domain modules (analyze, strings, memory, functions, etc.)
- `src/main/java/com/lauriewired/GhidraMCPPlugin.java`: Java plugin implementation
- `scripts/build_docker.sh`: Canonical build process for Ghidra extension
- `pom.xml`: Maven build configuration, Ghidra 11.4.2 dependencies

## Common Pitfalls

1. **Program not ready**: Ensure Ghidra has a program open and analysis complete before MCP operations
2. **Single SSE connection**: Second `/sse` connection returns 409 Conflict - wait for previous to close
3. **Writes disabled**: Set `ENABLE_WRITES=true` explicitly to use rename/comment operations
4. **Java 17 required**: Maven build expects JDK 17 (`maven.compiler.release=17`)
5. **Extension activation**: After installing extension, must check the box in File → Configure to activate
6. **Endpoint resolution**: GhidraClient tries multiple candidate names for backward compatibility

## Documentation

- `docs/api.md`: Complete API reference with request/response examples
- `docs/server.md`: SSE/stdio transports, readiness, connection management
- `docs/development.md`: Test workflow, Java build, utilities
- `docs/troubleshooting.md`: Common issues and error reference
- `docs/getting-started.md`: Installation and MCP client configuration
