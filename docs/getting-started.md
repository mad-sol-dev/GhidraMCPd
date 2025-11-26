# Getting started

This guide covers installation, local execution, and configuration for the Ghidra MCPd server.

## Install

Use Python 3.10+ and create an isolated environment:

```bash
python -m venv .venv
source .venv/bin/activate
# install the runtime dependencies only
python -m pip install -r requirements.txt
# optionally install development/test dependencies
python -m pip install -r requirements-dev.txt
```

The bridge depends on Ghidra's headless components through the bundled plugin. No additional system packages are required for basic usage.

## Run

Launch the deterministic ASGI app with Uvicorn:

```bash
uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000
```

The server exposes REST endpoints under `/api/*.json`, `/openapi.json`, server-sent events on `/sse`, and session state via `/state`. Clients should wait for readiness before issuing `/messages` calls; premature traffic receives HTTP 425 with `{"error":"mcp_not_ready"}`.

Batch-oriented tools (`disassemble_batch`, `read_words`, `search_scalars_with_context`) are available once the SSE bridge reports ready. When running against large programs, favor these endpoints to reduce token churn compared to issuing many single-address calls.

## Stdio mode

The repository still ships the legacy helper for console-first workflows or
environments where SSE/Web transports are blocked. Use it after completing the
same Python prerequisites (`python -m pip install -r requirements.txt` etc.).

Launch the helper by pointing it at your Ghidra Bridge URL and selecting a
transport:

```bash
python scripts/bridge_stdio.py --ghidra-server http://127.0.0.1:8080/ --transport stdio
```

- `--transport stdio` starts the MCP server in-process and speaks JSON-RPC over
  stdio (no `/sse`, `/messages`, or shim). This matches the classic CLI used
  before the Uvicorn-based server and is ideal for local smoke tests.
- `--transport sse` spins up the same MCP server but also boots an OpenWebUI shim
  (controlled by `--shim-host/--shim-port`) and forwards HTTP traffic to
  `/sse`, `/messages`, and `/state`. Use it when integrating with OpenWebUI or
  other SSE-aware clients.

Switch transports at runtime by re-running the command with the desired flag.
Other CLI options (`--mcp-host`, `--mcp-port`, and `--debug`) remain identical
between modes so you can keep a single `.env`/script and only toggle
`--transport` depending on your client.

## Configuration

Set environment variables before starting the server to adjust safety limits, auditing and endpoint targets:
- `GHIDRA_SERVER_URL` (default `http://127.0.0.1:8080/`)
  - Base URL (including trailing slash) for the Ghidra Java plugin.  The Python bridge uses this to communicate with Ghidra.  Override this if your plugin is running on a different host or port.
- `GHIDRA_MCP_ENABLE_WRITES` (default `false`)
  - Disable or enable write operations globally. When `false` or when requests include `dry_run=true`, write handlers perform no mutations.
- `GHIDRA_MCP_ENABLE_PROJECT_REBASE` (default `false`)
  - Enables `/api/project_rebase.json` to mutate the program image base when `dry_run=false` and the request includes `confirm=true`. Without the flag, the endpoint only reports what would change.
- `GHIDRA_MCP_AUDIT_LOG`
  - Optional filesystem path for JSONL write audits. When unset, successful writes are not logged.
- `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` (default `2`)
  - Caps the number of writes a single call may perform. Surpassing the cap raises `SafetyLimitExceeded`.
- `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` (default `256`)
  - Applies to batch endpoints and search windows, including `search_scalars_with_context`. Values above the limit raise `SafetyLimitExceeded` to preserve deterministic token budgets.
- `GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY` (default `strict`)
  - Governs mid-session program switching. `strict` returns errors once program-scoped tools have run; `soft` allows the change with warnings and confirmation guidance.
- `BRIDGE_OPTIONAL_ADAPTERS`
  - Comma-separated list of optional Ghidra adapters to enable. Unknown entries fail fast at startup.

For reproducibility, copy `.env.sample` to `.env` and edit values; the bridge will load
the file automatically at startup (no manual `export` needed).

> **Batch caps**
> - Search windows, compact string listings, and disassembly batches default to **256** items via `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`.
> - Write operations default to **2** mutations per request via `GHIDRA_MCP_MAX_WRITES_PER_REQUEST`.
> - Override the limits by setting the environment variables (or updating your `.env`) before starting the server.

### Batch limits (defaults)

The bridge enforces deterministic caps on batch-style operations to keep token usage predictable. All of the following limits default to `GHIDRA_MCP_MAX_ITEMS_PER_BATCH = 256` and raise `SafetyLimitExceeded` when exceeded (see the [error reference](troubleshooting.md#error-reference) for envelope details):

| Operation | Capped dimension | Default | Override |
| --- | --- | --- | --- |
| `disassemble_batch` | Addresses per request | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`
| `read_words` | Words per request | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`
| `search_strings`, `search_imports`, `search_exports`, `search_xrefs_to`, `strings_compact` | Window size (`page * limit` for search APIs, `offset + limit` for compact listings) | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`
| `search_scalars_with_context` | Matches returned | 256 | `GHIDRA_MCP_MAX_ITEMS_PER_BATCH`

Set the environment variable before starting the server to raise the ceiling, for example (values in `.env` are picked up automatically):

```bash
GHIDRA_MCP_MAX_ITEMS_PER_BATCH=512 uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000
```

Watch for repeated `SafetyLimitExceeded` responses to confirm the new cap is sufficient for your workload.

## Token efficiency notes

Ghidra MCPd keeps responses compact by enforcing deterministic schema envelopes (`{"ok":bool,"data":object|null,"errors":[]}`) and predictable limits. In typical analysis sessions, combining `disassemble_batch` with contextual search reduces total request tokens by roughly 70% (example: ~80k tokens before batching → ~25k after). Actual savings depend on program size and client prompting, but the enforced caps above protect against unbounded payloads.

## Basic usage workflows

### Working with programs

Before performing analysis operations, ensure you have a program loaded and ready:

```python
# Check current program status
project_info()  # Returns program metadata, entry points, memory blocks

# List available programs in the project
project_overview()  # Shows all domain files

# Switch to a specific program (auto-launches CodeBrowser if needed)
select_program(domain_file_id="ZK-INKJET-NANO-APP.bin_1")

# Verify program is ready
get_current_program()  # Should show status: READY
```

### Navigation and code inspection

Use `goto_address` to move the CodeBrowser cursor to specific locations during analysis:

```python
# Search for a function
results = search_functions(query="init", limit=10)

# Navigate to the first result
if results["data"]["items"]:
    address = results["data"]["items"][0]["address"]
    goto_address(address)  # CodeBrowser jumps to this address

# Follow cross-references
xrefs = search_xrefs_to(address="0x00000080", query="")
for xref in xrefs["data"]["items"]:
    goto_address(xref["from_address"])  # Inspect each caller

# Navigate to specific addresses found in analysis
goto_address("0x00000100")  # Entry point
goto_address("0x00002000")  # String reference
goto_address("0x0000ABCD")  # MMIO register access
```

The CodeBrowser window automatically centers on the specified address, making it easy to visually inspect code while programmatically exploring the binary.

### Common analysis patterns

**String analysis workflow:**
```python
# Find strings containing "error"
strings = search_strings(query="error", limit=20)

# For each string, find where it's used
for item in strings["data"]["items"]:
    xrefs = string_xrefs(string_addr=item["addr"])
    for caller in xrefs["data"]["callers"]:
        # Navigate to each usage
        goto_address(caller["addr"])
        # Disassemble surrounding context
        disasm = disassemble_at(address=caller["addr"], count=8)
```

**Scalar constant analysis:**
```python
# Find references to a specific address or constant
results = search_scalars_with_context(
    value="0xB0000084",  # MMIO register address
    context_lines=4
)

# Navigate to first usage
if results["data"]["matches"]:
    goto_address(results["data"]["matches"][0]["address"])
```

**Function exploration:**
```python
# List functions in a memory region
funcs = list_functions_in_range(
    address_min="0x00000000",
    address_max="0x00001000",
    limit=50
)

# Navigate through each function
for func in funcs["data"]["items"]:
    goto_address(func["address"])
    # Get detailed analysis
    analysis = analyze_function_complete(
        address=func["address"],
        fields=["function", "disasm", "xrefs"]
    )
```
