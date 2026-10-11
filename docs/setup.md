# Setup

Two parts, installed separately and kept at the same version: the plugin runs inside
Ghidra and serves HTTP on `127.0.0.1:8080`; the bridge is the MCP server your client
starts, and it talks to the plugin.

## The plugin

### Build

Needs a JDK (17 or newer; the build targets release 17) and Maven. The Ghidra JARs come either from an installation
(`GHIDRA_DIR`) or from `python scripts/fetch_ghidra_jars.py`, which puts them in `lib/`.

```bash
GHIDRA_DIR=/path/to/ghidra_11.4.2_PUBLIC mvn -DskipTests -Drevision="$(scripts/plugin_version.sh)" package
```

The version comes from git (`scripts/plugin_version.sh`): `<base>.<N>` on a clean tree, a
`-dev` suffix with uncommitted plugin changes. Without Maven, `./scripts/build_docker.sh`
builds in a container. Output: `target/GhidraMCP-<version>.zip`.

### Install

1. *File > Install Extensions*, add the ZIP.
2. Restart Ghidra. An installed extension loads only after a restart; until then the old
   one keeps answering.
3. *File > Configure > Developer*, tick *GhidraMCP*.
4. Open a program in the CodeBrowser.

Check what is running:

```bash
curl http://127.0.0.1:8080/plugin_version
# {"version":"1.3.66","api":3,"status":"ok"}
```

### Port and bind address

*Edit > Tool Options > GhidraMCP HTTP Server* sets port (8080) and bind address
(127.0.0.1); both need a Ghidra restart. The plugin has no authentication, and the write
guard is in the bridge: bind to anything but loopback only on a network you trust with
write access to your program.

## The bridge

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
```

`requirements-dev.txt` adds what the tests need.

### Connecting a client

The bridge speaks MCP over stdio; the client starts it as a subprocess. Use absolute paths.

**Claude Code**

```bash
claude mcp add ghidra -- /path/to/GhidraMCPd/.venv/bin/python /path/to/GhidraMCPd/scripts/bridge_stdio.py --transport stdio
```

Add `--scope project` to store it in the project's `.mcp.json` instead of your user
settings, and `-e GHIDRA_SERVER_URL=http://127.0.0.1:8081/` for a plugin on another port.

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "/path/to/GhidraMCPd/.venv/bin/python",
      "args": ["/path/to/GhidraMCPd/scripts/bridge_stdio.py", "--transport", "stdio"]
    }
  }
}
```

**Other clients** take the same command and arguments in their own format. The client
starts the bridge once per session; after updating the bridge, restart the client.

### Over HTTP

`uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8000` serves the MCP tools
over SSE at `/sse` and a plain HTTP API under `/api/` ([reference](reference/http-api.md)).
SSE has been superseded in the MCP specification by Streamable HTTP, which the bridge does
not offer yet; use stdio where the client allows it. The SSE endpoint takes one connection
at a time and answers a second with 409.

## Settings

Environment variables, read once at start. The bridge also loads `.env` from the
repository root (copy `.env.sample`); variables already set in the environment win.

| Variable | Default | Effect |
|---|---|---|
| `GHIDRA_SERVER_URL` | `http://127.0.0.1:8080/` | where the plugin listens |
| `GHIDRA_MCP_ENABLE_WRITES` | `false` | allow renames, comments, labels, structure edits and saving |
| `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` | `2` | writes one tool call may make |
| `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` | `256` | items one batch or page may hold |
| `GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY` | `strict` | `strict`: switching programs mid-session is an error; `soft`: a warning |
| `GHIDRA_MCP_AUDIT_LOG` | unset | JSONL file for structure edits (create/update/delete), including refused ones |
| `GHIDRA_MCP_USAGE_LOG` | unset | JSONL file with one line per tool call: bytes, estimated tokens, duration |
| `BRIDGE_OPTIONAL_ADAPTERS` | unset | optional architecture helpers, comma-separated; available: `x86` (alias `i386`). ARM/Thumb is built in. |

## Writes

Off by default, in two layers. Every writing tool takes `dry_run` (default `true`) and
answers what it would do; only with `GHIDRA_MCP_ENABLE_WRITES=true` *and* `dry_run=false`
does anything reach Ghidra. A write names the program the session selected, and the
plugin refuses it if another program has become active in the meantime.

Changes stay unsaved in Ghidra: `list_mutations` shows what this session changed (dry runs
included), `check_dirty_state` whether anything is unsaved, `save_program` saves. Undo in
Ghidra works as usual.

Byte patches and moving the image base are not offered; do them in Ghidra.
