# Troubleshooting

## First checks

```bash
curl http://127.0.0.1:8080/plugin_version          # plugin running, which version, which API
curl http://127.0.0.1:8080/api/current_program.json # program open, READY or LOADING
```

No answer on 8080: Ghidra is not running, the extension is not enabled (*File > Configure
> Developer*), or it listens on another port (*Edit > Tool Options > GhidraMCP HTTP
Server*). A freshly installed extension loads only after a Ghidra restart.

The client shows no tools or old behaviour: the client starts the bridge once per session,
so restart the client after updating the bridge.

## Error codes

Errors come as `{"ok": false, "errors": [{"code", "status", "message", "recovery", "upstream"?}]}`.
`upstream.code` is the plugin's code when the plugin refused.

| Code | Status | Means | Do |
|---|---|---|---|
| `UNAVAILABLE` + `PLUGIN_TOO_OLD` | 503 | the plugin speaks an older API than the bridge (or none, or lacks a route) | build and install the plugin from the same checkout, restart Ghidra |
| `UNAVAILABLE` + `PLUGIN_TOO_NEW` | 503 | the plugin speaks a newer API than the bridge | update the bridge to the same checkout, restart the client |
| `UNAVAILABLE`, "Program is not ready" | 503 | analysis is running (`LOADING`) or no program is open | wait for `READY`, or open a program |
| `UNAVAILABLE`, upstream `INTERNAL` | 503 | Ghidra failed; the message says how | read the message; retry if it says the connection failed |
| `INVALID_REQUEST` | 400 | a parameter is missing or out of range | the message names it |
| `INVALID_REQUEST`, upstream `NOT_FOUND`/`UNMAPPED`/`CONFLICT` | 404/409 | the plugin refused: nothing there, no memory there, or the name/type conflicts; nothing changed | |
| `INVALID_REQUEST`, "Writes are disabled" | 400 | `dry_run=false` without `GHIDRA_MCP_ENABLE_WRITES=true` | enable writes or stay with the dry run |
| `INVALID_REQUEST`, "Write refused" | 409 | the write named a program that is no longer the active one | make the session's program active again, or `select_program` the active one |
| `RESULT_TOO_LARGE` | 413 | a batch, page, write count or token budget is exceeded; or a search the plugin had to cut | narrow the query or raise the limit |
| `NOT_READY` | 425 | (HTTP/SSE only) a message before the MCP session finished starting | wait for the readiness event |
| `SSE_CONFLICT` | 409 | (SSE only) a second connection while one is open | close the other client; the bridge serves one SSE stream |
| `INTERNAL` | 500 | the bridge itself failed | a bug; the message and the bridge log help |

### Codes inside jump-table results

`jt_*` tools report per slot in `data.errors`, with `ok: true` for the call itself:
`OUT_OF_RANGE` (target outside `code_min`..`code_max`), `ARM_INSTRUCTION` (the slot holds
an instruction, not a pointer), `NO_FUNCTION_AT_TARGET`, `TOOL_BINDING_MISSING` (the slot
could not be read), `WRITE_DISABLED_DRY_RUN`, `WRITE_VERIFY_FAILED` (Ghidra did not
confirm the rename or comment).

## Answers that look wrong

- **Empty listing at an address.** If the answer says `UNMAPPED`, there is no memory there
  (`project_info` lists the blocks). If it has a `coverage` note, the bytes there are not
  defined as instructions in Ghidra; read them with `read_words`.
- **`search_scalars` finds nothing for a register address.** Those usually sit in a
  constant pool as data, not in an instruction; the answer's note says where to look.
- **Every jump-table slot is `OUT_OF_RANGE`.** The table's pointers do not match the
  program's memory map, usually because the image is loaded at the wrong base.
