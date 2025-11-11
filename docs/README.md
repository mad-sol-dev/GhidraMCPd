# Usage examples

A few copy/paste requests for local testing while developing against the API.

## Read bytes

```bash
curl -sS -X POST http://localhost:8000/api/read_bytes.json \
  -H 'content-type: application/json' \
  -d '{"address":"0x00400000","length":16}' | jq
```

## Write bytes (dry run)

```bash
curl -sS -X POST http://localhost:8000/api/write_bytes.json \
  -H 'content-type: application/json' \
  -d '{"address":"0x00400000","data":"AAEC","dry_run":true}' | jq
```

The response keeps `ok=true`, reports `written=false`, and includes the note
`"dry-run enabled: no bytes written"`. Set `dry_run:false` and enable writes via
`GHIDRA_MCP_ENABLE_WRITES=1` to apply the bytes when the safety limit allows it.
