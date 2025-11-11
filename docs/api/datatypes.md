# Data-type management API

The bridge exposes helper endpoints for creating, updating, and deleting
structures and unions inside the active Ghidra program. All endpoints share the
same safety model used elsewhere in the bridge: write operations are disabled by
default, calls honour the per-request write counters, and every response is
wrapped in the standard envelope returned by the API gateway.

Each route accepts a JSON payload that describes the type to manipulate and
responds with a stable summary of the operation that was attempted. When
`dry_run` is set to `true` (the default) no writes are forwarded to the Ghidra
plugin. Clearing `dry_run` requires the server to be started with
`GHIDRA_MCP_ENABLE_WRITES=1` and still consumes one write token from the current
request scope.

## POST `/api/datatypes/create.json`

Create a new structure or union in the active project. The request schema is
`datatypes_create.request.v1.json`.

```json
{
  "kind": "structure",
  "name": "Widget",
  "category": "/structs",
  "fields": [
    {"name": "id", "type": "uint32", "offset": 0, "length": 4},
    {"name": "flags", "type": "uint16", "offset": 4, "length": 2}
  ],
  "dry_run": false
}
```

Responses conform to `datatypes_create.v1.json` and always include the computed
path, the normalised field list, and the inferred size (when available). During
a dry run the `written` flag remains `false` and a note describing the simulated
operation is included.

## POST `/api/datatypes/update.json`

Update an existing structure or union in-place. The request schema is
`datatypes_update.request.v1.json` and requires the fully-qualified data-type
path plus the new field definitions. Response envelopes follow
`datatypes_update.v1.json` and echo the final layout reported by the plugin (or
the requested layout if the plugin returned no additional metadata).

## POST `/api/datatypes/delete.json`

Delete a structure or union by path. The request schema is
`datatypes_delete.request.v1.json` and the response schema is
`datatypes_delete.v1.json`. Successful deletes set `written` to `true` and return
the canonicalised `kind` and `path`. Dry runs add notes explaining that no data
types were removed.

## Safety limits

All three routes share the standard per-request write guard. Each successful
write consumes a single token and will raise an error if the configured limit is
exceeded. The bridge will also reject attempts to proceed while writes are
disabled, returning `WRITE_DISABLED` in the response envelope.
