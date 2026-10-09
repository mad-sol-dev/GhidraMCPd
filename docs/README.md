# Usage examples

A few copy/paste requests for local testing while developing against the API.

## Read bytes

```bash
curl -sS -X POST http://localhost:8000/api/read_bytes.json \
  -H 'content-type: application/json' \
  -d '{"address":"0x00400000","length":16}' | jq
```

## Navigate to address

Navigate the CodeBrowser cursor to a specific address, centering it on screen:

```bash
curl -sS "http://localhost:8080/goto?address=0x00000080"
```

Response:
```json
{
  "status": "ok",
  "address": "00000080",
  "message": "Navigated to address"
}
```

This endpoint is useful for programmatically inspecting code locations found through search operations. The address is centered in the listing window for immediate visibility.
