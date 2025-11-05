# Troubleshooting

- **409 on `/sse`**: by design; only one active client.
- **425 on `/messages`**: session not ready; connect SSE and wait for readiness.
- **Noisy `CancelledError` on shutdown**: ensure you are on a recent build; the bridge suppresses expected cancellations.
- **Adapter error**: unknown optional adapter → check `BRIDGE_OPTIONAL_ADAPTERS` names.

## SSE Connection Error (409 Conflict) - Detailed Guide

### Symptom
Error messages in MCP clients like AiderDesk:
- "SSE error: Non-200 status code (409)"
- "Error invoking remote method 'load-mcp-server-tools'"

### Root Cause
The Ghidra Java plugin does not support parallel operations. The GhidraMCP bridge enforces a single active SSE connection to prevent concurrent access that could cause data corruption or crashes in Ghidra.

### Common Scenarios

#### AiderDesk Task Switching
When switching between tasks or projects, AiderDesk may attempt to reconnect before the previous connection is fully closed.

Server logs show:
```
INFO: 127.0.0.1:44026 - "GET /sse HTTP/1.1" 200 OK          # First connection
INFO: 127.0.0.1:48446 - "GET /sse HTTP/1.1" 409 Conflict   # Second rejected
INFO: 127.0.0.1:57816 - "GET /sse HTTP/1.1" 200 OK          # After disconnect
```

#### MCP Server Reload
Reloading MCP servers can trigger reconnection attempts while the old connection is still active.

### Solution

**Wait 5-10 seconds** for the old connection to close automatically. The server accepts new connections once the previous one disconnects.

Check server logs for disconnect confirmation:
```
INFO: sse.disconnect {"connection_id": "...", "cancelled": false}
```

### Prevention

**For MCP clients**:
- Ensure old SSE connections are fully closed before opening new ones
- Implement proper connection lifecycle management
- Wait for HTTP disconnect to complete before reconnecting

**For AiderDesk users**:
- Avoid rapidly switching between tasks
- Wait for previous task to fully close before opening new one
- If error persists, restart the GhidraMCP server

### Manual Recovery

1. Check active connections:
   ```bash
   curl http://127.0.0.1:8081/state
   ```
   Look for `"active_sse": "<connection_id>"` (should be null when idle)

2. Restart the server if needed:
   ```bash
   python -m uvicorn bridge.app:create_app --factory --host 127.0.0.1 --port 8081
   ```

### Technical Details

The protection mechanism in bridge/app.py (lines 186-206) checks for active connections:
```python
if _BRIDGE_STATE.active_sse_id is not None:
    return JSONResponse(
        {"error": "sse_already_active", "detail": "Another client is connected."},
        status_code=409,
    )
```

This is intentional and necessary to protect the Ghidra plugin from concurrent access.

### FAQ

**Q: Why not allow multiple connections?**  
A: The Ghidra Java plugin doesn't support parallel operations. Multiple connections could cause data corruption.

**Q: Is this a bug?**  
A: No, this is intentional protection. The issue is clients reconnecting too quickly.

**Q: Will this be fixed?**  
A: The server behavior is correct. MCP clients should implement proper connection lifecycle management.
