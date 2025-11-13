# Migration (Legacy → Bridge)

- The renamed helper now lives at `python scripts/bridge_stdio.py` for stdio-only experiments; see [Stdio mode](getting-started.md#stdio-mode) for the updated CLI flags and usage tips.
- For supported SSE or production usage continue with the factory app: `uvicorn bridge.app:create_app --factory` and review [Server operations](server.md#legacy-stdio-transport) for differences between SSE and stdio.
- Reference pages: [search](api/search.md), [JT](api/jt.md), [strings](api/strings.md), [sse](sse.md)
