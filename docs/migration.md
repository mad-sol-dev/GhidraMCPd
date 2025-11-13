# Migration (Legacy → Bridge)

- The renamed helper now lives at `python scripts/bridge_stdio.py` for stdio-only experiments; SSE mode in that helper remains unsupported.
- For supported SSE or production usage continue with the factory app: `uvicorn bridge.app:create_app --factory`
- Reference pages: [search](api/search.md), [JT](api/jt.md), [strings](api/strings.md), [sse](sse.md)
