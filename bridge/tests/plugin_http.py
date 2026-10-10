"""Mock transports that answer the way the Ghidra plugin does (API 2).

Every plugin response carries ``X-GhidraMCP-API``; the bridge refuses one
without it (R.24).  A test that builds ``httpx.MockTransport`` directly would
be talking to a plugin older than the bridge accepts, so the tests use this.
The JDK server's own 404 for a missing route has no such header in reality,
which does not matter: the bridge recognises a missing route before it looks.
"""
from __future__ import annotations

from typing import Callable

import httpx

from bridge.ghidra.client import PLUGIN_API_HEADER, REQUIRED_PLUGIN_API

Handler = Callable[[httpx.Request], httpx.Response]


def plugin_transport(handler: Handler, *, api: int | None = REQUIRED_PLUGIN_API) -> httpx.MockTransport:
    """``handler``'s answers, each with the plugin's API header (``api=None``: an old plugin)."""

    def handle(request: httpx.Request) -> httpx.Response:
        response = handler(request)
        if api is not None:
            response.headers[PLUGIN_API_HEADER] = str(api)
        return response

    return httpx.MockTransport(handle)


def plugin_error(status: int, code: str, message: str) -> httpx.Response:
    """A failure as the plugin sends it under API 2."""

    return httpx.Response(status, json={"status": "error", "code": code, "error": message})
