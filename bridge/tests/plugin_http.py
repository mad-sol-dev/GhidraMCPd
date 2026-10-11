"""Mock transports that answer the way the Ghidra plugin does (API 3).

Every plugin response carries ``X-GhidraMCP-API``; the bridge refuses one
without it (R.24).  A test that builds ``httpx.MockTransport`` directly would
be talking to a plugin older than the bridge accepts, so the tests use this.
The JDK server's own 404 for a missing route has no such header in reality,
which does not matter: the bridge recognises a missing route before it looks.
"""
from __future__ import annotations

import base64
from typing import Callable

import httpx

from bridge.ghidra.client import PLUGIN_API_HEADER, REQUIRED_PLUGIN_API
from bridge.utils.errors import UpstreamFailed

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
    """A failure as the plugin sends it (since API 2)."""

    return httpx.Response(status, json={"status": "error", "code": code, "error": message})


# --- cursors as CursorPager writes and reads them --------------------------------


def _b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def plugin_cursor(route: str, discriminator: str, offset: int) -> str:
    """``v1.<b64url route>.<b64url discriminator>.<offset>``, as CursorPager encodes it.

    ``route`` is ``searchFunctions`` or ``searchScalars``; the discriminator is
    the lowercased query (``*`` for all) or the value as unsigned decimal.
    """

    return f"v1.{_b64url(route)}.{_b64url(discriminator)}.{offset}"


def plugin_cursor_start(cursor: str | None, route: str, discriminator: str, offset: int) -> int:
    """Where the plugin starts for ``cursor``, for client-level stubs.

    No cursor: ``offset``.  A cursor it cannot decode, or one for another
    route or query, is a 400 INVALID_REQUEST (API 3; API 2 restarted at
    ``offset`` silently), which the client raises as UpstreamFailed.
    """

    if not cursor:
        return max(0, offset)
    parts = cursor.split(".")
    if len(parts) == 4 and parts[:3] == ["v1", _b64url(route), _b64url(discriminator)]:
        try:
            return max(0, int(parts[3]))
        except ValueError:
            pass
    raise UpstreamFailed(
        f"cursor belongs to another search, not {route} for '{discriminator}'",
        code="INVALID_REQUEST",
        status=400,
    )
