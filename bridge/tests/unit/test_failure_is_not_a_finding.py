"""R.24 phase 1: a failed request must not come back as a finding.

From the inventory in docs/notes/ghidramcpd-rework.md ("R.24 — Bestandsaufnahme"): places
where the bridge turned a plugin failure into "no matches", "all functions",
"a function is here", or a field that is always the same value.  The mocked
plugin answers in the shapes the real one sends (API 2: a failure carries an
HTTP error status).
"""
from __future__ import annotations

import json

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from bridge.api.tools import register_tools
from bridge.ghidra.client import GhidraClient
from bridge.utils.cache import get_search_cache
from bridge.utils.program_context import PROGRAM_SELECTIONS
from bridge.tests.plugin_http import plugin_transport

STATUS = {"domain_file_id": "prog-1", "locked": False, "state": "READY",
          "state_duration_seconds": 1, "warnings": []}
#: What a program route answers without a program (``notReady`` in the handler).
_NO_PROGRAM = (425, '{"status":"error","code":"NOT_READY","error":"No program loaded"}')


def _client(routes: dict, seen: list | None = None) -> GhidraClient:
    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path.lstrip("/")
        if seen is not None:
            seen.append(path)
        if path == "api/current_program.json":
            return httpx.Response(200, text=json.dumps(STATUS))
        answer = routes.get(path)
        if answer is None:
            return httpx.Response(404, text="<h1>404 Not Found</h1>No context found for request")
        status, body = answer if isinstance(answer, tuple) else (200, answer)
        return httpx.Response(status, text=body)

    return GhidraClient("http://ghidra.test/", transport=plugin_transport(handle))


def _tools(factory):
    PROGRAM_SELECTIONS.clear()
    server = FastMCP("phase1")
    register_tools(server, client_factory=factory)
    return server._tool_manager._tools


@pytest.fixture(autouse=True)
def _fresh_cache():
    get_search_cache().clear()
    yield
    get_search_cache().clear()


# --- the resolver sends a request once -----------------------------------------


def test_failed_search_is_an_error_not_all_functions():
    """The old fallback asked /functions for ``filter``, which it never reads."""

    seen: list[str] = []
    routes = {
        "searchFunctions": _NO_PROGRAM,
        "functions": "FUN_00200060 at 00200060\nFUN_0020014c at 0020014c",
    }
    tools = _tools(lambda: _client(routes, seen))

    result = tools["search_functions"].fn("usb")

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "UNAVAILABLE"
    assert "No program loaded" in result["errors"][0]["message"]
    assert "functions" not in seen


def test_failed_search_is_not_cached():
    calls: list[str] = []
    routes = {"searchFunctions": _NO_PROGRAM}
    tools = _tools(lambda: _client(routes, calls))

    tools["search_functions"].fn("usb")
    tools["search_functions"].fn("usb")

    assert calls.count("searchFunctions") == 2


def test_a_real_empty_search_is_still_empty():
    routes = {"searchFunctions": '{"items":[],"has_more":false}'}
    tools = _tools(lambda: _client(routes))

    result = tools["search_functions"].fn("no_such_name")

    assert result["ok"] is True
    assert result["data"]["items"] == []


# --- a failed listing is not an empty one, and is not cached ------------------

@pytest.mark.parametrize(
    "tool, args, route",
    [
        ("search_imports", ("usb",), "imports"),
        ("search_exports", ("usb",), "exports"),
        ("search_strings", ("usb",), "strings"),
        ("search_xrefs_to", ("0x002af9c0", ""), "xrefs_to"),
        ("string_xrefs_compact", ("0x0020e76c",), "xrefs_to"),
    ],
)
def test_failed_listing_is_unavailable_and_not_cached(tool, args, route):
    seen: list[str] = []
    tools = _tools(lambda: _client({route: _NO_PROGRAM}, seen))

    first = tools[tool].fn(*args)
    tools[tool].fn(*args)

    assert first["ok"] is False, first
    assert first["errors"][0]["code"] == "UNAVAILABLE"
    assert "No program loaded" in first["errors"][0]["message"]
    assert seen.count(route) == 2


@pytest.mark.parametrize(
    "tool, args, route",
    [
        ("search_imports", ("usb",), "imports"),
        ("search_xrefs_to", ("0x002af9c0", ""), "xrefs_to"),
    ],
)
def test_a_real_empty_listing_is_still_empty(tool, args, route):
    tools = _tools(lambda: _client({route: '{"items":[],"has_more":false}'}))

    result = tools[tool].fn(*args)

    assert result["ok"] is True
    assert result["data"]["items"] == []


def test_an_unexpected_shape_says_so():
    """A strict client schema used to turn an extra field into a silent empty list."""

    body = '{"items":[],"has_more":false,"total":0}'
    tools = _tools(lambda: _client({"imports": body}))

    result = tools["search_imports"].fn("usb")

    assert result["ok"] is False
    assert "unexpected shape" in result["errors"][0]["message"]
