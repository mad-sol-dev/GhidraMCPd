"""R.24 phase 2: the plugin's failures have a status, and the bridge reads it.

API 2: every failure is an HTTP 4xx/5xx with {"status":"error","code","error"},
every response carries X-GhidraMCP-API.  The mocks answer exactly that.  The
source checks hold the plugin to it, the way test_plugin_routes holds the
bridge's aliases to real routes.
"""
from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from mcp.server.fastmcp import FastMCP

from bridge.api.tools import register_tools
from bridge.features import analyze, strings
from bridge.ghidra.client import GhidraClient
from bridge.tests.plugin_http import plugin_error, plugin_transport
from bridge.utils.cache import get_search_cache
from bridge.utils.program_context import PROGRAM_SELECTIONS

PLUGIN_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "src/main/java/com/lauriewired/GhidraMCPPlugin.java"
)
STATUS = {"domain_file_id": "prog-1", "locked": False, "state": "READY",
          "state_duration_seconds": 1, "warnings": []}
FILES = [{"domain_file_id": "prog-1", "name": "alpha", "path": "/alpha", "type": "Program"},
         {"domain_file_id": "prog-2", "name": "beta", "path": "/beta", "type": "Program"}]


def _client(routes: dict) -> GhidraClient:
    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path.lstrip("/")
        if path == "api/current_program.json":
            return httpx.Response(200, json=STATUS)
        if path == "project_files":
            return httpx.Response(200, json=FILES)
        answer = routes.get(path)
        if answer is None:
            return httpx.Response(404, text="<h1>404 Not Found</h1>No context found for request")
        return answer() if callable(answer) else answer

    return GhidraClient("http://ghidra.test/", transport=plugin_transport(handle))


def _tools(routes: dict, *, enable_writes: bool = True):
    PROGRAM_SELECTIONS.clear()
    get_search_cache().clear()
    server = FastMCP("api2")
    register_tools(server, client_factory=lambda: _client(routes), enable_writes=enable_writes)
    return server._tool_manager._tools


# --- the plugin's verdict reaches the caller -----------------------------------


def test_a_refused_rename_keeps_the_plugins_status():
    tools = _tools({
        "get_function_by_address": httpx.Response(
            200, text="Function: old at 00401000\nSignature: undefined old(void)\nEntry: 00401000\n"),
        "rename_function_by_address": plugin_error(409, "CONFLICT", "Symbol already exists: taken"),
    })

    result = tools["rename_function"].fn("0x401000", "taken", dry_run=False)

    error = result["errors"][0]
    assert (error["code"], error["status"]) == ("INVALID_REQUEST", 409)
    assert "already exists" in error["message"]
    assert error["upstream"]["code"] == "CONFLICT"


def test_a_plugin_without_api_2_is_named_with_how_to_fix():
    def old_plugin(request):
        return httpx.Response(200, text="Function: x at 00401000\n")

    PROGRAM_SELECTIONS.clear()
    server = FastMCP("old")
    register_tools(
        server,
        client_factory=lambda: GhidraClient("http://ghidra.test/", transport=plugin_transport(old_plugin, api=None)),
    )

    result = server._tool_manager._tools["project_info"].fn()

    error = result["errors"][0]
    assert error["code"] == "UNAVAILABLE"
    assert "predates API 2" in error["message"]
    assert any("install" in step.lower() for step in error["recovery"])


def test_an_invalid_address_is_a_bad_request_not_a_crash_text():
    tools = _tools({"readBytes": plugin_error(400, "INVALID_REQUEST", "invalid address for address: 'zz'")})

    result = tools["read_bytes"].fn("0x10", 4)

    assert result["ok"] is False
    assert (result["errors"][0]["code"], result["errors"][0]["status"]) == ("INVALID_REQUEST", 400)


def test_unmapped_memory_is_a_finding_not_a_failure():
    tools = _tools({"readBytes": plugin_error(404, "UNMAPPED", "memory access failed: no memory at 7f000000")})

    result = tools["read_bytes"].fn("0x7f000000", 4)

    assert result["ok"] is True
    assert result["data"]["length"] == 0
    assert "method_note" in result["data"]


def test_a_failed_read_is_not_reported_as_unmapped():
    tools = _tools({"readBytes": plugin_error(500, "INTERNAL", "memory access failed: boom")})

    result = tools["read_bytes"].fn("0x00200000", 4)

    assert result["ok"] is False
    assert result["errors"][0]["code"] == "UNAVAILABLE"


def test_decompiler_failure_stays_in_its_section():
    routes = {
        "get_function_by_address": httpx.Response(
            200, text="Function: f at 00401000\nSignature: undefined f(void)\nEntry: 00401000\nBody: 00401000 - 00401003\n"),
        "decompile_function": plugin_error(500, "INTERNAL", "Decompilation failed: timeout"),
    }
    client = _client(routes)

    section, _ = analyze._collect_decompile(client, entry_point=0x401000, enabled=True, max_lines=20)

    assert section["snippet"] is None
    assert section["error"].startswith("decompilation_failed")
    assert "timeout" in section["error"]


def test_a_failed_program_switch_keeps_the_previous_selection():
    tools = _tools({
        "open_program": plugin_error(409, "CONFLICT", "Cannot switch programs: current program has unsaved changes"),
    })

    first = tools["select_program"].fn("prog-2")

    assert first["ok"] is False
    assert "unsaved changes" in first["errors"][0]["message"]
    assert PROGRAM_SELECTIONS.selected_program_id(("mcp", "default")) is None


def test_string_refs_come_from_the_plugin():
    page = {"items": [{"address": "0x0020e76c", "literal": "%m/%d/%y", "refs": 3}], "has_more": False}
    client = _client({"strings": httpx.Response(200, json=page)})

    entries, _has_more = strings.fetch_strings_compact_entries(client, limit=5, offset=0)
    view = strings.strings_compact_view(entries)

    assert view["items"][0]["refs"] == 3


# --- the plugin keeps to it ----------------------------------------------------


def _source() -> str:
    return PLUGIN_SOURCE.read_text(encoding="utf-8")


def test_no_failure_is_returned_as_text():
    """Every failure throws a RouteError; none is a returned sentence."""

    leftovers = re.findall(
        r'return "(?:No |Failed|Error|Function not found|Decompilation failed|Variable not found|ERROR:)[^"]*"',
        _source(),
    )
    assert leftovers == []


def test_no_json_error_body_is_built_by_hand():
    source = _source()
    assert "jsonErrorEnvelope(" not in source
    assert "CursorPager.errorJson(" not in source
    assert '"Internal error: " + e.getMessage()' not in source


def test_every_response_writer_sets_the_api_header():
    source = _source()
    for writer in ("private void sendResponse(", "private void sendJsonResponse(",
                   "private static void writeJson(", 'server.createContext("/plugin_version"'):
        body = source[source.index(writer):]
        body = body[: body.index("sendResponseHeaders")]
        assert "API_HEADER" in body, writer
