"""R.26: a write goes only to the program it was meant for.

Every request through a write endpoint first reads the active program.  It is
refused before sending when no program is known or active, or when the session
chose another one with select_program; otherwise it carries the active
program's domain_file_id, and the plugin refuses it (HTTP 409) if a different
program became active in between.  A default selection taken from the project
listing is no choice and binds nothing.

The mocked plugin answers with the shapes the real one sends: the five fields
of /api/current_program.json, prose for get_function_by_address, and the
plugin's 409 body for a mismatch.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.api.tools import register_tools
from bridge.ghidra.client import (
    ENDPOINT_CANDIDATES,
    POST_ENDPOINT_CANDIDATES,
    WRITE_ENDPOINT_KEYS,
    GhidraClient,
)
from bridge.utils.program_context import PROGRAM_SELECTIONS

PLUGIN_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "src/main/java/com/lauriewired/GhidraMCPPlugin.java"
)

FILES = [
    {"domain_file_id": "prog-1", "name": "alpha", "path": "/alpha", "type": "Program"},
    {"domain_file_id": "prog-2", "name": "beta", "path": "/beta", "type": "Program"},
]


class FakePlugin:
    """The plugin's HTTP surface, as far as these tests need it."""

    def __init__(self, active: str | None = "prog-1") -> None:
        self.active = active
        self.status_up = True
        self.writes: list[httpx.Request] = []
        #: switch the active program after the bridge's check, before the write
        self.switch_before_write: str | None = None

    def status(self) -> dict:
        return {"domain_file_id": self.active, "locked": False, "state": "READY",
                "state_duration_seconds": 5, "warnings": []}

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.lstrip("/")
        if path == "api/current_program.json":
            if not self.status_up:
                return httpx.Response(503, text='{"error":"No active tool available","status":"error"}')
            return httpx.Response(200, text=json.dumps(self.status()))
        if path == "project_files":
            return httpx.Response(200, text=json.dumps(FILES))
        if path == "open_program":
            self.active = request.url.params["domain_file_id"]
            return httpx.Response(200, text=json.dumps({"status": "ok", "warnings": []}))
        if path == "get_function_by_address":
            return httpx.Response(200, text="Function: old_name at 00401000\nEntry: 00401000\n")
        if path in {"rename_function_by_address", "set_disassembly_comment", "createStructure"}:
            if self.switch_before_write:
                self.active = self.switch_before_write
            requested = request.url.params.get("domain_file_id")
            if requested and requested != self.active:
                body = {"status": "error",
                        "error": (f"Write refused: domain_file_id '{requested}' is not the active "
                                  f"program '{self.active}' (beta); nothing was changed"),
                        "requested_domain_file_id": requested,
                        "active_domain_file_id": self.active}
                return httpx.Response(409, text=json.dumps(body))
            self.writes.append(request)
            if path == "createStructure":
                return httpx.Response(200, text=json.dumps(
                    {"status": "ok", "datatype": {"kind": "structure", "name": "Widget",
                                                  "path": "/Widget", "size": 4, "fields": []}}))
            return httpx.Response(200, text="Function renamed successfully")
        return httpx.Response(404, text="ERROR: not found")


@pytest.fixture
def plugin():
    PROGRAM_SELECTIONS.clear()
    yield FakePlugin()
    PROGRAM_SELECTIONS.clear()


def _client(plugin: FakePlugin, expected: str | None = None) -> GhidraClient:
    client = GhidraClient("http://ghidra.test/", transport=httpx.MockTransport(plugin.handle))
    client.expected_program_id = expected
    return client


# --- the client ---------------------------------------------------------------


def test_matching_program_write_names_it(plugin):
    client = _client(plugin, expected="prog-1")

    assert client.rename_function(0x401000, "new_name") is True
    (write,) = plugin.writes
    assert write.url.params["domain_file_id"] == "prog-1"
    assert parse_qs(write.content.decode())["new_name"] == ["new_name"]
    assert client.write_refusal is None


def test_session_without_selection_writes_to_the_active_program(plugin):
    client = _client(plugin, expected=None)

    assert client.rename_function(0x401000, "new_name") is True
    assert plugin.writes[0].url.params["domain_file_id"] == "prog-1"


def test_mismatch_is_refused_before_sending(plugin):
    client = _client(plugin, expected="prog-2")

    assert client.rename_function(0x401000, "new_name") is False
    assert plugin.writes == []
    refusal = client.write_refusal
    assert refusal.status == 409 and not refusal.retryable
    assert "selected domain_file_id 'prog-2'" in refusal.reason
    assert "active program is 'prog-1'" in refusal.reason


def test_no_active_program_is_refused(plugin):
    plugin.active = None
    client = _client(plugin)

    assert client.set_disassembly_comment(0x401000, "x") is False
    assert plugin.writes == []
    assert "no program is active" in client.write_refusal.reason


def test_unknown_program_state_is_refused_and_retryable(plugin):
    plugin.status_up = False
    client = _client(plugin)

    assert client.rename_function(0x401000, "new_name") is False
    assert plugin.writes == []
    assert client.write_refusal.retryable is True


def test_switch_between_check_and_write_is_refused_by_the_plugin(plugin):
    plugin.switch_before_write = "prog-2"
    client = _client(plugin)

    assert client.rename_function(0x401000, "new_name") is False
    assert plugin.writes == []
    assert client.write_refusal.status == 409
    assert client.write_refusal.reason.startswith("Write refused: domain_file_id 'prog-1'")


def test_reads_do_not_check_the_program(plugin):
    seen: list[str] = []

    def handle(request):
        seen.append(request.url.path)
        return plugin.handle(request)

    client = GhidraClient("http://ghidra.test/", transport=httpx.MockTransport(handle))
    client.get_function_by_address(0x401000)

    assert seen == ["/get_function_by_address"]


# --- the plugin and the bridge agree on what a write is -----------------------


def _plugin_write_routes() -> set[str]:
    source = PLUGIN_SOURCE.read_text(encoding="utf-8")
    return set(re.findall(r'registerWriteHandler\(\s*server,\s*"/([^"]+)"', source))


def test_every_bridge_write_key_hits_a_checked_plugin_route():
    write_routes = _plugin_write_routes()
    # 15 routes that call a mutating method or save, on 2026-10-10
    assert len(write_routes) == 15
    candidates = {**ENDPOINT_CANDIDATES, **POST_ENDPOINT_CANDIDATES}
    for key, aliases in candidates.items():
        checked = all(alias in write_routes for alias in aliases)
        if key in WRITE_ENDPOINT_KEYS:
            assert checked, f"{key} -> {aliases} is not a registerWriteHandler route"
        else:
            assert not any(alias in write_routes for alias in aliases), (
                f"{key} -> {aliases} writes but is missing from WRITE_ENDPOINT_KEYS"
            )


def test_mutating_plugin_methods_sit_behind_write_routes():
    """No route reaches a transaction without the program check."""

    source = PLUGIN_SOURCE.read_text(encoding="utf-8")
    for match in re.finditer(r'register(Program|Project)Handler\(\s*server,\s*"/([^"]+)"', source):
        body = source[match.end(): source.index("});", match.end())]
        assert "startTransaction" not in body, match.group(2)
        assert not re.search(
            r"plugin\.(rename|set[A-Z]|create[A-Z]|update[A-Z]|delete[A-Z]|save[A-Z])", body
        ), f"/{match.group(2)} calls a write without registerWriteHandler"


# --- tools and routes ---------------------------------------------------------


def _tools(plugin: FakePlugin):
    server = FastMCP("guard")
    register_tools(server, client_factory=lambda: _client(plugin), enable_writes=True)
    return server._tool_manager._tools


def test_tool_refusal_is_a_structured_invalid_request(plugin):
    tools = _tools(plugin)
    assert tools["select_program"].fn("prog-2")["ok"] is True
    plugin.active = "prog-1"  # the user switched back in Ghidra

    result = tools["rename_function"].fn("0x401000", "new_name", dry_run=False)

    assert result["ok"] is False
    error = result["errors"][0]
    assert error["code"] == "INVALID_REQUEST" and error["status"] == 409
    assert "selected domain_file_id 'prog-2'" in error["message"]
    assert any("select_program" in step for step in error["recovery"])
    assert plugin.writes == []


def test_tool_writes_after_selecting_the_active_program(plugin):
    tools = _tools(plugin)
    assert tools["select_program"].fn("prog-2")["ok"] is True

    result = tools["rename_function"].fn("0x401000", "new_name", dry_run=False)

    assert result["ok"] is True
    assert plugin.writes[0].url.params["domain_file_id"] == "prog-2"


def test_a_default_selection_does_not_bind_writes(plugin):
    plugin.active = "prog-2"  # opened in Ghidra; the listing's first entry is prog-1
    tools = _tools(plugin)
    assert tools["get_current_program"].fn()["ok"] is True

    result = tools["rename_function"].fn("0x401000", "new_name", dry_run=False)

    assert result["ok"] is True
    assert plugin.writes[0].url.params["domain_file_id"] == "prog-2"


def test_http_write_route_refuses_a_mismatch(plugin):
    app = Starlette(routes=make_routes(lambda: _client(plugin), enable_writes=True))
    body = {"kind": "structure", "name": "Widget", "category": "/",
            "fields": [{"name": "id", "type": "uint32", "offset": 0, "length": 4}],
            "dry_run": False}
    with TestClient(app) as http:
        headers = {"x-requestor-id": "r26"}
        selected = http.post("/api/select_program.json", json={"domain_file_id": "prog-2"},
                             headers=headers)
        assert selected.status_code == 200
        plugin.active = "prog-1"

        refused = http.post("/api/datatypes/create.json", json=body, headers=headers)

    assert refused.status_code == 409
    error = refused.json()["errors"][0]
    assert error["code"] == "INVALID_REQUEST"
    assert "selected domain_file_id 'prog-2'" in error["message"]
    assert plugin.writes == []
