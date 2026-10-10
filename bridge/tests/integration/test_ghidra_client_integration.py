from __future__ import annotations

import httpx
import pytest

from bridge.ghidra.client import GhidraClient
from bridge.tests.plugin_http import plugin_error, plugin_transport
from bridge.utils.errors import UpstreamFailed


# Both handlers answer the plugin's own route names.  They used to answer the
# dead aliases /function_by_addr and /get_xrefs_to, which the plugin never had,
# so the tests passed only because the resolver fell through to them.
#: Every write first reads the active program (R.26).
_STATUS = {"domain_file_id": "prog-1", "locked": False, "state": "READY",
           "state_duration_seconds": 1, "warnings": []}


def _success_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/api/current_program.json"):
        return httpx.Response(200, json=_STATUS)
    if path.endswith("/read_dword"):
        return httpx.Response(200, text="00001000\n")
    if path.endswith("/get_function_by_address"):
        return httpx.Response(200, text="Function: target at 00001000\nSignature: undefined target(void)\nEntry: 00001000\n")
    if path.endswith("/disassemble"):
        return httpx.Response(200, text="00001000: PUSH {lr}\n00001004: BX LR\n")
    if path.endswith("/xrefs_to"):
        payload = {"items": [{"address": "0x00002000", "context": "BL target"}], "has_more": False}
        return httpx.Response(200, json=payload)
    if path.endswith("/rename_function_by_address"):
        return httpx.Response(200, text="Function renamed successfully")
    if path.endswith("/set_decompiler_comment"):
        return httpx.Response(200, text="Comment set successfully")
    if path.endswith("/set_disassembly_comment"):
        return httpx.Response(200, text="Comment set successfully")
    return httpx.Response(404, text="ERROR: not found\n")


def test_ghidra_client_happy_path() -> None:
    client = GhidraClient("http://ghidra/", transport=plugin_transport(_success_handler))

    assert client.read_dword(0x1000) == 0x1000
    meta = client.get_function_by_address(0x1000)
    assert meta and meta["Function"] == "target at 00001000" and meta["Entry"] == "00001000"
    assert client.disassemble_function(0x1000)
    assert client.get_xrefs_to(0x2000) == [
        {"addr": 0x2000, "context": "BL target"}
    ]
    assert client.rename_function(0x1000, "new_name") is True
    assert client.set_decompiler_comment(0x1000, "note") is True
    assert client.set_disassembly_comment(0x1000, "note") is True


def _failure_handler(request: httpx.Request) -> httpx.Response:
    """Failures as the plugin sends them under API 2: a status and one JSON body."""

    path = request.url.path
    if path.endswith("/api/current_program.json"):
        return httpx.Response(200, json=_STATUS)
    if path.endswith("/read_dword"):
        return plugin_error(404, "UNMAPPED", "memory access failed: Unable to read bytes at ram:7f000000")
    if path.endswith("/get_function_by_address"):
        return plugin_error(404, "NOT_FOUND", "No function found at address 0x00001000")
    if path.endswith("/rename_function_by_address"):
        return plugin_error(409, "CONFLICT", "name already exists: FUN_00001000")
    if path.endswith("/set_decompiler_comment") or path.endswith("/set_disassembly_comment"):
        return plugin_error(404, "UNMAPPED", "no memory at 00001000")
    if path.endswith("/decompile_function"):
        return plugin_error(500, "INTERNAL", "Decompilation failed: timeout")
    return httpx.Response(404, text="<h1>404 Not Found</h1>No context found for request")


def test_absent_is_an_answer() -> None:
    """A read answered NOT_FOUND or UNMAPPED is a fact: nothing there."""

    client = GhidraClient("http://ghidra/", transport=plugin_transport(_failure_handler))

    assert client.read_dword(0x7F000000) is None
    assert client.last_error.code == "UNMAPPED"
    assert client.get_function_by_address(0x1000) is None
    assert client.last_error.code == "NOT_FOUND"


def test_failures_raise_with_the_plugins_code() -> None:
    client = GhidraClient("http://ghidra/", transport=plugin_transport(_failure_handler))

    with pytest.raises(UpstreamFailed) as raised:
        client.rename_function(0x1000, "new")
    assert (raised.value.code, raised.value.status) == ("CONFLICT", 409)
    # a failed write is never "absent", not even a 404
    with pytest.raises(UpstreamFailed) as raised:
        client.set_decompiler_comment(0x1000, "note")
    assert raised.value.code == "UNMAPPED"
    with pytest.raises(UpstreamFailed, match="Decompilation failed"):
        client.decompile_function(0x1000)


def test_a_plugin_without_api_2_is_refused() -> None:
    client = GhidraClient("http://ghidra/", transport=plugin_transport(_success_handler, api=None))

    with pytest.raises(UpstreamFailed) as raised:
        client.read_dword(0x1000)
    assert raised.value.code == "PLUGIN_TOO_OLD"
    assert "install" in str(raised.value)


def test_ghidra_client_timeouts_are_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = GhidraClient("http://ghidra/", transport=plugin_transport(handler), timeout=0.01)

    with pytest.raises(UpstreamFailed) as raised:
        client.read_dword(0x1000)
    assert raised.value.retryable is True
