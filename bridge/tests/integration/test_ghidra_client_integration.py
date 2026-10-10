from __future__ import annotations

import httpx

from bridge.ghidra.client import GhidraClient


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
        return httpx.Response(200, text="name: target\nentry_point: 0x00001000\n")
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
    client = GhidraClient("http://ghidra/", transport=httpx.MockTransport(_success_handler))

    assert client.read_dword(0x1000) == 0x1000
    meta = client.get_function_by_address(0x1000)
    assert meta and meta["name"] == "target"
    assert client.disassemble_function(0x1000)
    assert client.get_xrefs_to(0x2000) == [
        {"addr": 0x2000, "context": "BL target"}
    ]
    assert client.rename_function(0x1000, "new_name") is True
    assert client.set_decompiler_comment(0x1000, "note") is True
    assert client.set_disassembly_comment(0x1000, "note") is True


def _failure_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path.endswith("/api/current_program.json"):
        return httpx.Response(200, json=_STATUS)
    if path.endswith("/read_dword"):
        return httpx.Response(200, text="n/a\n")
    if path.endswith("/get_function_by_address"):
        return httpx.Response(500, text="Internal error\n")
    # What the plugin really says when a rename or comment fails: HTTP 200
    # and prose.  These answers used to be "ERROR: ...", which it never sends.
    if path.endswith("/rename_function_by_address"):
        return httpx.Response(200, text="Failed to rename function")
    if path.endswith("/set_decompiler_comment"):
        return httpx.Response(200, text="Failed to set comment")
    if path.endswith("/set_disassembly_comment"):
        return httpx.Response(200, text="Failed to set comment")
    return httpx.Response(404, text="ERROR: not found\n")


def test_ghidra_client_handles_failures() -> None:
    client = GhidraClient("http://ghidra/", transport=httpx.MockTransport(_failure_handler))

    assert client.read_dword(0x1000) is None
    assert client.get_function_by_address(0x1000) is None
    assert client.rename_function(0x1000, "new") is False
    assert client.last_error.reason == "Failed to rename function"
    assert client.set_decompiler_comment(0x1000, "note") is False
    assert client.set_disassembly_comment(0x1000, "note") is False


def test_ghidra_client_timeouts_are_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    client = GhidraClient("http://ghidra/", transport=httpx.MockTransport(handler), timeout=0.01)

    assert client.read_dword(0x1000) is None
    assert client.rename_function(0x1000, "name") is False
