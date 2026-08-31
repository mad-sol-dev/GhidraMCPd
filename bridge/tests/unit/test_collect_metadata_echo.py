"""collect promises to echo metadata, and the response schema has to allow it.

The tool's docstring says "metadata: arbitrary JSON returned unchanged", the
request schema accepts it and the tool copies it into the response -- but the
response schema listed only queries, meta and projects with
additionalProperties false.  So a valid request produced a response the server
itself rejected, and the caller was told 400 INVALID_REQUEST: additional
properties are not allowed.  The blame landed on the request, which was fine.

An existing test already called collect with metadata and passed, because it
replaces validate_payload with a stub that approves everything.  These tests run
the real validator; that is the whole point of them.
"""
from typing import Any, Dict

import pytest
from mcp.server.fastmcp import FastMCP

import bridge.api.tools as tools
from bridge.api.tools import register_tools
from bridge.api.validators import validate_payload


class _Client:
    """Enough client for the collect tool to reach its own validation."""

    def __init__(self) -> None:
        self.base_url = "http://base/"

    def get_current_program_status(self):
        return {
            "program_name": "demo",
            "domain_file_id": "1",
            "state": "READY",
            "locked": False,
        }

    def close(self) -> None:  # pragma: no cover - nothing to close
        pass


@pytest.fixture
def collect_tool(monkeypatch):
    """The registered collect tool, with the real payload validation in place."""

    def fake_execute_collect(client, queries, result_budget=None):
        return {
            "queries": [
                {
                    "id": item["id"],
                    "op": item["op"],
                    "result": {"ok": True, "data": {}, "errors": []},
                }
                for item in queries
            ],
            "meta": {"estimate_tokens": len(list(queries))},
        }

    monkeypatch.setattr(tools, "execute_collect", fake_execute_collect)

    server = FastMCP("test")
    register_tools(server, client_factory=_Client, enable_writes=False)
    return server._tool_manager._tools["collect"].fn


def test_metadata_is_accepted_and_returned_unchanged(collect_tool):
    payload: Dict[str, Any] = {"zweck": "reproduktion", "nested": {"n": 1}}
    response = collect_tool(
        queries=[{"id": "q1", "op": "demo"}],
        metadata=payload,
    )

    assert response["ok"] is True, response["errors"]
    assert response["data"]["metadata"] == payload


def test_the_same_call_without_metadata_still_works(collect_tool):
    response = collect_tool(queries=[{"id": "q1", "op": "demo"}])
    assert response["ok"] is True, response["errors"]
    assert "metadata" not in response["data"]


def test_request_and_response_schemas_agree_on_metadata():
    """The two schemas have to move together, or the echo breaks again."""

    request = {"queries": [{"id": "q1", "op": "demo"}], "metadata": {"a": 1}}
    valid, errors = validate_payload("collect.request.v1.json", request)
    assert valid, errors

    response = {
        "queries": [{"id": "q1", "op": "demo", "result": {"ok": True, "data": {}, "errors": []}}],
        "meta": {"estimate_tokens": 1},
        "metadata": {"a": 1},
    }
    valid, errors = validate_payload("collect.v1.json", response)
    assert valid, errors
