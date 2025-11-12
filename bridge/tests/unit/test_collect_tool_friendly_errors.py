from __future__ import annotations

import pytest

import bridge.api.tools as tools
from bridge.api.tools import register_tools
from bridge.utils.errors import ErrorCode
from mcp.server.fastmcp import FastMCP


class DummyClient:
    def close(self) -> None:  # pragma: no cover - interface compliance
        pass


def _collect_tool(monkeypatch: pytest.MonkeyPatch):
    def fail_validate(name: str, payload):  # pragma: no cover - exercised in tests
        raise AssertionError("validate_payload should not run for friendly errors")

    monkeypatch.setattr(tools, "validate_payload", fail_validate)

    server = FastMCP("test")
    register_tools(server, client_factory=DummyClient)
    return server._tool_manager._tools["collect"]


def _error_message(response: dict[str, object]) -> str:
    assert response["ok"] is False
    errors = response["errors"]
    assert isinstance(errors, list) and errors
    first = errors[0]
    assert first["code"] == ErrorCode.INVALID_REQUEST.value
    message = first["message"]
    assert isinstance(message, str)
    return message


def test_collect_friendly_error_for_type(monkeypatch: pytest.MonkeyPatch) -> None:
    collect_tool = _collect_tool(monkeypatch)

    response = collect_tool.fn(
        queries=[{"id": "q1", "type": "search_functions", "filter": {"query": "main"}}]
    )

    message = _error_message(response)
    assert "Use 'op': 'search_functions' and 'params': {...}" in message
    assert "Supported 'op' values" in message


def test_collect_friendly_error_for_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    collect_tool = _collect_tool(monkeypatch)

    response = collect_tool.fn(
        queries=[{"id": "q1", "op": "search_functions", "filter": {"query": "main"}}]
    )

    message = _error_message(response)
    assert "uses 'filter'" in message
    assert "Use 'op': 'search_functions' and 'params': {...}" in message


def test_collect_friendly_error_for_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    collect_tool = _collect_tool(monkeypatch)

    response = collect_tool.fn(
        queries=[{"id": "q1", "op": "search_functions", "params": {}}],
        result_budget={"max_items": 50},
    )

    message = _error_message(response)
    assert "uses 'max_items'" in message
    assert "max_result_tokens" in message
    assert "docs/api.md" in message
