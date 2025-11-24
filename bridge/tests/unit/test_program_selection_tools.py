from mcp.server.fastmcp import FastMCP

import bridge.api.tools as tools
from bridge.api.tools import register_tools
from bridge.utils.program_context import PROGRAM_SELECTIONS


class _SelectionClient:
    def __init__(self) -> None:
        self.base_url = "http://ghidra/"

    def get_project_files(self):
        return [
            {
                "domain_file_id": "prog-1",
                "name": "alpha",
                "path": "/alpha",
                "type": "program",
                "size": 1024,
            },
            {
                "domain_file_id": "prog-2",
                "name": "beta",
                "path": "/beta",
                "type": "program",
                "size": 2048,
            },
        ]

    def close(self) -> None:  # pragma: no cover - exercised implicitly
        pass


def test_program_selection_tools_happy_path(monkeypatch) -> None:
    PROGRAM_SELECTIONS.clear()

    validations = []

    def fake_validate(name: str, payload):
        validations.append(name)
        return True, []

    monkeypatch.setattr(tools, "validate_payload", fake_validate)

    server = FastMCP("selection")
    register_tools(server, client_factory=_SelectionClient)

    current_tool = server._tool_manager._tools["get_current_program"]
    first = current_tool.fn()

    assert first["ok"] is True
    assert first["data"] == {"domain_file_id": "prog-1", "locked": False}

    select_tool = server._tool_manager._tools["select_program"]
    second = select_tool.fn("prog-2")

    assert second["ok"] is True
    assert second["data"] == {"domain_file_id": "prog-2", "locked": False}

    # Schema validation should be enforced for each envelope
    assert validations.count("current_program.v1.json") == 2


def test_program_selection_tools_reject_invalid_and_schema_error(monkeypatch) -> None:
    PROGRAM_SELECTIONS.clear()

    def fake_validate(name: str, payload):
        if name == "current_program.v1.json":
            return False, ["page size exceeds cap"]
        return True, []

    monkeypatch.setattr(tools, "validate_payload", fake_validate)

    server = FastMCP("selection-errors")
    register_tools(server, client_factory=_SelectionClient)

    select_tool = server._tool_manager._tools["select_program"]
    invalid = select_tool.fn("unknown")
    assert invalid["ok"] is False
    assert invalid["errors"][0]["message"].startswith("Unknown program id")

    current_tool = server._tool_manager._tools["get_current_program"]
    invalid_schema = current_tool.fn()
    assert invalid_schema["ok"] is False
    assert "page size exceeds cap" in invalid_schema["errors"][0]["message"]


def test_program_selection_tools_soft_policy_allows_switch(monkeypatch) -> None:
    PROGRAM_SELECTIONS.clear()
    monkeypatch.setenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY", "soft")

    validations = []

    def fake_validate(name: str, payload):
        validations.append(name)
        return True, []

    monkeypatch.setattr(tools, "validate_payload", fake_validate)

    server = FastMCP("selection-soft")
    register_tools(server, client_factory=_SelectionClient)

    current_tool = server._tool_manager._tools["get_current_program"]
    initial = current_tool.fn()
    assert initial["ok"] is True
    assert initial["data"]["domain_file_id"] == "prog-1"
    assert initial["data"].get("warnings") is None

    # Simulate program-dependent usage that locks the session for switching decisions
    PROGRAM_SELECTIONS.mark_used(("mcp", "default"))

    select_tool = server._tool_manager._tools["select_program"]
    switched = select_tool.fn("prog-2")

    assert switched["ok"] is True
    payload = switched["data"]
    assert payload["domain_file_id"] == "prog-2"
    assert payload["locked"] is True
    assert payload.get("warnings")
    assert payload["warnings"][0].startswith("Program selection switched mid-session")

    assert validations.count("current_program.v1.json") == 2
