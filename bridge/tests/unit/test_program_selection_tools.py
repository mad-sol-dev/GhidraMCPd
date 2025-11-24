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
