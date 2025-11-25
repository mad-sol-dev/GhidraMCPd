from __future__ import annotations

import bridge.api.tools as tools
from bridge.api.tools import register_tools
from bridge.utils.program_context import PROGRAM_SELECTIONS
from mcp.server.fastmcp import FastMCP


class _SelectionClient:
    def __init__(self) -> None:
        self.base_url = "http://ghidra/"
        self.open_calls: list[dict[str, object]] = []
        self._active_domain_file_id: str | None = None

    @property
    def _files(self) -> list[dict[str, object]]:
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

    def get_project_files(self):
        return self._files

    def get_project_info(self):
        current = self._active_domain_file_id or self._files[0]["domain_file_id"]
        selected = next(
            (entry for entry in self._files if entry["domain_file_id"] == current), None
        )
        program_name = selected["name"] if selected else "unknown"
        return {"program_name": program_name}

    def open_program(self, domain_file_id: str, *, path: str | None = None):
        self.open_calls.append({"domain_file_id": domain_file_id, "path": path})
        self._active_domain_file_id = domain_file_id
        return {"status": "ok", "warnings": ["Program auto-opened for test"]}

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
    client = _SelectionClient()
    register_tools(server, client_factory=lambda: client)

    current_tool = server._tool_manager._tools["get_current_program"]
    first = current_tool.fn()

    assert first["ok"] is True
    assert first["data"] == {"domain_file_id": "prog-1", "locked": False}

    select_tool = server._tool_manager._tools["select_program"]
    second = select_tool.fn("prog-2")

    assert second["ok"] is True
    assert second["data"]["domain_file_id"] == "prog-2"
    assert second["data"]["locked"] is True
    assert client.open_calls == [{"domain_file_id": "prog-2", "path": "/beta"}]
    assert any("auto-opened" in warning for warning in second["data"]["warnings"])

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
    assert any(
        warning.startswith("Program selection switched mid-session")
        for warning in payload["warnings"]
    )
    assert any("auto-opened" in warning for warning in payload["warnings"])

    assert validations.count("current_program.v1.json") == 2


def test_program_selection_autoopens_and_warns(monkeypatch) -> None:
    PROGRAM_SELECTIONS.clear()

    validations = []

    def fake_validate(name: str, payload):
        validations.append(name)
        return True, []

    monkeypatch.setattr(tools, "validate_payload", fake_validate)

    client = _SelectionClient()
    server = FastMCP("selection-autoopen")
    register_tools(server, client_factory=lambda: client)

    select_tool = server._tool_manager._tools["select_program"]
    result = select_tool.fn("prog-1")

    assert result["ok"] is True
    payload = result["data"]
    assert payload["locked"] is True
    assert payload["domain_file_id"] == "prog-1"
    assert client.open_calls == [{"domain_file_id": "prog-1", "path": "/alpha"}]
    assert payload.get("warnings")
    assert any("auto-opened" in warning for warning in payload["warnings"])
    assert validations.count("current_program.v1.json") == 1


def test_program_selection_propagates_open_errors(monkeypatch) -> None:
    PROGRAM_SELECTIONS.clear()

    validations = []

    def fake_validate(name: str, payload):
        validations.append(name)
        return True, []

    class _FailingClient(_SelectionClient):
        def __init__(self) -> None:
            super().__init__()
            self.last_error = None

        def open_program(self, domain_file_id: str, *, path: str | None = None):
            class _Error:
                def __init__(self):
                    self.status = 500
                    self.reason = "upstream failed"
                    self.retryable = False

                def as_dict(self):
                    return {"status": self.status, "reason": self.reason, "retryable": self.retryable}

            self.last_error = _Error()
            return None

        def get_project_info(self):
            return None

    monkeypatch.setattr(tools, "validate_payload", fake_validate)

    server = FastMCP("selection-errors")
    register_tools(server, client_factory=_FailingClient)

    select_tool = server._tool_manager._tools["select_program"]
    failure = select_tool.fn("prog-1")

    assert failure["ok"] is False
    assert failure["errors"][0]["code"] == "UNAVAILABLE"
    assert "Automatic program open failed" in failure["errors"][0]["message"]
    assert validations.count("current_program.v1.json") == 0
