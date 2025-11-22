from __future__ import annotations

from typing import Any, Dict, List

import bridge.api.tools as tools
from bridge.api.tools import register_tools
from mcp.server.fastmcp import FastMCP


class MockProjectClient:
    """Simple client used for project-related tool tests."""

    def __init__(self) -> None:
        self.base_url = "http://base/"

    def get_project_info(self) -> Dict[str, Any]:
        return {
            "program_name": "demo",
            "executable_path": None,
            "executable_md5": None,
            "executable_sha256": None,
            "executable_format": None,
            "image_base": "0x1000",
            "language_id": "lang",
            "compiler_spec_id": None,
            "entry_points": ["0x2000", "0x1000"],
            "memory_blocks": [
                {
                    "name": "text",
                    "start": "0x0",
                    "end": "0x10",
                    "length": 16,
                    "rwx": "r-x",
                    "loaded": True,
                    "initialized": True,
                }
            ],
            "imports_count": 1,
            "exports_count": 2,
        }

    def get_project_files(self) -> List[Dict[str, Any]]:
        return [
            {
                "domain_file_id": 1,
                "name": "demo",
                "path": "/demo",
                "type": "program",
                "size": "1024",
            },
            {
                "domain_file_id": None,
                "name": "notes",
                "path": "/docs/notes.txt",
                "type": "note",
                "size": None,
            },
        ]

    def close(self) -> None:  # pragma: no cover - nothing to close in tests
        pass


def test_project_tools_registered_and_envelopes(monkeypatch) -> None:
    validate_calls: List[str] = []

    def fake_validate(name: str, payload: Dict[str, Any]) -> tuple[bool, list[str]]:
        validate_calls.append(name)
        return True, []

    monkeypatch.setattr(tools, "validate_payload", fake_validate)
    monkeypatch.setattr(tools.config, "ENABLE_PROJECT_REBASE", True)

    rebase_args: Dict[str, Any] = {}

    def fake_rebase_project(
        client,
        *,
        new_base: int,
        dry_run: bool,
        confirm: bool,
        writes_enabled: bool,
        rebases_enabled: bool,
    ) -> Dict[str, Any]:
        rebase_args.update(
            {
                "client": client,
                "new_base": new_base,
                "dry_run": dry_run,
                "confirm": confirm,
                "writes_enabled": writes_enabled,
                "rebases_enabled": rebases_enabled,
            }
        )
        return {
            "dry_run": dry_run,
            "rebased": not dry_run and confirm,
            "notes": [],
            "errors": [],
            "requested_base": "0x2000",
            "previous_base": "0x1000",
            "offset": "0x1000",
            "project_info": {"program_name": "demo"},
        }

    monkeypatch.setattr(tools.project, "rebase_project", fake_rebase_project)

    server = FastMCP("test")
    register_tools(server, client_factory=MockProjectClient, enable_writes=True)

    tool_names = {tool.name for tool in server._tool_manager._tools.values()}
    assert {"project_info", "project_overview", "project_rebase"}.issubset(tool_names)

    info_tool = server._tool_manager._tools["project_info"]
    info_response = info_tool.fn()
    assert info_response["ok"] is True
    assert info_response["data"]["entry_points"] == ["0x1000", "0x2000"]

    overview_tool = server._tool_manager._tools["project_overview"]
    overview_response = overview_tool.fn()
    assert overview_response["ok"] is True
    assert overview_response["data"] == {
        "files": [
            {
                "domain_file_id": "1",
                "name": "demo",
                "path": "/demo",
                "type": "program",
                "size": 1024,
            },
            {
                "domain_file_id": None,
                "name": "notes",
                "path": "/docs/notes.txt",
                "type": "note",
                "size": None,
            },
        ]
    }

    rebase_tool = server._tool_manager._tools["project_rebase"]
    rebase_response = rebase_tool.fn(new_base="0x2000", dry_run=False, confirm=True)
    assert rebase_response["ok"] is True
    assert rebase_response["data"]["requested_base"] == "0x2000"
    assert rebase_args["writes_enabled"] is True
    assert rebase_args["rebases_enabled"] is True

    assert "project_info.v1.json" in validate_calls
    assert "project_overview.v1.json" in validate_calls
    assert "project_rebase.request.v1.json" in validate_calls
    assert "project_rebase.v1.json" in validate_calls


class MockClient:
    """Generic client used for analysis, collect, datatype, and memory tools."""

    created: List["MockClient"] = []

    def __init__(self) -> None:
        self.base_url = "http://base/"
        self.closed = False
        MockClient.created.append(self)

    def close(self) -> None:  # pragma: no cover - nothing to close in tests
        self.closed = True


def test_analysis_collect_datatype_and_write_tools(monkeypatch) -> None:
    validate_calls: List[str] = []

    def fake_validate(name: str, payload: Dict[str, Any]) -> tuple[bool, list[str]]:
        validate_calls.append(name)
        return True, []

    monkeypatch.setattr(tools, "validate_payload", fake_validate)

    analyze_calls: List[Dict[str, Any]] = []

    def fake_analyze(
        client,
        *,
        address: int,
        fields,
        fmt: str,
        max_result_tokens,
        options,
    ) -> Dict[str, Any]:
        analyze_calls.append(
            {
                "client": client,
                "address": address,
                "fields": list(fields) if fields is not None else None,
                "fmt": fmt,
                "max_result_tokens": max_result_tokens,
                "options": dict(options),
            }
        )
        return {
            "address": f"0x{address:x}",
            "function": None,
            "meta": {
                "fields": list(fields) if fields is not None else ["function"],
                "fmt": fmt,
                "max_result_tokens": max_result_tokens,
                "estimate_tokens": 2,
                "truncated": False,
            },
        }

    monkeypatch.setattr(tools.analyze, "analyze_function_complete", fake_analyze)

    collect_calls: List[Dict[str, Any]] = []

    def fake_execute_collect(client, queries, result_budget=None):
        collect_calls.append(
            {
                "client": client,
                "queries": list(queries),
                "result_budget": result_budget,
            }
        )
        items = list(queries)
        return {
            "queries": [
                {"id": item["id"], "op": item["op"], "result": {"ok": True, "data": {}, "errors": []}}
                for item in items
            ],
            "meta": {"estimate_tokens": len(items)},
        }

    monkeypatch.setattr(tools, "execute_collect", fake_execute_collect)

    datatype_calls: List[Dict[str, Any]] = []

    def _datatype_payload(kind: str, path: str, dry_run: bool, written: bool) -> Dict[str, Any]:
        return {
            "kind": kind,
            "path": path,
            "dry_run": dry_run,
            "written": written,
            "notes": [],
            "errors": [],
            "datatype": {
                "kind": kind,
                "name": "Demo",
                "category": "/category",
                "path": path,
                "size": 1,
                "fields": [{"name": "field", "type": "u32"}],
            },
        }

    def fake_create_datatype(
        client,
        *,
        kind: str,
        name: str,
        category: str,
        fields,
        dry_run: bool,
        writes_enabled: bool,
    ) -> Dict[str, Any]:
        datatype_calls.append(
            {
                "op": "create",
                "writes_enabled": writes_enabled,
                "dry_run": dry_run,
                "fields": list(fields),
            }
        )
        return _datatype_payload(kind, f"{category}/{name}", dry_run, not dry_run and writes_enabled)

    def fake_update_datatype(
        client,
        *,
        kind: str,
        path: str,
        fields,
        dry_run: bool,
        writes_enabled: bool,
    ) -> Dict[str, Any]:
        datatype_calls.append(
            {
                "op": "update",
                "writes_enabled": writes_enabled,
                "dry_run": dry_run,
                "fields": list(fields),
            }
        )
        return _datatype_payload(kind, path, dry_run, not dry_run and writes_enabled)

    def fake_delete_datatype(
        client,
        *,
        kind: str,
        path: str,
        dry_run: bool,
        writes_enabled: bool,
    ) -> Dict[str, Any]:
        datatype_calls.append(
            {
                "op": "delete",
                "writes_enabled": writes_enabled,
                "dry_run": dry_run,
            }
        )
        return _datatype_payload(kind, path, dry_run, not dry_run and writes_enabled)

    monkeypatch.setattr(tools.datatypes, "create_datatype", fake_create_datatype)
    monkeypatch.setattr(tools.datatypes, "update_datatype", fake_update_datatype)
    monkeypatch.setattr(tools.datatypes, "delete_datatype", fake_delete_datatype)

    write_calls: List[Dict[str, Any]] = []

    def fake_write_bytes(
        client,
        *,
        address: int,
        data: str,
        encoding: str,
        dry_run: bool,
        writes_enabled: bool,
    ) -> Dict[str, Any]:
        write_calls.append(
            {
                "address": address,
                "data": data,
                "encoding": encoding,
                "dry_run": dry_run,
                "writes_enabled": writes_enabled,
            }
        )
        return {
            "address": f"0x{address:x}",
            "length": len(data),
            "dry_run": dry_run,
            "written": not dry_run and writes_enabled,
            "notes": [],
            "errors": [],
        }

    monkeypatch.setattr(tools.memory, "write_bytes", fake_write_bytes)

    MockClient.created.clear()
    server = FastMCP("test")
    register_tools(server, client_factory=MockClient, enable_writes=True)

    tool_names = {tool.name for tool in server._tool_manager._tools.values()}
    expected_tools = {
        "analyze_function_complete",
        "collect",
        "datatypes_create",
        "datatypes_update",
        "datatypes_delete",
        "write_bytes",
    }
    assert expected_tools.issubset(tool_names)

    analyze_tool = server._tool_manager._tools["analyze_function_complete"]
    analyze_response = analyze_tool.fn(
        address="0x401000",
        fields=["function"],
        fmt="json",
        max_result_tokens=128,
        options={"strings": {"limit": 2}},
    )
    assert analyze_response["ok"] is True
    assert analyze_calls[0]["address"] == 0x401000

    before_collect = len(MockClient.created)
    collect_tool = server._tool_manager._tools["collect"]
    collect_response = collect_tool.fn(
        queries=[{"id": "q1", "op": "demo"}],
        projects=[
            {
                "id": "p1",
                "queries": [{"id": "pq1", "op": "demo"}],
                "ghidra_url": "http://other",
                "metadata": {"team": "analysis"},
            }
        ],
        result_budget={"mode": "auto_trim"},
        metadata={"source": "unit"},
    )
    assert collect_response["ok"] is True
    assert collect_response["data"]["meta"]["estimate_tokens"] == 2
    assert collect_response["data"]["projects"][0]["meta"]["ghidra_url"] == "http://other"
    assert collect_response["data"]["metadata"] == {"source": "unit"}
    assert len(MockClient.created) == before_collect + 2
    assert MockClient.created[-1].base_url == "http://other/"

    create_tool = server._tool_manager._tools["datatypes_create"]
    create_response = create_tool.fn(
        kind="structure",
        name="Widget",
        category="/category",
        fields=[{"name": "field", "type": "u32"}],
    )
    assert create_response["ok"] is True

    update_tool = server._tool_manager._tools["datatypes_update"]
    update_response = update_tool.fn(
        kind="structure",
        path="/category/Widget",
        fields=[{"name": "field", "type": "u32"}],
        dry_run=False,
    )
    assert update_response["ok"] is True

    delete_tool = server._tool_manager._tools["datatypes_delete"]
    delete_response = delete_tool.fn(
        kind="structure",
        path="/category/Widget",
    )
    assert delete_response["ok"] is True

    write_tool = server._tool_manager._tools["write_bytes"]
    write_response = write_tool.fn(
        address="0x1000",
        data="AAAA",
        encoding="base64",
        dry_run=True,
    )
    assert write_response["ok"] is True
    assert write_calls[0]["address"] == 0x1000

    for schema_name in [
        "analyze_function_complete.request.v1.json",
        "analyze_function_complete.v1.json",
        "collect.request.v1.json",
        "collect.v1.json",
        "datatypes_create.request.v1.json",
        "datatypes_create.v1.json",
        "datatypes_update.request.v1.json",
        "datatypes_update.v1.json",
        "datatypes_delete.request.v1.json",
        "datatypes_delete.v1.json",
        "write_bytes.request.v1.json",
        "write_bytes.v1.json",
    ]:
        assert schema_name in validate_calls
