from __future__ import annotations

from typing import Dict, List

import pytest

from bridge.features import datatypes
from bridge.ghidra.client import DataTypeOperationResult


class RecordingClient:
    def __init__(self) -> None:
        self.calls: List[tuple[str, Dict[str, object]]] = []

    def create_structure(
        self,
        *,
        name: str,
        category: str,
        fields: List[Dict[str, object]],
    ) -> DataTypeOperationResult:
        self.calls.append(
            ("create_structure", {"name": name, "category": category, "fields": fields})
        )
        payload = {
            "kind": "structure",
            "name": name,
            "category": category,
            "path": f"{category.rstrip('/')}/{name}" if category != "/" else f"/{name}",
            "fields": fields,
            "size": 8,
        }
        return DataTypeOperationResult(True, datatype=payload)

    def update_structure(
        self,
        *,
        path: str,
        fields: List[Dict[str, object]],
    ) -> DataTypeOperationResult:
        self.calls.append(("update_structure", {"path": path, "fields": fields}))
        payload = {
            "kind": "structure",
            "path": path,
            "fields": fields,
            "size": 4,
        }
        return DataTypeOperationResult(True, datatype=payload)

    def delete_datatype(self, *, kind: str, path: str) -> DataTypeOperationResult:
        self.calls.append(("delete_datatype", {"kind": kind, "path": path}))
        return DataTypeOperationResult(True, datatype={"kind": kind, "path": path})


def _field(offset: int) -> Dict[str, object]:
    return {"name": f"f{offset}", "type": "uint32", "offset": offset, "length": 4}


def test_create_datatype_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RecordingClient()
    attempts: List[None] = []
    monkeypatch.setattr(datatypes, "record_write_attempt", lambda: attempts.append(None))

    result = datatypes.create_datatype(
        client,
        kind="structure",
        name="Example",
        category="/structs",
        fields=[_field(0)],
        dry_run=True,
        writes_enabled=True,
    )

    assert client.calls == []
    assert attempts == []
    assert result["written"] is False
    assert any("dry-run" in note for note in result["notes"])


def test_create_datatype_writes_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RecordingClient()
    attempts: List[None] = []
    monkeypatch.setattr(datatypes, "record_write_attempt", lambda: attempts.append(None))

    result = datatypes.create_datatype(
        client,
        kind="structure",
        name="Example",
        category="structs",
        fields=[_field(0)],
        dry_run=False,
        writes_enabled=False,
    )

    assert client.calls == []
    assert attempts == []
    assert result["written"] is False
    assert result["errors"] == ["WRITE_DISABLED"]
    assert any("writes disabled" in note for note in result["notes"])


def test_create_datatype_success(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RecordingClient()
    called: List[None] = []
    monkeypatch.setattr(datatypes, "record_write_attempt", lambda: called.append(None))

    result = datatypes.create_datatype(
        client,
        kind="structure",
        name="Example",
        category="/structs",
        fields=[_field(0), _field(4)],
        dry_run=False,
        writes_enabled=True,
    )

    assert client.calls and client.calls[0][0] == "create_structure"
    assert called == [None]
    assert result["written"] is True
    datatype = result["datatype"]
    assert isinstance(datatype, dict)
    assert datatype["size"] == 8
    assert len(datatype["fields"]) == 2


def test_update_datatype_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RecordingClient()

    def failing_update(**_kwargs):
        return DataTypeOperationResult(False, error="update failed")

    monkeypatch.setattr(client, "update_structure", failing_update)
    monkeypatch.setattr(datatypes, "record_write_attempt", lambda: None)

    result = datatypes.update_datatype(
        client,
        kind="structure",
        path="/structs/Packet",
        fields=[_field(0)],
        dry_run=False,
        writes_enabled=True,
    )

    assert result["written"] is False
    assert result["errors"] == ["update failed"]


def test_delete_datatype_records_write(monkeypatch: pytest.MonkeyPatch) -> None:
    client = RecordingClient()
    attempts: List[str] = []
    monkeypatch.setattr(datatypes, "record_write_attempt", lambda: attempts.append("called"))

    result = datatypes.delete_datatype(
        client,
        kind="structure",
        path="/structs/Packet",
        dry_run=False,
        writes_enabled=True,
    )

    assert attempts == ["called"]
    assert client.calls and client.calls[0][0] == "delete_datatype"
    assert result["written"] is True
    assert result["datatype"] == {"kind": "structure", "path": "/structs/Packet"}
