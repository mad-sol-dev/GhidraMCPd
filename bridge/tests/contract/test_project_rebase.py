from __future__ import annotations

import json

from starlette.testclient import TestClient

from bridge.tests.contract.test_http_contracts import _assert_envelope
from bridge.utils import audit


def _post(client: TestClient, payload: dict) -> dict:
    response = client.post("/api/project_rebase.json", json=payload)
    assert response.status_code == 200
    envelope = response.json()
    _assert_envelope(envelope)
    return envelope["data"]


def test_project_rebase_dry_run(contract_client: TestClient) -> None:
    data = _post(
        contract_client,
        {"new_base": "0x00300000", "dry_run": True},
    )
    assert data["dry_run"] is True
    assert data["rebased"] is False
    assert any("dry-run" in note for note in data["notes"])
    assert data["project_info"]["image_base"] == "0x00100000"


def test_project_rebase_writes_disabled(contract_client: TestClient) -> None:
    data = _post(
        contract_client,
        {"new_base": "0x00300000", "dry_run": False, "confirm": True},
    )
    assert data["rebased"] is False
    assert "WRITE_DISABLED" in data["errors"]
    assert any("writes disabled" in note for note in data["notes"])


def test_project_rebase_requires_confirmation(
    contract_client_writable: TestClient,
) -> None:
    data = _post(
        contract_client_writable,
        {"new_base": "0x00300000", "dry_run": False},
    )
    assert data["rebased"] is False
    assert "CONFIRMATION_REQUIRED" in data["errors"]
    assert any("confirmation" in note for note in data["notes"])


def test_project_rebase_success(contract_client_writable: TestClient) -> None:
    data = _post(
        contract_client_writable,
        {"new_base": "0x00300000", "dry_run": False, "confirm": True},
    )
    assert data["rebased"] is True
    assert data["errors"] == []
    assert data["previous_base"] == "0x00100000"
    assert data["requested_base"] == "0x00300000"
    assert data["offset"] == "0x00200000"
    assert data["project_info"]["image_base"] == "0x00300000"
    assert any("Rebased" in note for note in data["notes"])


def test_project_rebase_audits_dry_run(contract_client: TestClient, tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    previous_path = audit.get_audit_log_path()
    audit.set_audit_log_path(audit_path)
    try:
        data = _post(contract_client, {"new_base": "0x00300000", "dry_run": True})
    finally:
        audit.set_audit_log_path(previous_path)

    entry = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert entry["category"] == "project.rebase"
    assert entry["dry_run"] is True
    assert entry["writes_enabled"] is False
    assert entry["result"]["rebased"] is False
    assert entry["result"]["ok"] is True
    assert entry["parameters"]["requested_base"] == "0x00300000"
    assert data["rebased"] is False


def test_project_rebase_audits_success(
    contract_client_writable: TestClient, tmp_path
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    previous_path = audit.get_audit_log_path()
    audit.set_audit_log_path(audit_path)
    try:
        data = _post(
            contract_client_writable,
            {"new_base": "0x00300000", "dry_run": False, "confirm": True},
        )
    finally:
        audit.set_audit_log_path(previous_path)

    entry = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert entry["category"] == "project.rebase"
    assert entry["dry_run"] is False
    assert entry["writes_enabled"] is True
    assert entry["result"]["rebased"] is True
    assert entry["result"]["ok"] is True
    assert entry["parameters"]["requested_base"] == "0x00300000"
    assert entry["parameters"]["confirm"] is True
    assert data["rebased"] is True
