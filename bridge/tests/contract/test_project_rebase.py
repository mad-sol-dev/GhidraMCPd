from __future__ import annotations

from starlette.testclient import TestClient

from bridge.tests.contract.test_http_contracts import _assert_envelope


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
