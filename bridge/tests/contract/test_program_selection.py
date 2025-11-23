from __future__ import annotations

from starlette.testclient import TestClient

from bridge.tests.contract.test_http_contracts import _assert_envelope
from bridge.utils.program_context import PROGRAM_SELECTIONS


def test_current_program_defaults(contract_client: TestClient) -> None:
    response = contract_client.get("/api/current_program.json")
    assert response.status_code == 200

    payload = response.json()
    _assert_envelope(payload)

    data = payload["data"]
    assert data == {"domain_file_id": "1", "locked": False}


def test_select_program_rejects_invalid_id(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/select_program.json", json={"domain_file_id": "99"}
    )

    assert response.status_code == 400
    payload = response.json()
    _assert_envelope(payload)
    assert payload["ok"] is False
    assert payload["errors"][0]["code"] == "INVALID_REQUEST"


def test_program_switching_is_gated(contract_client: TestClient) -> None:
    headers = {"x-requestor-id": "sess-1"}

    first = contract_client.post(
        "/api/select_program.json", json={"domain_file_id": "1"}, headers=headers
    )
    assert first.status_code == 200
    first_data = first.json()["data"]
    assert first_data["locked"] is False

    # Any non-selection call locks the selection for this requester
    info = contract_client.get("/api/project_info.json", headers=headers)
    assert info.status_code == 200

    switch = contract_client.post(
        "/api/select_program.json", json={"domain_file_id": "4"}, headers=headers
    )
    assert switch.status_code == 400
    payload = switch.json()
    _assert_envelope(payload)
    assert payload["ok"] is False
    assert payload["errors"][0]["code"] == "INVALID_REQUEST"

    # New requester can select independently
    other = contract_client.post(
        "/api/select_program.json", json={"domain_file_id": "4"}, headers={"x-requestor-id": "sess-2"}
    )
    assert other.status_code == 200
    assert other.json()["data"]["domain_file_id"] == "4"


def test_current_program_resets_stale_selection(contract_client: TestClient) -> None:
    key = ("http", "sess-stale")
    PROGRAM_SELECTIONS.select(key, "missing")

    response = contract_client.get(
        "/api/current_program.json", headers={"x-requestor-id": "sess-stale"}
    )

    assert response.status_code == 200
    payload = response.json()
    _assert_envelope(payload)
    assert payload["data"] == {"domain_file_id": "1", "locked": False}


def test_current_program_rejects_stale_when_locked(contract_client: TestClient) -> None:
    key = ("http", "sess-locked")
    PROGRAM_SELECTIONS.select(key, "missing")
    PROGRAM_SELECTIONS.mark_used(key)

    response = contract_client.get(
        "/api/current_program.json", headers={"x-requestor-id": "sess-locked"}
    )

    assert response.status_code == 400
    payload = response.json()
    _assert_envelope(payload)
    assert payload["ok"] is False
    assert payload["errors"][0]["code"] == "INVALID_REQUEST"

