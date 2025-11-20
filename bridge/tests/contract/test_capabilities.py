from __future__ import annotations

from typing import Iterable, Tuple

from starlette.testclient import TestClient

from bridge.api.validators import validate_payload


def _assert_valid_envelope(payload: dict) -> None:
    valid, errors = validate_payload("envelope.v1.json", payload)
    assert valid, f"Envelope validation failed: {errors}"
    assert payload["ok"] is True
    assert payload["errors"] == []
    assert isinstance(payload.get("data"), dict)


def _assert_valid_capabilities(data: dict) -> list[dict]:
    valid, errors = validate_payload("capabilities.v1.json", data)
    assert valid, f"Schema validation failed: {errors}"
    endpoints = data["endpoints"]
    _assert_sorted(endpoints)
    return endpoints


def _assert_sorted(endpoints: Iterable[dict]) -> None:
    pairs: list[Tuple[str, str]] = []
    for entry in endpoints:
        pairs.append((entry["path"], entry["method"]))
    assert pairs == sorted(pairs)


def test_capabilities_contract(contract_client: TestClient) -> None:
    response = contract_client.get("/api/capabilities.json")
    assert response.status_code == 200
    payload = response.json()
    _assert_valid_envelope(payload)
    endpoints = _assert_valid_capabilities(payload["data"])

    paths = {entry["path"] for entry in endpoints}
    assert "/api/project_info.json" in paths
    assert "/api/collect.json" in paths
    assert "/api/capabilities.json" in paths
