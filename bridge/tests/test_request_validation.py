from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.error_handlers import install_error_handlers
from bridge.tests.golden.test_http_parity import GoldenStubGhidraClient


@pytest.fixture()
def client() -> TestClient:
    def factory() -> GoldenStubGhidraClient:
        return GoldenStubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=True))
    install_error_handlers(app)
    with TestClient(app) as test_client:
        yield test_client


def _valid_payloads() -> dict[str, dict[str, object]]:
    return {
        "/api/jt_slot_check.json": {
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        "/api/jt_slot_process.json": {
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        "/api/jt_scan.json": {
            "jt_base": "0x00100000",
            "start": 0,
            "count": 1,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
        "/api/string_xrefs.json": {
            "string_addr": "0x00200000",
            "limit": 2,
        },
        "/api/strings_compact.json": {
            "limit": 3,
            "offset": 0,
        },
        "/api/mmio_annotate.json": {
            "function_addr": "0x00007000",
            "dry_run": True,
            "max_samples": 2,
        },
        "/api/datatypes/create.json": {
            "kind": "structure",
            "name": "Widget",
            "category": "/structs",
            "fields": [
                {"name": "id", "type": "uint32", "offset": 0, "length": 4}
            ],
            "dry_run": True,
        },
        "/api/datatypes/update.json": {
            "kind": "structure",
            "path": "/structs/Packet",
            "fields": [
                {"name": "id", "type": "uint32", "offset": 0, "length": 4}
            ],
            "dry_run": True,
        },
        "/api/datatypes/delete.json": {
            "kind": "structure",
            "path": "/structs/Packet",
            "dry_run": True,
        },
    }


@pytest.mark.parametrize(
    "path",
    list(_valid_payloads().keys()),
)
def test_rejects_additional_properties(client: TestClient, path: str) -> None:
    payload = dict(_valid_payloads()[path])
    payload["unexpected"] = "value"
    response = client.post(path, json=payload)
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["errors"], "Expected an error payload"
    first = body["errors"][0]
    assert first == {
        "status": 400,
        "code": "INVALID_REQUEST",
        "message": "Request was malformed or failed validation.",
        "recovery": ["Check required fields and value formats."],
    }
    meta = body.get("meta")
    assert meta, "Expected response metadata for triage"
    assert meta.get("correlation_id"), "Correlation ID should be provided"
    assert meta.get("summary") == "value_error"


def test_rejects_non_object_payload(client: TestClient) -> None:
    response = client.post(
        "/api/jt_slot_check.json",
        json=["jt_base", "0x00100000"],
    )
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["errors"][0] == {
        "status": 400,
        "code": "INVALID_REQUEST",
        "message": "Request was malformed or failed validation.",
        "recovery": ["Check required fields and value formats."],
    }
    meta = body.get("meta")
    assert meta, "Expected response metadata for triage"
    assert meta.get("correlation_id"), "Correlation ID should be provided"
    assert meta.get("summary") == "value_error"


def test_rejects_invalid_json(client: TestClient) -> None:
    response = client.post(
        "/api/jt_slot_check.json",
        content=b"{not-json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["ok"] is False
    assert body["errors"][0] == {
        "status": 400,
        "code": "INVALID_REQUEST",
        "message": "Request was malformed or failed validation.",
        "recovery": ["Check required fields and value formats."],
    }
    meta = body.get("meta")
    assert meta, "Expected response metadata for triage"
    assert meta.get("correlation_id"), "Correlation ID should be provided"
    assert meta.get("summary") == "json_decode_error"
