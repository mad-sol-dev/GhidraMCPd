from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.api.validators import validate_payload
from bridge.error_handlers import install_error_handlers
from bridge.tests.contract.conftest import StubGhidraClient
from bridge.utils.cache import get_search_cache

def _assert_valid(schema_name: str, payload: dict) -> None:
    valid, errors = validate_payload(schema_name, payload)
    assert valid, f"Schema validation failed: {errors}"


def _assert_envelope(payload: dict) -> None:
    _assert_valid("envelope.v1.json", payload)
    if payload["ok"]:
        assert isinstance(payload["data"], dict), payload
        assert payload["errors"] == [], payload
    else:
        assert payload["data"] is None, payload
        errors = payload.get("errors")
        assert isinstance(errors, list) and errors, payload


def test_project_info_contract(contract_client: TestClient) -> None:
    response = contract_client.get("/api/project_info.json")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    data = body["data"]
    _assert_valid("project_info.v1.json", data)
    entry_points = data["entry_points"]
    assert entry_points == sorted(entry_points)
    starts = [block["start"] for block in data["memory_blocks"]]
    assert starts == sorted(starts)
    assert data["imports_count"] == 24
    assert data["exports_count"] == 24


def test_project_info_missing_program() -> None:
    from bridge.tests.contract import conftest as contract_conftest

    class EmptyProjectStub(contract_conftest.StubGhidraClient):
        def get_project_info(self) -> dict[str, object] | None:  # type: ignore[override]
            return None

    def factory() -> contract_conftest.StubGhidraClient:
        return EmptyProjectStub()

    app = Starlette(routes=make_routes(factory, enable_writes=False))
    with TestClient(app) as client:
        response = client.get("/api/project_info.json")

    assert response.status_code == 503
    body = response.json()
    assert body["ok"] is False
    _assert_envelope(body)
    errors = body["errors"]
    assert errors == [
        {
            "status": 503,
            "code": "UNAVAILABLE",
            "message": "Required upstream data is unavailable.",
            "recovery": ["Ensure a program is open in Ghidra and try again."],
        }
    ]


def test_jt_slot_check_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_slot_check.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    _assert_valid("jt_slot_check.v1.json", body["data"])


def test_jt_slot_check_rejects_upper_bound(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_slot_check.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 1,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    _assert_valid("jt_slot_check.v1.json", body["data"])
    assert body["data"]["errors"] == ["OUT_OF_RANGE"]


def test_jt_slot_process_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_slot_process.json",
        json={
            "jt_base": "0x00100000",
            "slot_index": 0,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "rename_pattern": "slot_{slot}",
            "comment": "Processed",
            "dry_run": True,
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    _assert_valid("jt_slot_process.v1.json", body["data"])


def test_jt_scan_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/jt_scan.json",
        json={
            "jt_base": "0x00100000",
            "start": 0,
            "count": 16,
            "code_min": "0x00100000",
            "code_max": "0x0010FFFF",
            "arch": "arm",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    data = body["data"]
    _assert_valid("jt_scan.v1.json", data)
    items = data["items"]
    assert data["summary"]["total"] == len(items) == 16
    invalid = sum(1 for item in items if item["errors"])
    assert data["summary"]["invalid"] == invalid
    assert data["summary"]["valid"] == len(items) - invalid
    assert items[1]["errors"] == ["OUT_OF_RANGE"]
    assert items[2]["errors"] == ["ARM_INSTRUCTION"]
    assert items[3]["errors"] == ["TOOL_BINDING_MISSING"]
    assert items[4]["mode"] == "Thumb"


def test_string_xrefs_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/string_xrefs.json",
        json={"string_addr": "0x00200000", "limit": 4},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    data = body["data"]
    _assert_valid("string_xrefs.v1.json", data)
    assert data["count"] == 8
    assert len(data["callers"]) == 4
    assert data["callers"][0]["addr"] == "0x00100000"


def test_mmio_annotate_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/mmio_annotate.json",
        json={"function_addr": "0x00006000", "dry_run": True, "max_samples": 3},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    _assert_valid("mmio_annotate.v1.json", body["data"])


def test_analyze_function_complete_contract(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/analyze_function_complete.json",
        json={"address": "0x00102004"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    _assert_envelope(body)
    data = body["data"]
    _assert_valid("analyze_function_complete.v1.json", data)
    assert data["meta"]["fmt"] == "json"


class _CountingStub(StubGhidraClient):
    def __init__(self) -> None:
        super().__init__()
        self.function_calls = 0

    def search_functions(
        self,
        query: str,
        *,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ):
        self.function_calls += 1
        return super().search_functions(query, limit=limit, offset=offset, cursor=cursor)


class _ContractClock:
    def __init__(self, start: float = 5_000.0) -> None:
        self._value = start

    def now(self) -> float:
        return self._value

    def advance(self, seconds: float) -> None:
        self._value += seconds


def test_search_cache_contract_behaviour() -> None:
    cache = get_search_cache()
    cache.clear()
    clock = _ContractClock()
    cache.set_clock(clock.now)

    stub = _CountingStub()

    def factory() -> StubGhidraClient:
        return stub

    app = Starlette(routes=make_routes(factory, enable_writes=False))
    install_error_handlers(app)

    try:
        with TestClient(app) as client:
            body = {"query": "reset", "limit": 4, "page": 1}

            first = client.post("/api/search_functions.json", json=body)
            assert first.status_code == 200
            assert stub.function_calls == 1

            second = client.post("/api/search_functions.json", json=body)
            assert second.status_code == 200
            assert stub.function_calls == 1

            clock.advance(301)

            third = client.post("/api/search_functions.json", json=body)
            assert third.status_code == 200
            assert stub.function_calls == 2
    finally:
        cache.reset_clock()
        cache.clear()


@pytest.mark.parametrize(
    "path,payload",
    [
        ("/api/jt_slot_check.json", {"jt_base": "0x1", "slot_index": 0, "code_min": "0x1", "code_max": "0x2", "extra": 1}),
        (
            "/api/jt_slot_process.json",
            {
                "jt_base": "0x1",
                "slot_index": 0,
                "code_min": "0x1",
                "code_max": "0x2",
                "rename_pattern": "slot_{slot}",
                "comment": "hi",
                "dry_run": True,
                "extra": 1,
            },
        ),
        (
            "/api/jt_scan.json",
            {
                "jt_base": "0x1",
                "start": 0,
                "count": 4,
                "code_min": "0x1",
                "code_max": "0x2",
                "extra": 1,
            },
        ),
        (
            "/api/string_xrefs.json",
            {"string_addr": "0x2", "limit": 1, "extra": 1},
        ),
        (
            "/api/mmio_annotate.json",
            {"function_addr": "0x1", "dry_run": True, "max_samples": 2, "extra": 1},
        ),
        (
            "/api/analyze_function_complete.json",
            {"address": "0x00102004", "extra": 1},
        ),
    ],
)
def test_contract_rejects_additional_properties(contract_client: TestClient, path: str, payload: dict) -> None:
    response = contract_client.post(path, json=payload)
    assert response.status_code == 400
    body = response.json()
    _assert_envelope(body)
    assert body["ok"] is False
    assert body["errors"], "Expected schema validation errors"
