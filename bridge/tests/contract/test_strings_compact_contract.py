from __future__ import annotations

from typing import Iterable

import pytest
from starlette.testclient import TestClient

import bridge.app as bridge_app
from bridge.tests.contract.conftest import StubGhidraClient


@pytest.fixture()
def app_client(monkeypatch: pytest.MonkeyPatch) -> Iterable[TestClient]:
    monkeypatch.setattr(bridge_app, "_client_factory", lambda: StubGhidraClient())
    test_app = bridge_app.create_app()
    with TestClient(test_app) as client:
        yield client


def test_strings_compact_contract(app_client: TestClient) -> None:
    response = app_client.post(
        "/api/strings_compact.json",
        json={"limit": 3, "offset": 0},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["errors"] == []
    data = body["data"]
    assert data["total"] == len(data["items"])
    items = data["items"]
    assert items
    assert [item["addr"] for item in items] == sorted(item["addr"] for item in items)
    assert all(set(item.keys()) == {"s", "addr", "refs"} for item in items)

    repeat = app_client.post(
        "/api/strings_compact.json",
        json={"limit": 3, "offset": 0},
    )
    assert repeat.status_code == 200
    assert repeat.json()["data"] == body["data"]


def test_strings_compact_falls_back_to_search(monkeypatch: pytest.MonkeyPatch) -> None:
    class SearchOnlyStub(StubGhidraClient):
        def __init__(self) -> None:
            super().__init__()
            self.list_strings_compact = None
            self.list_strings = None

    monkeypatch.setattr(bridge_app, "_client_factory", lambda: SearchOnlyStub())
    test_app = bridge_app.create_app()

    with TestClient(test_app) as client:
        response = client.post(
            "/api/strings_compact.json",
            json={"limit": 2, "offset": 1},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["ok"] is True
        items = payload["data"]["items"]
        assert [item["addr"] for item in items] == ["0x00200010", "0x00200030"]


def test_strings_compact_reports_invalid_limit(app_client: TestClient) -> None:
    response = app_client.post(
        "/api/strings_compact.json",
        json={"limit": 0, "offset": 0},
    )

    assert response.status_code == 400
    payload = response.json()
    assert payload["ok"] is False
    error = payload["errors"][0]
    assert error["code"] == "INVALID_REQUEST"
    assert "limit must be a positive integer" in error["message"]
