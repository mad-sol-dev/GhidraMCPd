from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from bridge.tests.contract.conftest import contract_client


@pytest.mark.parametrize(
    "queries",
    [
        [
            {
                "id": "imports",
                "op": "search_imports",
                "params": {"query": "import", "limit": 3},
            },
            {
                "id": "xrefs",
                "op": "search_xrefs_to",
                "params": {"address": "0x00100000", "query": "call", "limit": 2},
            },
        ]
    ],
)
def test_collect_route_success(contract_client: TestClient, queries: list[dict[str, object]]) -> None:
    response = contract_client.post(
        "/api/collect.json",
        json={
            "queries": queries,
            "result_budget": {"max_result_tokens": 5000},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    data = body["data"]
    assert "queries" in data
    sub_results = data["queries"]
    assert isinstance(sub_results, list)
    assert len(sub_results) == len(queries)
    for item in sub_results:
        assert set(item.keys()) >= {"id", "op", "result"}
        envelope = item["result"]
        assert isinstance(envelope, dict)
        assert set(envelope.keys()) == {"ok", "data", "errors"}
        assert envelope["errors"] == []
        assert envelope["ok"] is True


def test_collect_route_budget_auto_trim(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/collect.json",
        json={
            "queries": [
                {
                    "id": "functions",
                    "op": "search_functions",
                    "params": {"query": "func", "limit": 5},
                }
            ],
            "result_budget": {"max_result_tokens": 1},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    query = body["data"]["queries"][0]
    assert query["result"]["ok"] is False
    error = query["result"]["errors"][0]
    assert error["code"] == "RESULT_TOO_LARGE"
    assert "request_budget_exceeded" in query["meta"].get("notes", [])


def test_collect_route_budget_strict(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/collect.json",
        json={
            "queries": [
                {
                    "id": "functions",
                    "op": "search_functions",
                    "params": {"query": "func", "limit": 5},
                }
            ],
            "result_budget": {"max_result_tokens": 1, "mode": "strict"},
        },
    )
    assert response.status_code == 413
    body = response.json()
    assert body["ok"] is False
    assert body["errors"][0]["code"] == "RESULT_TOO_LARGE"


def test_collect_route_multi_projects(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/collect.json",
        json={
            "projects": [
                {
                    "id": "primary",
                    "queries": [
                        {
                            "id": "imports",
                            "op": "search_imports",
                            "params": {"query": "import", "limit": 2},
                        }
                    ],
                },
                {
                    "id": "secondary",
                    "ghidra_url": "http://127.0.0.1:9000/",
                    "metadata": {"label": "alt"},
                    "queries": [
                        {
                            "id": "strings",
                            "op": "search_strings",
                            "params": {"query": "status", "limit": 2},
                        }
                    ],
                },
            ]
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    data = body["data"]
    assert data["queries"] == []
    projects = data.get("projects")
    assert isinstance(projects, list)
    assert len(projects) == 2

    total_tokens = 0
    for entry in projects:
        assert set(entry.keys()) >= {"id", "queries", "meta"}
        assert isinstance(entry["queries"], list)
        assert entry["queries"]
        for item in entry["queries"]:
            assert item["result"]["ok"] is True
        meta = entry["meta"]
        assert isinstance(meta, dict)
        assert "estimate_tokens" in meta
        total_tokens += meta["estimate_tokens"]

    assert data["meta"]["estimate_tokens"] == total_tokens
    secondary_meta = projects[1]["meta"]
    assert secondary_meta.get("ghidra_url") == "http://127.0.0.1:9000/"
