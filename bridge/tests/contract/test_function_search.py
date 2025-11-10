"""Contract tests for function search endpoint."""

import pytest
from starlette.testclient import TestClient


def test_search_functions_basic(contract_client: TestClient) -> None:
    """Test that search_functions returns correct structure."""
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 10, "page": 1},
    )
    
    assert response.status_code == 200
    payload = response.json()
    
    assert payload["ok"] is True
    data = payload["data"]
    
    assert data["query"] == "func"
    assert "total" in data
    assert isinstance(data["total"], int)
    assert data["page"] == 1
    assert data["limit"] == 10
    assert "items" in data
    assert isinstance(data["items"], list)
    
    # Each item should have name and address
    for item in data["items"]:
        assert "name" in item
        assert "address" in item
        assert item["address"].startswith("0x")


def test_search_functions_pagination(contract_client: TestClient) -> None:
    """Test that page-based pagination works correctly."""
    # First page
    response1 = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 5, "page": 1},
    )
    
    # Second page
    response2 = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 5, "page": 2},
    )
    
    assert response1.status_code == 200
    assert response2.status_code == 200
    
    data1 = response1.json()["data"]
    data2 = response2.json()["data"]
    
    # Both should have same total count
    assert data1["total"] == data2["total"]

    # Different pages
    assert data1["page"] == 1
    assert data2["page"] == 2

    # Items should be different (if there are enough results)
    if data1["total"] > 5:
        items1_addrs = [item["address"] for item in data1["items"]]
        items2_addrs = [item["address"] for item in data2["items"]]
        assert items1_addrs != items2_addrs


def test_search_functions_validates_schema(contract_client: TestClient) -> None:
    """Test that invalid payloads are rejected."""
    # Missing required query field
    response = contract_client.post(
        "/api/search_functions.json",
        json={"limit": 10},
    )
    
    assert response.status_code == 400
    payload = response.json()
    assert payload["ok"] is False
    
    # Invalid limit type
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "limit": "invalid"},
    )

    assert response.status_code == 400

    # Invalid rank option
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "rank": "advanced"},
    )

    assert response.status_code == 400

    # k without rank
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "k": 5},
    )

    assert response.status_code == 400

    # Invalid k value
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "rank": "simple", "k": 0},
    )

    assert response.status_code == 400


def test_search_functions_invalid_page(contract_client: TestClient) -> None:
    """Test that invalid page values are rejected."""
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "limit": 10, "page": 0},
    )
    
    assert response.status_code == 400
    payload = response.json()
    assert payload["ok"] is False


def test_search_functions_zero_limit(contract_client: TestClient) -> None:
    """Test that zero or negative limit is rejected."""
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "limit": 0, "page": 1},
    )

    assert response.status_code == 400
    payload = response.json()
    assert payload["ok"] is False


def test_search_functions_page_beyond_results(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 5, "page": 999},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    data = payload["data"]
    assert data["items"] == []
    assert data["has_more"] is False


def test_search_functions_simple_rank_trims_before_pagination(
    contract_client: TestClient,
) -> None:
    """Heuristic ranking trims to k before pagination and keeps ordering stable."""

    first_page = contract_client.post(
        "/api/search_functions.json",
        json={
            "query": "func",
            "limit": 2,
            "page": 1,
            "rank": "simple",
            "k": 3,
        },
    )

    second_page = contract_client.post(
        "/api/search_functions.json",
        json={
            "query": "func",
            "limit": 2,
            "page": 2,
            "rank": "simple",
            "k": 3,
        },
    )

    assert first_page.status_code == 200
    assert second_page.status_code == 200

    first_payload = first_page.json()["data"]
    second_payload = second_page.json()["data"]

    assert first_payload["total"] == 3
    assert second_payload["total"] == 3
    assert first_payload["items"]
    assert second_payload["items"]
    assert [item["name"] for item in first_payload["items"]] == [
        "func_0000",
        "func_0001",
    ]
    assert [item["name"] for item in second_payload["items"]] == ["func_0002"]
    assert first_payload["has_more"] is True
    assert second_payload["has_more"] is False
