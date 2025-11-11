"""Contract tests for function search endpoint."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient


def test_search_functions_basic(contract_client: TestClient) -> None:
    """Search results expose cursor metadata and structured items."""

    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 8, "page": 1},
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["ok"] is True
    data = payload["data"]

    assert data["query"] == "func"
    total = data["total"]
    assert total is None or isinstance(total, int)
    assert data["page"] == 1
    assert data["limit"] == 8
    assert isinstance(data["items"], list)
    assert "has_more" in data
    assert "resume_cursor" in data

    resume_cursor = data["resume_cursor"]
    if data["has_more"]:
        assert isinstance(resume_cursor, str)
        assert resume_cursor
    else:
        assert resume_cursor is None

    for item in data["items"]:
        assert set(item.keys()).issuperset({"name", "address"})
        assert item["address"].startswith("0x")


def test_search_functions_page_mode_totals(contract_client: TestClient) -> None:
    """Paging without cursors eventually reports a concrete total."""

    seen_addresses: list[str] = []
    page = 1
    total_reported: int | None = None

    # Limit iterations to avoid runaway loops if fixtures change.
    for _ in range(20):
        response = contract_client.post(
            "/api/search_functions.json",
            json={"query": "func", "limit": 4, "page": page},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        for item in data["items"]:
            seen_addresses.append(item["address"])
        if not data["has_more"]:
            assert isinstance(data["total"], int)
            total_reported = data["total"]
            assert data["resume_cursor"] is None
            break
        page += 1
    else:  # pragma: no cover - defensive guard
        pytest.fail("function search fixture produced too many pages")

    assert total_reported is not None
    assert total_reported == len(seen_addresses)


def test_search_functions_cursor_resume(contract_client: TestClient) -> None:
    """Cursor tokens resume from the last seen position."""

    first = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 3, "page": 1},
    )
    assert first.status_code == 200
    first_data = first.json()["data"]

    if not first_data["has_more"]:
        pytest.skip("fixture does not produce enough functions for cursor pagination")

    cursor = first_data["resume_cursor"]
    assert isinstance(cursor, str) and cursor

    second = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 3, "page": 1, "resume_cursor": cursor},
    )
    assert second.status_code == 200
    second_data = second.json()["data"]

    first_addresses = {item["address"] for item in first_data["items"]}
    second_addresses = {item["address"] for item in second_data["items"]}
    assert not first_addresses.intersection(second_addresses)

    if second_data["has_more"]:
        assert isinstance(second_data["resume_cursor"], str)
    else:
        assert second_data["resume_cursor"] is None


def test_search_functions_cursor_exhaustion(contract_client: TestClient) -> None:
    """Repeated cursor requests eventually exhaust the dataset."""

    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "func", "limit": 4, "page": 1},
    )
    assert response.status_code == 200
    data = response.json()["data"]

    seen = {item["address"] for item in data["items"]}
    cursor = data.get("resume_cursor")

    safety = 0
    while data["has_more"] and cursor:
        response = contract_client.post(
            "/api/search_functions.json",
            json={"query": "func", "limit": 4, "page": 1, "resume_cursor": cursor},
        )
        assert response.status_code == 200
        data = response.json()["data"]
        for item in data["items"]:
            assert item["address"] not in seen
            seen.add(item["address"])
        cursor = data.get("resume_cursor")
        safety += 1
        assert safety < 25, "cursor pagination did not terminate"

    assert data["has_more"] is False
    assert data.get("resume_cursor") is None


def test_search_functions_validates_schema(contract_client: TestClient) -> None:
    """Invalid payloads continue to surface structured errors."""

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

    # Non-string cursor
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "cursor": 123},
    )

    assert response.status_code == 400

    # Cursor plus rank is rejected
    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "test", "rank": "simple", "cursor": "token"},
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
    assert isinstance(data["total"], int)
    assert data["resume_cursor"] is None


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
    assert first_payload["resume_cursor"] is None
    assert second_payload["resume_cursor"] is None
