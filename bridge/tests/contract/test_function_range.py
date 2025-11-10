"""Contract tests for list_functions_in_range endpoint."""

from __future__ import annotations

import math

from starlette.testclient import TestClient


_ADDRESS_MIN = "0x00100000"
_ADDRESS_MAX = "0x00100020"


def _list_range(
    client: TestClient, *, page: int, limit: int
) -> dict:
    response = client.post(
        "/api/list_functions_in_range.json",
        json={
            "address_min": _ADDRESS_MIN,
            "address_max": _ADDRESS_MAX,
            "page": page,
            "limit": limit,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    return payload["data"]


def test_list_functions_in_range_includes_query_and_has_more(
    contract_client: TestClient,
) -> None:
    data = _list_range(contract_client, page=1, limit=3)

    assert data["query"] == "[0x00100000,0x00100020]"
    assert data["page"] == 1
    assert data["limit"] == 3
    assert data["has_more"] is True
    assert data["total"] >= len(data["items"])
    assert all(item["address"].startswith("0x") for item in data["items"])


def test_list_functions_in_range_last_page_has_more_false(
    contract_client: TestClient,
) -> None:
    first_page = _list_range(contract_client, page=1, limit=4)
    total = first_page["total"]
    assert total > 0

    last_page = math.ceil(total / first_page["limit"])
    last_page_data = _list_range(contract_client, page=last_page, limit=first_page["limit"])

    assert last_page_data["has_more"] is False
    assert last_page_data["query"] == first_page["query"]

    beyond_last_page = _list_range(
        contract_client, page=last_page + 1, limit=first_page["limit"]
    )
    assert beyond_last_page["items"] == []
    assert beyond_last_page["has_more"] is False
    assert beyond_last_page["query"] == first_page["query"]
