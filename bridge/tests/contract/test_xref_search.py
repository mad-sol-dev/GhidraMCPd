"""Contract tests for the search_xrefs_to endpoint."""

from starlette.testclient import TestClient


def test_search_xrefs_basic(contract_client: TestClient) -> None:
    """Verify the xref search endpoint returns the expected envelope."""

    response = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": 5, "page": 1},
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["ok"] is True
    data = payload["data"]

    assert data["query"] == ""
    assert isinstance(data["total"], int)
    assert data["page"] == 1
    assert data["limit"] == 5
    assert isinstance(data["items"], list)
    assert isinstance(data["has_more"], bool)
    assert data["items"], "Expected at least one xref match"

    for item in data["items"]:
        assert item["from_address"].startswith("0x")
        assert isinstance(item["context"], str)
        assert item["target_address"] == "0x00100000"


def test_search_xrefs_pagination(contract_client: TestClient) -> None:
    """Results should paginate deterministically across offsets."""

    first = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": 1, "page": 1},
    )
    second = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": 1, "page": 2},
    )

    assert first.status_code == 200
    assert second.status_code == 200

    page_one = first.json()["data"]
    page_two = second.json()["data"]

    assert page_one["total"] == page_two["total"]
    assert page_one["page"] == 1
    assert page_two["page"] == 2

    if page_one["total"] > 1:
        addresses_one = [item["from_address"] for item in page_one["items"]]
        addresses_two = [item["from_address"] for item in page_two["items"]]
        assert addresses_one != addresses_two
        assert page_one["has_more"] is True
        assert isinstance(page_two["has_more"], bool)
    else:
        assert page_one["has_more"] is False


def test_search_xrefs_validates_schema(contract_client: TestClient) -> None:
    """Invalid payloads should be rejected with a 400 envelope."""

    missing_address = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"query": "test"},
    )
    assert missing_address.status_code == 400
    assert missing_address.json()["ok"] is False

    missing_query = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000"},
    )
    assert missing_query.status_code == 400
    assert missing_query.json()["ok"] is False

    invalid_address = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "1234", "query": ""},
    )
    assert invalid_address.status_code == 400
    assert invalid_address.json()["ok"] is False

    invalid_limit = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": "nope"},
    )
    assert invalid_limit.status_code == 400


def test_search_xrefs_invalid_page(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": 5, "page": 0},
    )

    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_search_xrefs_passes_query(contract_client: TestClient) -> None:
    """Queries should be normalized, forwarded to the backend, and return results."""

    response = contract_client.post(
        "/api/search_xrefs_to.json",
        json={
            "address": "0x00100000",
            "query": "  CALL   at   00100008  ",
            "limit": 5,
            "page": 1,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    data = payload["data"]
    assert data["query"] == "call at 00100008"

    items = data["items"]
    assert items, "Expected at least one filtered xref match"
    assert all(item["from_address"] == "0x00100008" for item in items)


def test_search_xrefs_zero_limit(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": 0, "page": 1},
    )

    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_search_xrefs_window_exceeded(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": 300, "page": 1},
    )

    assert response.status_code == 413
    payload = response.json()
    assert payload["ok"] is False


def test_search_xrefs_page_beyond_results(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_xrefs_to.json",
        json={"address": "0x00100000", "query": "", "limit": 5, "page": 40},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    data = payload["data"]
    assert data["items"] == []
    assert data["has_more"] is False
