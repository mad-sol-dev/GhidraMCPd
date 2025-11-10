from starlette.testclient import TestClient


def test_search_imports_basic(contract_client: TestClient) -> None:
    """Verify the imports search endpoint returns the expected envelope."""

    response = contract_client.post(
        "/api/search_imports.json",
        json={"query": "import", "limit": 10, "page": 1},
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["ok"] is True
    data = payload["data"]

    assert data["query"] == "import"
    assert isinstance(data["total"], int)
    assert data["page"] == 1
    assert data["limit"] == 10
    assert isinstance(data["items"], list)
    assert data["items"], "Expected at least one import match"

    for item in data["items"]:
        assert "name" in item
        assert "address" in item
        assert item["address"].startswith("0x")


def test_search_imports_pagination(contract_client: TestClient) -> None:
    """Results should paginate deterministically across pages."""

    first = contract_client.post(
        "/api/search_imports.json",
        json={"query": "import", "limit": 5, "page": 1},
    )
    second = contract_client.post(
        "/api/search_imports.json",
        json={"query": "import", "limit": 5, "page": 2},
    )

    assert first.status_code == 200
    assert second.status_code == 200

    page_one = first.json()["data"]
    page_two = second.json()["data"]

    assert page_one["total"] == page_two["total"]
    assert page_one["page"] == 1
    assert page_two["page"] == 2

    if page_one["total"] > 5:
        names_one = [item["name"] for item in page_one["items"]]
        names_two = [item["name"] for item in page_two["items"]]
        assert names_one != names_two


def test_search_imports_validates_schema(contract_client: TestClient) -> None:
    """Invalid payloads should be rejected with a 400 envelope."""

    missing_query = contract_client.post(
        "/api/search_imports.json",
        json={"limit": 10},
    )
    assert missing_query.status_code == 400
    assert missing_query.json()["ok"] is False

    invalid_limit = contract_client.post(
        "/api/search_imports.json",
        json={"query": "test", "limit": "nope"},
    )
    assert invalid_limit.status_code == 400


def test_search_imports_invalid_page(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_imports.json",
        json={"query": "test", "limit": 10, "page": 0},
    )

    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_search_imports_zero_limit(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_imports.json",
        json={"query": "test", "limit": 0, "page": 1},
    )

    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_search_imports_page_beyond_results(contract_client: TestClient) -> None:
    response = contract_client.post(
        "/api/search_imports.json",
        json={"query": "import", "limit": 5, "page": 999},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    data = payload["data"]
    assert data["items"] == []
    assert data["has_more"] is False
