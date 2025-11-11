"""Contract tests validating search_functions payload normalisation."""

from __future__ import annotations

import re

from starlette.testclient import TestClient


def test_search_functions_normalizes_addresses(contract_client: TestClient) -> None:
    """Ensure plaintext results are parsed into 0x-prefixed addresses."""

    response = contract_client.post(
        "/api/search_functions.json",
        json={"query": "Reset", "limit": 5, "page": 1},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True

    data = payload["data"]
    total = data["total"]
    if total is not None:
        assert total >= 1
    assert data["items"], "Expected at least one search result"

    address_pattern = re.compile(r"^0x[0-9a-fA-F]+$")
    for item in data["items"]:
        assert address_pattern.match(item["address"])
