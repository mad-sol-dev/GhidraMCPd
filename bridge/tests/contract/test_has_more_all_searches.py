"""Live contract tests verifying `has_more` semantics across search endpoints."""
from __future__ import annotations

import os
from typing import Any, Dict

import pytest
import requests

from bridge.tests._env import env_flag

pytestmark = pytest.mark.skipif(
    not env_flag("RUN_LIVE_TESTS"),
    reason="Live tests disabled. Set RUN_LIVE_TESTS=1 to enable.",
)

BASE = (
    os.environ.get("BASE_URL")
    or os.environ.get("GHIDRA_MCP_URL")
    or "http://127.0.0.1:8000"
)


def _post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(f"{BASE}{path}", json=payload, timeout=30)
    assert response.status_code == 200, (path, response.status_code, response.text)
    envelope = response.json()
    assert isinstance(envelope, dict), (path, envelope)
    assert envelope.get("ok") is True, (path, envelope)
    assert envelope.get("errors") == [], (path, envelope)
    data = envelope.get("data")
    assert isinstance(data, dict), (path, envelope)
    return data


@pytest.mark.parametrize(
    ("path", "payload"),
    (
        (
            "/api/search_functions.json",
            {"query": "", "limit": 1, "page": 1},
        ),
        (
            "/api/search_imports.json",
            {"query": "a", "limit": 1, "page": 1},
        ),
        (
            "/api/search_exports.json",
            {"query": "a", "limit": 1, "page": 1},
        ),
        (
            "/api/search_scalars.json",
            {"value": "0x0", "limit": 1, "page": 1},
        ),
    ),
    ids=["functions", "imports", "exports", "scalars"],
)
def test_has_more_contract_for_searches(path: str, payload: Dict[str, Any]) -> None:
    data = _post(path, payload)

    for key in ("total", "page", "limit", "items", "has_more"):
        assert key in data, f"missing `{key}` in {path}: {data}"

    assert isinstance(data["items"], list), f"`items` should be a list in {path}"
    assert isinstance(data["has_more"], bool), "`has_more` must be a boolean"

    page = int(data["page"])
    limit = int(data["limit"])
    total_raw = data["total"]

    assert page >= 1, f"page must be >= 1 for {path}, got {page}"
    assert limit >= 1, f"limit must be >= 1 for {path}, got {limit}"
    if total_raw is not None:
        assert isinstance(total_raw, int), f"total must be int or null for {path}"
        assert total_raw >= 0, f"total must be >= 0 for {path}, got {total_raw}"
        expected = (page * limit) < total_raw
        assert (
            data["has_more"] == expected
        ), f"has_more mismatch for {path}: expected {expected} but got {data['has_more']}"
