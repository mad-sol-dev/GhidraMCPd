"""Live contract tests verifying `has_more` semantics across search endpoints."""
from __future__ import annotations

from typing import Any, Dict

import pytest

from bridge.tests.contract._live_bridge import (
    assert_pagination_contract,
    post_data as _post,
    requires_live_bridge,
)

pytestmark = requires_live_bridge


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
    assert_pagination_contract(data, path=path)
