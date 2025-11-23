"""Unit tests for search_xrefs_to helpers."""

import pytest

from bridge.features import xrefs
from bridge.utils.config import MAX_ITEMS_PER_BATCH
from bridge.utils.logging import SafetyLimitExceeded


class _FakeClient:
    def __init__(self, entries):
        self._entries = entries

    def search_xrefs_to(self, address: int, query: str):
        return self._entries


def test_search_xrefs_to_sorts_results() -> None:
    client = _FakeClient(
        [
            {"addr": 0x20, "context": "later"},
            {"addr": 0x10, "context": "earlier"},
            {"addr": 0x30, "context": "last"},
        ]
    )

    result = xrefs.search_xrefs_to(client, address="0x0", query="", limit=10, page=1)

    assert [item["from_address"] for item in result["items"]] == [
        "0x00000010",
        "0x00000020",
        "0x00000030",
    ]


def test_search_xrefs_to_window_limit() -> None:
    client = _FakeClient([])
    over_limit = MAX_ITEMS_PER_BATCH + 1

    with pytest.raises(SafetyLimitExceeded):
        xrefs.search_xrefs_to(client, address="0x0", query="", limit=over_limit, page=1)

    with pytest.raises(SafetyLimitExceeded):
        xrefs.search_xrefs_to(
            client,
            address="0x0",
            query="",
            limit=MAX_ITEMS_PER_BATCH,
            page=2,
        )
