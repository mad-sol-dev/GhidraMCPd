"""Unit tests for function search feature heuristics."""

from __future__ import annotations

from typing import Iterable, List

from bridge.features import functions


class DummyClient:
    def __init__(self, results: Iterable[str]) -> None:
        self._results = list(results)

    def search_functions(self, query: str) -> List[str]:
        normalized = query.lower()
        if not normalized:
            return list(self._results)
        return [
            line
            for line in self._results
            if normalized in line.lower()
        ]


def test_search_functions_preserves_default_ordering() -> None:
    client = DummyClient(
        [
            "alpha @ 1000",
            "beta @ 0x1004",
            "gamma at 0x1008",
        ]
    )

    result = functions.search_functions(client, query="", limit=10, page=1)

    assert result["total"] == 3
    assert [item["name"] for item in result["items"]] == [
        "alpha",
        "beta",
        "gamma",
    ]
    assert [item["address"] for item in result["items"]] == [
        "0x1000",
        "0x1004",
        "0x1008",
    ]


def test_simple_rank_applies_k_before_pagination() -> None:
    client = DummyClient(
        [
            "foo @ 0x1",
            "foo_helper @ 0x2",
            "helper_foo @ 0x3",
            "other @ 0x4",
        ]
    )

    page1 = functions.search_functions(
        client,
        query="foo",
        limit=1,
        page=1,
        rank="simple",
        k=2,
    )

    assert page1["total"] == 2
    assert page1["items"][0]["name"] == "foo"
    assert page1["has_more"] is True

    page2 = functions.search_functions(
        client,
        query="foo",
        limit=1,
        page=2,
        rank="simple",
        k=2,
    )

    assert page2["total"] == 2
    assert [item["name"] for item in page2["items"]] == ["foo_helper"]
    assert page2["has_more"] is False
