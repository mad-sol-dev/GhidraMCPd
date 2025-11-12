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

    def disassemble_at(self, address: int, count: int) -> List[dict[str, str]]:
        return [
            {
                "address": f"0x{address + i * 4:08x}",
                "bytes": f"{i:02x}{i:02x}",
                "text": f"INSN_{i}",
            }
            for i in range(max(0, count))
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


def test_context_lines_attach_disassembly() -> None:
    client = DummyClient(
        [
            "alpha @ 0x00001000",
            "beta @ 0x00001004",
        ]
    )

    result = functions.search_functions(
        client,
        query="",
        limit=2,
        page=1,
        context_lines=1,
    )

    assert result["total"] == 2
    for item in result["items"]:
        context = item.get("context")
        assert context is not None
        assert context["window"]["before"] == 1
        assert context["window"]["after"] == 1
        assert context["window"]["center"] == item["address"]
        disassembly = context["disassembly"]
        assert len(disassembly) == 3
        assert disassembly[0]["address"].startswith("0x")


def test_simple_rank_preserves_context_ordering() -> None:
    client = DummyClient(
        [
            "match_main @ 0x00002000",
            "match_helper @ 0x00002008",
            "helper_match @ 0x00002010",
            "other @ 0x00002020",
        ]
    )

    ranked = functions.search_functions(
        client,
        query="match",
        limit=2,
        page=1,
        rank="simple",
        k=3,
        context_lines=2,
    )

    assert ranked["total"] == 3
    names = [item["name"] for item in ranked["items"]]
    assert names == ["match_main", "match_helper"]
    windows = [item["context"]["window"] for item in ranked["items"]]
    assert all(window["before"] == 2 and window["after"] == 2 for window in windows)
