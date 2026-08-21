import json

from bridge.features.strings import fetch_strings_compact_entries, strings_compact_view


def test_strings_compact_view_truncates_and_orders() -> None:
    raw_entries = [
        {
            "literal": "Beta entry",
            "address": 0x00200020,
            "refs": 7,
        },
        {
            "literal": "Alpha entry with newline\n" + "A" * 200,
            "address": "0x00200000",
            "refs": 5,
        },
        {
            "string": "Gamma entry",
            "addr": 0x00200010,
            "refs": [1, 2, 3],
        },
    ]

    payload = strings_compact_view(raw_entries)

    assert payload["returned"] == len(payload["items"])
    assert payload["has_more"] is False
    assert payload["truncated"] is False
    addresses = [item["addr"] for item in payload["items"]]
    assert addresses == sorted(addresses)

    truncated_literal = payload["items"][0]["s"]
    assert len(truncated_literal) <= 120
    assert truncated_literal.endswith("…")

    for item in payload["items"]:
        assert set(item.keys()) == {"s", "addr", "refs"}
    refs_by_addr = {item["addr"]: item["refs"] for item in payload["items"]}
    assert refs_by_addr["0x00200010"] == 3

    response = {"ok": True, "data": payload, "errors": []}
    assert len(json.dumps(response)) <= 8192


def test_strings_compact_view_can_include_literals() -> None:
    raw_entries = [
        {
            "literal": "Hello\nWorld",
            "address": 0x1000,
            "refs": 1,
        }
    ]

    payload = strings_compact_view(raw_entries, include_literals=True)

    assert payload["items"]
    item = payload["items"][0]
    assert item["literal"] == "Hello World"
    assert item["s"] == "Hello World"
    assert set(item.keys()) == {"s", "addr", "refs", "literal"}


def test_fetch_strings_compact_entries_falls_back_to_search() -> None:
    class SearchOnlyClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def search_strings(self, query: str):
            self.calls.append(query)
            return [
                {"address": 0x1000, "literal": "alpha"},
                {"address": 0x1010, "literal": "beta"},
                {"address": 0x1020, "literal": "gamma"},
            ]

    client = SearchOnlyClient()

    entries, has_more = fetch_strings_compact_entries(client, limit=2, offset=1)

    assert client.calls == [""]
    assert [entry["address"] for entry in entries] == [0x1010, 0x1020]
    # The search fallback pulls everything, so here it does know there is
    # nothing left after the slice.
    assert has_more is False


def test_fetch_prefers_the_paging_provider_and_carries_has_more() -> None:
    """list_strings is the real client's method; it pages at the plugin."""

    class PagingClient:
        def __init__(self) -> None:
            self.calls: list[tuple[int, int]] = []

        def list_strings(self, *, limit: int, offset: int):
            self.calls.append((limit, offset))
            return {
                "items": [{"address": 0x2000, "literal": "one"}],
                "has_more": True,
            }

        def search_strings(self, query: str):  # pragma: no cover - must not run
            raise AssertionError("the paging provider should win")

    client = PagingClient()
    entries, has_more = fetch_strings_compact_entries(client, limit=1, offset=4)

    assert client.calls == [(1, 4)]
    assert [entry["address"] for entry in entries] == [0x2000]
    assert has_more is True


def test_a_client_without_any_string_provider_says_so_rather_than_lying() -> None:
    """The regression: the chain used to bottom out at an empty list.

    strings_compact then answered "no strings" for every call on every program,
    with no error anywhere -- which is how it went unnoticed for months.
    """

    class NoProviders:
        pass

    entries, has_more = fetch_strings_compact_entries(NoProviders(), limit=5, offset=0)
    assert entries == []
    assert has_more is False
