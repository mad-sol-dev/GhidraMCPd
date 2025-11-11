from __future__ import annotations

import pytest

from bridge.features import functions
from bridge.ghidra.client import CursorPageResult
from bridge.utils.cache import get_search_cache


class _RecordingClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_project_info(self) -> dict[str, object]:
        return {"executable_sha256": "deadbeef"}

    def search_functions(
        self,
        query: str,
        *,
        limit: int = 100,
        offset: int = 0,
        cursor: str | None = None,
    ) -> CursorPageResult[str]:
        self.calls += 1
        all_items = [f"func_{i:04d} @ 0x{i + 1:08x}" for i in range(10)]
        start = offset
        if cursor:
            try:
                start = max(0, int(cursor))
            except ValueError:
                start = offset
        end = start + max(1, limit)
        sliced = all_items[start:end]
        has_more = end < len(all_items)
        next_cursor = str(end) if has_more else None
        return CursorPageResult(sliced, has_more, next_cursor)


class _FakeClock:
    def __init__(self, start: float = 10_000.0) -> None:
        self._value = start

    def now(self) -> float:
        return self._value

    def advance(self, seconds: float) -> None:
        self._value += seconds


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    cache = get_search_cache()
    cache.clear()
    cache.reset_clock()
    yield
    cache.clear()
    cache.reset_clock()


def test_repeated_function_searches_hit_cache() -> None:
    client = _RecordingClient()

    first = functions.search_functions(client, query="func", limit=3, page=1)
    assert client.calls == 1

    second = functions.search_functions(client, query="func", limit=3, page=1)
    assert client.calls == 1
    assert first == second


def test_cache_refreshes_after_ttl_expiry() -> None:
    client = _RecordingClient()
    cache = get_search_cache()
    clock = _FakeClock()
    cache.set_clock(clock.now)

    try:
        functions.search_functions(client, query="func", limit=2, page=1)
        assert client.calls == 1

        functions.search_functions(client, query="func", limit=2, page=1)
        assert client.calls == 1

        clock.advance(301)

        functions.search_functions(client, query="func", limit=2, page=1)
        assert client.calls == 2
    finally:
        cache.reset_clock()
