import pytest

from bridge.features import scalars
from bridge.ghidra.client import CursorPageResult, RequestError
from bridge.utils.cache import build_search_cache_key, get_search_cache, normalize_search_query
from bridge.utils.logging import SafetyLimitExceeded


class _FakeClient:
    def __init__(self):
        self.calls = 0

    def get_project_info(self):
        return {"program_digest": "cafebabe"}

    def search_scalars(self, value: int, *, limit: int, offset: int, cursor=None):
        self.calls += 1
        error = RequestError(status=413, reason="Scan limit exceeded", retryable=False)
        return CursorPageResult([], False, None, error=error)


def test_search_scalars_raises_on_plugin_limits_and_invalidates_cache() -> None:
    cache = get_search_cache()
    cache.clear()

    client = _FakeClient()
    normalized_query = normalize_search_query("Test")
    cache_key = build_search_cache_key(
        program_digest="cafebabe",
        endpoint="scalars",
        normalized_query=normalized_query,
        options={"limit": 5, "page": 1, "cursor": None, "value": 0x10},
    )

    with pytest.raises(SafetyLimitExceeded):
        scalars.search_scalars(client, value=0x10, query="Test", limit=5, page=1)

    assert cache.get(cache_key) is None
    assert client.calls == 1

