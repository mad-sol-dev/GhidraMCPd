"""search_scalars and the plugin's inspection cap.

The plugin stops a page after 500 000 inspected instructions and says so in
the page envelope (API 3): ``{"items": [...found so far...], "has_more": false,
"truncated": true, "reason": "inspection cap of 500000 instructions reached
before completing the page"}`` -- no cursor to continue from.  Under API 2 the
reason came as ``"error"``.  This test used to model a
"Scan limit exceeded" with HTTP 413, which the plugin never sends; the
bridge's markers matched only that, so the real cap read as a complete result.
"""
import json

import httpx
import pytest

from bridge.features import scalars
from bridge.ghidra.client import GhidraClient
from bridge.utils.cache import get_search_cache
from bridge.utils.errors import UpstreamFailed
from bridge.tests.plugin_http import plugin_transport

CAP = "inspection cap of 500000 instructions reached before completing the page"


def _client(page: dict) -> GhidraClient:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/searchScalars":
            return httpx.Response(200, text=json.dumps(page))
        return httpx.Response(404, text="<h1>404 Not Found</h1>")

    return GhidraClient("http://ghidra.test/", transport=plugin_transport(handle))


@pytest.fixture(autouse=True)
def _fresh_cache():
    get_search_cache().clear()
    yield
    get_search_cache().clear()


def test_cap_before_any_hit_is_a_failed_search_not_no_hits():
    client = _client({"items": [], "has_more": False, "truncated": True, "reason": CAP})

    with pytest.raises(UpstreamFailed, match="inspection cap"):
        scalars.search_scalars(client, value=0x10, query="0x10", limit=5, page=1)


def test_cap_after_some_hits_keeps_them_and_says_truncated():
    page = {"items": ["002af9c0: mov r0,#0x10", "002afa00: cmp r1,#0x10"], "has_more": False, "truncated": True, "reason": CAP}

    result = scalars.search_scalars(_client(page), value=0x10, query="0x10", limit=5, page=1)

    assert [item["address"] for item in result["items"]] == ["0x002af9c0", "0x002afa00"]
    assert result["truncated"] is True
    assert result["has_more"] is False
    assert "total" not in result


def test_a_complete_page_is_not_truncated():
    page = {"items": ["002af9c0: mov r0,#0x10"], "has_more": False}

    result = scalars.search_scalars(_client(page), value=0x10, query="0x10", limit=5, page=1)

    assert result["truncated"] is False
    assert len(result["items"]) == 1


def test_an_empty_body_is_not_an_empty_page():
    def handle(request):
        return httpx.Response(200, text="")

    client = GhidraClient("http://ghidra.test/", transport=plugin_transport(handle))

    with pytest.raises(UpstreamFailed, match="empty body"):
        scalars.search_scalars(client, value=0x10, query="0x10", limit=5, page=1)


def test_with_context_passes_the_cap_on():
    from bridge.features import batch_ops

    page = {"items": ["002af9c0: mov r0,#0x10"], "has_more": False, "truncated": True, "reason": CAP}

    def handle(request):
        if request.url.path == "/searchScalars":
            return httpx.Response(200, text=json.dumps(page))
        if request.url.path == "/disassembleAt":
            return httpx.Response(200, text="002af9c0: 1000A0E3 mov r0,#0x10")
        return httpx.Response(404, text="<h1>404 Not Found</h1>")

    client = GhidraClient("http://ghidra.test/", transport=plugin_transport(handle))
    result = batch_ops.search_scalars_with_context(client, value=0x10, context_lines=0, limit=5)

    assert result["truncated"] is True
    assert result.get("total") is None


def test_a_page_with_an_error_field_is_not_an_api_3_answer():
    """API 3 marks a cut page with "truncated"; a 200 with "error" is a failure."""

    client = _client({"items": ["002af9c0: mov r0,#0x10"], "has_more": False, "error": CAP})

    with pytest.raises(UpstreamFailed, match="inspection cap"):
        scalars.search_scalars(client, value=0x10, query="0x10", limit=5, page=1)
