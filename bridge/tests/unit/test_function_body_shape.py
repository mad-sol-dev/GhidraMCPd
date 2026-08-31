"""Two entries of the same name are a thunk, not a duplicate.

Ghidra names a thunk after the function it jumps to.  In the ZK-Inkjet program
``boot_init`` therefore appears twice in one range: the function at 0x0025b0c4
and a four-byte veneer at 0x00273ee4 that does nothing but ``b 0x0025b0c4``.
The listing could not tell them apart, and the same listing's ``size`` could not
be reconciled with the range reported elsewhere.  Both are now answerable from
the response.

The plugin emits the extra fields only when asked (``fields=extended``), so a
bridge talking to an older plugin sees the old format -- which these tests cover
as well, because that is what runs until the extension is rebuilt.
"""
from typing import Any, Dict, List

import httpx
import pytest

from bridge.api.validators import validate_payload
from bridge.features import function_range
from bridge.ghidra.client import GhidraClient


def _client(body: str) -> GhidraClient:
    """A client whose Ghidra answers every request with ``body``."""

    def handler(request: httpx.Request) -> httpx.Response:
        handler.requests.append(request)
        return httpx.Response(200, text=body)

    handler.requests = []
    transport = httpx.MockTransport(handler)
    client = GhidraClient("http://ghidra.test/", transport=transport)
    client.last_requests = handler.requests
    return client


def _items(body: str) -> List[Dict[str, Any]]:
    client = _client(body)
    payload = function_range.list_functions_in_range(
        client, address_min="0x0025b000", address_max="0x00274000", limit=20, page=1
    )
    valid, errors = validate_payload("list_functions_in_range.v1.json", payload)
    assert valid, errors
    return payload["items"]


# --- the old format, which is what runs until the plugin is rebuilt ----------


def test_old_format_still_parses_unchanged():
    items = _items("boot_init @ 0025b0c4 392\nFUN_0025b284 @ 0025b284 48\n")
    assert items == [
        {"name": "boot_init", "address": "0x0025b0c4", "size": 392},
        {"name": "FUN_0025b284", "address": "0x0025b284", "size": 48},
    ]


def test_entry_without_a_size_survives():
    assert _items("FUN_00273ee8 @ 00273ee8\n") == [
        {"name": "FUN_00273ee8", "address": "0x00273ee8", "size": None}
    ]


def test_extended_fields_are_requested():
    """Asking costs nothing: a plugin that does not know the parameter ignores it."""

    client = _client("boot_init @ 0025b0c4 392\n")
    function_range.list_functions_in_range(
        client, address_min="0x0025b000", address_max="0x00274000", limit=20, page=1
    )
    assert "fields=extended" in str(client.last_requests[0].url)


# --- the extended format -----------------------------------------------------


def test_thunk_is_named_as_one():
    items = _items(
        "boot_init @ 0025b0c4 392 span=0025b0c4-0025b24b\n"
        "boot_init @ 00273ee4 4 span=00273ee4-00273ee7 thunk=0025b0c4\n"
    )
    assert items[0].get("is_thunk") is None
    assert items[1]["is_thunk"] is True
    assert items[1]["thunk_to"] == "0x0025b0c4"


def test_span_is_reported_only_where_it_differs_from_size():
    """FUN_0025b338: 1696 body bytes, 1732 of span, 36 of interior pool."""

    items = _items(
        "FUN_0025b338 @ 0025b338 1696 span=0025b338-0025b9fb\n"
        "FUN_0025ba00 @ 0025ba00 116 span=0025ba00-0025ba73\n"
    )
    assert items[0]["span_bytes"] == 1732
    assert items[0]["span_bytes"] - items[0]["size"] == 36
    # A contiguous body says the same thing twice; it is not repeated.
    assert "span_bytes" not in items[1]


def test_chunks_appear_only_for_a_split_body():
    items = _items(
        "FUN_00200000 @ 00200000 24 span=00200000-0020002f chunks=00200000-0020000f,00200020-0020002f\n"
        "FUN_00201000 @ 00201000 16 span=00201000-0020100f\n"
    )
    assert items[0]["chunks"] == [
        {"start": "0x00200000", "end": "0x0020000f"},
        {"start": "0x00200020", "end": "0x0020002f"},
    ]
    assert "chunks" not in items[1]


def test_unknown_fields_do_not_break_the_line():
    """A newer plugin may add a token this bridge has never heard of."""

    items = _items("FUN_0025b338 @ 0025b338 1696 span=0025b338-0025b9fb mood=cheerful\n")
    assert items[0]["size"] == 1696
    assert items[0]["span_bytes"] == 1732


def test_malformed_span_is_ignored_rather_than_guessed():
    items = _items("FUN_0025b338 @ 0025b338 1696 span=garbage\n")
    assert items[0] == {
        "name": "FUN_0025b338",
        "address": "0x0025b338",
        "size": 1696,
    }
