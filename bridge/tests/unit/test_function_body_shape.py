"""Two entries of the same name are a thunk, not a duplicate.

Ghidra names a thunk after the function it jumps to.  In the ZK-Inkjet program
``boot_init`` therefore appears twice in one range: the function at 0x0025b0c4
and a four-byte veneer at 0x00273ee4 that does nothing but ``b 0x0025b0c4``.
The listing could not tell them apart, and the same listing's ``size`` could not
be reconciled with the range reported elsewhere.  Both are now answerable from
the response.

Since rework stage 8d the plugin answers ``fmt=json`` with the same fields as
data; the bridge no longer splits ``name @ addr size span=...`` apart.  A plugin
from before 8d answers in text, and that is an error, not an empty range.
"""
import json
from typing import Any, Dict, List

import httpx
import pytest

from bridge.api.validators import validate_payload
from bridge.features import function_range
from bridge.features.listing import ListingUnavailable
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


def _fn(name, address, size=None, **extra):
    entry = {"name": name, "address": address}
    if size is not None:
        entry["size"] = size
    entry.update(extra)
    return entry


def _json(*functions) -> str:
    return json.dumps({"functions": list(functions)})


def test_plain_entries_keep_their_three_keys():
    items = _items(_json(_fn("boot_init", "0x0025b0c4", 392), _fn("FUN_0025b284", "0x0025b284", 48)))
    assert items == [
        {"name": "boot_init", "address": "0x0025b0c4", "size": 392},
        {"name": "FUN_0025b284", "address": "0x0025b284", "size": 48},
    ]


def test_entry_without_a_size_survives():
    assert _items(_json(_fn("FUN_00273ee8", "0x00273ee8", 0))) == [
        {"name": "FUN_00273ee8", "address": "0x00273ee8", "size": None}
    ]


def test_json_is_requested():
    client = _client(_json())
    function_range.list_functions_in_range(
        client, address_min="0x0025b000", address_max="0x00274000", limit=20, page=1
    )
    assert "fmt=json" in str(client.last_requests[0].url)


def test_a_plugin_answering_in_text_is_unavailable_not_empty():
    """The text parser returned [] on any failure -- "no functions here"."""

    client = _client("boot_init @ 0025b0c4 392\n")
    with pytest.raises(ListingUnavailable, match="without JSON"):
        function_range.list_functions_in_range(
            client, address_min="0x0025b000", address_max="0x00274000", limit=20, page=1
        )


def test_thunk_is_named_as_one():
    items = _items(_json(
        _fn("boot_init", "0x0025b0c4", 392, span={"start": "0x0025b0c4", "end": "0x0025b24b"}),
        _fn("boot_init", "0x00273ee4", 4, span={"start": "0x00273ee4", "end": "0x00273ee7"},
            thunk=True, thunk_to="0x0025b0c4"),
    ))
    assert items[0].get("is_thunk") is None
    assert items[1]["is_thunk"] is True
    assert items[1]["thunk_to"] == "0x0025b0c4"


def test_span_is_reported_only_where_it_differs_from_size():
    """FUN_0025b338: 1696 body bytes, 1732 of span, 36 of interior pool."""

    items = _items(_json(
        _fn("FUN_0025b338", "0x0025b338", 1696, span={"start": "0x0025b338", "end": "0x0025b9fb"}),
        _fn("FUN_0025ba00", "0x0025ba00", 116, span={"start": "0x0025ba00", "end": "0x0025ba73"}),
    ))
    assert items[0]["span_bytes"] == 1732
    assert items[0]["span_bytes"] - items[0]["size"] == 36
    assert "span_bytes" not in items[1]


def test_chunks_appear_only_for_a_split_body():
    items = _items(_json(
        _fn("FUN_00200000", "0x00200000", 24, span={"start": "0x00200000", "end": "0x0020002f"},
            chunks=[{"start": "0x00200000", "end": "0x0020000f"},
                    {"start": "0x00200020", "end": "0x0020002f"}]),
        _fn("FUN_00201000", "0x00201000", 16, span={"start": "0x00201000", "end": "0x0020100f"}),
    ))
    assert items[0]["chunks"] == [
        {"start": "0x00200000", "end": "0x0020000f"},
        {"start": "0x00200020", "end": "0x0020002f"},
    ]
    assert "chunks" not in items[1]


def test_unknown_fields_do_not_break_an_entry():
    """A newer plugin may add a field this bridge has never heard of."""

    items = _items(_json(_fn("FUN_0025b338", "0x0025b338", 1696,
                             span={"start": "0x0025b338", "end": "0x0025b9fb"}, mood="cheerful")))
    assert items[0]["size"] == 1696
    assert items[0]["span_bytes"] == 1732


def test_a_thunk_to_an_external_function_has_no_target_address():
    """Two of these in the reference program; the text form broke the schema."""

    items = _items(_json(_fn("thunk_EXT_FUN_0006781e", "0x00212504", 4, thunk=True)))
    assert items[0]["is_thunk"] is True
    assert "thunk_to" not in items[0]
