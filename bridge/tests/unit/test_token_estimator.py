"""Stage 2b: the budget has to measure what it is supposed to bound.

The old estimator counted string characters only.  Numbers, addresses and every
structural character were invisible, so a numeric response was estimated at a
fraction of its size and ``max_result_tokens`` never bound anything.  These
tests hold the estimate against the actual serialized length, per response
shape, with ``read_words`` as the case that used to fail worst.
"""
from __future__ import annotations

import json

import pytest

from bridge.utils.tokens import estimate_tokens, serialized_length

#: How far the estimate may sit from serialized-length-over-four.
#: The plan's acceptance is a mean ratio of 0.9-1.1 with no type below 0.7.
TOLERANCE = 0.05


def _ratio(payload: object) -> float:
    exact = len(json.dumps(payload, default=str)) / 4
    if exact == 0:
        return 1.0
    return estimate_tokens(payload) / exact


# One entry per response shape the server actually produces.
RESPONSE_SHAPES = {
    "read_words": {
        "address": "0x002afb34",
        "count": 10,
        "words": [
            0xFF9F0F1F, 0x6978, 0x2EE0, 0xB1008704, 0x8190,
            0x82B0, 0xB1008000, 0xE92D41F0, 0xE1A05000, 0xE1A06003,
        ],
    },
    "read_bytes": {
        "address": "0x002afb34",
        "length": 64,
        "encoding": "base64",
        "data": "H4sIAAAAAAAAA" * 5,
    },
    "disassemble_at": {
        "address": "0x002af9c0",
        "instructions": [
            {"address": f"0x002af9{index:02x}", "text": "ldr r1,[0x2afb34]"}
            for index in range(16)
        ],
    },
    "search_scalars_empty": {
        "value": "0xb1008000",
        "total": 0,
        "matches": [],
        "method_note": "Blind spot: ... Instead: ...",
    },
    "search_functions": {
        "query": "usb",
        "total": 5,
        "page": 1,
        "limit": 100,
        "has_more": False,
        "items": [
            {"name": "usbd_init_phy_cep", "address": "0x002af9c0"},
            {"name": "usbd_irq_setup", "address": "0x002af80c"},
        ],
    },
    "nested_mixed": {
        "meta": {"fields": ["disasm", "xrefs"], "truncated": False},
        "counts": {"reads": 12, "writes": 3, "toggles": 1},
        "samples": [{"op": "READ", "line": 8, "address": None} for _ in range(6)],
    },
    "all_numbers": {"words": list(range(200))},
    "all_nulls": {"words": [None] * 50},
}


@pytest.mark.parametrize("name", sorted(RESPONSE_SHAPES))
def test_estimate_tracks_serialized_length(name):
    payload = RESPONSE_SHAPES[name]
    ratio = _ratio(payload)
    assert abs(ratio - 1.0) <= TOLERANCE, f"{name}: ratio {ratio:.3f}"


def test_read_words_is_no_longer_invisible():
    """The case that proved the old estimator broken.

    A ten-word read serialized to 292 bytes and was estimated at 4 tokens,
    because only the address string was counted.
    """

    payload = RESPONSE_SHAPES["read_words"]
    exact = serialized_length(payload)
    assert estimate_tokens(payload) == exact // 4
    assert estimate_tokens(payload) > 30, "a numeric payload must not vanish"


def test_numbers_are_counted_at_all():
    """The specific blind spot, stated as a test.

    This payload contains not one string.  The old estimator returned 0 for it,
    which is how a budget comes to bound nothing.
    """

    payload = {"words": list(range(100))}
    assert estimate_tokens(payload) == serialized_length(payload) // 4
    assert estimate_tokens(payload) > 50


def test_structure_is_counted_at_all():
    """Keys, braces and commas are paid for too."""

    flat = {"a": "xxxx"}
    nested = {"a": {"b": {"c": {"d": "xxxx"}}}}
    assert estimate_tokens(nested) > estimate_tokens(flat)


def test_estimate_grows_with_the_payload():
    small = {"items": [{"address": "0x1000"}]}
    large = {"items": [{"address": "0x1000"}] * 40}
    assert estimate_tokens(large) > 20 * estimate_tokens(small)


def test_empty_payload_costs_nothing_meaningful():
    assert estimate_tokens({}) == 0
    assert estimate_tokens([]) == 0


def test_unserializable_values_do_not_raise():
    """An estimator that throws on an odd payload is worse than one that guesses."""

    class Opaque:
        def __str__(self) -> str:
            return "x" * 40

    assert estimate_tokens({"thing": Opaque()}) > 0
