"""Addresses in named address spaces are not numbers.

The Ghidra plugin renders every address as ``"0x" + address.toString()``.  For
the default space that is correct; for a named space Ghidra already renders
``SPACE:offset``, so the prefix produces ``0xEXTERNAL:00000001`` -- not valid
hex, and rejected by the response schema.  search_imports therefore failed
outright on ZK-INKJET-NANO-APP.bin, which has exactly one import, in the
EXTERNAL space.
"""
from __future__ import annotations

import pytest

from bridge.utils.hex import normalize_symbol_address


@pytest.mark.parametrize(
    "raw, expected",
    [
        # The actual failure, verbatim from the reference firmware.
        ("0xEXTERNAL:00000001", "EXTERNAL:00000001"),
        # Already correct, left alone.
        ("EXTERNAL:00000001", "EXTERNAL:00000001"),
        ("0x00200060", "0x00200060"),
        # Missing prefix, supplied.
        ("00200060", "0x00200060"),
        ("  0x1000  ", "0x1000"),
        # Other named spaces behave the same way.
        ("0xOVERLAY_1:0000dead", "OVERLAY_1:0000dead"),
        ("0xram:00001000", "ram:00001000"),
    ],
)
def test_symbol_addresses_are_normalised(raw, expected):
    assert normalize_symbol_address(raw) == expected


def test_empty_stays_empty():
    assert normalize_symbol_address("") == ""
    assert normalize_symbol_address("   ") == ""


def test_normalisation_is_idempotent():
    once = normalize_symbol_address("0xEXTERNAL:00000001")
    assert normalize_symbol_address(once) == once


@pytest.mark.parametrize("schema", ["search_imports.v1.json", "search_exports.v1.json"])
def test_the_schema_accepts_both_forms(schema):
    from bridge.api.validators import validate_payload

    payload = {
        "query": "e",
        "total": 2,
        "page": 1,
        "limit": 20,
        "has_more": False,
        "truncated": False,
        "returned": 2,
        "items": [
            {"name": "EXT_FUN_0006781e", "address": "EXTERNAL:00000001"},
            {"name": "Reset", "address": "0x00000000"},
        ],
    }
    valid, errors = validate_payload(schema, payload)
    assert valid, errors


@pytest.mark.parametrize("schema", ["search_imports.v1.json", "search_exports.v1.json"])
def test_the_schema_still_rejects_the_malformed_form(schema):
    """Widening the pattern must not turn it into "anything goes"."""

    from bridge.api.validators import validate_payload

    payload = {
        "query": "e",
        "total": 1,
        "page": 1,
        "limit": 20,
        "has_more": False,
        "truncated": False,
        "returned": 1,
        "items": [{"name": "broken", "address": "0xEXTERNAL:00000001"}],
    }
    valid, _ = validate_payload(schema, payload)
    assert not valid
