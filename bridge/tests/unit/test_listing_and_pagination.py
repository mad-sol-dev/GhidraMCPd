"""Stage 3: text listings, and omission that is visible."""
from __future__ import annotations

import json

import pytest

from bridge.features.listing import (
    batch_to_text,
    instruction_line,
    normalize_fmt,
    render_lines,
    to_text,
)
from bridge.features.pagination import finalize_page

INSTRUCTION = {"address": "0x00200d7c", "bytes": "C53400EB", "text": "bl 0x0020e098"}


# ------------------------------------------------------------------- listing

def test_a_line_renders_in_the_existing_house_format():
    """find_in_function already emits "002af9dc: ...", so listings match it."""

    assert instruction_line(INSTRUCTION) == "00200d7c: C53400EB bl 0x0020e098"


def test_text_is_about_half_the_json():
    as_json = json.dumps({"items": [INSTRUCTION] * 16})
    as_text = json.dumps({"lines": render_lines([INSTRUCTION] * 16)})
    assert len(as_text) < len(as_json) * 0.55


def test_missing_fields_are_dropped_not_padded():
    """A line must never imply a byte pattern it does not have."""

    assert instruction_line({"address": "0x1000", "text": "nop"}) == "1000: nop"
    assert instruction_line({"text": "nop"}) == "nop"
    assert instruction_line({}) == ""


def test_the_object_listing_is_replaced_not_duplicated():
    """Keeping both forms would cost more than the one it replaces."""

    payload = {"items": [INSTRUCTION]}
    to_text(payload)
    assert "items" not in payload
    assert payload["lines"] == ["00200d7c: C53400EB bl 0x0020e098"]


def test_to_text_on_a_missing_listing_yields_an_empty_one():
    payload = {}
    to_text(payload)
    assert payload["lines"] == []


def test_batch_rendering_keeps_the_address_keys():
    rendered = batch_to_text({"0x1000": [INSTRUCTION], "0x2000": []})
    assert set(rendered) == {"0x1000", "0x2000"}
    assert rendered["0x2000"] == []


@pytest.mark.parametrize("value, expected", [("json", "json"), ("TEXT", "text"), (None, "json")])
def test_fmt_is_normalised(value, expected):
    assert normalize_fmt(value) == expected


def test_an_unknown_fmt_is_an_error_not_a_silent_fallback():
    with pytest.raises(ValueError):
        normalize_fmt("yaml")


# ---------------------------------------------------------------- pagination

def test_an_unknown_total_is_removed():
    payload = {"total": None, "has_more": True, "items": [1]}
    finalize_page(payload)
    assert "total" not in payload


def test_a_known_total_is_kept():
    payload = {"total": 7, "has_more": False, "items": [1]}
    finalize_page(payload)
    assert payload["total"] == 7


def test_truncated_follows_the_read_more_signals_by_default():
    assert finalize_page({"total": None, "has_more": True})["truncated"] is True
    assert finalize_page({"total": 3, "has_more": False})["truncated"] is False
    assert finalize_page({"total": None, "cursor": "abc"})["truncated"] is True


def test_truncated_can_be_stated_where_pagination_does_not_explain_it():
    """A hard per-request cap truncates with nothing to page to.

    That case has to stay distinguishable from a complete result, which is why
    truncated is a separate field rather than an alias for has_more.
    """

    capped = finalize_page({"total": 5, "has_more": False, "items": [1]}, truncated=True)
    assert capped["truncated"] is True
    assert capped["has_more"] is False


def test_finalize_is_idempotent():
    payload = {"total": None, "has_more": True, "items": []}
    once = dict(finalize_page(payload))
    twice = dict(finalize_page(payload))
    assert once == twice


# ------------------------------------------------- the two surfaces disagree

def test_mcp_defaults_to_text_and_http_defaults_to_json():
    """A deliberate split, so it should be asserted rather than assumed.

    The MCP surface answers a model that reads listings; text costs about half
    and reads the same.  The HTTP surface answers programs that parse fields,
    where changing the shape under them would be a silent breaking change.
    """

    import asyncio
    import inspect

    from bridge.app import MCP_SERVER, configure
    from bridge.features import batch_ops, disasm

    configure()
    tools = {tool.name: tool for tool in asyncio.run(MCP_SERVER.list_tools())}

    for name in ("disassemble_at", "disassemble_batch", "search_scalars_with_context"):
        schema = tools[name].inputSchema or {}
        assert schema["properties"]["fmt"]["default"] == "text", name

    # The feature functions keep json, and the HTTP routes never pass fmt, so
    # that surface is unchanged.
    for func in (
        disasm.disassemble_at,
        batch_ops.disassemble_batch,
        batch_ops.search_scalars_with_context,
    ):
        assert inspect.signature(func).parameters["fmt"].default == "json", func.__name__


def test_http_routes_do_not_forward_a_listing_fmt():
    """Guards the half of the split that is an absence rather than a value.

    analyze_function_complete has its own unrelated `fmt` (which accepts only
    "json"), so the check is scoped to the calls that produce listings.
    """

    import pathlib
    import re

    listing_calls = re.compile(
        r"(disasm\.disassemble_at|batch_ops\.disassemble_batch|"
        r"batch_ops\.search_scalars_with_context)\s*\((?:[^()]|\([^()]*\))*\)"
    )

    forwarding = []
    for path in pathlib.Path("bridge/api/routes").glob("*.py"):
        for call in listing_calls.finditer(path.read_text()):
            if "fmt" in call.group(0):
                forwarding.append(f"{path.name}: {call.group(0)[:60]}")
    assert forwarding == [], forwarding


# ------------------------------------------------- Stage 4: the batch filter

from bridge.features.listing import compile_query, filter_instructions  # noqa: E402

WINDOW = [
    {"address": "0x002af9dc", "bytes": "140290E5", "text": "ldr r0,[r0,#0x214]"},
    {"address": "0x002af9e0", "bytes": "4C119FE5", "text": "ldr r1,[0x2afb34]"},
    {"address": "0x002af9e4", "bytes": "000000EA", "text": "b 0x002af9f0"},
    {"address": "0x002af9e8", "bytes": "0000A0E1", "text": "nop"},
    {"address": "0x002af9f0", "bytes": "40019FE5", "text": "ldr r0,[0x2afb38]"},
]


def _filter(query, **kwargs):
    pattern = compile_query(
        query,
        regex=kwargs.pop("regex", False),
        case_sensitive=kwargs.pop("case_sensitive", False),
    )
    return filter_instructions(WINDOW, pattern, **kwargs)


def test_a_literal_query_keeps_only_matching_instructions():
    kept, matched = _filter("ldr")
    assert matched == 3
    assert [entry["address"] for entry in kept] == [
        "0x002af9dc",
        "0x002af9e0",
        "0x002af9f0",
    ]


def test_matching_runs_against_the_rendered_line():
    """Address and encoded bytes are searchable, as in find_in_function."""

    _, by_address = _filter("002af9e0")
    assert by_address == 1
    _, by_bytes = _filter("4C119FE5")
    assert by_bytes == 1


def test_a_literal_query_is_escaped_not_interpreted():
    """'[0x2afb34]' is an operand, not a character class."""

    kept, matched = _filter("[0x2afb34]")
    assert matched == 1
    assert kept[0]["address"] == "0x002af9e0"


def test_regex_mode_interprets_the_pattern():
    _, matched = _filter(r"ldr \w+,\[0x", regex=True)
    assert matched == 2


def test_an_invalid_regex_is_an_error_not_a_silent_literal():
    with pytest.raises(ValueError):
        compile_query("ldr [", regex=True, case_sensitive=False)


def test_case_sensitivity_is_off_by_default_and_can_be_turned_on():
    _, insensitive = _filter("LDR")
    assert insensitive == 3
    _, sensitive = _filter("LDR", case_sensitive=True)
    assert sensitive == 0


def test_context_widens_the_result_without_inflating_the_match_count():
    """returned and matched are different numbers, and both are reported."""

    kept, matched = _filter("nop", context_lines=1)
    assert matched == 1
    assert len(kept) == 3


def test_overlapping_context_windows_merge_instead_of_duplicating():
    kept, matched = _filter("ldr", context_lines=2)
    assert matched == 3
    assert len(kept) == len(WINDOW)
    assert [entry["address"] for entry in kept] == [e["address"] for e in WINDOW]


def test_a_query_that_matches_nothing_returns_nothing():
    kept, matched = _filter("zzz")
    assert (kept, matched) == ([], 0)


def test_context_cannot_reach_past_the_window():
    kept, _ = _filter("ldr r0,[r0", context_lines=10)
    assert len(kept) == len(WINDOW)
