"""Stage 1: every tool the client sees must describe itself and its parameters.

These assertions run against ``MCP_SERVER.list_tools()`` -- the same code path
that serves the MCP ``tools/list`` request, so the objects here are the ones a
client receives.  That equivalence is not assumed: ``scripts/measure_schema_cost.py
--source both`` measures the real stdio ``tools/list`` response against this
in-process view and prints any tool whose docstring fails to reach the client.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from bridge.app import MCP_SERVER, configure
from bridge.features.analyze import _ALLOWED_FIELDS
from bridge.features.method_notes import METHOD_NOTES, SHORT_FORM, method_note_for


@pytest.fixture(scope="module")
def tools():
    configure()
    return {tool.name: tool for tool in asyncio.run(MCP_SERVER.list_tools())}


def test_the_full_surface_is_present(tools):
    # 35 through Stage 4; list_mutations is Stage 5.  Stage 8b removed
    # write_bytes and project_rebase, whose plugin endpoints never existed.
    # R.12 added apply_label, SCRIPT-ADAPTER run_script.
    assert len(tools) == 36


def test_no_tool_without_a_description(tools):
    undocumented = sorted(name for name, tool in tools.items() if not (tool.description or "").strip())
    assert undocumented == []


def test_no_parameter_without_documentation(tools):
    """Every parameter must be named in its tool's description.

    A parameter the model cannot see documented is a parameter it guesses at --
    which is how analyze_function_complete's budget control went unused.
    """

    missing: list[str] = []
    for name, tool in sorted(tools.items()):
        description = tool.description or ""
        properties = (tool.inputSchema or {}).get("properties") or {}
        for parameter in properties:
            if parameter not in description:
                missing.append(f"{name}.{parameter}")
    assert missing == []


def test_analyze_function_complete_lists_every_field(tools):
    """The `fields` list is the response-size control; all seven must be named."""

    description = tools["analyze_function_complete"].description or ""
    for field in _ALLOWED_FIELDS:
        assert f"'{field}'" in description, field


def test_analyze_function_complete_documents_its_enums(tools):
    description = tools["analyze_function_complete"].description or ""
    # fmt accepts exactly one value; saying so is the point.
    assert "'json'" in description
    assert "accepted" in description
    # The budget parameter is useless without its unit and its null case.
    assert "max_result_tokens" in description
    assert "null" in description


@pytest.mark.parametrize("tool_name", sorted(METHOD_NOTES))
def test_a_tool_with_a_blind_spot_carries_the_short_form(tools, tool_name):
    """The description pays per session, so it gets the one-line version.

    This checks that the two exist and belong together, not that they read
    alike: the long text with addresses and a worked example lives in
    method_notes.py, where it is only paid for when a search comes back empty.
    """

    description = tools[tool_name].description or ""
    assert "Not for:" in description, tool_name
    assert SHORT_FORM[tool_name] in description, tool_name
    assert method_note_for(tool_name) is not None, tool_name


def test_short_forms_stay_short():
    """A short form that grows back into an essay defeats the split."""

    for tool_name, text in SHORT_FORM.items():
        assert len(text) <= 220, f"{tool_name}: {len(text)} chars"


def test_every_short_form_belongs_to_a_note():
    assert sorted(SHORT_FORM) == sorted(METHOD_NOTES)


def test_the_detail_lives_in_the_note_not_the_description(tools):
    """The regression this project actually paid for, and where it is written."""

    note = METHOD_NOTES["search_scalars"]
    detail = f"{note.blind_spot} {note.alternative}"
    for anchor in ("0x002AFB4C", "0xB1008000", "read_words", "find_in_function"):
        assert anchor in detail, anchor

    # ...and specifically not in the description, which every session pays for.
    description = tools["search_scalars"].description or ""
    assert "0x002AFB4C" not in description
    assert "read_words" not in description


#: Stage 1 acceptance: the schema base is part of the deal, not a side effect.
#: Baseline before that stage was 5406 tokens, and the ceiling was 8000.
#:
#: Raised to 8400 in Stage 4, deliberately and with the reason recorded.  The
#: disassemble_batch filter (query, regex, case_sensitive, context_lines) costs
#: 442 tokens of schema, taking the base from 7756 to 8198.  It buys the call
#: that used to cost 4999 bytes for 64 instructions and now costs 792 for the 12
#: that were wanted.  The base is paid once per session; that response is paid
#: per call.  Framework condition 6 governs: response volume is what gets
#: optimised, the ceiling is a guard rail rather than a target, and whoever
#: breaks it says why and sets a new one.
#:
#: Raised again in Stage 5, to 8700: list_mutations is a 36th tool and costs 274
#: tokens.  It is the only way a session's renames and comments leave Ghidra as
#: anything other than a memory, which is worth a tool.
#:
#: Lowered in Stage 8b, to 8400: removing write_bytes and project_rebase took
#: the base from 8691 to 8307.  The ceiling follows it down so the 384 tokens
#: do not stay behind as headroom nobody had to argue for.
#:
#: Raised in R.12, to 8500: apply_label costs 151 tokens and takes the base to
#: 8466.  It is the one write the analysis was actually blocked on -- labelling
#: MMIO registers outside every memory block, which no other path could do.
SCHEMA_BASE_CEILING = 8500


def test_schema_base_stays_within_budget(tools):
    """Every session pays this before a single call happens.

    Documentation that doubles the fixed cost is not free documentation.  If
    this fails, run `python scripts/measure_schema_cost.py` for the per-tool
    ranking and trim the top of the list rather than raising the ceiling.
    """

    total = 0
    for name, tool in tools.items():
        schema = json.dumps(tool.inputSchema or {}, sort_keys=True, separators=(",", ":"))
        total += (len(name) + len(tool.description or "") + len(schema)) // 4

    assert total <= SCHEMA_BASE_CEILING, (
        f"schema base is {total} tokens, ceiling is {SCHEMA_BASE_CEILING}"
    )


def test_analyze_default_fields_leave_out_the_expensive_two(tools):
    """The default answers "is this the right function?", not "show me everything".

    Measured on 0x002AF9C0: decompile is 36% of a full dossier and disasm 22%.
    Both are available on better terms elsewhere, so an unparameterised call
    should not pay for them.
    """

    from bridge.features.analyze import _ALLOWED_FIELDS, _DEFAULT_FIELDS

    # 'constants' joined in ANALYZE-POOL-CONSTANTS: about 600 bytes on the
    # reference functions, and they carry USBD_BA and the RAM pointers.
    assert set(_DEFAULT_FIELDS) == {"function", "xrefs", "strings", "constants", "features"}
    assert set(_DEFAULT_FIELDS) < set(_ALLOWED_FIELDS)
    assert "decompile" not in _DEFAULT_FIELDS
    assert "disasm" not in _DEFAULT_FIELDS

    description = tools["analyze_function_complete"].description or ""
    assert "function, xrefs, strings, constants, features" in description
