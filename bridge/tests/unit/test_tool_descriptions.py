"""Stage 1: every tool the client sees must describe itself and its parameters.

These assertions run against ``MCP_SERVER.list_tools()`` -- the same code path
that serves the MCP ``tools/list`` request, so the objects here are the ones a
client receives.  That equivalence is not assumed: ``scripts/measure_schema_cost.py
--source both`` measures the real stdio ``tools/list`` response against this
in-process view and prints any tool whose docstring fails to reach the client.
"""
from __future__ import annotations

import asyncio

import pytest

from bridge.app import MCP_SERVER, configure
from bridge.features.analyze import _ALLOWED_FIELDS
from bridge.features.method_notes import METHOD_NOTES


@pytest.fixture(scope="module")
def tools():
    configure()
    return {tool.name: tool for tool in asyncio.run(MCP_SERVER.list_tools())}


def test_the_full_surface_is_present(tools):
    assert len(tools) == 35


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
    assert "Only 'json' is accepted" in description
    # The budget parameter is useless without its unit and its null case.
    assert "max_result_tokens" in description
    assert "null" in description


@pytest.mark.parametrize("tool_name", sorted(METHOD_NOTES))
def test_search_tools_state_their_blind_spot(tools, tool_name):
    """Stage 1 and Stage 2 share one text; the description carries it too."""

    description = tools[tool_name].description or ""
    assert "Not for:" in description, tool_name


@pytest.mark.parametrize("tool_name", sorted(METHOD_NOTES))
def test_search_tools_name_a_tool_that_exists(tools, tool_name):
    """An alternative path pointing at a capability we lack is worse than none.

    There is no byte-search anywhere in this server -- neither the bridge nor
    the Ghidra plugin has such an endpoint -- so no note may send the reader
    looking for one.
    """

    note = METHOD_NOTES[tool_name]
    text = f"{note.blind_spot} {note.alternative}"
    named = {word.strip("'\"`,.") for word in text.split() if word.strip("'\"`,.") in tools}
    assert named, f"{tool_name} names no alternative tool"

    forbidden = ("search_bytes", "byte search", "byte-search", "Bytesuche")
    for phrase in forbidden:
        assert phrase not in text, f"{tool_name} points at a nonexistent capability: {phrase}"


def test_scalar_tools_point_at_the_constant_pool_path(tools):
    """The regression this project actually paid for."""

    for tool_name in ("search_scalars", "search_scalars_with_context"):
        description = tools[tool_name].description or ""
        assert "read_words" in description, tool_name
        assert "find_in_function" in description, tool_name
        assert "constant pool" in description, tool_name
