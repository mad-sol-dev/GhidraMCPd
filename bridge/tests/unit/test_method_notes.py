"""The blind-spot texts shared by Stage 1 descriptions and Stage 2 responses."""
from __future__ import annotations

import pytest

from bridge.features.method_notes import METHOD_NOTES, method_note_for, note_text


def test_every_note_names_both_halves():
    """A blind spot without a way around it just tells the reader to give up."""

    for tool, note in METHOD_NOTES.items():
        assert note.blind_spot.strip(), tool
        assert note.alternative.strip(), tool


def test_notes_cover_the_tools_the_rework_named():
    required = {
        "search_scalars",
        "search_scalars_with_context",
        "search_functions",
        "search_xrefs_to",
    }
    assert required <= set(METHOD_NOTES)


def test_note_text_reads_as_one_statement():
    text = note_text("search_scalars")
    assert text is not None
    assert text.startswith("Blind spot:")
    assert "Instead:" in text


def test_unknown_tool_has_no_note():
    assert method_note_for("project_info") is None
    assert note_text("project_info") is None


@pytest.mark.parametrize("tool", sorted(METHOD_NOTES))
def test_no_note_promises_a_capability_the_server_lacks(tool):
    """There is no byte-search endpoint in the bridge or the Ghidra plugin.

    The rework draft listed "byte search" as the alternative path for scalars
    and xrefs.  It does not exist.  Sending a reader after it would repeat the
    exact failure these notes exist to prevent.
    """

    note = METHOD_NOTES[tool]
    text = f"{note.blind_spot} {note.alternative}".lower()
    for phrase in ("search_bytes", "byte search", "byte-search", "search bytes"):
        assert phrase not in text, f"{tool}: {phrase}"


def test_the_scalar_note_describes_the_case_that_cost_seven_months():
    note = METHOD_NOTES["search_scalars"]
    assert "operand" in note.blind_spot
    assert "pc-relative" in note.blind_spot.lower()
    assert "read_words" in note.alternative
    assert "find_in_function" in note.alternative
