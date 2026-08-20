"""What each search mode cannot see, and what to do instead.

A search that returns nothing says something about the search, not necessarily
about the firmware.  Reading an empty result as a statement about the binary is
the most expensive documented mistake in this project: ``search_scalars`` cannot
see constant-pool words, so ``0xB1008000`` came back empty while the value sat
at ``0x002AFB4C`` all along, and the USB path stayed blocked for seven months.

The text lives here once and is used twice: it is quoted in the tool
descriptions (so the limit is known *before* the call) and attached to empty
responses as ``method_note`` (so the limit is restated at the moment it bites).
``bridge/tests/unit/test_method_notes.py`` keeps the two copies in sync.

Every alternative path named here must be a tool that exists.  Naming a
capability the server does not have would recreate the very failure this module
is meant to prevent.
"""
from __future__ import annotations

from typing import Dict, Mapping, NamedTuple

__all__ = ["METHOD_NOTES", "MethodNote", "method_note_for", "note_text"]


class MethodNote(NamedTuple):
    """A search mode's structural blind spot and the way around it."""

    blind_spot: str
    alternative: str

    def as_text(self) -> str:
        return f"Blind spot: {self.blind_spot} Instead: {self.alternative}"


_POOL_ALTERNATIVE = (
    "find the constant pool the function loads from -- 'find_in_function' with "
    "query 'ldr' shows the pool address in the operand, e.g. "
    "'ldr r1,[0x2afb34]' -- then 'read_words' at that address. Constants "
    "reached through a PC-relative load are only visible as data, never as "
    "operands."
)

METHOD_NOTES: Mapping[str, MethodNote] = {
    "search_scalars": MethodNote(
        blind_spot=(
            "this searches instruction operands only. Values held in a constant "
            "pool and reached via a PC-relative load (the usual ARM way to "
            "materialise a 32-bit constant) are invisible to it, and so are "
            "values assembled from several immediates."
        ),
        alternative=_POOL_ALTERNATIVE,
    ),
    "search_scalars_with_context": MethodNote(
        blind_spot=(
            "this searches instruction operands only. Values held in a constant "
            "pool and reached via a PC-relative load (the usual ARM way to "
            "materialise a 32-bit constant) are invisible to it, and so are "
            "values assembled from several immediates."
        ),
        alternative=_POOL_ALTERNATIVE,
    ),
    "search_functions": MethodNote(
        blind_spot=(
            "this matches function names, not behaviour. On a stripped binary "
            "almost every name is 'FUN_<address>', so an empty result means the "
            "name is absent, not the functionality."
        ),
        alternative=(
            "search for a string the code must reference ('search_strings'), "
            "then follow it back with 'string_xrefs_compact'; or narrow by "
            "address with 'list_functions_in_range'."
        ),
    ),
    "search_xrefs_to": MethodNote(
        blind_spot=(
            "this reports references Ghidra has recognised as such. A pointer "
            "sitting in an unanalysed data region, a hand-rolled jump table or "
            "a computed branch produces no xref at all."
        ),
        alternative=(
            "read the suspected table directly with 'read_words' and look for "
            "the address word, or disassemble the caller with 'disassemble_at' "
            "and check the branch target by hand."
        ),
    ),
    "search_strings": MethodNote(
        blind_spot=(
            "this searches strings Ghidra has already defined as data. Bytes "
            "that were never turned into a string -- unanalysed regions, "
            "obfuscated or runtime-assembled text -- do not appear."
        ),
        alternative=(
            "read the suspected region with 'read_bytes' and decode it, or "
            "define the data in Ghidra first and search again."
        ),
    ),
}


def method_note_for(tool: str) -> MethodNote | None:
    """Return the note for ``tool``, or ``None`` when none is defined."""

    return METHOD_NOTES.get(tool)


def note_text(tool: str) -> str | None:
    """Return the ready-to-emit note text for ``tool``."""

    note = METHOD_NOTES.get(tool)
    return note.as_text() if note else None


def _known_tools() -> Dict[str, MethodNote]:
    return dict(METHOD_NOTES)
