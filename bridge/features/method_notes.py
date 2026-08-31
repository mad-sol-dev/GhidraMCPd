"""What each search mode cannot see, and what to do instead.

A search that returns nothing says something about the search, not necessarily
about the firmware.  Reading an empty result as a statement about the binary is
the most expensive documented mistake in this project: ``search_scalars`` cannot
see constant-pool words, so ``0xB1008000`` came back empty while the value sat
at ``0x002AFB4C`` all along, and the USB path stayed blocked for seven months.

The long text lives here and nowhere else.  A tool description is paid for in
every session; a method note is paid for only when a search comes back empty,
which is the moment the detail is actually worth reading.  So the descriptions
carry a one-line version and these notes carry the addresses and the worked
example.

Every alternative path named here must be a tool that exists.  Naming a
capability the server does not have would recreate the very failure this module
is meant to prevent.
"""
from __future__ import annotations

from typing import Mapping, MutableMapping, NamedTuple, Sequence

__all__ = [
    "METHOD_NOTES",
    "attach",
    "SHORT_FORM",
    "MethodNote",
    "listing_coverage_note",
    "method_note_for",
    "note_text",
    "short_form",
    "unmapped_memory_note",
]


class MethodNote(NamedTuple):
    """A search mode's structural blind spot and the way around it."""

    blind_spot: str
    alternative: str

    def as_text(self) -> str:
        return f"Blind spot: {self.blind_spot} Instead: {self.alternative}"


_POOL_BLIND_SPOT = (
    "this searches instruction operands only. A value held in a constant pool "
    "and reached by a PC-relative load -- the usual ARM way to materialise a "
    "32-bit constant -- never appears as an operand, and neither does a value "
    "assembled from several immediates."
)

_POOL_ALTERNATIVE = (
    "find the pool the function loads from, then read it as data. "
    "find_in_function(address, 'ldr') shows the pool address inside the "
    "operand, e.g. 'ldr r1,[0x2afb34]'; read_words at that address returns the "
    "constants themselves. Worked example from the reference firmware: "
    "search_scalars('0xB1008000') returns 0 hits, while "
    "read_words('0x002AFB34', 10) shows 0xB1008000 at 0x002AFB4C and "
    "0xB1008704 at 0x002AFB40."
)

METHOD_NOTES: Mapping[str, MethodNote] = {
    "search_scalars": MethodNote(
        blind_spot=_POOL_BLIND_SPOT,
        alternative=_POOL_ALTERNATIVE,
    ),
    "search_scalars_with_context": MethodNote(
        blind_spot=_POOL_BLIND_SPOT,
        alternative=_POOL_ALTERNATIVE,
    ),
    "search_functions": MethodNote(
        blind_spot=(
            "this matches function names, not behaviour. On a stripped binary "
            "almost every name is 'FUN_<address>', so an empty result means the "
            "name is absent, not the functionality."
        ),
        alternative=(
            "reach the function through data it must touch. "
            "search_strings for a string the code references, then "
            "string_xrefs_compact on that string's address gives the callers. "
            "Where you already know the region, list_functions_in_range walks "
            "it in address order."
        ),
    ),
    "search_xrefs_to": MethodNote(
        blind_spot=(
            "this reports references Ghidra has recognised as such. A pointer "
            "in an unanalysed data region, a hand-rolled jump table or a "
            "computed branch produces no xref at all."
        ),
        alternative=(
            "read the suspected table as data with read_words and look for the "
            "address word yourself, or disassemble the caller with "
            "disassemble_at and follow the branch target by hand. For a "
            "suspected jump table, jt_scan checks a run of slots at once."
        ),
    ),
    "search_strings": MethodNote(
        blind_spot=(
            "this searches strings Ghidra has already defined as data. Bytes "
            "never turned into a string -- unanalysed regions, obfuscated or "
            "runtime-assembled text -- do not appear."
        ),
        alternative=(
            "read the suspected region with read_bytes and decode it yourself, "
            "or define the data in Ghidra first and search again."
        ),
    ),
}

#: The one-line form quoted in the tool descriptions.  Kept short on purpose:
#: the description is paid for in every session, the note only on an empty hit.
SHORT_FORM: Mapping[str, str] = {
    "search_scalars": (
        "constants held in a constant pool -- this reads instruction operands "
        "only. On zero hits the response carries a method_note with the way "
        "around it."
    ),
    "search_scalars_with_context": (
        "constants held in a constant pool -- this reads instruction operands "
        "only. On zero hits the response carries a method_note with the way "
        "around it."
    ),
    "search_functions": (
        "finding functionality -- this matches names, and a stripped binary has "
        "none. On zero hits the response carries a method_note with the way "
        "around it."
    ),
    "search_xrefs_to": (
        "references Ghidra never recognised, such as computed branches or "
        "hand-rolled tables. On zero hits the response carries a method_note "
        "with the way around it."
    ),
    "search_strings": (
        "bytes Ghidra never defined as a string. On zero hits the response "
        "carries a method_note with the way around it."
    ),
}


def method_note_for(tool: str) -> MethodNote | None:
    """Return the note for ``tool``, or ``None`` when none is defined."""

    return METHOD_NOTES.get(tool)


def note_text(tool: str) -> str | None:
    """Return the ready-to-emit note text for ``tool``."""

    note = METHOD_NOTES.get(tool)
    return note.as_text() if note else None


def short_form(tool: str) -> str | None:
    """Return the one-line form used in the tool description."""

    return SHORT_FORM.get(tool)


# --- Notes for results that are wrong rather than empty ---------------------
#
# The notes above answer "nothing came back".  These answer the more expensive
# case: something came back, it looks complete, and it is not.  A listing that
# silently begins 21 KiB past the requested address reads exactly like one that
# begins at it, so the note has to carry the numbers, not just the warning.


def listing_coverage_note(
    *,
    requested: str,
    start: str | None,
    skipped_bytes: int,
    gap_bytes: int = 0,
    gap_count: int = 0,
) -> str | None:
    """Describe where a disassembly listing really starts and what it left out.

    Returns ``None`` for a listing that starts at the requested address and runs
    without holes -- the ordinary case, which must not pay for this text.
    """

    if start is None:
        return (
            f"Blind spot: no instructions are defined at or after {requested}, "
            "so this listing is empty for a reason that says nothing about the "
            "bytes there. Instead: read them as data with read_bytes or "
            "read_words, or define them as code in Ghidra and disassemble "
            "again."
        )

    parts: list[str] = []
    if skipped_bytes > 0:
        parts.append(
            f"this listing does not start at {requested}. Ghidra disassembles "
            f"only bytes it has defined as instructions, and the "
            f"{skipped_bytes} bytes from {requested} carry no definition, so "
            f"the listing begins at {start} instead. Nothing in the "
            f"instructions themselves says so."
        )
    if gap_bytes > 0:
        if gap_count == 1:
            where = f"1 hole of {gap_bytes} bytes lies"
        else:
            where = f"{gap_count} holes totalling {gap_bytes} bytes lie"
        parts.append(
            f"{where} inside the listing -- undefined bytes or data such as a "
            "constant pool, skipped without a marker. They are listed under "
            "coverage."
        )
    if not parts:
        return None

    return (
        "Blind spot: "
        + " Also: ".join(parts)
        + " Instead: read the skipped bytes as data with read_bytes or "
        "read_words, or define them as code in Ghidra and disassemble again."
    )


def unmapped_memory_note(
    *, address: str, unreadable: int, total: int, unit: str = "words"
) -> str:
    """Explain a read that returned nothing because nothing is mapped there.

    ``null`` is not zero, but it is one character away from looking like it.
    An unmapped MMIO register and a register that reads as zero produce the
    same shape of answer, and only one of them is a statement about the
    firmware.
    """

    scope = (
        "no memory is mapped"
        if unreadable >= total
        else f"{unreadable} of {total} {unit} fall outside any mapped block"
    )
    return (
        f"Blind spot: {scope} at {address}, so the nulls here mean 'not "
        "readable', not 'reads as zero'. A memory-mapped register that Ghidra "
        "has no block for looks exactly like one holding 0. Instead: check "
        "project_info for the mapped blocks and their ranges, and read at an "
        "address inside one; a register only present at runtime cannot be read "
        "from the image at all."
    )


#: Where each tool keeps its result list, for the empty-result check.
_RESULT_KEYS = ("items", "matches")


def _looks_empty(payload: Mapping[str, object]) -> bool:
    """True when the response carries no results.

    ``total == 0`` is the primary signal.  Cursor-paginated responses may report
    ``total`` as ``None``; there the emptiness of the result list decides, so a
    genuinely empty page still gets its note.
    """

    total = payload.get("total")
    if isinstance(total, int) and not isinstance(total, bool):
        return total == 0

    for key in _RESULT_KEYS:
        value = payload.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return len(value) == 0
        if isinstance(value, Mapping):
            return not any(value.values())
    return False


def attach(tool: str, payload: MutableMapping[str, object]) -> MutableMapping[str, object]:
    """Add ``method_note`` to ``payload`` when the search came back empty.

    Called from the feature functions rather than the tool wrappers, so the MCP
    tools, the HTTP routes and ``collect`` all carry the note without three
    copies of this decision.
    """

    note = METHOD_NOTES.get(tool)
    if note is None or not _looks_empty(payload):
        return payload
    payload["method_note"] = note.as_text()
    return payload
