"""Text rendering for instruction listings.

A disassembly line carries three short fields.  As JSON each one costs its key,
four quote marks and two separators::

    {"address": "0x00200d7c", "bytes": "C53400EB", "text": "bl 0x0020e098"}   71 chars
    "00200d7c: C53400EB bl 0x0020e098"                                        34 chars

That is 52% of a listing spent on punctuation the reader does not need, repeated
per line, on the tools that produce the largest responses on this server.

The text form follows the layout ``find_in_function`` already emits
(``002af9dc: ldr r0,[r0,#0x214]``), so listings look the same wherever they
appear.  ``fmt="json"`` remains the default: text is for reading, JSON is for
anything that parses fields.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Pattern, Sequence

__all__ = [
    "FORMATS",
    "compile_query",
    "filter_instructions",
    "instruction_line",
    "normalize_fmt",
    "render_lines",
    "to_text",
]

#: Accepted values for the ``fmt`` parameter.
FORMATS = ("json", "text")


def normalize_fmt(value: object) -> str:
    """Validate and normalise a ``fmt`` argument."""

    fmt = str(value or "json").strip().lower()
    if fmt not in FORMATS:
        raise ValueError(f"fmt must be one of {', '.join(FORMATS)}")
    return fmt


def instruction_line(entry: Mapping[str, Any]) -> str:
    """Render one instruction as ``address: bytes text``.

    Missing fields are dropped rather than rendered as empty padding, so a line
    never claims a byte pattern it does not have.
    """

    address = str(entry.get("address", "") or "").strip()
    if address[:2].lower() == "0x":
        address = address[2:]
    raw_bytes = str(entry.get("bytes", "") or "").strip()
    text = str(entry.get("text", "") or "").strip()

    head = f"{address}: " if address else ""
    body = " ".join(part for part in (raw_bytes, text) if part)
    return f"{head}{body}".rstrip()


def render_lines(entries: Iterable[Mapping[str, Any]]) -> List[str]:
    """Render a listing as text lines."""

    return [instruction_line(entry) for entry in entries]


def to_text(
    payload: MutableMapping[str, Any],
    *,
    source: str = "items",
    target: str = "lines",
) -> MutableMapping[str, Any]:
    """Replace an object listing with its text form, in place.

    The source key is removed rather than kept alongside: carrying both would
    cost more than the JSON form it is meant to replace.
    """

    entries = payload.pop(source, None)
    if isinstance(entries, list):
        payload[target] = render_lines(entries)
    else:
        payload[target] = []
    return payload


def batch_to_text(results: Mapping[str, Any]) -> Dict[str, List[str]]:
    """Render a ``{address: [instruction, ...]}`` mapping as text lines."""

    return {
        address: render_lines(entries if isinstance(entries, list) else [])
        for address, entries in results.items()
    }


def compile_query(query: str, *, regex: bool, case_sensitive: bool) -> Pattern[str]:
    """Compile a listing filter, with the same semantics as find_in_function.

    A literal query is escaped rather than interpreted, so searching for
    ``[0x2afb34]`` finds that operand instead of raising on an unbalanced
    bracket.
    """

    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = query if regex else re.escape(query)
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc


def filter_instructions(
    entries: Sequence[Mapping[str, Any]],
    pattern: Pattern[str],
    *,
    context_lines: int = 0,
) -> tuple[List[Mapping[str, Any]], int]:
    """Keep the instructions matching ``pattern``, plus their context.

    Matching runs against the rendered line -- ``address: bytes mnemonic`` --
    so the address and the encoded bytes are searchable, exactly as in
    ``find_in_function``.  Returns the kept entries in original order and the
    number of matches, which are different numbers as soon as context is
    requested and overlapping windows merge.
    """

    keep: set[int] = set()
    matched = 0

    for index, entry in enumerate(entries):
        if not pattern.search(instruction_line(entry)):
            continue
        matched += 1
        low = max(0, index - context_lines)
        high = min(len(entries), index + context_lines + 1)
        keep.update(range(low, high))

    return [entries[index] for index in sorted(keep)], matched
