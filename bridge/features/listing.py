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

from ..utils.hex import int_to_hex

__all__ = [
    "FORMATS",
    "ListingUnavailable",
    "structured_listing",
    "compile_query",
    "context_window",
    "coverage",
    "coverage_fields",
    "filter_instructions",
    "instruction_line",
    "normalize_fmt",
    "render_lines",
    "to_text",
]

#: Accepted values for the ``fmt`` parameter.
FORMATS = ("json", "text")


class ListingUnavailable(RuntimeError):
    """The plugin gave no structured listing; nothing can be classified."""


def structured_listing(client: Any, address: int) -> Mapping[str, Any]:
    """The function's structured listing, or ListingUnavailable with the reason.

    A missing listing must not become an empty one: "no instructions" reads as
    a statement about the function, when it is a statement about the plugin.
    """

    listing = client.disassemble_function_structured(address)
    if listing is None:
        error = getattr(client, "last_error", None)
        reason = getattr(error, "reason", None) or "structured disassembly unavailable"
        raise ListingUnavailable(f"cannot disassemble {int_to_hex(address)}: {reason}")
    return listing


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


def _entry_address(entry: Mapping[str, Any]) -> int | None:
    """Parse an entry address, tolerating both ``0x2818b0`` and ``2818b0``."""

    raw = str(entry.get("address", "") or "").strip()
    if not raw:
        return None
    try:
        return int(raw, 16)
    except ValueError:
        return None


def _entry_length(entry: Mapping[str, Any]) -> int | None:
    """Instruction length in bytes, from its hex byte string."""

    raw = str(entry.get("bytes", "") or "").strip()
    if not raw or len(raw) % 2:
        return None
    return len(raw) // 2


def context_window(client: Any, address: int, lines: int) -> List[Dict[str, Any]]:
    """``lines`` instructions either side of the one at ``address``.

    Asking for 2n+1 instructions from ``address - 4n`` centres the hit only
    where every instruction is 4 bytes and defined: with 2-byte Thumb code the
    hit lands late, with data in front it lands late, with short x86
    instructions it can fall outside the window.  So more is fetched (from
    ``address - 4n``, up to 4n+1+n instructions -- every possible instruction
    before plus n after), the hit is found by address, and n either side of it
    are kept.  A start before the memory block (UNMAPPED under API 3) falls
    back to starting at the hit.  If the hit is not an instruction start in
    the listing, the first 2n+1 instructions from the start are returned, as
    before.
    """

    count = 2 * lines + 1
    if lines <= 0:
        return list(client.disassemble_at(address, 1) or [])
    start = max(0, address - lines * 4)
    fetched = list(client.disassemble_at(start, min(128, 5 * lines + 1)) or [])
    if not fetched and start != address:
        fetched = list(client.disassemble_at(address, lines + 1) or [])
    hit = next((i for i, entry in enumerate(fetched) if _entry_address(entry) == address), None)
    if hit is None:
        return fetched[:count]
    return fetched[max(0, hit - lines): hit + lines + 1]


def coverage(entries: Sequence[Mapping[str, Any]], *, requested: int) -> Dict[str, Any]:
    """Report where a listing actually starts and which bytes it skipped.

    Ghidra iterates defined instructions, so a request inside an undefined
    region answers with the next defined instruction and no marker.  The caller
    cannot tell that from a listing that starts where it asked, which is why
    this is computed rather than trusted: the addresses in the response are the
    evidence, and they are already here.

    Returns ``start`` (``None`` for an empty listing), ``skipped_bytes`` before
    it, and the interior ``gaps``, each as ``{start, end, bytes}`` covering the
    undefined bytes themselves.
    """

    start: int | None = None
    gaps: List[Dict[str, Any]] = []
    expected: int | None = None

    for entry in entries:
        address = _entry_address(entry)
        if address is None:
            continue
        if start is None:
            start = address
        elif expected is not None and address > expected:
            gaps.append({"start": expected, "end": address - 1, "bytes": address - expected})
        length = _entry_length(entry)
        # An unknown length breaks the chain rather than inventing a gap at the
        # next instruction.
        expected = address + length if length is not None else None

    skipped = max(0, start - requested) if start is not None else 0
    return {
        "start": start,
        "skipped_bytes": skipped,
        "gaps": gaps,
        "gap_bytes": sum(gap["bytes"] for gap in gaps),
    }


def coverage_fields(report: Mapping[str, Any], *, requested: int) -> Dict[str, Any]:
    """Render a coverage report as the response fields, addresses in hex.

    Both disassemble_at and disassemble_batch report this; formatting it once
    keeps the two from drifting apart.
    """

    start = report["start"]
    fields: Dict[str, Any] = {
        "requested_address": int_to_hex(requested),
        "start_address": None if start is None else int_to_hex(int(start)),
        "skipped_bytes": int(report["skipped_bytes"]),
    }
    gaps = report["gaps"]
    if gaps:
        fields["gaps"] = [
            {
                "start": int_to_hex(int(gap["start"])),
                "end": int_to_hex(int(gap["end"])),
                "bytes": int(gap["bytes"]),
            }
            for gap in gaps
        ]
    return fields


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
