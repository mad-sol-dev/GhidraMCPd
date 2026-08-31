"""Disassembly helpers."""
from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex
from ..utils.logging import increment_counter
from . import method_notes
from .listing import coverage, coverage_fields, normalize_fmt, to_text


def disassemble_at(
    client: GhidraClient,
    *,
    address: int,
    count: int,
    fmt: str = "json",
) -> Dict[str, object]:
    """
    Disassemble instructions starting at the given address.
    
    Args:
        client: Ghidra client instance
        address: Starting address
        count: Number of instructions to disassemble (capped at 128)
        fmt: "json" for an items array of objects, "text" for a lines array of
            rendered strings (roughly half the bytes)

    Returns:
        Dictionary with an items array (json) or a lines array (text). When the
        listing does not start at ``address`` or has holes, a ``coverage``
        object and a ``method_note`` say so -- see ``attach_coverage``.
    """
    increment_counter("disasm.disassemble_at.calls")
    
    # Hard cap count to 128
    count = min(count, 128)
    
    # Fetch disassembly from Ghidra
    raw_results = client.disassemble_at(address, count)
    
    # Build items list
    items: List[Dict[str, str]] = []
    for entry in raw_results:
        items.append({
            "address": entry.get("address", ""),
            "bytes": entry.get("bytes", ""),
            "text": entry.get("text", ""),
        })
    
    increment_counter("disasm.disassemble_at.instructions", len(items))
    
    payload: Dict[str, object] = {"items": items}
    attach_coverage(payload, items, requested=address)
    if normalize_fmt(fmt) == "text":
        to_text(payload)
    return payload


def attach_coverage(
    payload: Dict[str, object],
    items: List[Dict[str, str]],
    *,
    requested: int,
) -> Dict[str, object]:
    """Add ``coverage`` and ``method_note`` when the listing is not what it looks like.

    Silent on the ordinary case -- a listing that starts at the requested
    address and runs without holes carries neither key, so the common response
    keeps its current size.
    """

    report = coverage(items, requested=requested)
    start = report["start"]
    skipped = int(report["skipped_bytes"])
    gaps = report["gaps"]

    note = method_notes.listing_coverage_note(
        requested=int_to_hex(requested),
        start=None if start is None else int_to_hex(int(start)),
        skipped_bytes=skipped,
        gap_bytes=int(report["gap_bytes"]),
        gap_count=len(gaps),
    )
    if note is None:
        return payload

    increment_counter("disasm.disassemble_at.coverage_notes")
    payload["coverage"] = coverage_fields(report, requested=requested)
    payload["method_note"] = note
    return payload


__all__ = ["attach_coverage", "disassemble_at"]
