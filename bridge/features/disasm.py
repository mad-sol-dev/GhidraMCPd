"""Disassembly helpers."""
from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex
from ..utils.logging import increment_counter
from .listing import normalize_fmt, to_text


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
        Dictionary with an items array (json) or a lines array (text)
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
    if normalize_fmt(fmt) == "text":
        to_text(payload)
    return payload


__all__ = ["disassemble_at"]
