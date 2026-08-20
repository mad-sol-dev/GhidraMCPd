"""Hex helpers shared across bridge features."""
from __future__ import annotations

from typing import Iterable


def int_to_hex(value: int) -> str:
    """Return a canonical hex string for addresses or values."""

    return f"0x{value:08x}" if value >= 0 else f"-0x{abs(value):08x}"


def parse_hex(value: str) -> int:
    """Parse a hex string into an integer."""

    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 16)


def normalize_symbol_address(raw: str) -> str:
    """Return a well-formed address for a symbol reported by the Ghidra plugin.

    The plugin renders every address as ``"0x" + address.toString()``.  For the
    default address space that is right; for a named space it is not, because
    Ghidra already renders those as ``SPACE:offset``.  An imported symbol on the
    reference firmware therefore arrives as ``0xEXTERNAL:00000001``, which is
    neither valid hex nor what Ghidra meant, and the response schema rejected
    it -- so ``search_imports`` failed outright on that program.

    Space-qualified addresses keep their qualifier and lose the bogus prefix;
    plain addresses gain the ``0x`` they may be missing.
    """

    address = raw.strip()
    if not address:
        return address

    body = address[2:] if address[:2].lower() == "0x" else address
    if ":" in body:
        # SPACE:offset -- a named address space, not a number.
        return body
    return f"0x{body}"


def slot_address(jt_base: int, slot_index: int) -> int:
    """Calculate the absolute address of a jump-table slot."""

    return jt_base + 4 * slot_index


def clamp_collection(items: Iterable, limit: int):
    """Yield items up to *limit* entries."""

    count = 0
    for item in items:
        if count >= limit:
            break
        count += 1
        yield item
