"""Where project_info's layout figures disagree with the memory map.

``image_base`` is Ghidra's value, not a guess -- but it need not be where the
image is.  The ZK-Inkjet app was imported as a raw binary with image base
0x00000000 and its one block, ``flash``, at 0x00200000; all 16 entry points
(the ARM vectors at 0x0 and 0xFFFF0000) lie where nothing is mapped.  Read
naively, the answer says the image starts at 0 and those entries are code
(IMAGE-BASE-STALE).  These notes say what the figures do not.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional, Sequence, Tuple

__all__ = ["layout_notes"]


def _int(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value.strip(), 16)
        except ValueError:
            return None
    return None


def _blocks(info: Mapping[str, Any]) -> List[Tuple[int, int, str]]:
    out = []
    for block in info.get("memory_blocks") or ():
        if not isinstance(block, Mapping):
            continue
        start, end = _int(block.get("start")), _int(block.get("end"))
        if start is not None and end is not None:
            out.append((start, end, str(block.get("name", ""))))
    return sorted(out)


def _ranges(values: Sequence[int]) -> str:
    """0x0,0x4,...,0x1c,0xffff0000,... -> '0x00000000-0x0000001c, 0xffff0000-0xffff001c'."""

    groups: List[List[int]] = []
    for value in sorted(values):
        if groups and value - groups[-1][-1] <= 4:
            groups[-1].append(value)
        else:
            groups.append([value])
    return ", ".join(
        f"0x{g[0]:08x}" if len(g) == 1 else f"0x{g[0]:08x}-0x{g[-1]:08x}" for g in groups
    )


def layout_notes(info: Mapping[str, Any]) -> List[str]:
    """Notes for each layout figure that lies outside every memory block."""

    blocks = _blocks(info)
    if not blocks:
        return []

    def mapped(address: int) -> bool:
        return any(start <= address <= end for start, end, _ in blocks)

    notes: List[str] = []
    base = _int(info.get("image_base"))
    if base is not None and not mapped(base):
        start, _end, name = blocks[0]
        notes.append(
            f"image_base 0x{base:08x} lies in no memory block; the lowest block, "
            f"{name or 'unnamed'}, starts at 0x{start:08x}. Addresses in this program are "
            "block addresses, not offsets from image_base."
        )
    entries = [e for e in (_int(v) for v in info.get("entry_points") or ()) if e is not None]
    outside = [e for e in entries if not mapped(e)]
    if outside:
        notes.append(
            f"{len(outside)} of {len(entries)} entry points lie in no memory block "
            f"({_ranges(outside)}); there are no bytes behind them in this program."
        )
    return notes
