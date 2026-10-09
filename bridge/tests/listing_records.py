"""Builders for the plugin's structured listing (``fmt=json``) in test stubs."""
from __future__ import annotations

from typing import Dict, List, Optional


def insn(
    address: int,
    mnemonic: str,
    *,
    registers: tuple[str, ...] = ("r0",),
    imm: Optional[int] = None,
    ref: Optional[tuple[int, str, bool]] = None,
    text: Optional[str] = None,
    flow: str = "fallthrough",
) -> Dict[str, object]:
    """One instruction record: a register operand, optionally a bare immediate
    and one reference ``(to, type, mapped)``."""

    operands: List[Dict[str, object]] = [{"registers": list(registers)}]
    if imm is not None:
        operands.append({"scalars": [f"0x{imm:x}"]})
    refs = []
    if ref is not None:
        to, kind, mapped = ref
        refs.append({"to": f"0x{to:08x}", "type": kind, "op": 1, "mapped": mapped})
    return {
        "address": f"0x{address:08x}",
        "bytes": "",
        "mnemonic": mnemonic,
        "text": text if text is not None else mnemonic,
        "flow": flow,
        "operands": operands,
        "refs": refs,
    }


def listing(address: int, instructions: List[Dict[str, object]]) -> Dict[str, object]:
    return {"function": f"0x{address:08x}", "instructions": instructions}


#: Accesses through registers with no known base: two unplaceable load/stores,
#: then OR/AND/TOGGLE on immediates and a register move.
UNPLACED_0x7000 = [
    insn(0x7000, "ldr", registers=("r0", "r1")),
    insn(0x7004, "str", registers=("r2", "r3")),
    insn(0x7008, "orr", registers=("r4", "r4"), imm=0x2),
    insn(0x700C, "and", registers=("r5", "r5"), imm=0xFFFFFFFD),
    insn(0x7010, "eor", registers=("r6", "r6"), imm=0x1),
    insn(0x7014, "mov", registers=("r7", "r7")),
]
