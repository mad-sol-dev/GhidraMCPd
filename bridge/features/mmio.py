"""MMIO annotation helpers."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Mapping, Optional

from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.hex import int_to_hex
from .listing import ListingUnavailable, structured_listing
from ..utils.logging import enforce_batch_limit, increment_counter, record_write_attempt


#: Load/store mnemonics, conditional and width suffixes included (ldrb, strneh,
#: ldrsb ...).  This reads the mnemonic, never the operand text.
_LOAD_STORE_RE = re.compile(r"^(ldr|str)", re.IGNORECASE)
_BITWISE_OPS = (("orr", "OR"), ("and", "AND"), ("bic", "AND"), ("eor", "TOGGLE"))
_DATA_REF_TYPES = {"READ": "READ", "WRITE": "WRITE"}


@dataclass(slots=True)
class _Operation:
    addr: int
    op: str
    target: Optional[int]

    def to_sample(self) -> Dict[str, Optional[str]]:
        """One sample line.

        For READ/WRITE ``target`` is the address accessed, repeated as
        ``address_abs``.  For OR/AND/TOGGLE it is the mask value, or None when
        the operand is a register (``and r0,r0,r1``); there is no address, so
        no ``address_abs``.  Both used to be filled regardless: a missing value
        came out as 0x00000000 -- "AND with zero" -- and address_abs fell back
        to the instruction address, or carried the mask as if it were one.
        """

        sample: Dict[str, Optional[str]] = {
            "addr": int_to_hex(self.addr),
            "op": self.op,
            "target": int_to_hex(self.target) if self.target is not None else None,
        }
        if self.op in ("READ", "WRITE") and self.target is not None:
            sample["address_abs"] = int_to_hex(self.target)
        return sample


def _bitwise_op(mnemonic: str) -> Optional[str]:
    for prefix, op in _BITWISE_OPS:
        if mnemonic.startswith(prefix):
            return op
    return None


def _immediate(instruction: Mapping[str, object]) -> Optional[int]:
    """The value of an operand that is a bare immediate.

    An operand that also names a register -- ``r6, lsl #0xc`` -- carries a
    shift amount, not a value, and yields nothing.
    """

    for operand in instruction.get("operands") or ():
        if not isinstance(operand, Mapping) or operand.get("registers"):
            continue
        scalars = operand.get("scalars") or ()
        if len(scalars) == 1:
            try:
                return int(str(scalars[0]), 16) & 0xFFFFFFFF
            except ValueError:
                return None
    return None


def _is_stack_access(instruction: Mapping[str, object]) -> bool:
    return any(
        "sp" in (operand.get("registers") or ())
        for operand in instruction.get("operands") or ()
        if isinstance(operand, Mapping)
    )


def _collect_operations(
    instructions: Iterable[Mapping[str, object]],
) -> tuple[List[_Operation], int]:
    """Classify a function's instructions from the plugin's structured listing.

    Addresses come from Ghidra's references, not from reassembling operand
    text.  Ghidra's constant propagation places a reference on the load or
    store itself, also when the target lies outside every memory block --
    measured on 0x002AF9C0, where it resolves ``ldr r0,[0x2afb40]`` /
    ``ldr r0,[r0,#0x0]`` to 0xB1008704.  The text classifier this replaces
    kept the base from an earlier ``mov r0,#0xb0000000`` and reported
    0xB0000000, five times in that one function.

    * A load/store with a READ or WRITE reference outside the image is an
      operation, at that address: peripherals, and RAM the image does not map.
    * One whose only reference points into the image -- a constant-pool or
      global load -- is resolved and is not I/O; it is neither an operation
      nor skipped.
    * A stack access is neither.
    * Anything else Ghidra could not place counts as skipped.
    * OR/AND/TOGGLE come from the mnemonic, with the bare immediate if any.
    """

    operations: List[_Operation] = []
    skipped = 0
    for instruction in instructions:
        if not isinstance(instruction, Mapping):
            continue
        try:
            addr = int(str(instruction.get("address")), 16)
        except ValueError:
            continue
        mnemonic = str(instruction.get("mnemonic") or "").lower()

        if _LOAD_STORE_RE.match(mnemonic):
            memory_refs = [
                ref
                for ref in instruction.get("refs") or ()
                if isinstance(ref, Mapping)
                and ref.get("type") in _DATA_REF_TYPES
                and "space" not in ref  # stack and register refs live in other spaces
            ]
            outside = [ref for ref in memory_refs if not ref.get("mapped")]
            if outside:
                ref = outside[0]
                operations.append(
                    _Operation(
                        addr=addr,
                        op=_DATA_REF_TYPES[str(ref["type"])],
                        target=int(str(ref["to"]), 16),
                    )
                )
            elif memory_refs or _is_stack_access(instruction):
                continue
            else:
                skipped += 1
                increment_counter("mmio.operations.skipped_no_target")
            continue

        op = _bitwise_op(mnemonic)
        if op:
            operations.append(_Operation(addr=addr, op=op, target=_immediate(instruction)))
    return operations, skipped


_NOTE_WRITES_DISABLED = "writes disabled: annotations were not applied"
_NOTE_DRY_RUN = "dry-run requested: annotations were not applied"


class WritesDisabledError(RuntimeError):
    """Retained for backwards compatibility (no longer raised)."""


def annotate(
    client: GhidraClient,
    *,
    function_addr: int,
    dry_run: bool = True,
    max_samples: int = 8,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    increment_counter("mmio.annotate.calls")

    enforce_batch_limit(max_samples, counter="mmio.max_samples")
    listing = structured_listing(client, function_addr)
    operations, skipped = _collect_operations(listing["instructions"])

    reads = sum(1 for op in operations if op.op == "READ")
    writes = sum(1 for op in operations if op.op == "WRITE")
    bitwise_or = sum(1 for op in operations if op.op == "OR")
    bitwise_and = sum(1 for op in operations if op.op == "AND")
    toggles = sum(1 for op in operations if op.op == "TOGGLE")

    samples = [op.to_sample() for op in operations[:max_samples]]
    increment_counter("mmio.operations.total", len(operations))
    increment_counter("mmio.samples.returned", len(samples))

    notes: List[str] = []
    annotated = 0
    if dry_run:
        notes.append(_NOTE_DRY_RUN)
    if not writes_enabled:
        notes.append(_NOTE_WRITES_DISABLED)
    if skipped > 0:
        notes.append(
            f"{skipped} load/store instruction(s) could not be placed: Ghidra "
            "holds no reference for them and they are not stack accesses. They "
            "are not counted above."
        )
    if not dry_run and writes_enabled and samples:
        for op in operations[:max_samples]:
            comment = _format_comment(op)
            record_write_attempt()
            if client.set_disassembly_comment(op.addr, comment):
                annotated += 1

    return {
        "function": int_to_hex(function_addr),
        "reads": reads,
        "writes": writes,
        "bitwise_or": bitwise_or,
        "bitwise_and": bitwise_and,
        "toggles": toggles,
        "annotated": annotated,
        # What the classifier could not resolve.  Counted since 0d45e14 but
        # never reported, and until the base-register fix it stayed near zero
        # because the offset fallback swallowed these cases as if they were
        # hits.  A load/store this tool cannot place has to be visible, or the
        # counts above read as a complete picture of the function.
        "skipped": skipped,
        "samples": samples,
        "notes": notes,
    }


def _format_comment(operation: _Operation) -> str:
    action = {
        "READ": "read",
        "WRITE": "write",
        "OR": "bitwise OR",
        "AND": "bitwise AND",
    }.get(operation.op, "toggle")
    if operation.target is None:
        # A register operand: there is no value to name, and "0x00000000"
        # would claim one.
        return f"MMIO {action}"
    return f"MMIO {action} target {int_to_hex(operation.target)}"


__all__ = ["annotate", "WritesDisabledError"]
