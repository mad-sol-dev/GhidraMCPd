"""MMIO annotation helpers."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, Iterable, List, Optional

from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.hex import int_to_hex
from ..utils.logging import enforce_batch_limit, increment_counter, record_write_attempt


_ADDRESS_RE = re.compile(r"^\s*([0-9A-Fa-f]+):\s*(.+?)\s*$")
_LITERAL_IMMEDIATE_RE = re.compile(r"=\s*(-?0x[0-9a-fA-F]+)")
_BRACKET_IMMEDIATE_RE = re.compile(r"\[[^\]]*#\s*(-?0x[0-9a-fA-F]+)")
_HASH_IMMEDIATE_RE = re.compile(r"#\s*(-?0x[0-9a-fA-F]+)")
_DATA_VALUE_RE = re.compile(r"^(?:\.word|DCD|DCW|DCB)?\s*(-?0x[0-9A-Fa-f]+)\s*$", re.IGNORECASE)
_REGISTER_RE = re.compile(r"^(R\d+|SP|LR|PC)$", re.IGNORECASE)
_BRACKET_BASE_RE = re.compile(
    r"\[\s*(R\d+|SP|LR|PC)\s*(?:,\s*#\s*(-?0x[0-9A-Fa-f]+))?\s*\]",
    re.IGNORECASE,
)
_ADD_IMMEDIATE_RE = re.compile(
    r"^\s*(R\d+|SP|LR|PC)\s*,\s*(R\d+|SP|LR|PC)\s*,\s*#\s*(-?0x[0-9A-Fa-f]+)\s*$",
    re.IGNORECASE,
)
_ARM_CONDITION_CODES = {
    "EQ",
    "NE",
    "CS",
    "HS",
    "CC",
    "LO",
    "MI",
    "PL",
    "VS",
    "VC",
    "HI",
    "LS",
    "GE",
    "LT",
    "GT",
    "LE",
    "AL",
}


@dataclass(slots=True)
class _Operation:
    addr: int
    op: str
    target: Optional[int]

    def to_sample(self) -> Dict[str, str]:
        # address_abs is the absolute address: target if available, otherwise addr
        address_abs = self.target if (self.target is not None and self.target != 0) else self.addr
        return {
            "addr": int_to_hex(self.addr),
            "op": self.op,
            "target": int_to_hex(self.target) if self.target is not None else "0x00000000",
            "address_abs": int_to_hex(address_abs),
        }


def _parse_line(line: str) -> Optional[tuple[int, str, str]]:
    match = _ADDRESS_RE.match(line)
    if not match:
        return None
    try:
        addr = int(match.group(1), 16)
    except ValueError:
        return None
    instruction = match.group(2).strip()
    if not instruction:
        return None
    parts = instruction.split(None, 1)
    mnemonic = parts[0].upper()
    operands = parts[1] if len(parts) > 1 else ""
    if "." in mnemonic:
        mnemonic = mnemonic.split(".", 1)[0]
    return addr, mnemonic, operands


def _parse_data_line(line: str) -> Optional[tuple[int, int]]:
    match = _ADDRESS_RE.match(line)
    if not match:
        return None
    try:
        addr = int(match.group(1), 16)
    except ValueError:
        return None
    body = match.group(2).strip()
    if not body:
        return None
    data_match = _DATA_VALUE_RE.match(body)
    if not data_match:
        return None
    try:
        value = int(data_match.group(1), 16)
    except ValueError:
        return None
    return addr, value


def _is_base_load_store(mnemonic: str, base: str) -> bool:
    if not mnemonic.startswith(base):
        return False
    suffix = mnemonic[len(base) :]
    if not suffix:
        return True
    return suffix in _ARM_CONDITION_CODES


def _classify(mnemonic: str) -> Optional[str]:
    if _is_base_load_store(mnemonic, "LDR"):
        return "READ"
    if _is_base_load_store(mnemonic, "STR"):
        return "WRITE"
    if mnemonic.startswith("ORR") or mnemonic == "OR" or mnemonic.startswith("ORI"):
        return "OR"
    if mnemonic.startswith("AND") or mnemonic.startswith("BIC"):
        return "AND"
    if mnemonic.startswith("EOR") or mnemonic.startswith("XOR"):
        return "TOGGLE"
    return None


def _extract_target(operands: str) -> Optional[int]:
    literal = _LITERAL_IMMEDIATE_RE.search(operands)
    if literal:
        try:
            return int(literal.group(1), 16)
        except ValueError:
            return None
    bracket = _BRACKET_IMMEDIATE_RE.search(operands)
    if bracket:
        try:
            return int(bracket.group(1), 16)
        except ValueError:
            return None
    hash_match = _HASH_IMMEDIATE_RE.search(operands)
    if hash_match:
        try:
            return int(hash_match.group(1), 16)
        except ValueError:
            return None
    return None


def _normalize_register(register: str) -> Optional[str]:
    match = _REGISTER_RE.match(register.strip())
    if not match:
        return None
    return match.group(1).upper()


def _extract_dest_register(operands: str) -> Optional[str]:
    if not operands:
        return None
    dest = operands.split(",", 1)[0]
    return _normalize_register(dest)


def _extract_literal_load_value(
    operands: str, *, addr: int, memory_literals: Dict[int, int]
) -> Optional[int]:
    literal = _LITERAL_IMMEDIATE_RE.search(operands)
    if literal:
        try:
            return int(literal.group(1), 16)
        except ValueError:
            return None
    bracket = _BRACKET_BASE_RE.search(operands)
    if bracket:
        base = _normalize_register(bracket.group(1))
        if base == "PC":
            try:
                offset = int(bracket.group(2), 16) if bracket.group(2) else 0
            except ValueError:
                return None
            literal_addr = addr + 8 + offset
            return memory_literals.get(literal_addr)
    return None


def _resolve_register_indirect_address(
    operands: str, register_bases: Dict[str, int]
) -> Optional[int]:
    bracket = _BRACKET_BASE_RE.search(operands)
    if not bracket:
        return None
    base = _normalize_register(bracket.group(1))
    if base is None or base not in register_bases:
        return None
    try:
        offset = int(bracket.group(2), 16) if bracket.group(2) else 0
    except ValueError:
        return None
    return register_bases[base] + offset


def _collect_operations(disassembly: Iterable[str]) -> tuple[List[_Operation], int]:
    operations: List[_Operation] = []
    skipped = 0
    lines = list(disassembly)
    memory_literals: Dict[int, int] = {}
    for line in lines:
        data_line = _parse_data_line(line)
        if data_line:
            addr, value = data_line
            memory_literals[addr] = value
    register_bases: Dict[str, int] = {}
    for line in lines:
        if _parse_data_line(line):
            continue
        parsed = _parse_line(line)
        if not parsed:
            continue
        addr, mnemonic, operands = parsed
        literal_load_value = None
        if _is_base_load_store(mnemonic, "LDR"):
            dest_register = _extract_dest_register(operands)
            literal_load_value = _extract_literal_load_value(
                operands, addr=addr, memory_literals=memory_literals
            )
            if dest_register and literal_load_value is not None:
                register_bases[dest_register] = literal_load_value
            elif dest_register:
                indirect_address = _resolve_register_indirect_address(operands, register_bases)
                if indirect_address is not None and indirect_address in memory_literals:
                    register_bases[dest_register] = memory_literals[indirect_address]
        if mnemonic.startswith("ADD"):
            add_match = _ADD_IMMEDIATE_RE.match(operands)
            if add_match:
                dest_register = _normalize_register(add_match.group(1))
                src_register = _normalize_register(add_match.group(2))
                if dest_register and src_register and src_register in register_bases:
                    try:
                        offset = int(add_match.group(3), 16)
                    except ValueError:
                        offset = None
                    if offset is not None:
                        register_bases[dest_register] = register_bases[src_register] + offset
        op = _classify(mnemonic)
        if not op:
            continue
        target = None
        if op in {"READ", "WRITE"}:
            if op == "READ" and literal_load_value is not None:
                target = literal_load_value
            else:
                resolved_address = _resolve_register_indirect_address(operands, register_bases)
                if resolved_address is not None:
                    if op == "READ" and resolved_address in memory_literals:
                        target = memory_literals[resolved_address]
                    else:
                        target = resolved_address
            if target is None:
                target = _extract_target(operands)
            if target is None:
                # Skip load/store instructions that do not reference an immediate
                # address or a known base register.
                skipped += 1
                increment_counter("mmio.operations.skipped_no_target")
                continue
        else:
            target = _extract_target(operands)
        operations.append(_Operation(addr=addr, op=op, target=target))
    return operations, skipped


_NOTE_WRITES_DISABLED = "writes disabled: annotations were not applied"
_NOTE_DRY_RUN = "dry-run requested: annotations were not applied"
_NOTE_SKIPPED_INDIRECT = (
    "skipped register-indirect MMIO accesses; no immediate targets found."
)


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
    disassembly = client.disassemble_function(function_addr)
    operations, skipped = _collect_operations(disassembly)

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
    if reads + writes == 0 and skipped > 0:
        notes.append(_NOTE_SKIPPED_INDIRECT)
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
        "samples": samples,
        "notes": notes,
    }


def _format_comment(operation: _Operation) -> str:
    target = int_to_hex(operation.target) if operation.target is not None else "0x00000000"
    if operation.op == "READ":
        action = "read"
    elif operation.op == "WRITE":
        action = "write"
    elif operation.op == "OR":
        action = "bitwise OR"
    elif operation.op == "AND":
        action = "bitwise AND"
    else:
        action = "toggle"
    return f"MMIO {action} target {target}"


__all__ = ["annotate", "WritesDisabledError"]
