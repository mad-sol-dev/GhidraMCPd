"""Memory read/write helpers."""
import base64
import binascii
from typing import Dict, List, Optional

from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils import audit
from ..utils.hex import int_to_hex
from ..utils.logging import increment_counter, record_write_attempt


_NOTE_DRY_RUN = "dry-run enabled: no bytes written"
_NOTE_WRITES_DISABLED = "writes disabled (set GHIDRA_MCP_ENABLE_WRITES=1 to enable)"


def read_bytes(
    client: GhidraClient,
    *,
    address: int,
    length: int,
    include_literals: bool = False,
) -> Dict[str, object]:
    """
    Read raw bytes from memory.
    
    Args:
        client: Ghidra client instance
        address: Starting address
        length: Number of bytes to read (capped at 4096)
        
    Returns:
        Dictionary with address, length, encoding, and base64-encoded data
    """
    increment_counter("memory.read_bytes.calls")
    
    # Hard cap length to 4096
    length = min(length, 4096)
    
    # Fetch bytes from Ghidra
    raw_bytes: Optional[bytes] = client.read_bytes(address, length)
    
    if raw_bytes is None:
        data_b64 = ""
        actual_length = 0
    else:
        data_b64 = base64.b64encode(raw_bytes).decode("ascii")
        actual_length = len(raw_bytes)
    
    increment_counter("memory.read_bytes.bytes", actual_length)
    
    payload: Dict[str, object] = {
        "address": int_to_hex(address),
        "length": actual_length,
        "encoding": "base64",
        "data": data_b64,
    }

    if include_literals:
        literal = "" if raw_bytes is None else raw_bytes.decode("latin1")
        payload["literal"] = literal

    return payload


def write_bytes(
    client: GhidraClient,
    *,
    address: int,
    data: str,
    encoding: str = "base64",
    dry_run: bool = True,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    """Write raw bytes to memory with guard rails."""

    increment_counter("memory.write_bytes.calls")

    normalized_encoding = str(encoding).strip().lower()
    if normalized_encoding != "base64":
        raise ValueError("encoding must be 'base64'")

    try:
        decoded = base64.b64decode(str(data), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("data must be valid base64") from exc

    if not decoded:
        raise ValueError("decoded payload is empty")

    length = len(decoded)
    increment_counter("memory.write_bytes.bytes", length)

    notes: List[str] = []
    errors: List[str] = []
    written = False

    if dry_run:
        notes.append(_NOTE_DRY_RUN)

    if not writes_enabled:
        notes.append(_NOTE_WRITES_DISABLED)
        if not dry_run:
            errors.append("WRITE_DISABLED")

    if not dry_run and writes_enabled:
        record_write_attempt()
        if client.write_bytes(address, decoded):
            written = True
        else:
            errors.append("WRITE_FAILED")

    payload = {
        "address": int_to_hex(address),
        "length": length,
        "dry_run": bool(dry_run),
        "written": written,
        "notes": notes,
        "errors": errors,
    }

    audit.record_write_event(
        category="memory.write_bytes",
        parameters={
            "address": int_to_hex(address),
            "encoding": normalized_encoding,
            "length": length,
            "data": str(data),
        },
        dry_run=dry_run,
        writes_enabled=writes_enabled,
        result={
            "written": written,
            "errors": list(errors),
            "notes": list(notes),
        },
    )

    return payload


__all__ = ["read_bytes", "write_bytes"]
