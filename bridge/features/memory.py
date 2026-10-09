"""Memory read helpers."""
import base64
from typing import Dict, Optional

from ..ghidra.client import GhidraClient
from . import method_notes
from ..utils.hex import int_to_hex
from ..utils.logging import increment_counter


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

    # An empty read and a run of zero bytes are different findings; base64 of
    # nothing does not say which one this is.
    if actual_length < length:
        payload["method_note"] = method_notes.unmapped_memory_note(
            address=int_to_hex(address),
            unreadable=length - actual_length,
            total=length,
            unit="bytes",
        )

    return payload


__all__ = ["read_bytes"]
