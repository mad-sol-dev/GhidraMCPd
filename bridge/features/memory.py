"""Memory read helpers."""
import base64
from typing import Dict, Optional

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex
from ..utils.logging import increment_counter


def read_bytes(
    client: GhidraClient,
    *,
    address: int,
    length: int,
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
    
    return {
        "address": int_to_hex(address),
        "length": actual_length,
        "encoding": "base64",
        "data": data_b64,
    }


__all__ = ["read_bytes"]
