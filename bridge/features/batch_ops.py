"""Batch operations for efficient multi-address queries.

This module provides functions that perform multiple related operations
in a single call, reducing round-trip overhead when working with multiple
addresses or performing context-aware queries.
"""
from __future__ import annotations

import base64

from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex, parse_hex
from ..utils.logging import enforce_batch_limit, increment_counter
from . import scalars


def disassemble_batch(
    client: GhidraClient,
    addresses: List[str],
    count: int = 16,
) -> Dict[str, object]:
    """Disassemble instructions at multiple addresses in one call.
    
    Args:
        client: GhidraClient instance for communicating with Ghidra
        addresses: List of address strings (hex format) to disassemble
        count: Number of instructions to disassemble at each address
        
    Returns:
        Dictionary with keys:
        - addresses: Original list of address strings
        - count: Number of instructions per address
        - results: Dict mapping address strings to instruction lists
    """
    enforce_batch_limit(len(addresses), counter="disassemble_batch.addresses")
    increment_counter("batch_ops.disassemble_batch")
    
    results = {}
    for addr_str in addresses:
        addr = parse_hex(addr_str)
        instructions = client.disassemble_at(addr, count)
        results[addr_str] = instructions if instructions is not None else []
    
    return {
        "addresses": addresses,
        "count": count,
        "results": results,
    }


def read_words(
    client: GhidraClient,
    address: int,
    count: int = 1,
    *,
    include_literals: bool = False,
) -> Dict[str, object]:
    """Read multiple 32-bit words from memory starting at an address.
    
    Args:
        client: GhidraClient instance for communicating with Ghidra
        address: Starting address to read from
        count: Number of 32-bit words to read
        
    Returns:
        Dictionary with keys:
        - address: Starting address as hex string
        - count: Number of words requested
        - words: List of integers (little-endian) or None for failed reads
    """
    enforce_batch_limit(count, counter="read_words.count")
    increment_counter("batch_ops.read_words")
    
    words = []
    literals: List[str | None] = []
    for i in range(count):
        current_addr = address + i * 4
        data = client.read_bytes(current_addr, 4)
        if data is not None and len(data) == 4:
            # Convert 4 bytes to little-endian integer
            word = int.from_bytes(data, byteorder='little', signed=False)
            words.append(word)
            if include_literals:
                literals.append(base64.b64encode(data).decode("ascii"))
        else:
            words.append(None)
            if include_literals:
                literals.append(None)

    payload: Dict[str, object] = {
        "address": int_to_hex(address),
        "count": count,
        "words": words,
    }
    if include_literals:
        payload["literals"] = literals

    return payload


def search_scalars_with_context(
    client: GhidraClient,
    value: int,
    context_lines: int = 4,
    limit: int = 100,
) -> Dict[str, object]:
    """Search for scalar values and include surrounding disassembly context.
    
    This function searches for scalar value references in the binary and
    provides disassembly context around each match for better understanding
    of how the value is used.
    
    Args:
        client: GhidraClient instance for communicating with Ghidra
        value: Scalar value to search for
        context_lines: Number of instructions before/after to include
        limit: Maximum number of results to return
        
    Returns:
        Dictionary with keys:
        - value: Search value as hex string
        - total: Total number of matches found (if known)
        - has_more: Whether additional pages of matches are available
        - resume_cursor: Cursor token for fetching the next page (if provided)
        - matches: List of match dicts, each containing:
            - address: Match address as hex string
            - value: Value as hex string
            - function: Function name containing the match
            - context_text: Text description of the context
            - disassembly: List of surrounding instructions
    """
    enforce_batch_limit(limit, counter="search_scalars_with_context.limit")
    increment_counter("batch_ops.search_scalars_with_context")
    
    # Get scalar search results
    results = scalars.search_scalars(
        client,
        value=value,
        query=int_to_hex(value),
        limit=limit,
        page=1,
    )
    
    matches = []
    items = results.get("items", [])
    for item in items[:limit]:
        addr_str = item.get("address", "0x0")
        addr = parse_hex(addr_str)
        
        # Calculate context window
        context_start = max(0, addr - context_lines * 4)
        context_count = context_lines * 2 + 1
        
        # Get disassembly context
        context_disasm = client.disassemble_at(context_start, context_count)
        
        match = {
            "address": addr_str,
            "value": int_to_hex(value),
            "function": item.get("function", ""),
            "context_text": item.get("context", ""),
            "disassembly": context_disasm if context_disasm is not None else [],
        }
        matches.append(match)
    
    total = results.get("total")
    has_more = bool(results.get("has_more", False))
    if total is None and not has_more:
        total = len(matches)

    resume_cursor = results.get("resume_cursor") or results.get("cursor")
    if isinstance(resume_cursor, str) and not resume_cursor:
        resume_cursor = None

    response: Dict[str, object] = {
        "value": int_to_hex(value),
        "total": total,
        "has_more": has_more,
        "matches": matches,
    }
    if resume_cursor is not None:
        response["resume_cursor"] = resume_cursor

    return response
