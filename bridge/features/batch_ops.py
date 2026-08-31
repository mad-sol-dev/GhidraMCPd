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
from . import method_notes
from .listing import (
    batch_to_text,
    compile_query,
    coverage,
    coverage_fields,
    filter_instructions,
    normalize_fmt,
    render_lines,
)
from .pagination import finalize_page


def disassemble_batch(
    client: GhidraClient,
    addresses: List[str],
    count: int = 16,
    fmt: str = "json",
    query: str = "",
    regex: bool = False,
    case_sensitive: bool = False,
    context_lines: int = 0,
) -> Dict[str, object]:
    """Disassemble instructions at multiple addresses in one call.
    
    Args:
        client: GhidraClient instance for communicating with Ghidra
        addresses: List of address strings (hex format) to disassemble
        count: Number of instructions to disassemble at each address
        fmt: "json" for instruction objects, "text" for rendered lines
        query: Keep only instructions matching this. Empty (default) returns
            everything, exactly as before.
        regex: Treat query as a regular expression rather than a literal
        case_sensitive: Match case
        context_lines: Instructions to keep either side of a match (0-16)

    Returns:
        Dictionary with keys:
        - addresses: Original list of address strings
        - count: Number of instructions per address
        - results: Dict mapping address strings to instruction lists (json) or
          to lists of rendered lines (text)
        - filter, summary: only when a query was given -- what was asked for,
          and how many instructions were scanned, matched and returned
    """
    enforce_batch_limit(len(addresses), counter="disassemble_batch.addresses")
    increment_counter("batch_ops.disassemble_batch")

    context_lines = max(0, min(int(context_lines), 16))
    pattern = (
        compile_query(query, regex=regex, case_sensitive=case_sensitive)
        if query
        else None
    )

    results: Dict[str, object] = {}
    coverage_report: Dict[str, object] = {}
    scanned = matched = returned = 0

    for addr_str in addresses:
        addr = parse_hex(addr_str)
        instructions = client.disassemble_at(addr, count)
        entries = instructions if instructions is not None else []
        scanned += len(entries)

        # Before the filter: what the filter removed is the caller's own doing,
        # what Ghidra never defined is not, and only the second belongs here.
        _record_coverage(coverage_report, entries, requested=addr, key=addr_str)

        if pattern is not None:
            entries, hits = filter_instructions(
                entries, pattern, context_lines=context_lines
            )
            matched += hits

        returned += len(entries)
        results[addr_str] = entries

    if normalize_fmt(fmt) == "text":
        results = batch_to_text(results)

    payload: Dict[str, object] = {
        "addresses": addresses,
        "count": count,
        "results": results,
    }

    # Only addresses whose listing lies about where it starts appear here.
    if coverage_report:
        payload["coverage"] = coverage_report
        payload["method_note"] = _batch_coverage_note(coverage_report)

    # Without a query the response is byte-for-byte what it always was.
    if pattern is not None:
        payload["filter"] = {
            "query": query,
            "regex": regex,
            "case_sensitive": case_sensitive,
            "context_lines": context_lines,
        }
        # What was dropped has to be visible, or a filtered listing reads like a
        # complete one.
        payload["summary"] = {
            "scanned": scanned,
            "matched": matched,
            "returned": returned,
        }

    return payload


def _record_coverage(
    report: Dict[str, object],
    entries: List[Dict[str, object]],
    *,
    requested: int,
    key: str,
) -> None:
    """Note one address's listing under ``key`` when it is not what it looks like."""

    found = coverage(entries, requested=requested)
    if found["start"] is not None and not found["skipped_bytes"] and not found["gaps"]:
        return
    report[key] = coverage_fields(found, requested=requested)


def _batch_coverage_note(report: Dict[str, object]) -> str:
    """One note for the batch, naming the addresses that need it."""

    empty = [
        key for key, entry in report.items()
        if isinstance(entry, dict) and entry.get("start_address") is None
    ]
    moved = [key for key in report if key not in empty]
    parts = []
    if moved:
        parts.append(
            "the listing for " + ", ".join(moved) + " does not cover every byte "
            "asked for: it starts past the address, has holes, or both"
        )
    if empty:
        parts.append(
            "no instructions are defined at or after " + ", ".join(empty)
        )
    return (
        "Blind spot: "
        + "; and ".join(parts)
        + ". Ghidra lists only bytes it has defined as instructions and skips "
        "the rest without a marker. See coverage for the addresses and byte "
        "counts. Instead: read those bytes as data with read_bytes or "
        "read_words, or define them as code in Ghidra and disassemble again."
    )


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

    unreadable = sum(1 for word in words if word is None)

    payload: Dict[str, object] = {
        "address": int_to_hex(address),
        "count": count,
        # Hex, not decimal.  These are register addresses and bit masks: 0xB1008000
        # is recognisable at a glance, 2969600000 has to be converted in the reader's
        # head, once per word, with nothing to check the result against.  It is not
        # shorter -- "0xb1008000" costs two characters more than 2969600000 -- but a
        # transcription error in hex is visible and in decimal is not.
        "words": [None if word is None else int_to_hex(word) for word in words],
    }
    if include_literals:
        payload["literals"] = literals

    # null is one character away from looking like zero, and a register that is
    # not mapped says nothing about the firmware while a register reading 0 does.
    if unreadable:
        payload["unreadable_words"] = unreadable
        payload["method_note"] = method_notes.unmapped_memory_note(
            address=int_to_hex(address),
            unreadable=unreadable,
            total=count,
        )

    return payload


def search_scalars_with_context(
    client: GhidraClient,
    value: int,
    context_lines: int = 4,
    limit: int = 20,
    fmt: str = "json",
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
        fmt: "json" for instruction objects under `disassembly`, "text" for
            rendered strings under `lines` (roughly half the bytes)
        
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
    text_mode = normalize_fmt(fmt) == "text"
    
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
        
        context_disasm = context_disasm if context_disasm is not None else []
        match: Dict[str, object] = {
            "address": addr_str,
            "value": int_to_hex(value),
            "function": item.get("function", ""),
            "context_text": item.get("context", ""),
        }
        if text_mode:
            match["lines"] = render_lines(context_disasm)
        else:
            match["disassembly"] = context_disasm
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

    method_notes.attach("search_scalars_with_context", response)
    finalize_page(response)

    return response
