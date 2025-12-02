"""Text search within function disassembly and decompilation."""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Pattern, Sequence

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex
from ..utils.logging import enforce_batch_limit, increment_counter


def find_in_function(
    client: GhidraClient,
    *,
    address: int,
    query: str,
    mode: str = "both",
    regex: bool = False,
    case_sensitive: bool = False,
    context_lines: int = 3,
    limit: int = 50,
) -> Dict[str, object]:
    """Search for text patterns within a function's disassembly or decompilation.

    Args:
        client: GhidraClient instance
        address: Function address (integer)
        query: Search string or regex pattern
        mode: Search in "disasm", "decompile", or "both"
        regex: Treat query as regex pattern
        case_sensitive: Perform case-sensitive search
        context_lines: Number of lines to include before/after match (0-16)
        limit: Maximum number of matches to return per mode (1-200)

    Returns:
        Dictionary with matches from disassembly and/or decompilation
    """
    if mode not in ("disasm", "decompile", "both"):
        raise ValueError("mode must be 'disasm', 'decompile', or 'both'")

    if not query:
        raise ValueError("query cannot be empty")

    # Clamp parameters
    context_lines = max(0, min(context_lines, 16))
    limit = max(1, min(limit, 200))

    enforce_batch_limit(limit, counter="search_function.limit")
    increment_counter("search_function.find_in_function")

    # Compile search pattern
    pattern = _compile_pattern(query, regex=regex, case_sensitive=case_sensitive)

    matches: Dict[str, List[Dict[str, object]]] = {
        "disassembly": [],
        "decompile": [],
    }

    # Search in disassembly
    if mode in ("disasm", "both"):
        disasm_raw = client.disassemble_function(address)
        if disasm_raw:
            matches["disassembly"] = _search_disassembly(
                disasm_raw, pattern, context_lines, limit
            )

    # Search in decompilation
    if mode in ("decompile", "both"):
        decompile_text = client.decompile_function(address)
        if decompile_text and decompile_text.strip():
            matches["decompile"] = _search_text_lines(
                decompile_text.splitlines(),
                pattern,
                context_lines,
                limit,
            )

    total = len(matches["disassembly"]) + len(matches["decompile"])
    truncated = (
        len(matches["disassembly"]) >= limit or
        len(matches["decompile"]) >= limit
    )

    return {
        "address": int_to_hex(address),
        "query": query,
        "mode": mode,
        "regex": regex,
        "case_sensitive": case_sensitive,
        "matches": matches,
        "summary": {
            "total_matches": total,
            "disassembly_matches": len(matches["disassembly"]),
            "decompile_matches": len(matches["decompile"]),
            "truncated": truncated,
        },
    }


def _compile_pattern(query: str, *, regex: bool, case_sensitive: bool) -> Pattern[str]:
    """Compile search query into regex pattern."""
    if regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.compile(query, flags)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}")
    else:
        # Escape special regex characters for literal search
        escaped = re.escape(query)
        flags = 0 if case_sensitive else re.IGNORECASE
        return re.compile(escaped, flags)


def _search_disassembly(
    lines: Sequence[str],
    pattern: Pattern[str],
    context_lines: int,
    limit: int,
) -> List[Dict[str, object]]:
    """Search within disassembly output, parsing address information."""
    matches: List[Dict[str, object]] = []

    for line_num, raw_line in enumerate(lines, start=1):
        if len(matches) >= limit:
            break

        line = raw_line.strip()
        if not line or ":" not in line:
            continue

        # Check if pattern matches
        if not pattern.search(line):
            continue

        # Parse address from disassembly line (format: "0x401000: bytes  instruction")
        addr_str: Optional[str] = None
        head, _, rest = line.partition(":")
        head_clean = head.strip()
        if head_clean and (head_clean.startswith("0x") or head_clean.isdigit()):
            addr_str = head_clean

        # Extract context
        context = _extract_context(lines, line_num - 1, context_lines)

        matches.append({
            "line_number": line_num,
            "address": addr_str,
            "matched_text": line,
            "context": context,
        })

    return matches


def _search_text_lines(
    lines: Sequence[str],
    pattern: Pattern[str],
    context_lines: int,
    limit: int,
) -> List[Dict[str, object]]:
    """Search within plain text lines (e.g., decompiled source)."""
    matches: List[Dict[str, object]] = []

    for line_num, line in enumerate(lines, start=1):
        if len(matches) >= limit:
            break

        if not pattern.search(line):
            continue

        context = _extract_context(lines, line_num - 1, context_lines)

        matches.append({
            "line_number": line_num,
            "matched_text": line.rstrip(),
            "context": context,
        })

    return matches


def _extract_context(
    lines: Sequence[str],
    match_index: int,
    context_lines: int,
) -> Dict[str, object]:
    """Extract context lines before and after a match."""
    start = max(0, match_index - context_lines)
    end = min(len(lines), match_index + context_lines + 1)

    before = [lines[i].rstrip() for i in range(start, match_index)]
    match_line = lines[match_index].rstrip() if match_index < len(lines) else ""
    after = [lines[i].rstrip() for i in range(match_index + 1, end)]

    return {
        "before": before,
        "match": match_line,
        "after": after,
    }


__all__ = ["find_in_function"]
