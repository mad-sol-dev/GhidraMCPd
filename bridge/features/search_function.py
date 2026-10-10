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
    limit: int = 20,
    fmt: str = "json",
) -> Dict[str, object]:
    """Search for text patterns within a function's disassembly or decompilation.

    ``fmt="json"`` returns one object per match with its own context.
    ``fmt="text"`` returns, per mode, the matching lines with their context as
    plain lines; overlapping windows merge, and ``--`` separates windows that
    do not touch.  The JSON form repeats each match line twice and every shared
    context line once per neighbouring match -- 6364 bytes for 'ldr' in
    0x002AF9C0 at the defaults.

    ``summary.truncated`` is true only when matches were left out, and
    ``*_found`` counts all of them.  It used to be true whenever exactly
    ``limit`` matches existed.
    """

    if mode not in ("disasm", "decompile", "both"):
        raise ValueError("mode must be 'disasm', 'decompile', or 'both'")
    if not query:
        raise ValueError("query cannot be empty")
    if fmt not in ("json", "text"):
        raise ValueError("fmt must be 'json' or 'text'")

    context_lines = max(0, min(context_lines, 16))
    limit = max(1, min(limit, 200))
    enforce_batch_limit(limit, counter="search_function.limit")
    increment_counter("search_function.find_in_function")

    pattern = _compile_pattern(query, regex=regex, case_sensitive=case_sensitive)

    sources: Dict[str, List[str]] = {"disassembly": [], "decompile": []}
    if mode in ("disasm", "both"):
        raw = client.disassemble_function(address) or []
        sources["disassembly"] = [line.strip() for line in raw if line.strip() and ":" in line]
    if mode in ("decompile", "both"):
        text = client.decompile_function(address)
        if text and text.strip():
            sources["decompile"] = [line.rstrip() for line in text.splitlines()]

    found: Dict[str, List[int]] = {
        key: [i for i, line in enumerate(lines) if pattern.search(line)]
        for key, lines in sources.items()
    }
    kept = {key: indices[:limit] for key, indices in found.items()}

    result: Dict[str, object] = {
        "address": int_to_hex(address),
        "query": query,
        "mode": mode,
        "regex": regex,
        "case_sensitive": case_sensitive,
    }
    if fmt == "text":
        result["fmt"] = "text"
        result["lines"] = {
            key: _merged_windows(sources[key], kept[key], context_lines) for key in sources
        }
    else:
        result["matches"] = {
            "disassembly": [
                _disassembly_match(sources["disassembly"], i, context_lines)
                for i in kept["disassembly"]
            ],
            "decompile": [
                {
                    "line_number": i + 1,
                    "matched_text": sources["decompile"][i],
                    "context": _extract_context(sources["decompile"], i, context_lines),
                }
                for i in kept["decompile"]
            ],
        }
    result["summary"] = {
        "total_matches": len(kept["disassembly"]) + len(kept["decompile"]),
        "disassembly_matches": len(kept["disassembly"]),
        "decompile_matches": len(kept["decompile"]),
        "disassembly_found": len(found["disassembly"]),
        "decompile_found": len(found["decompile"]),
        "truncated": any(len(found[k]) > len(kept[k]) for k in found),
    }
    return result


def _merged_windows(lines: Sequence[str], indices: Sequence[int], context_lines: int) -> List[str]:
    keep: set[int] = set()
    for index in indices:
        keep.update(range(max(0, index - context_lines), min(len(lines), index + context_lines + 1)))
    out: List[str] = []
    previous: Optional[int] = None
    for index in sorted(keep):
        if previous is not None and index != previous + 1:
            out.append("--")
        out.append(lines[index])
        previous = index
    return out


def _disassembly_match(lines: Sequence[str], index: int, context_lines: int) -> Dict[str, object]:
    line = lines[index]
    head = line.partition(":")[0].strip()
    try:
        # "002af9dc: ldr ..." -- the address is bare hex.  The old parse took
        # only "0x..." or all-digit heads, so it was null on almost every line.
        address: Optional[str] = int_to_hex(int(head, 16))
    except ValueError:
        address = None
    return {
        "line_number": index + 1,
        "address": address,
        "matched_text": line,
        "context": _extract_context(lines, index, context_lines),
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
