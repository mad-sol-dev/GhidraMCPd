"""Compact string cross reference helpers."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..ghidra.client import STRUCTURED_LISTING_UNSUPPORTED, GhidraClient
from ..utils.cache import (
    build_search_cache_key,
    get_program_digest,
    get_search_cache,
    normalize_search_query,
)
from ..utils.hex import int_to_hex, parse_hex
from .listing import ListingUnavailable
from ..utils.config import MAX_ITEMS_PER_BATCH
from ..utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
)
from . import method_notes
from .pagination import finalize_page


_REGISTER_ARG_ORDER = {
    # ARM / Thumb
    "r0": 0,
    "r1": 1,
    "r2": 2,
    "r3": 3,
    # AArch64
    "x0": 0,
    "x1": 1,
    "x2": 2,
    "x3": 3,
    "x4": 4,
    "x5": 5,
    "x6": 6,
    "x7": 7,
    "w0": 0,
    "w1": 1,
    "w2": 2,
    "w3": 3,
    "w4": 4,
    "w5": 5,
    "w6": 6,
    "w7": 7,
    # RISC-V
    "a0": 0,
    "a1": 1,
    "a2": 2,
    "a3": 3,
    "a4": 4,
    "a5": 5,
    "a6": 6,
    "a7": 7,
    # x86-64 System V
    "rdi": 0,
    "rsi": 1,
    "rdx": 2,
    "rcx": 3,
    "r8": 4,
    "r9": 5,
    # x86-32 fastcall / MS x64
    "edi": 0,
    "esi": 1,
    "edx": 2,
    "ecx": 3,
}

def _normalize_context(text: str, *, max_len: int = 140) -> str:
    normalized = " ".join(text.strip().split())
    return normalized[:max_len]


def _line(insn: Mapping[str, Any]) -> str:
    """The text route's line shape: ``002af9c4: adr r1,0x2afb10 ; comment``."""

    address = str(insn.get("address", "")).lower().removeprefix("0x")
    text = str(insn.get("text") or "")
    comment = insn.get("comment")
    return _normalize_context(f"{address}: {text} ; {comment}" if comment else f"{address}: {text}")


def _refs_to(insn: Mapping[str, Any], target: int) -> List[Mapping[str, Any]]:
    found = []
    for ref in insn.get("refs") or ():
        if isinstance(ref, Mapping) and "space" not in ref:
            try:
                if int(str(ref.get("to")), 16) == target:
                    found.append(ref)
            except ValueError:
                continue
    return found


def _find_referencing_instruction(
    instructions: Sequence[Mapping[str, Any]], *, ref_addr: int, string_addr: int
) -> Optional[int]:
    """Index of the instruction that brings the string into a register.

    In order: the instruction at the reference itself; one that references the
    string directly (``adr``); one that loads the pool slot the reference comes
    from.  The last case is the usual one on ARM -- the xref belongs to the
    pool word, not to the ``ldr`` -- and the text scan this replaces never
    found it.
    """

    for idx, insn in enumerate(instructions):
        if str(insn.get("address", "")).lower() == f"0x{ref_addr:08x}":
            return idx
    for idx, insn in enumerate(instructions):
        if _refs_to(insn, string_addr):
            return idx
    for idx, insn in enumerate(instructions):
        if any(ref.get("type") == "READ" for ref in _refs_to(insn, ref_addr)):
            return idx
    return None


def _collect_snippet(instructions: Sequence[Mapping[str, Any]], start: int) -> List[Mapping[str, Any]]:
    """The referencing instruction, then up to the next call within four."""

    snippet = [instructions[start]]
    for offset in range(1, 5):
        if start + offset >= len(instructions):
            break
        candidate = instructions[start + offset]
        if candidate.get("flow") == "call":
            snippet.append(candidate)
            break
        if len(snippet) == 1:
            snippet.append(candidate)
    return snippet


def _arg_index(insn: Mapping[str, Any]) -> Optional[int]:
    """The argument slot of the register the string is loaded into."""

    operands = insn.get("operands") or ()
    if not operands or not isinstance(operands[0], Mapping):
        return None
    registers = operands[0].get("registers") or ()
    if len(registers) != 1:
        return None
    return _REGISTER_ARG_ORDER.get(str(registers[0]).lower())


def _call_hint(snippet: Sequence[Mapping[str, Any]]) -> Optional[str]:
    for insn in snippet:
        if insn.get("flow") == "call":
            targets = insn.get("targets") or ()
            if targets:
                return str(targets[0])
    for insn in snippet:
        lower = _line(insn).lower()
        for keyword in ("printf", "sprintf", "snprintf", "log", "error", "panic", "print"):
            if keyword in lower:
                return keyword
    return None


def _extract_context(
    client: GhidraClient,
    *,
    string_addr: int,
    ref_addr: int,
    fallback: str,
) -> Tuple[str, Optional[int], Optional[str]]:
    listing = client.disassemble_function_structured(ref_addr)
    if listing is None:
        error = getattr(client, "last_error", None)
        if getattr(error, "reason", None) == STRUCTURED_LISTING_UNSUPPORTED:
            # Not "this reference has no function": the plugin cannot answer
            # for any of them, and the fallback would hide that.
            raise ListingUnavailable(f"cannot disassemble {int_to_hex(ref_addr)}: {error.reason}")
        return (_normalize_context(fallback) if fallback else "", None, None)

    instructions = [insn for insn in listing.get("instructions") or () if isinstance(insn, Mapping)]
    idx = _find_referencing_instruction(instructions, ref_addr=ref_addr, string_addr=string_addr)
    if idx is None:
        return (_normalize_context(fallback) if fallback else "", None, None)

    snippet_insns = _collect_snippet(instructions, idx)
    snippet = _normalize_context(" | ".join(_line(insn) for insn in snippet_insns))
    return (snippet or _normalize_context(fallback), _arg_index(instructions[idx]), _call_hint(snippet_insns))


def xrefs_compact(client: GhidraClient, *, string_addr: int, limit: int = 20) -> Dict[str, object]:
    increment_counter("strings.xrefs.calls")
    enforce_batch_limit(limit, counter="strings.xrefs.limit")
    refs = client.get_xrefs_to(string_addr, limit=limit)
    total = len(refs)
    callers: List[Dict[str, object]] = []
    for ref in refs[:limit]:
        addr = ref.get("addr")
        if addr is None:
            continue
        context, arg_index, hint = _extract_context(
            client,
            string_addr=string_addr,
            ref_addr=addr,
            fallback=ref.get("context", ""),
        )
        entry: Dict[str, object] = {"addr": int_to_hex(addr), "context": context}
        if arg_index is not None:
            entry["arg_index"] = arg_index
        if hint:
            entry["hint"] = hint
        callers.append(entry)
        increment_counter("strings.xrefs.callers")
    return {
        "string": int_to_hex(string_addr),
        "count": total,
        "callers": callers,
    }


def search_strings(
    client: GhidraClient,
    *,
    query: str,
    limit: int,
    page: int,
    include_literals: bool = False,
) -> Dict[str, Any]:
    limit = max(int(limit), 1)
    page = max(int(page), 1)

    normalized_query = normalize_search_query(query)

    cache_key = None
    digest = get_program_digest(client)
    cache = get_search_cache()
    if digest:
        cache_key = build_search_cache_key(
            program_digest=digest,
            endpoint="strings",
            normalized_query=normalized_query,
            options={
                "limit": limit,
                "page": page,
                "include_literals": include_literals,
            },
        )
        cached = cache.get(cache_key)
        if cached is not None:
            return dict(cached)

    try:
        all_entries = client.search_strings(query)
    except Exception:
        if cache_key is not None:
            cache.invalidate(cache_key)
        raise

    normalized = strings_compact_view(all_entries, include_literals=include_literals)
    normalized_entries = normalized.get("items", [])

    total = len(normalized_entries)
    window = page * limit
    if window > MAX_ITEMS_PER_BATCH:
        raise SafetyLimitExceeded("strings.search.window", MAX_ITEMS_PER_BATCH, window)
    offset = (page - 1) * limit
    start_index = min(offset, total)
    end_index = min(start_index + limit, total)
    paginated_items = normalized_entries[start_index:end_index]

    has_more = end_index < total

    result: Dict[str, Any] = {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }

    method_notes.attach("search_strings", result)
    finalize_page(result)

    if cache_key is not None:
        cache.set(cache_key, result)

    return result


def fetch_strings_compact_entries(
    client: object, *, limit: int, offset: int
) -> Tuple[List[Mapping[str, object]], bool]:
    """Collect one page of raw string metadata, plus whether more follow.

    Prefers ``list_strings``, which pages natively at the plugin and reports
    ``has_more``.  The ``search_strings`` fallback pulls everything and slices,
    so it can only say "more follow" by looking at what it sliced off.

    Note for anyone extending this: the previous version probed a
    ``list_strings_compact`` method that no client ever had, then a
    ``list_strings`` that did not exist either, and returned an empty list.
    strings_compact therefore answered "no strings" for every call, on every
    program, without ever failing.  A provider chain must not have a silent
    empty result as its floor.
    """

    lister = getattr(client, "list_strings", None)
    if callable(lister):
        result = lister(limit=limit, offset=offset)
        if isinstance(result, Mapping):
            return list(result.get("items", [])), bool(result.get("has_more", False))
        # An older client that returned a bare list.
        entries = [] if result is None else list(result)
        return entries, len(entries) >= limit

    search_fallback = getattr(client, "search_strings", None)
    if callable(search_fallback):
        result = search_fallback("")
        entries = [] if result is None else list(result)
        page = entries[offset : offset + limit]
        return page, len(entries) > offset + limit

    return [], False


_ELLIPSIS = "…"


def _normalize_literal(value: str) -> str:
    normalized = " ".join(value.replace("\n", " ").replace("\r", " ").split())
    return normalized


def _truncate_literal(value: str, *, max_len: int = 120) -> str:
    if len(value) <= max_len:
        return value
    if max_len <= 0:
        return ""
    return value[: max_len - 1] + _ELLIPSIS


def strings_compact_view(
    entries: Sequence[Mapping[str, object]],
    *,
    include_literals: bool = False,
    has_more: bool = False,
) -> Dict[str, object]:
    """Normalize raw string metadata into the compact response structure.

    Reports how many entries this page holds, never a total: paging through
    /strings never learns how many strings exist, and printing the page length
    under the name "total" claimed knowledge that was not there.
    """

    normalized: List[Tuple[int, Dict[str, object]]] = []
    for raw in entries:
        literal_raw = raw.get("literal")
        if literal_raw is None:
            literal_raw = raw.get("string")
        if literal_raw is None:
            literal_raw = raw.get("s", "")
        literal = _normalize_literal(str(literal_raw))
        literal_compact = _truncate_literal(literal)

        address_raw = raw.get("address")
        if address_raw is None:
            address_raw = raw.get("addr")
        if address_raw is None:
            raise ValueError("Missing address for compact string entry")
        if isinstance(address_raw, str):
            address = parse_hex(address_raw)
        elif isinstance(address_raw, int):
            address = address_raw
        else:
            raise ValueError("Invalid address type for compact string entry")

        refs_raw = None
        if "refs" in raw:
            refs_raw = raw.get("refs")
        elif "xref_count" in raw:
            refs_raw = raw.get("xref_count")
        elif "count" in raw:
            refs_raw = raw.get("count")
        elif "callers" in raw and isinstance(raw["callers"], (list, tuple, set)):
            refs_raw = len(raw["callers"])
        if refs_raw is None:
            refs = 0
        elif isinstance(refs_raw, (list, tuple, set)):
            refs = len(refs_raw)
        else:
            refs = int(refs_raw)
        if refs < 0:
            refs = 0

        normalized.append(
            (
                int(address),
                {
                    "s": literal_compact,
                    "addr": int_to_hex(int(address)),
                    "refs": refs,
                    **({"literal": literal} if include_literals else {}),
                },
            )
        )

    normalized.sort(key=lambda item: item[0])
    items = [payload for _, payload in normalized]
    return {
        "returned": len(items),
        "items": items,
        "has_more": bool(has_more),
        "truncated": bool(has_more),
    }


__all__ = [
    "fetch_strings_compact_entries",
    "search_strings",
    "strings_compact_view",
    "xrefs_compact",
]
