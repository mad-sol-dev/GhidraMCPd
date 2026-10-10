"""Function dossier aggregation helpers.

Instructions, calls and string candidates come from the plugin's structured
listing: call targets from Ghidra's CALL references, string candidates from
references into the image (rework stage 8c).  No operand text is taken apart.

Text that is still parsed, and why it is not operand text:

* the prose of ``get_function_by_address`` (``name at addr``, ``a-b``) -- the
  plugin's function-metadata route, outside stage 8c's scope;
* the inbound xref context (``... in caller [CALL]``) -- the xref route's own
  format, likewise;
* escaped bytes in a C string (``_ESCAPED_BYTE``) -- string content, measured
  for printability.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex
from .function_meta import read_function_name
from .listing import structured_listing
from ..utils.logging import enforce_batch_limit, increment_counter
from ..utils.tokens import estimate_tokens


_ALLOWED_FIELDS: Tuple[str, ...] = (
    "function",
    "disasm",
    "decompile",
    "xrefs",
    "callgraph",
    "strings",
    "constants",
    "features",
)

#: Fields returned when the caller names none.
#:
#: ``decompile`` and ``disasm`` are omitted deliberately.  Measured on
#: 0x002AF9C0 they are 36% and 22% of a full dossier -- 58% together -- and they
#: are the two a caller can fetch on their own terms once the cheap fields have
#: told them whether this is the right function: ``disassemble_at`` gives the
#: listing (as text, at half the bytes), ``find_in_function`` gives only the
#: matching lines.  What remains is the part that answers "is this the function
#: I want?", which is what an unparameterised call is asking.
_DEFAULT_FIELDS: Tuple[str, ...] = (
    "function",
    "xrefs",
    "strings",
    "constants",
    "features",
)



class AnalyzeConfig:
    """Parsed options controlling dossier generation."""

    __slots__ = (
        "before",
        "after",
        "max_instructions",
        "inbound_limit",
        "outbound_limit",
        "callgraph_limit",
        "strings_limit",
        "constants_limit",
        "cstring_max_len",
        "decompile_enabled",
        "decompile_max_lines",
    )

    def __init__(
        self,
        *,
        before: int = 8,
        after: int = 8,
        max_instructions: int = 48,
        inbound_limit: int = 40,
        outbound_limit: int = 40,
        callgraph_limit: int = 24,
        strings_limit: int = 6,
        constants_limit: int = 8,
        cstring_max_len: int = 256,
        decompile_enabled: bool = True,
        decompile_max_lines: int = 120,
    ) -> None:
        self.before = before
        self.after = after
        self.max_instructions = max_instructions
        self.inbound_limit = inbound_limit
        self.outbound_limit = outbound_limit
        self.callgraph_limit = callgraph_limit
        self.strings_limit = strings_limit
        self.constants_limit = constants_limit
        self.cstring_max_len = cstring_max_len
        self.decompile_enabled = decompile_enabled
        self.decompile_max_lines = decompile_max_lines


def analyze_function_complete(
    client: GhidraClient,
    *,
    address: int,
    fields: Optional[Iterable[str]] = None,
    fmt: str = "json",
    max_result_tokens: Optional[int] = None,
    options: Optional[Mapping[str, object]] = None,
) -> Dict[str, object]:
    """Collect a read-only function dossier for ``address``."""

    if fmt != "json":
        raise ValueError("fmt must be 'json'")

    requested = set(fields) if fields is not None else set(_DEFAULT_FIELDS)
    unknown = requested.difference(_ALLOWED_FIELDS)
    if unknown:
        raise ValueError(f"Unsupported fields requested: {sorted(unknown)}")

    config = _parse_options(options or {})

    increment_counter("analyze.function_complete")

    meta_raw = client.get_function_by_address(address)
    function_info, entry_point, body_range = _normalize_function_meta(meta_raw, address)

    payload: Dict[str, object] = {"address": int_to_hex(address)}

    if "function" in requested:
        payload["function"] = function_info

    disasm_entries: List[Dict[str, object]] = []
    disasm_data: Dict[str, object] | None = None
    disasm_truncated = False

    needs_disasm = bool(
        requested.intersection({"disasm", "xrefs", "callgraph", "strings", "constants", "features"})
    )
    if needs_disasm:
        disasm_entries = _listing_entries(client, entry_point)
        if "disasm" in requested:
            disasm_data, disasm_truncated = _build_disasm_window(
                disasm_entries,
                target=address,
                before=config.before,
                after=config.after,
                max_instructions=config.max_instructions,
            )
            payload["disasm"] = disasm_data

    decompile_info: Dict[str, object] | None = None
    decompile_truncated = False
    if "decompile" in requested:
        decompile_info, decompile_truncated = _collect_decompile(
            client,
            entry_point=entry_point,
            enabled=config.decompile_enabled,
            max_lines=config.decompile_max_lines,
        )
        payload["decompile"] = decompile_info

    inbound_entries: List[Dict[str, object]] = []
    outbound_entries: List[Dict[str, object]] = []
    if "xrefs" in requested or "callgraph" in requested or "features" in requested:
        inbound_entries = _collect_inbound_xrefs(
            client,
            entry_point,
            limit=config.inbound_limit,
        )
        call_refs = _extract_call_references(
            client,
            disasm_entries,
            limit=config.outbound_limit,
        )
        outbound_entries = call_refs
        if "xrefs" in requested:
            payload["xrefs"] = {
                "inbound": inbound_entries,
                "outbound": call_refs,
                "summary": {
                    "inbound": len(inbound_entries),
                    "outbound": len(call_refs),
                },
            }

        if "callgraph" in requested:
            payload["callgraph"] = {
                "callers": _callers_from_inbound(inbound_entries, config.callgraph_limit),
                "callees": _callees_from_outbound(call_refs, config.callgraph_limit),
            }

    string_items: List[Dict[str, object]] = []
    if "strings" in requested:
        string_items = _collect_strings(
            client,
            disasm_entries,
            limit=config.strings_limit,
            max_len=config.cstring_max_len,
        )
        payload["strings"] = {
            "items": string_items,
            "limit": config.strings_limit,
            "source": "disassembly_literals",
        }

    if "constants" in requested:
        payload["constants"] = _collect_constants(disasm_entries, limit=config.constants_limit)

    if "features" in requested:
        payload["features"] = _summarize_features(
            disasm_entries,
            inbound_entries,
            outbound_entries,
            string_items,
            body_range,
        )

    truncated = disasm_truncated or decompile_truncated

    data_without_meta = {k: v for k, v in payload.items() if k != "meta"}
    estimate_tokens = _estimate_tokens(data_without_meta)

    payload["meta"] = {
        "fields": sorted(requested),
        "fmt": fmt,
        "max_result_tokens": max_result_tokens,
        "estimate_tokens": estimate_tokens,
        "truncated": truncated,
    }

    return payload


def _parse_options(raw: Mapping[str, object]) -> AnalyzeConfig:
    disasm_opts = _coerce_mapping(raw.get("disasm"))
    xref_opts = _coerce_mapping(raw.get("xrefs"))
    callgraph_opts = _coerce_mapping(raw.get("callgraph"))
    string_opts = _coerce_mapping(raw.get("strings"))
    constant_opts = _coerce_mapping(raw.get("constants"))
    decomp_opts = _coerce_mapping(raw.get("decompile"))

    before = _clamped_int(disasm_opts.get("before", 8), minimum=0, maximum=64)
    after = _clamped_int(disasm_opts.get("after", 8), minimum=0, maximum=64)
    window = before + after + 1
    max_instr = _clamped_int(
        disasm_opts.get("max_instructions", max(window, 48)),
        minimum=1,
        maximum=128,
    )
    if max_instr < window:
        max_instr = window
    enforce_batch_limit(max_instr, counter="analyze.disasm.window")

    inbound_limit = _clamped_int(xref_opts.get("inbound_limit", 40), minimum=0, maximum=256)
    outbound_limit = _clamped_int(xref_opts.get("outbound_limit", 40), minimum=0, maximum=256)
    callgraph_limit = _clamped_int(callgraph_opts.get("limit", 24), minimum=0, maximum=256)
    strings_limit = _clamped_int(string_opts.get("limit", 6), minimum=0, maximum=64)
    constants_limit = _clamped_int(constant_opts.get("limit", 8), minimum=0, maximum=64)
    cstring_max_len = _clamped_int(
        string_opts.get("max_cstring_len", 256), minimum=1, maximum=1024
    )

    decompile_enabled = bool(decomp_opts.get("enabled", True))
    decompile_max_lines = _clamped_int(
        decomp_opts.get("max_lines", 120), minimum=1, maximum=500
    )

    for counter, value in (
        ("analyze.xrefs.inbound_limit", inbound_limit),
        ("analyze.xrefs.outbound_limit", outbound_limit),
        ("analyze.callgraph.limit", callgraph_limit),
        ("analyze.strings.limit", strings_limit),
        ("analyze.constants.limit", constants_limit),
    ):
        enforce_batch_limit(value or 0, counter=counter)

    return AnalyzeConfig(
        before=before,
        after=after,
        max_instructions=max_instr,
        inbound_limit=inbound_limit,
        outbound_limit=outbound_limit,
        callgraph_limit=callgraph_limit,
        strings_limit=strings_limit,
        constants_limit=constants_limit,
        cstring_max_len=cstring_max_len,
        decompile_enabled=decompile_enabled,
        decompile_max_lines=decompile_max_lines,
    )


def _clamped_int(value: object, *, minimum: int, maximum: int) -> int:
    try:
        candidate = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Expected integer between {minimum} and {maximum}")
    if candidate < minimum or candidate > maximum:
        raise ValueError(f"Integer out of range [{minimum}, {maximum}]")
    return candidate


def _coerce_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _normalize_function_meta(
    meta: Optional[Mapping[str, object]],
    fallback_addr: int,
) -> Tuple[Dict[str, object], int, Tuple[Optional[int], Optional[int]]]:
    name: Optional[str] = None
    entry = fallback_addr
    comment: Optional[str] = None
    signature: Optional[str] = None
    range_start: Optional[int] = None
    range_end: Optional[int] = None

    if meta:
        raw_name = _pick_first(meta, ("name", "Function"))
        if isinstance(raw_name, str):
            name = raw_name.split(" at ", 1)[0].strip()

        entry_raw = _pick_first(meta, ("entry_point", "Entry"))
        parsed_entry = _parse_intish(entry_raw)
        if parsed_entry is not None:
            entry = parsed_entry

        comment_raw = _pick_first(meta, ("comment", "Comment"))
        if isinstance(comment_raw, str) and comment_raw.strip():
            comment = comment_raw.strip()

        signature_raw = _pick_first(meta, ("signature", "Signature"))
        if isinstance(signature_raw, str) and signature_raw.strip():
            signature = signature_raw.strip()

        body_raw = _pick_first(meta, ("body", "Body"))
        if isinstance(body_raw, str) and "-" in body_raw:
            left, right = body_raw.split("-", 1)
            range_start = _parse_intish(left.strip())
            range_end = _parse_intish(right.strip())

    info: Dict[str, object] = {
        "name": name,
        "entry_point": int_to_hex(entry),
        "address": int_to_hex(entry),
        "signature": signature,
        "comment": comment,
    }
    if range_start is not None and range_end is not None:
        # start..end is the span the body reaches across, interior data
        # included.  It is deliberately not called a size: the function's own
        # bytes can be fewer, because a constant pool between two instructions
        # sits inside this span without belonging to the body.  list_functions_
        # in_range counts those body bytes and therefore reports the smaller
        # number; naming both "size" is what made them look contradictory.
        info["range"] = {
            "start": int_to_hex(range_start),
            "end": int_to_hex(range_end),
            "span_bytes": range_end - range_start + 1,
        }
    else:
        info["range"] = None
    return info, entry, (range_start, range_end)


def _pick_first(meta: Mapping[str, object], keys: Sequence[str]) -> object:
    for key in keys:
        if key in meta:
            return meta[key]
    return None


def _parse_intish(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 16)
    except ValueError:
        return None


def _listing_entries(client: GhidraClient, entry_point: int) -> List[Dict[str, object]]:
    """The function's instructions from the plugin's structured listing.

    ``text`` keeps the shape the text route gave -- instruction, then
    ``; comment`` -- and ``refs``/``flow``/``mnemonic`` carry what used to be
    read back out of that text.  Without a structured listing there is nothing
    to analyse honestly, so this raises instead of returning an empty list
    that would read as a function without instructions.
    """

    listing = structured_listing(client, entry_point)
    entries: List[Dict[str, object]] = []
    for insn in listing["instructions"]:
        if not isinstance(insn, Mapping):
            continue
        addr = _parse_intish(insn.get("address"))
        if addr is None:
            continue
        text = str(insn.get("text") or "")
        comment = insn.get("comment")
        if comment:
            text = f"{text} ; {comment}"
        entries.append(
            {
                "address_int": addr,
                "address": int_to_hex(addr),
                "bytes": str(insn.get("bytes") or ""),
                "text": text,
                "mnemonic": str(insn.get("mnemonic") or ""),
                "flow": str(insn.get("flow") or ""),
                "refs": [ref for ref in insn.get("refs") or () if isinstance(ref, Mapping)],
            }
        )
    entries.sort(key=lambda item: item["address_int"])
    return entries


def _build_disasm_window(
    entries: Sequence[Mapping[str, object]],
    *,
    target: int,
    before: int,
    after: int,
    max_instructions: int,
) -> Tuple[Dict[str, object], bool]:
    if not entries:
        return {
            "before": before,
            "after": after,
            "max_instructions": max_instructions,
            "window": [],
            "total_instructions": 0,
            "center_index": -1,
            "truncated": False,
        }, False

    index = _find_nearest_index(entries, target)
    start = max(index - before, 0)
    end = min(index + after + 1, len(entries))
    window = [dict(entries[i]) for i in range(start, end)]

    truncated = False
    if len(window) > max_instructions:
        truncated = True
        extra = len(window) - max_instructions
        center_offset = index - start
        drop_before = min(center_offset, (extra + 1) // 2)
        drop_after = extra - drop_before
        window = window[drop_before: len(window) - drop_after]
        start += drop_before

    for item in window:
        item["is_target"] = item["address_int"] == target

    center_index = next(
        (i for i, entry in enumerate(window) if entry["address_int"] == target),
        0,
    )

    return (
        {
            "before": before,
            "after": after,
            "max_instructions": max_instructions,
            "window": [
                {
                    "address": entry["address"],
                    "bytes": entry.get("bytes", ""),
                    "text": entry.get("text", ""),
                    "is_target": bool(entry.get("is_target")),
                }
                for entry in window
            ],
            "total_instructions": len(entries),
            "center_index": center_index,
            "truncated": truncated,
        },
        truncated,
    )


def _find_nearest_index(entries: Sequence[Mapping[str, object]], target: int) -> int:
    best_index = 0
    best_delta = abs(entries[0]["address_int"] - target)
    for idx, entry in enumerate(entries):
        delta = abs(entry["address_int"] - target)
        if delta < best_delta:
            best_delta = delta
            best_index = idx
        if delta == 0:
            return idx
    return best_index


def _collect_decompile(
    client: GhidraClient,
    *,
    entry_point: int,
    enabled: bool,
    max_lines: int,
) -> Tuple[Dict[str, object], bool]:
    if not enabled:
        return {
            "enabled": False,
            "snippet": None,
            "lines": 0,
            "truncated": False,
            "error": None,
        }, False

    source = client.decompile_function(entry_point)
    if not source:
        return (
            {
                "enabled": True,
                "snippet": None,
                "lines": 0,
                "truncated": False,
                "error": "decompilation_unavailable",
            },
            False,
        )

    lines = [line.rstrip() for line in source.splitlines()]
    truncated = len(lines) > max_lines
    snippet_lines = lines[:max_lines]
    return (
        {
            "enabled": True,
            "snippet": "\n".join(snippet_lines),
            "lines": len(lines),
            "truncated": truncated,
            "error": None,
        },
        truncated,
    )


def _collect_inbound_xrefs(
    client: GhidraClient,
    entry_point: int,
    *,
    limit: int,
) -> List[Dict[str, object]]:
    if limit <= 0:
        return []
    raw = client.get_xrefs_to(entry_point, limit=limit)
    results: List[Dict[str, object]] = []
    for item in raw[:limit]:
        addr = item.get("addr")
        context = str(item.get("context", ""))
        if not isinstance(addr, int):
            continue
        ref_type = _extract_ref_type(context)
        results.append(
            {
                "address": int_to_hex(addr),
                "type": ref_type,
                "function": _extract_function_name(context),
                "context": context,
            }
        )
    results.sort(key=lambda entry: entry["address"])
    return results


def _extract_ref_type(context: str) -> Optional[str]:
    if "[" not in context or "]" not in context:
        return None
    start = context.rfind("[")
    end = context.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return None
    return context[start + 1 : end].strip().upper() or None


def _extract_function_name(context: str) -> Optional[str]:
    marker = " in "
    if marker not in context:
        return None
    tail = context.split(marker, 1)[1]
    return tail.split("[")[0].strip() or None


def _extract_call_references(
    client: GhidraClient,
    entries: Sequence[Mapping[str, object]],
    *,
    limit: int,
) -> List[Dict[str, object]]:
    if limit <= 0:
        return []

    cache: MutableMapping[int, Optional[str]] = {}
    results: List[Dict[str, object]] = []
    for entry in entries:
        if entry.get("flow") != "call":
            continue
        # A computed call (blx r3) has no reference and no target to name.
        call_refs = [ref for ref in entry.get("refs", ()) if "CALL" in str(ref.get("type", ""))]
        if not call_refs:
            continue
        target_address = _parse_intish(call_refs[0].get("to"))
        if target_address is None:
            continue
        if target_address not in cache:
            # read_function_name parses the plugin's "Function: <name> at <hex>";
            # .get("name") read a field the plugin never sends -- always None.
            cache[target_address] = read_function_name(client, target_address)
        results.append(
            {
                "from_address": entry.get("address", ""),
                "to_address": int_to_hex(target_address),
                "name": cache[target_address],
                "type": str(entry.get("mnemonic", "")).upper(),
                "context": entry.get("text", ""),
            }
        )
        if len(results) >= limit:
            break

    results.sort(key=lambda item: (item.get("to_address") or "", item.get("from_address") or ""))
    return results


def _callers_from_inbound(
    inbound: Sequence[Mapping[str, object]],
    limit: int,
) -> List[Dict[str, object]]:
    seen: set[Tuple[Optional[str], str]] = set()
    callers: List[Dict[str, object]] = []
    for entry in inbound:
        if limit and len(callers) >= limit:
            break
        ref_type = (entry.get("type") or "").upper()
        if "CALL" not in ref_type:
            continue
        name = entry.get("function") or None
        key = (name, entry.get("address", ""))
        if key in seen:
            continue
        seen.add(key)
        callers.append(
            {
                "name": name,
                "site": entry.get("address"),
                "type": ref_type,
            }
        )
    return callers


def _callees_from_outbound(
    outbound: Sequence[Mapping[str, object]],
    limit: int,
) -> List[Dict[str, object]]:
    seen: set[Tuple[Optional[str], Optional[str]]] = set()
    callees: List[Dict[str, object]] = []
    for entry in outbound:
        if limit and len(callees) >= limit:
            break
        key = (entry.get("name"), entry.get("to_address"))
        if key in seen:
            continue
        seen.add(key)
        callees.append(
            {
                "name": entry.get("name"),
                "address": entry.get("to_address"),
                "type": entry.get("type"),
            }
        )
    return callees


def _collect_strings(
    client: GhidraClient,
    entries: Sequence[Mapping[str, object]],
    *,
    limit: int,
    max_len: int,
) -> List[Dict[str, object]]:
    if limit <= 0:
        return []
    seen: set[int] = set()
    results: List[Dict[str, object]] = []
    for entry in entries:
        if len(results) >= limit:
            break
        if entry.get("flow") != "fallthrough":
            # A branch or call operand is where control goes, not something to
            # read: a C string at a call target is the callee's first bytes.
            continue
        for ref in entry.get("refs", ()):
            # Only targets inside the image can hold text this program carries.
            if not ref.get("mapped") or "space" in ref:
                continue
            addr = _parse_intish(ref.get("to"))
            if addr is None or addr in seen:
                continue
            seen.add(addr)
            literal = client.read_cstring(addr, max_len=max_len)
            if not literal:
                continue
            cleaned = literal.split("\n", 1)[0].strip()
            if not _looks_like_string(cleaned):
                continue
            results.append(
                {
                    "address": int_to_hex(addr),
                    "source": entry.get("address"),
                    "literal": cleaned,
                    # Bytes, not the width of the escape text: "\\x1f" is one
                    # byte written as four characters.
                    "length": len(_decoded_view(cleaned)),
                }
            )
            if len(results) >= limit:
                break
    return results


def _collect_constants(
    entries: Sequence[Mapping[str, object]], *, limit: int
) -> Dict[str, object]:
    """The words the function loads from its constant pool (ANALYZE-POOL-CONSTANTS).

    Each READ reference into the image carries the word stored there (stage
    8c), which for a PC-relative load is the value loaded: peripheral bases,
    RAM pointers, masks.  The strings section drops these -- a pool word is
    not text -- and before 8c it called them strings; listed here they are
    what they are.  One item per distinct value, in order of first load, with
    where it sits and how often it is loaded.
    """

    by_value: Dict[str, Dict[str, object]] = {}
    for entry in entries:
        if entry.get("flow") != "fallthrough":
            continue
        for ref in entry.get("refs", ()):
            if ref.get("type") != "READ" or not ref.get("mapped") or "word" not in ref:
                continue
            value = str(ref["word"]).lower()
            item = by_value.get(value)
            if item is None:
                by_value[value] = {
                    "value": value,
                    "pool": int_to_hex(int(str(ref.get("to")), 16)),
                    "source": entry.get("address"),
                    "loads": 1,
                }
            else:
                item["loads"] = int(item["loads"]) + 1
    items = list(by_value.values())
    return {"items": items[:limit], "limit": limit, "total": len(items)}


#: The plugin escapes non-printable bytes as text: a word like 0xFF9F0F1F comes
#: back as the sixteen ASCII characters "\\x1f\\x0f\\x9f\\xff".
_ESCAPED_BYTE = re.compile(r"\\x[0-9a-fA-F]{2}")

#: Shortest run of bytes reported as a string.
_MIN_STRING_BYTES = 4

def _decoded_view(value: str) -> str:
    """Collapse each escaped byte to one placeholder that is not printable.

    Counting the escape text itself was the bug: "\\x1f" is four printable
    characters, so any binary data passed the printability test and a
    constant-pool word was reported as a string.
    """

    return _ESCAPED_BYTE.sub("\x00", value)


def _looks_like_string(value: str) -> bool:
    """Whether ``value`` reads as text rather than as data rendered as text.

    A constant pool sits in the same address space as the strings, and every
    pool address appears as an operand, so this is the only thing separating
    "the function references this text" from "the function loads this number".
    """

    if not value:
        return False
    decoded = _decoded_view(value)
    # A pool word whose low bytes happen to be printable ASCII -- 0x00006978
    # reads as "xi" -- is indistinguishable from a two-character string by
    # content alone. Requiring some length prefers a missed hint over a false
    # claim: a dropped string costs a follow-up call, a pool word presented as
    # text costs a wrong conclusion about the firmware.
    if len(decoded) < _MIN_STRING_BYTES:
        return False
    printable = sum(1 for ch in decoded if 32 <= ord(ch) <= 126)
    return printable >= max(1, len(decoded) * 3 // 4)


def _summarize_features(
    disasm_entries: Sequence[Mapping[str, object]],
    inbound: Sequence[Mapping[str, object]],
    outbound: Sequence[Mapping[str, object]],
    strings: Sequence[Mapping[str, object]],
    body_range: Tuple[Optional[int], Optional[int]],
) -> Dict[str, object]:
    start, end = body_range
    size_bytes = (end - start + 1) if start is not None and end is not None else None
    return {
        "instruction_count": len(disasm_entries),
        "call_count": sum(1 for entry in outbound if entry.get("type")),
        "string_reference_count": len(strings),
        "xrefs_inbound_count": len(inbound),
        "xrefs_outbound_count": len(outbound),
        "size_bytes": size_bytes,
        "notes": [],
    }


def _estimate_tokens(data: Mapping[str, object]) -> int:
    """Delegate to the shared estimator (also used by the usage log)."""

    return estimate_tokens(data)


__all__ = ["analyze_function_complete"]
