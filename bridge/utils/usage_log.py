"""Per-call usage logging for the MCP tool surface.

Every MCP tool call can append one JSONL record describing what the call cost:
timestamp, tool name, shortened parameters, response size in bytes, estimated
tokens, hit count and duration.  The log is the measurement basis for the
rework baseline; it is **disabled by default** and switched on by pointing
``GHIDRA_MCP_USAGE_LOG`` at a writable file path.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from .tokens import estimate_tokens

logger = logging.getLogger("bridge.usage")

#: Maximum characters kept per parameter value.
_PARAM_VALUE_CHARS = 80
#: Maximum characters kept for the whole serialized parameter map.
_PARAM_TOTAL_CHARS = 400
#: Maximum list elements kept per parameter value.
_PARAM_LIST_ITEMS = 5


def _initial_path() -> Optional[Path]:
    raw = os.getenv("GHIDRA_MCP_USAGE_LOG", "").strip()
    return Path(raw).expanduser() if raw else None


_usage_path: Optional[Path] = _initial_path()


def set_usage_log_path(path: Path | str | None) -> None:
    """Override the usage log location (used by tests and scripts)."""

    global _usage_path
    _usage_path = None if path is None else Path(path).expanduser()


def get_usage_log_path() -> Optional[Path]:
    """Return the active usage log path, or ``None`` when logging is off."""

    return _usage_path


def usage_log_enabled() -> bool:
    return _usage_path is not None


def _shorten(value: object, *, depth: int = 0) -> object:
    if isinstance(value, str):
        if len(value) <= _PARAM_VALUE_CHARS:
            return value
        return value[:_PARAM_VALUE_CHARS] + f"…(+{len(value) - _PARAM_VALUE_CHARS})"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        if depth >= 2:
            return f"<mapping:{len(value)}>"
        return {str(key): _shorten(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = list(value)
        head = [_shorten(item, depth=depth + 1) for item in items[:_PARAM_LIST_ITEMS]]
        if len(items) > _PARAM_LIST_ITEMS:
            head.append(f"…(+{len(items) - _PARAM_LIST_ITEMS})")
        return head
    return f"<{type(value).__name__}>"


def shorten_params(params: Mapping[str, Any]) -> Any:
    """Return a compact, JSON-safe rendering of the call parameters."""

    shortened = {str(key): _shorten(value) for key, value in params.items()}
    try:
        encoded = json.dumps(shortened, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return {"_unserializable": True}
    if len(encoded) <= _PARAM_TOTAL_CHARS:
        return shortened
    return encoded[:_PARAM_TOTAL_CHARS] + f"…(+{len(encoded) - _PARAM_TOTAL_CHARS})"


_TOTAL_KEYS = ("total", "total_matches", "match_count", "count")


def _int_or_none(value: object) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _sum_list_lengths(value: object, *, depth: int) -> Optional[int]:
    """Sum the lengths of every list found up to ``depth`` levels down."""

    if depth < 0:
        return None
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return len(value)
    if isinstance(value, Mapping):
        total: Optional[int] = None
        for item in value.values():
            found = _sum_list_lengths(item, depth=depth - 1)
            if found is not None:
                total = found if total is None else total + found
        return total
    return None


def count_hits(result: object) -> Optional[int]:
    """Best-effort hit count for a tool response envelope.

    Prefers an explicit ``total``-style field (also inside ``meta``/``summary``);
    otherwise sums the lengths of the result lists.  Returns ``None`` when
    neither is available, so "unknown" is never silently reported as zero.
    """

    data = result.get("data") if isinstance(result, Mapping) else None
    if data is None:
        return None
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return len(data)
    if not isinstance(data, Mapping):
        return None

    for key in _TOTAL_KEYS:
        found = _int_or_none(data.get(key))
        if found is not None:
            return found

    for container in ("meta", "summary"):
        nested = data.get(container)
        if isinstance(nested, Mapping):
            for key in _TOTAL_KEYS:
                found = _int_or_none(nested.get(key))
                if found is not None:
                    return found

    return _sum_list_lengths(data, depth=2)


def _result_bytes(result: object) -> int:
    try:
        return len(json.dumps(result, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def record_tool_call(
    *,
    tool: str,
    params: Mapping[str, Any],
    result: object,
    duration_s: float,
) -> None:
    """Append one usage record.  No-op while the log is disabled."""

    path = _usage_path
    if path is None:
        return

    ok = bool(result.get("ok")) if isinstance(result, Mapping) else None
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "params": shorten_params(params),
        "result_bytes": _result_bytes(result),
        "estimate_tokens": estimate_tokens(result),
        "hits": count_hits(result),
        "duration_ms": round(duration_s * 1000, 3),
        "ok": ok,
    }

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        logger.exception("Failed to write usage log entry", extra={"path": str(path)})


__all__ = [
    "count_hits",
    "get_usage_log_path",
    "record_tool_call",
    "set_usage_log_path",
    "shorten_params",
    "usage_log_enabled",
]
