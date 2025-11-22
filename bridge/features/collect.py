"""Multi-operation collection helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from ..ghidra.client import GhidraClient
from ..utils.errors import ErrorCode, make_error
from ..utils.hex import parse_hex
from ..utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
)
from .analyze import _estimate_tokens
from . import batch_ops, disasm, exports, functions, imports, memory, scalars, strings, xrefs


Envelope = Dict[str, object]
OperationHandler = Callable[[GhidraClient, Mapping[str, object]], Mapping[str, object]]


def _normalize_query_payload(
    query: Mapping[str, object]
) -> tuple[Mapping[str, object], List[str]]:
    """Normalize legacy query aliases to the canonical schema."""

    notes: List[str] = []
    normalized = dict(query)

    if "op" not in normalized and "type" in normalized:
        normalized["op"] = normalized["type"]
        notes.append("alias:op")

    if "params" not in normalized and "filter" in normalized:
        normalized["params"] = normalized["filter"]
        notes.append("alias:params")

    return normalized, notes


def _envelope_ok(data: Mapping[str, object]) -> Envelope:
    return {"ok": True, "data": dict(data), "errors": []}


def _envelope_error(code: ErrorCode, message: str) -> Envelope:
    return {
        "ok": False,
        "data": None,
        "errors": [make_error(code, message=message)],
    }


@dataclass
class _Budget:
    max_tokens: Optional[int]
    mode: str = "auto_trim"
    consumed: int = 0

    def account(self, estimate: int) -> bool:
        if self.max_tokens is None:
            self.consumed += estimate
            return True

        next_total = self.consumed + estimate
        if next_total <= self.max_tokens:
            self.consumed = next_total
            return True

        if self.mode == "strict":
            raise SafetyLimitExceeded("collect.tokens", self.max_tokens, next_total)

        self.consumed = self.max_tokens
        return False

    def remaining(self) -> Optional[int]:
        if self.max_tokens is None:
            return None
        return max(self.max_tokens - self.consumed, 0)

    def to_meta(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "mode": self.mode,
            "max_result_tokens": self.max_tokens,
            "consumed_tokens": self.consumed,
        }
        remaining = self.remaining()
        if remaining is not None:
            payload["remaining_tokens"] = remaining
        return payload


def _coerce_int(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):  # pragma: no cover - defensive guard
        raise TypeError("Boolean values are not valid for integer fields")
    return int(value)


def _budget_from_payload(
    payload: Mapping[str, object] | None,
    *,
    fallback_max: Optional[int] = None,
) -> _Budget:
    if payload is None:
        return _Budget(fallback_max, "auto_trim")

    max_value = payload.get("max_result_tokens", fallback_max)
    mode_raw = payload.get("mode", "auto_trim")
    mode = str(mode_raw)
    max_tokens = _coerce_int(max_value) if max_value is not None else None
    return _Budget(max_tokens, mode)


def _require(params: Mapping[str, object], key: str) -> object:
    if key not in params:
        raise KeyError(f"Missing required parameter: {key}")
    return params[key]


def _op_disassemble_at(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    address = parse_hex(str(_require(params, "address")))
    count = int(params.get("count", 16))
    return disasm.disassemble_at(client, address=address, count=count)


def _op_disassemble_batch(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    addresses_param = _require(params, "addresses")
    if not isinstance(addresses_param, Sequence) or isinstance(addresses_param, (str, bytes, bytearray)):
        raise TypeError("addresses must be an array of hex strings")
    addresses = [str(value) for value in addresses_param]
    count = int(params.get("count", 16))
    return batch_ops.disassemble_batch(client, addresses=addresses, count=count)


def _op_read_bytes(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    address = parse_hex(str(_require(params, "address")))
    length = int(params.get("length", 64))
    include_literals = bool(params.get("include_literals", False))
    return memory.read_bytes(
        client,
        address=address,
        length=length,
        include_literals=include_literals,
    )


def _op_read_words(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    address = parse_hex(str(_require(params, "address")))
    count = int(params.get("count", 1))
    include_literals = bool(params.get("include_literals", False))
    return batch_ops.read_words(
        client,
        address=address,
        count=count,
        include_literals=include_literals,
    )


def _op_search_strings(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    query = str(_require(params, "query"))
    limit = int(params.get("limit", 100))
    page = int(params.get("page", 1))
    if limit <= 0:
        raise ValueError("limit must be positive")
    if page <= 0:
        raise ValueError("page must be positive")
    include_literals = bool(params.get("include_literals", False))
    return strings.search_strings(
        client,
        query=query,
        limit=limit,
        page=page,
        include_literals=include_literals,
    )


def _fetch_strings(client: GhidraClient, *, limit: int, offset: int) -> Iterable[Mapping[str, object]]:
    fetcher = getattr(client, "list_strings_compact", None)
    if callable(fetcher):
        result = fetcher(limit=limit, offset=offset)
        return [] if result is None else list(result)

    fallback = getattr(client, "list_strings", None)
    if callable(fallback):
        try:
            result = fallback(limit=limit, offset=offset)
        except TypeError:
            result = fallback(limit=limit)
        return [] if result is None else list(result)

    return []


def _op_strings_compact(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    limit = int(params.get("limit", 0))
    offset = int(params.get("offset", 0))
    if limit <= 0:
        raise ValueError("limit must be a positive integer")
    if offset < 0:
        raise ValueError("offset must be a non-negative integer")
    enforce_batch_limit(limit, counter="strings.compact.limit")
    entries = _fetch_strings(client, limit=limit, offset=offset)
    return strings.strings_compact_view(entries)


def _op_string_xrefs(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    string_addr = parse_hex(str(_require(params, "string_addr")))
    limit = int(params.get("limit", 50))
    return strings.xrefs_compact(client, string_addr=string_addr, limit=limit)


def _op_search_imports(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    query = str(_require(params, "query"))
    limit = int(params.get("limit", 100))
    page = int(params.get("page", 1))
    if limit <= 0:
        raise ValueError("limit must be positive")
    if page <= 0:
        raise ValueError("page must be positive")
    return imports.search_imports(client, query=query, limit=limit, page=page)


def _op_search_exports(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    query = str(_require(params, "query"))
    limit = int(params.get("limit", 100))
    page = int(params.get("page", 1))
    if limit <= 0:
        raise ValueError("limit must be positive")
    if page <= 0:
        raise ValueError("page must be positive")
    return exports.search_exports(client, query=query, limit=limit, page=page)


def _op_search_functions(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    query = str(params.get("query", ""))
    limit = int(params.get("limit", 100))
    page = int(params.get("page", 1))
    cursor_param = params.get("resume_cursor") or params.get("cursor")
    rank_param = params.get("rank")
    rank: str | None
    if rank_param is None:
        rank = None
    else:
        rank = str(rank_param)
        if rank not in {"simple"}:
            raise ValueError("rank must be one of: simple")

    k_param = params.get("k")
    k: int | None = None
    if k_param is not None:
        k = int(k_param)
        if k <= 0:
            raise ValueError("k must be a positive integer")
        if rank != "simple":
            raise ValueError('k requires rank="simple"')
    if cursor_param is not None and rank is not None:
        raise ValueError("cursor pagination cannot be combined with rank")

    context_param = params.get("context_lines", 0)
    context_lines = int(context_param)
    if context_lines < 0 or context_lines > 16:
        raise ValueError("context_lines must be between 0 and 16")

    return functions.search_functions(
        client,
        query=query,
        limit=limit,
        page=page,
        rank=rank,
        k=k,
        resume_cursor=str(cursor_param) if cursor_param is not None else None,
        context_lines=context_lines,
    )


def _op_search_xrefs_to(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    address = str(_require(params, "address"))
    query = str(params.get("query", ""))
    limit = int(params.get("limit", 100))
    page = int(params.get("page", 1))
    if limit <= 0:
        raise ValueError("limit must be positive")
    if page <= 0:
        raise ValueError("page must be positive")
    return xrefs.search_xrefs_to(client, address=address, query=query, limit=limit, page=page)


def _op_search_scalars(client: GhidraClient, params: Mapping[str, object]) -> Mapping[str, object]:
    value = params.get("value")
    if value is None:
        raise KeyError("Missing required parameter: value")
    query = str(params.get("query", value))
    limit = int(params.get("limit", 50))
    page = int(params.get("page", 1))
    cursor_param = params.get("resume_cursor") or params.get("cursor")
    if limit <= 0:
        raise ValueError("limit must be positive")
    if page <= 0:
        raise ValueError("page must be positive")
    return scalars.search_scalars(
        client,
        value=value,
        query=query,
        limit=limit,
        page=page,
        resume_cursor=str(cursor_param) if cursor_param is not None else None,
    )


def _op_search_scalars_with_context(
    client: GhidraClient, params: Mapping[str, object]
) -> Mapping[str, object]:
    value_raw = _require(params, "value")
    value = parse_hex(str(value_raw)) if isinstance(value_raw, str) else int(value_raw)
    context_lines = int(params.get("context_lines", 4))
    limit = int(params.get("limit", 25))
    if context_lines < 0 or context_lines > 16:
        raise ValueError("context_lines must be between 0 and 16")
    if limit <= 0:
        raise ValueError("limit must be positive")
    context_window = context_lines * 2 + 1
    enforce_batch_limit(context_window, counter="search_scalars_with_context.window")
    return batch_ops.search_scalars_with_context(
        client,
        value=value,
        context_lines=context_lines,
        limit=limit,
    )


_OPERATIONS: Dict[str, OperationHandler] = {
    "disassemble_at": _op_disassemble_at,
    "disassemble_batch": _op_disassemble_batch,
    "read_bytes": _op_read_bytes,
    "read_words": _op_read_words,
    "search_strings": _op_search_strings,
    "strings_compact": _op_strings_compact,
    "string_xrefs": _op_string_xrefs,
    "search_imports": _op_search_imports,
    "search_exports": _op_search_exports,
    "search_functions": _op_search_functions,
    "search_xrefs_to": _op_search_xrefs_to,
    "search_scalars": _op_search_scalars,
    "search_scalars_with_context": _op_search_scalars_with_context,
}


def execute_collect(
    client: GhidraClient,
    queries: Sequence[Mapping[str, object]],
    *,
    result_budget: Mapping[str, object] | None = None,
) -> Dict[str, object]:
    """Execute a batch of read-only feature operations."""

    enforce_batch_limit(len(queries), counter="collect.queries")
    increment_counter("collect.query_count", len(queries))

    request_budget = _budget_from_payload(result_budget)

    results: List[Dict[str, object]] = []
    total_estimate = 0

    for raw_query in queries:
        if isinstance(raw_query, Mapping):
            query, alias_notes = _normalize_query_payload(raw_query)
        else:  # pragma: no cover - defensive guard
            query = raw_query
            alias_notes = []

        qid = str(query.get("id", "")) if query.get("id") is not None else ""
        if not qid:
            qid = ""
        op = str(query.get("op", ""))
        params_raw = query.get("params") or {}
        notes: List[str] = list(alias_notes)
        if not isinstance(params_raw, Mapping):
            envelope = _envelope_error(
                ErrorCode.INVALID_REQUEST, "params must be an object"
            )
            meta: Dict[str, object] = {
                "estimate_tokens": 0,
                "max_result_tokens": query.get("max_result_tokens"),
                "truncated": False,
            }
            if notes:
                meta["notes"] = notes
            results.append(
                {
                    "id": qid,
                    "op": op,
                    "result": envelope,
                    "meta": meta,
                }
            )
            continue

        handler = _OPERATIONS.get(op)
        if handler is None:
            envelope = _envelope_error(ErrorCode.INVALID_REQUEST, f"Unsupported op: {op}")
            results.append(
                {
                    "id": qid,
                    "op": op,
                    "result": envelope,
                    "meta": {
                        "estimate_tokens": 0,
                        "max_result_tokens": query.get("max_result_tokens"),
                        "truncated": False,
                        "notes": ["unsupported_op", *notes] if notes else ["unsupported_op"],
                    },
                }
            )
            continue

        per_query_budget = _budget_from_payload(
            query.get("result_budget") if isinstance(query, Mapping) else None,
            fallback_max=_coerce_int(query.get("max_result_tokens"))
            if isinstance(query, Mapping)
            else None,
        )

        truncated = False
        estimate_tokens = 0

        try:
            payload = handler(client, params_raw)
        except SafetyLimitExceeded as exc:
            envelope = _envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
        except (KeyError, TypeError, ValueError) as exc:
            envelope = _envelope_error(ErrorCode.INVALID_REQUEST, str(exc))
        else:
            estimate_tokens = _estimate_tokens(payload)
            try:
                allowed = per_query_budget.account(estimate_tokens)
            except SafetyLimitExceeded as exc:
                truncated = True
                envelope = _envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
            else:
                if not allowed:
                    truncated = True
                    envelope = _envelope_error(
                        ErrorCode.RESULT_TOO_LARGE,
                        "Sub-result exceeds max_result_tokens budget.",
                    )
                else:
                    envelope = _envelope_ok(payload)
                    request_allowed = request_budget.account(estimate_tokens)
                    total_estimate = request_budget.consumed
                    if not request_allowed:
                        truncated = True
                        notes.append("request_budget_exceeded")
                        envelope = _envelope_error(
                            ErrorCode.RESULT_TOO_LARGE,
                            "Request-level result budget exceeded; sub-result omitted.",
                        )

        meta: MutableMapping[str, object] = {
            "estimate_tokens": estimate_tokens,
            "max_result_tokens": query.get("max_result_tokens")
            if isinstance(query, Mapping)
            else None,
            "truncated": truncated,
        }
        budget_meta = per_query_budget.to_meta()
        if any(value is not None for value in budget_meta.values()):
            meta["budget"] = budget_meta
        if notes:
            meta["notes"] = notes

        results.append({"id": qid, "op": op, "result": envelope, "meta": dict(meta)})

    response_meta: Dict[str, object] = {
        "estimate_tokens": total_estimate,
    }
    budget_summary = request_budget.to_meta()
    if any(value is not None for value in budget_summary.values()):
        response_meta["result_budget"] = budget_summary

    return {"queries": results, "meta": response_meta}


__all__ = ["execute_collect"]
