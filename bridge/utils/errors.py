"""Error codes and helpers for the bridge server."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence


class ErrorCode(str, Enum):
    """Stable error codes returned from the deterministic endpoints."""

    INVALID_REQUEST = "INVALID_REQUEST"
    RESULT_TOO_LARGE = "RESULT_TOO_LARGE"
    NOT_READY = "NOT_READY"
    SSE_CONFLICT = "SSE_CONFLICT"
    TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"
    INTERNAL = "INTERNAL"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class ErrorTemplate:
    """Default status, message, and recovery hints for an error code."""

    status: int
    message: str
    recovery: Sequence[str] = ()


_TEMPLATES: Mapping[ErrorCode, ErrorTemplate] = {
    ErrorCode.INVALID_REQUEST: ErrorTemplate(
        status=400,
        message="Request was malformed or failed validation.",
        recovery=(
            "Check required fields and value formats.",
        ),
    ),
    ErrorCode.RESULT_TOO_LARGE: ErrorTemplate(
        status=413,
        message="Result exceeds configured limits.",
        recovery=(
            "Narrow the scope or reduce limits to shrink the result.",
        ),
    ),
    ErrorCode.NOT_READY: ErrorTemplate(
        status=425,
        message="Bridge is not ready yet.",
        recovery=(
            "Retry after the MCP bridge reports initialization complete.",
        ),
    ),
    ErrorCode.SSE_CONFLICT: ErrorTemplate(
        status=409,
        message="Server-sent events stream already active.",
        recovery=(
            "Disconnect the existing SSE client before reconnecting.",
        ),
    ),
    ErrorCode.TOO_MANY_REQUESTS: ErrorTemplate(
        status=429,
        message="Too many requests in flight.",
        recovery=(
            "Back off and retry with fewer concurrent requests.",
        ),
    ),
    ErrorCode.INTERNAL: ErrorTemplate(
        status=500,
        message="Internal server error.",
        recovery=(
            "Retry the request or contact support with request logs.",
        ),
    ),
    ErrorCode.UNAVAILABLE: ErrorTemplate(
        status=503,
        message="Required upstream data is unavailable.",
        recovery=(
            "Ensure a program is open in Ghidra and try again.",
        ),
    ),
}


class DetailCode(str, Enum):
    """Error codes embedded in result items for legacy compatibility."""

    ARM_INSTRUCTION = "ARM_INSTRUCTION"
    OUT_OF_RANGE = "OUT_OF_RANGE"
    NO_FUNCTION_AT_TARGET = "NO_FUNCTION_AT_TARGET"
    TOOL_BINDING_MISSING = "TOOL_BINDING_MISSING"
    WRITE_DISABLED_DRY_RUN = "WRITE_DISABLED_DRY_RUN"
    WRITE_VERIFY_FAILED = "WRITE_VERIFY_FAILED"


def _resolve_template(code: ErrorCode) -> ErrorTemplate:
    try:
        return _TEMPLATES[code]
    except KeyError:  # pragma: no cover - defensive guard
        raise ValueError(f"No error template registered for {code!s}") from None


def make_error(
    code: ErrorCode,
    message: Optional[str] = None,
    *,
    recovery: Optional[Iterable[str]] = None,
    status: Optional[int] = None,
) -> Dict[str, object]:
    """Create a JSON-serialisable error dict."""

    template = _resolve_template(code)
    resolved_message = message if message is not None else template.message
    resolved_status = status if status is not None else template.status
    resolved_recovery: List[str] = list(recovery) if recovery is not None else list(
        template.recovery
    )
    payload: MutableMapping[str, object] = {
        "status": int(resolved_status),
        "code": code.value,
        "message": resolved_message,
        "recovery": resolved_recovery,
    }
    return dict(payload)


__all__ = ["ErrorCode", "DetailCode", "ErrorTemplate", "make_error"]
