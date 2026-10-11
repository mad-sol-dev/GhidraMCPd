"""Error codes and helpers for the bridge server."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence


class UpstreamFailed(RuntimeError):
    """The plugin did not answer the question; the reason is the message.

    Raised where a failed request would otherwise read as an empty result --
    "no matches" is a statement about the program, a failed search is not.
    ``code`` and ``status`` are the plugin's (API 2: INVALID_REQUEST,
    NOT_FOUND, UNMAPPED, CONFLICT, NOT_READY, INTERNAL), or PLUGIN_TOO_OLD/_NEW, or
    None for a transport failure.
    """

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        status: Optional[int] = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.retryable = retryable


def upstream_failure_error(exc: "UpstreamFailed") -> Dict[str, object]:
    """The error entry for a failed plugin request, by the plugin's own code.

    A 400/404/409 from the plugin is about the request -- a bad name, nothing
    at that address, a name that exists -- and keeps its status; a plugin that
    could not answer is UNAVAILABLE.  Before API 2 all of these were HTTP 200.
    """

    code = exc.code
    if code in ("INVALID_REQUEST", "NOT_FOUND", "UNMAPPED", "CONFLICT"):
        status = exc.status or {"INVALID_REQUEST": 400, "CONFLICT": 409}.get(code, 404)
        return make_error(ErrorCode.INVALID_REQUEST, message=str(exc), status=status, recovery=(
            "Nothing was changed; the plugin refused the request as it stands.",
        ))
    if code == "PLUGIN_TOO_OLD":
        return make_error(ErrorCode.UNAVAILABLE, message=str(exc), recovery=(
            "Build and install the GhidraMCP extension from this repository, then restart Ghidra.",
            "Check the installed build with GET /plugin_version on the plugin port.",
        ))
    if code == "PLUGIN_TOO_NEW":
        return make_error(ErrorCode.UNAVAILABLE, message=str(exc), recovery=(
            "Update the bridge to the repository version the plugin was built from, then restart it.",
            "Check the plugin's API with GET /plugin_version on the plugin port.",
        ))
    if code == "NOT_READY":
        return make_error(ErrorCode.UNAVAILABLE, message=str(exc), recovery=(
            "Open a program in Ghidra (a CodeBrowser window), then retry.",
        ))
    recovery = ("Retry; the plugin or the connection failed.",) if exc.retryable else (
        "Ghidra failed doing this; the message says how.",
    )
    return make_error(ErrorCode.UNAVAILABLE, message=str(exc), recovery=recovery)


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
