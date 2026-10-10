"""Shared helpers for tools and HTTP routes."""
from __future__ import annotations

import inspect
import os
from functools import wraps
from typing import Callable, Dict, Sequence

from starlette.responses import JSONResponse

from ..adapters import ArchAdapter, load_optional_adapter, optional_adapter_names
from ..adapters.arm_thumb import ARMThumbAdapter
from ..adapters.fallback import FallbackAdapter
from ..ghidra.client import GhidraClient, RequestError
from ..utils.errors import ErrorCode, make_error


def envelope_ok(data: Dict[str, object]) -> Dict[str, object]:
    return {"ok": True, "data": data, "errors": []}


def envelope_error(
    code: ErrorCode,
    message: str | None = None,
    *,
    recovery: tuple[str, ...] | None = None,
    status: int | None = None,
    upstream_error: dict | None = None,
) -> Dict[str, object]:
    error_payload = make_error(
        code,
        message=message,
        recovery=recovery,
        status=status,
    )
    if upstream_error is not None:
        error_payload = dict(error_payload)
        error_payload["upstream"] = upstream_error
    return {
        "ok": False,
        "data": None,
        "errors": [error_payload],
    }


def response_schema_error(schema: str, errors: Sequence[str]) -> Dict[str, object]:
    """The bridge's own answer failed its schema: a server fault, not a bad request.

    These sites used to answer INVALID_REQUEST, which sends the caller looking
    through arguments that were fine -- COLLECT-METADATA-REJECTED presented as
    exactly that.  The message names the schema, so the defect can be found.
    """

    return envelope_error(
        ErrorCode.INTERNAL,
        f"response failed its own schema {schema}: " + "; ".join(errors),
        recovery=(
            "The request was valid; this is a defect in the bridge. Report the tool, "
            "its arguments and this message.",
        ),
    )


def write_refusal_envelope(refusal: RequestError) -> Dict[str, object]:
    """A write the program check stopped (R.26), as the call's answer.

    Replaces whatever the tool made of the failed request ("Failed to rename",
    UNAVAILABLE): the request was well-formed, it named the wrong program.  A
    call that writes several times stops being trustworthy at the first
    refusal, so the answer is the refusal even if earlier writes went through.
    """

    if refusal.retryable:
        recovery: tuple[str, ...] = ("Retry once Ghidra answers; nothing was written.",)
    else:
        recovery = (
            "Make the session's program active in Ghidra again, or call select_program "
            "for the program that is active now.",
            "A call with several writes stops at the first refusal; writes before it "
            "were applied (check_dirty_state shows whether anything changed).",
        )
    return envelope_error(
        ErrorCode.UNAVAILABLE if refusal.retryable else ErrorCode.INVALID_REQUEST,
        refusal.reason,
        recovery=recovery,
        status=503 if refusal.retryable else 409,
        upstream_error=refusal.as_dict(),
    )


def envelope_response(payload: Dict[str, object]) -> JSONResponse:
    status = 200
    if not payload.get("ok"):
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            status = int(first.get("status", 500))
        else:
            status = 500
    return JSONResponse(payload, status_code=status)


def error_response(
    code: ErrorCode,
    message: str | None = None,
    *,
    recovery: tuple[str, ...] | None = None,
    upstream_error: dict | None = None,
    status: int | None = None,
) -> JSONResponse:
    return envelope_response(
        envelope_error(
            code,
            message,
            recovery=recovery,
            upstream_error=upstream_error,
            status=status,
        )
    )


def adapter_for_arch(arch: str) -> ArchAdapter:
    normalized = arch.lower()
    if normalized in {"arm", "auto", "thumb"}:
        return ARMThumbAdapter()

    enabled = os.getenv("BRIDGE_OPTIONAL_ADAPTERS", "")
    if enabled:
        requested = {
            item.strip().lower()
            for item in enabled.split(",")
            if item.strip()
        }
        registry = optional_adapter_names()
        if normalized in requested and normalized in registry:
            return load_optional_adapter(normalized)

    return FallbackAdapter()


def inject_client(factory: Callable[[], GhidraClient]):
    """Inject a :class:`GhidraClient` and hide it from the published signature."""

    def decorator(func):
        sig = inspect.signature(func)
        params = list(sig.parameters.values())
        if not params:
            raise TypeError("inject_client requires a function that accepts a client parameter")

        public_params = params[1:]
        public_signature = inspect.Signature(
            public_params, return_annotation=sig.return_annotation
        )

        @wraps(func)
        def wrapper(*args, **kwargs):
            client = factory()
            try:
                return func(client, *args, **kwargs)
            finally:
                client.close()

        wrapper.__signature__ = public_signature
        return wrapper

    return decorator


def with_client(factory: Callable[[], GhidraClient]):
    """Helper used by HTTP routes that need explicit client injection."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client = factory()
            try:
                return func(client, *args, **kwargs)
            finally:
                client.close()

        return wrapper

    return decorator
