"""Centralized error handling for validation errors."""
import json
import logging
import uuid
from typing import Any, Dict, Optional

from starlette.responses import JSONResponse
from starlette.requests import Request

from .utils.logging import current_request

log = logging.getLogger(__name__)

GENERIC_400 = {
    "status": 400,
    "code": "INVALID_REQUEST",
    "message": "Request was malformed or failed validation.",
    "recovery": ["Check required fields and value formats."],
}


def _correlation_id() -> str:
    context = current_request()
    if context is not None:
        return context.request_id
    return uuid.uuid4().hex


def make_400_response(
    *,
    debug: bool = False,
    correlation_id: Optional[str] = None,
    summary: Optional[str] = None,
) -> Dict[str, Any]:
    """Create standardized 400 error response envelope."""
    payload = {
        "ok": False,
        "data": None,
        "errors": [GENERIC_400],
    }

    if not debug:
        meta: Dict[str, str] = {}
        if correlation_id:
            meta["correlation_id"] = correlation_id
        if summary:
            meta["summary"] = summary
        if meta:
            payload["meta"] = meta

    return payload


def _render_validation_error(
    request: Request, exc: Exception, summary: str
) -> JSONResponse:
    correlation_id = _correlation_id()
    log.warning(
        "%s: %s", summary, exc, extra={"correlation_id": correlation_id}
    )
    debug = getattr(request.app, "debug", False)
    return JSONResponse(
        status_code=400,
        content=make_400_response(
            debug=debug, correlation_id=correlation_id, summary=summary
        ),
    )

def install_error_handlers(app) -> None:
    """Install error handlers on the Starlette app."""

    async def _on_bad_request(request: Request, exc: Exception) -> JSONResponse:
        return _render_validation_error(request, exc, "bad_request")

    async def _on_json_decode_error(request: Request, exc: json.JSONDecodeError) -> JSONResponse:
        return _render_validation_error(request, exc, "json_decode_error")

    async def _on_value_error(request: Request, exc: ValueError) -> JSONResponse:
        return _render_validation_error(request, exc, "value_error")

    async def _on_type_error(request: Request, exc: TypeError) -> JSONResponse:
        return _render_validation_error(request, exc, "type_error")

    app.add_exception_handler(400, _on_bad_request)
    app.add_exception_handler(json.JSONDecodeError, _on_json_decode_error)
    app.add_exception_handler(ValueError, _on_value_error)
    app.add_exception_handler(TypeError, _on_type_error)
