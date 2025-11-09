"""Centralized error handling for validation errors."""
import logging
from typing import Any, Dict

from starlette.responses import JSONResponse
from starlette.requests import Request

log = logging.getLogger(__name__)

GENERIC_400 = {
    "status": 400,
    "code": "INVALID_REQUEST", 
    "message": "Request was malformed or failed validation.",
    "recovery": ["Check required fields and value formats."],
}

def make_400_response() -> Dict[str, Any]:
    """Create standardized 400 error response envelope."""
    return {
        "ok": False,
        "data": None,
        "errors": [GENERIC_400]
    }

def install_error_handlers(app) -> None:
    """Install error handlers on the Starlette app."""
    
    @app.exception_handler(400)
    async def _on_bad_request(request: Request, exc: Exception) -> JSONResponse:
        log.debug("bad request: %s", exc)
        return JSONResponse(
            status_code=400,
            content=make_400_response()
        )

    @app.exception_handler(ValueError)
    async def _on_value_error(request: Request, exc: ValueError) -> JSONResponse:
        log.debug("value error: %s", exc)
        return JSONResponse(
            status_code=400,
            content=make_400_response()
        )

    @app.exception_handler(TypeError)
    async def _on_type_error(request: Request, exc: TypeError) -> JSONResponse:
        log.debug("type error: %s", exc)
        return JSONResponse(
            status_code=400,
            content=make_400_response()
        )
"""Centralized error handling for validation errors."""
import logging
from typing import Any, Dict

from starlette.responses import JSONResponse
from starlette.requests import Request

log = logging.getLogger(__name__)

GENERIC_400 = {
    "status": 400,
    "code": "INVALID_REQUEST",
    "message": "Request was malformed or failed validation.",
    "recovery": ["Check required fields and value formats."],
}

def make_400_response() -> Dict[str, Any]:
    """Create standardized 400 error response envelope."""
    return {
        "ok": False,
        "data": None,
        "errors": [GENERIC_400]
    }

def install_error_handlers(app) -> None:
    """Install error handlers on the Starlette app."""
    
    @app.exception_handler(400)
    async def _on_bad_request(request: Request, exc: Exception) -> JSONResponse:
        log.debug("bad request: %s", exc)
        return JSONResponse(
            status_code=400,
            content=make_400_response()
        )

    @app.exception_handler(ValueError)
    async def _on_value_error(request: Request, exc: ValueError) -> JSONResponse:
        log.debug("value error: %s", exc)
        return JSONResponse(
            status_code=400,
            content=make_400_response()
        )

    @app.exception_handler(TypeError)
    async def _on_type_error(request: Request, exc: TypeError) -> JSONResponse:
        log.debug("type error: %s", exc)
        return JSONResponse(
            status_code=400,
            content=make_400_response()
        )
