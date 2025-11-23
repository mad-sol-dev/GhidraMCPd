from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from functools import wraps
from typing import Awaitable, Callable, Dict, Tuple

from starlette.requests import Request
from starlette.responses import JSONResponse

from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.program_context import PROGRAM_SELECTIONS, requestor_from_request
from ..validators import validate_payload
from .._shared import error_response

JsonBody = Tuple[Dict[str, object] | None, JSONResponse | None]
RouteHandler = Callable[[Request, GhidraClient], Awaitable[JSONResponse]]
RouteDecorator = Callable[[RouteHandler], Callable[[Request], Awaitable[JSONResponse]]]
JsonBodyValidator = Callable[[Request, str], Awaitable[Dict[str, object]]]


@dataclass(frozen=True)
class RouteDependencies:
    enable_writes: bool
    logger: logging.Logger
    validated_json_body: JsonBodyValidator
    with_client: RouteDecorator
    client_factory: Callable[[], GhidraClient]


async def validated_json_body(request: Request, schema: str) -> Dict[str, object]:
    try:
        data = await request.json()
    except json.JSONDecodeError as exc:
        # Re-raise to let the central error handler catch it
        raise

    if not isinstance(data, dict):
        raise ValueError("Payload must be a JSON object.")

    valid, errors = validate_payload(schema, data)
    if not valid:
        raise ValueError("; ".join(errors))

    return data


def build_with_client(
    factory: Callable[[], GhidraClient], *, enable_writes: bool, call_semaphore: asyncio.Semaphore
) -> RouteDecorator:
    def decorator(func: RouteHandler) -> Callable[[Request], Awaitable[JSONResponse]]:
        @wraps(func)
        async def wrapper(request: Request) -> JSONResponse:
            request.state.enable_writes = enable_writes
            requestor = requestor_from_request(request)
            request.state.program_requestor = requestor
            skip_paths = {
                "/api/current_program.json",
                "/api/select_program.json",
                "/api/capabilities.json",
                "/api/health.json",
                "/openapi.json",
                "/state",
            }
            if request.url.path not in skip_paths:
                PROGRAM_SELECTIONS.mark_used(requestor)
            client = factory()
            try:
                async with call_semaphore:
                    return await func(request, client)
            finally:
                client.close()

        return wrapper

    return decorator
