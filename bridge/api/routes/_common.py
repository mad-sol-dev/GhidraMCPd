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
from ..validators import validate_payload
from .._shared import error_response

JsonBody = Tuple[Dict[str, object] | None, JSONResponse | None]
RouteHandler = Callable[[Request, GhidraClient], Awaitable[JSONResponse]]
RouteDecorator = Callable[[RouteHandler], Callable[[Request], Awaitable[JSONResponse]]]
JsonBodyValidator = Callable[[Request, str], Awaitable[JsonBody]]


@dataclass(frozen=True)
class RouteDependencies:
    enable_writes: bool
    logger: logging.Logger
    validated_json_body: JsonBodyValidator
    with_client: RouteDecorator


async def validated_json_body(request: Request, schema: str) -> JsonBody:
    try:
        data = await request.json()
    except json.JSONDecodeError as exc:
        return (
            None,
            error_response(
                ErrorCode.INVALID_REQUEST,
                f"Invalid JSON payload: {exc.msg}",
            ),
        )

    if not isinstance(data, dict):
        return (
            None,
            error_response(
                ErrorCode.INVALID_REQUEST,
                "Payload must be a JSON object.",
            ),
        )

    valid, errors = validate_payload(schema, data)
    if not valid:
        return (
            None,
            error_response(
                ErrorCode.INVALID_REQUEST,
                "; ".join(errors),
            ),
        )
    return data, None


def build_with_client(
    factory: Callable[[], GhidraClient], *, enable_writes: bool, call_semaphore: asyncio.Semaphore
) -> RouteDecorator:
    def decorator(func: RouteHandler) -> Callable[[Request], Awaitable[JSONResponse]]:
        @wraps(func)
        async def wrapper(request: Request) -> JSONResponse:
            request.state.enable_writes = enable_writes
            client = factory()
            try:
                async with call_semaphore:
                    return await func(request, client)
            finally:
                client.close()

        return wrapper

    return decorator
