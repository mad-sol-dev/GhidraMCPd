from __future__ import annotations

import asyncio
import logging
from time import perf_counter
from typing import Callable, List

import httpx

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...ghidra.client import GhidraClient
from ...utils.logging import request_scope
from .._shared import envelope_ok


def create_health_routes(
    client_factory: Callable[[], GhidraClient],
    enable_writes: bool,
    logger: logging.Logger,
    semaphore: asyncio.Semaphore,
) -> List[Route]:
    async def health_route(request: Request) -> JSONResponse:
        request.state.enable_writes = enable_writes
        client = client_factory()
        try:
            async with semaphore:
                with request_scope(
                    "health",
                    logger=logger,
                    extra={"path": "/api/health.json"},
                ):
                    upstream = {
                        "base_url": client.base_url,
                        "reachable": False,
                    }
                    start = perf_counter()
                    try:
                        response = client._session.get(client.base_url, timeout=2.0)
                    except httpx.HTTPError as exc:
                        duration_ms = (perf_counter() - start) * 1000.0
                        logger.warning(
                            "ghidra.request",
                            extra={
                                "method": "GET",
                                "path": "/",
                                "duration_ms": duration_ms,
                                "error": str(exc),
                            },
                        )
                        upstream["error"] = str(exc)
                    else:
                        duration_ms = (perf_counter() - start) * 1000.0
                        logger.info(
                            "ghidra.request",
                            extra={
                                "method": "GET",
                                "path": "/",
                                "status_code": response.status_code,
                                "duration_ms": duration_ms,
                            },
                        )
                        upstream["reachable"] = response.is_success
                        upstream["status_code"] = response.status_code
                    payload = {
                        "service": "ghidra-mcp-bridge",
                        "writes_enabled": enable_writes,
                        "ghidra": upstream,
                    }
                    return JSONResponse(envelope_ok(payload))
        finally:
            client.close()

    return [Route("/api/health.json", health_route, methods=["GET"])]
