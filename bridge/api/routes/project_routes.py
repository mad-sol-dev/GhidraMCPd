from __future__ import annotations

from typing import List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...ghidra.client import GhidraClient
from ...utils.logging import request_scope
from .._shared import envelope_error, envelope_ok
from ._common import RouteDependencies


def create_project_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def project_info_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "project_info",
            logger=deps.logger,
            extra={"path": "/api/project_info.json"},
        ):
            payload = client.get_project_info()
            if payload is None:
                return JSONResponse(
                    envelope_error(
                        "PROGRAM_NOT_AVAILABLE",
                        "No program is currently loaded or metadata is unavailable.",
                    ),
                    status_code=404,
                )
            return JSONResponse(envelope_ok(payload))

    return [
        Route(
            "/api/project_info.json",
            project_info_route,
            methods=["GET", "HEAD"],
            name="project_info",
        )
    ]
