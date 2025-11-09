from __future__ import annotations

from typing import Any, Dict, List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.logging import request_scope
from .._shared import envelope_ok, envelope_response, error_response
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
                return error_response(ErrorCode.UNAVAILABLE)
            normalized = _normalise_project_info(payload)
            return envelope_response(envelope_ok(normalized))

    return [
        Route(
            "/api/project_info.json",
            project_info_route,
            methods=["GET", "HEAD"],
            name="project_info",
        )
    ]


def _normalise_project_info(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the payload with deterministic ordering applied."""

    data = dict(payload)

    entry_points = payload.get("entry_points")
    if isinstance(entry_points, list):
        data["entry_points"] = sorted(
            (value for value in entry_points if isinstance(value, str))
        )

    blocks = payload.get("memory_blocks")
    if isinstance(blocks, list):
        normalised_blocks: List[Dict[str, Any]] = []
        for block in blocks:
            if isinstance(block, dict):
                normalised_blocks.append(dict(block))
        normalised_blocks.sort(key=_block_sort_key)
        data["memory_blocks"] = normalised_blocks

    return data


def _block_sort_key(block: Dict[str, Any]) -> tuple[int, str]:
    start = block.get("start")
    if isinstance(start, str):
        try:
            value = int(start, 16)
        except ValueError:
            pass
        else:
            return (0, f"{value:016x}")
    return (1, str(start))
