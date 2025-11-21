from __future__ import annotations

from typing import Any, Dict, List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features import project
from ...ghidra.client import GhidraClient
from ...utils import config
from ...utils.errors import ErrorCode
from ...utils.hex import parse_hex
from ...utils.logging import request_scope
from .._shared import envelope_ok, envelope_response, error_response, envelope_error
from ..validators import validate_payload
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
                upstream = client.last_error.as_dict() if client.last_error else None
                message = None
                status = None
                if upstream is not None:
                    message = f"Upstream request failed: {upstream.get('reason', '')}".strip()
                    status_val = upstream.get("status")
                    if isinstance(status_val, int):
                        status = status_val
                return error_response(
                    ErrorCode.UNAVAILABLE,
                    message or None,
                    upstream_error=upstream,
                    status=status,
                )
            normalized = _normalise_project_info(payload)
            return envelope_response(envelope_ok(normalized))

    @deps.with_client
    async def project_rebase_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "project_rebase",
            logger=deps.logger,
            extra={"path": "/api/project_rebase.json"},
            max_writes=1,
        ):
            data = await deps.validated_json_body(
                request, "project_rebase.request.v1.json"
            )
            try:
                payload = project.rebase_project(
                    client,
                    new_base=parse_hex(str(data["new_base"])),
                    dry_run=bool(data.get("dry_run", True)),
                    confirm=bool(data.get("confirm", False)),
                    writes_enabled=deps.enable_writes,
                    rebases_enabled=config.ENABLE_PROJECT_REBASE,
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            valid, errors = validate_payload("project_rebase.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def project_overview_route(
        request: Request, client: GhidraClient
    ) -> JSONResponse:
        with request_scope(
            "project_overview",
            logger=deps.logger,
            extra={"path": "/api/project_overview.json"},
        ):
            payload = client.get_project_files()
            if payload is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                message = None
                status = None
                if upstream is not None:
                    message = f"Upstream request failed: {upstream.get('reason', '')}".strip()
                    status_val = upstream.get("status")
                    if isinstance(status_val, int):
                        status = status_val
                return error_response(
                    ErrorCode.UNAVAILABLE,
                    message or None,
                    upstream_error=upstream,
                    status=status,
                )
            files = _normalise_project_files(payload)
            response = {"files": files}
            valid, errors = validate_payload("project_overview.v1.json", response)
            if valid:
                return envelope_response(envelope_ok(response))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [
        Route(
            "/api/project_info.json",
            project_info_route,
            methods=["GET", "HEAD"],
            name="project_info",
        ),
        Route(
            "/api/project_rebase.json",
            project_rebase_route,
            methods=["POST"],
            name="project_rebase",
        ),
        Route(
            "/api/project_overview.json",
            project_overview_route,
            methods=["GET", "HEAD"],
            name="project_overview",
        ),
    ]


def _normalise_project_files(payload: object) -> List[Dict[str, object]]:
    files: List[Dict[str, object]] = []
    if not isinstance(payload, list):
        return files
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get("type")
        if not isinstance(entry_type, str):
            continue
        entry_id = entry.get("domain_file_id")
        size = _coerce_int(entry.get("size"))
        files.append(
            {
                "domain_file_id": str(entry_id) if entry_id is not None else None,
                "name": str(entry.get("name", "")),
                "path": str(entry.get("path", "")),
                "type": entry_type,
                "size": size,
            }
        )
    return files


def _coerce_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


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
