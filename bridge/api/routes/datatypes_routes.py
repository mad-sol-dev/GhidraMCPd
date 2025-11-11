from __future__ import annotations

from typing import List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features import datatypes
from ...ghidra.client import GhidraClient
from ...utils.config import MAX_WRITES_PER_REQUEST
from ...utils.errors import ErrorCode
from ...utils.logging import SafetyLimitExceeded, request_scope
from .._shared import envelope_error, envelope_ok, envelope_response, error_response
from ..validators import validate_payload
from ._common import RouteDependencies


def create_datatype_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def create_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "create_datatype",
            logger=deps.logger,
            extra={"path": "/api/datatypes/create.json"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            data = await deps.validated_json_body(
                request, "datatypes_create.request.v1.json"
            )
            try:
                payload = datatypes.create_datatype(
                    client,
                    kind=str(data["kind"]),
                    name=str(data["name"]),
                    category=str(data["category"]),
                    fields=list(data["fields"]),
                    dry_run=bool(data.get("dry_run", True)),
                    writes_enabled=deps.enable_writes,
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("datatypes_create.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def update_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "update_datatype",
            logger=deps.logger,
            extra={"path": "/api/datatypes/update.json"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            data = await deps.validated_json_body(
                request, "datatypes_update.request.v1.json"
            )
            try:
                payload = datatypes.update_datatype(
                    client,
                    kind=str(data["kind"]),
                    path=str(data["path"]),
                    fields=list(data["fields"]),
                    dry_run=bool(data.get("dry_run", True)),
                    writes_enabled=deps.enable_writes,
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("datatypes_update.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def delete_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "delete_datatype",
            logger=deps.logger,
            extra={"path": "/api/datatypes/delete.json"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            data = await deps.validated_json_body(
                request, "datatypes_delete.request.v1.json"
            )
            try:
                payload = datatypes.delete_datatype(
                    client,
                    kind=str(data["kind"]),
                    path=str(data["path"]),
                    dry_run=bool(data.get("dry_run", True)),
                    writes_enabled=deps.enable_writes,
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("datatypes_delete.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [
        Route("/api/datatypes/create.json", create_route, methods=["POST"]),
        Route("/api/datatypes/update.json", update_route, methods=["POST"]),
        Route("/api/datatypes/delete.json", delete_route, methods=["POST"]),
    ]


__all__ = ["create_datatype_routes"]
