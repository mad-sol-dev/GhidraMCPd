from __future__ import annotations

from typing import List, Mapping

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features.collect import execute_collect
from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.logging import SafetyLimitExceeded, request_scope
from .._shared import envelope_error, envelope_ok, envelope_response
from ..validators import validate_payload
from ._common import RouteDependencies


def create_collect_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def collect_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "collect",
            logger=deps.logger,
            extra={"path": "/api/collect.json"},
        ):
            try:
                data = await deps.validated_json_body(
                    request, "collect.request.v1.json"
                )
            except ValueError as exc:
                return envelope_response(envelope_error(ErrorCode.INVALID_REQUEST, str(exc)))

            queries = data.get("queries", [])
            result_budget = data.get("result_budget")
            if not isinstance(queries, list):
                return envelope_response(
                    envelope_error(ErrorCode.INVALID_REQUEST, "queries must be an array"),
                )

            try:
                payload = execute_collect(
                    client,
                    queries,
                    result_budget=result_budget
                    if isinstance(result_budget, Mapping)
                    else None,
                )
            except SafetyLimitExceeded as exc:
                return envelope_response(
                    envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
                )
            except (KeyError, TypeError, ValueError) as exc:
                return envelope_response(
                    envelope_error(ErrorCode.INVALID_REQUEST, str(exc))
                )

            valid, errors = validate_payload("collect.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [Route("/api/collect.json", collect_route, methods=["POST"])]


__all__ = ["create_collect_routes"]
