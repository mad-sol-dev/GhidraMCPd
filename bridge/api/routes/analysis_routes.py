from __future__ import annotations

from typing import List, Mapping

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features import analyze
from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.hex import parse_hex
from ...utils.logging import SafetyLimitExceeded, request_scope
from .._shared import envelope_ok, envelope_response, error_response
from ..validators import validate_payload
from ._common import RouteDependencies


def create_analysis_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def analyze_function_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "analyze_function_complete",
            logger=deps.logger,
            extra={"path": "/api/analyze_function_complete.json"},
        ):
            data = await deps.validated_json_body(
                request, "analyze_function_complete.request.v1.json"
            )
            try:
                address = parse_hex(str(data["address"]))
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))

            fields = data.get("fields")
            if fields is not None and not isinstance(fields, list):
                return error_response(
                    ErrorCode.INVALID_REQUEST, "fields must be an array when provided"
                )

            try:
                payload = analyze.analyze_function_complete(
                    client,
                    address=address,
                    fields=fields,
                    fmt=str(data.get("fmt", "json")),
                    max_result_tokens=(
                        int(data["max_result_tokens"])
                        if "max_result_tokens" in data
                        else None
                    ),
                    options=_coerce_mapping(data.get("options")),
                )
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except ValueError as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))

            valid, errors = validate_payload(
                "analyze_function_complete.v1.json", payload
            )
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [
        Route(
            "/api/analyze_function_complete.json",
            analyze_function_route,
            methods=["POST"],
        )
    ]


def _coerce_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


__all__ = ["create_analysis_routes"]
