from __future__ import annotations

from typing import List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features import memory
from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.hex import parse_hex
from ...utils.logging import SafetyLimitExceeded, request_scope
from .._shared import envelope_ok, envelope_response, error_response
from ..validators import validate_payload
from ._common import RouteDependencies


def create_memory_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def read_bytes_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "read_bytes",
            logger=deps.logger,
            extra={"path": "/api/read_bytes.json"},
        ):
            data = await deps.validated_json_body(
                request, "read_bytes.request.v1.json"
            )
            try:
                payload = memory.read_bytes(
                    client,
                    address=parse_hex(str(data["address"])),
                    length=int(data["length"]),
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("read_bytes.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [Route("/api/read_bytes.json", read_bytes_route, methods=["POST"])]
