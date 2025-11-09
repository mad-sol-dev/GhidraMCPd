from __future__ import annotations

from typing import List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features import mmio
from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.hex import parse_hex
from ...utils.logging import SafetyLimitExceeded, request_scope
from .._shared import envelope_ok, envelope_response, error_response
from ..validators import validate_payload
from ._common import RouteDependencies


def create_mmio_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def mmio_annotate_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "mmio_annotate",
            logger=deps.logger,
            extra={"path": "/api/mmio_annotate.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "mmio_annotate.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                payload = mmio.annotate(
                    client,
                    function_addr=parse_hex(str(data["function_addr"])),
                    dry_run=bool(data.get("dry_run", True)),
                    max_samples=int(data.get("max_samples", 8)),
                    writes_enabled=deps.enable_writes,
                )
            except mmio.WritesDisabledError:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "Writes are disabled while dry_run is false.",
                    recovery=("Enable writes or run in dry_run mode.",),
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("mmio_annotate.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [Route("/api/mmio_annotate.json", mmio_annotate_route, methods=["POST"])]
