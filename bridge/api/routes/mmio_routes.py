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
from .._shared import envelope_error, envelope_ok
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
                return JSONResponse(
                    envelope_error(
                        ErrorCode.WRITE_DISABLED_DRY_RUN,
                        "Writes are disabled while dry_run is false.",
                    ),
                    status_code=400,
                )
            except (KeyError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)), status_code=400
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("mmio_annotate.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    return [Route("/api/mmio_annotate.json", mmio_annotate_route, methods=["POST"])]
