from __future__ import annotations

from typing import List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...adapters import ArchAdapter
from ...features import jt
from ...ghidra.client import GhidraClient
from ...utils.config import MAX_WRITES_PER_REQUEST
from ...utils.errors import ErrorCode
from ...utils.hex import parse_hex
from ...utils.logging import SafetyLimitExceeded, request_scope
from .._shared import envelope_ok, envelope_response, error_response
from ..validators import validate_payload
from ._common import RouteDependencies


def _resolve_adapter(arch: str) -> ArchAdapter:
    from . import adapter_for_arch

    return adapter_for_arch(arch)


def create_jt_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def jt_slot_check_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "jt_slot_check",
            logger=deps.logger,
            extra={"path": "/api/jt_slot_check.json"},
        ):
            data = await deps.validated_json_body(request, "jt_slot_check.request.v1.json")
            try:
                adapter = _resolve_adapter(str(data.get("arch", "auto")))
                payload = jt.slot_check(
                    client,
                    jt_base=parse_hex(str(data["jt_base"])),
                    slot_index=int(data["slot_index"]),
                    code_min=parse_hex(str(data["code_min"])),
                    code_max=parse_hex(str(data["code_max"])),
                    adapter=adapter,
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("jt_slot_check.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def jt_slot_process_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "jt_slot_process",
            logger=deps.logger,
            extra={"path": "/api/jt_slot_process.json"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            data = await deps.validated_json_body(
                request, "jt_slot_process.request.v1.json"
            )
            try:
                adapter = _resolve_adapter(str(data.get("arch", "auto")))
                payload = jt.slot_process(
                    client,
                    jt_base=parse_hex(str(data["jt_base"])),
                    slot_index=int(data["slot_index"]),
                    code_min=parse_hex(str(data["code_min"])),
                    code_max=parse_hex(str(data["code_max"])),
                    rename_pattern=str(data.get("rename_pattern", "{target}")),
                    comment=str(data.get("comment", "")),
                    adapter=adapter,
                    dry_run=bool(data.get("dry_run", True)),
                    writes_enabled=deps.enable_writes,
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("jt_slot_process.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def jt_scan_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "jt_scan",
            logger=deps.logger,
            extra={"path": "/api/jt_scan.json"},
        ):
            data = await deps.validated_json_body(request, "jt_scan.request.v1.json")
            try:
                adapter = _resolve_adapter(str(data.get("arch", "auto")))
                payload = jt.scan(
                    client,
                    jt_base=parse_hex(str(data["jt_base"])),
                    start=int(data["start"]),
                    count=int(data["count"]),
                    code_min=parse_hex(str(data["code_min"])),
                    code_max=parse_hex(str(data["code_max"])),
                    adapter=adapter,
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("jt_scan.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [
        Route("/api/jt_slot_check.json", jt_slot_check_route, methods=["POST"]),
        Route("/api/jt_slot_process.json", jt_slot_process_route, methods=["POST"]),
        Route("/api/jt_scan.json", jt_scan_route, methods=["POST"]),
    ]
