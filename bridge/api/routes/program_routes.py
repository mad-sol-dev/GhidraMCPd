from __future__ import annotations

from typing import List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...utils.errors import ErrorCode
from ...utils.logging import request_scope
from ...utils.program_context import (
    PROGRAM_SELECTIONS,
    ProgramSelectionError,
    lock_selection_for_requestor,
    normalize_selection,
    requestor_from_request,
    validate_program_id,
)
from ..tools import _maybe_autoopen_program
from .._shared import envelope_error, envelope_ok, envelope_response
from ..validators import validate_payload
from ._common import RouteDependencies


def create_program_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def current_program_route(request: Request, client) -> JSONResponse:
        with request_scope(
            "current_program",
            logger=deps.logger,
            extra={"path": "/api/current_program.json"},
        ):
            requestor = getattr(request.state, "program_requestor", None) or requestor_from_request(
                request
            )
            files = client.get_project_files()

            if files is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_response(
                    envelope_error(
                        ErrorCode.UNAVAILABLE,
                        "Failed to enumerate project files.",
                        upstream_error=upstream,
                        recovery=("Ensure a project is open in Ghidra.",),
                        status=503,
                    )
                )

            try:
                selection = normalize_selection(files, requestor=requestor)
            except ProgramSelectionError as exc:
                message = (
                    "Program selection is locked for this session; "
                    f"previous selection '{exc.current}' is unavailable."
                )
                return envelope_response(
                    envelope_error(
                        ErrorCode.INVALID_REQUEST,
                        message,
                        recovery=("Start a new session to switch programs.",),
                        status=400,
                    )
                )
            state = selection.state
            warnings: list[str] = []
            if selection.warning:
                warnings.append(selection.warning)
            if state.domain_file_id is None:
                return envelope_response(
                    envelope_error(
                        ErrorCode.UNAVAILABLE,
                        "No program files are available in the current project.",
                        recovery=("Open a program in Ghidra and retry.",),
                        status=503,
                    )
                )

            payload = {"domain_file_id": state.domain_file_id, "locked": state.locked}
            if warnings:
                payload["warnings"] = warnings
            valid, errors = validate_payload("current_program.v1.json", payload)
            if not valid:
                return envelope_response(
                    envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
                )
            return envelope_response(envelope_ok(payload))

    @deps.with_client
    async def select_program_route(request: Request, client) -> JSONResponse:
        with request_scope(
            "select_program",
            logger=deps.logger,
            extra={"path": "/api/select_program.json"},
        ):
            data = await deps.validated_json_body(request, "select_program.request.v1.json")
            domain_file_id = str(data.get("domain_file_id", "")).strip()
            requestor = getattr(request.state, "program_requestor", None) or requestor_from_request(
                request
            )
            files = client.get_project_files()

            if files is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_response(
                    envelope_error(
                        ErrorCode.UNAVAILABLE,
                        "Failed to enumerate project files.",
                        upstream_error=upstream,
                        recovery=("Ensure a project is open in Ghidra.",),
                        status=503,
                    )
                )

            if not validate_program_id(files, domain_file_id):
                return envelope_response(
                    envelope_error(
                        ErrorCode.INVALID_REQUEST,
                        f"Unknown program id '{domain_file_id}'.",
                        recovery=("Use a domain_file_id from /api/project_overview.json.",),
                        status=400,
                    )
                )

            try:
                selection = PROGRAM_SELECTIONS.select(requestor, domain_file_id)
            except ProgramSelectionError as exc:
                message = (
                    "Program selection is locked for this session; "
                    f"currently using '{exc.current}'."
                )
                return envelope_response(
                    envelope_error(
                        ErrorCode.INVALID_REQUEST,
                        message,
                        recovery=("Start a new session to switch programs.",),
                        status=400,
                    )
                )
            lock_selection_for_requestor(requestor)
            state = selection.state
            warnings: list[str] = []
            if selection.warning:
                warnings.append(selection.warning)
            autoopen_warnings, autoopen_error = _maybe_autoopen_program(
                client, files, state.domain_file_id
            )
            if autoopen_error:
                return envelope_response(autoopen_error)
            warnings.extend(autoopen_warnings)

            payload = {"domain_file_id": state.domain_file_id, "locked": state.locked}
            if warnings:
                payload["warnings"] = warnings
            valid, errors = validate_payload("current_program.v1.json", payload)
            if not valid:
                return envelope_response(
                    envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
                )
            return envelope_response(envelope_ok(payload))

    return [
        Route(
            "/api/current_program.json",
            current_program_route,
            methods=["GET", "HEAD"],
            name="current_program",
        ),
        Route(
            "/api/select_program.json",
            select_program_route,
            methods=["POST"],
            name="select_program",
        ),
    ]


__all__ = ["create_program_routes"]
