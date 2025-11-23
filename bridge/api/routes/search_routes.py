from __future__ import annotations

from typing import List

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...features import (
    exports as export_features,
    function_range,
    functions,
    imports as import_features,
    scalars,
    strings,
    xrefs,
)
from ...ghidra.client import GhidraClient
from ...utils.errors import ErrorCode
from ...utils.hex import int_to_hex, parse_hex
from ...utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
    request_scope,
)
from .._shared import envelope_ok, envelope_response, error_response, envelope_error
from ..validators import validate_payload
from ._common import RouteDependencies


def _validate_pagination(limit: int, page: int) -> JSONResponse | None:
    if limit <= 0:
        return error_response(
            ErrorCode.INVALID_REQUEST,
            "limit must be a positive integer.",
        )
    if page <= 0:
        return error_response(
            ErrorCode.INVALID_REQUEST,
            "page must be a positive integer.",
        )
    return None


MAX_FUNCTION_CONTEXT_LINES = 16


def create_search_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def string_xrefs_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "string_xrefs",
            logger=deps.logger,
            extra={"path": "/api/string_xrefs.json"},
        ):
            data = await deps.validated_json_body(
                request, "string_xrefs.request.v1.json"
            )
            try:
                payload = strings.xrefs_compact(
                    client,
                    string_addr=parse_hex(str(data["string_addr"])),
                    limit=int(data.get("limit", 50)),
                )
            except (KeyError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("string_xrefs.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def search_strings_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_strings",
            logger=deps.logger,
            extra={"path": "/api/search_strings.json"},
        ):
            data = await deps.validated_json_body(
                request, "search_strings.request.v1.json"
            )
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                page = int(data.get("page", 1))
                include_literals = bool(data.get("include_literals", False))
            except (KeyError, TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            pagination_error = _validate_pagination(limit, page)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = strings.search_strings(
                    client,
                    query=query,
                    limit=limit,
                    page=page,
                    include_literals=include_literals,
                )
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("search_strings.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def strings_compact_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "strings_compact",
            logger=deps.logger,
            extra={"path": "/api/strings_compact.json"},
        ):
            data = await deps.validated_json_body(
                request, "strings_compact.request.v1.json"
            )
            try:
                limit = int(data.get("limit", 0))
                offset = int(data.get("offset", 0))
                include_literals = bool(data.get("include_literals", False))
            except (TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            if limit <= 0:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "limit must be a positive integer.",
                )
            if offset < 0:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "offset must be a non-negative integer.",
                )
            try:
                enforce_batch_limit(limit, counter="strings.compact.limit")
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            increment_counter("strings.compact.calls")

            raw_entries = strings.fetch_strings_compact_entries(
                client, limit=limit, offset=offset
            )

            try:
                payload = strings.strings_compact_view(
                    raw_entries, include_literals=include_literals
                )
            except (TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))

            valid, errors = validate_payload("strings_compact.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def search_imports_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_imports",
            logger=deps.logger,
            extra={"path": "/api/search_imports.json"},
        ):
            data = await deps.validated_json_body(
                request, "search_imports.request.v1.json"
            )
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                page = int(data.get("page", 1))
            except (KeyError, TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            pagination_error = _validate_pagination(limit, page)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = import_features.search_imports(
                    client,
                    query=query,
                    limit=limit,
                    page=page,
                )
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("search_imports.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def search_exports_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_exports",
            logger=deps.logger,
            extra={"path": "/api/search_exports.json"},
        ):
            data = await deps.validated_json_body(
                request, "search_exports.request.v1.json"
            )
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                page = int(data.get("page", 1))
            except (KeyError, TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            pagination_error = _validate_pagination(limit, page)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = export_features.search_exports(
                    client,
                    query=query,
                    limit=limit,
                    page=page,
                )
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("search_exports.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def search_xrefs_to_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_xrefs_to",
            logger=deps.logger,
            extra={"path": "/api/search_xrefs_to.json"},
        ):
            data = await deps.validated_json_body(
                request, "search_xrefs_to.request.v1.json"
            )
            try:
                address = str(data["address"])
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                page = int(data.get("page", 1))
            except (KeyError, TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            if query.strip():
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "query must be empty; filtering is not supported.",
                )
            pagination_error = _validate_pagination(limit, page)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = xrefs.search_xrefs_to(
                    client,
                    address=address,
                    query=query,
                    limit=limit,
                    page=page,
                )
            except ValueError as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("search_xrefs_to.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def search_functions_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_functions",
            logger=deps.logger,
            extra={"path": "/api/search_functions.json"},
        ):
            data = await deps.validated_json_body(
                request, "search_functions.request.v1.json"
            )
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                page = int(data.get("page", 1))
                cursor_token_raw = data.get("resume_cursor")
                if cursor_token_raw is None:
                    cursor_token_raw = data.get("cursor")
                cursor_token: str | None
                if cursor_token_raw is None:
                    cursor_token = None
                elif isinstance(cursor_token_raw, str):
                    cursor_token = cursor_token_raw
                else:
                    return error_response(
                        ErrorCode.INVALID_REQUEST,
                        "cursor must be a string if provided.",
                    )
                context_lines_raw = data.get("context_lines", 0)
                context_lines = int(context_lines_raw)
            except (KeyError, TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))

            if context_lines < 0 or context_lines > MAX_FUNCTION_CONTEXT_LINES:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    f"context_lines must be between 0 and {MAX_FUNCTION_CONTEXT_LINES}.",
                )

            rank_raw = data.get("rank")
            rank: str | None
            if rank_raw is None:
                rank = None
            elif isinstance(rank_raw, str):
                rank = rank_raw
            else:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "rank must be a string.",
                )

            if rank is not None and rank not in {"simple"}:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "rank must be one of: simple.",
                )

            k_raw = data.get("k")
            k: int | None = None
            if k_raw is not None:
                try:
                    k = int(k_raw)
                except (TypeError, ValueError):
                    return error_response(
                        ErrorCode.INVALID_REQUEST,
                        "k must be a positive integer.",
                    )
                if k <= 0:
                    return error_response(
                        ErrorCode.INVALID_REQUEST,
                        "k must be a positive integer.",
                    )
                if rank != "simple":
                    return error_response(
                        ErrorCode.INVALID_REQUEST,
                        'k requires rank="simple".',
                    )
            if cursor_token is not None and rank is not None:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "cursor pagination cannot be combined with rank.",
                )
            pagination_error = _validate_pagination(limit, page)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = functions.search_functions(
                    client,
                    query=query,
                    limit=limit,
                    page=page,
                    rank=rank,
                    k=k,
                    resume_cursor=cursor_token,
                    context_lines=context_lines,
                )
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            valid, errors = validate_payload("search_functions.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def search_scalars_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_scalars",
            logger=deps.logger,
            extra={"path": "/api/search_scalars.json"},
        ):
            data = await deps.validated_json_body(
                request, "search_scalars.request.v1.json"
            )
            try:
                raw_value = data["value"]
                if isinstance(raw_value, str):
                    query_value = raw_value
                    if raw_value.startswith("0x"):
                        normalized_value = parse_hex(raw_value)
                    else:
                        normalized_value = int(raw_value)
                else:
                    normalized_value = int(raw_value)
                    query_value = int_to_hex(normalized_value)
                limit = int(data.get("limit", 100))
                page = int(data.get("page", 1))
                cursor_token_raw = data.get("resume_cursor")
                if cursor_token_raw is None:
                    cursor_token_raw = data.get("cursor")
                cursor_token: str | None
                if cursor_token_raw is None:
                    cursor_token = None
                elif isinstance(cursor_token_raw, str):
                    cursor_token = cursor_token_raw
                else:
                    return error_response(
                        ErrorCode.INVALID_REQUEST,
                        "cursor must be a string if provided.",
                    )
            except (KeyError, TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            if limit <= 0 or page <= 0:
                return error_response(
                    ErrorCode.INVALID_REQUEST,
                    "limit and page must be positive integers.",
                )
            try:
                payload = scalars.search_scalars(
                    client,
                    value=normalized_value,
                    query=query_value,
                    limit=limit,
                    page=page,
                    resume_cursor=cursor_token,
                )
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except (ValueError, TypeError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            valid, errors = validate_payload("search_scalars.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    @deps.with_client
    async def list_functions_in_range_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "list_functions_in_range",
            logger=deps.logger,
            extra={"path": "/api/list_functions_in_range.json"},
        ):
            data = await deps.validated_json_body(
                request, "list_functions_in_range.request.v1.json"
            )
            try:
                address_min = str(data["address_min"])
                address_max = str(data["address_max"])
                limit = int(data.get("limit", 200))
                page = int(data.get("page", 1))
            except (KeyError, TypeError, ValueError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            try:
                payload = function_range.list_functions_in_range(
                    client,
                    address_min=address_min,
                    address_max=address_max,
                    limit=limit,
                    page=page,
                )
            except SafetyLimitExceeded as exc:
                return error_response(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except (ValueError, TypeError) as exc:
                return error_response(ErrorCode.INVALID_REQUEST, str(exc))
            valid, errors = validate_payload("list_functions_in_range.v1.json", payload)
            if valid:
                return envelope_response(envelope_ok(payload))
            return envelope_response(
                envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
            )

    return [
        Route("/api/string_xrefs.json", string_xrefs_route, methods=["POST"]),
        Route("/api/search_strings.json", search_strings_route, methods=["POST"]),
        Route("/api/strings_compact.json", strings_compact_route, methods=["POST"]),
        Route("/api/search_imports.json", search_imports_route, methods=["POST"]),
        Route("/api/search_exports.json", search_exports_route, methods=["POST"]),
        Route("/api/search_xrefs_to.json", search_xrefs_to_route, methods=["POST"]),
        Route("/api/search_functions.json", search_functions_route, methods=["POST"]),
        Route("/api/search_scalars.json", search_scalars_route, methods=["POST"]),
        Route("/api/list_functions_in_range.json", list_functions_in_range_route, methods=["POST"]),
    ]
