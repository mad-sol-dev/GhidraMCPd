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
from ...utils.hex import parse_hex
from ...utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
    request_scope,
)
from .._shared import envelope_error, envelope_ok
from ..validators import validate_payload
from ._common import RouteDependencies


def _validate_pagination(limit: int, offset: int) -> JSONResponse | None:
    if limit <= 0:
        return JSONResponse(
            envelope_error(
                ErrorCode.INVALID_ARGUMENT,
                "limit must be a positive integer.",
            ),
            status_code=400,
        )
    if offset < 0:
        return JSONResponse(
            envelope_error(
                ErrorCode.INVALID_ARGUMENT,
                "offset must be a non-negative integer.",
            ),
            status_code=400,
        )
    return None


def create_search_routes(deps: RouteDependencies) -> List[Route]:
    @deps.with_client
    async def string_xrefs_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "string_xrefs",
            logger=deps.logger,
            extra={"path": "/api/string_xrefs.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "string_xrefs.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                payload = strings.xrefs_compact(
                    client,
                    string_addr=parse_hex(str(data["string_addr"])),
                    limit=int(data.get("limit", 50)),
                )
            except (KeyError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)), status_code=400
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("string_xrefs.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def search_strings_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_strings",
            logger=deps.logger,
            extra={"path": "/api/search_strings.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "search_strings.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                offset = int(data.get("offset", 0))
            except (KeyError, TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            pagination_error = _validate_pagination(limit, offset)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = strings.search_strings(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("search_strings.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def strings_compact_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "strings_compact",
            logger=deps.logger,
            extra={"path": "/api/strings_compact.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "strings_compact.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                limit = int(data.get("limit", 0))
                offset = int(data.get("offset", 0))
            except (TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            pagination_error = _validate_pagination(limit, offset)
            if pagination_error is not None:
                return pagination_error
            try:
                enforce_batch_limit(limit, counter="strings.compact.limit")
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            increment_counter("strings.compact.calls")

            raw_entries: list[dict[str, object]] = []
            fetcher = getattr(client, "list_strings_compact", None)
            if callable(fetcher):
                result = fetcher(limit=limit, offset=offset)
                raw_entries = [] if result is None else list(result)
            else:
                fallback = getattr(client, "list_strings", None)
                if callable(fallback):
                    try:
                        result = fallback(limit=limit, offset=offset)
                    except TypeError:
                        result = fallback(limit=limit)
                    raw_entries = [] if result is None else list(result)

            try:
                payload = strings.strings_compact_view(raw_entries)
            except (TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )

            valid, errors = validate_payload("strings_compact.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def search_imports_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_imports",
            logger=deps.logger,
            extra={"path": "/api/search_imports.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "search_imports.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                offset = int(data.get("offset", 0))
            except (KeyError, TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            pagination_error = _validate_pagination(limit, offset)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = import_features.search_imports(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("search_imports.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def search_exports_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_exports",
            logger=deps.logger,
            extra={"path": "/api/search_exports.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "search_exports.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                offset = int(data.get("offset", 0))
            except (KeyError, TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            pagination_error = _validate_pagination(limit, offset)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = export_features.search_exports(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("search_exports.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def search_xrefs_to_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_xrefs_to",
            logger=deps.logger,
            extra={"path": "/api/search_xrefs_to.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "search_xrefs_to.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                address = str(data["address"])
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                offset = int(data.get("offset", 0))
            except (KeyError, TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            pagination_error = _validate_pagination(limit, offset)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = xrefs.search_xrefs_to(
                    client,
                    address=address,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
            except ValueError as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("search_xrefs_to.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def search_functions_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_functions",
            logger=deps.logger,
            extra={"path": "/api/search_functions.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "search_functions.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                query = str(data["query"])
                limit = int(data.get("limit", 100))
                offset = int(data.get("offset", 0))
            except (KeyError, TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            pagination_error = _validate_pagination(limit, offset)
            if pagination_error is not None:
                return pagination_error
            try:
                payload = functions.search_functions(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            valid, errors = validate_payload("search_functions.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def search_scalars_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "search_scalars",
            logger=deps.logger,
            extra={"path": "/api/search_scalars.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "search_scalars.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                value = data["value"]
                if isinstance(value, str) and value.startswith("0x"):
                    normalized_value = parse_hex(value)
                else:
                    normalized_value = int(value)
                limit = int(data.get("limit", 100))
                page = int(data.get("page", 1))
            except (KeyError, TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            try:
                payload = scalars.search_scalars(
                    client,
                    value=normalized_value,
                    limit=limit,
                    page=page,
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            except (ValueError, TypeError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            valid, errors = validate_payload("search_scalars.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

    @deps.with_client
    async def list_functions_in_range_route(request: Request, client: GhidraClient) -> JSONResponse:
        with request_scope(
            "list_functions_in_range",
            logger=deps.logger,
            extra={"path": "/api/list_functions_in_range.json"},
        ):
            data, error = await deps.validated_json_body(
                request, "list_functions_in_range.request.v1.json"
            )
            if error is not None:
                return error
            assert data is not None
            try:
                address_min = str(data["address_min"])
                address_max = str(data["address_max"])
                limit = int(data.get("limit", 200))
                page = int(data.get("page", 1))
            except (KeyError, TypeError, ValueError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            try:
                payload = function_range.list_functions_in_range(
                    client,
                    address_min=address_min,
                    address_max=address_max,
                    limit=limit,
                    page=page,
                )
            except SafetyLimitExceeded as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.SAFETY_LIMIT, str(exc)), status_code=400
                )
            except (ValueError, TypeError) as exc:
                return JSONResponse(
                    envelope_error(ErrorCode.INVALID_ARGUMENT, str(exc)),
                    status_code=400,
                )
            valid, errors = validate_payload("list_functions_in_range.v1.json", payload)
            response = (
                envelope_ok(payload)
                if valid
                else envelope_error(ErrorCode.SCHEMA_INVALID, "; ".join(errors))
            )
            return JSONResponse(response)

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
