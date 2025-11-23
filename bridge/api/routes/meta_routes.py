from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ...utils.logging import request_scope
from .._shared import envelope_ok
from ..validators import validate_payload
from ._common import RouteDependencies

CapabilityEntry = Tuple[str, str, str, str, str]


def _ordered_capabilities(definitions: Sequence[CapabilityEntry]) -> List[dict[str, str]]:
    sorted_defs = sorted(definitions, key=lambda entry: (entry[0], entry[1]))
    capabilities: List[dict[str, str]] = []
    for path, method, category, budget_hint, description in sorted_defs:
        capabilities.append(
            {
                "path": path,
                "method": method,
                "category": category,
                "budget_hint": budget_hint,
                "description": description,
            }
        )
    return capabilities


def _capability_definitions(enable_writes: bool) -> Iterable[CapabilityEntry]:
    budget_write = "medium" if enable_writes else "small"
    return (
        ("/api/analyze_function_complete.json", "POST", "detail", "large", "Analyze a function with optional decompilation."),
        ("/api/capabilities.json", "GET", "overview", "small", "List available bridge endpoints."),
        ("/api/collect.json", "POST", "detail", "large", "Execute compound analysis queries."),
        ("/api/datatypes/create.json", "POST", "write", budget_write, "Create a datatype definition."),
        ("/api/datatypes/delete.json", "POST", "write", budget_write, "Delete a datatype definition."),
        ("/api/datatypes/update.json", "POST", "write", budget_write, "Update a datatype definition."),
        ("/api/disassemble_at.json", "POST", "detail", "medium", "Disassemble instructions at an address."),
        ("/api/current_program.json", "GET", "overview", "small", "Return the active program selection."),
        ("/api/health.json", "GET", "overview", "small", "Service and upstream health status."),
        ("/api/jt_scan.json", "POST", "detail", "medium", "Scan a jump table for slot metadata."),
        ("/api/jt_slot_check.json", "POST", "detail", "small", "Validate a jump table slot target."),
        ("/api/jt_slot_process.json", "POST", "write", budget_write, "Annotate a jump table slot."),
        ("/api/list_functions_in_range.json", "POST", "detail", "medium", "List functions within an address range."),
        ("/api/mmio_annotate.json", "POST", "write", budget_write, "Annotate MMIO access patterns."),
        ("/api/project_info.json", "GET", "overview", "small", "Summarize the current project."),
        ("/api/project_rebase.json", "POST", "write", "large", "Rebase the open project."),
        ("/api/read_bytes.json", "POST", "detail", "medium", "Read a window of bytes."),
        ("/api/search_exports.json", "POST", "detail", "small", "Search exported symbols."),
        ("/api/search_functions.json", "POST", "detail", "medium", "Search functions by metadata."),
        ("/api/search_imports.json", "POST", "detail", "small", "Search imported symbols."),
        ("/api/search_scalars.json", "POST", "detail", "medium", "Search scalar values in code."),
        ("/api/search_strings.json", "POST", "detail", "medium", "Search string literals."),
        ("/api/search_xrefs_to.json", "POST", "detail", "medium", "Search cross-references to an address."),
        ("/api/select_program.json", "POST", "overview", "small", "Select the active program for this session."),
        ("/api/string_xrefs.json", "POST", "detail", "small", "List references to a string literal."),
        ("/api/strings_compact.json", "POST", "overview", "small", "List compact string summaries."),
        ("/api/write_bytes.json", "POST", "write", budget_write, "Write bytes to memory."),
    )


def create_meta_routes(deps: RouteDependencies) -> List[Route]:
    async def capabilities_route(request: Request) -> JSONResponse:
        with request_scope(
            "capabilities",
            logger=deps.logger,
            extra={"path": "/api/capabilities.json"},
        ):
            payload = {
                "endpoints": _ordered_capabilities(
                    _capability_definitions(deps.enable_writes)
                )
            }
            valid, errors = validate_payload("capabilities.v1.json", payload)
            if not valid:
                deps.logger.warning("capabilities.validation_failed", extra={"errors": errors})
            return JSONResponse(envelope_ok(payload))

    return [
        Route(
            "/api/capabilities.json",
            capabilities_route,
            methods=["GET", "HEAD"],
            name="capabilities",
        )
    ]
__all__ = ["create_meta_routes"]
