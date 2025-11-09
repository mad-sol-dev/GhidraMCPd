"""MCP tool surface for the deterministic bridge endpoints."""
from __future__ import annotations

import logging
from typing import Callable, Dict

from mcp.server.fastmcp import FastMCP

from ..features import (
    batch_ops,
    disasm,
    exports as export_features,
    function_range,
    functions,
    imports as import_features,
    jt,
    memory,
    mmio,
    scalars,
    strings,
    xrefs,
)
from ..ghidra.client import GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.errors import ErrorCode
from ..utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
    request_scope,
)
from ..utils.hex import int_to_hex, parse_hex
from ._shared import adapter_for_arch, envelope_error, envelope_ok, inject_client
from .validators import validate_payload


def register_tools(
    server: FastMCP,
    *,
    client_factory: Callable[[], GhidraClient],
    enable_writes: bool = ENABLE_WRITES,
) -> None:
    tool_client = inject_client(client_factory)
    logger = logging.getLogger("bridge.mcp.tools")

    @server.tool()
    @tool_client
    def jt_slot_check(
        client,
        jt_base: str,
        slot_index: int,
        code_min: str,
        code_max: str,
        arch: str = "auto",
    ) -> Dict[str, object]:
        request_payload = {
            "jt_base": jt_base,
            "slot_index": slot_index,
            "code_min": code_min,
            "code_max": code_max,
            "arch": arch,
        }
        valid, errors = validate_payload("jt_slot_check.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        adapter = adapter_for_arch(arch)
        with request_scope(
            "jt_slot_check",
            logger=logger,
            extra={"tool": "jt_slot_check"},
        ):
            data = jt.slot_check(
                client,
                jt_base=parse_hex(jt_base),
                slot_index=slot_index,
                code_min=parse_hex(code_min),
                code_max=parse_hex(code_max),
                adapter=adapter,
            )
        valid, errors = validate_payload("jt_slot_check.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def jt_slot_process(
        client,
        jt_base: str,
        slot_index: int,
        code_min: str,
        code_max: str,
        rename_pattern: str,
        comment: str,
        dry_run: bool = True,
        arch: str = "auto",
    ) -> Dict[str, object]:
        request_payload = {
            "jt_base": jt_base,
            "slot_index": slot_index,
            "code_min": code_min,
            "code_max": code_max,
            "rename_pattern": rename_pattern,
            "comment": comment,
            "dry_run": dry_run,
            "arch": arch,
        }
        valid, errors = validate_payload("jt_slot_process.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        adapter = adapter_for_arch(arch)
        try:
            with request_scope(
                "jt_slot_process",
                logger=logger,
                extra={"tool": "jt_slot_process"},
                max_writes=2,
            ):
                data = jt.slot_process(
                    client,
                    jt_base=parse_hex(jt_base),
                    slot_index=slot_index,
                    code_min=parse_hex(code_min),
                    code_max=parse_hex(code_max),
                    rename_pattern=rename_pattern,
                    comment=comment,
                    adapter=adapter,
                    dry_run=dry_run,
                    writes_enabled=enable_writes,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
        valid, errors = validate_payload("jt_slot_process.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def jt_scan(
        client,
        jt_base: str,
        start: int,
        count: int,
        code_min: str,
        code_max: str,
        arch: str = "auto",
    ) -> Dict[str, object]:
        request_payload = {
            "jt_base": jt_base,
            "start": start,
            "count": count,
            "code_min": code_min,
            "code_max": code_max,
            "arch": arch,
        }
        valid, errors = validate_payload("jt_scan.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        adapter = adapter_for_arch(arch)
        with request_scope(
            "jt_scan",
            logger=logger,
            extra={"tool": "jt_scan"},
        ):
            data = jt.scan(
                client,
                jt_base=parse_hex(jt_base),
                start=start,
                count=count,
                code_min=parse_hex(code_min),
                code_max=parse_hex(code_max),
                adapter=adapter,
            )
        valid, errors = validate_payload("jt_scan.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def string_xrefs_compact(
        client,
        string_addr: str,
        limit: int = 50,
    ) -> Dict[str, object]:
        request_payload = {
            "string_addr": string_addr,
            "limit": limit,
        }
        valid, errors = validate_payload("string_xrefs.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        with request_scope(
            "string_xrefs",
            logger=logger,
            extra={"tool": "string_xrefs_compact"},
        ):
            data = strings.xrefs_compact(
                client,
                string_addr=parse_hex(string_addr),
                limit=limit,
            )
        valid, errors = validate_payload("string_xrefs.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_strings(
        client,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        request_payload = {"query": query, "limit": limit, "offset": offset}
        valid, errors = validate_payload("search_strings.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "search_strings",
                logger=logger,
                extra={"tool": "search_strings"},
            ):
                data = strings.search_strings(
                    client,
                    query=query,
                    limit=int(limit),
                    offset=int(offset),
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_strings.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def strings_compact(
        client,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, object]:
        request_payload = {"limit": limit, "offset": offset}
        valid, errors = validate_payload("strings_compact.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            enforce_batch_limit(limit, counter="strings.compact.limit")
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        with request_scope(
            "strings_compact",
            logger=logger,
            extra={"tool": "strings_compact"},
        ):
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
                data = strings.strings_compact_view(raw_entries)
            except (TypeError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload("strings_compact.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_imports(
        client,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        """Search imported symbols matching a query with pagination support."""

        request_payload = {"query": query, "limit": limit, "offset": offset}
        valid, errors = validate_payload(
            "search_imports.request.v1.json", request_payload
        )
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "search_imports",
                logger=logger,
                extra={"tool": "search_imports"},
            ):
                data = import_features.search_imports(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_imports.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_exports(
        client,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        """Search exported symbols matching a query with pagination support."""

        request_payload = {"query": query, "limit": limit, "offset": offset}
        valid, errors = validate_payload(
            "search_exports.request.v1.json", request_payload
        )
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "search_exports",
                logger=logger,
                extra={"tool": "search_exports"},
            ):
                data = export_features.search_exports(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_exports.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_xrefs_to(
        client,
        address: str,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        """Search cross-references to an address with pagination support."""

        request_payload = {
            "address": address,
            "query": query,
            "limit": limit,
            "offset": offset,
        }
        valid, errors = validate_payload(
            "search_xrefs_to.request.v1.json", request_payload
        )
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "search_xrefs_to",
                logger=logger,
                extra={"tool": "search_xrefs_to"},
            ):
                data = xrefs.search_xrefs_to(
                    client,
                    address=address,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
        except ValueError as exc:
            return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_xrefs_to.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_functions(
        client,
        query: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, object]:
        """
        Search for functions matching a query with pagination support.
        
        Args:
            query: Search query string (function name pattern)
            limit: Maximum number of results to return (default: 100)
            offset: Number of results to skip for pagination (default: 0)
            
        Returns:
            Dictionary with query, total count, page, limit, and items array.
            Each item contains name and address fields.
        """
        request_payload = {"query": query, "limit": limit, "offset": offset}
        valid, errors = validate_payload("search_functions.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "search_functions",
                logger=logger,
                extra={"tool": "search_functions"},
            ):
                data = functions.search_functions(
                    client,
                    query=query,
                    limit=limit,
                    offset=offset,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_functions.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def mmio_annotate_compact(
        client,
        function_addr: str,
        dry_run: bool = True,
        max_samples: int = 8,
    ) -> Dict[str, object]:
        request_payload = {
            "function_addr": function_addr,
            "dry_run": dry_run,
            "max_samples": max_samples,
        }
        valid, errors = validate_payload("mmio_annotate.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "mmio_annotate",
                logger=logger,
                extra={"tool": "mmio_annotate_compact"},
            ):
                data = mmio.annotate(
                    client,
                    function_addr=parse_hex(function_addr),
                    dry_run=dry_run,
                    max_samples=max_samples,
                    writes_enabled=enable_writes,
                )
        except mmio.WritesDisabledError:
            return envelope_error(
                ErrorCode.INVALID_REQUEST,
                "Writes are disabled while dry_run is false.",
            )
        valid, errors = validate_payload("mmio_annotate.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_scalars(
        client,
        value: str | int,
        limit: int = 100,
        page: int = 1,
    ) -> Dict[str, object]:
        """Search for scalar values in the binary with pagination support."""

        request_payload = {"value": value, "limit": limit, "page": page}
        valid, errors = validate_payload("search_scalars.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        # Normalize value
        if isinstance(value, str):
            query_value = value
            if value.startswith("0x"):
                normalized_value = parse_hex(value)
            else:
                normalized_value = int(value)
        else:
            normalized_value = int(value)
            query_value = int_to_hex(normalized_value)

        try:
            with request_scope(
                "search_scalars",
                logger=logger,
                extra={"tool": "search_scalars"},
            ):
                data = scalars.search_scalars(
                    client,
                    value=normalized_value,
                    query=query_value,
                    limit=limit,
                    page=page,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_scalars.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def list_functions_in_range(
        client,
        address_min: str,
        address_max: str,
        limit: int = 200,
        page: int = 1,
    ) -> Dict[str, object]:
        """List functions within an address range with pagination support."""

        request_payload = {
            "address_min": address_min,
            "address_max": address_max,
            "limit": limit,
            "page": page,
        }
        valid, errors = validate_payload(
            "list_functions_in_range.request.v1.json", request_payload
        )
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "list_functions_in_range",
                logger=logger,
                extra={"tool": "list_functions_in_range"},
            ):
                data = function_range.list_functions_in_range(
                    client,
                    address_min=address_min,
                    address_max=address_max,
                    limit=limit,
                    page=page,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("list_functions_in_range.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def disassemble_at(
        client,
        address: str,
        count: int = 16,
    ) -> Dict[str, object]:
        """Disassemble instructions at a given address."""

        request_payload = {"address": address, "count": count}
        valid, errors = validate_payload("disassemble_at.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "disassemble_at",
                logger=logger,
                extra={"tool": "disassemble_at"},
            ):
                data = disasm.disassemble_at(
                    client,
                    address=parse_hex(address),
                    count=count,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("disassemble_at.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def read_bytes(
        client,
        address: str,
        length: int,
    ) -> Dict[str, object]:
        """Read raw bytes from memory at a given address."""

        request_payload = {"address": address, "length": length}
        valid, errors = validate_payload("read_bytes.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "read_bytes",
                logger=logger,
                extra={"tool": "read_bytes"},
            ):
                data = memory.read_bytes(
                    client,
                    address=parse_hex(address),
                    length=length,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("read_bytes.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def disassemble_batch(
        client,
        addresses: list[str],
        count: int = 16,
    ) -> Dict[str, object]:
        """
        Disassemble multiple addresses in one call for efficient batch processing.
        
        Useful when you need to examine several functions or code locations at once
        without making separate calls for each address.
        
        Args:
            addresses: List of hex strings like ['0x1000', '0x2000']
            count: Number of instructions per address (default: 16)
            
        Returns:
            Dictionary with results keyed by address string.
        """
        request_payload = {"addresses": addresses, "count": count}
        valid, errors = validate_payload("disassemble_batch.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "disassemble_batch",
                logger=logger,
                extra={"tool": "disassemble_batch", "batch_size": len(addresses)},
            ):
                data = batch_ops.disassemble_batch(
                    client,
                    addresses=addresses,
                    count=count,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("disassemble_batch.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def read_words(
        client,
        address: str,
        count: int = 1,
    ) -> Dict[str, object]:
        """
        Read multiple 32-bit words from memory at once.
        
        More efficient than calling read_bytes repeatedly. Returns decoded integer
        values (little-endian) instead of base64.
        
        Args:
            address: Starting hex address like '0x1000'
            count: Number of 32-bit words (default: 1, max: 256)
            
        Returns:
            Dictionary with address, count, and array of word values (integers or
            None for unreadable).
        """
        request_payload = {"address": address, "count": count}
        valid, errors = validate_payload("read_words.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            with request_scope(
                "read_words",
                logger=logger,
                extra={"tool": "read_words"},
            ):
                data = batch_ops.read_words(
                    client,
                    address=parse_hex(address),
                    count=count,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("read_words.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)

    @server.tool()
    @tool_client
    def search_scalars_with_context(
        client,
        value: str | int,
        context_lines: int = 4,
        limit: int = 100,
    ) -> Dict[str, object]:
        """
        Search for scalar values and include surrounding disassembly context.
        
        Combines scalar search with automatic disassembly of surrounding code,
        reducing the need for follow-up disassemble_at calls.
        
        Args:
            value: Hex string like '0xB8000000' or integer
            context_lines: Instructions before/after (default: 4)
            limit: Max results (default: 100)
            
        Returns:
            Dictionary with matches array including address, value, function name,
            context text, and disassembly.
        """
        request_payload = {
            "value": value,
            "context_lines": context_lines,
            "limit": limit,
        }
        valid, errors = validate_payload(
            "search_scalars_with_context.request.v1.json", request_payload
        )
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        # Normalize value
        if isinstance(value, str) and value.startswith("0x"):
            normalized_value = parse_hex(value)
        else:
            normalized_value = int(value)

        try:
            with request_scope(
                "search_scalars_with_context",
                logger=logger,
                extra={"tool": "search_scalars_with_context"},
            ):
                data = batch_ops.search_scalars_with_context(
                    client,
                    value=normalized_value,
                    context_lines=context_lines,
                    limit=limit,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_scalars_with_context.v1.json", data)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(data)


__all__ = ["register_tools"]
