"""MCP tool surface for the deterministic bridge endpoints."""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Mapping, Sequence

from mcp.server.fastmcp import FastMCP

from ..features import (
    analyze,
    batch_ops,
    disasm,
    datatypes,
    exports as export_features,
    function_range,
    functions,
    imports as import_features,
    jt,
    memory,
    mmio,
    project,
    scalars,
    strings,
    xrefs,
)
from ..features.collect import execute_collect
from ..ghidra.client import GhidraClient
from ..utils import config
from ..utils.config import ENABLE_WRITES, MAX_WRITES_PER_REQUEST
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
    def project_info(client) -> Dict[str, object]:
        with request_scope(
            "project_info",
            logger=logger,
            extra={"tool": "project_info"},
        ):
            payload = client.get_project_info()
            if payload is None:
                return envelope_error(ErrorCode.UNAVAILABLE)
            normalized = _normalise_project_info(payload)

        valid, errors = validate_payload("project_info.v1.json", normalized)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(normalized)

    @server.tool()
    @tool_client
    def project_rebase(
        client,
        new_base: str,
        *,
        dry_run: bool = True,
        confirm: bool = False,
    ) -> Dict[str, object]:
        request_payload: Dict[str, object] = {
            "new_base": new_base,
            "dry_run": dry_run,
            "confirm": confirm,
        }
        valid, errors = validate_payload("project_rebase.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            parsed_new_base = parse_hex(new_base)
        except ValueError as exc:
            return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        with request_scope(
            "project_rebase",
            logger=logger,
            extra={"tool": "project_rebase"},
            max_writes=1,
        ):
            try:
                payload = project.rebase_project(
                    client,
                    new_base=parsed_new_base,
                    dry_run=dry_run,
                    confirm=confirm,
                    writes_enabled=enable_writes,
                    rebases_enabled=config.ENABLE_PROJECT_REBASE,
                )
            except ValueError as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload("project_rebase.v1.json", payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(payload)

    @server.tool()
    @tool_client
    def analyze_function_complete(
        client,
        address: str,
        *,
        fields: list[str] | None = None,
        fmt: str = "json",
        max_result_tokens: int | None = None,
        options: dict[str, object] | None = None,
    ) -> Dict[str, object]:
        request_payload: Dict[str, object] = {"address": address}
        if fields is not None:
            request_payload["fields"] = list(fields)
        if fmt is not None:
            request_payload["fmt"] = fmt
        if max_result_tokens is not None:
            request_payload["max_result_tokens"] = max_result_tokens
        if options is not None:
            request_payload["options"] = dict(options)

        valid, errors = validate_payload(
            "analyze_function_complete.request.v1.json", request_payload
        )
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            parsed_address = parse_hex(address)
        except ValueError as exc:
            return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        with request_scope(
            "analyze_function_complete",
            logger=logger,
            extra={"tool": "analyze_function_complete"},
        ):
            try:
                payload = analyze.analyze_function_complete(
                    client,
                    address=parsed_address,
                    fields=list(fields) if fields is not None else None,
                    fmt=fmt,
                    max_result_tokens=max_result_tokens,
                    options=_coerce_mapping(options),
                )
            except SafetyLimitExceeded as exc:
                return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except ValueError as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload(
            "analyze_function_complete.v1.json", payload
        )
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(payload)

    @server.tool()
    @tool_client
    def collect(
        client,
        *,
        queries: list[dict[str, object]] | None = None,
        projects: list[dict[str, object]] | None = None,
        result_budget: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> Dict[str, object]:
        """Execute read-only feature queries across one or more projects.

        The request envelope mirrors ``collect.request.v1`` and accepts:

        * ``queries`` – in-project query objects. Each entry requires an ``id``
          and ``op`` plus optional ``params`` (default ``{}``), per-query
          ``result_budget`` overrides, ``max_result_tokens`` hints, and arbitrary
          ``metadata`` echoed into the response.
        * ``projects`` – cross-project overrides. Each project entry includes
          an ``id`` (used to annotate the response), a ``queries`` list with the
          same shape as the top-level collection, optional ``result_budget``
          overrides, ``metadata`` passthrough, and an alternate ``ghidra_url`` or
          ``base_url`` for remote analysis.
        * ``result_budget`` – aggregate budget controls shared by all queries.
          Budgets accept ``max_result_tokens`` (``int`` or ``null`` for
          unlimited) and ``mode`` (``"auto_trim"`` to soft cap or
          ``"strict"`` to raise ``RESULT_TOO_LARGE`` when exceeded).
        * ``metadata`` – an arbitrary JSON object returned unchanged alongside
          the aggregated result bundle.

        Supported ``op`` values and common parameters:

        * ``disassemble_at`` – ``address`` (hex) with optional ``count`` of
          instructions (default ``16``).
          Example: ``{"id": "head", "op": "disassemble_at", "params": {"address": "0x401000", "count": 8}}``
        * ``disassemble_batch`` – ``addresses`` (array of hex strings) and
          optional ``count`` (default ``16``).
          Example: ``{"id": "epilogue", "op": "disassemble_batch", "params": {"addresses": ["0x401000", "0x401020"], "count": 4}}``
        * ``read_bytes`` – ``address`` (hex) and ``length`` in bytes (default
          ``64``).
          Example: ``{"id": "bytes", "op": "read_bytes", "params": {"address": "0x401000", "length": 32}}``
        * ``read_words`` – ``address`` (hex) and ``count`` of machine words
          (default ``1``).
          Example: ``{"id": "words", "op": "read_words", "params": {"address": "0x401000", "count": 2}}``
        * ``search_strings`` – ``query`` substring, optional ``limit``
          (default ``100``) and ``page`` (default ``1``).
          Example: ``{"id": "long-strings", "op": "search_strings", "params": {"query": "init", "limit": 25}}``
        * ``strings_compact`` – paginated listing with ``limit`` (required) and
          ``offset`` (default ``0``).
          Example: ``{"id": "strings", "op": "strings_compact", "params": {"limit": 100, "offset": 0}}``
        * ``string_xrefs`` – ``string_addr`` (hex) target and optional ``limit``
          (default ``50``).
          Example: ``{"id": "string-xrefs", "op": "string_xrefs", "params": {"string_addr": "0x500123", "limit": 10}}``
        * ``search_imports`` – ``query`` substring plus ``limit``/``page``
          pagination (defaults ``100``/``1``).
          Example: ``{"id": "imports", "op": "search_imports", "params": {"query": "socket", "limit": 10}}``
        * ``search_exports`` – ``query`` substring plus ``limit``/``page``
          pagination (defaults ``100``/``1``).
          Example: ``{"id": "exports", "op": "search_exports", "params": {"query": "init", "limit": 10}}``
        * ``search_functions`` – optional ``query`` text, ``limit``/``page``
          pagination (defaults ``100``/``1``), optional ``rank="simple"`` with
          ``k`` best results, cursor-based pagination via ``resume_cursor``
          (mutually exclusive with ranking), and ``context_lines`` (0–16).
          Example: ``{"id": "init-funcs", "op": "search_functions", "params": {"query": "init", "limit": 20, "context_lines": 2}}``
        * ``search_xrefs_to`` – destination ``address`` (hex), optional ``query``
          filter plus ``limit``/``page`` (defaults ``100``/``1``).
          Example: ``{"id": "xref", "op": "search_xrefs_to", "params": {"address": "0x401050", "limit": 50}}``
        * ``search_scalars`` – numeric ``value`` (decimal or hex), optional
          ``query`` label, ``limit``/``page`` pagination, and ``resume_cursor``
          for deep paging.
          Example: ``{"id": "scalars", "op": "search_scalars", "params": {"value": "0xDEADBEEF", "limit": 10}}``
        * ``search_scalars_with_context`` – numeric ``value``, ``context_lines``
          (0–16, default ``4``), and ``limit`` (default ``25``) for annotated
          disassembly windows.
          Example: ``{"id": "scalar-context", "op": "search_scalars_with_context", "params": {"value": "0x8040123", "context_lines": 3}}``

        Each query returns an envelope containing ``result.ok``/``errors`` as
        described by ``envelope.v1``; aggregate metadata records the total token
        estimate for all queries (including per-project batches).
        """
        request_payload: Dict[str, object] = {}
        if queries is not None:
            request_payload["queries"] = [dict(item) for item in queries]
        if projects is not None:
            request_payload["projects"] = [dict(item) for item in projects]
        if result_budget is not None:
            request_payload["result_budget"] = dict(result_budget)
        if metadata is not None:
            request_payload["metadata"] = dict(metadata)

        valid, errors = validate_payload("collect.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        queries_payload: list[dict[str, object]] = request_payload.get(
            "queries", []
        )
        projects_payload: list[dict[str, object]] = request_payload.get(
            "projects", []
        )
        budget_payload: Mapping[str, object] | None = request_payload.get(
            "result_budget"
        )

        with request_scope(
            "collect",
            logger=logger,
            extra={"tool": "collect"},
        ):
            try:
                base_payload = execute_collect(
                    client,
                    queries_payload,
                    result_budget=budget_payload,
                )
            except SafetyLimitExceeded as exc:
                return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except (KeyError, TypeError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        response_payload: Dict[str, Any] = {
            "queries": base_payload.get("queries", []),
            "meta": dict(base_payload.get("meta", {})),
        }
        if metadata is not None:
            response_payload["metadata"] = dict(metadata)

        aggregate_tokens = int(response_payload["meta"].get("estimate_tokens", 0) or 0)

        if projects_payload:
            project_results: List[Dict[str, Any]] = []
            for project_entry in projects_payload:
                project_id = project_entry.get("id")
                project_queries = project_entry.get("queries", [])
                project_budget = project_entry.get("result_budget")
                project_url = project_entry.get("ghidra_url") or project_entry.get(
                    "base_url"
                )

                project_client = client
                created_client = False
                if project_url:
                    project_client = client_factory()
                    created_client = True
                    if hasattr(project_client, "base_url"):
                        try:
                            project_client.base_url = (
                                project_url
                                if project_url.endswith("/")
                                else f"{project_url}/"
                            )
                        except AttributeError:
                            pass

                try:
                    project_payload = execute_collect(
                        project_client,
                        project_queries,
                        result_budget=project_budget,
                    )
                except SafetyLimitExceeded as exc:
                    if created_client:
                        project_client.close()
                    return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
                except (KeyError, TypeError, ValueError) as exc:
                    if created_client:
                        project_client.close()
                    return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

                project_meta = dict(project_payload.get("meta", {}))
                estimate = int(project_meta.get("estimate_tokens", 0) or 0)
                aggregate_tokens += estimate
                if project_url:
                    project_meta.setdefault("ghidra_url", project_url)

                project_result: Dict[str, Any] = {
                    "id": project_id,
                    "queries": project_payload.get("queries", []),
                    "meta": project_meta,
                }

                if "metadata" in project_entry:
                    project_result["metadata"] = project_entry["metadata"]

                project_results.append(project_result)

                if created_client:
                    project_client.close()

            response_payload["projects"] = project_results

        response_payload["meta"]["estimate_tokens"] = aggregate_tokens

        valid, errors = validate_payload("collect.v1.json", response_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(response_payload)

    @server.tool()
    @tool_client
    def datatypes_create(
        client,
        *,
        kind: str,
        name: str,
        category: str,
        fields: list[dict[str, object]],
        dry_run: bool = True,
    ) -> Dict[str, object]:
        request_payload: Dict[str, object] = {
            "kind": kind,
            "name": name,
            "category": category,
            "fields": [dict(field) for field in fields],
            "dry_run": dry_run,
        }
        valid, errors = validate_payload("datatypes_create.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        with request_scope(
            "create_datatype",
            logger=logger,
            extra={"tool": "datatypes_create"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            try:
                payload = datatypes.create_datatype(
                    client,
                    kind=kind,
                    name=name,
                    category=category,
                    fields=list(request_payload["fields"]),
                    dry_run=dry_run,
                    writes_enabled=enable_writes,
                )
            except SafetyLimitExceeded as exc:
                return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except (KeyError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload("datatypes_create.v1.json", payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(payload)

    @server.tool()
    @tool_client
    def datatypes_update(
        client,
        *,
        kind: str,
        path: str,
        fields: list[dict[str, object]],
        dry_run: bool = True,
    ) -> Dict[str, object]:
        request_payload: Dict[str, object] = {
            "kind": kind,
            "path": path,
            "fields": [dict(field) for field in fields],
            "dry_run": dry_run,
        }
        valid, errors = validate_payload("datatypes_update.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        with request_scope(
            "update_datatype",
            logger=logger,
            extra={"tool": "datatypes_update"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            try:
                payload = datatypes.update_datatype(
                    client,
                    kind=kind,
                    path=path,
                    fields=list(request_payload["fields"]),
                    dry_run=dry_run,
                    writes_enabled=enable_writes,
                )
            except SafetyLimitExceeded as exc:
                return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except (KeyError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload("datatypes_update.v1.json", payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(payload)

    @server.tool()
    @tool_client
    def datatypes_delete(
        client,
        *,
        kind: str,
        path: str,
        dry_run: bool = True,
    ) -> Dict[str, object]:
        request_payload: Dict[str, object] = {
            "kind": kind,
            "path": path,
            "dry_run": dry_run,
        }
        valid, errors = validate_payload("datatypes_delete.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        with request_scope(
            "delete_datatype",
            logger=logger,
            extra={"tool": "datatypes_delete"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            try:
                payload = datatypes.delete_datatype(
                    client,
                    kind=kind,
                    path=path,
                    dry_run=dry_run,
                    writes_enabled=enable_writes,
                )
            except SafetyLimitExceeded as exc:
                return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except (KeyError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload("datatypes_delete.v1.json", payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(payload)

    @server.tool()
    @tool_client
    def write_bytes(
        client,
        address: str,
        data: str,
        *,
        encoding: str = "base64",
        dry_run: bool = True,
    ) -> Dict[str, object]:
        request_payload: Dict[str, object] = {
            "address": address,
            "data": data,
            "encoding": encoding,
            "dry_run": dry_run,
        }
        valid, errors = validate_payload("write_bytes.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))

        try:
            parsed_address = parse_hex(address)
        except ValueError as exc:
            return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        with request_scope(
            "write_bytes",
            logger=logger,
            extra={"tool": "write_bytes"},
            max_writes=MAX_WRITES_PER_REQUEST,
        ):
            try:
                payload = memory.write_bytes(
                    client,
                    address=parsed_address,
                    data=data,
                    encoding=encoding,
                    dry_run=dry_run,
                    writes_enabled=enable_writes,
                )
            except SafetyLimitExceeded as exc:
                return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))
            except (KeyError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload("write_bytes.v1.json", payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        return envelope_ok(payload)

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
        page: int = 1,
    ) -> Dict[str, object]:
        request_payload = {"query": query, "limit": limit, "page": page}
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
                    page=int(page),
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
        page: int = 1,
    ) -> Dict[str, object]:
        """Search imported symbols matching a query with pagination support."""

        request_payload = {"query": query, "limit": limit, "page": page}
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
                    page=page,
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
        page: int = 1,
    ) -> Dict[str, object]:
        """Search exported symbols matching a query with pagination support."""

        request_payload = {"query": query, "limit": limit, "page": page}
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
                    page=page,
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
        page: int = 1,
    ) -> Dict[str, object]:
        """Search cross-references to an address with pagination support."""

        request_payload = {
            "address": address,
            "query": query,
            "limit": limit,
            "page": page,
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
                    page=page,
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
        page: int = 1,
        *,
        rank: str | None = None,
        k: int | None = None,
        context_lines: int = 0,
    ) -> Dict[str, object]:
        """
        Search for functions matching a query with pagination support.

        Args:
            query: Search query string (function name pattern)
            limit: Maximum number of results to return (default: 100)
            page: 1-based page number for pagination (default: 1)
            rank: Optional ranking mode ("simple") applied before pagination
            k: Optional cap on ranked results prior to pagination
            context_lines: Instructions before/after to include in the
                disassembly snippet for each match (default: 0)

        Returns:
            Dictionary with query, total count, page, limit, and items array.
            Each item contains name and address fields, plus an optional
            ``context`` payload when ``context_lines`` is greater than zero.
        """
        request_payload = {
            "query": query,
            "limit": limit,
            "page": page,
            "context_lines": context_lines,
        }
        if rank is not None:
            request_payload["rank"] = rank
        if k is not None:
            request_payload["k"] = k
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
                    page=page,
                    rank=rank,
                    k=k,
                    context_lines=context_lines,
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


def _coerce_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _normalise_project_info(payload: Mapping[str, Any]) -> Dict[str, Any]:
    data = dict(payload)

    entry_points = payload.get("entry_points")
    if isinstance(entry_points, list):
        data["entry_points"] = sorted(
            (value for value in entry_points if isinstance(value, str))
        )

    blocks = payload.get("memory_blocks")
    if isinstance(blocks, list):
        normalised_blocks: List[Dict[str, Any]] = []
        for block in blocks:
            if isinstance(block, Mapping):
                normalised_blocks.append(dict(block))
        normalised_blocks.sort(key=_block_sort_key)
        data["memory_blocks"] = normalised_blocks

    return data


def _block_sort_key(block: Mapping[str, Any]) -> tuple[int, str]:
    start = block.get("start")
    if isinstance(start, str):
        try:
            value = int(start, 16)
        except ValueError:
            pass
        else:
            return (0, f"{value:016x}")
    return (1, str(start))


__all__ = ["register_tools"]
