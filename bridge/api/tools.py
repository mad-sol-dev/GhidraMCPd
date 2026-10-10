"""MCP tool surface for the deterministic bridge endpoints."""
from __future__ import annotations

import logging
from functools import wraps
import time
from time import monotonic
from typing import Any, Callable, Dict, List, Mapping, Sequence

from mcp.server.fastmcp import FastMCP

from ..features import (
    analyze,
    batch_ops,
    collect as collect_feature,
    disasm,
    datatypes,
    exports as export_features,
    function_range,
    functions,
    imports as import_features,
    jt,
    labels,
    memory,
    mmio,
    scalars,
    search_function,
    strings,
    xrefs,
)
from ..features import listing, mutations
from ..features.listing import ListingUnavailable
from ..features.function_meta import read_function_name
from ..features.project_layout import layout_notes
from ..features.collect import execute_collect
from ..ghidra.client import GhidraClient, RequestError
from ..utils.config import ENABLE_WRITES, MAX_WRITES_PER_REQUEST
from ..utils.errors import ErrorCode
from ..utils.logging import (
    SafetyLimitExceeded,
    enforce_batch_limit,
    increment_counter,
    request_scope,
)
from ..utils.hex import int_to_hex, parse_hex
from ..utils.usage_log import record_tool_call, usage_log_enabled
from ..utils.program_context import (
    PROGRAM_SELECTIONS,
    ProgramSelectionError,
    lock_selection_for_requestor,
    mark_used_for_context,
    normalize_selection,
    requestor_from_context,
    validate_program_id,
)
from ._shared import (
    adapter_for_arch,
    envelope_error,
    envelope_ok,
    inject_client,
    response_schema_error,
    write_refusal_envelope,
)
from .validators import validate_payload


#: The plugin renders a function as "<name> at <hex>".  Anchored at both ends so
#: a response in any other shape is rejected rather than partially believed.
COLLECT_DOCS_URL = "docs/api.md#/api/collect.json"
_SUPPORTED_COLLECT_OPS: tuple[str, ...] = tuple(
    sorted(getattr(collect_feature, "_OPERATIONS", {}).keys())
)

if _SUPPORTED_COLLECT_OPS:
    _COLLECT_OP_HINT = (
        "Supported 'op' values: "
        + ", ".join(_SUPPORTED_COLLECT_OPS)
        + f". See {COLLECT_DOCS_URL} for details."
    )
else:  # pragma: no cover - fallback when operations are unavailable
    _COLLECT_OP_HINT = f"See {COLLECT_DOCS_URL} for supported 'op' values."


def _find_program_entry(files: object, domain_file_id: str) -> Mapping[str, object] | None:
    if not isinstance(files, Sequence):
        return None
    for entry in files:
        if not isinstance(entry, Mapping):
            continue
        entry_id = str(entry.get("domain_file_id", "")).strip()
        if entry_id == domain_file_id:
            return entry
    return None


def _maybe_autoopen_program(
    client: GhidraClient, files: object, domain_file_id: str, on_dirty: str | None = None
) -> tuple[list[str], Dict[str, object] | None]:
    entry = _find_program_entry(files, domain_file_id)
    path = None
    if entry:
        path_val = entry.get("path")
        if isinstance(path_val, str) and path_val:
            path = path_val

    open_kwargs: Dict[str, object] = {}
    if path is not None:
        open_kwargs["path"] = path
    if on_dirty is not None:
        open_kwargs["on_dirty"] = on_dirty
    payload = client.open_program(domain_file_id, **open_kwargs)
    if payload is None:
        upstream = getattr(getattr(client, "last_error", None), "as_dict", lambda: None)()
        return (
            [],
            envelope_error(
                ErrorCode.UNAVAILABLE,
                (
                    "Automatic program open failed; confirm the target program is active in "
                    "Ghidra before continuing."
                ),
                upstream_error=upstream,
            ),
        )

    warnings: List[str] = []
    status = str(payload.get("status", "")).lower()
    if status != "ok":
        message = payload.get("message")
        detail = message if isinstance(message, str) and message.strip() else "unknown error"
        code = ErrorCode.INVALID_REQUEST if status == "error" else ErrorCode.UNAVAILABLE
        return (
            warnings,
            envelope_error(
                code,
                (
                    "Automatic program open failed upstream: "
                    f"{detail}. Confirm the correct program is active before proceeding."
                ),
                upstream_error=payload if isinstance(payload, dict) else None,
            ),
        )

    plugin_warnings = payload.get("warnings")
    if isinstance(plugin_warnings, Sequence):
        warnings.extend(str(warning) for warning in plugin_warnings if str(warning).strip())

    status_payload = client.get_current_program_status()
    if status_payload is None:
        upstream = getattr(getattr(client, "last_error", None), "as_dict", lambda: None)()
        warnings.append(
            "Program opened but current program status is unavailable upstream; "
            "confirm the active file before proceeding."
        )
        if upstream:
            warnings.append(f"Upstream status error: {upstream}")
        return warnings, None

    requested_id = str(domain_file_id).strip()
    active_id_raw = status_payload.get("domain_file_id") if isinstance(status_payload, Mapping) else None
    active_domain_id = str(active_id_raw).strip() if active_id_raw is not None else ""
    if requested_id and active_domain_id and active_domain_id != requested_id:
        return (
            warnings,
            envelope_error(
                ErrorCode.INVALID_REQUEST,
                (
                    "Program open succeeded but the active program upstream does not match the "
                    f"requested domain_file_id '{requested_id}' (current '{active_domain_id}')."
                ),
                upstream_error=status_payload if isinstance(status_payload, Mapping) else None,
                recovery=(
                    "Ask the user to confirm program switches during a session.",
                    "Retry once the requested program is active in Ghidra.",
                ),
            ),
        )

    expected_name = None
    if entry:
        name_val = entry.get("name")
        if isinstance(name_val, str) and name_val:
            expected_name = name_val
    if not expected_name:
        name_val = payload.get("name") if isinstance(payload, Mapping) else None
        if isinstance(name_val, str) and name_val:
            expected_name = name_val

    current_name = status_payload.get("program_name") if isinstance(status_payload, Mapping) else None
    if expected_name and isinstance(current_name, str) and current_name and current_name != expected_name:
        warnings.append(
            (
                "Requested program selection does not match the active program upstream: "
                f"expected '{expected_name}', current '{current_name}'."
            )
        )

    upstream_warnings = status_payload.get("warnings") if isinstance(status_payload, Mapping) else None
    if isinstance(upstream_warnings, Sequence):
        warnings.extend(str(item) for item in upstream_warnings if str(item).strip())

    return warnings, None


# How long select_program waits for auto-analysis after opening a program.
# Short enough for one tool call; a longer analysis is reported, not awaited.
PROGRAM_READY_WAIT_SECONDS = 10.0
PROGRAM_READY_POLL_SECONDS = 0.5


def _await_program_ready(client: GhidraClient) -> tuple[Mapping[str, object] | None, list[str]]:
    """Poll the plugin's program state while it is LOADING, up to the wait limit.

    Returns the last status payload (None if the plugin did not answer) and
    the warnings to pass on: the plugin's own, plus a note when analysis was
    still running at the deadline.
    """

    deadline = monotonic() + PROGRAM_READY_WAIT_SECONDS
    while True:
        status = client.get_current_program_status()
        state = str(status.get("state", "")).upper() if isinstance(status, Mapping) else ""
        if state != "LOADING" or monotonic() >= deadline:
            break
        time.sleep(PROGRAM_READY_POLL_SECONDS)

    warnings: list[str] = []
    if isinstance(status, Mapping):
        upstream_warnings = status.get("warnings")
        if isinstance(upstream_warnings, list):
            warnings.extend(str(item) for item in upstream_warnings)
    if state == "LOADING":
        warnings.append(
            f"Ghidra is still running auto-analysis after {PROGRAM_READY_WAIT_SECONDS:g} s; "
            "analysis tools refuse until state is READY. Check with get_current_program."
        )
    return status, warnings


def _detect_collect_misspecifications(
    payload: Mapping[str, object] | None,
) -> str | None:
    if not isinstance(payload, Mapping):
        return None

    def _budget_issue(
        budget_payload: object,
        *,
        context: str,
    ) -> str | None:
        if isinstance(budget_payload, Mapping) and "max_items" in budget_payload:
            return (
                f"{context} uses 'max_items'. Result budgets accept 'max_result_tokens'. "
                "Example: {'result_budget': {'max_result_tokens': 500}}. "
                f"See {COLLECT_DOCS_URL} for budgeting fields."
            )
        return None

    def _query_issue(source: str, queries_payload: object) -> str | None:
        if not isinstance(queries_payload, Sequence) or isinstance(
            queries_payload, (str, bytes, bytearray)
        ):
            return None

        for index, raw_query in enumerate(queries_payload):
            if not isinstance(raw_query, Mapping):
                continue

            qid = raw_query.get("id")
            if isinstance(qid, str) and qid:
                context = f"{source} query '{qid}'"
            else:
                context = f"{source} query #{index + 1}"

            if "type" in raw_query:
                return (
                    f"{context} uses 'type'. Collect queries require an 'op' field. "
                    "Use 'op': 'search_functions' and 'params': {...}. "
                    f"{_COLLECT_OP_HINT}"
                )

            if "filter" in raw_query and "params" not in raw_query:
                return (
                    f"{context} uses 'filter'. Move filters under 'params'. "
                    "Use 'op': 'search_functions' and 'params': {...}. "
                    f"{_COLLECT_OP_HINT}"
                )

            budget_message = _budget_issue(
                raw_query.get("result_budget"), context=f"{context} result_budget"
            )
            if budget_message:
                return budget_message

        return None

    message = _query_issue("Top-level", payload.get("queries"))
    if message:
        return message

    projects_payload = payload.get("projects")
    if isinstance(projects_payload, Sequence):
        for project in projects_payload:
            if not isinstance(project, Mapping):
                continue

            pid = project.get("id")
            source = f"Project '{pid}'" if isinstance(pid, str) and pid else "Project"

            budget_message = _budget_issue(
                project.get("result_budget"), context=f"{source} result_budget"
            )
            if budget_message:
                return budget_message

            message = _query_issue(source, project.get("queries"))
            if message:
                return message

    budget_message = _budget_issue(
        payload.get("result_budget"), context="Collect result_budget"
    )
    if budget_message:
        return budget_message

    return None


def register_tools(
    server: FastMCP,
    *,
    client_factory: Callable[[], GhidraClient],
    enable_writes: bool = ENABLE_WRITES,
) -> None:
    tool_client = inject_client(client_factory)
    logger = logging.getLogger("bridge.mcp.tools")

    def _ensure_program_ready(client) -> Dict[str, object] | None:
        status_payload = client.get_current_program_status()
        if status_payload is None:
            upstream = client.last_error.as_dict() if client.last_error else None
            return envelope_error(
                ErrorCode.UNAVAILABLE,
                "Active program status is unavailable from Ghidra.",
                upstream_error=upstream,
            )

        state = str(status_payload.get("state", "")).upper()
        if state and state != "READY":
            warnings = status_payload.get("warnings")
            extra_warning = None
            if isinstance(warnings, list) and warnings:
                extra_warning = warnings[0]

            # Extract state duration for better diagnostics
            duration_seconds = status_payload.get("state_duration_seconds", 0)

            # Build message with duration context
            message = (
                f"Program is not ready (state={state})."
                if not extra_warning
                else f"Program is not ready (state={state}): {extra_warning}"
            )

            # LOADING is the plugin reading AutoAnalysisManager.isAnalyzing() at
            # this moment -- a long duration is a long analysis, not a stale state.
            recovery = []
            if state == "LOADING":
                recovery.append(
                    f"Ghidra has been running auto-analysis for at least {duration_seconds} s; "
                    "large binaries can take minutes. Progress shows in Ghidra's status bar."
                )
                recovery.append("Retry once get_current_program reports state READY.")
            else:
                recovery.append("Ensure a program is open and ready in Ghidra.")

            return envelope_error(
                ErrorCode.UNAVAILABLE,
                message,
                recovery=tuple(recovery),
                upstream_error=status_payload,
            )
        return None

    def _wrap_usage(
        fn: Callable[..., Any], *, lock_usage: bool = True, require_ready: bool | None = None
    ):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            client_arg = kwargs.get("client") if "client" in kwargs else (args[0] if args else None)
            should_require_ready = require_ready if require_ready is not None else lock_usage
            if should_require_ready and client_arg is not None:
                readiness = _ensure_program_ready(client_arg)
                if readiness is not None:
                    return readiness

            mark_used_for_context(server, lock_usage=lock_usage)
            if isinstance(client_arg, GhidraClient):
                client_arg.expected_program_id = PROGRAM_SELECTIONS.selected_program_id(
                    _current_requestor()
                )
            result = fn(*args, **kwargs)
            refusal = getattr(client_arg, "write_refusal", None)
            if isinstance(refusal, RequestError):
                return write_refusal_envelope(refusal)
            return result

        return wrapper

    def _log_usage(fn: Callable[..., Any], *, tool_name: str):
        """Append one usage-log record per call (no-op while logging is off)."""

        signature = getattr(fn, "__signature__", None)

        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not usage_log_enabled():
                return fn(*args, **kwargs)

            started = monotonic()
            result: Any = None
            try:
                result = fn(*args, **kwargs)
                return result
            finally:
                params: Dict[str, Any] = dict(kwargs)
                if args and signature is not None:
                    names = list(signature.parameters)
                    for name, value in zip(names, args):
                        params[name] = value
                record_tool_call(
                    tool=tool_name,
                    params=params,
                    result=result,
                    duration_s=monotonic() - started,
                )

        if signature is not None:
            wrapper.__signature__ = signature
        return wrapper

    def tracked_tool(*, lock_usage: bool = True, require_ready: bool | None = None):
        def decorator(fn: Callable[..., Any]):
            injected = tool_client(
                _wrap_usage(fn, lock_usage=lock_usage, require_ready=require_ready)
            )
            return _log_usage(injected, tool_name=fn.__name__)

        return decorator

    def _current_requestor() -> object:
        return requestor_from_context(server)

    def _current_function_name(client, address: int) -> str | None:
        """Read the name a rename is about to replace, or admit it cannot.

        See bridge.features.function_meta: the plugin answers in prose, and the
        parse is exact and cross-checked against the address.
        """

        return read_function_name(client, address)

    def _current_function_comment(client, address: int) -> str | None:
        """The comment a write is about to replace -- if it can be read at all.

        It cannot: the plugin exposes no endpoint that returns an existing
        comment, and get_function_by_address answers with Function, Signature,
        Entry and Body only.  Rather than spend a round trip to learn nothing,
        this reports None, and the ledger prints "?" for the old value instead
        of implying the comment was empty.
        """

        return None

    @server.tool()
    @tracked_tool()
    def project_info(client) -> Dict[str, object]:
        """Identity and layout of the open program.

        Name, executable path, MD5/SHA-256, format, image base, language,
        compiler spec, entry points, memory blocks, import/export counts.
        source_files: SHA-256 as imported vs. now (patched=true: bytes were
        changed). Each block: file_offset and sha256 of its contents.

        Not for: locating anything -- it describes the container, not the
        contents. Takes no parameters."""
        with request_scope(
            "project_info",
            logger=logger,
            extra={"tool": "project_info"},
        ):
            payload = client.get_project_info()
            if payload is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                message = None
                status = None
                if upstream is not None:
                    message = f"Upstream request failed: {upstream.get('reason', '')}".strip()
                    status_val = upstream.get("status")
                    if isinstance(status_val, int):
                        status = status_val
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    message,
                    status=status,
                    upstream_error=upstream,
                )
            normalized = _normalise_project_info(payload)

        valid, errors = validate_payload("project_info.v1.json", normalized)
        if not valid:
            return response_schema_error("project_info.v1.json", errors)
        return envelope_ok(normalized)

    @server.tool()
    @tracked_tool(lock_usage=False, require_ready=False)
    def project_overview(client) -> Dict[str, object]:
        """List the programs in the open Ghidra project.

        One entry per program file with its domain_file_id (what select_program
        expects), path, name and open state. Works before analysis finishes.

        Not for: anything inside a program. Takes no parameters."""
        with request_scope(
            "project_overview",
            logger=logger,
            extra={"tool": "project_overview"},
        ):
            payload = client.get_project_files()
            if payload is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                message = None
                status = None
                if upstream is not None:
                    message = f"Upstream request failed: {upstream.get('reason', '')}".strip()
                    status_val = upstream.get("status")
                    if isinstance(status_val, int):
                        status = status_val
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    message,
                    status=status,
                    upstream_error=upstream,
                )
            files = _normalise_project_files(payload)

        response_payload = {"files": files}

        valid, errors = validate_payload("project_overview.v1.json", response_payload)
        if not valid:
            return response_schema_error("project_overview.v1.json", errors)
        return envelope_ok(response_payload)

    @server.tool()
    @tracked_tool(lock_usage=False)
    def get_current_program(client) -> Dict[str, object]:
        """Which program is active, and whether it is ready to query.

        Returns name, domain_file_id and analysis state: READY once
        auto-analysis has finished, LOADING while it runs. Most tools refuse to
        run unless READY, so call this when they report "Program is not ready".

        Not for: switching programs (select_program) or unsaved-work checks
        (check_dirty_state). Takes no parameters."""
        with request_scope(
            "current_program",
            logger=logger,
            extra={"tool": "get_current_program"},
        ):
            status_payload = client.get_current_program_status()
            if status_payload is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    "Failed to query the current program status upstream.",
                    upstream_error=upstream,
                )

            files = client.get_project_files()
            if files is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    "Failed to enumerate project files.",
                    upstream_error=upstream,
                )

            try:
                selection = normalize_selection(files, requestor=_current_requestor())
            except ProgramSelectionError as exc:
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    (
                        "Program selection is locked for this session; "
                        f"previous selection '{exc.current}' is unavailable."
                    ),
                    recovery=("Start a new session to switch programs.",),
                )
            state = selection.state
            warnings: list[str] = []
            if selection.warning:
                warnings.append(selection.warning)
            if state.domain_file_id is None:
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    "No program files are available in the current project.",
                )

            upstream_warnings = (
                status_payload.get("warnings")
                if isinstance(status_payload, Mapping)
                else None
            )
            state_value = str(status_payload.get("state", "IDLE")).upper()
            upstream_domain_id = (
                str(status_payload.get("domain_file_id"))
                if isinstance(status_payload, Mapping)
                else None
            )
            upstream_locked = bool(status_payload.get("locked"))

        selected_domain = state.domain_file_id or upstream_domain_id
        warnings: list[str] = []
        if selection.warning:
            warnings.append(selection.warning)
        if upstream_warnings:
            warnings.extend(str(item) for item in upstream_warnings)
        if selected_domain and upstream_domain_id and selected_domain != upstream_domain_id:
            warnings.append(
                "Requested program selection does not match the active program upstream."
            )

        if selected_domain is None:
            return envelope_error(
                ErrorCode.UNAVAILABLE,
                "No program files are available in the current project.",
            )

        payload = {
            "domain_file_id": selected_domain,
            "locked": state.locked or upstream_locked,
            "state": state_value,
        }
        if warnings:
            payload["warnings"] = warnings
        valid, errors = validate_payload("current_program.v1.json", payload)
        if not valid:
            return response_schema_error("current_program.v1.json", errors)
        return envelope_ok(payload)

    @server.tool()
    @tracked_tool(lock_usage=False)
    def select_program(client, domain_file_id: str, on_dirty: str = "error") -> Dict[str, object]:
        """Open a program from the current project, making it the active one.

        Not for: discovering what is available -- take domain_file_id from
        project_overview. Switching mid-session is governed by
        GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY.

        Args:
            domain_file_id: from project_overview.
            on_dirty: what to do if the current program has unsaved work --
                'error' (default, refuse), 'save' (save first) or 'discard'
                (switch and lose it)."""
        with request_scope(
            "select_program",
            logger=logger,
            extra={"tool": "select_program"},
        ):
            requestor = _current_requestor()
            files = client.get_project_files()
            if files is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    "Failed to enumerate project files.",
                    upstream_error=upstream,
                )

            if not validate_program_id(files, domain_file_id):
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    f"Unknown program id '{domain_file_id}'.",
                    recovery=("Use a domain_file_id from project_overview.",),
                )

            previous_state = PROGRAM_SELECTIONS.snapshot(requestor)
            try:
                selection = PROGRAM_SELECTIONS.select(requestor, domain_file_id)
            except ProgramSelectionError as exc:
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    (
                        "Program selection is locked for this session; "
                        f"currently using '{exc.current}'."
                    ),
                    recovery=("Start a new session to switch programs.",),
                )
            state = selection.state
            warnings: list[str] = []
            if selection.warning:
                warnings.append(selection.warning)
            autoopen_warnings, autoopen_error = _maybe_autoopen_program(
                client, files, state.domain_file_id, on_dirty
            )
            if autoopen_error:
                PROGRAM_SELECTIONS.restore(requestor, previous_state)
                return autoopen_error
            warnings.extend(autoopen_warnings)
            lock_selection_for_requestor(requestor)

            status_payload, status_warnings = _await_program_ready(client)
            warnings.extend(status_warnings)
            if status_payload is None:
                state_value = "IDLE"
            else:
                state_value = str(status_payload.get("state", "IDLE")).upper()

        payload = {
            "domain_file_id": state.domain_file_id,
            "locked": state.locked,
            "state": state_value,
        }
        if warnings:
            payload["warnings"] = warnings
        valid, errors = validate_payload("current_program.v1.json", payload)
        if not valid:
            return response_schema_error("current_program.v1.json", errors)
        return envelope_ok(payload)

    @server.tool()
    @tracked_tool()
    def goto_address(client, address: str) -> Dict[str, object]:
        """Move the CodeBrowser cursor to an address and centre it.

        Affects the Ghidra window only -- useful when you want to look at what
        the model is discussing. Returns no program data.

        Not for: reading anything. Use disassemble_at or read_bytes.

        Args:
            address: hex, e.g. '0x401000'."""
        with request_scope(
            "goto_address",
            logger=logger,
            extra={"tool": "goto_address", "address": address},
        ):
            if not address or not isinstance(address, str):
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    "address parameter is required and must be a string",
                )

            response = client.goto_address(address)
            if response is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    "Failed to navigate to address.",
                    upstream_error=upstream,
                )

            if response.get("status") == "error":
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    response.get("message", "Navigation failed"),
                )

            return envelope_ok({
                "address": response.get("address"),
                "message": response.get("message", "Navigated successfully")
            })

    @server.tool()
    @tracked_tool(lock_usage=False, require_ready=False)
    def list_mutations(client, fmt: str = "text") -> Dict[str, object]:
        """Everything this session changed since the last save_program.

        Renames, comments and data types, with address, old value and new
        value, rendered so the block drops straight into a commit
        message or a TRUTH line. It is the answer check_dirty_state cannot give:
        that tool knows *that* something is unsaved, this one knows *what*.

        Proposals are included and marked. A dry-run rename is a decision you
        made about the binary, worth writing down -- but it carries a
        "[proposed]" prefix, because a ledger where an intention reads as an
        accomplishment is worse than none.

        Not for: history. The list resets on a successful save_program, since
        everything before that is in the file. It also lives in this server
        process, so a restart loses it -- save first.

        Args:
            fmt: 'text' (default) returns `lines`, ready to paste; 'json'
                returns `mutations` as structured records.

        Returns summary (total, applied, proposed, by_kind) plus lines or
        mutations."""
        with request_scope(
            "list_mutations",
            logger=logger,
            extra={"tool": "list_mutations", "fmt": fmt},
        ):
            try:
                normalized_fmt = listing.normalize_fmt(fmt)
            except ValueError as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

            entries = mutations.since_last_save()
            payload: Dict[str, object] = {"summary": mutations.summarise(entries)}
            if normalized_fmt == "text":
                payload["lines"] = mutations.render_lines(entries)
            else:
                payload["mutations"] = [entry.as_dict() for entry in entries]

        valid, errors = validate_payload("list_mutations.v1.json", payload)
        if not valid:
            return response_schema_error("list_mutations.v1.json", errors)
        return envelope_ok(payload)

    @server.tool()
    @tracked_tool()
    def check_dirty_state(client) -> Dict[str, object]:
        """Report whether the active program has unsaved changes.

        Not for: finding out *what* changed -- it answers whether, not which.

        Takes no parameters. Returns changed (bool), can_save (bool),
        program_name and a human-readable message."""
        with request_scope(
            "check_dirty_state",
            logger=logger,
            extra={"tool": "check_dirty_state"},
        ):
            response = client.check_dirty_state()
            if response is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    "Failed to check dirty state.",
                    upstream_error=upstream,
                )

            if response.get("status") == "error":
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    response.get("message", "Failed to check dirty state"),
                )

            return envelope_ok({
                "changed": response.get("changed") == "true",
                "can_save": response.get("can_save") == "true",
                "program_name": response.get("program_name"),
                "message": response.get("message", "Dirty state checked")
            })

    @server.tool()
    @tracked_tool()
    def save_program(client, description: str | None = None) -> Dict[str, object]:
        """Persist unsaved changes to the active program.

        Requires ownership and a program that is not read-only.

        Not for: exporting anything -- this writes into the Ghidra project, not
        to a file you can version.

        Args:
            description: optional note about the changes, e.g. 'named USB
                handlers'.

        Returns saved (bool), program_name, mutations_cleared (how many entries
        list_mutations was holding) and a message."""
        with request_scope(
            "save_program",
            logger=logger,
            extra={"tool": "save_program", "description": description},
        ):
            response = client.save_program(description)
            if response is None:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    "Failed to save program.",
                    upstream_error=upstream,
                )

            if response.get("status") == "error":
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    response.get("error", "Failed to save program"),
                )

            saved = response.get("saved") == "true"
            # The ledger resets only on an actual save: after a no-op the
            # mutations are still unwritten, and list_mutations must keep saying so.
            cleared = mutations.mark_saved() if saved else 0
            return envelope_ok({
                "saved": saved,
                "program_name": response.get("program_name"),
                "mutations_cleared": cleared,
                "message": response.get("message", "Save operation completed")
            })

    @server.tool()
    @tracked_tool()
    def apply_label(
        client,
        address: str,
        name: str,
        *,
        dry_run: bool = True,
    ) -> Dict[str, object]:
        """Put a label at any address, including MMIO registers outside every
        memory block.

        The dry run still asks Ghidra: it validates the name and lists what
        is already there. Writing needs GHIDRA_MCP_ENABLE_WRITES=true. Not
        for: renaming a function (rename_function).

        Args:
            address: hex, e.g. '0xB1006000'.
            name: the label.
            dry_run: default true."""
        request_payload = {"address": address, "name": name, "dry_run": dry_run}
        valid, errors = validate_payload("apply_label.request.v1.json", request_payload)
        if not valid:
            return envelope_error(ErrorCode.INVALID_REQUEST, "; ".join(errors))
        with request_scope(
            "apply_label",
            logger=logger,
            extra={"tool": "apply_label", "address": address, "dry_run": dry_run},
            max_writes=1,
        ):
            try:
                data = labels.apply_label(
                    client,
                    address=parse_hex(address),
                    name=name,
                    dry_run=dry_run,
                    writes_enabled=enable_writes,
                )
            except labels.LabelRejected as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))
            except labels.LabelUnavailable as exc:
                return envelope_error(ErrorCode.UNAVAILABLE, str(exc))
        valid, errors = validate_payload("apply_label.v1.json", data)
        if not valid:
            return response_schema_error("apply_label.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def rename_function(
        client,
        address: str,
        new_name: str,
        *,
        dry_run: bool = True,
    ) -> Dict[str, object]:
        """Rename the function at an address.

        Needs GHIDRA_MCP_ENABLE_WRITES=true unless dry_run.

        Args:
            address: function entry, hex, e.g. '0x401000'.
            new_name: the new name.
            dry_run: default true; validate and report without renaming.

        Returns success (false in dry_run), address, new_name and a message."""
        with request_scope(
            "rename_function",
            logger=logger,
            extra={"tool": "rename_function", "address": address, "new_name": new_name, "dry_run": dry_run},
            max_writes=1,
        ):
            # Validate address format
            try:
                parsed_address = parse_hex(address)
            except ValueError as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

            # Validate new_name
            if not new_name or not isinstance(new_name, str):
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    "new_name parameter is required and must be a non-empty string",
                )

            previous_name = _current_function_name(client, parsed_address)

            # Dry run mode - return success without executing
            if dry_run:
                mutations.record(
                    kind="rename",
                    target=address,
                    old=previous_name,
                    new=new_name,
                    applied=False,
                    reason="dry_run",
                )
                return envelope_ok({
                    "success": False,
                    "address": address,
                    "new_name": new_name,
                    "message": f"DRY RUN: Would rename function at {address} to '{new_name}' (set dry_run=false to execute)"
                })

            # Check if writes are enabled
            if not enable_writes:
                mutations.record(
                    kind="rename",
                    target=address,
                    old=previous_name,
                    new=new_name,
                    applied=False,
                    reason="writes_disabled",
                )
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    "Write operations are disabled. Set GHIDRA_MCP_ENABLE_WRITES=true to enable.",
                    recovery=("Enable writes in environment configuration.",),
                )

            # Execute the rename
            success = client.rename_function(parsed_address, new_name)

            if not success:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    f"Failed to rename function at {address}",
                    upstream_error=upstream,
                )

            mutations.record(
                kind="rename",
                target=address,
                old=previous_name,
                new=new_name,
                applied=True,
            )
            return envelope_ok({
                "success": True,
                "address": address,
                "new_name": new_name,
                "message": f"Function at {address} renamed to '{new_name}'"
            })

    @server.tool()
    @tracked_tool()
    def set_comment(
        client,
        address: str,
        comment: str,
        *,
        comment_type: str = "decompiler",
        dry_run: bool = True,
    ) -> Dict[str, object]:
        """Add or replace a comment at an address.

        Needs GHIDRA_MCP_ENABLE_WRITES=true unless dry_run. Replaces any
        existing comment of the same type at that address rather than appending.

        Args:
            address: hex, e.g. '0x401000'.
            comment: the text.
            comment_type: 'decompiler' (default) or 'disassembly' -- they are
                separate comments and do not overwrite each other.
            dry_run: default true; validate and report without writing.

        Returns success (false in dry_run), address, comment, comment_type and
        a message."""
        with request_scope(
            "set_comment",
            logger=logger,
            extra={"tool": "set_comment", "address": address, "comment_type": comment_type, "dry_run": dry_run},
            max_writes=1,
        ):
            # Validate address format
            try:
                parsed_address = parse_hex(address)
            except ValueError as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

            # Validate comment
            if not comment or not isinstance(comment, str):
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    "comment parameter is required and must be a non-empty string",
                )

            # Validate comment_type
            if comment_type not in ("decompiler", "disassembly"):
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    f"comment_type must be 'decompiler' or 'disassembly', got '{comment_type}'",
                )

            # Dry run mode - return success without executing
            previous_comment = _current_function_comment(client, parsed_address)

            if dry_run:
                mutations.record(
                    kind="comment",
                    target=address,
                    old=previous_comment,
                    new=comment,
                    applied=False,
                    reason="dry_run",
                    detail=comment_type,
                )
                return envelope_ok({
                    "success": False,
                    "address": address,
                    "comment": comment,
                    "comment_type": comment_type,
                    "message": f"DRY RUN: Would set {comment_type} comment at {address} (set dry_run=false to execute)"
                })

            # Check if writes are enabled
            if not enable_writes:
                mutations.record(
                    kind="comment",
                    target=address,
                    old=previous_comment,
                    new=comment,
                    applied=False,
                    reason="writes_disabled",
                    detail=comment_type,
                )
                return envelope_error(
                    ErrorCode.INVALID_REQUEST,
                    "Write operations are disabled. Set GHIDRA_MCP_ENABLE_WRITES=true to enable.",
                    recovery=("Enable writes in environment configuration.",),
                )

            # Execute the comment set operation
            if comment_type == "decompiler":
                success = client.set_decompiler_comment(parsed_address, comment)
            else:  # disassembly
                success = client.set_disassembly_comment(parsed_address, comment)

            if not success:
                upstream = client.last_error.as_dict() if client.last_error else None
                return envelope_error(
                    ErrorCode.UNAVAILABLE,
                    f"Failed to set {comment_type} comment at {address}",
                    upstream_error=upstream,
                )

            mutations.record(
                kind="comment",
                target=address,
                old=previous_comment,
                new=comment,
                applied=True,
                detail=comment_type,
            )
            return envelope_ok({
                "success": True,
                "address": address,
                "comment": comment,
                "comment_type": comment_type,
                "message": f"{comment_type.capitalize()} comment set at {address}"
            })

    @server.tool()
    @tracked_tool()
    def analyze_function_complete(
        client,
        address: str,
        *,
        fields: list[str] | None = None,
        fmt: str = "json",
        max_result_tokens: int | None = None,
        options: dict[str, object] | None = None,
    ) -> Dict[str, object]:
        """One dossier for one function: xrefs, referenced strings, derived
        features and, on request, the disassembly and decompilation.

        The default answers "is this the function I want?" and costs about
        2 KB. It leaves out 'disasm' and 'decompile', which are 58% of a full
        dossier and which you can fetch on better terms once you know:
        disassemble_at returns the listing as text at half the bytes, and
        find_in_function returns only the lines that match.

        Not for: finding a function -- you must know its address.

        Args:
            address: function entry, hex, e.g. '0x002af9c0'.
            fields: sections to include, any of 'function' (name, entry,
                body range, prototype), 'disasm', 'decompile', 'xrefs',
                'callgraph', 'strings', 'constants' (words loaded from the
                constant pool), 'features' (derived counts). Default:
                function, xrefs, strings, constants, features. Naming any field replaces
                the default set rather than adding to it, so pass
                ['disasm'] to get only the listing.
            fmt: only 'json' is accepted (not disassemble_at's listing fmt).
            max_result_tokens: int ceiling on the response, or null (default)
                for none. When exceeded, disasm and decompile are trimmed and
                meta.truncated is set.
            options: per-section bounds, each range-checked (out of range is an
                error, not a clamp):
                disasm.before/after 0-64 (8), disasm.max_instructions 1-128 (48),
                xrefs.inbound_limit/outbound_limit 0-256 (40),
                callgraph.limit 0-256 (24), strings.limit 0-64 (6),
                constants.limit 0-64 (8),
                strings.max_cstring_len 1-1024 (256),
                decompile.enabled bool (true), decompile.max_lines 1-500 (120).

        range.span_bytes is end - start + 1, interior data included."""
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
            except ListingUnavailable as exc:
                return envelope_error(ErrorCode.UNAVAILABLE, str(exc))
            except ValueError as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload(
            "analyze_function_complete.v1.json", payload
        )
        if not valid:
            return response_schema_error("analyze_function_complete.v1.json", errors)
        return envelope_ok(payload)

    @server.tool()
    @tracked_tool()
    def collect(
        client,
        *,
        queries: list[dict[str, object]] | None = None,
        projects: list[dict[str, object]] | None = None,
        result_budget: dict[str, object] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> Dict[str, object]:
        """Run several read-only queries in one call, optionally across projects.

        Batches what would otherwise be separate round trips, and applies one
        shared token budget over the lot.

        Args:
            queries: in-project queries. Each needs an ``id`` and an ``op``,
                plus optional ``params`` (default {}), a per-query
                ``result_budget``, and ``metadata`` echoed back.
                Example: {"id": "head", "op": "disassemble_at",
                          "params": {"address": "0x401000", "count": 8}}
            projects: cross-project overrides. Each entry has an ``id``, its own
                ``queries`` list of the same shape, optional ``result_budget``
                and ``metadata``, and an alternate ``ghidra_url``/``base_url``
                for a remote instance.
            result_budget: shared budget. ``max_result_tokens`` is an int or
                null for unlimited; ``mode`` is "auto_trim" (soft cap) or
                "strict" (raise RESULT_TOO_LARGE when exceeded).
            metadata: arbitrary JSON returned unchanged.

        Supported ``op`` values and their params:
            disassemble_at              address, count (16), fmt ("json"/"text")
            disassemble_batch           addresses[], count (16), fmt,
                                        query, regex, case_sensitive,
                                        context_lines (0-16)
            read_bytes                  address, length (64)
            read_words                  address, count (1)
            search_strings              query, limit (20), page (1)
            strings_compact             limit (required), offset (0)
            string_xrefs                string_addr, limit (20)
            search_imports              query, limit (20), page (1)
            search_exports              query, limit (20), page (1)
            search_functions            query, limit (20), page (1),
                                        rank="simple" with k, resume_cursor
                                        (excludes rank), context_lines (0-16)
            search_xrefs_to             address, query (required, may be ""),
                                        limit (20), page (1)
            search_scalars              value (dec or hex), query, limit (20),
                                        page (1), resume_cursor
            search_scalars_with_context value, context_lines (0-16, default 4),
                                        limit (20), fmt

        Each query returns its own envelope. Aggregate metadata records the
        total token estimate across all queries and projects."""
        request_payload: Dict[str, object] = {}
        if queries is not None:
            request_payload["queries"] = [dict(item) for item in queries]
        if projects is not None:
            request_payload["projects"] = [dict(item) for item in projects]
        if result_budget is not None:
            request_payload["result_budget"] = dict(result_budget)
        if metadata is not None:
            request_payload["metadata"] = dict(metadata)

        friendly_error = _detect_collect_misspecifications(request_payload)
        if friendly_error:
            return envelope_error(ErrorCode.INVALID_REQUEST, friendly_error)

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
            return response_schema_error("collect.v1.json", errors)
        return envelope_ok(response_payload)

    @server.tool()
    @tracked_tool()
    def datatypes_create(
        client,
        *,
        kind: str,
        name: str,
        category: str,
        fields: list[dict[str, object]],
        dry_run: bool = True,
    ) -> Dict[str, object]:
        """Create a structure or union in the data type manager.

        Not for: applying the type to an address -- this only defines it. Not
        for editing an existing one (datatypes_update); a duplicate name is an
        error. Needs GHIDRA_MCP_ENABLE_WRITES=true.

        Args:
            kind: 'structure' or 'union'; nothing else.
            name: type name, must not exist in the category.
            category: path in the data type manager, e.g. '/USB', '/' for root.
            fields: at least one member, each {name, type, offset?, length?}.
                type is a Ghidra type name ('uint', 'char[16]', 'void *').
                offset is bytes from the start, >= 0, required for structures.
                length is size in bytes, >= 0, optional. Structure fields are
                sorted by offset; overlaps are rejected by Ghidra on apply.
            dry_run: default true; report the layout without creating it."""
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
            return response_schema_error("datatypes_create.v1.json", errors)
        return envelope_ok(payload)

    @server.tool()
    @tracked_tool()
    def datatypes_update(
        client,
        *,
        kind: str,
        path: str,
        fields: list[dict[str, object]],
        dry_run: bool = True,
    ) -> Dict[str, object]:
        """Replace the fields of an existing structure or union.

        Not for: partial edits -- the list replaces the existing one wholesale,
        so fields you leave out are gone. Read the current definition first;
        every place the type is applied follows the new layout. Needs
        GHIDRA_MCP_ENABLE_WRITES=true.

        Args:
            kind: 'structure' or 'union'; must match what the type is.
            path: full path of the type, e.g. '/USB/USBD_Regs'.
            fields: at least one member, each {name, type, offset?, length?};
                same shape as datatypes_create.
            dry_run: default true; report the layout without changing anything."""
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
            return response_schema_error("datatypes_update.v1.json", errors)
        return envelope_ok(payload)

    @server.tool()
    @tracked_tool()
    def datatypes_delete(
        client,
        *,
        kind: str,
        path: str,
        dry_run: bool = True,
    ) -> Dict[str, object]:
        """Delete a structure or union from the data type manager.

        Not for: use while the type is applied -- every location using it
        reverts to undefined data, with no undo through this API. Needs
        GHIDRA_MCP_ENABLE_WRITES=true.

        Args:
            kind: 'structure' or 'union'; must match what the type is.
            path: full path of the type, e.g. '/USB/USBD_Regs'.
            dry_run: default true; report without deleting."""
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
            return response_schema_error("datatypes_delete.v1.json", errors)
        return envelope_ok(payload)

    @server.tool()
    @tracked_tool()
    def jt_slot_check(
        client,
        jt_base: str,
        slot_index: int,
        code_min: str,
        code_max: str,
        arch: str = "auto",
    ) -> Dict[str, object]:
        """Read one jump-table slot and judge whether it holds a code pointer.

        Reads the word at jt_base + slot_index*4, rejects it if it looks like an
        instruction or falls outside the code range, and reports ARM/Thumb mode
        and the target function. Read-only.

        Not for: finding the table -- a wrong jt_base yields confident nonsense,
        since every slot resolves to something. Check with jt_scan first.

        Args:
            jt_base: table start, hex.
            slot_index: slot number, >= 0.
            code_min: lower bound of the valid code range, hex.
            code_max: upper bound of the valid code range, hex.
            arch: 'auto' (default), 'arm' or 'thumb' -- all use the ARM/Thumb
                decoder, which strips the Thumb bit. Other values fall back to a
                passthrough decoder unless enabled via
                BRIDGE_OPTIONAL_ADAPTERS."""
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
            return response_schema_error("jt_slot_check.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
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
        """Check one jump-table slot and name the function it points at.

        jt_slot_check plus a rename and a comment on the target, verified
        afterwards and recorded in the audit log.

        Not for: bulk work -- one slot per call, and the write limit applies
        (GHIDRA_MCP_MAX_WRITES_PER_REQUEST, 2). A wrong jt_base renames real
        functions after table entries that do not exist; run jt_scan first.
        Needs GHIDRA_MCP_ENABLE_WRITES=true.

        Args:
            jt_base: table start, hex.
            slot_index: slot number, >= 0.
            code_min: lower bound of the valid code range, hex.
            code_max: upper bound of the valid code range, hex.
            rename_pattern: new name for the target; '{slot}' is replaced by the
                slot index, e.g. 'jt_handler_{slot}'.
            comment: comment placed at the target function.
            dry_run: default true; report without applying.
            arch: 'auto' (default), 'arm' or 'thumb'; see jt_slot_check."""
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
            return response_schema_error("jt_slot_process.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def jt_scan(
        client,
        jt_base: str,
        start: int,
        count: int,
        code_min: str,
        code_max: str,
        arch: str = "auto",
    ) -> Dict[str, object]:
        """Check a run of jump-table slots in one call.

        jt_slot_check over count consecutive slots plus a summary. The way to
        confirm a suspected base: a correct one gives a long run of valid slots,
        a wrong one scattered rejects. Never writes.

        Args:
            jt_base: table start, hex.
            start: first slot index, >= 0.
            count: consecutive slots, >= 1, <= 256
                (GHIDRA_MCP_MAX_ITEMS_PER_BATCH). One memory read each.
            code_min: lower bound of the valid code range, hex.
            code_max: upper bound of the valid code range, hex.
            arch: 'auto' (default), 'arm' or 'thumb'; see jt_slot_check."""
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
            return response_schema_error("jt_scan.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def string_xrefs_compact(
        client,
        string_addr: str,
        limit: int = 20,
    ) -> Dict[str, object]:
        """List the code locations referencing one string, compactly.

        Second half of the string-to-function path: search_strings gives the
        address, this gives the users.

        Not for: references Ghidra never recognised. An empty result means
        Ghidra sees none, not that nothing uses the string.

        Args:
            string_addr: the string's address, hex, from search_strings.
            limit: max references, >= 1, default 20."""
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
            try:
                data = strings.xrefs_compact(
                    client,
                    string_addr=parse_hex(string_addr),
                    limit=limit,
                )
            except ListingUnavailable as exc:
                return envelope_error(ErrorCode.UNAVAILABLE, str(exc))
        valid, errors = validate_payload("string_xrefs.v1.json", data)
        if not valid:
            return response_schema_error("string_xrefs.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def search_strings(
        client,
        query: str,
        limit: int = 20,
        page: int = 1,
        include_literals: bool = False,
    ) -> Dict[str, object]:
        """Find defined strings whose text matches a query.

        Feeds straight into string_xrefs_compact, which is usually the fastest
        route to a named function on a stripped binary.

        Not for: bytes Ghidra never defined as a string. On zero hits the response carries a method_note with the way around it.

        Args:
            query: substring, case-insensitive, non-empty.
            limit: results per page, >= 1, default 20. limit*page must stay <= 256 (GHIDRA_MCP_MAX_ITEMS_PER_BATCH).
            page: 1-based, >= 1, default 1.
            include_literals: include the text, truncated to 120 chars. Default
                false, which returns addresses only and is markedly cheaper."""
        request_payload = {
            "query": query,
            "limit": limit,
            "page": page,
            "include_literals": include_literals,
        }
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
                    include_literals=include_literals,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_strings.v1.json", data)
        if not valid:
            return response_schema_error("search_strings.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def strings_compact(
        client,
        limit: int = 20,
        offset: int = 0,
        include_literals: bool = False,
    ) -> Dict[str, object]:
        """Page through all defined strings, without a query.

        Reconnaissance for when you do not yet know what to search for.

        Not for: targeted lookups (search_strings is cheaper). Sees only
        strings Ghidra defined as data, so an empty page says nothing about the
        raw bytes.

        Args:
            limit: strings per page, >= 1, default 20. limit+offset must stay
                <= 256 (GHIDRA_MCP_MAX_ITEMS_PER_BATCH).
            offset: strings to skip, >= 0, default 0.
            include_literals: include the text, truncated to 120 chars, default
                false.

        Returns `returned` (entries on this page), `items`, `has_more` and
        `truncated`. There is no total: paging through the string table never
        learns one, and a page length under that name would be a made-up
        figure."""
        request_payload = {
            "limit": limit,
            "offset": offset,
            "include_literals": include_literals,
        }
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
            raw_entries, has_more = strings.fetch_strings_compact_entries(
                client, limit=limit, offset=offset
            )
            try:
                data = strings.strings_compact_view(
                    raw_entries,
                    include_literals=include_literals,
                    has_more=has_more,
                )
            except (TypeError, ValueError) as exc:
                return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))

        valid, errors = validate_payload("strings_compact.v1.json", data)
        if not valid:
            return response_schema_error("strings_compact.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def search_imports(
        client,
        query: str,
        limit: int = 20,
        page: int = 1,
    ) -> Dict[str, object]:
        """Find imported symbols whose name matches a query.

        Not for: statically linked firmware, which has essentially none -- the
        reference image has one. An empty result there is expected.

        Args:
            query: substring, case-insensitive, non-empty.
            limit: results per page, >= 1, default 20. limit*page must stay <= 256 (GHIDRA_MCP_MAX_ITEMS_PER_BATCH).
            page: 1-based, >= 1, default 1."""

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
            return response_schema_error("search_imports.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def search_exports(
        client,
        query: str,
        limit: int = 20,
        page: int = 1,
    ) -> Dict[str, object]:
        """Find exported symbols whose name matches a query.

        On bare-metal firmware the exports are usually vector-table entries.

        Not for: discovering internal functions -- most are not exported. Use
        search_functions or list_functions_in_range.

        Args:
            query: substring, case-insensitive, non-empty.
            limit: results per page, >= 1, default 20. limit*page must stay <= 256 (GHIDRA_MCP_MAX_ITEMS_PER_BATCH).
            page: 1-based, >= 1, default 1."""

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
            return response_schema_error("search_exports.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def search_xrefs_to(
        client,
        address: str,
        query: str,
        limit: int = 20,
        page: int = 1,
    ) -> Dict[str, object]:
        """List the locations that reference an address.

        Not for: references Ghidra never recognised, such as computed branches or hand-rolled tables. On zero hits the response carries a method_note with the way around it.

        Args:
            address: target, hex, e.g. '0x002af9c0'.
            query: substring filter on referencing symbol names; '' keeps all.
            limit: results per page, >= 1, default 20. limit*page must stay <= 256 (GHIDRA_MCP_MAX_ITEMS_PER_BATCH).
            page: 1-based, >= 1, default 1."""

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
            return response_schema_error("search_xrefs_to.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def search_functions(
        client,
        query: str,
        limit: int = 20,
        page: int = 1,
        *,
        rank: str | None = None,
        k: int | None = None,
        context_lines: int = 0,
    ) -> Dict[str, object]:
        """Find functions whose name matches a query.

        Not for: finding functionality -- this matches names, and a stripped binary has none. On zero hits the response carries a method_note with the way around it.

        Args:
            query: substring, case-insensitive, non-empty.
            limit: results per page, >= 1, default 20. limit*page must stay <= 256 (GHIDRA_MCP_MAX_ITEMS_PER_BATCH).
            page: 1-based, >= 1, default 1.
            rank: only 'simple' is recognised, sorting by match quality; null
                (default) keeps address order. Excludes cursor pagination.
            k: with rank='simple', keep the best k, >= 1. Ignored otherwise.
            context_lines: disassembly lines per hit, >= 0, default 0. Every
                line multiplies the response."""
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
            return response_schema_error("search_functions.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def find_in_function(
        client,
        address: str,
        query: str,
        mode: str = "both",
        regex: bool = False,
        case_sensitive: bool = False,
        context_lines: int = 3,
        limit: int = 20,
        fmt: str = "text",
    ) -> Dict[str, object]:
        """Search a function's disassembly or decompilation for a pattern.

        Filters server-side and returns only the matching lines with context,
        which is what makes it far cheaper than disassembling and reading.

        Args:
            address: function entry, hex, e.g. '0x401000'.
            query: literal text, or a regex when regex=True.
            mode: 'disasm', 'decompile' or 'both' (default).
            regex: treat query as a regex, default false.
            case_sensitive: default false.
            context_lines: lines each side of a match, default 3, max 16.
            limit: matches per mode, default 20, max 200.
            fmt: 'text' (default; merged windows, '--' between) or 'json'.

        Example: find_in_function('0x002af9c0', 'ldr') to locate the constant
        pool a function loads from."""
        try:
            with request_scope(
                "find_in_function",
                logger=logger,
                extra={"tool": "find_in_function", "address": address, "query": query},
            ):
                data = search_function.find_in_function(
                    client,
                    address=parse_hex(address),
                    query=query,
                    mode=mode,
                    regex=regex,
                    case_sensitive=case_sensitive,
                    context_lines=context_lines,
                    limit=limit,
                    fmt=str(fmt).strip().lower(),
                )
        except ValueError as exc:
            return envelope_error(ErrorCode.INVALID_REQUEST, str(exc))
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def mmio_annotate_compact(
        client,
        function_addr: str,
        dry_run: bool = True,
        max_samples: int = 8,
    ) -> Dict[str, object]:
        """Summarise a function's memory-mapped I/O accesses, optionally
        commenting them.

        Counts reads, writes and the read-modify-write patterns (OR, AND,
        toggle) that mark register manipulation, and returns sample lines
        rather than the whole function.

        Addresses are Ghidra's own references: every load/store whose target
        lies outside the loaded image -- peripherals, and RAM the image does
        not map. Constant-pool loads and stack accesses are not counted;
        'skipped' is what Ghidra could not place.

        Args:
            function_addr: function entry, hex.
            dry_run: default true; classify without writing comments. Writing
                also needs GHIDRA_MCP_ENABLE_WRITES=true.
            max_samples: sample lines, >= 1, default 8, <= 256
                (GHIDRA_MCP_MAX_ITEMS_PER_BATCH)."""
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
        except ListingUnavailable as exc:
            return envelope_error(ErrorCode.UNAVAILABLE, str(exc))
        valid, errors = validate_payload("mmio_annotate.v1.json", data)
        if not valid:
            return response_schema_error("mmio_annotate.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def search_scalars(
        client,
        value: str | int,
        limit: int = 20,
        page: int = 1,
    ) -> Dict[str, object]:
        """Find instructions whose operand is a given constant.

        Not for: constants held in a constant pool -- this reads instruction operands only. On zero hits the response carries a method_note with the way around it.

        Args:
            value: the constant, hex string '0xB1008000' or int.
            limit: results per page, >= 1, default 20.
            page: 1-based, >= 1, default 1.

        size counts body bytes, not end minus start; a thunk shares its
        target's name and is flagged is_thunk."""

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
            return response_schema_error("search_scalars.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def list_functions_in_range(
        client,
        address_min: str,
        address_max: str,
        limit: int = 20,
        page: int = 1,
    ) -> Dict[str, object]:
        """List the functions defined within an address range, in address order.

        Not for: searching by name or behaviour. Narrow the range rather than paging: the
        response grows with the number of functions, not with their size.

        Args:
            address_min: inclusive lower bound, hex, e.g. '0x002af000'.
            address_max: inclusive upper bound, hex, >= address_min.
            limit: results per page, >= 1, default 20.
            page: 1-based, >= 1, default 1."""

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
        except ListingUnavailable as exc:
            return envelope_error(ErrorCode.UNAVAILABLE, str(exc))

        valid, errors = validate_payload("list_functions_in_range.v1.json", data)
        if not valid:
            return response_schema_error("list_functions_in_range.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def disassemble_at(
        client,
        address: str,
        count: int = 16,
        fmt: str = "text",
    ) -> Dict[str, object]:
        """Disassemble a run of instructions at an address.

        Not for: locating anything, or several places at once
        (disassemble_batch). When you only want matching lines,
        find_in_function filters server-side and returns a fraction of this.

        Args:
            address: start, hex, inside a mapped block.
            count: instructions, >= 1, default 16, clamped to 128.
            fmt: 'text' (default) returns lines as "address: bytes mnemonic"
                strings; 'json' returns items as objects, at roughly twice the
                bytes. Pass 'json' when you need the fields separately.

        Undefined bytes are skipped; coverage and a method_note then say so."""

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
                    fmt=fmt,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("disassemble_at.v1.json", data)
        if not valid:
            return response_schema_error("disassemble_at.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def read_bytes(
        client,
        address: str,
        length: int,
        include_literals: bool = False,
    ) -> Dict[str, object]:
        """Read raw bytes from memory, returned as base64.

        Not for: searching -- there is no byte-search on this server. For
        32-bit words use read_words, which decodes them.

        Args:
            address: start, hex, inside a mapped block.
            length: bytes, >= 1, clamped to 4096.
            include_literals: add a decoded ASCII rendering, default false."""

        request_payload = {
            "address": address,
            "length": length,
            "include_literals": include_literals,
        }
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
                    include_literals=include_literals,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("read_bytes.v1.json", data)
        if not valid:
            return response_schema_error("read_bytes.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def disassemble_batch(
        client,
        addresses: list[str],
        count: int = 16,
        fmt: str = "text",
        query: str = "",
        regex: bool = False,
        case_sensitive: bool = False,
        context_lines: int = 0,
    ) -> Dict[str, object]:
        """Disassemble several addresses in one call, optionally filtered.

        With a query it answers "every constant-pool load in these four
        functions" in one call and returns only those lines: 4 addresses x 16
        instructions is 64 lines, of which 12 match.

        Not for: locating the addresses -- you bring those. Without a query it
        returns every instruction for every address, so 20 addresses at the
        default count is 320 lines.

        Args:
            addresses: list of hex strings, e.g. ['0x1000', '0x2000']. Bounded
                by GHIDRA_MCP_MAX_ITEMS_PER_BATCH (256).
            count: instructions per address, >= 1, default 16.
            fmt: 'text' (default) or 'json'; see disassemble_at.
            query: keep only instructions matching this. Empty (default)
                returns everything, unchanged. Matched against the rendered
                line, so the address and the encoded bytes are searchable --
                the same rule as find_in_function.
            regex: treat query as a regular expression, default false. A
                literal query is escaped, so '[0x2afb34]' searches for that
                operand instead of a character class.
            case_sensitive: default false.
            context_lines: instructions kept either side of a match, 0-16,
                default 0. find_in_function defaults to 3 because it scans a
                whole function; here you already chose the addresses.

        Returns results keyed by address string. With a query it also returns
        `filter` (what was asked for) and `summary` with scanned, matched and
        returned counts, so a filtered listing cannot be read as a complete
        one. Skipped bytes appear under `coverage`."""
        request_payload = {
            "addresses": addresses,
            "count": count,
            "fmt": fmt,
            "query": query,
            "regex": regex,
            "case_sensitive": case_sensitive,
            "context_lines": context_lines,
        }
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
                    fmt=fmt,
                    query=query,
                    regex=regex,
                    case_sensitive=case_sensitive,
                    context_lines=context_lines,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("disassemble_batch.v1.json", data)
        if not valid:
            return response_schema_error("disassemble_batch.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def read_words(
        client,
        address: str,
        count: int = 1,
        include_literals: bool = False,
    ) -> Dict[str, object]:
        """Read consecutive 32-bit words and return them as integers.

        Little-endian, decoded rather than base64. This is the tool for reading
        a constant pool: when search_scalars reports nothing, the value is
        usually sitting here as data.

        Not for: searching -- you must know the address.

        Args:
            address: start, hex, e.g. '0x002afb34', inside a mapped block.
            count: words, >= 1, default 1, <= 256
                (GHIDRA_MCP_MAX_ITEMS_PER_BATCH).
            include_literals: add a literals array with each word's four raw
                bytes base64-encoded, default false. Useful when a word may be
                four ASCII characters.

        Returns words as hex strings ('0xb1008000'), null where the address
        could not be read. Hex because these are register addresses and masks:
        a transcription error is visible in hex and invisible in decimal. null
        means unreadable, not zero."""
        request_payload = {
            "address": address,
            "count": count,
            "include_literals": include_literals,
        }
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
                    include_literals=include_literals,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("read_words.v1.json", data)
        if not valid:
            return response_schema_error("read_words.v1.json", errors)
        return envelope_ok(data)

    @server.tool()
    @tracked_tool()
    def search_scalars_with_context(
        client,
        value: str | int,
        context_lines: int = 4,
        limit: int = 20,
        fmt: str = "text",
    ) -> Dict[str, object]:
        """search_scalars plus a disassembly window per hit.

        Historically the most expensive call here: at the old default of 100
        with 4 context lines one call returned ~900 lines of disassembly, and
        two such calls were 61% of the reference run. The default is now 20,
        and the window comes back as text unless you ask for fmt='json'.

        Not for: constants held in a constant pool -- this reads instruction operands only. On zero hits the response carries a method_note with the way around it.

        Args:
            value: the constant, hex string '0xB1008000' or int.
            context_lines: instructions each side of a hit, >= 0, default 4.
            limit: results per page, >= 1, default 20.
            page: 1-based, >= 1, default 1.
            fmt: 'text' (default) puts rendered lines under lines; 'json' puts
                instruction objects under disassembly, at roughly twice the
                bytes."""
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
                    fmt=fmt,
                )
        except SafetyLimitExceeded as exc:
            return envelope_error(ErrorCode.RESULT_TOO_LARGE, str(exc))

        valid, errors = validate_payload("search_scalars_with_context.v1.json", data)
        if not valid:
            return response_schema_error("search_scalars_with_context.v1.json", errors)
        return envelope_ok(data)


def _coerce_mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _normalise_project_files(payload: object) -> List[Dict[str, object]]:
    files: List[Dict[str, object]] = []
    if not isinstance(payload, list):
        return files
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get("type")
        if not isinstance(entry_type, str):
            continue
        entry_id = entry.get("domain_file_id")
        size = _coerce_int(entry.get("size"))
        files.append(
            {
                "domain_file_id": str(entry_id) if entry_id is not None else None,
                "name": str(entry.get("name", "")),
                "path": str(entry.get("path", "")),
                "type": entry_type,
                "size": size,
            }
        )
    return files


def _coerce_int(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


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

    notes = layout_notes(data)
    if notes:
        data["layout_notes"] = notes
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
