"""HTTP client wrapper around the Ghidra MCP bridge plugin."""
from __future__ import annotations

import ast
import base64
import json
from jsonschema import Draft202012Validator
from dataclasses import dataclass, field
import logging
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    TypeVar,
)
from urllib.parse import urljoin

import httpx
from time import perf_counter

from .models import FunctionMeta, Xref
from .whitelist import DEFAULT_WHITELIST, WhitelistEntry
from ..utils.logging import current_request, increment_counter, scoped_timer

logger = logging.getLogger("ghidra.bridge.client")


T = TypeVar("T")


ENDPOINT_CANDIDATES: Mapping[str, Iterable[str]] = {
    "DISASSEMBLE": ("disassemble", "disassemble_function", "disasmByAddr"),
    "FUNC_BY_ADDR": ("function_by_addr", "get_function_by_address", "functionMeta"),
    "GET_XREFS_TO": ("get_xrefs_to", "xrefs_to"),
    "DECOMPILE": (
        "decompile_function",
        "decompileFunction",
        "decompile_by_addr",
        "decompileByAddr",
    ),
    "OPEN_PROGRAM": ("open_program",),
    "CURRENT_PROGRAM_STATUS": ("api/current_program.json", "current_program"),
}

POST_ENDPOINT_CANDIDATES: Mapping[str, Iterable[str]] = {
    "RENAME_FUNCTION": (
        "rename_function_by_address",
        "renameFunctionByAddress",
    ),
    "SET_DECOMPILER_COMMENT": (
        "set_decompiler_comment",
        "setDecompilerComment",
    ),
    "SET_DISASSEMBLY_COMMENT": (
        "set_disassembly_comment",
        "setDisassemblyComment",
    ),
    "START_TRANSACTION": ("startTransaction",),
    "COMMIT_TRANSACTION": ("commitTransaction",),
    "ROLLBACK_TRANSACTION": ("rollbackTransaction",),
    "WRITE_BYTES": ("writeBytes",),
    "REBUILD_CODE_UNITS": ("rebuildCodeUnits",),
    "REBASE_PROGRAM": ("rebaseProgram", "rebase_program"),
    "CREATE_STRUCTURE": ("createStructure", "create_structure"),
    "UPDATE_STRUCTURE": ("updateStructure", "update_structure"),
    "CREATE_UNION": ("createUnion", "create_union"),
    "UPDATE_UNION": ("updateUnion", "update_union"),
    "DELETE_DATATYPE": ("deleteDataType", "delete_datatype"),
}


@dataclass(slots=True)
class EndpointResolver:
    candidates: Mapping[str, Iterable[str]]
    _cache: MutableMapping[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._cache = {}

    def resolve(self, key: str, requester: "EndpointRequester") -> List[str]:
        cached = self._cache.get(key)
        if cached:
            result = requester.request(cached)
            if not _is_error(result):
                return result
        last_error: List[str] = [f"ERROR: no candidates for {key}"]
        for candidate in self.candidates.get(key, (key,)):
            result = requester.request(candidate)
            if not _is_error(result):
                self._cache[key] = candidate
                return result
            last_error = result
        return last_error


class EndpointRequester:
    def __init__(
        self,
        client: "GhidraClient",
        method: str,
        *,
        key: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.client = client
        self.method = method
        self.key = key
        self.params = params or {}
        self.data = data if data is not None else {}

    def request(self, path: str) -> List[str]:
        if self.method == "GET":
            return self.client._request_lines("GET", path, key=self.key, params=self.params)
        if self.method == "POST":
            return self.client._request_lines(
                "POST", path, key=self.key, data=self.data
            )
        raise ValueError(f"Unsupported method {self.method}")


def _is_error(lines: object) -> bool:
    if isinstance(lines, RequestError):
        return True
    if isinstance(lines, list) and lines:
        first = lines[0]
        return isinstance(first, str) and first.startswith("ERROR:")
    return False


def _error_summary(data: object) -> str:
    if isinstance(data, RequestError):
        status = data.status if data.status is not None else "unknown"
        return f"status={status}, reason={data.reason}, retryable={data.retryable}"
    if isinstance(data, list) and data:
        return str(data[0])
    return str(data)


def _parse_xref_lines(lines: Iterable[str]) -> List[Xref]:
    logger.warning(
        "_parse_xref_lines is deprecated; the plugin should return JSON envelopes",
    )
    out: List[Xref] = []
    for raw in lines:
        parts = raw.split("|", 1)
        if not parts:
            continue
        addr_str = parts[0].strip()
        context = parts[1].strip() if len(parts) > 1 else ""
        try:
            addr_val = int(addr_str, 16)
        except ValueError:
            continue
        out.append({"addr": addr_val, "context": context})
    return out


def _has_confirm_true(
    params: Optional[Mapping[str, Any]], data: Optional[Mapping[str, Any]]
) -> bool:
    def _matches(mapping: Optional[Mapping[str, Any]]) -> bool:
        if not mapping:
            return False
        for key, value in mapping.items():
            if key.lower() == "confirm" and str(value).lower() in {"true", "1", "yes"}:
                return True
        return False

    return _matches(params) or _matches(data)


@dataclass(slots=True)
class RequestError:
    """Structured transport error returned when upstream HTTP calls fail."""

    status: Optional[int]
    reason: str
    retryable: bool

    def as_dict(self) -> Dict[str, object]:
        return {"status": self.status, "reason": self.reason, "retryable": self.retryable}


@dataclass(slots=True)
class CursorPageResult(Generic[T]):
    """Structured payload returned by cursor-aware plugin endpoints."""

    items: List[T]
    has_more: bool
    cursor: Optional[str]
    error: Optional[object] = None


@dataclass(slots=True)
class DataTypeOperationResult:
    """Canonicalised response returned by data-type management calls."""

    ok: bool
    error: Optional[object] = None
    datatype: Optional[Dict[str, Any]] = None
    details: Optional[Dict[str, Any]] = None
    transport_error: Optional[RequestError] = None


class GhidraClient:
    """Small wrapper that handles whitelist enforcement and alias resolution."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        whitelist: Optional[Mapping[str, Iterable[WhitelistEntry]]] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.base_url = base_url if base_url.endswith("/") else f"{base_url}/"
        self.timeout = timeout
        self._session = httpx.Client(timeout=timeout, transport=transport)
        self._whitelist = whitelist or DEFAULT_WHITELIST
        self._get_resolver = EndpointResolver(ENDPOINT_CANDIDATES)
        self._post_resolver = EndpointResolver(POST_ENDPOINT_CANDIDATES)
        self._last_error: Optional[RequestError] = None
        self._validators = {
            "xrefs": Draft202012Validator(
                {
                    "type": "object",
                    "required": ["items", "has_more"],
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["address", "context"],
                                "properties": {
                                    "address": {"type": "string"},
                                    "context": {"type": "string"},
                                },
                                "additionalProperties": False,
                            },
                        },
                        "has_more": {"type": "boolean"},
                        "error": {"type": "string"},
                    },
                    "additionalProperties": False,
                }
            ),
            "strings": Draft202012Validator(
                {
                    "type": "object",
                    "required": ["items", "has_more"],
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["address", "literal"],
                                "properties": {
                                    "address": {"type": "string"},
                                    "literal": {"type": "string"},
                                },
                                "additionalProperties": False,
                            },
                        },
                        "has_more": {"type": "boolean"},
                        "error": {"type": "string"},
                    },
                    "additionalProperties": False,
                }
            ),
            "symbols": Draft202012Validator(
                {
                    "type": "object",
                    "required": ["items", "has_more"],
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "has_more": {"type": "boolean"},
                        "error": {"type": "string"},
                    },
                    "additionalProperties": False,
                }
            ),
        }

    # ------------------------------------------------------------------
    # low level
    # ------------------------------------------------------------------

    @property
    def last_error(self) -> Optional[RequestError]:
        """Return the most recent transport error, if any."""

        return self._last_error

    def _is_allowed(self, method: str, *, key: Optional[str] = None, path: Optional[str] = None) -> bool:
        entries = self._whitelist.get(method.upper(), ())
        if key is not None:
            for entry in entries:
                if entry.key == key:
                    if path is None:
                        return True
                    return entry.allows(path)
            return False
        if path is not None:
            return any(entry.allows(path) for entry in entries)
        raise ValueError("Either key or path must be provided for whitelist checks")

    def _request_lines(
        self,
        method: str,
        path: str,
        *,
        key: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> List[str] | RequestError:
        self._last_error = None
        if not self._is_allowed(method, key=key, path=path):
            logger.error("Attempted to call non-whitelisted endpoint %s %s", method, path)
            return [f"ERROR: endpoint {method} {path} not allowed"]
        if _has_confirm_true(params=params, data=data):
            logger.error(
                "Attempted to call endpoint %s %s with confirm=true, blocking for safety",
                method,
                path,
            )
            return [f"ERROR: endpoint {method} {path} not allowed"]
        url = urljoin(self.base_url, path)
        context = current_request()
        timer_extra: Dict[str, Any]
        if context is not None:
            timer_extra = context.extra(
                event="timer",
                operation=f"ghidra.{method.lower()}",
                path=path,
            )
        else:  # pragma: no cover - request scope always set in integration tests
            timer_extra = {"event": "timer", "operation": f"ghidra.{method.lower()}", "path": path}
        with scoped_timer(logger, f"ghidra.{method.lower()}", extra=timer_extra):
            start = perf_counter()
            try:
                response = self._session.request(method, url, params=params, data=data)
            except httpx.HTTPError as exc:  # pragma: no cover - transport errors are environment specific
                duration_ms = (perf_counter() - start) * 1000.0
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                retryable = bool(status_code is None or int(status_code) >= 500)
                self._last_error = RequestError(
                    status=int(status_code) if status_code is not None else None,
                    reason=str(exc),
                    retryable=retryable,
                )
                logger.warning(
                    "ghidra.request",
                    extra={
                        "method": method,
                        "path": path,
                        "duration_ms": duration_ms,
                        "error": str(exc),
                    },
                )
                return self._last_error
        duration_ms = (perf_counter() - start) * 1000.0
        logger.info(
            "ghidra.request",
            extra={
                "method": method,
                "path": path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        if response.is_error:
            retryable = int(response.status_code) >= 500 if response.status_code is not None else False
            self._last_error = RequestError(
                status=int(response.status_code) if response.status_code is not None else None,
                reason=response.text.strip(),
                retryable=retryable,
            )
            return self._last_error
        self._last_error = None
        text = response.text
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, Mapping) and "error" in payload:
            message = str(payload.get("error"))
            retryable = int(response.status_code) >= 500 if response.status_code is not None else False
            self._last_error = RequestError(
                status=int(response.status_code) if response.status_code is not None else None,
                reason=message,
                retryable=retryable,
            )
            return self._last_error
        lines = text.replace("\r\n", "\n").splitlines()
        return lines

    def _request_json_payload(
        self,
        method: str,
        path: str,
        *,
        key: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        schema_key: Optional[str] = None,
    ) -> Optional[Mapping[str, Any]]:
        lines = self._request_lines(method, path, key=key, params=params, data=data)
        if _is_error(lines):
            logger.warning("%s request failed: %s", path, _error_summary(lines))
            return None
        text = "\n".join(line for line in lines if line is not None).strip()
        if not text:
            logger.warning("%s returned empty payload", path)
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            logger.warning(
                "%s returned invalid JSON", path, extra={"error": str(exc), "preview": text[:256]}
            )
            return None
        if schema_key is not None:
            validator = self._validators.get(schema_key)
            if validator is None:
                logger.warning("No validator configured for %s", schema_key)
            else:
                errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
                if errors:
                    logger.warning(
                        "%s response failed schema validation", path,
                        extra={"errors": [err.message for err in errors][:3]},
                    )
                    return None
        if not isinstance(payload, Mapping):
            logger.warning("%s payload was not an object", path, extra={"type": type(payload).__name__})
            return None
        if "error" in payload:
            message = str(payload.get("error"))
            self._last_error = RequestError(status=None, reason=message, retryable=False)
            logger.warning("%s request failed: %s", path, message)
            return None
        return payload

    def _request_cursor_page(
        self,
        method: str,
        path: str,
        *,
        key: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        item_parser: Optional[Callable[[Any], Optional[T]]] = None,
    ) -> CursorPageResult[T]:
        """Request a cursor-enabled endpoint and parse the JSON envelope."""

        raw_lines = self._request_lines(
            method,
            path,
            key=key,
            params=params,
            data=data,
        )
        if _is_error(raw_lines):
            if isinstance(raw_lines, RequestError):
                error: object = raw_lines
            elif isinstance(raw_lines, list) and raw_lines:
                error = raw_lines[0]
            else:
                error = "unknown error"
            return CursorPageResult([], False, None, error=error)

        text = "\n".join(line for line in raw_lines if line is not None).strip()
        if not text:
            return CursorPageResult([], False, None)

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            logger.warning(
                "cursor endpoint returned invalid JSON",
                extra={
                    "path": path,
                    "error": str(exc),
                    "payload_preview": text[:256],
                },
            )
            return CursorPageResult([], False, None, error="invalid json payload")

        items_raw = payload.get("items", [])
        if not isinstance(items_raw, list):
            logger.warning(
                "cursor endpoint returned non-list items",
                extra={"path": path, "items_type": type(items_raw).__name__},
            )
            items_raw = []

        parsed_items: List[T] = []
        if item_parser is None:
            parsed_items = [item for item in items_raw if item is not None]
        else:
            for raw_item in items_raw:
                try:
                    parsed = item_parser(raw_item)
                except Exception:  # pragma: no cover - defensive guard
                    logger.exception("item parser raised", extra={"path": path})
                    continue
                if parsed is not None:
                    parsed_items.append(parsed)

        has_more = bool(payload.get("has_more"))
        cursor_val = payload.get("cursor")
        if not isinstance(cursor_val, str):
            cursor_val = None
        error_val = payload.get("error")
        if error_val is not None and not isinstance(error_val, str):
            error_val = str(error_val)
        return CursorPageResult(parsed_items, has_more, cursor_val, error=error_val)

    # ------------------------------------------------------------------
    # public helpers
    # ------------------------------------------------------------------

    def read_dword(self, address: int) -> Optional[int]:
        increment_counter("ghidra.read")
        result = self._request_lines(
            "GET",
            "read_dword",
            key="READ_DWORD",
            params={"address": f"0x{address:08x}"},
        )
        if _is_error(result) or not result:
            logger.warning(
                "read_dword failed for 0x%08x: %s", address, _error_summary(result)
            )
            return None
        line = result[0].strip()
        try:
            return int(line, 16)
        except ValueError:
            logger.warning("Unexpected read_dword payload %s", line)
            return None

    def get_project_info(self) -> Optional[Dict[str, Any]]:
        """Fetch metadata about the active program from Ghidra."""

        increment_counter("ghidra.project_info")
        lines = self._request_lines("GET", "projectInfo", key="PROJECT_INFO")
        if _is_error(lines) or not lines:
            logger.warning("project_info request failed: %s", _error_summary(lines))
            return None
        text = "\n".join(line.strip() for line in lines if line.strip())
        if not text:
            logger.warning("project_info returned empty payload")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to decode project_info payload: %s", text)
            return None
        if not isinstance(payload, dict):
            logger.warning("Unexpected project_info payload type: %s", type(payload))
            return None
        return payload

    def get_project_files(self) -> Optional[List[Dict[str, Any]]]:
        """Fetch a list of files in the current Ghidra project."""

        increment_counter("ghidra.project_files")
        lines = self._request_lines("GET", "project_files", key="PROJECT_FILES")
        if _is_error(lines) or not lines:
            logger.warning("project_files request failed: %s", _error_summary(lines))
            return None
        text = "\n".join(line.strip() for line in lines if line.strip())
        if not text:
            logger.warning("project_files returned empty payload")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to decode project_files payload: %s", text)
            return None
        if not isinstance(payload, list):
            logger.warning("Unexpected project_files payload type: %s", type(payload))
            return None
        return payload

    def get_current_program_status(self) -> Optional[Dict[str, Any]]:
        """Fetch status information for the active program."""

        increment_counter("ghidra.current_program_status")
        requester = EndpointRequester(
            self,
            "GET",
            key="CURRENT_PROGRAM_STATUS",
        )
        lines = self._get_resolver.resolve("CURRENT_PROGRAM_STATUS", requester)
        if _is_error(lines) or not lines:
            logger.warning(
                "current_program_status request failed: %s", _error_summary(lines)
            )
            return None
        text = "\n".join(line.strip() for line in lines if line.strip())
        if not text:
            logger.warning("current_program_status returned empty payload")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to decode current_program_status payload: %s", text)
            return None
        if not isinstance(payload, dict):
            logger.warning(
                "Unexpected current_program_status payload type: %s", type(payload)
            )
            return None
        return payload

    def open_program(self, domain_file_id: str, *, path: str | None = None) -> Optional[Dict[str, Any]]:
        """Request the plugin to open the specified program."""

        increment_counter("ghidra.open_program")
        params: Dict[str, Any] = {"domain_file_id": domain_file_id}
        if path:
            params["path"] = path
        requester = EndpointRequester(
            self,
            "GET",
            key="OPEN_PROGRAM",
            params=params,
        )
        lines = self._get_resolver.resolve("OPEN_PROGRAM", requester)
        if _is_error(lines) or not lines:
            logger.warning("open_program request failed: %s", _error_summary(lines))
            return None
        text = "\n".join(line.strip() for line in lines if line.strip())
        if not text:
            logger.warning("open_program returned empty payload")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to decode open_program payload: %s", text)
            return None
        if not isinstance(payload, dict):
            logger.warning("Unexpected open_program payload type: %s", type(payload))
            return None
        return payload

    def disassemble_function(self, address: int) -> List[str]:
        increment_counter("ghidra.disasm")
        requester = EndpointRequester(
            self,
            "GET",
            key="DISASSEMBLE",
            params={"address": f"0x{address:08x}"},
        )
        lines = self._get_resolver.resolve("DISASSEMBLE", requester)
        return [] if _is_error(lines) else lines

    def decompile_function(self, address: int) -> Optional[str]:
        increment_counter("ghidra.decompile")
        requester = EndpointRequester(
            self,
            "GET",
            key="DECOMPILE",
            params={"address": f"0x{address:08x}"},
        )
        lines = self._get_resolver.resolve("DECOMPILE", requester)
        if _is_error(lines):
            return None
        text = "\n".join(line.rstrip("\r\n") for line in lines).strip()
        if not text or text.startswith("ERROR"):
            return None
        return text

    # ------------------------------------------------------------------
    # data-type helpers
    # ------------------------------------------------------------------

    def _request_datatype_operation(
        self,
        key: str,
        path: str,
        data: Dict[str, Any],
    ) -> DataTypeOperationResult:
        requester = EndpointRequester(self, "POST", key=key, data=data)
        lines = self._post_resolver.resolve(key, requester)
        if _is_error(lines):
            if isinstance(lines, RequestError):
                message = f"request failed: {lines.reason}"
                return DataTypeOperationResult(
                    False, error=message, transport_error=lines
                )
            return DataTypeOperationResult(False, error=lines[0])
        text = "\n".join(line for line in lines if line is not None).strip()
        if not text:
            return DataTypeOperationResult(False, error="empty response")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning(
                "datatype operation returned invalid JSON",
                extra={"path": path, "payload_preview": text[:256]},
            )
            return DataTypeOperationResult(False, error="invalid json payload")
        if not isinstance(payload, dict):
            return DataTypeOperationResult(False, error="invalid response payload")

        ok_field = payload.get("ok")
        if ok_field is None:
            ok_field = payload.get("success")
        if isinstance(ok_field, str):
            ok = ok_field.lower() in {"true", "1", "yes", "ok", "success"}
        else:
            ok = bool(ok_field)

        error = payload.get("error")
        if error is None and not ok:
            message = payload.get("message")
            if isinstance(message, str) and message:
                error = message

        datatype = payload.get("datatype")
        if datatype is not None and not isinstance(datatype, dict):
            datatype = None

        return DataTypeOperationResult(ok, error, datatype, details=payload)

    def create_structure(
        self,
        *,
        name: str,
        category: str,
        fields: List[Mapping[str, Any]],
    ) -> DataTypeOperationResult:
        data = {
            "name": name,
            "category": category,
            "fields": json.dumps(list(fields)),
        }
        return self._request_datatype_operation("CREATE_STRUCTURE", "createStructure", data)

    def update_structure(
        self,
        *,
        path: str,
        fields: List[Mapping[str, Any]],
    ) -> DataTypeOperationResult:
        data = {"path": path, "fields": json.dumps(list(fields))}
        return self._request_datatype_operation("UPDATE_STRUCTURE", "updateStructure", data)

    def create_union(
        self,
        *,
        name: str,
        category: str,
        fields: List[Mapping[str, Any]],
    ) -> DataTypeOperationResult:
        data = {
            "name": name,
            "category": category,
            "fields": json.dumps(list(fields)),
        }
        return self._request_datatype_operation("CREATE_UNION", "createUnion", data)

    def update_union(
        self,
        *,
        path: str,
        fields: List[Mapping[str, Any]],
    ) -> DataTypeOperationResult:
        data = {"path": path, "fields": json.dumps(list(fields))}
        return self._request_datatype_operation("UPDATE_UNION", "updateUnion", data)

    def delete_datatype(self, *, kind: str, path: str) -> DataTypeOperationResult:
        data = {"kind": kind, "path": path}
        return self._request_datatype_operation("DELETE_DATATYPE", "deleteDataType", data)

    def get_function_by_address(self, address: int) -> Optional[FunctionMeta]:
        increment_counter("ghidra.verify")
        requester = EndpointRequester(
            self,
            "GET",
            key="FUNC_BY_ADDR",
            params={"address": f"0x{address:08x}"},
        )
        lines = self._get_resolver.resolve("FUNC_BY_ADDR", requester)
        if _is_error(lines):
            return None
        meta: Dict[str, Any] = {}
        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
            elif "=" in line:
                key, value = line.split("=", 1)
            else:
                continue
            meta[key.strip()] = value.strip()
        if "entry_point" in meta:
            try:
                meta["entry_point"] = int(meta["entry_point"], 16)
            except ValueError:
                pass
        if "address" in meta:
            try:
                meta["address"] = int(meta["address"], 16)
            except ValueError:
                pass
        return meta if meta else None

    def get_xrefs_to(self, address: int, *, limit: int = 50) -> List[Xref]:
        increment_counter("ghidra.xrefs")
        params = {"address": f"0x{address:08x}", "limit": int(limit)}
        payload = None
        path_used = "get_xrefs_to"
        for candidate in ENDPOINT_CANDIDATES.get("GET_XREFS_TO", ("get_xrefs_to",)):
            payload = self._request_json_payload(
                "GET",
                candidate,
                params=params,
                key="GET_XREFS_TO",
                schema_key="xrefs",
            )
            path_used = candidate
            if payload is not None:
                break
        if not payload:
            return []
        if payload.get("error"):
            logger.warning("%s returned error", path_used, extra={"error": payload.get("error")})
        items_raw = payload.get("items", [])
        results: List[Xref] = []
        for raw in items_raw:
            if not isinstance(raw, Mapping):
                continue
            addr_str = str(raw.get("address", "")).strip()
            context = str(raw.get("context", ""))
            try:
                addr_val = int(addr_str, 16)
            except ValueError:
                logger.warning("Invalid xref address %s", addr_str)
                continue
            results.append({"addr": addr_val, "context": context})
        return results

    def search_xrefs_to(self, address: int, query: str) -> List[Xref]:
        increment_counter("ghidra.search_xrefs_to")
        params = {
            "address": f"0x{address:08x}",
            "limit": 999999,
            "offset": 0,
            "filter": query,
        }
        payload = None
        path_used = "get_xrefs_to"
        for candidate in ENDPOINT_CANDIDATES.get("GET_XREFS_TO", ("get_xrefs_to",)):
            payload = self._request_json_payload(
                "GET", candidate, key="GET_XREFS_TO", params=params, schema_key="xrefs"
            )
            path_used = candidate
            if payload is not None:
                break
        if not payload:
            return []
        if payload.get("error"):
            logger.warning("%s returned error", path_used, extra={"error": payload.get("error")})
        items_raw = payload.get("items", [])
        parsed: List[Xref] = []
        for raw in items_raw:
            if not isinstance(raw, Mapping):
                continue
            addr_str = str(raw.get("address", "")).strip()
            context = str(raw.get("context", ""))
            try:
                addr_val = int(addr_str, 16)
            except ValueError:
                logger.warning("Invalid xref address %s", addr_str)
                continue
            parsed.append({"addr": addr_val, "context": context})
        return parsed

    def search_strings(self, query: str) -> List[Dict[str, Any]]:
        increment_counter("ghidra.search_strings")
        payload = self._request_json_payload(
            "GET",
            "strings",
            key="SEARCH_STRINGS",
            params={"filter": query, "limit": 100000, "offset": 0},
            schema_key="strings",
        )
        if not payload:
            return []
        if payload.get("error"):
            logger.warning("strings returned error", extra={"error": payload.get("error")})
        results: List[Dict[str, Any]] = []
        for raw in payload.get("items", []):
            if not isinstance(raw, Mapping):
                continue
            address = str(raw.get("address", "")).strip()
            literal_val = raw.get("literal", "")
            literal = str(literal_val)
            results.append({"address": address, "literal": literal})
        return results

    def search_imports(self, query: str) -> List[str]:
        """Search for imported symbols matching the provided filter."""

        increment_counter("ghidra.search_imports")
        payload = self._request_json_payload(
            "GET",
            "imports",
            key="SEARCH_IMPORTS",
            params={"filter": query, "limit": 999999, "offset": 0},
            schema_key="symbols",
        )
        if not payload:
            return []
        if payload.get("error"):
            logger.warning("imports returned error", extra={"error": payload.get("error")})
        return [str(item).strip() for item in payload.get("items", []) if str(item).strip()]

    def search_exports(self, query: str) -> List[str]:
        """Search for exported symbols matching the provided filter."""

        increment_counter("ghidra.search_exports")
        payload = self._request_json_payload(
            "GET",
            "exports",
            key="SEARCH_EXPORTS",
            params={"filter": query, "limit": 999999, "offset": 0},
            schema_key="symbols",
        )
        if not payload:
            return []
        if payload.get("error"):
            logger.warning("exports returned error", extra={"error": payload.get("error")})
        return [str(item).strip() for item in payload.get("items", []) if str(item).strip()]

    def search_functions(
        self,
        query: str,
        *,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> CursorPageResult[str]:
        """Search for functions using the cursor-aware /searchFunctions endpoint."""

        increment_counter("ghidra.search_functions")
        params: Dict[str, Any] = {
            "query": query,
            "limit": max(1, int(limit)),
            "offset": max(0, int(offset)),
        }
        if cursor:
            params["cursor"] = cursor

        def _ensure_str(item: Any) -> Optional[str]:
            if isinstance(item, str):
                stripped = item.strip()
                return stripped if stripped else None
            return None

        result = self._request_cursor_page(
            "GET",
            "searchFunctions",
            key="SEARCH_FUNCTIONS",
            params=params,
            item_parser=_ensure_str,
        )

        # Fallback to legacy endpoint if plugin predates cursor support
        if result.error and not result.items:
            legacy_lines = self._request_lines(
                "GET",
                "functions",
                key="SEARCH_FUNCTIONS",
                params={"filter": query, "limit": 999999, "offset": 0},
            )
            if _is_error(legacy_lines):
                if isinstance(legacy_lines, RequestError):
                    legacy_error: object = legacy_lines
                elif isinstance(legacy_lines, list) and legacy_lines:
                    legacy_error = legacy_lines[0]
                else:
                    legacy_error = "unknown error"
                return CursorPageResult([], False, None, error=legacy_error)
            legacy_items = [line.strip() for line in legacy_lines if line.strip()]
            has_more = len(legacy_items) > max(0, int(offset)) + max(1, int(limit))
            sliced = legacy_items[offset : offset + limit]
            return CursorPageResult(sliced, has_more, None, error=None)

        return result


    def search_scalars(
        self,
        value: int,
        *,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> CursorPageResult[Dict[str, Any]]:
        """Search for scalar values via the cursor-aware endpoint."""

        increment_counter("ghidra.search_scalars")
        params: Dict[str, Any] = {
            "value": f"0x{value:x}",
            "limit": max(1, int(limit)),
            "offset": max(0, int(offset)),
        }
        if cursor:
            params["cursor"] = cursor

        def _parse_scalar(item: Any) -> Optional[Dict[str, Any]]:
            if isinstance(item, str):
                stripped = item.strip()
                if not stripped:
                    return None
                if ":" in stripped:
                    address_part, rest = stripped.split(":", 1)
                    address = address_part.strip()
                    context = rest.strip()
                else:
                    address = stripped
                    context = ""
                return {
                    "address": address,
                    "context": context,
                }
            if isinstance(item, Mapping):  # pragma: no cover - defensive future-proofing
                return {
                    "address": str(item.get("address", "")),
                    "context": str(item.get("context", "")),
                }
            return None

        result = self._request_cursor_page(
            "GET",
            "searchScalars",
            key="SEARCH_SCALARS",
            params=params,
            item_parser=_parse_scalar,
        )

        if result.error and not result.items:
            lines = self._request_lines(
                "GET",
                "searchScalars",
                key="SEARCH_SCALARS",
                params={"value": f"0x{value:x}", "limit": 999999},
            )
            if _is_error(lines):
                if isinstance(lines, RequestError):
                    scalar_error: object = lines
                elif isinstance(lines, list) and lines:
                    scalar_error = lines[0]
                else:
                    scalar_error = "unknown error"
                return CursorPageResult([], False, None, error=scalar_error)
            parsed: List[Dict[str, Any]] = []
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if ":" in stripped:
                    address_part, rest = stripped.split(":", 1)
                    address = address_part.strip()
                    context = rest.strip()
                else:
                    address = stripped
                    context = ""
                parsed.append({"address": address, "context": context})
            sliced = parsed[offset : offset + limit]
            has_more = len(parsed) > offset + limit
            return CursorPageResult(sliced, has_more, None, error=None)

        return result

    def list_functions_in_range(self, address_min: int, address_max: int) -> List[Dict[str, Any]]:
        """
        List all functions within an address range.
        
        Args:
            address_min: Start address (inclusive)
            address_max: End address (inclusive)
            
        Returns:
            List of dicts with name, address, and size
        """
        increment_counter("ghidra.list_functions_in_range")
        lines = self._request_lines(
            "GET",
            "functionsInRange",
            key="FUNCTIONS_IN_RANGE",
            params={
                "min": f"0x{address_min:08x}",
                "max": f"0x{address_max:08x}",
            },
        )
        if _is_error(lines):
            return []
        results: List[Dict[str, Any]] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Expected format: "name @ address [size]"
            if " @ " not in stripped:
                continue
            name_part, addr_part = stripped.split(" @ ", 1)
            name = name_part.strip()
            addr_and_size = addr_part.split(None, 1)
            address = addr_and_size[0].strip()
            size = None
            if len(addr_and_size) > 1:
                try:
                    size = int(addr_and_size[1].strip())
                except ValueError:
                    pass
            results.append({
                "name": name,
                "address": address,
                "size": size,
            })
        return results

    def disassemble_at(self, address: int, count: int) -> List[Dict[str, Any]]:
        """
        Disassemble instructions starting at address.
        
        Args:
            address: Starting address
            count: Number of instructions to disassemble
            
        Returns:
            List of dicts with address, bytes, and text
        """
        increment_counter("ghidra.disassemble_at")
        lines = self._request_lines(
            "GET",
            "disassembleAt",
            key="DISASSEMBLE_AT",
            params={"address": f"0x{address:08x}", "count": count},
        )
        if _is_error(lines):
            return []
        results: List[Dict[str, Any]] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Expected format: "address: bytes text"
            if ":" not in stripped:
                continue
            addr_part, rest = stripped.split(":", 1)
            address_str = addr_part.strip()
            rest = rest.strip()
            # Split bytes and text (bytes are typically hex separated by spaces)
            parts = rest.split(None, 1)
            bytes_str = parts[0] if parts else ""
            text = parts[1] if len(parts) > 1 else ""
            results.append({
                "address": address_str if address_str.startswith("0x") else f"0x{address_str}",
                "bytes": bytes_str,
                "text": text,
            })
        return results

    def read_bytes(self, address: int, length: int) -> Optional[bytes]:
        """
        Read raw bytes from memory.

        Args:
            address: Starting address
            length: Number of bytes to read
            
        Returns:
            Bytes object or None on error
        """
        increment_counter("ghidra.read_bytes")
        lines = self._request_lines(
            "GET",
            "readBytes",
            key="READ_BYTES",
            params={"address": f"0x{address:08x}", "length": length},
        )
        if _is_error(lines) or not lines:
            return None
        # Expected format: base64 encoded data on first line
        try:
            import base64
            return base64.b64decode(lines[0].strip())
        except Exception as exc:
            logger.warning("Failed to decode bytes: %s", exc)
            return None

    def read_cstring(self, address: int, *, max_len: int = 256) -> Optional[str]:
        increment_counter("ghidra.read_cstring")
        lines = self._request_lines(
            "GET",
            "read_cstring",
            key="READ_CSTRING",
            params={"address": f"0x{address:08x}", "max_len": int(max_len)},
        )
        if _is_error(lines) or not lines:
            return None
        text = "\n".join(line.rstrip("\r\n") for line in lines).strip()
        if not text or text.startswith("ERROR") or text.startswith("No program"):
            return None
        return text

    def rename_function(self, address: int, new_name: str) -> bool:
        increment_counter("ghidra.rename")
        requester = EndpointRequester(
            self,
            "POST",
            key="RENAME_FUNCTION",
            data={"function_address": f"0x{address:08x}", "new_name": new_name},
        )
        response = self._post_resolver.resolve("RENAME_FUNCTION", requester)
        return not _is_error(response)

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        increment_counter("ghidra.decompiler_comment")
        requester = EndpointRequester(
            self,
            "POST",
            key="SET_DECOMPILER_COMMENT",
            data={"address": f"0x{address:08x}", "comment": comment},
        )
        response = self._post_resolver.resolve("SET_DECOMPILER_COMMENT", requester)
        return not _is_error(response)

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        increment_counter("ghidra.disassembly_comment")
        requester = EndpointRequester(
            self,
            "POST",
            key="SET_DISASSEMBLY_COMMENT",
            data={"address": f"0x{address:08x}", "comment": comment},
        )
        response = self._post_resolver.resolve(
            "SET_DISASSEMBLY_COMMENT", requester
        )
        return not _is_error(response)

    def _begin_transaction(self, name: str) -> Optional[str]:
        requester = EndpointRequester(
            self,
            "POST",
            key="START_TRANSACTION",
            data={"name": name},
        )
        response = self._post_resolver.resolve("START_TRANSACTION", requester)
        if _is_error(response) or not response:
            return None
        token = response[0].strip()
        return token or None

    def _commit_transaction(self, token: str) -> bool:
        requester = EndpointRequester(
            self,
            "POST",
            key="COMMIT_TRANSACTION",
            data={"transaction": token},
        )
        response = self._post_resolver.resolve("COMMIT_TRANSACTION", requester)
        return not _is_error(response)

    def _rollback_transaction(self, token: str) -> None:
        requester = EndpointRequester(
            self,
            "POST",
            key="ROLLBACK_TRANSACTION",
            data={"transaction": token},
        )
        self._post_resolver.resolve("ROLLBACK_TRANSACTION", requester)

    def write_bytes(self, address: int, data: bytes) -> bool:
        """Write raw bytes to the active program and rebuild affected code."""

        increment_counter("ghidra.write_bytes")

        transaction = self._begin_transaction("write_bytes")
        if not transaction:
            return False

        encoded = base64.b64encode(data).decode("ascii")
        address_hex = f"0x{address:08x}"
        committed = False
        try:
            write_requester = EndpointRequester(
                self,
                "POST",
                key="WRITE_BYTES",
                data={
                    "transaction": transaction,
                    "address": address_hex,
                    "encoding": "base64",
                    "data": encoded,
                },
            )
            write_response = self._post_resolver.resolve("WRITE_BYTES", write_requester)
            if _is_error(write_response):
                return False

            rebuild_requester = EndpointRequester(
                self,
                "POST",
                key="REBUILD_CODE_UNITS",
                data={
                    "transaction": transaction,
                    "address": address_hex,
                    "length": len(data),
                },
            )
            rebuild_response = self._post_resolver.resolve(
                "REBUILD_CODE_UNITS", rebuild_requester
            )
            if _is_error(rebuild_response):
                return False

            committed = self._commit_transaction(transaction)
            return committed
        finally:
            if transaction and not committed:
                self._rollback_transaction(transaction)

    def rebase_program(
        self,
        *,
        new_base: int,
        offset: Optional[int] = None,
        confirm: bool = False,
    ) -> tuple[bool, List[str]]:
        """Request a program rebase via the plugin with transaction safety."""

        increment_counter("ghidra.rebase_program")

        transaction = self._begin_transaction("rebase_program")
        if not transaction:
            return False, ["ERROR: failed to start rebase transaction"]

        payload: Dict[str, Any] = {
            "transaction": transaction,
            "confirm": bool(confirm),
        }

        new_base_hex = f"0x{new_base:x}"
        payload["new_base"] = new_base_hex
        payload["newBase"] = new_base_hex

        if offset is not None:
            payload["offset"] = int(offset)
            payload["offset_hex"] = f"0x{offset:x}"

        requester = EndpointRequester(
            self,
            "POST",
            key="REBASE_PROGRAM",
            data=payload,
        )

        committed = False
        notes: List[str] = []
        try:
            response = self._post_resolver.resolve("REBASE_PROGRAM", requester)
            if _is_error(response):
                notes.extend(response)
                return False, notes

            notes.extend(line for line in response if line.strip())

            committed = self._commit_transaction(transaction)
            if not committed:
                notes.append("ERROR: failed to commit rebase transaction")
            return committed, notes
        finally:
            if transaction and not committed:
                self._rollback_transaction(transaction)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "GhidraClient":  # pragma: no cover - convenience wrapper
        return self

    def __exit__(self, *exc_info: Any) -> None:  # pragma: no cover - convenience wrapper
        self.close()


__all__ = [
    "CursorPageResult",
    "DataTypeOperationResult",
    "ENDPOINT_CANDIDATES",
    "GhidraClient",
    "POST_ENDPOINT_CANDIDATES",
    "RequestError",
]
