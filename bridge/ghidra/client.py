"""HTTP client wrapper around the Ghidra MCP bridge plugin."""
from __future__ import annotations

import ast
import base64
import json
import re
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
    Sequence,
    TypeVar,
)
from urllib.parse import urljoin

import httpx
from time import perf_counter

from .models import FunctionMeta, Xref
from .whitelist import DEFAULT_WHITELIST, WhitelistEntry
from ..utils.errors import UpstreamFailed
from ..utils.logging import current_request, increment_counter, scoped_timer

logger = logging.getLogger("ghidra.bridge.client")


T = TypeVar("T")

#: ``last_error.reason`` when the plugin ignores ``fmt=json`` (a build from
#: before rework stage 8c/8d).  Callers that may fall back for a missing
#: *function* must still fail loudly on this.
STRUCTURED_LISTING_UNSUPPORTED = (
    "the Ghidra plugin answered without JSON; it predates structured "
    "responses -- rebuild and reinstall the extension"
)


ENDPOINT_CANDIDATES: Mapping[str, Iterable[str]] = {
    "DISASSEMBLE": ("disassemble", "disassemble_function"),
    "FUNC_BY_ADDR": ("get_function_by_address",),
    "GET_XREFS_TO": ("xrefs_to",),
    "DECOMPILE": (
        "decompile_function",
        "decompile_by_addr",
    ),
    "OPEN_PROGRAM": ("open_program",),
    "CURRENT_PROGRAM_STATUS": ("api/current_program.json",),
    "GOTO": ("goto",),
    "CHECK_DIRTY_STATE": ("check_dirty_state",),
    "SAVE_PROGRAM": ("save_program",),
}

POST_ENDPOINT_CANDIDATES: Mapping[str, Iterable[str]] = {
    "RENAME_FUNCTION": (
        "rename_function_by_address",
    ),
    "SET_DECOMPILER_COMMENT": (
        "set_decompiler_comment",
    ),
    "SET_DISASSEMBLY_COMMENT": (
        "set_disassembly_comment",
    ),
    "CREATE_LABEL": ("createLabel",),
    "CREATE_STRUCTURE": ("createStructure",),
    "UPDATE_STRUCTURE": ("updateStructure",),
    "CREATE_UNION": ("createUnion",),
    "UPDATE_UNION": ("updateUnion",),
    "DELETE_DATATYPE": ("deleteDataType",),
}


#: The first line of /get_function_by_address when a function is there.
_FUNCTION_LINE = re.compile(r"^.+ at [0-9a-fA-F]+$")

#: The plugin's answers to a successful rename_function_by_address and
#: set_*_comment; everything else, "Failed to ..." included, is a failure.
RENAMED_ANSWER = "Function renamed successfully"
COMMENT_SET_ANSWER = "Comment set successfully"

#: The plugin's answer convention this bridge speaks (X-GhidraMCP-API).  At 2,
#: every failure is an HTTP 4xx/5xx with {"status":"error","code","error"};
#: older plugins answered failures in HTTP 200 prose, which this bridge no
#: longer tries to recognise (R.24).
PLUGIN_API_HEADER = "X-GhidraMCP-API"
REQUIRED_PLUGIN_API = 2
PLUGIN_TOO_OLD = (
    "the Ghidra plugin predates API 2 (structured errors); install the "
    "current GhidraMCP extension from this repository and restart Ghidra"
)

#: Answers to a read that are facts about the program, not failures: nothing
#: is there.  Everything else the plugin refuses raises UpstreamFailed.
ABSENT_CODES = frozenset({"NOT_FOUND", "UNMAPPED"})

#: Endpoint keys that change the program (or, for SAVE_PROGRAM, its file).
#: Each request through one of them is checked first: the active program must
#: be known, and must be the session's selection when there is one; the
#: request then names it as ``domain_file_id``, so the plugin refuses it if a
#: different program became active in between (R.26).
WRITE_ENDPOINT_KEYS = frozenset(
    {
        "RENAME_FUNCTION",
        "SET_DECOMPILER_COMMENT",
        "SET_DISASSEMBLY_COMMENT",
        "CREATE_LABEL",
        "CREATE_STRUCTURE",
        "UPDATE_STRUCTURE",
        "CREATE_UNION",
        "UPDATE_UNION",
        "DELETE_DATATYPE",
        "SAVE_PROGRAM",
    }
)

#: Start of every ``RequestError.reason`` for a write refused over the program,
#: by the bridge or the plugin; the tool layer turns those into INVALID_REQUEST.
WRITE_REFUSED_PREFIX = "Write refused"


@dataclass(slots=True)
class EndpointResolver:
    candidates: Mapping[str, Iterable[str]]
    _cache: MutableMapping[str, str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._cache = {}

    def resolve(self, key: str, requester: "EndpointRequester") -> List[str]:
        """Send the request once, to the first candidate route that exists.

        Only a missing route moves on to the next candidate.  Any other failure
        is the answer: retrying it on an alias of the same handler sent every
        failed request twice, POST writes included -- a create that had landed
        before a timeout came back "already exists".
        """

        cached = self._cache.get(key)
        candidates = (cached,) if cached else tuple(self.candidates.get(key, (key,)))
        result: List[str] | RequestError = [f"ERROR: no candidates for {key}"]
        for candidate in candidates:
            result = requester.request(candidate)
            if not _route_missing(result):
                self._cache[key] = candidate
                return result
        if _route_missing(result):
            raise UpstreamFailed(
                f"the plugin has none of the routes {', '.join('/' + c for c in candidates)}; {PLUGIN_TOO_OLD}",
                code="PLUGIN_TOO_OLD",
                status=404,
            )
        return result


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
            return self.client._request_lines(
                "GET", path, key=self.key, params=self.params, route_may_be_missing=True
            )
        if self.method == "POST":
            return self.client._request_lines(
                "POST", path, key=self.key, data=self.data, route_may_be_missing=True
            )
        raise ValueError(f"Unsupported method {self.method}")


def _route_missing(result: object) -> bool:
    """The plugin has no such route: the JDK server's own 404, which is not JSON."""

    return isinstance(result, RequestError) and result.code == "ROUTE_MISSING"


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
    #: The plugin's error code (API 2), when it sent one.
    code: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "status": self.status, "reason": self.reason, "retryable": self.retryable,
        }
        if self.code is not None:
            payload["code"] = self.code
        return payload


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
        #: The program this session selected (select_program), set by the tool
        #: layer; None when the session has made no explicit choice.
        self.expected_program_id: Optional[str] = None
        #: The first write refusal of this client's call, kept although later
        #: requests reset ``last_error``.
        self.write_refusal: Optional[RequestError] = None
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
                                "required": ["address", "literal", "refs"],
                                "properties": {
                                    "address": {"type": "string"},
                                    "literal": {"type": "string"},
                                    "refs": {"type": "integer", "minimum": 0},
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
        route_may_be_missing: bool = False,
    ) -> List[str] | RequestError:
        """The answer's lines, or a RequestError for an answer that says "not there".

        Under API 2 the plugin's status decides: a read answered 404 NOT_FOUND
        or UNMAPPED is a fact and comes back as a RequestError for the caller
        to treat as absent.  Any other failure -- another error status, any
        failed write, a transport error, a plugin that does not speak API 2 --
        raises UpstreamFailed, so it cannot be mistaken for an empty result.
        A missing route (the JDK server's HTML 404) is returned only to the
        resolver (``route_may_be_missing``), which then tries the next alias.
        """

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
        if key in WRITE_ENDPOINT_KEYS:
            guard = self._write_target()
            if isinstance(guard, RequestError):
                return self._refuse_write(guard)
            params = {**(params or {}), "domain_file_id": guard}
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
                raise UpstreamFailed(
                    f"{method} /{path} failed: {exc}",
                    status=self._last_error.status,
                    retryable=retryable,
                ) from exc
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
        status = int(response.status_code)
        body = response.text
        if status == 404 and not body.lstrip().startswith("{"):
            # The JDK server's own 404: the plugin has no such route at all.
            missing = RequestError(
                status=404, reason=f"the plugin has no route /{path}", retryable=False, code="ROUTE_MISSING"
            )
            self._last_error = missing
            if route_may_be_missing:
                return missing
            raise UpstreamFailed(f"{missing.reason}; {PLUGIN_TOO_OLD}", code="PLUGIN_TOO_OLD", status=404)
        api = response.headers.get(PLUGIN_API_HEADER, "")
        if not api.strip().isdigit() or int(api) < REQUIRED_PLUGIN_API:
            self._last_error = RequestError(
                status=None, reason=PLUGIN_TOO_OLD, retryable=False, code="PLUGIN_TOO_OLD"
            )
            raise UpstreamFailed(PLUGIN_TOO_OLD, code="PLUGIN_TOO_OLD")
        if response.is_error:
            code: Optional[str] = None
            reason = body.strip()
            try:
                error_body = json.loads(body)
            except json.JSONDecodeError:
                error_body = None
            if isinstance(error_body, Mapping):
                reason = str(error_body.get("error") or reason)
                code = str(error_body["code"]) if error_body.get("code") else None
            if status == 409 and key in WRITE_ENDPOINT_KEYS and reason.startswith(WRITE_REFUSED_PREFIX):
                return self._refuse_write(
                    RequestError(status=409, reason=reason, retryable=False, code=code)
                )
            retryable = status >= 500 or status == 425
            self._last_error = RequestError(status=status, reason=reason, retryable=retryable, code=code)
            if method.upper() == "GET" and code in ABSENT_CODES:
                return self._last_error
            raise UpstreamFailed(reason, code=code, status=status, retryable=retryable)
        self._last_error = None
        text = body
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        # A page envelope ({"items": [...], "error": ...}) is left to the page
        # parsers: searchScalars sends found items *with* an error when its
        # inspection cap stops it.  Any other 200 carrying "error" is not an
        # API 2 answer and is a failure.
        if isinstance(payload, Mapping) and "error" in payload and "items" not in payload:
            message = str(payload.get("error"))
            self._last_error = RequestError(status=status, reason=message, retryable=False)
            raise UpstreamFailed(message, status=status)
        lines = text.replace("\r\n", "\n").splitlines()
        return lines

    def _note_failure(self, reason: str) -> None:
        """Keep a transport error's own reason; otherwise record why there is no answer."""

        if self._last_error is None:
            self._last_error = RequestError(status=None, reason=reason, retryable=False)

    def _read_flags(
        self, payload: Dict[str, Any], keys: Sequence[str], path: str
    ) -> Optional[Dict[str, Any]]:
        """The payload with ``keys`` as real booleans, or None if one is neither.

        API 2 plugins send ``"true"``/``"false"``; JSON booleans are accepted too,
        so a plugin that fixes the type is not misread as "false".  Anything
        else is a failure: defaulting to false would report a dirty program as
        clean, or a save as not done.
        """

        flags: Dict[str, Any] = dict(payload)
        for key in keys:
            value = payload.get(key)
            if value is True or value == "true":
                flags[key] = True
            elif value is False or value == "false":
                flags[key] = False
            else:
                logger.warning("%s answered %s=%r", path, key, value)
                self._note_failure(f"{path} answered {key}={value!r}, not a boolean")
                return None
        return flags

    def _require_payload(self, payload: Optional[Mapping[str, Any]], what: str) -> Mapping[str, Any]:
        """The payload, or UpstreamFailed: a failed listing must not read as an empty one."""

        if payload:
            return payload
        reason = self._last_error.reason if self._last_error else "no answer"
        raise UpstreamFailed(f"{what} failed upstream: {reason}")

    def _write_target(self) -> str | RequestError:
        """The domain_file_id a write may go to, or why it may not be sent."""

        try:
            status = self.get_current_program_status()
        except UpstreamFailed:
            status = None
        if not isinstance(status, Mapping):
            return RequestError(
                status=None,
                reason=(
                    f"{WRITE_REFUSED_PREFIX}: the active program could not be determined "
                    "(no answer from /api/current_program.json); nothing was sent"
                ),
                retryable=True,
            )
        active = str(status.get("domain_file_id") or "").strip()
        if not active:
            return RequestError(
                status=409,
                reason=f"{WRITE_REFUSED_PREFIX}: no program is active in Ghidra; nothing was sent",
                retryable=False,
            )
        expected = (self.expected_program_id or "").strip()
        if expected and expected != active:
            return RequestError(
                status=409,
                reason=(
                    f"{WRITE_REFUSED_PREFIX}: this session selected domain_file_id "
                    f"'{expected}', but the active program is '{active}'; nothing was sent"
                ),
                retryable=False,
            )
        return active

    def _refuse_write(self, error: RequestError) -> RequestError:
        logger.warning("ghidra.write_refused", extra={"reason": error.reason})
        if self.write_refusal is None:
            self.write_refusal = error
        self._last_error = error
        return error

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
            self._note_failure(_error_summary(lines))
            return None
        text = "\n".join(line for line in lines if line is not None).strip()
        if not text:
            logger.warning("%s returned empty payload", path)
            self._note_failure(f"{path} answered with an empty body")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            logger.warning(
                "%s returned invalid JSON", path, extra={"error": str(exc), "preview": text[:256]}
            )
            self._note_failure(f"{path} answered with something that is not JSON: {text[:80]!r}")
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
                    self._note_failure(
                        f"{path} answered in an unexpected shape: {errors[0].message}"
                    )
                    return None
        if not isinstance(payload, Mapping):
            logger.warning("%s payload was not an object", path, extra={"type": type(payload).__name__})
            self._note_failure(f"{path} answered with a {type(payload).__name__}, not an object")
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
            # not an empty page: an empty page is {"items":[],"has_more":false}
            return CursorPageResult([], False, None, error=f"{path} answered with an empty body")

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
        if not isinstance(payload, Mapping):
            return CursorPageResult(
                [], False, None, error=f"{path} answered with a {type(payload).__name__}, not a page"
            )

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

    def goto_address(self, address: str) -> Optional[Dict[str, Any]]:
        """Navigate CodeBrowser to a specific address."""

        increment_counter("ghidra.goto_address")
        requester = EndpointRequester(
            self,
            "GET",
            key="GOTO",
            params={"address": address},
        )
        lines = self._get_resolver.resolve("GOTO", requester)
        if _is_error(lines) or not lines:
            logger.warning("goto_address request failed: %s", _error_summary(lines))
            return None
        text = "\n".join(line.strip() for line in lines if line.strip())
        if not text:
            logger.warning("goto_address returned empty payload")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to decode goto_address payload: %s", text)
            return None
        if not isinstance(payload, dict):
            logger.warning("Unexpected goto_address payload type: %s", type(payload))
            return None
        return payload

    def check_dirty_state(self) -> Optional[Dict[str, Any]]:
        """Check if the current program has unsaved changes."""

        increment_counter("ghidra.check_dirty_state")
        requester = EndpointRequester(
            self,
            "GET",
            key="CHECK_DIRTY_STATE",
            params={},
        )
        lines = self._get_resolver.resolve("CHECK_DIRTY_STATE", requester)
        if _is_error(lines) or not lines:
            logger.warning("check_dirty_state request failed: %s", _error_summary(lines))
            return None
        text = "\n".join(line.strip() for line in lines if line.strip())
        if not text:
            logger.warning("check_dirty_state returned empty payload")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to decode check_dirty_state payload: %s", text)
            return None
        if not isinstance(payload, dict):
            logger.warning("Unexpected check_dirty_state payload type: %s", type(payload))
            return None
        return self._read_flags(payload, ("changed", "can_save"), "check_dirty_state")

    def save_program(self, description: str | None = None) -> Optional[Dict[str, Any]]:
        """Save the current program with an optional description."""

        increment_counter("ghidra.save_program")
        params: Dict[str, Any] = {}
        if description:
            params["description"] = description
        requester = EndpointRequester(
            self,
            "GET",
            key="SAVE_PROGRAM",
            params=params,
        )
        lines = self._get_resolver.resolve("SAVE_PROGRAM", requester)
        if _is_error(lines) or not lines:
            logger.warning("save_program request failed: %s", _error_summary(lines))
            return None
        text = "\n".join(line.strip() for line in lines if line.strip())
        if not text:
            logger.warning("save_program returned empty payload")
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Failed to decode save_program payload: %s", text)
            return None
        if not isinstance(payload, dict):
            logger.warning("Unexpected save_program payload type: %s", type(payload))
            return None
        return self._read_flags(payload, ("saved",), "save_program")

    def open_program(self, domain_file_id: str, *, path: str | None = None, on_dirty: str | None = None) -> Optional[Dict[str, Any]]:
        """Request the plugin to open the specified program.

        Args:
            domain_file_id: The domain file ID of the program to open
            path: Optional path to the program file
            on_dirty: Action to take if current program has unsaved changes:
                     "error" (default) - Fail with error
                     "save" - Save current program before switching
                     "discard" - Discard unsaved changes
        """

        increment_counter("ghidra.open_program")
        params: Dict[str, Any] = {"domain_file_id": domain_file_id}
        if path:
            params["path"] = path
        if on_dirty:
            params["on_dirty"] = on_dirty
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

    def disassemble_function_structured(self, address: int) -> Optional[Mapping[str, Any]]:
        """The function's instructions as structured records (``fmt=json``).

        Each record carries Ghidra's own operands, flow and references, so the
        caller reads fields instead of taking ``toString()`` apart.  A plugin
        built before rework stage 8c ignores ``fmt`` and answers in text; that
        returns None with ``last_error`` saying so, rather than an empty
        listing that would read like a function without instructions.
        """

        increment_counter("ghidra.disasm_structured")
        self._last_error = None
        payload = self._request_json_payload(
            "GET",
            "disassemble_function",
            key="DISASSEMBLE",
            params={"address": f"0x{address:08x}", "fmt": "json"},
        )
        if payload is None:
            if self._last_error is None:
                self._last_error = RequestError(
                    status=None, reason=STRUCTURED_LISTING_UNSUPPORTED, retryable=False
                )
            return None
        if not isinstance(payload.get("instructions"), list):
            self._last_error = RequestError(
                status=None, reason="structured disassembly without an instruction list", retryable=False
            )
            return None
        return payload

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
        # The plugin's answer is prose: "Function: <name> at <hex>", then
        # Signature/Entry/Body.  Anything else -- "No function found at
        # address ...", "Error getting function: ..." -- is no function, and
        # its text is the reason.  Split on ":" alone, "Error getting
        # function: <msg>" used to become a truthy {"Error getting function": msg}.
        meta: Dict[str, Any] = {}
        for line in lines:
            key, sep, value = line.partition(":")
            if sep:
                meta[key.strip()] = value.strip()
        if not _FUNCTION_LINE.match(str(meta.get("Function", ""))):
            text = " ".join(line.strip() for line in lines if line.strip())
            self._last_error = RequestError(
                status=200, reason=text or "empty answer from the plugin", retryable=False
            )
            return None
        return meta

    def get_xrefs_to(self, address: int, *, limit: int = 50) -> List[Xref]:
        increment_counter("ghidra.xrefs")
        params = {"address": f"0x{address:08x}", "limit": int(limit)}
        payload = None
        for candidate in ENDPOINT_CANDIDATES.get("GET_XREFS_TO", ("xrefs_to",)):
            payload = self._request_json_payload(
                "GET",
                candidate,
                params=params,
                key="GET_XREFS_TO",
                schema_key="xrefs",
            )
            if payload is not None:
                break
        payload = self._require_payload(payload, f"references to 0x{address:08x}")
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
        for candidate in ENDPOINT_CANDIDATES.get("GET_XREFS_TO", ("xrefs_to",)):
            payload = self._request_json_payload(
                "GET", candidate, key="GET_XREFS_TO", params=params, schema_key="xrefs"
            )
            if payload is not None:
                break
        payload = self._require_payload(payload, f"references to 0x{address:08x}")
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
        payload = self._require_payload(payload, "string search")
        results: List[Dict[str, Any]] = []
        for raw in payload.get("items", []):
            if not isinstance(raw, Mapping):
                continue
            address = str(raw.get("address", "")).strip()
            literal_val = raw.get("literal", "")
            literal = str(literal_val)
            results.append({"address": address, "literal": literal, "refs": int(raw.get("refs", 0))})
        return results

    def list_strings(
        self, *, limit: int, offset: int = 0
    ) -> Dict[str, Any]:
        """Page through defined strings without a query.

        The plugin's /strings endpoint pages natively, so this asks for one
        window instead of pulling everything and slicing.  strings_compact
        looked for exactly this method and, not finding it, returned an empty
        list on every call -- a well-formed answer that said nothing.
        """

        increment_counter("ghidra.list_strings")
        payload = self._request_json_payload(
            "GET",
            "strings",
            key="SEARCH_STRINGS",
            params={"limit": max(int(limit), 1), "offset": max(int(offset), 0)},
            schema_key="strings",
        )
        payload = self._require_payload(payload, "string listing")
        results: List[Dict[str, Any]] = []
        for raw in payload.get("items", []):
            if not isinstance(raw, Mapping):
                continue
            results.append(
                {
                    "address": str(raw.get("address", "")).strip(),
                    "literal": str(raw.get("literal", "")),
                    "refs": int(raw.get("refs", 0)),
                }
            )
        # The plugin knows whether more pages follow; it does not know the
        # total, and neither do we.
        return {"items": results, "has_more": bool(payload.get("has_more", False))}

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
        payload = self._require_payload(payload, "import search")
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
        payload = self._require_payload(payload, "export search")
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

        # No fallback: the old one asked /functions for ``filter``, which that
        # route never reads, and answered every failure with all functions.
        return self._request_cursor_page(
            "GET",
            "searchFunctions",
            key="SEARCH_FUNCTIONS",
            params=params,
            item_parser=_ensure_str,
        )


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

        # No fallback: the old one asked again with limit=999999 (the plugin
        # caps at 500) and parsed the JSON answer line by line.
        return self._request_cursor_page(
            "GET",
            "searchScalars",
            key="SEARCH_SCALARS",
            params=params,
            item_parser=_parse_scalar,
        )

    def list_functions_in_range(
        self, address_min: int, address_max: int
    ) -> Optional[List[Dict[str, Any]]]:
        """Functions whose entry lies in ``[address_min, address_max]``.

        Each entry has ``name``, ``address`` and ``size``, plus ``span``,
        ``thunk_to`` and ``chunks`` where they say something.  Read from the
        plugin's ``fmt=json`` answer (rework stage 8d) rather than split out of
        ``name @ addr size span=...``.  None on failure, with ``last_error``
        set -- an error is not an empty range.
        """

        increment_counter("ghidra.list_functions_in_range")
        self._last_error = None
        payload = self._request_json_payload(
            "GET",
            "functionsInRange",
            key="FUNCTIONS_IN_RANGE",
            params={
                "min": f"0x{address_min:08x}",
                "max": f"0x{address_max:08x}",
                "fmt": "json",
            },
        )
        if payload is None:
            if self._last_error is None:
                self._last_error = RequestError(
                    status=None, reason=STRUCTURED_LISTING_UNSUPPORTED, retryable=False
                )
            return None
        functions = payload.get("functions")
        if not isinstance(functions, list):
            self._last_error = RequestError(
                status=None, reason="function listing without a functions array", retryable=False
            )
            return None
        results: List[Dict[str, Any]] = []
        for raw in functions:
            if not isinstance(raw, Mapping):
                continue
            size = raw.get("size")
            results.append(
                {
                    "name": str(raw.get("name", "")),
                    "address": str(raw.get("address", "")),
                    "size": size if isinstance(size, int) and size > 0 else None,
                    "span": raw.get("span") if isinstance(raw.get("span"), Mapping) else None,
                    "thunk": raw.get("thunk") is True,
                    "thunk_to": raw.get("thunk_to"),
                    "chunks": [c for c in raw.get("chunks") or () if isinstance(c, Mapping)],
                }
            )
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
        return self._confirmed(response, RENAMED_ANSWER)

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        increment_counter("ghidra.decompiler_comment")
        requester = EndpointRequester(
            self,
            "POST",
            key="SET_DECOMPILER_COMMENT",
            data={"address": f"0x{address:08x}", "comment": comment},
        )
        response = self._post_resolver.resolve("SET_DECOMPILER_COMMENT", requester)
        return self._confirmed(response, COMMENT_SET_ANSWER)

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
        return self._confirmed(response, COMMENT_SET_ANSWER)

    def _confirmed(self, response: object, success: str) -> bool:
        """True only for the plugin's success sentence.

        The plugin answers a failed rename or comment with HTTP 200 and prose
        ("Failed to rename function"), not with "ERROR:"; reading anything but
        an error as success reported those as done (WRITE-ANSWER-TRUTHFUL).
        """

        if _is_error(response):
            return False
        text = "\n".join(response).strip() if isinstance(response, list) else ""
        if text == success:
            return True
        self._last_error = RequestError(
            status=200, reason=text or "empty answer from the plugin", retryable=False
        )
        return False

    def create_label(self, address: int, name: str, *, dry_run: bool) -> Optional[Mapping[str, Any]]:
        """Place a label at ``address`` through ``/createLabel`` (R.12).

        Returns the plugin's answer as is, including one with ``status:
        "error"`` -- a rejected name is a finding, not a transport failure.
        None only when there is no JSON answer at all, with ``last_error`` set;
        a plugin from before R.12 has no such route.
        """

        increment_counter("ghidra.create_label")
        self._last_error = None
        lines = self._request_lines(
            "POST",
            "createLabel",
            key="CREATE_LABEL",
            data={
                "address": f"0x{address:08x}",
                "name": name,
                "dry_run": "true" if dry_run else "false",
            },
        )
        if _is_error(lines):
            if self._last_error is None:
                self._last_error = RequestError(
                    status=None, reason=_error_summary(lines), retryable=False
                )
            return None
        text = "\n".join(lines).strip()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if not isinstance(payload, Mapping):
            self._last_error = RequestError(
                status=None, reason=STRUCTURED_LISTING_UNSUPPORTED, retryable=False
            )
            return None
        return payload

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
    "STRUCTURED_LISTING_UNSUPPORTED",
]
