"""HTTP client wrapper around the Ghidra MCP bridge plugin."""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
import logging
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional
from urllib.parse import urljoin

import httpx
from time import perf_counter

from .models import FunctionMeta, Xref
from .whitelist import DEFAULT_WHITELIST, WhitelistEntry
from ..utils.logging import current_request, increment_counter, scoped_timer

logger = logging.getLogger("ghidra.bridge.client")


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


def _is_error(lines: List[str]) -> bool:
    return bool(lines) and lines[0].startswith("ERROR:")


def _parse_xref_lines(lines: Iterable[str]) -> List[Xref]:
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

    # ------------------------------------------------------------------
    # low level
    # ------------------------------------------------------------------

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
    ) -> List[str]:
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
                logger.warning(
                    "ghidra.request",
                    extra={
                        "method": method,
                        "path": path,
                        "duration_ms": duration_ms,
                        "error": str(exc),
                    },
                )
                return [f"ERROR: Request failed: {exc}"]
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
            return [f"ERROR: {response.status_code}: {response.text.strip()}"]
        text = response.text
        lines = text.replace("\r\n", "\n").splitlines()
        return lines

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
            logger.warning("read_dword failed for 0x%08x: %s", address, result[:1])
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
            logger.warning("project_info request failed: %s", lines[:1])
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
        requester = EndpointRequester(
            self,
            "GET",
            key="GET_XREFS_TO",
            params={"address": f"0x{address:08x}", "limit": int(limit)},
        )
        lines = self._get_resolver.resolve("GET_XREFS_TO", requester)
        if _is_error(lines):
            return []
        return _parse_xref_lines(lines)

    def search_xrefs_to(self, address: int, query: str) -> List[Xref]:
        increment_counter("ghidra.search_xrefs_to")
        requester = EndpointRequester(
            self,
            "GET",
            key="GET_XREFS_TO",
            params={
                "address": f"0x{address:08x}",
                "limit": 999999,
                "offset": 0,
                "filter": query,
            },
        )
        lines = self._get_resolver.resolve("GET_XREFS_TO", requester)
        if _is_error(lines):
            return []
        return _parse_xref_lines(lines)

    def search_strings(self, query: str) -> List[Dict[str, Any]]:
        increment_counter("ghidra.search_strings")
        lines = self._request_lines(
            "GET",
            "strings",
            key="SEARCH_STRINGS",
            params={"filter": query, "limit": 100000, "offset": 0},
        )
        if _is_error(lines):
            return []
        results: List[Dict[str, Any]] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            address_part, _, literal_part = stripped.partition(":")
            if not address_part:
                continue
            address = address_part.strip()
            literal_text = literal_part.strip()
            literal = literal_text
            if literal_text:
                try:
                    literal = ast.literal_eval(literal_text)
                except (ValueError, SyntaxError):
                    literal = literal_text.strip('"')
            results.append({"address": address, "literal": literal})
        return results

    def search_imports(self, query: str) -> List[str]:
        """Search for imported symbols matching the provided filter."""

        increment_counter("ghidra.search_imports")
        lines = self._request_lines(
            "GET",
            "imports",
            key="SEARCH_IMPORTS",
            params={"filter": query, "limit": 999999, "offset": 0},
        )
        if _is_error(lines):
            return []
        return [line.strip() for line in lines if line.strip()]

    def search_exports(self, query: str) -> List[str]:
        """Search for exported symbols matching the provided filter."""

        increment_counter("ghidra.search_exports")
        lines = self._request_lines(
            "GET",
            "exports",
            key="SEARCH_EXPORTS",
            params={"filter": query, "limit": 999999, "offset": 0},
        )
        if _is_error(lines):
            return []
        return [line.strip() for line in lines if line.strip()]
def search_functions(self, query: str) -> List[str]:
        """
        Search for functions using the plaintext /functions endpoint.
        Returns list lines like "Name at 00000000".
        """
        increment_counter("ghidra.search_functions")
        lines = self._request_lines(
            "GET",
            "functions",
            key="SEARCH_FUNCTIONS",
            params={"filter": query, "limit": 999999, "offset": 0},
        )
        if _is_error(lines):
            return []
        return [line.strip() for line in lines if line.strip()]


    def search_scalars(self, value: int) -> List[Dict[str, Any]]:
        """
        Search for scalar values in the binary.
        
        Args:
            value: Integer value to search for
            
        Returns:
            List of dicts with address, value, function, and context
        """
        increment_counter("ghidra.search_scalars")
        lines = self._request_lines(
            "GET",
            "searchScalars",
            key="SEARCH_SCALARS",
            params={"value": f"0x{value:x}", "limit": 999999},
        )
        if _is_error(lines):
            return []
        results: List[Dict[str, Any]] = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Expected format: "address: value [function] context"
            parts = stripped.split(None, 1)
            if not parts:
                continue
            address = parts[0].rstrip(":")
            rest = parts[1] if len(parts) > 1 else ""
            results.append({
                "address": address,
                "value": f"0x{value:x}",
                "function": None,
                "context": rest,
            })
        return results

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

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "GhidraClient":  # pragma: no cover - convenience wrapper
        return self

    def __exit__(self, *exc_info: Any) -> None:  # pragma: no cover - convenience wrapper
        self.close()


__all__ = ["GhidraClient", "ENDPOINT_CANDIDATES", "POST_ENDPOINT_CANDIDATES"]
