from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from bridge.ghidra.client import CursorPageResult, RequestError


@dataclass
class _FunctionMeta:
    name: str
    comment: str = ""


class ReferenceGhidraClient:
    """Deterministic stub backed by a reference firmware fixture."""

    def __init__(self, firmware_path: Path) -> None:
        self._firmware_path = Path(firmware_path)
        self._data = self._firmware_path.read_bytes()
        self._base = 0x0040_0000
        self._last_error: Optional[RequestError] = None
        self._functions: Dict[int, _FunctionMeta] = {
            self._base: _FunctionMeta("reset_handler", "entrypoint"),
            self._base + 0x50: _FunctionMeta("init_peripherals"),
            self._base + 0x100: _FunctionMeta("main"),
        }
        self._strings: List[Dict[str, object]] = [
            {
                "literal": "Error: invalid checksum\n(retry)",
                "address": self._base + 0x90,
                "refs": 8,
            },
            {
                "literal": "Boot complete",
                "address": self._base + 0x40,
                "refs": 2,
            },
            {
                "literal": "Status: ready for commands",
                "address": self._base + 0x60,
                "refs": 4,
            },
        ]
        self._xrefs = [
            {"addr": self._base + 0x110, "context": "call puts"},
            {"addr": self._base + 0x124, "context": "log message"},
        ]
        self._scalar_matches = [
            {
                "address": f"0x{self._base + 0x20:08x}",
                "function": "init_peripherals",
                "context": "load base address",
            },
            {
                "address": f"0x{self._base + 0x24:08x}",
                "function": "init_peripherals",
                "context": "mask constants",
            },
        ]
        self._disassembly = [
            f"{self._base + 0x100:08X}: PUSH {{lr}}",
            f"{self._base + 0x104:08X}: LDR r0, =0x40000000",
            f"{self._base + 0x108:08X}: STR r1, [r0]",
            f"{self._base + 0x10C:08X}: LDR r2, =0x40000020",
            f"{self._base + 0x110:08X}: BL puts",
            f"{self._base + 0x114:08X}: BX lr",
        ]

    @property
    def last_error(self) -> Optional[RequestError]:
        return self._last_error

    def _clear_error(self) -> None:
        self._last_error = None

    def _set_error(self, status: int, reason: str, retryable: bool = False) -> None:
        self._last_error = RequestError(status=status, reason=reason, retryable=retryable)

    def get_project_info(self) -> Dict[str, object]:
        self._clear_error()
        md5 = hashlib.md5(self._data).hexdigest()
        sha256 = hashlib.sha256(self._data).hexdigest()
        return {
            "program_name": self._firmware_path.name,
            "executable_path": str(self._firmware_path),
            "executable_md5": md5,
            "executable_sha256": sha256,
            "executable_format": "RAW",
            "image_base": f"0x{self._base:08x}",
            "language_id": "ARM:LE:32:v7",
            "compiler_spec_id": "default",
            "entry_points": [f"0x{self._base:08x}"],
            "memory_blocks": [
                {
                    "name": ".text",
                    "start": f"0x{self._base:08x}",
                    "end": f"0x{self._base + len(self._data) - 1:08x}",
                    "length": len(self._data),
                    "rwx": "r-x",
                    "loaded": True,
                    "initialized": True,
                }
            ],
            "imports_count": 0,
            "exports_count": 0,
        }

    def get_project_files(self) -> List[Dict[str, object]]:
        self._clear_error()
        return [
            {
                "domain_file_id": None,
                "name": "root",
                "path": "/",
                "type": "Folder",
                "size": None,
            },
            {
                "domain_file_id": "1",
                "name": self._firmware_path.name,
                "path": f"/{self._firmware_path.name}",
                "type": "Program",
                "size": self._firmware_path.stat().st_size,
            },
        ]

    def search_strings(self, query: str) -> List[Dict[str, object]]:
        self._clear_error()
        needle = query.lower().strip()
        return [
            entry
            for entry in self._strings
            if not needle or needle in str(entry["literal"]).lower()
        ]

    def get_xrefs_to(self, address: int, limit: int | None = None) -> List[Dict[str, object]]:
        self._clear_error()
        results = list(self._xrefs)
        return results[:limit] if limit else results

    def disassemble_function(self, address: int) -> List[str]:
        self._clear_error()
        # Always return the same annotated window for determinism
        return list(self._disassembly)

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        self._clear_error()
        return True

    def search_functions(
        self,
        query: str,
        *,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> CursorPageResult[str]:
        self._clear_error()
        all_functions = [
            f"{meta.name} @ 0x{addr:08x}" for addr, meta in sorted(self._functions.items())
        ]
        needle = query.lower().strip()
        filtered = [f for f in all_functions if needle in f.lower()]
        filtered.sort()
        start = offset
        if cursor:
            try:
                start = int(cursor)
            except ValueError:
                start = offset
        end = start + max(1, limit)
        page = filtered[start:end]
        has_more = end < len(filtered)
        next_cursor = str(end) if has_more else None
        return CursorPageResult(page, has_more, next_cursor)

    def disassemble_at(self, address: int, count: int) -> List[Dict[str, str]]:
        self._clear_error()
        return [
            {
                "address": f"0x{address + i * 4:08x}",
                "bytes": "",
                "text": f"LDR r{i}, =0x40000000" if i == 1 else f"INSN_{i}",
            }
            for i in range(max(0, count))
        ]

    def search_scalars(
        self, value: int, *, limit: int = 100, offset: int = 0, cursor: Optional[str] = None
    ) -> CursorPageResult[Dict[str, object]]:
        self._clear_error()
        matches = [m for m in self._scalar_matches if value == 0x40000000 or value == 0xDEADBEEF]
        start = offset
        if cursor:
            try:
                start = int(cursor)
            except ValueError:
                start = offset
        end = start + max(1, limit)
        page = matches[start:end]
        has_more = end < len(matches)
        next_cursor = str(end) if has_more else None
        return CursorPageResult(page, has_more, next_cursor)

    def read_bytes(self, address: int, length: int) -> Optional[bytes]:
        self._clear_error()
        if length <= 0:
            return b""
        offset = address - self._base
        if offset < 0 or offset >= len(self._data):
            self._set_error(404, "address out of range")
            return None
        end = min(offset + length, len(self._data))
        return bytes(self._data[offset:end])

    def close(self) -> None:  # pragma: no cover - compatibility hook
        return None


__all__ = ["ReferenceGhidraClient"]
