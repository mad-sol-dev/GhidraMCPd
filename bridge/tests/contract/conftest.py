from __future__ import annotations

from typing import Dict, List, Optional

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.ghidra.client import CursorPageResult, DataTypeOperationResult
from bridge.error_handlers import install_error_handlers
from bridge.tests._env import env_flag, in_ci
from bridge.utils import config


_RUN_CONTRACT_TESTS = env_flag("RUN_CONTRACT_TESTS", default=not in_ci())

if not _RUN_CONTRACT_TESTS:
    _SKIP_REASON = "Contract tests disabled. Set RUN_CONTRACT_TESTS=1 to enable."

    def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
        skip_marker = pytest.mark.skip(reason=_SKIP_REASON)
        for item in items:
            item.add_marker(skip_marker)


class StubGhidraClient:
    """Minimal stub that satisfies feature dependencies for contract tests."""

    def __init__(self) -> None:
        self._jt_base = 0x00100000
        self._slot_values: List[Optional[int]] = [
            0x00102030,
            0x0010FFFF,
            0xE12FFF1C,
            None,
            0x00102031,
            0x00111000,
            0x00100000,
            0x00100004,
            0x00100008,
            0x0010000C,
            0x00100010,
            0x00100014,
            0x00100018,
            0x0010001C,
            0x00100020,
            0x00100024,
        ]
        valid_targets = {
            0x00102030: {"name": "target_func", "comment": "existing"},
            0x00100000: {"name": "sub_00100000", "comment": ""},
            0x00100004: {"name": "sub_00100004", "comment": ""},
            0x00100008: {"name": "sub_00100008", "comment": ""},
            0x0010000C: {"name": "sub_0010000c", "comment": ""},
            0x00100010: {"name": "sub_00100010", "comment": ""},
            0x00100014: {"name": "sub_00100014", "comment": ""},
            0x00100018: {"name": "sub_00100018", "comment": ""},
            0x0010001C: {"name": "sub_0010001c", "comment": ""},
            0x00100020: {"name": "sub_00100020", "comment": ""},
            0x00100024: {"name": "sub_00100024", "comment": ""},
        }
        self._functions: Dict[int, Dict[str, str]] = valid_targets
        self._xrefs: List[Dict[str, object]] = [
            {"addr": addr, "context": f"Call at {addr:08x}"}
            for addr in (
                0x00100000,
                0x00100004,
                0x00100008,
                0x0010000C,
                0x00100010,
                0x00100014,
                0x00100018,
                0x0010001C,
            )
        ]
        self._strings: List[Dict[str, object]] = [
            {
                "literal": "Error: invalid checksum\n(retry)",
                "address": 0x00200000,
                "refs": 8,
            },
            {"literal": "Boot complete", "address": 0x00200030, "refs": 2},
            {
                "literal": "Status: ready for commands",
                "address": 0x00200010,
                "refs": 4,
            },
        ]
        self._string_lookup = {
            entry["address"]: str(entry["literal"])
            for entry in self._strings
        }
        self._imports: List[str] = [
            f"import_symbol_{i:04d} -> 0x{0x10000000 + i:08x}"
            for i in range(24)
        ]
        self._exports: List[str] = [
            f"export_symbol_{i:04d} -> 0x{0x20000000 + i:08x}"
            for i in range(24)
        ]
        self._project_info: Dict[str, object] = {
            "program_name": "stub_program",
            "executable_path": "/opt/programs/stub_program.bin",
            "executable_md5": "0123456789abcdef0123456789abcdef",
            "executable_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "executable_format": "ELF",
            "image_base": "0x00100000",
            "language_id": "ARM:LE:32:v7",
            "compiler_spec_id": "default",
            "entry_points": ["0x00100000"],
            "memory_blocks": [
                {
                    "name": ".text",
                    "start": "0x00100000",
                    "end": "0x0010ffff",
                    "length": 65536,
                    "rwx": "r-x",
                    "loaded": True,
                    "initialized": True,
                },
                {
                    "name": ".data",
                    "start": "0x00200000",
                    "end": "0x00200fff",
                    "length": 4096,
                    "rwx": "rw-",
                    "loaded": True,
                    "initialized": True,
                },
                {
                    "name": ".bss",
                    "start": "0x00201000",
                    "end": "0x00201fff",
                    "length": 4096,
                    "rwx": "rw-",
                    "loaded": True,
                    "initialized": False,
                },
            ],
            "imports_count": len(self._imports),
            "exports_count": len(self._exports),
        }
        self._project_files: List[Dict[str, object]] = [
            {
                "domain_file_id": None,
                "name": "root",
                "path": "/",
                "type": "Folder",
                "size": None,
            },
            {
                "domain_file_id": "1",
                "name": "sample_program",
                "path": "/sample_program",
                "type": "Program",
                "size": 1024,
            },
            {
                "domain_file_id": "2",
                "name": "docs",
                "path": "/docs",
                "type": "Folder",
                "size": None,
            },
            {
                "domain_file_id": "3",
                "name": "readme.txt",
                "path": "/docs/readme.txt",
                "type": "Text",
                "size": 256,
            },
        ]
        self._datatypes: Dict[str, Dict[str, object]] = {
            "/structs/Packet": {
                "kind": "structure",
                "name": "Packet",
                "category": "/structs",
                "path": "/structs/Packet",
                "fields": [
                    {"name": "id", "type": "uint32", "offset": 0, "length": 4},
                    {"name": "flags", "type": "uint16", "offset": 4, "length": 2},
                ],
                "size": 6,
            },
            "/unions/Payload": {
                "kind": "union",
                "name": "Payload",
                "category": "/unions",
                "path": "/unions/Payload",
                "fields": [
                    {"name": "raw", "type": "uint32", "length": 4},
                    {"name": "ptr", "type": "pointer", "length": 8},
                ],
                "size": 8,
            },
        }

    def _normalize_category(self, category: str) -> str:
        value = str(category or "").strip()
        if not value:
            return "/"
        if not value.startswith("/"):
            value = f"/{value}"
        if value != "/":
            value = value.rstrip("/")
        return value or "/"

    def _datatype_path(self, category: str, name: str) -> str:
        category = self._normalize_category(category)
        if category == "/":
            return f"/{name}"
        return f"{category}/{name}"

    def _prepare_fields(self, fields: List[Dict[str, object]]) -> List[Dict[str, object]]:
        prepared: List[Dict[str, object]] = []
        for field in fields:
            entry: Dict[str, object] = {
                "name": str(field.get("name", "")),
                "type": str(field.get("type", "")),
            }
            if "offset" in field:
                entry["offset"] = int(field.get("offset", 0))
            if "length" in field:
                entry["length"] = int(field.get("length", 0))
            prepared.append(entry)
        return prepared

    def _estimate_size(self, kind: str, fields: List[Dict[str, object]]) -> int:
        size = 0
        for field in fields:
            length = int(field.get("length", 0) or 0)
            if kind == "structure":
                offset = int(field.get("offset", 0) or 0)
                size = max(size, offset + length)
            else:
                size = max(size, length)
        return size

    def create_structure(
        self,
        *,
        name: str,
        category: str,
        fields: List[Dict[str, object]],
    ) -> DataTypeOperationResult:
        category_norm = self._normalize_category(category)
        path = self._datatype_path(category_norm, name)
        prepared = self._prepare_fields(fields)
        payload = {
            "kind": "structure",
            "name": name,
            "category": category_norm,
            "path": path,
            "fields": prepared,
            "size": self._estimate_size("structure", prepared),
        }
        self._datatypes[path] = payload
        return DataTypeOperationResult(True, datatype=dict(payload))

    def update_structure(
        self,
        *,
        path: str,
        fields: List[Dict[str, object]],
    ) -> DataTypeOperationResult:
        existing = self._datatypes.get(path)
        if existing is None:
            return DataTypeOperationResult(False, error="datatype not found")
        prepared = self._prepare_fields(fields)
        payload = dict(existing)
        payload.update(
            {
                "kind": "structure",
                "path": path,
                "fields": prepared,
                "size": self._estimate_size("structure", prepared),
            }
        )
        self._datatypes[path] = payload
        return DataTypeOperationResult(True, datatype=dict(payload))

    def create_union(
        self,
        *,
        name: str,
        category: str,
        fields: List[Dict[str, object]],
    ) -> DataTypeOperationResult:
        category_norm = self._normalize_category(category)
        path = self._datatype_path(category_norm, name)
        prepared = self._prepare_fields(fields)
        payload = {
            "kind": "union",
            "name": name,
            "category": category_norm,
            "path": path,
            "fields": prepared,
            "size": self._estimate_size("union", prepared),
        }
        self._datatypes[path] = payload
        return DataTypeOperationResult(True, datatype=dict(payload))

    def update_union(
        self,
        *,
        path: str,
        fields: List[Dict[str, object]],
    ) -> DataTypeOperationResult:
        existing = self._datatypes.get(path)
        if existing is None:
            return DataTypeOperationResult(False, error="datatype not found")
        prepared = self._prepare_fields(fields)
        payload = dict(existing)
        payload.update(
            {
                "kind": "union",
                "path": path,
                "fields": prepared,
                "size": self._estimate_size("union", prepared),
            }
        )
        self._datatypes[path] = payload
        return DataTypeOperationResult(True, datatype=dict(payload))

    def delete_datatype(self, *, kind: str, path: str) -> DataTypeOperationResult:
        existing = self._datatypes.pop(path, None)
        if existing is None:
            return DataTypeOperationResult(False, error="datatype not found")
        payload = {
            "kind": existing.get("kind", kind),
            "path": path,
        }
        return DataTypeOperationResult(True, datatype=payload)

    def read_dword(self, address: int) -> Optional[int]:
        index = (address - self._jt_base) // 4
        if 0 <= index < len(self._slot_values):
            return self._slot_values[index]
        return 0x00102030

    def get_function_by_address(self, address: int) -> Optional[Dict[str, str]]:
        meta = self._functions.get(address)
        return dict(meta) if meta else None

    def rename_function(self, address: int, new_name: str) -> bool:
        return True

    def set_decompiler_comment(self, address: int, comment: str) -> bool:
        return True

    def get_xrefs_to(self, address: int, *, limit: int = 50):
        return list(self._xrefs)

    def search_xrefs_to(self, address: int, query: str):
        normalized = query.lower()
        return [
            dict(entry)
            for entry in self._xrefs
            if not normalized or normalized in str(entry["context"]).lower()
        ]

    def disassemble_function(self, address: int):
        if address == 0x00005000:
            return [
                "00005000: BL target_func",
                "00005004: MOV R0, R1",
            ]
        if address == 0x00006000:
            return [
                "00006000: LDR R0, [R1, #0x10]",
                "00006004: STR R0, [R1, #0x10]",
                "00006008: ORR R0, R0, #0x1",
                "0000600C: AND R0, R0, #0xfffffffe",
                "00006010: EOR R0, R0, #0x1",
            ]
        if address == 0x00007000:
            return [
                "00007000: LDR R0, [R1, #0x0]",
                "00007004: STR R2, [R3, #0x4]",
                "00007008: ORR R4, R4, #0x2",
                "0000700C: AND R5, R5, #0xfffffffd",
                "00007010: EOR R6, R6, #0x1",
                "00007014: MOV R7, R7",
            ]
        if address in self._functions:
            return [
                f"{address:08x}: PUSH {{lr}}",
                f"{address + 4:08x}: BL dispatch_handler",
                f"{address + 8:08x}: ADR R0, 0x00200000",
            ]
        return []

    def decompile_function(self, address: int) -> Optional[str]:
        if address in self._functions:
            return "int sub_stub(void) {\n    return 1;\n}"
        return "void helper(void) {\n    return;\n}"

    def set_disassembly_comment(self, address: int, comment: str) -> bool:
        return True

    def rebase_program(
        self,
        *,
        new_base: int,
        offset: Optional[int] = None,
        confirm: bool = False,
    ) -> tuple[bool, list[str]]:
        if not confirm:
            return False, ["ERROR: confirmation required"]

        try:
            current_base = int(str(self._project_info["image_base"]), 16)
        except (KeyError, TypeError, ValueError):
            current_base = None

        if offset is None and current_base is not None:
            offset = new_base - current_base

        if current_base is not None and offset is not None:
            delta = offset
        elif current_base is not None:
            delta = new_base - current_base
        else:
            delta = offset or 0

        self._project_info["image_base"] = f"0x{new_base:08x}"

        if delta:
            updated_entry_points: list[str] = []
            for entry in self._project_info.get("entry_points", []):
                try:
                    value = int(str(entry), 16)
                except (TypeError, ValueError):
                    updated_entry_points.append(str(entry))
                else:
                    updated_entry_points.append(f"0x{value + delta:08x}")
            if updated_entry_points:
                self._project_info["entry_points"] = updated_entry_points

            blocks: list[Dict[str, object]] = []
            for block in self._project_info.get("memory_blocks", []):
                if not isinstance(block, dict):
                    continue
                start = block.get("start")
                end = block.get("end")
                try:
                    start_value = int(str(start), 16)
                    end_value = int(str(end), 16)
                except (TypeError, ValueError):
                    blocks.append(dict(block))
                    continue
                updated = dict(block)
                updated["start"] = f"0x{start_value + delta:08x}"
                updated["end"] = f"0x{end_value + delta:08x}"
                blocks.append(updated)
            if blocks:
                self._project_info["memory_blocks"] = blocks

        message = f"Rebased by {delta:+#x}" if delta else "Rebase applied"
        return True, [message]

    def list_strings_compact(
        self, *, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, object]]:
        if limit < 0:
            limit = 0
        start = max(offset, 0)
        end = start + limit
        return [dict(entry) for entry in self._strings[start:end]]

    def search_strings(self, query: str) -> List[Dict[str, object]]:
        normalized = query.lower()
        results: List[Dict[str, object]] = []
        for entry in self._strings:
            literal = str(entry.get("literal", ""))
            if not normalized or normalized in literal.lower():
                results.append(dict(entry))
        return results

    def read_cstring(self, address: int, *, max_len: int = 256) -> Optional[str]:
        return self._string_lookup.get(address)

    def search_functions(
        self,
        query: str,
        *,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> CursorPageResult[str]:
        """Return a predictable list of functions for testing."""

        all_functions = [
            "Reset at 0000ABCD",
            "reset_handler @ 00FF10",
        ]
        all_functions.extend(
            f"func_{i:04d} @ 0x{0x00400000 + i * 0x100:08x}"
            for i in range(20)
        )
        for addr, meta in self._functions.items():
            all_functions.append(f"{meta['name']} @ 0x{addr:08x}")

        normalized_query = query.lower()
        filtered = [f for f in all_functions if normalized_query in f.lower()]

        # Stable ordering to mimic plugin behaviour.
        filtered.sort()

        start = max(0, offset)
        if cursor:
            try:
                start = max(0, int(cursor))
            except ValueError:
                start = max(0, offset)
        end = start + max(1, limit)
        page_items = filtered[start:end]
        has_more = end < len(filtered)
        next_cursor = str(end) if has_more else None
        return CursorPageResult(page_items, has_more, next_cursor)

    def disassemble_at(self, address: int, count: int) -> List[Dict[str, str]]:
        return [
            {
                "address": f"0x{address + i * 4:08x}",
                "bytes": "",
                "text": f"INSN_{i}",
            }
            for i in range(max(0, count))
        ]

    def list_functions_in_range(
        self, address_min: int, address_max: int
    ) -> List[Dict[str, object]]:
        results: List[Dict[str, object]] = []
        for addr, meta in sorted(self._functions.items()):
            if address_min <= addr <= address_max:
                results.append(
                    {
                        "name": meta.get("name", f"sub_{addr:08x}"),
                        "address": f"0x{addr:08x}",
                        "size": None,
                    }
                )
        return results

    def search_imports(self, query: str) -> List[str]:
        normalized_query = query.lower()
        return [
            entry
            for entry in self._imports
            if not normalized_query or normalized_query in entry.lower()
        ]

    def search_exports(self, query: str) -> List[str]:
        normalized_query = query.lower()
        return [
            entry
            for entry in self._exports
            if not normalized_query or normalized_query in entry.lower()
        ]

    def get_project_info(self) -> Dict[str, object]:
        return {
            "program_name": self._project_info["program_name"],
            "executable_path": self._project_info["executable_path"],
            "executable_md5": self._project_info["executable_md5"],
            "executable_sha256": self._project_info["executable_sha256"],
            "executable_format": self._project_info["executable_format"],
            "image_base": self._project_info["image_base"],
            "language_id": self._project_info["language_id"],
            "compiler_spec_id": self._project_info["compiler_spec_id"],
            "entry_points": list(self._project_info["entry_points"]),
            "memory_blocks": [dict(block) for block in self._project_info["memory_blocks"]],
            "imports_count": self._project_info["imports_count"],
            "exports_count": self._project_info["exports_count"],
        }

    def get_project_files(self) -> List[Dict[str, object]]:
        return [dict(entry) for entry in self._project_files]

    def close(self) -> None:
        return None


@pytest.fixture()
def contract_client() -> TestClient:
    def factory() -> StubGhidraClient:
        return StubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=False))
    install_error_handlers(app)
    return TestClient(app)


@pytest.fixture()
def contract_client_writable(
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    monkeypatch.setattr(config, "ENABLE_PROJECT_REBASE", True)

    def factory() -> StubGhidraClient:
        return StubGhidraClient()

    app = Starlette(routes=make_routes(factory, enable_writes=True))
    install_error_handlers(app)
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()
