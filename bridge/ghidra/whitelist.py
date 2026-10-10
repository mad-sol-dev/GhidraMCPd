"""Whitelist definitions for allowed Ghidra REST endpoints."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple


@dataclass(frozen=True)
class WhitelistEntry:
    """Represents a logical operation and the aliases it may resolve to."""

    method: str
    key: str
    aliases: Tuple[str, ...]

    def allows(self, path: str) -> bool:
        """Return ``True`` when ``path`` is one of the whitelisted aliases."""

        return path in self.aliases


DEFAULT_WHITELIST: Dict[str, Iterable[WhitelistEntry]] = {
    "GET": (
        WhitelistEntry("GET", "READ_DWORD", ("read_dword",)),
        WhitelistEntry(
            "GET",
            "DISASSEMBLE",
            ("disassemble", "disassemble_function"),
        ),
        WhitelistEntry(
            "GET",
            "FUNC_BY_ADDR",
            ("get_function_by_address",),
        ),
        WhitelistEntry("GET", "GET_XREFS_TO", ("xrefs_to",)),
        WhitelistEntry("GET", "SEARCH_STRINGS", ("strings",)),
        WhitelistEntry(
            "GET",
            "SEARCH_FUNCTIONS",
            ("searchFunctions", "functions"),
        ),
        WhitelistEntry("GET", "SEARCH_IMPORTS", ("imports",)),
        WhitelistEntry("GET", "SEARCH_EXPORTS", ("exports",)),
        WhitelistEntry("GET", "SEARCH_SCALARS", ("searchScalars",)),
        WhitelistEntry("GET", "FUNCTIONS_IN_RANGE", ("functionsInRange",)),
        WhitelistEntry("GET", "DISASSEMBLE_AT", ("disassembleAt",)),
        WhitelistEntry("GET", "READ_BYTES", ("readBytes",)),
        WhitelistEntry("GET", "READ_CSTRING", ("read_cstring",)),
        WhitelistEntry(
            "GET",
            "DECOMPILE",
            ("decompile_function", "decompile_by_addr"),
        ),
        WhitelistEntry("GET", "PROJECT_INFO", ("projectInfo", "project_info")),
        WhitelistEntry("GET", "PROJECT_FILES", ("project_files",)),
        WhitelistEntry(
            "GET",
            "CURRENT_PROGRAM_STATUS",
            ("api/current_program.json",),
        ),
        WhitelistEntry("GET", "OPEN_PROGRAM", ("open_program",)),
        WhitelistEntry("GET", "GOTO", ("goto",)),
        WhitelistEntry("GET", "CHECK_DIRTY_STATE", ("check_dirty_state",)),
        WhitelistEntry("GET", "SAVE_PROGRAM", ("save_program",)),
    ),
    "POST": (
        WhitelistEntry(
            "POST",
            "RENAME_FUNCTION",
            ("rename_function_by_address",),
        ),
        WhitelistEntry(
            "POST",
            "SET_DECOMPILER_COMMENT",
            ("set_decompiler_comment",),
        ),
        WhitelistEntry(
            "POST",
            "SET_DISASSEMBLY_COMMENT",
            ("set_disassembly_comment",),
        ),
        WhitelistEntry("POST", "CREATE_LABEL", ("createLabel",)),
        WhitelistEntry("POST", "CREATE_STRUCTURE", ("createStructure",)),
        WhitelistEntry("POST", "UPDATE_STRUCTURE", ("updateStructure",)),
        WhitelistEntry("POST", "CREATE_UNION", ("createUnion",)),
        WhitelistEntry("POST", "UPDATE_UNION", ("updateUnion",)),
        WhitelistEntry("POST", "DELETE_DATATYPE", ("deleteDataType",)),
    ),
}
