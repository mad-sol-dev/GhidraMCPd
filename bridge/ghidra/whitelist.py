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
            ("disassemble", "disassemble_function", "disasmByAddr"),
        ),
        WhitelistEntry(
            "GET",
            "FUNC_BY_ADDR",
            ("function_by_addr", "get_function_by_address", "functionMeta"),
        ),
        WhitelistEntry("GET", "GET_XREFS_TO", ("get_xrefs_to", "xrefs_to")),
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
            ("decompile_function", "decompileFunction", "decompile_by_addr", "decompileByAddr"),
        ),
        WhitelistEntry("GET", "PROJECT_INFO", ("projectInfo", "project_info")),
        WhitelistEntry("GET", "PROJECT_FILES", ("project_files",)),
        WhitelistEntry(
            "GET",
            "CURRENT_PROGRAM_STATUS",
            ("api/current_program.json", "current_program"),
        ),
        WhitelistEntry("GET", "OPEN_PROGRAM", ("open_program",)),
        WhitelistEntry("GET", "GOTO", ("goto",)),
    ),
    "POST": (
        WhitelistEntry(
            "POST",
            "RENAME_FUNCTION",
            ("rename_function_by_address", "renameFunctionByAddress"),
        ),
        WhitelistEntry(
            "POST",
            "SET_DECOMPILER_COMMENT",
            ("set_decompiler_comment", "setDecompilerComment"),
        ),
        WhitelistEntry(
            "POST",
            "SET_DISASSEMBLY_COMMENT",
            ("set_disassembly_comment", "setDisassemblyComment"),
        ),
        WhitelistEntry("POST", "START_TRANSACTION", ("startTransaction",)),
        WhitelistEntry("POST", "COMMIT_TRANSACTION", ("commitTransaction",)),
        WhitelistEntry("POST", "ROLLBACK_TRANSACTION", ("rollbackTransaction",)),
        WhitelistEntry("POST", "WRITE_BYTES", ("writeBytes",)),
        WhitelistEntry("POST", "REBUILD_CODE_UNITS", ("rebuildCodeUnits",)),
        WhitelistEntry("POST", "REBASE_PROGRAM", ("rebaseProgram", "rebase_program")),
        WhitelistEntry("POST", "CREATE_STRUCTURE", ("createStructure", "create_structure")),
        WhitelistEntry("POST", "UPDATE_STRUCTURE", ("updateStructure", "update_structure")),
        WhitelistEntry("POST", "CREATE_UNION", ("createUnion", "create_union")),
        WhitelistEntry("POST", "UPDATE_UNION", ("updateUnion", "update_union")),
        WhitelistEntry("POST", "DELETE_DATATYPE", ("deleteDataType", "delete_datatype")),
    ),
}
