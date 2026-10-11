#!/usr/bin/env python3
"""Write the MCP tool catalogue (docs/reference/tools.md) from the tools' docstrings.

The docstrings are what a model reads when it picks a tool, so they are the
source; this page only arranges them for people.  A unit test regenerates the
page and fails when it drifts, and when a tool has no group below.

Usage::

    python scripts/gen_tools_md.py > docs/reference/tools.md
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: Section title -> tools, in the order a session tends to use them.
GROUPS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Orientation", (
        "project_info", "project_overview", "get_current_program", "select_program", "goto_address",
    )),
    ("Finding things", (
        "search_functions", "search_strings", "strings_compact", "string_xrefs_compact",
        "search_xrefs_to", "search_scalars", "search_scalars_with_context", "search_imports",
        "search_exports", "list_functions_in_range",
    )),
    ("Reading code and memory", (
        "analyze_function_complete", "disassemble_at", "disassemble_batch", "find_in_function",
        "read_bytes", "read_words", "mmio_annotate_compact", "collect",
    )),
    ("Jump tables", ("jt_slot_check", "jt_scan", "jt_slot_process")),
    ("Writing (dry run by default)", (
        "rename_function", "set_comment", "apply_label", "datatypes_create", "datatypes_update",
        "datatypes_delete",
    )),
    ("Unsaved work", ("list_mutations", "check_dirty_state", "save_program")),
)


def tool_docs() -> Dict[str, str]:
    from mcp.server.fastmcp import FastMCP

    from bridge.api.tools import register_tools

    server = FastMCP("catalogue")
    register_tools(server, client_factory=lambda: None, enable_writes=False)
    return {name: (tool.fn.__doc__ or "") for name, tool in server._tool_manager._tools.items()}


def _paragraphs(doc: str) -> List[str]:
    lines = [line.strip() for line in doc.strip().splitlines()]
    paragraphs, current = [], []
    for line in lines:
        if line:
            current.append(line)
        elif current:
            paragraphs.append(" ".join(current))
            current = []
    if current:
        paragraphs.append(" ".join(current))
    return paragraphs


def entry(name: str, doc: str) -> str:
    paragraphs = _paragraphs(doc)
    summary = paragraphs[0] if paragraphs else ""
    not_for = next((p for p in paragraphs if p.startswith("Not for:")), None)
    writes = "GHIDRA_MCP_ENABLE_WRITES" in doc
    lines = [f"### `{name}`", "", summary]
    if not_for:
        lines += ["", f"*{not_for.split(':', 1)[0]}:*{not_for.split(':', 1)[1]}"]
    if writes:
        lines += ["", "Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`."]
    return "\n".join(lines)


def render(docs: Dict[str, str]) -> str:
    grouped = [name for _, names in GROUPS for name in names]
    missing = sorted(set(docs) - set(grouped))
    unknown = sorted(set(grouped) - set(docs))
    if missing or unknown:
        raise SystemExit(f"tools without a group: {missing}; grouped but not registered: {unknown}")

    out = [
        "# MCP tools",
        "",
        "Generated from the tool docstrings by `scripts/gen_tools_md.py`; do not edit by hand.",
        "The docstrings are what a model sees when it chooses a tool. Full parameter",
        "descriptions are in each tool's schema, as the MCP client shows it.",
        "",
        f"{len(docs)} tools.",
    ]
    for title, names in GROUPS:
        out += ["", f"## {title}"]
        for name in names:
            out += ["", entry(name, docs[name])]
    return "\n".join(out) + "\n"


def main() -> int:
    sys.stdout.write(render(tool_docs()))
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
