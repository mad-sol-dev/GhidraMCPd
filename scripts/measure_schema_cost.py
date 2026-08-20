#!/usr/bin/env python3
"""Measure the schema base cost of the MCP tool surface.

Every session pays for the tool list before a single call happens: name,
description and input schema of each tool are part of the prompt.  This script
reports that fixed cost, per tool and in total, using the same estimator as the
usage log.

**It measures the real ``tools/list`` response** of a bridge started over stdio
-- what an MCP client actually receives -- not what introspecting the decorated
Python functions suggests.  ``--source introspect`` measures the in-process tool
manager instead, and ``--source both`` prints the two side by side; a difference
between them means docstrings exist in the code that never reach the model.

Usage::

    python scripts/measure_schema_cost.py
    python scripts/measure_schema_cost.py --source both
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Sequence

import mcp.types as types
from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.utils.tokens import estimate_tokens  # noqa: E402

DEFAULT_BRIDGE = ROOT / "scripts/bridge_stdio.py"
DEFAULT_GHIDRA = "http://127.0.0.1:8080/"


def _chars_to_tokens(chars: int) -> int:
    return chars // 4


def _row(name: str, description: str | None, schema: Dict[str, Any] | None) -> Dict[str, Any]:
    description = description or ""
    schema = schema or {}
    schema_json = json.dumps(schema, sort_keys=True, separators=(",", ":"))

    total_chars = len(name) + len(description) + len(schema_json)
    return {
        "tool": name,
        "has_description": bool(description.strip()),
        "description_chars": len(description),
        "schema_chars": len(schema_json),
        "total_chars": total_chars,
        "total_tokens": _chars_to_tokens(total_chars),
        # Same estimator as the usage log, applied to the advertised schema
        # payload, for a like-for-like comparison.
        "estimate_tokens": estimate_tokens(
            {"name": name, "description": description, "schema": schema}
        ),
    }


def _report(rows: List[Dict[str, Any]], source: str) -> Dict[str, Any]:
    rows.sort(key=lambda row: row["total_tokens"], reverse=True)
    return {
        "source": source,
        "tool_count": len(rows),
        "undocumented_tools": [r["tool"] for r in rows if not r["has_description"]],
        "total_chars": sum(r["total_chars"] for r in rows),
        "total_tokens": sum(r["total_tokens"] for r in rows),
        "tools": rows,
    }


async def _list_tools_over_stdio(args: argparse.Namespace) -> List[types.Tool]:
    env = dict(os.environ)
    env["GHIDRA_SERVER_URL"] = args.ghidra_server_url
    env["GHIDRA_MCP_ENABLE_WRITES"] = "false"
    env.pop("GHIDRA_MCP_USAGE_LOG", None)

    server = StdioServerParameters(
        command=args.python_command,
        args=[str(args.bridge_script), "--transport", "stdio"],
        env=env,
        cwd=str(ROOT),
    )
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(
            read_stream, write_stream, read_timeout_seconds=timedelta(seconds=args.timeout)
        ) as session:
            await session.initialize()
            return (await session.list_tools()).tools


def collect_from_wire(args: argparse.Namespace) -> Dict[str, Any]:
    """The authoritative measurement: what a client receives from tools/list."""

    tools = asyncio.run(_list_tools_over_stdio(args))
    return _report([_row(t.name, t.description, t.inputSchema) for t in tools], "tools/list")


def collect_from_introspection() -> Dict[str, Any]:
    """The in-process view, kept only to expose disagreement with the wire."""

    from bridge.app import MCP_SERVER, configure

    configure()
    tools = asyncio.run(MCP_SERVER.list_tools())
    return _report([_row(t.name, t.description, t.inputSchema) for t in tools], "introspect")


def render_table(report: Dict[str, Any]) -> str:
    lines = [
        f"source: {report['source']}",
        f"Tools: {report['tool_count']}",
        f"Schema base cost: {report['total_tokens']} tokens "
        f"({report['total_chars']} chars)",
        f"Without description: {len(report['undocumented_tools'])}",
        "",
        f"{'tool':<32} {'desc_ch':>8} {'schema_ch':>10} {'tokens':>8}  doc",
        "-" * 72,
    ]
    for row in report["tools"]:
        lines.append(
            f"{row['tool']:<32} {row['description_chars']:>8} "
            f"{row['schema_chars']:>10} {row['total_tokens']:>8}  "
            f"{'yes' if row['has_description'] else 'NO'}"
        )
    return "\n".join(lines)


def render_comparison(wire: Dict[str, Any], introspect: Dict[str, Any]) -> str:
    wire_docs = {r["tool"]: r["description_chars"] for r in wire["tools"]}
    intro_docs = {r["tool"]: r["description_chars"] for r in introspect["tools"]}

    lines = [
        "",
        "tools/list vs introspection",
        "-" * 72,
        f"tools:            {wire['tool_count']:>6} / {introspect['tool_count']:>6}",
        f"schema tokens:    {wire['total_tokens']:>6} / {introspect['total_tokens']:>6}",
        f"undocumented:     {len(wire['undocumented_tools']):>6} / "
        f"{len(introspect['undocumented_tools']):>6}",
    ]

    disagreements = [
        name
        for name in sorted(set(wire_docs) | set(intro_docs))
        if wire_docs.get(name) != intro_docs.get(name)
    ]
    if disagreements:
        lines.append("")
        lines.append("Docstrings that do NOT reach the client:")
        for name in disagreements:
            lines.append(
                f"  {name:<32} wire={wire_docs.get(name)!s:>6} "
                f"introspect={intro_docs.get(name)!s:>6}"
            )
    else:
        lines.append("")
        lines.append("The two agree: every docstring in the code reaches the client.")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        choices=("wire", "introspect", "both"),
        default="wire",
        help="wire (default) measures the real tools/list response",
    )
    parser.add_argument("--json", type=Path, help="write the raw report to this path")
    parser.add_argument(
        "--ghidra-server-url", default=os.getenv("GHIDRA_SERVER_URL", DEFAULT_GHIDRA)
    )
    parser.add_argument("--bridge-script", type=Path, default=DEFAULT_BRIDGE)
    parser.add_argument("--python-command", default=sys.executable)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)

    if args.source == "introspect":
        report = collect_from_introspection()
        print(render_table(report))
    elif args.source == "wire":
        report = collect_from_wire(args)
        print(render_table(report))
    else:
        report = collect_from_wire(args)
        introspect = collect_from_introspection()
        print(render_table(report))
        print(render_comparison(report, introspect))
        report = {"wire": report, "introspect": introspect}

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
