#!/usr/bin/env python3
"""Measure the schema base cost of the MCP tool surface.

Every session pays for the tool list before a single call happens: name,
description and input schema of each tool are part of the prompt.  This script
registers the tools in-process and reports that fixed cost, per tool and in
total, using the same estimator as the usage log.

Usage::

    python scripts/measure_schema_cost.py [--json OUT.json]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.app import MCP_SERVER, configure  # noqa: E402
from bridge.utils.tokens import estimate_tokens  # noqa: E402


def _chars_to_tokens(chars: int) -> int:
    return chars // 4


def collect_schema_cost() -> Dict[str, Any]:
    configure()
    tools = asyncio.run(MCP_SERVER.list_tools())

    rows: List[Dict[str, Any]] = []
    for tool in tools:
        name = tool.name
        description = tool.description or ""
        schema = tool.inputSchema or {}
        schema_json = json.dumps(schema, sort_keys=True, separators=(",", ":"))

        name_chars = len(name)
        desc_chars = len(description)
        schema_chars = len(schema_json)
        total_chars = name_chars + desc_chars + schema_chars

        rows.append(
            {
                "tool": name,
                "has_description": bool(description.strip()),
                "description_chars": desc_chars,
                "schema_chars": schema_chars,
                "total_chars": total_chars,
                "total_tokens": _chars_to_tokens(total_chars),
                # Same estimator as the usage log, applied to the advertised
                # schema payload, for a like-for-like comparison.
                "estimate_tokens": estimate_tokens(
                    {"name": name, "description": description, "schema": schema}
                ),
            }
        )

    rows.sort(key=lambda row: row["total_tokens"], reverse=True)
    return {
        "tool_count": len(rows),
        "undocumented_tools": [r["tool"] for r in rows if not r["has_description"]],
        "total_chars": sum(r["total_chars"] for r in rows),
        "total_tokens": sum(r["total_tokens"] for r in rows),
        "tools": rows,
    }


def render_table(report: Dict[str, Any]) -> str:
    lines = [
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


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write the raw report to this path")
    args = parser.parse_args(argv)

    report = collect_schema_cost()
    print(render_table(report))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
