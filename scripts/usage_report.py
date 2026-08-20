#!/usr/bin/env python3
"""Summarise a usage JSONL log into a "tokens by tool" table.

Reads the JSONL produced by ``GHIDRA_MCP_USAGE_LOG`` (see
``scripts/reference_run.py``) and prints the per-tool ranking that the rework
baseline is measured against.

Two token columns are reported on purpose:

``est_tokens``
    The shared estimator (``bridge.utils.tokens.estimate_tokens``), i.e. the
    same function that drives the ``collect`` result budget.  It counts string
    characters only, so payloads made of numbers are under-reported.
``bytes/4``
    The serialized response size divided by four.  This is the honest upper
    bound and makes the estimator's blind spot visible instead of hiding it.

Usage::

    python scripts/usage_report.py baseline/reference_run.jsonl
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Sequence


def load_entries(path: Path) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        entries.append(json.loads(line))
    return entries


def summarise(entries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    per_tool: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "calls": 0,
            "est_tokens": 0,
            "result_bytes": 0,
            "duration_ms": 0.0,
            "hits": 0,
            "hits_known": 0,
            "errors": 0,
        }
    )
    for entry in entries:
        row = per_tool[entry.get("tool", "?")]
        row["calls"] += 1
        row["est_tokens"] += int(entry.get("estimate_tokens") or 0)
        row["result_bytes"] += int(entry.get("result_bytes") or 0)
        row["duration_ms"] += float(entry.get("duration_ms") or 0.0)
        hits = entry.get("hits")
        if isinstance(hits, int) and not isinstance(hits, bool):
            row["hits"] += hits
            row["hits_known"] += 1
        if entry.get("ok") is False:
            row["errors"] += 1

    rows = []
    for tool, row in per_tool.items():
        rows.append(
            {
                "tool": tool,
                **row,
                "bytes_tokens": row["result_bytes"] // 4,
            }
        )
    rows.sort(key=lambda item: (item["bytes_tokens"], item["est_tokens"]), reverse=True)

    return {
        "calls": len(entries),
        "tools": len(rows),
        "total_est_tokens": sum(r["est_tokens"] for r in rows),
        "total_bytes": sum(r["result_bytes"] for r in rows),
        "total_bytes_tokens": sum(r["bytes_tokens"] for r in rows),
        "rows": rows,
    }


def render(report: Dict[str, Any]) -> str:
    lines = [
        f"calls: {report['calls']}   distinct tools: {report['tools']}",
        f"total est_tokens: {report['total_est_tokens']}   "
        f"total bytes: {report['total_bytes']} ({report['total_bytes_tokens']} tokens)",
        "",
        f"{'tool':<30} {'calls':>5} {'est_tokens':>11} {'bytes':>9} "
        f"{'bytes/4':>8} {'hits':>6} {'ms':>9} {'err':>4}",
        "-" * 92,
    ]
    for row in report["rows"]:
        hits = str(row["hits"]) if row["hits_known"] else "-"
        lines.append(
            f"{row['tool']:<30} {row['calls']:>5} {row['est_tokens']:>11} "
            f"{row['result_bytes']:>9} {row['bytes_tokens']:>8} {hits:>6} "
            f"{row['duration_ms']:>9.1f} {row['errors']:>4}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="usage JSONL log")
    parser.add_argument("--json", type=Path, help="also write the summary as JSON")
    args = parser.parse_args(argv)

    report = summarise(load_entries(args.log))
    print(render(report))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
