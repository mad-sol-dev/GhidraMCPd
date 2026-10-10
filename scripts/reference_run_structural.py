#!/usr/bin/env python3
"""Replay a fixed reference session with **fixed parameters** and ``fmt="text"``.

``reference_run.py`` measures what an unprepared session costs: it passes no
size parameters, so Stage 3's lowered defaults show up there in full.  That
number is real, but it is a default effect -- less was asked for, so less came
back.

This script measures the other half.  Every call passes the *old* limits
explicitly, so the requested amount is identical before and after, and the
disassembly listings ask for ``fmt="text"``.  What it shows is efficiency per
delivered result: the text listing format, the batch filter, a leaner envelope.

Both scripts are frozen.  Comparing a Stage 7 run against Stage 3 numbers is
only meaningful while neither has been edited.

Usage::

    python scripts/reference_run_structural.py --expect-fingerprint baseline/fingerprint.json

Logs go to ``runs/`` by default; replacing a file under ``baseline/`` needs
``--overwrite-baseline`` (see ``reference_run.py``).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

import mcp.types as types
from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# The fingerprint machinery is shared with the baseline run rather than copied:
# two scripts that disagree about which database they measured would be worse
# than no fingerprint at all.
import importlib.util as _importlib_util  # noqa: E402

_spec = _importlib_util.spec_from_file_location(
    "reference_run", ROOT / "scripts" / "reference_run.py"
)
_reference_run = _importlib_util.module_from_spec(_spec)
_spec.loader.exec_module(_reference_run)

FINGERPRINT_KEYS = _reference_run.FINGERPRINT_KEYS
compare_fingerprints = _reference_run.compare_fingerprints
fingerprint_database = _reference_run.fingerprint_database
baseline_conflicts = _reference_run.baseline_conflicts
RUNS_DIR = _reference_run.RUNS_DIR

DEFAULT_BRIDGE = ROOT / "scripts/bridge_stdio.py"
DEFAULT_GHIDRA = "http://127.0.0.1:8080/"

# Known, hard-wired anchors in ZK-INKJET-NANO-APP.bin.
FN_USBD_INIT_PHY_CEP = "0x002af9c0"
FN_USBD_IRQ_SETUP = "0x002af80c"
FN_UI_MAIN_LOOP = "0x0026a7f8"
FN_BOOT_INIT = "0x0025b0c4"
LITERAL_POOL = "0x002afb34"
USBD_BA_SLOT = "0x002afb4c"

#: The limits that were the defaults before Stage 3.  Passed explicitly so the
#: requested amount is the same in a before-run and an after-run.
OLD_SEARCH_LIMIT = 100
OLD_RANGE_LIMIT = 200
OLD_FIND_LIMIT = 50
OLD_COMPACT_LIMIT = 50

#: analyze_function_complete's per-section bounds, at their documented defaults.
#: Named so a later change to any of them cannot masquerade as efficiency here.
ANALYZE_OPTIONS = {
    "disasm": {"before": 8, "after": 8, "max_instructions": 48},
    "xrefs": {"inbound_limit": 40, "outbound_limit": 40},
    "callgraph": {"limit": 24},
    "strings": {"limit": 6, "max_cstring_len": 256},
    "decompile": {"enabled": True, "max_lines": 120},
}

#: analyze_function_complete returned every field before Stage 3.
ALL_FIELDS = [
    "function",
    "disasm",
    "decompile",
    "xrefs",
    "callgraph",
    "strings",
    "features",
]

#: Fixed-parameter session.  Same shape as the baseline run, but **no quantity
#: parameter is left implicit** -- not one.  Every count, limit, page, offset,
#: context_lines, fields, options and include_literals is named, at the value
#: that was the default before Stage 3.
#:
#: This is completeness, not judgement.  A parameter left to its default turns
#: any later change of that default into an apparent structural saving, in the
#: one script whose entire job is to hold the requested amount constant.  It
#: already happened once: analyze_function_complete was called without `fields`,
#: and Stage 3's narrower default showed up here as efficiency it had not
#: earned.
CALLS: Tuple[Tuple[str, Dict[str, Any]], ...] = (
    ("project_info", {}),
    ("project_overview", {}),
    ("get_current_program", {}),
    ("search_functions", {"query": "usb", "limit": OLD_SEARCH_LIMIT, "page": 1, "context_lines": 0}),
    ("search_functions", {"query": "init", "limit": OLD_SEARCH_LIMIT, "page": 1, "context_lines": 0}),
    ("search_functions", {"query": "boot", "limit": OLD_SEARCH_LIMIT, "page": 1, "context_lines": 0}),
    ("search_functions", {"query": "dma", "limit": OLD_SEARCH_LIMIT, "page": 1, "context_lines": 0}),
    ("search_functions", {"query": "print", "limit": OLD_SEARCH_LIMIT, "page": 1, "context_lines": 0}),
    (
        "search_strings",
        {"query": "USB", "limit": OLD_SEARCH_LIMIT, "page": 1, "include_literals": False},
    ),
    (
        "search_strings",
        {"query": "error", "limit": OLD_SEARCH_LIMIT, "page": 1, "include_literals": False},
    ),
    (
        "search_strings",
        {"query": "init", "limit": OLD_SEARCH_LIMIT, "page": 1, "include_literals": False},
    ),
    (
        "strings_compact",
        {"limit": OLD_COMPACT_LIMIT, "offset": 0, "include_literals": False},
    ),
    ("string_xrefs_compact", {"string_addr": "0x00400000", "limit": OLD_COMPACT_LIMIT}),
    ("search_imports", {"query": "e", "limit": OLD_SEARCH_LIMIT, "page": 1}),
    ("search_exports", {"query": "e", "limit": OLD_SEARCH_LIMIT, "page": 1}),
    ("search_scalars", {"value": "0xB1008000", "limit": OLD_SEARCH_LIMIT, "page": 1}),
    ("search_scalars", {"value": "0x40000000", "limit": OLD_SEARCH_LIMIT, "page": 1}),
    ("search_scalars", {"value": "0x1000", "limit": OLD_SEARCH_LIMIT, "page": 1}),
    (
        "search_scalars_with_context",
        {
            "value": "0x1000",
            "context_lines": 4,
            "limit": OLD_SEARCH_LIMIT,
            "page": 1,
            "fmt": "text",
        },
    ),
    (
        "search_scalars_with_context",
        {
            "value": "0x40000000",
            "context_lines": 4,
            "limit": OLD_SEARCH_LIMIT,
            "page": 1,
            "fmt": "text",
        },
    ),
    ("read_words", {"address": LITERAL_POOL, "count": 8, "include_literals": False}),
    ("read_words", {"address": USBD_BA_SLOT, "count": 4, "include_literals": False}),
    ("read_bytes", {"address": LITERAL_POOL, "length": 64, "include_literals": False}),
    ("disassemble_at", {"address": FN_USBD_INIT_PHY_CEP, "count": 16, "fmt": "text"}),
    ("disassemble_at", {"address": FN_USBD_IRQ_SETUP, "count": 16, "fmt": "text"}),
    ("disassemble_at", {"address": FN_UI_MAIN_LOOP, "count": 16, "fmt": "text"}),
    ("disassemble_at", {"address": FN_BOOT_INIT, "count": 16, "fmt": "text"}),
    (
        "disassemble_batch",
        {
            "addresses": [
                FN_USBD_INIT_PHY_CEP,
                FN_USBD_IRQ_SETUP,
                FN_UI_MAIN_LOOP,
                FN_BOOT_INIT,
            ],
            "count": 16,
            "fmt": "text",
            # No filter: this call measures the unfiltered listing, which is
            # what it measured before Stage 4.  Stated rather than defaulted.
            "query": "",
            "regex": False,
            "case_sensitive": False,
            "context_lines": 0,
        },
    ),
    (
        "find_in_function",
        {
            "address": FN_USBD_INIT_PHY_CEP,
            "query": "ldr",
            "mode": "both",
            "regex": False,
            "case_sensitive": False,
            "context_lines": 3,
            "limit": OLD_FIND_LIMIT,
            # The JSON form the baseline measured; text became the default later.
            "fmt": "json",
        },
    ),
    (
        "find_in_function",
        {
            "address": FN_USBD_IRQ_SETUP,
            "query": "str",
            "mode": "both",
            "regex": False,
            "case_sensitive": False,
            "context_lines": 3,
            "limit": OLD_FIND_LIMIT,
            # The JSON form the baseline measured; text became the default later.
            "fmt": "json",
        },
    ),
    (
        "search_xrefs_to",
        {
            "address": FN_USBD_INIT_PHY_CEP,
            "query": "",
            "limit": OLD_SEARCH_LIMIT,
            "page": 1,
        },
    ),
    (
        "search_xrefs_to",
        {"address": FN_USBD_IRQ_SETUP, "query": "", "limit": OLD_SEARCH_LIMIT, "page": 1},
    ),
    (
        "list_functions_in_range",
        {
            "address_min": "0x002af000",
            "address_max": "0x002b0000",
            "limit": OLD_RANGE_LIMIT,
            "page": 1,
        },
    ),
    (
        "list_functions_in_range",
        {
            "address_min": "0x0025b000",
            "address_max": "0x0025c000",
            "limit": OLD_RANGE_LIMIT,
            "page": 1,
        },
    ),
    (
        "mmio_annotate_compact",
        {"function_addr": FN_USBD_INIT_PHY_CEP, "dry_run": True, "max_samples": 8},
    ),
    (
        "analyze_function_complete",
        {
            "address": FN_USBD_INIT_PHY_CEP,
            "fields": ALL_FIELDS,
            "fmt": "json",
            "max_result_tokens": None,
            "options": ANALYZE_OPTIONS,
        },
    ),
    (
        "analyze_function_complete",
        {
            "address": FN_USBD_IRQ_SETUP,
            "fields": ALL_FIELDS,
            "fmt": "json",
            "max_result_tokens": None,
            "options": ANALYZE_OPTIONS,
        },
    ),
    (
        "collect",
        {
            "queries": [
                {
                    "id": "fns",
                    "op": "search_functions",
                    "params": {
                        "query": "usbd",
                        "limit": OLD_SEARCH_LIMIT,
                        "page": 1,
                        "context_lines": 0,
                    },
                },
                {
                    "id": "strs",
                    "op": "search_strings",
                    "params": {
                        "query": "USB",
                        "limit": OLD_SEARCH_LIMIT,
                        "page": 1,
                        "include_literals": False,
                    },
                },
            ]
        },
    ),
    (
        "collect",
        {
            "queries": [
                {
                    "id": "disasm",
                    "op": "disassemble_at",
                    "params": {
                        "address": FN_USBD_INIT_PHY_CEP,
                        "count": 16,
                        "fmt": "text",
                    },
                },
                {
                    "id": "words",
                    "op": "read_words",
                    "params": {
                        "address": LITERAL_POOL,
                        "count": 8,
                        "include_literals": False,
                    },
                },
            ]
        },
    ),
    ("check_dirty_state", {}),
)


def _first_json(result: types.CallToolResult) -> Any:
    for content in result.content:
        if isinstance(content, types.TextContent):
            try:
                return json.loads(content.text)
            except json.JSONDecodeError:
                return content.text
    return None


async def _run(args: argparse.Namespace, fingerprint: Mapping[str, Any]) -> int:
    env = dict(os.environ)
    env["GHIDRA_SERVER_URL"] = args.ghidra_server_url
    env["GHIDRA_MCP_USAGE_LOG"] = str(args.usage_log)
    # The reference session is read-only; keep writes off regardless of .env.
    env["GHIDRA_MCP_ENABLE_WRITES"] = "false"

    server = StdioServerParameters(
        command=args.python_command,
        args=[str(args.bridge_script), "--transport", "stdio"],
        env=env,
        cwd=str(ROOT),
    )

    failures: List[str] = []
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=args.timeout),
        ) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(
                f"tools advertised: {len(tools.tools)}   "
                f"program: {fingerprint.get('program_name')}   "
                f"functions: {fingerprint.get('function_count')} "
                f"({fingerprint.get('user_named_functions')} user-named)"
            )

            for index, (name, arguments) in enumerate(CALLS, start=1):
                try:
                    result = await session.call_tool(name, arguments or None)
                except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                    failures.append(f"{index:02d} {name}: {type(exc).__name__}: {exc}")
                    print(f"{index:02d}/{len(CALLS)} {name:<30} EXCEPTION")
                    continue

                payload = _first_json(result)
                ok = isinstance(payload, dict) and payload.get("ok") is True
                if not ok:
                    failures.append(f"{index:02d} {name}: {json.dumps(payload)[:200]}")
                print(f"{index:02d}/{len(CALLS)} {name:<30} {'ok' if ok else 'ERROR'}")

    print(f"\ncalls: {len(CALLS)}, errors: {len(failures)}")
    for line in failures:
        print(f"  ! {line}")
    print(f"usage log: {args.usage_log}")
    # Errors are reported but do not fail the run: the point is to measure the
    # cost of a fixed call list, and a legitimate empty result is not a failure.
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-server-url", default=os.getenv("GHIDRA_SERVER_URL", DEFAULT_GHIDRA))
    parser.add_argument("--bridge-script", type=Path, default=DEFAULT_BRIDGE)
    parser.add_argument("--python-command", default=sys.executable)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--usage-log",
        type=Path,
        default=RUNS_DIR / "reference_run_structural.jsonl",
        help="JSONL usage log written by this run (truncated first)",
    )
    parser.add_argument(
        "--overwrite-baseline",
        action="store_true",
        help="allow replacing an existing file under baseline/",
    )
    parser.add_argument(
        "--expect-fingerprint",
        type=Path,
        help="abort unless the database fingerprint matches this JSON file",
    )
    parser.add_argument(
        "--write-fingerprint",
        type=Path,
        help="store this run's database fingerprint at this path",
    )
    args = parser.parse_args(argv)

    args.usage_log = args.usage_log.expanduser().resolve()
    conflicts = baseline_conflicts(
        [args.usage_log, args.write_fingerprint], overwrite_baseline=args.overwrite_baseline
    )
    if conflicts:
        for path in conflicts:
            print(f"refusing to overwrite checked-in baseline file: {path}")
        print("pass --overwrite-baseline to replace it, or write somewhere else")
        return 2
    args.usage_log.parent.mkdir(parents=True, exist_ok=True)

    fingerprint = fingerprint_database(args.ghidra_server_url)
    print("database fingerprint:")
    for key in FINGERPRINT_KEYS:
        print(f"  {key:<24} {fingerprint.get(key)}")

    if args.expect_fingerprint:
        expected = json.loads(args.expect_fingerprint.read_text(encoding="utf-8"))
        drift = compare_fingerprints(fingerprint, expected)
        if drift:
            print("\nFINGERPRINT MISMATCH -- this run is not comparable:")
            for line in drift:
                print(f"  ! {line}")
            print(
                "\nRefusing to run.  Restore the frozen project copy, or accept that\n"
                "the numbers measure a different database and re-baseline."
            )
            return 2
        print("  -> matches the expected fingerprint")

    if args.write_fingerprint:
        args.write_fingerprint.parent.mkdir(parents=True, exist_ok=True)
        args.write_fingerprint.write_text(
            json.dumps(fingerprint, indent=2, sort_keys=True), encoding="utf-8"
        )
        print(f"  -> wrote {args.write_fingerprint}")

    # The fingerprint is the first line of the log, so a log always carries the
    # identity of what it measured.
    args.usage_log.write_text(json.dumps(fingerprint, sort_keys=True) + "\n", encoding="utf-8")

    return asyncio.run(_run(args, fingerprint))


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
