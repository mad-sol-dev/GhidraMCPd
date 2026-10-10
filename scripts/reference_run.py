#!/usr/bin/env python3
"""Replay a fixed reference session against a running Ghidra instance.

The rework baseline must be reproducible, so it does not come from an
interactive analysis session but from this hard-wired call list: 40 read-only
MCP calls that mirror a typical analysis session (function search, string
search with xrefs, scalar search, disassembly of several addresses, two
``analyze_function_complete`` dossiers, literal-pool reads around
``0x002AFB34``).  Addresses are fixed on purpose -- no sampling, no randomness.

Target program: ``ZK-INKJET-NANO-APP.bin`` (a frozen copy of the ZK-Inkjet
project, opened in a dedicated Ghidra instance).  The run performs reads only.

Before the first call the script records a **fingerprint of the database** it is
talking to -- program name, binary checksum, function count and the number of
non-default (user-named) functions.  The binary never changes; the ``.rep``
does: renames, comments and applied data types move response sizes around with
no relation to the rework.  If the fingerprint differs between the Stage 0 and
Stage 7 runs, the comparison is void.  ``--expect-fingerprint`` turns that from
an assumption into a check.

Logs go to ``runs/`` (ignored by git) unless told otherwise.  ``baseline/``
holds the checked-in comparison points; a run replaces a file there only with
``--overwrite-baseline``, so a routine run cannot overwrite one by accident.

Usage::

    python scripts/reference_run.py --expect-fingerprint baseline/fingerprint.json
    python scripts/reference_run.py --usage-log baseline/reference_run_new.jsonl \
        --expect-fingerprint baseline/fingerprint.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

import httpx
import mcp.types as types
from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_BRIDGE = ROOT / "scripts/bridge_stdio.py"
DEFAULT_GHIDRA = "http://127.0.0.1:8080/"
BASELINE_DIR = ROOT / "baseline"
RUNS_DIR = ROOT / "runs"

# Known, hard-wired anchors in ZK-INKJET-NANO-APP.bin.
FN_USBD_INIT_PHY_CEP = "0x002af9c0"
FN_USBD_IRQ_SETUP = "0x002af80c"
FN_UI_MAIN_LOOP = "0x0026a7f8"
FN_BOOT_INIT = "0x0025b0c4"
LITERAL_POOL = "0x002afb34"
USBD_BA_SLOT = "0x002afb4c"

#: The reference session.  Order matters; it is part of the measurement.
CALLS: Tuple[Tuple[str, Dict[str, Any]], ...] = (
    # -- orientation -------------------------------------------------------
    ("project_info", {}),
    ("project_overview", {}),
    ("get_current_program", {}),
    # -- locating candidates by name --------------------------------------
    ("search_functions", {"query": "usb"}),
    ("search_functions", {"query": "init"}),
    ("search_functions", {"query": "boot"}),
    ("search_functions", {"query": "dma"}),
    ("search_functions", {"query": "print"}),
    # -- locating candidates by string ------------------------------------
    ("search_strings", {"query": "USB"}),
    ("search_strings", {"query": "error"}),
    ("search_strings", {"query": "init"}),
    ("strings_compact", {"limit": 50}),
    ("string_xrefs_compact", {"string_addr": "0x00400000"}),
    # -- imports / exports -------------------------------------------------
    # NOTE: search_imports currently fails schema validation on this program
    # (Ghidra reports "0xEXTERNAL:00000001" as an address).  The failure is
    # deterministic and is kept in the baseline on purpose: an error response
    # costs context too, and hiding it would flatter the numbers.
    ("search_imports", {"query": "e"}),
    ("search_exports", {"query": "e"}),
    # -- scalar hunting ----------------------------------------------------
    ("search_scalars", {"value": "0xB1008000"}),
    ("search_scalars", {"value": "0x40000000"}),
    ("search_scalars", {"value": "0x1000"}),
    ("search_scalars_with_context", {"value": "0x1000"}),
    ("search_scalars_with_context", {"value": "0x40000000"}),
    # -- literal pool around 0x002AFB34 ------------------------------------
    ("read_words", {"address": LITERAL_POOL, "count": 8}),
    ("read_words", {"address": USBD_BA_SLOT, "count": 4}),
    ("read_bytes", {"address": LITERAL_POOL, "length": 64}),
    # -- disassembly of several addresses ----------------------------------
    ("disassemble_at", {"address": FN_USBD_INIT_PHY_CEP, "count": 16}),
    ("disassemble_at", {"address": FN_USBD_IRQ_SETUP, "count": 16}),
    ("disassemble_at", {"address": FN_UI_MAIN_LOOP, "count": 16}),
    ("disassemble_at", {"address": FN_BOOT_INIT, "count": 16}),
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
        },
    ),
    # -- narrowing inside a function ---------------------------------------
    ("find_in_function", {"address": FN_USBD_INIT_PHY_CEP, "query": "ldr"}),
    ("find_in_function", {"address": FN_USBD_IRQ_SETUP, "query": "str"}),
    # -- cross references ---------------------------------------------------
    ("search_xrefs_to", {"address": FN_USBD_INIT_PHY_CEP, "query": ""}),
    ("search_xrefs_to", {"address": FN_USBD_IRQ_SETUP, "query": ""}),
    # -- neighbourhood ------------------------------------------------------
    ("list_functions_in_range", {"address_min": "0x002af000", "address_max": "0x002b0000"}),
    ("list_functions_in_range", {"address_min": "0x0025b000", "address_max": "0x0025c000"}),
    # -- MMIO ---------------------------------------------------------------
    ("mmio_annotate_compact", {"function_addr": FN_USBD_INIT_PHY_CEP, "dry_run": True}),
    # -- full dossiers on two known functions -------------------------------
    ("analyze_function_complete", {"address": FN_USBD_INIT_PHY_CEP}),
    ("analyze_function_complete", {"address": FN_USBD_IRQ_SETUP}),
    # -- batched reads -------------------------------------------------------
    (
        "collect",
        {
            "queries": [
                {"id": "fns", "op": "search_functions", "params": {"query": "usbd"}},
                {"id": "strs", "op": "search_strings", "params": {"query": "USB"}},
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
                    "params": {"address": FN_USBD_INIT_PHY_CEP, "count": 16},
                },
                {
                    "id": "words",
                    "op": "read_words",
                    "params": {"address": LITERAL_POOL, "count": 8},
                },
            ]
        },
    ),
    ("check_dirty_state", {}),
)


#: Ghidra's auto-generated symbol names.  Everything else counts as user work.
_DEFAULT_SYMBOL = re.compile(
    r"^(?:thunk_)?(?:FUN|SUB|LAB|DAT|UNK|EXT_FUN|SWITCH|caseD)_[0-9A-Fa-f]+$"
)

#: Fields that must match between two runs for their numbers to be comparable.
FINGERPRINT_KEYS = (
    "program_name",
    "executable_sha256",
    "function_count",
    "user_named_functions",
)


def fingerprint_database(ghidra_url: str, *, timeout: float = 60.0) -> Dict[str, Any]:
    """Identify the database this run is measuring.

    Talks to the Ghidra plugin directly rather than through the bridge, so the
    fingerprint costs nothing in the usage log it is about to annotate.
    """

    base = ghidra_url.rstrip("/") + "/"
    with httpx.Client(base_url=base, timeout=timeout) as http:
        info = http.get("project_info").json()
        methods = http.get("methods", params={"offset": 0, "limit": 1_000_000}).text

    names = [line.strip() for line in methods.splitlines() if line.strip()]
    user_named = [name for name in names if not _DEFAULT_SYMBOL.match(name)]

    return {
        "kind": "fingerprint",
        "program_name": info.get("program_name"),
        "executable_sha256": info.get("executable_sha256"),
        "executable_md5": info.get("executable_md5"),
        "image_base": info.get("image_base"),
        "language_id": info.get("language_id"),
        "function_count": len(names),
        "user_named_functions": len(user_named),
    }


def compare_fingerprints(
    current: Mapping[str, Any], expected: Mapping[str, Any]
) -> List[str]:
    """Return one line per field that drifted, empty when the runs match."""

    drift: List[str] = []
    for key in FINGERPRINT_KEYS:
        have, want = current.get(key), expected.get(key)
        if have != want:
            drift.append(f"{key}: expected {want!r}, got {have!r}")
    return drift


def baseline_conflicts(paths: Sequence[Path | None], *, overwrite_baseline: bool) -> List[Path]:
    """Return the output paths that would replace a checked-in baseline file.

    A new file in ``baseline/`` is fine; replacing an existing one needs
    ``--overwrite-baseline``.  Empty when the run may go ahead.
    """

    if overwrite_baseline:
        return []
    base = BASELINE_DIR.resolve()
    return [
        path
        for path in paths
        if path is not None and path.exists() and path.resolve().is_relative_to(base)
    ]


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
        default=RUNS_DIR / "reference_run.jsonl",
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
