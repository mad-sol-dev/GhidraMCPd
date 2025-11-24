#!/usr/bin/env python3
"""Run a deterministic MCP smoke test against the reference fixture."""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

import mcp.types as types
from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SERVER = ROOT / "scripts/reference_mcp_server.py"
DEFAULT_FIRMWARE = ROOT / "bridge/tests/fixtures/reference.bin"

EXPECTED = {
    "image_base": "0x00400000",
    "strings": {"Boot complete": "0x00400040"},
    "functions": ["main", "init_peripherals", "reset_handler"],
    "scalar_value": "0x40000000",
    "mmio_function": "0x00400100",
    "read_bytes": {
        "address": "0x00400020",
        "length": 8,
        "literal_prefix": base64.b64encode(bytes.fromhex("00000040efbeadde")).decode("ascii"),
    },
    "read_words": {
        "address": "0x00400020",
        "count": 2,
        "words": [0x40000000, 0xDEADBEEF],
    },
}


@dataclass
class ToolExpectation:
    name: str
    args: dict[str, Any] | None
    validator: Callable[[types.CallToolResult], None]


@dataclass
class ToolOutcome:
    expectation: ToolExpectation
    success: bool
    error: str | None = None


def _first_json(result: types.CallToolResult) -> Any:
    for content in result.content:
        if isinstance(content, types.TextContent):
            try:
                return json.loads(content.text)
            except json.JSONDecodeError:
                continue
    raise AssertionError(f"{result.name} returned no JSON text content")


def _assert_project_info(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"], "project_info returned error"
    data = payload["data"]
    assert data["image_base"] == EXPECTED["image_base"]
    assert data["program_name"] == DEFAULT_FIRMWARE.name


def _assert_project_overview(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"], "project_overview returned error"
    paths = [entry["path"] for entry in payload["data"]["files"]]
    assert f"/{DEFAULT_FIRMWARE.name}" in paths


def _assert_strings(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"]
    items = payload["data"]["items"]
    seen = {
        entry.get("literal") or entry.get("s"): entry.get("address") or entry.get("addr")
        for entry in items
    }
    for literal, addr in EXPECTED["strings"].items():
        assert literal in seen, f"missing string {literal}"
        assert seen[literal] == addr, f"string address mismatch for {literal}"


def _assert_functions(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"]
    items: Iterable[dict[str, object]] = payload["data"].get("items", [])
    names = {str(entry.get("name", "")) for entry in items}
    for name in EXPECTED["functions"]:
        assert name in names


def _assert_scalars(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"]
    matches = payload["data"]["matches"]
    assert matches, "expected scalar matches"
    for entry in matches:
        assert entry["value"].lower() == EXPECTED["scalar_value"].lower()
        assert entry["disassembly"], "disassembly context missing"


def _assert_mmio(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"]
    data = payload["data"]
    assert data["function"] == EXPECTED["mmio_function"]
    assert data["reads"] >= 1
    assert data["samples"], "expected mmio samples"


def _assert_read_bytes(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"]
    data = payload["data"]
    assert data["address"] == EXPECTED["read_bytes"]["address"]
    assert data["length"] == EXPECTED["read_bytes"]["length"]
    assert data["data"].startswith(EXPECTED["read_bytes"]["literal_prefix"])


def _assert_read_words(result: types.CallToolResult) -> None:
    payload = _first_json(result)
    assert payload["ok"]
    data = payload["data"]
    assert data["address"] == EXPECTED["read_words"]["address"]
    assert data["count"] == EXPECTED["read_words"]["count"]
    assert data["words"] == EXPECTED["read_words"]["words"]


TOOLS: list[ToolExpectation] = [
    ToolExpectation("project_info", None, _assert_project_info),
    ToolExpectation("project_overview", None, _assert_project_overview),
    ToolExpectation("search_strings", {"query": "boot", "limit": 10, "page": 1}, _assert_strings),
    ToolExpectation(
        "search_functions",
        {"query": "", "limit": 10, "page": 1, "context_lines": 0},
        _assert_functions,
    ),
    ToolExpectation(
        "search_scalars_with_context",
        {"value": EXPECTED["scalar_value"], "limit": 4, "context_lines": 2},
        _assert_scalars,
    ),
    ToolExpectation(
        "mmio_annotate_compact",
        {"function_addr": EXPECTED["mmio_function"], "max_samples": 4, "dry_run": True},
        _assert_mmio,
    ),
    ToolExpectation(
        "read_bytes",
        {
            "address": EXPECTED["read_bytes"]["address"],
            "length": EXPECTED["read_bytes"]["length"],
            "include_literals": False,
        },
        _assert_read_bytes,
    ),
    ToolExpectation(
        "read_words",
        {
            "address": EXPECTED["read_words"]["address"],
            "count": EXPECTED["read_words"]["count"],
            "include_literals": False,
        },
        _assert_read_words,
    ),
]


def _build_server(args: argparse.Namespace) -> StdioServerParameters:
    env = dict()
    return StdioServerParameters(
        command=args.python_command,
        args=[str(args.server_script), "--firmware", str(args.firmware)],
        env=env,
        cwd=args.cwd,
    )


def _render_status(name: str, success: bool) -> str:
    return f"[{'PASS' if success else 'FAIL'}] {name}"


async def _run(args: argparse.Namespace) -> int:
    server_params = _build_server(args)
    outcomes: list[ToolOutcome] = []
    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            server_info = init_result.serverInfo
            print(f"Connected to {server_info.name} {server_info.version}")
            for expectation in TOOLS:
                try:
                    result = await session.call_tool(expectation.name, expectation.args)
                    expectation.validator(result)
                    outcomes.append(ToolOutcome(expectation, True))
                except Exception as exc:  # pragma: no cover - smoke test path
                    outcomes.append(ToolOutcome(expectation, False, str(exc)))
                    print(_render_status(expectation.name, False))
                    print(f"  {exc}")
                else:
                    print(_render_status(expectation.name, True))

    failures = [outcome for outcome in outcomes if not outcome.success]
    if failures:
        print(f"Completed with {len(failures)} failing tool(s).")
        return 1

    print("All smoke tests passed.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--server-script",
        type=Path,
        default=DEFAULT_SERVER,
        help="Path to reference_mcp_server.py",
    )
    parser.add_argument(
        "--firmware",
        type=Path,
        default=DEFAULT_FIRMWARE,
        help="Path to reference firmware fixture",
    )
    parser.add_argument(
        "--python-command",
        default=sys.executable,
        help="Python interpreter used for the MCP server",
    )
    parser.add_argument(
        "--cwd",
        default=ROOT,
        help="Working directory for the MCP server",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
