#!/usr/bin/env python3
"""Stdio MCP server using the reference fixture stub."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.api.tools import register_tools
from bridge.tests.fixtures.reference_ghidra import ReferenceGhidraClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start MCP server with reference stub data.")
    parser.add_argument(
        "--firmware",
        type=Path,
        default=ROOT / "bridge/tests/fixtures/reference.bin",
        help="Path to the reference firmware fixture",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client_factory = lambda: ReferenceGhidraClient(args.firmware)
    server = FastMCP("ghidra-bridge-reference")
    register_tools(server, client_factory=client_factory, enable_writes=False)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
