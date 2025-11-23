#!/usr/bin/env python3
"""Sanity-check MCP tools against a running Ghidra session.

This script launches ``uvicorn bridge.app:create_app --factory`` via the MCP
Python client (stdio transport) and exercises a handful of tools in order:
``project_info``, ``search_strings``, ``search_functions``, and ``read_bytes``.
It exits non-zero on any failure, MCP error envelope, or empty result.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import timedelta
from typing import Any

import mcp.types as types
from mcp import StdioServerParameters, stdio_client
from mcp.client.session import ClientSession
from mcp.shared.exceptions import McpError

DEFAULT_STRING_QUERY = "boot"
DEFAULT_FUNCTION_QUERY = "main"
DEFAULT_READ_ADDRESS = "0x401000"
DEFAULT_READ_LENGTH = 32


def _first_text_content(result: types.CallToolResult) -> str | None:
    """Return the first text payload from a tool result, if present."""

    for content in result.content:
        if isinstance(content, types.TextContent):
            return content.text
    return None


async def _call_tool(
    session: ClientSession, name: str, arguments: dict[str, Any] | None = None
) -> types.CallToolResult:
    """Invoke an MCP tool and raise if it reports an error."""

    result = await session.call_tool(name, arguments)
    if result.isError:
        raise RuntimeError(f"{name} returned an error payload")
    if not result.content:
        raise RuntimeError(f"{name} returned an empty content array")
    return result


async def _run_sequence(args: argparse.Namespace) -> int:
    """Run the required MCP tools sequentially."""

    env = dict(os.environ)
    if args.ghidra_server_url:
        env["GHIDRA_SERVER_URL"] = args.ghidra_server_url

    server = StdioServerParameters(
        command=args.uvicorn_command,
        args=["bridge.app:create_app", "--factory"],
        env=env,
        cwd=args.cwd,
    )

    try:
        async with stdio_client(server) as (read_stream, write_stream):
            session = ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=args.timeout),
            )

            await session.initialize()

            project_info = await _call_tool(session, "project_info")
            print(_first_text_content(project_info) or "project_info returned data")

            strings = await _call_tool(
                session,
                "search_strings",
                {"query": args.string_query, "limit": args.limit},
            )
            print(_first_text_content(strings) or "search_strings returned data")

            functions = await _call_tool(
                session,
                "search_functions",
                {"query": args.function_query, "limit": args.limit},
            )
            print(_first_text_content(functions) or "search_functions returned data")

            bytes_result = await _call_tool(
                session,
                "read_bytes",
                {"address": args.read_address, "length": args.read_length},
            )
            print(
                _first_text_content(bytes_result)
                or f"read_bytes returned {len(bytes_result.content)} items"
            )
    except (McpError, Exception) as exc:
        print(f"[verify] failure: {exc}", file=sys.stderr)
        return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Configure CLI parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Launch uvicorn bridge.app:create_app --factory via the MCP stdio client "
            "and verify common tools succeed."
        )
    )
    parser.add_argument(
        "--uvicorn-command",
        default="uvicorn",
        help="Command used to launch the bridge (default: uvicorn)",
    )
    parser.add_argument(
        "--ghidra-server-url",
        help="Override GHIDRA_SERVER_URL for the subprocess.",
    )
    parser.add_argument(
        "--cwd",
        default=os.getcwd(),
        help="Working directory for the uvicorn subprocess (default: repo root)",
    )
    parser.add_argument(
        "--string-query",
        default=DEFAULT_STRING_QUERY,
        help="Query for search_strings (default: %(default)s)",
    )
    parser.add_argument(
        "--function-query",
        default=DEFAULT_FUNCTION_QUERY,
        help="Query for search_functions (default: %(default)s)",
    )
    parser.add_argument(
        "--read-address",
        default=DEFAULT_READ_ADDRESS,
        help="Address passed to read_bytes (default: %(default)s)",
    )
    parser.add_argument(
        "--read-length",
        type=int,
        default=DEFAULT_READ_LENGTH,
        help="Length (bytes) passed to read_bytes (default: %(default)s)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Result limit for search tools (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Read timeout (seconds) for MCP responses (default: %(default)s)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point."""

    args = build_parser().parse_args(argv)
    return asyncio.run(_run_sequence(args))


if __name__ == "__main__":  # pragma: no cover - script entry point
    raise SystemExit(main())
