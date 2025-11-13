#!/usr/bin/env python3
"""Legacy helper to run the bridge over stdio or SSE transports."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Sequence

from starlette.routing import Route

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.app import MCP_SERVER, build_api_app, set_ghidra_base_url
from bridge.cli import build_parser, run as run_cli
from bridge.shim import build_openwebui_shim

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
LOGGER = logging.getLogger("bridge.legacy")


def _shim_factory(upstream_base: str, extra_routes: Sequence[Route]):
    """Return an OpenWebUI shim decorated with API routes."""

    return build_openwebui_shim(upstream_base, extra_routes=extra_routes)


def _start_sse(host: str, port: int) -> None:
    """Launch the MCP SSE server with explicit host/port bindings."""

    MCP_SERVER.settings.host = host
    MCP_SERVER.settings.port = int(port)
    MCP_SERVER.run(transport="sse")


def main(argv: Sequence[str] | None = None) -> None:
    """Entry-point used for ad-hoc stdio/SSE workflows."""

    parser = build_parser(DEFAULT_GHIDRA_SERVER)
    args = parser.parse_args(argv)

    routes = build_api_app().routes

    def shim_factory(upstream_base: str):
        return _shim_factory(upstream_base, routes)

    run_cli(
        args,
        logger=LOGGER,
        default_ghidra_server=DEFAULT_GHIDRA_SERVER,
        set_ghidra_url=set_ghidra_base_url,
        start_sse=_start_sse,
        run_stdio=MCP_SERVER.run,
        shim_factory=shim_factory,
    )


if __name__ == "__main__":  # pragma: no cover - script entry point
    main()
