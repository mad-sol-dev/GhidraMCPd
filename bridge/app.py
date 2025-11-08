"""Application wiring for the modular bridge server."""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MethodType
from importlib import resources
from functools import lru_cache

from mcp import types
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import SseServerTransport
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from .api.routes import make_routes
from .api.tools import register_tools
from .ghidra.client import GhidraClient
from .utils.logging import configure_root

MCP_SERVER = FastMCP("ghidra-bridge")
_ghidra_server_url = os.getenv("GHIDRA_SERVER_URL", "http://127.0.0.1:8080/")
_CONFIGURED = False


@dataclass(slots=True)
class BridgeState:
    """Mutable diagnostics for guarding the SSE endpoint."""

    active_sse_id: str | None = None
    connects: int = 0
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    initialization_logged: bool = False
    last_init_ts: str | None = None
    ghidra_sema: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(1)
    )


_BRIDGE_STATE = BridgeState()
_STATE_LOCK = asyncio.Lock()
_SSE_LOGGER = logging.getLogger("bridge.sse")


_REQUEST_SCHEMA_MAP = {
    "/api/search_strings.json": "search_strings.request.v1.json",
    "/api/search_functions.json": "search_functions.request.v1.json",
    "/api/search_imports.json": "search_imports.request.v1.json",
    "/api/search_exports.json": "search_exports.request.v1.json",
}

_RESPONSE_SCHEMA_MAP = {
    "/api/search_strings.json": "search_strings.v1.json",
    "/api/search_functions.json": "search_functions.v1.json",
    "/api/search_imports.json": "search_imports.v1.json",
    "/api/search_exports.json": "search_exports.v1.json",
    "/api/project_info.json": "project_info.v1.json",
}


@lru_cache(maxsize=None)
def _load_schema(name: str) -> dict[str, object]:
    with resources.files("bridge.api.schemas").joinpath(name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _build_openapi_schema(routes: list[Route]) -> dict[str, object]:
    paths: dict[str, dict[str, object]] = {}
    for route in routes:
        # Only document standard HTTP routes.
        if not isinstance(route, Route):  # pragma: no cover - defensive
            continue
        if route.path == "/openapi.json":
            continue
        methods = sorted(route.methods or set())
        if not methods:
            continue
        operations = paths.setdefault(route.path, {})
        for method in methods:
            operation: dict[str, object] = {
                "summary": route.name or getattr(route.endpoint, "__name__", "handler"),
            }
            if method == "POST":
                request_schema_name = _REQUEST_SCHEMA_MAP.get(route.path)
                if request_schema_name is not None:
                    operation["requestBody"] = {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": _load_schema(request_schema_name)
                            }
                        },
                    }
            response_schema_name = _RESPONSE_SCHEMA_MAP.get(route.path)
            if response_schema_name is not None:
                operation["x-response-model"] = response_schema_name
                operation.setdefault("responses", {})["200"] = {
                    "description": "Successful Response",
                    "content": {
                        "application/json": {
                            "schema": _load_schema(response_schema_name)
                        }
                    },
                }
            operations[method.lower()] = operation
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Ghidra MCP Bridge API",
            "version": "1.0.0",
        },
        "paths": paths,
    }


def set_ghidra_base_url(url: str) -> None:
    """Override the default Ghidra server used by API client factories."""

    global _ghidra_server_url
    _ghidra_server_url = url


def _client_factory() -> GhidraClient:
    return GhidraClient(_ghidra_server_url)


def configure() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    configure_root()
    register_tools(MCP_SERVER, client_factory=_client_factory)
    if types.InitializedNotification not in MCP_SERVER._mcp_server.notification_handlers:
        async def _mark_ready(_: types.InitializedNotification) -> None:
            async with _STATE_LOCK:
                if not _BRIDGE_STATE.ready.is_set():
                    _BRIDGE_STATE.ready.set()
                    _BRIDGE_STATE.last_init_ts = datetime.now(timezone.utc).isoformat()
                    if not _BRIDGE_STATE.initialization_logged:
                        _SSE_LOGGER.info("MCP INITIALIZED")
                        _BRIDGE_STATE.initialization_logged = True

        MCP_SERVER._mcp_server.notification_handlers[
            types.InitializedNotification
        ] = _mark_ready
    _CONFIGURED = True


def _guarded_sse_app(self: FastMCP) -> Starlette:
    """Return an SSE app that enforces a single active connection."""

    configure()
    transport = SseServerTransport(self.settings.message_path)

    def _replay_receive(body: bytes):
        sent = False

        async def _inner() -> dict[str, object]:
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        return _inner

    def _is_handshake_message(body: bytes) -> bool:
        if not body:
            return False
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return False
        method = payload.get("method")
        return method in {"initialize", "notifications/initialized"}

    async def handle_get(request: Request) -> None:
        client = request.client or ("unknown", 0)
        user_agent = request.headers.get("user-agent", "")
        async with _STATE_LOCK:
            if _BRIDGE_STATE.active_sse_id is not None:
                _SSE_LOGGER.warning(
                    "sse.reject",
                    extra={
                        "path": request.url.path,
                        "client_host": client[0],
                        "client_port": client[1],
                        "user_agent": user_agent,
                        "active_sse_id": _BRIDGE_STATE.active_sse_id,
                        "status_code": 409,
                        "reason": "sse_already_active",
                    },
                )
                return JSONResponse(
                    {"error": "sse_already_active", "detail": "Another client is connected."},
                    status_code=409,
                )
            connection_id = uuid.uuid4().hex
            _BRIDGE_STATE.active_sse_id = connection_id
            _BRIDGE_STATE.connects += 1
            _BRIDGE_STATE.ready.clear()
            _BRIDGE_STATE.initialization_logged = False
            _BRIDGE_STATE.last_init_ts = None

        _SSE_LOGGER.info(
            "sse.connect",
            extra={
                "client_host": client[0],
                "client_port": client[1],
                "user_agent": user_agent,
                "connection_id": connection_id,
                "connects": _BRIDGE_STATE.connects,
            },
        )

        disconnect_event = asyncio.Event()

        async def receive_with_disconnect() -> dict[str, object]:
            message = await request.receive()
            if message.get("type") == "http.disconnect":
                disconnect_event.set()
            return message

        async def _watch_disconnect() -> None:
            while True:
                if disconnect_event.is_set() or await request.is_disconnected():
                    return
                await asyncio.sleep(0.1)

        cancelled = False
        run_task: asyncio.Task[None] | None = None
        watch_task: asyncio.Task[None] | None = None
        pending: set[asyncio.Task[object]] = set()

        try:
            async with transport.connect_sse(
                request.scope,
                receive_with_disconnect,
                request._send,  # type: ignore[arg-type]
            ) as streams:
                run_task = asyncio.create_task(
                    self._mcp_server.run(
                        streams[0],
                        streams[1],
                        self._mcp_server.create_initialization_options(),
                    )
                )
                watch_task = asyncio.create_task(_watch_disconnect())
                done, pending = await asyncio.wait(
                    {run_task, watch_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if watch_task in done and not run_task.done():
                    run_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await run_task
                else:
                    watch_task.cancel()
                for task in pending:
                    task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.gather(*pending, return_exceptions=False)
        except asyncio.CancelledError:
            cancelled = True
            disconnect_event.set()
            tasks_to_cleanup: list[asyncio.Task[object]] = []
            for task in (run_task, watch_task):
                if task is None:
                    continue
                task.cancel()
                tasks_to_cleanup.append(task)
            for task in pending:
                task.cancel()
                tasks_to_cleanup.append(task)
            if tasks_to_cleanup:
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.gather(*tasks_to_cleanup, return_exceptions=False)
        finally:
            async with _STATE_LOCK:
                if _BRIDGE_STATE.active_sse_id == connection_id:
                    _BRIDGE_STATE.active_sse_id = None
                _BRIDGE_STATE.ready.clear()
                _BRIDGE_STATE.last_init_ts = None
        _SSE_LOGGER.info(
            "sse.disconnect",
            extra={
                "client_host": client[0],
                "client_port": client[1],
                "user_agent": user_agent,
                "connection_id": connection_id,
                "cancelled": cancelled,
            },
        )

        return Response(status_code=204)

    async def handle_post(request: Request) -> JSONResponse:
        client = request.client or ("unknown", 0)
        user_agent = request.headers.get("user-agent", "")
        _SSE_LOGGER.info(
            "sse.method_not_allowed",
            extra={
                "path": request.url.path,
                "client_host": client[0],
                "client_port": client[1],
                "user_agent": user_agent,
                "status_code": 405,
                "reason": "method_not_allowed",
            },
        )
        return JSONResponse(
            {"error": "method_not_allowed", "allow": "GET"},
            status_code=405,
            headers={"Allow": "GET"},
        )

    async def handle_message(scope, receive, send) -> None:  # type: ignore[override]
        if scope.get("type") != "http":  # pragma: no cover - defensive
            await transport.handle_post_message(scope, receive, send)
            return

        if _BRIDGE_STATE.ready.is_set():
            await transport.handle_post_message(scope, receive, send)
            return

        request = Request(scope, receive)
        body = await request.body()

        if _is_handshake_message(body):
            await transport.handle_post_message(scope, _replay_receive(body), send)
            return

        client = request.client or ("unknown", 0)
        user_agent = request.headers.get("user-agent", "")
        _SSE_LOGGER.warning(
            "messages.not_ready",
            extra={
                "client_host": client[0],
                "client_port": client[1],
                "user_agent": user_agent,
                "path": scope.get("path"),
                "status_code": 425,
                "reason": "mcp_not_ready",
            },
        )
        response = JSONResponse({"error": "mcp_not_ready"}, status_code=425)
        await response(scope, _replay_receive(b""), send)

    return Starlette(
        debug=self.settings.debug,
        routes=[
            Route(self.settings.sse_path, endpoint=handle_get, methods=["GET"]),
            Route(self.settings.sse_path, endpoint=handle_post, methods=["POST"]),
            Mount(self.settings.message_path, app=handle_message),
        ],
    )


def build_api_app() -> Starlette:
    configure()
    async def state(_: Request) -> JSONResponse:
        async with _STATE_LOCK:
            session_ready = _BRIDGE_STATE.ready.is_set()
            payload = {
                "bridge_ready": _CONFIGURED,
                "session_ready": session_ready,
                "ready": session_ready,
                "active_sse": _BRIDGE_STATE.active_sse_id,
                "connects": _BRIDGE_STATE.connects,
                "last_init_ts": _BRIDGE_STATE.last_init_ts,
            }
        return JSONResponse(payload)

    state_route = Route("/state", state, methods=["GET"], name="state")

    routes = list(make_routes(_client_factory, call_semaphore=_BRIDGE_STATE.ghidra_sema))
    schema = _build_openapi_schema([*routes, state_route])

    async def openapi(_: Request) -> JSONResponse:
        return JSONResponse(schema)

    openapi_route = Route(
        "/openapi.json", openapi, methods=["GET"], name="openapi"
    )

    routes.extend([openapi_route, state_route])
    return Starlette(routes=routes)


def create_app() -> Starlette:
    """Factory compatible with ``uvicorn --factory``."""

    api_app = build_api_app()
    sse_app = MCP_SERVER.sse_app()
    api_app.router.routes.extend(sse_app.routes)
    return api_app


app = build_api_app()


# Install the guarded SSE app on import so both tests and runtime honour it.
MCP_SERVER.sse_app = MethodType(_guarded_sse_app, MCP_SERVER)


__all__ = [
    "MCP_SERVER",
    "app",
    "build_api_app",
    "configure",
    "create_app",
    "set_ghidra_base_url",
]
