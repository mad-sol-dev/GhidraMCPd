from __future__ import annotations

import asyncio
import contextlib
import json
import logging

import anyio
import pytest

from bridge import app as bridge_app
from bridge.app import MCP_SERVER, configure


@pytest.fixture
def anyio_backend() -> str:
    """Force the anyio pytest plugin to use the asyncio backend."""

    return "asyncio"


@pytest.mark.anyio
async def test_sse_handshake_emits_endpoint_event() -> None:
    """The SSE endpoint should emit an endpoint event with a session URI."""

    configure()
    app = MCP_SERVER.sse_app()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/sse",
        "raw_path": b"/sse",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"accept", b"text/event-stream")],
        "client": ("testclient", 12345),
        "server": ("testserver", 80),
    }

    event_received = anyio.Event()
    messages: list[dict[str, object]] = []
    received_request = False

    async def receive() -> dict[str, object]:
        nonlocal received_request
        if not received_request:
            received_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await anyio.sleep_forever()

    async def send(message: dict[str, object]) -> None:
        messages.append(message)
        if message["type"] == "http.response.body" and message.get("body"):
            event_received.set()

    cancel_scope = anyio.CancelScope()

    async def run_app() -> None:
        with cancel_scope:
            await app(scope, receive, send)

    async with anyio.create_task_group() as tg:
        tg.start_soon(run_app)
        with anyio.fail_after(2):
            await event_received.wait()
        cancel_scope.cancel()

    status_messages = [m for m in messages if m["type"] == "http.response.start"]
    assert status_messages, "Expected HTTP response start message"
    status = status_messages[0]
    assert status["status"] == 200

    body_chunks = [
        m["body"].decode("utf-8")
        for m in messages
        if m["type"] == "http.response.body" and m.get("body")
    ]
    assert body_chunks, "Expected at least one SSE body chunk"

    payload = "".join(body_chunks)
    lines = [line for line in payload.splitlines() if line]

    event_line = next(line for line in lines if line.startswith("event:"))
    data_line = next(line for line in lines if line.startswith("data:"))

    assert event_line.split(":", 1)[1].strip() == "endpoint"
    session_uri = data_line.split(":", 1)[1].strip()
    assert session_uri.startswith("/messages")
    assert "session_id=" in session_uri


@pytest.mark.anyio
async def test_messages_block_until_initialized() -> None:
    """Messages should return 425 until the client sends initialized."""

    configure()
    app = MCP_SERVER.sse_app()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/sse",
        "raw_path": b"/sse",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"accept", b"text/event-stream")],
        "client": ("testclient", 12345),
        "server": ("testserver", 80),
    }

    session_ready = anyio.Event()
    session_uri: str | None = None
    received_request = False

    async def receive() -> dict[str, object]:
        nonlocal received_request
        if not received_request:
            received_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await anyio.sleep_forever()

    async def send(message: dict[str, object]) -> None:
        nonlocal session_uri
        if message["type"] != "http.response.body" or not message.get("body"):
            return
        payload = message["body"].decode("utf-8")
        for line in payload.splitlines():
            if line.startswith("data:"):
                session_uri = line.split(":", 1)[1].strip()
                session_ready.set()

    cancel_scope = anyio.CancelScope()

    async def run_app() -> None:
        with cancel_scope:
            await app(scope, receive, send)

    async with anyio.create_task_group() as tg:
        tg.start_soon(run_app)
        with anyio.fail_after(2):
            await session_ready.wait()

        assert session_uri is not None
        path, _, query = session_uri.partition("?")
        query_bytes = query.encode("utf-8")

        base_scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("utf-8"),
            "root_path": "",
            "query_string": query_bytes,
            "headers": [(b"content-type", b"application/json")],
            "client": ("testclient", 12345),
            "server": ("testserver", 80),
        }

        async def post_message(payload: dict[str, object]) -> tuple[int, bytes]:
            body = json.dumps(payload).encode("utf-8")
            sent = False
            messages: list[dict[str, object]] = []
            scope = dict(base_scope)
            scope["headers"] = list(base_scope["headers"])

            async def receive_body() -> dict[str, object]:
                nonlocal sent
                if sent:
                    return {"type": "http.request", "body": b"", "more_body": False}
                sent = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }

            async def send_response(message: dict[str, object]) -> None:
                messages.append(message)

            await app(scope, receive_body, send_response)
            status = next(m for m in messages if m["type"] == "http.response.start")[
                "status"
            ]
            body_bytes = b"".join(
                m.get("body", b"")
                for m in messages
                if m["type"] == "http.response.body"
            )
            return status, body_bytes

        status, body_bytes = await post_message(
            {"jsonrpc": "2.0", "id": 99, "method": "ping", "params": None}
        )
        assert status == 425
        payload = json.loads(body_bytes)
        assert payload["ok"] is False
        assert payload["data"] is None
        assert payload["errors"] == [
            {
                "status": 425,
                "code": "NOT_READY",
                "message": "Bridge is not ready yet.",
                "recovery": [
                    "Retry after the MCP bridge reports initialization complete.",
                ],
            }
        ]

        initialize_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0.0.0"},
            },
        }
        status, _ = await post_message(initialize_payload)
        assert status == 202

        status, _ = await post_message(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        assert status == 202

        with anyio.fail_after(2):
            while not bridge_app._BRIDGE_STATE.ready.is_set():  # type: ignore[attr-defined]
                await anyio.sleep(0)

        status, _ = await post_message(
            {"jsonrpc": "2.0", "id": 100, "method": "ping", "params": None}
        )
        assert status == 202

        cancel_scope.cancel()


@pytest.mark.anyio
async def test_second_sse_request_logs_rejection(caplog: pytest.LogCaptureFixture) -> None:
    configure()
    app = MCP_SERVER.sse_app()

    caplog.set_level(logging.WARNING, logger="bridge.sse")

    async with bridge_app._STATE_LOCK:  # type: ignore[attr-defined]
        bridge_app._BRIDGE_STATE.active_sse_id = "existing"  # type: ignore[attr-defined]
        bridge_app._BRIDGE_STATE.ready.clear()  # type: ignore[attr-defined]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/sse",
        "raw_path": b"/sse",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"accept", b"text/event-stream")],
        "client": ("testclient", 12345),
        "server": ("testserver", 80),
    }

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await app(scope, receive, send)

    status = next(m for m in messages if m["type"] == "http.response.start")["status"]
    assert status == 409
    payload_bytes = b"".join(
        m.get("body", b"") for m in messages if m["type"] == "http.response.body"
    )
    payload = json.loads(payload_bytes)
    assert payload["ok"] is False
    assert payload["data"] is None
    assert payload["errors"] == [
        {
            "status": 409,
            "code": "SSE_CONFLICT",
            "message": "Server-sent events stream already active.",
            "recovery": [
                "Disconnect the existing SSE client before reconnecting.",
            ],
        }
    ]

    rejection_records = [r for r in caplog.records if r.message == "sse.reject"]
    assert rejection_records, "Expected a rejection log entry"
    record = rejection_records[0]
    assert getattr(record, "status_code", None) == 409
    assert getattr(record, "reason", "") == "sse_already_active"
    assert getattr(record, "active_sse_id", "") == "existing"
    assert getattr(record, "path", "") == "/sse"

    async with bridge_app._STATE_LOCK:  # type: ignore[attr-defined]
        bridge_app._BRIDGE_STATE.active_sse_id = None  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_sse_disconnect_releases_lock_quickly() -> None:
    """An abrupt disconnect should release the SSE lock promptly."""

    configure()
    app = MCP_SERVER.sse_app()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/sse",
        "raw_path": b"/sse",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"accept", b"text/event-stream")],
        "client": ("testclient", 12345),
        "server": ("testserver", 80),
    }

    disconnect_event = anyio.Event()
    received_request = False
    disconnect_sent = False

    async def receive() -> dict[str, object]:
        nonlocal received_request, disconnect_sent
        if not received_request:
            received_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await disconnect_event.wait()
        if not disconnect_sent:
            disconnect_sent = True
            return {"type": "http.disconnect"}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, object]) -> None:
        # The response stream is ignored for this test; we only care about lock release.
        return None

    app_task = asyncio.create_task(app(scope, receive, send))

    try:
        with anyio.fail_after(2):
            while bridge_app._BRIDGE_STATE.active_sse_id is None:  # type: ignore[attr-defined]
                await anyio.sleep(0)

        disconnect_event.set()

        with anyio.fail_after(1):
            while bridge_app._BRIDGE_STATE.active_sse_id is not None:  # type: ignore[attr-defined]
                await anyio.sleep(0.05)

    finally:
        if not app_task.done():
            app_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await app_task

    async with bridge_app._STATE_LOCK:  # type: ignore[attr-defined]
        bridge_app._BRIDGE_STATE.active_sse_id = None  # type: ignore[attr-defined]


@pytest.mark.anyio
async def test_messages_not_ready_logs_rejection(caplog: pytest.LogCaptureFixture) -> None:
    configure()
    app = MCP_SERVER.sse_app()

    caplog.set_level(logging.WARNING, logger="bridge.sse")

    async with bridge_app._STATE_LOCK:  # type: ignore[attr-defined]
        bridge_app._BRIDGE_STATE.active_sse_id = None  # type: ignore[attr-defined]
        bridge_app._BRIDGE_STATE.ready.clear()  # type: ignore[attr-defined]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/messages/test",
        "raw_path": b"/messages/test",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("testclient", 54321),
        "server": ("testserver", 80),
    }

    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": None}).encode(
        "utf-8"
    )
    sent = False
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    await app(scope, receive, send)

    status = next(m for m in messages if m["type"] == "http.response.start")["status"]
    assert status == 425
    payload_bytes = b"".join(
        m.get("body", b"") for m in messages if m["type"] == "http.response.body"
    )
    payload = json.loads(payload_bytes)
    assert payload["ok"] is False
    assert payload["data"] is None
    assert payload["errors"] == [
        {
            "status": 425,
            "code": "NOT_READY",
            "message": "Bridge is not ready yet.",
            "recovery": [
                "Retry after the MCP bridge reports initialization complete.",
            ],
        }
    ]

    rejection_records = [r for r in caplog.records if r.message == "messages.not_ready"]
    assert rejection_records, "Expected a readiness rejection log entry"
    record = rejection_records[0]
    assert getattr(record, "status_code", None) == 425
    assert getattr(record, "reason", "") == "mcp_not_ready"
    assert getattr(record, "path", "") == "/messages/test"
