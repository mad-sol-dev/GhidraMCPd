from __future__ import annotations

from starlette.testclient import TestClient

from bridge.app import build_api_app
from bridge import app as bridge_app


def _reset_bridge_state() -> None:
    bridge_app._BRIDGE_STATE.active_sse_id = None
    bridge_app._BRIDGE_STATE.connects = 0
    bridge_app._BRIDGE_STATE.ready.clear()
    bridge_app._BRIDGE_STATE.initialization_logged = False
    bridge_app._BRIDGE_STATE.last_init_ts = None


def test_state_endpoint_reports_bridge_status() -> None:
    _reset_bridge_state()
    app = build_api_app()

    with TestClient(app) as client:
        response = client.get("/state")
        assert response.status_code == 200
        assert response.json() == {
            "bridge_ready": True,
            "session_ready": False,
            "ready": False,
            "active_sse": None,
            "connects": 0,
            "last_init_ts": None,
        }

        bridge_app._BRIDGE_STATE.active_sse_id = "abc123"
        bridge_app._BRIDGE_STATE.connects = 5
        bridge_app._BRIDGE_STATE.ready.set()
        bridge_app._BRIDGE_STATE.last_init_ts = "2024-01-01T00:00:00+00:00"

        response = client.get("/state")
        assert response.status_code == 200
        assert response.json() == {
            "bridge_ready": True,
            "session_ready": True,
            "ready": True,
            "active_sse": "abc123",
            "connects": 5,
            "last_init_ts": "2024-01-01T00:00:00+00:00",
        }

    _reset_bridge_state()
