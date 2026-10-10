"""R.25: read-only unless asked otherwise, and every surface says so.

The bridge starts with writes off when GHIDRA_MCP_ENABLE_WRITES is unset or
false.  MCP clients learn it from project_info, HTTP clients from
/api/health.json and /api/project_info.json, and every refusal or note of a
write tool says how to turn writes on, in the same words.  save_program is a
write too: it puts unsaved changes into the project file.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.api.tools import register_tools
from bridge.features import datatypes, jt, labels, mmio
from bridge.utils.config import WRITES_DISABLED_NOTE, WRITES_ENABLE_HOWTO, writes_status
from bridge.utils.program_context import PROGRAM_SELECTIONS


REPO = Path(__file__).resolve().parents[3]


def _enable_writes_in_fresh_process(value: str | None, cwd: Path) -> str:
    """ENABLE_WRITES as a new bridge process sees it.

    Run from an empty directory: the bridge loads a ``.env`` from the working
    directory on import, and a developer's local one (writes on, say) must not
    decide what the code's default is.
    """

    env = {k: v for k, v in os.environ.items() if k != "GHIDRA_MCP_ENABLE_WRITES"}
    env["PYTHONPATH"] = str(REPO)
    if value is not None:
        env["GHIDRA_MCP_ENABLE_WRITES"] = value
    out = subprocess.run(
        [sys.executable, "-c", "from bridge.utils.config import ENABLE_WRITES; print(ENABLE_WRITES)"],
        env=env, cwd=cwd, capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


@pytest.mark.parametrize("value", [None, "", "false", "0", "no", "nonsense"])
def test_writes_are_off_unless_enabled(value, tmp_path):
    assert _enable_writes_in_fresh_process(value, tmp_path) == "False"


def test_writes_on_when_enabled(tmp_path):
    assert _enable_writes_in_fresh_process("true", tmp_path) == "True"


def test_writes_status_carries_the_howto_only_while_off():
    assert writes_status(False) == {"writes_enabled": False, "writes_note": WRITES_ENABLE_HOWTO}
    assert writes_status(True) == {"writes_enabled": True}
    assert "GHIDRA_MCP_ENABLE_WRITES=true" in WRITES_ENABLE_HOWTO
    assert "dry_run=false" in WRITES_ENABLE_HOWTO


def test_every_write_feature_notes_the_same_words():
    for module in (datatypes, jt, labels, mmio):
        assert module._NOTE_WRITES_DISABLED == WRITES_DISABLED_NOTE, module.__name__
    assert WRITES_DISABLED_NOTE.startswith("writes disabled")


# --- MCP tools ----------------------------------------------------------------


class _Client:
    base_url = "http://ghidra/"
    last_error = None

    def __init__(self) -> None:
        self.saves = 0

    def get_current_program_status(self):
        return {"domain_file_id": "prog-1", "locked": False, "state": "READY",
                "state_duration_seconds": 1, "warnings": []}

    def get_project_info(self):
        return {"program_name": "p", "executable_path": None, "executable_md5": None,
                "executable_sha256": None, "executable_format": None, "image_base": "0x0",
                "language_id": "ARM:LE:32:v7", "compiler_spec_id": "default",
                "entry_points": [], "memory_blocks": [], "imports_count": 0,
                "exports_count": 0}

    def get_function_by_address(self, address):
        return {"Function": f"old_name at {address:08x}", "Entry": f"{address:08x}"}

    def save_program(self, description=None):
        self.saves += 1
        return {"status": "ok", "saved": "true", "program_name": "p", "message": "saved"}

    def close(self):
        pass


def _tools(enable_writes: bool, client: _Client):
    PROGRAM_SELECTIONS.clear()
    server = FastMCP("r25")
    register_tools(server, client_factory=lambda: client, enable_writes=enable_writes)
    return server._tool_manager._tools


@pytest.mark.parametrize("enabled", [False, True])
def test_project_info_reports_write_enablement(enabled):
    result = _tools(enabled, _Client())["project_info"].fn()

    assert result["ok"] is True, result
    assert result["data"]["writes_enabled"] is enabled
    assert ("writes_note" in result["data"]) is (not enabled)


def test_save_program_is_refused_while_writes_are_off():
    client = _Client()
    result = _tools(False, client)["save_program"].fn()

    assert result["ok"] is False
    assert result["errors"][0]["recovery"] == [WRITES_ENABLE_HOWTO]
    assert client.saves == 0


def test_save_program_saves_once_writes_are_on():
    client = _Client()
    result = _tools(True, client)["save_program"].fn()

    assert result["ok"] is True and client.saves == 1


def test_rename_refusal_says_how_to_enable():
    result = _tools(False, _Client())["rename_function"].fn("0x401000", "x", dry_run=False)

    assert result["ok"] is False
    assert result["errors"][0]["recovery"] == [WRITES_ENABLE_HOWTO]


def test_dry_run_does_not_promise_what_a_real_run_would_refuse():
    result = _tools(False, _Client())["rename_function"].fn("0x401000", "x")

    message = result["data"]["message"]
    assert "dry_run=false would be refused too" in message
    assert WRITES_ENABLE_HOWTO in message


def test_dry_run_with_writes_on_points_at_dry_run_false():
    result = _tools(True, _Client())["rename_function"].fn("0x401000", "x")

    assert result["data"]["message"].endswith("(set dry_run=false to execute)")


# --- HTTP ---------------------------------------------------------------------


@pytest.mark.parametrize("enabled", [False, True])
def test_http_surfaces_report_write_enablement(enabled):
    app = Starlette(routes=make_routes(lambda: _Client(), enable_writes=enabled))
    with TestClient(app) as http:
        info = http.get("/api/project_info.json").json()["data"]

    assert info["writes_enabled"] is enabled
    assert (info.get("writes_note") == WRITES_ENABLE_HOWTO) is (not enabled)


@pytest.mark.parametrize("enabled", [False, True])
def test_health_reports_write_enablement(enabled):
    import httpx

    from bridge.ghidra.client import GhidraClient

    def factory():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, text="{}"))
        client = GhidraClient("http://ghidra.test/", transport=transport)
        return client

    app = Starlette(routes=make_routes(factory, enable_writes=enabled))
    with TestClient(app) as http:
        health = http.get("/api/health.json").json()["data"]

    assert health["writes_enabled"] is enabled
    assert (health.get("writes_note") == WRITES_ENABLE_HOWTO) is (not enabled)
