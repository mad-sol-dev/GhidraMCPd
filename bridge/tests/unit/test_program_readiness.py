"""R.23: what the bridge does while Ghidra is still analysing.

The plugin reports LOADING exactly while AutoAnalysisManager.isAnalyzing() is
true (read per request, no timeout).  select_program waits for that to end up
to a bounded limit and says so when it does not; analysis tools refuse with
guidance instead of answering from a half-analysed program.

The stub answers with the fields the plugin's /api/current_program.json
really sends -- domain_file_id, locked, state, state_duration_seconds,
warnings -- and nothing else.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP

import bridge.api.tools as tools
from bridge.api.tools import register_tools
from bridge.utils.program_context import PROGRAM_SELECTIONS

PLUGIN_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "src/main/java/com/lauriewired/GhidraMCPPlugin.java"
)


class _AnalysingClient:
    """Reports LOADING for the first ``loading_polls`` status reads, then READY."""

    def __init__(self, loading_polls: int, duration: int = 3) -> None:
        self.base_url = "http://ghidra/"
        self.loading_polls = loading_polls
        self.duration = duration
        self.status_reads = 0
        self.last_error = None

    def get_project_files(self):
        return [{"domain_file_id": "prog-1", "name": "alpha", "path": "/alpha", "type": "program"}]

    def open_program(self, domain_file_id, *, path=None, on_dirty=None):
        return {"status": "ok", "path": path, "domain_file_id": domain_file_id,
                "name": "alpha", "warnings": []}

    def get_current_program_status(self):
        self.status_reads += 1
        loading = self.status_reads <= self.loading_polls
        return {
            "domain_file_id": "prog-1",
            "locked": False,
            "state": "LOADING" if loading else "READY",
            "state_duration_seconds": self.duration,
            "warnings": [],
        }

    def close(self) -> None:
        pass


@pytest.fixture
def no_sleep(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(tools.time, "sleep", sleeps.append)
    return sleeps


def _select(client):
    PROGRAM_SELECTIONS.clear()
    server = FastMCP("readiness")
    register_tools(server, client_factory=lambda: client)
    return server._tool_manager._tools["select_program"].fn("prog-1")


def test_select_program_waits_until_analysis_ends(no_sleep) -> None:
    client = _AnalysingClient(loading_polls=3)

    result = _select(client)

    assert result["ok"] is True
    assert result["data"]["state"] == "READY"
    assert "warnings" not in result["data"]
    # the auto-open check reads the first LOADING; two more LOADING polls
    # sleep once each, the fourth read is READY
    assert client.status_reads == 4
    assert len(no_sleep) == 2


def test_select_program_reports_analysis_still_running(no_sleep, monkeypatch) -> None:
    clock = iter(range(0, 1000))
    monkeypatch.setattr(tools, "monotonic", lambda: next(clock))
    monkeypatch.setattr(tools, "PROGRAM_READY_WAIT_SECONDS", 4.0)
    client = _AnalysingClient(loading_polls=10_000)

    result = _select(client)

    assert result["ok"] is True
    assert result["data"]["state"] == "LOADING"
    assert any("still running auto-analysis after 4 s" in w for w in result["data"]["warnings"])
    assert 0 < len(no_sleep) < 10


def test_analysis_tool_refuses_while_loading_with_guidance() -> None:
    PROGRAM_SELECTIONS.clear()
    client = _AnalysingClient(loading_polls=10_000, duration=420)
    server = FastMCP("readiness-gate")
    register_tools(server, client_factory=lambda: client)

    result = server._tool_manager._tools["goto_address"].fn("0x1000")

    assert result["ok"] is False
    error = result["errors"][0]
    assert error["code"] == "UNAVAILABLE"
    assert "state=LOADING" in error["message"]
    recovery = " ".join(error["recovery"])
    assert "420 s" in recovery and "READY" in recovery
    # a long analysis is not a stale state: no advice to restart anything
    assert "restart" not in recovery.lower()


def _tracker_source() -> str:
    source = PLUGIN_SOURCE.read_text(encoding="utf-8")
    start = source.index("private final class ProgramStatusTracker")
    end = source.index("interface ServerFactory", start)
    return source[start:end]


def test_plugin_reads_analysis_state_per_request() -> None:
    tracker = _tracker_source()
    snapshot = tracker[tracker.index("ProgramStatusSnapshot snapshot()"):]
    snapshot = snapshot[: snapshot.index("void applyWarnings")]

    assert "currentState(" in snapshot
    assert "isAnalyzing()" in tracker


def test_plugin_never_forces_ready() -> None:
    """The old watcher declared READY after five minutes while analysis ran on."""

    tracker = _tracker_source()

    assert not re.search(r"TIMEOUT|forcing READY|Thread\.sleep", tracker)
