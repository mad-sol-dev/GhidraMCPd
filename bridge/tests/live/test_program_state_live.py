"""R.23 against the reference program: the state the plugin reports.

Read-only.  The reference copy is analysed and nothing analyses it during a
test run, so the plugin must say READY without a "not analysed" warning, and
the bridge's wait must return at once.  The LOADING -> READY transition needs
a running analysis, which writes to the program; it is not exercised here.
"""
from __future__ import annotations

from bridge.api import tools

#: The fields /api/current_program.json sends (plugin 1.3.61); the unit stubs
#: in test_program_readiness.py model exactly these.
STATUS_FIELDS = {"domain_file_id", "locked", "state", "state_duration_seconds", "warnings"}


def test_status_has_the_modelled_shape(client):
    status = client.get_current_program_status()

    assert set(status) == STATUS_FIELDS
    assert status["domain_file_id"]


def test_analysed_reference_program_is_ready(client):
    status = client.get_current_program_status()

    assert status["state"] == "READY"
    assert not any("not been run" in w for w in status["warnings"])


def test_bridge_wait_returns_at_once_when_ready(client, monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(tools.time, "sleep", sleeps.append)

    status, warnings = tools._await_program_ready(client)

    assert status["state"] == "READY"
    assert sleeps == []
    assert warnings == []
