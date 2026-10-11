"""R.26 against the reference program, without writing anything.

The plugin's check is exercised through /createLabel with dry_run=true: a
write route, so the check applies, but a dry run changes nothing even if the
check were missing.  The bridge's check refuses before sending, so its probe
uses a real write call that never reaches the plugin.  Every test ends by
confirming the program has no unsaved changes.
"""
from __future__ import annotations

import httpx
import pytest

from bridge.ghidra.client import GhidraClient

from bridge.tests.live.conftest import GHIDRA_URL

PROBE = {"address": "0xb1006000", "name": "R26_probe", "dry_run": "true"}


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("-")[0].split("."))


@pytest.fixture(scope="module")
def plugin(client):
    answer = httpx.get(f"{GHIDRA_URL}plugin_version", timeout=10).json()
    if _version(answer["version"]) < (1, 3, 63):
        pytest.skip(f"plugin {answer['version']} predates the write check (1.3.63)")
    return client


@pytest.fixture
def unchanged(plugin):
    yield
    dirty = httpx.get(f"{GHIDRA_URL}check_dirty_state", timeout=10).json()
    assert dirty["changed"] is False, dirty


def _active_id(client: GhidraClient) -> str:
    return client.get_current_program_status()["domain_file_id"]


def test_plugin_refuses_a_foreign_domain_file_id(plugin, unchanged):
    active = _active_id(plugin)
    response = httpx.post(f"{GHIDRA_URL}createLabel", params={"domain_file_id": "not-this-one"},
                          data=PROBE, timeout=10)

    assert response.status_code == 409
    body = response.json()
    assert body["requested_domain_file_id"] == "not-this-one"
    assert body["active_domain_file_id"] == active
    assert body["error"].startswith("Write refused")


def test_plugin_lets_the_active_program_through(plugin, unchanged):
    response = httpx.post(f"{GHIDRA_URL}createLabel", params={"domain_file_id": _active_id(plugin)},
                          data=PROBE, timeout=10)

    assert response.status_code == 200
    assert response.json()["dry_run"] is True


def test_bridge_refuses_before_sending(plugin, unchanged):
    client = GhidraClient(GHIDRA_URL, timeout=10)
    client.expected_program_id = "not-this-one"
    try:
        assert client.rename_function(0x002AF9C0, "R26_must_not_happen") is False
        assert "selected domain_file_id 'not-this-one'" in client.write_refusal.reason
    finally:
        client.close()


def test_bridge_dry_run_label_names_the_active_program(plugin, unchanged):
    client = GhidraClient(GHIDRA_URL, timeout=10)
    try:
        answer = client.create_label(0xB1006000, "R26_probe", dry_run=True)
        assert answer["status"] == "ok" and answer["created"] is False
        assert client.write_refusal is None
    finally:
        client.close()
