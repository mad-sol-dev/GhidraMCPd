"""Stage 5 acceptance, on the live program.

Three trial renames in dry-run mode; the tool lists exactly those three.
"""
from __future__ import annotations

import pytest

from bridge.features import mutations

#: Functions the reference session already knows, with their real names.
TRIAL_RENAMES = [
    ("0x002af9c0", "usbd_init_phy_cep", "usbd_init_phy_cep_v2"),
    ("0x002af80c", "usbd_irq_setup", "usbd_irq_setup_v2"),
    ("0x0026a7f8", "ui_main_loop", "ui_main_loop_v2"),
]


@pytest.fixture(autouse=True)
def _empty_ledger():
    mutations.clear()
    yield
    mutations.clear()


@pytest.fixture
def rename(project_info):
    """The real MCP tool surface, with writes off.

    The acceptance is about the ledger, and the frozen project copy has to come
    out of this unchanged.

    The factory builds a client per call rather than sharing one: inject_client
    closes whatever it is handed, so a shared client dies after the first tool
    call.
    """

    from mcp.server.fastmcp import FastMCP

    from bridge.api.tools import register_tools
    from bridge.ghidra.client import GhidraClient
    from bridge.tests.live.conftest import GHIDRA_URL

    server = FastMCP("ledger-test")
    register_tools(
        server,
        client_factory=lambda: GhidraClient(GHIDRA_URL, timeout=120),
        enable_writes=False,
    )
    return server


def _current_name(client, address: int) -> str | None:
    meta = client.get_function_by_address(address)
    described = meta.get("Function", "") if isinstance(meta, dict) else ""
    name, separator, _ = str(described).rpartition(" at ")
    return name if separator else None


def test_the_old_names_are_actually_readable(client):
    """Guard the guard: a ledger of "? -> new" would pass a weaker test.

    The plugin returns the name inside "Function": "<name> at <address>", not in
    a field of its own, so this is worth asserting before relying on it.
    """

    for address, expected, _ in TRIAL_RENAMES:
        assert _current_name(client, int(address, 16)) == expected


def test_three_dry_run_renames_are_listed_as_exactly_three(client, rename):
    import asyncio
    import json

    async def call(name, arguments):
        result = await rename.call_tool(name, arguments)
        text = result[0].text if isinstance(result, list) else result.content[0].text
        return json.loads(text)

    async def run():
        assert (await call("list_mutations", {}))["data"]["summary"]["total"] == 0

        for address, _, new_name in TRIAL_RENAMES:
            response = await call(
                "rename_function", {"address": address, "new_name": new_name}
            )
            assert response["ok"] is True
            assert response["data"]["success"] is False, "dry run must not write"

        return await call("list_mutations", {"fmt": "json"})

    listed = asyncio.run(run())["data"]

    assert listed["summary"] == {
        "total": 3,
        "applied": 0,
        "proposed": 3,
        "by_kind": {"rename": 3},
    }

    entries = listed["mutations"]
    assert [entry["target"] for entry in entries] == [a for a, _, _ in TRIAL_RENAMES]
    assert [entry["old"] for entry in entries] == [o for _, o, _ in TRIAL_RENAMES]
    assert [entry["new"] for entry in entries] == [n for _, _, n in TRIAL_RENAMES]
    assert all(entry["applied"] is False for entry in entries)
    assert all(entry["reason"] == "dry_run" for entry in entries)


def test_the_text_form_is_pasteable_and_marks_every_proposal(client, rename):
    import asyncio
    import json

    async def run():
        for address, _, new_name in TRIAL_RENAMES:
            result = await rename.call_tool(
                "rename_function", {"address": address, "new_name": new_name}
            )
            del result
        result = await rename.call_tool("list_mutations", {})
        text = result[0].text if isinstance(result, list) else result.content[0].text
        return json.loads(text)

    lines = asyncio.run(run())["data"]["lines"]

    assert len(lines) == 3
    assert all(line.startswith("[proposed] ") for line in lines)
    assert all("\n" not in line for line in lines)
    assert "usbd_init_phy_cep -> usbd_init_phy_cep_v2" in lines[0]


def test_the_program_was_not_modified(client):
    """The acceptance runs on the frozen copy; it must come out unchanged."""

    for address, expected, _ in TRIAL_RENAMES:
        assert _current_name(client, int(address, 16)) == expected
