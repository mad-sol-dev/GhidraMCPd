"""The plugin answers in prose; parsing prose must not guess.

get_function_by_address returns {"Function": "<name> at <hex>"} -- the name
inside a sentence rather than in a field.  A loose parse yields a
plausible-looking wrong name, which in the mutation ledger is worse than "?":
"?" says the old value is unknown, a wrong name asserts something false about
the binary.
"""
from __future__ import annotations

from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from bridge.api.tools import register_tools
from bridge.tests.plugin_http import function_search_page

ADDRESS = 0x002AF9C0


class _Client:
    """Returns whatever the test wants get_function_by_address to say."""

    def __init__(self, payload: Any):
        self.payload = payload

    def get_function_by_address(self, address: int) -> Any:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload

    def search_functions(self, query: str, *, limit: int = 100, offset: int = 0, cursor=None):
        # No other function has the new name (rename_function checks for duplicates).
        return function_search_page([], query, limit=limit, offset=offset, cursor=cursor)

    def get_current_program_status(self) -> dict[str, Any]:
        return {"state": "READY"}

    def close(self) -> None:
        pass


def _name_for(payload: Any) -> str | None:
    """Reach the helper through the surface that uses it."""

    import bridge.api.tools as tools_module

    captured: dict[str, Any] = {}
    original = tools_module.mutations.record

    def spy(**kwargs):
        captured.update(kwargs)
        return original(**kwargs)

    tools_module.mutations.record = spy
    try:
        server = FastMCP("name-parse-test")
        register_tools(server, client_factory=lambda: _Client(payload), enable_writes=False)
        import asyncio

        asyncio.run(
            server.call_tool(
                "rename_function", {"address": "0x002af9c0", "new_name": "x"}
            )
        )
    finally:
        tools_module.mutations.record = original
        tools_module.mutations.clear()
    return captured.get("old")


def test_the_documented_shape_is_parsed():
    assert _name_for({"Function": "usbd_init_phy_cep at 002af9c0"}) == "usbd_init_phy_cep"


def test_a_name_containing_at_keeps_all_of_it():
    """The anchor is the last separator, so the name survives intact."""

    assert (
        _name_for({"Function": "look at this at 002af9c0"}) == "look at this"
    )


def test_a_name_that_looks_like_an_address_suffix_is_not_truncated():
    assert (
        _name_for({"Function": "handler at 1234 at 002af9c0"}) == "handler at 1234"
    )


@pytest.mark.parametrize(
    "described",
    [
        "usbd_init_phy_cep",                     # no separator at all
        "usbd_init_phy_cep at ",                 # no address
        "usbd_init_phy_cep at notahexstring",    # not hex
        " at 002af9c0",                          # no name
        "usbd_init_phy_cep at 002af9c0 (thunk)",  # trailing prose
        "Function usbd_init_phy_cep, entry 002af9c0",  # a different format
        "",
    ],
)
def test_any_other_shape_yields_no_guess(described):
    """Better an admitted unknown than a sentence in a name field."""

    assert _name_for({"Function": described}) is None


def test_a_mismatched_address_is_rejected():
    """The address in the prose must be the one that was asked about.

    A response about a different function is not a better answer than none.
    """

    assert _name_for({"Function": "some_other_function at 00112233"}) is None


def test_a_proper_field_would_be_used_if_the_plugin_grew_one():
    assert _name_for({"name": "usbd_init_phy_cep"}) == "usbd_init_phy_cep"


@pytest.mark.parametrize(
    "payload",
    [None, [], "a string", {"Signature": "void f(void)"}, {"Function": None}],
)
def test_unusable_responses_yield_no_guess(payload):
    assert _name_for(payload) is None


def test_an_upstream_error_does_not_break_the_write():
    """The ledger is a bystander; it must never be why a rename fails."""

    assert _name_for(RuntimeError("upstream is down")) is None
