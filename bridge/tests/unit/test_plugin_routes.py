"""Every endpoint the bridge may call exists in the Java plugin.

The contract and unit suites run against stubs, so a bridge tool whose plugin
endpoint was never written passes them all and fails on the first real call.
This test reads the routes straight from ``GhidraMCPPlugin.java`` and checks
them against ``DEFAULT_WHITELIST``, which ``GhidraClient._request_lines``
enforces on every request -- no path reaches the plugin without being in it.

Two rules.  A key with no live alias is a tool that cannot work (stage 8b).
And every alias must be live: the resolver's cache dies with the client,
which is built per tool call, so a dead alias first in line cost a 404 on
every call -- measured as 2 of 19 requests of an analyze_function_complete
dossier (DEAD-ALIAS-FIRST).  The aliases were kept for plugin builds older
than this bridge can talk to anyway; they are gone, and this keeps them gone.
"""
from __future__ import annotations

import re
from pathlib import Path

from bridge.ghidra.whitelist import DEFAULT_WHITELIST

PLUGIN_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "src/main/java/com/lauriewired/GhidraMCPPlugin.java"
)
#: Both ways the plugin registers a route: through its three helpers, and
#: directly (``/plugin_version`` needs no program context and skips them).
ROUTE_PATTERN = re.compile(
    r'(?:register(?:Program|Project|Write)Handler\(\s*server,\s*|server\.createContext\(\s*)"/([^"]+)"'
)

# The extraction is only trustworthy if it finds what is known to be there.
# 51 register*Handler calls on 2026-10-09, plus /plugin_version (e49ea83),
# which the first version of this pattern did not see, plus /createLabel
# (R.12).  A change in the plugin moves the number, and then it is updated
# deliberately.
EXPECTED_ROUTE_COUNT = 53


def plugin_routes() -> set[str]:
    return set(ROUTE_PATTERN.findall(PLUGIN_SOURCE.read_text(encoding="utf-8")))


def test_route_extraction_finds_known_routes() -> None:
    routes = plugin_routes()
    assert len(routes) == EXPECTED_ROUTE_COUNT, sorted(routes)
    # one program route, one project route, one with a nested path
    assert {"disassembleAt", "open_program", "api/current_program.json", "plugin_version"} <= routes


def test_every_whitelisted_key_has_a_plugin_route() -> None:
    routes = plugin_routes()
    missing = sorted(
        f"{method} {entry.key} {entry.aliases}"
        for method, entries in DEFAULT_WHITELIST.items()
        for entry in entries
        if not routes.intersection(entry.aliases)
    )
    assert missing == []


def test_every_alias_has_a_plugin_route() -> None:
    routes = plugin_routes()
    dead = sorted(
        f"{method} {entry.key} {alias}"
        for method, entries in DEFAULT_WHITELIST.items()
        for entry in entries
        for alias in entry.aliases
        if alias not in routes
    )
    assert dead == []
