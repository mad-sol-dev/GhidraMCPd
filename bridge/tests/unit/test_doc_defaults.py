"""What a tool description says about defaults is what the code does.

The description is all a model reads before calling; a default it states
wrongly is a wrong call with no error.  The "default limit of 100" that the
field test found had survived months of green suites, because nothing compared
the two (DOC-DEFAULT-DRIFT).
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Dict, Optional

import pytest

from bridge.app import MCP_SERVER, configure
from bridge.features.analyze import AnalyzeConfig

SCHEMAS = Path(__file__).resolve().parents[2] / "api" / "schemas"

#: How descriptions state a parameter default, most specific first.
_STATED = (
    re.compile(r"'([^']+)' \(default"),
    re.compile(r"\bdefault:?\s+'([^']+)'", re.I),
    re.compile(r"\bdefault:?\s+(-?\d+|true|false|null|none)\b", re.I),
)


@pytest.fixture(scope="module")
def tools():
    configure()
    return {tool.name: tool for tool in asyncio.run(MCP_SERVER.list_tools())}


def _args(description: str, params) -> Dict[str, str]:
    """The text of each parameter's entry in the Args section."""

    match = re.search(r"\n\s*Args:\n(.*)", description, re.S)
    if not match:
        return {}
    blocks: Dict[str, str] = {}
    current: Optional[str] = None
    for line in match.group(1).splitlines():
        if not line.strip():
            break  # the Args section ends at its first blank line
        head = re.match(r"^\s{4,12}(\w+):\s*(.*)$", line)
        if head and head.group(1) in params:
            current = head.group(1)
            blocks[current] = head.group(2)
        elif current:
            blocks[current] += " " + line.strip()
    return blocks


def _stated(text: str) -> Optional[str]:
    for pattern in _STATED:
        found = pattern.search(text)
        if found:
            return found.group(1)
    return None


def _norm(value: object) -> str:
    return str(value).lower().replace("none", "null")


def _stated_defaults(tools):
    for name, tool in sorted(tools.items()):
        props = (tool.inputSchema or {}).get("properties", {})
        for param, text in _args(tool.description or "", props).items():
            stated = _stated(text)
            if stated is not None:
                yield name, param, stated, props[param].get("default", "<required>")


def test_the_extraction_sees_the_defaults_it_is_about(tools):
    """A pattern that matched nothing would pass every check below."""

    found = {(name, param) for name, param, _, _ in _stated_defaults(tools)}
    assert len(found) >= 50, len(found)
    assert {("find_in_function", "limit"), ("disassemble_at", "fmt"), ("apply_label", "dry_run")} <= found


def test_every_stated_parameter_default_is_the_real_one(tools):
    wrong = [
        f"{name}.{param}: description says {stated!r}, signature has {actual!r}"
        for name, param, stated, actual in _stated_defaults(tools)
        if _norm(stated) != _norm(actual)
    ]
    assert wrong == []


# --- analyze_function_complete options ----------------------------------------
#
# Documented as "disasm.before/after 0-64 (8)", bounded in the request schema,
# defaulted in AnalyzeConfig: three places, one description.

_OPTION = re.compile(r"(\w+)\.([\w/]+) (?:(\d+)-(\d+)|bool) \(([^)]+)\)")

#: option path -> AnalyzeConfig attribute
_CONFIG_ATTR = {
    ("disasm", "before"): "before",
    ("disasm", "after"): "after",
    ("disasm", "max_instructions"): "max_instructions",
    ("xrefs", "inbound_limit"): "inbound_limit",
    ("xrefs", "outbound_limit"): "outbound_limit",
    ("callgraph", "limit"): "callgraph_limit",
    ("strings", "limit"): "strings_limit",
    ("strings", "max_cstring_len"): "cstring_max_len",
    ("constants", "limit"): "constants_limit",
    ("decompile", "enabled"): "decompile_enabled",
    ("decompile", "max_lines"): "decompile_max_lines",
}


def _documented_options(tools):
    text = " ".join((tools["analyze_function_complete"].description or "").split())
    for section, names, low, high, default in _OPTION.findall(text):
        for name in names.split("/"):
            yield section, name, (int(low), int(high)) if low else None, default


def test_every_analyze_option_is_documented_once(tools):
    documented = {(s, n) for s, n, _, _ in _documented_options(tools)}
    assert documented == set(_CONFIG_ATTR)


def test_analyze_option_ranges_and_defaults_match_schema_and_code(tools):
    schema = json.loads((SCHEMAS / "analyze_function_complete.request.v1.json").read_text())
    options = schema["properties"]["options"]["properties"]
    config = AnalyzeConfig()
    wrong = []
    for section, name, bounds, default in _documented_options(tools):
        spec = options[section]["properties"][name]
        if bounds is not None and (spec.get("minimum"), spec.get("maximum")) != bounds:
            wrong.append(f"{section}.{name}: doc {bounds}, schema {(spec.get('minimum'), spec.get('maximum'))}")
        actual = getattr(config, _CONFIG_ATTR[(section, name)])
        if _norm(default) != _norm(actual):
            wrong.append(f"{section}.{name}: doc default {default}, code {actual}")
    assert wrong == []
