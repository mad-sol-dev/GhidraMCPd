"""The generated reference pages match their sources (tool docstrings, plugin source)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PAGE = ROOT / "docs" / "reference" / "tools.md"


def _generator(name: str = "gen_tools_md"):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_the_catalogue_matches_the_docstrings():
    gen = _generator()

    expected = gen.render(gen.tool_docs())

    assert PAGE.read_text(encoding="utf-8") == expected, (
        "docs/reference/tools.md is stale: python scripts/gen_tools_md.py > docs/reference/tools.md"
    )


def test_every_tool_has_a_group():
    gen = _generator()
    grouped = {name for _, names in gen.GROUPS for name in names}

    assert grouped == set(gen.tool_docs())


def test_the_plugin_reference_matches_the_plugin_source():
    gen = _generator("gen_plugin_routes_md")
    page = ROOT / "docs" / "reference" / "plugin-api.md"

    assert page.read_text(encoding="utf-8") == gen.render(), (
        "docs/reference/plugin-api.md is stale: "
        "python scripts/gen_plugin_routes_md.py > docs/reference/plugin-api.md"
    )
