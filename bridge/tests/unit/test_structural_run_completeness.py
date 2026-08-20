"""The structural reference run may not leave a quantity parameter implicit.

That script exists to hold the requested amount constant, so that what it
measures is efficiency per delivered result rather than a change of defaults.
A parameter left to its default breaks exactly that: change the default later,
and the script reports a structural saving it did not earn.

It happened once already -- analyze_function_complete was called without
`fields`, and Stage 3's narrower default showed up there as efficiency.  A
subsequent audit found thirteen more such parameters.  All thirteen happened to
still sit at their old defaults, so the number did not move; the script was
lucky rather than correct.  This test removes the luck.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "bridge" / "api" / "tools.py"
STRUCTURAL = ROOT / "scripts" / "reference_run_structural.py"

#: Parameters that influence how much comes back, or in what shape.
QUANTITY_PARAMETERS = {
    "case_sensitive",
    "context_lines",
    "count",
    "dry_run",
    "fields",
    "fmt",
    "include_literals",
    "length",
    "limit",
    "max_result_tokens",
    "max_samples",
    "mode",
    "offset",
    "options",
    "page",
    "regex",
    "start",
}


def _tool_parameters() -> dict[str, set[str]]:
    signatures: dict[str, set[str]] = {}
    for node in ast.walk(ast.parse(TOOLS.read_text(encoding="utf-8"))):
        if isinstance(node, ast.FunctionDef):
            args = node.args.args + node.args.kwonlyargs
            signatures.setdefault(
                node.name, {arg.arg for arg in args if arg.arg != "client"}
            )
    return signatures


def _structural_calls() -> list[tuple[str, set[str]]]:
    source = STRUCTURAL.read_text(encoding="utf-8")
    block = source[source.index("CALLS:"):]
    block = block[block.index("("): block.index("\n)\n") + 2]
    tree = ast.parse("CALLS = " + block)

    calls: list[tuple[str, set[str]]] = []
    for element in tree.body[0].value.elts:
        name = element.elts[0].value
        passed = {key.value for key in element.elts[1].keys}
        calls.append((name, passed))
    return calls


def test_the_script_still_parses_into_calls():
    """Guard the guard: a parse that silently yields nothing proves nothing."""

    calls = _structural_calls()
    assert len(calls) >= 30, len(calls)
    assert {name for name, _ in calls} >= {
        "analyze_function_complete",
        "disassemble_batch",
        "find_in_function",
        "search_scalars_with_context",
    }


def test_no_quantity_parameter_is_left_implicit():
    signatures = _tool_parameters()
    gaps: list[str] = []

    for name, passed in _structural_calls():
        accepted = signatures.get(name)
        assert accepted is not None, f"unknown tool in structural run: {name}"
        missing = sorted((accepted & QUANTITY_PARAMETERS) - passed)
        if missing:
            gaps.append(f"{name}: {', '.join(missing)}")

    assert gaps == [], (
        "the structural run leaves quantity parameters to their defaults, so a "
        "later change of any of them would look like a structural saving:\n  "
        + "\n  ".join(gaps)
    )


def test_collect_sub_queries_are_explicit_too():
    """A default inside a collect op counts just the same."""

    source = STRUCTURAL.read_text(encoding="utf-8")
    block = source[source.index("CALLS:"):]
    block = block[block.index("("): block.index("\n)\n") + 2]
    tree = ast.parse("CALLS = " + block)

    signatures = _tool_parameters()
    gaps: list[str] = []

    for element in tree.body[0].value.elts:
        if element.elts[0].value != "collect":
            continue
        for key, value in zip(element.elts[1].keys, element.elts[1].values):
            if key.value != "queries":
                continue
            for query in value.elts:
                fields = dict(zip([k.value for k in query.keys], query.values))
                op = fields["op"].value
                params = {k.value for k in fields["params"].keys}
                accepted = signatures.get(op, set())
                missing = sorted((accepted & QUANTITY_PARAMETERS) - params)
                if missing:
                    gaps.append(f"collect/{op}: {', '.join(missing)}")

    assert gaps == [], "\n  ".join(gaps)


@pytest.mark.parametrize(
    "parameter", sorted({"count", "limit", "page", "context_lines", "fields", "fmt"})
)
def test_the_parameter_list_covers_the_obvious_ones(parameter):
    """If someone trims QUANTITY_PARAMETERS, the check quietly weakens."""

    assert parameter in QUANTITY_PARAMETERS
