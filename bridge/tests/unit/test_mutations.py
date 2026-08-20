"""Stage 5: the session ledger, and what it must not let you believe."""
from __future__ import annotations

import pytest

from bridge.features import mutations


@pytest.fixture(autouse=True)
def _empty_ledger():
    mutations.clear()
    yield
    mutations.clear()


def test_an_empty_ledger_says_nothing_happened():
    assert mutations.since_last_save() == []
    assert mutations.summarise([]) == {
        "total": 0,
        "applied": 0,
        "proposed": 0,
        "by_kind": {},
    }


def test_a_proposal_is_never_rendered_like_an_accomplishment():
    """The whole point: a dry run is a decision, not a change."""

    mutations.record(
        kind="rename", target="0x1000", old="FUN_1000", new="init", applied=False,
        reason="dry_run",
    )
    mutations.record(
        kind="rename", target="0x2000", old="FUN_2000", new="boot", applied=True,
    )

    proposed, applied = mutations.render_lines(mutations.since_last_save())
    assert proposed.startswith("[proposed] ")
    assert not applied.startswith("[proposed] ")


def test_summary_separates_applied_from_proposed():
    mutations.record(kind="rename", target="0x1000", new="a", applied=False)
    mutations.record(kind="comment", target="0x2000", new="b", applied=True)
    mutations.record(kind="comment", target="0x3000", new="c", applied=True)

    assert mutations.summarise(mutations.since_last_save()) == {
        "total": 3,
        "applied": 2,
        "proposed": 1,
        "by_kind": {"rename": 1, "comment": 2},
    }


def test_an_unknown_old_value_is_not_an_empty_one():
    """"?" and "(empty)" are different claims about the binary."""

    mutations.record(kind="comment", target="0x1000", old=None, new="x", applied=True)
    mutations.record(kind="comment", target="0x2000", old="", new="y", applied=True)

    unknown, empty = mutations.render_lines(mutations.since_last_save())
    assert "? -> x" in unknown
    assert "(empty) -> y" in empty


def test_a_deletion_renders_as_one():
    mutations.record(
        kind="datatype", target="/USB/Regs", old="/USB/Regs", new=None, applied=True
    )
    assert "deleted" in mutations.render_lines(mutations.since_last_save())[0]


def test_a_creation_renders_as_one():
    mutations.record(
        kind="datatype", target="/USB/Regs", old=None, new="structure(3 fields)",
        applied=False, reason="dry_run",
    )
    line = mutations.render_lines(mutations.since_last_save())[0]
    assert "created structure(3 fields)" in line
    assert line.startswith("[proposed] ")


def test_saving_clears_the_ledger_and_reports_what_it_held():
    for index in range(3):
        mutations.record(kind="rename", target=f"0x{index:04x}", new="x", applied=True)

    assert mutations.mark_saved() == 3
    assert mutations.since_last_save() == []
    assert mutations.mark_saved() == 0


def test_long_values_are_shortened_not_dropped():
    mutations.record(
        kind="comment", target="0x1000", old=None, new="x" * 200, applied=True
    )
    entry = mutations.since_last_save()[0]
    assert entry.new is not None
    assert len(entry.new) < 200
    assert "…" in entry.new


def test_newlines_do_not_break_a_pasteable_block():
    """The output goes into a commit message; one entry is one line."""

    mutations.record(
        kind="comment", target="0x1000", new="first\nsecond", applied=True
    )
    lines = mutations.render_lines(mutations.since_last_save())
    assert len(lines) == 1
    assert "\n" not in lines[0]


def test_the_detail_is_carried_through():
    mutations.record(
        kind="comment", target="0x1000", new="x", applied=True, detail="disassembly"
    )
    assert "(disassembly)" in mutations.render_lines(mutations.since_last_save())[0]


def test_entries_keep_their_order():
    for index in range(5):
        mutations.record(kind="rename", target=f"0x{index:04x}", new="x", applied=True)
    targets = [entry.target for entry in mutations.since_last_save()]
    assert targets == [f"0x{index:04x}" for index in range(5)]
