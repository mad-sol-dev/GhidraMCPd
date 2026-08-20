"""An unplaceable load/store must not be reported as an MMIO register.

The classifier resolved a register-indirect access by falling back to whatever
immediate it found in the brackets -- which for `ldr r0,[r0,#0x214]` is the
*offset*, not the address.  Two consequences, both silent:

* a real MMIO access at 0xB0000214 was reported at 0x214, and
* an ordinary stack access `ldr r0,[sp,#0x8]` was reported as a register at 0x8.

On ui_main_loop that produced 161 reads and 153 writes where there is no MMIO at
all.  Nothing failed; the numbers just meant nothing.
"""
from __future__ import annotations

import pytest

from bridge.features.mmio import _collect_operations


def _run(lines):
    operations, skipped = _collect_operations(lines)
    return [(op.op, op.target) for op in operations], skipped


def test_a_mov_immediate_supplies_the_base():
    """The firmware's usual idiom, and the one that was unsupported."""

    ops, skipped = _run([
        "002af9d8: mov r0,#0xb0000000",
        "002af9dc: ldr r0,[r0,#0x214]",
    ])
    assert ops == [("READ", 0xB0000214)]
    assert skipped == 0


def test_a_store_through_a_mov_base_resolves_too():
    ops, _ = _run([
        "002af9e8: mov r1,#0xb0000000",
        "002af9ec: str r0,[r1,#0x214]",
    ])
    assert ops == [("WRITE", 0xB0000214)]


def test_a_stack_access_is_not_an_mmio_register():
    """The clearest case: no MMIO anywhere, and nothing may be reported."""

    ops, skipped = _run(["0026a804: ldr r0,[sp,#0x8]"])
    assert ops == []
    assert skipped == 1


def test_an_unknown_base_is_skipped_rather_than_guessed():
    ops, skipped = _run(["00450010: ldr r1,[r2,#0x10]"])
    assert ops == []
    assert skipped == 1


def test_the_offset_is_never_used_as_an_address():
    """The specific regression, stated as its own test."""

    ops, _ = _run(["00450010: ldr r1,[r2,#0x214]"])
    assert (("READ", 0x214)) not in ops


def test_a_register_move_invalidates_a_stale_base():
    """Keeping the old value would resolve to a confident wrong address."""

    ops, skipped = _run([
        "002af9d8: mov r0,#0xb0000000",
        "002af9d4: mov r0,r5",
        "002af9dc: ldr r1,[r0,#0x214]",
    ])
    assert ops == []
    assert skipped == 1


def test_mvn_is_understood_as_a_base_load():
    ops, _ = _run([
        "00400000: mvn r0,#0x0",
        "00400004: ldr r1,[r0,#0x4]",
    ])
    assert ops == [("READ", 0xFFFFFFFF + 0x4)]


def test_an_add_still_offsets_a_known_base():
    ops, _ = _run([
        "00400000: mov r0,#0xb0000000",
        "00400004: add r1,r0,#0x100",
        "00400008: ldr r2,[r1,#0x4]",
    ])
    assert ops == [("READ", 0xB0000104)]


def test_a_direct_absolute_load_still_works():
    """Removing the bracket fallback must not break literal addressing."""

    ops, _ = _run(["00400000: ldr r0,=0x50000000"])
    assert ops == [("READ", 0x50000000)]


@pytest.mark.parametrize(
    "line",
    [
        "00400000: ldr r0,[r1]",
        "00400000: str r0,[r2]",
        "00400000: ldr r2,[r3,r4]",
    ],
)
def test_every_unresolvable_form_counts_as_skipped(line):
    ops, skipped = _run([line])
    assert ops == []
    assert skipped == 1
