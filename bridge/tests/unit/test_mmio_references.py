"""MMIO addresses come from Ghidra's references, not from operand text.

The text classifier this replaces tracked base registers itself and got the
one case that mattered wrong: a base reloaded from the constant pool after
``mov r0,#0xb0000000`` kept the stale base.  On 0x002AF9C0 that was five of
eleven resolved accesses, each a plausible register address that the program
never touches.  Before that it had reported stack offsets as registers.

The records below have the shape the plugin's ``fmt=json`` listing returns.
"""
from __future__ import annotations

from bridge.features.mmio import _collect_operations


def _insn(address, mnemonic, *, refs=(), operands=()):
    return {
        "address": address,
        "mnemonic": mnemonic,
        "operands": list(operands),
        "refs": list(refs),
    }


def _ref(to, kind, *, mapped=False, space=None):
    ref = {"to": to, "type": kind, "op": 1, "mapped": mapped}
    if space:
        ref["space"] = space
    return ref


def _run(instructions):
    operations, skipped = _collect_operations(instructions)
    return [(op.addr, op.op, op.target) for op in operations], skipped


def test_a_pool_reloaded_base_takes_ghidras_address():
    """0x002afa38/3c on the reference program: the regression this replaces."""

    ops, skipped = _run([
        _insn("0x002afa30", "mov", operands=[{"registers": ["r1"]}, {"scalars": ["0xb0000000"]}]),
        _insn("0x002afa38", "ldr", refs=[_ref("0x002afb40", "READ", mapped=True)]),
        _insn("0x002afa3c", "ldr", refs=[_ref("0xb1008704", "READ")]),
    ])
    assert ops == [(0x002AFA3C, "READ", 0xB1008704)]
    assert skipped == 0


def test_a_write_outside_the_image_is_a_write():
    ops, _ = _run([_insn("0x002af9ec", "str", refs=[_ref("0xb0000214", "WRITE")])])
    assert ops == [(0x002AF9EC, "WRITE", 0xB0000214)]


def test_byte_and_conditional_forms_count():
    """strb into unmapped RAM was invisible to the old LDR/STR-only match."""

    ops, _ = _run([
        _insn("0x002afa54", "strb", refs=[_ref("0x0000829e", "WRITE")]),
        _insn("0x00400000", "ldrne", refs=[_ref("0xb0000014", "READ")]),
    ])
    assert ops == [(0x002AFA54, "WRITE", 0x829E), (0x00400000, "READ", 0xB0000014)]


def test_a_constant_pool_load_is_neither_io_nor_skipped():
    ops, skipped = _run([_insn("0x002af9e0", "ldr", refs=[_ref("0x002afb34", "READ", mapped=True)])])
    assert ops == []
    assert skipped == 0


def test_a_stack_access_is_not_an_mmio_register():
    """Ghidra gives it a stack-space reference; that is not an address."""

    ops, skipped = _run([
        _insn(
            "0x0026a804",
            "ldr",
            operands=[{"registers": ["r0"]}, {"registers": ["sp"], "scalars": ["0x8"]}],
            refs=[_ref("0x00000008", "READ", space="stack")],
        )
    ])
    assert ops == []
    assert skipped == 0


def test_a_load_ghidra_could_not_place_is_skipped():
    ops, skipped = _run([
        _insn("0x00450010", "ldr", operands=[{"registers": ["r1"]}, {"registers": ["r2"], "scalars": ["0x214"]}])
    ])
    assert ops == []
    assert skipped == 1


def test_the_offset_is_never_used_as_an_address():
    ops, _ = _run([
        _insn("0x00450010", "ldr", operands=[{"registers": ["r1"]}, {"registers": ["r2"], "scalars": ["0x214"]}])
    ])
    assert all(target != 0x214 for _addr, _op, target in ops)


def test_a_bitwise_op_takes_the_bare_immediate():
    ops, _ = _run([
        _insn(
            "0x002afa9c",
            "orr",
            operands=[{"registers": ["r0"]}, {"registers": ["r0"]}, {"scalars": ["0x50000"]}],
        )
    ])
    assert ops == [(0x002AFA9C, "OR", 0x50000)]


def test_a_shift_amount_is_not_a_value():
    """``orr r0,r0,r6, lsl #0xc`` was reported with target 0xc."""

    ops, _ = _run([
        _insn(
            "0x002afa2c",
            "orr",
            operands=[{"registers": ["r0"]}, {"registers": ["r0"]}, {"registers": ["r6"], "scalars": ["0xc"]}],
        )
    ])
    assert ops == [(0x002AFA2C, "OR", None)]


def test_bic_counts_as_and_and_eor_as_toggle():
    ops, _ = _run([
        _insn("0x002afac0", "bic", operands=[{"registers": ["r0"]}, {"registers": ["r0"]}, {"scalars": ["0x40"]}]),
        _insn("0x00400000", "eor", operands=[{"registers": ["r0"]}, {"registers": ["r0"]}, {"scalars": ["0x1"]}]),
    ])
    assert [(op, target) for _a, op, target in ops] == [("AND", 0x40), ("TOGGLE", 0x1)]
