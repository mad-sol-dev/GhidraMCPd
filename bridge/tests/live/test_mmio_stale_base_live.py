"""mmio_annotate_compact against the reference program: MMIO-STALE-BASE.

The text classifier kept the base from ``mov rX,#0xb0000000`` after the
register was reloaded from the constant pool, and reported five register
addresses on 0x002AF9C0 that the program never touches.  The program's own
comments name the right ones (USBD_BA+0x704, USBD_BA+0x58).
"""
from __future__ import annotations

import pytest

from bridge.features import mmio

FUNCTION = 0x002AF9C0

#: instruction -> (op, address); the text classifier's answer in the comment.
CORRECTED = {
    0x002AFA3C: ("READ", 0xB1008704),   # was 0xb0000000
    0x002AFA6C: ("WRITE", 0x000082B4),  # was 0xb0000004
    0x002AFA90: ("WRITE", 0x000082B4),  # was 0xb0000004
    0x002AFAD0: ("WRITE", 0xB1008704),  # was 0xb0000000
    0x002AFADC: ("WRITE", 0xB1008058),  # was 0xb0000058
}


@pytest.fixture(scope="module")
def operations(client):
    payload = mmio.annotate(client, function_addr=FUNCTION, max_samples=256)
    return {int(s["addr"], 16): (s["op"], int(s["target"], 16)) for s in payload["samples"]}, payload


def test_the_five_stale_bases_are_corrected(operations):
    found, _payload = operations
    for addr, expected in CORRECTED.items():
        assert found.get(addr) == expected, f"0x{addr:08x}"


def test_every_access_matches_a_ghidra_reference(client, operations):
    """The classifier adds nothing Ghidra does not hold, and drops nothing."""

    found, payload = operations
    listing = client.disassemble_function_structured(FUNCTION)
    expected = {}
    for insn in listing["instructions"]:
        for ref in insn["refs"]:
            if ref["type"] in ("READ", "WRITE") and not ref["mapped"] and "space" not in ref:
                expected[int(insn["address"], 16)] = (ref["type"], int(ref["to"], 16))
    accesses = {addr: v for addr, v in found.items() if v[0] in ("READ", "WRITE")}
    assert accesses == expected
    assert len(accesses) == payload["reads"] + payload["writes"] == 28
