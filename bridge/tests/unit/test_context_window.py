"""Context windows are centred on the hit, whatever the instruction sizes.

The windows of search_scalars_with_context and search_functions(context_lines)
were 2n+1 instructions from ``hit - 4n``: centred only for 4-byte code with no
data in front.  The stub lists instructions the way the plugin does -- from the
first defined instruction at or after the start -- and refuses a start outside
memory (UNMAPPED, API 3), which the client reads as an empty listing.
"""
from __future__ import annotations

from typing import Dict, List

from bridge.features.listing import context_window


class Listing:
    def __init__(self, addresses: List[int], *, block_start: int = 0) -> None:
        self.addresses = sorted(addresses)
        self.block_start = block_start
        self.calls: List[tuple] = []

    def disassemble_at(self, address: int, count: int) -> List[Dict[str, str]]:
        self.calls.append((address, count))
        if address < self.block_start:
            return []  # UNMAPPED
        after = [a for a in self.addresses if a >= address][:count]
        return [{"address": f"0x{a:08x}", "bytes": "", "text": f"insn_{a:x}"} for a in after]


def _addresses(window) -> List[int]:
    return [int(entry["address"], 16) for entry in window]


def test_four_byte_code_is_unchanged():
    code = Listing([0x1000 + 4 * i for i in range(40)])

    assert _addresses(context_window(code, 0x1040, 2)) == [0x1038, 0x103C, 0x1040, 0x1044, 0x1048]


def test_thumb_code_is_centred():
    """2-byte instructions: hit - 4n holds 2n instructions before the hit."""

    code = Listing([0x1000 + 2 * i for i in range(80)])

    window = _addresses(context_window(code, 0x1040, 3))

    assert window == [0x103A, 0x103C, 0x103E, 0x1040, 0x1042, 0x1044, 0x1046]


def test_data_in_front_still_gives_n_after():
    """A literal pool before the hit: fewer before is all there is, but n after."""

    code = Listing([0x1030, 0x1034] + [0x1040 + 4 * i for i in range(10)])

    window = _addresses(context_window(code, 0x1040, 4))

    assert window == [0x1030, 0x1034, 0x1040, 0x1044, 0x1048, 0x104C, 0x1050]


def test_short_x86_instructions_keep_the_hit_inside():
    """1-byte instructions: 4n bytes hold 4n of them; 2n+1 from there missed the hit."""

    code = Listing([0x1000 + i for i in range(100)])

    window = _addresses(context_window(code, 0x1020, 2))

    assert window == [0x101E, 0x101F, 0x1020, 0x1021, 0x1022]


def test_a_start_before_the_block_falls_back_to_the_hit():
    code = Listing([0x200000 + 4 * i for i in range(20)], block_start=0x200000)

    window = _addresses(context_window(code, 0x200004, 4))

    # hit - 16 lies before the block; the window starts at the hit instead of
    # coming back empty, and still has n after it
    assert window == [0x200004, 0x200008, 0x20000C, 0x200010, 0x200014]


def test_a_hit_that_is_no_instruction_start_keeps_the_old_window():
    code = Listing([0x1000 + 4 * i for i in range(40)])

    window = _addresses(context_window(code, 0x1041, 1))

    assert len(window) == 3
