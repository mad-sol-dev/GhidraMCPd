"""IMAGE-BASE-STALE: project_info says when its figures lie outside the map."""

from bridge.features.project_layout import layout_notes

ZK = {  # the reference program, as the plugin reports it
    "image_base": "0x00000000",
    "entry_points": [f"0x{a:08x}" for a in (*range(0, 0x20, 4), *range(0xFFFF0000, 0xFFFF0020, 4))],
    "memory_blocks": [{"name": "flash", "start": "0x00200000", "end": "0x0047522b"}],
}


def test_the_reference_program_gets_both_notes():
    notes = layout_notes(ZK)
    assert notes[0].startswith("image_base 0x00000000 lies in no memory block; the lowest block, flash, starts at 0x00200000")
    assert notes[1].startswith("16 of 16 entry points lie in no memory block (0x00000000-0x0000001c, 0xffff0000-0xffff001c)")


def test_a_consistent_program_gets_none():
    info = {
        "image_base": "0x00200000",
        "entry_points": ["0x00200000", "0x00200100"],
        "memory_blocks": [{"name": "flash", "start": "0x00200000", "end": "0x0047522b"}],
    }
    assert layout_notes(info) == []


def test_only_the_unmapped_entries_are_counted():
    info = dict(ZK, image_base="0x00200000", entry_points=["0x00200000", "0xffff0000"])
    assert layout_notes(info) == [
        "1 of 2 entry points lie in no memory block (0xffff0000); there are no bytes behind them in this program."
    ]


def test_no_blocks_means_no_claim():
    assert layout_notes({"image_base": "0x0", "entry_points": ["0x0"], "memory_blocks": []}) == []
