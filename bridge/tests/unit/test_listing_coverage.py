"""A listing that skips bytes has to say so.

Ghidra iterates defined instructions.  Ask ``disassemble_at`` for an address
inside an undefined region and it answers with the next defined instruction and
no marker, so the response looks exactly like one that starts where it was
asked.  The addresses in these tests are the ones the defect was found on: a
request at ``0x002818b0`` came back with instructions from ``0x00286d94``,
21732 bytes further on, and the reader had no way to tell.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from bridge.api.validators import validate_payload
from bridge.features import batch_ops, disasm, memory
from bridge.features.listing import coverage


@dataclass
class StubClient:
    """Returns pre-recorded listings and byte reads."""

    disasm_results: Dict[int, List[Dict[str, str]]] = field(default_factory=dict)
    read_results: Dict[int, bytes] = field(default_factory=dict)

    def disassemble_at(self, address: int, count: int) -> List[Dict[str, str]]:
        return self.disasm_results.get(address, [])

    def read_bytes(self, address: int, length: int) -> Optional[bytes]:
        return self.read_results.get(address)


def _instr(address: int, encoding: str = "00000000", text: str = "nop") -> Dict[str, str]:
    return {"address": f"0x{address:08x}", "bytes": encoding, "text": text}


# --- coverage() -------------------------------------------------------------


def test_contiguous_listing_reports_no_gap():
    entries = [_instr(0x1000), _instr(0x1004), _instr(0x1008)]
    report = coverage(entries, requested=0x1000)
    assert report == {
        "start": 0x1000,
        "skipped_bytes": 0,
        "gaps": [],
        "gap_bytes": 0,
    }


def test_leading_skip_is_measured_from_the_requested_address():
    """The defect as found: 0x002818b0 asked, 0x00286d94 answered."""

    entries = [_instr(0x00286D94, "F0472DE9", "stmdb sp!,{r4,r5}")]
    report = coverage(entries, requested=0x002818B0)
    assert report["start"] == 0x00286D94
    assert report["skipped_bytes"] == 21732
    assert report["gaps"] == []


def test_interior_gap_covers_the_undefined_bytes_only():
    """FUN_0025b338's constant pool: 0x25b878..0x25b89b sits inside the body."""

    entries = [
        _instr(0x0025B870, "0530A0E1", "mov r3,r5"),
        _instr(0x0025B874, "080000EA", "b 0x0025b89c"),
        _instr(0x0025B89C, "F0039DE5", "ldr r0,[sp,#0x3f0]"),
    ]
    report = coverage(entries, requested=0x0025B870)
    assert report["skipped_bytes"] == 0
    assert report["gaps"] == [
        {"start": 0x0025B878, "end": 0x0025B89B, "bytes": 36}
    ]
    assert report["gap_bytes"] == 36


def test_empty_listing_has_no_start():
    report = coverage([], requested=0x1000)
    assert report["start"] is None
    assert report["skipped_bytes"] == 0


def test_unknown_instruction_length_does_not_invent_a_gap():
    """An entry without parsable bytes breaks the chain rather than guessing."""

    entries = [
        {"address": "0x00001000", "bytes": "", "text": "nop"},
        _instr(0x1010),
    ]
    assert coverage(entries, requested=0x1000)["gaps"] == []


# --- disassemble_at ---------------------------------------------------------


def test_clean_listing_carries_neither_coverage_nor_note():
    """The ordinary response must not pay for the anomaly case."""

    client = StubClient(disasm_results={0x1000: [_instr(0x1000), _instr(0x1004)]})
    payload = disasm.disassemble_at(client, address=0x1000, count=2)
    assert "coverage" not in payload
    assert "method_note" not in payload


def test_skipped_region_is_reported_with_both_addresses():
    client = StubClient(
        disasm_results={
            0x002818B0: [_instr(0x00286D94, "F0472DE9", "stmdb sp!,{r4}")]
        }
    )
    payload = disasm.disassemble_at(client, address=0x002818B0, count=1)

    assert payload["coverage"] == {
        "requested_address": "0x002818b0",
        "start_address": "0x00286d94",
        "skipped_bytes": 21732,
    }
    note = payload["method_note"]
    assert "0x002818b0" in note and "0x00286d94" in note and "21732" in note

    valid, errors = validate_payload("disassemble_at.v1.json", payload)
    assert valid, errors


def test_interior_gap_is_listed_under_coverage():
    client = StubClient(
        disasm_results={
            0x0025B870: [
                _instr(0x0025B870, "0530A0E1", "mov r3,r5"),
                _instr(0x0025B874, "080000EA", "b 0x0025b89c"),
                _instr(0x0025B89C, "F0039DE5", "ldr r0,[sp,#0x3f0]"),
            ]
        }
    )
    payload = disasm.disassemble_at(client, address=0x0025B870, count=3)

    assert payload["coverage"]["skipped_bytes"] == 0
    assert payload["coverage"]["gaps"] == [
        {"start": "0x0025b878", "end": "0x0025b89b", "bytes": 36}
    ]
    assert "36 bytes" in payload["method_note"]

    valid, errors = validate_payload("disassemble_at.v1.json", payload)
    assert valid, errors


def test_empty_listing_says_nothing_is_defined_there():
    client = StubClient(disasm_results={})
    payload = disasm.disassemble_at(client, address=0x002818B0, count=8)

    assert payload["coverage"]["start_address"] is None
    assert "no instructions are defined" in payload["method_note"]

    valid, errors = validate_payload("disassemble_at.v1.json", payload)
    assert valid, errors


def test_text_format_keeps_the_coverage_report():
    """fmt='text' drops the objects, not the warning about them."""

    client = StubClient(
        disasm_results={0x002818B0: [_instr(0x00286D94, "F0472DE9", "stmdb")]}
    )
    payload = disasm.disassemble_at(client, address=0x002818B0, count=1, fmt="text")
    assert payload["lines"] == ["00286d94: F0472DE9 stmdb"]
    assert payload["coverage"]["skipped_bytes"] == 21732

    valid, errors = validate_payload("disassemble_at.v1.json", payload)
    assert valid, errors


# --- disassemble_batch ------------------------------------------------------


def test_batch_reports_only_the_addresses_that_need_it():
    client = StubClient(
        disasm_results={
            0x1000: [_instr(0x1000), _instr(0x1004)],
            0x002818B0: [_instr(0x00286D94, "F0472DE9", "stmdb")],
        }
    )
    payload = batch_ops.disassemble_batch(
        client, addresses=["0x1000", "0x002818b0"], count=2
    )

    assert list(payload["coverage"]) == ["0x002818b0"]
    assert payload["coverage"]["0x002818b0"]["skipped_bytes"] == 21732
    assert "0x002818b0" in payload["method_note"]

    valid, errors = validate_payload("disassemble_batch.v1.json", payload)
    assert valid, errors


def test_batch_without_anomalies_is_unchanged():
    client = StubClient(disasm_results={0x1000: [_instr(0x1000)]})
    payload = batch_ops.disassemble_batch(client, addresses=["0x1000"], count=1)
    assert set(payload) == {"addresses", "count", "results"}


def test_filtered_batch_does_not_report_the_filter_as_a_gap():
    """What the query removed is the caller's doing; only Ghidra's holes count."""

    client = StubClient(
        disasm_results={
            0x1000: [
                _instr(0x1000, "00000000", "nop"),
                _instr(0x1004, "01000000", "bl 0x2000"),
                _instr(0x1008, "00000000", "nop"),
            ]
        }
    )
    payload = batch_ops.disassemble_batch(
        client, addresses=["0x1000"], count=3, query="bl"
    )
    assert "coverage" not in payload
    assert payload["summary"]["returned"] == 1


# --- read_words / read_bytes ------------------------------------------------


def test_unreadable_words_are_named_as_such():
    """null is not zero, and an unmapped register must not read like one."""

    client = StubClient(read_results={})
    payload = batch_ops.read_words(client, 0xB1006000, 4)

    assert payload["words"] == [None, None, None, None]
    assert payload["unreadable_words"] == 4
    assert "not 'reads as zero'" in payload["method_note"]

    valid, errors = validate_payload("read_words.v1.json", payload)
    assert valid, errors


def test_partially_readable_words_report_the_count():
    client = StubClient(read_results={0x2AFB34: b"\x00\x80\x00\xb1"})
    payload = batch_ops.read_words(client, 0x2AFB34, 2)

    assert payload["words"] == ["0xb1008000", None]
    assert payload["unreadable_words"] == 1
    assert "1 of 2 words" in payload["method_note"]


def test_readable_words_carry_no_note():
    client = StubClient(read_results={0x2AFB34: b"\x00\x80\x00\xb1"})
    payload = batch_ops.read_words(client, 0x2AFB34, 1)
    assert "method_note" not in payload
    assert "unreadable_words" not in payload


def test_the_byte_note_does_not_speak_of_nulls():
    """read_bytes answers with a short buffer, not with nulls -- so must the note.

    It shared read_words' wording and told a caller who had received no nulls
    what the nulls meant. The point of a method_note is precision.
    """

    client = StubClient(read_results={})
    payload = memory.read_bytes(client, address=0x7D8, length=16)

    assert payload["length"] == 0
    note = payload["method_note"]
    assert "null" not in note.lower()
    assert "short rather than zero-filled" in note

    words = batch_ops.read_words(StubClient(read_results={}), 0x7D8, 4)
    assert "nulls here" in words["method_note"]


def test_short_read_bytes_reports_the_unmapped_tail():
    client = StubClient(read_results={0x1000: b"\x01\x02"})
    payload = memory.read_bytes(client, address=0x1000, length=4)

    assert payload["length"] == 2
    assert "2 of 4 bytes" in payload["method_note"]

    valid, errors = validate_payload("read_bytes.v1.json", payload)
    assert valid, errors


def test_full_read_bytes_carries_no_note():
    client = StubClient(read_results={0x1000: b"\x01\x02\x03\x04"})
    payload = memory.read_bytes(client, address=0x1000, length=4)
    assert "method_note" not in payload
