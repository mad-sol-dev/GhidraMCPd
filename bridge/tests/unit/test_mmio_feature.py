import pytest

from bridge.features import mmio


def _insn(address, mnemonic, *, ref=None, imm=None, registers=("r0",)):
    operands = [{"registers": list(registers)}]
    if imm is not None:
        operands.append({"scalars": [imm]})
    refs = []
    if ref is not None:
        to, kind, mapped = ref
        refs.append({"to": to, "type": kind, "op": 1, "mapped": mapped})
    return {"address": address, "mnemonic": mnemonic, "operands": operands, "refs": refs}


class DummyClient:
    def __init__(self, instructions, *, comment_success=True):
        self._instructions = list(instructions)
        self.comment_success = comment_success
        self.requested = []
        self.comments = []
        self.last_error = None

    def disassemble_function_structured(self, address):
        self.requested.append(address)
        return {"function": f"0x{address:08x}", "instructions": list(self._instructions)}

    def set_disassembly_comment(self, address, comment):
        self.comments.append((address, comment))
        return self.comment_success


def test_mmio_annotate_collects_counts_and_samples():
    client = DummyClient([
        _insn("0x00400000", "ldr", ref=("0xb0004000", "READ", False)),
        _insn("0x00400004", "str", ref=("0xb0005000", "WRITE", False)),
        _insn("0x00400008", "orr", imm="0x1"),
        _insn("0x0040000c", "and", imm="0xfffffffe"),
        _insn("0x00400010", "eor", imm="0x1"),
        _insn("0x00400014", "nop"),
    ])

    payload = mmio.annotate(client, function_addr=0x400000)

    assert payload["function"] == "0x00400000"
    assert payload["reads"] == 1
    assert payload["writes"] == 1
    assert payload["bitwise_or"] == 1
    assert payload["bitwise_and"] == 1
    assert payload["toggles"] == 1
    assert payload["annotated"] == 0
    assert [sample["op"] for sample in payload["samples"]] == ["READ", "WRITE", "OR", "AND", "TOGGLE"]
    assert client.requested == [0x400000]
    assert "dry-run" in " ".join(payload["notes"])
    assert "writes disabled" in " ".join(payload["notes"])


@pytest.mark.parametrize("success", [True, False])
def test_mmio_annotate_sets_comments_when_writes_enabled(success):
    client = DummyClient(
        [
            _insn("0x00410000", "ldr", ref=("0xb0004100", "READ", False)),
            _insn("0x00410004", "str", ref=("0xb0004100", "WRITE", False)),
            _insn("0x00410008", "orr", imm="0x2"),
        ],
        comment_success=success,
    )

    payload = mmio.annotate(client, function_addr=0x410000, dry_run=False, writes_enabled=True, max_samples=2)

    assert payload["annotated"] == (2 if success else 0)
    assert len(client.comments) == 2
    assert client.comments[0] == (0x00410000, "MMIO read target 0xb0004100")
    assert payload["notes"] == []


def test_mmio_annotate_skips_block_transfer_instructions():
    client = DummyClient([
        _insn("0x00420000", "ldmia", registers=("r0",)),
        _insn("0x00420004", "stmia", registers=("r3",)),
        _insn("0x00420008", "ldr", ref=("0xb0004200", "READ", False)),
    ])

    payload = mmio.annotate(client, function_addr=0x420000)

    assert payload["reads"] == 1
    assert payload["writes"] == 0
    assert payload["skipped"] == 0
    assert [sample["addr"] for sample in payload["samples"]] == ["0x00420008"]


def test_mmio_annotate_counts_byte_halfword_and_conditional_forms():
    """The text classifier ignored ldrb/strh; a byte write to a register is I/O."""

    client = DummyClient([
        _insn("0x00425000", "ldrb", ref=("0xb0000001", "READ", False)),
        _insn("0x00425004", "strh", ref=("0xb0000002", "WRITE", False)),
        _insn("0x00425008", "ldrne", ref=("0xb0000004", "READ", False)),
        _insn("0x0042500c", "strcs", ref=("0xb0000008", "WRITE", False)),
    ])

    payload = mmio.annotate(client, function_addr=0x425000)

    assert payload["reads"] == 2
    assert payload["writes"] == 2
    targets = {s["addr"]: s["target"] for s in payload["samples"]}
    assert targets == {
        "0x00425000": "0xb0000001",
        "0x00425004": "0xb0000002",
        "0x00425008": "0xb0000004",
        "0x0042500c": "0xb0000008",
    }


def test_a_literal_load_is_a_constant_not_a_read_of_its_value():
    """``ldr r0,=0x50000000`` reads the pool, not 0x50000000.

    The text classifier reported a READ at the loaded value.
    """

    client = DummyClient([
        _insn("0x00430000", "ldr", ref=("0x00430100", "READ", True)),
        _insn("0x00430004", "str", ref=("0xb0000100", "WRITE", False)),
        _insn("0x0043000c", "orr", imm="0x8"),
    ])

    payload = mmio.annotate(client, function_addr=0x430000)

    samples = {sample["addr"]: sample for sample in payload["samples"]}
    assert "0x00430000" not in samples
    assert samples["0x00430004"]["target"] == "0xb0000100"
    assert samples["0x0043000c"]["target"] == "0x00000008"
    assert payload["skipped"] == 0


def test_mmio_annotate_notes_skipped_accesses():
    client = DummyClient([
        _insn("0x00435000", "ldr", registers=("r0", "r1")),
        _insn("0x00435004", "str", registers=("r0", "r2")),
        _insn("0x00435008", "nop"),
    ])

    payload = mmio.annotate(client, function_addr=0x435000)

    assert payload["reads"] == 0
    assert payload["writes"] == 0
    assert payload["samples"] == []
    assert payload["skipped"] == 2
    notes = " ".join(payload["notes"]).lower()
    assert "could not be placed" in notes
    assert "not counted above" in notes


def test_a_plugin_without_structured_listing_is_reported_not_emptied():
    class OldPlugin(DummyClient):
        def disassemble_function_structured(self, address):
            self.last_error = type("E", (), {"reason": "the Ghidra plugin answered without JSON"})()
            return None

    with pytest.raises(mmio.ListingUnavailable, match="without JSON"):
        mmio.annotate(OldPlugin([]), function_addr=0x400000)
