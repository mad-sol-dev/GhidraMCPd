from bridge.features.strings import xrefs_compact
from bridge.tests.listing_records import insn, listing


class RecordingClient:
    def __init__(self, xrefs, disassembly_map):
        self._xrefs = list(xrefs)
        self._disassembly_map = dict(disassembly_map)
        self.last_limit = None
        self.disasm_calls = []
        self.last_error = None

    def get_xrefs_to(self, address, *, limit=50):
        self.last_limit = limit
        return list(self._xrefs)

    def disassemble_function_structured(self, address):
        self.disasm_calls.append(address)
        return listing(address, [insn(address, "mov")]) if address in self._disassembly_map else None


def test_xrefs_compact_records_limit_and_disassembly_calls():
    xrefs = [
        {"addr": 0x401000, "context": "call site"},
        {"addr": 0x401010, "context": "another"},
    ]
    disassembly_map = {
        0x401000: [
            "00401000: MOV R0, #0x00001000",
            "00401004: BL puts",
        ],
        0x401010: [
            "00401010: MOV R1, #0x00001000",
            "00401014: BL printf",
        ],
    }
    client = RecordingClient(xrefs, disassembly_map)

    payload = xrefs_compact(client, string_addr=0x1000)

    assert payload["count"] == len(xrefs)
    assert payload["truncated"] is False
    # Stage 3 lowered the default page size to 20; one more tells a cut list.
    assert client.last_limit == 21
    assert client.disasm_calls == [0x401000, 0x401010]


def test_xrefs_compact_limits_processed_callers():
    xrefs = [
        {"addr": 0x500000, "context": "first"},
        {"addr": 0x500010, "context": "second"},
        {"addr": 0x500020, "context": "third"},
    ]
    disassembly_map = {
        0x500000: ["00500000: MOV R0, #0x0", "00500004: BL puts"],
        0x500010: ["00500010: MOV R1, #0x0", "00500014: BL puts"],
        0x500020: ["00500020: MOV R2, #0x0", "00500024: BL puts"],
    }
    client = RecordingClient(xrefs, disassembly_map)

    payload = xrefs_compact(client, string_addr=0x2000, limit=2)

    assert payload["count"] == 2
    assert payload["truncated"] is True
    assert len(payload["callers"]) == 2
    assert client.last_limit == 3
    assert client.disasm_calls == [0x500000, 0x500010]
