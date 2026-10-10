import pytest

from bridge.features.listing import ListingUnavailable
from bridge.features.strings import xrefs_compact
from bridge.ghidra.client import STRUCTURED_LISTING_UNSUPPORTED
from bridge.tests.listing_records import insn, listing


def _call(address, target):
    record = insn(address, "bl", text=f"bl 0x{target:08x}", flow="call",
                  ref=(target, "UNCONDITIONAL_CALL", True))
    record["targets"] = [f"0x{target:08x}"]
    return record


class DummyClient:
    def __init__(self, xrefs, listings, *, unsupported=False):
        self._xrefs = xrefs
        self._listings = listings
        self._unsupported = unsupported
        self.disasm_calls = []
        self.last_limit = None
        self.last_error = None

    def get_xrefs_to(self, address, *, limit=50):
        self.last_limit = limit
        return list(self._xrefs)

    def disassemble_function_structured(self, address):
        self.disasm_calls.append(address)
        if self._unsupported:
            self.last_error = type("E", (), {"reason": STRUCTURED_LISTING_UNSUPPORTED})()
            return None
        if address not in self._listings:
            self.last_error = type("E", (), {"reason": "no function found"})()
            return None
        return listing(address, self._listings[address])


def test_a_direct_reference_gives_context_register_and_call():
    client = DummyClient(
        xrefs=[{"addr": 0x401000, "context": "From 0x401000 [PARAM]"}],
        listings={0x401000: [
            insn(0x401000, "adr", registers=("r1",), text="adr r1,0x1000", ref=(0x1000, "PARAM", True)),
            _call(0x401004, 0x402000),
        ]},
    )

    payload = xrefs_compact(client, string_addr=0x1000, limit=5)

    assert payload["string"] == "0x00001000"
    assert payload["count"] == 1
    caller = payload["callers"][0]
    assert caller["context"] == "00401000: adr r1,0x1000 | 00401004: bl 0x00402000"
    assert caller["arg_index"] == 1
    assert caller["hint"] == "0x00402000"


def test_a_reference_from_a_pool_word_finds_the_load():
    """The ARM case: the xref belongs to the pool slot, not to the ldr.

    The text scan looked for the pool address as an instruction, found none,
    and fell back to the raw xref context.
    """

    client = DummyClient(
        xrefs=[{"addr": 0x401100, "context": "From 0x401100 [DATA]"}],
        listings={0x401100: [
            insn(0x401000, "ldr", registers=("r0",), text="ldr r0,[0x401100]",
                 ref=(0x401100, "READ", True)),
            _call(0x401004, 0x402000),
        ]},
    )

    caller = xrefs_compact(client, string_addr=0x1000, limit=5)["callers"][0]

    assert caller["context"] == "00401000: ldr r0,[0x401100] | 00401004: bl 0x00402000"
    assert caller["arg_index"] == 0


def test_respects_limit():
    xrefs = [{"addr": a, "context": "hit"} for a in (0x500000, 0x500010, 0x500020)]
    listings = {a: [insn(a, "adr", ref=(0x2000, "PARAM", True))] for a in (0x500000, 0x500010, 0x500020)}
    client = DummyClient(xrefs, listings)

    payload = xrefs_compact(client, string_addr=0x2000, limit=2)

    assert payload["count"] == 2
    assert payload["truncated"] is True
    assert len(payload["callers"]) == 2
    assert client.last_limit == 3
    assert client.disasm_calls == [0x500000, 0x500010]


def test_a_reference_outside_any_function_keeps_the_xref_context():
    client = DummyClient(xrefs=[{"addr": 0x600000, "context": "  Raw context snippet  "}], listings={})

    caller = xrefs_compact(client, string_addr=0x3000, limit=3)["callers"][0]

    assert caller["context"] == "Raw context snippet"
    assert "arg_index" not in caller
    assert "hint" not in caller


def test_a_plugin_without_structured_listing_is_reported_not_hidden():
    client = DummyClient(xrefs=[{"addr": 0x600000, "context": "x"}], listings={}, unsupported=True)

    with pytest.raises(ListingUnavailable, match="without JSON"):
        xrefs_compact(client, string_addr=0x3000, limit=3)
