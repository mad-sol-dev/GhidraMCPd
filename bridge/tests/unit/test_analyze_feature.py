from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from bridge.features import analyze
from bridge.utils.logging import SafetyLimitExceeded
from bridge.tests.listing_records import insn, listing


class StubClient:
    def __init__(self) -> None:
        self._strings = {0x00003000: "hello world"}

    def get_function_by_address(self, address: int) -> Optional[Dict[str, object]]:
        return {
            "name": "sub_1000",
            "entry_point": "0x00001000",
            "body": "0x00001000 - 0x0000100f",
            "comment": "init",
            "signature": "int sub_1000(void)",
        }

    def disassemble_function_structured(self, address: int) -> Dict[str, object]:
        # The shapes the plugin returns on the reference program: a call
        # carries an UNCONDITIONAL_CALL reference, and a string address is
        # loaded with adr, which Ghidra references as PARAM (0x002af9c4).
        return listing(address, [
            insn(0x1000, "push", text="push {lr}"),
            insn(0x1004, "bl", text="bl 0x00001500", flow="call",
                 ref=(0x1500, "UNCONDITIONAL_CALL", True)),
            insn(0x1008, "adr", text="adr r0,0x3000", ref=(0x3000, "PARAM", True)),
            insn(0x100C, "bl", text="bl 0x00002000", flow="call",
                 ref=(0x2000, "UNCONDITIONAL_CALL", True)),
        ])

    def get_xrefs_to(self, address: int, *, limit: int = 50):
        return [
            {"addr": 0x00002010, "context": "00002010 in caller_one [CALL]"},
            {"addr": 0x00002020, "context": "00002020 in caller_two [CALL]"},
        ][:limit]

    def decompile_function(self, address: int) -> Optional[str]:
        return "int sub_1000(void) {\n    return 0;\n}"

    def read_cstring(self, address: int, *, max_len: int = 256) -> Optional[str]:
        return self._strings.get(address)


def test_analyze_function_complete_full_payload() -> None:
    """All seven fields, asked for explicitly.

    They are no longer the default -- see
    test_analyze_default_omits_disasm_and_decompile -- so this names them.
    """

    client = StubClient()
    payload = analyze.analyze_function_complete(
        client,
        address=0x00001004,
        fields=list(analyze._ALLOWED_FIELDS),
    )

    assert payload["address"] == "0x00001004"
    assert payload["function"]["name"] == "sub_1000"
    assert payload["disasm"]["window"]
    assert payload["decompile"]["snippet"].startswith("int sub_1000")
    assert payload["xrefs"]["summary"] == {
        "inbound": 2, "outbound": 2, "inbound_truncated": False, "outbound_truncated": False,
    }
    assert payload["callgraph"]["callees"]
    assert payload["strings"]["items"] == [
        {
            "address": "0x00003000",
            "source": "0x00001008",
            "literal": "hello world",
            "length": 11,
        }
    ]
    assert payload["features"]["instruction_count"] == 4
    assert payload["meta"]["fields"] == sorted(
        ["function", "disasm", "decompile", "xrefs", "callgraph", "strings", "constants", "features"]
    )


def test_analyze_default_omits_disasm_and_decompile() -> None:
    """An unparameterised call answers "is this the right function?".

    disasm and decompile are 58% of a full dossier and are available on better
    terms from disassemble_at and find_in_function, so the default leaves them
    out rather than making every caller pay for them.
    """

    client = StubClient()
    payload = analyze.analyze_function_complete(client, address=0x00001004)

    assert payload["meta"]["fields"] == sorted(
        ["function", "xrefs", "strings", "constants", "features"]
    )
    assert "disasm" not in payload
    assert "decompile" not in payload

    # The cheap fields that make the dossier worth calling are still there.
    assert payload["function"]["name"] == "sub_1000"
    assert payload["xrefs"]["summary"] == {
        "inbound": 2, "outbound": 2, "inbound_truncated": False, "outbound_truncated": False,
    }
    assert payload["features"]["instruction_count"] == 4


def test_naming_a_field_replaces_the_default_rather_than_adding_to_it() -> None:
    client = StubClient()
    payload = analyze.analyze_function_complete(
        client, address=0x00001004, fields=["disasm"]
    )
    assert payload["meta"]["fields"] == ["disasm"]
    assert "function" not in payload


def test_analyze_function_respects_field_filter() -> None:
    client = StubClient()
    payload = analyze.analyze_function_complete(
        client,
        address=0x00001000,
        fields=["function", "strings"],
        max_result_tokens=2048,
    )

    assert "function" in payload
    assert "strings" in payload
    assert "disasm" not in payload
    assert payload["meta"]["max_result_tokens"] == 2048
    assert payload["meta"]["fields"] == ["function", "strings"]


def test_analyze_function_rejects_invalid_field() -> None:
    client = StubClient()
    with pytest.raises(ValueError):
        analyze.analyze_function_complete(client, address=0x1000, fields=["invalid"])


def test_constants_are_the_pool_words_a_function_loads():
    """ANALYZE-POOL-CONSTANTS, with the shapes of 0x002AF9C0."""

    def load(address, pool, word):
        record = insn(address, "ldr", text=f"ldr r0,[0x{pool:x}]", ref=(pool, "READ", True))
        record["refs"][0]["word"] = f"0x{word:08x}"
        return record

    entries = analyze._listing_entries(type("C", (), {
        "disassemble_function_structured": lambda self, a: listing(a, [
            load(0x2AFA38, 0x2AFB40, 0xB1008704),
            insn(0x2AFA3C, "ldr", ref=(0xB1008704, "READ", False)),  # MMIO, no word
            load(0x2AFA50, 0x2AFB44, 0x00008190),
            load(0x2AFAD0, 0x2AFB40, 0xB1008704),
            insn(0x2AFB0C, "ldmia", flow="return"),
        ]),
        "last_error": None,
    })(), 0x2AF9C0)

    result = analyze._collect_constants(entries, limit=8)

    assert result == {
        "items": [
            {"value": "0xb1008704", "pool": "0x002afb40", "source": "0x002afa38", "loads": 2},
            {"value": "0x00008190", "pool": "0x002afb44", "source": "0x002afa50", "loads": 1},
        ],
        "limit": 8,
        "total": 2,
    }
    assert analyze._collect_constants(entries, limit=1)["total"] == 2


def test_xrefs_cut_at_their_limit_say_so() -> None:
    """Two callers, two calls, limit 1 each: the counts are not all there is."""

    payload = analyze.analyze_function_complete(
        StubClient(),
        address=0x00001004,
        fields=["xrefs", "features"],
        options={"xrefs": {"inbound_limit": 1, "outbound_limit": 1}},
    )

    assert payload["xrefs"]["summary"] == {
        "inbound": 1, "outbound": 1, "inbound_truncated": True, "outbound_truncated": True,
    }
    notes = payload["features"]["notes"]
    assert any("inbound_limit 1" in note for note in notes)
    assert any("outbound_limit 1" in note for note in notes)
    assert payload["meta"]["truncated"] is True


def test_xrefs_exactly_at_their_limit_are_complete() -> None:
    """Asking one more than shown tells a full list from a cut one."""

    payload = analyze.analyze_function_complete(
        StubClient(),
        address=0x00001004,
        fields=["xrefs", "features"],
        options={"xrefs": {"inbound_limit": 2, "outbound_limit": 2}},
    )

    summary = payload["xrefs"]["summary"]
    assert (summary["inbound_truncated"], summary["outbound_truncated"]) == (False, False)
    assert payload["features"]["notes"] == []
    assert payload["meta"]["truncated"] is False


# --- max_result_tokens is a ceiling, not a label -----------------------------


class LongFunction(StubClient):
    """40 instructions and a 60-line decompilation: big enough to need trimming."""

    def disassemble_function_structured(self, address: int) -> Dict[str, object]:
        return listing(address, [
            insn(0x1000 + 4 * i, "mov", text=f"mov r{i % 8},#0x{i:x}") for i in range(40)
        ])

    def decompile_function(self, address: int) -> Optional[str]:
        return "\n".join(f"  uVar{i} = FUN_{i:08x}(param_1, {i});" for i in range(60))


def _dossier(budget: Optional[int]) -> Dict[str, object]:
    return analyze.analyze_function_complete(
        LongFunction(),
        address=0x1000 + 4 * 20,
        fields=["function", "disasm", "decompile"],
        max_result_tokens=budget,
        options={"disasm": {"before": 16, "after": 16}, "decompile": {"max_lines": 500}},
    )


def test_without_a_budget_nothing_is_trimmed() -> None:
    payload = _dossier(None)

    assert len(payload["disasm"]["window"]) == 33
    assert payload["decompile"]["snippet"].count("\n") == 59
    assert payload["meta"]["truncated"] is False


def test_a_budget_trims_disasm_and_decompile_to_fit() -> None:
    full = _dossier(None)["meta"]["estimate_tokens"]
    budget = full // 2

    payload = _dossier(budget)

    assert payload["meta"]["estimate_tokens"] <= budget
    assert payload["meta"]["truncated"] is True
    window = payload["disasm"]["window"]
    assert 0 < len(window) < 33 and payload["disasm"]["truncated"] is True
    # cut around the target, which stays in the window and is pointed at
    assert window[payload["disasm"]["center_index"]]["is_target"] is True
    snippet = payload["decompile"]["snippet"]
    assert payload["decompile"]["truncated"] is True and payload["decompile"]["lines"] == 60
    # whole lines from the start: no line is cut in the middle
    assert all(line.endswith(";") for line in snippet.split("\n"))
    assert snippet.startswith("  uVar0 = ")


def test_a_budget_that_already_fits_changes_nothing() -> None:
    full = _dossier(None)
    payload = _dossier(full["meta"]["estimate_tokens"])

    assert payload["disasm"] == full["disasm"]
    assert payload["decompile"] == full["decompile"]
    assert payload["meta"]["truncated"] is False


def test_a_budget_too_small_for_the_rest_is_refused_not_ignored() -> None:
    """The function and meta alone exceed 10 tokens; trimming cannot help."""

    with pytest.raises(SafetyLimitExceeded, match="even without disasm and decompile"):
        _dossier(10)
