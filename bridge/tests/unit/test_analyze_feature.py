from __future__ import annotations

from typing import Dict, List, Optional

import pytest

from bridge.features import analyze


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

    def disassemble_function(self, address: int) -> List[str]:
        return [
            "00001000: AABB PUSH {lr}",
            "00001004: 0011 BL callee_func",
            "00001008: 2233 LDR R0, =0x00003000",
            "0000100C: 4455 BL 0x00002000",
        ]

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
    client = StubClient()
    payload = analyze.analyze_function_complete(client, address=0x00001004)

    assert payload["address"] == "0x00001004"
    assert payload["function"]["name"] == "sub_1000"
    assert payload["disasm"]["window"]
    assert payload["decompile"]["snippet"].startswith("int sub_1000")
    assert payload["xrefs"]["summary"] == {"inbound": 2, "outbound": 2}
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
        ["function", "disasm", "decompile", "xrefs", "callgraph", "strings", "features"]
    )


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
