"""Unit tests for find_in_function feature."""

from __future__ import annotations

from typing import List

import pytest

from bridge.features import search_function


class DummyClient:
    """Mock client for testing search_function feature."""

    def __init__(
        self,
        disasm_lines: List[str] | None = None,
        decompile_text: str | None = None,
    ) -> None:
        self._disasm_lines = disasm_lines or []
        self._decompile_text = decompile_text or ""

    def disassemble_function(self, address: int) -> List[str]:
        """Return mock disassembly lines."""
        return self._disasm_lines

    def decompile_function(self, address: int) -> str:
        """Return mock decompiled source."""
        return self._decompile_text


def test_find_in_disassembly_basic() -> None:
    """Test basic text search in disassembly."""
    client = DummyClient(
        disasm_lines=[
            "0x401000: 1234  MOV R0, #0x10",
            "0x401004: 5678  MOV R1, #0x251",
            "0x401008: 9abc  ADD R2, R0, R1",
            "0x40100c: def0  BL 0x401100",
        ]
    )

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="0x251",
        mode="disasm",
    )

    assert result["address"] == "0x00401000"
    assert result["query"] == "0x251"
    assert result["mode"] == "disasm"
    assert result["summary"]["total_matches"] == 1
    assert result["summary"]["disassembly_matches"] == 1
    assert result["summary"]["decompile_matches"] == 0

    matches = result["matches"]["disassembly"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 2
    assert matches[0]["address"] == "0x401004"
    assert "0x251" in matches[0]["matched_text"]


def test_find_in_decompile_basic() -> None:
    """Test basic text search in decompiled code."""
    decompile = """void init(void) {
    int offset;
    offset = 0x251;
    configure(offset);
    return;
}"""
    client = DummyClient(decompile_text=decompile)

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="0x251",
        mode="decompile",
    )

    assert result["summary"]["total_matches"] == 1
    assert result["summary"]["decompile_matches"] == 1
    assert result["summary"]["disassembly_matches"] == 0

    matches = result["matches"]["decompile"]
    assert len(matches) == 1
    assert matches[0]["line_number"] == 3
    assert "0x251" in matches[0]["matched_text"]


def test_find_in_both_modes() -> None:
    """Test searching in both disassembly and decompile."""
    client = DummyClient(
        disasm_lines=[
            "0x401000: 1234  MOV R0, #0x251",
            "0x401004: 5678  MOV R1, #0x10",
        ],
        decompile_text="void func(void) {\n    offset = 0x251;\n}",
    )

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="0x251",
        mode="both",
    )

    assert result["summary"]["total_matches"] == 2
    assert result["summary"]["disassembly_matches"] == 1
    assert result["summary"]["decompile_matches"] == 1
    assert len(result["matches"]["disassembly"]) == 1
    assert len(result["matches"]["decompile"]) == 1


def test_case_sensitive_search() -> None:
    """Test case-sensitive search."""
    client = DummyClient(
        disasm_lines=[
            "0x401000: 1234  MOV r0, #0x10",
            "0x401004: 5678  MOV R0, #0x20",
        ]
    )

    # Case-insensitive (default)
    result_insensitive = search_function.find_in_function(
        client,
        address=0x401000,
        query="r0",
        mode="disasm",
        case_sensitive=False,
    )
    assert result_insensitive["summary"]["total_matches"] == 2

    # Case-sensitive
    result_sensitive = search_function.find_in_function(
        client,
        address=0x401000,
        query="r0",
        mode="disasm",
        case_sensitive=True,
    )
    assert result_sensitive["summary"]["total_matches"] == 1


def test_regex_search() -> None:
    """Test regex pattern search."""
    client = DummyClient(
        disasm_lines=[
            "0x401000: 1234  BL 0x402000",
            "0x401004: 5678  MOV R0, #0x10",
            "0x401008: 9abc  BL 0x403000",
        ]
    )

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query=r"BL\s+0x[0-9A-Fa-f]+",
        mode="disasm",
        regex=True,
    )

    assert result["regex"] is True
    assert result["summary"]["total_matches"] == 2
    matches = result["matches"]["disassembly"]
    assert len(matches) == 2
    assert "BL" in matches[0]["matched_text"]
    assert "BL" in matches[1]["matched_text"]


def test_context_lines() -> None:
    """Test context line extraction."""
    client = DummyClient(
        disasm_lines=[
            "0x401000: 0000  NOP",
            "0x401004: 1111  NOP",
            "0x401008: 2222  MOV R0, #0x251",  # Match
            "0x40100c: 3333  NOP",
            "0x401010: 4444  NOP",
        ]
    )

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="0x251",
        mode="disasm",
        context_lines=2,
    )

    matches = result["matches"]["disassembly"]
    assert len(matches) == 1
    context = matches[0]["context"]

    assert len(context["before"]) == 2
    assert "0x401004" in context["before"][1]  # Most recent before line
    assert "0x401008" in context["match"]
    assert len(context["after"]) == 2
    assert "0x40100c" in context["after"][0]  # First after line


def test_limit_enforcement() -> None:
    """Test that limit parameter is enforced."""
    disasm_lines = [f"0x{0x401000 + i*4:x}: {i:04x}  MOV R{i % 8}, #0x251" for i in range(100)]
    client = DummyClient(disasm_lines=disasm_lines)

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="0x251",
        mode="disasm",
        limit=10,
    )

    assert result["summary"]["total_matches"] == 10
    assert len(result["matches"]["disassembly"]) == 10
    assert result["summary"]["truncated"] is True


def test_invalid_mode_raises_error() -> None:
    """Test that invalid mode raises ValueError."""
    client = DummyClient()

    with pytest.raises(ValueError, match="mode must be"):
        search_function.find_in_function(
            client,
            address=0x401000,
            query="test",
            mode="invalid",
        )


def test_empty_query_raises_error() -> None:
    """Test that empty query raises ValueError."""
    client = DummyClient()

    with pytest.raises(ValueError, match="query cannot be empty"):
        search_function.find_in_function(
            client,
            address=0x401000,
            query="",
        )


def test_invalid_regex_raises_error() -> None:
    """Test that invalid regex pattern raises ValueError."""
    client = DummyClient()

    with pytest.raises(ValueError, match="Invalid regex pattern"):
        search_function.find_in_function(
            client,
            address=0x401000,
            query="[invalid",
            regex=True,
        )


def test_no_matches_returns_empty() -> None:
    """Test that no matches returns empty results."""
    client = DummyClient(
        disasm_lines=["0x401000: 1234  MOV R0, #0x10"],
        decompile_text="void func(void) { return; }",
    )

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="nonexistent",
        mode="both",
    )

    assert result["summary"]["total_matches"] == 0
    assert len(result["matches"]["disassembly"]) == 0
    assert len(result["matches"]["decompile"]) == 0
    assert result["summary"]["truncated"] is False


def test_context_at_boundaries() -> None:
    """Test context extraction at start/end of function."""
    client = DummyClient(
        disasm_lines=[
            "0x401000: 0000  MOV R0, #0x251",  # Match at start
            "0x401004: 1111  NOP",
            "0x401008: 2222  MOV R1, #0x251",  # Match at end
        ]
    )

    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="0x251",
        mode="disasm",
        context_lines=5,  # Request more context than available
    )

    matches = result["matches"]["disassembly"]
    assert len(matches) == 2

    # First match: no lines before, lines after available
    assert len(matches[0]["context"]["before"]) == 0
    assert len(matches[0]["context"]["after"]) == 2

    # Last match: lines before available, no lines after
    assert len(matches[1]["context"]["before"]) == 2
    assert len(matches[1]["context"]["after"]) == 0


def test_special_regex_chars_escaped_in_literal_mode() -> None:
    """Test that special regex characters are escaped in literal search."""
    client = DummyClient(
        disasm_lines=[
            "0x401000: 1234  ADD R0, R1, #0x10",
            "0x401004: 5678  LDR R0, [R1, #0x4]",
        ]
    )

    # Should find literal "[R1" not treat [ as regex
    result = search_function.find_in_function(
        client,
        address=0x401000,
        query="[R1",
        mode="disasm",
        regex=False,
    )

    assert result["summary"]["total_matches"] == 1
    assert "[R1" in result["matches"]["disassembly"][0]["matched_text"]
