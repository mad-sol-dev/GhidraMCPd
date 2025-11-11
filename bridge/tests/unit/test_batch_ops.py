"""Unit tests for batch operations feature module."""
from dataclasses import dataclass
from typing import Dict, List, Optional

import pytest

from bridge.features import batch_ops
from bridge.ghidra.client import CursorPageResult


@dataclass
class StubClient:
    """Minimal stub client for testing batch operations."""
    
    disasm_results: Dict[int, List[Dict[str, str]]]
    read_results: Dict[int, bytes]
    scalar_results: Dict[str, object]
    
    def disassemble_at(self, address: int, count: int) -> List[Dict[str, str]]:
        """Return pre-configured disassembly results."""
        return self.disasm_results.get(address, [])
    
    def read_bytes(self, address: int, length: int) -> Optional[bytes]:
        """Return pre-configured byte data."""
        return self.read_results.get(address)
    
    def search_scalars(
        self,
        value: int,
        *,
        limit: int = 100,
        offset: int = 0,
        cursor: Optional[str] = None,
    ) -> CursorPageResult[Dict[str, object]]:
        """Return pre-configured scalar search results."""
        items = list(self.scalar_results.get("items", []))
        has_more = bool(self.scalar_results.get("has_more", False))
        resume = self.scalar_results.get("cursor") if has_more else None
        return CursorPageResult(items, has_more, resume)


def test_disassemble_batch_single_address():
    """Test batch disassembly with single address."""
    client = StubClient(
        disasm_results={
            0x1000: [
                {"address": "0x00001000", "bytes": "00 48", "text": "ldr r0, [r0]"},
                {"address": "0x00001002", "bytes": "70 47", "text": "bx lr"},
            ]
        },
        read_results={},
        scalar_results={},
    )
    
    result = batch_ops.disassemble_batch(
        client,
        addresses=["0x1000"],
        count=2,
    )
    
    assert result["addresses"] == ["0x1000"]
    assert result["count"] == 2
    assert "0x1000" in result["results"]
    assert len(result["results"]["0x1000"]) == 2


def test_disassemble_batch_multiple_addresses():
    """Test batch disassembly with multiple addresses."""
    client = StubClient(
        disasm_results={
            0x1000: [{"address": "0x00001000", "bytes": "00 48", "text": "ldr r0, [r0]"}],
            0x2000: [{"address": "0x00002000", "bytes": "01 48", "text": "ldr r1, [r1]"}],
        },
        read_results={},
        scalar_results={},
    )
    
    result = batch_ops.disassemble_batch(
        client,
        addresses=["0x1000", "0x2000"],
        count=1,
    )
    
    assert len(result["results"]) == 2
    assert "0x1000" in result["results"]
    assert "0x2000" in result["results"]


def test_read_words_single():
    """Test reading single 32-bit word."""
    client = StubClient(
        disasm_results={},
        read_results={
            0x1000: b'\x00\x20\x00\xB8',  # 0xB8002000 little-endian
        },
        scalar_results={},
    )
    
    result = batch_ops.read_words(
        client,
        address=0x1000,
        count=1,
    )
    
    assert result["address"] == "0x00001000"
    assert result["count"] == 1
    assert result["words"] == [0xB8002000]


def test_read_words_multiple():
    """Test reading multiple 32-bit words."""
    client = StubClient(
        disasm_results={},
        read_results={
            0x1000: b'\x01\x00\x00\x00',  # 1
            0x1004: b'\x02\x00\x00\x00',  # 2
            0x1008: b'\x03\x00\x00\x00',  # 3
        },
        scalar_results={},
    )
    
    result = batch_ops.read_words(
        client,
        address=0x1000,
        count=3,
    )
    
    assert result["count"] == 3
    assert result["words"] == [1, 2, 3]


def test_read_words_handles_none():
    """Test that read_words handles unreadable memory."""
    client = StubClient(
        disasm_results={},
        read_results={
            0x1000: b'\x01\x00\x00\x00',
            # 0x1004 missing - simulates unreadable memory
        },
        scalar_results={},
    )
    
    result = batch_ops.read_words(
        client,
        address=0x1000,
        count=2,
    )
    
    assert result["words"][0] == 1
    assert result["words"][1] is None


def test_search_scalars_with_context_preserves_pagination(monkeypatch):
    """search_scalars_with_context should surface pagination metadata."""

    client = StubClient(
        disasm_results={
            0x0FFC: [
                {"address": "0x00000FFC", "bytes": "00 00", "text": "nop"},
                {"address": "0x00001000", "bytes": "00 48", "text": "ldr r0, [r0]"},
                {"address": "0x00001004", "bytes": "70 47", "text": "bx lr"},
            ]
        },
        read_results={},
        scalar_results={},
    )

    def fake_search_scalars(
        client_arg,
        *,
        value,
        query,
        limit,
        page,
        cursor=None,
        resume_cursor=None,
    ):
        assert client_arg is client
        assert limit == 1
        assert page == 1
        return {
            "items": [
                {"address": "0x00001000", "function": "handler", "context": "LDR"},
                {"address": "0x00002000", "function": "other", "context": "MOV"},
            ],
            "total": 12,
            "has_more": True,
            "resume_cursor": "cursor-1",
        }

    monkeypatch.setattr(batch_ops.scalars, "search_scalars", fake_search_scalars)

    result = batch_ops.search_scalars_with_context(
        client,
        value=0x1,
        context_lines=1,
        limit=1,
    )

    assert result["total"] == 12
    assert result["has_more"] is True
    assert result["resume_cursor"] == "cursor-1"
    assert len(result["matches"]) == 1
    assert result["matches"][0]["address"] == "0x00001000"
