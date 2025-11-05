"""Integration tests for batch operation MCP tools."""
from typing import Dict, List, Optional

import pytest

from bridge.api.tools import register_tools
from mcp.server.fastmcp import FastMCP


class MockGhidraClient:
    """Mock client for integration testing."""
    
    def disassemble_at(self, address: int, count: int) -> List[Dict[str, str]]:
        """Return mock disassembly."""
        return [
            {"address": f"0x{address:08x}", "bytes": "00 48", "text": "ldr r0, [r0]"},
        ]
    
    def read_bytes(self, address: int, length: int) -> Optional[bytes]:
        """Return mock bytes."""
        if length == 4:
            return b'\x00\x20\x00\xB8'
        return None
    
    def search_scalars(self, value: int) -> List[Dict[str, object]]:
        """Return mock scalar results."""
        return []
    
    def close(self) -> None:
        """No-op close."""
        pass


def test_disassemble_batch_tool_registration():
    """Test that disassemble_batch tool is properly registered."""
    server = FastMCP("test")
    register_tools(server, client_factory=lambda: MockGhidraClient(), enable_writes=False)
    
    tool_names = [tool.name for tool in server._tool_manager._tools.values()]
    assert "disassemble_batch" in tool_names


def test_read_words_tool_registration():
    """Test that read_words tool is properly registered."""
    server = FastMCP("test")
    register_tools(server, client_factory=lambda: MockGhidraClient(), enable_writes=False)
    
    tool_names = [tool.name for tool in server._tool_manager._tools.values()]
    assert "read_words" in tool_names


def test_search_scalars_with_context_tool_registration():
    """Test that search_scalars_with_context tool is properly registered."""
    server = FastMCP("test")
    register_tools(server, client_factory=lambda: MockGhidraClient(), enable_writes=False)
    
    tool_names = [tool.name for tool in server._tool_manager._tools.values()]
    assert "search_scalars_with_context" in tool_names


def test_all_batch_tools_have_docstrings():
    """Verify all batch tools have proper documentation."""
    server = FastMCP("test")
    register_tools(server, client_factory=lambda: MockGhidraClient(), enable_writes=False)
    
    batch_tools = ["disassemble_batch", "read_words", "search_scalars_with_context"]
    
    for tool_name in batch_tools:
        tool = server._tool_manager._tools.get(tool_name)
        assert tool is not None, f"Tool {tool_name} not found"
        assert tool.description, f"Tool {tool_name} missing description"
        assert len(tool.description) > 50, f"Tool {tool_name} description too short"
