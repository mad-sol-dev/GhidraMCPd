"""Modular Python bridge for the Ghidra MCP server."""

from .utils.env import load_env

# Ensure environment defaults from `.env` are available to all modules on import.
load_env()
