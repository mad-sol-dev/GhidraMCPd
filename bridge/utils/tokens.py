"""Shared token estimation used by result budgets and the usage log.

``collect`` and ``analyze_function_complete`` already report an
``estimate_tokens`` value in their aggregate metadata.  The usage log applies
the very same function to every tool call so the numbers stay comparable
across tools.
"""
from __future__ import annotations

from typing import Mapping, Sequence

__all__ = ["estimate_tokens"]


def estimate_tokens(data: object) -> int:
    """Estimate the token cost of ``data`` as ``string characters / 4``.

    Only string content is counted; this is the historical behaviour of the
    ``collect`` budget accounting and is kept unchanged so budgets and the
    usage log measure the same thing.  Callers that need the true payload size
    should record the serialized byte count alongside this value.
    """

    total_chars = 0

    def _walk(value: object) -> None:
        nonlocal total_chars
        if isinstance(value, str):
            total_chars += len(value)
        elif isinstance(value, Mapping):
            for item in value.values():
                _walk(item)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                _walk(item)

    _walk(data)
    return total_chars // 4 if total_chars else 0
