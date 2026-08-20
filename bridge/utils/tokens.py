"""Shared token estimation used by result budgets and the usage log.

The estimate approximates the cost of a response as its serialized length over
four.  ``collect`` and ``analyze_function_complete`` bound their output with it,
and the usage log records it per call, so it has to measure the whole payload --
not a part of it.

History, because it explains the shape: this counted string characters only.
Numbers, addresses, byte counts and every structural character were invisible,
so ``read_words`` was estimated at 4 tokens for a 292-byte response.  A budget
that undercounts by a factor of two is not a limit, and
``max_result_tokens`` never bound anything in practice.  Serializing the payload
and dividing by four is the simplest estimate that measures what is actually
sent.
"""
from __future__ import annotations

import json

__all__ = ["estimate_tokens", "serialized_length"]

#: Characters per token.  A rough industry rule, and deliberately rough: the
#: point is a bound that tracks payload size, not a tokenizer.
_CHARS_PER_TOKEN = 4


def serialized_length(data: object) -> int:
    """Return the length of ``data`` as JSON, in characters.

    Uses the same serialization the client receives, so the estimate and the
    measured response size describe the same thing.  Values JSON cannot
    represent fall back to their ``str()`` form rather than raising: an
    estimator that throws on an odd payload would be worse than one that
    approximates it.
    """

    try:
        return len(json.dumps(data, default=str))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return len(str(data))


def estimate_tokens(data: object) -> int:
    """Estimate the token cost of ``data`` as serialized length over four."""

    return serialized_length(data) // _CHARS_PER_TOKEN
