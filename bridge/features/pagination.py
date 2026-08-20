"""Make omission visible on paginated responses.

Two rules, both learned the hard way in this rework:

**Never report a total that is not known.**  These searches page by cursor when
the caller asks for a small window, and in that mode the upstream does not know
how many results exist.  Reporting a plausible-looking number there would be the
Stage 2 mistake in a new place -- a figure that reads like knowledge and is not.
When the total is unknown the key is absent, so a caller cannot mistake a
default for a count.

**Say when something was left out.**  ``truncated`` is the answer to "is this
everything?", separately from ``has_more``/cursor, which answer "how do I get the
rest?".  They usually agree, but not always: a hard per-request cap truncates
with nothing to page to, and that case has to stay distinguishable from a
complete result.
"""
from __future__ import annotations

from typing import MutableMapping, Optional

__all__ = ["finalize_page"]


def finalize_page(
    payload: MutableMapping[str, object],
    *,
    truncated: Optional[bool] = None,
) -> MutableMapping[str, object]:
    """Drop an unknown ``total`` and state ``truncated`` explicitly.

    ``truncated`` defaults to whatever the read-more signals say; pass it when
    the response was capped by something other than pagination.
    """

    if payload.get("total") is None:
        payload.pop("total", None)

    if truncated is None:
        truncated = bool(payload.get("has_more")) or bool(
            payload.get("cursor") or payload.get("resume_cursor")
        )

    payload["truncated"] = bool(truncated)
    return payload
