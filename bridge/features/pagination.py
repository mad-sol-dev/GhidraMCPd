"""Make omission visible on paginated responses.

Two rules, both learned the hard way in this rework:

**Never report a total that is not known**, and never let its presence depend on
the data.  These searches page by cursor when the caller asks for a small
window, and in that mode the upstream does not know how many results exist.

Dropping the key only when the number happened to be unknown produced the worst
possible shape: an empty result still carried ``total: 0``, so a caller written
against ``data["total"]`` passed every empty-result test and broke the first time
a search actually matched something.  A field whose presence varies with the
answer is worse than one that is always absent.  So a tool either always reports
a total or never does, and every response carries ``returned``.

**Say when something was left out.**  ``truncated`` is the answer to "is this
everything?", separately from ``has_more``/cursor, which answer "how do I get the
rest?".  They usually agree, but not always: a hard per-request cap truncates
with nothing to page to, and that case has to stay distinguishable from a
complete result.
"""
from __future__ import annotations

from typing import MutableMapping, Optional, Sequence

__all__ = ["finalize_page"]


def finalize_page(
    payload: MutableMapping[str, object],
    *,
    truncated: Optional[bool] = None,
    keeps_total: bool = True,
) -> MutableMapping[str, object]:
    """State ``returned`` and ``truncated``, and handle ``total`` consistently.

    ``truncated`` defaults to whatever the read-more signals say; pass it when
    the response was capped by something other than pagination.

    ``keeps_total=False`` marks a tool that cannot always know its total -- the
    cursor-paginated searches.  Those drop the key unconditionally rather than
    only when it happens to be unknown, so a caller cannot be taught the wrong
    shape by an empty result.
    """

    if not keeps_total or payload.get("total") is None:
        payload.pop("total", None)

    for key in ("items", "matches"):
        value = payload.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            payload["returned"] = len(value)
            break
    else:
        payload.setdefault("returned", 0)

    if truncated is None:
        truncated = bool(payload.get("has_more")) or bool(
            payload.get("cursor") or payload.get("resume_cursor")
        )

    payload["truncated"] = bool(truncated)
    return payload
