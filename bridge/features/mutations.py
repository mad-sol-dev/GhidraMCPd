"""A ledger of what this session changed, so the yield can leave Ghidra.

Renames, comments and data types land in the ``.rep`` and in no versioned
artefact.  ``check_dirty_state`` knows *that* something is open, not *what*, so
the work of a session has to be reconstructed from memory when it comes time to
write it down.

This module records each mutation as it is attempted -- what was changed, from
what, to what, and whether it was actually applied -- and renders the list in a
form that drops straight into a commit message or a TRUTH line.

Two things it is careful about:

*Proposals are not changes.*  A ``dry_run`` call and a real write both appear,
and they are never rendered alike: a proposed rename is marked as such, because
a ledger that lets an intention read as an accomplishment is worse than none.

*"Since the last save" is a real boundary.*  ``save_program`` marks the ledger,
and everything before that mark is gone from the listing -- it is in the file.
"""
from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional, Sequence

__all__ = [
    "Mutation",
    "clear",
    "mark_saved",
    "record",
    "render_lines",
    "since_last_save",
    "summarise",
]

Kind = Literal["rename", "comment", "datatype", "bytes"]

#: Longest old/new value kept verbatim; the rest is elided.
_VALUE_CHARS = 60


@dataclass(frozen=True)
class Mutation:
    """One attempted change."""

    kind: Kind
    #: Hex address, or the data type path for ``datatype`` entries.
    target: str
    #: What the value was.  ``None`` means it could not be determined -- which
    #: is not the same as "it was empty", and is rendered differently.
    old: Optional[str]
    #: What it was set to.  ``None`` for a deletion.
    new: Optional[str]
    #: False for a dry run, or when writes are disabled.
    applied: bool
    #: Why it was not applied, when it was not.
    reason: Optional[str] = None
    detail: Optional[str] = None
    ts: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> Dict[str, object]:
        return asdict(self)


_LOCK = threading.Lock()
_JOURNAL: List[Mutation] = []


def record(
    *,
    kind: Kind,
    target: str,
    old: Optional[str] = None,
    new: Optional[str] = None,
    applied: bool,
    reason: Optional[str] = None,
    detail: Optional[str] = None,
) -> Mutation:
    """Append one mutation to the ledger and return it."""

    entry = Mutation(
        kind=kind,
        target=target,
        old=_shorten(old),
        new=_shorten(new),
        applied=applied,
        reason=reason,
        detail=detail,
    )
    with _LOCK:
        _JOURNAL.append(entry)
    return entry


def since_last_save() -> List[Mutation]:
    """Everything recorded since the last ``mark_saved()``."""

    with _LOCK:
        return list(_JOURNAL)


def mark_saved() -> int:
    """Clear the ledger after a successful save, returning how many it held."""

    with _LOCK:
        count = len(_JOURNAL)
        _JOURNAL.clear()
    return count


def clear() -> None:
    """Drop the ledger without treating it as saved (tests)."""

    with _LOCK:
        _JOURNAL.clear()


def _shorten(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).replace("\n", " ").strip()
    if len(text) <= _VALUE_CHARS:
        return text
    return text[:_VALUE_CHARS] + f"…(+{len(text) - _VALUE_CHARS})"


def _render_value(value: Optional[str]) -> str:
    """``None`` means unknown, and must not read as an empty string."""

    if value is None:
        return "?"
    if value == "":
        return "(empty)"
    return value


def render_lines(mutations: Sequence[Mutation]) -> List[str]:
    """Render the ledger as lines fit for a commit message or a TRUTH line.

    Applied changes carry no marker; proposals are prefixed, so a block pasted
    into a commit message cannot claim work that was never written.
    """

    lines: List[str] = []
    for entry in mutations:
        marker = "" if entry.applied else "[proposed] "
        if entry.kind == "datatype":
            body = f"{entry.target}  datatype  {_datatype_body(entry)}"
        elif entry.kind == "bytes":
            body = f"{entry.target}  bytes     {_render_value(entry.new)}"
        else:
            body = (
                f"{entry.target}  {entry.kind:<8}  "
                f"{_render_value(entry.old)} -> {_render_value(entry.new)}"
            )
        if entry.detail:
            body = f"{body}  ({entry.detail})"
        lines.append(f"{marker}{body}")
    return lines


def _datatype_body(entry: Mutation) -> str:
    """created / updated / deleted are three different claims; keep them apart."""

    if entry.new is None:
        return f"deleted {_render_value(entry.old)}"
    if entry.old is None:
        return f"created {entry.new}"
    return f"updated to {entry.new}"


def summarise(mutations: Sequence[Mutation]) -> Dict[str, object]:
    """Counts by kind, and applied versus merely proposed."""

    by_kind: Dict[str, int] = {}
    applied = 0
    for entry in mutations:
        by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1
        if entry.applied:
            applied += 1
    return {
        "total": len(mutations),
        "applied": applied,
        "proposed": len(mutations) - applied,
        "by_kind": by_kind,
    }
