"""Labels at arbitrary addresses (R.12).

The plugin's only label path used to sit inside ``renameDataAtAddress``, behind
``getDefinedDataAt(addr) != null``.  An MMIO register has no defined data, so
labelling 0xB1006000 did nothing -- and ``/renameData`` answered "Rename data
attempted" regardless.  ``/createLabel`` places the label unconditionally and
says what happened.
"""
from __future__ import annotations

from typing import Dict, List, Mapping, Optional

from ..ghidra.client import GhidraClient
from ..utils.config import WRITES_DISABLED_NOTE
from ..utils.hex import int_to_hex
from ..utils.logging import increment_counter, record_write_attempt
from . import mutations

__all__ = ["LabelRejected", "LabelUnavailable", "apply_label"]

_NOTE_DRY_RUN = "dry-run requested: label not created"
_NOTE_WRITES_DISABLED = WRITES_DISABLED_NOTE
_NOTE_ALREADY_PRESENT = "a label of this name is already at this address; nothing to do"
_NOTE_SECONDARY = (
    "created as a secondary label: a user-named symbol is primary here and "
    "stays primary -- a label adds a name, it does not replace one"
)
_NOTE_UNMAPPED = "address lies outside every memory block (MMIO, unmapped RAM); labelled anyway"


class LabelRejected(ValueError):
    """The plugin refused the address or the name."""


class LabelUnavailable(RuntimeError):
    """No answer from /createLabel -- an older plugin, or the call failed."""


def apply_label(
    client: GhidraClient,
    *,
    address: int,
    name: str,
    dry_run: bool = True,
    writes_enabled: bool = False,
) -> Dict[str, object]:
    """Create ``name`` at ``address``, or report what doing so would find.

    A dry run still asks the plugin, which validates the name with Ghidra's own
    rules and lists the symbols already there: a dry run that cannot fail tells
    you nothing about whether the real call will.
    """

    increment_counter("labels.apply.calls")
    name = str(name).strip()
    if not name:
        raise LabelRejected("name must be a non-empty string")

    write = not dry_run and writes_enabled
    if write:
        record_write_attempt()
    answer = client.create_label(address, name, dry_run=not write)
    if answer is None:
        error = getattr(client, "last_error", None)
        reason = getattr(error, "reason", None) or "no answer"
        raise LabelUnavailable(f"cannot label {int_to_hex(address)}: {reason}")

    if answer.get("status") != "ok":
        message = str(answer.get("error") or "label rejected")
        if "invalid" in message.lower() or "required" in message.lower():
            raise LabelRejected(message)
        raise LabelUnavailable(f"cannot label {int_to_hex(address)}: {message}")

    already = bool(answer.get("already_present"))
    created = bool(answer.get("created"))
    primary_before = answer.get("primary_before")
    existing: List[str] = [str(n) for n in answer.get("existing") or ()]

    notes: List[str] = []
    if dry_run:
        notes.append(_NOTE_DRY_RUN)
    if not writes_enabled:
        notes.append(_NOTE_WRITES_DISABLED)
    if already:
        notes.append(_NOTE_ALREADY_PRESENT)
    if created and not answer.get("primary"):
        notes.append(_NOTE_SECONDARY)
    if not answer.get("mapped"):
        notes.append(_NOTE_UNMAPPED)

    if not already:
        reason: Optional[str] = None
        if not created:
            reason = "dry_run" if dry_run else "writes_disabled"
        # A label adds a name; nothing is replaced, so there is no "old".
        # What was primary goes into detail, or the ledger line would read
        # "DMAC_BA -> R12_live_check", a rename that did not happen.
        mutations.record(
            kind="label",
            target=int_to_hex(address),
            old=None,
            new=name,
            applied=created,
            reason=reason,
            detail=f"beside {primary_before}" if primary_before is not None else None,
        )

    return {
        "address": int_to_hex(address),
        "name": name,
        "dry_run": bool(dry_run),
        "applied": created,
        "already_present": already,
        "primary": bool(answer.get("primary")),
        "primary_before": str(primary_before) if primary_before is not None else None,
        "existing": existing,
        "mapped": bool(answer.get("mapped")),
        "notes": notes,
    }
