"""Project-level helpers."""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..ghidra.client import GhidraClient
from ..utils import audit
from ..utils.hex import int_to_hex
from ..utils.logging import (
    SafetyLimitExceeded,
    increment_counter,
    record_write_attempt,
)


__all__ = ["rebase_project"]


_NOTE_DRY_RUN = "dry-run enabled: no rebase applied"
_NOTE_WRITES_DISABLED = (
    "writes disabled (set GHIDRA_MCP_ENABLE_WRITES=1 to enable)"
)
_NOTE_REBASE_DISABLED = (
    "rebasing disabled (set GHIDRA_MCP_ENABLE_PROJECT_REBASE=1 to enable)"
)
_NOTE_CONFIRM_REQUIRED = "confirmation required: set confirm=true to proceed"


def _parse_base(value: Any) -> Optional[int]:
    if isinstance(value, str) and value.strip():
        try:
            return int(value, 16)
        except ValueError:
            return None
    if isinstance(value, int):
        return value
    return None


def rebase_project(
    client: GhidraClient,
    *,
    new_base: int,
    dry_run: bool,
    confirm: bool,
    writes_enabled: bool,
    rebases_enabled: bool,
) -> Dict[str, object]:
    """Request a program rebase with guard rails and caching updates."""

    increment_counter("project.rebase.calls")

    project_info = client.get_project_info()
    if not isinstance(project_info, dict):
        raise ValueError("Project info unavailable; cannot rebase.")

    previous_base = _parse_base(project_info.get("image_base"))
    offset: Optional[int] = None
    if previous_base is not None:
        offset = new_base - previous_base

    notes: list[str] = []
    errors: list[str] = []
    rebased = False

    if dry_run:
        notes.append(_NOTE_DRY_RUN)

    if not writes_enabled:
        notes.append(_NOTE_WRITES_DISABLED)
    if not rebases_enabled:
        notes.append(_NOTE_REBASE_DISABLED)

    if not dry_run:
        if not writes_enabled:
            errors.append("WRITE_DISABLED")
        elif not rebases_enabled:
            errors.append("REBASE_DISABLED")
        elif not confirm:
            errors.append("CONFIRMATION_REQUIRED")
            notes.append(_NOTE_CONFIRM_REQUIRED)
        else:
            try:
                record_write_attempt()
            except SafetyLimitExceeded as exc:
                errors.append("SAFETY_LIMIT")
                notes.append(str(exc))
            else:
                success, details = client.rebase_program(
                    new_base=new_base,
                    offset=offset,
                    confirm=True,
                )
                if success:
                    rebased = True
                else:
                    errors.append("REBASE_FAILED")
                if details:
                    notes.extend(details)

    refreshed_info: Optional[Dict[str, Any]] = project_info
    if not dry_run:
        updated = client.get_project_info()
        if isinstance(updated, dict):
            refreshed_info = updated

    payload: Dict[str, object] = {
        "dry_run": bool(dry_run),
        "rebased": rebased,
        "errors": errors,
        "notes": notes,
        "requested_base": int_to_hex(new_base),
        "project_info": refreshed_info,
        "previous_base": int_to_hex(previous_base) if previous_base is not None else None,
    }
    if offset is not None:
        payload["offset"] = int_to_hex(offset)
    else:
        payload["offset"] = None

    audit.record_write_event(
        category="project.rebase",
        parameters={
            "requested_base": int_to_hex(new_base),
            "previous_base": payload["previous_base"],
            "offset": payload["offset"],
            "confirm": bool(confirm),
        },
        dry_run=dry_run,
        writes_enabled=writes_enabled,
        controls={"rebases_enabled": rebases_enabled},
        result={
            "rebased": rebased,
            "errors": list(errors),
            "notes": list(notes),
        },
    )

    return payload
