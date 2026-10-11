"""Ghidra scripts from the analysis project's script folder (SCRIPT-ADAPTER).

The gap this closes is the hand-over: a script written for the analysis had to
be placed and started by hand.  run_script starts it -- but only a file below
the configured folder (``GHIDRA_MCP_SCRIPT_DIR``), never submitted code, and
never a path that leaves the folder, by ``..`` or by a symlink.

The plugin runs the script inside one outer transaction.  A dry run rolls back
everything the script did to the program, its own commits included; a real
run is one undo step.  What a script does outside the program database (files,
other programs, saving) is not rolled back -- that is the script's business,
and the reason the folder is the analysis project's, under its own review.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from ..ghidra.client import GhidraClient
from ..utils.config import WRITES_DISABLED_NOTE
from ..utils.errors import UpstreamFailed
from ..utils.logging import increment_counter, record_write_attempt
from . import mutations

__all__ = ["ScriptRejected", "ScriptUnavailable", "resolve_script", "run_script"]

SCRIPTS_OFF = (
    "run_script is off: set GHIDRA_MCP_SCRIPT_DIR to the analysis project's "
    "script folder and restart the bridge"
)

_NOTE_DRY_RUN = "dry run: the script ran, then everything it changed in the program was rolled back"
_NOTE_WRITES_DISABLED = WRITES_DISABLED_NOTE
_NOTE_LOAD_FAILED = "the script did not load; the compiler's messages are in output"
_NOTE_TIMED_OUT = (
    "timed out: the script stopped at its next monitor check; nothing was committed"
)
_NOTE_TRUNCATED = "output cut at 64 KiB"
_NOTE_NOT_CAPTURED = "the script's prints could not be captured; they are in Ghidra's console"
_NOTE_BUNDLE_ADDED = "Ghidra's Bundle Manager now lists the script's folder (needed to compile Java)"
_NOTE_FAILED = "the script failed; nothing was committed -- output shows how far it got"


class ScriptRejected(ValueError):
    """The script name is not a file below the script folder."""


class ScriptUnavailable(RuntimeError):
    """run_script is not configured, or the request was not sent."""


def resolve_script(script_dir: Optional[Path], script: str) -> Path:
    """The real path of ``script`` below ``script_dir``, or ScriptRejected.

    Both sides are resolved first, symlinks included, so neither ``..`` nor a
    link pointing out of the folder gets past the containment check.
    """

    if script_dir is None:
        raise ScriptUnavailable(SCRIPTS_OFF)
    name = str(script).strip()
    if not name:
        raise ScriptRejected("script must be a non-empty path below the script folder")
    if Path(name).is_absolute():
        raise ScriptRejected(f"script must be relative to the script folder, got '{name}'")
    try:
        base = script_dir.resolve(strict=True)
    except OSError as exc:
        raise ScriptUnavailable(f"script folder {script_dir} is not there: {exc}") from exc
    if not base.is_dir():
        raise ScriptUnavailable(f"script folder {script_dir} is not a directory")
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise ScriptRejected(f"'{name}' leads out of the script folder")
    if not target.is_file():
        raise ScriptRejected(f"no script '{name}' in the script folder")
    return target


def _flag(answer: Mapping[str, object], key: str) -> bool:
    """A boolean the plugin must send; anything else is a failure, not False."""

    value = answer.get(key)
    if not isinstance(value, bool):
        raise UpstreamFailed(f"runScript answered {key}={value!r}, not a boolean")
    return value


def run_script(
    client: GhidraClient,
    *,
    script_dir: Optional[Path],
    script: str,
    args: Sequence[str] = (),
    dry_run: bool = True,
    timeout_s: int = 60,
    writes_enabled: bool = False,
) -> Dict[str, object]:
    """Run ``script`` from the script folder and report what it did.

    A script that throws or times out is a result (``ok`` false, with its
    output and error), not a tool failure; a request the plugin refuses is.
    """

    increment_counter("scripts.run.calls")
    target = resolve_script(script_dir, script)
    base = script_dir.resolve() if script_dir is not None else target.parent
    relative = target.relative_to(base).as_posix()
    arguments: List[str] = [str(a) for a in args]

    write = not dry_run and writes_enabled
    if write:
        record_write_attempt()
    answer = client.run_script(str(target), arguments, dry_run=not write, timeout_s=timeout_s)
    if answer is None:
        raise ScriptUnavailable("run_script was not sent to Ghidra")
    if answer.get("status") != "ok":
        raise UpstreamFailed(f"runScript answered {answer.get('error') or 'no status'}")

    ok = _flag(answer, "ok")
    committed = _flag(answer, "committed")
    modified = _flag(answer, "modified")
    timed_out = _flag(answer, "timed_out")
    truncated = _flag(answer, "output_truncated")
    captured = _flag(answer, "output_captured")
    phase = str(answer.get("phase") or "")
    error = answer.get("script_error")
    output = str(answer.get("output") or "")

    notes: List[str] = []
    if not write:
        notes.append(_NOTE_DRY_RUN)
    if not dry_run and not writes_enabled:
        notes.append(_NOTE_WRITES_DISABLED)
    if phase == "load" and not ok:
        notes.append(_NOTE_LOAD_FAILED)
    elif timed_out:
        notes.append(_NOTE_TIMED_OUT)
    elif not ok:
        notes.append(_NOTE_FAILED)
    if truncated:
        notes.append(_NOTE_TRUNCATED)
    if phase == "run" and not captured:
        notes.append(_NOTE_NOT_CAPTURED)
    if answer.get("bundle_added") is True:
        notes.append(_NOTE_BUNDLE_ADDED)

    if ok and modified:
        reason: Optional[str] = None
        if not committed:
            reason = "dry_run" if dry_run else "writes_disabled"
        mutations.record(
            kind="script",
            target=relative,
            new=" ".join(arguments) if arguments else "(no args)",
            applied=committed,
            reason=reason,
        )

    return {
        "script": relative,
        "args": arguments,
        "dry_run": bool(dry_run),
        "ok": ok,
        "applied": committed,
        "modified": modified,
        "phase": phase,
        "timed_out": timed_out,
        "error": str(error) if error is not None else None,
        "output": output,
        "notes": notes,
    }
