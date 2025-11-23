"""Helpers for tracking per-request program selection state."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Hashable, Mapping, MutableMapping, Sequence
from weakref import WeakKeyDictionary

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request


@dataclass(slots=True)
class ProgramState:
    """Mutable state for a single requester."""

    domain_file_id: str | None = None
    locked: bool = False


class ProgramSelectionError(RuntimeError):
    """Raised when a selection request violates gating rules."""

    def __init__(self, *, current: str | None) -> None:
        super().__init__("Program selection is locked for this session")
        self.current = current


class ProgramSelectionStore:
    """Track program selections per requester with session scoping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_session: "WeakKeyDictionary[object, ProgramState]" = WeakKeyDictionary()
        self._by_key: MutableMapping[Hashable, ProgramState] = {}

    def _state_for(self, key: Hashable | object) -> ProgramState:
        with self._lock:
            try:
                state = self._by_session.get(key)
            except TypeError:
                state = None
            if state is not None:
                return state
            try:
                self._by_session[key] = ProgramState()
                return self._by_session[key]
            except TypeError:
                pass

            state = self._by_key.get(key)
            if state is None:
                state = ProgramState()
                self._by_key[key] = state
            return state

    def clear(self) -> None:
        """Reset all tracked selections (useful for tests)."""

        with self._lock:
            self._by_session.clear()
            self._by_key.clear()

    def ensure_default(
        self, key: Hashable | object, provider: Callable[[], str | None]
    ) -> ProgramState:
        """Ensure *key* has a selection, using *provider* if unset."""

        state = self._state_for(key)
        if state.domain_file_id is None:
            state.domain_file_id = provider()
        return state

    def mark_used(self, key: Hashable | object) -> None:
        """Mark a requester as having used program-dependent APIs."""

        state = self._state_for(key)
        state.locked = True

    def select(self, key: Hashable | object, domain_file_id: str) -> ProgramState:
        """Record a selection for *key* with gating on mid-session switches."""

        state = self._state_for(key)
        if (
            state.locked
            and state.domain_file_id is not None
            and state.domain_file_id != domain_file_id
        ):
            raise ProgramSelectionError(current=state.domain_file_id)
        state.domain_file_id = domain_file_id
        return state

    def snapshot(self, key: Hashable | object) -> ProgramState:
        """Return a shallow copy of the current state for *key*."""

        state = self._state_for(key)
        return ProgramState(domain_file_id=state.domain_file_id, locked=state.locked)


PROGRAM_SELECTIONS = ProgramSelectionStore()


def _normalize_domain_file_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def default_program_id(files: object) -> str | None:
    """Return the first Program domain ID from a project file listing."""

    if not isinstance(files, Sequence):
        return None

    for entry in files:
        if not isinstance(entry, Mapping):
            continue
        entry_type = str(entry.get("type", "")).lower()
        if entry_type != "program":
            continue
        normalized = _normalize_domain_file_id(entry.get("domain_file_id"))
        if normalized:
            return normalized
    return None


def normalize_selection(
    files: object, *, requestor: Hashable | object, store: ProgramSelectionStore = PROGRAM_SELECTIONS
) -> ProgramState:
    """Ensure the stored selection for *requestor* matches available files.

    * When no selection exists, the first available Program is used.
    * If a stale selection is present and unlocked, it is replaced by the first
      available Program (when present).
    * If a stale selection is present and the requester is locked, a
      :class:`ProgramSelectionError` is raised to signal a required session
      restart.
    """

    state = store.ensure_default(requestor, lambda: default_program_id(files))

    normalized = _normalize_domain_file_id(state.domain_file_id)
    if normalized and validate_program_id(files, normalized):
        state.domain_file_id = normalized
        return state

    fallback = default_program_id(files)
    if fallback is None:
        state.domain_file_id = None
        return state

    if normalized and state.locked and normalized != fallback:
        raise ProgramSelectionError(current=normalized)

    state.domain_file_id = fallback
    return state


def validate_program_id(files: object, domain_file_id: str) -> bool:
    """Return ``True`` if *domain_file_id* is a known Program entry."""

    if not isinstance(files, Sequence):
        return False

    for entry in files:
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get("type", "")).lower() != "program":
            continue
        current = _normalize_domain_file_id(entry.get("domain_file_id"))
        if current is not None and domain_file_id == current:
            return True
    return False


def requestor_from_request(request: Request) -> Hashable:
    """Derive a stable requester key from an HTTP request."""

    header = request.headers.get("x-requestor-id")
    if isinstance(header, str) and header.strip():
        return ("http", header.strip())

    client = request.client
    if client is not None and client[0]:
        return ("http", client[0], client[1])

    return ("http", "default")


def requestor_from_context(server: FastMCP) -> object:
    """Return the MCP session object for the active request."""

    try:
        ctx = server.get_context()
    except Exception:  # pragma: no cover - defensive fallback
        raise RuntimeError("MCP context unavailable")

    try:
        return ctx.session
    except Exception:  # pragma: no cover - defensive fallback
        client_id = getattr(ctx, "client_id", None)
        if client_id:
            return ("mcp", client_id)
    return ("mcp", getattr(ctx, "request_id", "unknown"))


def mark_used_for_context(server: FastMCP, *, lock_usage: bool = True) -> None:
    """Mark the current MCP session as having used program-dependent APIs."""

    if not lock_usage:
        return
    try:
        key = requestor_from_context(server)
    except RuntimeError:
        return
    PROGRAM_SELECTIONS.mark_used(key)

