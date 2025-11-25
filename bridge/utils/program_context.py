"""Helpers for tracking per-request program selection state."""

from __future__ import annotations

import threading
import os
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

    def select(self, key: Hashable | object, domain_file_id: str) -> "SelectionResult":
        """Record a selection for *key* with gating on mid-session switches."""

        state = self._state_for(key)
        warning = None
        current = _normalize_domain_file_id(state.domain_file_id)
        requested = _normalize_domain_file_id(domain_file_id)
        if requested is None:
            state.domain_file_id = None
            return SelectionResult(state=state, warning=None)
        if (
            state.locked
            and current is not None
            and current != requested
        ):
            policy = program_switch_policy()
            if policy == "strict":
                raise ProgramSelectionError(current=current)
            warning = _mid_session_warning(current, requested)
        state.domain_file_id = requested
        return SelectionResult(state=state, warning=warning)

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
) -> "SelectionResult":
    """Ensure the stored selection for *requestor* matches available files.

    * When no selection exists, the first available Program is used.
    * If a stale selection is present and unlocked, it is replaced by the first
      available Program (when present).
    * If a stale selection is present and the requester is locked, a
      :class:`ProgramSelectionError` is raised to signal a required session
      restart.
    """

    state = store.ensure_default(requestor, lambda: default_program_id(files))
    warning = None

    normalized = _normalize_domain_file_id(state.domain_file_id)
    if normalized and validate_program_id(files, normalized):
        state.domain_file_id = normalized
        return SelectionResult(state=state, warning=None)

    fallback = default_program_id(files)
    if fallback is None:
        state.domain_file_id = None
        return SelectionResult(state=state, warning=None)

    if normalized and state.locked and normalized != fallback:
        policy = program_switch_policy()
        if policy == "strict":
            raise ProgramSelectionError(current=normalized)
        warning = _mid_session_warning(normalized, fallback)

    state.domain_file_id = fallback
    return SelectionResult(state=state, warning=warning)


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
    except ValueError:
        # Outside of an MCP request (e.g., direct unit invocation) there is no
        # request_context. Use a stable fallback key so non-request usage still
        # participates in program tracking without crashing tests.
        return ("mcp", "default")
    except Exception:  # pragma: no cover - defensive fallback
        raise RuntimeError("MCP context unavailable")

    try:
        return ctx.session
    except ValueError:
        return ("mcp", "default")
    except Exception:  # pragma: no cover - defensive fallback
        try:
            client_id = getattr(ctx, "client_id", None)
        except Exception:
            client_id = None
        if client_id:
            return ("mcp", client_id)
    return ("mcp", getattr(ctx, "request_id", "unknown"))


def mark_used_for_context(server: FastMCP, *, lock_usage: bool = True) -> None:
    """Mark the current MCP session as having used program-dependent APIs."""

    if not lock_usage:
        return
    policy = program_switch_policy()
    if policy not in {"soft", "strict"}:  # pragma: no cover - defensive fallback
        return
    try:
        key = requestor_from_context(server)
    except RuntimeError:
        return
    PROGRAM_SELECTIONS.mark_used(key)


def lock_selection_for_requestor(key: Hashable | object) -> None:
    """Mark the given requester as having established a program selection."""

    policy = program_switch_policy()
    if policy not in {"soft", "strict"}:  # pragma: no cover - defensive fallback
        return
    PROGRAM_SELECTIONS.mark_used(key)


def program_switch_policy() -> str:
    """Return the configured mid-session program switching policy."""

    value = os.getenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY") or "strict"
    normalized = value.strip().lower()
    if normalized == "soft":
        return "soft"
    return "strict"


def _mid_session_warning(previous: str | None, requested: str | None) -> str:
    current = previous or "unknown"
    target = requested or "unknown"
    return (
        "Program selection switched mid-session from "
        f"'{current}' to '{target}'. Confirm this change before continuing; "
        "start a new session if you want to avoid mixed context."
    )


@dataclass(slots=True)
class SelectionResult:
    """Return type for program selection normalization operations."""

    state: ProgramState
    warning: str | None = None

