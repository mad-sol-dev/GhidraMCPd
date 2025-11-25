import pytest

from bridge.utils.program_context import (
    PROGRAM_SELECTIONS,
    ProgramSelectionError,
    ProgramSelectionStore,
    normalize_selection,
    program_switch_policy,
)


def test_selection_defaults_and_switch_gating(monkeypatch) -> None:
    monkeypatch.setenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY", "strict")
    store = ProgramSelectionStore()

    # No default selection until provider runs
    state = store.ensure_default("req", lambda: "1")
    assert state.domain_file_id == "1"
    assert state.locked is False

    # Mark usage locks the selection against switching
    store.mark_used("req")
    snapshot = store.snapshot("req")
    assert snapshot.locked is True
    assert snapshot.domain_file_id == "1"

    # Switching while locked raises
    try:
        store.select("req", "2")
    except ProgramSelectionError as exc:
        assert exc.current == "1"
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected ProgramSelectionError")

    # A fresh requester can select freely
    other = store.select("other", "3").state
    assert other.domain_file_id == "3"
    assert other.locked is False


def test_global_store_can_be_cleared() -> None:
    PROGRAM_SELECTIONS.select("req", "1")
    PROGRAM_SELECTIONS.mark_used("req")
    PROGRAM_SELECTIONS.clear()

    state = PROGRAM_SELECTIONS.snapshot("req")
    assert state.domain_file_id is None
    assert state.locked is False


def test_normalize_selection_recovers_unlocked_state() -> None:
    files = [
        {"type": "Program", "domain_file_id": "1"},
        {"type": "Program", "domain_file_id": "2"},
    ]
    store = ProgramSelectionStore()
    store.select("req", "stale")

    state = normalize_selection(files, requestor="req", store=store).state

    assert state.domain_file_id == "1"
    assert state.locked is False


def test_normalize_selection_raises_when_locked_and_stale() -> None:
    files = [{"type": "Program", "domain_file_id": "1"}]
    store = ProgramSelectionStore()
    store.select("req", "stale")
    store.mark_used("req")

    try:
        normalize_selection(files, requestor="req", store=store)
    except ProgramSelectionError as exc:
        assert exc.current == "stale"
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected ProgramSelectionError")


def test_normalize_selection_locked_and_missing_fallback_raises() -> None:
    store = ProgramSelectionStore()
    store.select("req", "stale")
    store.mark_used("req")

    with pytest.raises(ProgramSelectionError) as exc:
        normalize_selection([], requestor="req", store=store)

    assert exc.value.current == "stale"


def test_normalize_selection_locked_stale_raises_even_soft(monkeypatch) -> None:
    monkeypatch.setenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY", "soft")
    files = [{"type": "Program", "domain_file_id": "1"}]
    store = ProgramSelectionStore()
    store.select("req", "stale")
    store.mark_used("req")

    with pytest.raises(ProgramSelectionError) as exc:
        normalize_selection(files, requestor="req", store=store)

    assert exc.value.current == "stale"


def test_select_normalizes_and_blocks_switch_when_locked(monkeypatch) -> None:
    monkeypatch.delenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY", raising=False)
    store = ProgramSelectionStore()

    initial = store.select("req", " prog-1 ").state
    assert initial.domain_file_id == "prog-1"

    store.mark_used("req")

    same = store.select("req", "prog-1").state
    assert same.domain_file_id == "prog-1"

    with pytest.raises(ProgramSelectionError) as exc:
        store.select("req", "prog-2")
    assert exc.value.current == "prog-1"


def test_program_switch_policy_defaults_to_strict(monkeypatch) -> None:
    monkeypatch.delenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY", raising=False)

    assert program_switch_policy() == "strict"

    store = ProgramSelectionStore()
    store.select("req", "1")
    store.mark_used("req")

    with pytest.raises(ProgramSelectionError):
        store.select("req", "2")

    monkeypatch.setenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY", "unexpected")
    assert program_switch_policy() == "strict"

    with pytest.raises(ProgramSelectionError):
        store.select("req", "3")

