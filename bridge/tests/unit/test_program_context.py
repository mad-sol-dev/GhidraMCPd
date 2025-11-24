from bridge.utils.program_context import (
    PROGRAM_SELECTIONS,
    ProgramSelectionError,
    ProgramSelectionStore,
    normalize_selection,
)


def test_selection_defaults_and_switch_gating() -> None:
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


def test_normalize_selection_soft_policy_warns(monkeypatch) -> None:
    monkeypatch.setenv("GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY", "soft")
    files = [{"type": "Program", "domain_file_id": "1"}]
    store = ProgramSelectionStore()
    store.select("req", "stale")
    store.mark_used("req")

    result = normalize_selection(files, requestor="req", store=store)

    assert result.state.domain_file_id == "1"
    assert result.warning
    assert result.warning.startswith("Program selection switched mid-session")

