"""Unit tests for the per-call usage log (Stage 0 measurement basis)."""
from __future__ import annotations

import json

import pytest

from bridge.utils import usage_log
from bridge.utils.tokens import estimate_tokens


@pytest.fixture(autouse=True)
def _reset_path():
    previous = usage_log.get_usage_log_path()
    yield
    usage_log.set_usage_log_path(previous)


def test_logging_is_disabled_by_default(tmp_path):
    usage_log.set_usage_log_path(None)
    assert usage_log.usage_log_enabled() is False

    target = tmp_path / "never.jsonl"
    usage_log.record_tool_call(
        tool="search_strings", params={"query": "x"}, result={"ok": True}, duration_s=0.1
    )
    assert not target.exists()


def test_record_writes_one_jsonl_line(tmp_path):
    path = tmp_path / "usage.jsonl"
    usage_log.set_usage_log_path(path)

    result = {"ok": True, "data": {"total": 3, "matches": [1, 2, 3]}, "errors": []}
    usage_log.record_tool_call(
        tool="search_scalars",
        params={"value": "0xB1008000", "limit": 100},
        result=result,
        duration_s=0.25,
    )
    usage_log.record_tool_call(
        tool="read_words",
        params={"address": "0x002afb34", "count": 8},
        result={"ok": True, "data": {"words": [1, 2]}, "errors": []},
        duration_s=0.5,
    )

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    first = json.loads(lines[0])
    assert first["tool"] == "search_scalars"
    assert first["params"]["value"] == "0xB1008000"
    assert first["hits"] == 3
    assert first["ok"] is True
    assert first["duration_ms"] == pytest.approx(250.0, rel=0.01)
    assert first["result_bytes"] == len(json.dumps(result).encode("utf-8"))
    assert first["estimate_tokens"] == estimate_tokens(result)
    assert first["ts"].endswith("+00:00")


def test_params_are_shortened():
    long_value = "a" * 500
    shortened = usage_log.shorten_params({"query": long_value})
    encoded = json.dumps(shortened, ensure_ascii=False) if isinstance(shortened, dict) else shortened
    assert len(encoded) < 500
    assert "…" in encoded

    listed = usage_log.shorten_params({"addresses": [f"0x{i:04x}" for i in range(20)]})
    assert listed["addresses"][-1] == "…(+15)"


def test_hits_unknown_stays_none():
    assert usage_log.count_hits({"ok": True, "data": {"address": "0x1", "name": "f"}}) is None
    assert usage_log.count_hits({"ok": False, "data": None, "errors": [{}]}) is None


def test_hits_counts_nested_lists():
    payload = {
        "ok": True,
        "data": {"matches": {"disassembly": [1, 2, 3], "decompile": [4]}},
    }
    assert usage_log.count_hits(payload) == 4


def test_hits_prefers_explicit_total():
    payload = {"ok": True, "data": {"total": 42, "items": [1, 2]}}
    assert usage_log.count_hits(payload) == 42


def test_estimator_is_shared_with_collect_budget():
    """One estimator, so the budget and the log measure the same thing."""

    from bridge.features.analyze import _estimate_tokens

    payload = {"a": "x" * 40, "b": [{"c": "y" * 8}], "n": list(range(20))}
    assert _estimate_tokens(payload) == estimate_tokens(payload)


def test_the_log_estimate_matches_the_bytes_it_records():
    """After Stage 2b both columns describe the same serialized payload.

    They are no longer independent measurements -- that is the fix, not a
    coincidence -- so the report must not present their agreement as evidence
    of anything beyond the estimator measuring the response.
    """

    payload = {"ok": True, "data": {"words": list(range(64))}, "errors": []}
    assert estimate_tokens(payload) == len(json.dumps(payload)) // 4
