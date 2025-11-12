from __future__ import annotations

import pytest

import bridge.features.collect as collect
from bridge.features.collect import execute_collect
from bridge.utils.errors import ErrorCode
from bridge.utils.logging import SafetyLimitExceeded


class StubClient:
    def disassemble_at(self, address: int, count: int):  # pragma: no cover - helper
        return [
            {"address": f"0x{address:08x}", "bytes": "", "text": "NOP"}
            for _ in range(min(count, 1))
        ]

    def search_functions(self, query: str):
        return [
            "foo @ 0x00100000",
            "bar @ 0x00200000",
        ]


def _first_query(result: dict[str, object]) -> dict[str, object]:
    queries = result["queries"]
    assert isinstance(queries, list)
    payload = queries[0]
    assert isinstance(payload, dict)
    return payload


def test_execute_collect_allows_empty_queries() -> None:
    client = StubClient()
    payload = execute_collect(client, [])

    assert payload["queries"] == []
    assert payload["meta"]["estimate_tokens"] == 0


def test_execute_collect_success() -> None:
    client = StubClient()
    payload = execute_collect(
        client,
        [
            {
                "id": "search",
                "op": "search_functions",
                "params": {"query": "foo", "limit": 1},
            }
        ],
    )

    query = _first_query(payload)
    result = query["result"]
    assert isinstance(result, dict)
    assert result["ok"] is True
    assert result["errors"] == []


def test_execute_collect_query_budget_auto_trim() -> None:
    client = StubClient()
    payload = execute_collect(
        client,
        [
            {
                "id": "search",
                "op": "search_functions",
                "params": {"query": "foo", "limit": 2},
                "max_result_tokens": 1,
            }
        ],
    )

    query = _first_query(payload)
    result = query["result"]
    assert result["ok"] is False
    error = result["errors"][0]
    assert error["code"] == ErrorCode.RESULT_TOO_LARGE.value
    assert query["meta"]["truncated"] is True


def test_execute_collect_request_budget_auto_trim() -> None:
    client = StubClient()
    payload = execute_collect(
        client,
        [
            {
                "id": "search",
                "op": "search_functions",
                "params": {"query": "foo", "limit": 2},
            }
        ],
        result_budget={"max_result_tokens": 1},
    )

    query = _first_query(payload)
    result = query["result"]
    assert result["ok"] is False
    error = result["errors"][0]
    assert error["code"] == ErrorCode.RESULT_TOO_LARGE.value
    assert "request_budget_exceeded" in query["meta"].get("notes", [])


def test_execute_collect_request_budget_strict() -> None:
    client = StubClient()
    with pytest.raises(SafetyLimitExceeded):
        execute_collect(
            client,
            [
                {
                    "id": "search",
                    "op": "search_functions",
                    "params": {"query": "foo", "limit": 2},
                }
            ],
            result_budget={"max_result_tokens": 1, "mode": "strict"},
        )


def test_execute_collect_unsupported_op() -> None:
    client = StubClient()
    payload = execute_collect(
        client,
        [
            {
                "id": "bad",
                "op": "unknown",
                "params": {},
            }
        ],
    )

    query = _first_query(payload)
    result = query["result"]
    assert result["ok"] is False
    error = result["errors"][0]
    assert error["code"] == ErrorCode.INVALID_REQUEST.value


def test_search_scalars_with_context_rejects_invalid_context_lines() -> None:
    client = StubClient()
    with pytest.raises(ValueError):
        collect._op_search_scalars_with_context(
            client, {"value": 0x10, "context_lines": -1}
        )
    with pytest.raises(ValueError):
        collect._op_search_scalars_with_context(
            client, {"value": 0x10, "context_lines": 17}
        )


def test_search_scalars_with_context_rejects_non_positive_limit() -> None:
    client = StubClient()
    with pytest.raises(ValueError):
        collect._op_search_scalars_with_context(client, {"value": 0x10, "limit": 0})


@pytest.mark.parametrize(
    "context_lines, expected_window",
    [
        (0, 1),
        (16, 33),
    ],
)
def test_search_scalars_with_context_accepts_edge_values(
    monkeypatch: pytest.MonkeyPatch, context_lines: int, expected_window: int
) -> None:
    client = StubClient()
    enforce_calls: dict[str, object] = {}

    def fake_enforce(size: int, *, counter: str = "") -> None:
        enforce_calls["size"] = size
        enforce_calls["counter"] = counter

    captured: dict[str, object] = {}

    def fake_search_scalars_with_context(
        client_arg: StubClient, *, value: int, context_lines: int, limit: int
    ) -> dict[str, object]:
        captured["client"] = client_arg
        captured["value"] = value
        captured["context_lines"] = context_lines
        captured["limit"] = limit
        return {"value": value, "matches": []}

    monkeypatch.setattr(collect, "enforce_batch_limit", fake_enforce)
    monkeypatch.setattr(
        collect.batch_ops,
        "search_scalars_with_context",
        fake_search_scalars_with_context,
    )

    result = collect._op_search_scalars_with_context(
        client, {"value": 0x10, "context_lines": context_lines, "limit": 1}
    )

    assert result == {"value": 0x10, "matches": []}
    assert captured["client"] is client
    assert captured["value"] == 0x10
    assert captured["context_lines"] == context_lines
    assert captured["limit"] == 1
    assert enforce_calls["size"] == expected_window
    assert enforce_calls["counter"] == "search_scalars_with_context.window"
