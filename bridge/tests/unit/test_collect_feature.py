from __future__ import annotations

import pytest

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
