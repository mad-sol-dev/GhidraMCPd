from __future__ import annotations

import pytest

import bridge.features.collect as collect
from bridge.features.collect import execute_collect
from bridge.tests.plugin_http import function_search_page
from bridge.utils.errors import ErrorCode
from bridge.utils.logging import SafetyLimitExceeded


class StubClient:
    def disassemble_at(self, address: int, count: int):  # pragma: no cover - helper
        return [
            {
                "address": f"0x{address + index * 4:08x}",
                "bytes": "",
                "text": f"NOP_{index}",
            }
            for index in range(max(0, count))
        ]

    def search_functions(self, query: str, *, limit: int = 100, offset: int = 0, cursor=None):
        lines = ["foo @ 0x00100000", "bar @ 0x00200000"]
        return function_search_page(lines, query, limit=limit, offset=offset, cursor=cursor)


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


def test_execute_collect_aliases_type_and_filter() -> None:
    client = StubClient()
    payload = execute_collect(
        client,
        [
            {
                "id": "search",
                "type": "search_functions",
                "filter": {"query": "foo", "limit": 1},
            }
        ],
    )

    query = _first_query(payload)
    assert query["op"] == "search_functions"

    result = query["result"]
    assert isinstance(result, dict)
    assert result["ok"] is True

    notes = query["meta"].get("notes", [])
    assert "alias:op" in notes
    assert "alias:params" in notes


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
    """Stage 5: a request-level violation drops the sub-result, not the batch.

    It used to raise out of execute_collect, so one over-budget query cost the
    caller every other answer in the batch.  Whoever sends a batch wants the
    rest.
    """

    client = StubClient()
    result = execute_collect(
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

    entry = result["queries"][0]
    assert entry["result"]["ok"] is False
    assert entry["result"]["errors"][0]["code"] == "RESULT_TOO_LARGE"
    assert entry["meta"]["truncated"] is True
    assert result["meta"]["dropped_by_budget"] == ["search"]


def test_execute_collect_keeps_the_queries_that_fit() -> None:
    """The reason the change matters: the rest of the batch survives."""

    client = StubClient()
    result = execute_collect(
        client,
        [
            {"id": "big", "op": "search_functions", "params": {"query": "foo", "limit": 2}},
            {"id": "small", "op": "disassemble_at",
             "params": {"address": "0x1000", "count": 1}},
        ],
        result_budget={"max_result_tokens": 40, "mode": "strict"},
    )

    by_id = {entry["id"]: entry for entry in result["queries"]}
    dropped = result["meta"].get("dropped_by_budget", [])
    assert dropped, "the budget has to bind for this test to mean anything"
    survivors = [qid for qid, entry in by_id.items() if entry["result"]["ok"]]
    assert set(survivors) | set(dropped) == {"big", "small"}
    assert set(survivors) & set(dropped) == set()


def test_search_functions_rejects_invalid_context_lines() -> None:
    client = StubClient()
    with pytest.raises(ValueError):
        collect._op_search_functions(client, {"context_lines": -1})
    with pytest.raises(ValueError):
        collect._op_search_functions(client, {"context_lines": 17})


def test_search_functions_forwards_context_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    client = StubClient()
    captured: dict[str, object] = {}

    def fake_search_functions(
        client_arg: StubClient,
        *,
        query: str,
        limit: int,
        page: int,
        rank: str | None,
        k: int | None,
        resume_cursor: str | None,
        context_lines: int,
    ) -> dict[str, object]:
        captured.update(
            {
                "client": client_arg,
                "context_lines": context_lines,
                "query": query,
            }
        )
        return {"items": [], "query": query, "total": 0, "page": page, "limit": limit, "has_more": False}

    monkeypatch.setattr(collect.functions, "search_functions", fake_search_functions)

    result = collect._op_search_functions(
        client,
        {"query": "foo", "limit": 5, "page": 1, "context_lines": 4},
    )

    assert captured["client"] is client
    assert captured["context_lines"] == 4
    assert captured["query"] == "foo"
    assert result["query"] == "foo"


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
        client_arg: StubClient,
        *,
        value: int,
        context_lines: int,
        limit: int,
        fmt: str = "json",
    ) -> dict[str, object]:
        captured["client"] = client_arg
        captured["value"] = value
        captured["context_lines"] = context_lines
        captured["limit"] = limit
        captured["fmt"] = fmt
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


class _Untouched:
    """Every plugin call fails the test: a refused query must not reach it."""

    def __getattr__(self, name: str):
        raise AssertionError(f"refused query reached the client ({name})")


@pytest.mark.parametrize("op, params", [
    ("read_bytes", {"address": "0x1000", "length": 0}),   # the plugin read 1 byte for 0
    ("read_bytes", {"address": "0x1000", "length": 4097}),
    ("read_words", {"address": "0x1000", "count": 0}),
    ("read_words", {"address": "0x1000", "count": 257}),
    ("disassemble_at", {"address": "0x1000", "count": 0}),
    ("disassemble_at", {"address": "0x1000", "count": 129}),
    ("disassemble_batch", {"addresses": ["0x1000"], "count": 0}),
    ("disassemble_batch", {"addresses": ["0x1000"], "context_lines": 17}),
])
def test_ops_hold_the_dedicated_tools_bounds(op: str, params: dict) -> None:
    result = execute_collect(_Untouched(), [{"id": "q", "op": op, "params": params}])

    query = _first_query(result)
    assert query["result"]["ok"] is False
    error = query["result"]["errors"][0]
    assert error["code"] == ErrorCode.INVALID_REQUEST.value
    assert "must be between" in error["message"]
