"""Stage 2b: prove the strict budget path is reachable at all.

``collect`` documents ``mode: "strict"`` as raising RESULT_TOO_LARGE once
``max_result_tokens`` is exceeded.  Nothing so far showed the path had ever been
taken -- and with the old estimator, which under-reported numeric payloads by
roughly a factor of two, it plausibly never was.  These run against the live
program so the payload sizes are real ones.
"""
from __future__ import annotations

import pytest

from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes
from bridge.error_handlers import install_error_handlers
from bridge.features.collect import execute_collect
from bridge.utils.logging import SafetyLimitExceeded
from bridge.utils.tokens import estimate_tokens

#: A query that returns a real, comfortably-sized payload.
POOL_READ = {
    "id": "pool",
    "op": "read_words",
    "params": {"address": "0x002afb34", "count": 64},
}


@pytest.fixture(scope="module")
def http(client):
    """The real request path, where SafetyLimitExceeded becomes an envelope.

    The route wrapper closes the client it is handed, so the factory builds a
    fresh one per request rather than sharing the session fixture's.
    """

    from bridge.tests.live.conftest import GHIDRA_URL
    from bridge.ghidra.client import GhidraClient

    app = Starlette(
        routes=make_routes(lambda: GhidraClient(GHIDRA_URL, timeout=120), enable_writes=False)
    )
    install_error_handlers(app)
    with TestClient(app) as test_client:
        yield test_client


def _run(client, *, budget):
    return execute_collect(client, [POOL_READ], result_budget=budget)


def _post(http, *, budget):
    response = http.post(
        "/api/collect.json",
        json={"queries": [POOL_READ], "result_budget": budget},
    )
    return response


def test_the_query_is_big_enough_to_be_worth_bounding(client):
    """Guard the guard: a budget test on an empty payload proves nothing."""

    result = _run(client, budget={"max_result_tokens": None, "mode": "auto_trim"})
    meta = result["meta"]
    assert meta["estimate_tokens"] > 100, meta


def _batch(client, *, budget):
    """Three queries where the middle one is the only one over budget."""

    return execute_collect(
        client,
        [
            {"id": "before", "op": "read_words",
             "params": {"address": "0x002afb34", "count": 2}},
            {"id": "over", "op": "read_words",
             "params": {"address": "0x002afb34", "count": 64}},
            {"id": "after", "op": "read_words",
             "params": {"address": "0x002afb34", "count": 2}},
        ],
        result_budget=budget,
    )


def test_a_request_budget_violation_no_longer_takes_the_batch_with_it(client):
    """Stage 5: both budget levels drop one sub-result, not the whole batch.

    Whoever sends a batch wants the other answers.  Before this, a per-query
    violation dropped one result while a request-level violation raised out of
    execute_collect and the caller got a single error instead of twelve results.
    """

    result = _batch(client, budget={"max_result_tokens": 60, "mode": "strict"})

    by_id = {entry["id"]: entry for entry in result["queries"]}
    assert by_id["before"]["result"]["ok"] is True
    assert by_id["over"]["result"]["ok"] is False
    assert by_id["over"]["result"]["errors"][0]["code"] == "RESULT_TOO_LARGE"
    assert by_id["after"]["result"]["ok"] is True, "the batch continued"


def test_the_dropped_queries_are_named_not_just_counted(client):
    """A partial batch must not read like a complete one."""

    result = _batch(client, budget={"max_result_tokens": 60, "mode": "strict"})
    assert result["meta"]["dropped_by_budget"] == ["over"]


def test_nothing_is_named_when_nothing_was_dropped(client):
    result = _batch(client, budget={"max_result_tokens": None, "mode": "auto_trim"})
    assert "dropped_by_budget" not in result["meta"]
    assert all(entry["result"]["ok"] for entry in result["queries"])


def test_both_modes_report_what_they_dropped(client):
    """auto_trim and strict differ in how much they drop, not in whether they say so.

    auto_trim marks the budget spent once it overflows, so later queries fall
    too; strict does not consume on refusal, so a small query after a large one
    still fits.  Both name every id they dropped.
    """

    for mode in ("strict", "auto_trim"):
        result = _batch(client, budget={"max_result_tokens": 60, "mode": mode})
        dropped = result["meta"]["dropped_by_budget"]
        assert "over" in dropped, mode
        failed = {
            entry["id"]
            for entry in result["queries"]
            if not entry["result"]["ok"]
        }
        assert failed == set(dropped), (mode, failed, dropped)


def test_the_partial_batch_still_validates(client):
    from bridge.api.validators import validate_payload

    result = _batch(client, budget={"max_result_tokens": 60, "mode": "strict"})
    valid, errors = validate_payload("collect.v1.json", result)
    assert valid, errors


def test_strict_mode_actually_returns_result_too_large(http):
    """The Stage 2b requirement, restated for Stage 5's partial behaviour.

    The error still appears, but per sub-result rather than as a 413 for the
    whole request: a single-query batch over budget now returns HTTP 200 with
    that one query failed and named in dropped_by_budget.
    """

    response = _post(http, budget={"max_result_tokens": 10, "mode": "strict"})

    assert response.status_code == 200
    payload = response.json()["data"]
    assert payload["meta"]["dropped_by_budget"] == ["pool"]
    codes = [
        error["code"]
        for entry in payload["queries"]
        for error in (entry["result"].get("errors") or [])
    ]
    assert codes == ["RESULT_TOO_LARGE"]


def test_strict_mode_reaches_the_limit_check_with_a_real_payload(client):
    """The path itself, with the numbers that prove it was exercised.

    Since Stage 5 the limit no longer escapes execute_collect, so the evidence
    is the error message rather than a raised exception.  It still carries the
    estimate that triggered it -- under the pre-Stage-2b estimator this payload
    counted as a handful of tokens and would have passed a budget of 10 untouched.
    """

    result = _run(client, budget={"max_result_tokens": 10, "mode": "strict"})
    message = result["queries"][0]["result"]["errors"][0]["message"]

    assert "10" in message
    estimate = result["queries"][0]["meta"]["estimate_tokens"]
    assert estimate > 100


def test_both_budget_levels_now_behave_the_same(client, http):
    """The asymmetry Stage 2b recorded, fixed in Stage 5.

    A per-query violation and a request-level one both drop the offending
    sub-result and leave the batch intact.
    """

    per_query = execute_collect(
        client,
        [{**POOL_READ, "result_budget": {"max_result_tokens": 10, "mode": "strict"}}],
        result_budget={"max_result_tokens": None, "mode": "auto_trim"},
    )
    codes = [
        error["code"]
        for entry in per_query["queries"]
        for error in (entry["result"].get("errors") or [])
    ]
    assert codes == ["RESULT_TOO_LARGE"]

    assert _post(http, budget={"max_result_tokens": 10, "mode": "strict"}).status_code == 200


def test_a_generous_strict_budget_lets_the_query_through(client):
    """Strict must bind on size, not simply always refuse."""

    sized = _run(client, budget={"max_result_tokens": None, "mode": "auto_trim"})
    needed = sized["meta"]["estimate_tokens"]

    result = _run(client, budget={"max_result_tokens": needed * 4, "mode": "strict"})
    envelopes = [entry["result"] for entry in result["queries"]]
    assert all(envelope["ok"] for envelope in envelopes), result


def test_the_budget_is_measured_against_the_real_payload(client):
    """The estimate must match what the response actually serializes to.

    This is the whole point of Stage 2b: under the old estimator this payload --
    64 integers and two short strings -- counted as a handful of tokens, so a
    budget of 10 would have let it straight through.
    """

    result = _run(client, budget={"max_result_tokens": None, "mode": "auto_trim"})
    payload = result["queries"][0]["result"]["data"]

    reported = result["meta"]["estimate_tokens"]
    direct = estimate_tokens(payload)
    assert direct > 0
    # The aggregate covers the query envelope, so it is at least the payload's.
    assert reported >= direct
    assert reported <= direct * 2


def test_auto_trim_omits_rather_than_aborts(client):
    """auto_trim is soft in the sense that it does not raise.

    It still reports RESULT_TOO_LARGE for the sub-result it dropped, and says so
    in the notes -- which is correct: an omitted result that looked like a
    delivered one would be Stage 2 all over again.
    """

    result = _run(client, budget={"max_result_tokens": 10, "mode": "auto_trim"})

    entry = result["queries"][0]
    assert entry["result"]["ok"] is False
    assert [error["code"] for error in entry["result"]["errors"]] == ["RESULT_TOO_LARGE"]
    assert entry["meta"]["truncated"] is True
