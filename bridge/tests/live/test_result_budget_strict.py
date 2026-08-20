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


def test_strict_mode_actually_returns_result_too_large(http):
    """The requirement: a tight budget in strict mode must produce the error.

    Measured over the real request path, because that is where the limit
    exception is turned into an envelope.
    """

    response = _post(http, budget={"max_result_tokens": 10, "mode": "strict"})

    assert response.status_code == 413
    payload = response.json()
    assert payload["ok"] is False
    assert [error["code"] for error in payload["errors"]] == ["RESULT_TOO_LARGE"]


def test_strict_mode_reaches_the_limit_check_with_a_real_payload(client):
    """The path itself, with the numbers that prove it was exercised.

    Calling the feature function directly shows the raise, and the message
    carries the estimate that triggered it -- under the old estimator this
    payload counted as a handful of tokens and would have passed a budget of 10
    untouched.
    """

    with pytest.raises(SafetyLimitExceeded) as excinfo:
        _run(client, budget={"max_result_tokens": 10, "mode": "strict"})

    assert excinfo.value.limit == 10
    assert excinfo.value.attempted > 100


def test_request_level_strict_aborts_where_per_query_strict_does_not(client, http):
    """A behavioural asymmetry inside collect, recorded rather than changed.

    A per-query strict violation is caught inside execute_collect and returned
    as one failed sub-result, leaving the rest of the batch intact.  A
    request-level violation propagates out and the whole batch fails.  Both end
    up as RESULT_TOO_LARGE for the caller, but one is partial and one is total.
    Changing that is not part of this stage.
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

    assert _post(http, budget={"max_result_tokens": 10, "mode": "strict"}).status_code == 413


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
