"""Gate for contract tests that need a running bridge server.

These talk HTTP to a bridge at ``$BASE_URL`` (default 127.0.0.1:8000), which in
turn talks to Ghidra.  Two ways to be wrong that this module rules out:

* **Passing without checking anything.**  If no bridge answers, the tests skip
  with a reason naming the URL -- they never report success.
* **Passing against the wrong program.**  Assertions here are about
  ZK-INKJET-NANO-APP.bin.  Run against a different binary they would be
  measuring something else, so the identity is checked and mismatches skip with
  the two checksums printed.

``RUN_LIVE_TESTS=0`` disables them outright.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

import pytest
import requests

BASE = (
    os.environ.get("BASE_URL")
    or os.environ.get("GHIDRA_MCP_URL")
    or "http://127.0.0.1:8000"
)

#: The frozen copy these assertions describe.
EXPECTED_SHA256 = "3be9028b01c0007aab9192877341918a0bc155beef55ac17e7e8f3bcc95151ea"


def _probe() -> tuple[Optional[Dict[str, Any]], str]:
    """Return (project_info, reason).  ``project_info`` is None when unusable."""

    if os.environ.get("RUN_LIVE_TESTS", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return None, "live tests disabled (RUN_LIVE_TESTS)"

    try:
        response = requests.get(f"{BASE}/api/project_info.json", timeout=5)
    except requests.RequestException as exc:
        return None, f"no bridge at {BASE} ({type(exc).__name__})"

    if response.status_code != 200:
        return None, f"bridge at {BASE} returned HTTP {response.status_code}"

    try:
        envelope = response.json()
    except ValueError:
        return None, f"bridge at {BASE} returned no JSON"

    data = envelope.get("data") if isinstance(envelope, dict) else None
    if not isinstance(data, dict):
        return None, f"bridge at {BASE} returned no project data"

    actual = str(data.get("executable_sha256", "")).lower()
    if actual != EXPECTED_SHA256:
        return None, (
            f"bridge at {BASE} is serving a different program "
            f"(sha256 {actual[:16] or '?'}…, expected {EXPECTED_SHA256[:16]}…)"
        )

    return data, ""


PROJECT_INFO, SKIP_REASON = _probe()

#: Apply as ``pytestmark`` in modules that need a live bridge.
requires_live_bridge = pytest.mark.skipif(PROJECT_INFO is None, reason=SKIP_REASON)


def post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST to the bridge and return the envelope, asserting its shape."""

    response = requests.post(f"{BASE}{path}", json=payload, timeout=30)
    assert response.status_code == 200, (path, response.status_code, response.text)
    envelope = response.json()
    assert isinstance(envelope, dict) and "ok" in envelope, (path, envelope)
    assert "data" in envelope and "errors" in envelope, (path, envelope)
    assert isinstance(envelope["errors"], list), (path, envelope)
    return envelope


def post_data(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST and return ``data``, asserting the call succeeded."""

    envelope = post(path, payload)
    assert envelope.get("ok") is True, (path, envelope)
    assert envelope.get("errors") == [], (path, envelope)
    data = envelope.get("data")
    assert isinstance(data, dict), (path, envelope)
    return data


def assert_pagination_contract(data: Dict[str, Any], *, path: str) -> None:
    """Check the Stage 3 pagination contract on a search response.

    ``total`` is optional by design: a cursor-paged search does not know it, and
    an absent key is the only honest way to say so.  Where it *is* present it
    must agree with ``has_more``.  ``truncated`` is mandatory -- it is the field
    that makes omission visible without depending on a total.
    """

    for key in ("page", "limit", "items", "has_more", "truncated"):
        assert key in data, f"missing `{key}` in {path}: {data}"

    assert isinstance(data["items"], list), f"`items` should be a list in {path}"
    assert isinstance(data["has_more"], bool), f"`has_more` must be a boolean in {path}"
    assert isinstance(data["truncated"], bool), f"`truncated` must be a boolean in {path}"

    page = int(data["page"])
    limit = int(data["limit"])
    assert page >= 1, f"page must be >= 1 for {path}, got {page}"
    assert limit >= 1, f"limit must be >= 1 for {path}, got {limit}"

    if "total" in data:
        total = data["total"]
        assert isinstance(total, int) and not isinstance(total, bool), (
            f"a present total must be an integer for {path}, got {total!r}"
        )
        assert total >= 0, f"total must be >= 0 for {path}, got {total}"
        expected = (page * limit) < total
        assert data["has_more"] == expected, (
            f"has_more mismatch for {path}: expected {expected} but got "
            f"{data['has_more']} for page={page} limit={limit} total={total}"
        )

    # Whatever the total situation, truncation must not contradict has_more.
    if data["has_more"]:
        assert data["truncated"] is True, (
            f"{path} reports more pages but does not report truncation"
        )
