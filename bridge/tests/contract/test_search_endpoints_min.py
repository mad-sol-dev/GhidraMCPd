# bridge/tests/contract/test_search_endpoints_min.py
import json
import os
import re

import pytest
import requests

from bridge.tests.contract._live_bridge import (
    BASE,
    assert_pagination_contract,
    post,
    requires_live_bridge,
)

pytestmark = requires_live_bridge


def _string_from_item(item):
    for key in ("s", "value", "literal", "string"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    return ""

def test_strings_basic_contract():
    body = {"query": "http", "limit": 50, "page": 1}
    payload = post("/api/search_strings.json", body)
    assert payload["ok"] is True
    assert payload["errors"] == []
    data = payload["data"]
    assert "items" in data and isinstance(data["items"], list)
    assert isinstance(data.get("has_more"), bool)
    for item in data["items"]:
        literal = _string_from_item(item)
        # Falls Treffer vorhanden: sicherstellen, dass 'http' tatsächlich vorkommt (case-insensitiv)
        if literal:
            assert "http" in literal.lower()

def test_strings_regex_toggle_and_errors():
    # Regex aus → wörtlich (Patternzeichen als Literal behandeln)
    literal_payload = post(
        "/api/search_strings.json",
        {"query": r".*HTTP.*", "limit": 10, "page": 1},
    )
    literal_hits = literal_payload["data"]["items"]

    # Regex an → Pattern greifen lassen (über Trefferliste simulieren)
    regex_payload = post(
        "/api/search_strings.json",
        {"query": "HTTP", "limit": 10, "page": 1},
    )
    regex_hits = [
        item
        for item in regex_payload["data"]["items"]
        if re.search(r".*HTTP.*", _string_from_item(item) or "")
    ]
    # Mindestens eines der Sets darf sich unterscheiden (sonst wäre Regex sinnlos oder defekt)
    assert literal_hits != regex_hits or (not literal_hits and not regex_hits)

    # Ungültiges Limit → sauberer Fehler
    r = requests.post(
        f"{BASE}/api/search_strings.json",
        json={"query": "http", "limit": 0, "page": 1},
        timeout=30,
    )
    assert r.status_code == 400
    dj = r.json()
    assert dj.get("ok") is False and isinstance(dj.get("errors"), list) and dj["errors"], dj

    invalid_page = requests.post(
        f"{BASE}/api/search_strings.json",
        json={"query": "http", "limit": 10, "page": 0},
        timeout=30,
    )
    assert invalid_page.status_code == 400
    invalid_page_payload = invalid_page.json()
    assert (
        invalid_page_payload.get("ok") is False
        and isinstance(invalid_page_payload.get("errors"), list)
        and invalid_page_payload["errors"]
    ), invalid_page_payload

def test_strings_pagination_is_deterministic():
    q = {"query": "http", "limit": 20, "page": 1}
    first = post("/api/search_strings.json", q)["data"]
    q["page"] = 2
    second = post("/api/search_strings.json", q)["data"]
    # deterministische Reihenfolge: der erste Block soll sich bei erneutem Abruf nicht ändern
    first2 = post("/api/search_strings.json", {"query": "http", "limit": 20, "page": 1})["data"]
    assert [it.get("addr") for it in first["items"]] == [
        it.get("addr") for it in first2["items"]
    ]
    # keine Überschneidungen zwischen den Seiten
    a1 = {(it.get("addr"), _string_from_item(it)) for it in first["items"]}
    a2 = {(it.get("addr"), _string_from_item(it)) for it in second["items"]}
    assert not (a1 & a2)

    # A page past the end is empty.  The page number has to stay inside the
    # batch ceiling: the server bounds page*limit by GHIDRA_MCP_MAX_ITEMS_PER_BATCH
    # (256) and answers 413 above it, so the original page+100 could never have
    # reached this assertion.
    far_page = 256 // 20
    empty = post(
        "/api/search_strings.json",
        {"query": "http", "limit": 20, "page": far_page},
    )["data"]
    assert empty["items"] == []
    assert empty["has_more"] is False
    assert empty["truncated"] is False


def test_a_page_beyond_the_batch_ceiling_is_refused_not_silently_emptied():
    """The guard that made the old page+100 unreachable, asserted on purpose.

    An over-wide window must fail loudly.  Returning an empty page instead would
    be indistinguishable from "no more results".
    """

    response = requests.post(
        f"{BASE}/api/search_strings.json",
        json={"query": "http", "limit": 20, "page": 101},
        timeout=30,
    )
    assert response.status_code == 413
    payload = response.json()
    assert payload["ok"] is False
    assert payload["errors"][0]["code"] == "RESULT_TOO_LARGE"

def test_functions_basic_contract_and_section_bounds():
    data = post(
        "/api/search_functions.json",
        {"query": "FUN_", "limit": 100, "page": 1},
    )
    assert data["ok"] is True
    items = data["data"]["items"]
    assert isinstance(data["data"].get("has_more"), bool)
    for it in items:
        kind = it.get("kind")
        if kind is not None:
            assert kind == "function"
        assert it.get("address", "").startswith("0x")
        nm = it.get("name", "")
        assert isinstance(nm, str) and len(nm) >= 1
        # Größen & Xref-Counts sind nicht-negativ, wenn vorhanden
        for k in ("size", "xrefs_in", "xrefs_out"):
            if k in it and it[k] is not None:
                assert int(it[k]) >= 0

def test_xrefs_roundtrip_symmetry_sample():
    # Nimm eine Funktion als Anker
    funcs = post(
        "/api/search_functions.json",
        {"query": "FUN_", "limit": 1, "page": 1},
    )["data"]["items"]
    if not funcs:
        return
    faddr = funcs[0]["address"]

    # Xrefs TO der Funktion erfassen
    to_list = post(
        "/api/search_xrefs_to.json",
        {"address": faddr, "query": "call", "limit": 200, "page": 1},
    )["data"]["items"]

    # Für einige Einträge prüfen: FROM → TO muss die Zieladresse sein
    for it in to_list[:10]:
        assert it.get("from_address", "").startswith("0x")
        assert it.get("context") is not None
        assert it.get("target_address") == faddr

def test_search_strings_has_more_contract():
    """Contract: /api/search_strings.json reports its pagination honestly.

    Since Stage 3 `total` is present only when it is actually known -- a
    cursor-paged search does not know it, and null would let a caller read a
    placeholder as a count.  Where present it must agree with `has_more`.
    `truncated` is the field that always answers "is this everything?".
    """
    body = {
        "query": "http",  # non-empty per schema; any non-empty token works
        "limit": 1,       # tiny for deterministic expectation
        "page": 1
    }
    envelope = post("/api/search_strings.json", body)

    # standard envelope
    assert isinstance(envelope, dict), "expected standard envelope"
    assert envelope.get("ok") is True, f"unexpected envelope: {envelope}"
    assert "data" in envelope, "envelope must include data"
    data = envelope["data"]

    assert_pagination_contract(data, path="/api/search_strings.json")

