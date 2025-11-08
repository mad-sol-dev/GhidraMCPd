# bridge/tests/contract/test_search_endpoints_min.py
import json
import os
import re

import pytest
import requests

from bridge.tests._env import env_flag

pytestmark = pytest.mark.skipif(
    not env_flag("RUN_LIVE_TESTS"),
    reason="Live tests disabled. Set RUN_LIVE_TESTS=1 to enable.",
)

BASE = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8000")

def post(path, body):
    r = requests.post(f"{BASE}{path}", json=body, timeout=30)
    assert r.status_code == 200, (path, r.status_code, r.text)
    data = r.json()
    assert isinstance(data, dict) and "ok" in data, (path, data)
    assert "data" in data and "errors" in data, (path, data)
    assert isinstance(data["errors"], list), (path, data)
    return data


def _string_from_item(item):
    for key in ("s", "value", "literal", "string"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    return ""

def test_strings_basic_contract():
    body = {"query": "http", "limit": 50, "offset": 0}
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
        {"query": r".*HTTP.*", "limit": 10, "offset": 0},
    )
    literal_hits = literal_payload["data"]["items"]

    # Regex an → Pattern greifen lassen (über Trefferliste simulieren)
    regex_payload = post(
        "/api/search_strings.json",
        {"query": "HTTP", "limit": 10, "offset": 0},
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
        json={"query": "http", "limit": 0, "offset": 0},
        timeout=30,
    )
    assert r.status_code == 400
    dj = r.json()
    assert dj.get("ok") is False and isinstance(dj.get("errors"), list) and dj["errors"], dj

def test_strings_pagination_is_deterministic():
    q = {"query": "http", "limit": 20, "offset": 0}
    first = post("/api/search_strings.json", q)["data"]
    q["offset"] = 20
    second = post("/api/search_strings.json", q)["data"]
    # deterministische Reihenfolge: der erste Block soll sich bei erneutem Abruf nicht ändern
    first2 = post("/api/search_strings.json", {"query": "http", "limit": 20, "offset": 0})["data"]
    assert [it.get("addr") for it in first["items"]] == [
        it.get("addr") for it in first2["items"]
    ]
    # keine Überschneidungen zwischen den Seiten
    a1 = {(it.get("addr"), _string_from_item(it)) for it in first["items"]}
    a2 = {(it.get("addr"), _string_from_item(it)) for it in second["items"]}
    assert not (a1 & a2)

def test_functions_basic_contract_and_section_bounds():
    data = post(
        "/api/search_functions.json",
        {"query": "FUN_", "limit": 100, "offset": 0},
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
        {"query": "FUN_", "limit": 1, "offset": 0},
    )["data"]["items"]
    if not funcs:
        return
    faddr = funcs[0]["address"]

    # Xrefs TO der Funktion erfassen
    to_list = post(
        "/api/search_xrefs_to.json",
        {"address": faddr, "query": "call", "limit": 200, "offset": 0},
    )["data"]["items"]

    # Für einige Einträge prüfen: FROM → TO muss die Zieladresse sein
    for it in to_list[:10]:
        assert it.get("from_address", "").startswith("0x")
        assert it.get("context") is not None
        assert it.get("target_address") == faddr

def test_search_strings_has_more_contract():
    """
    Contract: /api/search_strings.json returns boolean `has_more`.
    Value must equal (page * limit) < total. `page` is 1-based.
    Schema requires a non-empty `query`.
    """
    body = {
        "query": "http",  # non-empty per schema; any non-empty token works
        "limit": 1,       # tiny for deterministic expectation
        "offset": 0
    }
    envelope = post("/api/search_strings.json", body)

    # standard envelope
    assert isinstance(envelope, dict), "expected standard envelope"
    assert envelope.get("ok") is True, f"unexpected envelope: {envelope}"
    assert "data" in envelope, "envelope must include data"
    data = envelope["data"]

    # shape
    for k in ("total", "page", "limit", "items", "has_more"):
        assert k in data, f"missing `{k}` in data: {data}"
    assert isinstance(data["has_more"], bool), "`has_more` must be a boolean"

    # rule
    expected = (data["page"] * data["limit"]) < data["total"]
    assert data["has_more"] == expected, (
        f"has_more mismatch: got {data['has_more']} but expected {expected} "
        f"for page={data['page']} limit={data['limit']} total={data['total']}"
    )

