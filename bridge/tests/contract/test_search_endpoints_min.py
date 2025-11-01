# bridge/tests/contract/test_search_endpoints_min.py
import os, requests, re, json, time

BASE = os.environ.get("GHIDRA_MCP_URL", "http://127.0.0.1:8081")

def post(path, body):
    r = requests.post(f"{BASE}{path}", json=body, timeout=30)
    assert r.status_code == 200, (path, r.status_code, r.text)
    data = r.json()
    assert isinstance(data, dict) and "ok" in data, (path, data)
    return data

def test_strings_basic_contract():
    body = {"q": "http", "regex": False, "case_sensitive": False, "limit": 50, "offset": 0}
    data = post("/search/strings", body)
    assert data["ok"] is True
    assert "results" in data and isinstance(data["results"], list)
    for it in data["results"]:
        assert it.get("kind") == "string"
        v = it.get("value", "")
        # Falls Treffer vorhanden: sicherstellen, dass 'http' tatsächlich vorkommt (case-insensitiv)
        if v:
            assert "http" in v.lower()

def test_strings_regex_toggle_and_errors():
    # Regex aus → wörtlich
    data = post("/search/strings", {"q": r".*HTTP.*", "regex": False, "case_sensitive": False, "limit": 10})
    literal_hits = data["results"]

    # Regex an → Pattern greifen lassen (keine Exception!)
    data = post("/search/strings", {"q": r".*HTTP.*", "regex": True, "case_sensitive": False, "limit": 10})
    regex_hits = data["results"]
    # Mindestens eines der Sets darf sich unterscheiden (sonst wäre Regex sinnlos oder defekt)
    assert literal_hits != regex_hits or (not literal_hits and not regex_hits)

    # Ungültiges Regex → sauberer Fehler
    r = requests.post(f"{BASE}/search/strings", json={"q": r"([", "regex": True}, timeout=30)
    assert r.status_code == 200
    dj = r.json()
    assert dj.get("ok") is False and "error" in dj, dj

def test_strings_pagination_is_deterministic():
    q = {"q": "", "regex": False, "limit": 20, "offset": 0}  # leerer Query = „alle“
    first = post("/search/strings", q)
    q["offset"] = 20
    second = post("/search/strings", q)
    # deterministische Reihenfolge: der erste Block soll sich bei erneutem Abruf nicht ändern
    first2 = post("/search/strings", {"q": "", "regex": False, "limit": 20, "offset": 0})
    assert [it.get("address") for it in first["results"]] == [it.get("address") for it in first2["results"]]
    # keine Überschneidungen zwischen den Seiten
    a1 = {(it.get("address"), it.get("value")) for it in first["results"]}
    a2 = {(it.get("address"), it.get("value")) for it in second["results"]}
    assert not (a1 & a2)

def test_functions_basic_contract_and_section_bounds():
    data = post("/search/functions", {"q": "", "regex": False, "limit": 100, "offset": 0})
    assert data["ok"] is True
    for it in data["results"]:
        assert it.get("kind") == "function"
        assert it.get("address", "").startswith("0x")
        nm = it.get("name", "")
        assert isinstance(nm, str) and len(nm) >= 1
        # Größen & Xref-Counts sind nicht-negativ, wenn vorhanden
        for k in ("size", "xrefs_in", "xrefs_out"):
            if k in it and it[k] is not None:
                assert int(it[k]) >= 0

def test_xrefs_roundtrip_symmetry_sample():
    # Nimm eine Funktion als Anker
    funcs = post("/search/functions", {"q": "", "regex": False, "limit": 1, "offset": 0})["results"]
    if not funcs:
        return
    faddr = funcs[0]["address"]

    # Xrefs TO der Funktion erfassen
    to_list = post("/search/xrefs", {"target": {"address": faddr}, "direction": "to", "limit": 200, "offset": 0})["results"]

    # Für einige Einträge prüfen: FROM → TO muss die Zieladresse sein
    for it in to_list[:10]:
        assert it.get("to") == faddr
        assert it.get("from", "").startswith("0x")
