"""R.24 phases 2 and 3 against the reference program: statuses, codes, the header.

Read-only.  Every probe is a read or a dry run (/createLabel with
dry_run=true changes nothing even if its checks were missing); each test
ends by confirming the program has no unsaved changes.  Skips unless the
plugin speaks the bridge's API level.
"""
from __future__ import annotations

import httpx
import pytest

from bridge.ghidra.client import REQUIRED_PLUGIN_API, GhidraClient
from bridge.tests.live.conftest import GHIDRA_URL
from bridge.utils.errors import UpstreamFailed

INSIDE_FUNCTION = "0x002af9c4"  # usbd_init_phy_cep starts at 0x002af9c0
UNMAPPED = "0x7f000000"


def _get(path: str, **params) -> httpx.Response:
    return httpx.get(f"{GHIDRA_URL}{path}", params=params, timeout=30)


@pytest.fixture(scope="module", autouse=True)
def api_level(client):
    if _get("plugin_version").json().get("api") != REQUIRED_PLUGIN_API:
        pytest.skip(f"plugin does not speak API {REQUIRED_PLUGIN_API}")


@pytest.fixture(autouse=True)
def unchanged():
    yield
    assert _get("check_dirty_state").json()["changed"] is False


def _error(response: httpx.Response) -> tuple[int, str]:
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["status"] == "error" and body["error"]
    return response.status_code, body["code"]


def test_every_answer_carries_the_header():
    for response in (_get("plugin_version"), _get("read_dword", address="0x002af9c0"),
                     _get("read_dword", address=UNMAPPED)):
        assert response.headers["X-GhidraMCP-API"] == str(REQUIRED_PLUGIN_API)


@pytest.mark.parametrize(
    "path, params, expected",
    [
        ("read_dword", {"address": "zzzz"}, (400, "INVALID_REQUEST")),
        ("read_dword", {}, (400, "INVALID_REQUEST")),
        ("read_dword", {"address": UNMAPPED}, (404, "UNMAPPED")),
        ("readBytes", {"address": UNMAPPED, "length": "4"}, (404, "UNMAPPED")),
        ("get_function_by_address", {"address": INSIDE_FUNCTION}, (404, "NOT_FOUND")),
        ("decompile_function", {"address": UNMAPPED}, (404, "NOT_FOUND")),
        ("disassemble", {"address": "zzzz", "fmt": "json"}, (400, "INVALID_REQUEST")),
        ("function_xrefs", {"name": "no_such_function_xyz"}, (404, "NOT_FOUND")),
        ("xrefs_to", {"address": "zzzz"}, (400, "INVALID_REQUEST")),
        ("searchScalars", {"value": "zz"}, (400, "INVALID_REQUEST")),
        # API 3: what used to be answered anyway
        ("readBytes", {"address": "0x00200000", "length": "0"}, (400, "INVALID_REQUEST")),
        ("readBytes", {"address": "0x00200000", "length": "4097"}, (400, "INVALID_REQUEST")),
        ("methods", {"limit": "abc"}, (400, "INVALID_REQUEST")),
        ("searchFunctions", {"query": "thunk", "cursor": "garbage"}, (400, "INVALID_REQUEST")),
        ("disassembleAt", {"address": UNMAPPED}, (404, "UNMAPPED")),
        ("disassembleAt", {"address": "0x00200060", "count": "0"}, (400, "INVALID_REQUEST")),
        ("xrefs_from", {"address": UNMAPPED}, (404, "UNMAPPED")),
    ],
)
def test_failures_have_a_status_and_a_code(path, params, expected):
    assert _error(_get(path, **params)) == expected


def test_a_known_function_without_callers_is_not_unknown():
    # boot_init exists; whatever its references, it is not a 404
    assert _get("function_xrefs", name="boot_init").status_code == 200


def test_a_missing_route_is_the_servers_own_404():
    response = _get("no_such_route_xyz")
    assert response.status_code == 404
    assert not response.text.lstrip().startswith("{")


def test_an_invalid_label_name_is_a_bad_request_on_a_dry_run():
    response = httpx.post(f"{GHIDRA_URL}createLabel", timeout=30,
                          data={"address": "0xb1006000", "name": "a b", "dry_run": "true"})
    assert _error(response) == (400, "INVALID_REQUEST")


def test_strings_carry_reference_counts():
    page = _get("strings", limit="5").json()
    assert all(isinstance(item["refs"], int) for item in page["items"])
    assert any(item["refs"] > 0 for item in _get("strings", limit="200").json()["items"])


def test_the_client_tells_absence_from_failure():
    client = GhidraClient(GHIDRA_URL, timeout=30)
    try:
        assert client.get_function_by_address(int(INSIDE_FUNCTION, 16)) is None
        assert client.last_error.code == "NOT_FOUND"
        assert client.read_bytes(int(UNMAPPED, 16), 4) is None
        assert client.last_error.code == "UNMAPPED"
        with pytest.raises(UpstreamFailed) as raised:
            client._request_lines("GET", "read_dword", key="READ_DWORD", params={"address": "zzzz"})
        assert raised.value.code == "INVALID_REQUEST"
    finally:
        client.close()


# --- API 3 --------------------------------------------------------------------


def test_flags_are_json_booleans():
    dirty = _get("check_dirty_state").json()
    assert dirty["changed"] is False and isinstance(dirty["can_save"], bool)


def test_a_cursor_from_another_search_is_refused():
    first = _get("searchFunctions", query="thunk", limit="2").json()
    assert first["has_more"] is True
    again = _get("searchFunctions", query="thunk", limit="2", cursor=first["cursor"]).json()
    assert again["items"] != first["items"]
    other = _get("searchFunctions", query="usb", limit="2", cursor=first["cursor"])
    assert _error(other) == (400, "INVALID_REQUEST")


def test_disassembly_from_inside_an_instruction_says_where_it_starts():
    # 0x00200062 is inside the instruction at 0x00200060; the next starts at 0x00200064
    listing = _get("disassembleAt", address="0x00200062", count="2", fmt="json").json()
    assert listing["requested"] == "0x00200062"
    assert listing["start"] == "0x00200064"
    assert listing["instructions"][0]["address"] == "0x00200064"


def test_addresses_outside_memory_are_not_hex_with_a_prefix():
    imports = _get("imports", limit="20").json()["items"]
    assert imports and not any("0xEXTERNAL" in line for line in imports)
    refs = _get("xrefs_to", address="0x10", limit="20").json()["items"]
    assert all(ref["address"].startswith("0x") and " " not in ref["address"] for ref in refs)


def test_a_complete_scalar_page_is_not_truncated():
    page = _get("searchScalars", value="0xB1008000", limit="5").json()
    assert "error" not in page and "truncated" not in page
