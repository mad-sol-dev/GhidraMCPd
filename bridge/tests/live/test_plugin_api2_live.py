"""R.24 phase 2 against the reference program: statuses, codes, and the header.

Read-only.  Every probe is a read or a dry run (/createLabel with
dry_run=true changes nothing even if its checks were missing); each test
ends by confirming the program has no unsaved changes.  Skips below API 2.
"""
from __future__ import annotations

import httpx
import pytest

from bridge.ghidra.client import GhidraClient
from bridge.tests.live.conftest import GHIDRA_URL
from bridge.utils.errors import UpstreamFailed

INSIDE_FUNCTION = "0x002af9c4"  # usbd_init_phy_cep starts at 0x002af9c0
UNMAPPED = "0x7f000000"


def _get(path: str, **params) -> httpx.Response:
    return httpx.get(f"{GHIDRA_URL}{path}", params=params, timeout=30)


@pytest.fixture(scope="module", autouse=True)
def api2(client):
    if _get("plugin_version").json().get("api") != 2:
        pytest.skip("plugin does not speak API 2")


@pytest.fixture(autouse=True)
def unchanged():
    yield
    assert _get("check_dirty_state").json()["changed"] == "false"


def _error(response: httpx.Response) -> tuple[int, str]:
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["status"] == "error" and body["error"]
    return response.status_code, body["code"]


def test_every_answer_carries_the_header():
    for response in (_get("plugin_version"), _get("read_dword", address="0x002af9c0"),
                     _get("read_dword", address=UNMAPPED)):
        assert response.headers["X-GhidraMCP-API"] == "2"


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
