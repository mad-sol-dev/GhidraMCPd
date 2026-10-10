"""apply_label: a label at any address, and an answer that says what happened.

The old path (renameDataAtAddress) skipped every address without defined data
-- every MMIO register -- and /renameData reported "attempted" regardless.
"""
from __future__ import annotations

import pytest

from bridge.features import labels, mutations
from bridge.utils.errors import UpstreamFailed
from bridge.ghidra.client import STRUCTURED_LISTING_UNSUPPORTED


class FakeClient:
    def __init__(self, answer=None, *, existing=(), primary_before=None, mapped=False):
        self.calls = []
        self._answer = answer
        self._existing = list(existing)
        self._primary_before = primary_before
        self._mapped = mapped
        self.last_error = None

    def create_label(self, address, name, *, dry_run):
        self.calls.append((address, name, dry_run))
        if self._answer is not None:
            return self._answer(address, name, dry_run) if callable(self._answer) else self._answer
        already = name in self._existing
        created = not dry_run and not already
        return {
            "status": "ok",
            "address": f"0x{address:08x}",
            "name": name,
            "dry_run": dry_run,
            "mapped": self._mapped,
            "already_present": already,
            "created": created,
            "primary": created and self._primary_before is None,
            "primary_before": self._primary_before,
            "existing": list(self._existing),
        }


@pytest.fixture(autouse=True)
def _clean_ledger():
    mutations.clear()
    yield
    mutations.clear()


def test_an_unmapped_mmio_register_is_labelled_when_writes_are_on():
    client = FakeClient()
    data = labels.apply_label(client, address=0xB1006000, name="FMI_CTL", dry_run=False, writes_enabled=True)

    assert client.calls == [(0xB1006000, "FMI_CTL", False)]
    assert data["applied"] is True
    assert data["primary"] is True
    assert any("outside every memory block" in n for n in data["notes"])
    [entry] = mutations.since_last_save()
    assert (entry.kind, entry.target, entry.new, entry.applied) == ("label", "0xb1006000", "FMI_CTL", True)


def test_a_dry_run_asks_ghidra_but_writes_nothing():
    client = FakeClient()
    data = labels.apply_label(client, address=0xB1006000, name="FMI_CTL", dry_run=True, writes_enabled=True)

    assert client.calls == [(0xB1006000, "FMI_CTL", True)]
    assert data["applied"] is False
    [entry] = mutations.since_last_save()
    assert entry.applied is False and entry.reason == "dry_run"


def test_writes_disabled_turns_a_real_call_into_a_dry_run():
    client = FakeClient()
    data = labels.apply_label(client, address=0xB1006000, name="FMI_CTL", dry_run=False, writes_enabled=False)

    assert client.calls[0][2] is True
    assert data["applied"] is False
    assert any("writes disabled" in n for n in data["notes"])
    assert mutations.since_last_save()[0].reason == "writes_disabled"


def test_the_same_name_twice_is_not_a_second_label():
    client = FakeClient(existing=["FMI_CTL"], primary_before="FMI_CTL")
    data = labels.apply_label(client, address=0xB1006000, name="FMI_CTL", dry_run=False, writes_enabled=True)

    assert data["applied"] is False
    assert data["already_present"] is True
    assert mutations.since_last_save() == []


def test_a_user_named_primary_is_kept_and_said_so():
    client = FakeClient(existing=["usbd_init_phy_cep"], primary_before="usbd_init_phy_cep", mapped=True)
    data = labels.apply_label(client, address=0x002AF9C0, name="alias", dry_run=False, writes_enabled=True)

    assert data["applied"] is True
    assert data["primary"] is False
    assert any("secondary" in n for n in data["notes"])
    entry = mutations.since_last_save()[0]
    assert entry.old is None
    assert entry.detail == "beside usbd_init_phy_cep"
    # Found live: rendered as "DMAC_BA -> R12_live_check", which reads as a rename.
    assert mutations.render_lines([entry]) == ["0x002af9c0  label     + alias  (beside usbd_init_phy_cep)"]


def test_ghidras_name_rule_is_reported_as_a_bad_request():
    class Refusing(FakeClient):
        def create_label(self, address, name, *, dry_run):
            # the plugin's HTTP 400 INVALID_REQUEST, as the client raises it
            raise UpstreamFailed("invalid label name 'a b': contains spaces",
                                 code="INVALID_REQUEST", status=400)

    with pytest.raises(labels.LabelRejected, match="invalid label name"):
        labels.apply_label(Refusing(), address=0xB1006000, name="a b", dry_run=True)


def test_any_other_plugin_failure_is_not_a_rejected_name():
    class Failing(FakeClient):
        def create_label(self, address, name, *, dry_run):
            raise UpstreamFailed("rename failed: boom", code="INTERNAL", status=500)

    with pytest.raises(UpstreamFailed, match="boom"):
        labels.apply_label(Failing(), address=0xB1006000, name="ok_name", dry_run=True)


def test_a_plugin_without_the_route_is_unavailable_not_success():
    class Old(FakeClient):
        def create_label(self, address, name, *, dry_run):
            self.last_error = type("E", (), {"reason": STRUCTURED_LISTING_UNSUPPORTED})()
            return None

    with pytest.raises(labels.LabelUnavailable, match="without JSON"):
        labels.apply_label(Old(), address=0xB1006000, name="FMI_CTL", dry_run=False, writes_enabled=True)


def test_an_empty_name_never_reaches_ghidra():
    client = FakeClient()
    with pytest.raises(labels.LabelRejected):
        labels.apply_label(client, address=0xB1006000, name="   ", dry_run=True)
    assert client.calls == []


# --- the client against a mocked plugin ---------------------------------------

import json  # noqa: E402
from urllib.parse import parse_qs  # noqa: E402

import httpx  # noqa: E402

from bridge.ghidra.client import GhidraClient  # noqa: E402
from bridge.tests.plugin_http import plugin_transport  # noqa: E402


#: What /api/current_program.json answers; every write checks it first (R.26).
STATUS = {"domain_file_id": "prog-1", "locked": False, "state": "READY",
          "state_duration_seconds": 1, "warnings": []}


def _client(status, body):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/current_program.json":
            return httpx.Response(200, text=json.dumps(STATUS))
        seen.append(request)
        return httpx.Response(status, text=body)

    return GhidraClient("http://ghidra.test/", transport=plugin_transport(handler)), seen


def test_the_client_posts_address_name_and_an_explicit_dry_run_flag():
    answer = {"status": "ok", "created": True}
    client, seen = _client(200, json.dumps(answer))

    assert client.create_label(0xB1006000, "FMI_CTL", dry_run=False) == answer
    request = seen[0]
    assert request.method == "POST" and request.url.path == "/createLabel"
    assert request.url.params["domain_file_id"] == "prog-1"
    assert parse_qs(request.content.decode()) == {
        "address": ["0xb1006000"], "name": ["FMI_CTL"], "dry_run": ["false"],
    }


def test_a_text_answer_is_no_answer():
    client, _ = _client(200, "Rename data attempted")
    assert client.create_label(0xB1006000, "FMI_CTL", dry_run=True) is None
    assert client.last_error.reason == STRUCTURED_LISTING_UNSUPPORTED


def test_a_missing_route_is_a_plugin_too_old():
    client, _ = _client(404, "<h1>404 Not Found</h1>")
    with pytest.raises(UpstreamFailed) as raised:
        client.create_label(0xB1006000, "FMI_CTL", dry_run=True)
    assert raised.value.code == "PLUGIN_TOO_OLD"


def test_a_refusal_is_a_rejected_name_not_a_transport_failure():
    """Found live: an invalid name came back as UNAVAILABLE.  Under API 2 the
    plugin answers HTTP 400 INVALID_REQUEST."""

    body = json.dumps({"status": "error", "code": "INVALID_REQUEST",
                       "error": "invalid label name 'a b': Symbol name contains invalid characters: a b"})
    client, _ = _client(400, body)
    with pytest.raises(labels.LabelRejected, match="invalid label name"):
        labels.apply_label(client, address=0xB1006000, name="a b", dry_run=True)
