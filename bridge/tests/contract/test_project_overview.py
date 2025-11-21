from __future__ import annotations

from starlette.testclient import TestClient

from bridge.tests.contract.test_http_contracts import _assert_envelope


def test_project_overview(contract_client: TestClient) -> None:
    response = contract_client.get("/api/project_overview.json")
    assert response.status_code == 200
    envelope = response.json()
    _assert_envelope(envelope)

    data = envelope["data"]
    assert isinstance(data, dict)
    files = data.get("files")
    assert isinstance(files, list)
    assert any(entry.get("type") == "Program" for entry in files)

    for entry in files:
        assert set(entry.keys()) == {
            "domain_file_id",
            "name",
            "path",
            "type",
            "size",
        }
        assert isinstance(entry["name"], str)
        assert isinstance(entry["path"], str)
        assert isinstance(entry["type"], str)
        domain_id = entry["domain_file_id"]
        assert domain_id is None or isinstance(domain_id, str)
        size = entry["size"]
        if size is not None:
            assert isinstance(size, int)
            assert size >= 0
