from __future__ import annotations

from typing import Dict, Iterable, List

from starlette.applications import Starlette
from starlette.testclient import TestClient

from bridge.api.routes import make_routes


class _ProjectInfoStub:
    def __init__(self, payload: Dict[str, object]) -> None:
        self._payload = payload
        self.closed = False

    def get_project_info(self) -> Dict[str, object]:
        return self._payload

    def close(self) -> None:
        self.closed = True


def _make_client(payload: Dict[str, object]) -> Iterable[TestClient]:
    def factory() -> _ProjectInfoStub:
        return _ProjectInfoStub(payload)

    app = Starlette(routes=make_routes(factory, enable_writes=False))
    with TestClient(app) as client:
        yield client


def test_project_info_route_normalises_payload() -> None:
    payload: Dict[str, object] = {
        "program_name": "stub.bin",
        "executable_path": None,
        "executable_md5": None,
        "executable_sha256": None,
        "executable_format": "ELF",
        "image_base": "0x00100000",
        "language_id": "ARM:LE:32:v7",
        "compiler_spec_id": "default",
        "entry_points": ["0x00100010", "0x00100000"],
        "memory_blocks": [
            {
                "name": ".data",
                "start": "0x00200000",
                "end": "0x00200fff",
                "length": 4096,
                "rwx": "rw-",
                "loaded": True,
                "initialized": True,
            },
            {
                "name": ".text",
                "start": "0x00100000",
                "end": "0x0010ffff",
                "length": 65536,
                "rwx": "r-x",
                "loaded": True,
                "initialized": True,
            },
        ],
        "imports_count": 1,
        "exports_count": None,
    }

    for client in _make_client(payload):
        response = client.get("/api/project_info.json")
        assert response.status_code == 200

        body = response.json()
        assert body["ok"] is True
        data = body["data"]

        assert data["program_name"] == "stub.bin"
        assert data["executable_path"] is None
        assert data["executable_format"] == "ELF"
        assert isinstance(data["imports_count"], int)
        assert data["imports_count"] == 1
        assert data["exports_count"] is None

        entry_points = data["entry_points"]
        assert entry_points == sorted(entry_points)
        assert entry_points == ["0x00100000", "0x00100010"]

        blocks: List[Dict[str, object]] = data["memory_blocks"]
        starts = [block["start"] for block in blocks]
        assert starts == sorted(starts)
        for block in blocks:
            assert isinstance(block["name"], str)
            assert isinstance(block["length"], int)
            assert isinstance(block["rwx"], str)
            assert isinstance(block["loaded"], bool)
            assert isinstance(block["initialized"], bool)
