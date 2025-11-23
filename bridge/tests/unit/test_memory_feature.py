import base64

from bridge.features import memory


class _StubClient:
    def __init__(self, data: bytes | None) -> None:
        self._data = data

    def read_bytes(self, address: int, length: int):
        return self._data


def test_read_bytes_can_include_literal_payload() -> None:
    raw = b"Test"
    client = _StubClient(raw)

    result = memory.read_bytes(
        client,
        address=0x1000,
        length=len(raw),
        include_literals=True,
    )

    assert result["data"] == base64.b64encode(raw).decode("ascii")
    assert result["literal"] == "Test"
    assert result["length"] == len(raw)
