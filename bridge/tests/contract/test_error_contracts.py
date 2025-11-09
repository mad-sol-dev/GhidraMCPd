import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from bridge.utils.errors import ErrorCode
from bridge.api._shared import envelope_error, envelope_response


_EXPECTED_STATUS = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.RESULT_TOO_LARGE: 413,
    ErrorCode.NOT_READY: 425,
    ErrorCode.SSE_CONFLICT: 409,
    ErrorCode.TOO_MANY_REQUESTS: 429,
    ErrorCode.INTERNAL: 500,
    ErrorCode.UNAVAILABLE: 503,
}


@pytest.mark.parametrize("code", list(ErrorCode))
def test_envelope_error_contract(code: ErrorCode) -> None:
    async def handler(_):
        return envelope_response(envelope_error(code))

    app = Starlette(routes=[Route("/", handler, methods=["GET"])])
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == _EXPECTED_STATUS[code]
    payload = response.json()
    from bridge.tests.contract.test_http_contracts import _assert_envelope

    _assert_envelope(payload)
    error = payload["errors"][0]
    assert error["status"] == _EXPECTED_STATUS[code]
    assert error["code"] == code.value
