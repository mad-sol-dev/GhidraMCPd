from bridge.utils.errors import ErrorCode, make_error


def test_error_templates_map_to_status_and_message() -> None:
    expected = {
        ErrorCode.INVALID_REQUEST: (
            400,
            "Request was malformed or failed validation.",
            ["Check required fields and value formats."],
        ),
        ErrorCode.RESULT_TOO_LARGE: (
            413,
            "Result exceeds configured limits.",
            ["Narrow the scope or reduce limits to shrink the result."],
        ),
        ErrorCode.NOT_READY: (
            425,
            "Bridge is not ready yet.",
            ["Retry after the MCP bridge reports initialization complete."],
        ),
        ErrorCode.SSE_CONFLICT: (
            409,
            "Server-sent events stream already active.",
            ["Disconnect the existing SSE client before reconnecting."],
        ),
        ErrorCode.TOO_MANY_REQUESTS: (
            429,
            "Too many requests in flight.",
            ["Back off and retry with fewer concurrent requests."],
        ),
        ErrorCode.INTERNAL: (
            500,
            "Internal server error.",
            ["Retry the request or contact support with request logs."],
        ),
        ErrorCode.UNAVAILABLE: (
            503,
            "Required upstream data is unavailable.",
            ["Ensure a program is open in Ghidra and try again."],
        ),
    }

    for code, (status, message, recovery) in expected.items():
        payload = make_error(code)
        assert payload["status"] == status
        assert payload["code"] == code.value
        assert payload["message"] == message
        assert payload["recovery"] == recovery
