"""A response that fails its own schema is the server's fault.

29 MCP tools and 23 HTTP routes answered INVALID_REQUEST when their *own*
payload failed validation, sending the caller looking for a mistake in
arguments that were fine.  COLLECT-METADATA-REJECTED presented as exactly that.
"""
from __future__ import annotations

import re
from pathlib import Path

from bridge.api._shared import response_schema_error
from bridge.utils.errors import ErrorCode

API = Path(__file__).resolve().parents[2] / "api"


def test_the_error_blames_the_server_and_names_the_schema():
    envelope = response_schema_error("collect.v1.json", ["'metadata' was unexpected"])
    [error] = envelope["errors"]
    assert error["code"] == ErrorCode.INTERNAL.value
    assert error["status"] == 500
    assert "collect.v1.json" in error["message"]
    assert "'metadata' was unexpected" in error["message"]
    assert "request was valid" in error["recovery"][0]


def _response_validations(source: str):
    """(schema, the code returned when it fails) for every response schema check."""

    for match in re.finditer(r'validate_payload\(\s*"([a-z_]+)\.v1\.json"', source):
        tail = source[match.end(): match.end() + 400]
        failure = re.search(r'(response_schema_error|ErrorCode\.[A-Z_]+)', tail)
        yield match.group(1), failure.group(1) if failure else None


def test_no_response_schema_failure_is_reported_as_a_bad_request():
    found = []
    for path in [API / "tools.py", *sorted((API / "routes").glob("*.py"))]:
        for schema, failure in _response_validations(path.read_text(encoding="utf-8")):
            found.append((path.name, schema, failure))
    # The extraction must see the sites it is about; 29 + 23 on 2026-10-10.
    assert len(found) >= 52, len(found)
    # /api/capabilities.json serves a static list and only logs a schema
    # failure; it blames no caller, so it is not part of this rule.
    allowed = {("meta_routes.py", "capabilities", None)}
    wrong = [e for e in found if e[2] != "response_schema_error" and e not in allowed]
    assert wrong == []
