from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from starlette.routing import Route
from starlette.testclient import TestClient

from bridge.app import build_api_app, create_app


_DATA_DIR = Path(__file__).parent / "data"
_SNAPSHOT_PATH = _DATA_DIR / "openapi_snapshot.json"
_UPDATE_SNAPSHOTS = os.getenv("UPDATE_SNAPSHOTS") == "1"


def _normalized_schema(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return the subset of the OpenAPI schema we want to guard."""

    filtered: Dict[str, Any] = {}
    for key, value in raw.items():
        if key in {"servers", "tags", "externalDocs", "x-generated-at"}:
            continue
        filtered[key] = value

    paths = filtered.get("paths", {})
    if isinstance(paths, dict):
        filtered["paths"] = {path: paths[path] for path in sorted(paths)}

    components = filtered.get("components")
    if isinstance(components, dict):
        schemas = components.get("schemas")
        if isinstance(schemas, dict):
            filtered.setdefault("components", {})["schemas"] = {
                name: schemas[name] for name in sorted(schemas)
            }
        else:
            filtered.setdefault("components", {})

    return filtered


def _load_snapshot() -> Dict[str, Any]:
    if not _SNAPSHOT_PATH.exists():
        if _UPDATE_SNAPSHOTS:
            return {}
        raise AssertionError(
            "Missing OpenAPI snapshot. Run with UPDATE_SNAPSHOTS=1 to refresh."
        )
    with _SNAPSHOT_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_snapshot(snapshot: Dict[str, Any]) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _SNAPSHOT_PATH.open("w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, sort_keys=True)
        handle.write("\n")


def test_openapi_snapshot_drift() -> None:
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    normalized = _normalized_schema(schema)

    assert "paths" in normalized, "OpenAPI schema must define paths"
    components = normalized.get("components", {})
    assert isinstance(components, dict)
    if "schemas" in components:
        assert isinstance(components["schemas"], dict)

    if _UPDATE_SNAPSHOTS:
        _write_snapshot(normalized)
        return

    snapshot = _load_snapshot()
    assert normalized == snapshot, "OpenAPI schema drift detected"


def test_openapi_documents_all_routes() -> None:
    app = build_api_app()
    expected_methods: Dict[str, set[str]] = {}
    for route in app.router.routes:
        if not isinstance(route, Route) or route.path == "/openapi.json":
            continue
        methods = {method for method in (route.methods or set()) if method != "OPTIONS"}
        expected_methods[route.path] = methods

    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    schema = response.json()
    paths = schema.get("paths", {})

    assert set(paths) == set(expected_methods), "OpenAPI is missing registered routes"

    for path, methods in expected_methods.items():
        path_item = paths.get(path)
        assert isinstance(path_item, dict), f"Path {path} missing from OpenAPI"
        for method in sorted(methods):
            operation = path_item.get(method.lower())
            assert operation is not None, f"{method} {path} missing from OpenAPI"
            if method == "POST":
                assert (
                    "requestBody" in operation
                ), f"POST {path} is missing a requestBody schema"
            responses = operation.get("responses")
            assert (
                isinstance(responses, dict) and "200" in responses
            ), f"{method} {path} is missing a 200 response"
            payload_schema = (
                responses["200"]
                .get("content", {})
                .get("application/json", {})
                .get("schema")
            )
            assert payload_schema is not None, f"{method} {path} missing response schema"
