#!/usr/bin/env python3
"""Generate Markdown API reference from an OpenAPI JSON document."""
from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen


def load_openapi(source: str) -> Mapping[str, Any]:
    """Load OpenAPI JSON from an HTTP(S) URL or filesystem path."""
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        with urlopen(source) as response:  # type: ignore[arg-type]
            data = response.read()
            encoding = response.headers.get_content_charset("utf-8")
            text = data.decode(encoding)
            return json.loads(text)
    if parsed.scheme and parsed.scheme != "file":
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    path = parsed.path if parsed.scheme else source
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def example_from_schema(schema: Mapping[str, Any] | None, depth: int = 0) -> Any:
    """Derive a minimal example for the provided JSON schema."""
    if schema is None or depth > 5:
        return "…"

    def normalize_type(t: Any) -> Any:
        if isinstance(t, list):
            t = [x for x in t if x != "null"]
            return t[0] if t else "null"
        return t

    for key in ("oneOf", "anyOf"):
        if key in schema and isinstance(schema[key], list) and schema[key]:
            return example_from_schema(schema[key][0], depth + 1)
    if "allOf" in schema and isinstance(schema["allOf"], list):
        merged: dict[str, Any] = {}
        for part in schema["allOf"]:
            if isinstance(part, Mapping) and "properties" in part:
                merged.setdefault("type", "object")
                merged.setdefault("properties", {}).update(part["properties"])
        if merged:
            return example_from_schema(merged, depth + 1)

    schema_type = normalize_type(schema.get("type"))

    if "example" in schema:
        return schema["example"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    if schema_type in {"integer", "number"}:
        return schema.get("default", 0)
    if schema_type == "string":
        if schema.get("pattern", "").startswith("^0x"):
            return "0x0"
        return schema.get("example", schema.get("default", "string"))
    if schema_type == "boolean":
        return schema.get("default", False)
    if schema_type == "array":
        return [example_from_schema(schema.get("items", {}), depth + 1)]
    if schema_type == "object" or "properties" in schema:
        props = schema.get("properties", {})
        example_obj: dict[str, Any] = {}
        for key in sorted(props):
            example_obj[key] = example_from_schema(props[key], depth + 1)
        additional = schema.get("additionalProperties")
        if isinstance(additional, Mapping):
            example_obj.setdefault("key", example_from_schema(additional, depth + 1))
        return example_obj
    return schema.get("default", "…")


def summarise_properties(schema: Mapping[str, Any]) -> list[tuple[str, str, str, str]]:
    """Return property summary tuples (name, type, required, notes)."""
    required = set(schema.get("required", []))
    props = schema.get("properties", {})
    rows: list[tuple[str, str, str, str]] = []
    for name in sorted(props):
        prop = props[name]
        prop_type = prop.get("type", "object")
        if prop_type == "array":
            item = prop.get("items", {})
            item_type = item.get("type", "object")
            prop_type = f"array<{item_type}>"
        notes_parts = []
        if "default" in prop:
            notes_parts.append(f"default={prop['default']!r}")
        if "minimum" in prop:
            notes_parts.append(f"min={prop['minimum']}")
        if "maximum" in prop:
            notes_parts.append(f"max={prop['maximum']}")
        if "pattern" in prop:
            notes_parts.append(f"pattern={prop['pattern']}")
        if "enum" in prop:
            notes_parts.append(f"enum={prop['enum']}")
        notes = ", ".join(notes_parts)
        rows.append((name, prop_type, "Yes" if name in required else "No", notes))
    return rows


def render_table(rows: list[tuple[str, str, str, str]]) -> str:
    if not rows:
        return ""
    header = "| Field | Type | Required | Notes |\n| --- | --- | --- | --- |"
    body_lines = [
        f"| `{name}` | {typ} | {req} | {notes} |" for name, typ, req, notes in rows
    ]
    return "\n".join([header, *body_lines])


def render_schema_details(schema: Mapping[str, Any]) -> list[str]:
    lines: list[str] = []
    if "$id" in schema:
        lines.append(f"- Schema ID: `{schema['$id']}`")
    if "$schema" in schema:
        lines.append(f"- Declares: `{schema['$schema']}`")
    if "description" in schema:
        lines.append(f"- Description: {schema['description']}")
    table = render_table(summarise_properties(schema))
    if table:
        lines.append("")
        lines.append(table)
    example = example_from_schema(schema)
    if example not in ("…", {}, []):
        example_json = json.dumps(example, indent=2, sort_keys=True)
        lines.append("")
        lines.append("```json")
        lines.append(example_json)
        lines.append("```")
    return lines


def render_method(path: str, method: str, spec: Mapping[str, Any]) -> list[str]:
    lines: list[str] = [f"### {method.upper()}"]
    summary = spec.get("summary")
    if summary:
        lines.append("")
        lines.append(f"**Summary:** {summary}")
    description = spec.get("description")
    if description:
        lines.append("")
        lines.append(description)
    request_body = spec.get("requestBody")
    if request_body:
        content = request_body.get("content", {})
        schema = None
        for mimetype in ["application/json", "application/problem+json"]:
            schema = content.get(mimetype, {}).get("schema")
            if schema:
                break
        if schema:
            lines.append("")
            lines.append("#### Request body")
            lines.extend(render_schema_details(schema))
    responses = spec.get("responses", {})
    if responses:
        lines.append("")
        lines.append("#### Responses")
        for status in sorted(responses, key=lambda code: (code != "default", code)):
            resp = responses[status]
            title = resp.get("description") or resp.get("summary") or ""
            if title:
                lines.append(f"- `{status}` — {title}")
            else:
                lines.append(f"- `{status}`")
            content = resp.get("content", {}) if isinstance(resp, Mapping) else {}
            schema = None
            for mimetype in ["application/json", "application/problem+json"]:
                schema = content.get(mimetype, {}).get("schema")
                if schema:
                    break
            if schema:
                details = render_schema_details(schema)
                if details:
                    lines.extend([f"  {line}" if line else "" for line in details])
    return lines


def render_api(doc: Mapping[str, Any], source: str) -> str:
    parts: list[str] = []
    info = doc.get("info", {})
    title = info.get("title", "OpenAPI document")
    version = info.get("version", "")
    parts.append("# Ghidra MCPd API reference")
    parts.append("")
    parts.append(f"_Source: {source} — {title} v{version}_")
    parts.append("")
    paths = doc.get("paths", {})
    for path in sorted(paths):
        parts.append(f"## `{path}`")
        parts.append("")
        path_item = paths[path]
        for method in sorted(path_item):
            parts.extend(render_method(path, method, path_item[method]))
            parts.append("")
    return "\n".join(part for part in parts if part is not None)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: gen_api_md.py <openapi-url-or-path>", file=sys.stderr)
        return 1
    source = argv[1]
    doc = load_openapi(source)
    markdown = render_api(doc, source)
    sys.stdout.write(markdown)
    if not markdown.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
