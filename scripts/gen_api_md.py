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


def normalize_schema_type(type_value: Any) -> str | None:
    """Return the first non-null schema type as a string."""
    if isinstance(type_value, list):
        filtered = [value for value in type_value if value != "null"]
        if filtered:
            type_value = filtered[0]
        elif type_value:
            # Only explicit null entries remain.
            type_value = type_value[0]
        else:
            return None
    if isinstance(type_value, str):
        return type_value
    return None


def example_from_schema(schema: Mapping[str, Any] | None, depth: int = 0) -> Any:
    """Derive a minimal example for the provided JSON schema."""
    if schema is None or depth > 5:
        return "…"

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

    schema_type = normalize_schema_type(schema.get("type"))

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
        items = schema.get("items")
        if isinstance(items, list) and items:
            item_schema = items[0] if isinstance(items[0], Mapping) else {}
        elif isinstance(items, Mapping):
            item_schema = items
        else:
            item_schema = {}
        return [example_from_schema(item_schema, depth + 1)]
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
        prop_type = normalize_schema_type(prop.get("type")) or "object"
        if prop_type == "array":
            item = prop.get("items")
            if isinstance(item, list) and item:
                candidate = item[0] if isinstance(item[0], Mapping) else {}
            elif isinstance(item, Mapping):
                candidate = item
            else:
                candidate = {}
            if isinstance(candidate, Mapping):
                item_type = normalize_schema_type(candidate.get("type")) or "object"
            else:
                item_type = "object"
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


def collect_extra_sections() -> list[str]:
    """Return additional documentation for the collect endpoint."""

    query_rows = [
        ("id", "string", "Yes", "minLength=1"),
        ("op", "string", "Yes", "minLength=1"),
        ("params", "object", "No", "default={}"),
        ("result_budget", "object", "No", "See Result budget object"),
        ("max_result_tokens", "integer|null", "No", "min=0"),
        ("metadata", "object", "No", "echoed in response"),
    ]
    project_rows = [
        ("id", "string", "Yes", "minLength=1"),
        ("queries", "array<query>", "Yes", "1-256 entries"),
        ("result_budget", "object", "No", "See Result budget object"),
        ("metadata", "object", "No", "echoed in response"),
        ("ghidra_url", "string", "No", "alternate server base URL"),
        ("base_url", "string", "No", "legacy alias for ghidra_url"),
    ]
    budget_rows = [
        ("max_result_tokens", "integer|null", "No", "min=0; null for unlimited"),
        ("mode", "string", "No", "enum=['auto_trim', 'strict']; default='auto_trim'"),
    ]

    operations = [
        (
            "disassemble_at",
            "Disassemble instructions at a single address. Required: address (hex). Optional: count (default 16).",
            {"id": "head", "op": "disassemble_at", "params": {"address": "0x401000", "count": 8}},
        ),
        (
            "disassemble_batch",
            "Disassemble multiple addresses in one call. Required: addresses (array of hex strings). Optional: count (default 16).",
            {
                "id": "epilogue",
                "op": "disassemble_batch",
                "params": {"addresses": ["0x401000", "0x401020"], "count": 4},
            },
        ),
        (
            "read_bytes",
            "Read a raw byte window. Required: address (hex). Optional: length in bytes (default 64).",
            {"id": "bytes", "op": "read_bytes", "params": {"address": "0x401000", "length": 32}},
        ),
        (
            "read_words",
            "Read machine words. Required: address (hex). Optional: count (default 1).",
            {"id": "words", "op": "read_words", "params": {"address": "0x401000", "count": 2}},
        ),
        (
            "search_strings",
            "Search string literals. Required: query substring. Optional: limit (default 100) and page (default 1).",
            {"id": "long-strings", "op": "search_strings", "params": {"query": "init", "limit": 25}},
        ),
        (
            "strings_compact",
            "List compact string summaries. Required: limit (>0). Optional: offset (default 0).",
            {"id": "strings", "op": "strings_compact", "params": {"limit": 100, "offset": 0}},
        ),
        (
            "string_xrefs",
            "Lookup cross-references to a string. Required: string_addr (hex). Optional: limit (default 50).",
            {"id": "string-xrefs", "op": "string_xrefs", "params": {"string_addr": "0x500123", "limit": 10}},
        ),
        (
            "search_imports",
            "Search imported symbols. Required: query substring. Optional: limit (default 100) and page (default 1).",
            {"id": "imports", "op": "search_imports", "params": {"query": "socket", "limit": 10}},
        ),
        (
            "search_exports",
            "Search exported symbols. Required: query substring. Optional: limit (default 100) and page (default 1).",
            {"id": "exports", "op": "search_exports", "params": {"query": "init", "limit": 10}},
        ),
        (
            "search_functions",
            "Search functions with optional ranking. Optional params: query text, limit/page (defaults 100/1), context_lines (0-16). "
            "Use rank='simple' with optional k, or resume_cursor for pagination (not both).",
            {
                "id": "init-funcs",
                "op": "search_functions",
                "params": {"query": "init", "limit": 20, "context_lines": 2},
            },
        ),
        (
            "search_xrefs_to",
            "Search inbound references to an address. Required: address (hex). Optional: query, limit (default 100), page (default 1).",
            {"id": "xref", "op": "search_xrefs_to", "params": {"address": "0x401050", "limit": 50}},
        ),
        (
            "search_scalars",
            "Search scalar values. Required: value (int or hex string). Optional: query label, limit/page (defaults 50/1), resume_cursor.",
            {"id": "scalars", "op": "search_scalars", "params": {"value": "0xDEADBEEF", "limit": 10}},
        ),
        (
            "search_scalars_with_context",
            "Search scalars and include annotated disassembly context. Required: value. Optional: context_lines (0-16, default 4) and limit (default 25).",
            {
                "id": "scalar-context",
                "op": "search_scalars_with_context",
                "params": {"value": "0x8040123", "context_lines": 3},
            },
        ),
    ]

    example_primary = {
        "queries": [
            {
                "id": "init-funcs",
                "op": "search_functions",
                "params": {"query": "init", "limit": 20, "context_lines": 2},
                "result_budget": {"max_result_tokens": 600},
            },
            {
                "id": "long-strings",
                "op": "search_strings",
                "params": {"query": "initialization complete", "limit": 50},
            },
        ],
        "result_budget": {"max_result_tokens": 1500, "mode": "auto_trim"},
        "metadata": {"request": "search init functions & long strings"},
    }

    example_cross_project = {
        "queries": [
            {
                "id": "xref-to-target",
                "op": "search_xrefs_to",
                "params": {"address": "0x401050", "limit": 25},
            }
        ],
        "projects": [
            {
                "id": "linux-build",
                "ghidra_url": "http://ghidra.example.local:13100/",
                "queries": [
                    {
                        "id": "batch-disasm",
                        "op": "disassemble_batch",
                        "params": {"addresses": ["0x401050", "0x401060"], "count": 8},
                    }
                ],
                "result_budget": {"mode": "strict", "max_result_tokens": 800},
            }
        ],
        "result_budget": {"max_result_tokens": 2000},
    }

    lines: list[str] = []
    lines.append("##### Query object")
    lines.append("")
    table = render_table(query_rows)
    if table:
        lines.append(table)
    lines.append("")

    lines.append("##### Project object")
    lines.append("")
    table = render_table(project_rows)
    if table:
        lines.append(table)
    lines.append("")

    lines.append("##### Result budget object")
    lines.append("")
    table = render_table(budget_rows)
    if table:
        lines.append(table)
    lines.append("")

    lines.append("#### Supported `op` values")
    lines.append("")
    for name, description, example in operations:
        lines.append(f"- `{name}` — {description}")
        lines.append("")
        lines.append("  ```json")
        example_json = json.dumps(example, indent=2)
        for line in example_json.splitlines():
            lines.append(f"  {line}")
        lines.append("  ```")
        lines.append("")

    lines.append("#### Example requests")
    lines.append("")
    lines.append("**Search init functions & long strings**")
    lines.append("")
    lines.append("```json")
    example_json = json.dumps(example_primary, indent=2)
    lines.extend(example_json.splitlines())
    lines.append("```")
    lines.append("")

    lines.append("**Xref lookup + batch disassembly**")
    lines.append("")
    lines.append("```json")
    example_json = json.dumps(example_cross_project, indent=2)
    lines.extend(example_json.splitlines())
    lines.append("```")

    return lines


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
        lines.extend(table.splitlines())
    example = example_from_schema(schema)
    if example not in ("…", {}, []):
        example_json = json.dumps(example, indent=2, sort_keys=True)
        lines.append("")
        lines.append("```json")
        for line in example_json.splitlines():
            lines.append(line)
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
    if path == "/api/collect.json":
        lines.append("")
        lines.extend(collect_extra_sections())
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
