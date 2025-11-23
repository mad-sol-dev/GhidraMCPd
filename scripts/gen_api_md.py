#!/usr/bin/env python3
"""Generate Markdown API reference from an OpenAPI JSON document."""
from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse
from urllib.request import urlopen
from textwrap import dedent


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


CURATED_SECTIONS = dedent(
    """
    ## Overview

    All endpoints use the envelope `{ok, data|null, errors[]}` with error entries shaped as `{status, code, message, recovery[]}` plus strict JSON schemas.

    - `POST /api/search_strings.json`
    - `POST /api/search_functions.json`
    - `POST /api/search_imports.json`
    - `POST /api/search_exports.json`
    - `POST /api/search_xrefs_to.json`
    - `POST /api/search_scalars.json`
    - `POST /api/list_functions_in_range.json`
    - `POST /api/disassemble_at.json`
    - `POST /api/read_bytes.json`
    - `POST /api/write_bytes.json`
    - `POST /api/jt_slot_check.json`
    - `POST /api/jt_scan.json`
    - `POST /api/strings_compact.json`
    - `POST /api/mmio_annotate.json`
    - `POST /api/analyze_function_complete.json`
    - `GET /api/project_info.json`

    See the sections below for parameters and invariants.

    > OpenAPI: `GET /openapi.json`
    > **Conventions:** `data.total` is an integer; `data.page` is **1-based** on search endpoints.

    ## Search endpoints

    ### Common semantics

    - **Server-side filtering first** (no information loss), then pagination.
    - Responses unify on: `query`, `total`, `page` (1-based), `limit`, `items`, `has_more`.

    ### Strings

    `POST /api/search_strings.json`

    ```json
    { "query": "memcpy", "limit": 50, "page": 1 }
    ```

    ### Functions / Imports / Exports / Xrefs

    Same shape; each filters in its domain. See OpenAPI for item fields.

    ### Scalars

    `POST /api/search_scalars.json`

    Search for immediate/constant values in code.

    **Request:**
    ```json
    { "value": "0xB0000084", "limit": 100, "page": 1 }
    ```

    **Response:**
    ```json
    {
      "ok": true,
      "data": {
        "query": "0xB0000084",
        "total": 42,
        "page": 1,
        "limit": 100,
        "items": [
          {
            "address": "0x0020A1C0",
            "value": "0xB0000084",
            "function": "init_board",
            "context": "LDR R0, =0xB0000084"
          }
        ],
        "has_more": false
      },
      "errors": []
    }
    ```

    - `value`: hex string (0x...) or integer
    - `limit`: max 500
    - `page`: 1-based pagination
    - `has_more`: true when another page exists (`page * limit < total`)

    ### Functions in range

    `POST /api/list_functions_in_range.json`

    List all functions within an address range.

    **Request:**
    ```json
    { "address_min": "0x00000000", "address_max": "0x00001000", "limit": 200, "page": 1 }
    ```

    **Response:**
    ```json
    {
      "ok": true,
      "data": {
        "total": 12,
        "page": 1,
        "limit": 200,
        "items": [
          {
            "name": "Reset",
            "address": "0x00000000",
            "size": 3
          }
        ]
      },
      "errors": []
    }
    ```

    - `address_min`, `address_max`: hex strings (inclusive range)
    - `size`: optional, number of addresses in function body
    - `limit`: max 500

    ### Disassemble at

    `POST /api/disassemble_at.json`

    Disassemble N instructions starting at an address.

    **Request:**
    ```json
    { "address": "0x00000000", "count": 16 }
    ```

    **Response:**
    ```json
    {
      "ok": true,
      "data": {
        "items": [
          {
            "address": "0x00000000",
            "bytes": "DBF021E3",
            "text": "msr cpsr_c,#0xdb"
          }
        ]
      },
      "errors": []
    }
    ```

    - `count`: max 128, default 16
    - `bytes`: uppercase hex string of instruction bytes

    ### Read bytes

    `POST /api/read_bytes.json`

    Read raw bytes from memory.

    **Request:**
    ```json
    { "address": "0x00000000", "length": 16 }
    ```

    **Response:**
    ```json
    {
    "ok": true,
    "data": {
      "address": "0x00000000",
      "length": 16,
      "encoding": "base64",
      "data": "2/Ah4zTQn+XX8CHjMNCf5Q==",
      "literal": "\\xDB\\xF0!\\xE35\\x10\\x9F\\xE5\\xD7\\xF0!\\xE30\\xD0\\x9F\\xE5"
    },
    "errors": []
    }
    ```

    - `length`: max 4096 bytes
    - `encoding`: always "base64"
    - `data`: Base64-encoded bytes
    - `literal`: Optional raw byte string (Latin-1 safe) when `include_literals: true` is requested

    ### Wildcard queries

    The following endpoints support wildcard queries (return all items without filtering):
    - `search_functions`: use `query: "*"` or `query: ""`

    `search_xrefs_to` requires an empty `query` string. Requests with non-empty or wildcard queries are rejected with `400` because upstream filtering is not available.

    All search endpoints enforce the shared batch window cap (`page * limit <= 256` by default). Oversized windows return `413 Payload Too Large` so callers can retry with a smaller page or limit.

    ## String endpoints

    ### `strings_compact`

    Returns a compact listing of program strings with deterministic ordering:

    - Items contain `addr`, `s`, and `refs` counts with optional full `literal` text.
    - Results are bounded by `limit` and always include `total` metadata.
    - Empty strings are omitted; ASCII/UTF-16 variants are normalized to UTF-8 output.
    - When Ghidra bindings do not implement `list_strings_compact`, the bridge falls back to `list_strings` or a wildcard `search_strings("")` call before applying `offset`/`limit`. Some environments may still return an empty catalog if upstream discovery is unavailable.
    - Set `include_literals: true` to include the full normalized literal (without truncation) alongside the compact `s` preview.

    ### `search_strings`

    See [Search endpoints](#search-endpoints) for shared pagination semantics. Query terms are matched server-side with no client-side filtering. Set `include_literals: true` to ask for full normalized string contents in addition to the compact snippet, which stays capped at 120 characters.

    ## Xref endpoints

    ### `search_xrefs_to`

    Search for references pointing to a target address:

    - Accepts `target`, `limit`, and `page` parameters plus a required **empty** `query` string. Non-empty queries return `400 Bad Request` because filtering is not supported upstream.
    - Results include caller/callee metadata plus reference kinds and repeat the `target_address` on each item for clarity.
    - Pagination mirrors other search endpoints with deterministic totals (`has_more` flips to `false` on the last page).
    - Oversized windows (`page * limit` over the configured maximum, default `256`) fail fast with `413 Payload Too Large` so callers can retry with a smaller batch.

    ## Jump-table endpoints

    ### `jt_slot_check`

    Validates a single pointer as ARM/Thumb (or none), enforcing `[code_min, code_max)`.

    **Tip — Deriving CODE_MIN/MAX:** fetch segments from the plugin and choose the `.text`/code bounds.

    ### `jt_scan`

    Batch over many slots; invariants:

    - `summary.total == len(items)`
    - `summary.valid + summary.invalid == summary.total`

    ## MMIO endpoint

    ### `mmio_annotate`

    Annotates addresses for memory-mapped IO while respecting write guards:

    - Requires explicit `addresses` and `annotation` payloads.
    - Honors `dry_run` to preview changes without writes.
    - When writes execute, they are limited by `GHIDRA_MCP_MAX_WRITES_PER_REQUEST` and logged if `GHIDRA_MCP_AUDIT_LOG` is configured.

    #### Response format

    **Request:**
    ```json
    {
      "function_addr": "0x0002df2c",
      "dry_run": true,
      "max_samples": 4
    }
    ```

    **Response:**
    ```json
    {
      "ok": true,
      "data": {
        "function": "0x0002df2c",
        "reads": 10,
        "writes": 9,
        "bitwise_or": 2,
        "bitwise_and": 1,
        "toggles": 0,
        "annotated": 0,
        "samples": [
          {
            "addr": "0x0002df30",
            "op": "READ",
            "target": "0x00000018",
            "address_abs": "0x00000018"
          },
          {
            "addr": "0x0002df34",
            "op": "OR",
            "target": "0x00004000",
            "address_abs": "0x00004000"
          }
        ],
        "notes": ["dry-run requested: annotations were not applied"]
      },
      "errors": []
    }
    ```

    ##### Fields

    - `addr`: instruction address where the operation occurs
    - `op`: operation type (READ, WRITE, OR, AND, TOGGLE)
    - `target`: immediate value extracted from the instruction
    - `address_abs`: **absolute address** for the operation
      - If `target` is a valid address (non-zero), uses `target`
      - Otherwise falls back to `addr` (the instruction address)
    - `annotated`: number of comments actually written (0 when `dry_run: true`)
    - `notes`: array of informational messages

    ##### Limits

    - `max_samples`: max 8 (default), caps the number of sample operations returned
    - Write operations require `dry_run: false` and `GHIDRA_MCP_ENABLE_WRITES=1`

    ## Data-type management API

    The bridge exposes helper endpoints for creating, updating, and deleting structures and unions inside the active Ghidra program. All endpoints share the same safety model used elsewhere in the bridge: write operations are disabled by default, calls honour the per-request write counters, and every response is wrapped in the standard envelope returned by the API gateway.

    Each route accepts a JSON payload that describes the type to manipulate and responds with a stable summary of the operation that was attempted. When `dry_run` is set to `true` (the default) no writes are forwarded to the Ghidra plugin. Clearing `dry_run` requires the server to be started with `GHIDRA_MCP_ENABLE_WRITES=1` and still consumes one write token from the current request scope.

    ### POST `/api/datatypes/create.json`

    Create a new structure or union in the active project. The request schema is `datatypes_create.request.v1.json`.

    ```json
    {
      "kind": "structure",
      "name": "Widget",
      "category": "/structs",
      "fields": [
        {"name": "id", "type": "uint32", "offset": 0, "length": 4},
        {"name": "flags", "type": "uint16", "offset": 4, "length": 2}
      ],
      "dry_run": false
    }
    ```

    Responses conform to `datatypes_create.v1.json` and always include the computed path, the normalised field list, and the inferred size (when available). During a dry run the `written` flag remains `false` and a note describing the simulated operation is included.

    ### POST `/api/datatypes/update.json`

    Update an existing structure or union in-place. The request schema is `datatypes_update.request.v1.json` and requires the fully-qualified data-type path plus the new field definitions. Response envelopes follow `datatypes_update.v1.json` and echo the final layout reported by the plugin (or the requested layout if the plugin returned no additional metadata).

    ### POST `/api/datatypes/delete.json`

    Delete a structure or union by path. The request schema is `datatypes_delete.request.v1.json` and the response schema is `datatypes_delete.v1.json`. Successful deletes set `written` to `true` and return the canonicalised `kind` and `path`. Dry runs add notes explaining that no data types were removed.

    ### Safety limits

    All three routes share the standard per-request write guard. Each successful write consumes a single token and will raise an error if the configured limit is exceeded. The bridge will also reject attempts to proceed while writes are disabled, returning `WRITE_DISABLED` in the response envelope.
    """
).strip()


def curated_sections() -> list[str]:
    """Return the curated human-written notes to prepend to the generated API docs."""

    return CURATED_SECTIONS.splitlines()


def render_api(doc: Mapping[str, Any], source: str) -> str:
    parts: list[str] = []
    info = doc.get("info", {})
    title = info.get("title", "OpenAPI document")
    version = info.get("version", "")
    parts.append("# Ghidra MCPd API reference")
    parts.append("")
    parts.append(f"_Source: {source} — {title} v{version}_")
    parts.append("")
    parts.extend(curated_sections())
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
