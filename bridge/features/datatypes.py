"""Helpers for managing user-defined data types in Ghidra."""
from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional

from ..ghidra.client import DataTypeOperationResult, GhidraClient
from ..utils.config import ENABLE_WRITES
from ..utils.logging import increment_counter, record_write_attempt


_NOTE_DRY_RUN = "dry-run enabled: no data types modified"
_NOTE_WRITES_DISABLED = "writes disabled (set GHIDRA_MCP_ENABLE_WRITES=1 to enable)"
_ERR_WRITE_DISABLED = "WRITE_DISABLED"
_ERR_WRITE_FAILED = "WRITE_FAILED"
_VALID_KINDS = {"structure", "union"}


def _normalize_kind(value: str) -> str:
    kind = str(value or "").strip().lower()
    if kind not in _VALID_KINDS:
        raise ValueError("kind must be 'structure' or 'union'")
    return kind


def _normalize_name(value: str) -> str:
    name = str(value or "").strip()
    if not name:
        raise ValueError("name is required")
    return name


def _normalize_category(value: str) -> str:
    category = str(value or "").strip()
    if not category:
        raise ValueError("category is required")
    if not category.startswith("/"):
        category = f"/{category}"
    if category != "/":
        category = category.rstrip("/")
    return category or "/"


def _normalize_path(value: str) -> str:
    path = str(value or "").strip()
    if not path:
        raise ValueError("path is required")
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def _compose_path(category: str, name: str) -> str:
    if category in {"", "/"}:
        return f"/{name}"
    return f"{category.rstrip('/')}/{name}"


def _normalize_length(value: object, *, field_index: int) -> Optional[int]:
    if value is None:
        return None
    try:
        length = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"field[{field_index}].length must be an integer") from exc
    if length <= 0:
        raise ValueError("field length must be positive")
    return length


def _normalize_offset(value: object, *, field_index: int) -> int:
    try:
        offset = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"field[{field_index}].offset must be an integer") from exc
    if offset < 0:
        raise ValueError("field offset must be non-negative")
    return offset


def _normalize_fields(
    kind: str, fields: Iterable[Mapping[str, object]]
) -> List[Dict[str, object]]:
    normalized: List[Dict[str, object]] = []
    for index, raw in enumerate(fields):
        if not isinstance(raw, Mapping):
            raise ValueError("fields must contain JSON objects")
        name = str(raw.get("name", "")).strip()
        if not name:
            raise ValueError(f"field[{index}] missing name")
        type_name = str(raw.get("type", "")).strip()
        if not type_name:
            raise ValueError(f"field[{index}] missing type")
        entry: Dict[str, object] = {"name": name, "type": type_name}

        if "length" in raw:
            length = _normalize_length(raw.get("length"), field_index=index)
            if length is not None:
                entry["length"] = length

        if "offset" in raw:
            entry["offset"] = _normalize_offset(raw.get("offset"), field_index=index)
        elif kind == "structure":
            raise ValueError(f"field[{index}] requires an offset for structures")

        normalized.append(entry)

    if not normalized:
        raise ValueError("at least one field is required")

    if kind == "structure":
        normalized.sort(key=lambda item: int(item["offset"]))

    return normalized


def _estimate_size(kind: str, fields: Iterable[Mapping[str, object]]) -> Optional[int]:
    size = 0
    has_value = False
    for entry in fields:
        length = int(entry.get("length", 0) or 0)
        if length < 0:
            length = 0
        if kind == "structure":
            offset = int(entry.get("offset", 0) or 0)
            candidate = offset + length
        else:
            candidate = length
        size = max(size, candidate)
        has_value = has_value or candidate > 0
    return size if has_value else None


def _base_envelope(kind: str, path: str, *, dry_run: bool) -> Dict[str, object]:
    return {
        "kind": kind,
        "path": path,
        "dry_run": bool(dry_run),
        "written": False,
        "notes": [],
        "errors": [],
        "datatype": None,
        "transport_error": None,
    }


def _apply_result_metadata(
    envelope: MutableMapping[str, object], result: DataTypeOperationResult
) -> None:
    if result.transport_error is not None:
        envelope["transport_error"] = result.transport_error.as_dict()
    if result.details:
        message = result.details.get("message")
        if isinstance(message, str) and message.strip():
            _add_note(envelope, message.strip())
        extra_notes = result.details.get("notes")
        if isinstance(extra_notes, list):
            for note in extra_notes:
                _add_note(envelope, note)


def _merge_datatype_payload(
    kind: str,
    base: Optional[MutableMapping[str, object]],
    result: Optional[Mapping[str, object]],
) -> Optional[Dict[str, object]]:
    merged: Dict[str, object] = dict(base or {"kind": kind})
    if not isinstance(result, Mapping):
        return merged

    name = result.get("name")
    if isinstance(name, str) and name.strip():
        try:
            merged["name"] = _normalize_name(name)
        except ValueError:
            pass

    category = result.get("category")
    if isinstance(category, str) and category.strip():
        try:
            merged["category"] = _normalize_category(category)
        except ValueError:
            pass

    path = result.get("path") or result.get("full_path")
    if isinstance(path, str) and path.strip():
        try:
            merged["path"] = _normalize_path(path)
        except ValueError:
            pass

    size = result.get("size")
    if isinstance(size, int) and size >= 0:
        merged["size"] = size

    fields = result.get("fields")
    if isinstance(fields, list):
        try:
            merged["fields"] = _normalize_fields(kind, fields)
        except ValueError:
            pass

    return merged


def _add_note(envelope: MutableMapping[str, object], note: object) -> None:
    text = str(note or "").strip()
    if text:
        notes = envelope.setdefault("notes", [])
        if isinstance(notes, list):
            notes.append(text)


def _add_error(envelope: MutableMapping[str, object], error: object) -> None:
    text = str(error or "").strip()
    if text:
        errors = envelope.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(text)


def _finalize_datatype(
    kind: str,
    base: Optional[Dict[str, object]],
    result: DataTypeOperationResult,
) -> Optional[Dict[str, object]]:
    merged = _merge_datatype_payload(kind, base, result.datatype)
    if merged.get("fields") is None and base and base.get("fields") is not None:
        merged["fields"] = list(base["fields"])  # type: ignore[index]
    if merged.get("category") is None and base and base.get("category"):
        merged["category"] = base["category"]
    if merged.get("name") is None and base and base.get("name"):
        merged["name"] = base["name"]
    if merged.get("path") is None and base and base.get("path"):
        merged["path"] = base["path"]
    if merged.get("size") is None and base and base.get("size") is not None:
        merged["size"] = base["size"]
    return merged


def _perform_operation(
    *,
    kind: str,
    base_datatype: Optional[Dict[str, object]],
    envelope: MutableMapping[str, object],
    dry_run: bool,
    writes_enabled: bool,
    operation: Optional[Callable[[], DataTypeOperationResult]],
) -> None:
    if dry_run:
        _add_note(envelope, _NOTE_DRY_RUN)
        return

    if not writes_enabled:
        _add_note(envelope, _NOTE_WRITES_DISABLED)
        _add_error(envelope, _ERR_WRITE_DISABLED)
        return

    record_write_attempt()
    if operation is None:
        _add_error(envelope, _ERR_WRITE_FAILED)
        return

    result: DataTypeOperationResult = operation()
    _apply_result_metadata(envelope, result)
    envelope["datatype"] = _finalize_datatype(kind, base_datatype, result)
    if result.ok:
        envelope["written"] = True
    else:
        _add_error(envelope, result.error or _ERR_WRITE_FAILED)


def create_datatype(
    client: GhidraClient,
    *,
    kind: str,
    name: str,
    category: str,
    fields: Iterable[Mapping[str, object]],
    dry_run: bool = True,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    """Create a new structure or union in the active program."""

    increment_counter("datatypes.create.calls")
    normalized_kind = _normalize_kind(kind)
    normalized_name = _normalize_name(name)
    normalized_category = _normalize_category(category)
    normalized_fields = _normalize_fields(normalized_kind, fields)
    path = _compose_path(normalized_category, normalized_name)
    envelope = _base_envelope(normalized_kind, path, dry_run=dry_run)

    datatype: Dict[str, object] = {
        "kind": normalized_kind,
        "name": normalized_name,
        "category": normalized_category,
        "path": path,
        "fields": normalized_fields,
    }
    size = _estimate_size(normalized_kind, normalized_fields)
    if size is not None:
        datatype["size"] = size
    envelope["datatype"] = datatype

    def _op() -> DataTypeOperationResult:
        if normalized_kind == "structure":
            return client.create_structure(
                name=normalized_name,
                category=normalized_category,
                fields=normalized_fields,
            )
        return client.create_union(
            name=normalized_name,
            category=normalized_category,
            fields=normalized_fields,
        )

    _perform_operation(
        kind=normalized_kind,
        base_datatype=datatype,
        envelope=envelope,
        dry_run=dry_run,
        writes_enabled=writes_enabled,
        operation=None if dry_run else _op,
    )

    return envelope


def update_datatype(
    client: GhidraClient,
    *,
    kind: str,
    path: str,
    fields: Iterable[Mapping[str, object]],
    dry_run: bool = True,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    """Update the layout of an existing structure or union."""

    increment_counter("datatypes.update.calls")
    normalized_kind = _normalize_kind(kind)
    normalized_path = _normalize_path(path)
    normalized_fields = _normalize_fields(normalized_kind, fields)
    envelope = _base_envelope(normalized_kind, normalized_path, dry_run=dry_run)

    datatype: Dict[str, object] = {
        "kind": normalized_kind,
        "path": normalized_path,
        "fields": normalized_fields,
    }
    size = _estimate_size(normalized_kind, normalized_fields)
    if size is not None:
        datatype["size"] = size
    envelope["datatype"] = datatype

    def _op() -> DataTypeOperationResult:
        if normalized_kind == "structure":
            return client.update_structure(path=normalized_path, fields=normalized_fields)
        return client.update_union(path=normalized_path, fields=normalized_fields)

    _perform_operation(
        kind=normalized_kind,
        base_datatype=datatype,
        envelope=envelope,
        dry_run=dry_run,
        writes_enabled=writes_enabled,
        operation=None if dry_run else _op,
    )

    return envelope


def delete_datatype(
    client: GhidraClient,
    *,
    kind: str,
    path: str,
    dry_run: bool = True,
    writes_enabled: bool = ENABLE_WRITES,
) -> Dict[str, object]:
    """Delete a structure or union by its path."""

    increment_counter("datatypes.delete.calls")
    normalized_kind = _normalize_kind(kind)
    normalized_path = _normalize_path(path)
    envelope = _base_envelope(normalized_kind, normalized_path, dry_run=dry_run)
    datatype: Dict[str, object] = {"kind": normalized_kind, "path": normalized_path}
    envelope["datatype"] = datatype

    def _op() -> DataTypeOperationResult:
        return client.delete_datatype(kind=normalized_kind, path=normalized_path)

    _perform_operation(
        kind=normalized_kind,
        base_datatype=datatype,
        envelope=envelope,
        dry_run=dry_run,
        writes_enabled=writes_enabled,
        operation=None if dry_run else _op,
    )

    return envelope


__all__ = ["create_datatype", "update_datatype", "delete_datatype"]
