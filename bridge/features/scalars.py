"""Scalar value search helpers."""
from typing import Dict, List, Optional, Union

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex, parse_hex
from ..utils.logging import enforce_batch_limit, increment_counter, SafetyLimitExceeded


def search_scalars(
    client: GhidraClient,
    *,
    value: Union[int, str],
    query: str,
    limit: int,
    page: int,
    cursor: Optional[str] = None,
    resume_cursor: Optional[str] = None,
) -> Dict[str, object]:
    """
    Search for scalar values in the binary and return paginated results.
    
    Args:
        client: Ghidra client instance
        value: Integer value or hex string to search for
        limit: Maximum number of results per page
        page: Page number (1-based)
        
    Returns:
        Dictionary with query, total count, page, limit, items array, and has_more flag
    """
    increment_counter("scalars.search.calls")
    
    # Normalize value to int
    if isinstance(value, str):
        value_int = parse_hex(value)
    else:
        value_int = int(value)
    
    cursor_token = resume_cursor or cursor
    request_offset = 0 if cursor_token else max(0, (page - 1) * limit)

    page_result = client.search_scalars(
        value_int,
        limit=limit,
        offset=request_offset,
        cursor=cursor_token,
    )

    raw_items = page_result.items if page_result.items is not None else []

    items: List[Dict[str, object]] = []
    for entry in raw_items:
        if not isinstance(entry, dict):
            continue
        addr_str = str(entry.get("address", ""))
        if not addr_str.lower().startswith("0x"):
            addr_str = f"0x{addr_str}"
        items.append({
            "address": addr_str.lower(),
            "value": int_to_hex(value_int),
            "function": entry.get("function"),
            "context": entry.get("context"),
        })

    # Sort current slice for determinism without materialising all results
    items.sort(key=lambda item: parse_hex(item["address"]))

    increment_counter("scalars.search.results", len(items))

    has_more = page_result.has_more
    total: Optional[int] = None
    if page_result.error and not items:
        has_more = False
    if not has_more and not cursor_token:
        total = request_offset + len(items)

    return {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": items,
        "has_more": has_more,
        "resume_cursor": page_result.cursor,
        "cursor": page_result.cursor,
    }


__all__ = ["search_scalars"]
