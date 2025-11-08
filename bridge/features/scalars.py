"""Scalar value search helpers."""
from typing import Dict, List, Union

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
    
    # Fetch all matching scalars from Ghidra
    raw_results = client.search_scalars(value_int)
    
    # Sort by address for determinism
    sorted_results = sorted(raw_results, key=lambda x: parse_hex(x["address"]))
    
    # Build items list
    items: List[Dict[str, object]] = []
    for entry in sorted_results:
        addr_str = entry.get("address", "")
        if not addr_str.startswith("0x"):
            addr_str = f"0x{addr_str}"
        
        items.append({
            "address": addr_str,
            "value": int_to_hex(value_int),
            "function": entry.get("function"),
            "context": entry.get("context"),
        })
    
    # Calculate pagination
    total = len(items)
    if page < 1:
        page = 1
    if limit <= 0:
        limit = total if total > 0 else 1

    page = max(page, 1)
    limit = max(limit, 1)

    start = (page - 1) * limit
    end = start + limit

    paginated_items = items[start:end]

    increment_counter("scalars.search.results", len(paginated_items))

    has_more = (page * limit) < total

    return {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }


__all__ = ["search_scalars"]
