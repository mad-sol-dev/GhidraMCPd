"""Function range listing helpers."""
from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.hex import int_to_hex, parse_hex
from ..utils.logging import increment_counter
from .pagination import finalize_page


def _hex(value: object) -> str:
    text = str(value)
    return text if text.startswith("0x") else f"0x{text}"


def _add_body_shape(item: Dict[str, object], entry: Dict[str, object]) -> None:
    """Add what distinguishes a function from its own thunk -- and only that.

    Every field here is omitted when it would say nothing, so the ordinary
    entry stays the three keys it has always been.  A plugin too old to report
    any of it leaves them all absent, which is the same thing.
    """

    thunk_to = entry.get("thunk_to")
    if thunk_to:
        # Ghidra names a thunk after the function it jumps to, so without this
        # two entries of the same name in one range look like a duplicate.
        item["is_thunk"] = True
        item["thunk_to"] = _hex(thunk_to)

    span = entry.get("span")
    size = entry.get("size")
    if isinstance(span, dict):
        span_bytes = parse_hex(_hex(span["end"])) - parse_hex(_hex(span["start"])) + 1
        # Reported only where the two numbers differ, which is exactly where
        # the body holds interior data and the difference has to be explained.
        if span_bytes > 0 and span_bytes != size:
            item["span_bytes"] = span_bytes

    chunks = entry.get("chunks")
    if isinstance(chunks, list) and len(chunks) > 1:
        item["chunks"] = [
            {"start": _hex(chunk["start"]), "end": _hex(chunk["end"])}
            for chunk in chunks
        ]


def list_functions_in_range(
    client: GhidraClient,
    *,
    address_min: str,
    address_max: str,
    limit: int,
    page: int,
) -> Dict[str, object]:
    """
    List all functions within an address range and return paginated results.
    
    Args:
        client: Ghidra client instance
        address_min: Start address (hex string, inclusive)
        address_max: End address (hex string, inclusive)
        limit: Maximum number of results per page
        page: Page number (1-based)
        
    Returns:
        Dictionary with total count, page, limit, and items array
    """
    increment_counter("function_range.list.calls")
    
    # Parse addresses
    min_addr = parse_hex(address_min)
    max_addr = parse_hex(address_max)
    
    # Fetch all functions in range from Ghidra
    raw_results = client.list_functions_in_range(min_addr, max_addr)

    # Canonical query representation for metadata parity with other search APIs
    query = f"[{int_to_hex(min_addr)},{int_to_hex(max_addr)}]"
    
    # Sort by address for determinism
    sorted_results = sorted(raw_results, key=lambda x: parse_hex(x["address"]))
    
    # Build items list
    items: List[Dict[str, object]] = []
    for entry in sorted_results:
        addr_str = entry.get("address", "")
        if not addr_str.startswith("0x"):
            addr_str = f"0x{addr_str}"

        item: Dict[str, object] = {
            "name": entry.get("name", ""),
            "address": addr_str,
            "size": entry.get("size"),
        }
        _add_body_shape(item, entry)
        items.append(item)
    
    # Calculate pagination
    total = len(items)
    if page < 1:
        page = 1
    if limit <= 0:
        limit = total
    
    start = (page - 1) * limit
    end = start + limit

    paginated_items = items[start:end]

    increment_counter("function_range.list.results", len(paginated_items))

    return finalize_page(
        {
            "query": query,
            "total": total,
            "page": page,
            "limit": limit,
            "has_more": end < total,
            "items": paginated_items,
        }
    )


__all__ = ["list_functions_in_range"]
