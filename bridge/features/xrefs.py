"""Cross-reference search helpers."""

from typing import Dict, List

from ..ghidra.client import GhidraClient


def search_xrefs_to(
    client: GhidraClient,
    *,
    address: str,
    query: str,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, object]:
    """Search cross-references to ``address`` and return a paginated response.
    
    Args:
        client: Ghidra client instance
        address: Target address as hex string
        query: Search query string (use "*" or "" for all xrefs)
        limit: Maximum number of results per page
        offset: Number of results to skip
        
    Returns:
        Dictionary with query, total count, page, limit, items array, and has_more flag
    """

    try:
        address_value = int(address, 16)
    except ValueError as exc:  # pragma: no cover - validated earlier
        raise ValueError(f"Invalid address: {address}") from exc

    # Use empty query for wildcard searches
    search_query = "" if query in ("*", "") else query
    raw_results = client.search_xrefs_to(address_value, search_query)

    target_address = f"0x{address_value:08x}"
    items: List[Dict[str, str]] = []
    for entry in raw_results:
        addr_val = entry.get("addr")
        context = entry.get("context", "")
        if not isinstance(addr_val, int):
            continue
        context_text = str(context)
        items.append(
            {
                "from_address": f"0x{addr_val:08x}",
                "context": context_text,
                "target_address": target_address,
            }
        )

    total = len(items)
    if limit <= 0:
        limit = total if total > 0 else 1
        page = 1
        paginated_items = items[offset:]
    else:
        page = offset // limit + 1
        paginated_items = items[offset : offset + limit]

    has_more = (page * limit) < total

    return {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }
