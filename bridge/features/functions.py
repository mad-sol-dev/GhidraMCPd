"""Function search and listing features."""

from typing import Dict, List

from ..ghidra.client import GhidraClient


def search_functions(
    client: GhidraClient,
    *,
    query: str,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, object]:
    """
    Search for functions matching the query and return paginated results.
    
    Args:
        client: Ghidra client instance
        query: Search query string (use "*" or "" for all functions)
        limit: Maximum number of results per page (capped at 500)
        offset: Number of results to skip
        
    Returns:
        Dictionary with query, total count, 1-based page, limit, and items array
    """
    # Cap limit at 500 maximum
    limit = min(limit, 500) if limit > 0 else 500
    
    # Fetch all matching functions from Ghidra
    # Use empty query for wildcard searches
    search_query = "" if query in ("*", "") else query
    raw_results = client.search_functions(search_query)
    
    # Parse the raw results into structured objects
    items = []
    for line in raw_results:
        # Expected format: "function_name @ 0xaddress"
        if " @ " not in line:
            continue
        
        parts = line.split(" @ ", 1)
        if len(parts) != 2:
            continue
            
        name = parts[0].strip()
        address = parts[1].strip()
        
        # Ensure address has 0x prefix
        if not address.startswith("0x"):
            address = f"0x{address}"
            
        items.append({
            "name": name,
            "address": address,
        })
    
    # Calculate pagination
    total = len(items)
    if limit <= 0:
        limit = total if total > 0 else 1
        page = 1
        paginated_items = items[offset:]
    else:
        page = offset // limit + 1
        paginated_items = items[offset : offset + limit]

    page = max(page, 1)
    limit = max(limit, 1)
    has_more = (page * limit) < total

    return {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }
