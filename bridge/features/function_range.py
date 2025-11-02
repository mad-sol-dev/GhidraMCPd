"""Function range listing helpers."""
from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.hex import parse_hex
from ..utils.logging import increment_counter


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
    
    # Sort by address for determinism
    sorted_results = sorted(raw_results, key=lambda x: parse_hex(x["address"]))
    
    # Build items list
    items: List[Dict[str, object]] = []
    for entry in sorted_results:
        addr_str = entry.get("address", "")
        if not addr_str.startswith("0x"):
            addr_str = f"0x{addr_str}"
        
        items.append({
            "name": entry.get("name", ""),
            "address": addr_str,
            "size": entry.get("size"),
        })
    
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
    
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
    }


__all__ = ["list_functions_in_range"]
