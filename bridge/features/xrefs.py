"""Cross-reference search helpers."""

from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.cache import (
    build_search_cache_key,
    get_program_digest,
    get_search_cache,
    normalize_search_query,
)
from ..utils.config import MAX_ITEMS_PER_BATCH
from ..utils.logging import SafetyLimitExceeded


def search_xrefs_to(
    client: GhidraClient,
    *,
    address: str,
    query: str,
    limit: int = 100,
    page: int = 1,
) -> Dict[str, object]:
    """Search cross-references to ``address`` and return a paginated response.
    
    Args:
        client: Ghidra client instance
        address: Target address as hex string
        query: Search query string
        limit: Maximum number of results per page
        page: 1-based page number for pagination
        
    Returns:
        Dictionary with query, total count, page, limit, items array, and has_more flag
    """

    try:
        address_value = int(address, 16)
    except ValueError as exc:  # pragma: no cover - validated earlier
        raise ValueError(f"Invalid address: {address}") from exc

    limit = max(int(limit), 1)
    page = max(int(page), 1)

    window = page * limit
    if window > MAX_ITEMS_PER_BATCH:
        raise SafetyLimitExceeded("xrefs.search.window", MAX_ITEMS_PER_BATCH, window)

    normalized_query = normalize_search_query(query)
    search_query = normalized_query

    cache_key = None
    digest = get_program_digest(client)
    cache = get_search_cache()
    if digest:
        cache_key = build_search_cache_key(
            program_digest=digest,
            endpoint="xrefs_to",
            normalized_query=normalized_query,
            options={
                "address": address_value,
                "limit": limit,
                "page": page,
            },
        )
        cached = cache.get(cache_key)
        if cached is not None:
            return dict(cached)

    try:
        raw_results = client.search_xrefs_to(address_value, search_query)
    except Exception:
        if cache_key is not None:
            cache.invalidate(cache_key)
        raise

    target_address = f"0x{address_value:08x}"
    items: List[Dict[str, str]] = []
    ordered_entries = []
    for entry in raw_results:
        addr_val = entry.get("addr")
        context = entry.get("context", "")
        if not isinstance(addr_val, int):
            continue
        ordered_entries.append((addr_val, str(context)))

    ordered_entries.sort(key=lambda item: item[0])

    for addr_val, context_text in ordered_entries:
        items.append(
            {
                "from_address": f"0x{addr_val:08x}",
                "context": context_text,
                "target_address": target_address,
            }
        )

    total = len(items)
    offset = (page - 1) * limit
    start = min(offset, total)
    end = min(start + limit, total)
    paginated_items = items[start:end]

    has_more = end < total

    result = {
        "query": search_query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }

    if cache_key is not None:
        cache.set(cache_key, result)

    return result
