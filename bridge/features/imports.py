from typing import Dict, List

from ..ghidra.client import GhidraClient
from ..utils.cache import (
    build_search_cache_key,
    get_program_digest,
    get_search_cache,
    normalize_search_query,
)


def search_imports(
    client: GhidraClient,
    *,
    query: str,
    limit: int = 100,
    page: int = 1,
) -> Dict[str, object]:
    """Search for imported symbols matching ``query`` and return paginated results."""

    limit = max(int(limit), 1)
    page = max(int(page), 1)

    normalized_query = normalize_search_query(query)

    cache_key = None
    digest = get_program_digest(client)
    cache = get_search_cache()
    if digest:
        cache_key = build_search_cache_key(
            program_digest=digest,
            endpoint="imports",
            normalized_query=normalized_query,
            options={"limit": limit, "page": page},
        )
        cached = cache.get(cache_key)
        if cached is not None:
            return dict(cached)

    try:
        raw_results = client.search_imports(query)
    except Exception:
        if cache_key is not None:
            cache.invalidate(cache_key)
        raise

    items: List[Dict[str, str]] = []
    for line in raw_results:
        if "->" not in line:
            continue
        name_part, _, address_part = line.partition("->")
        name = name_part.strip()
        address = address_part.strip()
        if not name or not address:
            continue
        if not address.startswith("0x"):
            address = f"0x{address}"
        items.append({"name": name, "address": address})

    total = len(items)
    offset = (page - 1) * limit
    start = min(offset, total)
    end = min(start + limit, total)
    paginated_items = items[start:end]

    has_more = end < total

    result = {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }

    if cache_key is not None:
        cache.set(cache_key, result)

    return result
