from typing import Dict, List

from ..ghidra.client import GhidraClient


def search_imports(
    client: GhidraClient,
    *,
    query: str,
    limit: int = 100,
    page: int = 1,
) -> Dict[str, object]:
    """Search for imported symbols matching ``query`` and return paginated results."""

    raw_results = client.search_imports(query)

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
    limit = max(int(limit), 1)
    page = max(int(page), 1)
    offset = (page - 1) * limit
    start = min(offset, total)
    end = min(start + limit, total)
    paginated_items = items[start:end]

    has_more = end < total

    return {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }
