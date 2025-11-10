"""Function search and listing features."""

from __future__ import annotations

import re
from typing import Dict, List

from ..ghidra.client import GhidraClient

_FUNCTION_LINE = re.compile(
    r"^(?P<name>.+?)\s+(?:@|at)\s+(?P<addr>(?:0x)?[0-9A-Fa-f]+)\s*$"
)


def search_functions(
    client: GhidraClient,
    *,
    query: str,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, object]:
    """Search for functions matching *query* and return a paginated payload."""

    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))

    query_str = str(query)
    search_query = "" if query_str in {"", "*"} else query_str
    raw_results = client.search_functions(search_query) or []

    parsed_items: List[Dict[str, str]] = []
    for line in raw_results:
        match = _FUNCTION_LINE.match(line.strip())
        if not match:
            continue
        name = match.group("name").strip()
        addr = match.group("addr").strip()
        if not addr.lower().startswith("0x"):
            addr = f"0x{addr}"
        parsed_items.append({
            "name": name,
            "address": addr.lower(),
        })

    total = len(parsed_items)
    start = min(offset, total)
    end = min(start + limit, total)
    paginated_items = parsed_items[start:end]

    page = (start // limit) + 1 if limit else 1
    has_more = end < total

    return {
        "query": query_str,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }
