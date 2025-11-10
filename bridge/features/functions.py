"""Function search and listing features."""

from __future__ import annotations

import re
from typing import Dict, List

from ..ghidra.client import GhidraClient

_FUNCTION_LINE = re.compile(
    r"^(?P<name>.+?)\s+(?:@|at)\s+(?P<addr>(?:0x)?[0-9A-Fa-f]+)\s*$"
)


def _rank_functions_simple(
    items: List[Dict[str, str]], query: str
) -> List[Dict[str, str]]:
    """Apply a simple heuristic scoring to *items* and return a new ordering."""

    normalized_query = query.strip().lower()
    if not normalized_query:
        return list(items)

    scored: List[tuple[int, int, Dict[str, str]]] = []
    for index, item in enumerate(items):
        name = item.get("name", "")
        address = item.get("address", "")
        name_normalized = name.lower()
        address_normalized = address.lower()

        score = 0
        if name_normalized == normalized_query:
            score += 400
        if name_normalized.startswith(normalized_query):
            score += 200
        if normalized_query in name_normalized:
            score += 100
        if address_normalized == normalized_query:
            score += 350
        elif normalized_query in address_normalized:
            score += 150

        scored.append((-score, index, item))

    scored.sort()
    return [entry[2] for entry in scored]


def search_functions(
    client: GhidraClient,
    *,
    query: str,
    limit: int = 100,
    page: int = 1,
    rank: str | None = None,
    k: int | None = None,
) -> Dict[str, object]:
    """Search for functions matching *query* and return a paginated payload."""

    limit = max(1, min(int(limit), 500))
    page = max(1, int(page))
    offset = (page - 1) * limit

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

    ranked_items = parsed_items
    if rank == "simple":
        ranked_items = _rank_functions_simple(parsed_items, query_str)
        if k is not None:
            k = max(1, int(k))
            ranked_items = ranked_items[:k]

    total = len(ranked_items)
    start = min(offset, total)
    end = min(start + limit, total)
    paginated_items = ranked_items[start:end]

    has_more = end < total

    return {
        "query": query_str,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }
