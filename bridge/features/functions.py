"""Function search and listing features."""

from __future__ import annotations

import re
from typing import Dict, List, Optional

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
    cursor: Optional[str] = None,
    resume_cursor: Optional[str] = None,
) -> Dict[str, object]:
    """Search for functions matching *query* and return a paginated payload."""

    limit = max(1, min(int(limit), 500))
    page = max(1, int(page))
    offset = (page - 1) * limit

    query_str = str(query)
    search_query = "" if query_str in {"", "*"} else query_str
    cursor_token = resume_cursor or cursor
    request_offset = 0 if cursor_token else offset

    page_result = client.search_functions(
        search_query,
        limit=limit,
        offset=request_offset,
        cursor=cursor_token,
    )

    def _parse_lines(lines: Optional[List[str]]) -> List[Dict[str, str]]:
        parsed: List[Dict[str, str]] = []
        if not lines:
            return parsed
        for line in lines:
            if not isinstance(line, str):
                continue
            match = _FUNCTION_LINE.match(line.strip())
            if not match:
                continue
            name = match.group("name").strip()
            addr = match.group("addr").strip()
            if not addr.lower().startswith("0x"):
                addr = f"0x{addr}"
            parsed.append({
                "name": name,
                "address": addr.lower(),
            })
        return parsed

    parsed_items = _parse_lines(page_result.items)

    ranked_items = parsed_items
    computed_total: Optional[int] = None
    computed_cursor: Optional[str] = page_result.cursor
    has_more = page_result.has_more

    if page_result.error and not parsed_items:
        has_more = False
        computed_cursor = None

    if rank == "simple":
        if cursor_token:
            raise ValueError("cursor pagination cannot be combined with rank")

        aggregated_lines: List[Dict[str, str]] = []
        fetch_cursor: Optional[str] = None
        fetch_offset = 0
        safety = 0
        while True:
            next_page = client.search_functions(
                search_query,
                limit=limit,
                offset=fetch_offset,
                cursor=fetch_cursor,
            )
            aggregated_lines.extend(_parse_lines(next_page.items))
            if next_page.error and not next_page.items:
                break
            if not next_page.has_more:
                break
            safety += 1
            if safety > 1000:  # pragma: no cover - defensive guard
                raise RuntimeError("cursor pagination did not converge for rank=simple")
            if next_page.cursor:
                fetch_cursor = next_page.cursor
                fetch_offset = 0
            else:
                fetch_offset += len(next_page.items or [])

        ranked_items = _rank_functions_simple(aggregated_lines, query_str)
        if k is not None:
            k = max(1, int(k))
            ranked_items = ranked_items[:k]
        computed_total = len(ranked_items)
        start = min(offset, computed_total)
        end = min(start + limit, computed_total)
        paginated_items = ranked_items[start:end]
        has_more = end < computed_total
        computed_cursor = None
    else:
        paginated_items = ranked_items
        if not has_more and not cursor_token:
            computed_total = request_offset + len(paginated_items)

    return {
        "query": query_str,
        "total": computed_total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
        "resume_cursor": computed_cursor,
        "cursor": computed_cursor,
    }
