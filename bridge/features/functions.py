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
    """Search for functions matching *query* and return a paginated payload."""

    # Requests are validated but we defensively clamp the limit to the schema bounds.
    limit = max(1, min(int(limit), 500))
    offset = max(int(offset), 0)

    # Normalize wildcard searches to match Ghidra's behaviour.
    search_query = "" if query in ("", "*") else query
    raw_results = client.search_functions(search_query) or []

    # Parse raw strings into structured name/address pairs while ensuring 0x prefix.
    parsed_items: List[Dict[str, str]] = []
    for line in raw_results:
        line = line.strip()
        if " @ " in line:
            parts = line.rsplit(" @ ", 1)
        elif " at " in line:
            parts = line.rsplit(" at ", 1)
        else:
            continue

        if len(parts) != 2:
            continue

        name, addr = parts
        addr = addr.strip()
        if addr and not addr.lower().startswith("0x"):
            addr = f"0x{addr}"

        parsed_items.append({
            "name": name.strip(),
            "address": addr.lower() if addr else addr,
        })

    total = len(parsed_items)

    start = min(offset, total)
    end = min(start + limit, total)
    paginated_items = parsed_items[start:end]

    page = (start // limit) + 1 if limit else 1
    has_more = end < total

    return {
        "query": query,
        "total": total,
        "page": page,
        "limit": limit,
        "items": paginated_items,
        "has_more": has_more,
    }
