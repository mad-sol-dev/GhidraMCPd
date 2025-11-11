"""Generic TTL cache helpers for bridge features."""

from __future__ import annotations

import json
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Any, Callable, Dict, Hashable, Iterable, Mapping, MutableMapping, Optional, Tuple
from weakref import WeakKeyDictionary

from .logging import increment_counter


Serializer = Callable[[Mapping[str, Any]], Any]
Deserializer = Callable[[Any], Mapping[str, Any]]


@dataclass(slots=True)
class _CacheEntry:
    payload: Any
    expires_at: float


class TTLCache:
    """A small in-memory TTL cache with optional serialization support."""

    def __init__(
        self,
        *,
        ttl_seconds: float,
        namespace: str,
        serializer: Serializer,
        deserializer: Deserializer,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._ttl = float(ttl_seconds)
        self._namespace = namespace
        self._serializer = serializer
        self._deserializer = deserializer
        self._clock = clock
        self._default_clock = clock
        self._entries: Dict[Hashable, _CacheEntry] = {}
        self._lock = Lock()

    def _now(self) -> float:
        return self._clock()

    def get(self, key: Hashable) -> Optional[Mapping[str, Any]]:
        """Return the cached payload for *key* if present and fresh."""

        with self._lock:
            entry = self._entries.get(key)
            if not entry:
                increment_counter(f"{self._namespace}.miss")
                return None
            if entry.expires_at <= self._now():
                self._entries.pop(key, None)
                increment_counter(f"{self._namespace}.miss")
                return None
            payload = entry.payload
        increment_counter(f"{self._namespace}.hit")
        return self._deserializer(payload)

    def set(self, key: Hashable, value: Mapping[str, Any]) -> None:
        """Store *value* for *key* with a TTL."""

        serialized = self._serializer(value)
        expires_at = self._now() + self._ttl
        with self._lock:
            self._entries[key] = _CacheEntry(payload=serialized, expires_at=expires_at)

    def invalidate(self, key: Hashable) -> None:
        """Remove *key* from the cache if present."""

        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        """Remove all cached entries."""

        with self._lock:
            self._entries.clear()

    def set_clock(self, clock: Callable[[], float]) -> None:
        """Override the clock used for TTL calculations (primarily for tests)."""

        self._clock = clock

    def reset_clock(self) -> None:
        """Restore the default monotonic clock."""

        self._clock = self._default_clock


def _freeze_option(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((k, _freeze_option(v)) for k, v in value.items()))
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return tuple(_freeze_option(item) for item in value)
    return value


def normalize_search_query(query: str | None) -> str:
    """Collapse whitespace and lowercase search *query* for cache keys."""

    if query is None:
        return ""
    normalized = " ".join(str(query).strip().split())
    return normalized.lower()


def build_search_cache_key(
    *,
    program_digest: str,
    endpoint: str,
    normalized_query: str,
    options: Mapping[str, Any],
) -> Tuple[Any, ...]:
    """Create a stable cache key for search responses."""

    frozen_options = tuple(sorted((key, _freeze_option(value)) for key, value in options.items()))
    return (program_digest, endpoint, normalized_query, frozen_options)


def _serialize_payload(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def _deserialize_payload(data: Any) -> Mapping[str, Any]:
    if isinstance(data, str):
        return json.loads(data)
    raise TypeError("Unexpected payload type in cache")


_search_cache = TTLCache(
    ttl_seconds=300,
    namespace="search.cache",
    serializer=_serialize_payload,
    deserializer=_deserialize_payload,
)


def get_search_cache() -> TTLCache:
    """Return the shared TTL cache for search responses."""

    return _search_cache


_DIGEST_CACHE: "WeakKeyDictionary[Any, Optional[str]]" = WeakKeyDictionary()


def _extract_digest(info: Mapping[str, Any]) -> Optional[str]:
    for key in ("program_digest", "digest", "executable_sha256", "executable_md5"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


def get_program_digest(client: Any) -> Optional[str]:
    """Return a stable digest for the active program if available."""

    try:
        cached = _DIGEST_CACHE.get(client)
    except TypeError:
        cached = None
    if cached:
        return cached

    getter = getattr(client, "get_project_info", None)
    if getter is None:
        return None
    try:
        info = getter()
    except Exception:  # pragma: no cover - defensive
        return None
    if not isinstance(info, Mapping):
        return None
    digest = _extract_digest(info)
    if digest:
        try:
            _DIGEST_CACHE[client] = digest
        except TypeError:
            pass
    return digest


__all__ = [
    "TTLCache",
    "build_search_cache_key",
    "get_program_digest",
    "get_search_cache",
    "normalize_search_query",
]

