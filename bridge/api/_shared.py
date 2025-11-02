"""Shared helpers for tools and HTTP routes."""
from __future__ import annotations

import inspect
import os
from functools import wraps
from typing import Callable, Dict

from ..adapters import ArchAdapter, load_optional_adapter, optional_adapter_names
from ..adapters.arm_thumb import ARMThumbAdapter
from ..adapters.fallback import FallbackAdapter
from ..ghidra.client import GhidraClient
from ..utils.errors import ErrorCode, make_error


def envelope_ok(data: Dict[str, object]) -> Dict[str, object]:
    return {"ok": True, "data": data, "errors": []}


def envelope_error(code: ErrorCode | str, message: str) -> Dict[str, object]:
    return {"ok": False, "data": None, "errors": [make_error(code, message)]}


def adapter_for_arch(arch: str) -> ArchAdapter:
    normalized = arch.lower()
    if normalized in {"arm", "auto", "thumb"}:
        return ARMThumbAdapter()

    enabled = os.getenv("BRIDGE_OPTIONAL_ADAPTERS", "")
    if enabled:
        requested = {
            item.strip().lower()
            for item in enabled.split(",")
            if item.strip()
        }
        registry = optional_adapter_names()
        if normalized in requested and normalized in registry:
            return load_optional_adapter(normalized)

    return FallbackAdapter()


def inject_client(factory: Callable[[], GhidraClient]):
    """Inject a :class:`GhidraClient` and hide it from the published signature."""

    def decorator(func):
        sig = inspect.signature(func)
        params = list(sig.parameters.values())
        if not params:
            raise TypeError("inject_client requires a function that accepts a client parameter")

        public_params = params[1:]
        public_signature = inspect.Signature(
            public_params, return_annotation=sig.return_annotation
        )

        @wraps(func)
        def wrapper(*args, **kwargs):
            client = factory()
            try:
                return func(client, *args, **kwargs)
            finally:
                client.close()

        wrapper.__signature__ = public_signature
        return wrapper

    return decorator


def with_client(factory: Callable[[], GhidraClient]):
    """Helper used by HTTP routes that need explicit client injection."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client = factory()
            try:
                return func(client, *args, **kwargs)
            finally:
                client.close()

        return wrapper

    return decorator
