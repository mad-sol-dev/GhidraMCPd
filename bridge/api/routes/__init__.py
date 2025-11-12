from __future__ import annotations

import asyncio
import logging
from typing import Callable, Iterable, List

from starlette.routing import Route

from ...ghidra.client import GhidraClient
from ...utils.config import ENABLE_WRITES
from ._common import RouteDependencies, build_with_client, validated_json_body
from .._shared import adapter_for_arch
from .analysis_routes import create_analysis_routes
from .collect_routes import create_collect_routes
from .datatypes_routes import create_datatype_routes
from .disasm_routes import create_disasm_routes
from .health_routes import create_health_routes
from .jt_routes import create_jt_routes
from .memory_routes import create_memory_routes
from .mmio_routes import create_mmio_routes
from .project_routes import create_project_routes
from .search_routes import create_search_routes


def make_routes(
    client_factory: Callable[[], GhidraClient], *, enable_writes: bool = ENABLE_WRITES,
    call_semaphore: asyncio.Semaphore | None = None,
) -> List[Route]:
    logger = logging.getLogger("bridge.api")
    semaphore = call_semaphore or asyncio.Semaphore(1)

    with_client = build_with_client(
        client_factory, enable_writes=enable_writes, call_semaphore=semaphore
    )
    deps = RouteDependencies(
        enable_writes=enable_writes,
        logger=logger,
        validated_json_body=validated_json_body,
        with_client=with_client,
        client_factory=client_factory,
    )

    groups: Iterable[List[Route]] = (
        create_health_routes(client_factory, enable_writes, logger, semaphore),
        create_project_routes(deps),
        create_jt_routes(deps),
        create_search_routes(deps),
        create_collect_routes(deps),
        create_mmio_routes(deps),
        create_disasm_routes(deps),
        create_memory_routes(deps),
        create_analysis_routes(deps),
        create_datatype_routes(deps),
    )

    routes: List[Route] = []
    for group in groups:
        routes.extend(group)
    return routes


__all__ = ["make_routes", "adapter_for_arch"]
