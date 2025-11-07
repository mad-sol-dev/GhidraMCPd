"""Configuration for golden tests (OpenAPI snapshots, HTTP parity, etc.)."""
from __future__ import annotations

import pytest

from bridge.tests._env import env_flag, in_ci


_RUN_GOLDEN_TESTS = env_flag("RUN_GOLDEN_TESTS", default=not in_ci())

if not _RUN_GOLDEN_TESTS:
    _SKIP_REASON = "Golden tests disabled. Set RUN_GOLDEN_TESTS=1 to enable."

    def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
        skip_marker = pytest.mark.skip(reason=_SKIP_REASON)
        for item in items:
            item.add_marker(skip_marker)
