"""Environment helpers for test selection and configuration."""
from __future__ import annotations

import os
from typing import Final


_TRUE_VALUES: Final[set[str]] = {"1", "true", "yes", "on"}


def env_flag(name: str, *, default: bool = False) -> bool:
    """Return True if the environment flag is set to a truthy value."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in _TRUE_VALUES


def in_ci() -> bool:
    """Detect whether the tests are running in CI."""
    return env_flag("CI")


__all__ = ["env_flag", "in_ci"]
