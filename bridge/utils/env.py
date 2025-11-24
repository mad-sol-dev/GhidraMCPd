"""Lightweight helpers for loading local environment defaults."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

__all__ = ["load_env"]


_env_loaded = False


def load_env(*, dotenv_path: Optional[str | Path] = None) -> None:
    """Load a ``.env`` file once, if present.

    The loader is intentionally quiet when no file exists and avoids reloading after the
    first call so imports remain inexpensive.
    """

    global _env_loaded
    if _env_loaded:
        return

    load_dotenv(dotenv_path=dotenv_path, override=False)
    _env_loaded = True
