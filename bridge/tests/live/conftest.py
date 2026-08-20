"""Tests that need a live Ghidra instance with the frozen ZK-Inkjet copy.

Skipped automatically when no instance answers, so the default suite stays
runnable without Ghidra.  Point GHIDRA_SERVER_URL elsewhere to use a different
instance; set RUN_LIVE_TESTS=0 to skip them even when one is reachable.
"""
from __future__ import annotations

import os

import pytest

from bridge.ghidra.client import GhidraClient

GHIDRA_URL = os.getenv("GHIDRA_SERVER_URL", "http://127.0.0.1:8080/")

#: The program these tests make claims about.
EXPECTED_SHA256 = "3be9028b01c0007aab9192877341918a0bc155beef55ac17e7e8f3bcc95151ea"


def _probe() -> dict | None:
    if os.getenv("RUN_LIVE_TESTS", "1") not in {"1", "true", "yes", "on"}:
        return None
    try:
        client = GhidraClient(GHIDRA_URL, timeout=10)
    except Exception:  # noqa: BLE001
        return None
    try:
        return client.get_project_info()
    except Exception:  # noqa: BLE001
        return None
    finally:
        client.close()


_PROJECT_INFO = _probe()


@pytest.fixture(scope="session")
def project_info():
    if _PROJECT_INFO is None:
        pytest.skip(f"no Ghidra instance at {GHIDRA_URL}")
    return _PROJECT_INFO


@pytest.fixture(scope="session")
def client(project_info):
    """A client, but only after the program has been identified.

    A regression test that silently runs against a different binary proves
    nothing, so the fixture refuses rather than reporting a false pass.
    """

    actual = str(project_info.get("executable_sha256", "")).lower()
    if actual != EXPECTED_SHA256:
        pytest.skip(
            "live Ghidra is serving a different program "
            f"(sha256 {actual[:16]}…, expected {EXPECTED_SHA256[:16]}…)"
        )

    handle = GhidraClient(GHIDRA_URL, timeout=120)
    yield handle
    handle.close()
