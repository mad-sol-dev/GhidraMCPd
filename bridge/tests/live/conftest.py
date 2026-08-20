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


def _probe() -> tuple[Optional[dict], str]:
    """Return (project_info, reason).  ``project_info`` is None when unusable.

    The reason has to name the actual cause.  A run that reports "no Ghidra
    instance" when Ghidra is running and the flag is off tells you nothing was
    checked *and* why -- wrongly, which is the failure mode this whole suite
    exists to prevent.
    """

    if os.getenv("RUN_LIVE_TESTS", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return None, "live tests disabled (RUN_LIVE_TESTS=0)"

    try:
        client = GhidraClient(GHIDRA_URL, timeout=10)
    except Exception as exc:  # noqa: BLE001
        return None, f"cannot build a client for {GHIDRA_URL} ({type(exc).__name__})"

    try:
        info = client.get_project_info()
    except Exception as exc:  # noqa: BLE001
        return None, f"no Ghidra instance at {GHIDRA_URL} ({type(exc).__name__})"
    finally:
        client.close()

    if not isinstance(info, dict):
        return None, f"Ghidra at {GHIDRA_URL} returned no project info"

    actual = str(info.get("executable_sha256", "")).lower()
    if actual != EXPECTED_SHA256:
        return None, (
            f"Ghidra at {GHIDRA_URL} is serving a different program "
            f"(sha256 {actual[:16] or '?'}…, expected {EXPECTED_SHA256[:16]}…)"
        )

    return info, ""


_PROJECT_INFO, _SKIP_REASON = _probe()


@pytest.fixture(scope="session")
def project_info():
    if _PROJECT_INFO is None:
        pytest.skip(_SKIP_REASON)
    return _PROJECT_INFO


@pytest.fixture(scope="session")
def client(project_info):
    """A client for the identified program.

    ``project_info`` has already established that an instance answers and that
    it serves the expected binary; a regression test running silently against a
    different one would prove nothing.
    """

    handle = GhidraClient(GHIDRA_URL, timeout=120)
    yield handle
    handle.close()
