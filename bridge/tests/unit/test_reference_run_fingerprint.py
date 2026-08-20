"""The Stage 7 comparison is only valid if it measures the same database."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "reference_run.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("reference_run", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


reference_run = _load_script()


BASE = {
    "kind": "fingerprint",
    "program_name": "ZK-INKJET-NANO-APP.bin",
    "executable_sha256": "3be9028b",
    "function_count": 1266,
    "user_named_functions": 24,
}


def test_identical_fingerprints_do_not_drift():
    assert reference_run.compare_fingerprints(BASE, dict(BASE)) == []


@pytest.mark.parametrize(
    "key, value",
    [
        ("program_name", "OTHER.bin"),
        ("executable_sha256", "deadbeef"),
        ("function_count", 1267),
        ("user_named_functions", 25),
    ],
)
def test_any_identity_field_drifting_is_reported(key, value):
    current = {**BASE, key: value}
    drift = reference_run.compare_fingerprints(current, BASE)
    assert len(drift) == 1
    assert key in drift[0]


def test_renaming_functions_is_detected():
    """Renames are the realistic drift: same binary, changed .rep."""

    after_a_session = {**BASE, "user_named_functions": 31}
    assert reference_run.compare_fingerprints(after_a_session, BASE)


def test_default_symbol_names_are_not_counted_as_user_work():
    default_names = [
        "FUN_00200060",
        "thunk_FUN_0020014c",
        "SUB_00200254",
        "LAB_00200264",
        "DAT_002afb34",
        "EXT_FUN_0006781e",
    ]
    for name in default_names:
        assert reference_run._DEFAULT_SYMBOL.match(name), name

    for name in ("usbd_init_phy_cep", "ui_main_loop", "boot_init", "FUN_notahexstring"):
        assert not reference_run._DEFAULT_SYMBOL.match(name), name
