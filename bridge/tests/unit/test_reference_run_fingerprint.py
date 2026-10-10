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


# -- the checked-in baseline is not a scratch file ---------------------------

STRUCTURAL = ROOT / "scripts" / "reference_run_structural.py"
CHECKED_IN = ROOT / "baseline" / "reference_run.jsonl"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("script", [SCRIPT, STRUCTURAL], ids=["reference", "structural"])
def test_a_run_without_arguments_does_not_write_into_baseline(script, monkeypatch):
    module = _load(script, script.stem)
    seen = {}

    class Stop(Exception):
        pass

    def stop(*_, **__):
        raise Stop

    monkeypatch.setattr(module, "fingerprint_database", stop)
    parse = module.argparse.ArgumentParser.parse_args

    def capture(self, argv=None, namespace=None):
        args = parse(self, argv, namespace)
        seen["usage_log"] = args.usage_log
        return args

    monkeypatch.setattr(module.argparse.ArgumentParser, "parse_args", capture)
    with pytest.raises(Stop):
        module.main([])

    assert seen["usage_log"].resolve().is_relative_to(ROOT / "runs")


@pytest.mark.parametrize("script", [SCRIPT, STRUCTURAL], ids=["reference", "structural"])
@pytest.mark.parametrize("flag", ["--usage-log", "--write-fingerprint"])
def test_replacing_a_baseline_file_is_refused_before_anything_runs(script, flag, monkeypatch, capsys):
    assert CHECKED_IN.exists()
    before = CHECKED_IN.read_bytes()
    module = _load(script, script.stem)

    def must_not_run(*_, **__):
        raise AssertionError("refused runs must not contact Ghidra")

    monkeypatch.setattr(module, "fingerprint_database", must_not_run)
    argv = [flag, str(CHECKED_IN)]
    if flag == "--write-fingerprint":
        argv += ["--usage-log", str(ROOT / "runs" / "unused.jsonl")]

    assert module.main(argv) == 2
    assert CHECKED_IN.read_bytes() == before
    assert "--overwrite-baseline" in capsys.readouterr().out


def test_baseline_conflicts_only_names_existing_baseline_files(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    existing = baseline / "reference_run.jsonl"
    existing.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(reference_run, "BASELINE_DIR", baseline)

    new_in_baseline = baseline / "reference_run_r24.jsonl"
    elsewhere = tmp_path / "runs" / "reference_run.jsonl"
    paths = [existing, new_in_baseline, elsewhere, None]

    assert reference_run.baseline_conflicts(paths, overwrite_baseline=False) == [existing]
    assert reference_run.baseline_conflicts(paths, overwrite_baseline=True) == []
