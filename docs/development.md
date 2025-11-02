# Development

## Tests

```bash
python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden
```

## Plan workflow

* Edit `.plan/TODO.md`, `.plan/tasks.manifest.json`, `.plan/state.json`
* Keep them in sync with `python3 bin/plan_check.py`
* Use `.plan/sync_state.sh` after each task

## CI

GitHub Actions runs:

* Plan check
* Python tests
* Maven packaging (only when Java changes)

## Ghidra-API Quicklinks

* [`docs/ghidra-plugin-ground-truth.md`](ghidra-plugin-ground-truth.md)

Additional design notes and roadmap context live in [`docs/ROADMAP.md`](ROADMAP.md).
