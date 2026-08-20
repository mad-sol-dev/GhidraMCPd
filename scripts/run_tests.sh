#!/usr/bin/env bash
# Run the whole test suite.
#
# There is one argument on purpose: the suite root.  Naming subdirectories
# instead -- `pytest bridge/tests/unit bridge/tests/contract ...` -- silently
# drops whatever directory is not on the list, and a green result from a subset
# reads exactly like a green result from the whole.  During this rework that
# cost 37 of 472 tests (integration, obs, plan and test_request_validation.py)
# and hid three real failures for several stages.
#
# Usage:
#   scripts/run_tests.sh                # everything
#   scripts/run_tests.sh -k pagination  # extra args are passed through
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="${ROOT}/bridge/tests"

PYTHON="${PYTHON:-}"
if [[ -z "${PYTHON}" ]]; then
    if [[ -x "${ROOT}/.venv/bin/python" ]]; then
        PYTHON="${ROOT}/.venv/bin/python"
    elif [[ -x "${ROOT}/../../../.venv/bin/python" ]]; then
        # Worktrees keep the virtualenv in the main checkout.
        PYTHON="$(cd "${ROOT}/../../.." && pwd)/.venv/bin/python"
    else
        PYTHON="python3"
    fi
fi

echo "suite:  ${SUITE}"
echo "python: ${PYTHON}"
echo

# The suite pins the write flags itself (bridge/tests/conftest.py); nothing to
# set here.  Live tests skip themselves when no Ghidra or bridge answers.
exec "${PYTHON}" -m pytest "${SUITE}" "$@"
