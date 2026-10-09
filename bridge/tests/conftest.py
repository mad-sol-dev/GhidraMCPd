"""Test configuration helpers to ensure package imports work from the repository root."""
from __future__ import annotations

import os
import sys
from pathlib import Path


# The suite pins the write flags itself instead of trusting the environment.
# python-dotenv searches upwards from the working directory, so a run started in
# a worktree picks up the main repository's .env -- which has writes enabled.  A
# test run that merely happens not to write is no protection, so the values are
# forced here, before any bridge module reads them at import time.
os.environ["GHIDRA_MCP_ENABLE_WRITES"] = "false"

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
