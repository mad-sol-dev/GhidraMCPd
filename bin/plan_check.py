#!/usr/bin/env python3
import re, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
todo_p = ROOT/".plan"/"TODO.md"
man_p  = ROOT/".plan"/"tasks.manifest.json"
st_p   = ROOT/".plan"/"state.json"

def die(msg):
    """Print an error message and exit with failure."""
    print(f"PLAN CHECK ✖ {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    """Print a success message for informational checks."""
    print(f"PLAN CHECK ✓ {msg}")

# --- read files
try:
    todo = todo_p.read_text(encoding="utf-8")
    man_raw = man_p.read_text(encoding="utf-8")
    man  = json.loads(man_raw)
    st   = json.loads(st_p.read_text(encoding="utf-8"))
except Exception as e:
    die(f"failed to read plan files: {e}")

# --- UTF-8 sanity (simple mojibake marker)
if "â†’" in todo or "â†’" in man_raw:
    die("UTF-8 mojibake detected (e.g., 'â†’'). Fix arrows like 'READ→VERIFY'.")

# --- IDs from TODO lists like '- {TASK-ID} Summary'
todo_items = []
section = None
pat = re.compile(r"^-\s*\{([^}]+)\}\s*(.*)$")
for line in todo.splitlines():
    if line.startswith("## "):
        section = line[3:].strip()
        continue
    m = pat.match(line.strip())
    if not m:
        continue
    tid = m.group(1).strip()
    if tid.lower() == "none":
        continue
    todo_items.append((tid, section))

todo_ids = {tid for tid,_ in todo_items}
if not todo_ids:
    die("no tasks parsed from TODO.md bullet list (expected '- {TASK-ID} Summary')")

if isinstance(man, dict):
    man_entries = man.get("sequence", [])
else:
    man_entries = man
try:
    man_ids = {e["id"] for e in man_entries}
except Exception:
    die("tasks.manifest.json must contain objects with an 'id' field")
state_ids = set(st.get("tasks", {}).keys())

# --- ID set checks
missing_in_state  = todo_ids - state_ids
missing_in_man    = todo_ids - man_ids
extra_in_state    = state_ids - todo_ids  # tolerated, but warn

if missing_in_state:
    die(f"IDs in TODO missing in state.json: {sorted(missing_in_state)}")
if missing_in_man:
    die(f"IDs in TODO missing in tasks.manifest.json: {sorted(missing_in_man)}")

if extra_in_state:
    ok(f"note: extra IDs in state.json (not in TODO): {sorted(extra_in_state)}")

# --- status mapping
# Determine expected state based on TODO sections.
def expected_status(section_name: str):
    if not section_name:
        return ("todo", "in-progress")
    section_upper = section_name.upper()
    if "BLOCKED" in section_upper:
        return "blocked"
    if "DONE" in section_upper:
        return "done"
    return ("todo", "in-progress")

problems = []
for tid, section_name in todo_items:
    s = st["tasks"].get(tid, {})
    want = expected_status(section_name)
    got  = s.get("status")
    if isinstance(want, tuple):
        if got not in want:
            problems.append(f"{tid}: section '{section_name}' expects {want}, state.json has '{got}'")
    else:
        if got != want:
            problems.append(f"{tid}: section '{section_name}' expects '{want}', state.json has '{got}'")
        if want == "done" and not s.get("commit"):
            problems.append(f"{tid}: marked done but state.json.commit is missing")
if problems:
    die("status/commit mismatch:\n  - " + "\n  - ".join(problems))

ok("IDs aligned across TODO/manifest/state")
ok("Statuses & commits consistent")
sys.exit(0)
