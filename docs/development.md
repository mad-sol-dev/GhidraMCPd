# Development

## Tests

```bash
python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden
```

## Building the Ghidra Plugin

### Prerequisites

* JDK 17 or later
* Maven 3.6+
* Ghidra 11.4.2 (or set `GHIDRA_DIR` to your local installation)

### Build Steps

1. **Fetch Ghidra dependencies:**

   ```bash
   python scripts/fetch_ghidra_jars.py
   ```

   This downloads the required Ghidra JARs into `lib/`. Alternatively, if you have a local Ghidra installation:

   ```bash
   export GHIDRA_DIR=/path/to/ghidra_11.4.2_PUBLIC
   ```

2. **Build the extension:**

   ```bash
   mvn -DskipTests package
   ```

   To include tests:

   ```bash
   mvn package
   ```

### Output Location

The build produces:

```
target/GhidraMCP-1.0-SNAPSHOT.jar
```

### Installation

**Option 1: Manual copy**

```bash
cp target/GhidraMCP-1.0-SNAPSHOT.jar $GHIDRA_INSTALL_DIR/Extensions/Ghidra/
```

**Option 2: Ghidra GUI**

1. Open Ghidra
2. Go to **File → Install Extensions**
3. Click the **+** button
4. Select `target/GhidraMCP-1.0-SNAPSHOT.jar`
5. Restart Ghidra

**Verify installation:**

After restarting Ghidra, the extension should appear in **File → Configure → Miscellaneous → GhidraMCP**.

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
