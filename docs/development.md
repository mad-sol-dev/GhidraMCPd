# Development

## Tests

```bash
python -m pytest -q bridge/tests/unit bridge/tests/contract bridge/tests/golden
```

## Java Development

Use this path when you need IDE support or want to iterate on the Ghidra extension outside the Docker builder.

### Prerequisites

* JDK 21
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
   mvn -DskipTests -Drevision="$(scripts/plugin_version.sh)" package
   ```

   To include tests, drop `-DskipTests`. Without `-Drevision` the build is
   labelled `1.3.0-local`.

### Plugin Version

The version counts up by itself with every plugin change. `scripts/plugin_version.sh`
derives it from git; `scripts/build_docker.sh` and CI call it for you.

| Tree state | Version | Example |
|---|---|---|
| clean | `<base>.<N>`, N = commits touching `src/` or `pom.xml` | `1.3.54` |
| uncommitted plugin changes | `<base>.<N+1>-dev.<UTC timestamp>` | `1.3.55-dev.20261010084359` |

`<base>` (major.minor) is set by hand as `<plugin.version.base>` in `pom.xml`.

Where to read the installed version:
- Install Extensions dialog: in the description ("Plugin version ...")
- Ghidra log: `GhidraMCPPlugin <version> loaded!`
- HTTP: `curl http://127.0.0.1:8080/plugin_version` (works without an open program;
  `"api"` is the answer convention, 2 since R.24)

The bridge refuses a plugin below API 2. Tests that talk to a mocked plugin over HTTP
build their transport with `bridge/tests/plugin_http.py` (`plugin_transport` adds the
API header, `plugin_error` builds an API 2 failure), so the mocks answer the way the
plugin does.

The `version=` line in `extension.properties` must stay the Ghidra version; Ghidra
refuses the extension otherwise.

### Output Location

The build produces:

```
target/GhidraMCP-<version>.zip
```

### Installation

**Option 1: Manual copy**

```bash
cp target/GhidraMCP.jar $GHIDRA_INSTALL_DIR/Extensions/Ghidra/
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

## Utilities

### `aggregate_transcripts` (in `bridge.orchestrator`)

Parses transcript records to extract the **first JSON object per record**, validates each object against a JSON schema (default:
 `envelope.v1.json`), and produces a summary dict:

* `total`: number of records processed
* `ok`: records whose first JSON object matched the schema
* `failed`: records that did not match

Use this when you need a quick quality check on logged transcripts.
