# Session Notes - 2025-11-26

## Current State

**Version**: 1.3.0 (built, not yet installed)
**Location**: `target/GhidraMCP-1.3.0.zip`
**Last Commit**: 6f50269 - "Implement dirty-state handling and program save functionality (v1.3.0)"

## What We Accomplished This Session

### ✅ Path 3: Improve Reliability - Dirty-State Handling (COMPLETE)

Implemented comprehensive dirty-state checking to prevent data loss when switching programs.

**Features Added:**
1. **Dirty State Detection** (`check_dirty_state()`)
   - Checks if program has unsaved changes via `program.isChanged()`
   - Returns: changed status, save permission, program name

2. **Program Save** (`save_program(description?)`)
   - Saves current program with optional description
   - Uses `program.save(description, monitor)`
   - Validates ownership and write permissions

3. **Smart Program Switching** (enhanced `open_program`)
   - New `on_dirty` parameter with 3 modes:
     - `"error"` (default) - Fail if unsaved changes exist
     - `"save"` - Auto-save before switching
     - `"discard"` - Proceed with warning

**Implementation:**
- Java: 3 new methods in GhidraMCPPlugin.java (~130 lines)
- Python: 2 new client methods + 2 MCP tools (~157 lines)
- New HTTP endpoints: `/check_dirty_state`, `/save_program`
- Enhanced endpoint: `/open_program?on_dirty=<mode>`

**API References Used:**
- `Program.isChanged()` - Check for unsaved modifications
- `Program.canSave()` - Verify save permission
- `Program.save(String, TaskMonitor)` - Persist changes
- Docs: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html

### ✅ Documentation Updates (Previous Session)

Added comprehensive navigation documentation (commit 5c40dd1):
- docs/ROADMAP.md - Marked navigation as complete
- docs/README.md - Added curl example for goto endpoint
- docs/getting-started.md - Added "Basic usage workflows" section with navigation patterns

## What Needs Testing (NEXT STEPS)

### 1. Install v1.3.0 in Ghidra
```bash
# In Ghidra:
# File → Install Extensions → select target/GhidraMCP-1.3.0.zip
# Restart Ghidra
# File → Configure → check "GhidraMCP" to activate
```

### 2. Test Dirty-State Handling

**Test Case 1: Check Clean Program**
```python
# With a clean program loaded
result = check_dirty_state()
# Expected: {"changed": false, "can_save": true, "program_name": "..."}
```

**Test Case 2: Make Changes and Check**
```python
# Make some edits in Ghidra (rename function, add comment, etc.)
result = check_dirty_state()
# Expected: {"changed": true, "can_save": true, ...}
```

**Test Case 3: Save Program**
```python
result = save_program(description="Test save from MCP")
# Expected: {"saved": true, "program_name": "..."}
```

**Test Case 4: Switch Programs with Dirty State**
```python
# With unsaved changes:
# 1. Try switching with default (should fail)
result = select_program(domain_file_id="other_program")
# Expected: Error about unsaved changes

# 2. Try with save mode
result = select_program(domain_file_id="other_program", on_dirty="save")
# Expected: Success with warning about auto-save

# 3. Try with discard mode
result = select_program(domain_file_id="other_program", on_dirty="discard")
# Expected: Success with warning about discarded changes
```

### 3. Verify Navigation Still Works
```python
# Quick smoke test that v1.3.0 didn't break anything
goto_address("0x00000080")
# Expected: CodeBrowser jumps to address
```

## Roadmap Progress

### Path 3: Improve Reliability
- ✅ Dirty-state handling (COMPLETE)
- ⏳ Readiness gating (PARTIAL - ProgramStatusTracker exists but needs enhancement)
  - Need to expose state more prominently
  - Add automatic retry/wait logic for LOADING state
  - Document state transitions

### Path 2: Complete Navigation Story (NEXT PRIORITY)
- ⏳ Write tools for annotations:
  - `rename_function(address, new_name)` - Rename functions
  - `set_comment(address, comment, type)` - Add comments (EOL, PRE, PLATE, etc.)
  - All with write guards and dry_run support
  - Estimated: 1-2 hours

### Path 1: Polish & Documentation (FINAL PRIORITY)
- ⏳ Write AGENTS.md guide
  - Recommended tool sequencing
  - Common workflows (strings → xrefs → navigation)
- ⏳ User-facing cookbooks
  - USB handlers, bootloader analysis, MMIO surveys
  - Estimated: 2-3 hours

## Key Technical Details

### Version History
- v1.0-SNAPSHOT - Initial release
- v1.1.0 - Fixed ToolServices for auto-launch
- v1.1.1 - Refined tool launching
- v1.2.0 - Added goto_address navigation
- v1.3.0 - **Current** - Added dirty-state handling

### Important Files
- Java plugin: `src/main/java/com/lauriewired/GhidraMCPPlugin.java`
- Python client: `bridge/ghidra/client.py`
- MCP tools: `bridge/api/tools.py` (71KB file)
- Whitelist: `bridge/ghidra/whitelist.py`
- Build output: `target/GhidraMCP-1.3.0.zip`

### Build Command
```bash
mvn -DskipTests package
# Output: target/GhidraMCP-1.3.0.zip (66KB)
```

### Test Previous Features
From TESTING_REPORT.md:
- ✅ Project info, overview, current_program
- ✅ Program selection with auto-launch (v1.1.1)
- ✅ Navigation with goto_address (v1.2.0)
- ⚠️ Many operations fail when program is IDLE (needs readiness gating)

## How to Resume Next Session

1. **Check current version installed in Ghidra**
   ```bash
   # In Ghidra: Help → About Ghidra → Extensions
   # Look for GhidraMCP version
   ```

2. **If need to install v1.3.0**
   - Use installation steps above
   - Restart Ghidra

3. **Run test cases** (see "What Needs Testing" section above)

4. **After testing, choose next path:**
   - **Option A**: Complete Path 3 readiness gating (~1-2h)
   - **Option B**: Path 2 write tools (~1h)
   - **Option C**: Path 1 documentation (~2-3h)

5. **Resume command context**
   ```bash
   cd /home/martinm/programme/Projekte/GhidraMCPd
   source .venv/bin/activate  # if using Python venv
   ```

## Known Issues & Considerations

1. **Program must be READY** - Many operations fail with 503 if program is IDLE
   - Current workaround: Manually ensure analysis completes
   - Future: Readiness gating will handle this automatically

2. **Write operations disabled by default**
   - Set `GHIDRA_MCP_ENABLE_WRITES=true` to enable saves
   - This is intentional for safety

3. **Session continuity**
   - Git commits capture all changes
   - This SESSION_NOTES.md provides quick resume point
   - TESTING_REPORT.md has detailed test results

## Quick Reference - New MCP Tools

```python
# Check if program needs saving
check_dirty_state()
# → {"changed": bool, "can_save": bool, "program_name": str}

# Save current program
save_program(description="Fixed string references")
# → {"saved": bool, "program_name": str}

# Switch programs with dirty handling
select_program(domain_file_id="...", on_dirty="error|save|discard")
# → Success or error based on dirty state
```

## Resources

- **Ghidra API Docs**: https://ghidra.re/ghidra_docs/api/
- **Program API**: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
- **ROADMAP**: docs/ROADMAP.md
- **Getting Started**: docs/getting-started.md (has usage examples)
- **Testing Report**: TESTING_REPORT.md

---

**Next Session Goal**: Test v1.3.0 dirty-state handling, then proceed with Path 2 (write tools)
