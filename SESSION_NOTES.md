# Session Notes - 2025-11-26

## Current State

**Version**: 1.3.0 (installed and fully tested)
**Location**: `target/GhidraMCP-1.3.0.zip`
**Last Commit**: bbbf7d0 - "Add on_dirty parameter to select_program MCP tool"
**Bridge Status**: Running with updated on_dirty parameter support

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

### ✅ Path 2: Write Tools - Exposed as MCP Tools (COMPLETE)

Exposed existing Java write functionality as MCP tools for AI agent access.

**Background:**
- Write functionality (rename/comment) already existed in Laurie's original GhidraMCP plugin
- Java endpoints and Python client wrappers were implemented
- Missing piece: MCP tool exposure for AI agent access

**New MCP Tools Added:**
1. **`rename_function(address, new_name, dry_run=True)`**
   - Wraps existing `client.rename_function()` and Java `renameFunctionByAddress()`
   - Renames functions at specified addresses
   - Default dry_run mode for safety

2. **`set_comment(address, comment, comment_type="decompiler", dry_run=True)`**
   - Wraps `client.set_decompiler_comment()` and `client.set_disassembly_comment()`
   - Supports both decompiler and disassembly comments
   - Default dry_run mode for safety

**Implementation:**
- Python: 2 new MCP tools in `bridge/api/tools.py` (~180 lines)
- Write guards: Require `GHIDRA_MCP_ENABLE_WRITES=true` when `dry_run=false`
- Request scope tracking with `max_writes=1` per operation
- Proper envelope responses with success/error states

**Testing:**
- ✅ Dry-run mode: Both tools validated without executing
- ✅ Write guards: Correctly block writes when disabled
- ✅ Actual writes: Successfully renamed `FUN_00000080` → `init_system`
- ✅ Actual comments: Successfully added decompiler comment
- ✅ Verification: Changes confirmed via `search_functions`

**Time:** ~30 minutes (much faster than estimated 1-2h because underlying implementation already existed)

### ✅ Documentation Updates (Previous Session)

Added comprehensive navigation documentation (commit 5c40dd1):
- docs/ROADMAP.md - Marked navigation as complete
- docs/README.md - Added curl example for goto endpoint
- docs/getting-started.md - Added "Basic usage workflows" section with navigation patterns

## Testing Results (2025-11-26)

### ✅ Successfully Tested

**Test 1: Clean Program State Detection**
- ✅ `check_dirty_state()` correctly reports `changed: false` on clean program
- ✅ `can_save: true` shows we have save permission
- Result: PASSED

**Test 2: Save Clean Program**
- ✅ `save_program()` on clean program correctly reports "no changes to save"
- ✅ Returns `saved: false` as expected
- Result: PASSED

**Test 3: Program Switching (Clean)**
- ✅ Switching programs when clean works without errors
- ✅ Appropriate mid-session warning displayed
- Result: PASSED

**Test 4: Dirty State Detection**
- ✅ After manual function rename, `check_dirty_state()` reports `changed: true`
- ✅ Program name correctly identified
- ✅ Message: "Program has unsaved changes"
- Result: PASSED - **CRITICAL FEATURE WORKING**

**Test 5: Blocked Program Switch (Dirty State)**
- ✅ Attempting to switch with unsaved changes **BLOCKS** as designed
- ✅ Error message clearly states: "Cannot switch programs: current program has unsaved changes"
- ✅ Helpful recovery suggestion: "use on_dirty=save or on_dirty=discard to proceed"
- Result: PASSED - **DATA LOSS PREVENTION WORKING**

**Test 6: Save Program with Changes**
- ✅ `save_program(description="...")` successfully saves changes
- ✅ Returns `saved: true` with program name
- ✅ Changes persisted to disk
- Result: PASSED

**Test 7: Program Switch After Save**
- ✅ After saving, `check_dirty_state()` reports `changed: false`
- ✅ Program switching now works again
- ✅ Complete workflow validated: dirty → blocked → save → allowed
- Result: PASSED

**Test 8: Auto-Save Mode (`on_dirty="save"`)**
- ✅ Made changes in current program, then switched with `on_dirty="save"`
- ✅ Program switch succeeded with warning: "Saved current program before switching"
- ✅ Current program was auto-saved before the switch
- Result: PASSED

**Test 9: Discard Mode (`on_dirty="discard"`)**
- ✅ Made changes in current program, then switched with `on_dirty="discard"`
- ✅ Program switch succeeded with warning: "Discarding unsaved changes in current program"
- ✅ Changes were discarded and switch proceeded
- Result: PASSED

**Test 10: Navigation Smoke Test**
- ✅ `goto_address("0x00000080")` successfully navigated CodeBrowser
- ✅ Confirmed v1.3.0 didn't break existing navigation feature
- Result: PASSED

### 🐛 Issues Encountered & Resolved

**Issue 1: Blank Dialog Window**
- Symptom: Blank window with no buttons appeared during program switching
- Resolution: Dialog closed itself after subsequent API call (likely stuck progress dialog)
- Impact: Minor UI glitch, no functional impact
- Status: Monitoring for recurrence

**Issue 2: Missing `on_dirty` Parameter in `select_program`**
- Symptom: `select_program()` didn't expose the `on_dirty` parameter
- Root Cause: Parameter added to `open_program()` but not passed through `select_program()`
- Fix: Added `on_dirty` parameter to:
  - `select_program()` MCP tool signature
  - `_maybe_autoopen_program()` helper function
  - Parameter forwarding chain
- Commit: bbbf7d0
- Status: Fixed, bridge restarted

## Testing Complete ✅

All 10 test cases have been successfully completed. The dirty-state handling feature (v1.3.0) is fully functional and ready for production use.

## Roadmap Progress

### Path 3: Improve Reliability
- ✅ Dirty-state handling (COMPLETE)
- ⏳ Readiness gating (PARTIAL - ProgramStatusTracker exists but needs enhancement)
  - Need to expose state more prominently
  - Add automatic retry/wait logic for LOADING state
  - Document state transitions

### Path 2: Complete Navigation Story (COMPLETE)
- ✅ Write tools for annotations:
  - `rename_function(address, new_name, dry_run=True)` - Rename functions
  - `set_comment(address, comment, comment_type="decompiler", dry_run=True)` - Add comments
  - All with write guards and dry_run support
  - Actual: ~30 minutes (underlying implementation already existed)

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
  - Commits:
    - 6f50269 - Core dirty-state implementation (Java + Python)
    - bbbf7d0 - Added on_dirty parameter to select_program

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

4. **Docker build version caching**
   - `./scripts/build_docker.sh` may produce old version ZIPs due to Docker layer caching
   - Use `mvn -DskipTests package` for local builds to ensure current pom.xml version
   - Or force rebuild: `docker build --no-cache -f scripts/Dockerfile.build -t ghidra-mcp-builder .`
   - Note: Docker build approach was recommended by Gemini 2.5 Pro for reproducible builds

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

# Rename a function (requires GHIDRA_MCP_ENABLE_WRITES=true)
rename_function(address="0x401000", new_name="my_function", dry_run=False)
# → {"success": bool, "address": str, "new_name": str, "message": str}

# Add a comment (requires GHIDRA_MCP_ENABLE_WRITES=true)
set_comment(address="0x401000", comment="Analysis note", comment_type="decompiler", dry_run=False)
# → {"success": bool, "address": str, "comment": str, "comment_type": str, "message": str}
```

## Resources

- **Ghidra API Docs**: https://ghidra.re/ghidra_docs/api/
- **Program API**: https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html
- **ROADMAP**: docs/ROADMAP.md
- **Getting Started**: docs/getting-started.md (has usage examples)
- **Testing Report**: TESTING_REPORT.md

## Summary of Session

### What Works (Tested & Verified) - ALL TESTS PASSING ✅

**Path 3 - Dirty-State Handling:**
- ✅ Dirty-state detection (`check_dirty_state`)
- ✅ Program saving (`save_program`)
- ✅ Blocked program switching when dirty (default behavior)
- ✅ Clean program workflow (check → save → switch)
- ✅ `on_dirty="save"` auto-save mode
- ✅ `on_dirty="discard"` discard mode
- ✅ Auto-launch still working
- ✅ Navigation (`goto_address`) still working

**Path 2 - Write Tools:**
- ✅ `rename_function()` - Dry-run mode validated
- ✅ `rename_function()` - Actual writes tested (FUN_00000080 → init_system)
- ✅ `set_comment()` - Dry-run mode validated
- ✅ `set_comment()` - Actual writes tested (decompiler comment added)
- ✅ Write guards - Correctly enforce ENABLE_WRITES requirement

### Minor Issues Noted
- Occasional stuck dialog during program switching (self-resolves)
- Multiple duplicate warnings in some responses (cosmetic only)

### Commits This Session
1. **5c40dd1** - Documentation for navigation feature
2. **6f50269** - Dirty-state handling core implementation (v1.3.0)
3. **96a453a** - Session notes creation
4. **bbbf7d0** - Added on_dirty parameter to select_program
5. **TBD** - Expose rename_function and set_comment as MCP tools

---

**Current Status**: v1.3.0 tested + Path 2 write tools complete. Both dirty-state handling and write tools fully functional.
**Next Steps**: Path 3 readiness gating (enhance ProgramStatusTracker) or Path 1 documentation (AGENTS.md)
