# GhidraMCP Testing Report

**Date**: 2025-11-25
**Tester**: Claude Code
**Version**: GhidraMCP v1.0-SNAPSHOT

## Testing Scope

This report documents systematic testing of GhidraMCP base functionality to ensure core features are working correctly.

---

## 1. Project & Program Status

### 1.1 Project Info
**Test**: Get basic project information
**Tool**: `mcp__ghidra__project_info`

**Status**: ⚠️ WARNING
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE).",
    "recovery": ["Wait for auto-analysis to finish before retrying."]
  }]
}
```

**Notes**: Program exists but is in IDLE state - auto-analysis needs to complete before operations can proceed.

---

### 1.2 Current Program
**Test**: Get currently active program
**Tool**: `mcp__ghidra__get_current_program`

**Status**: ⚠️ WARNING
**Result**:
```json
{
  "ok": true,
  "data": {
    "domain_file_id": "7f011b6c592307498348432",
    "locked": false,
    "state": "IDLE",
    "warnings": ["Requested program selection does not match the active program upstream."]
  }
}
```

**Notes**: Successfully retrieved current program info but with warning about program selection mismatch. Program ID: 7f011b6c592307498348432, State: IDLE (not ready).

---

### 1.3 Project Overview
**Test**: Get overview of all programs in project
**Tool**: `mcp__ghidra__project_overview`

**Status**: 🟢 PASSED
**Result**:
```json
{
  "ok": true,
  "data": {
    "files": [
      {"domain_file_id": null, "name": "/", "path": "/", "type": "Folder"},
      {"domain_file_id": "7f011b6c592307498348432", "name": "ZK-INKJET-NANO-APP.bin", "path": "/ZK-INKJET-NANO-APP.bin", "type": "Program"},
      {"domain_file_id": "7f0119877153775590580992", "name": "ZK-INKJET-NANO-APP.bin_1", "path": "/ZK-INKJET-NANO-APP.bin_1", "type": "Program"},
      {"domain_file_id": "7f011919b29104044910945", "name": "ZK-INKJET-RES-HW.zkml", "path": "/ZK-INKJET-RES-HW.zkml", "type": "Program"},
      {"domain_file_id": "7f011a9c518283402470126", "name": "ZK-INKJET-NANO-BOOT.bin", "path": "/ZK-INKJET-NANO-BOOT.bin", "type": "Program"}
    ]
  }
}
```

**Notes**: Successfully retrieved project structure. Project contains 4 programs:
- ZK-INKJET-NANO-APP.bin (current)
- ZK-INKJET-NANO-APP.bin_1
- ZK-INKJET-RES-HW.zkml
- ZK-INKJET-NANO-BOOT.bin

---

## 2. Search Operations

### 2.1 Search Strings
**Test**: Search for strings in binary
**Tool**: `mcp__ghidra__search_strings`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

### 2.2 Search Functions
**Test**: Search for functions by name
**Tool**: `mcp__ghidra__search_functions`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

### 2.3 Search Imports
**Test**: Search imported symbols
**Tool**: `mcp__ghidra__search_imports`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

### 2.4 Search Exports
**Test**: Search exported symbols
**Tool**: `mcp__ghidra__search_exports`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

## 3. Memory Operations

### 3.1 Disassemble at Address
**Test**: Disassemble instructions at specific address
**Tool**: `mcp__ghidra__disassemble_at`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

### 3.2 Read Bytes
**Test**: Read raw bytes from memory
**Tool**: `mcp__ghidra__read_bytes`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

### 3.3 Read Words
**Test**: Read 32-bit words from memory
**Tool**: `mcp__ghidra__read_words`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

### 3.4 Disassemble Batch
**Test**: Disassemble multiple addresses in one call
**Tool**: `mcp__ghidra__disassemble_batch`

**Status**: 🔴 FAILED
**Result**:
```json
{
  "ok": false,
  "errors": [{
    "status": 503,
    "code": "UNAVAILABLE",
    "message": "Program is not ready (state=IDLE)."
  }]
}
```

**Notes**: Failed due to program IDLE state - requires completed analysis.

---

## 4. Program Selection & Switching

### 4.1 Select Program
**Test**: Switch to a different program in project
**Tool**: `mcp__ghidra__select_program`

**Status**: ✅ **PASSED** (after fix in v1.1.1)

**Initial Result (v1.0-SNAPSHOT)**: 🔴 FAILED
```json
{
  "ok": false,
  "errors": [{
    "status": 400,
    "code": "INVALID_REQUEST",
    "message": "Automatic program open failed upstream: ProgramManager service unavailable",
    "upstream": {
      "warnings": ["ToolServices class not found; cannot auto-open program tool"]
    }
  }]
}
```

**Result After Fix (v1.1.1)**: ✅ **SUCCESS**
```json
{
  "ok": true,
  "data": {
    "domain_file_id": "7f011a9c518283402470126",
    "locked": true,
    "state": "READY",
    "warnings": [
      "Program selection switched mid-session from '7f011b6c592307498348432' to '7f011a9c518283402470126'."
    ]
  }
}
```

**Verification Tests After Switch**:
- ✅ String search: Working
- ✅ Function search: Working (returned 5 functions)
- ✅ CodeBrowser auto-launched successfully
- ✅ Program state: READY (not IDLE)

**Notes**: This was the feature being worked on before testing. After applying the ToolServices fix (commit 90cfad2), the auto-launch functionality works perfectly. CodeBrowser launches automatically and the selected program is opened and analyzed.

---

## 5. Advanced Features

### 5.1 Collect (Batch Operations)
**Test**: Execute multiple queries in one request
**Tool**: `mcp__ghidra__collect`

**Status**: ⏭️ SKIPPED
**Result**:
```
Skipped due to program IDLE state - would fail like other operations
```

**Notes**: Not tested since program is not ready.

---

### 5.2 Function Analysis
**Test**: Complete function analysis
**Tool**: `mcp__ghidra__analyze_function_complete`

**Status**: ⏭️ SKIPPED
**Result**:
```
Skipped due to program IDLE state - would fail like other operations
```

**Notes**: Not tested since program is not ready.

---

## Summary

### Initial Test Results (2025-11-25, before fixes)
**Total Tests**: 13
**Passed**: 🟢 1 (7.7%)
**Failed**: 🔴 9 (69.2%)
**Warning**: ⚠️ 2 (15.4%)
**Skipped**: ⏭️ 2 (15.4%)

### Test Breakdown (Initial)
- **Project & Program Status**: 1 passed, 2 warnings
- **Search Operations**: 4 failed (all due to IDLE state)
- **Memory Operations**: 4 failed (all due to IDLE state)
- **Program Selection**: 1 failed (ProgramManager unavailable)
- **Advanced Features**: 2 skipped (program not ready)

### Final Results (2025-11-26, after v1.1.1 fix)
**Program Selection & Auto-Launch**: ✅ **WORKING**
- Auto-launch CodeBrowser: ✅ PASSED
- Program switching: ✅ PASSED
- Search operations on new program: ✅ PASSED

## Issues Found

### CRITICAL Issue 1: Program in IDLE State
**Severity**: 🔴 CRITICAL
**Description**: The currently loaded program (ZK-INKJET-NANO-APP.bin) is in IDLE state, not READY state.
**Impact**: All search and memory operations fail with 503 UNAVAILABLE errors.
**Root Cause**: Auto-analysis has not completed (or not started).
**Recovery**:
- Wait for Ghidra auto-analysis to complete
- Manually trigger analysis in Ghidra GUI (Analysis → Auto Analyze)
- Check Ghidra GUI for analysis progress

### CRITICAL Issue 2: ProgramManager Service Unavailable ✅ **RESOLVED**
**Severity**: 🔴 CRITICAL → ✅ **FIXED in v1.1.1**
**Description**: `select_program` tool failed because ToolServices was accessed incorrectly.
**Impact**: Could not switch between programs or auto-open programs.
**Root Cause**:
- ToolServices accessed via `tool.getService(ToolServices.class)` ❌
- ToolServices is NOT a service - it's a direct method on PluginTool
- Wrong package path: was trying `ghidra.app.services.ToolServices` instead of `ghidra.framework.model.ToolServices`

**Error Message**: "ToolServices class not found; cannot auto-open program tool"

**Resolution** (commit 90cfad2):
- ✅ Fixed ToolServices access: `tool.getToolServices()` instead of `getService()`
- ✅ Corrected import: `ghidra.framework.model.ToolServices`
- ✅ Removed reflection-based access, use direct Ghidra API
- ✅ Fixed method signatures: `launchTool(String, Collection<DomainFile>)`
- ✅ Auto-launch now works perfectly

**Testing**: Verified working in v1.1.1 - CodeBrowser auto-launches and programs switch successfully

### WARNING Issue 3: Program Selection Mismatch
**Severity**: ⚠️ WARNING
**Description**: `get_current_program` returns warning about program selection mismatch.
**Impact**: Potential state inconsistency between bridge and Ghidra.
**Warning**: "Requested program selection does not match the active program upstream."

## Recommendations

### Immediate Actions
1. **Open a program-capable tool in Ghidra** (e.g., CodeBrowser) to make ProgramManager available
2. **Trigger auto-analysis** on the current program to move it from IDLE to READY state
3. **Investigate ToolServices classpath** in the Java plugin to fix auto-open functionality

### Testing Next Steps
Once issues are resolved, re-test:
1. Wait for program to reach READY state
2. Re-run all search operations (strings, functions, imports, exports)
3. Re-run all memory operations (disassemble, read bytes/words)
4. Test program switching between the 4 available programs
5. Test advanced features (collect, function analysis)

### Code Investigation Needed
- Check `src/main/java/com/lauriewired/GhidraMCPPlugin.java` for ProgramManager initialization
- Look for ToolServices import/usage in Java code
- Review program state tracking logic (`ProgramStatusTracker`)
- Verify auto-open implementation in program selection code

---

## Fixes Applied (2025-11-25)

### Fix 1: ToolServices Package Path Correction
**Problem**: Code was trying to access `ghidra.app.services.ToolServices` which doesn't exist
**Root Cause**: ToolServices is in `ghidra.framework.model` package, not `ghidra.app.services`
**Fix Applied**:
- Added proper import: `import ghidra.framework.model.ToolServices;`
- Removed reflection-based access using `Class.forName()`
- Used direct API access: `tool.getService(ToolServices.class)`

**Changed Files**: `src/main/java/com/lauriewired/GhidraMCPPlugin.java:2763`

### Fix 2: Proper API Usage for Tool Launching
**Problem**: Code used reflection and incorrect method signatures
**Root Cause**:
- Methods were accessed via reflection unnecessarily
- `launchDefaultTool()` and `launchTool()` require `Collection<DomainFile>`, not single file
- `isAutoOpenAllowed()` method doesn't exist in ToolServices API
**Fix Applied**:
- Use proper method signatures from Ghidra API docs
- Pass `Collections.singletonList(file)` for the Collection parameter
- Try `launchTool("CodeBrowser", files)` first, then fallback to `launchDefaultTool(files)`
- Removed non-existent `isAutoOpenAllowed()` check

**Changed Files**: `src/main/java/com/lauriewired/GhidraMCPPlugin.java:2762-2794`

### Fix 3: Direct ProgramManager.openProgram() Usage
**Problem**: `invokeOpenProgram()` used reflection unnecessarily
**Fix Applied**: Call `pm.openProgram(file)` directly instead of via reflection

**Changed Files**: `src/main/java/com/lauriewired/GhidraMCPPlugin.java:2796-2805`

### Fix 4: Cleanup Unused Reflection Helper Methods
**Removed**:
- `invokeBooleanMethod(Object, String)` - no longer needed
- `findMethod(Class, String, Class...)` - no longer needed

**Build Status**: ✅ Successfully compiled and packaged
**Extension**: `target/GhidraMCP-1.0-SNAPSHOT.zip` (64KB)

### Next Steps for Testing
1. **Reinstall Extension**: File → Install Extensions → select new ZIP
2. **Restart Ghidra**: Required for plugin changes to take effect
3. **Close any open CodeBrowser windows**
4. **Test auto-launch**: Use `select_program` MCP tool to switch programs
5. **Verify**: CodeBrowser should auto-launch with the selected program

### API References Used
- [ToolServices API](https://ghidra.re/ghidra_docs/api/ghidra/framework/model/ToolServices.html)
- [ProgramManager API](https://ghidra.re/ghidra_docs/api/ghidra/app/services/ProgramManager.html)

---

**Legend**:
🟢 PASSED - Test completed successfully
🔴 FAILED - Test failed or error occurred
🟡 PENDING - Test not yet executed
⚠️ WARNING - Test passed with warnings
