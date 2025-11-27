# GhidraMCPd Roadmap

> **Mission**: Token-efficient MCP server bridging Ghidra reverse engineering with AI assistants through deterministic APIs, batch operations, and server-side context assembly.

## Overview

GhidraMCPd is a production-quality bridge between Ghidra and LLM-based tools via the Model Context Protocol (MCP). The architecture prioritizes:

1. **Token efficiency** — Batch operations, server-side context assembly, and result budgeting
2. **Deterministic APIs** — Stable pagination, strict schemas, reproducible results
3. **Observability** — State tracking, duration metrics, context-aware error messages
4. **Safety** — Read-only defaults, write guards, audit logging

## Current Status (v1.3.0)

### Production Features
- ✅ Single-port multi-context server (Java singleton, FrontEnd loading)
- ✅ Program selection & state tracking (IDLE/LOADING/READY with duration metrics)
- ✅ Composite operations (`collect`, `analyze_function_complete`)
- ✅ Search ranking, pagination, cursor streaming
- ✅ Write operations with dry-run mode & environment gates
- ✅ Timestamp logging for debugging timing issues
- ✅ Staleness detection (5-min timeout for stuck LOADING state)
- ✅ Context-aware error messages with recovery suggestions

### Architecture
```
AI Client ↔ Bridge (Python/FastMCP) ↔ Ghidra Plugin (Java/HTTP) ↔ Ghidra API
            ├─ SSE transport (web)
            └─ stdio transport (CLI)
```

## Roadmap Phases

### Phase 1: Observability & Reliability (CURRENT)
**Goal**: Production-ready diagnostics and error handling

- [x] **DIAG.1** — State duration tracking & staleness detection
- [x] **DIAG.2** — Timestamp logging (bridge + uvicorn)
- [ ] **DIAG.3** — Force-refresh endpoint for manual state checks
- [ ] **DIAG.4** — Analysis completion metadata in search results
- [ ] **R.22** — Data type lookup cache (per-DataTypeManager map)
- [ ] **R.23** — Enhanced readiness semantics (state endpoint + bridge polling)
- [ ] **BUILD.1** — Docker cache workaround docs

**Success Criteria**: Zero stuck states, <500ms diagnostic overhead, clear recovery paths

### Phase 2: Write Operations & Safety
**Goal**: Safe, auditable mutations with LLM-friendly workflows

- [ ] **R.25** — Default read-only mode with `/info` reflecting enablement
- [ ] **R.26** — Write endpoint validation against active program
- [ ] **R.27** — LLM-visible comment tagging for write operations
- [ ] **R.28** — Comprehensive audit logging with redaction

**Success Criteria**: All writes auditable, zero unintended mutations, dry-run coverage

### Phase 3: Workflow Optimization
**Goal**: Multi-binary analysis and LLM recipe library

- [ ] **R.9** — Firmware-set workflows (boot→app→res prompts)
- [ ] **R.11** — LLM recipes (string→xrefs→disasm chains)
- [ ] **R.17** — AGENTS.md guidance for ghidra-bridge usage
- [ ] **R.18** — Cookbook snippets for USB/update/MMIO workflows
- [ ] **R.19** — Cross-binary analysis (BOOT⇄APP links, diffing)

**Success Criteria**: <3 round-trips for common tasks, recipe library validated

### Phase 4: Production Hardening
**Goal**: Enterprise deployment readiness

- [ ] **R.5** — CORS/origin whitelist controls
- [ ] **R.6** — Docker images + CI packaging
- [ ] **R.7** — MCP tool UX docs (flows, screenshots, failure drills)
- [ ] **R.14** — Ghidra version-compat matrix
- [ ] **R.20** — Controlled auto-analysis automation

**Success Criteria**: Docker Hub images, multi-Ghidra-version CI matrix

## Design Principles

### 1. Token Efficiency
**Batch over round-trips**: Use `collect`, `disassemble_batch`, `read_words` for multiple operations
**Server-side context**: `search_scalars_with_context` includes disassembly to avoid follow-ups
**Result budgeting**: `max_result_tokens` with auto-trim or strict enforcement

### 2. Deterministic APIs
**Stable pagination**: `page` (1-based), `has_more`, `total`
**Cursor resumption**: For large sets, stable cursor-based streaming
**Strict schemas**: `additionalProperties: false` for LLM-friendly, diff-able responses

### 3. Observability Best Practices
**State duration tracking**: Every state transition records timestamp
**Timeout handling**: 5-min timeout for LOADING state with auto-recovery
**Context-aware errors**: Error messages include duration, suggested actions
**Timestamp logging**: All logs include ISO 8601 timestamps with milliseconds

### 4. Safety & Security
**Read-only defaults**: Write operations require explicit `GHIDRA_MCP_ENABLE_WRITES=true`
**Dry-run mode**: Test write operations before execution
**Audit logging**: All writes logged with program context and outcomes
**Validation gates**: Write endpoints validate against active program

## Good Practices

### State Management
```java
// Always track state transitions
stateTransitionTime = System.currentTimeMillis();

// Include duration in diagnostics
long durationSeconds = (System.currentTimeMillis() - stateTransitionTime) / 1000;

// Timeout long-running operations
if (elapsed > TIMEOUT_MS) {
    Msg.warn(this, "Operation timeout after " + elapsed/1000 + " seconds");
    // Force recovery
}
```

### Error Messages
```python
# Context-aware recovery suggestions
if duration_seconds > 300:  # > 5 minutes
    recovery = [
        f"Program has been in LOADING state for {duration_seconds} seconds. "
        "This may indicate a stale state.",
        "Try selecting a different program, then re-selecting the original.",
    ]
elif duration_seconds > 60:  # > 1 minute
    recovery = [
        f"Analysis may take several minutes for large binaries.",
        "Wait for auto-analysis to complete, or check Ghidra UI.",
    ]
```

### Logging
```python
# Always include timestamps
log_format = "%(asctime)s.%(msecs)03d %(levelname)s:%(name)s:%(message)s"
date_format = "%Y-%m-%d %H:%M:%S"

# Example output:
# 2025-11-27 11:19:59.757 INFO:bridge.mcp.tools: Operation completed
```

### Docker Builds
```bash
# Avoid version cache issues
docker build --no-cache -f Dockerfile.build .

# Or use version-tagged images
docker build -t ghidra-mcp:1.3.0 .
```

## Contributing

See `.plan/TODO.md` for active tasks and `.plan/DONE.md` for completed work.

**Workflow**:
1. Pick task from TODO.md
2. Implement with tests (unit, contract, golden)
3. Update `.plan/tasks.manifest.json` with status
4. Run `.plan/sync_state.sh` to sync TODO/DONE
5. Commit with task ID in message

**Standards**:
- CI green (Unit/Contract/Golden)
- OpenAPI drift-free
- Breaking defaults only via minor bump

## References

- **CLAUDE.md**: Development guide for AI assistants
- **docs/api.md**: Complete API reference
- **docs/server.md**: SSE/stdio transports, connection management
- **docs/development.md**: Test workflow, Java build
- **docs/troubleshooting.md**: Common issues and error reference
