# Diagnose Report – Bridge Function Search & Health Probe

## Findings

1. **Plaintext function search blocked by whitelist**  
   *Location:* `bridge/ghidra/whitelist.py` (lines 29–47).  
   The whitelist only allows the legacy `searchFunctions` alias. Calls to the
   plaintext `/functions` endpoint are rejected before reaching the plugin,
   leaving `/api/search_functions.json` with empty results.

2. **Function parser drops valid results**  
   *Location:* `bridge/features/functions.py` (lines 8–64).  
   Parsing relied on naive string splits (`" @ "`/`" at "`) and leaked mixed-case
   addresses. Legitimate responses such as `"Reset at 0000ABCD"` were ignored or
   emitted without a `0x` prefix, violating the schema requirement.

3. **Health probe hits non-existent root**  
   *Location:* `bridge/api/routes/health_routes.py` (lines 34–78).  
   The bridge probes `GET /` on the plugin, which returns 404, so `reachable`
  flips to `false` even when the plugin is healthy. Switching to
   `GET /projectInfo` avoids the false negative.

## Evaluation

The above issues explain the observed regressions:

- The whitelist mismatch blocks the new plaintext search strategy entirely.
- The fragile parser prevents schema-compliant addresses from propagating to
  clients, breaking contract tests.
- The health probe’s 404 response masks the plugin’s availability, producing a
  spurious failure signal in monitoring dashboards.

Addressing these hotspots restores functional parity between the bridge and the
plugin while keeping the external API unchanged.
