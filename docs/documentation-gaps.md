# Documentation blind spots

The review below highlights areas where the codebase implements functionality that is not yet covered (or only minimally covered) by the existing documentation set. Each item links to the relevant implementation so the missing documentation can be added in the right place.

## Ghidra HTTP plugin surface

The Java plugin exposes a set of HTTP endpoints directly from Ghidra (e.g., `/methods`, `/classes`, `/read_bytes`, `/read_cstring`, `/renameFunction`, `/renameData`, `/renameVariable`). These routes support pagination and write actions but are not described in the docs alongside the MCP-facing APIs, leaving users without guidance on the plugin server’s semantics, limits, or safety expectations.

## Transcript aggregation helper

The `aggregate_transcripts` helper parses transcripts, extracts the first JSON object per record, validates it against a schema, and produces ok/failure summaries. There is no user-facing guidance on when to use this utility, what input shape it expects, or how to interpret the resulting summary counts.

## Ghidra call whitelist and adapter coverage

The bridge hard-codes a whitelist of permitted Ghidra bridge calls (reads, searches, write operations, and datatype mutations) plus optional architecture adapters. The public docs list environment flags to toggle adapters but do not enumerate the whitelisted call surface or explain how adapter selection affects available operations.
