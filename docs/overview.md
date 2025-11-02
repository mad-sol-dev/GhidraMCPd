# Overview

The bridge provides a deterministic, LLM-friendly API over the Ghidra plugin:

- **Strict envelopes**: every response is `{ ok, data|null, errors[] }`.
- **Schemas & tests**: contract + golden tests guard drift.
- **Batching & pagination**: search endpoints return full totals and 1-based `page`.
- **Safety**: write paths disabled by default; `dry_run` supported.

Use this when you need reliable, paginated, and schema-validated access to program analysis data.
