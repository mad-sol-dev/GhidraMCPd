# JT Endpoints

## `jt_slot_check`

Validates a single pointer as ARM/Thumb (or none), enforcing `[code_min, code_max)`.

**Tip — Deriving CODE_MIN/MAX:** fetch segments from the plugin and choose the `.text`/code bounds.

## `jt_scan`

Batch over many slots; invariants:

- `summary.total == len(items)`
- `summary.valid + summary.invalid == summary.total`
