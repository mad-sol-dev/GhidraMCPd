# Design

What the bridge promises about its answers, what it costs, and -- at the end -- how it got
this way.

## Answers

### One envelope

Every tool and every bridge HTTP route answers `{"ok": bool, "data": ..., "errors": [...]}`.
`data` follows a JSON schema per tool (`bridge/api/schemas/`) with
`additionalProperties: false`, so a field either is documented or is not there. An error
carries a code (`INVALID_REQUEST`, `NOT_READY`, `RESULT_TOO_LARGE`, `UNAVAILABLE`, ...),
a message, recovery hints, and the plugin's own code under `upstream` when the plugin
refused.

### Failure is not absence

The rule most of the rework was about. "No function at this address" and "the plugin
failed to look" are different answers: the first is `NOT_FOUND`/`UNMAPPED` from the
plugin and comes back as an empty or `null` result; every other failure becomes an error
envelope. A failed search is never reported as zero hits, a failed write never as success.

### Cut answers say so

A list stopped at its limit carries `has_more` or `truncated`; the bridge asks the plugin
for one more item than it shows, so a list of exactly 20 is not mistaken for a cut one. A
disassembly that starts later than the requested address (undefined bytes in between)
carries `coverage` and a note. Searches that fetch everything at once refuse a list the
plugin cut instead of counting it as complete.

### The plugin convention (API 3)

Between bridge and plugin: every failure is an HTTP 4xx/5xx with one JSON body, flags are
JSON booleans, every response carries `X-GhidraMCP-API: 3`. The bridge accepts exactly
that level; a plugin of any other level is refused by name (`PLUGIN_TOO_OLD`,
`PLUGIN_TOO_NEW`), because under another level the same answer can mean something else --
`"false"` against `false`. Details: [plugin HTTP API](reference/plugin-api.md).

## Costs

### Budgets

- Lists default to 20 items, listings to text; batches are capped by
  `GHIDRA_MCP_MAX_ITEMS_PER_BATCH` (256).
- `analyze_function_complete` leaves disassembly and decompilation out unless asked, and
  takes `max_result_tokens`: both are cut at whole lines, by the same fraction, until the
  dossier fits, or the call fails with `RESULT_TOO_LARGE`.
- `collect` takes one budget for all its queries (`auto_trim` or `strict`).

### Measured

The reference run (`scripts/reference_run.py`) replays 40 fixed read-only tool calls
against a frozen copy of one firmware project and records the response size of each. The
copy's fingerprint (binary hash, function count, user-named functions) is checked first,
so two runs compare the same database.

| | Responses, 40 calls | Schema base |
|---|--:|--:|
| Before the rework (2026-08-20) | 184 441 bytes | 5 406 tokens |
| Now (2026-10-11, plugin 1.3.66) | 60 193 bytes | 8 493 tokens |

(Responses: bytes of the tool results as the client receives them. Schema base: the tool
descriptions and parameter schemas every session pays once before the first call,
estimated by `scripts/measure_schema_cost.py` as characters over four.)

The schema base went up on purpose: before, 16 of 35 tools had no description at all;
now every tool says what it is not for, and every parameter its range. At 40 calls that is
about a third of a session's tokens, at 200 calls a tenth.

## Writes

Two independent switches: `dry_run` per call (default true) and `GHIDRA_MCP_ENABLE_WRITES`
per bridge (default false); a write needs both. A tool call may make at most
`GHIDRA_MCP_MAX_WRITES_PER_REQUEST` writes (2). Each write names the program the session
selected; the plugin refuses it if another program is active by the time it arrives.
`list_mutations` keeps the session's changes, including dry runs, until `save_program`.

`run_script` is the one write whose effect the bridge cannot describe in advance, so its
dry run is real: the plugin runs the script inside an outer transaction and ends it
without commit, which discards the script's own commits too (Ghidra nests transactions).
Only scripts below `GHIDRA_MCP_SCRIPT_DIR` run, never submitted code.

## How it got here

As I understood it from my conversations with the maintainer (@mad-sol-dev), the fork
exists for reverse engineering printer firmware, where a session runs to hundreds of calls
and the cost of each answer adds up. The first stages of the rework (from August 2026) were
about that: defaults, text listings, batch filters, dossiers that leave out what is rarely
needed.

What took longer was a finding that kept coming back in different places: answers that
looked fine and were not. A failed search returned an empty list; a plugin error came back
in an HTTP 200 as prose and was read as a result; a write that failed was reported as
done; a parameter (`max_result_tokens`) was documented as a ceiling and only copied into
the answer. Several of these survived because the test stubs answered in shapes the plugin
never sends. The fixes were structural rather than one at a time: an error convention with
real statuses in the plugin (API 2, then 3), one place in the bridge that applies it, the
rule above that a failure never becomes an empty result, and stubs held to the plugin's
real answers.

The working log, in German and with every stage's numbers, is in
[notes/ghidramcpd-rework.md](notes/ghidramcpd-rework.md).
