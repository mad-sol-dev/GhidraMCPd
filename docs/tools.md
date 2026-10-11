# Using the tools

Which tool answers which question, and the paths that tend to come up when working
through firmware. Every tool's own description (what the model sees) is in the
[catalogue](reference/tools.md); this page is the overview.

## Getting your bearings

`get_current_program` says which program is open and whether its analysis has finished
(`READY`); most tools refuse to run while it is `LOADING`. `project_info` gives the memory
blocks, image base and entry points -- worth one call at the start, because an address
outside every block is answered as `UNMAPPED`, not as "nothing there".

## Finding things

| You have | Use | Then |
|---|---|---|
| part of a function name | `search_functions` | `analyze_function_complete` |
| a piece of text the firmware prints | `search_strings` | `string_xrefs_compact` on the string's address gives the code using it, with the instructions around each use |
| an address | `search_xrefs_to` | who references it |
| a constant in an instruction (`mov r0,#0x1000`) | `search_scalars`, or `search_scalars_with_context` for a disassembly window per hit | |
| a constant in a constant pool (register addresses, usually) | not the scalar search -- it reads operands only | `analyze_function_complete` lists the pool words a function loads (`constants`); `read_words` reads a pool directly |
| an address range | `list_functions_in_range` | |

## Looking at code

`analyze_function_complete` is the first look at a function: name and range, callers and
callees, referenced strings, constant-pool words, derived counts -- about 2 KB. The
disassembly and decompilation are left out by default; ask for them with
`fields=["disasm"]` or `["decompile"]` when you know you want them.

For anything narrower:

- `find_in_function` searches one function's disassembly or decompilation and returns only
  the matching lines with context. Usually the cheapest way to answer "where does it load
  X".
- `disassemble_at` lists instructions from an address; `disassemble_batch` does several
  addresses at once and can filter them with a query.
- `read_words` reads 32-bit words as hex (constant pools, tables); `read_bytes` reads raw
  bytes as base64.
- `mmio_annotate_compact` summarises a function's peripheral accesses (reads, writes,
  read-modify-write) with a few sample lines instead of the listing.

`collect` runs several of these in one call under one token budget, when you already know
the next few questions.

## Keeping answers small

- Lists have small defaults (20) and say `has_more`; raise `limit` or page on when you
  need more, rather than by default.
- Listings come as text unless you ask for `fmt="json"`; text is about half the bytes.
- `analyze_function_complete` takes `max_result_tokens`: disassembly and decompilation are
  cut at whole lines until the dossier fits, and the answer says so.
- A list cut at its limit says `truncated` (references, strings, callers), so a short
  answer is not mistaken for a complete one.

## Changing the program

With writes enabled ([setup](setup.md#writes)), the usual round:

1. Call the writing tool as it is (`dry_run` defaults to true) and read what it would do.
   `rename_function` warns there if another function already has the name -- Ghidra would
   accept the duplicate.
2. Call it again with `dry_run=false`.
3. `list_mutations` shows the session's changes; nothing is saved until `save_program`,
   and Ghidra's undo works as usual.

## Jump tables

`jt_slot_check`, `jt_scan` and `jt_slot_process` read a table of code pointers, judge
each slot (ARM or Thumb, inside the code range, a function at the target) and, for
`jt_slot_process`, name the target. They expect the table's pointers to match the program's
memory map: on an image loaded at the wrong base they report every slot as out of range.
