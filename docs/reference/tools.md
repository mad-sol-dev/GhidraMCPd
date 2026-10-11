# MCP tools

Generated from the tool docstrings by `scripts/gen_tools_md.py`; do not edit by hand.
The docstrings are what a model sees when it chooses a tool. Full parameter
descriptions are in each tool's schema, as the MCP client shows it.

35 tools.

## Orientation

### `project_info`

Identity and layout of the open program.

*Not for:* locating anything -- it describes the container, not the contents. Takes no parameters.

### `project_overview`

List the programs in the open Ghidra project.

*Not for:* anything inside a program. Takes no parameters.

### `get_current_program`

Which program is active, and whether it is ready to query.

*Not for:* switching programs (select_program) or unsaved-work checks (check_dirty_state). Takes no parameters.

### `select_program`

Open a program from the current project, making it the active one.

*Not for:* discovering what is available -- take domain_file_id from project_overview. Switching mid-session is governed by GHIDRA_BRIDGE_PROGRAM_SWITCH_POLICY.

### `goto_address`

Move the CodeBrowser cursor to an address and centre it.

*Not for:* reading anything. Use disassemble_at or read_bytes.

## Finding things

### `search_functions`

Find functions whose name matches a query.

*Not for:* finding functionality -- this matches names, and a stripped binary has none. On zero hits the response carries a method_note with the way around it.

### `search_strings`

Find defined strings whose text matches a query.

*Not for:* bytes Ghidra never defined as a string. On zero hits the response carries a method_note with the way around it.

### `strings_compact`

Page through all defined strings, without a query.

*Not for:* targeted lookups (search_strings is cheaper). Sees only strings Ghidra defined as data, so an empty page says nothing about the raw bytes.

### `string_xrefs_compact`

List the code locations referencing one string, compactly.

*Not for:* references Ghidra never recognised. An empty result means Ghidra sees none, not that nothing uses the string.

### `search_xrefs_to`

List the locations that reference an address.

*Not for:* references Ghidra never recognised, such as computed branches or hand-rolled tables. On zero hits the response carries a method_note with the way around it.

### `search_scalars`

Find instructions whose operand is a given constant.

*Not for:* constants held in a constant pool -- this reads instruction operands only. On zero hits the response carries a method_note with the way around it.

### `search_scalars_with_context`

search_scalars plus a disassembly window per hit.

*Not for:* constants held in a constant pool -- this reads instruction operands only. On zero hits the response carries a method_note with the way around it.

### `search_imports`

Find imported symbols whose name matches a query.

*Not for:* statically linked firmware, which has essentially none -- the reference image has one. An empty result there is expected.

### `search_exports`

Find exported symbols whose name matches a query.

*Not for:* discovering internal functions -- most are not exported. Use search_functions or list_functions_in_range.

### `list_functions_in_range`

List the functions defined within an address range, in address order.

*Not for:* searching by name or behaviour. Narrow the range rather than paging: the response grows with the number of functions, not with their size.

## Reading code and memory

### `analyze_function_complete`

One dossier for one function: xrefs, referenced strings, derived features and, on request, the disassembly and decompilation.

*Not for:* finding a function -- you must know its address.

### `disassemble_at`

Disassemble a run of instructions at an address.

*Not for:* locating anything, or several places at once (disassemble_batch). When you only want matching lines, find_in_function filters server-side and returns a fraction of this.

### `disassemble_batch`

Disassemble several addresses in one call, optionally filtered.

*Not for:* locating the addresses -- you bring those. Without a query it returns every instruction for every address, so 20 addresses at the default count is 320 lines.

### `find_in_function`

Search a function's disassembly or decompilation for a pattern.

### `read_bytes`

Read raw bytes from memory, returned as base64.

*Not for:* searching -- there is no byte-search on this server. For 32-bit words use read_words, which decodes them.

### `read_words`

Read consecutive 32-bit words and return them as integers.

*Not for:* searching -- you must know the address.

### `mmio_annotate_compact`

Summarise a function's memory-mapped I/O accesses, optionally commenting them.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

### `collect`

Run several read-only queries in one call, optionally across projects.

## Jump tables

### `jt_slot_check`

Read one jump-table slot and judge whether it holds a code pointer.

*Not for:* finding the table -- a wrong jt_base yields confident nonsense, since every slot resolves to something. Check with jt_scan first.

### `jt_scan`

Check a run of jump-table slots in one call.

### `jt_slot_process`

Check one jump-table slot and name the function it points at.

*Not for:* bulk work -- one slot per call, and the write limit applies (GHIDRA_MCP_MAX_WRITES_PER_REQUEST, 2). A wrong jt_base renames real functions after table entries that do not exist; run jt_scan first. Needs GHIDRA_MCP_ENABLE_WRITES=true.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

## Writing (dry run by default)

### `rename_function`

Rename the function at an address.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

### `set_comment`

Add or replace a comment at an address.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

### `apply_label`

Put a label at any address, including MMIO registers outside every memory block.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

### `datatypes_create`

Create a structure or union in the data type manager.

*Not for:* applying the type to an address -- this only defines it. Not for editing an existing one (datatypes_update); a duplicate name is an error. Needs GHIDRA_MCP_ENABLE_WRITES=true.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

### `datatypes_update`

Replace the fields of an existing structure or union.

*Not for:* partial edits -- the list replaces the existing one wholesale, so fields you leave out are gone. Read the current definition first; every place the type is applied follows the new layout. Needs GHIDRA_MCP_ENABLE_WRITES=true.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

### `datatypes_delete`

Delete a structure or union from the data type manager.

*Not for:* use while the type is applied -- every location using it reverts to undefined data, with no undo through this API. Needs GHIDRA_MCP_ENABLE_WRITES=true.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.

## Unsaved work

### `list_mutations`

Everything this session changed since the last save_program.

*Not for:* history. The list resets on a successful save_program, since everything before that is in the file. It also lives in this server process, so a restart loses it -- save first.

### `check_dirty_state`

Report whether the active program has unsaved changes.

*Not for:* finding out *what* changed -- it answers whether, not which.

### `save_program`

Persist unsaved changes to the active program.

*Not for:* exporting anything -- this writes into the Ghidra project, not to a file you can version.

Writes only with `GHIDRA_MCP_ENABLE_WRITES=true` and `dry_run=false`.
