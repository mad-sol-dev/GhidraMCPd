# Ghidra script: import MMIO register labels from a register JSON.
#
# Why this exists as a script
# ---------------------------
# It was the only way to label an MMIO register: the plugin's one createLabel()
# call sat inside renameDataAtAddress(), behind `getDefinedDataAt(addr) != null`,
# which an unmapped register never passes, and /renameData answered "Rename data
# attempted" either way.  Since R.12 the apply_label tool (plugin 1.3.57+) does
# this for single addresses and is the normal way; the script remains a bulk
# import from the register JSON.
#
# A rerun no longer duplicates.  Until 2026-10-10 make_unique_name() appended
# _<ADDR> whenever the same name was already at the same address, so a second
# run doubled every label: all 96 registers in the ZK-Inkjet app database carry
# NAME and NAME_B100xxxx (zk-inkjet TRUTH.csv, CL-TOOL-REC-122).  Ghidra allows
# one name at several addresses, so no suffix is ever needed; a name already at
# its address is simply skipped.
#
# Input: a JSON file of the form
#   {"entries": [{"address": "0xB1006000", "register_name": "FMI_CTL"}, ...]}
#
#@author
#@category ZK-Inkjet
#@keybinding
#@menupath
#@toolbar

import json
from ghidra.program.model.symbol import SourceType


def load_entries(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)
    return data.get("entries", [])


def in_target_range(addr):
    return 0xB1006000 <= addr <= 0xB1006FFF


def already_labelled(symtab, addr, name):
    return symtab.getSymbol(name, addr, None) is not None


def run():
    json_file = askFile("Select n32903_registers.json", "Open")
    entries = load_entries(json_file.getAbsolutePath())

    try:
        program = getCurrentProgram()
    except Exception:
        program = currentProgram() if callable(currentProgram) else currentProgram

    symtab = program.getSymbolTable()
    created = 0
    present = 0
    skipped = 0

    for ent in entries:
        addr_str = ent.get("address")
        reg_name = ent.get("register_name")
        if not addr_str or not reg_name:
            skipped += 1
            continue
        try:
            addr_val = int(addr_str, 16)
        except Exception:
            skipped += 1
            continue
        if not in_target_range(addr_val):
            continue

        addr = toAddr(addr_val)
        if already_labelled(symtab, addr, reg_name):
            present += 1
            continue
        try:
            symtab.createLabel(addr, reg_name, SourceType.USER_DEFINED)
            created += 1
        except Exception:
            skipped += 1

    print("Import complete: created=%d already_present=%d skipped=%d" % (created, present, skipped))


run()
