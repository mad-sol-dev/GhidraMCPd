# Ghidra script: import MMIO register labels from a register JSON.
#
# Why this exists as a script rather than an MCP tool
# ---------------------------------------------------
# The bridge has no way to place a label at an arbitrary address.  The Ghidra
# plugin's only createLabel() call sits inside renameDataAtAddress(), behind
# `listing.getDefinedDataAt(addr) != null` -- so it does nothing at an address
# with no defined data, which is exactly what an unmapped MMIO register is.  The
# /renameData endpoint that reaches it returns "Rename data attempted" without
# checking, so the failure is silent, and the bridge does not expose it at all.
#
# See .plan task R.12 (apply_label).  Once that exists, this script becomes a
# convenience rather than the only way.
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


def make_unique_name(symtab, addr, addr_val, name):
    if symtab.getSymbol(name, addr, None) is None:
        return name
    return "%s_%08X" % (name, addr_val)


def run():
    json_file = askFile("Select n32903_registers.json", "Open")
    entries = load_entries(json_file.getAbsolutePath())

    try:
        program = getCurrentProgram()
    except Exception:
        program = currentProgram() if callable(currentProgram) else currentProgram

    symtab = program.getSymbolTable()
    created = 0
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
        name = make_unique_name(symtab, addr, addr_val, reg_name)
        try:
            symtab.createLabel(addr, name, SourceType.USER_DEFINED)
            created += 1
        except Exception:
            skipped += 1

    print("Import complete: created=%d skipped=%d" % (created, skipped))


run()
