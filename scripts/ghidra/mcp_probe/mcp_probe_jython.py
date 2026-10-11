# Probe for /runScript with Jython (SCRIPT-ADAPTER): sets an EOL comment, says so
# with Python's print and with println, and with "fail" raises afterwards.
#
# Arguments:
#   <address>        set the EOL comment "MCP jython probe" there
#   <address> fail   the same, then raise: ok must be false, nothing committed,
#                    the traceback in output
#
# @category GhidraMCPd
# @runtime Jython

from ghidra.program.model.listing import CodeUnit

args = getScriptArgs()
address = toAddr(args[0])
currentProgram.getListing().setComment(address, CodeUnit.EOL_COMMENT, "MCP jython probe")
print("print: EOL comment set at %s" % address)
println("println: EOL comment set at %s" % address)
if len(args) > 1 and args[1] == "fail":
    raise ValueError("mcp_probe_jython: failing on purpose after the comment")
