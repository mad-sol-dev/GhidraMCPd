// Probe for the /runScript prototype (SCRIPT-ADAPTER): sets an EOL comment and
// says so, so a run shows whether output comes back and whether the comment
// stays (real run) or is rolled back (dry run).
//
// Arguments:
//   <address>         set the EOL comment "MCP script probe" there, print one line
//   <address> fail    the same, then throw: nothing may be committed
//   (none)            askAddress() instead -- shows what a dialog does when the
//                     script runs from the HTTP thread
//
// Only for the prototype; real scripts live in the analysis project.
//
//@category GhidraMCPd

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;

public class McpProbe extends GhidraScript {

    static final String COMMENT = "MCP script probe";

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Address address = args.length > 0
            ? toAddr(args[0])
            : askAddress("McpProbe", "Address for the probe comment");
        if (address == null) {
            throw new IllegalArgumentException("not an address: " + args[0]);
        }
        currentProgram.getListing().setComment(address, CommentType.EOL, COMMENT);
        println("McpProbe: EOL comment set at " + address);
        if (args.length > 1 && args[1].equals("fail")) {
            throw new IllegalStateException("McpProbe: failing on purpose after the comment");
        }
    }
}
