// Probe for /runScript load failures (SCRIPT-ADAPTER): does not compile on
// purpose.  It has a directory of its own because Ghidra compiles a script
// directory as one bundle -- a broken file next to McpProbe would stop that
// one as well.
//
//@category GhidraMCPd

import ghidra.app.script.GhidraScript;

public class McpBroken extends GhidraScript {

    @Override
    protected void run() throws Exception {
        println("McpBroken: never reached")   // missing semicolon
    }
}
