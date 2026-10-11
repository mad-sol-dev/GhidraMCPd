// Probe for the /runScript timeout (SCRIPT-ADAPTER): loops for up to 60 s,
// checking its monitor every 100 ms, and changes nothing.  With timeout_s
// below 60 the run must end as timed_out.
//
//@category GhidraMCPd

import ghidra.app.script.GhidraScript;

public class McpSpin extends GhidraScript {

    @Override
    protected void run() throws Exception {
        println("McpSpin: start");
        for (int i = 0; i < 600; i++) {
            monitor.checkCancelled();
            Thread.sleep(100);
        }
        println("McpSpin: ran 60 s without being cancelled");
    }
}
