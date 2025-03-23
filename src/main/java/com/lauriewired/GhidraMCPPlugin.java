package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.Msg;

import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.app.services.ProgramManager;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.SwingUtilities;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "✅ GhidraMCPPlugin loaded!");

        try {
            startServer();
        } catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
    }

    private void startServer() throws IOException {
        int port = 8080;
        server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/methods", exchange -> sendResponse(exchange, getAllFunctionNames()));
        server.createContext("/classes", exchange -> sendResponse(exchange, getAllClassNames()));
        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes());
            sendResponse(exchange, decompileFunctionByName(name));
        });
        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });
        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });
        server.createContext("/segments", exchange -> sendResponse(exchange, listSegments()));
        server.createContext("/imports", exchange -> sendResponse(exchange, listImports()));
        server.createContext("/exports", exchange -> sendResponse(exchange, listExports()));
        server.createContext("/namespaces", exchange -> sendResponse(exchange, listNamespaces()));
        server.createContext("/data", exchange -> sendResponse(exchange, listDefinedData()));

        server.setExecutor(null);
        new Thread(() -> {
            server.start();
            Msg.info(this, "🌐 GhidraMCP HTTP server started on port " + port);
        }, "GhidraMCP-HTTP-Server").start();
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes());
        Map<String, String> params = new HashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) params.put(kv[0], kv[1]);
        }
        return params;
    }

    private String getAllFunctionNames() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        StringBuilder sb = new StringBuilder();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            sb.append(f.getName()).append("\n");
        }
        return sb.toString();
    }

    private String getAllClassNames() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        return String.join("\n", classNames);
    }

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else return "Decompilation failed";
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        // Use AtomicBoolean to capture the result from inside the Task
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            // Run in Swing EDT to ensure proper transaction handling
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });
        } 
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }

        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            // Run in Swing EDT to ensure proper transaction handling
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String listSegments() {
        Program program = getCurrentProgram();
        StringBuilder sb = new StringBuilder();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            sb.append(String.format("%s: %s - %s\n", block.getName(), block.getStart(), block.getEnd()));
        }
        return sb.toString();
    }

    private String listImports() {
        Program program = getCurrentProgram();
        StringBuilder sb = new StringBuilder();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            sb.append(symbol.getName()).append(" -> ").append(symbol.getAddress()).append("\n");
        }
        return sb.toString();
    }

    private String listExports() {
        Program program = getCurrentProgram();
        StringBuilder sb = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.isExternal()) {
                sb.append(func.getName()).append(" -> ").append(func.getEntryPoint()).append("\n");
            }
        }
        return sb.toString();
    }

    private String listNamespaces() {
        Program program = getCurrentProgram();
        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        return String.join("\n", namespaces);
    }

    private String listDefinedData() {
        Program program = getCurrentProgram();
        StringBuilder sb = new StringBuilder();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    sb.append(String.format("%s: %s = %s\n",
                        data.getAddress(),
                        data.getLabel() != null ? data.getLabel() : "(unnamed)",
                        data.getDefaultValueRepresentation()));
                }
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager programManager = tool.getService(ProgramManager.class);
        return programManager != null ? programManager.getCurrentProgram() : null;
    }

    @Override
    public void dispose() {
        if (server != null) {
            server.stop(0);
            Msg.info(this, "🛑 HTTP server stopped.");
        }
        super.dispose();
    }
}
