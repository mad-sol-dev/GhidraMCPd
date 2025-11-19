package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import com.lauriewired.CursorPager;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Arrays;
import java.util.Base64;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;
    private static final int DEFAULT_HEXDUMP_WIDTH = 16;
    private static final int MAX_BYTE_READ = 0x200;      // 512 bytes
    private static final int MAX_DATA_WINDOW = 0x800;    // 2048 bytes
    private static final int MAX_CSTRING_LEN = 0x800;    // 2048 chars

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/read_dword", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, readDword(address));
        });

        server.createContext("/read_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            sendResponse(exchange, readBytesHexdump(address, length));
        });

        server.createContext("/read_cstring", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int maxLen = parseIntOrDefault(qparams.get("max_len"), 256);
            sendResponse(exchange, readCString(address, maxLen));
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

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String filter = qparams.get("filter");
            sendJsonResponse(exchange, listImports(filter, offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String filter = qparams.get("filter");
            sendJsonResponse(exchange, listExports(filter, offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/data_window", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            sendResponse(exchange, readDataWindow(start, end));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String cursor = qparams.get("cursor");
            sendJsonResponse(exchange, searchFunctionsByName(searchTerm, cursor, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listFunctions(offset, limit));
        });

        server.createContext("/functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listFunctions(offset, limit));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/decompile_by_addr", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/disassemble", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendJsonResponse(exchange, getXrefsTo(address, offset, limit, filter));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendJsonResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        server.createContext("/searchScalars", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String value = qparams.get("value");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 500);
            String cursor = qparams.get("cursor");
            sendJsonResponse(exchange, handleSearchScalars(value, cursor, offset, limit));
        });

        server.createContext("/functionsInRange", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String min = qparams.get("min");
            String max = qparams.get("max");
            sendResponse(exchange, handleFunctionsInRange(min, max));
        });

        server.createContext("/disassembleAt", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int count = parseIntOrDefault(qparams.get("count"), 16);
            sendResponse(exchange, handleDisassembleAt(address, count));
        });

        server.createContext("/project_info", exchange -> {
            sendResponse(exchange, getProjectInfo());
        });

        server.createContext("/projectInfo", exchange -> {
            sendResponse(exchange, getProjectInfo());
        });

        server.createContext("/readBytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String lengthStr = qparams.get("length");
            if (lengthStr == null) {
                sendJsonResponse(exchange, errorResponse("length parameter is required"));
                return;
            }
            int length = parseIntOrDefault(lengthStr, -1);
            if (length < 0) {
                sendJsonResponse(exchange, errorResponse("invalid length parameter"));
                return;
            }
            sendResponse(exchange, readBytesBase64(address, length));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(String filter, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return jsonErrorEnvelope("No program loaded");

        String normalized = (filter == null) ? "" : filter.toLowerCase();
        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            String name = symbol.getName();
            if (name == null) {
                continue;
            }
            if (!normalized.isEmpty() && !name.toLowerCase().contains(normalized)) {
                continue;
            }
            lines.add(name + " -> " + formatAddress(symbol.getAddress()));
        }
        return buildJsonEnvelope(lines, offset, limit, s -> '"' + jsonEscape(s) + '"');
    }

    private String listExports(String filter, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return jsonErrorEnvelope("No program loaded");

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        String normalized = (filter == null) ? "" : filter.toLowerCase();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                String name = s.getName();
                if (name == null) {
                    continue;
                }
                if (!normalized.isEmpty() && !name.toLowerCase().contains(normalized)) {
                    continue;
                }
                lines.add(name + " -> " + formatAddress(s.getAddress()));
            }
        }
        return buildJsonEnvelope(lines, offset, limit, s -> '"' + jsonEscape(s) + '"');
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, String cursorParam, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return CursorPager.errorJson("No program loaded", this::jsonEscape);
        }

        // Wildcard support: empty or "*" means return all functions
        boolean matchAll = (searchTerm == null || searchTerm.isEmpty() || searchTerm.equals("*"));

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (matchAll || name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        CursorPager.CursorRequest request = new CursorPager.CursorRequest(
            "searchFunctions",
            matchAll ? "*" : searchTerm.toLowerCase(Locale.ROOT),
            offset,
            limit,
            100,
            1000,
            cursorParam
        );
        CursorPager.CursorPage page = CursorPager.fromList(matches, request);
        return CursorPager.toJson(page, this::jsonEscape);
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
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
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
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

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Read a 32-bit little-endian value from memory.
     */
    private String readDword(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            byte[] buffer = new byte[4];
            int read = program.getMemory().getBytes(addr, buffer);
            if (read < 4) {
                return errorResponse("unable to read 4 bytes at " + addressStr);
            }

            long value = ((long) buffer[0] & 0xff)
                | (((long) buffer[1] & 0xff) << 8)
                | (((long) buffer[2] & 0xff) << 16)
                | (((long) buffer[3] & 0xff) << 24);

            return String.format("0x%08x", value);
        } catch (MemoryAccessException e) {
            return errorResponse("memory access failed: " + e.getMessage());
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * Read raw bytes from memory with a hexdump style formatting.
     */
    private String readBytesHexdump(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address is required");

        int effectiveLength = clampLength(length, MAX_BYTE_READ);
        if (effectiveLength <= 0) {
            return errorResponse("length must be greater than zero");
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            byte[] buffer = new byte[effectiveLength];
            int read = program.getMemory().getBytes(addr, buffer);
            if (read <= 0) {
                return errorResponse("unable to read memory at " + addressStr);
            }

            String dump = formatHexDump(addr, buffer, read);
            if (read < effectiveLength || length > effectiveLength) {
                dump += String.format("\n... (truncated to %d bytes)", read);
            }
            return dump;
        } catch (MemoryAccessException e) {
            return errorResponse("memory access failed: " + e.getMessage());
        } catch (AddressOutOfBoundsException e) {
            return errorResponse("address out of bounds");
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * Read a zero terminated string from memory.
     */
    private String readCString(String addressStr, int maxLen) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address is required");

        int effectiveLen = clampLength(maxLen, MAX_CSTRING_LEN);
        if (effectiveLen <= 0) {
            return errorResponse("max_len must be greater than zero");
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            StringBuilder builder = new StringBuilder();
            boolean terminated = false;

            for (int i = 0; i < effectiveLen; i++) {
                byte value = program.getMemory().getByte(addr);
                if (value == 0) {
                    terminated = true;
                    break;
                }
                builder.append(toPrintableByte(value));
                addr = addr.add(1);
            }

            if (!terminated) {
                if (builder.length() > 0) {
                    builder.append('\n');
                }
                builder.append(String.format("[truncated after %d bytes]", effectiveLen));
            }

            return builder.toString();
        } catch (MemoryAccessException e) {
            return errorResponse("memory access failed: " + e.getMessage());
        } catch (AddressOutOfBoundsException e) {
            return errorResponse("address out of bounds");
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * Read a bounded data window and return a hexdump.
     */
    private String readDataWindow(String startStr, String endStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startStr == null || endStr == null) return errorResponse("start and end are required");

        try {
            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = program.getAddressFactory().getAddress(endStr);

            if (start == null || end == null) {
                return errorResponse("invalid address range");
            }

            if (start.compareTo(end) >= 0) {
                return errorResponse("start must be less than end");
            }

            long span = end.subtract(start);
            if (span <= 0) {
                return errorResponse("invalid range length");
            }

            long cappedSpan = Math.min(span, MAX_DATA_WINDOW);
            int bytesToRead = (int) cappedSpan;
            if (bytesToRead <= 0) {
                return errorResponse("empty range");
            }

            byte[] buffer = new byte[bytesToRead];
            int read = program.getMemory().getBytes(start, buffer);
            if (read <= 0) {
                return errorResponse("unable to read memory");
            }

            String dump = formatHexDump(start, buffer, read);
            if (read < bytesToRead || span > bytesToRead) {
                dump += String.format("\n... (truncated to %d bytes)", read);
            }
            return dump;
        } catch (MemoryAccessException e) {
            return errorResponse("memory access failed: " + e.getMessage());
        } catch (AddressOutOfBoundsException e) {
            return errorResponse("address out of bounds");
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * Format bytes into a traditional hex + ASCII dump.
     */
    private String formatHexDump(Address start, byte[] data, int length) throws AddressOutOfBoundsException {
        if (length <= 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i += DEFAULT_HEXDUMP_WIDTH) {
            int chunk = Math.min(DEFAULT_HEXDUMP_WIDTH, length - i);
            Address lineAddress = start.add(i);
            StringBuilder ascii = new StringBuilder();

            sb.append(String.format("%s: ", lineAddress));
            for (int j = 0; j < chunk; j++) {
                int value = data[i + j] & 0xff;
                sb.append(String.format("%02x ", value));
                ascii.append((value >= 32 && value < 127) ? (char) value : '.');
            }

            if (chunk < DEFAULT_HEXDUMP_WIDTH) {
                for (int j = chunk; j < DEFAULT_HEXDUMP_WIDTH; j++) {
                    sb.append("   ");
                }
            }

            sb.append("|").append(ascii).append("|");
            if (i + chunk < length) {
                sb.append('\n');
            }
        }

        return sb.toString();
    }

    private int clampLength(int requested, int max) {
        if (requested <= 0) {
            return 0;
        }
        return Math.min(requested, max);
    }

    private String toPrintableByte(byte value) {
        int unsigned = value & 0xff;
        if (unsigned >= 32 && unsigned < 127) {
            return Character.toString((char) unsigned);
        }
        return String.format("\\x%02x", unsigned);
    }

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> entries = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            entries.add(String.format("%s at %s", func.getName(), func.getEntryPoint()));
        }

        return paginateList(entries, offset, limit);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        return getXrefsTo(addressStr, offset, limit, null);
    }

    private String getXrefsTo(String addressStr, int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return jsonErrorEnvelope("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return jsonErrorEnvelope("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            record Xref(String address, String context) {}
            List<Xref> refs = new ArrayList<>();
            String normalized = (filter == null) ? "" : filter.toLowerCase();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                String context = String.format("%s%s [%s]", fromAddr, funcInfo, refType.getName());
                if (!normalized.isEmpty() && !context.toLowerCase().contains(normalized)) {
                    continue;
                }
                refs.add(new Xref(formatAddress(fromAddr), context));
            }

            return buildJsonEnvelope(refs, offset, limit, xref -> {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                sb.append("\"address\":\"").append(jsonEscape(xref.address())).append('\"');
                sb.append(',');
                sb.append("\"context\":\"").append(jsonEscape(xref.context())).append('\"');
                sb.append('}');
                return sb.toString();
            });
        } catch (Exception e) {
            return jsonErrorEnvelope("Error getting references to address: " + e.getMessage());
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return jsonErrorEnvelope("No program loaded");

        record StringEntry(String address, String literal) {}

        List<StringEntry> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(new StringEntry(formatAddress(data.getAddress()), escapedValue));
                }
            }
        }

        return buildJsonEnvelope(lines, offset, limit, entry -> {
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            sb.append("\"address\":\"").append(jsonEscape(entry.address())).append('\"');
            sb.append(',');
            sb.append("\"literal\":\"").append(jsonEscape(entry.literal())).append('\"');
            sb.append('}');
            return sb.toString();
        });
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    private <T> String buildJsonEnvelope(List<T> items, int offset, int limit, Function<T, String> serializer) {
        int start = Math.max(0, offset);
        int effectiveLimit = Math.max(1, limit);
        int end = Math.min(items.size(), start + effectiveLimit);
        List<T> sub = start < items.size() ? items.subList(start, end) : List.of();
        boolean hasMore = end < items.size();

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"items\":[");
        for (int i = 0; i < sub.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(serializer.apply(sub.get(i)));
        }
        sb.append("],\"has_more\":").append(hasMore);
        sb.append('}');
        return sb.toString();
    }

    private String errorResponse(String message) {
        return "{\"error\":\"" + jsonEscape(message) + "\",\"status\":\"error\"}";
    }

    private String jsonErrorEnvelope(String message) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"items\":[],\"has_more\":false");
        if (message != null && !message.isEmpty()) {
            sb.append(",\"error\":\"").append(jsonEscape(message)).append('\"');
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Search for scalar values (immediates/constants) in instructions
     */
    private String handleSearchScalars(String valueStr, String cursorParam, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return CursorPager.errorJson("No program loaded", this::jsonEscape);
        }
        if (valueStr == null || valueStr.isEmpty()) {
            return CursorPager.errorJson("value parameter is required", this::jsonEscape);
        }

        int requestedLimit = limit > 0 ? limit : 100;
        int effectiveLimit = Math.min(requestedLimit, 500);

        try {
            // Parse value as hex or decimal
            long searchValue;
            if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                searchValue = Long.parseLong(valueStr.substring(2), 16);
            } else {
                searchValue = Long.parseLong(valueStr);
            }

            CursorPager.CursorRequest request = new CursorPager.CursorRequest(
                "searchScalars",
                Long.toUnsignedString(searchValue),
                offset,
                effectiveLimit,
                100,
                500,
                cursorParam
            );

            CursorPager.ResolvedRequest resolved = CursorPager.resolve(request);
            InstructionIterator instructions = program.getListing().getInstructions(true);

            List<String> pageItems = new ArrayList<>();
            int matchIndex = 0;
            boolean hasMore = false;

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (!instructionHasScalarValue(instr, searchValue)) {
                    continue;
                }

                if (matchIndex >= resolved.startOffset() + resolved.limit()) {
                    hasMore = true;
                    break;
                }

                if (matchIndex >= resolved.startOffset()) {
                    pageItems.add(String.format("%s: %s",
                        instr.getAddress(),
                        instr.toString()));
                }

                matchIndex++;
            }

            CursorPager.CursorPage page = CursorPager.buildPage(resolved, pageItems, hasMore);
            return CursorPager.toJson(page, this::jsonEscape);

        } catch (NumberFormatException e) {
            return CursorPager.errorJson("invalid value format", this::jsonEscape);
        } catch (Exception e) {
            return CursorPager.errorJson(e.getMessage(), this::jsonEscape);
        }
    }

    private boolean instructionHasScalarValue(Instruction instr, long searchValue) {
        int numOperands = instr.getNumOperands();
        for (int i = 0; i < numOperands; i++) {
            Object[] opObjects = instr.getOpObjects(i);
            for (Object obj : opObjects) {
                if (obj instanceof Scalar) {
                    Scalar scalar = (Scalar) obj;
                    if (scalar.getUnsignedValue() == searchValue) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * List functions in a given address range
     */
    private String handleFunctionsInRange(String minStr, String maxStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (minStr == null || minStr.isEmpty()) return errorResponse("min parameter is required");
        if (maxStr == null || maxStr.isEmpty()) return errorResponse("max parameter is required");

        try {
            Address minAddr = program.getAddressFactory().getAddress(minStr);
            Address maxAddr = program.getAddressFactory().getAddress(maxStr);

            if (minAddr == null || maxAddr == null) {
                return errorResponse("invalid address range");
            }

            if (minAddr.compareTo(maxAddr) > 0) {
                return errorResponse("min must be less than or equal to max");
            }

            AddressSet addressSet = new AddressSet(minAddr, maxAddr);
            FunctionIterator functions = program.getFunctionManager().getFunctions(addressSet, true);

            List<String> results = new ArrayList<>();
            while (functions.hasNext()) {
                Function func = functions.next();
                String name = func.getName();
                Address entryPoint = func.getEntryPoint();
                
                // Try to get body size
                long size = func.getBody().getNumAddresses();
                
                if (size > 0) {
                    results.add(String.format("%s @ %s %d", name, entryPoint, size));
                } else {
                    results.add(String.format("%s @ %s", name, entryPoint));
                }
            }

            // Already sorted by address (forward iteration)
            return results.isEmpty() ? "" : String.join("\n", results);

        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * Disassemble instructions starting at a given address
     */
    private String handleDisassembleAt(String addressStr, int count) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address parameter is required");

        // Cap count at 128
        int effectiveCount = Math.min(Math.max(count, 1), 128);

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return errorResponse("invalid address");
            }

            List<String> lines = new ArrayList<>();
            InstructionIterator instructions = program.getListing().getInstructions(addr, true);

            int collected = 0;
            while (instructions.hasNext() && collected < effectiveCount) {
                Instruction instr = instructions.next();
                
                // Get instruction bytes as uppercase hex string
                byte[] bytes = instr.getBytes();
                StringBuilder hexBytes = new StringBuilder();
                for (byte b : bytes) {
                    hexBytes.append(String.format("%02X", b & 0xFF));
                }

                lines.add(String.format("%s: %s %s", 
                    instr.getAddress(), 
                    hexBytes.toString(),
                    instr.toString()));
                
                collected++;
            }

            return lines.isEmpty() ? "" : String.join("\n", lines);

        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * Read raw bytes from memory and return as Base64
     */
    private String readBytesBase64(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address parameter is required");

        // Cap length at 4096
        int effectiveLength = Math.min(Math.max(length, 1), 4096);

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return errorResponse("invalid address");
            }

            byte[] buffer = new byte[effectiveLength];
            int bytesRead = program.getMemory().getBytes(addr, buffer);

            if (bytesRead <= 0) {
                return errorResponse("unable to read memory at address");
            }

            // If we read fewer bytes than requested, trim the buffer
            byte[] actualData = (bytesRead < effectiveLength) 
                ? Arrays.copyOf(buffer, bytesRead) 
                : buffer;

            // Encode as Base64 (single line, no newline)
            return Base64.getEncoder().encodeToString(actualData);

        } catch (MemoryAccessException e) {
            return errorResponse("memory access failed: " + e.getMessage());
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJsonResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private String getProjectInfo() {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorResponse("No program loaded");
        }

        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{");

            appendJsonField(sb, "program_name", program.getDomainFile() != null
                ? program.getDomainFile().getName()
                : program.getName());
            appendJsonField(sb, "executable_path", safeStringCall(program::getExecutablePath));
            appendJsonField(sb, "executable_md5", safeStringCall(program::getExecutableMD5));
            appendJsonField(sb, "executable_sha256", safeStringCall(program::getExecutableSHA256));
            appendJsonField(sb, "executable_format", safeStringCall(program::getExecutableFormat));

            Address imageBase = program.getImageBase();
            appendJsonField(sb, "image_base", imageBase != null ? formatAddress(imageBase) : null);

            appendJsonField(sb, "language_id", program.getLanguageID().getIdAsString());
            appendJsonField(sb, "compiler_spec_id", program.getCompilerSpec() != null
                ? program.getCompilerSpec().getCompilerSpecID().getIdAsString()
                : null);

            appendEntryPoints(sb, program);
            appendMemoryBlocks(sb, program);
            appendCounts(sb, program);
            if (sb.charAt(sb.length() - 1) == ',') {
                sb.setLength(sb.length() - 1);
            }
            sb.append('}');
            return sb.toString();
        }
        catch (Exception ex) {
            Msg.error(this, "Failed to collect project info", ex);
            return errorResponse("Failed to collect project info");
        }
    }

    private void appendJsonField(StringBuilder sb, String key, String value) {
        sb.append('"').append(key).append('"').append(':');
        if (value == null) {
            sb.append("null");
        }
        else {
            sb.append('"').append(jsonEscape(value)).append('"');
        }
        sb.append(',');
    }

    private void appendEntryPoints(StringBuilder sb, Program program) {
        List<Address> entries = new ArrayList<>();
        SymbolTable table = program.getSymbolTable();
        AddressIterator externalEntries = table.getExternalEntryPointIterator();
        while (externalEntries.hasNext()) {
            Address addr = externalEntries.next();
            if (addr != null && !entries.contains(addr)) {
                entries.add(addr);
            }
        }

        if (entries.isEmpty()) {
            SymbolIterator entrySymbols = table.getSymbols("entry");
            while (entrySymbols != null && entrySymbols.hasNext()) {
                Symbol symbol = entrySymbols.next();
                if (symbol != null && symbol.getAddress() != null) {
                    Address addr = symbol.getAddress();
                    if (!entries.contains(addr)) {
                        entries.add(addr);
                    }
                }
            }
        }

        if (entries.isEmpty()) {
            Address base = program.getImageBase();
            if (base != null) {
                Function func = program.getListing().getFunctionAt(base);
                if (func != null) {
                    Address addr = func.getEntryPoint();
                    if (!entries.contains(addr)) {
                        entries.add(addr);
                    }
                }
            }
        }

        Collections.sort(entries);

        sb.append("\"entry_points\": [");
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(formatAddress(entries.get(i))).append('"');
        }
        sb.append("],");
    }

    private void appendMemoryBlocks(StringBuilder sb, Program program) {
        List<MemoryBlock> blocks = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            blocks.add(block);
        }
        blocks.sort((a, b) -> a.getStart().compareTo(b.getStart()));

        sb.append("\"memory_blocks\":[");
        for (int i = 0; i < blocks.size(); i++) {
            MemoryBlock block = blocks.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append('{');
            appendJsonField(sb, "name", block.getName());
            appendJsonField(sb, "start", block.getStart() != null ? formatAddress(block.getStart()) : null);
            appendJsonField(sb, "end", block.getEnd() != null ? formatAddress(block.getEnd()) : null);
            sb.append("\"length\":").append(block.getSize()).append(',');
            appendJsonField(sb, "rwx", buildPermissions(block));
            sb.append("\"loaded\":").append(block.isLoaded()).append(',');
            sb.append("\"initialized\":").append(block.isInitialized());
            sb.append('}');
        }
        sb.append("],");
    }

    private void appendCounts(StringBuilder sb, Program program) {
        SymbolTable table = program.getSymbolTable();
        int importCount = 0;
        for (Symbol ignored : table.getExternalSymbols()) {
            importCount++;
        }
        sb.append("\"imports_count\":").append(importCount).append(',');

        int exportCount = 0;
        SymbolIterator all = table.getAllSymbols(true);
        while (all.hasNext()) {
            Symbol symbol = all.next();
            if (symbol != null && symbol.isExternalEntryPoint()) {
                exportCount++;
            }
        }
        if (exportCount > 0) {
            sb.append("\"exports_count\":").append(exportCount).append(',');
        }
        else {
            sb.append("\"exports_count\":null,");
        }
    }

    private String buildPermissions(MemoryBlock block) {
        StringBuilder perms = new StringBuilder();
        perms.append(block.isRead() ? 'r' : '-');
        perms.append(block.isWrite() ? 'w' : '-');
        perms.append(block.isExecute() ? 'x' : '-');
        return perms.toString();
    }

    private String formatAddress(Address address) {
        return "0x" + address.toString();
    }

    private String jsonEscape(String input) {
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                case '"':
                    escaped.append('\\').append(c);
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        escaped.append(c);
                    }
                    break;
            }
        }
        return escaped.toString();
    }

    private String safeStringCall(Supplier<String> supplier) {
        try {
            return supplier.get();
        }
        catch (Exception ex) {
            Msg.debug(this, "Failed to read program metadata: " + ex.getMessage());
            return null;
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
