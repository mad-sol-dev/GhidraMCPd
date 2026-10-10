package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ToolServices;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
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
import ghidra.app.plugin.ProgramPlugin;
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
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.listing.Variable;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import com.lauriewired.CursorPager;
import com.lauriewired.ProgramCapable;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.function.Predicate;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends ProgramPlugin implements ProgramCapable {

    private HttpServer server;
    private final ProgramStatusTracker statusTracker = new ProgramStatusTracker();
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final String BIND_OPTION_NAME = "Bind Address";
    private static final String DEFAULT_BIND_ADDRESS = "127.0.0.1";
    private static final int DEFAULT_PORT = 8080;
    /** Build version, filled in by Maven from scripts/plugin_version.sh. */
    static final String PLUGIN_VERSION = loadPluginVersion();
    private static final int DEFAULT_HEXDUMP_WIDTH = 16;
    private static final int MAX_BYTE_READ = 0x200;      // 512 bytes
    private static final int MAX_DATA_WINDOW = 0x800;    // 2048 bytes
    private static final int MAX_CSTRING_LEN = 0x800;    // 2048 chars

    private static final PluginContextRegistry<GhidraMCPPlugin> CONTEXT_REGISTRY =
        new PluginContextRegistry<>();
    private static final SharedHttpServerState SERVER_STATE = new SharedHttpServerState();
    private static final AtomicBoolean ROUTES_REGISTERED = new AtomicBoolean(false);

    @FunctionalInterface
    private interface PluginExchangeHandler {
        void handle(GhidraMCPPlugin plugin, HttpExchange exchange) throws Exception;
    }

    static final class PluginContextRegistry<T extends ProgramCapable> {
        private final LinkedHashSet<T> contexts = new LinkedHashSet<>();
        private T active;

        synchronized void register(T context) {
            contexts.add(context);
            if (active == null || context.hasProgramContext() ||
                (!active.hasProgramManagerService() && context.hasProgramManagerService())) {
                active = context;
            }
        }

        synchronized void promote(T context) {
            if (contexts.contains(context)) {
                if (context.hasProgramContext() || context.hasProgramManagerService()) {
                    active = context;
                }
                else if (active == null) {
                    active = context;
                }
            }
        }

        synchronized Optional<T> active(boolean requireProgramContext) {
            if (active != null) {
                if (requireProgramContext && active.hasProgramContext()) {
                    return Optional.of(active);
                }

                if (!requireProgramContext &&
                    (active.hasProgramContext() || active.hasProgramManagerService())) {
                    return Optional.of(active);
                }
            }

            Optional<T> programCapable = contexts.stream()
                .filter(ProgramCapable::hasProgramContext)
                .findFirst();
            if (programCapable.isPresent()) {
                if (!requireProgramContext) {
                    active = programCapable.get();
                }
                return programCapable;
            }

            if (!requireProgramContext) {
                Optional<T> programManagerCapable = contexts.stream()
                    .filter(ProgramCapable::hasProgramManagerService)
                    .findFirst();
                if (programManagerCapable.isPresent()) {
                    active = programManagerCapable.get();
                    return programManagerCapable;
                }
            }

            if (requireProgramContext) {
                return Optional.empty();
            }

            return contexts.stream().findFirst();
        }

        synchronized Optional<T> firstMatching(Predicate<T> predicate) {
            return contexts.stream().filter(predicate).findFirst();
        }

        synchronized void unregister(T context) {
            contexts.remove(context);
            if (Objects.equals(active, context)) {
                active = contexts.stream().findFirst().orElse(null);
            }
        }

        synchronized boolean isEmpty() {
            return contexts.isEmpty();
        }
    }

    static final class SharedHttpServerState {
        record ServerHandle(HttpServer server, boolean newlyCreated, int boundPort) {}

        private HttpServer server;
        private int port = -1;

        synchronized ServerHandle ensureServer(int requestedPort, ServerFactory factory)
                throws IOException {
            if (server == null) {
                HttpServer created = factory.create();
                server = created;
                port = requestedPort;
                return new ServerHandle(created, true, port);
            }
            return new ServerHandle(server, false, port);
        }

        synchronized void stopIfIdle(boolean idle) {
            if (idle && server != null) {
                server.stop(1);
                server = null;
                port = -1;
                ROUTES_REGISTERED.set(false);
            }
        }
    }

    private enum ProgramState {
        IDLE,
        LOADING,
        READY
    }

    private static final class ProgramStatusSnapshot {
        final String domainFileId;
        final boolean locked;
        final ProgramState state;
        final List<String> warnings;
        final long stateDurationSeconds;

        ProgramStatusSnapshot(String domainFileId, boolean locked, ProgramState state,
                List<String> warnings, long stateDurationSeconds) {
            this.domainFileId = domainFileId;
            this.locked = locked;
            this.state = state;
            this.warnings = warnings;
            this.stateDurationSeconds = stateDurationSeconds;
        }
    }

    private final class ProgramStatusTracker {
        private final Object lock = new Object();
        private ProgramState state = ProgramState.IDLE;
        private long stateTransitionTime = System.currentTimeMillis();
        private String domainFileId;
        private boolean locked;
        private List<String> warnings = new ArrayList<>();
        private Thread watcher;

        ProgramStatusSnapshot snapshot() {
            synchronized (lock) {
                long durationSeconds = (System.currentTimeMillis() - stateTransitionTime) / 1000;
                return new ProgramStatusSnapshot(domainFileId, locked, state,
                    new ArrayList<>(warnings), durationSeconds);
            }
        }

        void applyWarnings(List<String> newWarnings) {
            if (newWarnings == null || newWarnings.isEmpty()) {
                return;
            }
            synchronized (lock) {
                warnings = new ArrayList<>(newWarnings);
            }
        }

        void markLoading(DomainFile target, List<String> initialWarnings) {
            synchronized (lock) {
                state = ProgramState.LOADING;
                stateTransitionTime = System.currentTimeMillis();
                domainFileId = target != null ? target.getFileID() : null;
                locked = target != null && target.isCheckedOut();
                warnings = initialWarnings == null ? new ArrayList<>()
                    : new ArrayList<>(initialWarnings);
            }
        }

        void initialise(ProgramManager manager) {
            if (manager != null) {
                trackProgram(manager.getCurrentProgram());
            }
        }

        void onProgramActivated(Program program) {
            trackProgram(program);
        }

        void onProgramClosed(Program program) {
            trackProgram(null);
        }

        void onProgramOpened(Program program) {
            trackProgram(program);
        }

        private void trackProgram(Program program) {
            stopWatcher();
            if (program == null) {
                synchronized (lock) {
                    state = ProgramState.IDLE;
                    stateTransitionTime = System.currentTimeMillis();
                    domainFileId = null;
                    locked = false;
                    warnings = new ArrayList<>();
                }
                return;
            }

            DomainFile file = program.getDomainFile();
            synchronized (lock) {
                domainFileId = file != null ? file.getFileID() : null;
                locked = file != null && file.isCheckedOut();
                warnings = new ArrayList<>();
            }

            AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
            if (manager == null || !manager.isAnalyzing()) {
                markReady(program);
                return;
            }

            synchronized (lock) {
                state = ProgramState.LOADING;
                stateTransitionTime = System.currentTimeMillis();
            }

            watcher = new Thread(() -> awaitAnalysisCompletion(program, manager),
                "GhidraMCP-AnalysisWatcher");
            watcher.setDaemon(true);
            watcher.start();
        }

        private void awaitAnalysisCompletion(Program program, AutoAnalysisManager manager) {
            final long startTime = System.currentTimeMillis();
            final long TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

            while (!Thread.currentThread().isInterrupted()) {
                try {
                    if (!manager.isAnalyzing()) {
                        markReady(program);
                        return;
                    }

                    // Detect stale state - if stuck in LOADING for > 5 minutes, force READY
                    long elapsed = System.currentTimeMillis() - startTime;
                    if (elapsed > TIMEOUT_MS) {
                        Msg.warn(this,
                            String.format("Analysis watcher timeout after %d seconds, forcing READY state",
                                elapsed / 1000));
                        markReady(program);
                        return;
                    }

                    Thread.sleep(500);
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                catch (Exception e) {
                    // Log the exception instead of silently ignoring it
                    Msg.error(this, "Analysis watcher exception, forcing READY state", e);
                    markReady(program);
                    return;
                }
            }
        }

        private void markReady(Program program) {
            DomainFile file = program != null ? program.getDomainFile() : null;
            synchronized (lock) {
                state = ProgramState.READY;
                stateTransitionTime = System.currentTimeMillis();
                domainFileId = file != null ? file.getFileID() : null;
                locked = file != null && file.isCheckedOut();
            }
        }

        private void stopWatcher() {
            synchronized (lock) {
                if (watcher != null) {
                    watcher.interrupt();
                }
                watcher = null;
            }
        }
    }

    @FunctionalInterface
    interface ServerFactory {
        HttpServer create() throws IOException;
    }

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin " + PLUGIN_VERSION + " loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        options.registerOption(BIND_OPTION_NAME, DEFAULT_BIND_ADDRESS,
            null,
            "The interface address the embedded HTTP server binds to. The server has no " +
            "authentication, and the write guard lives in the bridge, not here: any address " +
            "other than loopback exposes read and write routes to everyone who can reach it. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin " + PLUGIN_VERSION + " loaded!");
    }

    static String loadPluginVersion() {
        try (InputStream in = GhidraMCPPlugin.class.getResourceAsStream("/ghidramcp-version.properties")) {
            if (in == null) {
                return "unknown";
            }
            Properties props = new Properties();
            props.load(in);
            String version = props.getProperty("version", "").trim();
            // An unfiltered resource (IDE build) still holds the Maven placeholder
            return version.isEmpty() || version.startsWith("${") ? "unknown" : version;
        } catch (IOException e) {
            return "unknown";
        }
    }

    /**
     * Resolves the bind address option. Blank means loopback, so a cleared option field
     * cannot silently widen the server to all interfaces; "0.0.0.0" has to be typed.
     */
    static InetAddress resolveBindAddress(String configured) throws UnknownHostException {
        if (configured == null || configured.isBlank()) {
            return InetAddress.getLoopbackAddress();
        }
        return InetAddress.getByName(configured.trim());
    }

    private void startServer() throws IOException {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        InetAddress bindAddress =
            resolveBindAddress(options.getString(BIND_OPTION_NAME, DEFAULT_BIND_ADDRESS));

        CONTEXT_REGISTRY.register(this);

        SharedHttpServerState.ServerHandle handle = SERVER_STATE.ensureServer(port,
            () -> HttpServer.create(new InetSocketAddress(bindAddress, port), 0));
        server = handle.server();

        if (!ROUTES_REGISTERED.get()) {
            registerRoutes(handle.server());
            ROUTES_REGISTERED.set(true);
        }

        if (handle.newlyCreated()) {
            handle.server().setExecutor(null);
            new Thread(() -> {
                try {
                    handle.server().start();
                    Msg.info(this, "GhidraMCP HTTP server started on "
                        + bindAddress.getHostAddress() + ":" + handle.boundPort());
                    if (!bindAddress.isLoopbackAddress()) {
                        Msg.warn(this, "GhidraMCP HTTP server is bound to "
                            + bindAddress.getHostAddress()
                            + ", not loopback. It has no authentication; anyone who can reach "
                            + "this address can read and modify the open programs.");
                    }
                } catch (Exception e) {
                    Msg.error(this, "Failed to start HTTP server on port " + handle.boundPort() + ". Port might be in use.", e);
                    SERVER_STATE.stopIfIdle(true);
                }
            }, "GhidraMCP-HTTP-Server").start();
        }

        if (hasProgramContext()) {
            CONTEXT_REGISTRY.promote(this);
        }

        ProgramManager programManager = tool.getService(ProgramManager.class);
        if (programManager != null) {
            statusTracker.initialise(programManager);
        }
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        statusTracker.onProgramActivated(program);
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);
        statusTracker.onProgramClosed(program);
    }

    @Override
    protected void programOpened(Program program) {
        super.programOpened(program);
        statusTracker.onProgramOpened(program);
    }

    @Override
    protected void programClosed(Program program) {
        super.programClosed(program);
        statusTracker.onProgramClosed(program);
    }

    private static void registerRoutes(HttpServer server) {
        // Answers without any tool or program, so the installed build can always be checked
        server.createContext("/plugin_version", exchange -> {
            byte[] bytes = ("{\"version\":\"" + PLUGIN_VERSION + "\",\"status\":\"ok\"}")
                .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        registerProgramHandler(server, "/methods", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"),  100);
            plugin.sendResponse(exchange, plugin.getAllFunctionNames(offset, limit));
        });

        registerProgramHandler(server, "/classes", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"),  100);
            plugin.sendResponse(exchange, plugin.getAllClassNames(offset, limit));
        });

        registerProgramHandler(server, "/decompile", (plugin, exchange) -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            plugin.sendResponse(exchange, plugin.decompileFunctionByName(name));
        });

        registerProgramHandler(server, "/read_dword", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            plugin.sendResponse(exchange, plugin.readDword(address));
        });

        registerProgramHandler(server, "/read_bytes", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = plugin.parseIntOrDefault(qparams.get("length"), 16);
            plugin.sendResponse(exchange, plugin.readBytesHexdump(address, length));
        });

        registerProgramHandler(server, "/read_cstring", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            int maxLen = plugin.parseIntOrDefault(qparams.get("max_len"), 256);
            plugin.sendResponse(exchange, plugin.readCString(address, maxLen));
        });

        registerProgramHandler(server, "/renameFunction", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String response = plugin.renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            plugin.sendResponse(exchange, response);
        });

        registerProgramHandler(server, "/renameData", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            plugin.sendResponse(exchange, plugin.renameDataAtAddress(params.get("address"), params.get("newName")));
        });

        registerProgramHandler(server, "/createLabel", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            // Anything but an explicit "false" is a dry run.
            boolean dryRun = !"false".equalsIgnoreCase(params.get("dry_run"));
            plugin.sendJsonResponse(exchange, plugin.createLabelAt(params.get("address"), params.get("name"), dryRun));
        });
        registerProgramHandler(server, "/renameVariable", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = plugin.renameVariableInFunction(functionName, oldName, newName);
            plugin.sendResponse(exchange, result);
        });

        registerProgramHandler(server, "/segments", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"),  100);
            plugin.sendResponse(exchange, plugin.listSegments(offset, limit));
        });

        registerProgramHandler(server, "/imports", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"),  100);
            String filter = qparams.get("filter");
            plugin.sendJsonResponse(exchange, plugin.listImports(filter, offset, limit));
        });

        registerProgramHandler(server, "/exports", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"),  100);
            String filter = qparams.get("filter");
            plugin.sendJsonResponse(exchange, plugin.listExports(filter, offset, limit));
        });

        registerProgramHandler(server, "/namespaces", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"),  100);
            plugin.sendResponse(exchange, plugin.listNamespaces(offset, limit));
        });

        registerProgramHandler(server, "/data", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"),  100);
            plugin.sendResponse(exchange, plugin.listDefinedData(offset, limit));
        });

        registerProgramHandler(server, "/data_window", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            plugin.sendResponse(exchange, plugin.readDataWindow(start, end));
        });

        registerProgramHandler(server, "/searchFunctions", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = plugin.parseIntOrDefault(qparams.get("limit"), 100);
            String cursor = qparams.get("cursor");
            plugin.sendJsonResponse(exchange, plugin.searchFunctionsByName(searchTerm, cursor, offset, limit));
        });

        registerProgramHandler(server, "/get_function_by_address", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            plugin.sendResponse(exchange, plugin.getFunctionByAddress(address));
        });

        registerProgramHandler(server, "/get_current_address", (plugin, exchange) -> {
            plugin.sendResponse(exchange, plugin.getCurrentAddress());
        });

        registerProgramHandler(server, "/get_current_function", (plugin, exchange) -> {
            plugin.sendResponse(exchange, plugin.getCurrentFunction());
        });

        registerProgramHandler(server, "/goto", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            plugin.sendJsonResponse(exchange, plugin.goToAddress(qparams.get("address")));
        });

        registerProgramHandler(server, "/list_functions", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"), 100);
            plugin.sendResponse(exchange, plugin.listFunctions(offset, limit));
        });

        registerProgramHandler(server, "/functions", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = plugin.parseIntOrDefault(qparams.get("limit"), 100);
            plugin.sendResponse(exchange, plugin.listFunctions(offset, limit));
        });

        registerProgramHandler(server, "/decompile_function", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            plugin.sendResponse(exchange, plugin.decompileFunctionByAddress(address));
        });

        registerProgramHandler(server, "/decompile_by_addr", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            plugin.sendResponse(exchange, plugin.decompileFunctionByAddress(address));
        });

        registerProgramHandler(server, "/disassemble_function", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            if ("json".equals(qparams.get("fmt"))) {
                plugin.sendJsonResponse(exchange, plugin.disassembleFunctionJson(address));
            } else {
                plugin.sendResponse(exchange, plugin.disassembleFunction(address));
            }
        });

        registerProgramHandler(server, "/disassemble", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            if ("json".equals(qparams.get("fmt"))) {
                plugin.sendJsonResponse(exchange, plugin.disassembleFunctionJson(address));
            } else {
                plugin.sendResponse(exchange, plugin.disassembleFunction(address));
            }
        });

        registerProgramHandler(server, "/set_decompiler_comment", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = plugin.setDecompilerComment(address, comment);
            plugin.sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        registerProgramHandler(server, "/set_disassembly_comment", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = plugin.setDisassemblyComment(address, comment);
            plugin.sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        registerProgramHandler(server, "/rename_function_by_address", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = plugin.renameFunctionByAddress(functionAddress, newName);
            plugin.sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        registerProgramHandler(server, "/set_function_prototype", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            PrototypeResult result = plugin.setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                plugin.sendResponse(exchange, successMsg);
            } else {
                plugin.sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        registerProgramHandler(server, "/set_local_variable_type", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            Program program = plugin.getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = plugin.findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = plugin.findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            boolean success = plugin.setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            plugin.sendResponse(exchange, responseMsg.toString());
        });

        registerProgramHandler(server, "/xrefs_to", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = plugin.parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            plugin.sendJsonResponse(exchange, plugin.getXrefsTo(address, offset, limit, filter));
        });

        registerProgramHandler(server, "/xrefs_from", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = plugin.parseIntOrDefault(qparams.get("limit"), 100);
            plugin.sendResponse(exchange, plugin.getXrefsFrom(address, offset, limit));
        });

        registerProgramHandler(server, "/function_xrefs", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = plugin.parseIntOrDefault(qparams.get("limit"), 100);
            plugin.sendResponse(exchange, plugin.getFunctionXrefs(name, offset, limit));
        });

        registerProgramHandler(server, "/strings", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = plugin.parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            plugin.sendJsonResponse(exchange, plugin.listDefinedStrings(offset, limit, filter));
        });

        registerProgramHandler(server, "/searchScalars", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String value = qparams.get("value");
            int offset = plugin.parseIntOrDefault(qparams.get("offset"), 0);
            int limit = plugin.parseIntOrDefault(qparams.get("limit"), 500);
            String cursor = qparams.get("cursor");
            plugin.sendJsonResponse(exchange, plugin.handleSearchScalars(value, cursor, offset, limit));
        });

        registerProgramHandler(server, "/functionsInRange", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String min = qparams.get("min");
            String max = qparams.get("max");
            // Opt-in, so an older bridge that does not ask keeps the exact
            // format it parses today.
            boolean extended = "extended".equals(qparams.get("fields"));
            if ("json".equals(qparams.get("fmt"))) {
                plugin.sendJsonResponse(exchange, plugin.functionsInRangeJson(min, max));
            } else {
                plugin.sendResponse(exchange, plugin.handleFunctionsInRange(min, max, extended));
            }
        });

        registerProgramHandler(server, "/disassembleAt", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            int count = plugin.parseIntOrDefault(qparams.get("count"), 16);
            if ("json".equals(qparams.get("fmt"))) {
                plugin.sendJsonResponse(exchange, plugin.disassembleAtJson(address, count));
            } else {
                plugin.sendResponse(exchange, plugin.handleDisassembleAt(address, count));
            }
        });

        registerProgramHandler(server, "/project_info", (plugin, exchange) -> {
            plugin.sendResponse(exchange, plugin.getProjectInfo());
        });

        registerProgramHandler(server, "/projectInfo", (plugin, exchange) -> {
            plugin.sendResponse(exchange, plugin.getProjectInfo());
        });

        registerProjectHandler(server, "/project_files", (plugin, exchange) -> {
            plugin.sendResponse(exchange, plugin.getProjectFiles());
        });

        registerProjectHandler(server, "/api/current_program.json", (plugin, exchange) -> {
            plugin.sendJsonResponse(exchange, plugin.getCurrentProgramStatus());
        });

        registerProjectHandler(server, "/open_program", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            plugin.sendJsonResponse(exchange,
                plugin.openProgram(qparams.get("domain_file_id"), qparams.get("path"), qparams.get("on_dirty")));
        });

        registerProgramHandler(server, "/check_dirty_state", (plugin, exchange) -> {
            plugin.sendJsonResponse(exchange, plugin.checkProgramDirtyState());
        });

        registerProgramHandler(server, "/save_program", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            plugin.sendJsonResponse(exchange, plugin.saveCurrentProgram(qparams.get("description")));
        });

        registerProgramHandler(server, "/readBytes", (plugin, exchange) -> {
            Map<String, String> qparams = plugin.parseQueryParams(exchange);
            String address = qparams.get("address");
            String lengthStr = qparams.get("length");
            if (lengthStr == null) {
                plugin.sendJsonResponse(exchange, plugin.errorResponse("length parameter is required"));
                return;
            }
            int length = plugin.parseIntOrDefault(lengthStr, -1);
            if (length < 0) {
                plugin.sendJsonResponse(exchange, plugin.errorResponse("invalid length parameter"));
                return;
            }
            plugin.sendResponse(exchange, plugin.readBytesBase64(address, length));
        });

        registerProgramHandler(server, "/createStructure", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            plugin.sendJsonResponse(exchange,
                plugin.createDataType("structure", params.get("name"), params.get("category"), params.get("fields")));
        });

        registerProgramHandler(server, "/createUnion", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            plugin.sendJsonResponse(exchange,
                plugin.createDataType("union", params.get("name"), params.get("category"), params.get("fields")));
        });

        registerProgramHandler(server, "/updateStructure", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            plugin.sendJsonResponse(exchange,
                plugin.updateDataType("structure", params.get("path"), params.get("fields")));
        });

        registerProgramHandler(server, "/updateUnion", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            plugin.sendJsonResponse(exchange,
                plugin.updateDataType("union", params.get("path"), params.get("fields")));
        });

        registerProgramHandler(server, "/deleteDataType", (plugin, exchange) -> {
            Map<String, String> params = plugin.parsePostParams(exchange);
            plugin.sendJsonResponse(exchange,
                plugin.deleteDataType(params.get("kind"), params.get("path")));
        });
    }

    private static void registerProgramHandler(HttpServer server, String path, PluginExchangeHandler handler) {
        registerContext(server, path, true, handler);
    }

    private static void registerProjectHandler(HttpServer server, String path, PluginExchangeHandler handler) {
        registerContext(server, path, false, handler);
    }

    private static void registerContext(
            HttpServer server, String path, boolean requireProgramContext, PluginExchangeHandler handler) {
        server.createContext(path, exchange -> dispatchToTool(requireProgramContext, handler, exchange));
    }

    private static void dispatchToTool(
            boolean requireProgramContext, PluginExchangeHandler handler, HttpExchange exchange) throws IOException {
        Optional<GhidraMCPPlugin> target = CONTEXT_REGISTRY.active(requireProgramContext);
        if (target.isEmpty()) {
            writeUnavailable(exchange, requireProgramContext);
            return;
        }

        GhidraMCPPlugin plugin = target.get();
        if (plugin.hasProgramContext()) {
            CONTEXT_REGISTRY.promote(plugin);
        }

        try {
            handler.handle(plugin, exchange);
        } catch (Exception e) {
            Msg.error(plugin, "Error handling request for " + exchange.getRequestURI(), e);
            plugin.sendJsonResponse(exchange, plugin.errorResponse("Internal error: " + e.getMessage()));
        }
    }

    private static void writeUnavailable(HttpExchange exchange, boolean requireProgramContext) throws IOException {
        String message = requireProgramContext
            ? "{\"error\":\"No active tool with a program context\",\"status\":\"error\"}"
            : "{\"error\":\"No active tool available\",\"status\":\"error\"}";
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(requireProgramContext ? 425 : 503, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (ghidra.program.model.listing.Function f : program.getFunctionManager().getFunctions(true)) {
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
        for (ghidra.program.model.listing.Function func : program.getFunctionManager().getFunctions(true)) {
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
        for (ghidra.program.model.listing.Function func : program.getFunctionManager().getFunctions(true)) {
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
                    for (ghidra.program.model.listing.Function func : program.getFunctionManager().getFunctions(true)) {
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

    /**
     * {@code POST /renameData}: rename the symbol on defined data.
     *
     * <p>Answers what happened.  It used to answer "Rename data attempted"
     * whatever happened -- including at an address without defined data, where
     * it did nothing at all -- and committed its transaction even after an
     * exception.  A label at an arbitrary address is {@code /createLabel}.
     */
    private String renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "ERROR: no program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "ERROR: address is required";
        if (newName == null || newName.isEmpty()) return "ERROR: newName is required";

        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            addr = null;
        }
        if (addr == null) return "ERROR: invalid address " + addressStr;
        if (program.getListing().getDefinedDataAt(addr) == null) {
            return "ERROR: no defined data at " + addr
                + "; /createLabel places a label at any address";
        }
        Symbol current = program.getSymbolTable().getPrimarySymbol(addr);
        if (current != null && current.getName().equals(newName)) {
            // No transaction for a no-op; the first live run reported
            // "R58_live_check -> R58_live_check" and left an undo step behind.
            return "Data already named " + newName + " at " + addr;
        }

        StringBuilder outcome = new StringBuilder();
        Address target = addr;
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                boolean commit = false;
                try {
                    SymbolTable symTable = program.getSymbolTable();
                    Symbol symbol = symTable.getPrimarySymbol(target);
                    String oldName = symbol != null ? symbol.getName() : "(none)";
                    if (symbol != null) {
                        symbol.setName(newName, SourceType.USER_DEFINED);
                    } else {
                        symTable.createLabel(target, newName, SourceType.USER_DEFINED);
                    }
                    commit = true;
                    outcome.append("Data renamed: ").append(oldName).append(" -> ")
                        .append(newName).append(" at ").append(target);
                } catch (Exception e) {
                    outcome.append("ERROR: rename data failed: ").append(e.getMessage());
                    Msg.error(this, "Rename data error", e);
                } finally {
                    program.endTransaction(tx, commit);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "ERROR: rename data failed: " + e.getMessage();
        }
        return outcome.toString();
    }

    /**
     * {@code POST /createLabel}: place a label at any address, including one
     * no memory block covers (R.12).
     *
     * <p>The only other {@code createLabel()} call sits inside
     * {@link #renameDataAtAddress}, behind {@code getDefinedDataAt(addr) != null};
     * an MMIO register has no defined data, so that path silently did nothing,
     * and {@code /renameData} answered "Rename data attempted" either way.
     *
     * <p>{@code dry_run=true} (the default) validates the name and reports what
     * is already at the address without opening a transaction.  The same name
     * already at the same address is not duplicated: {@code created=false}.  A
     * label added where a user-named symbol is primary stays secondary --
     * renaming that symbol is a rename, not a label -- and {@code primary} says
     * which happened.
     */
    private String createLabelAt(String addressStr, String name, boolean dryRun) {
        Program program = getCurrentProgram();
        if (program == null) return errorResponse("no program loaded");
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address parameter is required");
        if (name == null || name.isEmpty()) return errorResponse("name parameter is required");

        Address addr;
        try {
            addr = program.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            addr = null;
        }
        if (addr == null || !addr.isMemoryAddress()) {
            return errorResponse("invalid address: " + addressStr);
        }
        try {
            SymbolUtilities.validateName(name);
        } catch (InvalidInputException e) {
            return errorResponse("invalid label name '" + name + "': " + e.getMessage());
        }

        SymbolTable symbolTable = program.getSymbolTable();
        Symbol primaryBefore = symbolTable.getPrimarySymbol(addr);
        List<String> existing = new ArrayList<>();
        boolean alreadyThere = false;
        for (Symbol symbol : symbolTable.getSymbols(addr)) {
            existing.add(symbol.getName());
            if (symbol.getName().equals(name)) {
                alreadyThere = true;
            }
        }

        boolean created = false;
        boolean primary = primaryBefore != null && primaryBefore.getName().equals(name);
        String failure = null;
        if (!dryRun && !alreadyThere) {
            AtomicBoolean ok = new AtomicBoolean(false);
            AtomicBoolean isPrimary = new AtomicBoolean(false);
            StringBuilder error = new StringBuilder();
            Address target = addr;
            try {
                SwingUtilities.invokeAndWait(() -> {
                    int tx = program.startTransaction("Create label " + name);
                    boolean commit = false;
                    try {
                        Symbol symbol = symbolTable.createLabel(target, name, SourceType.USER_DEFINED);
                        isPrimary.set(symbol.isPrimary());
                        ok.set(true);
                        commit = true;
                    } catch (Exception e) {
                        error.append(e.getMessage());
                    } finally {
                        program.endTransaction(tx, commit);
                    }
                });
            } catch (InterruptedException | InvocationTargetException e) {
                error.append(e.getMessage());
            }
            created = ok.get();
            primary = isPrimary.get();
            if (!created) {
                failure = error.length() > 0 ? error.toString() : "createLabel failed";
            }
        }

        StringBuilder sb = new StringBuilder("{");
        sb.append("\"status\":\"").append(failure == null ? "ok" : "error").append('"');
        sb.append(",\"address\":\"").append(hexAddress(addr)).append('"');
        sb.append(",\"name\":\"").append(jsonEscape(name)).append('"');
        sb.append(",\"dry_run\":").append(dryRun);
        sb.append(",\"mapped\":").append(program.getMemory().contains(addr));
        sb.append(",\"already_present\":").append(alreadyThere);
        sb.append(",\"created\":").append(created);
        sb.append(",\"primary\":").append(primary);
        sb.append(",\"primary_before\":");
        if (primaryBefore == null) {
            sb.append("null");
        } else {
            sb.append('"').append(jsonEscape(primaryBefore.getName())).append('"');
        }
        sb.append(",\"existing\":[");
        for (int i = 0; i < existing.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(jsonEscape(existing.get(i))).append('"');
        }
        sb.append(']');
        if (failure != null) {
            sb.append(",\"error\":\"").append(jsonEscape(failure)).append('"');
        }
        return sb.append('}').toString();
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        ghidra.program.model.listing.Function func = null;
        for (ghidra.program.model.listing.Function f : program.getFunctionManager().getFunctions(true)) {
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
        final ghidra.program.model.listing.Function finalFunction = func;
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
            ghidra.program.model.listing.Function function = hfunction.getFunction();
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
            ghidra.program.model.listing.Function func = program.getFunctionManager().getFunctionAt(addr);

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

        ghidra.program.model.listing.Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * Navigate CodeBrowser to a specific address
     */
    private String goToAddress(String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            return errorResponse("address parameter is required");
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return errorResponse("No program loaded");
        }

        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) {
            return errorResponse("Code viewer service not available");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return errorResponse("Invalid address: " + addressStr);
            }

            ProgramLocation location = new ProgramLocation(program, address);
            boolean success = service.goTo(location, true); // true = center on screen

            if (success) {
                StringBuilder sb = new StringBuilder();
                sb.append('{');
                appendJsonField(sb, "status", "ok");
                appendJsonField(sb, "address", address.toString());
                sb.append("\"message\":\"Navigated to address\"");
                sb.append('}');
                return sb.toString();
            } else {
                return errorResponse("Failed to navigate to address: " + addressStr);
            }
        } catch (Exception e) {
            return errorResponse("Error navigating to address: " + e.getMessage());
        }
    }

    /**
     * List all functions in the database
     */
    private String listFunctions(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> entries = new ArrayList<>();
        for (ghidra.program.model.listing.Function func : program.getFunctionManager().getFunctions(true)) {
            entries.add(String.format("%s at %s", func.getName(), func.getEntryPoint()));
        }

        return paginateList(entries, offset, limit);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private ghidra.program.model.listing.Function getFunctionForAddress(Program program, Address addr) {
        ghidra.program.model.listing.Function func = program.getFunctionManager().getFunctionAt(addr);
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
            ghidra.program.model.listing.Function func = getFunctionForAddress(program, addr);
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
            ghidra.program.model.listing.Function func = getFunctionForAddress(program, addr);
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
            ghidra.program.model.listing.Function func = getFunctionForAddress(program, addr);

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
            ghidra.program.model.listing.Function func = getFunctionForAddress(program, addr);

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
    private void addPrototypeComment(Program program, ghidra.program.model.listing.Function func, String prototype) {
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
            ghidra.program.model.listing.Function func = getFunctionForAddress(program, addr);

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
    private DecompileResults decompileFunction(ghidra.program.model.listing.Function func, Program program) {
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

                ghidra.program.model.listing.Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
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
                ghidra.program.model.listing.Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
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
            for (ghidra.program.model.listing.Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        ghidra.program.model.listing.Function fromFunc = funcManager.getFunctionContaining(fromAddr);
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

    // ----------------------------------------------------------------------------------
    // Datatype CRUD operations (createStructure, createUnion, updateStructure, etc.)
    // ----------------------------------------------------------------------------------

    private String createDataType(String kind, String name, String category, String fieldsJson) {
        if (name == null || name.isEmpty()) {
            return dtOpError("name parameter is required");
        }
        if (category == null || category.isEmpty()) {
            category = "/";
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return dtOpError("No program loaded");
        }

        List<Map<String, String>> fields = parseFieldsJson(fieldsJson);
        if (fields == null) {
            return dtOpError("Invalid or missing fields JSON");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath catPath = new CategoryPath(category);

        // Check if datatype already exists
        DataType existing = dtm.getDataType(catPath, name);
        if (existing != null) {
            return dtOpError("DataType already exists at path " + existing.getPathName());
        }

        final String finalCategory = category;
        StringBuilder result = new StringBuilder();
        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create " + kind + " " + name);
                try {
                    DataType created;
                    if ("union".equals(kind)) {
                        created = createUnionType(dtm, catPath, name, fields);
                    } else {
                        created = createStructureType(dtm, catPath, name, fields);
                    }
                    result.append(serializeDataType(created, kind));
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating " + kind + " " + name, e);
                    result.append(dtOpError("Failed to create " + kind + ": " + e.getMessage()));
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to create datatype on Swing thread", e);
            return dtOpError("Swing thread error: " + e.getMessage());
        }

        return result.toString();
    }

    private DataType createStructureType(DataTypeManager dtm, CategoryPath catPath, String name,
                                          List<Map<String, String>> fields) {
        StructureDataType struct = new StructureDataType(catPath, name, 0, dtm);
        for (Map<String, String> field : fields) {
            String fieldName = field.get("name");
            String fieldType = field.get("type");
            String offsetStr = field.get("offset");
            String lengthStr = field.get("length");

            DataType fieldDt = requireDataType(dtm, fieldType, fieldName);
            int fieldLen = (lengthStr != null) ? Integer.parseInt(lengthStr) : fieldDt.getLength();
            if (fieldLen <= 0) fieldLen = 1;

            if (offsetStr != null) {
                int offset = Integer.parseInt(offsetStr);
                // Grow structure if needed
                while (struct.getLength() < offset + fieldLen) {
                    struct.add(Undefined1DataType.dataType, 1, null, null);
                }
                struct.replaceAtOffset(offset, fieldDt, fieldLen, fieldName, null);
            } else {
                struct.add(fieldDt, fieldLen, fieldName, null);
            }
        }
        return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private DataType createUnionType(DataTypeManager dtm, CategoryPath catPath, String name,
                                      List<Map<String, String>> fields) {
        UnionDataType union = new UnionDataType(catPath, name, dtm);
        for (Map<String, String> field : fields) {
            String fieldName = field.get("name");
            String fieldType = field.get("type");
            String lengthStr = field.get("length");

            DataType fieldDt = requireDataType(dtm, fieldType, fieldName);
            int fieldLen = (lengthStr != null) ? Integer.parseInt(lengthStr) : fieldDt.getLength();
            if (fieldLen <= 0) fieldLen = 1;

            union.add(fieldDt, fieldLen, fieldName, null);
        }
        return dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private String updateDataType(String kind, String path, String fieldsJson) {
        if (path == null || path.isEmpty()) {
            return dtOpError("path parameter is required");
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return dtOpError("No program loaded");
        }

        List<Map<String, String>> fields = parseFieldsJson(fieldsJson);
        if (fields == null) {
            return dtOpError("Invalid or missing fields JSON");
        }

        DataTypeManager dtm = program.getDataTypeManager();

        // Resolve path: ensure leading slash
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        DataType existing = dtm.getDataType(path);
        if (existing == null) {
            return dtOpError("DataType not found at path: " + path);
        }

        final String resolvedKind;
        if (existing instanceof Structure) {
            resolvedKind = "structure";
        } else if (existing instanceof Union) {
            resolvedKind = "union";
        } else {
            return dtOpError("DataType at " + path + " is not a structure or union");
        }

        StringBuilder result = new StringBuilder();
        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Update " + resolvedKind + " " + existing.getName());
                try {
                    if (existing instanceof Structure) {
                        updateStructureFields((Structure) existing, dtm, fields);
                    } else {
                        updateUnionFields((Union) existing, dtm, fields);
                    }
                    result.append(serializeDataType(existing, resolvedKind));
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error updating " + resolvedKind, e);
                    result.append(dtOpError("Failed to update: " + e.getMessage()));
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to update datatype on Swing thread", e);
            return dtOpError("Swing thread error: " + e.getMessage());
        }

        return result.toString();
    }

    private void updateStructureFields(Structure struct, DataTypeManager dtm,
                                        List<Map<String, String>> fields) {
        // Clear existing fields
        struct.deleteAll();

        for (Map<String, String> field : fields) {
            String fieldName = field.get("name");
            String fieldType = field.get("type");
            String offsetStr = field.get("offset");
            String lengthStr = field.get("length");

            DataType fieldDt = requireDataType(dtm, fieldType, fieldName);
            int fieldLen = (lengthStr != null) ? Integer.parseInt(lengthStr) : fieldDt.getLength();
            if (fieldLen <= 0) fieldLen = 1;

            if (offsetStr != null) {
                int offset = Integer.parseInt(offsetStr);
                while (struct.getLength() < offset + fieldLen) {
                    struct.add(Undefined1DataType.dataType, 1, null, null);
                }
                struct.replaceAtOffset(offset, fieldDt, fieldLen, fieldName, null);
            } else {
                struct.add(fieldDt, fieldLen, fieldName, null);
            }
        }
    }

    private void updateUnionFields(Union union, DataTypeManager dtm,
                                    List<Map<String, String>> fields) {
        // Remove all existing components
        while (union.getNumComponents() > 0) {
            union.delete(0);
        }

        for (Map<String, String> field : fields) {
            String fieldName = field.get("name");
            String fieldType = field.get("type");
            String lengthStr = field.get("length");

            DataType fieldDt = requireDataType(dtm, fieldType, fieldName);
            int fieldLen = (lengthStr != null) ? Integer.parseInt(lengthStr) : fieldDt.getLength();
            if (fieldLen <= 0) fieldLen = 1;

            union.add(fieldDt, fieldLen, fieldName, null);
        }
    }

    private String deleteDataType(String kind, String path) {
        if (path == null || path.isEmpty()) {
            return dtOpError("path parameter is required");
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return dtOpError("No program loaded");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        DataType existing = dtm.getDataType(path);
        if (existing == null) {
            return dtOpError("DataType not found at path: " + path);
        }

        final String dtPath = existing.getPathName();
        final String dtKind = (existing instanceof Union) ? "union" : "structure";
        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete " + dtKind + " " + existing.getName());
                try {
                    dtm.remove(existing, TaskMonitor.DUMMY);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error deleting datatype", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to delete datatype on Swing thread", e);
            return dtOpError("Swing thread error: " + e.getMessage());
        }

        if (!success.get()) {
            return dtOpError("Failed to delete datatype at " + dtPath);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"datatype\":{");
        appendJsonField(sb, "kind", dtKind);
        appendJsonField(sb, "path", dtPath);
        trimTrailingComma(sb);
        sb.append("}}");
        return sb.toString();
    }

    private String serializeDataType(DataType dt, String kind) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ok\":true,\"datatype\":{");
        appendJsonField(sb, "kind", kind);
        appendJsonField(sb, "name", dt.getName());
        String catPath = dt.getCategoryPath().getPath();
        appendJsonField(sb, "category", catPath);
        appendJsonField(sb, "path", dt.getPathName());
        sb.append("\"size\":").append(dt.getLength()).append(',');

        sb.append("\"fields\":[");
        if (dt instanceof Structure) {
            Structure struct = (Structure) dt;
            boolean first = true;
            for (var comp : struct.getDefinedComponents()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('{');
                appendJsonField(sb, "name", comp.getFieldName());
                appendJsonField(sb, "type", comp.getDataType().getName());
                sb.append("\"offset\":").append(comp.getOffset()).append(',');
                sb.append("\"length\":").append(comp.getLength());
                sb.append('}');
            }
        } else if (dt instanceof Union) {
            Union union = (Union) dt;
            boolean first = true;
            for (var comp : union.getDefinedComponents()) {
                if (!first) sb.append(',');
                first = false;
                sb.append('{');
                appendJsonField(sb, "name", comp.getFieldName());
                appendJsonField(sb, "type", comp.getDataType().getName());
                sb.append("\"length\":").append(comp.getLength());
                sb.append('}');
            }
        }
        sb.append(']');

        sb.append("}}");
        return sb.toString();
    }

    private String dtOpError(String message) {
        return "{\"ok\":false,\"error\":\"" + jsonEscape(message) + "\"}";
    }

    private List<Map<String, String>> parseFieldsJson(String fieldsJson) {
        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return null;
        }
        try {
            // Minimal JSON array parser for field objects
            // Expected format: [{"name":"x","type":"int","offset":0},...]
            List<Map<String, String>> result = new ArrayList<>();
            fieldsJson = fieldsJson.trim();
            if (!fieldsJson.startsWith("[") || !fieldsJson.endsWith("]")) {
                return null;
            }
            // Strip outer brackets
            String inner = fieldsJson.substring(1, fieldsJson.length() - 1).trim();
            if (inner.isEmpty()) {
                return result;
            }

            // Split on top-level commas between objects
            List<String> objects = splitJsonObjects(inner);
            for (String obj : objects) {
                obj = obj.trim();
                if (!obj.startsWith("{") || !obj.endsWith("}")) {
                    continue;
                }
                Map<String, String> fieldMap = parseJsonObject(obj);
                if (fieldMap != null && fieldMap.containsKey("name") && fieldMap.containsKey("type")) {
                    result.add(fieldMap);
                }
            }
            return result;
        } catch (Exception e) {
            Msg.error(this, "Error parsing fields JSON", e);
            return null;
        }
    }

    private List<String> splitJsonObjects(String inner) {
        List<String> objects = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < inner.length(); i++) {
            char c = inner.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') depth--;
            else if (c == ',' && depth == 0) {
                objects.add(inner.substring(start, i));
                start = i + 1;
            }
        }
        if (start < inner.length()) {
            objects.add(inner.substring(start));
        }
        return objects;
    }

    private Map<String, String> parseJsonObject(String obj) {
        // Strip braces
        String content = obj.substring(1, obj.length() - 1).trim();
        Map<String, String> map = new HashMap<>();

        // Parse key-value pairs, handling quoted strings and numbers
        int i = 0;
        while (i < content.length()) {
            // Skip whitespace and commas
            while (i < content.length() && (content.charAt(i) == ' ' || content.charAt(i) == ','
                    || content.charAt(i) == '\n' || content.charAt(i) == '\r' || content.charAt(i) == '\t')) {
                i++;
            }
            if (i >= content.length()) break;

            // Parse key (expect quoted string)
            if (content.charAt(i) != '"') break;
            i++; // skip opening quote
            int keyStart = i;
            while (i < content.length() && content.charAt(i) != '"') i++;
            String key = content.substring(keyStart, i);
            i++; // skip closing quote

            // Skip colon and whitespace
            while (i < content.length() && (content.charAt(i) == ':' || content.charAt(i) == ' ')) i++;
            if (i >= content.length()) break;

            // Parse value
            String value;
            if (content.charAt(i) == '"') {
                // String value
                i++; // skip opening quote
                StringBuilder valBuf = new StringBuilder();
                while (i < content.length() && content.charAt(i) != '"') {
                    if (content.charAt(i) == '\\' && i + 1 < content.length()) {
                        i++; // skip escape char
                    }
                    valBuf.append(content.charAt(i));
                    i++;
                }
                value = valBuf.toString();
                i++; // skip closing quote
            } else {
                // Number or literal value
                int valStart = i;
                while (i < content.length() && content.charAt(i) != ',' && content.charAt(i) != '}'
                        && content.charAt(i) != ' ') {
                    i++;
                }
                value = content.substring(valStart, i).trim();
            }
            map.put(key, value);
        }
        return map;
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

            // Only when the base exists: "PacketHeader" is not a pointer to
            // "acketHeader", and an unknown base used to become void* silently.
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }
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

                // Unknown.  This used to return int with a log warning, so a
                // structure field typed "uint8_t" became an int and the call
                // reported success.  The caller decides; see requireDataType.
                return null;
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // One pass covers both: the search already falls back to a match that
        // ignores case.  The second, lowercased scan never found anything new.
        return searchByNameInAllCategories(dtm, typeName);
    }

    /**
     * A structure or union field's type, or an exception naming it.  Thrown
     * inside the caller's transaction, it rolls the whole operation back and
     * reaches the response as "Failed to create ...: unknown data type ...".
     */
    private DataType requireDataType(DataTypeManager dtm, String typeName, String fieldName) {
        DataType dataType = typeName == null ? null : resolveDataType(dtm, typeName);
        if (dataType == null) {
            throw new IllegalArgumentException(
                "unknown data type '" + typeName + "' for field '" + fieldName + "'");
        }
        return dataType;
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // An exact match wins wherever it sits; a match ignoring case is only
        // the fallback.  The old loop returned whichever came first, so "Foo"
        // could resolve to an earlier "FOO" while "Foo" itself existed.
        DataType ignoringCase = null;
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
            if (ignoringCase == null && dt.getName().equalsIgnoreCase(name)) {
                ignoringCase = dt;
            }
        }
        return ignoringCase;
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
        String safeMessage = (message == null || message.isEmpty()) ? "unexpected error" : message;
        return "{\"error\":\"" + jsonEscape(safeMessage) + "\",\"status\":\"error\"}";
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

        final int inspectionCap = 500_000;

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
            TaskMonitor monitor = new ConsoleTaskMonitor();

            List<String> pageItems = new ArrayList<>();
            int matchIndex = 0;
            boolean hasMore = false;
            int inspected = 0;
            boolean inspectionLimitHit = false;
            boolean cancelled = false;

            while (instructions.hasNext()) {
                if (monitor.isCancelled()) {
                    cancelled = true;
                    break;
                }

                Instruction instr = instructions.next();
                inspected++;
                if (pageItems.size() < resolved.limit() && inspected >= inspectionCap) {
                    inspectionLimitHit = true;
                    break;
                }
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

                if (pageItems.size() < resolved.limit() && inspected >= inspectionCap) {
                    inspectionLimitHit = true;
                    break;
                }
            }

            CursorPager.CursorPage page = CursorPager.buildPage(resolved, pageItems, hasMore);
            if ((inspectionLimitHit || cancelled) && pageItems.size() < resolved.limit()) {
                String errorMessage = inspectionLimitHit
                    ? "inspection cap of " + inspectionCap + " instructions reached before completing the page"
                    : "search cancelled after inspecting " + inspected + " instructions";
                return CursorPager.toJson(page, this::jsonEscape, errorMessage);
            }
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
        return handleFunctionsInRange(minStr, maxStr, false);
    }

    /**
     * List functions in a range.
     *
     * <p>With {@code extended} the line carries what the name alone cannot say:
     * the span the body reaches across, whether the entry is a thunk -- Ghidra
     * names a thunk after its target, so the same name legitimately appears
     * twice in one range -- and the individual chunks of a body that is not
     * contiguous. Without it the format is unchanged, because an older bridge
     * parses the token after the address as the size and nothing else.
     */
    private String handleFunctionsInRange(String minStr, String maxStr, boolean extended) {
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
                ghidra.program.model.listing.Function func = functions.next();
                String name = func.getName();
                Address entryPoint = func.getEntryPoint();
                AddressSetView body = func.getBody();

                // Bytes belonging to the body. Interior data -- a constant pool
                // between two instructions -- is not counted here, which is why
                // this can be smaller than the span below.
                long size = body.getNumAddresses();

                StringBuilder line = new StringBuilder();
                line.append(name).append(" @ ").append(entryPoint);
                if (size > 0) {
                    line.append(' ').append(size);
                }
                if (extended) {
                    appendExtendedFields(line, func, body);
                }
                results.add(line.toString());
            }

            // Already sorted by address (forward iteration)
            return results.isEmpty() ? "" : String.join("\n", results);

        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * {@code /functionsInRange?fmt=json}: the extended fields as data, so the
     * bridge stops splitting "name @ addr size span=..." apart (rework stage
     * 8d).  Optional fields appear only where they say something, exactly as
     * in the text form: a thunk target for a thunk, chunks for a body Ghidra
     * holds in more than one range.
     */
    private String functionsInRangeJson(String minStr, String maxStr) {
        Program program = getCurrentProgram();
        if (program == null) return errorResponse("no program loaded");
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

            FunctionIterator functions =
                program.getFunctionManager().getFunctions(new AddressSet(minAddr, maxAddr), true);
            StringBuilder sb = new StringBuilder("{\"functions\":[");
            boolean first = true;
            while (functions.hasNext()) {
                ghidra.program.model.listing.Function func = functions.next();
                AddressSetView body = func.getBody();
                if (!first) sb.append(',');
                first = false;
                sb.append("{\"name\":\"").append(jsonEscape(func.getName())).append('"');
                sb.append(",\"address\":\"").append(hexAddress(func.getEntryPoint())).append('"');
                sb.append(",\"size\":").append(body.getNumAddresses());
                if (body.getMinAddress() != null && body.getMaxAddress() != null) {
                    sb.append(",\"span\":{\"start\":\"").append(hexAddress(body.getMinAddress()))
                        .append("\",\"end\":\"").append(hexAddress(body.getMaxAddress())).append("\"}");
                }
                if (func.isThunk()) {
                    sb.append(",\"thunk\":true");
                    ghidra.program.model.listing.Function thunked = func.getThunkedFunction(true);
                    // An external target has no address in this program; its
                    // offset in the EXTERNAL space would read as a real one
                    // (0x00000001).  The thunk stays a thunk, without a target.
                    if (thunked != null && !thunked.isExternal()
                            && thunked.getEntryPoint().isMemoryAddress()) {
                        sb.append(",\"thunk_to\":\"").append(hexAddress(thunked.getEntryPoint())).append('"');
                    }
                }
                List<AddressRange> ranges = new ArrayList<>();
                body.getAddressRanges().forEach(ranges::add);
                if (ranges.size() > 1) {
                    sb.append(",\"chunks\":[");
                    for (int i = 0; i < ranges.size(); i++) {
                        if (i > 0) sb.append(',');
                        sb.append("{\"start\":\"").append(hexAddress(ranges.get(i).getMinAddress()))
                            .append("\",\"end\":\"").append(hexAddress(ranges.get(i).getMaxAddress())).append("\"}");
                    }
                    sb.append(']');
                }
                sb.append('}');
            }
            return sb.append("]}").toString();
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * Append the fields that distinguish a function from its own thunk.
     *
     * <p>Each is emitted only when it says something: a span always, a thunk
     * target only for a thunk, and chunks only for a body that Ghidra holds in
     * more than one range.
     */
    private void appendExtendedFields(
            StringBuilder line,
            ghidra.program.model.listing.Function func,
            AddressSetView body) {
        Address bodyMin = body.getMinAddress();
        Address bodyMax = body.getMaxAddress();
        if (bodyMin != null && bodyMax != null) {
            line.append(" span=").append(bodyMin).append('-').append(bodyMax);
        }

        if (func.isThunk()) {
            ghidra.program.model.listing.Function thunked = func.getThunkedFunction(true);
            if (thunked != null) {
                line.append(" thunk=").append(thunked.getEntryPoint());
            }
        }

        List<String> chunks = new ArrayList<>();
        AddressRangeIterator ranges = body.getAddressRanges();
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            chunks.add(range.getMinAddress() + "-" + range.getMaxAddress());
        }
        if (chunks.size() > 1) {
            line.append(" chunks=").append(String.join(",", chunks));
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
     * {@code /disassembleAt?fmt=json}: the same instructions as the text form,
     * each as structured data (see {@link #instructionJson}).
     */
    private String disassembleAtJson(String addressStr, int count) {
        Program program = getCurrentProgram();
        if (program == null) return errorResponse("no program loaded");
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address parameter is required");

        int effectiveCount = Math.min(Math.max(count, 1), 128);
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return errorResponse("invalid address");
            }
            StringBuilder sb = new StringBuilder("{\"instructions\":[");
            InstructionIterator instructions = program.getListing().getInstructions(addr, true);
            int collected = 0;
            while (instructions.hasNext() && collected < effectiveCount) {
                if (collected > 0) sb.append(',');
                sb.append(instructionJson(program, instructions.next()));
                collected++;
            }
            return sb.append("]}").toString();
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * {@code /disassemble_function?fmt=json}: walks exactly what the text form
     * walks -- every instruction from the entry point up to the body's maximum
     * address -- so a bridge switching formats sees the same instructions.
     */
    private String disassembleFunctionJson(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return errorResponse("no program loaded");
        if (addressStr == null || addressStr.isEmpty()) return errorResponse("address parameter is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ghidra.program.model.listing.Function func = getFunctionForAddress(program, addr);
            if (func == null) return errorResponse("no function found at or containing address " + addressStr);

            Address end = func.getBody().getMaxAddress();
            StringBuilder sb = new StringBuilder("{");
            sb.append("\"function\":\"").append(hexAddress(func.getEntryPoint())).append("\",");
            sb.append("\"name\":\"").append(jsonEscape(func.getName())).append("\",");
            sb.append("\"instructions\":[");
            InstructionIterator instructions = program.getListing().getInstructions(func.getEntryPoint(), true);
            boolean first = true;
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break;
                }
                if (!first) sb.append(',');
                sb.append(instructionJson(program, instr));
                first = false;
            }
            return sb.append("]}").toString();
        } catch (Exception e) {
            return errorResponse(e.getMessage());
        }
    }

    /**
     * One instruction as structured data, read from the Ghidra API instead of
     * {@code toString()}, so the bridge stops reconstructing operands, flow and
     * pool words by regex (rework stage 8c).
     *
     * <p>{@code refs} are Ghidra's own references from this instruction.  They
     * include targets outside the memory map: constant propagation places
     * MMIO accesses on the load or store even when no block covers them,
     * measured on 0x002AF9C0.  {@code mapped} says which is which.  A READ
     * reference into the image also carries the 32-bit word stored there,
     * which for a PC-relative load is the value loaded.
     */
    private String instructionJson(Program program, Instruction instr) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"address\":\"").append(hexAddress(instr.getAddress())).append("\",");

        StringBuilder hexBytes = new StringBuilder();
        try {
            for (byte b : instr.getBytes()) {
                hexBytes.append(String.format("%02X", b & 0xFF));
            }
        } catch (MemoryAccessException e) {
            hexBytes.setLength(0);
        }
        sb.append("\"bytes\":\"").append(hexBytes).append("\",");
        sb.append("\"mnemonic\":\"").append(jsonEscape(instr.getMnemonicString().toLowerCase())).append("\",");
        sb.append("\"text\":\"").append(jsonEscape(instr.toString())).append('"');

        String comment = program.getListing().getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
        if (comment != null) {
            sb.append(",\"comment\":\"").append(jsonEscape(comment)).append('"');
        }

        FlowType flowType = instr.getFlowType();
        String flow;
        if (flowType.isTerminal()) {
            flow = "return";
        } else if (flowType.isCall()) {
            flow = "call";
        } else if (flowType.isJump()) {
            flow = "jump";
        } else {
            flow = "fallthrough";
        }
        sb.append(",\"flow\":\"").append(flow).append('"');
        if (flowType.isConditional()) {
            sb.append(",\"conditional\":true");
        }
        if (flowType.isComputed()) {
            sb.append(",\"computed\":true");
        }
        Address[] flows = instr.getFlows();
        if (flows != null && flows.length > 0) {
            sb.append(",\"targets\":[");
            for (int i = 0; i < flows.length; i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(hexAddress(flows[i])).append('"');
            }
            sb.append(']');
        }

        sb.append(",\"operands\":[");
        for (int i = 0; i < instr.getNumOperands(); i++) {
            if (i > 0) sb.append(',');
            sb.append("{\"text\":\"").append(jsonEscape(instr.getDefaultOperandRepresentation(i))).append('"');
            sb.append(",\"type\":\"").append(jsonEscape(OperandType.toString(instr.getOperandType(i)).trim())).append('"');
            List<String> registers = new ArrayList<>();
            List<String> scalars = new ArrayList<>();
            List<String> addresses = new ArrayList<>();
            Object[] objects = instr.getOpObjects(i);
            if (objects != null) {
                for (Object obj : objects) {
                    if (obj instanceof Register reg) {
                        registers.add(reg.getName().toLowerCase());
                    } else if (obj instanceof Scalar scalar) {
                        // Ghidra's own signedness, the same that renders #0xb0000000
                        // unsigned and [sp,#-0x4] signed in the listing text.
                        long value = scalar.isSigned() ? scalar.getSignedValue() : scalar.getUnsignedValue();
                        scalars.add(value < 0 ? "-0x" + Long.toHexString(-value) : "0x" + Long.toHexString(value));
                    } else if (obj instanceof Address opAddr) {
                        addresses.add(hexAddress(opAddr));
                    }
                }
            }
            appendStringArray(sb, "registers", registers);
            appendStringArray(sb, "scalars", scalars);
            appendStringArray(sb, "addresses", addresses);
            sb.append('}');
        }
        sb.append(']');

        Reference[] refs = instr.getReferencesFrom();
        sb.append(",\"refs\":[");
        for (int i = 0; i < refs.length; i++) {
            Reference ref = refs[i];
            Address to = ref.getToAddress();
            RefType refType = ref.getReferenceType();
            boolean mapped = to.isMemoryAddress() && program.getMemory().contains(to);
            if (i > 0) sb.append(',');
            sb.append("{\"to\":\"").append(hexAddress(to)).append('"');
            if (!to.isMemoryAddress()) {
                sb.append(",\"space\":\"").append(jsonEscape(to.getAddressSpace().getName())).append('"');
            }
            sb.append(",\"type\":\"").append(jsonEscape(refType.getName())).append('"');
            sb.append(",\"op\":").append(ref.getOperandIndex());
            sb.append(",\"mapped\":").append(mapped);
            if (mapped && refType.isRead()) {
                try {
                    long word = program.getMemory().getInt(to) & 0xFFFFFFFFL;
                    sb.append(",\"word\":\"").append(String.format("0x%08x", word)).append('"');
                } catch (MemoryAccessException e) {
                    sb.append(",\"word_unreadable\":true");
                }
            }
            sb.append('}');
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String hexAddress(Address address) {
        return String.format("0x%08x", address.getOffset());
    }

    private void appendStringArray(StringBuilder sb, String key, List<String> values) {
        if (values.isEmpty()) {
            return;
        }
        sb.append(",\"").append(key).append("\":[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(jsonEscape(values.get(i))).append('"');
        }
        sb.append(']');
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

    @Override
    public boolean hasProgramContext() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null && pm.getCurrentProgram() != null;
    }

    @Override
    public boolean hasProgramManagerService() {
        return tool.getService(ProgramManager.class) != null;
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private String getCurrentProgramStatus() {
        ProgramStatusSnapshot snapshot = statusTracker.snapshot();
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendJsonField(sb, "domain_file_id", snapshot.domainFileId);
        sb.append("\"locked\":").append(snapshot.locked).append(',');
        appendJsonField(sb, "state", snapshot.state.name());
        sb.append("\"state_duration_seconds\":").append(snapshot.stateDurationSeconds).append(',');
        appendWarnings(sb, snapshot.warnings == null ? List.of() : snapshot.warnings);
        trimTrailingComma(sb);
        sb.append('}');
        return sb.toString();
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

    private String openProgram(String domainFileIdParam, String path) {
        return openProgram(domainFileIdParam, path, null);
    }

    private String openProgram(String domainFileIdParam, String path, String onDirty) {
        List<String> warnings = new ArrayList<>();

        if ((path == null || path.isEmpty()) && (domainFileIdParam == null || domainFileIdParam.isEmpty())) {
            return errorResponse("path or domain_file_id parameter is required");
        }

        // Check dirty state before switching programs
        if (!checkDirtyStateBeforeSwitch(onDirty, warnings)) {
            return openProgramResponse("error",
                "Cannot switch programs: current program has unsaved changes",
                null, warnings);
        }

        Project project = tool.getProject();
        if (project == null) {
            return errorResponse("No project loaded");
        }

        ProjectData projectData = project.getProjectData();
        if (projectData == null) {
            return errorResponse("Project data unavailable");
        }

        DomainFile file = resolveDomainFile(projectData, domainFileIdParam, path, warnings);
        if (file == null) {
            return errorResponse("File not found for provided path or ID");
        }

        statusTracker.markLoading(file, warnings);
        ProgramManager pm = ensureProgramManager(file, warnings);
        if (pm == null) {
            return openProgramResponse("error",
                "ProgramManager service unavailable; launch a program-capable tool manually",
                file, warnings);
        }

        if (!invokeOpenProgram(pm, file, warnings)) {
            return openProgramResponse("error",
                "ProgramManager missing openProgram(DomainFile) support",
                file, warnings);
        }

        // Ensure the tracker transitions out of LOADING even when the program
        // is already open and Ghidra does not fire programOpened/programActivated
        // callbacks.  Without this, the state stays LOADING permanently and all
        // subsequent operations are blocked with 503 UNAVAILABLE.
        Program currentProgram = pm.getCurrentProgram();
        if (currentProgram != null) {
            statusTracker.onProgramActivated(currentProgram);
        }

        statusTracker.applyWarnings(warnings);

        return openProgramResponse("ok", null, file, warnings);
    }

    private ProgramManager ensureProgramManager(DomainFile file, List<String> warnings) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) {
            return pm;
        }

        PluginTool launchedTool = launchProgramCapableTool(file, warnings);
        if (launchedTool == null) {
            return null;
        }

        ProgramManager launchedPm = launchedTool.getService(ProgramManager.class);
        if (launchedPm == null) {
            warnings.add("Program-capable tool launched but ProgramManager service remains unavailable");
        }

        return launchedPm;
    }

    private PluginTool launchProgramCapableTool(DomainFile file, List<String> warnings) {
        ToolServices toolServices = tool.getToolServices();
        if (toolServices == null) {
            warnings.add("ToolServices unavailable; cannot auto-open a program tool");
            return null;
        }

        // Create a collection with the single file
        Collection<DomainFile> files = Collections.singletonList(file);

        // Try launching CodeBrowser specifically (best for program analysis)
        try {
            PluginTool launched = toolServices.launchTool("CodeBrowser", files);
            if (launched != null) {
                return launched;
            }
        } catch (Exception e) {
            warnings.add("Failed to launch CodeBrowser: " + e.getMessage());
        }

        // Fallback to default tool
        try {
            PluginTool launched = toolServices.launchDefaultTool(files);
            if (launched != null) {
                return launched;
            }
        } catch (Exception e) {
            warnings.add("Failed to launch default tool: " + e.getMessage());
        }

        warnings.add("ToolServices did not return a PluginTool when launching a program tool");
        return null;
    }

    private boolean invokeOpenProgram(ProgramManager pm, DomainFile file, List<String> warnings) {
        try {
            pm.openProgram(file);
            return true;
        }
        catch (Exception e) {
            warnings.add("Failed to open program: " + e.getMessage());
            return false;
        }
    }

    /**
     * Check if the current program has unsaved changes.
     * @return JSON response with dirty state information
     */
    private String checkProgramDirtyState() {
        Program program = getCurrentProgram();
        if (program == null) {
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            appendJsonField(sb, "status", "ok");
            appendJsonField(sb, "changed", "false");
            appendJsonField(sb, "can_save", "false");
            sb.append("\"message\":\"No program currently loaded\"");
            sb.append('}');
            return sb.toString();
        }

        boolean isChanged = program.isChanged();
        boolean canSave = program.canSave();
        String programName = program.getName();

        StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendJsonField(sb, "status", "ok");
        appendJsonField(sb, "program_name", programName);
        appendJsonField(sb, "changed", String.valueOf(isChanged));
        appendJsonField(sb, "can_save", String.valueOf(canSave));
        if (isChanged) {
            sb.append("\"message\":\"Program has unsaved changes\"");
        } else {
            sb.append("\"message\":\"Program has no unsaved changes\"");
        }
        sb.append('}');
        return sb.toString();
    }

    /**
     * Save the current program with a description.
     * @param description Description of changes being saved
     * @return JSON response with save result
     */
    private String saveCurrentProgram(String description) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorResponse("No program currently loaded");
        }

        if (!program.canSave()) {
            return errorResponse("Program cannot be saved (not the owner or file is read-only)");
        }

        if (!program.isChanged()) {
            StringBuilder sb = new StringBuilder();
            sb.append('{');
            appendJsonField(sb, "status", "ok");
            appendJsonField(sb, "saved", "false");
            sb.append("\"message\":\"Program has no unsaved changes\"");
            sb.append('}');
            return sb.toString();
        }

        try {
            String saveDescription = (description == null || description.isEmpty())
                ? "Saved via GhidraMCP"
                : description;
            program.save(saveDescription, new ghidra.util.task.TaskMonitorAdapter());

            StringBuilder sb = new StringBuilder();
            sb.append('{');
            appendJsonField(sb, "status", "ok");
            appendJsonField(sb, "saved", "true");
            appendJsonField(sb, "program_name", program.getName());
            sb.append("\"message\":\"Program saved successfully\"");
            sb.append('}');
            return sb.toString();
        } catch (Exception e) {
            return errorResponse("Failed to save program: " + e.getMessage());
        }
    }

    /**
     * Check dirty state before opening a new program.
     * @param onDirty Action to take if current program is dirty: "error", "save", "discard"
     * @param warnings List to accumulate warnings
     * @return true if safe to proceed, false if should abort
     */
    private boolean checkDirtyStateBeforeSwitch(String onDirty, List<String> warnings) {
        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            return true; // No current program, safe to proceed
        }

        if (!currentProgram.isChanged()) {
            return true; // No unsaved changes, safe to proceed
        }

        // Program has unsaved changes - handle based on onDirty flag
        String action = (onDirty == null || onDirty.isEmpty()) ? "error" : onDirty.toLowerCase();

        switch (action) {
            case "save":
                if (!currentProgram.canSave()) {
                    warnings.add("Current program has unsaved changes but cannot be saved (not owner or read-only)");
                    return false;
                }
                try {
                    currentProgram.save("Auto-save before program switch", new ghidra.util.task.TaskMonitorAdapter());
                    warnings.add("Saved current program before switching");
                    return true;
                } catch (Exception e) {
                    warnings.add("Failed to save current program: " + e.getMessage());
                    return false;
                }

            case "discard":
                warnings.add("Discarding unsaved changes in current program");
                return true;

            case "error":
            default:
                warnings.add("Current program has unsaved changes - use on_dirty=save or on_dirty=discard to proceed");
                return false;
        }
    }

    private DomainFile resolveDomainFile(ProjectData projectData, String domainFileIdParam,
            String path, List<String> warnings) {

        DomainFile file = null;
        if (domainFileIdParam != null && !domainFileIdParam.isEmpty()) {
            file = findDomainFileById(projectData.getRootFolder(), domainFileIdParam);
            if (file == null) {
                warnings.add("No DomainFile found for ID " + domainFileIdParam);
            }
        }

        if (file == null && path != null && !path.isEmpty()) {
            file = projectData.getFile(path);
            if (file == null) {
                warnings.add("File not found at path: " + path);
            }
        }

        return file;
    }

    private DomainFile findDomainFileById(DomainFolder folder, String domainFileId) {
        for (DomainFile file : folder.getFiles()) {
            String fileId = file.getFileID();
            if (fileId != null && fileId.equals(domainFileId)) {
                return file;
            }
        }

        for (DomainFolder child : folder.getFolders()) {
            DomainFile found = findDomainFileById(child, domainFileId);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

    private String openProgramResponse(String status, String message, DomainFile file,
            List<String> warnings) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendJsonField(sb, "status", status);
        appendJsonField(sb, "path", file != null ? file.getPathname() : null);
        appendJsonField(sb, "domain_file_id", file != null ? file.getFileID() : null);
        appendJsonField(sb, "name", file != null ? file.getName() : null);
        if (message != null && !message.isEmpty()) {
            appendJsonField(sb, "message", message);
        }
        appendWarnings(sb, warnings);
        trimTrailingComma(sb);
        sb.append('}');
        return sb.toString();
    }

    private void appendWarnings(StringBuilder sb, List<String> warnings) {
        sb.append("\"warnings\": [");
        for (int i = 0; i < warnings.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(jsonEscape(warnings.get(i))).append('"');
        }
        sb.append(']').append(',');
    }

    private void trimTrailingComma(StringBuilder sb) {
        int length = sb.length();
        if (length > 0 && sb.charAt(length - 1) == ',') {
            sb.setLength(length - 1);
        }
    }

    private String getProjectFiles() {
        Project project = tool.getProject();
        if (project == null) {
            return errorResponse("No project loaded");
        }

        ProjectData projectData = project.getProjectData();
        if (projectData == null) {
            return errorResponse("Project data unavailable");
        }

        DomainFolder rootFolder = projectData.getRootFolder();
        if (rootFolder == null) {
            return errorResponse("Project root folder not found");
        }

        List<String> entries = new ArrayList<>();
        collectProjectEntries(rootFolder, entries);

        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(entries.get(i));
        }
        sb.append(']');
        return sb.toString();
    }

    private void collectProjectEntries(DomainFolder folder, List<String> entries) {
        entries.add(buildFolderEntry(folder));

        for (DomainFile file : folder.getFiles()) {
            entries.add(buildFileEntry(file));
        }

        for (DomainFolder child : folder.getFolders()) {
            collectProjectEntries(child, entries);
        }
    }

    private String buildFolderEntry(DomainFolder folder) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendJsonField(sb, "domain_file_id", (Number) null);
        appendJsonField(sb, "name", folder.getName());
        appendJsonField(sb, "path", folder.getPathname());
        appendJsonField(sb, "type", "Folder");
        sb.append("\"size\":null");
        sb.append('}');
        return sb.toString();
    }

    private String buildFileEntry(DomainFile file) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        appendJsonField(sb, "domain_file_id", file.getFileID());
        appendJsonField(sb, "name", file.getName());
        appendJsonField(sb, "path", file.getPathname());
        appendJsonField(sb, "type", file.getContentType());
        Long size = getDomainFileSize(file);
        sb.append("\"size\":");
        if (size == null) {
            sb.append("null");
        }
        else {
            sb.append(size);
        }
        sb.append('}');
        return sb.toString();
    }

    private Long getDomainFileSize(DomainFile file) {
        try {
            Method method = file.getClass().getMethod("getSize");
            Object value = method.invoke(file);
            if (value instanceof Number) {
                return ((Number) value).longValue();
            }
        }
        catch (Exception ignored) {
            // Ignore and fallback to null
        }
        return null;
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
            List<FileBytes> sourceFiles = program.getMemory().getAllFileBytes();
            appendSourceFiles(sb, sourceFiles);
            appendMemoryBlocks(sb, program, sourceFiles);
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

    private void appendJsonField(StringBuilder sb, String key, Number value) {
        sb.append('"').append(key).append('"').append(':');
        if (value == null) {
            sb.append("null");
        }
        else {
            sb.append(value);
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
                ghidra.program.model.listing.Function func = program.getListing().getFunctionAt(base);
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

    /**
     * Imported source files with two digests each: the bytes as imported and the
     * bytes as they stand now. They differ as soon as anything in the database
     * patched program bytes. Pattern taken from REA's Ghidra bridge (MIT).
     */
    private void appendSourceFiles(StringBuilder sb, List<FileBytes> files) {
        sb.append("\"source_files\":[");
        for (int i = 0; i < files.size(); i++) {
            FileBytes file = files.get(i);
            if (i > 0) {
                sb.append(',');
            }
            String original = hashFileBytes(file, false);
            String modified = hashFileBytes(file, true);
            sb.append('{');
            appendJsonField(sb, "name", file.getFilename());
            sb.append("\"size\":").append(file.getSize()).append(',');
            appendJsonField(sb, "original_sha256", original);
            appendJsonField(sb, "modified_sha256", modified);
            if (original == null || modified == null) {
                sb.append("\"patched\":null");
            }
            else {
                sb.append("\"patched\":").append(!original.equals(modified));
            }
            sb.append('}');
        }
        sb.append("],");
    }

    private String hashFileBytes(FileBytes source, boolean modified) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] chunk = new byte[65536];
            long size = source.getSize();
            for (long offset = 0; offset < size;) {
                int length = (int) Math.min(chunk.length, size - offset);
                int read = modified
                    ? source.getModifiedBytes(offset, chunk, 0, length)
                    : source.getOriginalBytes(offset, chunk, 0, length);
                if (read != length) {
                    return null;
                }
                digest.update(chunk, 0, read);
                offset += read;
            }
            return HexFormat.of().formatHex(digest.digest());
        }
        catch (Exception ex) {
            Msg.warn(this, "Could not hash file bytes " + source.getFilename(), ex);
            return null;
        }
    }

    private String hashBlock(Program program, MemoryBlock block) {
        if (!block.isInitialized()) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] chunk = new byte[65536];
            long size = block.getSize();
            for (long offset = 0; offset < size;) {
                int count = (int) Math.min(chunk.length, size - offset);
                int read = program.getMemory().getBytes(block.getStart().add(offset), chunk, 0, count);
                if (read != count) {
                    return null;
                }
                digest.update(chunk, 0, read);
                offset += read;
            }
            return HexFormat.of().formatHex(digest.digest());
        }
        catch (Exception ex) {
            Msg.warn(this, "Could not hash block " + block.getName(), ex);
            return null;
        }
    }

    private void appendMemoryBlocks(StringBuilder sb, Program program, List<FileBytes> sourceFiles) {
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
            sb.append("\"initialized\":").append(block.isInitialized()).append(',');
            // A block backed by exactly one stretch of one source file gets that
            // file and offset; anything else (no file, several pieces) gets null.
            Integer sourceIndex = null;
            Long fileOffset = null;
            List<MemoryBlockSourceInfo> infos = block.getSourceInfos();
            if (infos != null && infos.size() == 1) {
                MemoryBlockSourceInfo info = infos.get(0);
                FileBytes backing = info.getFileBytes().orElse(null);
                if (backing != null && info.getFileBytesOffset() >= 0) {
                    int index = sourceFiles.indexOf(backing);
                    if (index >= 0) {
                        sourceIndex = index;
                        fileOffset = info.getFileBytesOffset();
                    }
                }
            }
            appendJsonField(sb, "source_file_index", sourceIndex);
            appendJsonField(sb, "file_offset", fileOffset);
            String blockHash = hashBlock(program, block);
            sb.append("\"sha256\":");
            sb.append(blockHash == null ? "null" : '"' + blockHash + '"');
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
        CONTEXT_REGISTRY.unregister(this);
        if (CONTEXT_REGISTRY.isEmpty() && server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            SERVER_STATE.stopIfIdle(true);
            server = null;
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
