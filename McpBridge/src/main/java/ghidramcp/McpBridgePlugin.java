package ghidramcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.Map;

@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = "McpBridge",
        category = "Integration",
        shortDescription = "MCP Bridge",
        description = "Exposes a localhost HTTP bridge for MCP server integration."
)
public class McpBridgePlugin extends Plugin {

    private HttpServer server;

    public McpBridgePlugin(PluginTool tool) {
        super(tool);
        startServer();
    }

    private Program getCurrentProgramSafe() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }
        return pm.getCurrentProgram();
    }

    private void startServer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 17664), 0);

            server.createContext("/health", exchange -> {
                respondJson(exchange, 200, "{\"ok\":true}");
            });

            server.createContext("/program", exchange -> {
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }
                String name = escapeJson(p.getName());
                String imageBase = p.getImageBase().toString();
                respondJson(exchange, 200,
                        "{\"name\":\"" + name + "\",\"imageBase\":\"" + imageBase + "\"}");
            });

            server.createContext("/functions", exchange -> {
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"functions\":[");
                FunctionIterator it = p.getFunctionManager().getFunctions(true);

                boolean first = true;
                int count = 0;
                while (it.hasNext() && count < 5000) {
                    Function f = it.next();
                    if (!first) {
                        sb.append(",");
                    }
                    first = false;

                    String entry = f.getEntryPoint().toString();
                    String fname = escapeJson(f.getName());
                    sb.append("{\"entry\":\"").append(entry).append("\",\"name\":\"").append(fname).append("\"}");
                    count++;
                }
                sb.append("]}");

                respondJson(exchange, 200, sb.toString());
            });

            server.createContext("/functionContext", exchange -> {
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respondJson(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }

                Map<String, String> req = parseJsonObjectFlat(readBody(exchange));
                Address entry = parseAddress(p, req.get("entry"));
                boolean includeDecompile = parseBool(req.get("includeDecompile"), false);
                int decompileTimeoutSec = clampInt(parseInt(req.get("decompileTimeoutSec"), 10), 1, 120);
                if (entry == null) {
                    respondJson(exchange, 400, "{\"error\":\"Missing entry\"}");
                    return;
                }

                Function f = p.getFunctionManager().getFunctionAt(entry);
                if (f == null) {
                    respondJson(exchange, 404, "{\"error\":\"No function at entry\"}");
                    return;
                }

                TaskMonitor monitor = TaskMonitor.DUMMY;
                FunctionContext ctx = buildFunctionContext(p, f, monitor, includeDecompile, decompileTimeoutSec);
                respondJson(exchange, 200, ctx.toJson());
            });

            server.createContext("/scanAntiDebug", exchange -> {
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }
                int maxFindings = 500;
                if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    Map<String, String> req = parseJsonObjectFlat(readBody(exchange));
                    maxFindings = clampInt(parseInt(req.get("maxFindings"), 500), 1, 5000);
                }

                TaskMonitor monitor = TaskMonitor.DUMMY;
                List<AntiDebugFinding> findings = scanAntiDebug(p, monitor, maxFindings);
                StringBuilder sb = new StringBuilder();
                sb.append("{\"findings\":[");
                boolean first = true;
                for (AntiDebugFinding f : findings) {
                    if (!first) sb.append(",");
                    first = false;
                    sb.append(f.toJson());
                }
                sb.append("],\"total\":").append(findings.size()).append("}");
                respondJson(exchange, 200, sb.toString());
            });

            server.createContext("/autoRenameFunctions", exchange -> {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respondJson(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }

                Map<String, String> req = parseJsonObjectFlat(readBody(exchange));
                int limit = clampInt(parseInt(req.get("limit"), 200), 1, 5000);
                boolean onlyDefault = parseBool(req.get("onlyDefaultNames"), true);
                boolean dryRun = parseBool(req.get("dryRun"), true);
                int minScore = clampInt(parseInt(req.get("minScore"), 60), 0, 100);
                int decompileTimeoutSec = clampInt(parseInt(req.get("decompileTimeoutSec"), 10), 1, 120);

                TaskMonitor monitor = TaskMonitor.DUMMY;
                AutoRenameResult result = autoRenameFunctions(p, monitor, limit, onlyDefault, dryRun, minScore, decompileTimeoutSec);
                respondJson(exchange, 200, result.toJson());
            });

            server.createContext("/renameFunction", exchange -> {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respondJson(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }

                Map<String, String> req = parseJsonObjectFlat(readBody(exchange));
                Address entry = parseAddress(p, req.get("entry"));
                String newName = req.getOrDefault("newName", "").trim();
                if (entry == null || newName.isEmpty()) {
                    respondJson(exchange, 400, "{\"error\":\"Missing entry or newName\"}");
                    return;
                }

                FunctionManager fm = p.getFunctionManager();
                Function f = fm.getFunctionAt(entry);
                if (f == null) {
                    respondJson(exchange, 404, "{\"error\":\"No function at entry\"}");
                    return;
                }

                int tx = p.startTransaction("MCP Rename Function");
                try {
                    String oldName = f.getName();
                    f.setName(newName, SourceType.USER_DEFINED);
                    p.endTransaction(tx, true);
                    respondJson(exchange, 200, "{\"ok\":true,\"oldName\":\"" + escapeJson(oldName) + "\",\"newName\":\"" + escapeJson(newName) + "\"}");
                } catch (Exception e) {
                    p.endTransaction(tx, false);
                    respondJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
                }
            });

            server.createContext("/patchBytes", exchange -> {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respondJson(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }

                Map<String, String> req = parseJsonObjectFlat(readBody(exchange));
                Address addr = parseAddress(p, req.get("address"));
                byte[] patch = parseHexBytes(req.get("bytesHex"));
                if (addr == null || patch.length == 0) {
                    respondJson(exchange, 400, "{\"error\":\"Missing address or bytesHex\"}");
                    return;
                }

                Memory mem = p.getMemory();
                byte[] before = new byte[patch.length];

                int tx = p.startTransaction("MCP Patch Bytes");
                try {
                    mem.getBytes(addr, before);
                    mem.setBytes(addr, patch);
                    p.endTransaction(tx, true);

                    respondJson(exchange, 200,
                            "{\"ok\":true,\"address\":\"" + addr + "\",\"before\":\"" + toHex(before) + "\",\"after\":\"" + toHex(patch) + "\"}");
                } catch (MemoryAccessException e) {
                    p.endTransaction(tx, false);
                    respondJson(exchange, 500, "{\"error\":\"Memory access failed: " + escapeJson(e.getMessage()) + "\"}");
                } catch (Exception e) {
                    p.endTransaction(tx, false);
                    respondJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
                }
            });

            server.createContext("/setComment", exchange -> {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    respondJson(exchange, 405, "{\"error\":\"POST required\"}");
                    return;
                }
                Program p = getCurrentProgramSafe();
                if (p == null) {
                    respondJson(exchange, 400, "{\"error\":\"No program open\"}");
                    return;
                }

                Map<String, String> req = parseJsonObjectFlat(readBody(exchange));
                Address addr = parseAddress(p, req.get("address"));
                String comment = req.getOrDefault("comment", "");
                if (addr == null) {
                    respondJson(exchange, 400, "{\"error\":\"Missing address\"}");
                    return;
                }

                Listing listing = p.getListing();
                CodeUnit cu = listing.getCodeUnitAt(addr);
                if (cu == null) {
                    respondJson(exchange, 404, "{\"error\":\"No code unit at address\"}");
                    return;
                }

                int tx = p.startTransaction("MCP Set Comment");
                try {
                    cu.setComment(CodeUnit.EOL_COMMENT, comment);
                    p.endTransaction(tx, true);
                    respondJson(exchange, 200, "{\"ok\":true}");
                } catch (Exception e) {
                    p.endTransaction(tx, false);
                    respondJson(exchange, 500, "{\"error\":\"" + escapeJson(e.getMessage()) + "\"}");
                }
            });

            server.setExecutor(null);
            server.start();
            Msg.info(this, "MCP Bridge listening on http://127.0.0.1:17664");
        } catch (IOException e) {
            Msg.error(this, "Failed to start MCP Bridge server", e);
        }
    }

    private static void respondJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        // Must escape control characters to keep JSON valid (e.g., decompile text has newlines).
        StringBuilder out = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                // These can break JS/JSON consumers in some contexts; safe to escape.
                case '\u2028':
                    out.append("\\u2028");
                    break;
                case '\u2029':
                    out.append("\\u2029");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                    break;
            }
        }
        return out.toString();
    }

    @Override
    public void dispose() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        super.dispose();
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseJsonObjectFlat(String body) {
        Map<String, String> m = new HashMap<>();
        if (body == null) {
            return m;
        }
        String s = body.trim();
        if (s.startsWith("{")) {
            s = s.substring(1);
        }
        if (s.endsWith("}")) {
            s = s.substring(0, s.length() - 1);
        }

        boolean inStr = false;
        StringBuilder cur = new StringBuilder();
        java.util.List<String> parts = new java.util.ArrayList<>();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' && (i == 0 || s.charAt(i - 1) != '\\')) {
                inStr = !inStr;
            }
            if (c == ',' && !inStr) {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) {
            parts.add(cur.toString());
        }

        for (String p : parts) {
            String[] kv = p.split(":", 2);
            if (kv.length != 2) {
                continue;
            }
            String k = kv[0].trim();
            String v = kv[1].trim();
            k = stripQuotes(k);
            v = stripQuotes(v);
            m.put(k, v);
        }
        return m;
    }

    private static String stripQuotes(String s) {
        if (s == null) {
            return "";
        }
        s = s.trim();
        if (s.startsWith("\"") && s.endsWith("\"") && s.length() >= 2) {
            s = s.substring(1, s.length() - 1);
        }
        return s.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private Address parseAddress(Program p, String addrStr) {
        if (p == null || addrStr == null || addrStr.isBlank()) {
            return null;
        }
        return p.getAddressFactory().getAddress(addrStr.trim());
    }

    private static boolean parseBool(String s, boolean def) {
        if (s == null) return def;
        String v = s.trim().toLowerCase();
        if (v.equals("true") || v.equals("1") || v.equals("yes") || v.equals("y")) return true;
        if (v.equals("false") || v.equals("0") || v.equals("no") || v.equals("n")) return false;
        return def;
    }

    private static int parseInt(String s, int def) {
        if (s == null) return def;
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static int clampInt(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }

    private static byte[] parseHexBytes(String bytesHex) {
        if (bytesHex == null) {
            return new byte[0];
        }
        String s = bytesHex.replace("0x", "").replace(",", " ").replaceAll("\\s+", " ").trim();
        if (s.isEmpty()) {
            return new byte[0];
        }
        String[] parts = s.split(" ");
        byte[] out = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            out[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return out;
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(String.format("%02X", b[i]));
        }
        return sb.toString();
    }

    private static FunctionContext buildFunctionContext(
            Program p,
            Function f,
            TaskMonitor monitor,
            boolean includeDecompile,
            int decompileTimeoutSec
    ) {
        FunctionContext ctx = new FunctionContext();
        ctx.entry = f.getEntryPoint().toString();
        ctx.name = f.getName();
        ctx.isThunk = f.isThunk();
        ctx.isExternal = f.isExternal();
        try {
            ctx.prototype = f.getPrototypeString(true, true);
        } catch (Exception e) {
            ctx.prototype = f.getName();
        }

        // Called functions (direct call flows)
        Set<Address> seen = new HashSet<>();
        List<CalledFunction> called = new ArrayList<>();
        Listing listing = p.getListing();
        AddressSetView body = f.getBody();
        for (Instruction ins : listing.getInstructions(body, true)) {
            if (!ins.getFlowType().isCall()) continue;
            Address[] flows = ins.getFlows();
            if (flows == null || flows.length == 0) continue;
            Address target = flows[0];
            if (target == null || !seen.add(target)) continue;
            Function cf = p.getFunctionManager().getFunctionAt(target);
            if (cf == null) continue;
            CalledFunction c = new CalledFunction();
            c.entry = cf.getEntryPoint().toString();
            c.name = cf.getName();
            called.add(c);
            if (called.size() >= 500) break;
        }
        ctx.called = called;

        // String references from within function body
        Set<String> uniqStrings = new HashSet<>();
        List<String> strings = new ArrayList<>();
        for (Instruction ins : listing.getInstructions(body, true)) {
            Reference[] refs = p.getReferenceManager().getReferencesFrom(ins.getAddress());
            if (refs == null || refs.length == 0) continue;
            for (Reference r : refs) {
                Address to = r.getToAddress();
                if (to == null) continue;
                Data d = listing.getDataAt(to);
                if (d == null || !d.hasStringValue()) continue;
                Object v = d.getValue();
                String sv = (v instanceof String) ? (String) v : d.getDefaultValueRepresentation();
                if (sv == null || sv.isBlank()) continue;
                if (uniqStrings.add(sv)) {
                    strings.add(sv);
                    if (strings.size() >= 200) break;
                }
            }
            if (strings.size() >= 200) break;
        }
        ctx.strings = strings;

        if (includeDecompile) {
            ctx.decompile = decompileFunction(p, f, decompileTimeoutSec, monitor);
        }
        return ctx;
    }

    private static String decompileFunction(Program p, Function f, int timeoutSec, TaskMonitor monitor) {
        DecompInterface ifc = new DecompInterface();
        try {
            if (!ifc.openProgram(p)) {
                return "/* decompiler: failed to open program */";
            }
            DecompileResults res = ifc.decompileFunction(f, timeoutSec, monitor);
            if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
                return "/* decompiler: no result */";
            }
            String c = res.getDecompiledFunction().getC();
            if (c == null) return "/* decompiler: empty */";
            return c;
        } catch (Exception e) {
            return "/* decompiler error: " + e.getMessage() + " */";
        } finally {
            try { ifc.dispose(); } catch (Exception ignore) {}
        }
    }

    private static List<AntiDebugFinding> scanAntiDebug(Program p, TaskMonitor monitor, int maxFindings) {
        Set<String> api = antiDebugApiNamesLower();
        Set<String> mnems = antiDebugMnemonicsUpper();

        List<AntiDebugFinding> out = new ArrayList<>();
        Listing listing = p.getListing();
        FunctionIterator it = p.getFunctionManager().getFunctions(true);

        while (it.hasNext() && out.size() < maxFindings) {
            if (monitor.isCancelled()) break;
            Function f = it.next();
            AddressSetView body = f.getBody();

            // Instruction patterns (timing, traps, VM checks)
            for (Instruction ins : listing.getInstructions(body, true)) {
                if (monitor.isCancelled()) break;
                String m = ins.getMnemonicString();
                if (m == null) continue;
                String up = m.toUpperCase();
                if (mnems.contains(up)) {
                    AntiDebugFinding fd = new AntiDebugFinding();
                    fd.entry = f.getEntryPoint().toString();
                    fd.functionName = f.getName();
                    fd.kind = "instruction";
                    fd.evidence = up + " at " + ins.getAddress();
                    out.add(fd);
                    if (out.size() >= maxFindings) break;
                }
            }
            if (out.size() >= maxFindings) break;

            // API call heuristics (by resolved callee name)
            for (Instruction ins : listing.getInstructions(body, true)) {
                if (monitor.isCancelled()) break;
                if (!ins.getFlowType().isCall()) continue;
                Address[] flows = ins.getFlows();
                if (flows == null || flows.length == 0) continue;
                Address target = flows[0];
                if (target == null) continue;
                Function cf = p.getFunctionManager().getFunctionAt(target);
                if (cf == null) continue;
                String callee = cf.getName();
                if (callee == null) continue;
                String low = callee.toLowerCase();
                if (api.contains(low)) {
                    AntiDebugFinding fd = new AntiDebugFinding();
                    fd.entry = f.getEntryPoint().toString();
                    fd.functionName = f.getName();
                    fd.kind = "api_call";
                    fd.evidence = "calls " + callee + " at " + ins.getAddress();
                    out.add(fd);
                    if (out.size() >= maxFindings) break;
                }
            }
        }
        return out;
    }

    private static AutoRenameResult autoRenameFunctions(
            Program p,
            TaskMonitor monitor,
            int limit,
            boolean onlyDefaultNames,
            boolean dryRun,
            int minScore,
            int decompileTimeoutSec
    ) {
        AutoRenameResult r = new AutoRenameResult();
        r.dryRun = dryRun;
        r.minScore = minScore;

        FunctionIterator it = p.getFunctionManager().getFunctions(true);
        int considered = 0;
        int renamed = 0;
        int skipped = 0;

        int tx = -1;
        boolean txEnded = false;
        if (!dryRun) {
            tx = p.startTransaction("MCP Auto Rename Functions");
        }
        try {
            while (it.hasNext() && renamed < limit) {
                if (monitor.isCancelled()) break;
                Function f = it.next();
                considered++;

                if (f.isExternal() || f.isThunk()) {
                    skipped++;
                    continue;
                }
                if (onlyDefaultNames && !looksDefaultName(f.getName())) {
                    skipped++;
                    continue;
                }

                RenameSuggestion sug = suggestFunctionName(p, f, monitor, decompileTimeoutSec);
                if (sug == null || sug.newName == null || sug.newName.isBlank()) {
                    skipped++;
                    continue;
                }
                if (sug.score < minScore) {
                    skipped++;
                    continue;
                }

                String oldName = f.getName();
                String newName = makeUniqueName(p, sug.newName);
                boolean did = false;
                String err = null;
                if (!dryRun) {
                    try {
                        f.setName(newName, SourceType.USER_DEFINED);
                        did = true;
                    } catch (Exception e) {
                        err = e.getMessage();
                    }
                }

                ProposedRename pr = new ProposedRename();
                pr.entry = f.getEntryPoint().toString();
                pr.oldName = oldName;
                pr.newName = newName;
                pr.score = sug.score;
                pr.reason = sug.reason;
                pr.applied = dryRun ? false : did;
                pr.error = err;
                r.renames.add(pr);

                if (dryRun || did) {
                    renamed++;
                } else {
                    skipped++;
                }
            }

            r.considered = considered;
            r.renamed = renamed;
            r.skipped = skipped;

            if (!dryRun) {
                p.endTransaction(tx, true);
                txEnded = true;
            }
        } catch (Exception e) {
            if (!dryRun && tx != -1 && !txEnded) {
                p.endTransaction(tx, false);
            }
            r.error = e.getMessage();
        }
        return r;
    }

    private static boolean looksDefaultName(String name) {
        if (name == null) return true;
        return name.startsWith("FUN_") || name.startsWith("sub_") || name.startsWith("thunk_FUN_");
    }

    private static String makeUniqueName(Program p, String base) {
        String b = sanitizeIdentifier(base);
        if (b.isBlank()) return b;
        SymbolTable st = p.getSymbolTable();

        String candidate = b;
        for (int i = 0; i < 100; i++) {
            SymbolIterator it = st.getSymbols(candidate);
            boolean exists = it != null && it.hasNext();
            if (!exists) return candidate;
            candidate = b + "_" + (i + 1);
        }
        return b + "_u";
    }

    private static String sanitizeIdentifier(String s) {
        if (s == null) return "";
        String t = s.trim().replaceAll("\\s+", "_");
        t = t.replaceAll("[^A-Za-z0-9_]", "_");
        t = t.replaceAll("_+", "_");
        if (t.startsWith("_")) t = t.replaceFirst("^_+", "");
        if (t.isBlank()) return "";
        if (Character.isDigit(t.charAt(0))) t = "fn_" + t;
        if (t.length() > 60) t = t.substring(0, 60);
        return t;
    }

    private static RenameSuggestion suggestFunctionName(Program p, Function f, TaskMonitor monitor, int decompileTimeoutSec) {
        // Heuristic, deterministic naming. If you want LLM-quality names, the MCP side can use
        // /functionContext(includeDecompile=true) and then call rename_function with an AI-chosen name.
        FunctionContext ctx = buildFunctionContext(p, f, monitor, false, decompileTimeoutSec);

        List<String> calledNames = new ArrayList<>();
        for (CalledFunction cf : ctx.called) {
            if (cf.name != null) calledNames.add(cf.name);
        }

        // Anti-debug gets highest priority
        for (String n : calledNames) {
            String low = n.toLowerCase();
            if (low.equals("isdebuggerpresent") || low.equals("checkremotedebuggerpresent") ||
                    low.equals("ntqueryinformationprocess") || low.equals("zwqueryinformationprocess")) {
                return RenameSuggestion.of("anti_debug_check", 90, "calls " + n);
            }
        }

        // Common IO / networking / crypto-ish cues
        String apiBased = nameFromApis(calledNames);
        if (apiBased != null) {
            return RenameSuggestion.of(apiBased, 75, "based on API calls: " + String.join(",", topN(calledNames, 5)));
        }

        // Fallback: string-based hints
        String stringBased = nameFromStrings(ctx.strings);
        if (stringBased != null) {
            return RenameSuggestion.of(stringBased, 60, "based on referenced strings");
        }

        // Nothing strong enough
        return null;
    }

    private static List<String> topN(List<String> xs, int n) {
        List<String> out = new ArrayList<>();
        if (xs == null) return out;
        for (int i = 0; i < xs.size() && i < n; i++) out.add(xs.get(i));
        return out;
    }

    private static String nameFromApis(List<String> callees) {
        if (callees == null) return null;
        Set<String> low = new HashSet<>();
        for (String c : callees) if (c != null) low.add(c.toLowerCase());

        // Windows file IO
        if (containsAny(low, "createfilea", "createfilew", "createfile")) return "create_file";
        if (containsAny(low, "readfile")) return "read_file";
        if (containsAny(low, "writefile")) return "write_file";
        if (containsAny(low, "deletefilea", "deletefilew", "deletefile")) return "delete_file";

        // Registry
        if (containsAny(low, "regopenkeya", "regopenkeyw", "regopenkeyexa", "regopenkeyexw")) return "open_registry_key";
        if (containsAny(low, "regqueryvalueexa", "regqueryvalueexw")) return "read_registry_value";

        // Process / injection-ish
        if (containsAny(low, "openprocess")) return "open_process";
        if (containsAny(low, "virtualalloc", "virtualallocex")) return "allocate_memory";
        if (containsAny(low, "writeprocessmemory")) return "write_process_memory";
        if (containsAny(low, "createremotethread")) return "create_remote_thread";

        // Networking
        if (containsAny(low, "wsastartup", "socket", "connect", "send", "recv")) return "network_client";

        // Crypto (very rough)
        if (containsAny(low, "cryptacquirecontexta", "cryptacquirecontextw", "cryptcreatehash", "cryptdecrypt", "cryptencrypt")) return "crypto_routine";

        return null;
    }

    private static boolean containsAny(Set<String> s, String... xs) {
        for (String x : xs) {
            if (s.contains(x)) return true;
        }
        return false;
    }

    private static String nameFromStrings(List<String> strings) {
        if (strings == null || strings.isEmpty()) return null;
        // Pick a “keyword” token from strings that looks meaningful.
        String best = null;
        for (String st : strings) {
            if (st == null) continue;
            String t = st.trim();
            if (t.length() < 6) continue;
            // Avoid super-generic format-only strings
            if (t.matches(".*%[0-9\\.]*[sdxXuif].*") && t.replaceAll("%[0-9\\.]*[sdxXuif]", "").trim().length() < 4) {
                continue;
            }
            if (best == null || t.length() > best.length()) best = t;
        }
        if (best == null) return null;
        // Extract alnum tokens
        String token = best.replaceAll("[^A-Za-z0-9]+", "_").replaceAll("_+", "_");
        token = token.replaceAll("^_+", "").replaceAll("_+$", "");
        if (token.length() > 24) token = token.substring(0, 24);
        if (token.isBlank()) return null;
        return "handle_" + token.toLowerCase();
    }

    private static Set<String> antiDebugApiNamesLower() {
        Set<String> s = new HashSet<>();
        // Windows
        s.add("isdebuggerpresent");
        s.add("checkremotedebuggerpresent");
        s.add("ntqueryinformationprocess");
        s.add("zwqueryinformationprocess");
        s.add("outputdebugstringa");
        s.add("outputdebugstringw");
        s.add("setunhandledexceptionfilter");
        s.add("gettickcount");
        s.add("gettickcount64");
        s.add("queryperformancecounter");
        s.add("rdtsc"); // sometimes lifted as a helper
        // Linux / POSIX
        s.add("ptrace");
        s.add("sysctl");
        s.add("prctl");
        s.add("raise");
        s.add("kill");
        return s;
    }

    private static Set<String> antiDebugMnemonicsUpper() {
        Set<String> s = new HashSet<>();
        s.add("RDTSC");
        s.add("RDTSCP");
        s.add("CPUID");
        s.add("INT3");
        s.add("ICEBP");
        s.add("SIDT");
        s.add("SGDT");
        s.add("SLDT");
        s.add("STR");
        s.add("IN");
        s.add("RDMSR");
        s.add("WRMSR");
        return s;
    }

    private static final class FunctionContext {
        String entry;
        String name;
        String prototype;
        boolean isThunk;
        boolean isExternal;
        List<CalledFunction> called = new ArrayList<>();
        List<String> strings = new ArrayList<>();
        String decompile;

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"entry\":\"").append(escapeJson(entry)).append("\",");
            sb.append("\"name\":\"").append(escapeJson(name)).append("\",");
            sb.append("\"prototype\":\"").append(escapeJson(prototype)).append("\",");
            sb.append("\"isThunk\":").append(isThunk).append(",");
            sb.append("\"isExternal\":").append(isExternal).append(",");

            sb.append("\"called\":[");
            boolean first = true;
            for (CalledFunction c : called) {
                if (!first) sb.append(",");
                first = false;
                sb.append("{\"entry\":\"").append(escapeJson(c.entry)).append("\",\"name\":\"").append(escapeJson(c.name)).append("\"}");
            }
            sb.append("],");

            sb.append("\"strings\":[");
            first = true;
            for (String s : strings) {
                if (!first) sb.append(",");
                first = false;
                sb.append("\"").append(escapeJson(s)).append("\"");
            }
            sb.append("]");

            if (decompile != null) {
                sb.append(",\"decompile\":\"").append(escapeJson(decompile)).append("\"");
            }

            sb.append("}");
            return sb.toString();
        }
    }

    private static final class CalledFunction {
        String entry;
        String name;
    }

    private static final class AntiDebugFinding {
        String entry;
        String functionName;
        String kind;
        String evidence;

        String toJson() {
            return "{\"entry\":\"" + escapeJson(entry) + "\",\"functionName\":\"" + escapeJson(functionName) + "\",\"kind\":\"" +
                    escapeJson(kind) + "\",\"evidence\":\"" + escapeJson(evidence) + "\"}";
        }
    }

    private static final class RenameSuggestion {
        String newName;
        int score;
        String reason;

        static RenameSuggestion of(String newName, int score, String reason) {
            RenameSuggestion r = new RenameSuggestion();
            r.newName = newName;
            r.score = score;
            r.reason = reason;
            return r;
        }
    }

    private static final class ProposedRename {
        String entry;
        String oldName;
        String newName;
        int score;
        String reason;
        boolean applied;
        String error;

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"entry\":\"").append(escapeJson(entry)).append("\",");
            sb.append("\"oldName\":\"").append(escapeJson(oldName)).append("\",");
            sb.append("\"newName\":\"").append(escapeJson(newName)).append("\",");
            sb.append("\"score\":").append(score).append(",");
            sb.append("\"applied\":").append(applied).append(",");
            sb.append("\"reason\":\"").append(escapeJson(reason)).append("\"");
            if (error != null) {
                sb.append(",\"error\":\"").append(escapeJson(error)).append("\"");
            }
            sb.append("}");
            return sb.toString();
        }
    }

    private static final class AutoRenameResult {
        boolean dryRun;
        int minScore;
        int considered;
        int renamed;
        int skipped;
        String error;
        List<ProposedRename> renames = new ArrayList<>();

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"dryRun\":").append(dryRun).append(",");
            sb.append("\"minScore\":").append(minScore).append(",");
            sb.append("\"considered\":").append(considered).append(",");
            sb.append("\"renamed\":").append(renamed).append(",");
            sb.append("\"skipped\":").append(skipped).append(",");
            sb.append("\"renames\":[");
            boolean first = true;
            for (ProposedRename r : renames) {
                if (!first) sb.append(",");
                first = false;
                sb.append(r.toJson());
            }
            sb.append("]");
            if (error != null) {
                sb.append(",\"error\":\"").append(escapeJson(error)).append("\"");
            }
            sb.append("}");
            return sb.toString();
        }
    }

}
