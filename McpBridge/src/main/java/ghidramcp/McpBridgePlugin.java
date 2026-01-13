package ghidramcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;

import java.io.InputStream;
import java.util.HashMap;
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
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
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

}
