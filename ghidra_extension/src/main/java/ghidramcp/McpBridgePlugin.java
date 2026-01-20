package ghidramcp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

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
                    if (!first) sb.append(",");
                    first = false;

                    String entry = f.getEntryPoint().toString();
                    String fname = escapeJson(f.getName());
                    sb.append("{\"entry\":\"").append(entry).append("\",\"name\":\"").append(fname).append("\"}");
                    count++;
                }
                sb.append("]}");

                respondJson(exchange, 200, sb.toString());
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
        if (s == null) return "";
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
}
