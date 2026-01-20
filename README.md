# Ghidra MCP Bridge

A Model Context Protocol (MCP) server that provides AI assistants with the ability to interact with Ghidra through a local HTTP bridge. This project enables AI tools to query program information, list functions, rename functions, patch bytes, and set comments in Ghidra.

## Overview

This project consists of two main components:

1. **Ghidra Extension** (`McpBridge`): A Java plugin that runs an HTTP server inside Ghidra, exposing program data and operations via REST API endpoints.
2. **MCP Server** (`mcp_server`): A Python-based MCP server that connects to the Ghidra bridge and provides tools for AI assistants.

## Prerequisites

Before setting up this project, ensure you have the following installed:

- **Ghidra**: Version 12.0 or compatible (download from [Ghidra's official site](https://ghidra-sre.org/))
- **Java Development Kit (JDK)**: Version 11 or higher (required for building Ghidra extensions)
- **Gradle**: Version 7.0 or higher (for building the extension)
- **Python**: Version 3.8 or higher
- **pip**: Python package manager

## Setup Instructions

### Step 1: Configure Ghidra Installation Path

The build scripts need to know where Ghidra is installed. Edit the `build.gradle` files in both extension directories:

1. Open `McpBridge/build.gradle`
2. Update the `ghidraInstallDir` path to match your Ghidra installation:

```gradle
ext.ghidraInstallDir = "D:/ghidra_12.0_PUBLIC_20251205/ghidra_12.0_PUBLIC"
```

Replace the path with your actual Ghidra installation directory. On Windows, use forward slashes (`/`) or escaped backslashes (`\\`). On Linux/Mac, use the appropriate path format.

**Note**: If you have the `ghidra_extension` directory, update its `build.gradle` file as well.

### Step 2: Build the Ghidra Extension

1. Navigate to the `McpBridge` directory:
   ```bash
   cd McpBridge
   ```

2. Build the extension using Gradle:
   ```bash
   gradle buildExtension
   ```

   This will create a ZIP file in the `McpBridge/dist/` directory (e.g., `ghidra_12.0_PUBLIC_20260109_McpBridge.zip`).

3. If you also have the `ghidra_extension` directory, build it similarly:
   ```bash
   cd ../ghidra_extension
   gradle buildExtension
   ```

### Step 3: Install the Extension in Ghidra

1. Launch Ghidra.

2. Go to **File → Install Extensions...**

3. Click the **+** button (or "Add Extension") and navigate to the ZIP file you built:
   - Location: `McpBridge/dist/ghidra_12.0_PUBLIC_YYYYMMDD_McpBridge.zip`

4. Check the box next to "McpBridge" to enable it.

5. Click **OK** and restart Ghidra when prompted.

6. After restarting, open a project and load a program. The MCP Bridge plugin will automatically start and listen on `http://127.0.0.1:17664`.

   You should see a message in Ghidra's console: `MCP Bridge listening on http://127.0.0.1:17664`

### Step 4: Install Python Dependencies

1. Navigate to the `mcp_server` directory:
   ```bash
   cd mcp_server
   ```

2. Install the required Python packages:
   ```bash
   pip install fastmcp requests
   ```

   Or if you prefer using a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install fastmcp requests
   ```

### Step 5: Run the MCP Server

1. Make sure Ghidra is running with a program loaded (the bridge must be active).

2. Start the MCP server:
   ```bash
   python server.py
   ```

   The server will connect to the Ghidra bridge at `http://127.0.0.1:17664` and expose the following MCP tools:
   - `ghidra_health`: Check if the Ghidra bridge is reachable
   - `get_current_program`: Get the current program name and image base
   - `list_functions`: List functions from the current program
   - `get_function_context`: Get a function’s prototype/callees/strings (+ optional decompile text)
   - `rename_function`: Rename a function at a specific entry address
   - `auto_rename_functions`: Batch suggest/apply renames for default `FUN_`/`sub_` names
   - `scan_anti_debug`: Scan for common anti-debugging heuristics (API calls + instruction mnemonics)
   - `patch_bytes`: Patch bytes at a specific address
   - `set_comment`: Set an end-of-line comment at an address

## Configuration

### Changing the Bridge Port

By default, the Ghidra bridge runs on port `17664`. To change this:

1. Edit `McpBridge/src/main/java/ghidramcp/McpBridgePlugin.java`
2. Find the line: `server = HttpServer.create(new InetSocketAddress("127.0.0.1", 17664), 0);`
3. Change the port number to your desired port.
4. Rebuild the extension and update the `BRIDGE` constant in `mcp_server/server.py` to match.

### MCP Server Configuration

The MCP server connects to the bridge at `http://127.0.0.1:17664` by default. To change this, edit the `BRIDGE` constant in `mcp_server/server.py`:

```python
BRIDGE = "http://127.0.0.1:17664"
```

## Usage

Once everything is set up:

1. **Start Ghidra** and open a program (the bridge starts automatically when the plugin loads).
2. **Start the MCP server** by running `python mcp_server/server.py`.
3. **Connect your MCP client** (e.g., Claude Desktop, Cursor) to the MCP server.

The AI assistant can now interact with Ghidra through the MCP tools, allowing it to:
- Query program information
- List and analyze functions
- Rename functions
- Patch binary data
- Add comments to code

## Troubleshooting

### Extension Not Loading

- Verify that the Ghidra version in the ZIP filename matches your Ghidra installation.
- Check Ghidra's console for error messages.
- Ensure the extension is enabled in **File → Install Extensions...**.

### Bridge Not Starting

- Make sure a program is loaded in Ghidra (the bridge requires an active program context).
- Check if port 17664 is already in use by another application.
- Review Ghidra's console for error messages.

### MCP Server Connection Errors

- Verify that Ghidra is running with a program loaded.
- Test the bridge manually: `curl http://127.0.0.1:17664/health` should return `{"ok":true}`.
- Ensure the `BRIDGE` URL in `server.py` matches the bridge address and port.

### Build Errors

- Verify your `ghidraInstallDir` path in `build.gradle` is correct.
- Ensure you have the correct Java version (JDK 11+).
- Make sure Gradle can access the Ghidra installation directory.

## Project Structure

```
ghidra_mcp/
├── McpBridge/              # Main Ghidra extension
│   ├── src/
│   │   └── main/java/ghidramcp/
│   │       └── McpBridgePlugin.java
│   ├── build.gradle
│   └── dist/               # Built extension ZIP files
├── ghidra_extension/       # Alternative/older extension (if present)
├── mcp_server/             # Python MCP server
│   └── server.py
└── README.md
```

