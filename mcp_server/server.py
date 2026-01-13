from fastmcp import FastMCP
import requests

mcp = FastMCP("Ghidra MCP")

BRIDGE = "http://127.0.0.1:17664"


def _get(path: str, timeout: int = 10) -> dict:
    r = requests.get(f"{BRIDGE}{path}", timeout=timeout)
    r.raise_for_status()
    return r.json()


def _post(path: str, payload: dict, timeout: int = 10) -> dict:
    r = requests.post(f"{BRIDGE}{path}", json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()


@mcp.tool
def ghidra_health() -> dict:
    """Check if Ghidra bridge is reachable."""
    return _get("/health", timeout=3)


@mcp.tool
def get_current_program() -> dict:
    """Get current program name and image base from Ghidra."""
    return _get("/program", timeout=5)


@mcp.tool
def list_functions(limit: int = 200) -> dict:
    """List functions (capped) from the current program."""
    data = _get("/functions", timeout=20)
    funcs = data.get("functions", [])
    limit = max(1, min(int(limit), 2000))
    return {"functions": funcs[:limit], "total": len(funcs)}


@mcp.tool
def rename_function(entry: str, new_name: str) -> dict:
    """Rename the function at entry address."""
    payload = {"entry": entry, "newName": new_name}
    return _post("/renameFunction", payload, timeout=10)


@mcp.tool
def patch_bytes(address: str, bytes_hex: str) -> dict:
    """Patch bytes at address. bytes_hex example: '90 90 90'."""
    payload = {"address": address, "bytesHex": bytes_hex}
    return _post("/patchBytes", payload, timeout=10)


@mcp.tool
def set_comment(address: str, comment: str) -> dict:
    """Set EOL comment at address."""
    payload = {"address": address, "comment": comment}
    return _post("/setComment", payload, timeout=10)


if __name__ == "__main__":
    mcp.run()
