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


@mcp.tool
def get_function_context(
    entry: str,
    include_decompile: bool = False,
    decompile_timeout_sec: int = 10,
) -> dict:
    """
    Get per-function context: prototype, callees, referenced strings, optional decompile text.
    """
    payload = {
        "entry": entry,
        "includeDecompile": str(bool(include_decompile)).lower(),
        "decompileTimeoutSec": str(int(decompile_timeout_sec)),
    }
    return _post("/functionContext", payload, timeout=30)


@mcp.tool
def scan_anti_debug(max_findings: int = 500) -> dict:
    """
    Scan the program for common anti-debugging heuristics (API calls + instruction mnemonics).
    """
    payload = {"maxFindings": str(int(max_findings))}
    return _post("/scanAntiDebug", payload, timeout=60)


@mcp.tool
def auto_rename_functions(
    limit: int = 200,
    only_default_names: bool = True,
    dry_run: bool = True,
    min_score: int = 60,
    decompile_timeout_sec: int = 10,
) -> dict:
    """
    Suggest (and optionally apply) deterministic function renames for default FUN_/sub_ names.
    Use dry_run=True first; then re-run with dry_run=False to apply.
    """
    payload = {
        "limit": str(int(limit)),
        "onlyDefaultNames": str(bool(only_default_names)).lower(),
        "dryRun": str(bool(dry_run)).lower(),
        "minScore": str(int(min_score)),
        "decompileTimeoutSec": str(int(decompile_timeout_sec)),
    }
    return _post("/autoRenameFunctions", payload, timeout=120)


@mcp.tool
def program_overview(function_limit: int = 200, anti_debug_max_findings: int = 200) -> dict:
    """
    Lightweight program overview for analysis workflows (no LLM): program info, function list (capped),
    and anti-debug scan results (capped).
    """
    prog = _get("/program", timeout=5)
    funcs = _get("/functions", timeout=20).get("functions", [])
    function_limit = max(1, min(int(function_limit), 2000))
    anti = _post("/scanAntiDebug", {"maxFindings": str(int(anti_debug_max_findings))}, timeout=60)
    return {
        "program": prog,
        "functions": funcs[:function_limit],
        "functionsTotal": len(funcs),
        "antiDebug": anti,
    }


if __name__ == "__main__":
    mcp.run()
