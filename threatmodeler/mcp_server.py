"""THREATMODELER MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from threatmodeler.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-threatmodeler[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-threatmodeler[mcp]'")
        return 1
    app = FastMCP("threatmodeler")

    @app.tool()
    def threatmodeler_scan(target: str) -> str:
        """Generate STRIDE threat models and attack trees from a YAML system spec.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
