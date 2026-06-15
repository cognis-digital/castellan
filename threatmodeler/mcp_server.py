"""THREATMODELER MCP server — exposes analyze() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from threatmodeler.core import parse_spec, build_threat_model, SpecError


def _analyze(spec_text: str) -> str:
    """Parse *spec_text* as a YAML system spec and return a JSON threat model.

    Returns a JSON object. On parse or validation error, returns a JSON object
    with ``{"error": "<message>"}`` rather than raising, so MCP callers always
    receive well-formed JSON.
    """
    if not spec_text or not spec_text.strip():
        return json.dumps({"error": "empty spec"})
    try:
        spec = parse_spec(spec_text)
        model = build_threat_model(spec)
        return json.dumps(model.to_dict(), indent=2)
    except SpecError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:  # pragma: no cover
        return json.dumps({"error": f"unexpected error: {exc}"})


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-threatmodeler[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print(
            "Install the MCP extra: pip install 'cognis-threatmodeler[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("threatmodeler")

    @app.tool()
    def threatmodeler_scan(spec: str) -> str:
        """Generate STRIDE threat models and attack trees from a YAML system spec. Returns JSON findings."""
        return _analyze(spec)

    app.run()
    return 0
