"""castellan MCP server — threat modeling as tools for AI agents and IDEs.

Exposes the engine over the Model Context Protocol so assistants (Claude
Desktop, Cursor, Cognis.Studio, the uncensored-fleet, …) can build threat
models, scan IaC, and pull the compliance matrix directly.

Run:  castellan mcp      (requires the 'mcp' extra: pip install 'cognis-castellan[mcp]')
"""
from __future__ import annotations

import json

from .core import (
    parse_spec, build_threat_model, model_from_path, spec_from_path, SpecError,
)
from . import report as _report
from . import library as _library


def _model_json(spec_text: str) -> str:
    spec = parse_spec(spec_text)
    return json.dumps(build_threat_model(spec).to_dict(), indent=2, default=str)


def serve() -> int:
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-castellan[mcp]'")
        return 1

    app = FastMCP("castellan")

    @app.tool()
    def castellan_analyze(spec: str) -> str:
        """Build a full STRIDE+LINDDUN threat model from a castellan YAML spec.

        Returns JSON with threats (risk-scored, with CWE/CAPEC/ATT&CK/OWASP and
        compliance refs), attack trees, and a summary.
        """
        try:
            return _model_json(spec)
        except SpecError as exc:
            return json.dumps({"error": str(exc)})

    @app.tool()
    def castellan_scan(path: str) -> str:
        """Auto-detect a spec or Infrastructure-as-Code at `path` and model it.

        Accepts a castellan spec, a Terraform/CloudFormation/Kubernetes/compose
        file, or a directory. Returns the JSON threat model.
        """
        try:
            return json.dumps(model_from_path(path).to_dict(), indent=2, default=str)
        except SpecError as exc:
            return json.dumps({"error": str(exc)})

    @app.tool()
    def castellan_validate(spec: str) -> str:
        """Validate a castellan spec; returns {valid, system, elements, flows} or an error."""
        try:
            s = parse_spec(spec)
            return json.dumps({"valid": True, "system": s.name,
                               "elements": len(s.elements), "flows": len(s.flows)})
        except SpecError as exc:
            return json.dumps({"valid": False, "error": str(exc)})

    @app.tool()
    def castellan_import_iac(path: str) -> str:
        """Convert IaC (Terraform/CFN/K8s/compose) at `path` into a castellan spec (YAML)."""
        from .core import spec_to_yaml
        try:
            return spec_to_yaml(spec_from_path(path))
        except SpecError as exc:
            return json.dumps({"error": str(exc)})

    @app.tool()
    def castellan_compliance(spec: str) -> str:
        """Return the framework control matrix (framework -> category -> control) for a spec."""
        try:
            model = build_threat_model(parse_spec(spec))
        except SpecError as exc:
            return json.dumps({"error": str(exc)})
        matrix: dict = {}
        for t in model.threats:
            for fw, ctrl in t.compliance.items():
                matrix.setdefault(fw, {})[t.category] = ctrl
        return json.dumps({"system": model.system, "matrix": matrix}, indent=2)

    @app.tool()
    def castellan_report_markdown(spec: str) -> str:
        """Render a full Markdown threat-model report from a castellan spec."""
        try:
            spec_obj = parse_spec(spec)
        except SpecError as exc:
            return json.dumps({"error": str(exc)})
        return _report.render_markdown(build_threat_model(spec_obj))

    @app.tool()
    def castellan_library_stats() -> str:
        """Return counts of the bundled threat / requirement / framework catalogs."""
        return json.dumps(_library.stats(), indent=2)

    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(serve())
