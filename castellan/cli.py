"""Command-line interface for castellan.

Subcommands:
  analyze     Build the full STRIDE+LINDDUN threat model from a spec.
  scan        Auto-detect a spec OR Infrastructure-as-Code and model it.
  validate    Check that a spec / IaC input is well-formed.
  import      Convert IaC (Terraform/CFN/K8s/compose) into a castellan spec.
  compliance  Print the framework control matrix for a model.
  library     Inspect the bundled threat / requirement / framework catalogs.
  mcp         Start the MCP server (for AI agents / IDEs).

Exit codes:
  0  success / valid
  1  unmitigated threats at/above --fail-on (analyze/scan) or invalid spec
  2  usage / parse error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    parse_spec, build_threat_model, spec_from_path, model_from_path,
    spec_to_yaml, SpecError, _SEVERITY_RANK,
)
from . import report as _report


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _emit(text: str, output: Optional[str]) -> None:
    if output and output != "-":
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"{TOOL_NAME}: wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _fail_on(model, threshold_name: Optional[str]) -> int:
    if not threshold_name:
        return 0
    threshold = _SEVERITY_RANK[threshold_name]
    breaching = [t for t in model.threats
                 if not t.mitigated and _SEVERITY_RANK[t.severity] >= threshold]
    if breaching:
        print(f"{TOOL_NAME}: {len(breaching)} unmitigated threat(s) "
              f"at or above '{threshold_name}'", file=sys.stderr)
        return 1
    return 0


def _cmd_analyze(args) -> int:
    try:
        spec = parse_spec(_read(args.spec))
        model = build_threat_model(spec)
    except SpecError as exc:
        print(f"{TOOL_NAME}: spec error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"{TOOL_NAME}: no such file: {args.spec}", file=sys.stderr)
        return 2
    _emit(_report.render(model, args.format, spec=spec), args.output)
    return _fail_on(model, args.fail_on)


def _cmd_scan(args) -> int:
    try:
        spec = spec_from_path(args.target)
        model = build_threat_model(spec)
    except SpecError as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return 2
    _emit(_report.render(model, args.format, spec=spec), args.output)
    return _fail_on(model, args.fail_on)


def _cmd_validate(args) -> int:
    try:
        spec = spec_from_path(args.target) if args.target != "-" else parse_spec(_read("-"))
    except SpecError as exc:
        if args.format == "json":
            _emit(json.dumps({"valid": False, "error": str(exc)}, indent=2), args.output)
        else:
            print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"{TOOL_NAME}: no such file: {args.target}", file=sys.stderr)
        return 2
    result = {"valid": True, "system": spec.name,
              "elements": len(spec.elements), "flows": len(spec.flows)}
    if args.format == "json":
        _emit(json.dumps(result, indent=2), args.output)
    else:
        print(f"VALID: '{spec.name}' ({len(spec.elements)} elements, "
              f"{len(spec.flows)} flows)")
    return 0


def _cmd_import(args) -> int:
    from . import importers
    try:
        spec = importers.import_path(args.target)
    except SpecError as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        from dataclasses import asdict
        _emit(json.dumps({
            "name": spec.name, "description": spec.description,
            "elements": [asdict(e) for e in spec.elements],
            "flows": [asdict(f) for f in spec.flows],
        }, indent=2, default=str), args.output)
    else:
        _emit(spec_to_yaml(spec), args.output)
    return 0


def _cmd_compliance(args) -> int:
    try:
        model = model_from_path(args.target)
    except SpecError as exc:
        print(f"{TOOL_NAME}: {exc}", file=sys.stderr)
        return 2
    matrix: dict = {}
    for t in model.threats:
        for fw, ctrl in t.compliance.items():
            matrix.setdefault(fw, {})[t.category] = ctrl
    if args.format == "json":
        _emit(json.dumps({"system": model.system, "matrix": matrix}, indent=2), args.output)
        return 0
    lines = [f"Compliance control matrix - {model.system}",
             f"Frameworks referenced: {len(matrix)}", ""]
    for fw in sorted(matrix):
        lines.append(f"## {fw}")
        for cat, ctrl in sorted(matrix[fw].items()):
            lines.append(f"  - {cat:<26} -> {ctrl}")
        lines.append("")
    _emit("\n".join(lines), args.output)
    return 0


def _cmd_library(args) -> int:
    from . import library
    what = args.what
    if what == "stats":
        data = library.stats()
        if args.format == "json":
            _emit(json.dumps(data, indent=2), args.output)
        else:
            lines = [
                f"{TOOL_NAME} bundled knowledge",
                f"  threat scenarios     : {data['threat_scenarios']}",
                f"  security requirements: {data['security_requirements']}",
                f"  compliance frameworks: {data['compliance_frameworks']}",
                f"  base attack patterns : {data['base_patterns']}",
                f"  asset classes        : {data['asset_classes']}",
                f"  methodologies        : {', '.join(data['methodologies'])}",
                "  knowledge base       :",
            ]
            for k, v in data["knowledge_base"].items():
                lines.append(f"    {k:<20}: {v}")
            _emit("\n".join(lines), args.output)
        return 0
    if what == "threats":
        items: list = [s.to_dict() for s in library.build_threat_library()]
    elif what == "requirements":
        items = [r.to_dict() for r in library.build_requirements()]
    elif what == "frameworks":
        from .data import frameworks as F
        items = F.FRAMEWORKS
    else:  # pragma: no cover
        print(f"{TOOL_NAME}: unknown library target", file=sys.stderr)
        return 2
    if args.limit:
        items = items[: args.limit]
    if args.format == "json":
        _emit(json.dumps(items, indent=2, default=str), args.output)
    else:
        for it in items:
            _emit(json.dumps(it, default=str), None)
    return 0


def _cmd_mcp(args) -> int:
    from .mcp_server import serve
    return serve()


def _add_io(sp, with_fail=False):
    sp.add_argument("--format", default="table", help="output format")
    sp.add_argument("--output", "-o", default=None, help="write to file ('-' = stdout)")
    if with_fail:
        sp.add_argument("--fail-on", choices=tuple(_SEVERITY_RANK.keys()), default=None,
                        help="exit non-zero if any unmitigated threat is >= this severity")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="castellan — STRIDE + LINDDUN threat models, risk scoring, "
                    "attack trees and compliance mapping, from a spec or your IaC.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="build the full threat model from a spec "
                       "(formats: table|json|sarif|markdown|html)")
    a.add_argument("spec", help="path to system spec ('-' for stdin)")
    _add_io(a, with_fail=True)
    a.set_defaults(func=_cmd_analyze)

    sc = sub.add_parser("scan", help="auto-detect a spec or IaC and model it")
    sc.add_argument("target", help="path to a spec, IaC file, or directory")
    _add_io(sc, with_fail=True)
    sc.set_defaults(func=_cmd_scan)

    v = sub.add_parser("validate", help="check that a spec/IaC input is well-formed")
    v.add_argument("target", help="path to a spec/IaC ('-' for stdin)")
    _add_io(v)
    v.set_defaults(func=_cmd_validate)

    im = sub.add_parser("import", help="convert IaC into a castellan spec")
    im.add_argument("target", help="IaC file or directory")
    _add_io(im)
    im.set_defaults(func=_cmd_import)

    co = sub.add_parser("compliance", help="print the framework control matrix")
    co.add_argument("target", help="spec or IaC path")
    _add_io(co)
    co.set_defaults(func=_cmd_compliance)

    lib = sub.add_parser("library", help="inspect bundled catalogs")
    lib.add_argument("what", choices=("stats", "threats", "requirements", "frameworks"),
                     nargs="?", default="stats")
    lib.add_argument("--limit", type=int, default=0, help="cap number of items")
    _add_io(lib)
    lib.set_defaults(func=_cmd_library)

    mc = sub.add_parser("mcp", help="start the MCP server")
    mc.set_defaults(func=_cmd_mcp)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
