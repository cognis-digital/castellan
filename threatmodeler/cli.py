"""Command-line interface for THREATMODELER.

Subcommands:
  analyze   Parse a spec and emit the full STRIDE threat model.
  validate  Parse a spec and report whether it is well-formed.

Exit codes:
  0  success / spec valid
  1  failure: unmitigated threats at/above --fail-on severity (analyze)
     or invalid spec (validate)
  2  usage / parse error
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    parse_spec,
    build_threat_model,
    SpecError,
    _SEVERITY_RANK,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _print_table(model, stream) -> None:
    s = model.summary()
    print(f"System: {model.system}", file=stream)
    print(
        f"Threats: {s['total_threats']}  Unmitigated: {s['unmitigated']}",
        file=stream,
    )
    print("", file=stream)
    header = f"{'ID':<10} {'SEVERITY':<9} {'CATEGORY':<23} {'M':<2} TARGET"
    print(header, file=stream)
    print("-" * len(header), file=stream)
    ordered = sorted(
        model.threats,
        key=lambda t: (-_SEVERITY_RANK[t.severity], t.category, t.target),
    )
    for t in ordered:
        m = "Y" if t.mitigated else "-"
        print(
            f"{t.id:<10} {t.severity:<9} {t.category:<23} {m:<2} {t.target}",
            file=stream,
        )
    print("", file=stream)
    print("By severity:", file=stream)
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in s["by_severity"]:
            print(f"  {sev:<9} {s['by_severity'][sev]}", file=stream)


def _cmd_analyze(args) -> int:
    try:
        text = _read(args.spec)
        spec = parse_spec(text)
        model = build_threat_model(spec)
    except SpecError as exc:
        print(f"{TOOL_NAME}: spec error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"{TOOL_NAME}: no such file: {args.spec}", file=sys.stderr)
        return 2

    if args.format == "json":
        json.dump(model.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_table(model, sys.stdout)

    # Determine failure based on unmitigated threats at/above threshold.
    if args.fail_on:
        threshold = _SEVERITY_RANK[args.fail_on]
        breaching = [
            t
            for t in model.threats
            if not t.mitigated and _SEVERITY_RANK[t.severity] >= threshold
        ]
        if breaching:
            print(
                f"{TOOL_NAME}: {len(breaching)} unmitigated threat(s) "
                f"at or above '{args.fail_on}'",
                file=sys.stderr,
            )
            return 1
    return 0


def _cmd_validate(args) -> int:
    try:
        text = _read(args.spec)
        spec = parse_spec(text)
    except SpecError as exc:
        if args.format == "json":
            json.dump({"valid": False, "error": str(exc)}, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"{TOOL_NAME}: no such file: {args.spec}", file=sys.stderr)
        return 2

    result = {
        "valid": True,
        "system": spec.name,
        "elements": len(spec.elements),
        "flows": len(spec.flows),
    }
    if args.format == "json":
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(
            f"VALID: '{spec.name}' "
            f"({len(spec.elements)} elements, {len(spec.flows)} flows)"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="STRIDE threat models and attack trees as code.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    p.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="derive the full STRIDE threat model")
    a.add_argument("spec", help="path to system spec ('-' for stdin)")
    a.add_argument(
        "--fail-on",
        choices=tuple(_SEVERITY_RANK.keys()),
        default=None,
        help="exit non-zero if any unmitigated threat is >= this severity",
    )
    a.set_defaults(func=_cmd_analyze)

    v = sub.add_parser("validate", help="check that a spec is well-formed")
    v.add_argument("spec", help="path to system spec ('-' for stdin)")
    v.set_defaults(func=_cmd_validate)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
