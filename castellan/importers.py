"""Input auto-detection and dispatch.

`import_path` is the single entry point the engine calls for anything that is
not already a castellan spec: it sniffs a file (or every recognizable file in a
directory) as Terraform / CloudFormation / Kubernetes / docker-compose and
returns a merged SystemSpec.
"""
from __future__ import annotations

import os
import re
from typing import List, Optional, Tuple

from .core import SystemSpec, Element, DataFlow, SpecError, parse_spec
from .iac import terraform, cloudformation, kubernetes, compose

# Extensions we will even look at when walking a directory.
_IAC_EXTS = (".tf", ".json", ".yml", ".yaml")
_SKIP_DIRS = {".git", "node_modules", ".terraform", "__pycache__", "venv", ".venv"}


def detect(filename: str, text: str) -> Optional[str]:
    """Return the importer kind for a file, or None if unrecognized."""
    fn = os.path.basename(filename).lower()
    head = text[:4000]
    low = head.lower()
    if fn.endswith(".tf") or re.search(r'(?m)^\s*resource\s+"', head):
        return "terraform"
    if "awstemplateformatversion" in low or re.search(r"(?m)^Resources:\s*$", head) and "aws::" in low:
        return "cloudformation"
    if ("compose" in fn) or (re.search(r"(?m)^services:\s*$", head) and "image:" in low):
        return "compose"
    if re.search(r"(?m)^apiVersion:", head) and re.search(r"(?m)^kind:", head):
        return "kubernetes"
    if fn.endswith(".json"):
        if any(k in low for k in ("planned_values", "resource_changes", '"terraform_version"')):
            return "terraform"
        if "aws::" in low and "resources" in low:
            return "cloudformation"
    # spec file?
    if "elements:" in low and ("name:" in low or "system:" in low):
        return "spec"
    return None


_DISPATCH = {
    "terraform": terraform.import_text,
    "cloudformation": cloudformation.import_text,
    "kubernetes": kubernetes.import_text,
    "compose": compose.import_text,
}


def import_file(path: str) -> SystemSpec:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    kind = detect(path, text)
    if kind is None:
        raise SpecError(f"unrecognized input (not a spec or supported IaC): {path}")
    if kind == "spec":
        return parse_spec(text)
    name = os.path.splitext(os.path.basename(path))[0]
    return _DISPATCH[kind](text, name=f"{name} ({kind})")


def _merge(specs: List[Tuple[str, SystemSpec]], system_name: str) -> SystemSpec:
    """Merge several specs, namespacing element names by source to avoid clashes."""
    elements: List[Element] = []
    flows: List[DataFlow] = []
    rename = {}
    for src, sp in specs:
        prefix = re.sub(r"[^A-Za-z0-9]+", "-", src).strip("-")
        local = {}
        for e in sp.elements:
            new = f"{prefix}/{e.name}" if len(specs) > 1 else e.name
            local[e.name] = new
            elements.append(Element(name=new, type=e.type, raw_type=e.raw_type,
                                    trusted=e.trusted, metadata=dict(e.metadata)))
        for fl in sp.flows:
            flows.append(DataFlow(
                source=local.get(fl.source, fl.source),
                dest=local.get(fl.dest, fl.dest),
                name=fl.name, encrypted=fl.encrypted, authenticated=fl.authenticated,
                crosses_boundary=fl.crosses_boundary, metadata=dict(fl.metadata)))
    # dedup duplicate element names (e.g., shared 'internet')
    seen = {}
    deduped: List[Element] = []
    for e in elements:
        if e.name in seen:
            continue
        seen[e.name] = True
        deduped.append(e)
    valid = {e.name for e in deduped}
    flows = [f for f in flows if f.source in valid and f.dest in valid]
    return SystemSpec(name=system_name, elements=deduped, flows=flows,
                      description="Merged from multiple IaC sources.")


def import_path(target: str) -> SystemSpec:
    if os.path.isfile(target):
        return import_file(target)
    if not os.path.isdir(target):
        raise SpecError(f"no such file or directory: {target}")

    collected: List[Tuple[str, SystemSpec]] = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in sorted(files):
            if not fn.lower().endswith(_IAC_EXTS):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except OSError:
                continue
            kind = detect(path, text)
            if not kind or kind == "spec":
                # a spec file inside a dir short-circuits to that spec
                if kind == "spec":
                    return parse_spec(text)
                continue
            try:
                rel = os.path.relpath(path, target)
                collected.append((rel, _DISPATCH[kind](text, name=rel)))
            except (ValueError, SpecError):
                continue
    if not collected:
        raise SpecError(
            f"no spec or supported IaC found under {target} "
            f"(looked for Terraform/CloudFormation/Kubernetes/compose)")
    system_name = os.path.basename(os.path.abspath(target)) or "System"
    return _merge(collected, system_name)
