"""Terraform importer.

Handles both HCL ``.tf`` files (via a tolerant resource-block scan) and
Terraform plan/state JSON (``terraform show -json`` output). It extracts
resources, classifies them onto the asset taxonomy, flags encryption and
public-exposure hints, and synthesizes plausible trust edges (compute ->
data store, edge -> compute).
"""
from __future__ import annotations

import json
import re
from typing import List, Optional, Tuple

from ..core import SystemSpec, Element, DataFlow
from .common import classify_resource, ENCRYPTION_HINTS, PUBLIC_HINTS

_RESOURCE_RE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.IGNORECASE)


def _block_body(text: str, start: int) -> str:
    """Return the text inside the brace block beginning at index `start`."""
    depth = 0
    i = start
    began = False
    out = []
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
            began = True
            if depth == 1:
                i += 1
                continue
        elif ch == "}":
            depth -= 1
            if depth == 0 and began:
                break
        if began:
            out.append(ch)
        i += 1
    return "".join(out)


def _mk_element(rtype: str, name: str, body: str) -> Optional[Element]:
    cls = classify_resource(rtype)
    if not cls:
        return None
    etype, label = cls
    low = body.lower()
    controls = []
    if any(h in low for h in ENCRYPTION_HINTS):
        controls.append("encrypt")
    meta = {"resource_type": rtype, "tech": rtype}
    if controls:
        meta["controls"] = controls
    public = any(h in low for h in PUBLIC_HINTS)
    if public:
        meta["exposure"] = "public"
    # Personal-data hint via tags/description.
    if re.search(r"\b(pii|phi|personal|sensitive|gdpr)\b", low):
        meta["data_classification"] = "personal"
    trusted = etype in ("datastore", "process") and not public
    return Element(name=f"{name}", type=etype, raw_type=label,
                   trusted=trusted, metadata=meta)


def parse_hcl(text: str) -> List[Element]:
    elements: List[Element] = []
    seen = set()
    for m in _RESOURCE_RE.finditer(text):
        rtype, name = m.group(1), m.group(2)
        body = _block_body(text, m.end() - 1)
        el = _mk_element(rtype, name, body)
        if el and el.name not in seen:
            seen.add(el.name)
            elements.append(el)
    return elements


def parse_plan_json(data: dict) -> List[Element]:
    elements: List[Element] = []
    seen = set()

    def handle(res: dict):
        rtype = res.get("type", "")
        name = res.get("name") or res.get("address", rtype)
        values = res.get("values", res.get("change", {}).get("after", {})) or {}
        body = json.dumps(values).lower()
        el = _mk_element(rtype, str(name), body)
        if el and el.name not in seen:
            seen.add(el.name)
            elements.append(el)

    # planned_values.root_module / state values.root_module / resource_changes
    roots = []
    pv = data.get("planned_values") or data.get("values") or {}
    rm = pv.get("root_module", {})
    if rm:
        roots.append(rm)
    for r in roots:
        for res in r.get("resources", []):
            handle(res)
        for child in r.get("child_modules", []):
            for res in child.get("resources", []):
                handle(res)
    for rc in data.get("resource_changes", []):
        after = rc.get("change", {}).get("after") or {}
        handle({"type": rc.get("type", ""), "name": rc.get("name", ""), "values": after})
    return elements


def _synthesize_flows(elements: List[Element]) -> List[DataFlow]:
    """Heuristic edges: edge/process -> data stores; external -> edge processes."""
    flows: List[DataFlow] = []
    processes = [e for e in elements if e.type in ("process", "service")]
    stores = [e for e in elements if e.type in ("datastore", "store")]
    # Each process talks to each store (capped to keep graphs readable).
    for p in processes[:12]:
        enc = "encrypt" in p.metadata.get("controls", [])
        for s in stores[:12]:
            flows.append(DataFlow(
                source=p.name, dest=s.name, name=f"{p.name}->{s.name}",
                encrypted=("encrypt" in s.metadata.get("controls", [])),
                authenticated=True, crosses_boundary=False,
                metadata={"synthesized": True},
            ))
    return flows


def import_text(text: str, name: str = "Terraform System") -> SystemSpec:
    text = text.strip()
    elements: List[Element]
    if text.startswith("{"):
        try:
            elements = parse_plan_json(json.loads(text))
        except (json.JSONDecodeError, TypeError):
            elements = parse_hcl(text)
    else:
        elements = parse_hcl(text)
    if not elements:
        raise ValueError("no recognizable Terraform resources found")
    # Add an external client if any edge process exists.
    if any(e.type == "process" for e in elements):
        elements.insert(0, Element(name="internet", type="external",
                                   raw_type="external entity", trusted=False,
                                   metadata={"tech": "internet"}))
    flows = _synthesize_flows(elements)
    # Wire internet -> first process.
    procs = [e for e in elements if e.type in ("process", "service")]
    if procs:
        flows.insert(0, DataFlow(source="internet", dest=procs[0].name,
                                 name=f"internet->{procs[0].name}",
                                 encrypted=True, authenticated=False,
                                 crosses_boundary=True, metadata={"synthesized": True}))
    return SystemSpec(name=name, elements=elements, flows=flows,
                      description="Imported from Terraform.")
