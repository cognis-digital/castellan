"""CloudFormation importer.

Accepts JSON or YAML CloudFormation templates. For JSON we parse the
``Resources`` map directly; for YAML we do a tolerant scan for logical IDs and
their ``Type:`` (robust against CFN intrinsic-function YAML tags that a strict
YAML parser would choke on).
"""
from __future__ import annotations

import json
import re
from typing import Dict, List

from ..core import SystemSpec, Element, DataFlow
from .common import classify_resource

_LOGICAL_RE = re.compile(r"^  ([A-Za-z0-9]+):\s*$")
_TYPE_RE = re.compile(r"^\s+Type:\s*['\"]?(AWS::[A-Za-z0-9:]+)['\"]?")


def _resources_from_yaml(text: str) -> Dict[str, dict]:
    """Best-effort: map logical-id -> {'Type': ...} from a YAML CFN template."""
    out: Dict[str, dict] = {}
    in_resources = False
    current = None
    for line in text.splitlines():
        if re.match(r"^Resources:\s*$", line):
            in_resources = True
            continue
        if in_resources and re.match(r"^[A-Za-z]", line):
            # left the Resources block (a new top-level key)
            break
        if not in_resources:
            continue
        m = _LOGICAL_RE.match(line)
        if m:
            current = m.group(1)
            out[current] = {}
            continue
        mt = _TYPE_RE.match(line)
        if mt and current:
            out[current]["Type"] = mt.group(1)
            # capture a couple of property hints for encryption/public flags
        if current and re.search(r"(Encrypt|KmsKey|SSE)", line, re.IGNORECASE):
            out[current]["_encrypted"] = True
        if current and re.search(r"PublicRead|0\.0\.0\.0/0|PublicAccessBlock", line):
            out[current]["_public"] = True
    return out


def _build_elements(resources: Dict[str, dict]) -> List[Element]:
    elements: List[Element] = []
    seen = set()
    for logical, body in resources.items():
        rtype = body.get("Type", "")
        cls = classify_resource(rtype)
        if not cls:
            continue
        etype, label = cls
        blob = json.dumps(body).lower()
        controls = []
        if body.get("_encrypted") or "encrypt" in blob or "kmskey" in blob:
            controls.append("encrypt")
        meta = {"resource_type": rtype, "tech": rtype}
        if controls:
            meta["controls"] = controls
        if body.get("_public") or "publicread" in blob:
            meta["exposure"] = "public"
        if logical in seen:
            continue
        seen.add(logical)
        trusted = etype in ("datastore", "process") and "exposure" not in meta
        elements.append(Element(name=logical, type=etype, raw_type=label,
                                trusted=trusted, metadata=meta))
    return elements


def import_text(text: str, name: str = "CloudFormation Stack") -> SystemSpec:
    resources: Dict[str, dict] = {}
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            doc = json.loads(text)
            resources = doc.get("Resources", {}) or {}
        except json.JSONDecodeError:
            resources = _resources_from_yaml(text)
    else:
        resources = _resources_from_yaml(text)
    elements = _build_elements(resources)
    if not elements:
        raise ValueError("no recognizable CloudFormation resources found")
    if any(e.type == "process" for e in elements):
        elements.insert(0, Element(name="internet", type="external",
                                   raw_type="external entity", trusted=False,
                                   metadata={"tech": "internet"}))
    flows: List[DataFlow] = []
    procs = [e for e in elements if e.type in ("process", "service")]
    stores = [e for e in elements if e.type in ("datastore", "store")]
    if procs:
        flows.append(DataFlow(source="internet", dest=procs[0].name,
                              name=f"internet->{procs[0].name}", encrypted=True,
                              authenticated=False, crosses_boundary=True,
                              metadata={"synthesized": True}))
    for p in procs[:12]:
        for s in stores[:12]:
            flows.append(DataFlow(source=p.name, dest=s.name, name=f"{p.name}->{s.name}",
                                  encrypted=("encrypt" in s.metadata.get("controls", [])),
                                  authenticated=True, crosses_boundary=False,
                                  metadata={"synthesized": True}))
    return SystemSpec(name=name, elements=elements, flows=flows,
                      description="Imported from CloudFormation.")
