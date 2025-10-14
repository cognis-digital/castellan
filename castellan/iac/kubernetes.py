"""Kubernetes manifest importer.

Handles multi-document YAML (``---`` separated). Each workload kind becomes a
process element; Services/Ingress become edge processes; Secrets/ConfigMaps
become data stores. Hardening gaps (privileged, hostNetwork, runAsRoot, no
resource limits) are surfaced as missing controls so the engine scores them.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ..core import SystemSpec, Element, DataFlow

_WORKLOAD_KINDS = {
    "Deployment": "Kubernetes workload",
    "StatefulSet": "Kubernetes workload",
    "DaemonSet": "Kubernetes workload",
    "Pod": "Kubernetes pod",
    "Job": "Kubernetes job",
    "CronJob": "Kubernetes job",
    "ReplicaSet": "Kubernetes workload",
}
_EDGE_KINDS = {
    "Service": "Kubernetes service",
    "Ingress": "Kubernetes ingress",
    "Gateway": "Kubernetes gateway",
}
_STORE_KINDS = {
    "Secret": "Kubernetes secret",
    "ConfigMap": "config store",
    "PersistentVolumeClaim": "persistent volume",
}


def _docs(text: str) -> List[str]:
    return [d for d in re.split(r"(?m)^---\s*$", text) if d.strip()]


def _field(doc: str, key: str) -> str:
    m = re.search(rf"(?m)^\s*{re.escape(key)}:\s*['\"]?([A-Za-z0-9._-]+)['\"]?\s*$", doc)
    return m.group(1) if m else ""


def import_text(text: str, name: str = "Kubernetes Workloads") -> SystemSpec:
    elements: List[Element] = []
    seen = set()
    edge_present = False
    for doc in _docs(text):
        kind = _field(doc, "kind")
        if not kind:
            continue
        nm = _field(doc, "name") or kind.lower()
        low = doc.lower()
        if kind in _WORKLOAD_KINDS:
            controls = []
            if "runasnonroot: true" in low:
                controls.append("least-privilege")
            if "readonlyrootfilesystem: true" in low:
                controls.append("integrity")
            if re.search(r"limits:", low):
                controls.append("rate-limit")
            meta = {"kind": kind, "tech": "kubernetes container"}
            if controls:
                meta["controls"] = controls
            if "privileged: true" in low or "hostnetwork: true" in low or "hostpath" in low:
                meta["exposure"] = "privileged"
            key = f"{kind}/{nm}"
            if key not in seen:
                seen.add(key)
                elements.append(Element(name=nm, type="process",
                                        raw_type=_WORKLOAD_KINDS[kind],
                                        trusted=("exposure" not in meta), metadata=meta))
        elif kind in _EDGE_KINDS:
            edge_present = True
            key = f"{kind}/{nm}"
            if key not in seen:
                seen.add(key)
                meta = {"kind": kind, "tech": "kubernetes ingress"}
                tls = "tls:" in low
                if tls:
                    meta["controls"] = ["tls"]
                elements.append(Element(name=nm, type="process", raw_type=_EDGE_KINDS[kind],
                                        trusted=False, metadata=meta))
        elif kind in _STORE_KINDS:
            key = f"{kind}/{nm}"
            if key not in seen:
                seen.add(key)
                meta = {"kind": kind, "tech": "kubernetes " + kind.lower()}
                if kind == "Secret":
                    meta["tech"] = "kubernetes secret store"
                elements.append(Element(name=nm, type="datastore", raw_type=_STORE_KINDS[kind],
                                        trusted=True, metadata=meta))
    if not elements:
        raise ValueError("no recognizable Kubernetes resources found")
    if edge_present or any(e.type == "process" for e in elements):
        elements.insert(0, Element(name="internet", type="external",
                                   raw_type="external entity", trusted=False,
                                   metadata={"tech": "internet"}))
    flows: List[DataFlow] = []
    procs = [e for e in elements if e.type == "process"]
    stores = [e for e in elements if e.type == "datastore"]
    if procs:
        flows.append(DataFlow(source="internet", dest=procs[0].name,
                              name=f"ingress->{procs[0].name}", encrypted=True,
                              authenticated=False, crosses_boundary=True,
                              metadata={"synthesized": True}))
    for p in procs[:10]:
        for s in stores[:10]:
            flows.append(DataFlow(source=p.name, dest=s.name, name=f"{p.name}->{s.name}",
                                  encrypted=False, authenticated=True, crosses_boundary=False,
                                  metadata={"synthesized": True}))
    return SystemSpec(name=name, elements=elements, flows=flows,
                      description="Imported from Kubernetes manifests.")
