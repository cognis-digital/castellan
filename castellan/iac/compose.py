"""docker-compose importer.

Each service becomes a process; services that publish ports become edge
processes reachable from the internet; well-known database/cache/queue images
become data stores; ``depends_on`` becomes internal trust edges.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ..core import SystemSpec, Element, DataFlow

_DB_IMAGES = {
    "postgres": "relational database", "mysql": "relational database",
    "mariadb": "relational database", "mongo": "NoSQL database",
    "redis": "cache", "memcached": "cache", "elasticsearch": "search index",
    "rabbitmq": "message queue", "kafka": "event stream", "nats": "message queue",
    "cassandra": "NoSQL database", "vault": "secrets manager", "minio": "object store",
}


def _services(text: str) -> Dict[str, dict]:
    """Parse the services block by indentation (2-space convention)."""
    services: Dict[str, dict] = {}
    lines = text.splitlines()
    in_services = False
    cur = None
    base_indent = None
    for ln in lines:
        if re.match(r"^services:\s*$", ln):
            in_services = True
            continue
        if not in_services:
            continue
        if re.match(r"^\S", ln):  # back to top-level key
            break
        m = re.match(r"^(\s+)([A-Za-z0-9._-]+):\s*$", ln)
        if m and (base_indent is None or len(m.group(1)) <= base_indent):
            base_indent = len(m.group(1))
            cur = m.group(2)
            services[cur] = {"_raw": []}
            continue
        if cur is not None:
            services[cur]["_raw"].append(ln)
    return services


def import_text(text: str, name: str = "Compose Stack") -> SystemSpec:
    services = _services(text)
    if not services:
        raise ValueError("no recognizable docker-compose services found")
    elements: List[Element] = []
    edges: List[tuple] = []
    has_edge = False
    for svc, body in services.items():
        raw = "\n".join(body.get("_raw", [])).lower()
        image_m = re.search(r"image:\s*['\"]?([A-Za-z0-9._/-]+)", raw)
        image = image_m.group(1) if image_m else ""
        store_label = None
        for key, label in _DB_IMAGES.items():
            if key in image or key in svc.lower():
                store_label = label
                break
        published = bool(re.search(r"ports:", raw))
        if published:
            has_edge = True
        if store_label:
            etype, label = "datastore", store_label
            meta = {"image": image or svc, "tech": image or store_label}
            trusted = True
        else:
            etype, label = "process", "service"
            meta = {"image": image or svc, "tech": image or "container"}
            trusted = not published
            if published:
                meta["exposure"] = "published-port"
        elements.append(Element(name=svc, type=etype, raw_type=label,
                                trusted=trusted, metadata=meta))
        for dep in re.findall(r"-\s*([A-Za-z0-9._-]+)", raw[raw.find("depends_on"):]) if "depends_on" in raw else []:
            edges.append((svc, dep))
    if has_edge:
        elements.insert(0, Element(name="internet", type="external",
                                   raw_type="external entity", trusted=False,
                                   metadata={"tech": "internet"}))
    flows: List[DataFlow] = []
    names = {e.name for e in elements}
    edge_procs = [e for e in elements if e.type == "process" and "exposure" in e.metadata]
    if edge_procs:
        flows.append(DataFlow(source="internet", dest=edge_procs[0].name,
                              name=f"internet->{edge_procs[0].name}", encrypted=True,
                              authenticated=False, crosses_boundary=True,
                              metadata={"synthesized": True}))
    for src, dst in edges:
        if src in names and dst in names:
            flows.append(DataFlow(source=src, dest=dst, name=f"{src}->{dst}",
                                  encrypted=False, authenticated=True, crosses_boundary=False,
                                  metadata={"synthesized": True}))
    return SystemSpec(name=name, elements=elements, flows=flows,
                      description="Imported from docker-compose.")
