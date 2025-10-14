"""Core threat-modeling engine for THREATMODELER.

Parses a minimal YAML-subset system spec (stdlib only, no PyYAML dependency)
describing elements (actors, processes, datastores) and the data flows between
them, then derives STRIDE threats and attack trees.

The STRIDE methodology maps each element type to the threat categories that are
relevant to it (per the classic Microsoft element-to-STRIDE mapping):

  - External Entity (actor):  Spoofing, Repudiation
  - Process:                  Spoofing, Tampering, Repudiation, Information
                              Disclosure, Denial of Service, Elevation of
                              Privilege (all six)
  - Data Store:               Tampering, Repudiation, Information Disclosure,
                              Denial of Service
  - Data Flow:                Tampering, Information Disclosure, Denial of
                              Service
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


class SpecError(Exception):
    """Raised when a system spec is malformed or semantically invalid."""


STRIDE_CATEGORIES = {
    "Spoofing": "Impersonating something or someone else.",
    "Tampering": "Modifying data or code.",
    "Repudiation": "Claiming to not have performed an action.",
    "Information Disclosure": "Exposing information to unauthorized parties.",
    "Denial of Service": "Denying or degrading service to legitimate users.",
    "Elevation of Privilege": "Gaining capabilities without proper authorization.",
}

# Map normalized element types -> applicable STRIDE letters/categories.
_TYPE_STRIDE = {
    "actor": ["Spoofing", "Repudiation"],
    "external": ["Spoofing", "Repudiation"],
    "process": list(STRIDE_CATEGORIES.keys()),
    "service": list(STRIDE_CATEGORIES.keys()),
    "datastore": [
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
    ],
    "store": [
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
    ],
}

_TYPE_ALIASES = {
    "external_entity": "actor",
    "externalentity": "actor",
    "user": "actor",
    "client": "actor",
    "actor": "actor",
    "external": "external",
    "process": "process",
    "service": "service",
    "server": "process",
    "app": "process",
    "datastore": "datastore",
    "data_store": "datastore",
    "database": "datastore",
    "db": "datastore",
    "store": "store",
    "queue": "datastore",
}

# Per-category attack-tree refinement templates (sub-goals an attacker pursues).
_ATTACK_REFINEMENTS = {
    "Spoofing": [
        "Steal or replay credentials/tokens",
        "Exploit weak or missing authentication",
        "Forge identity on an unauthenticated channel",
    ],
    "Tampering": [
        "Modify data in transit (no integrity protection)",
        "Modify data at rest (weak access control)",
        "Inject malicious input that mutates state",
    ],
    "Repudiation": [
        "Perform actions without audit logging",
        "Alter or delete log records",
    ],
    "Information Disclosure": [
        "Read data in transit (no encryption)",
        "Read data at rest (no encryption/over-broad access)",
        "Leak via verbose errors or side channels",
    ],
    "Denial of Service": [
        "Exhaust resources (flooding / amplification)",
        "Trigger expensive operations with crafted input",
    ],
    "Elevation of Privilege": [
        "Exploit missing authorization checks",
        "Abuse confused-deputy / trust boundary crossing",
        "Exploit a code vulnerability to run with higher privilege",
    ],
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Element:
    name: str
    type: str  # normalized type
    raw_type: str
    trusted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataFlow:
    source: str
    dest: str
    name: str = ""
    encrypted: bool = False
    authenticated: bool = False
    crosses_boundary: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemSpec:
    name: str
    elements: List[Element] = field(default_factory=list)
    flows: List[DataFlow] = field(default_factory=list)
    description: str = ""

    def element(self, name: str) -> Optional[Element]:
        for e in self.elements:
            if e.name == name:
                return e
        return None


@dataclass
class Threat:
    id: str
    category: str
    target: str
    target_kind: str  # element | flow
    title: str
    description: str
    severity: str
    mitigated: bool = False
    mitigation: str = ""


@dataclass
class AttackTreeNode:
    goal: str
    operator: str = "OR"  # OR | AND | LEAF
    children: List["AttackTreeNode"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"goal": self.goal, "operator": self.operator}
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


@dataclass
class ThreatModel:
    system: str
    threats: List[Threat] = field(default_factory=list)
    attack_trees: Dict[str, AttackTreeNode] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system": self.system,
            "summary": self.summary(),
            "threats": [asdict(t) for t in self.threats],
            "attack_trees": {k: v.to_dict() for k, v in self.attack_trees.items()},
        }

    def summary(self) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        unmitigated = 0
        for t in self.threats:
            by_cat[t.category] = by_cat.get(t.category, 0) + 1
            by_sev[t.severity] = by_sev.get(t.severity, 0) + 1
            if not t.mitigated:
                unmitigated += 1
        return {
            "total_threats": len(self.threats),
            "unmitigated": unmitigated,
            "by_category": by_cat,
            "by_severity": by_sev,
        }


# --------------------------------------------------------------------------- #
# Minimal YAML-subset parser (stdlib only).
# Supports: top-level scalars, block lists of mappings under a key, inline
# scalars, booleans, and `key: value` pairs. Enough for the threat spec format.
# --------------------------------------------------------------------------- #

def _coerce(value: str) -> Any:
    v = value.strip()
    if v == "":
        return ""
    if (v[0] == v[-1]) and v[0] in ("'", '"') and len(v) >= 2:
        return v[1:-1]
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~"):
        return None
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    if re.fullmatch(r"-?\d+\.\d+", v):
        return float(v)
    return v


def _strip_comment(line: str) -> str:
    # Remove trailing comments not inside quotes.
    out = []
    in_s = None
    for ch in line:
        if in_s:
            out.append(ch)
            if ch == in_s:
                in_s = None
        elif ch in ("'", '"'):
            in_s = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


def _parse_yaml_subset(text: str) -> Dict[str, Any]:
    """Parse the supported YAML subset into nested dict/list structures."""
    root: Dict[str, Any] = {}
    raw_lines = text.splitlines()
    lines = []
    for ln in raw_lines:
        s = _strip_comment(ln.rstrip("\n"))
        if s.strip() == "":
            continue
        indent = len(s) - len(s.lstrip(" "))
        lines.append((indent, s.strip()))

    i = 0
    n = len(lines)

    def parse_block(parent_indent: int):
        nonlocal i
        # Determine if this block is a list (starts with '-') or a mapping.
        result_map: Dict[str, Any] = {}
        result_list: List[Any] = []
        is_list = None
        while i < n:
            indent, content = lines[i]
            if indent < parent_indent:
                break
            if indent > parent_indent:
                # Shouldn't happen at this level; treat defensively.
                raise SpecError(f"unexpected indentation near: {content!r}")
            if content.startswith("- ") or content == "-":
                is_list = True
                item_text = content[1:].strip()
                i += 1
                if item_text == "":
                    child = parse_block(parent_indent + 1)
                    result_list.append(child)
                elif ":" in item_text and not _looks_scalar(item_text):
                    # First key of a mapping item on the dash line.
                    key, _, val = item_text.partition(":")
                    item: Dict[str, Any] = {}
                    if val.strip():
                        item[key.strip()] = _coerce(val)
                    else:
                        item[key.strip()] = parse_block(_next_indent(parent_indent))
                    # Continue collecting sibling keys at deeper indent.
                    more = _collect_deeper(parent_indent)
                    item.update(more)
                    result_list.append(item)
                else:
                    result_list.append(_coerce(item_text))
            else:
                is_list = False
                key, _, val = content.partition(":")
                key = key.strip()
                i += 1
                if val.strip() == "":
                    if i < n and lines[i][0] > parent_indent:
                        result_map[key] = parse_block(lines[i][0])
                    else:
                        result_map[key] = {}
                else:
                    result_map[key] = _coerce(val)
        return result_list if is_list else result_map

    def _next_indent(parent_indent: int) -> int:
        if i < n and lines[i][0] > parent_indent:
            return lines[i][0]
        return parent_indent + 1

    def _collect_deeper(dash_indent: int) -> Dict[str, Any]:
        nonlocal i
        collected: Dict[str, Any] = {}
        while i < n:
            indent, content = lines[i]
            if indent <= dash_indent:
                break
            key, _, val = content.partition(":")
            key = key.strip()
            i += 1
            if val.strip() == "":
                if i < n and lines[i][0] > indent:
                    collected[key] = parse_block(lines[i][0])
                else:
                    collected[key] = {}
            else:
                collected[key] = _coerce(val)
        return collected

    def _looks_scalar(text: str) -> bool:
        # "a: b" is a mapping; a bare URL like "http://x" should be scalar.
        m = re.match(r"^[^\s:]+:\s", text)
        return not bool(m) and not text.endswith(":")

    while i < n:
        indent, content = lines[i]
        if indent != 0:
            raise SpecError(f"top-level content must not be indented: {content!r}")
        key, _, val = content.partition(":")
        key = key.strip()
        i += 1
        if val.strip() == "":
            if i < n and lines[i][0] > 0:
                root[key] = parse_block(lines[i][0])
            else:
                root[key] = {}
        else:
            root[key] = _coerce(val)
    return root


def parse_spec(text: str) -> SystemSpec:
    """Parse a system spec from YAML-subset text into a SystemSpec."""
    data = _parse_yaml_subset(text)
    if not isinstance(data, dict):
        raise SpecError("spec root must be a mapping")

    name = data.get("name") or data.get("system")
    if not name:
        raise SpecError("spec must define a top-level 'name'")

    raw_elements = data.get("elements", [])
    if not isinstance(raw_elements, list) or not raw_elements:
        raise SpecError("spec must define a non-empty 'elements' list")

    elements: List[Element] = []
    seen = set()
    for raw in raw_elements:
        if not isinstance(raw, dict):
            raise SpecError(f"each element must be a mapping, got: {raw!r}")
        ename = raw.get("name")
        etype = raw.get("type")
        if not ename or not etype:
            raise SpecError(f"element missing name/type: {raw!r}")
        if ename in seen:
            raise SpecError(f"duplicate element name: {ename!r}")
        seen.add(ename)
        norm = _TYPE_ALIASES.get(str(etype).lower().replace("-", "_"))
        if norm is None:
            raise SpecError(
                f"unknown element type {etype!r} for {ename!r}; "
                f"valid: {sorted(set(_TYPE_ALIASES))}"
            )
        meta = {
            k: v
            for k, v in raw.items()
            if k not in ("name", "type", "trusted")
        }
        elements.append(
            Element(
                name=str(ename),
                type=norm,
                raw_type=str(etype),
                trusted=bool(raw.get("trusted", False)),
                metadata=meta,
            )
        )

    raw_flows = data.get("flows", []) or data.get("dataflows", [])
    flows: List[DataFlow] = []
    names = {e.name for e in elements}
    if isinstance(raw_flows, list):
        for raw in raw_flows:
            if not isinstance(raw, dict):
                raise SpecError(f"each flow must be a mapping, got: {raw!r}")
            src = raw.get("source") or raw.get("from")
            dst = raw.get("dest") or raw.get("to")
            if not src or not dst:
                raise SpecError(f"flow missing source/dest: {raw!r}")
            if src not in names:
                raise SpecError(f"flow source {src!r} is not a defined element")
            if dst not in names:
                raise SpecError(f"flow dest {dst!r} is not a defined element")
            meta = {
                k: v
                for k, v in raw.items()
                if k
                not in (
                    "source",
                    "from",
                    "dest",
                    "to",
                    "name",
                    "encrypted",
                    "authenticated",
                    "crosses_boundary",
                )
            }
            flows.append(
                DataFlow(
                    source=str(src),
                    dest=str(dst),
                    name=str(raw.get("name", f"{src}->{dst}")),
                    encrypted=bool(raw.get("encrypted", False)),
                    authenticated=bool(raw.get("authenticated", False)),
                    crosses_boundary=bool(raw.get("crosses_boundary", False)),
                    metadata=meta,
                )
            )

    return SystemSpec(
        name=str(name),
        elements=elements,
        flows=flows,
        description=str(data.get("description", "")),
    )


# --------------------------------------------------------------------------- #
# Threat derivation
# --------------------------------------------------------------------------- #

def _severity_for(category: str, *, trusted: bool, crosses_boundary: bool,
                  weak: bool) -> str:
    base = {
        "Spoofing": "medium",
        "Tampering": "high",
        "Repudiation": "low",
        "Information Disclosure": "high",
        "Denial of Service": "medium",
        "Elevation of Privilege": "critical",
    }[category]
    rank = _SEVERITY_RANK[base]
    if crosses_boundary:
        rank += 1
    if weak:
        rank += 1
    if trusted and category in ("Information Disclosure", "Tampering"):
        rank += 1
    rank = max(0, min(rank, 4))
    inv = {v: k for k, v in _SEVERITY_RANK.items()}
    return inv[rank]


def build_threat_model(spec: SystemSpec) -> ThreatModel:
    """Derive STRIDE threats and attack trees from a system spec."""
    threats: List[Threat] = []
    counter = 0

    def next_id(cat: str) -> str:
        nonlocal counter
        counter += 1
        return f"T{counter:03d}-{cat[0]}"

    # Element-based threats.
    for el in spec.elements:
        for cat in _TYPE_STRIDE.get(el.type, []):
            sev = _severity_for(
                cat, trusted=el.trusted, crosses_boundary=False, weak=False
            )
            mitig = _element_mitigation(el, cat)
            threats.append(
                Threat(
                    id=next_id(cat),
                    category=cat,
                    target=el.name,
                    target_kind="element",
                    title=f"{cat} against {el.raw_type} '{el.name}'",
                    description=(
                        f"{STRIDE_CATEGORIES[cat]} "
                        f"Applies to the {el.raw_type} element '{el.name}'."
                    ),
                    severity=sev,
                    mitigated=bool(mitig),
                    mitigation=mitig,
                )
            )

    # Flow-based threats.
    for fl in spec.flows:
        for cat in ("Tampering", "Information Disclosure", "Denial of Service"):
            weak = False
            mitig = ""
            if cat in ("Tampering", "Information Disclosure"):
                if fl.encrypted:
                    mitig = "Channel is encrypted (confidentiality + integrity)."
                else:
                    weak = True
            if cat == "Tampering" and not fl.authenticated and not mitig:
                weak = True
            sev = _severity_for(
                cat,
                trusted=False,
                crosses_boundary=fl.crosses_boundary,
                weak=weak,
            )
            threats.append(
                Threat(
                    id=next_id(cat),
                    category=cat,
                    target=fl.name,
                    target_kind="flow",
                    title=f"{cat} on data flow '{fl.name}'",
                    description=(
                        f"{STRIDE_CATEGORIES[cat]} "
                        f"Data flows {fl.source} -> {fl.dest}"
                        + (" (crosses trust boundary)" if fl.crosses_boundary else "")
                        + "."
                    ),
                    severity=sev,
                    mitigated=bool(mitig),
                    mitigation=mitig,
                )
            )

    trees = {}
    for el in spec.elements:
        if el.type in ("process", "service", "datastore", "store"):
            trees[el.name] = build_attack_tree(spec, el)

    return ThreatModel(system=spec.name, threats=threats, attack_trees=trees)


def _element_mitigation(el: Element, cat: str) -> str:
    """Return a mitigation note if the element declares a relevant control."""
    controls = el.metadata.get("controls")
    if not isinstance(controls, list):
        return ""
    control_words = " ".join(str(c).lower() for c in controls)
    keywords = {
        "Spoofing": ["auth", "mfa", "mtls", "identity"],
        "Tampering": ["integrity", "signing", "hmac", "waf"],
        "Repudiation": ["audit", "log", "logging"],
        "Information Disclosure": ["encrypt", "tls", "redact"],
        "Denial of Service": ["rate", "throttle", "quota", "autoscale"],
        "Elevation of Privilege": ["rbac", "authz", "least-privilege", "sandbox"],
    }
    for kw in keywords.get(cat, []):
        if kw in control_words:
            return f"Mitigated by declared control matching '{kw}'."
    return ""


def build_attack_tree(spec: SystemSpec, target: Element) -> AttackTreeNode:
    """Build an OR-rooted attack tree for compromising a target element."""
    root = AttackTreeNode(
        goal=f"Compromise {target.raw_type} '{target.name}'", operator="OR"
    )
    for cat in _TYPE_STRIDE.get(target.type, []):
        cat_node = AttackTreeNode(goal=f"Achieve {cat}", operator="OR")
        for refinement in _ATTACK_REFINEMENTS.get(cat, []):
            cat_node.children.append(
                AttackTreeNode(goal=refinement, operator="LEAF")
            )
        if cat_node.children:
            root.children.append(cat_node)

    # Flows into/out of the target add concrete attack surface.
    for fl in spec.flows:
        if target.name in (fl.source, fl.dest):
            if not fl.encrypted:
                root.children.append(
                    AttackTreeNode(
                        goal=f"Attack unencrypted flow '{fl.name}'",
                        operator="LEAF",
                    )
                )
    return root
