"""Core threat-modeling engine for castellan.

Parses a minimal YAML-subset system spec (stdlib only, no PyYAML dependency)
describing elements (actors, processes, datastores) and the data flows between
them, then derives:

  * STRIDE threats (the classic element-to-STRIDE mapping),
  * LINDDUN privacy threats for elements/flows handling personal data,
  * DREAD-scored, CIA-tagged risk for every threat,
  * attack trees per process/datastore,
  * real CWE / CAPEC / ATT&CK / OWASP references and a compliance control matrix.

`scan(target)` is the path-oriented entry point used by the CLI and MCP server:
it accepts a spec file, an IaC file/directory, or a directory containing either,
auto-detects the input, and returns the full model as a dict.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from . import TOOL_NAME, TOOL_VERSION  # noqa: F401  (re-exported identity)
from . import compliance as _compliance
from . import scoring as _scoring
from .library import BASE_PATTERNS
from .data import knowledge as _K  # noqa: F401  (kept for downstream imports)


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

LINDDUN_CATEGORIES = {
    "Linkability": "Linking two or more items of interest about a data subject.",
    "Identifiability": "Identifying a data subject from a set of items.",
    "Non-repudiation (privacy)": "A data subject cannot deny an action they wish to.",
    "Detectability": "Detecting that an item of interest about a subject exists.",
    "Disclosure of Information": "Exposing personal data to unauthorized parties.",
    "Unawareness": "A data subject is unaware of the processing of their data.",
    "Non-compliance": "Processing deviates from legal/regulatory requirements.",
}

# Map normalized element types -> applicable STRIDE categories.
_TYPE_STRIDE = {
    "actor": ["Spoofing", "Repudiation"],
    "external": ["Spoofing", "Repudiation"],
    "process": list(STRIDE_CATEGORIES.keys()),
    "service": list(STRIDE_CATEGORIES.keys()),
    "datastore": [
        "Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
    ],
    "store": [
        "Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
    ],
}

_TYPE_ALIASES = {
    "external_entity": "actor", "externalentity": "actor", "user": "actor",
    "client": "actor", "actor": "actor", "external": "external",
    "process": "process", "service": "service", "server": "process",
    "app": "process", "function": "process", "lambda": "process",
    "datastore": "datastore", "data_store": "datastore", "database": "datastore",
    "db": "datastore", "store": "store", "queue": "datastore", "bucket": "datastore",
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
_INV_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}

# Keywords -> asset tags, used to infer cloud/container/ai/identity context.
_TAG_KEYWORDS = {
    "cloud": ["s3", "bucket", "blob", "gcs", "lambda", "cloud", "azure", "aws", "gcp", "serverless"],
    "containers": ["container", "kubernetes", "k8s", "pod", "docker", "ecs", "eks", "aks", "gke"],
    "ai": ["llm", "agent", "model", "embedding", "vector", "ml", "ai", "rag"],
    "identity": ["auth", "iam", "identity", "login", "sso", "oauth", "token", "secret", "vault", "kms"],
    "data": ["db", "database", "store", "cache", "redis", "queue", "kafka", "warehouse", "lake"],
    "api": ["api", "gateway", "graphql", "rest", "endpoint"],
    "mobile": ["mobile", "ios", "android"],
    "supply-chain": ["ci", "cd", "pipeline", "build", "registry", "artifact"],
    "network": ["lb", "load-balancer", "gateway", "proxy", "ingress", "edge"],
}

# Tokens in element metadata that mark personal-data handling (-> LINDDUN).
_PII_TOKENS = ("pii", "phi", "personal", "gdpr", "sensitive", "ssn", "pci", "biometric")
# LINDDUN categories applied to personal-data assets, by element kind.
_LINDDUN_FOR = {
    "datastore": ["Linkability", "Identifiability", "Disclosure of Information",
                  "Detectability", "Non-compliance"],
    "store": ["Linkability", "Identifiability", "Disclosure of Information",
              "Detectability", "Non-compliance"],
    "process": ["Linkability", "Disclosure of Information", "Non-compliance"],
    "service": ["Linkability", "Disclosure of Information", "Non-compliance"],
    "actor": ["Unawareness"],
    "external": ["Unawareness"],
}


@dataclass
class Element:
    name: str
    type: str  # normalized type
    raw_type: str
    trusted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def tags(self) -> List[str]:
        """Infer asset tags from type, name, raw_type, and metadata."""
        base = {"actor": ["edge", "untrusted"], "external": ["edge", "untrusted", "supply-chain"],
                "process": ["app"], "service": ["app"],
                "datastore": ["data"], "store": ["data"]}.get(self.type, ["app"])
        tags = set(base)
        hay = " ".join([
            self.name.lower(), self.raw_type.lower(),
            str(self.metadata.get("asset", "")).lower(),
            str(self.metadata.get("tech", "")).lower(),
        ])
        for tag, kws in _TAG_KEYWORDS.items():
            if any(re.search(rf"\b{re.escape(k)}\b", hay) for k in kws):
                tags.add(tag)
        if not self.trusted and self.type in ("actor", "external"):
            tags.add("untrusted")
        if self.type in ("process", "service") and "internal" not in tags and "edge" not in tags:
            tags.add("internal")
        return sorted(tags)

    def handles_personal_data(self) -> bool:
        blob = " ".join(str(v).lower() for v in self.metadata.values())
        blob += " " + self.name.lower() + " " + self.raw_type.lower()
        if self.metadata.get("personal_data") in (True, "true", "yes"):
            return True
        return any(tok in blob for tok in _PII_TOKENS)


@dataclass
class DataFlow:
    source: str
    dest: str
    name: str = ""
    encrypted: bool = False
    authenticated: bool = False
    crosses_boundary: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def carries_personal_data(self) -> bool:
        blob = " ".join(str(v).lower() for v in self.metadata.values()) + " " + self.name.lower()
        return any(tok in blob for tok in _PII_TOKENS)


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
    methodology: str  # STRIDE | LINDDUN
    category: str
    target: str
    target_kind: str  # element | flow
    title: str
    description: str
    severity: str
    risk: float = 0.0
    risk_level: str = "info"
    mitigated: bool = False
    mitigation: str = ""
    cia: List[str] = field(default_factory=list)
    dread: Dict[str, Any] = field(default_factory=dict)
    cwe: List[str] = field(default_factory=list)
    capec: List[str] = field(default_factory=list)
    attack: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)
    compliance: Dict[str, str] = field(default_factory=dict)


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
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "system": self.system,
            "description": self.description,
            "summary": self.summary(),
            "threats": [asdict(t) for t in self.threats],
            "attack_trees": {k: v.to_dict() for k, v in self.attack_trees.items()},
        }

    def summary(self) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        by_method: Dict[str, int] = {}
        unmitigated = 0
        for t in self.threats:
            by_cat[t.category] = by_cat.get(t.category, 0) + 1
            by_sev[t.severity] = by_sev.get(t.severity, 0) + 1
            by_method[t.methodology] = by_method.get(t.methodology, 0) + 1
            if not t.mitigated:
                unmitigated += 1
        risks = [t.risk for t in self.threats if not t.mitigated]
        return {
            "total_threats": len(self.threats),
            "unmitigated": unmitigated,
            "risk_score": _scoring.aggregate_risk(risks),
            "by_methodology": by_method,
            "by_category": by_cat,
            "by_severity": by_sev,
            "frameworks_referenced": _frameworks_referenced(self.threats),
        }


def _frameworks_referenced(threats: List[Threat]) -> int:
    seen = set()
    for t in threats:
        seen.update(t.compliance.keys())
    return len(seen)


# --------------------------------------------------------------------------- #
# Minimal YAML-subset parser (stdlib only).
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
        result_map: Dict[str, Any] = {}
        result_list: List[Any] = []
        is_list = None
        while i < n:
            indent, content = lines[i]
            if indent < parent_indent:
                break
            if indent > parent_indent:
                raise SpecError(f"unexpected indentation near: {content!r}")
            if content.startswith("- ") or content == "-":
                is_list = True
                item_text = content[1:].strip()
                i += 1
                if item_text == "":
                    child = parse_block(parent_indent + 1)
                    result_list.append(child)
                elif ":" in item_text and not _looks_scalar(item_text):
                    key, _, val = item_text.partition(":")
                    item: Dict[str, Any] = {}
                    if val.strip():
                        item[key.strip()] = _coerce(val)
                    else:
                        item[key.strip()] = parse_block(_next_indent(parent_indent))
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
        meta = {k: v for k, v in raw.items() if k not in ("name", "type", "trusted")}
        elements.append(Element(
            name=str(ename), type=norm, raw_type=str(etype),
            trusted=bool(raw.get("trusted", False)), metadata=meta,
        ))

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
            meta = {k: v for k, v in raw.items() if k not in (
                "source", "from", "dest", "to", "name",
                "encrypted", "authenticated", "crosses_boundary")}
            flows.append(DataFlow(
                source=str(src), dest=str(dst),
                name=str(raw.get("name", f"{src}->{dst}")),
                encrypted=bool(raw.get("encrypted", False)),
                authenticated=bool(raw.get("authenticated", False)),
                crosses_boundary=bool(raw.get("crosses_boundary", False)),
                metadata=meta,
            ))

    return SystemSpec(
        name=str(name), elements=elements, flows=flows,
        description=str(data.get("description", "")),
    )


# --------------------------------------------------------------------------- #
# Reference enrichment from the threat library.
# --------------------------------------------------------------------------- #

def _refs_for(category: str, tags: List[str]) -> Dict[str, List[str]]:
    """Union real CWE/CAPEC/ATT&CK/OWASP refs from applicable library patterns."""
    cwe: set = set(); capec: set = set(); attack: set = set(); owasp: set = set()
    for p in BASE_PATTERNS:
        if p.category != category:
            continue
        if p.applies != ("*",) and not any(t in p.applies for t in tags):
            continue
        cwe.update(p.cwe); capec.update(p.capec); attack.update(p.attack); owasp.update(p.owasp)
    return {
        "cwe": sorted(cwe), "capec": sorted(capec),
        "attack": sorted(attack), "owasp": sorted(owasp),
    }


def _severity_for(category: str, *, trusted: bool, crosses_boundary: bool,
                  weak: bool) -> str:
    base = {
        "Spoofing": "medium", "Tampering": "high", "Repudiation": "low",
        "Information Disclosure": "high", "Denial of Service": "medium",
        "Elevation of Privilege": "critical",
        "Linkability": "medium", "Identifiability": "medium",
        "Non-repudiation (privacy)": "low", "Detectability": "low",
        "Disclosure of Information": "high", "Unawareness": "low",
        "Non-compliance": "medium",
    }.get(category, "medium")
    rank = _SEVERITY_RANK[base]
    if crosses_boundary:
        rank += 1
    if weak:
        rank += 1
    if trusted and category in ("Information Disclosure", "Tampering"):
        rank += 1
    rank = max(0, min(rank, 4))
    return _INV_SEVERITY[rank]


def _make_threat(tid: str, methodology: str, category: str, target: str,
                 target_kind: str, title: str, description: str, *,
                 severity: str, tags: List[str], exposed: bool,
                 crosses_boundary: bool, mitigated: bool, mitigation: str) -> Threat:
    refs = _refs_for(category, tags)
    dread = _scoring.compute_dread(
        category, exposed=exposed, crosses_boundary=crosses_boundary, mitigated=mitigated)
    return Threat(
        id=tid, methodology=methodology, category=category, target=target,
        target_kind=target_kind, title=title, description=description,
        severity=severity, risk=float(dread["risk"]), risk_level=str(dread["level"]),
        mitigated=mitigated, mitigation=mitigation, cia=list(dread["cia"]),
        dread=dread, cwe=refs["cwe"], capec=refs["capec"], attack=refs["attack"],
        owasp=refs["owasp"], compliance=_compliance.controls_for_category(category),
    )


def build_threat_model(spec: SystemSpec) -> ThreatModel:
    """Derive STRIDE + LINDDUN threats, scores, and attack trees from a spec."""
    threats: List[Threat] = []
    counter = 0

    def next_id(cat: str) -> str:
        nonlocal counter
        counter += 1
        return f"T{counter:03d}-{cat[0]}"

    # ---- Element-based STRIDE threats ----
    for el in spec.elements:
        tags = el.tags()
        exposed = ("edge" in tags) or ("untrusted" in tags)
        for cat in _TYPE_STRIDE.get(el.type, []):
            sev = _severity_for(cat, trusted=el.trusted, crosses_boundary=False, weak=False)
            mitig = _element_mitigation(el, cat)
            threats.append(_make_threat(
                next_id(cat), "STRIDE", cat, el.name, "element",
                f"{cat} against {el.raw_type} '{el.name}'",
                f"{STRIDE_CATEGORIES[cat]} Applies to the {el.raw_type} element '{el.name}'.",
                severity=sev, tags=tags, exposed=exposed, crosses_boundary=False,
                mitigated=bool(mitig), mitigation=mitig,
            ))

        # ---- Element-based LINDDUN privacy threats (personal-data assets) ----
        if el.handles_personal_data():
            for cat in _LINDDUN_FOR.get(el.type, []):
                sev = _severity_for(cat, trusted=el.trusted, crosses_boundary=False, weak=False)
                threats.append(_make_threat(
                    next_id(cat), "LINDDUN", cat, el.name, "element",
                    f"{cat} for personal data in '{el.name}'",
                    f"{LINDDUN_CATEGORIES[cat]} The {el.raw_type} '{el.name}' handles personal data.",
                    severity=sev, tags=tags, exposed=exposed, crosses_boundary=False,
                    mitigated=False, mitigation="",
                ))

    # ---- Flow-based STRIDE threats ----
    for fl in spec.flows:
        ftags = _flow_tags(spec, fl)
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
            sev = _severity_for(cat, trusted=False, crosses_boundary=fl.crosses_boundary, weak=weak)
            threats.append(_make_threat(
                next_id(cat), "STRIDE", cat, fl.name, "flow",
                f"{cat} on data flow '{fl.name}'",
                f"{STRIDE_CATEGORIES[cat]} Data flows {fl.source} -> {fl.dest}"
                + (" (crosses trust boundary)" if fl.crosses_boundary else "") + ".",
                severity=sev, tags=ftags, exposed=fl.crosses_boundary,
                crosses_boundary=fl.crosses_boundary, mitigated=bool(mitig), mitigation=mitig,
            ))

        # ---- Flow-based LINDDUN (personal data on the wire) ----
        if fl.carries_personal_data():
            for cat in ("Disclosure of Information", "Linkability"):
                mitig = "Channel is encrypted." if (fl.encrypted and cat == "Disclosure of Information") else ""
                sev = _severity_for(cat, trusted=False, crosses_boundary=fl.crosses_boundary,
                                    weak=not fl.encrypted)
                threats.append(_make_threat(
                    next_id(cat), "LINDDUN", cat, fl.name, "flow",
                    f"{cat} of personal data on flow '{fl.name}'",
                    f"{LINDDUN_CATEGORIES[cat]} Personal data flows {fl.source} -> {fl.dest}.",
                    severity=sev, tags=ftags, exposed=fl.crosses_boundary,
                    crosses_boundary=fl.crosses_boundary, mitigated=bool(mitig), mitigation=mitig,
                ))

    trees = {}
    for el in spec.elements:
        if el.type in ("process", "service", "datastore", "store"):
            trees[el.name] = build_attack_tree(spec, el)

    return ThreatModel(system=spec.name, threats=threats, attack_trees=trees,
                       description=spec.description)


def _flow_tags(spec: SystemSpec, fl: DataFlow) -> List[str]:
    tags = {"network"}
    if fl.crosses_boundary:
        tags.add("edge")
    for end in (fl.source, fl.dest):
        el = spec.element(end)
        if el:
            tags.update(el.tags())
    return sorted(tags)


def _element_mitigation(el: Element, cat: str) -> str:
    controls = el.metadata.get("controls")
    if not isinstance(controls, list):
        return ""
    control_words = " ".join(str(c).lower() for c in controls)
    keywords = {
        "Spoofing": ["auth", "mfa", "mtls", "identity", "sso", "fido"],
        "Tampering": ["integrity", "signing", "hmac", "waf", "sign"],
        "Repudiation": ["audit", "log", "logging"],
        "Information Disclosure": ["encrypt", "tls", "redact"],
        "Denial of Service": ["rate", "throttle", "quota", "autoscale", "limit"],
        "Elevation of Privilege": ["rbac", "authz", "least-privilege", "sandbox", "abac"],
    }
    for kw in keywords.get(cat, []):
        if kw in control_words:
            return f"Mitigated by declared control matching '{kw}'."
    return ""


def build_attack_tree(spec: SystemSpec, target: Element) -> AttackTreeNode:
    """Build an OR-rooted attack tree for compromising a target element."""
    root = AttackTreeNode(goal=f"Compromise {target.raw_type} '{target.name}'", operator="OR")
    for cat in _TYPE_STRIDE.get(target.type, []):
        cat_node = AttackTreeNode(goal=f"Achieve {cat}", operator="OR")
        for refinement in _ATTACK_REFINEMENTS.get(cat, []):
            cat_node.children.append(AttackTreeNode(goal=refinement, operator="LEAF"))
        if cat_node.children:
            root.children.append(cat_node)
    for fl in spec.flows:
        if target.name in (fl.source, fl.dest) and not fl.encrypted:
            root.children.append(AttackTreeNode(
                goal=f"Attack unencrypted flow '{fl.name}'", operator="LEAF"))
    return root


# --------------------------------------------------------------------------- #
# Path-oriented scanning (CLI / MCP entry point).
# --------------------------------------------------------------------------- #

_SPEC_EXTS = (".yml", ".yaml")


def _looks_like_spec(text: str) -> bool:
    head = text.lower()
    return ("elements:" in head) and ("name:" in head or "system:" in head)


def spec_from_path(target: str) -> SystemSpec:
    """Load a SystemSpec from a spec file, IaC file, or directory (auto-detect)."""
    from . import importers  # local import avoids cycle at module load
    if os.path.isdir(target):
        for fn in sorted(os.listdir(target)):
            if fn.lower().endswith(_SPEC_EXTS):
                p = os.path.join(target, fn)
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        txt = fh.read()
                    if _looks_like_spec(txt):
                        return parse_spec(txt)
                except (OSError, SpecError):
                    continue
        return importers.import_path(target)
    if not os.path.exists(target):
        raise SpecError(f"no such file or directory: {target}")
    with open(target, "r", encoding="utf-8") as fh:
        txt = fh.read()
    if target.lower().endswith(_SPEC_EXTS) and _looks_like_spec(txt):
        return parse_spec(txt)
    return importers.import_path(target)


def model_from_path(target: str) -> ThreatModel:
    """Load a ThreatModel from a spec file, IaC file, or directory."""
    return build_threat_model(spec_from_path(target))


def scan(target: str) -> Dict[str, Any]:
    """Scan a path and return the full threat model as a dict (MCP/CLI use)."""
    return model_from_path(target).to_dict()


def spec_to_yaml(spec: SystemSpec) -> str:
    """Serialize a SystemSpec back to castellan spec YAML (round-trippable)."""
    out: List[str] = [f"name: {spec.name}"]
    if spec.description:
        out.append(f"description: {spec.description}")
    out.append("elements:")
    for e in spec.elements:
        out.append(f"  - name: {e.name}")
        out.append(f"    type: {e.raw_type}")
        if e.trusted:
            out.append("    trusted: true")
        controls = e.metadata.get("controls")
        if isinstance(controls, list) and controls:
            out.append("    controls:")
            for c in controls:
                out.append(f"      - {c}")
    if spec.flows:
        out.append("flows:")
        for f in spec.flows:
            out.append(f"  - name: {f.name}")
            out.append(f"    from: {f.source}")
            out.append(f"    to: {f.dest}")
            if f.encrypted:
                out.append("    encrypted: true")
            if f.authenticated:
                out.append("    authenticated: true")
            if f.crosses_boundary:
                out.append("    crosses_boundary: true")
    return "\n".join(out) + "\n"


def to_json(obj: Any, indent: int = 2) -> str:
    import json
    if hasattr(obj, "to_dict"):
        obj = obj.to_dict()
    return json.dumps(obj, indent=indent, default=str)
