"""Output renderers for castellan threat models.

Formats: table (human), json, sarif (code-scanning), markdown (PRs/wikis),
html (standalone, shareable), and mermaid diagrams (data-flow + attack trees).
All renderers are stdlib-only and take a :class:`castellan.core.ThreatModel`.
"""
from __future__ import annotations

import html as _html
import json
from typing import List, Optional

from .core import ThreatModel, SystemSpec, AttackTreeNode, _SEVERITY_RANK

_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


# --------------------------------------------------------------------------- #
# Table
# --------------------------------------------------------------------------- #
def render_table(model: ThreatModel) -> str:
    s = model.summary()
    out: List[str] = []
    out.append(f"System: {model.system}")
    out.append(
        f"Threats: {s['total_threats']}  Unmitigated: {s['unmitigated']}  "
        f"Risk score: {s['risk_score']}/10  "
        f"Frameworks: {s['frameworks_referenced']}")
    methods = ", ".join(f"{k}:{v}" for k, v in s["by_methodology"].items())
    out.append(f"Methodologies: {methods}")
    out.append("")
    header = f"{'ID':<10} {'RISK':<5} {'SEVERITY':<9} {'METH':<8} {'CATEGORY':<24} {'M':<2} TARGET"
    out.append(header)
    out.append("-" * len(header))
    ordered = sorted(
        model.threats,
        key=lambda t: (-t.risk, -_SEVERITY_RANK[t.severity], t.category, t.target))
    for t in ordered:
        m = "Y" if t.mitigated else "-"
        out.append(
            f"{t.id:<10} {t.risk:<5} {t.severity:<9} {t.methodology:<8} "
            f"{t.category:<24} {m:<2} {t.target}")
    out.append("")
    out.append("By severity:")
    for sev in _SEV_ORDER:
        if sev in s["by_severity"]:
            out.append(f"  {sev:<9} {s['by_severity'][sev]}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def render_json(model: ThreatModel) -> str:
    return json.dumps(model.to_dict(), indent=2, default=str)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0
# --------------------------------------------------------------------------- #
def render_sarif(model: ThreatModel) -> str:
    from . import TOOL_NAME, TOOL_VERSION
    rule_ids = {}
    rules = []
    for t in model.threats:
        rid = f"{t.methodology}/{t.category}".replace(" ", "-")
        if rid not in rule_ids:
            rule_ids[rid] = True
            rules.append({
                "id": rid,
                "name": t.category.replace(" ", ""),
                "shortDescription": {"text": f"{t.methodology}: {t.category}"},
                "helpUri": "https://github.com/cognis-digital/castellan",
            })
    results = []
    for t in model.threats:
        if t.mitigated:
            continue
        rid = f"{t.methodology}/{t.category}".replace(" ", "-")
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(t.severity, "warning"),
            "message": {"text": f"{t.title} — {t.description}"},
            "properties": {
                "id": t.id, "risk": t.risk, "severity": t.severity,
                "cwe": t.cwe, "capec": t.capec, "attack": t.attack,
                "owasp": t.owasp, "target": t.target,
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"threat-model/{t.target}"},
                }
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME, "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/castellan",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def render_markdown(model: ThreatModel) -> str:
    s = model.summary()
    out: List[str] = []
    out.append(f"# Threat Model — {model.system}")
    if model.description:
        out.append(f"\n_{model.description}_")
    out.append("\n## Summary\n")
    out.append(f"- **Total threats:** {s['total_threats']}")
    out.append(f"- **Unmitigated:** {s['unmitigated']}")
    out.append(f"- **Risk score:** {s['risk_score']} / 10")
    out.append(f"- **Frameworks referenced:** {s['frameworks_referenced']}")
    out.append(f"- **Methodologies:** " + ", ".join(
        f"{k} ({v})" for k, v in s["by_methodology"].items()))
    out.append("\n## Threats\n")
    out.append("| ID | Risk | Severity | Methodology | Category | Target | Mitigated |")
    out.append("|----|------|----------|-------------|----------|--------|-----------|")
    ordered = sorted(model.threats, key=lambda t: (-t.risk, t.category))
    for t in ordered:
        out.append(
            f"| {t.id} | {t.risk} | {t.severity} | {t.methodology} | "
            f"{t.category} | {t.target} | {'✅' if t.mitigated else '❌'} |")
    out.append("\n## Detail\n")
    for t in ordered:
        out.append(f"### {t.id} · {t.title}")
        out.append(f"\n{t.description}\n")
        out.append(f"- **Risk:** {t.risk}/10 ({t.risk_level}) · **Severity:** {t.severity} · **CIA:** {', '.join(t.cia) or '—'}")
        if t.cwe or t.capec or t.attack or t.owasp:
            refs = []
            if t.cwe:
                refs.append("CWE: " + ", ".join(t.cwe))
            if t.attack:
                refs.append("ATT&CK: " + ", ".join(t.attack))
            if t.capec:
                refs.append("CAPEC: " + ", ".join(t.capec))
            if t.owasp:
                refs.append("OWASP: " + ", ".join(t.owasp))
            out.append("- **References:** " + " · ".join(refs))
        if t.mitigation:
            out.append(f"- **Mitigation:** {t.mitigation}")
        if t.compliance:
            out.append("- **Controls:** " + "; ".join(
                f"{fw} ({ctrl})" for fw, ctrl in t.compliance.items()))
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Mermaid diagrams
# --------------------------------------------------------------------------- #
def render_mermaid_dfd(spec: SystemSpec) -> str:
    shape = {"actor": ("[", "]"), "external": ("[/", "/]"),
             "process": ("((", "))"), "service": ("((", "))"),
             "datastore": ("[(", ")]"), "store": ("[(", ")]")}
    lines = ["flowchart LR"]
    ids = {}
    for i, e in enumerate(spec.elements):
        nid = f"n{i}"
        ids[e.name] = nid
        op, cl = shape.get(e.type, ("[", "]"))
        lines.append(f'  {nid}{op}"{e.name}<br/><i>{e.raw_type}</i>"{cl}')
    for fl in spec.flows:
        a = ids.get(fl.source); b = ids.get(fl.dest)
        if not a or not b:
            continue
        label = fl.name + ("" if fl.encrypted else " ⚠")
        arrow = "-->" if fl.encrypted else "-.->"
        lines.append(f'  {a} {arrow}|"{label}"| {b}')
    return "\n".join(lines)


def render_mermaid_attack_tree(name: str, root: AttackTreeNode) -> str:
    lines = ["flowchart TD"]
    counter = [0]

    def walk(node: AttackTreeNode, parent: Optional[str]):
        counter[0] += 1
        nid = f"a{counter[0]}"
        label = node.goal.replace('"', "'")
        tag = "{" + f'"{label}"' + "}" if node.operator in ("OR", "AND") else f'["{label}"]'
        lines.append(f"  {nid}{tag}")
        if parent:
            lines.append(f"  {parent} --> {nid}")
        for c in node.children:
            walk(c, nid)

    walk(root, None)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML (standalone, self-contained)
# --------------------------------------------------------------------------- #
def render_html(model: ThreatModel, spec: Optional[SystemSpec] = None) -> str:
    from . import TOOL_NAME, TOOL_VERSION
    s = model.summary()
    e = _html.escape

    def sev_color(sev: str) -> str:
        return {"critical": "#b91c1c", "high": "#dc2626", "medium": "#d97706",
                "low": "#65a30d", "info": "#6b7280"}.get(sev, "#6b7280")

    rows = []
    for t in sorted(model.threats, key=lambda x: (-x.risk, x.category)):
        refs = " ".join(f'<span class="ref">{e(r)}</span>'
                        for r in (t.cwe + t.attack + t.owasp))
        rows.append(
            f'<tr><td><code>{e(t.id)}</code></td>'
            f'<td><b>{t.risk}</b></td>'
            f'<td><span class="sev" style="background:{sev_color(t.severity)}">{e(t.severity)}</span></td>'
            f'<td>{e(t.methodology)}</td><td>{e(t.category)}</td>'
            f'<td>{e(t.target)}</td>'
            f'<td>{"✅" if t.mitigated else "❌"}</td>'
            f'<td>{e(t.title)}<br><small>{e(t.description)}</small><br>{refs}</td></tr>')

    diagrams = ""
    if spec is not None:
        diagrams += ('<h2>Data-flow diagram</h2><div class="mermaid">'
                     + e(render_mermaid_dfd(spec)) + "</div>")
    for nm, tree in list(model.attack_trees.items())[:6]:
        diagrams += (f'<h2>Attack tree — {e(nm)}</h2><div class="mermaid">'
                     + e(render_mermaid_attack_tree(nm, tree)) + "</div>")

    by_sev = " ".join(
        f'<span class="pill" style="background:{sev_color(k)}">{k}: {v}</span>'
        for k, v in s["by_severity"].items())

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>castellan · {e(model.system)}</title>
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>window.addEventListener('load',()=>{{if(window.mermaid)mermaid.initialize({{startOnLoad:true}});}});</script>
<style>
 :root{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1f2937}}
 body{{margin:0;background:#f8fafc}}
 header{{background:linear-gradient(90deg,#6b46c1,#2b6cb0);color:#fff;padding:28px 32px}}
 header h1{{margin:0;font-size:24px}} header p{{margin:6px 0 0;opacity:.9}}
 main{{max-width:1100px;margin:0 auto;padding:24px 32px}}
 .cards{{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}}
 .card{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:14px 18px;min-width:130px}}
 .card b{{font-size:26px;display:block}}
 .pill,.sev,.ref{{color:#fff;border-radius:999px;padding:2px 9px;font-size:12px}}
 .ref{{background:#475569;margin:1px;display:inline-block}}
 table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden}}
 th,td{{text-align:left;padding:9px 11px;border-bottom:1px solid #eef2f7;vertical-align:top;font-size:14px}}
 th{{background:#f1f5f9}} code{{background:#f1f5f9;padding:1px 5px;border-radius:5px}}
 .mermaid{{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin:10px 0;overflow:auto}}
 footer{{text-align:center;color:#6b7280;padding:24px;font-size:13px}}
</style></head><body>
<header><h1>🏰 castellan · {e(model.system)}</h1>
<p>{e(model.description or 'Threat model')} — generated by {e(TOOL_NAME)} {e(TOOL_VERSION)}</p></header>
<main>
 <div class="cards">
  <div class="card"><b>{s['total_threats']}</b>threats</div>
  <div class="card"><b>{s['unmitigated']}</b>unmitigated</div>
  <div class="card"><b>{s['risk_score']}</b>risk / 10</div>
  <div class="card"><b>{s['frameworks_referenced']}</b>frameworks</div>
 </div>
 <div>{by_sev}</div>
 {diagrams}
 <h2>Threats</h2>
 <table><thead><tr><th>ID</th><th>Risk</th><th>Severity</th><th>Method</th>
 <th>Category</th><th>Target</th><th>Mit.</th><th>Detail</th></tr></thead>
 <tbody>{''.join(rows)}</tbody></table>
</main>
<footer>Generated by <b>castellan</b> — the keeper of your threat model · Cognis Digital</footer>
</body></html>"""


def render(model: ThreatModel, fmt: str, spec: Optional[SystemSpec] = None) -> str:
    fmt = fmt.lower()
    if fmt == "table":
        return render_table(model)
    if fmt == "json":
        return render_json(model)
    if fmt == "sarif":
        return render_sarif(model)
    if fmt in ("md", "markdown"):
        return render_markdown(model)
    if fmt == "html":
        return render_html(model, spec)
    if fmt in ("mermaid", "dfd") and spec is not None:
        return render_mermaid_dfd(spec)
    raise ValueError(f"unknown format: {fmt}")
