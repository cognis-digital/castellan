"""Risk scoring: DREAD, CIA impact, and a normalized 0-10 risk score.

castellan derives DREAD components from the structural facts it already knows
(threat category, exposure, trust-boundary crossing, declared controls) so every
threat gets a defensible, reproducible score — not a guess. The model's overall
risk score is the exposure-weighted aggregate of its unmitigated threats.
"""
from __future__ import annotations

from typing import Dict, List

# Base DREAD components per category, each 1..3 (Low/Med/High).
# D=Damage, R=Reproducibility, E=Exploitability, A=Affected users, Di=Discoverability
_DREAD_BASE: Dict[str, Dict[str, int]] = {
    "Spoofing":               {"D": 2, "R": 3, "E": 2, "A": 2, "Di": 2},
    "Tampering":              {"D": 3, "R": 2, "E": 2, "A": 2, "Di": 2},
    "Repudiation":            {"D": 1, "R": 2, "E": 2, "A": 1, "Di": 2},
    "Information Disclosure": {"D": 3, "R": 2, "E": 2, "A": 3, "Di": 2},
    "Denial of Service":      {"D": 2, "R": 3, "E": 3, "A": 3, "Di": 3},
    "Elevation of Privilege": {"D": 3, "R": 2, "E": 2, "A": 3, "Di": 1},
    # LINDDUN privacy categories scored on data-subject harm.
    "Linkability":                {"D": 2, "R": 2, "E": 2, "A": 3, "Di": 2},
    "Identifiability":            {"D": 2, "R": 2, "E": 2, "A": 3, "Di": 2},
    "Non-repudiation (privacy)":  {"D": 1, "R": 2, "E": 1, "A": 2, "Di": 2},
    "Detectability":              {"D": 1, "R": 2, "E": 2, "A": 2, "Di": 3},
    "Disclosure of Information":  {"D": 3, "R": 2, "E": 2, "A": 3, "Di": 2},
    "Unawareness":                {"D": 1, "R": 1, "E": 1, "A": 3, "Di": 2},
    "Non-compliance":             {"D": 2, "R": 1, "E": 1, "A": 3, "Di": 2},
}

# CIA impact each category primarily threatens.
_CIA: Dict[str, List[str]] = {
    "Spoofing": ["Integrity"],
    "Tampering": ["Integrity"],
    "Repudiation": ["Integrity"],
    "Information Disclosure": ["Confidentiality"],
    "Denial of Service": ["Availability"],
    "Elevation of Privilege": ["Confidentiality", "Integrity", "Availability"],
    "Disclosure of Information": ["Confidentiality"],
}

_clamp = lambda v: max(1, min(3, v))  # noqa: E731


def compute_dread(
    category: str,
    *,
    exposed: bool = False,
    crosses_boundary: bool = False,
    mitigated: bool = False,
) -> Dict[str, object]:
    """Return DREAD components, total (5..15), and a normalized 0-10 risk."""
    base = dict(_DREAD_BASE.get(category, {"D": 2, "R": 2, "E": 2, "A": 2, "Di": 2}))
    if exposed:
        base["E"] = _clamp(base["E"] + 1)
        base["Di"] = _clamp(base["Di"] + 1)
    if crosses_boundary:
        base["A"] = _clamp(base["A"] + 1)
    total = sum(base.values())  # 5..15
    risk = round((total / 15) * 10, 1)
    if mitigated:
        risk = round(risk * 0.4, 1)  # residual risk after a declared control
    return {
        "components": base,
        "total": total,
        "risk": risk,
        "level": risk_level(risk),
        "cia": _CIA.get(category, []),
    }


def risk_level(risk: float) -> str:
    if risk >= 8.0:
        return "critical"
    if risk >= 6.0:
        return "high"
    if risk >= 4.0:
        return "medium"
    if risk >= 2.0:
        return "low"
    return "info"


def aggregate_risk(risks: List[float]) -> float:
    """Aggregate per-threat risk into a single model score (0-10).

    Uses a soft-max style aggregate: dominated by the worst threats but nudged
    up by volume, so '20 highs' scores worse than 'one high'.
    """
    if not risks:
        return 0.0
    top = max(risks)
    avg = sum(risks) / len(risks)
    score = top * 0.7 + avg * 0.3
    return round(min(10.0, score), 1)
