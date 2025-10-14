"""castellan — the keeper of your threat model.

An offline, self-hostable, MCP-native threat-modeling engine. Generates STRIDE
and LINDDUN threat models, DREAD-scored risk, attack trees, and compliance
mappings from a YAML system spec *or* straight from your Infrastructure-as-Code
(Terraform, CloudFormation, Kubernetes, docker-compose).

Part of the Cognis Neural Suite.
"""
from __future__ import annotations

import os as _os

TOOL_NAME = "castellan"


def _read_version() -> str:
    here = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    try:
        with open(_os.path.join(here, "VERSION"), "r", encoding="utf-8") as fh:
            v = fh.read().strip()
            if v:
                return v
    except Exception:  # pragma: no cover
        pass
    return "1.0.0"


TOOL_VERSION = _read_version()
__version__ = TOOL_VERSION

# Re-export the public engine API so `from castellan import parse_spec, scan` works.
try:  # pragma: no cover - exercised indirectly via tests
    from castellan.core import (  # noqa: F401
        SpecError,
        SystemSpec,
        Element,
        DataFlow,
        Threat,
        ThreatModel,
        AttackTreeNode,
        STRIDE_CATEGORIES,
        LINDDUN_CATEGORIES,
        parse_spec,
        build_threat_model,
        scan,
        to_json,
    )
except Exception:  # pragma: no cover
    pass

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "__version__",
    "SpecError",
    "SystemSpec",
    "Element",
    "DataFlow",
    "Threat",
    "ThreatModel",
    "AttackTreeNode",
    "STRIDE_CATEGORIES",
    "LINDDUN_CATEGORIES",
    "parse_spec",
    "build_threat_model",
    "scan",
    "to_json",
]
