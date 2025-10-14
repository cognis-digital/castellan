# castellan — Architecture

castellan turns a system description into a scored, referenced, compliance-mapped
threat model. Inputs are a YAML spec **or** Infrastructure-as-Code; outputs are
table / JSON / SARIF / Markdown / HTML / Mermaid.

```
spec.yml ─────────────┐
                      ├─▶ parse_spec ─▶ SystemSpec ─▶ build_threat_model ─▶ ThreatModel ─▶ report.render
IaC (tf/cfn/k8s) ─────┘        ▲                          │                                  │
   importers.import_path ──────┘                 enrich from library +              table·json·sarif
                                                 scoring + compliance               markdown·html·mermaid
```

## Modules

- **`core.py`** — the spec parser (stdlib-only YAML subset), the STRIDE + LINDDUN
  derivation engine, attack-tree builder, and the `scan` / `spec_from_path`
  path entry points.
- **`scoring.py`** — DREAD components, CIA impact, normalized 0–10 risk, and the
  model-level aggregate.
- **`library.py`** — the threat-pattern catalog (98 base patterns) materialized
  across the asset taxonomy into 5,000+ scenarios and 12,000+ requirements.
- **`compliance.py`** — maps each threat category to real control references.
- **`data/`** — reference knowledge: 625 frameworks, MITRE ATT&CK, CWE, OWASP,
  CAPEC, and the asset taxonomy.
- **`iac/`** + **`importers.py`** — Terraform / CloudFormation / Kubernetes /
  docker-compose importers and auto-detection.
- **`report.py`** — renderers for every output format.
- **`mcp_server.py`** — exposes the engine as MCP tools for AI agents.

## Extending

Add a `Pattern` to `library.BASE_PATTERNS` (with real CWE/CAPEC/ATT&CK refs), a
test, and — for new input kinds — an importer under `iac/`. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
