# Demo 02 — Privacy threat model (LINDDUN)

`health-portal.yml` models a telehealth portal that handles **PHI**. Because
the `records-db` is tagged `data_classification: phi` and the `analytics`
process sets `personal_data: true`, castellan adds **LINDDUN** privacy threats
(Linkability, Identifiability, Disclosure of Information, Detectability,
Non-compliance, …) on top of the STRIDE model.

## Run it

```sh
castellan analyze demos/02-privacy/health-portal.yml
castellan analyze demos/02-privacy/health-portal.yml --format json | \
  python -c "import sys,json;m=json.load(sys.stdin);print(m['summary']['by_methodology'])"
castellan compliance demos/02-privacy/health-portal.yml   # GDPR / ISO 27701 / HIPAA mapping
```

## What to look for

- `by_methodology` now reports both **STRIDE** and **LINDDUN**.
- The unencrypted `ship-to-analytics` flow carrying personal data raises a
  Disclosure-of-Information privacy threat.
- The compliance matrix maps privacy threats to GDPR articles, ISO/IEC 27701,
  the NIST Privacy Framework, and HIPAA.
