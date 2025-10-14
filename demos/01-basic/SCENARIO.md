# Demo 01 — Basic web app threat model

A small web application with three trust zones:

- An external **user** (browser) — untrusted external entity.
- A **web-api** process that handles requests (declares `mfa` + `rate-limit`).
- A **user-db** datastore.

`webapp.yml` describes the elements and the data flows between them, including
which are encrypted, authenticated, and which cross a trust boundary.

## Run it

```sh
castellan analyze demos/01-basic/webapp.yml                 # human table
castellan analyze demos/01-basic/webapp.yml --format json   # JSON for CI/dashboards
castellan analyze demos/01-basic/webapp.yml --format html -o webapp.html
castellan analyze demos/01-basic/webapp.yml --fail-on high  # non-zero exit on leaks
castellan validate demos/01-basic/webapp.yml
```

## What to look for

- The unencrypted `db-query` flow that crosses a trust boundary is rated higher
  for Tampering / Information Disclosure, with a higher DREAD risk score.
- `web-api` Spoofing and Denial-of-Service threats are marked **mitigated**
  because the element declares `mfa` and `rate-limit` controls.
- Each threat carries real CWE / CAPEC / ATT&CK / OWASP references and a
  compliance control matrix (NIST, ISO 27001, PCI, OWASP ASVS, …).
- Each process/datastore gets its own attack tree under `attack_trees`.
