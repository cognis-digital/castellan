# Demo 01 - Basic web app threat model

This demo models a small web application with three trust zones:

- An external **user** (browser) — untrusted external entity.
- A **web-api** process that handles requests.
- A **user-db** PostgreSQL datastore holding credentials and PII.

The spec (`webapp.yml`) describes the elements and the data flows between
them, including which flows are encrypted, which are authenticated, and which
cross a trust boundary. The `web-api` declares a couple of security controls
so you can see THREATMODELER mark the corresponding STRIDE threats as
mitigated.

## Run it

Derive the full STRIDE threat model as a human-readable table:

```sh
python -m threatmodeler analyze demos/01-basic/webapp.yml
```

Emit JSON for piping into CI / dashboards:

```sh
python -m threatmodeler --format json analyze demos/01-basic/webapp.yml
```

Fail a CI job if any **unmitigated** threat is `high` or worse (this demo
spec is intentionally leaky, so this returns a non-zero exit code):

```sh
python -m threatmodeler analyze demos/01-basic/webapp.yml --fail-on high
echo "exit code: $?"
```

Validate the spec without generating the model:

```sh
python -m threatmodeler validate demos/01-basic/webapp.yml
```

## What to look for

- The unencrypted `db-query` flow that crosses a trust boundary is rated
  higher severity for Tampering / Information Disclosure.
- The `web-api` Spoofing and Denial-of-Service threats are marked mitigated
  because the element declares `mfa` and `rate-limit` controls.
- Each process/datastore element gets its own attack tree under
  `attack_trees` in the JSON output.
