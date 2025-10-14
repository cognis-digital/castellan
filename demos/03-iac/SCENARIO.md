# Demo 03 — Threat-model your Infrastructure-as-Code

`main.tf` is ordinary Terraform. castellan reads it directly — no diagram, no
hand-written spec — classifies each resource, flags encryption and public
exposure, synthesizes trust edges, and runs the full engine.

## Run it

```sh
castellan scan demos/03-iac/main.tf                  # auto-detect + model
castellan scan demos/03-iac/main.tf --format json
castellan import demos/03-iac/main.tf                # convert to an editable spec
castellan scan demos/03-iac/main.tf --fail-on high   # gate CI on IaC risk
```

Also works on CloudFormation templates, Kubernetes manifests, `docker-compose`
files, and whole directories (`castellan scan ./infra`) — every recognized file
is merged into one model.

## What to look for

- The `public-read` S3 bucket is flagged as publicly exposed and scored higher.
- The encrypted RDS instance records an `encrypt` control, lowering its residual
  Information-Disclosure risk.
- An `internet` external entity and trust edges are synthesized automatically.
