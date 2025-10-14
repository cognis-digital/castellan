"""Infrastructure-as-Code importers.

Turn real IaC — Terraform, CloudFormation, Kubernetes manifests, and
docker-compose — directly into a castellan SystemSpec, so you can threat-model
what you actually deploy instead of a diagram that drifts from reality.

Each importer is dependency-free and tolerant: it extracts the resources,
identities, data stores, and trust edges it recognizes and maps them onto the
asset taxonomy the engine reasons about.
"""
from .common import RESOURCE_MAP, classify_resource  # noqa: F401
