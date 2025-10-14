"""Shared resource-type taxonomy for the IaC importers.

Maps concrete provider resource types (AWS/Azure/GCP/Kubernetes) onto the
castellan element model: (normalized element type, raw label, asset tags).
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

# substring-in-type -> (element type, label, default-trusted)
# Order matters: more specific keys should precede generic ones.
RESOURCE_MAP: Dict[str, Tuple[str, str]] = {
    # --- storage / data ---
    "s3_bucket": ("datastore", "object store"),
    "s3": ("datastore", "object store"),
    "storage_account": ("datastore", "object store"),
    "storage_bucket": ("datastore", "object store"),
    "blob": ("datastore", "object store"),
    "dynamodb": ("datastore", "NoSQL table"),
    "cosmosdb": ("datastore", "NoSQL database"),
    "firestore": ("datastore", "NoSQL database"),
    "documentdb": ("datastore", "NoSQL database"),
    "rds": ("datastore", "relational database"),
    "db_instance": ("datastore", "relational database"),
    "sql_database": ("datastore", "relational database"),
    "sql_server": ("datastore", "relational database"),
    "spanner": ("datastore", "relational database"),
    "redshift": ("datastore", "data warehouse"),
    "bigquery": ("datastore", "data warehouse"),
    "synapse": ("datastore", "data warehouse"),
    "elasticache": ("datastore", "cache"),
    "memorystore": ("datastore", "cache"),
    "redis": ("datastore", "cache"),
    "sqs": ("datastore", "message queue"),
    "sns": ("datastore", "message topic"),
    "kinesis": ("datastore", "event stream"),
    "pubsub": ("datastore", "event stream"),
    "eventhub": ("datastore", "event stream"),
    "servicebus": ("datastore", "message queue"),
    # --- secrets / identity ---
    "secretsmanager": ("datastore", "secrets manager"),
    "kms_key": ("datastore", "key management"),
    "key_vault": ("datastore", "secrets manager"),
    "ssm_parameter": ("datastore", "parameter store"),
    "iam_role": ("process", "IAM role"),
    "iam_user": ("actor", "IAM user"),
    "iam_policy": ("process", "IAM policy"),
    "service_account": ("process", "service account"),
    # --- compute / app ---
    "lambda": ("process", "serverless function"),
    "cloud_function": ("process", "serverless function"),
    "function_app": ("process", "serverless function"),
    "ecs_service": ("process", "container service"),
    "ecs_task": ("process", "container task"),
    "eks": ("process", "Kubernetes cluster"),
    "aks": ("process", "Kubernetes cluster"),
    "gke": ("process", "Kubernetes cluster"),
    "container": ("process", "container service"),
    "app_service": ("process", "web application"),
    "instance": ("process", "compute instance"),
    "virtual_machine": ("process", "compute instance"),
    "autoscaling": ("process", "compute fleet"),
    # --- edge / network ---
    "api_gateway": ("process", "API gateway"),
    "apigatewayv2": ("process", "API gateway"),
    "lb": ("process", "load balancer"),
    "alb": ("process", "load balancer"),
    "elb": ("process", "load balancer"),
    "cloudfront": ("process", "CDN / edge"),
    "front_door": ("process", "CDN / edge"),
    "application_gateway": ("process", "application gateway"),
}

# Encryption / hardening attribute hints -> control keywords for the element.
ENCRYPTION_HINTS = (
    "server_side_encryption", "encrypted", "encryption", "kms",
    "sse_algorithm", "storage_encrypted", "encryption_at_rest",
)
PUBLIC_HINTS = (
    "0.0.0.0/0", "public-read", "publicread", "publicly_accessible = true",
    "public_network_access_enabled = true", "::/0",
)


def classify_resource(rtype: str) -> Optional[Tuple[str, str]]:
    """Return (element_type, label) for a provider resource type, or None."""
    t = rtype.lower()
    for key, val in RESOURCE_MAP.items():
        if key in t:
            return val
    return None
