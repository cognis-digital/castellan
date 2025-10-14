"""Security knowledge base: MITRE ATT&CK, CWE, OWASP, CAPEC and asset taxonomy.

Real reference identifiers used to give every derived threat concrete provenance
(a CWE weakness, a CAPEC pattern, an ATT&CK technique) instead of hand-wavy
prose. Kept as plain data so it is offline and auditable.
"""
from __future__ import annotations

from typing import Dict, List

# --------------------------------------------------------------------------- #
# MITRE ATT&CK Enterprise tactics (real TA identifiers + names).
# --------------------------------------------------------------------------- #
ATTACK_TACTICS: Dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# A representative set of real ATT&CK techniques keyed by id -> name.
ATTACK_TECHNIQUES: Dict[str, str] = {
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.004": "Credential Stuffing",
    "T1212": "Exploitation for Credential Access",
    "T1556": "Modify Authentication Process",
    "T1539": "Steal Web Session Cookie",
    "T1550": "Use Alternate Authentication Material",
    "T1606": "Forge Web Credentials",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1059": "Command and Scripting Interpreter",
    "T1203": "Exploitation for Client Execution",
    "T1068": "Exploitation for Privilege Escalation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1134": "Access Token Manipulation",
    "T1611": "Escape to Host",
    "T1610": "Deploy Container",
    "T1525": "Implant Internal Image",
    "T1499": "Endpoint Denial of Service",
    "T1498": "Network Denial of Service",
    "T1565": "Data Manipulation",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1530": "Data from Cloud Storage",
    "T1213": "Data from Information Repositories",
    "T1119": "Automated Collection",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1040": "Network Sniffing",
    "T1557": "Adversary-in-the-Middle",
    "T1552": "Unsecured Credentials",
    "T1552.001": "Credentials In Files",
    "T1528": "Steal Application Access Token",
    "T1098": "Account Manipulation",
    "T1136": "Create Account",
    "T1070": "Indicator Removal",
    "T1562": "Impair Defenses",
    "T1505": "Server Software Component",
    "T1195": "Supply Chain Compromise",
    "T1199": "Trusted Relationship",
    "T1213.003": "Code Repositories",
    "T1574": "Hijack Execution Flow",
    "T1027": "Obfuscated Files or Information",
    "T1592": "Gather Victim Host Information",
    "T1589": "Gather Victim Identity Information",
}

# --------------------------------------------------------------------------- #
# CWE Top 25 (2023) — real IDs and names.
# --------------------------------------------------------------------------- #
CWE_TOP25: Dict[str, str] = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-416": "Use After Free",
    "CWE-78": "OS Command Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-125": "Out-of-bounds Read",
    "CWE-22": "Path Traversal",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-862": "Missing Authorization",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-287": "Improper Authentication",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-77": "Command Injection",
    "CWE-119": "Improper Restriction of Operations within Memory Buffer",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-362": "Race Condition",
    "CWE-269": "Improper Privilege Management",
    "CWE-94": "Code Injection",
    "CWE-863": "Incorrect Authorization",
    "CWE-276": "Incorrect Default Permissions",
    # A few extra high-value weaknesses beyond the Top 25:
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-285": "Improper Authorization",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
}

# --------------------------------------------------------------------------- #
# OWASP catalogs (real).
# --------------------------------------------------------------------------- #
OWASP_TOP10_2021: Dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

OWASP_API_TOP10_2023: Dict[str, str] = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

OWASP_LLM_TOP10: Dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# --------------------------------------------------------------------------- #
# CAPEC mechanisms of attack (real CAPEC-1000 top-level domains/ids).
# --------------------------------------------------------------------------- #
CAPEC_MECHANISMS: Dict[str, str] = {
    "CAPEC-118": "Collect and Analyze Information",
    "CAPEC-119": "Manipulate Timing and State",
    "CAPEC-122": "Privilege Abuse",
    "CAPEC-152": "Inject Unexpected Items",
    "CAPEC-153": "Input Data Manipulation",
    "CAPEC-156": "Engage in Deceptive Interactions",
    "CAPEC-172": "Manipulate System Resources",
    "CAPEC-210": "Abuse Existing Functionality",
    "CAPEC-225": "Exploitation of Trusted Identifiers",
    "CAPEC-232": "Exploitation of Privilege/Trust",
    "CAPEC-233": "Privilege Escalation",
    "CAPEC-242": "Code Injection",
    "CAPEC-248": "Command Injection",
    "CAPEC-272": "Protocol Manipulation",
    "CAPEC-310": "Scanning for Vulnerable Software",
    "CAPEC-560": "Use of Known Domain Credentials",
    "CAPEC-593": "Session Hijacking",
    "CAPEC-600": "Credential Stuffing",
    "CAPEC-625": "Mobile Device Fault Injection",
}

# --------------------------------------------------------------------------- #
# Asset taxonomy — the element classes castellan reasons about. The threat
# library is generated across these so coverage scales with real architectures.
# --------------------------------------------------------------------------- #
# key -> (display label, normalized stride element type, tags)
ASSET_CLASSES: Dict[str, Dict[str, object]] = {
    "external_user":   {"label": "External user / client",      "type": "actor",     "tags": ["edge", "untrusted"]},
    "third_party_api": {"label": "Third-party API / SaaS",      "type": "external",  "tags": ["edge", "supply-chain"]},
    "web_app":         {"label": "Web application",             "type": "process",   "tags": ["app", "edge"]},
    "rest_api":        {"label": "REST/GraphQL API service",    "type": "process",   "tags": ["app", "api"]},
    "auth_service":    {"label": "Authentication service",      "type": "process",   "tags": ["app", "identity"]},
    "microservice":    {"label": "Backend microservice",       "type": "process",   "tags": ["app", "internal"]},
    "serverless_fn":   {"label": "Serverless function",        "type": "process",   "tags": ["app", "cloud"]},
    "batch_job":       {"label": "Batch / worker job",         "type": "process",   "tags": ["app", "internal"]},
    "llm_agent":       {"label": "LLM / AI agent",             "type": "process",   "tags": ["app", "ai"]},
    "mobile_app":      {"label": "Mobile application",         "type": "process",   "tags": ["app", "mobile", "edge"]},
    "sql_db":          {"label": "Relational database",        "type": "datastore", "tags": ["data", "internal"]},
    "nosql_db":        {"label": "NoSQL / document store",     "type": "datastore", "tags": ["data", "internal"]},
    "object_store":    {"label": "Object storage (S3/Blob/GCS)","type": "datastore","tags": ["data", "cloud"]},
    "cache":           {"label": "Cache (Redis/Memcached)",    "type": "datastore", "tags": ["data", "internal"]},
    "message_queue":   {"label": "Message queue / event bus",  "type": "datastore", "tags": ["data", "internal"]},
    "secret_store":    {"label": "Secrets manager / vault",    "type": "datastore", "tags": ["data", "identity"]},
    "data_lake":       {"label": "Data lake / warehouse",      "type": "datastore", "tags": ["data", "cloud"]},
    "vector_db":       {"label": "Vector database / index",    "type": "datastore", "tags": ["data", "ai"]},
    "container_host":  {"label": "Container / Kubernetes node", "type": "process",  "tags": ["infra", "containers"]},
    "ci_cd":           {"label": "CI/CD pipeline",             "type": "process",   "tags": ["infra", "supply-chain"]},
    "iam_role":        {"label": "Cloud IAM role / principal", "type": "process",   "tags": ["infra", "identity", "cloud"]},
    "network_edge":    {"label": "Load balancer / gateway",    "type": "process",   "tags": ["infra", "network", "edge"]},
    # ---- additional real component classes -------------------------------
    "graphql_api":     {"label": "GraphQL API",               "type": "process",   "tags": ["app", "api"]},
    "grpc_service":    {"label": "gRPC service",              "type": "process",   "tags": ["app", "api", "internal"]},
    "websocket_gw":    {"label": "WebSocket / realtime gateway","type": "process",  "tags": ["app", "api", "edge", "network"]},
    "identity_provider": {"label": "Identity provider (IdP/SSO)", "type": "process", "tags": ["app", "identity", "edge"]},
    "payment_service": {"label": "Payment / billing service",  "type": "process",   "tags": ["app", "api", "data"]},
    "email_gateway":   {"label": "Email / notification gateway","type": "process",  "tags": ["app", "edge", "network"]},
    "dns_service":     {"label": "DNS service",               "type": "process",   "tags": ["infra", "network", "edge"]},
    "vpn_gateway":     {"label": "VPN / remote-access gateway", "type": "process",  "tags": ["infra", "network", "edge", "identity"]},
    "bastion_host":    {"label": "Bastion / jump host",       "type": "process",   "tags": ["infra", "internal", "identity"]},
    "service_mesh":    {"label": "Service mesh / sidecar",    "type": "process",   "tags": ["infra", "internal", "network", "containers"]},
    "cdn_edge":        {"label": "CDN / edge cache",          "type": "process",   "tags": ["infra", "network", "edge", "cloud"]},
    "log_pipeline":    {"label": "Log / telemetry pipeline",  "type": "datastore", "tags": ["data", "internal", "infra"]},
    "monitoring":      {"label": "Monitoring / observability", "type": "process",  "tags": ["app", "internal", "infra"]},
    "feature_store":   {"label": "Feature / model store",     "type": "datastore", "tags": ["data", "ai"]},
    "search_index":    {"label": "Search index",              "type": "datastore", "tags": ["data", "app"]},
    "backup_vault":    {"label": "Backup / archive vault",    "type": "datastore", "tags": ["data", "cloud"]},
    "artifact_registry": {"label": "Artifact / image registry","type": "datastore", "tags": ["data", "supply-chain", "infra"]},
    # ---- third expansion: more real component classes --------------------
    "soap_api":        {"label": "SOAP / XML web service",    "type": "process",   "tags": ["app", "api"]},
    "webhook_receiver":{"label": "Webhook receiver",          "type": "process",   "tags": ["app", "api", "edge"]},
    "sse_endpoint":    {"label": "Server-sent events endpoint","type": "process",   "tags": ["app", "api", "edge"]},
    "api_management":  {"label": "API management gateway",    "type": "process",   "tags": ["app", "api", "edge", "network"]},
    "reverse_proxy":   {"label": "Reverse proxy",             "type": "process",   "tags": ["infra", "network", "edge"]},
    "waf":             {"label": "Web application firewall",  "type": "process",   "tags": ["infra", "network", "edge"]},
    "ldap_directory":  {"label": "LDAP / directory service",  "type": "datastore", "tags": ["data", "identity", "internal"]},
    "ad_domain":       {"label": "Active Directory domain",   "type": "process",   "tags": ["infra", "identity", "internal"]},
    "cert_authority":  {"label": "Certificate authority / PKI","type": "process",   "tags": ["infra", "identity", "internal"]},
    "hsm":             {"label": "Hardware security module",  "type": "datastore", "tags": ["data", "identity", "infra"]},
    "config_service":  {"label": "Configuration service",     "type": "datastore", "tags": ["data", "infra", "internal"]},
    "feature_flags":   {"label": "Feature-flag service",      "type": "process",   "tags": ["app", "internal"]},
    "admin_console":   {"label": "Admin console",             "type": "process",   "tags": ["app", "identity", "internal"]},
    "partner_portal":  {"label": "Partner / B2B portal",      "type": "process",   "tags": ["app", "edge", "supply-chain"]},
    "edi_gateway":     {"label": "EDI / B2B gateway",         "type": "process",   "tags": ["app", "supply-chain", "network"]},
    "sftp_server":     {"label": "SFTP / file-transfer server","type": "process",  "tags": ["app", "data", "edge", "network"]},
    "stream_processor":{"label": "Stream processor",          "type": "process",   "tags": ["app", "data", "internal"]},
    "etl_job":         {"label": "ETL / data pipeline job",   "type": "process",   "tags": ["app", "data", "internal"]},
    "scheduler":       {"label": "Scheduler / cron service",  "type": "process",   "tags": ["app", "internal", "infra"]},
    "notification_svc":{"label": "Notification service",      "type": "process",   "tags": ["app", "edge", "network"]},
    "sms_gateway":     {"label": "SMS gateway",               "type": "process",   "tags": ["app", "edge", "network"]},
    "push_service":    {"label": "Push-notification service", "type": "process",   "tags": ["app", "edge", "mobile"]},
    "mobile_backend":  {"label": "Mobile backend (BaaS)",     "type": "process",   "tags": ["app", "api", "mobile", "cloud"]},
    "browser_ext":     {"label": "Browser extension",         "type": "process",   "tags": ["app", "edge", "untrusted"]},
    "desktop_app":     {"label": "Desktop application",       "type": "process",   "tags": ["app", "edge"]},
    "ml_training":     {"label": "ML training pipeline",      "type": "process",   "tags": ["app", "ai", "data"]},
    "ml_inference":    {"label": "ML inference service",      "type": "process",   "tags": ["app", "ai", "api"]},
    "model_registry":  {"label": "Model registry",           "type": "datastore", "tags": ["data", "ai", "supply-chain"]},
    "prompt_gateway":  {"label": "LLM prompt gateway",        "type": "process",   "tags": ["app", "ai", "api", "edge"]},
    "agent_orchestrator": {"label": "Agent orchestrator",     "type": "process",   "tags": ["app", "ai", "internal"]},
    "tool_plugin":     {"label": "Agent tool / plugin",       "type": "process",   "tags": ["app", "ai", "supply-chain"]},
    "time_series_db":  {"label": "Time-series database",      "type": "datastore", "tags": ["data", "internal"]},
    "graph_db":        {"label": "Graph database",            "type": "datastore", "tags": ["data", "internal"]},
    "ledger_db":       {"label": "Ledger / append-only store","type": "datastore", "tags": ["data", "internal"]},
    "blockchain_node": {"label": "Blockchain / DLT node",     "type": "process",   "tags": ["app", "network", "data"]},
    "payment_gateway": {"label": "Payment gateway",           "type": "process",   "tags": ["app", "api", "edge", "data"]},
    "fraud_engine":    {"label": "Fraud / risk engine",       "type": "process",   "tags": ["app", "data", "internal"]},
    "kyc_service":     {"label": "KYC / identity-verify service","type": "process", "tags": ["app", "identity", "data"]},
    "analytics_pipeline": {"label": "Analytics pipeline",     "type": "process",   "tags": ["app", "data", "internal"]},
    "content_cms":     {"label": "Content management system", "type": "process",   "tags": ["app", "edge"]},
    "media_transcoder":{"label": "Media transcoder",          "type": "process",   "tags": ["app", "internal"]},
    "email_relay":     {"label": "Email relay / MTA",         "type": "process",   "tags": ["app", "edge", "network"]},
    "chatbot":         {"label": "Chatbot / conversational UI","type": "process",  "tags": ["app", "ai", "edge"]},
    "iot_device":      {"label": "IoT device",                "type": "process",   "tags": ["edge", "untrusted", "network"]},
    "edge_gateway":    {"label": "IoT / edge gateway",        "type": "process",   "tags": ["infra", "network", "edge"]},
    "ota_service":     {"label": "OTA firmware-update service","type": "process",   "tags": ["app", "supply-chain", "edge"]},
    "data_broker":     {"label": "Data subscription / broker","type": "datastore", "tags": ["data", "supply-chain"]},
    "report_store":    {"label": "Reporting / BI store",      "type": "datastore", "tags": ["data", "internal"]},
}

# Mitigation/control areas threats and requirements draw from.
CONTROL_AREAS: List[str] = [
    "authentication", "authorization", "session-management", "input-validation",
    "output-encoding", "cryptography-in-transit", "cryptography-at-rest",
    "secrets-management", "logging-and-monitoring", "rate-limiting",
    "network-segmentation", "least-privilege", "supply-chain-integrity",
    "data-minimization", "backup-and-recovery", "configuration-hardening",
]


def counts() -> Dict[str, int]:
    return {
        "attack_tactics": len(ATTACK_TACTICS),
        "attack_techniques": len(ATTACK_TECHNIQUES),
        "cwe": len(CWE_TOP25),
        "owasp_top10": len(OWASP_TOP10_2021),
        "owasp_api_top10": len(OWASP_API_TOP10_2023),
        "owasp_llm_top10": len(OWASP_LLM_TOP10),
        "capec_mechanisms": len(CAPEC_MECHANISMS),
        "asset_classes": len(ASSET_CLASSES),
        "control_areas": len(CONTROL_AREAS),
    }
