"""castellan threat & requirements library.

A deterministic generator that materializes a large, *real* catalog of concrete
threat scenarios and security requirements by combining base attack patterns
(each tied to a CWE/CAPEC/ATT&CK/OWASP reference) with the asset taxonomy in
``data.knowledge``. This is how commercial threat libraries scale: a curated set
of patterns expanded across the asset classes they apply to.

Nothing here is invented at runtime — `stats()` counts exactly what ships, and
the CLI / README cite those numbers rather than asserting them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .data import knowledge as K


# --------------------------------------------------------------------------- #
# Base attack patterns. `applies` is a set of asset tags (or "*" for all). Each
# pattern carries real reference IDs so every generated scenario is traceable.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Pattern:
    category: str          # STRIDE or LINDDUN category
    vector: str            # short kebab id for the specific attack vector
    title: str             # human title (asset name is appended at materialize)
    description: str
    mitigation: str
    area: str              # control area
    base_severity: str
    applies: tuple         # asset tags this applies to, or ("*",)
    cwe: tuple = ()
    capec: tuple = ()
    attack: tuple = ()
    owasp: tuple = ()


# Severity ranks reused across the engine.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# STRIDE + LINDDUN category definitions.
STRIDE = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
]
LINDDUN = [
    "Linkability", "Identifiability", "Non-repudiation (privacy)",
    "Detectability", "Disclosure of Information", "Unawareness",
    "Non-compliance",
]

_ALL = ("*",)

BASE_PATTERNS: List[Pattern] = [
    # ---- Spoofing --------------------------------------------------------
    Pattern("Spoofing", "credential-theft", "Credential theft / replay",
            "An attacker steals or replays credentials or tokens to impersonate a legitimate principal.",
            "Enforce MFA and short-lived, audience-bound tokens; bind sessions to device/IP where feasible.",
            "authentication", "high", ("app", "identity", "edge"),
            cwe=("CWE-287", "CWE-798"), capec=("CAPEC-560", "CAPEC-600"),
            attack=("T1078", "T1110.004", "T1539"), owasp=("A07", "API2")),
    Pattern("Spoofing", "weak-auth", "Weak or missing authentication",
            "A critical function is reachable without strong authentication, allowing identity forgery.",
            "Require authentication on every non-public entry point; prefer phishing-resistant factors (FIDO2/WebAuthn).",
            "authentication", "high", ("app", "api", "edge"),
            cwe=("CWE-306", "CWE-287"), capec=("CAPEC-115",), attack=("T1078",), owasp=("A07", "API2")),
    Pattern("Spoofing", "token-forgery", "Token / assertion forgery",
            "Weak signing or validation lets an attacker forge JWTs, SAML assertions, or cloud tokens.",
            "Validate signature, issuer, audience and expiry; rotate signing keys; reject 'alg:none'.",
            "session-management", "high", ("app", "identity", "cloud"),
            cwe=("CWE-287", "CWE-345"), capec=("CAPEC-225",), attack=("T1606", "T1528"), owasp=("A07",)),
    Pattern("Spoofing", "service-impersonation", "Upstream service impersonation",
            "Without mutual authentication an attacker impersonates a trusted upstream/peer service.",
            "Use mTLS or signed service identities (SPIFFE/SVID); pin trust anchors.",
            "authentication", "medium", ("internal", "api", "supply-chain"),
            cwe=("CWE-287",), capec=("CAPEC-94",), attack=("T1557",), owasp=("A07",)),

    # ---- Tampering -------------------------------------------------------
    Pattern("Tampering", "injection", "Injection (SQL/NoSQL/command/code)",
            "Untrusted input is interpreted as code or query, letting an attacker alter execution or data.",
            "Use parameterized queries / safe APIs; validate and canonicalize input; least-privilege data accounts.",
            "input-validation", "high", ("app", "api", "data"),
            cwe=("CWE-89", "CWE-78", "CWE-94", "CWE-77"), capec=("CAPEC-242", "CAPEC-248"),
            attack=("T1190", "T1059"), owasp=("A03",)),
    Pattern("Tampering", "tamper-in-transit", "Tampering of data in transit",
            "Data on an unauthenticated/unencrypted channel can be modified before it is consumed.",
            "Enforce TLS 1.2+/1.3 with integrity protection; reject downgrade; verify message signatures.",
            "cryptography-in-transit", "high", ("edge", "api", "network"),
            cwe=("CWE-319", "CWE-345"), capec=("CAPEC-272",), attack=("T1557",), owasp=("A02",)),
    Pattern("Tampering", "tamper-at-rest", "Unauthorized modification at rest",
            "Weak access control or missing integrity checks allow stored data or config to be altered.",
            "Enforce least-privilege write access; use checksums/object-lock/WORM for critical records.",
            "cryptography-at-rest", "high", ("data",),
            cwe=("CWE-276", "CWE-862"), capec=("CAPEC-153",), attack=("T1565",), owasp=("A01",)),
    Pattern("Tampering", "deserialization", "Insecure deserialization",
            "Untrusted serialized objects are deserialized, enabling object/state tampering or RCE.",
            "Avoid native deserialization of untrusted data; use schema-validated formats; sign payloads.",
            "input-validation", "high", ("app", "api"),
            cwe=("CWE-502",), capec=("CAPEC-586",), attack=("T1059",), owasp=("A08",)),
    Pattern("Tampering", "supply-chain", "Build / dependency tampering",
            "A poisoned dependency, image, or pipeline step injects malicious code into the artifact.",
            "Pin and verify dependencies; sign artifacts (Sigstore); enforce SLSA provenance; protect CI secrets.",
            "supply-chain-integrity", "high", ("supply-chain",),
            cwe=("CWE-1357", "CWE-829"), capec=("CAPEC-538",), attack=("T1195", "T1199"), owasp=("A08",)),

    # ---- Repudiation -----------------------------------------------------
    Pattern("Repudiation", "no-audit", "Insufficient audit logging",
            "Security-relevant actions are not logged, so malicious activity cannot be attributed or proven.",
            "Log authn/authz decisions and state changes with actor, time, and request id; protect log integrity.",
            "logging-and-monitoring", "medium", _ALL,
            cwe=("CWE-778", "CWE-862"), capec=("CAPEC-93",), attack=("T1070",), owasp=("A09",)),
    Pattern("Repudiation", "log-tampering", "Log tampering / deletion",
            "An attacker alters or deletes logs to erase evidence of their actions.",
            "Ship logs to append-only/WORM storage off-host; sign or hash-chain log records.",
            "logging-and-monitoring", "medium", _ALL,
            cwe=("CWE-117", "CWE-532"), capec=("CAPEC-93",), attack=("T1070", "T1562"), owasp=("A09",)),

    # ---- Information Disclosure ------------------------------------------
    Pattern("Information Disclosure", "plaintext-transit", "Sensitive data exposed in transit",
            "Sensitive data crosses the network without encryption and can be intercepted.",
            "Encrypt all sensitive traffic (TLS); enable HSTS; disable legacy protocols/ciphers.",
            "cryptography-in-transit", "high", ("edge", "api", "network"),
            cwe=("CWE-319", "CWE-311"), capec=("CAPEC-157",), attack=("T1040",), owasp=("A02",)),
    Pattern("Information Disclosure", "plaintext-rest", "Sensitive data unencrypted at rest",
            "Stored sensitive data is unencrypted, exposing it on storage compromise or misconfig.",
            "Encrypt at rest with managed keys; separate key custody from data; restrict snapshot/backup access.",
            "cryptography-at-rest", "high", ("data",),
            cwe=("CWE-311", "CWE-326"), capec=("CAPEC-37",), attack=("T1530",), owasp=("A02",)),
    Pattern("Information Disclosure", "excessive-exposure", "Excessive data exposure / IDOR",
            "An endpoint returns more data than authorized or allows access to other users' objects.",
            "Enforce object- and field-level authorization; filter responses server-side; deny by default.",
            "authorization", "high", ("api", "app"),
            cwe=("CWE-639", "CWE-200"), capec=("CAPEC-122",), attack=("T1213",), owasp=("A01", "API1")),
    Pattern("Information Disclosure", "secrets-leak", "Secret / credential leakage",
            "Secrets are committed to code, baked into images, or logged, exposing downstream systems.",
            "Use a secrets manager; scan code/images for secrets; redact secrets from logs; rotate on exposure.",
            "secrets-management", "high", _ALL,
            cwe=("CWE-798", "CWE-532"), capec=("CAPEC-37",), attack=("T1552", "T1552.001"), owasp=("A05",)),
    Pattern("Information Disclosure", "verbose-errors", "Information leak via errors / side channels",
            "Verbose errors, stack traces, or timing reveal internal structure useful for attacks.",
            "Return generic errors to clients; log detail server-side; normalize timing on sensitive paths.",
            "output-encoding", "low", ("app", "api"),
            cwe=("CWE-209", "CWE-200"), capec=("CAPEC-54",), attack=("T1592",), owasp=("A05",)),
    Pattern("Information Disclosure", "ssrf", "Server-Side Request Forgery",
            "A server fetches an attacker-controlled URL, exposing internal services or cloud metadata.",
            "All-list outbound destinations; block link-local/metadata IPs; require auth on internal services.",
            "network-segmentation", "high", ("api", "app", "cloud"),
            cwe=("CWE-918",), capec=("CAPEC-664",), attack=("T1190",), owasp=("A10", "API7")),

    # ---- Denial of Service ----------------------------------------------
    Pattern("Denial of Service", "resource-exhaustion", "Resource exhaustion / flooding",
            "Unbounded requests or work exhaust CPU, memory, connections, or budget.",
            "Apply rate limits, quotas, timeouts, and autoscaling; shed load; cap request/work size.",
            "rate-limiting", "medium", _ALL,
            cwe=("CWE-400", "CWE-770"), capec=("CAPEC-125",), attack=("T1499", "T1498"), owasp=("A04", "API4")),
    Pattern("Denial of Service", "amplification", "Algorithmic / amplification abuse",
            "Crafted input triggers disproportionately expensive operations (regex, zip, query, recursion).",
            "Bound complexity; use safe parsers; paginate; reject pathological inputs early.",
            "rate-limiting", "medium", ("app", "api", "data"),
            cwe=("CWE-1333", "CWE-400"), capec=("CAPEC-492",), attack=("T1499",), owasp=("A04",)),

    # ---- Elevation of Privilege -----------------------------------------
    Pattern("Elevation of Privilege", "missing-authz", "Missing / broken authorization",
            "An action runs without an authorization check, letting users exceed their privileges.",
            "Centralize authorization; deny by default; enforce function- and object-level checks server-side.",
            "authorization", "critical", ("app", "api"),
            cwe=("CWE-862", "CWE-285", "CWE-863"), capec=("CAPEC-122",), attack=("T1068",), owasp=("A01", "API5")),
    Pattern("Elevation of Privilege", "overprivileged-identity", "Over-privileged identity / role",
            "A principal holds more permissions than needed; its compromise grants broad control.",
            "Apply least privilege; scope roles tightly; use just-in-time elevation; review IAM regularly.",
            "least-privilege", "high", ("identity", "cloud", "infra"),
            cwe=("CWE-269", "CWE-250"), capec=("CAPEC-122",), attack=("T1078", "T1098"), owasp=("A01",)),
    Pattern("Elevation of Privilege", "container-escape", "Container escape / host takeover",
            "A weak container boundary (privileged, hostPath, capabilities) lets a workload reach the host.",
            "Drop capabilities; run non-root/read-only FS; enforce seccomp/AppArmor; no privileged or hostPath.",
            "configuration-hardening", "high", ("containers",),
            cwe=("CWE-250", "CWE-269"), capec=("CAPEC-233",), attack=("T1611", "T1610"), owasp=("A05",)),
    Pattern("Elevation of Privilege", "confused-deputy", "Confused-deputy / trust boundary abuse",
            "A more-privileged component performs actions on behalf of a less-trusted caller without checks.",
            "Propagate and re-check caller identity; avoid ambient authority; scope downstream credentials.",
            "authorization", "high", ("internal", "api", "cloud"),
            cwe=("CWE-441",), capec=("CAPEC-233",), attack=("T1134",), owasp=("A04",)),

    # ---- Cloud / infra specific (STRIDE-tagged) -------------------------
    Pattern("Information Disclosure", "public-bucket", "Publicly exposed storage / data",
            "Object storage or a database is exposed to the public internet or 'any' principal.",
            "Block public access by default; require explicit, reviewed exceptions; enable access logging.",
            "configuration-hardening", "high", ("cloud", "data"),
            cwe=("CWE-732", "CWE-200"), capec=("CAPEC-37",), attack=("T1530",), owasp=("A05",)),
    Pattern("Spoofing", "no-mfa-admin", "Admin/root access without MFA",
            "Privileged cloud or admin accounts lack MFA, enabling takeover from a single stolen secret.",
            "Mandate MFA for all privileged access; alarm on root usage; prefer federated SSO.",
            "authentication", "high", ("cloud", "identity", "infra"),
            cwe=("CWE-308",), capec=("CAPEC-560",), attack=("T1078",), owasp=("A07",)),
    Pattern("Denial of Service", "no-backup", "No tested backup / recovery path",
            "Loss, ransomware, or corruption is unrecoverable because backups are missing or untested.",
            "Maintain immutable, off-account backups; test restores; define and rehearse RTO/RPO.",
            "backup-and-recovery", "medium", ("data", "cloud"),
            cwe=("CWE-404",), capec=(), attack=("T1485", "T1486"), owasp=()),

    # ---- AI / LLM specific ----------------------------------------------
    Pattern("Tampering", "prompt-injection", "Prompt injection / instruction hijack",
            "Untrusted content in the prompt or tool output overrides intended instructions of an LLM/agent.",
            "Isolate untrusted content; constrain tool scope; require human approval for high-impact actions.",
            "input-validation", "high", ("ai",),
            cwe=("CWE-20",), capec=("CAPEC-153",), attack=("T1059",), owasp=("A03",)),
    Pattern("Elevation of Privilege", "excessive-agency", "Excessive agent autonomy",
            "An AI agent holds broad tool/credential scope and can take harmful actions without guardrails.",
            "Least-privilege tool grants; allow-list actions; rate/spend caps; audit and human-in-the-loop.",
            "least-privilege", "high", ("ai",),
            cwe=("CWE-269",), capec=("CAPEC-122",), attack=("T1078",), owasp=("A04",)),
    Pattern("Information Disclosure", "model-data-leak", "Training/context data leakage",
            "Sensitive data in context, embeddings, or training set is reflected back to unauthorized users.",
            "Filter sensitive data from context/training; enforce per-tenant retrieval scoping; redact outputs.",
            "data-minimization", "high", ("ai", "data"),
            cwe=("CWE-200",), capec=(), attack=("T1213",), owasp=("A01",)),

    # ---- LINDDUN privacy patterns ---------------------------------------
    Pattern("Linkability", "cross-context-linking", "Linkable identifiers across contexts",
            "Stable identifiers let separate datasets or sessions be correlated to one data subject.",
            "Use context-scoped pseudonyms; rotate identifiers; avoid sharing keys across domains.",
            "data-minimization", "medium", ("data", "ai", "app"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Identifiability", "reidentification", "Re-identification of pseudonymized data",
            "Quasi-identifiers allow an attacker to re-identify individuals from 'anonymized' data.",
            "Apply k-anonymity/differential privacy; minimize quasi-identifiers; gate re-identification risk.",
            "data-minimization", "medium", ("data",),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Non-repudiation (privacy)", "undeniable-action", "Loss of plausible deniability",
            "Excessive, non-deniable logging of personal actions harms data-subject privacy.",
            "Log only what is necessary and lawful; support deniability where required; minimize retention.",
            "data-minimization", "low", ("data", "app"),
            cwe=(), capec=(), attack=(), owasp=()),
    Pattern("Detectability", "presence-disclosure", "Detectable presence of a record",
            "An attacker can infer that a record about an individual exists (e.g., via response differences).",
            "Normalize responses for present/absent records; avoid enumeration; rate-limit probing.",
            "output-encoding", "low", ("data", "api"),
            cwe=("CWE-204",), capec=(), attack=(), owasp=()),
    Pattern("Disclosure of Information", "excessive-collection", "Excessive personal-data collection",
            "More personal data is collected or retained than the purpose requires.",
            "Apply data minimization and purpose limitation; define retention and deletion; map data flows.",
            "data-minimization", "medium", ("data", "app", "ai"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Unawareness", "no-transparency", "Data subject unaware of processing",
            "Individuals are not informed about how their personal data is processed or shared.",
            "Provide clear notice and consent; surface processing purposes; honor preference signals.",
            "data-minimization", "low", ("app", "edge"),
            cwe=(), capec=(), attack=(), owasp=()),
    Pattern("Non-compliance", "policy-gap", "Processing without a lawful/compliant basis",
            "Personal data is processed without a documented lawful basis or required control mapping.",
            "Maintain a record of processing; map controls to applicable regimes; run DPIAs for high risk.",
            "data-minimization", "medium", ("data", "app"),
            cwe=(), capec=(), attack=(), owasp=()),
]

# --------------------------------------------------------------------------- #
# Extended attack-vector library. Each is a distinct, real-world vector; the
# engine materializes one concrete scenario per applicable asset class.
# --------------------------------------------------------------------------- #
BASE_PATTERNS += [
    # ---- Spoofing -------------------------------------------------------
    Pattern("Spoofing", "session-fixation", "Session fixation / hijacking",
            "An attacker fixes or steals a session identifier to ride a victim's authenticated session.",
            "Rotate session IDs on auth; bind sessions to client context; set Secure/HttpOnly/SameSite.",
            "session-management", "medium", ("app", "api", "edge"),
            cwe=("CWE-384", "CWE-613"), capec=("CAPEC-593",), attack=("T1539", "T1550"), owasp=("A07",)),
    Pattern("Spoofing", "mfa-bypass", "MFA bypass / fatigue",
            "Weak MFA flows (push fatigue, SMS interception, recovery abuse) let attackers bypass second factor.",
            "Use phishing-resistant MFA; number matching; rate-limit prompts; harden account recovery.",
            "authentication", "high", ("identity", "app", "edge"),
            cwe=("CWE-287", "CWE-308"), capec=("CAPEC-560",), attack=("T1556", "T1621"), owasp=("A07",)),
    Pattern("Spoofing", "oauth-misconfig", "OAuth/OIDC misconfiguration",
            "Loose redirect URIs, implicit flow, or missing PKCE allow token theft and account takeover.",
            "Enforce exact redirect URIs and PKCE; validate state/nonce; use authorization-code flow.",
            "authentication", "high", ("identity", "api", "app"),
            cwe=("CWE-601", "CWE-287"), capec=("CAPEC-219",), attack=("T1528",), owasp=("A07",)),
    Pattern("Spoofing", "default-credentials", "Default / shared credentials",
            "Components ship with default or shared credentials that are never rotated.",
            "Force credential change on first use; ban shared accounts; detect default creds in CI.",
            "authentication", "high", ("infra", "internal", "containers", "data"),
            cwe=("CWE-1392", "CWE-798"), capec=("CAPEC-70",), attack=("T1078",), owasp=("A07",)),
    Pattern("Spoofing", "lateral-cred-reuse", "Credential reuse for lateral movement",
            "Shared or cached credentials let an attacker pivot between internal services.",
            "Scope credentials per service; rotate; use workload identity; segment trust.",
            "least-privilege", "high", ("internal", "infra"),
            cwe=("CWE-522",), capec=("CAPEC-560",), attack=("T1550", "T1078"), owasp=("A07",)),

    # ---- Tampering ------------------------------------------------------
    Pattern("Tampering", "xss", "Cross-site scripting (XSS)",
            "Unescaped output lets an attacker run script in a victim's browser session.",
            "Context-aware output encoding; CSP; sanitize HTML; use framework auto-escaping.",
            "output-encoding", "high", ("app", "edge"),
            cwe=("CWE-79",), capec=("CAPEC-63",), attack=("T1059",), owasp=("A03",)),
    Pattern("Tampering", "csrf", "Cross-site request forgery (CSRF)",
            "A victim's browser is tricked into submitting a state-changing request.",
            "Use anti-CSRF tokens and SameSite cookies; require re-auth for sensitive actions.",
            "session-management", "medium", ("app", "edge"),
            cwe=("CWE-352",), capec=("CAPEC-62",), attack=(), owasp=("A01",)),
    Pattern("Tampering", "mass-assignment", "Mass assignment / over-binding",
            "Clients set fields they should not by submitting unexpected properties.",
            "Allow-list bindable fields; separate input DTOs from entities; ignore unknown fields.",
            "input-validation", "high", ("api", "app"),
            cwe=("CWE-915",), capec=("CAPEC-1",), attack=(), owasp=("A08", "API3")),
    Pattern("Tampering", "path-traversal", "Path traversal / file inclusion",
            "Untrusted path input escapes the intended directory to read or write arbitrary files.",
            "Canonicalize and validate paths; use safe file APIs; run with least file privilege.",
            "input-validation", "high", ("app", "api"),
            cwe=("CWE-22",), capec=("CAPEC-126",), attack=("T1083",), owasp=("A01",)),
    Pattern("Tampering", "malicious-upload", "Malicious file upload",
            "Unrestricted uploads let an attacker plant webshells or trigger parser exploits.",
            "Validate type/size; store outside webroot; scan content; serve from a sandboxed domain.",
            "input-validation", "high", ("app", "api", "data"),
            cwe=("CWE-434",), capec=("CAPEC-650",), attack=("T1505",), owasp=("A04",)),
    Pattern("Tampering", "request-smuggling", "HTTP request smuggling / cache poisoning",
            "Desync between proxies and origin lets an attacker poison caches or hijack requests.",
            "Normalize parsing across hops; reject ambiguous length/encoding; segment caches by key.",
            "input-validation", "high", ("edge", "network", "api"),
            cwe=("CWE-444",), capec=("CAPEC-33",), attack=("T1557",), owasp=("A05",)),
    Pattern("Tampering", "iac-misconfig", "Insecure-by-default IaC",
            "Templates ship insecure defaults (open ports, public access, weak TLS) that reach production.",
            "Scan IaC pre-merge; enforce secure baselines as policy-as-code; block on high findings.",
            "configuration-hardening", "high", ("infra", "cloud", "supply-chain", "containers"),
            cwe=("CWE-1188", "CWE-16"), capec=(), attack=(), owasp=("A05",)),
    Pattern("Tampering", "race-condition", "Race condition / TOCTOU",
            "Concurrent operations on shared state produce inconsistent or exploitable outcomes.",
            "Use atomic operations/locks; idempotency keys; validate at time-of-use, not check.",
            "input-validation", "medium", ("app", "api", "data"),
            cwe=("CWE-362", "CWE-367"), capec=("CAPEC-29",), attack=(), owasp=("A04",)),

    # ---- Repudiation ----------------------------------------------------
    Pattern("Repudiation", "weak-time-source", "Untrusted timestamps",
            "Log timestamps rely on a manipulable local clock, undermining forensic ordering.",
            "Use a trusted time source (NTP/secure); record server time; monotonic sequence ids.",
            "logging-and-monitoring", "low", _ALL,
            cwe=("CWE-829",), capec=(), attack=("T1070",), owasp=("A09",)),
    Pattern("Repudiation", "no-correlation-id", "No request/trace correlation",
            "Actions cannot be traced end-to-end across services for attribution.",
            "Propagate a correlation/trace id through all hops and into logs.",
            "logging-and-monitoring", "low", ("app", "api", "internal"),
            cwe=("CWE-778",), capec=(), attack=(), owasp=("A09",)),

    # ---- Information Disclosure -----------------------------------------
    Pattern("Information Disclosure", "metadata-creds", "Cloud metadata credential theft",
            "An SSRF or compromised workload reads the instance metadata service to steal credentials.",
            "Enforce IMDSv2/hop-limit; block metadata IP egress; scope workload credentials tightly.",
            "secrets-management", "high", ("cloud", "containers", "api"),
            cwe=("CWE-918", "CWE-522"), capec=("CAPEC-664",), attack=("T1552",), owasp=("A10",)),
    Pattern("Information Disclosure", "debug-endpoint", "Exposed debug / admin endpoint",
            "Debug consoles, actuators, or admin panels are reachable without strong controls.",
            "Disable debug in prod; bind admin to private networks; require strong authn/authz.",
            "configuration-hardening", "high", ("app", "api", "edge"),
            cwe=("CWE-489", "CWE-215"), capec=("CAPEC-121",), attack=("T1592",), owasp=("A05",)),
    Pattern("Information Disclosure", "graphql-introspection", "Excessive API/schema introspection",
            "Introspection or verbose schemas reveal internal structure and hidden operations.",
            "Disable introspection in prod; apply field-level authz; throttle and depth-limit queries.",
            "authorization", "medium", ("api",),
            cwe=("CWE-200",), capec=("CAPEC-54",), attack=("T1592",), owasp=("A05", "API9")),
    Pattern("Information Disclosure", "backup-exposure", "Unprotected backups / snapshots",
            "Backups and snapshots are exposed or shared without the protections of the live data.",
            "Encrypt and access-control backups; restrict snapshot sharing; audit access.",
            "cryptography-at-rest", "high", ("data", "cloud"),
            cwe=("CWE-530", "CWE-200"), capec=("CAPEC-37",), attack=("T1530",), owasp=("A02",)),
    Pattern("Information Disclosure", "insecure-mobile-storage", "Insecure on-device storage",
            "A mobile app stores secrets or personal data in cleartext on the device.",
            "Use the platform keystore/keychain; encrypt local data; avoid logging sensitive data.",
            "cryptography-at-rest", "high", ("mobile",),
            cwe=("CWE-312", "CWE-922"), capec=("CAPEC-37",), attack=(), owasp=("A02",)),

    # ---- Denial of Service ----------------------------------------------
    Pattern("Denial of Service", "billing-dos", "Denial of wallet / cost amplification",
            "Unbounded paid operations (egress, compute, LLM tokens) let attackers run up the bill.",
            "Cap spend and concurrency; budget alarms; quota per tenant; backpressure.",
            "rate-limiting", "medium", ("cloud", "ai", "api"),
            cwe=("CWE-400",), capec=("CAPEC-125",), attack=("T1496",), owasp=("API4",)),
    Pattern("Denial of Service", "unbounded-pagination", "Unbounded query / pagination",
            "Endpoints return unbounded result sets, exhausting memory and bandwidth.",
            "Enforce max page size and total caps; cursor pagination; server-side limits.",
            "rate-limiting", "medium", ("api", "data"),
            cwe=("CWE-770",), capec=("CAPEC-125",), attack=("T1499",), owasp=("API4",)),
    Pattern("Denial of Service", "pool-exhaustion", "Connection / thread pool exhaustion",
            "Slow or abundant clients exhaust connection, thread, or socket pools.",
            "Set timeouts and pool limits; shed load; circuit-break dependencies.",
            "rate-limiting", "medium", ("app", "api", "internal"),
            cwe=("CWE-400", "CWE-410"), capec=("CAPEC-469",), attack=("T1499",), owasp=("A04",)),

    # ---- Elevation of Privilege -----------------------------------------
    Pattern("Elevation of Privilege", "idor", "Insecure direct object reference (IDOR)",
            "Predictable identifiers let a user access or modify objects belonging to others.",
            "Enforce per-object ownership checks server-side; use unguessable references; deny by default.",
            "authorization", "high", ("api", "app"),
            cwe=("CWE-639", "CWE-862"), capec=("CAPEC-122",), attack=(), owasp=("A01", "API1")),
    Pattern("Elevation of Privilege", "k8s-rbac-excess", "Excessive Kubernetes RBAC / privileges",
            "Wildcard RBAC, cluster-admin bindings, or privileged pods enable cluster takeover.",
            "Least-privilege RBAC; no wildcard verbs; Pod Security admission; separate namespaces.",
            "least-privilege", "high", ("containers",),
            cwe=("CWE-269", "CWE-250"), capec=("CAPEC-233",), attack=("T1611",), owasp=("A01",)),
    Pattern("Elevation of Privilege", "cloud-priv-esc", "Cloud IAM privilege-escalation chain",
            "Permissive IAM (iam:PassRole, policy edit, function update) chains into full account control.",
            "Remove escalation primitives; permission boundaries; review with IAM analyzers.",
            "least-privilege", "critical", ("cloud", "identity"),
            cwe=("CWE-269",), capec=("CAPEC-233",), attack=("T1078", "T1098"), owasp=("A01",)),
    Pattern("Elevation of Privilege", "secret-to-rce", "Leaked secret to remote code execution",
            "A leaked CI or cloud credential is used to push code or run workloads with high privilege.",
            "Short-lived, scoped CI credentials; OIDC federation; protect runners; sign releases.",
            "secrets-management", "critical", ("supply-chain", "cloud", "infra"),
            cwe=("CWE-798", "CWE-269"), capec=("CAPEC-560",), attack=("T1078", "T1199"), owasp=("A08",)),

    # ---- AI / LLM -------------------------------------------------------
    Pattern("Tampering", "rag-poisoning", "RAG / data-source poisoning",
            "Poisoned documents in a retrieval corpus steer the model toward attacker goals.",
            "Vet and sign ingested sources; isolate tenants; provenance on retrieved chunks.",
            "supply-chain-integrity", "high", ("ai", "data"),
            cwe=("CWE-20",), capec=("CAPEC-153",), attack=("T1195",), owasp=("A08",)),
    Pattern("Information Disclosure", "system-prompt-leak", "System-prompt / instruction leakage",
            "Crafted inputs coax the model into revealing its system prompt or hidden config.",
            "Treat the system prompt as non-secret; keep secrets out of context; monitor for exfil patterns.",
            "data-minimization", "medium", ("ai",),
            cwe=("CWE-200",), capec=(), attack=("T1213",), owasp=("A05",)),
    Pattern("Tampering", "insecure-output-handling", "Unsafe handling of model output",
            "Model output is passed to a shell, SQL, browser, or tool without validation.",
            "Treat model output as untrusted; encode/validate before use; constrain downstream actions.",
            "output-encoding", "high", ("ai", "app"),
            cwe=("CWE-79", "CWE-94"), capec=("CAPEC-242",), attack=("T1059",), owasp=("A03",)),
    Pattern("Information Disclosure", "membership-inference", "Membership / model-inversion inference",
            "An attacker infers training-set membership or reconstructs data from model behavior.",
            "Limit output confidence/granularity; apply differential privacy; throttle probing.",
            "data-minimization", "medium", ("ai",),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),

    # ---- LINDDUN privacy extensions -------------------------------------
    Pattern("Disclosure of Information", "third-party-sharing", "Unvetted third-party data sharing",
            "Personal data is shared with processors/partners without contracts or controls.",
            "Maintain processor inventory and DPAs; minimize shared fields; verify partner controls.",
            "supply-chain-integrity", "medium", ("data", "supply-chain", "app"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Non-compliance", "retention-violation", "Retention / deletion non-compliance",
            "Personal data is kept past its lawful retention period or deletion requests are not honored.",
            "Automate retention and deletion; honor subject requests; log lifecycle events.",
            "data-minimization", "medium", ("data", "app"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Linkability", "profiling", "Behavioral profiling / secondary use",
            "Data collected for one purpose is repurposed to profile data subjects.",
            "Enforce purpose limitation; separate datasets; require consent for secondary use.",
            "data-minimization", "medium", ("data", "ai", "app"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Non-compliance", "cross-border-transfer", "Unlawful cross-border transfer",
            "Personal data is transferred across jurisdictions without an adequate legal mechanism.",
            "Map data residency; use SCCs/adequacy mechanisms; pin storage regions.",
            "data-minimization", "medium", ("data", "cloud"),
            cwe=(), capec=(), attack=(), owasp=()),

    # ---- Broadly-applicable hygiene patterns ----------------------------
    Pattern("Tampering", "vulnerable-components", "Vulnerable / outdated components",
            "Known-vulnerable dependencies, images, or runtimes expose the asset to public exploits.",
            "Maintain an SBOM; patch on a schedule; scan dependencies/images; pin and verify versions.",
            "supply-chain-integrity", "high", _ALL,
            cwe=("CWE-1104", "CWE-937"), capec=("CAPEC-310",), attack=("T1190", "T1195"), owasp=("A06",)),
    Pattern("Elevation of Privilege", "security-misconfiguration", "Security misconfiguration",
            "Insecure defaults, unnecessary features, or permissive settings widen the attack surface.",
            "Apply hardened baselines; remove unused features; review config drift; least functionality.",
            "configuration-hardening", "high", _ALL,
            cwe=("CWE-16", "CWE-1188"), capec=("CAPEC-1",), attack=("T1190",), owasp=("A05",)),
    Pattern("Repudiation", "missing-monitoring", "Missing detection / alerting",
            "Attacks proceed undetected because there is no monitoring, alerting, or response coverage.",
            "Define detections for key abuse cases; alert with SLAs; test with purple-team exercises.",
            "logging-and-monitoring", "medium", _ALL,
            cwe=("CWE-778", "CWE-223"), capec=(), attack=("T1562",), owasp=("A09",)),
    Pattern("Information Disclosure", "weak-tls-config", "Weak transport security configuration",
            "Legacy protocols, weak ciphers, or unvalidated certificates weaken transport security.",
            "Require TLS 1.2+/1.3; disable weak ciphers; validate certs; enable HSTS; rotate keys.",
            "cryptography-in-transit", "high", ("edge", "api", "network", "internal"),
            cwe=("CWE-326", "CWE-327", "CWE-295"), capec=("CAPEC-217",), attack=("T1557",), owasp=("A02",)),
    Pattern("Spoofing", "dependency-confusion", "Dependency confusion / typosquat",
            "A build resolves an attacker-published package from a public registry instead of the intended one.",
            "Pin registries and namespaces; verify package provenance; reserve internal names publicly.",
            "supply-chain-integrity", "high", ("supply-chain", "app", "api", "ai"),
            cwe=("CWE-829", "CWE-427"), capec=("CAPEC-538",), attack=("T1195",), owasp=("A08",)),

    # ---- Third batch: additional real vectors ---------------------------
    Pattern("Spoofing", "weak-password-policy", "Weak password / no lockout policy",
            "Weak password rules and missing lockout enable brute force and guessing.",
            "Enforce strong policy and breached-password checks; lockout/backoff; prefer passkeys.",
            "authentication", "medium", ("app", "api", "identity", "edge"),
            cwe=("CWE-521", "CWE-307"), capec=("CAPEC-49",), attack=("T1110",), owasp=("A07",)),
    Pattern("Spoofing", "api-key-no-rotation", "Long-lived / unrotated API keys",
            "Static, long-lived API keys are widely distributed and never rotated.",
            "Use short-lived tokens / workload identity; rotate keys; scope per consumer; revoke fast.",
            "secrets-management", "medium", ("api", "app", "cloud", "supply-chain"),
            cwe=("CWE-798",), capec=("CAPEC-560",), attack=("T1528",), owasp=("API2",)),
    Pattern("Spoofing", "replay-attack", "Message replay",
            "Captured requests/messages are replayed because they lack nonces or freshness checks.",
            "Add nonces, timestamps, and idempotency keys; bind requests to a session; short TTLs.",
            "session-management", "medium", ("api", "network", "edge", "internal"),
            cwe=("CWE-294",), capec=("CAPEC-60",), attack=("T1550",), owasp=("A07",)),
    Pattern("Spoofing", "webhook-spoofing", "Unverified inbound webhooks",
            "Inbound webhooks are processed without verifying signatures or source.",
            "Verify HMAC signatures and source allow-lists; reject unsigned; replay-protect.",
            "authentication", "medium", ("api", "edge", "supply-chain"),
            cwe=("CWE-345",), capec=("CAPEC-94",), attack=("T1190",), owasp=("API8",)),

    Pattern("Tampering", "xxe", "XML external entity (XXE) injection",
            "An XML parser resolves external entities, enabling file read, SSRF, or DoS.",
            "Disable DTD/external entity resolution; use hardened parsers; validate schemas.",
            "input-validation", "high", ("app", "api"),
            cwe=("CWE-611",), capec=("CAPEC-201",), attack=("T1059",), owasp=("A05",)),
    Pattern("Tampering", "open-redirect", "Open redirect",
            "Unvalidated redirect targets enable phishing and token leakage via referer.",
            "Allow-list redirect destinations; use relative paths; never reflect raw URLs.",
            "input-validation", "medium", ("app", "api", "edge"),
            cwe=("CWE-601",), capec=("CAPEC-194",), attack=(), owasp=("A01",)),
    Pattern("Tampering", "cors-misconfig", "Permissive CORS configuration",
            "Wildcard or reflected CORS origins with credentials expose data to malicious sites.",
            "Allow-list specific origins; never reflect origin with credentials; restrict methods.",
            "configuration-hardening", "medium", ("app", "api", "edge"),
            cwe=("CWE-942",), capec=("CAPEC-141",), attack=(), owasp=("A05",)),
    Pattern("Tampering", "clickjacking", "Clickjacking / UI redress",
            "The UI can be framed by an attacker to trick users into unintended actions.",
            "Set frame-ancestors CSP / X-Frame-Options; confirm sensitive actions.",
            "output-encoding", "low", ("app", "edge"),
            cwe=("CWE-1021",), capec=("CAPEC-103",), attack=(), owasp=("A05",)),
    Pattern("Tampering", "unsigned-artifacts", "Unsigned / unverified artifacts",
            "Deployable artifacts are not signed or verified, allowing substitution.",
            "Sign artifacts (Sigstore); verify signatures at deploy; enforce admission policy.",
            "supply-chain-integrity", "high", ("supply-chain", "app", "api", "containers", "ai"),
            cwe=("CWE-347",), capec=("CAPEC-538",), attack=("T1195",), owasp=("A08",)),

    Pattern("Repudiation", "no-admin-action-log", "Unlogged privileged actions",
            "Administrative and configuration changes are not individually attributable.",
            "Log all admin/config actions with actor and before/after; alert on sensitive changes.",
            "logging-and-monitoring", "medium", _ALL,
            cwe=("CWE-778",), capec=("CAPEC-93",), attack=("T1070",), owasp=("A09",)),

    Pattern("Information Disclosure", "sensitive-data-in-url", "Sensitive data in URLs / referrer",
            "Tokens or personal data placed in URLs leak via logs, history, and referrer headers.",
            "Keep secrets/PII out of URLs; use POST bodies/headers; set Referrer-Policy.",
            "data-minimization", "medium", ("app", "api", "edge"),
            cwe=("CWE-598",), capec=("CAPEC-37",), attack=(), owasp=("A02",)),
    Pattern("Information Disclosure", "verbose-headers", "Information leak via headers/banners",
            "Server banners and verbose headers reveal versions and internals for targeting.",
            "Strip version/banner headers; standardize responses; minimize fingerprinting.",
            "configuration-hardening", "low", ("app", "api", "edge", "network"),
            cwe=("CWE-200",), capec=("CAPEC-170",), attack=("T1592",), owasp=("A05",)),
    Pattern("Information Disclosure", "directory-listing", "Directory listing / exposed files",
            "Auto-indexing or stray files expose source, configs, or data.",
            "Disable directory listing; remove stray files; deny by default; scan exposed paths.",
            "configuration-hardening", "medium", ("app", "edge", "data"),
            cwe=("CWE-548",), capec=("CAPEC-127",), attack=("T1083",), owasp=("A05",)),

    Pattern("Denial of Service", "no-timeout", "Missing timeouts / circuit breakers",
            "Calls without timeouts let one slow dependency cascade into a full outage.",
            "Set client/server timeouts; circuit-break; bulkhead; fail fast with fallbacks.",
            "rate-limiting", "medium", ("app", "api", "internal", "network"),
            cwe=("CWE-400",), capec=("CAPEC-469",), attack=("T1499",), owasp=("A04",)),
    Pattern("Denial of Service", "cache-stampede", "Cache stampede / thundering herd",
            "Mass cache expiry sends a surge of identical requests to the origin.",
            "Stagger TTLs; request coalescing; serve-stale-while-revalidate; backpressure.",
            "rate-limiting", "low", ("app", "api", "data"),
            cwe=("CWE-400",), capec=("CAPEC-125",), attack=("T1499",), owasp=("A04",)),

    Pattern("Elevation of Privilege", "jwt-claim-tamper", "JWT claim / role tampering",
            "Trusting unverified or client-mutable JWT claims lets users escalate roles.",
            "Verify signatures server-side; never trust client claims for authz; re-check on each request.",
            "authorization", "high", ("api", "app", "identity"),
            cwe=("CWE-287", "CWE-863"), capec=("CAPEC-225",), attack=("T1606",), owasp=("A01",)),
    Pattern("Elevation of Privilege", "ci-poisoning", "CI/CD pipeline poisoning",
            "A compromised pipeline step or runner injects code or steals deploy credentials.",
            "Isolate runners; least-privilege CI tokens (OIDC); pin actions; require reviews; sign outputs.",
            "supply-chain-integrity", "critical", ("supply-chain", "infra"),
            cwe=("CWE-269",), capec=("CAPEC-233",), attack=("T1195", "T1078"), owasp=("A08",)),

    # ---- AI / agent specific -------------------------------------------
    Pattern("Elevation of Privilege", "tool-misuse", "Agent tool misuse / confused deputy",
            "An agent invokes powerful tools with attacker-influenced arguments and ambient authority.",
            "Constrain tool scope and arguments; re-check caller intent; human approval for high impact.",
            "least-privilege", "high", ("ai",),
            cwe=("CWE-441",), capec=("CAPEC-233",), attack=("T1078",), owasp=("A04",)),
    Pattern("Tampering", "jailbreak", "Guardrail jailbreak",
            "Crafted inputs bypass safety/guardrail policies of an LLM or agent.",
            "Layer input/output filters; constrain capabilities; monitor for policy-bypass patterns.",
            "input-validation", "medium", ("ai",),
            cwe=("CWE-20",), capec=("CAPEC-153",), attack=(), owasp=("A04",)),

    # ---- LINDDUN privacy extensions ------------------------------------
    Pattern("Non-compliance", "consent-not-enforced", "Consent not enforced",
            "Processing proceeds even when a data subject has withheld or withdrawn consent.",
            "Enforce consent at processing time; propagate withdrawal; log consent state.",
            "data-minimization", "medium", ("app", "data", "edge", "ai"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Unawareness", "tracking-without-notice", "Tracking without notice",
            "Users are tracked (analytics, fingerprinting) without clear notice or opt-out.",
            "Disclose tracking; honor opt-out/GPC; minimize identifiers; gate non-essential tracking.",
            "data-minimization", "low", ("app", "edge", "ai"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
    Pattern("Non-compliance", "no-dsr-mechanism", "No data-subject-rights mechanism",
            "There is no way to fulfil access, correction, or deletion requests within legal timelines.",
            "Provide DSR intake and fulfilment workflows; track SLAs; verify requester identity.",
            "data-minimization", "medium", ("app", "data"),
            cwe=("CWE-359",), capec=(), attack=(), owasp=()),
]


@dataclass
class Scenario:
    id: str
    category: str
    vector: str
    asset_class: str
    asset_label: str
    title: str
    description: str
    severity: str
    mitigation: str
    control_area: str
    cwe: List[str] = field(default_factory=list)
    capec: List[str] = field(default_factory=list)
    attack: List[str] = field(default_factory=list)
    owasp: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return self.__dict__.copy()


def _applies(pattern: Pattern, tags: List[str]) -> bool:
    if pattern.applies == _ALL:
        return True
    return any(t in pattern.applies for t in tags)


_LIBRARY_CACHE: Optional[List[Scenario]] = None


def build_threat_library() -> List[Scenario]:
    """Materialize the full catalog: every base pattern × each applicable asset."""
    global _LIBRARY_CACHE
    if _LIBRARY_CACHE is not None:
        return _LIBRARY_CACHE
    out: List[Scenario] = []
    n = 0
    for pat in BASE_PATTERNS:
        for akey, meta in K.ASSET_CLASSES.items():
            tags = list(meta["tags"])  # type: ignore[arg-type]
            if not _applies(pat, tags):
                continue
            n += 1
            label = str(meta["label"])
            out.append(Scenario(
                id=f"CAS-{n:04d}",
                category=pat.category,
                vector=pat.vector,
                asset_class=akey,
                asset_label=label,
                title=f"{pat.title} — {label}",
                description=pat.description,
                severity=pat.base_severity,
                mitigation=pat.mitigation,
                control_area=pat.area,
                cwe=list(pat.cwe),
                capec=list(pat.capec),
                attack=list(pat.attack),
                owasp=list(pat.owasp),
            ))
    _LIBRARY_CACHE = out
    return out


@dataclass
class Requirement:
    id: str
    statement: str
    asset_class: str
    control_area: str
    kind: str          # preventive | detective | responsive
    derived_from: str  # scenario id
    frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return self.__dict__.copy()


# Templated requirement phrasings per control area (preventive/detective/responsive).
_REQ_TEMPLATES = {
    "preventive": "The {asset} MUST enforce {area} controls so that '{vector}' cannot succeed by design.",
    "detective": "The {asset} MUST emit signals that detect attempts at '{vector}' and alert within policy SLAs.",
    "responsive": "The organization MUST have a tested response/rollback for '{vector}' affecting the {asset}.",
}

_REQUIREMENTS_CACHE: Optional[List[Requirement]] = None


def build_requirements() -> List[Requirement]:
    """Derive a security-requirements catalog from the threat library."""
    global _REQUIREMENTS_CACHE
    if _REQUIREMENTS_CACHE is not None:
        return _REQUIREMENTS_CACHE
    from .compliance import frameworks_for_category  # local import avoids cycle
    scenarios = build_threat_library()
    out: List[Requirement] = []
    rn = 0
    for sc in scenarios:
        fws = frameworks_for_category(sc.category, limit=6)
        # critical/high scenarios get all three requirement kinds; lower get two.
        kinds = ("preventive", "detective", "responsive")
        if SEVERITY_RANK[sc.severity] < SEVERITY_RANK["high"]:
            kinds = ("preventive", "detective")
        for kind in kinds:
            rn += 1
            stmt = _REQ_TEMPLATES[kind].format(
                asset=sc.asset_label.lower(), area=sc.control_area.replace("-", " "),
                vector=sc.vector.replace("-", " "),
            )
            out.append(Requirement(
                id=f"REQ-{rn:04d}",
                statement=stmt,
                asset_class=sc.asset_class,
                control_area=sc.control_area,
                kind=kind,
                derived_from=sc.id,
                frameworks=fws,
            ))
    _REQUIREMENTS_CACHE = out
    return out


def stats() -> Dict[str, object]:
    """Real, computed counts that back the README's headline numbers."""
    from .data import frameworks as F
    lib = build_threat_library()
    reqs = build_requirements()
    by_cat: Dict[str, int] = {}
    for s in lib:
        by_cat[s.category] = by_cat.get(s.category, 0) + 1
    methodologies = sorted({"STRIDE", "LINDDUN", "DREAD", "Attack Trees", "PASTA-style risk", "CIA"})
    return {
        "threat_scenarios": len(lib),
        "security_requirements": len(reqs),
        "compliance_frameworks": F.count(),
        "base_patterns": len(BASE_PATTERNS),
        "asset_classes": len(K.ASSET_CLASSES),
        "methodologies": methodologies,
        "scenarios_by_category": by_cat,
        "knowledge_base": K.counts(),
        "framework_domains": F.by_domain(),
    }


def patterns_for(element_tags: List[str], stride_only: bool = False) -> List[Pattern]:
    """Patterns applicable to an element with the given tags."""
    res = []
    for p in BASE_PATTERNS:
        if stride_only and p.category not in STRIDE:
            continue
        if _applies(p, element_tags):
            res.append(p)
    return res
