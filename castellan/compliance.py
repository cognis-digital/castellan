"""Map threat categories to real control references across major frameworks.

Each STRIDE / LINDDUN category resolves to concrete control identifiers in the
frameworks people actually get audited against (NIST 800-53, ISO/IEC 27001:2022
Annex A, PCI DSS v4, OWASP ASVS, CIS Controls v8, SOC 2 TSC, and — for privacy —
GDPR, ISO 27701, HIPAA, NIST Privacy Framework). This is what turns a threat
model into an audit-ready control matrix.
"""
from __future__ import annotations

from typing import Dict, List

# category -> {framework display name: control reference}
CATEGORY_CONTROLS: Dict[str, Dict[str, str]] = {
    "Spoofing": {
        "NIST SP 800-53 Rev. 5": "IA-2, IA-5, IA-8",
        "ISO/IEC 27001:2022": "A.5.16, A.5.17, A.8.5",
        "PCI DSS v4.0": "8.3, 8.4, 8.5",
        "OWASP ASVS 4.0": "V2 Authentication, V3 Session",
        "CIS Controls v8.1": "6 Access Control Management",
        "SOC 2 (Trust Services Criteria)": "CC6.1",
        "OWASP Top 10 (2021)": "A07 Identification & Auth Failures",
    },
    "Tampering": {
        "NIST SP 800-53 Rev. 5": "SI-7, SC-8, SC-23",
        "ISO/IEC 27001:2022": "A.8.24, A.8.26, A.8.28",
        "PCI DSS v4.0": "6.2, 6.5, 11.5",
        "OWASP ASVS 4.0": "V1 Architecture, V5 Validation",
        "CIS Controls v8.1": "3 Data Protection, 16 App Software Security",
        "SOC 2 (Trust Services Criteria)": "CC7.1",
        "OWASP Top 10 (2021)": "A03 Injection, A08 Integrity Failures",
    },
    "Repudiation": {
        "NIST SP 800-53 Rev. 5": "AU-2, AU-3, AU-9, AU-12",
        "ISO/IEC 27001:2022": "A.8.15, A.8.16, A.8.17",
        "PCI DSS v4.0": "10.2, 10.3, 10.5",
        "OWASP ASVS 4.0": "V7 Logging & Error Handling",
        "CIS Controls v8.1": "8 Audit Log Management",
        "SOC 2 (Trust Services Criteria)": "CC7.2, CC7.3",
        "OWASP Top 10 (2021)": "A09 Logging & Monitoring Failures",
    },
    "Information Disclosure": {
        "NIST SP 800-53 Rev. 5": "SC-8, SC-13, SC-28, AC-4",
        "ISO/IEC 27001:2022": "A.8.24, A.5.33, A.8.12",
        "PCI DSS v4.0": "3.5, 4.2, 8.3.2",
        "OWASP ASVS 4.0": "V6 Cryptography, V8 Data Protection, V9 Comms",
        "CIS Controls v8.1": "3 Data Protection",
        "SOC 2 (Trust Services Criteria)": "CC6.7, C1.1",
        "OWASP Top 10 (2021)": "A02 Cryptographic Failures",
    },
    "Denial of Service": {
        "NIST SP 800-53 Rev. 5": "SC-5, SC-6, CP-2, CP-10",
        "ISO/IEC 27001:2022": "A.8.6, A.5.30, A.8.14",
        "PCI DSS v4.0": "6.4, 12.10",
        "OWASP ASVS 4.0": "V11 Business Logic, V13 API",
        "CIS Controls v8.1": "13 Network Monitoring & Defense",
        "SOC 2 (Trust Services Criteria)": "A1.1, A1.2",
        "OWASP Top 10 (2021)": "A04 Insecure Design",
    },
    "Elevation of Privilege": {
        "NIST SP 800-53 Rev. 5": "AC-3, AC-6, AC-2",
        "ISO/IEC 27001:2022": "A.8.2, A.8.3, A.5.15, A.5.18",
        "PCI DSS v4.0": "7.2, 7.3",
        "OWASP ASVS 4.0": "V4 Access Control",
        "CIS Controls v8.1": "6 Access Control Management, 5 Account Mgmt",
        "SOC 2 (Trust Services Criteria)": "CC6.3",
        "OWASP Top 10 (2021)": "A01 Broken Access Control",
    },
    # ---- LINDDUN privacy categories -------------------------------------
    "Linkability": {
        "EU GDPR": "Art.5(1)(c) Data Minimisation, Art.25",
        "ISO/IEC 27701 Privacy": "7.4.4, 7.4.5",
        "NIST Privacy Framework 1.0": "CT.DM-P",
        "ISO/IEC 27018 Cloud PII": "A.10.1",
    },
    "Identifiability": {
        "EU GDPR": "Art.4(5) Pseudonymisation, Art.25",
        "ISO/IEC 27701 Privacy": "7.4.5",
        "NIST Privacy Framework 1.0": "CT.DM-P, CT.PO-P",
        "HIPAA Security Rule": "164.514 De-identification",
    },
    "Non-repudiation (privacy)": {
        "EU GDPR": "Art.5(1) Purpose & Storage Limitation",
        "ISO/IEC 27701 Privacy": "7.4.9",
        "NIST Privacy Framework 1.0": "CT.DM-P",
    },
    "Detectability": {
        "EU GDPR": "Art.32 Security of Processing",
        "ISO/IEC 27701 Privacy": "7.4.6",
        "NIST Privacy Framework 1.0": "PR.DS-P",
    },
    "Disclosure of Information": {
        "EU GDPR": "Art.5(1)(f), Art.32",
        "ISO/IEC 27701 Privacy": "7.4.7, 8.4",
        "HIPAA Security Rule": "164.312(a),(e)",
        "ISO/IEC 27018 Cloud PII": "A.11",
    },
    "Unawareness": {
        "EU GDPR": "Art.12-14 Transparency",
        "ISO/IEC 27701 Privacy": "7.3.2, 7.3.3",
        "NIST Privacy Framework 1.0": "CM.AW-P",
    },
    "Non-compliance": {
        "EU GDPR": "Art.30 Records, Art.35 DPIA",
        "ISO/IEC 27701 Privacy": "7.2.1, 7.2.5",
        "NIST Privacy Framework 1.0": "GV.PO-P",
        "ISO/IEC 42001 AI Management": "Clause 6, 8",
    },
}


def controls_for_category(category: str) -> Dict[str, str]:
    """Return {framework: control-ref} for a threat category."""
    return dict(CATEGORY_CONTROLS.get(category, {}))


def frameworks_for_category(category: str, limit: int = 0) -> List[str]:
    """Return "Framework:Control" strings for a category (optionally capped)."""
    items = [f"{fw}:{ctrl}" for fw, ctrl in CATEGORY_CONTROLS.get(category, {}).items()]
    return items[:limit] if limit else items


def coverage() -> Dict[str, int]:
    """How many distinct frameworks are referenced per category."""
    return {cat: len(m) for cat, m in CATEGORY_CONTROLS.items()}
