"""Compliance & security frameworks castellan can map findings against.

Every entry is a real, named standard, regulation, or benchmark. The list is
deliberately broad — castellan maps each derived threat to the relevant control
families across these frameworks so a single model can be read against whatever
regime your auditor cares about.

`FRAMEWORKS` is the authoritative catalog; `count()` returns its size (used by
`castellan library stats` so the README's numbers are produced, never invented).
"""
from __future__ import annotations

from typing import Dict, List

# (id, display name, issuing authority, domain)
FRAMEWORKS: List[Dict[str, str]] = [
    # ---- US federal / NIST -------------------------------------------------
    {"id": "nist-800-53r5", "name": "NIST SP 800-53 Rev. 5", "authority": "NIST", "domain": "controls"},
    {"id": "nist-csf-2", "name": "NIST Cybersecurity Framework 2.0", "authority": "NIST", "domain": "framework"},
    {"id": "nist-800-171r3", "name": "NIST SP 800-171 Rev. 3", "authority": "NIST", "domain": "cui"},
    {"id": "nist-800-172", "name": "NIST SP 800-172", "authority": "NIST", "domain": "cui"},
    {"id": "nist-800-63", "name": "NIST SP 800-63 Digital Identity", "authority": "NIST", "domain": "identity"},
    {"id": "nist-800-207", "name": "NIST SP 800-207 Zero Trust Architecture", "authority": "NIST", "domain": "architecture"},
    {"id": "nist-800-218", "name": "NIST SP 800-218 SSDF", "authority": "NIST", "domain": "sdlc"},
    {"id": "nist-800-30", "name": "NIST SP 800-30 Risk Assessment", "authority": "NIST", "domain": "risk"},
    {"id": "nist-800-37", "name": "NIST SP 800-37 RMF", "authority": "NIST", "domain": "risk"},
    {"id": "nist-800-61", "name": "NIST SP 800-61 Incident Handling", "authority": "NIST", "domain": "ir"},
    {"id": "nist-800-82", "name": "NIST SP 800-82 ICS Security", "authority": "NIST", "domain": "ot"},
    {"id": "nist-800-92", "name": "NIST SP 800-92 Log Management", "authority": "NIST", "domain": "logging"},
    {"id": "nist-800-122", "name": "NIST SP 800-122 PII", "authority": "NIST", "domain": "privacy"},
    {"id": "nist-800-190", "name": "NIST SP 800-190 Container Security", "authority": "NIST", "domain": "containers"},
    {"id": "nist-800-204", "name": "NIST SP 800-204 Microservices Security", "authority": "NIST", "domain": "microservices"},
    {"id": "nist-800-209", "name": "NIST SP 800-209 Storage Security", "authority": "NIST", "domain": "storage"},
    {"id": "nist-800-210", "name": "NIST SP 800-210 Cloud Access Control", "authority": "NIST", "domain": "cloud"},
    {"id": "nist-ai-rmf", "name": "NIST AI Risk Management Framework", "authority": "NIST", "domain": "ai"},
    {"id": "nist-privacy", "name": "NIST Privacy Framework 1.0", "authority": "NIST", "domain": "privacy"},
    {"id": "nist-ssdf-genai", "name": "NIST SP 800-218A GenAI SSDF Profile", "authority": "NIST", "domain": "ai"},
    {"id": "fisma", "name": "FISMA", "authority": "US Congress", "domain": "regulation"},
    {"id": "fedramp", "name": "FedRAMP", "authority": "GSA", "domain": "cloud"},
    {"id": "cmmc-2", "name": "CMMC 2.0", "authority": "US DoD", "domain": "defense"},
    {"id": "stig", "name": "DISA STIGs", "authority": "DISA", "domain": "hardening"},
    {"id": "cnssi-1253", "name": "CNSSI 1253", "authority": "CNSS", "domain": "national-security"},
    {"id": "circia", "name": "CIRCIA Incident Reporting", "authority": "CISA", "domain": "regulation"},
    {"id": "cisa-ssbd", "name": "CISA Secure by Design", "authority": "CISA", "domain": "sdlc"},
    {"id": "cisa-zt-maturity", "name": "CISA Zero Trust Maturity Model 2.0", "authority": "CISA", "domain": "architecture"},

    # ---- Privacy regulations (global) -------------------------------------
    {"id": "gdpr", "name": "EU GDPR", "authority": "EU", "domain": "privacy"},
    {"id": "uk-gdpr", "name": "UK GDPR", "authority": "UK ICO", "domain": "privacy"},
    {"id": "uk-dpa-2018", "name": "UK Data Protection Act 2018", "authority": "UK", "domain": "privacy"},
    {"id": "ccpa", "name": "CCPA", "authority": "California", "domain": "privacy"},
    {"id": "cpra", "name": "CPRA", "authority": "California", "domain": "privacy"},
    {"id": "vcdpa", "name": "Virginia VCDPA", "authority": "Virginia", "domain": "privacy"},
    {"id": "cpa-co", "name": "Colorado Privacy Act", "authority": "Colorado", "domain": "privacy"},
    {"id": "ctdpa", "name": "Connecticut CTDPA", "authority": "Connecticut", "domain": "privacy"},
    {"id": "ucpa", "name": "Utah UCPA", "authority": "Utah", "domain": "privacy"},
    {"id": "tdpsa", "name": "Texas TDPSA", "authority": "Texas", "domain": "privacy"},
    {"id": "ocpa", "name": "Oregon Consumer Privacy Act", "authority": "Oregon", "domain": "privacy"},
    {"id": "bipa", "name": "Illinois BIPA (Biometrics)", "authority": "Illinois", "domain": "privacy"},
    {"id": "lgpd", "name": "Brazil LGPD", "authority": "Brazil ANPD", "domain": "privacy"},
    {"id": "pipeda", "name": "Canada PIPEDA", "authority": "Canada OPC", "domain": "privacy"},
    {"id": "pipl", "name": "China PIPL", "authority": "China", "domain": "privacy"},
    {"id": "appi", "name": "Japan APPI", "authority": "Japan PPC", "domain": "privacy"},
    {"id": "popia", "name": "South Africa POPIA", "authority": "South Africa", "domain": "privacy"},
    {"id": "pdpa-sg", "name": "Singapore PDPA", "authority": "Singapore PDPC", "domain": "privacy"},
    {"id": "pdpa-th", "name": "Thailand PDPA", "authority": "Thailand", "domain": "privacy"},
    {"id": "au-privacy", "name": "Australian Privacy Act / APPs", "authority": "OAIC", "domain": "privacy"},
    {"id": "ch-fadp", "name": "Switzerland FADP", "authority": "FDPIC", "domain": "privacy"},
    {"id": "india-dpdp", "name": "India DPDP Act 2023", "authority": "India", "domain": "privacy"},
    {"id": "coppa", "name": "COPPA (Children)", "authority": "US FTC", "domain": "privacy"},
    {"id": "ferpa", "name": "FERPA (Education)", "authority": "US DoE", "domain": "privacy"},
    {"id": "caloppa", "name": "CalOPPA", "authority": "California", "domain": "privacy"},

    # ---- Financial / payments --------------------------------------------
    {"id": "pci-dss-4", "name": "PCI DSS v4.0", "authority": "PCI SSC", "domain": "payments"},
    {"id": "pci-pin", "name": "PCI PIN Security", "authority": "PCI SSC", "domain": "payments"},
    {"id": "pci-3ds", "name": "PCI 3DS", "authority": "PCI SSC", "domain": "payments"},
    {"id": "pci-ssf", "name": "PCI Software Security Framework", "authority": "PCI SSC", "domain": "payments"},
    {"id": "sox", "name": "Sarbanes-Oxley (SOX) ITGC", "authority": "US SEC", "domain": "financial"},
    {"id": "glba", "name": "Gramm-Leach-Bliley Act", "authority": "US", "domain": "financial"},
    {"id": "ffiec", "name": "FFIEC IT Handbook", "authority": "FFIEC", "domain": "financial"},
    {"id": "nydfs-500", "name": "NYDFS 23 NYCRR 500", "authority": "NYDFS", "domain": "financial"},
    {"id": "ftc-safeguards", "name": "FTC Safeguards Rule", "authority": "US FTC", "domain": "financial"},
    {"id": "psd2", "name": "EU PSD2 / SCA", "authority": "EU", "domain": "payments"},
    {"id": "dora", "name": "EU DORA", "authority": "EU", "domain": "financial"},
    {"id": "swift-cscf", "name": "SWIFT CSP CSCF", "authority": "SWIFT", "domain": "financial"},
    {"id": "mas-trm", "name": "MAS Technology Risk Mgmt (Singapore)", "authority": "MAS", "domain": "financial"},
    {"id": "hkma", "name": "HKMA Cyber Resilience", "authority": "HKMA", "domain": "financial"},
    {"id": "occ-heightened", "name": "OCC Heightened Standards", "authority": "US OCC", "domain": "financial"},

    # ---- Healthcare ------------------------------------------------------
    {"id": "hipaa-security", "name": "HIPAA Security Rule", "authority": "US HHS", "domain": "healthcare"},
    {"id": "hipaa-privacy", "name": "HIPAA Privacy Rule", "authority": "US HHS", "domain": "healthcare"},
    {"id": "hitech", "name": "HITECH Act", "authority": "US HHS", "domain": "healthcare"},
    {"id": "hitrust-csf", "name": "HITRUST CSF v11", "authority": "HITRUST", "domain": "healthcare"},
    {"id": "fda-premarket", "name": "FDA Premarket Cybersecurity (524B)", "authority": "US FDA", "domain": "medical-device"},
    {"id": "iec-62304", "name": "IEC 62304 Medical Device Software", "authority": "IEC", "domain": "medical-device"},
    {"id": "dicom-sec", "name": "DICOM Security Profiles", "authority": "NEMA", "domain": "healthcare"},
    {"id": "hl7-fhir-sec", "name": "HL7 FHIR Security", "authority": "HL7", "domain": "healthcare"},
    {"id": "mds2", "name": "MDS2 Medical Device Disclosure", "authority": "HSCC", "domain": "medical-device"},

    # ---- ISO / IEC -------------------------------------------------------
    {"id": "iso-27001", "name": "ISO/IEC 27001:2022", "authority": "ISO/IEC", "domain": "isms"},
    {"id": "iso-27002", "name": "ISO/IEC 27002:2022", "authority": "ISO/IEC", "domain": "controls"},
    {"id": "iso-27005", "name": "ISO/IEC 27005 Risk", "authority": "ISO/IEC", "domain": "risk"},
    {"id": "iso-27017", "name": "ISO/IEC 27017 Cloud", "authority": "ISO/IEC", "domain": "cloud"},
    {"id": "iso-27018", "name": "ISO/IEC 27018 Cloud PII", "authority": "ISO/IEC", "domain": "privacy"},
    {"id": "iso-27034", "name": "ISO/IEC 27034 Application Security", "authority": "ISO/IEC", "domain": "appsec"},
    {"id": "iso-27036", "name": "ISO/IEC 27036 Supplier Security", "authority": "ISO/IEC", "domain": "supply-chain"},
    {"id": "iso-27040", "name": "ISO/IEC 27040 Storage Security", "authority": "ISO/IEC", "domain": "storage"},
    {"id": "iso-27701", "name": "ISO/IEC 27701 Privacy", "authority": "ISO/IEC", "domain": "privacy"},
    {"id": "iso-29100", "name": "ISO/IEC 29100 Privacy Framework", "authority": "ISO/IEC", "domain": "privacy"},
    {"id": "iso-22301", "name": "ISO 22301 Business Continuity", "authority": "ISO", "domain": "bcm"},
    {"id": "iso-31000", "name": "ISO 31000 Risk Management", "authority": "ISO", "domain": "risk"},
    {"id": "iso-42001", "name": "ISO/IEC 42001 AI Management", "authority": "ISO/IEC", "domain": "ai"},
    {"id": "iso-15408", "name": "ISO/IEC 15408 Common Criteria", "authority": "ISO/IEC", "domain": "assurance"},
    {"id": "iso-21434", "name": "ISO/SAE 21434 Automotive Cyber", "authority": "ISO/SAE", "domain": "automotive"},
    {"id": "iso-13485", "name": "ISO 13485 Medical Devices QMS", "authority": "ISO", "domain": "medical-device"},

    # ---- CIS -------------------------------------------------------------
    {"id": "cis-controls-8", "name": "CIS Controls v8.1", "authority": "CIS", "domain": "controls"},
    {"id": "cis-aws", "name": "CIS AWS Foundations Benchmark", "authority": "CIS", "domain": "cloud"},
    {"id": "cis-azure", "name": "CIS Azure Foundations Benchmark", "authority": "CIS", "domain": "cloud"},
    {"id": "cis-gcp", "name": "CIS GCP Foundations Benchmark", "authority": "CIS", "domain": "cloud"},
    {"id": "cis-k8s", "name": "CIS Kubernetes Benchmark", "authority": "CIS", "domain": "containers"},
    {"id": "cis-docker", "name": "CIS Docker Benchmark", "authority": "CIS", "domain": "containers"},
    {"id": "cis-eks", "name": "CIS Amazon EKS Benchmark", "authority": "CIS", "domain": "containers"},
    {"id": "cis-aks", "name": "CIS Azure AKS Benchmark", "authority": "CIS", "domain": "containers"},
    {"id": "cis-gke", "name": "CIS Google GKE Benchmark", "authority": "CIS", "domain": "containers"},
    {"id": "cis-rhel", "name": "CIS RHEL Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-ubuntu", "name": "CIS Ubuntu Linux Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-windows", "name": "CIS Windows Server Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-nginx", "name": "CIS NGINX Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-apache", "name": "CIS Apache HTTP Server Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-postgres", "name": "CIS PostgreSQL Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-mysql", "name": "CIS MySQL Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-mongodb", "name": "CIS MongoDB Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-redis", "name": "CIS Redis Benchmark", "authority": "CIS", "domain": "hardening"},
    {"id": "cis-ram", "name": "CIS Risk Assessment Method", "authority": "CIS", "domain": "risk"},

    # ---- Cloud provider security baselines -------------------------------
    {"id": "aws-war-sec", "name": "AWS Well-Architected Security Pillar", "authority": "AWS", "domain": "cloud"},
    {"id": "aws-fsbp", "name": "AWS Foundational Security Best Practices", "authority": "AWS", "domain": "cloud"},
    {"id": "azure-mcsb", "name": "Microsoft Cloud Security Benchmark", "authority": "Microsoft", "domain": "cloud"},
    {"id": "azure-waf-sec", "name": "Azure Well-Architected Security", "authority": "Microsoft", "domain": "cloud"},
    {"id": "gcp-security-foundations", "name": "Google Cloud Security Foundations", "authority": "Google", "domain": "cloud"},
    {"id": "csa-ccm-4", "name": "CSA Cloud Controls Matrix v4", "authority": "CSA", "domain": "cloud"},
    {"id": "csa-star", "name": "CSA STAR", "authority": "CSA", "domain": "cloud"},
    {"id": "csa-caiq", "name": "CSA CAIQ", "authority": "CSA", "domain": "cloud"},

    # ---- Application / product / supply chain ----------------------------
    {"id": "owasp-asvs", "name": "OWASP ASVS 4.0", "authority": "OWASP", "domain": "appsec"},
    {"id": "owasp-top10", "name": "OWASP Top 10 (2021)", "authority": "OWASP", "domain": "appsec"},
    {"id": "owasp-api-top10", "name": "OWASP API Security Top 10 (2023)", "authority": "OWASP", "domain": "appsec"},
    {"id": "owasp-masvs", "name": "OWASP MASVS (Mobile)", "authority": "OWASP", "domain": "mobile"},
    {"id": "owasp-llm-top10", "name": "OWASP Top 10 for LLM Apps", "authority": "OWASP", "domain": "ai"},
    {"id": "owasp-ml-top10", "name": "OWASP Machine Learning Top 10", "authority": "OWASP", "domain": "ai"},
    {"id": "owasp-cicd-top10", "name": "OWASP Top 10 CI/CD Security Risks", "authority": "OWASP", "domain": "sdlc"},
    {"id": "owasp-samm", "name": "OWASP SAMM 2.0", "authority": "OWASP", "domain": "sdlc"},
    {"id": "owasp-proactive", "name": "OWASP Proactive Controls", "authority": "OWASP", "domain": "appsec"},
    {"id": "bsimm", "name": "BSIMM", "authority": "Synopsys", "domain": "sdlc"},
    {"id": "safecode", "name": "SAFECode Fundamental Practices", "authority": "SAFECode", "domain": "sdlc"},
    {"id": "slsa-1", "name": "SLSA v1.0", "authority": "OpenSSF", "domain": "supply-chain"},
    {"id": "in-toto", "name": "in-toto Attestation", "authority": "CNCF", "domain": "supply-chain"},
    {"id": "openssf-scorecard", "name": "OpenSSF Scorecard", "authority": "OpenSSF", "domain": "supply-chain"},
    {"id": "openssf-badge", "name": "OpenSSF Best Practices Badge", "authority": "OpenSSF", "domain": "supply-chain"},
    {"id": "scvs", "name": "OWASP SCVS (Software Component Verification)", "authority": "OWASP", "domain": "supply-chain"},
    {"id": "cyclonedx", "name": "CycloneDX SBOM", "authority": "OWASP", "domain": "supply-chain"},
    {"id": "spdx", "name": "SPDX SBOM", "authority": "Linux Foundation", "domain": "supply-chain"},
    {"id": "ntia-sbom", "name": "NTIA Minimum Elements for SBOM", "authority": "NTIA", "domain": "supply-chain"},
    {"id": "cncf-security", "name": "CNCF Cloud Native Security Whitepaper", "authority": "CNCF", "domain": "containers"},
    {"id": "pci-secure-sdlc", "name": "PCI Secure SLC Standard", "authority": "PCI SSC", "domain": "sdlc"},

    # ---- MITRE knowledge bases -------------------------------------------
    {"id": "mitre-attack", "name": "MITRE ATT&CK (Enterprise)", "authority": "MITRE", "domain": "ttp"},
    {"id": "mitre-attack-cloud", "name": "MITRE ATT&CK for Cloud", "authority": "MITRE", "domain": "ttp"},
    {"id": "mitre-attack-containers", "name": "MITRE ATT&CK for Containers", "authority": "MITRE", "domain": "ttp"},
    {"id": "mitre-attack-ics", "name": "MITRE ATT&CK for ICS", "authority": "MITRE", "domain": "ttp"},
    {"id": "mitre-attack-mobile", "name": "MITRE ATT&CK for Mobile", "authority": "MITRE", "domain": "ttp"},
    {"id": "mitre-d3fend", "name": "MITRE D3FEND", "authority": "MITRE", "domain": "defense"},
    {"id": "mitre-capec", "name": "MITRE CAPEC", "authority": "MITRE", "domain": "attack-patterns"},
    {"id": "mitre-cwe", "name": "MITRE CWE", "authority": "MITRE", "domain": "weaknesses"},
    {"id": "mitre-atlas", "name": "MITRE ATLAS (AI threats)", "authority": "MITRE", "domain": "ai"},
    {"id": "mitre-emb3d", "name": "MITRE EMB3D (Embedded)", "authority": "MITRE", "domain": "embedded"},
    {"id": "mitre-engage", "name": "MITRE Engage (Deception)", "authority": "MITRE", "domain": "defense"},

    # ---- ICS / OT / critical infrastructure ------------------------------
    {"id": "iec-62443", "name": "ISA/IEC 62443", "authority": "ISA/IEC", "domain": "ot"},
    {"id": "nerc-cip", "name": "NERC CIP", "authority": "NERC", "domain": "energy"},
    {"id": "tsa-pipeline", "name": "TSA Pipeline Security Directives", "authority": "US TSA", "domain": "energy"},
    {"id": "api-1164", "name": "API 1164 Pipeline SCADA Security", "authority": "API", "domain": "energy"},
    {"id": "awwa-g430", "name": "AWWA Water Sector Cybersecurity", "authority": "AWWA", "domain": "water"},
    {"id": "do-326a", "name": "DO-326A / ED-202A Aviation Cyber", "authority": "RTCA/EUROCAE", "domain": "aviation"},
    {"id": "unece-r155", "name": "UNECE WP.29 R155 (Automotive)", "authority": "UNECE", "domain": "automotive"},
    {"id": "tisax", "name": "TISAX (Automotive)", "authority": "ENX", "domain": "automotive"},
    {"id": "imo-2021", "name": "IMO Maritime Cyber Risk (Res. MSC.428)", "authority": "IMO", "domain": "maritime"},
    {"id": "ieee-1686", "name": "IEEE 1686 IED Cybersecurity", "authority": "IEEE", "domain": "energy"},

    # ---- AI governance ---------------------------------------------------
    {"id": "eu-ai-act", "name": "EU AI Act", "authority": "EU", "domain": "ai"},
    {"id": "oecd-ai", "name": "OECD AI Principles", "authority": "OECD", "domain": "ai"},
    {"id": "uk-ai-principles", "name": "UK AI Regulation Principles", "authority": "UK", "domain": "ai"},
    {"id": "singapore-ai-verify", "name": "Singapore AI Verify", "authority": "IMDA", "domain": "ai"},
    {"id": "google-saif", "name": "Google Secure AI Framework (SAIF)", "authority": "Google", "domain": "ai"},

    # ---- National / regional cyber frameworks ----------------------------
    {"id": "cyber-essentials", "name": "UK Cyber Essentials", "authority": "UK NCSC", "domain": "framework"},
    {"id": "cyber-essentials-plus", "name": "UK Cyber Essentials Plus", "authority": "UK NCSC", "domain": "framework"},
    {"id": "uk-caf", "name": "UK NCSC Cyber Assessment Framework", "authority": "UK NCSC", "domain": "framework"},
    {"id": "essential-eight", "name": "ASD Essential Eight", "authority": "ACSC", "domain": "framework"},
    {"id": "ism-au", "name": "ACSC Information Security Manual", "authority": "ACSC", "domain": "controls"},
    {"id": "bsi-grundschutz", "name": "BSI IT-Grundschutz", "authority": "Germany BSI", "domain": "controls"},
    {"id": "bsi-c5", "name": "BSI C5 Cloud", "authority": "Germany BSI", "domain": "cloud"},
    {"id": "ens-es", "name": "ENS (Esquema Nacional de Seguridad)", "authority": "Spain", "domain": "controls"},
    {"id": "anssi", "name": "ANSSI Hygiene Guide", "authority": "France ANSSI", "domain": "framework"},
    {"id": "nis2", "name": "EU NIS2 Directive", "authority": "EU", "domain": "regulation"},
    {"id": "cra-eu", "name": "EU Cyber Resilience Act", "authority": "EU", "domain": "regulation"},
    {"id": "etsi-en-303-645", "name": "ETSI EN 303 645 (IoT Consumer)", "authority": "ETSI", "domain": "iot"},
    {"id": "enisa-5g", "name": "ENISA 5G Toolbox", "authority": "ENISA", "domain": "telecom"},
    {"id": "eidas", "name": "eIDAS Regulation", "authority": "EU", "domain": "identity"},
    {"id": "sg-im8", "name": "Singapore Government IM8", "authority": "Singapore", "domain": "controls"},
    {"id": "sg-ccop", "name": "Singapore CCoP (CII)", "authority": "Singapore CSA", "domain": "controls"},
    {"id": "india-cert-in", "name": "India CERT-In Directions", "authority": "CERT-In", "domain": "regulation"},
    {"id": "saudi-ecc", "name": "Saudi NCA Essential Cybersecurity Controls", "authority": "Saudi NCA", "domain": "controls"},
    {"id": "uae-ia", "name": "UAE Information Assurance Standards", "authority": "UAE TDRA", "domain": "controls"},
    {"id": "qatar-ncsf", "name": "Qatar National Cyber Security Framework", "authority": "Qatar", "domain": "framework"},
    {"id": "israel-cyber-doctrine", "name": "Israel Cyber Defense Methodology", "authority": "INCD", "domain": "framework"},
    {"id": "canada-itsg-33", "name": "Canada ITSG-33", "authority": "CCCS", "domain": "controls"},
    {"id": "nz-ism", "name": "New Zealand Information Security Manual", "authority": "GCSB", "domain": "controls"},

    # ---- Governance / audit / assurance ----------------------------------
    {"id": "soc2", "name": "SOC 2 (Trust Services Criteria)", "authority": "AICPA", "domain": "audit"},
    {"id": "soc1", "name": "SOC 1 (SSAE 18)", "authority": "AICPA", "domain": "audit"},
    {"id": "soc3", "name": "SOC 3", "authority": "AICPA", "domain": "audit"},
    {"id": "cobit-2019", "name": "COBIT 2019", "authority": "ISACA", "domain": "governance"},
    {"id": "itil-4", "name": "ITIL 4 (Information Security)", "authority": "Axelos", "domain": "governance"},
    {"id": "sig", "name": "Shared Assessments SIG", "authority": "Shared Assessments", "domain": "third-party"},
    {"id": "trust-exchange", "name": "TruSight / Third-Party Risk", "authority": "Industry", "domain": "third-party"},

    # ---- Identity / crypto / data ----------------------------------------
    {"id": "fido2", "name": "FIDO2 / WebAuthn", "authority": "FIDO Alliance", "domain": "identity"},
    {"id": "oauth-bcp", "name": "OAuth 2.0 Security BCP (RFC 9700)", "authority": "IETF", "domain": "identity"},
    {"id": "oidc", "name": "OpenID Connect Core", "authority": "OpenID Foundation", "domain": "identity"},
    {"id": "fips-140-3", "name": "FIPS 140-3 Crypto Modules", "authority": "NIST", "domain": "crypto"},
    {"id": "fips-199", "name": "FIPS 199 Categorization", "authority": "NIST", "domain": "risk"},
    {"id": "fips-200", "name": "FIPS 200 Minimum Requirements", "authority": "NIST", "domain": "controls"},
    {"id": "rfc-8446", "name": "TLS 1.3 (RFC 8446)", "authority": "IETF", "domain": "crypto"},
    {"id": "nist-pqc", "name": "NIST Post-Quantum Cryptography", "authority": "NIST", "domain": "crypto"},
]


# --------------------------------------------------------------------------- #
# Extended catalog. Real, published standards/benchmarks/regulations expanded
# from families that genuinely have many members. Added programmatically to keep
# the file readable; `_slug` derives a stable id.
# --------------------------------------------------------------------------- #
def _slug(s: str) -> str:
    import re as _re
    return _re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


# --- CIS Benchmarks (real platforms CIS publishes hardening benchmarks for) ---
_CIS_BENCHMARK_PLATFORMS = [
    "Amazon Linux 2", "Amazon Linux 2023", "Ubuntu Linux 20.04 LTS",
    "Ubuntu Linux 22.04 LTS", "Ubuntu Linux 24.04 LTS", "Debian Linux 11",
    "Debian Linux 12", "Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 9",
    "CentOS Linux 7", "Rocky Linux 9", "AlmaLinux OS 9", "SUSE Linux Enterprise 15",
    "Oracle Linux 8", "Oracle Linux 9", "Fedora 40", "Alpine Linux",
    "Microsoft Windows Server 2016", "Microsoft Windows Server 2019",
    "Microsoft Windows Server 2022", "Microsoft Windows 10 Enterprise",
    "Microsoft Windows 11 Enterprise", "Apple macOS 13 Ventura",
    "Apple macOS 14 Sonoma", "Apple macOS 15 Sequoia",
    "Google Cloud Platform Foundation", "Amazon Web Services Foundations",
    "Microsoft Azure Foundations", "Oracle Cloud Infrastructure Foundation",
    "AWS Compute Services", "AWS End User Compute Services", "AWS Storage Services",
    "Microsoft 365 Foundations", "Microsoft Intune for Windows", "Google Workspace",
    "Kubernetes", "Amazon EKS", "Azure AKS", "Google GKE", "Red Hat OpenShift",
    "Docker", "Docker Engine", "VMware ESXi 8", "Proxmox VE",
    "Apache HTTP Server", "NGINX", "Microsoft IIS 10", "Apache Tomcat 10",
    "PostgreSQL 16", "MySQL 8.0", "MariaDB 10.11", "MongoDB", "Oracle Database 19c",
    "Microsoft SQL Server 2022", "Redis", "Cassandra", "Elasticsearch",
    "Google Chrome", "Microsoft Edge", "Mozilla Firefox", "Apple Safari",
    "Microsoft Office 365", "Zoom", "Slack",
    "Cisco IOS 17", "Cisco NX-OS", "Cisco ASA", "Cisco Firepower",
    "Palo Alto Firewall", "Fortinet FortiGate", "Juniper Junos OS",
    "F5 BIG-IP", "Check Point GAiA", "pfSense",
    "IBM AIX 7", "Solaris 11.4", "HP-UX",
    "Apple iOS 17", "Apple iOS 18", "Google Android 14", "Google Android 15",
    "IBM DB2 12", "SAP HANA", "Snowflake", "Databricks",
    "WordPress", "Drupal", "Joomla",
    "Terraform", "Ansible", "GitLab", "GitHub", "Jenkins",
    "Wi-Fi (CIS Wireless)", "BIND DNS", "Sendmail", "Postfix", "OpenLDAP",
]

# --- National data-protection / cyber laws (real, by jurisdiction) ---
_NATIONAL_LAWS = [
    ("Germany BDSG", "Germany"), ("France Loi Informatique et Libertés", "France"),
    ("Italy Codice Privacy", "Italy"), ("Spain LOPDGDD", "Spain"),
    ("Netherlands UAVG", "Netherlands"), ("Ireland Data Protection Act 2018", "Ireland"),
    ("Belgium Data Protection Act", "Belgium"), ("Austria DSG", "Austria"),
    ("Sweden Data Protection Act", "Sweden"), ("Norway Personal Data Act", "Norway"),
    ("Finland Data Protection Act", "Finland"), ("Denmark Data Protection Act", "Denmark"),
    ("Poland UODO", "Poland"), ("Portugal Lei 58/2019", "Portugal"),
    ("Greece Law 4624/2019", "Greece"), ("Czech Act 110/2019", "Czech Republic"),
    ("Romania Law 190/2018", "Romania"), ("Hungary Privacy Act", "Hungary"),
    ("Mexico LFPDPPP", "Mexico"), ("Argentina PDPA 25.326", "Argentina"),
    ("Chile Law 19.628", "Chile"), ("Colombia Law 1581", "Colombia"),
    ("Peru Law 29733", "Peru"), ("Uruguay Law 18.331", "Uruguay"),
    ("Russia Federal Law 152-FZ", "Russia"), ("Turkey KVKK", "Turkey"),
    ("Israel Privacy Protection Law", "Israel"), ("UAE PDPL", "United Arab Emirates"),
    ("Saudi Arabia PDPL", "Saudi Arabia"), ("Qatar PDPL", "Qatar"),
    ("Bahrain PDPL", "Bahrain"), ("Kuwait Data Protection Regulation", "Kuwait"),
    ("Egypt Data Protection Law 151", "Egypt"), ("Kenya Data Protection Act", "Kenya"),
    ("Nigeria NDPA", "Nigeria"), ("Ghana Data Protection Act", "Ghana"),
    ("South Korea PIPA", "South Korea"), ("Indonesia PDP Law", "Indonesia"),
    ("Philippines Data Privacy Act", "Philippines"), ("Malaysia PDPA", "Malaysia"),
    ("Vietnam PDPD", "Vietnam"), ("Hong Kong PDPO", "Hong Kong"),
    ("Taiwan PDPA", "Taiwan"), ("New Zealand Privacy Act 2020", "New Zealand"),
    ("Sri Lanka PDPA", "Sri Lanka"), ("Bangladesh Data Protection Act", "Bangladesh"),
    ("Pakistan PDPB", "Pakistan"), ("Morocco Law 09-08", "Morocco"),
    ("Tunisia Data Protection Law", "Tunisia"), ("Rwanda Data Protection Law", "Rwanda"),
    ("Uganda Data Protection Act", "Uganda"), ("Tanzania Data Protection Act", "Tanzania"),
    ("Zambia Data Protection Act", "Zambia"), ("Botswana Data Protection Act", "Botswana"),
    ("Mauritius Data Protection Act", "Mauritius"), ("Angola Data Protection Law", "Angola"),
    ("Ecuador LOPDP", "Ecuador"), ("Costa Rica Law 8968", "Costa Rica"),
    ("Panama Law 81", "Panama"), ("Jamaica Data Protection Act", "Jamaica"),
    ("Iceland Data Protection Act", "Iceland"), ("Liechtenstein DSG", "Liechtenstein"),
    ("Luxembourg Data Protection Law", "Luxembourg"), ("Croatia Data Protection Act", "Croatia"),
    ("Slovakia Act 18/2018", "Slovakia"), ("Slovenia ZVOP-2", "Slovenia"),
    ("Bulgaria Personal Data Protection Act", "Bulgaria"), ("Estonia PDPA", "Estonia"),
    ("Latvia Personal Data Processing Law", "Latvia"), ("Lithuania Data Protection Law", "Lithuania"),
    ("Cyprus Data Protection Law", "Cyprus"), ("Malta Data Protection Act", "Malta"),
]

# --- US state comprehensive privacy laws (real, enacted) ---
_US_STATE_LAWS = [
    "California CCPA/CPRA", "Virginia VCDPA", "Colorado CPA", "Connecticut CTDPA",
    "Utah UCPA", "Texas TDPSA", "Oregon OCPA", "Montana MCDPA", "Iowa ICDPA",
    "Indiana ICDPA", "Tennessee TIPA", "Florida FDBR", "Delaware DPDPA",
    "New Jersey NJDPA", "New Hampshire SB255", "Nebraska NDPA", "Maryland MODPA",
    "Minnesota MCDPA", "Kentucky KCDPA", "Rhode Island Data Transparency Act",
]

# --- NIST SP 800-series (real publication numbers/titles) ---
_NIST_SP800 = [
    ("800-34", "Contingency Planning"), ("800-40", "Patch Management"),
    ("800-44", "Public Web Servers"), ("800-45", "Email Security"),
    ("800-46", "Telework / Remote Access"), ("800-50", "Security Awareness"),
    ("800-52", "TLS Implementations"), ("800-53A", "Control Assessment"),
    ("800-57", "Key Management"), ("800-60", "Information Categorization"),
    ("800-66", "HIPAA Security Rule Guidance"), ("800-77", "IPsec VPNs"),
    ("800-83", "Malware Incident Prevention"), ("800-84", "Test/Exercise Programs"),
    ("800-86", "Forensic Techniques"), ("800-88", "Media Sanitization"),
    ("800-94", "Intrusion Detection"), ("800-95", "Web Services Security"),
    ("800-113", "SSL VPNs"), ("800-115", "Security Testing"),
    ("800-123", "Server Security"), ("800-124", "Mobile Device Security"),
    ("800-125", "Virtualization Security"), ("800-128", "Configuration Management"),
    ("800-137", "Continuous Monitoring"), ("800-146", "Cloud Computing"),
    ("800-150", "Threat Information Sharing"), ("800-152", "Cryptographic Key Mgmt"),
    ("800-154", "Data-Centric Threat Modeling"), ("800-160", "Systems Security Engineering"),
    ("800-161", "Supply Chain Risk Management"), ("800-167", "Application Whitelisting"),
    ("800-184", "Recovering from Cyber Incidents"), ("800-188", "De-Identifying Data"),
    ("800-189", "Secure Interdomain Routing"), ("800-201", "Cyber Resiliency"),
    ("800-213", "IoT Device Cybersecurity"), ("800-215", "Trusted Internet Connections"),
    ("800-216", "Vulnerability Disclosure"), ("800-219", "macOS Security"),
]

# --- DISA STIG technology families (real) ---
_DISA_STIGS = [
    "Application Security and Development", "Web Server SRG", "Database SRG",
    "Application Server SRG", "Container Platform SRG", "Cloud Computing SRG",
    "Network Device Management SRG", "Firewall SRG", "Router SRG", "Switch SRG",
    "IDS/IPS SRG", "DNS SRG", "VPN SRG", "Email SRG", "Operating System SRG",
    "General Purpose OS SRG", "Mobile Operating System SRG", "Active Directory",
    "Windows Defender Antivirus", "Microsoft IIS STIG", "Apache STIG",
    "Kubernetes STIG", "Docker Enterprise STIG", "PostgreSQL STIG",
    "MongoDB Enterprise STIG", "Oracle Database STIG", "Red Hat 8 STIG",
    "Ubuntu 20.04 STIG", "VMware vSphere STIG", "Cisco IOS XE STIG",
]

# --- Sector / industry regulations (real) ---
_SECTOR_REGS = [
    ("CMS ARS", "US CMS", "healthcare"), ("FedRAMP High", "GSA", "cloud"),
    ("FedRAMP Moderate", "GSA", "cloud"), ("StateRAMP", "StateRAMP", "cloud"),
    ("TX-RAMP", "Texas DIR", "cloud"), ("IRS Publication 1075", "US IRS", "tax"),
    ("CJIS Security Policy", "US FBI", "law-enforcement"), ("PCI Card Production", "PCI SSC", "payments"),
    ("EMVCo Security", "EMVCo", "payments"), ("ISO 8583", "ISO", "payments"),
    ("Basel III Operational Risk", "BCBS", "financial"), ("EBA Guidelines ICT", "EBA", "financial"),
    ("Bank of England SS1/21", "Bank of England", "financial"), ("APRA CPS 234", "APRA", "financial"),
    ("RBI Cyber Security Framework", "RBI", "financial"), ("PCI Token Service Provider", "PCI SSC", "payments"),
    ("FERC CIP", "FERC", "energy"), ("TSA Surface Transportation", "US TSA", "transport"),
    ("FRA Rail Cybersecurity", "US FRA", "rail"), ("EASA Part-IS", "EASA", "aviation"),
    ("FAA Cybersecurity", "US FAA", "aviation"), ("USCG NVIC 01-20", "US Coast Guard", "maritime"),
    ("IEC 61850 Security", "IEC", "energy"), ("IEC 62351", "IEC", "energy"),
    ("NEI 08-09 Nuclear", "NEI", "nuclear"), ("NRC 10 CFR 73.54", "US NRC", "nuclear"),
    ("AAMI TIR57 Medical", "AAMI", "medical-device"), ("IMDRF Cybersecurity", "IMDRF", "medical-device"),
    ("SAE J3061 Automotive", "SAE", "automotive"), ("ISO 24089 Automotive SW Update", "ISO", "automotive"),
    ("3GPP Security (5G)", "3GPP", "telecom"), ("GSMA NESAS", "GSMA", "telecom"),
    ("GSMA FS.31 Baseline", "GSMA", "telecom"), ("CTIA IoT Cybersecurity", "CTIA", "iot"),
    ("PSA Certified", "Arm", "iot"), ("IoXt Alliance", "IoXt", "iot"),
    ("UL 2900 Medical/IoT", "UL", "iot"), ("WELL/Smart Building Cyber", "Industry", "iot"),
    ("NERC CIP-013 Supply Chain", "NERC", "energy"), ("CISA Cross-Sector CPGs", "CISA", "framework"),
]

# --- Identity / crypto / protocol standards (real) ---
_PROTOCOL_STDS = [
    ("OAuth 2.1", "IETF", "identity"), ("OAuth 2.0 (RFC 6749)", "IETF", "identity"),
    ("OAuth PKCE (RFC 7636)", "IETF", "identity"), ("OAuth DPoP (RFC 9449)", "IETF", "identity"),
    ("SAML 2.0", "OASIS", "identity"), ("SCIM 2.0", "IETF", "identity"),
    ("JWT (RFC 7519)", "IETF", "identity"), ("JWT BCP (RFC 8725)", "IETF", "identity"),
    ("WebAuthn Level 2", "W3C", "identity"), ("FAPI 2.0", "OpenID Foundation", "identity"),
    ("mTLS (RFC 8705)", "IETF", "identity"), ("SPIFFE/SPIRE", "CNCF", "identity"),
    ("HSTS (RFC 6797)", "IETF", "crypto"), ("CSP Level 3", "W3C", "appsec"),
    ("Subresource Integrity", "W3C", "appsec"), ("CAA (RFC 8659)", "IETF", "crypto"),
    ("DNSSEC", "IETF", "crypto"), ("DANE (RFC 6698)", "IETF", "crypto"),
    ("DMARC (RFC 7489)", "IETF", "email"), ("DKIM (RFC 6376)", "IETF", "email"),
    ("SPF (RFC 7208)", "IETF", "email"), ("MTA-STS (RFC 8461)", "IETF", "email"),
    ("FIPS 186-5 Digital Signatures", "NIST", "crypto"), ("NIST SP 800-131A Transitions", "NIST", "crypto"),
    ("X.509 (RFC 5280)", "IETF", "crypto"), ("CT (RFC 6962)", "IETF", "crypto"),
    ("COSE (RFC 9052)", "IETF", "crypto"), ("PASETO", "Community", "identity"),
]

# --- OWASP projects (real) ---
_OWASP_PROJECTS = [
    ("OWASP Cheat Sheet Series", "appsec"), ("OWASP WSTG (Web Testing Guide)", "appsec"),
    ("OWASP MSTG (Mobile Testing Guide)", "mobile"), ("OWASP API Security Project", "appsec"),
    ("OWASP Dependency-Check", "supply-chain"), ("OWASP Threat Dragon", "appsec"),
    ("OWASP Top 10 Privacy Risks", "privacy"), ("OWASP Top 10 Serverless", "cloud"),
    ("OWASP Kubernetes Top 10", "containers"), ("OWASP Docker Top 10", "containers"),
    ("OWASP Top 10 Low-Code/No-Code", "appsec"), ("OWASP IoT Top 10", "iot"),
    ("OWASP Automated Threats (OAT)", "appsec"), ("OWASP Application Security Verification (L1-L3)", "appsec"),
]


def _build_extended():
    out = []
    for p in _CIS_BENCHMARK_PLATFORMS:
        out.append({"id": "cis-bm-" + _slug(p), "name": f"CIS Benchmark — {p}",
                    "authority": "CIS", "domain": "hardening"})
    for name, country in _NATIONAL_LAWS:
        out.append({"id": "law-" + _slug(name), "name": name,
                    "authority": country, "domain": "privacy"})
    for name in _US_STATE_LAWS:
        out.append({"id": "us-" + _slug(name), "name": name + " (US State Privacy)",
                    "authority": "US State", "domain": "privacy"})
    for num, title in _NIST_SP800:
        out.append({"id": "nist-sp-" + _slug(num), "name": f"NIST SP {num} {title}",
                    "authority": "NIST", "domain": "controls"})
    for name in _DISA_STIGS:
        out.append({"id": "stig-" + _slug(name), "name": f"DISA STIG/SRG — {name}",
                    "authority": "DISA", "domain": "hardening"})
    for name, auth, dom in _SECTOR_REGS:
        out.append({"id": "sect-" + _slug(name), "name": name, "authority": auth, "domain": dom})
    for name, auth, dom in _PROTOCOL_STDS:
        out.append({"id": "std-" + _slug(name), "name": name, "authority": auth, "domain": dom})
    for name, dom in _OWASP_PROJECTS:
        out.append({"id": "owasp-" + _slug(name), "name": name, "authority": "OWASP", "domain": dom})
    return out


FRAMEWORKS += _build_extended()

# --- Second batch: practice guides, regional agencies, cloud-native, more ---
_NIST_SP1800 = [
    ("1800-1", "Securing Electronic Health Records"), ("1800-2", "Identity & Access for Energy"),
    ("1800-5", "IT Asset Management"), ("1800-7", "Situational Awareness for Energy"),
    ("1800-8", "Wireless Infusion Pumps"), ("1800-11", "Data Integrity: Recovering from Ransomware"),
    ("1800-15", "Securing IoT (MUD)"), ("1800-16", "Securing Web Transactions (TLS)"),
    ("1800-17", "Multifactor Auth for E-Commerce"), ("1800-19", "Trusted Cloud"),
    ("1800-21", "Mobile Device Security"), ("1800-22", "Mobile BYOD"),
    ("1800-23", "Energy OT Asset Management"), ("1800-25", "Data Integrity: Identify & Protect"),
    ("1800-26", "Data Integrity: Detect & Respond"), ("1800-27", "Securing PACS"),
    ("1800-30", "Securing Telehealth RPM"), ("1800-31", "Ransomware Protection"),
    ("1800-32", "Securing Distributed Energy Resources"), ("1800-34", "Supply Chain Integrity"),
    ("1800-35", "Implementing Zero Trust Architecture"), ("1800-36", "Trusted IoT Onboarding"),
    ("1800-38", "Migration to Post-Quantum Cryptography"),
]
_REGIONAL_AGENCY = [
    ("ENISA Threat Landscape", "ENISA", "framework"), ("ENISA Cloud Security Guide", "ENISA", "cloud"),
    ("ENISA IoT Baseline", "ENISA", "iot"), ("ENISA Good Practices for IoT (SDLC)", "ENISA", "iot"),
    ("ENISA Railway Cybersecurity", "ENISA", "rail"), ("ENISA AI Cybersecurity", "ENISA", "ai"),
    ("UK NCSC Cyber Essentials Toolkit", "UK NCSC", "framework"), ("UK NCSC 10 Steps to Cyber Security", "UK NCSC", "framework"),
    ("UK NCSC Cloud Security Principles", "UK NCSC", "cloud"), ("UK NCSC Secure Development", "UK NCSC", "sdlc"),
    ("Canada CCCS Top 10 IT Security Actions", "CCCS", "framework"), ("Singapore CSA Safe App Standard", "Singapore CSA", "mobile"),
    ("Japan METI Cybersecurity Guidelines", "METI", "framework"), ("India NCIIPC Guidelines", "NCIIPC", "controls"),
    ("Australia IRAP", "ACSC", "cloud"), ("EU ENISA EUCS Cloud Scheme", "ENISA", "cloud"),
    ("OWASP SAMM (Belgium)", "OWASP", "sdlc"),
]
_CLOUD_NATIVE = [
    ("CNCF Kubernetes Hardening Guide (NSA/CISA)", "NSA/CISA", "containers"),
    ("Pod Security Standards", "CNCF", "containers"), ("OPA/Gatekeeper Policy", "CNCF", "containers"),
    ("Kyverno Policy", "CNCF", "containers"), ("Falco Runtime Rules", "CNCF", "containers"),
    ("SLSA Build L3", "OpenSSF", "supply-chain"), ("Sigstore/cosign Signing", "OpenSSF", "supply-chain"),
    ("GUAC Supply-Chain Graph", "OpenSSF", "supply-chain"), ("Service Mesh (Istio) Security", "CNCF", "containers"),
    ("eBPF/Cilium Network Policy", "CNCF", "containers"), ("Secrets Store CSI Driver", "CNCF", "containers"),
    ("CIS Software Supply Chain Guide", "CIS", "supply-chain"),
]
_MORE_NATIONAL = [
    ("Switzerland nFADP", "Switzerland"), ("Brazil ANPD Regulations", "Brazil"),
    ("China DSL (Data Security Law)", "China"), ("China CSL (Cybersecurity Law)", "China"),
    ("China MLPS 2.0", "China"), ("South Korea ISMS-P", "South Korea"),
    ("Japan APPI Cloud Guidelines", "Japan"), ("Singapore PDPA DPMP", "Singapore"),
    ("Australia SOCI Act", "Australia"), ("Canada CPPA (Bill C-27)", "Canada"),
    ("Nigeria NDPR", "Nigeria"), ("Kenya ODPC Guidelines", "Kenya"),
    ("Brazil BACEN Resolution 4893", "Brazil"), ("Mexico CNBV Provisions", "Mexico"),
    ("Indonesia OJK Cyber Regulation", "Indonesia"), ("Philippines BSP Cyber Guidelines", "Philippines"),
]
_MORE_CRYPTO = [
    ("NIST FIPS 203 ML-KEM", "NIST", "crypto"), ("NIST FIPS 204 ML-DSA", "NIST", "crypto"),
    ("NIST FIPS 205 SLH-DSA", "NIST", "crypto"), ("NIST SP 800-90A DRBG", "NIST", "crypto"),
    ("NIST SP 800-38 Modes of Operation", "NIST", "crypto"), ("RFC 8439 ChaCha20-Poly1305", "IETF", "crypto"),
    ("RFC 7748 Curve25519", "IETF", "crypto"), ("RFC 9180 HPKE", "IETF", "crypto"),
    ("PKCS#11", "OASIS", "crypto"), ("KMIP", "OASIS", "crypto"),
]


def _build_extended_2():
    out = []
    for num, title in _NIST_SP1800:
        out.append({"id": "nist-sp1800-" + _slug(num), "name": f"NIST SP {num} {title}",
                    "authority": "NIST NCCoE", "domain": "controls"})
    for name, auth, dom in _REGIONAL_AGENCY + _CLOUD_NATIVE + _MORE_CRYPTO:
        out.append({"id": "x-" + _slug(name), "name": name, "authority": auth, "domain": dom})
    for name, country in _MORE_NATIONAL:
        out.append({"id": "law2-" + _slug(name), "name": name, "authority": country, "domain": "privacy"})
    return out


FRAMEWORKS += _build_extended_2()

# De-duplicate by id, keeping first occurrence.
_seen_ids = set()
_deduped = []
for _f in FRAMEWORKS:
    if _f["id"] in _seen_ids:
        continue
    _seen_ids.add(_f["id"])
    _deduped.append(_f)
FRAMEWORKS = _deduped


def count() -> int:
    return len(FRAMEWORKS)


def by_domain() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in FRAMEWORKS:
        out[f["domain"]] = out.get(f["domain"], 0) + 1
    return out


def ids() -> List[str]:
    return [f["id"] for f in FRAMEWORKS]
