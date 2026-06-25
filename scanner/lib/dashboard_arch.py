"""
dashboard_arch.py — Architecture security-domain mapping data and helper.

Extracted from dashboard_mapping.py to keep that module under the 800-line
cap (coding-style rule). Re-exported by dashboard_mapping for backward
compatibility; importers may use either path.

Public names: ARCH_DOMAINS, ARCH_DOMAIN_LINKS, OWASP_TO_ARCH, map_architecture.
"""

# ── Architecture Security Domains ────────────────────────────────────────────

ARCH_DOMAINS = [
    {
        "name": "Network & TLS",
        "icon": "🌐",
        "checks": ["tls", "ssl", "https", "certificate", "network", "firewall", "dns"],
        "summary": "TLS/SSL, certificates, firewall and DNS for secure communication.",
        "action": "TLS 1.2+ and strong ciphers; monitor cert expiry; block unnecessary ports.",
    },
    {
        "name": "Identity & Access",
        "icon": "🔑",
        "checks": [
            "mfa",
            "sso",
            "iam",
            "access",
            "permission",
            "admin",
            "authentication",
            "two_factor",
            "branch_protection",
            "require_approval",
        ],
        "summary": "IAM, MFA, branch protection, PR approval for access control and authentication.",
        "action": "Apply MFA and SSO; least privilege and RBAC; branch protection and mandatory code review.",
    },
    {
        "name": "Data protection",
        "icon": "🔒",
        "checks": [
            "encrypt",
            "secret",
            "kms",
            "key_rotation",
            "plaintext",
            "credential",
            "secret_scanning",
        ],
        "summary": "Encryption, secret and key management, secret scanning to prevent data exposure.",
        "action": "Encrypt in transit and at rest; KMS and rotation; use secret manager; scan code for secrets.",
    },
    {
        "name": "CI/CD pipeline",
        "icon": "⚡",
        "checks": [
            "pipeline",
            "workflow",
            "deploy",
            "action",
            "cicd",
            "webhook",
            "deploy_key",
            "signing",
        ],
        "summary": "Build and deploy pipelines; webhooks and signing for integrity and safe deployment.",
        "action": "Least privilege for workflows; webhook signature verification; manage deploy keys and signing; audit logs.",
    },
    {
        "name": "Monitoring & logging",
        "icon": "📊",
        "checks": ["logging", "monitoring", "audit", "alert", "detection", "siem"],
        "summary": "Logs, audit, and alerts for detection and incident response.",
        "action": "Integrate GuardDuty, Security Hub; collect and retain logs; alerting and response procedures.",
    },
    {
        "name": "Supply chain",
        "icon": "📦",
        "checks": [
            "dependency",
            "dependabot",
            "sbom",
            "slsa",
            "provenance",
            "vulnerability_alert",
            "cve",
            "outdated",
        ],
        "summary": "Dependencies, CVE, and SBOM for supply chain vulnerability management.",
        "action": "Dependabot and CVE scanning; generate and verify SBOM; immutable releases and patch policy.",
    },
    {
        "name": "Endpoint security",
        "icon": "💻",
        "checks": [
            "edr",
            "endpoint",
            "sentinelone",
            "antivirus",
            "malware",
            "mdm",
            "jamf",
            "device",
        ],
        "summary": "Endpoint Detection and Response (EDR), MDM, and device management for endpoint protection.",
        "action": "Deploy SentinelOne/EDR on all endpoints; enforce MDM enrollment via Jamf/Intune; monitor threat alerts.",
    },
    {
        "name": "Cloud & K8s security",
        "icon": "☁",
        "checks": [
            "cluster",
            "pod",
            "rbac",
            "karpenter",
            "eks",
            "s3",
            "rds",
            "vpc",
            "security_group",
            "guardduty",
        ],
        "summary": "Cloud infrastructure, Kubernetes, and managed services security posture.",
        "action": "CIS benchmark compliance; Pod Security Standards; least privilege RBAC; encrypt data at rest; enable GuardDuty.",
    },
]

# Mapping: architecture domains <-> OWASP / compliance / scanner categories
ARCH_DOMAIN_LINKS = [
    {
        "owasp": ["A02", "A05", "A09"],
        "compliance": [
            ("ISO 27001:2022", "A.8.9"),
            ("PCI-DSS v4.0.1", "Req 1"),
            ("PCI-DSS v4.0.1", "Req 2"),
        ],
        "scanner": ["network"],
    },
    {
        "owasp": ["A01", "A07"],
        "compliance": [
            ("ISO 27001:2022", "A.8.2"),
            ("ISO 27001:2022", "A.8.5"),
            ("KISA ISMS-P", "2.6.1"),
            ("KISA ISMS-P", "2.6.2"),
            ("PCI-DSS v4.0.1", "Req 7"),
            ("PCI-DSS v4.0.1", "Req 8"),
        ],
        "scanner": ["access-control"],
    },
    {
        "owasp": ["A04", "A02"],
        "compliance": [
            ("ISO 27001:2022", "A.8.24"),
            ("KISA ISMS-P", "2.7.1"),
            ("PCI-DSS v4.0.1", "Req 3"),
        ],
        "scanner": ["access-control", "code"],
    },
    {
        "owasp": ["A03", "A08"],
        "compliance": [
            ("ISO 27001:2022", "A.8.28"),
            ("KISA ISMS-P", "2.9.1"),
            ("PCI-DSS v4.0.1", "Req 6"),
        ],
        "scanner": ["cicd"],
    },
    {
        "owasp": ["A09"],
        "compliance": [
            ("ISO 27001:2022", "A.8.2"),
            ("KISA ISMS-P", "2.11.1"),
            ("PCI-DSS v4.0.1", "Req 10"),
        ],
        "scanner": ["cloud", "infra"],
    },
    {
        "owasp": ["A03", "A08"],
        "compliance": [("ISO 27001:2022", "A.8.8"), ("PCI-DSS v4.0.1", "Req 6")],
        "scanner": ["cicd", "code", "infra"],
    },
    # Endpoint security
    {
        "owasp": ["A05", "A07"],
        "compliance": [
            ("ISO 27001:2022", "A.8.1"),
            ("KISA ISMS-P", "2.10.1"),
            ("PCI-DSS v4.0.1", "Req 5"),
        ],
        "scanner": ["infra"],
    },
    # Cloud & K8s security
    {
        "owasp": ["A01", "A05", "A09"],
        "compliance": [
            ("ISO 27001:2022", "A.8.23"),
            ("KISA ISMS-P", "2.8.1"),
            ("PCI-DSS v4.0.1", "Req 1"),
            ("PCI-DSS v4.0.1", "Req 2"),
        ],
        "scanner": ["cloud", "infra", "prowler"],
    },
]

# OWASP → related architecture domains (reverse mapping)
OWASP_TO_ARCH = {
    "A01": [1, 7],
    "A02": [0, 2],
    "A03": [3, 5],
    "A04": [2],
    "A05": [0, 6, 7],
    "A06": [],
    "A07": [1, 6],
    "A08": [3, 5],
    "A09": [0, 4, 7],
    "A10": [],
}


def map_architecture(all_findings):
    result = []
    for i, domain in enumerate(ARCH_DOMAINS):
        matching = []
        for f in all_findings:
            text = f"{f['check']} {f['title']} {f['message']}".lower()
            if any(kw in text for kw in domain["checks"]):
                matching.append(f)
        links = (
            ARCH_DOMAIN_LINKS[i]
            if i < len(ARCH_DOMAIN_LINKS)
            else {"owasp": [], "compliance": [], "scanner": []}
        )
        result.append(
            {
                **domain,
                "fail_count": len(matching),
                "findings": matching[:10],
                "links": links,
            }
        )
    return result
