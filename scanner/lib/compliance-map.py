"""
ClaudeSec — Compliance framework mapping (lightweight standalone module).

Extracted from dashboard-gen.py so that output.sh can load compliance
logic without importing the full 5000+ line dashboard module.
"""

COMPLIANCE_CONTROL_MAP = {
    "ISO 27001:2022": [
        {
            "control": "A.5.1",
            "name": "Information security policy",
            "desc": "Policies documented, shared, and reviewed",
            "action": "Document policy, periodic review, staff training and approval.",
            "checks": ["security_policy"],
            "status": "",
        },
        {
            "control": "A.8.2",
            "name": "Access control",
            "desc": "Access to resources and systems restricted by role and need",
            "action": "Apply RBAC, branch protection, PR approval; minimize admin rights.",
            "checks": ["branch_protection", "require_approval", "admin"],
            "status": "",
        },
        {
            "control": "A.8.5",
            "name": "Secure authentication",
            "desc": "Strong authentication (MFA, SSO) in use",
            "action": "Adopt MFA and SSO; strengthen password policy and session management.",
            "checks": ["mfa", "two_factor", "sso", "authentication"],
            "status": "",
        },
        {
            "control": "A.8.9",
            "name": "Configuration management",
            "desc": "Config and defaults managed per security baseline",
            "action": "Apply hardening guides; change defaults; disable unnecessary services.",
            "checks": ["configuration", "misconfigur", "default"],
            "status": "",
        },
        {
            "control": "A.8.24",
            "name": "Cryptography",
            "desc": "Encryption and key management for data in transit and at rest",
            "action": "Use TLS and KMS; store secrets in secret manager; key rotation.",
            "checks": ["encrypt", "tls", "ssl", "secret"],
            "status": "",
        },
        {
            "control": "A.8.28",
            "name": "Secure coding",
            "desc": "Secure coding and SAST for vulnerability management",
            "action": "Adopt CodeQL/SAST, code review; prevent injection and XSS.",
            "checks": ["code_scanning", "sast", "injection", "codeql"],
            "status": "",
        },
        {
            "control": "A.8.8",
            "name": "Technical vulnerability management",
            "desc": "Dependency, CVE detection, and patching in place",
            "action": "Dependabot and CVE scanning; patch policy and SBOM.",
            "checks": ["dependabot", "cve", "vulnerability", "outdated"],
            "status": "",
        },
    ],
    "KISA ISMS-P": [
        {
            "control": "2.6.1",
            "name": "Access control policy",
            "desc": "Access control policy and access rights management",
            "action": "Document access policy; least privilege; periodic permission review.",
            "checks": ["branch_protection", "access", "permission", "restrict"],
            "status": "",
        },
        {
            "control": "2.6.2",
            "name": "Authentication and authorization",
            "desc": "Strong authentication and separation of duties",
            "action": "MFA and SSO; separate admin accounts; track permission changes.",
            "checks": ["mfa", "authentication", "sso", "two_factor", "admin"],
            "status": "",
        },
        {
            "control": "2.7.1",
            "name": "Cryptographic policy",
            "desc": "Encryption and key management policy",
            "action": "TLS and encryption at rest; key protection and rotation; no plaintext secrets.",
            "checks": ["encrypt", "tls", "ssl", "secret", "kms"],
            "status": "",
        },
        {
            "control": "2.9.1",
            "name": "Change management",
            "desc": "Change request, review, and approval process",
            "action": "PR and approval workflow; change log and rollback procedure.",
            "checks": ["require_approval", "review", "pull_request"],
            "status": "",
        },
        {
            "control": "2.11.1",
            "name": "Incident response",
            "desc": "Detection, response, and recovery",
            "action": "Logging, monitoring, alerting; response playbook; post-incident analysis.",
            "checks": ["monitoring", "logging", "alert", "audit"],
            "status": "",
        },
        {
            "control": "2.12.1",
            "name": "Privacy protection",
            "desc": "Prevent exposure of PII and sensitive data",
            "action": "Secret scanning; no plaintext storage; access log and masking.",
            "checks": ["secret_scanning", "credential", "plaintext"],
            "status": "",
        },
    ],
    "PCI-DSS v4.0.1": [
        {
            "control": "Req 1",
            "name": "Network security controls",
            "desc": "Firewall, network segmentation, TLS",
            "action": "Firewall policy; DMZ and segmentation; enforce TLS.",
            "checks": ["firewall", "network", "tls"],
            "status": "",
        },
        {
            "control": "Req 2",
            "name": "Secure configuration",
            "desc": "Hardened system and service settings",
            "action": "Hardening; change default passwords; remove unnecessary services.",
            "checks": ["configuration", "default", "hardening", "benchmark"],
            "status": "",
        },
        {
            "control": "Req 3",
            "name": "Protect stored data",
            "desc": "Encryption and key management for cardholder data",
            "action": "Encrypt at rest; KMS and key rotation; consider tokenization.",
            "checks": ["encrypt", "kms", "key_rotation"],
            "status": "",
        },
        {
            "control": "Req 6",
            "name": "Secure software development",
            "desc": "Secure SDLC and vulnerability management",
            "action": "SAST and dependency checks; patching and code review.",
            "checks": ["code_scanning", "sast", "injection", "vulnerability"],
            "status": "",
        },
        {
            "control": "Req 7",
            "name": "Access restriction",
            "desc": "Access only for those who need it",
            "action": "RBAC and least privilege; branch protection and approval policy.",
            "checks": ["branch_protection", "permission", "restrict", "admin"],
            "status": "",
        },
        {
            "control": "Req 8",
            "name": "User identification and authentication",
            "desc": "Strong authentication and account management",
            "action": "MFA; password policy; account lockout and session management.",
            "checks": ["mfa", "authentication", "two_factor", "sso"],
            "status": "",
        },
        {
            "control": "Req 10",
            "name": "Logging and monitoring",
            "desc": "Logs and monitoring for access, change, and incidents",
            "action": "Collect and retain audit logs; detection and alerting; periodic review.",
            "checks": ["logging", "monitoring", "audit", "alert"],
            "status": "",
        },
    ],
    "NIST 800-53 Rev5": [
        {
            "control": "AC-2",
            "name": "Account management",
            "desc": "Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts",
            "action": "Enforce account lifecycle management; periodic access review; disable inactive accounts.",
            "checks": ["account", "user", "admin", "permission", "iam"],
            "status": "",
        },
        {
            "control": "AC-6",
            "name": "Least privilege",
            "desc": "Employ the principle of least privilege, allowing only authorized accesses necessary for organizational missions",
            "action": "Implement RBAC; restrict admin privileges; review and minimize permissions regularly.",
            "checks": ["least_privilege", "rbac", "restrict", "permission", "branch_protection", "admin"],
            "status": "",
        },
        {
            "control": "AU-2",
            "name": "Event logging",
            "desc": "Identify events that the system is capable of logging in support of the audit function",
            "action": "Enable audit logging for all critical events; configure log retention and integrity checks.",
            "checks": ["logging", "audit", "log_maxage", "event_log", "monitoring"],
            "status": "",
        },
        {
            "control": "CA-7",
            "name": "Continuous monitoring",
            "desc": "Develop a continuous monitoring strategy and implement a continuous monitoring program",
            "action": "Deploy SIEM/monitoring tools; continuous vulnerability scanning; automated alerts.",
            "checks": ["monitoring", "alert", "scan", "vulnerability", "continuous"],
            "status": "",
        },
        {
            "control": "CM-6",
            "name": "Configuration settings",
            "desc": "Establish and document configuration settings for components using security configuration checklists",
            "action": "Apply CIS benchmarks; enforce secure defaults; automate configuration drift detection.",
            "checks": ["configuration", "benchmark", "hardening", "default", "baseline"],
            "status": "",
        },
        {
            "control": "IA-2",
            "name": "Identification and authentication",
            "desc": "Uniquely identify and authenticate organizational users and processes",
            "action": "Enforce MFA for all users; implement SSO; strong password and session policies.",
            "checks": ["mfa", "authentication", "two_factor", "sso", "identity"],
            "status": "",
        },
        {
            "control": "RA-5",
            "name": "Vulnerability monitoring and scanning",
            "desc": "Monitor and scan for vulnerabilities in the system and hosted applications",
            "action": "Run SAST/DAST scans; dependency vulnerability checks; prioritize by CVSS severity.",
            "checks": ["vulnerability", "code_scanning", "sast", "dependency", "cve"],
            "status": "",
        },
        {
            "control": "SC-8",
            "name": "Transmission confidentiality and integrity",
            "desc": "Protect the confidentiality and integrity of transmitted information",
            "action": "Enforce TLS 1.2+; certificate management; HSTS and secure transport headers.",
            "checks": ["tls", "ssl", "https", "certificate", "encrypt"],
            "status": "",
        },
        {
            "control": "SC-28",
            "name": "Protection of information at rest",
            "desc": "Protect the confidentiality and integrity of information at rest",
            "action": "Encrypt data at rest; KMS key management and rotation; secure backup storage.",
            "checks": ["encrypt", "kms", "key_rotation", "storage", "secret"],
            "status": "",
        },
        {
            "control": "SI-4",
            "name": "System monitoring",
            "desc": "Monitor the system to detect attacks, indicators of potential attacks, and unauthorized connections",
            "action": "Deploy IDS/IPS; network monitoring; real-time alerting and incident correlation.",
            "checks": ["monitoring", "detection", "alert", "intrusion", "anomaly"],
            "status": "",
        },
    ],
    "CIS Benchmarks": [
        {
            "control": "CIS-1.1",
            "name": "Inventory of authorized and unauthorized devices",
            "desc": "Maintain an accurate and up-to-date inventory of all technology assets",
            "action": "Automate asset discovery; tag and classify resources; remove unauthorized assets.",
            "checks": ["inventory", "asset", "resource", "discovery"],
            "status": "",
        },
        {
            "control": "CIS-4.1",
            "name": "Secure configuration for network infrastructure",
            "desc": "Establish and maintain secure network device configurations",
            "action": "Apply firewall rules; enforce network segmentation; disable unused ports and services.",
            "checks": ["firewall", "network", "segmentation", "port"],
            "status": "",
        },
        {
            "control": "CIS-5.1",
            "name": "Account management policies",
            "desc": "Establish and maintain an account management process",
            "action": "Enforce MFA; regular access reviews; promptly disable departed user accounts.",
            "checks": ["mfa", "account", "authentication", "access", "admin"],
            "status": "",
        },
        {
            "control": "CIS-6.1",
            "name": "Audit log management",
            "desc": "Establish and maintain an audit log management process",
            "action": "Enable logging on all critical systems; define retention policies; protect log integrity.",
            "checks": ["logging", "audit", "log_maxage", "retention"],
            "status": "",
        },
        {
            "control": "CIS-7.1",
            "name": "Vulnerability management process",
            "desc": "Establish and maintain a vulnerability management process",
            "action": "Automate vulnerability scanning; track remediation SLAs; prioritize critical CVEs.",
            "checks": ["vulnerability", "scan", "patch", "cve", "remediation"],
            "status": "",
        },
        {
            "control": "CIS-8.1",
            "name": "Data protection",
            "desc": "Establish and maintain a data management process including encryption requirements",
            "action": "Classify data sensitivity; encrypt in transit and at rest; secret scanning enabled.",
            "checks": ["encrypt", "secret", "kms", "tls", "data_protection"],
            "status": "",
        },
        {
            "control": "CIS-K8s-1.1",
            "name": "API server secure configuration",
            "desc": "Ensure the API server is configured securely per CIS Kubernetes Benchmark",
            "action": "Enable audit logging; restrict anonymous auth; enforce RBAC; TLS for API server.",
            "checks": ["apiserver", "kube", "rbac", "anonymous", "kubelet"],
            "status": "",
        },
        {
            "control": "CIS-K8s-4.1",
            "name": "Worker node security",
            "desc": "Ensure worker node components are configured securely",
            "action": "Restrict kubelet permissions; enable read-only port protection; enforce TLS certificates.",
            "checks": ["kubelet", "worker", "node", "tls_cert", "readonly"],
            "status": "",
        },
    ],
}


def _match_prowler_compliance(finding, framework_key):
    """Check if a prowler finding's native compliance data references a framework."""
    comp = finding.get("compliance", {})
    if not comp:
        return False
    fk = framework_key.lower()
    for key, val in comp.items():
        k = key.lower()
        if fk in k or k in fk:
            return True
        if isinstance(val, (list, str)) and any(
            fk in str(v).lower() for v in (val if isinstance(val, list) else [val])
        ):
            return True
    return False


def map_compliance(all_findings):
    """Map findings to compliance framework controls. Returns {framework: [ctrl_with_status]}."""
    result = {}
    for framework, controls in COMPLIANCE_CONTROL_MAP.items():
        mapped = []
        for ctrl in controls:
            matching = []
            for f in all_findings:
                text = f"{f['check']} {f['title']} {f['message']}".lower()
                keyword_match = any(kw in text for kw in ctrl["checks"])
                native_match = _match_prowler_compliance(f, framework)
                if keyword_match or native_match:
                    matching.append(f)
            status = "PASS" if len(matching) == 0 else "FAIL"
            mapped.append(
                {
                    **ctrl,
                    "status": status,
                    "count": len(matching),
                    "findings": matching[:5],
                }
            )
        result[framework] = mapped
    return result


def compliance_summary(compliance_map):
    """Return {framework: {pass, fail, total}} from map_compliance output."""
    summary = {}
    for fw, controls in compliance_map.items():
        p = sum(1 for c in controls if c["status"] == "PASS")
        f = sum(1 for c in controls if c["status"] == "FAIL")
        summary[fw] = {"pass": p, "fail": f, "total": p + f}
    return summary
