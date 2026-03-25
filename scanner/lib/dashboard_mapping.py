"""
dashboard_mapping.py — Shared mapping data extracted from dashboard-gen.py.

Contains:
  - CHECK_EN_MAP / DEFAULT_SUMMARY / DEFAULT_ACTION / get_check_en()
  - OWASP_2025 / OWASP_CHECK_MAP / OWASP_LLM_2025 / map_findings_to_owasp()
  - COMPLIANCE_FRAMEWORKS / COMPLIANCE_CONTROL_MAP (with compliance-map.py dynamic import)
  - ARCH_DOMAINS / ARCH_DOMAIN_LINKS / OWASP_TO_ARCH / map_architecture()
  - CATEGORY_META
"""

import os
import importlib.util
from typing import Any

# ── Prowler/GitHub check code → English summary & remediation ────────────────

CHECK_EN_MAP = {
    "guardduty_is_enabled": {
        "summary": "GuardDuty is disabled or not configured per region; threat detection may be missing.",
        "action": "Enable GuardDuty in each region; configure Finding event alerts (SNS/EventBridge).",
    },
    "iam_role_administratoraccess_policy": {
        "summary": "IAM role has AdministratorAccess policy granting excessive privileges.",
        "action": "Apply least privilege; replace with custom policy containing only required permissions.",
    },
    "awslambda_function_no_secrets_in_variables": {
        "summary": "Lambda environment variables contain secrets (API keys, tokens, etc.).",
        "action": "Use Secrets Manager or Parameter Store; remove secrets from environment variables.",
    },
    "cloudformation_stack_outputs_find_secrets": {
        "summary": "CloudFormation stack outputs contain secret strings and may be exposed.",
        "action": "Remove secrets from outputs; reference sensitive values via SSM/Secrets Manager.",
    },
    "s3_bucket_public_access": {
        "summary": "S3 bucket allows public access or Block Public Access is disabled.",
        "action": "Enable Block Public Access at account/bucket level; review bucket policies.",
    },
    "s3_bucket_no_mfa_delete": {
        "summary": "S3 bucket versioning allows delete without MFA; accidental or malicious deletion risk.",
        "action": "Enable MFA delete for versioned buckets; restrict delete permissions.",
    },
    "rds_instance_public_access": {
        "summary": "RDS instance is publicly accessible; increases exposure to network attacks.",
        "action": "Set RDS to private; use VPC and security groups; access via bastion or VPN.",
    },
    "ec2_instance_public_ip": {
        "summary": "EC2 instance has a public IP; may be exposed to the internet.",
        "action": "Use private subnets and NAT; restrict security groups; avoid unnecessary public IPs.",
    },
    "lambda_function_url_public": {
        "summary": "Lambda function URL is publicly accessible without auth.",
        "action": "Add IAM auth or custom auth; restrict via resource policy and VPC.",
    },
    "cloudtrail_log_file_validation": {
        "summary": "CloudTrail log file validation is disabled; integrity of logs cannot be verified.",
        "action": "Enable log file validation for all trails; monitor and alert on changes.",
    },
    "kms_key_rotation": {
        "summary": "KMS key rotation is disabled; key compromise impact is higher.",
        "action": "Enable automatic key rotation for customer-managed KMS keys.",
    },
    "branch_protection": {
        "summary": "Default branch has no branch protection; force push and delete are possible.",
        "action": "Configure branch protection rules; require PR approval, status checks, linear history.",
    },
    "require_approval": {
        "summary": "PR approval and code review are not required before merge.",
        "action": "Set required number of approvals; apply CODEOWNERS and review policy.",
    },
    "secret_scanning": {
        "summary": "Secret scanning is disabled; committed secrets may not be detected.",
        "action": "Enable secret scanning and push protection; configure alerts.",
    },
    "dependabot": {
        "summary": "Dependency vulnerability alerts and auto-PRs are not configured.",
        "action": "Enable Dependabot alerts and security updates; define patch policy.",
    },
    "code_scanning": {
        "summary": "Code scanning (e.g. CodeQL) is not configured; static analysis may be missing.",
        "action": "Enable CodeQL or equivalent SAST; include scan results in PR checks.",
    },
    "vulnerability_alerts": {
        "summary": "Repository vulnerability alerts are disabled; known CVEs may not be surfaced.",
        "action": "Enable Dependabot or security alerts; fix or dismiss findings per policy.",
    },
    "security_policy": {
        "summary": "Security policy (SECURITY.md) is missing; contributors lack a clear reporting path.",
        "action": "Add SECURITY.md with contact and disclosure policy; consider GitHub Advisory.",
    },
    "default_branch_deletion": {
        "summary": "Default branch can be deleted or force-pushed; repository integrity at risk.",
        "action": "Enable branch protection; disallow force push and branch deletion.",
    },
    "repository_private": {
        "summary": "Repository is public; code and metadata are visible to everyone.",
        "action": "Make repository private or reduce exposed secrets and metadata.",
    },
    "mfa": {
        "summary": "Multi-factor authentication is not enforced for organization or high-privilege access.",
        "action": "Enforce MFA for all members; use conditional access and phishing-resistant methods.",
    },
    "two_factor": {
        "summary": "Two-factor authentication is not required; account takeover risk is higher.",
        "action": "Require 2FA for all users; prefer TOTP or hardware keys.",
    },
    "encrypt": {
        "summary": "Encryption at rest or in transit is missing or weak for sensitive data.",
        "action": "Enable TLS 1.2+ and strong ciphers; use KMS or managed encryption for data at rest.",
    },
    "logging": {
        "summary": "Logging or audit trail is disabled or insufficient for detection and forensics.",
        "action": "Enable relevant logging (CloudTrail, VPC flow, app logs); retain and protect logs.",
    },
    "backup": {
        "summary": "Backups are not configured or not tested; recovery may not be possible.",
        "action": "Enable automated backups; test restore; define RPO/RTO and retention.",
    },
    # GCP-specific checks
    "compute_instance_public_ip": {
        "summary": "Compute Engine instance has a public IP; direct exposure to internet increases attack surface.",
        "action": "Use Cloud NAT or IAP for internet access; remove public IPs where not strictly necessary.",
    },
    "compute_instance_ip_forwarding": {
        "summary": "IP forwarding is enabled on instance; may allow packet routing bypass.",
        "action": "Disable IP forwarding unless the instance is a NAT gateway or load balancer.",
    },
    "compute_firewall": {
        "summary": "Firewall rule allows overly permissive ingress (e.g. 0.0.0.0/0 on sensitive ports).",
        "action": "Restrict source ranges to known IPs/CIDRs; deny by default; limit ports.",
    },
    "iam_sa_key": {
        "summary": "Service account key is user-managed; higher key leakage risk than workload identity.",
        "action": "Use Workload Identity Federation instead of long-lived keys; rotate if keys are required.",
    },
    "iam_user_mfa": {
        "summary": "User account lacks MFA; increases risk of credential-based account takeover.",
        "action": "Enforce 2-Step Verification for all users in Google Admin Console.",
    },
    "storage_bucket_public": {
        "summary": "Cloud Storage bucket is publicly accessible; data exposure risk.",
        "action": "Remove allUsers/allAuthenticatedUsers; apply uniform bucket-level access.",
    },
    "storage_bucket_uniform_access": {
        "summary": "Bucket does not enforce uniform access; mixed ACL and IAM policies can be confusing.",
        "action": "Enable uniform bucket-level access and manage permissions via IAM only.",
    },
    "sql_instance_public": {
        "summary": "Cloud SQL instance has a public IP or allows 0.0.0.0/0 access.",
        "action": "Use private IP and Cloud SQL Proxy; restrict authorized networks.",
    },
    "gke_legacy_abac": {
        "summary": "GKE cluster uses legacy ABAC authorization; less granular than RBAC.",
        "action": "Disable legacy ABAC; use Kubernetes RBAC (Role-Based Access Control).",
    },
    "gke_network_policy": {
        "summary": "GKE cluster does not enforce network policies; pod-to-pod traffic is unrestricted.",
        "action": "Enable network policy enforcement; define ingress/egress rules per namespace.",
    },
    "gke_private_cluster": {
        "summary": "GKE cluster nodes have public IPs; increases lateral movement risk.",
        "action": "Enable private cluster mode; use authorized networks for API server access.",
    },
    "dns_dnssec": {
        "summary": "DNS zone does not have DNSSEC enabled; DNS spoofing risk.",
        "action": "Enable DNSSEC in Cloud DNS managed zones.",
    },
    # Google Workspace-specific checks
    "gws_admin_mfa": {
        "summary": "Admin accounts lack 2-Step Verification; high-privilege account takeover risk.",
        "action": "Enforce 2SV for all admin accounts; prefer security keys.",
    },
    "gws_user_mfa": {
        "summary": "User accounts lack 2-Step Verification; credential-based attack risk.",
        "action": "Enforce 2SV for all users; set enrollment deadline.",
    },
    "gws_oauth_app": {
        "summary": "Unreviewed third-party OAuth app has access to organizational data.",
        "action": "Review and restrict third-party app access in Admin Console > Security > API Controls.",
    },
    "gws_dlp": {
        "summary": "Data Loss Prevention rules are not configured; sensitive data may leave the organization.",
        "action": "Configure DLP rules for Gmail and Drive to detect and protect sensitive data.",
    },
    "gws_password_policy": {
        "summary": "Password policy does not meet minimum complexity or length requirements.",
        "action": "Set minimum password length (14+); enforce complexity; enable password reuse restrictions.",
    },
}

# Fallback when no CHECK_EN_MAP match — so every finding has Summary and Remediation
DEFAULT_SUMMARY = "Security finding from scan. Review the finding details and reference link below for context."
DEFAULT_ACTION = "Review the finding, apply security best practices per your risk appetite, and refer to the official documentation for detailed remediation steps."


def get_check_en(check_name):
    """Return English summary and remediation for a check name (or keyword). Always returns at least fallback text."""
    c = (check_name or "").lower()
    for key, val in CHECK_EN_MAP.items():
        if key in c:
            return {
                "summary": val.get("summary") or DEFAULT_SUMMARY,
                "action": val.get("action") or DEFAULT_ACTION,
            }
    return {"summary": DEFAULT_SUMMARY, "action": DEFAULT_ACTION}


# ── OWASP Top 10:2025 Mapping (Official — released 2025) ─────────────────────

OWASP_2025 = [
    {
        "id": "A01:2025",
        "name": "Broken Access Control",
        "desc": "CORS misconfiguration, privilege escalation, IDOR, SSRF (CWE-200, CWE-918, CWE-352)",
        "summary": "Access control failures allow unauthorized resource access; CORS, privilege escalation, IDOR, or SSRF can expose or manipulate data.",
        "action": "Apply branch protection, PR approval, least privilege; validate and whitelist CORS and SSRF inputs.",
        "url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
    },
    {
        "id": "A02:2025",
        "name": "Security Misconfiguration",
        "desc": "Missing security headers, default values unchanged, unnecessary features enabled (CWE-16, CWE-611 XXE)",
        "summary": "Default config, unused features, or weak security headers widen attack surface or expose information.",
        "action": "Apply security headers (CSP, X-Frame-Options); remove default passwords and debug mode; enable minimal features.",
        "url": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
    },
    {
        "id": "A03:2025",
        "name": "Software Supply Chain Failures",
        "desc": "Third-party dependencies, CI/CD pipelines, unmanaged components (CWE-1104, CWE-1395)",
        "summary": "External libs, build pipelines, or unpatched components can introduce malware or leave known CVEs exploitable.",
        "action": "Enable Dependabot/CodeQL; SBOM and dependency checks; immutable releases and CODEOWNERS for changes.",
        "url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
    },
    {
        "id": "A04:2025",
        "name": "Cryptographic Failures",
        "desc": "Insufficient encryption for sensitive data; weak algorithms",
        "summary": "Missing encryption in transit or at rest, weak algorithms or fixed keys can leak secrets or PII.",
        "action": "TLS 1.2+, strong ciphers; KMS and key rotation for stored data; never store secrets in plaintext.",
        "url": "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
    },
    {
        "id": "A05:2025",
        "name": "Injection",
        "desc": "SQL, XSS, Command Injection — 37 CWE mappings",
        "summary": "User input reflected in queries, commands, or output can lead to SQL/OS/code injection or XSS.",
        "action": "Use parameterized queries and prepared statements; input validation and escaping; output encoding; SAST/CodeQL.",
        "url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
    },
    {
        "id": "A06:2025",
        "name": "Insecure Design",
        "desc": "Design-phase security flaws — missing threat modeling and secure design patterns",
        "summary": "Missing threat modeling or security requirements at design can enable logic flaws and business logic bypass.",
        "action": "Perform threat modeling (e.g. STRIDE); security design review; safe defaults and fail-secure design.",
        "url": "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
    },
    {
        "id": "A07:2025",
        "name": "Authentication Failures",
        "desc": "MFA not enforced, weak passwords, session management flaws",
        "summary": "No MFA, weak password policy, or poor session invalidation can enable account takeover and privilege escalation.",
        "action": "Enforce MFA and SSO; strengthen password policy; session timeout, re-auth, and token invalidation.",
        "url": "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
    },
    {
        "id": "A08:2025",
        "name": "Software or Data Integrity Failures",
        "desc": "Integrity verification failures — CI/CD, auto-updates, deserialization",
        "summary": "Code applied without signature verification in CI/CD or auto-updates, or deserialization can lead to RCE.",
        "action": "Verify signatures and checksums; least-privilege deployment; webhook secret/signature verification; block untrusted deserialization.",
        "url": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    },
    {
        "id": "A09:2025",
        "name": "Security Logging & Alerting Failures",
        "desc": "Insufficient logging and alerting — hinders detection and response",
        "summary": "Lack of logs, audit trail, or alerts makes detection, response, and forensics difficult.",
        "action": "Collect auth, access, and change logs; integrate GuardDuty/Security Hub; define alerting and response procedures.",
        "url": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
    },
    {
        "id": "A10:2025",
        "name": "Mishandling of Exceptional Conditions",
        "desc": "Error handling and logic errors — 24 CWEs (new)",
        "summary": "Poor exception handling or boundary/logic errors can cause DoS, information disclosure, or unexpected behavior.",
        "action": "Consistent exception handling and user-friendly messages; logic and boundary checks; log detailed errors only.",
        "url": "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
    },
]

OWASP_CHECK_MAP = {
    "A01:2025": [
        "branch_protection",
        "require_pull_request",
        "require_approval",
        "default_branch_deletion",
        "admin_permission",
        "repository_private",
        "dismiss_stale_review",
        "iam",
        "access",
        "permission",
        "restrict",
        "cors",
        "force_push",
        "ssrf",
        "request_forgery",
    ],
    "A02:2025": [
        "configuration",
        "default",
        "misconfigur",
        "hardening",
        "baseline",
        "cis",
        "benchmark",
        "logging_enabled",
        "security_policy",
        "security_header",
        "xxe",
        "unnecessary",
        "enabled_feature",
    ],
    "A03:2025": [
        "dependency",
        "dependabot",
        "sbom",
        "slsa",
        "provenance",
        "supply_chain",
        "vulnerability_alert",
        "cve",
        "outdated",
        "vulnerable",
        "patch",
        "version",
        "eol",
        "deprecat",
        "immutable_release",
        "codeowners",
    ],
    "A04:2025": [
        "encrypt",
        "tls",
        "ssl",
        "certificate",
        "secret",
        "kms",
        "key_rotation",
        "plaintext",
        "https",
        "cryptograph",
        "weak_cipher",
        "rotation",
    ],
    "A05:2025": [
        "injection",
        "input",
        "sanitiz",
        "escap",
        "parameteriz",
        "codeql",
        "sast",
        "xss",
        "command_injection",
        "sql",
    ],
    "A06:2025": [
        "design",
        "architecture",
        "threat_model",
        "security_review",
        "insecure_design",
    ],
    "A07:2025": [
        "authentication",
        "mfa",
        "password",
        "credential",
        "session",
        "totp",
        "sso",
        "two_factor",
        "2fa",
        "login",
        "brute_force",
    ],
    "A08:2025": [
        "integrity",
        "signing",
        "webhook",
        "deploy_key",
        "signature",
        "cicd",
        "pipeline",
        "auto_update",
        "deserialization",
    ],
    "A09:2025": [
        "logging",
        "monitoring",
        "audit",
        "alert",
        "trace",
        "observ",
        "siem",
        "detection",
        "guardduty",
        "securityhub",
        "cloudtrail",
    ],
    "A10:2025": [
        "error",
        "exception",
        "handler",
        "unhandled",
        "crash",
        "panic",
        "overflow",
        "boundary",
        "validation_error",
        "logic_error",
    ],
}

# ── OWASP Top 10 for LLM Applications 2025 ──────────────────────────────────

OWASP_LLM_2025 = [
    {
        "id": "LLM01",
        "name": "Prompt Injection",
        "desc": "Malicious input causes LLM to perform unintended actions or leak data",
        "summary": "Adversarial instructions or delimiters can override system prompts and cause the LLM to leak secrets or misbehave.",
        "action": "Input validation and sanitization; privilege separation and output filtering; protect system prompt and audit logging.",
        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    },
    {
        "id": "LLM02",
        "name": "Sensitive Information Disclosure",
        "desc": "Secrets, PII, or confidential data in responses or logs",
        "summary": "LLM responses or logs may contain passwords, API keys, or PII and leak via third parties or log pipelines.",
        "action": "Mask responses and logs; minimize PII collection; use env vars or secret managers for secrets.",
        "url": "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    },
    {
        "id": "LLM03",
        "name": "Supply Chain",
        "desc": "Risks from model providers, datasets, dependencies, and infrastructure",
        "summary": "Unverified provenance of models, datasets, SDKs, or infra can introduce backdoors, malware, or licensing risk.",
        "action": "Use official or verified sources; checksum and signature verification; SBOM and license checks.",
        "url": "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
    },
    {
        "id": "LLM04",
        "name": "Data and Model Poisoning",
        "desc": "Poisoned training or fine-tuning data to manipulate behavior",
        "summary": "Tampered training or fine-tuning data can make the model learn bias, backdoors, or wrong answers.",
        "action": "Verify data provenance and quality; inspect data before fine-tuning; version and provenance tracking.",
        "url": "https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    },
    {
        "id": "LLM05",
        "name": "Improper Output Handling",
        "desc": "Trusting or executing model output without verification",
        "summary": "Executing LLM output as code, commands, or queries can lead to injection or privilege escalation.",
        "action": "Validate and whitelist output; human-in-the-loop and confirmation steps; sandbox and least-privilege execution.",
        "url": "https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    },
    {
        "id": "LLM06",
        "name": "Excessive Agency",
        "desc": "AI agents with excessive autonomy or permissions",
        "summary": "Agents with too much permission or autonomy can cause data loss, cost waste, or policy bypass.",
        "action": "Least privilege and scope limits; require user confirmation; set cost and call limits.",
        "url": "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    },
    {
        "id": "LLM07",
        "name": "System Prompt Leakage",
        "desc": "Extraction of hidden prompts, policy, or tool schemas",
        "summary": "Attackers can use special inputs to expose system prompt, policy, or tool schema in responses.",
        "action": "Isolate and protect prompts; filter output to remove internal instructions; regular red-team testing.",
        "url": "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    },
    {
        "id": "LLM08",
        "name": "Vector and Embedding Weaknesses",
        "desc": "RAG store or embeddings as attack surface",
        "summary": "Malicious or poisoned data in RAG or embedding DB can manipulate search results or leak information.",
        "action": "Validate RAG input and access control; verify embedding source trust; filter queries and results.",
        "url": "https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    },
    {
        "id": "LLM09",
        "name": "Misinformation",
        "desc": "Confidently generated false information causes harm",
        "summary": "Hallucination or manipulated training can lead to wrong decisions or reputation damage.",
        "action": "Show sources and confidence in output; fact-check and verification steps; inform users of uncertainty.",
        "url": "https://genai.owasp.org/llmrisk/llm09-misinformation/",
    },
    {
        "id": "LLM10",
        "name": "Unbounded Consumption",
        "desc": "Abuse leads to cost spike, latency, or capacity exhaustion",
        "summary": "Unlimited use of API, tokens, or resources can cause cost explosion, DoS, or service outage.",
        "action": "Rate limits and quotas; per-user and daily caps; detect and block anomalous traffic.",
        "url": "https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    },
]


def map_findings_to_owasp(all_findings):
    mapping = {o["id"]: [] for o in OWASP_2025}
    for f in all_findings:
        check = f["check"].lower()
        title = f["title"].lower()
        msg = f["message"].lower()
        text = f"{check} {title} {msg}"
        for oid, keywords in OWASP_CHECK_MAP.items():
            if any(kw in text for kw in keywords):
                mapping[oid].append(f)
                break
    return mapping


# ── Compliance Frameworks ────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = [
    {
        "name": "OWASP Top 10:2025",
        "url": "https://owasp.org/Top10/2025/",
        "desc": "Web application security risks Top 10 (2025)",
    },
    {
        "name": "OWASP LLM Top 10",
        "url": "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/",
        "desc": "LLM application security risks Top 10 (2025)",
    },
    {
        "name": "NIST 800-53 Rev5",
        "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "desc": "US federal information system security controls",
    },
    {
        "name": "NIST CSF 2.0",
        "url": "https://www.nist.gov/cyberframework",
        "desc": "Cybersecurity Framework 2.0",
    },
    {
        "name": "ISO 27001:2022",
        "url": "https://www.iso.org/isoiec-27001-information-security.html",
        "desc": "Information security management system (ISMS) international standard",
    },
    {
        "name": "ISO 27701:2025",
        "url": "https://www.iso.org/standard/85819.html",
        "desc": "Privacy information management (PIMS) — certifiable",
    },
    {
        "name": "PCI-DSS v4.0.1",
        "url": "https://www.pcisecuritystandards.org/document_library/?category=pcidss",
        "desc": "Payment Card Industry Data Security Standard",
    },
    {
        "name": "KISA ISMS-P",
        "url": "https://isms.kisa.or.kr/main/ispims/intro/",
        "desc": "Korea information security and privacy management certification",
    },
    {
        "name": "CIS Benchmarks",
        "url": "https://www.cisecurity.org/cis-benchmarks",
        "desc": "Center for Internet Security benchmarks",
    },
    {
        "name": "SLSA v1.0",
        "url": "https://slsa.dev/spec/v1.0/",
        "desc": "Supply chain Levels for Software Artifacts",
    },
    {
        "name": "MITRE ATT&CK",
        "url": "https://attack.mitre.org/",
        "desc": "Cyber attack tactics, techniques, and procedures (TTP) knowledge base",
    },
]

# Import compliance mapping from standalone module (shared with output.sh).
# Falls back to inline definitions below if the module is unavailable.
_COMPLIANCE_IMPORTED = False
try:
    import importlib.util as _ilu

    _cm_spec = _ilu.spec_from_file_location(
        "compliance_map",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "compliance-map.py"),
    )
    if _cm_spec and _cm_spec.loader:
        _cm_mod = _ilu.module_from_spec(_cm_spec)
        _cm_spec.loader.exec_module(_cm_mod)
        COMPLIANCE_CONTROL_MAP = _cm_mod.COMPLIANCE_CONTROL_MAP
        _COMPLIANCE_IMPORTED = True
except Exception:
    pass

if not _COMPLIANCE_IMPORTED:
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


if _COMPLIANCE_IMPORTED:
    from importlib import import_module as _im  # noqa: F401 (used above)

    _match_prowler_compliance = _cm_mod._match_prowler_compliance
    map_compliance = _cm_mod.map_compliance
else:

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
            if isinstance(val, (list, str)) and any(fk in str(v).lower() for v in (val if isinstance(val, list) else [val])):
                return True
        return False

    def map_compliance(all_findings):
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


# ── Scanner category metadata (used by _build_scanner_section) ───────────────

CATEGORY_META = {
    "access-control": {
        "icon": "🔑",
        "label": "Access control & IAM",
        "desc": "Checks for secret exposure, .env handling, auth tokens, cookie security.",
    },
    "infra": {
        "icon": "🏗️",
        "label": "Infrastructure",
        "desc": "Docker, Kubernetes, IaC security configuration.",
    },
    "network": {
        "icon": "🌐",
        "label": "Network security",
        "desc": "TLS/SSL, certificates, cipher suites.",
    },
    "cicd": {
        "icon": "⚙️",
        "label": "CI/CD pipeline",
        "desc": "GitHub Actions workflow permissions, secret exposure, dependency review.",
    },
    "code": {
        "icon": "💻",
        "label": "Code (SAST)",
        "desc": "Injection, XSS, hardcoded secrets and other code flaws.",
    },
    "ai": {
        "icon": "🤖",
        "label": "AI / LLM security",
        "desc": "Prompt injection, model config, API key protection.",
    },
    "cloud": {
        "icon": "☁️",
        "label": "Cloud (AWS/GCP/Azure)",
        "desc": "Cloud infra config, IAM policies, storage access.",
    },
    "macos": {
        "icon": "🍎",
        "label": "macOS / CIS benchmark",
        "desc": "FileVault, firewall, SIP, Gatekeeper per CIS.",
    },
    "saas": {
        "icon": "🔌",
        "label": "SaaS & solutions",
        "desc": "GitHub, Vercel, ArgoCD, Sentry and other SaaS security.",
    },
    "windows": {
        "icon": "🪟",
        "label": "Windows (KISA)",
        "desc": "Windows security policy and settings per KISA.",
    },
    "prowler": {
        "icon": "🔍",
        "label": "Prowler deep scan",
        "desc": "Prowler multi-cloud security scan results.",
    },
    "other": {"icon": "📋", "label": "Other", "desc": "Uncategorized security checks."},
}

__all__ = [
    "CHECK_EN_MAP",
    "DEFAULT_SUMMARY",
    "DEFAULT_ACTION",
    "get_check_en",
    "OWASP_2025",
    "OWASP_CHECK_MAP",
    "OWASP_LLM_2025",
    "map_findings_to_owasp",
    "COMPLIANCE_FRAMEWORKS",
    "COMPLIANCE_CONTROL_MAP",
    "_match_prowler_compliance",
    "map_compliance",
    "ARCH_DOMAINS",
    "ARCH_DOMAIN_LINKS",
    "OWASP_TO_ARCH",
    "map_architecture",
    "CATEGORY_META",
]
