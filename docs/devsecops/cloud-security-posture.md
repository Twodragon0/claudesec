---
title: Cloud Security Posture Management (CSPM)
description: Cloud security with Prowler, compliance frameworks, and posture management
tags: [cspm, prowler, cloud-security, aws, azure, gcp, compliance]
---

# Cloud Security Posture Management (CSPM)

## CNAPP Taxonomy

```
CNAPP (Cloud-Native Application Protection Platform)
├── CSPM  — Configuration and compliance posture
├── CWPP  — Workload protection (VMs, containers, serverless)
├── CIEM  — Cloud identity and entitlement management
└── KSPM  — Kubernetes-specific posture management
```

---

## Prowler — Open Source CSPM

[prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) — 13k+ stars, the most widely used open-source cloud security platform.

### Coverage

| Provider | Checks | Services |
|----------|--------|----------|
| AWS | 572 | 83 |
| Azure | 165 | 20 |
| GCP | 100 | 13 |
| Kubernetes | 83 | 7 |
| GitHub | Available | Repo/org security |

### Quick Start

```bash
# Install
pip install prowler

# AWS — full scan with CIS compliance
prowler aws --compliance cis_2.0_aws

# AWS — critical/high findings only
prowler aws --severity critical high --output-formats json

# Azure — specific services
prowler azure --service iam keyvault storage

# GCP — with HTML report
prowler gcp --output-formats html json

# Kubernetes — cluster security
prowler kubernetes

# GitHub — repository security
prowler github \
  --personal-access-token "$GITHUB_TOKEN" \
  --repository "myorg/myrepo"
```

### CI/CD Integration

{% raw %}
```yaml
# .github/workflows/prowler.yml
name: Cloud Security Scan
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  id-token: write

jobs:
  prowler:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-arn: arn:aws:iam::${{ secrets.AWS_ACCOUNT_ID }}:role/prowler-role
          aws-region: us-east-1

      - name: Validate IAM Identity Center list permissions
        env:
          STRICT_SSO: ${{ vars.CLAUDESEC_STRICT_SSO || '1' }}
        run: |
          INSTANCE_ARN=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text)
          aws sso-admin list-permission-sets --instance-arn "$INSTANCE_ARN" --max-results 1 >/dev/null

      - name: Run Prowler
        env:
          CI: "true"
          CLAUDESEC_CI: 1
        run: |
          pip install prowler
          prowler aws \
            --severity critical high \
            --compliance cis_2.0_aws \
            --output-formats json-ocsf csv html

      - name: Collect Datadog logs (optional)
        if: ${{ secrets.DD_API_KEY != '' && secrets.DD_APP_KEY != '' }}
        env:
          DD_SERVICE: prowler
          DD_ENV: ci
          CI_PIPELINE_ID: ${{ github.run_id }}
          DD_TAGS: service:prowler,env:ci,ci_pipeline_id:${{ github.run_id }}
        run: |
          mkdir -p .claudesec-datadog
          curl -sS -X POST "https://http-intake.logs.datadoghq.com/v1/input?ddtags=${DD_TAGS}" \
            -H "Content-Type: application/json" \
            -H "DD-API-KEY: ${{ secrets.DD_API_KEY }}" \
            -d "{\"message\":\"ClaudeSec Prowler CI workflow run\",\"service\":\"${DD_SERVICE}\",\"env\":\"${DD_ENV}\",\"ci_pipeline_id\":\"${CI_PIPELINE_ID}\",\"status\":\"info\",\"source\":\"claudesec-ci\"}" >/dev/null
          DD_QUERY="service:${DD_SERVICE} env:${DD_ENV} ci_pipeline_id:${CI_PIPELINE_ID}"
          curl -sS -X POST "https://api.datadoghq.com/api/v2/logs/events/search" \
            -H "Content-Type: application/json" \
            -H "DD-API-KEY: ${{ secrets.DD_API_KEY }}" \
            -H "DD-APPLICATION-KEY: ${{ secrets.DD_APP_KEY }}" \
            -d "{\"filter\":{\"from\":\"now-1h\",\"to\":\"now\",\"query\":\"${DD_QUERY}\"},\"sort\":\"timestamp\",\"page\":{\"limit\":200}}" \
            > .claudesec-datadog/datadog-logs.json

      - name: Sanitize Datadog log artifact
        if: ${{ secrets.DD_API_KEY != '' && secrets.DD_APP_KEY != '' }}
        run: |
          python3 - <<'PY'
          import json
          import re
          src = ".claudesec-datadog/datadog-logs.json"
          dst = ".claudesec-datadog/datadog-logs-sanitized.json"
          with open(src, "r", encoding="utf-8") as f:
            data = f.read()
          data = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<redacted-email>", data)
          data = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<redacted-ip>", data)
          data = re.sub(r"\b\d{12}\b", "<redacted-account-id>", data)
          with open(dst, "w", encoding="utf-8") as f:
            f.write(data)
          PY
          rm -f .claudesec-datadog/datadog-logs.json

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: prowler-report
          path: |
            output/
            .claudesec-datadog/datadog-logs-sanitized.json

      - name: Fail on critical findings
        run: |
          CRITICAL=$(jq '[.[] | select(.StatusExtended == "FAIL" and .Severity == "critical")] | length' output/*.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Found $CRITICAL critical findings"
            exit 1
          fi
```
{% endraw %}

### Compliance Frameworks (41+)

| Category | Frameworks |
|----------|-----------|
| Industry | CIS Benchmarks (AWS/Azure/GCP/GitHub), NIST 800-53, NIST CSF, MITRE ATT&CK |
| Regulatory | PCI-DSS, FedRAMP, NIS2, CISA |
| Privacy | GDPR, HIPAA, FFIEC, GXP |
| Governance | SOC2, ISO 27001, **KISA ISMS-P** |
| Cloud-native | AWS Well-Architected, AWS FTR, BSI C5 |

### Output Formats

| Format | Use Case |
|--------|----------|
| JSON-OCSF | SIEM integration (Splunk, OpenSearch) |
| JSON-ASFF | AWS Security Hub |
| CSV | Spreadsheet analysis |
| HTML | Human-readable reports |

---

## Cloud Security Checklist

### Identity & Access (CIEM)

- [ ] No root/owner account for daily operations
- [ ] MFA enabled for all human users
- [ ] Service accounts use short-lived credentials (OIDC, workload identity)
- [ ] IAM policies follow least privilege
- [ ] No wildcard (`*`) permissions on critical services
- [ ] Unused credentials/roles cleaned up (90-day rule)
- [ ] Cross-account access reviewed and justified

### Network

- [ ] Default VPC deleted or unused
- [ ] Security groups deny all inbound by default
- [ ] No 0.0.0.0/0 on SSH (port 22) or RDP (port 3389)
- [ ] VPC Flow Logs enabled
- [ ] Private subnets for databases and internal services
- [ ] WAF in front of public endpoints

### Storage

- [ ] No public S3 buckets / Blob containers / GCS buckets
- [ ] Encryption at rest enabled (KMS-managed keys)
- [ ] Versioning enabled for critical data
- [ ] Lifecycle policies for data retention
- [ ] Access logging enabled

### Compute

- [ ] AMIs/images from trusted sources only
- [ ] SSM/OS Login instead of direct SSH
- [ ] Auto-patching enabled
- [ ] IMDSv2 enforced (AWS EC2)
- [ ] No public IPs on non-edge instances

### Logging & Monitoring

- [ ] CloudTrail / Activity Log / Audit Logs enabled in all regions
- [ ] Log integrity validation enabled
- [ ] Alerts on root account usage
- [ ] Alerts on IAM policy changes
- [ ] Alerts on security group changes
- [ ] Centralized log aggregation (90+ day retention)

---

## Multi-Cloud Security Comparison

| Control | AWS | Azure | GCP |
|---------|-----|-------|-----|
| CSPM | Security Hub + Prowler | Defender for Cloud | Security Command Center |
| Identity | IAM + Organizations | Entra ID + PIM | Cloud IAM + Organization |
| Secrets | Secrets Manager | Key Vault | Secret Manager |
| WAF | AWS WAF | Azure WAF | Cloud Armor |
| Encryption | KMS | Key Vault | Cloud KMS |
| Logging | CloudTrail | Activity Log | Audit Logs |
| Compliance | Audit Manager | Compliance Manager | Compliance Reports |

---

## Infrastructure as Code Security

Scan IaC before deployment to prevent misconfigurations.

| Tool | Supported IaC | Integration |
|------|---------------|-------------|
| **Checkov** (Bridgecrew) | Terraform, CloudFormation, K8s, Dockerfile | CLI, CI, IDE |
| **tfsec** (Aqua) | Terraform | CLI, CI, GitHub Action |
| **KICS** (Checkmarx) | Multi-IaC (15+ platforms) | CLI, CI |
| **Prowler** | AWS/Azure/GCP runtime | CLI, CI |

```bash
# Checkov — scan Terraform
checkov -d terraform/ --framework terraform --check HIGH,CRITICAL

# tfsec — Terraform-specific
tfsec terraform/ --minimum-severity HIGH
```

## References

- [Prowler Documentation — docs.prowler.com](https://docs.prowler.com)
- [Prowler GitHub — prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
- [CIS Benchmarks — cisecurity.org](https://www.cisecurity.org/cis-benchmarks)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [Azure Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Checkov — bridgecrew.io](https://www.checkov.io/)
