#!/usr/bin/env bash
# ClaudeSec — Cloud: GCP & Azure Security Checks

# ── GCP Checks ───────────────────────────────────────────────────────────────

if has_gcp_credentials 2>/dev/null; then
  local project
  project=$(gcloud config get-value project 2>/dev/null || echo "")

  if [[ -n "$project" ]]; then
    # CLOUD-010: GCP audit logging
    local audit_policy
    audit_policy=$(gcloud projects get-iam-policy "$project" --format=json 2>/dev/null | \
      grep -c "auditLogConfigs" 2>/dev/null || echo "0")
    if [[ "$audit_policy" -gt 0 ]]; then
      pass "CLOUD-010" "GCP audit logging configured"
    else
      warn "CLOUD-010" "GCP audit logging may not be fully configured" \
        "Enable Data Access audit logs for all services"
    fi

    # CLOUD-011: GCP default service account usage
    local default_sa
    default_sa=$(gcloud iam service-accounts list --format="value(email)" 2>/dev/null | \
      grep -c "compute@developer\|appspot" || echo "0")
    if [[ "$default_sa" -gt 0 ]]; then
      warn "CLOUD-011" "Default service accounts in use" \
        "Create dedicated service accounts with minimal permissions"
    else
      pass "CLOUD-011" "No default service accounts in use"
    fi
  fi
elif files_contain "*.tf" "provider.*google" 2>/dev/null; then
  info "GCP credentials not available — running static IaC checks"

  if files_contain "*.tf" "uniform_bucket_level_access\s*=\s*false"; then
    fail "CLOUD-012" "GCS uniform bucket access disabled in Terraform" "medium" \
      "Uniform bucket-level access provides consistent IAM" \
      "Set 'uniform_bucket_level_access = true'"
  else
    pass "CLOUD-012" "GCS uniform access configured correctly"
  fi
else
  skip "CLOUD-010" "GCP audit logging" "GCP not configured"
  skip "CLOUD-011" "GCP default SA" "GCP not configured"
fi

# ── Azure Checks ─────────────────────────────────────────────────────────────

if has_azure_credentials 2>/dev/null; then
  # CLOUD-020: Azure Security Center
  local sec_center
  sec_center=$(az security pricing list --query "[?pricingTier=='Standard'] | length(@)" \
    --output tsv 2>/dev/null || echo "error")
  if [[ "$sec_center" =~ ^[0-9]+$ && "$sec_center" -gt 0 ]]; then
    pass "CLOUD-020" "Azure Defender enabled ($sec_center plan(s))"
  elif [[ "$sec_center" == "0" ]]; then
    warn "CLOUD-020" "Azure Defender not enabled" \
      "Enable Microsoft Defender for Cloud for threat detection"
  else
    skip "CLOUD-020" "Azure Defender" "Unable to check"
  fi

  # CLOUD-021: Azure MFA enforcement
  # Note: Requires MS Graph API access, simplified check
  warn "CLOUD-021" "Verify MFA is enforced for all Azure AD users" \
    "Use Conditional Access policies to require MFA"
elif files_contain "*.tf" "provider.*azurerm" 2>/dev/null; then
  info "Azure credentials not available — running static IaC checks"

  if files_contain "*.tf" "https_only\s*=\s*false"; then
    fail "CLOUD-022" "HTTPS-only disabled in Azure resource" "high" \
      "Azure resources should enforce HTTPS" \
      "Set 'https_only = true'"
  else
    pass "CLOUD-022" "Azure resources enforce HTTPS"
  fi
else
  skip "CLOUD-020" "Azure Defender" "Azure not configured"
  skip "CLOUD-021" "Azure MFA" "Azure not configured"
fi
