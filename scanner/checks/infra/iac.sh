#!/usr/bin/env bash
# ClaudeSec — Infrastructure: IaC Security Checks

# INFRA-020: Terraform — no hardcoded secrets
if has_dir "terraform" || files_contain "*.tf" "resource\s+" 2>/dev/null; then
  if files_contain "*.tf" "(password|secret|api_key|token)\s*=\s*\"[^\"]+\""; then
    fail "INFRA-020" "Hardcoded secrets in Terraform files" "critical" \
      "Secrets in .tf files are stored in plaintext state" \
      "Use variables with sensitive=true or a secrets manager"
  else
    pass "INFRA-020" "No hardcoded secrets in Terraform"
  fi

  # INFRA-021: Terraform state not in repo
  if has_file "terraform.tfstate" || has_file "*.tfstate"; then
    fail "INFRA-021" "Terraform state file in repository" "critical" \
      "State files contain sensitive data and should be stored remotely" \
      "Use remote backend (S3, GCS) and add *.tfstate to .gitignore"
  else
    pass "INFRA-021" "Terraform state not stored in repository"
  fi

  # INFRA-022: Terraform lock file
  if has_file ".terraform.lock.hcl"; then
    pass "INFRA-022" "Terraform dependency lock file exists"
  else
    warn "INFRA-022" "Missing .terraform.lock.hcl" \
      "Lock file ensures reproducible provider versions"
  fi
else
  skip "INFRA-020" "Terraform secrets" "No Terraform files found"
  skip "INFRA-021" "Terraform state" "No Terraform files found"
  skip "INFRA-022" "Terraform lock" "No Terraform files found"
fi

# INFRA-023: Helm charts — no default passwords
if has_dir "charts" || files_contain "Chart.yaml" "apiVersion" 2>/dev/null; then
  if files_contain "values.yaml" "(password|secret):\s*\"(admin|password|default|changeme)\""; then
    fail "INFRA-023" "Default passwords in Helm values" "critical" \
      "Default credentials in values.yaml" \
      "Use sealed-secrets or external secrets operator"
  else
    pass "INFRA-023" "No default passwords in Helm values"
  fi
else
  skip "INFRA-023" "Helm chart security" "No Helm charts found"
fi
