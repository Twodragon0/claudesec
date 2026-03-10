#!/usr/bin/env bash
# ClaudeSec — Cloud: AWS Security Checks

if has_aws_credentials 2>/dev/null; then
  # CLOUD-001: Root account MFA
  root_mfa=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text 2>/dev/null || echo "error")
  if [[ "$root_mfa" == "1" ]]; then
    pass "CLOUD-001" "AWS root account MFA enabled"
  elif [[ "$root_mfa" == "0" ]]; then
    fail "CLOUD-001" "AWS root account MFA not enabled" "critical" \
      "Root account without MFA is a critical security risk" \
      "Enable MFA on the root account immediately"
  else
    skip "CLOUD-001" "AWS root MFA" "Unable to check (insufficient permissions)"
  fi

  # CLOUD-002: CloudTrail enabled
  trail_count=$(aws cloudtrail describe-trails --query 'trailList | length(@)' --output text 2>/dev/null || echo "0")
  if [[ "$trail_count" -gt 0 ]]; then
    pass "CLOUD-002" "AWS CloudTrail enabled ($trail_count trail(s))"
  else
    fail "CLOUD-002" "AWS CloudTrail not configured" "critical" \
      "Without CloudTrail, API activity is not audited" \
      "Enable CloudTrail in all regions"
  fi

  # CLOUD-003: S3 public access block
  s3_block=$(aws s3control get-public-access-block \
    --account-id "$(aws sts get-caller-identity --query Account --output text 2>/dev/null)" \
    --query 'PublicAccessBlockConfiguration.BlockPublicAcls' --output text 2>/dev/null || echo "error")
  if [[ "$s3_block" == "True" ]]; then
    pass "CLOUD-003" "S3 account-level public access block enabled"
  elif [[ "$s3_block" == "False" ]]; then
    fail "CLOUD-003" "S3 public access block not enabled" "high" \
      "Buckets can be made public without account-level protection" \
      "Enable S3 Block Public Access at account level"
  else
    skip "CLOUD-003" "S3 public access block" "Unable to check"
  fi

  # CLOUD-004: Default VPC usage
  default_vpcs=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
    --query 'Vpcs | length(@)' --output text 2>/dev/null || echo "0")
  if [[ "$default_vpcs" -gt 0 ]]; then
    warn "CLOUD-004" "Default VPC exists" \
      "Default VPCs have permissive security groups. Consider removing or restricting."
  else
    pass "CLOUD-004" "No default VPC found"
  fi

  # CLOUD-005: IMDSv2 enforcement
  imdsv1_instances=$(aws ec2 describe-instances \
    --query 'Reservations[].Instances[?MetadataOptions.HttpTokens==`optional`] | length(@)' \
    --output text 2>/dev/null || echo "error")
  if [[ "$imdsv1_instances" == "0" ]]; then
    pass "CLOUD-005" "All EC2 instances enforce IMDSv2"
  elif [[ "$imdsv1_instances" =~ ^[0-9]+$ ]]; then
    fail "CLOUD-005" "$imdsv1_instances EC2 instance(s) allow IMDSv1" "high" \
      "IMDSv1 is vulnerable to SSRF-based credential theft" \
      "Set HttpTokens=required for all instances"
  else
    skip "CLOUD-005" "EC2 IMDSv2" "Unable to check"
  fi

elif files_contain "*.tf" "provider.*aws" 2>/dev/null; then
  # Static IaC checks when AWS creds not available
  info "AWS credentials not available — running static IaC checks only"

  if files_contain "*.tf" "acl.*public"; then
    fail "CLOUD-006" "Public ACL in Terraform S3 configuration" "high" \
      "S3 bucket with public ACL detected" \
      "Remove 'acl = \"public-read\"' and use bucket policies"
  else
    pass "CLOUD-006" "No public S3 ACLs in Terraform"
  fi

  if files_contain "*.tf" "encrypted\s*=\s*false"; then
    fail "CLOUD-007" "Encryption disabled in Terraform resource" "high" \
      "Storage resources should always be encrypted" \
      "Set 'encrypted = true' or use KMS keys"
  else
    pass "CLOUD-007" "No unencrypted resources in Terraform"
  fi
else
  skip "CLOUD-001" "AWS root MFA" "AWS not configured"
  skip "CLOUD-002" "AWS CloudTrail" "AWS not configured"
  skip "CLOUD-003" "S3 public block" "AWS not configured"
  skip "CLOUD-004" "Default VPC" "AWS not configured"
  skip "CLOUD-005" "EC2 IMDSv2" "AWS not configured"
fi
