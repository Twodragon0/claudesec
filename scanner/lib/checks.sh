#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Check helper library
# ============================================================================

# Check if a command exists
has_command() {
  command -v "$1" &>/dev/null
}

# Check if a file exists in the scan directory
has_file() {
  [[ -f "$SCAN_DIR/$1" ]]
}

# Check if a directory exists
has_dir() {
  [[ -d "$SCAN_DIR/$1" ]]
}

# Search for a pattern in files
file_contains() {
  local file="$1" pattern="$2"
  [[ -f "$SCAN_DIR/$file" ]] && grep -qE "$pattern" "$SCAN_DIR/$file" 2>/dev/null
}

# Search for pattern across files matching a glob
files_contain() {
  local glob="$1" pattern="$2"
  find "$SCAN_DIR" -name "$glob" -not -path "*/node_modules/*" -not -path "*/.git/*" \
    -exec grep -lE "$pattern" {} \; 2>/dev/null | head -1 | grep -q .
}

# Count files matching a pattern
count_files() {
  local glob="$1"
  find "$SCAN_DIR" -name "$glob" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null | wc -l | tr -d ' '
}

# Check if running in a git repo
is_git_repo() {
  git -C "$SCAN_DIR" rev-parse --is-inside-work-tree &>/dev/null
}

# Get git remote URL
git_remote_url() {
  git -C "$SCAN_DIR" remote get-url origin 2>/dev/null || echo ""
}

# Check AWS credentials availability
has_aws_credentials() {
  has_command aws && aws sts get-caller-identity &>/dev/null
}

# Check GCP credentials
has_gcp_credentials() {
  has_command gcloud && gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q .
}

# Check Azure credentials
has_azure_credentials() {
  has_command az && az account show &>/dev/null
}

# Check kubectl access
has_kubectl_access() {
  has_command kubectl && kubectl cluster-info &>/dev/null
}

# Map check ID to compliance frameworks
compliance_map() {
  local id="$1"
  # Returns compliance mappings for a check ID
  # Format: "NIST:AC-2|ISO:A.9.2|ISMS-P:2.5.1|SOC2:CC6.1"
  case "$id" in
    IAM-*) echo "NIST:AC-2,IA-2|ISO:A.9|ISMS-P:2.5|SOC2:CC6.1" ;;
    NET-*) echo "NIST:SC-7,SC-8|ISO:A.13|ISMS-P:2.6|SOC2:CC6.6" ;;
    CLOUD-*) echo "NIST:CM-6,AC-3|ISO:A.12,A.14|ISMS-P:2.10|SOC2:CC6.1" ;;
    CICD-*) echo "NIST:SA-11,CM-2|ISO:A.14|ISMS-P:2.9|SOC2:CC8.1" ;;
    AI-*) echo "NIST-AI:MAP,MEASURE|ISO42001:6,7|ISMS-P:2.9" ;;
    INFRA-*) echo "NIST:CM-6,CM-7|ISO:A.12,A.14|ISMS-P:2.10|SOC2:CC6.6" ;;
    *) echo "" ;;
  esac
}
