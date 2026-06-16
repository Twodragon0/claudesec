#!/usr/bin/env bash
# =============================================================================
# ClaudeSec — sync-repo-protection.sh
#
# PURPOSE
#   Idempotent infrastructure-as-code script that codifies the desired branch-
#   protection and merge settings for the Twodragon0/claudesec repository.
#   Running this repeatedly is safe: it PUTs/PATCHes to the desired state.
#
# SAFE BY DEFAULT (DRY-RUN)
#   Without any flag (or with --dry-run) the script READS current settings,
#   prints a current-vs-desired diff, and exits non-zero if drift is detected.
#   NO writes are made in dry-run mode.
#
#   To actually apply the desired state:
#     ./scripts/sync-repo-protection.sh --apply
#
# USAGE
#   ./scripts/sync-repo-protection.sh [--dry-run | --apply]
#
#   --dry-run   (default) Read-only check; exit 1 if drift detected.
#   --apply     Apply the desired state via GitHub REST API.
#
# REQUIREMENTS
#   gh CLI authenticated with a token that has repo admin scope.
#
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# DESIRED STATE — single source of truth
# Change these variables, not the logic below, when policy changes.
# ---------------------------------------------------------------------------

REPO="Twodragon0/claudesec"
BRANCH="main"

# Required status checks ─────────────────────────────────────────────────────
# strict=true: PRs must be up-to-date with main before merge.
# "Lint" and "Security Scan Gate" are the two required CI jobs defined in
# .github/workflows/lint.yml (aggregator job pattern, #186).
DESIRED_STRICT="true"
DESIRED_CONTEXTS='["Lint","Security Scan Gate"]'

# Required pull-request reviews ──────────────────────────────────────────────
# require_code_owner_reviews=true: any path touched needs a CODEOWNERS match.
# required_approving_review_count=0: bot-only PRs (Dependabot, auto-merge) can
#   merge without a human approval count, relying solely on CODEOWNERS gating.
# dismiss_stale_reviews=false: avoids blocking auto-merge on trivial rebases.
# require_last_push_approval=false: last-push rule unnecessary given CODEOWNERS.
DESIRED_CODE_OWNER_REVIEWS="true"
DESIRED_APPROVING_COUNT="0"
DESIRED_DISMISS_STALE="false"
DESIRED_LAST_PUSH_APPROVAL="false"

# Admin enforcement ───────────────────────────────────────────────────────────
# enforce_admins=true: repo admins (including the owner) are NOT exempt from
# branch-protection rules.  Prevents accidental force-push to main by admins.
DESIRED_ENFORCE_ADMINS="true"

# Repo-level merge settings ───────────────────────────────────────────────────
# allow_auto_merge=true: lets Dependabot and bots auto-merge once CI is green.
# allow_squash_merge=true: standard merge method for PRs (clean history).
# delete_branch_on_merge=true: automatic branch cleanup after merge.
# allow_merge_commit=true / allow_rebase_merge=true: also enabled on the live
#   repo; codified here for full visibility even though not in the original spec.
DESIRED_AUTO_MERGE="true"
DESIRED_SQUASH_MERGE="true"
DESIRED_DELETE_BRANCH="true"
DESIRED_MERGE_COMMIT="true"
DESIRED_REBASE_MERGE="true"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MODE="dry-run"
case "${1:-}" in
  --apply)    MODE="apply" ;;
  --dry-run|"") MODE="dry-run" ;;
  -h|--help)
    sed -n '2,30p' "$0"
    exit 0
    ;;
  *)
    echo "Unknown flag: ${1}" >&2
    echo "Usage: $0 [--dry-run | --apply]" >&2
    exit 1
    ;;
esac

log()  { echo "[sync-repo-protection] $*"; }
err()  { echo "[sync-repo-protection] ERROR: $*" >&2; }

check_deps() {
  local missing=0
  for cmd in gh python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      err "Required command not found: $cmd"
      missing=1
    fi
  done
  if [[ "$missing" -eq 1 ]]; then
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Read current state
# ---------------------------------------------------------------------------

PROTECTION_JSON=""
REPO_JSON=""

read_current_state() {
  log "Reading current branch-protection settings for ${REPO}:${BRANCH}..."
  PROTECTION_JSON="$(gh api "repos/${REPO}/branches/${BRANCH}/protection")" || {
    err "Failed to read branch protection. Check gh auth and repo name."
    exit 1
  }

  log "Reading current repo merge settings for ${REPO}..."
  REPO_JSON="$(gh api "repos/${REPO}")" || {
    err "Failed to read repo settings."
    exit 1
  }
}

# ---------------------------------------------------------------------------
# Diff: compare current vs desired
# ---------------------------------------------------------------------------

DRIFT_REPORT=""
DRIFT_EXIT=0

compute_drift() {
  local pyout
  local pyexit=0
  pyout="$(python3 - \
    "${PROTECTION_JSON}" \
    "${REPO_JSON}" \
    "${DESIRED_STRICT}" \
    "${DESIRED_CONTEXTS}" \
    "${DESIRED_CODE_OWNER_REVIEWS}" \
    "${DESIRED_APPROVING_COUNT}" \
    "${DESIRED_DISMISS_STALE}" \
    "${DESIRED_LAST_PUSH_APPROVAL}" \
    "${DESIRED_ENFORCE_ADMINS}" \
    "${DESIRED_AUTO_MERGE}" \
    "${DESIRED_SQUASH_MERGE}" \
    "${DESIRED_DELETE_BRANCH}" \
    "${DESIRED_MERGE_COMMIT}" \
    "${DESIRED_REBASE_MERGE}" <<'PYEOF'
import json, sys

protection = json.loads(sys.argv[1])
repo       = json.loads(sys.argv[2])

desired = {
    "strict":                 sys.argv[3].lower() == "true",
    "contexts":               sorted(json.loads(sys.argv[4])),
    "require_code_owner":     sys.argv[5].lower() == "true",
    "approving_count":        int(sys.argv[6]),
    "dismiss_stale":          sys.argv[7].lower() == "true",
    "last_push_approval":     sys.argv[8].lower() == "true",
    "enforce_admins":         sys.argv[9].lower() == "true",
    "allow_auto_merge":       sys.argv[10].lower() == "true",
    "allow_squash_merge":     sys.argv[11].lower() == "true",
    "delete_branch_on_merge": sys.argv[12].lower() == "true",
    "allow_merge_commit":     sys.argv[13].lower() == "true",
    "allow_rebase_merge":     sys.argv[14].lower() == "true",
}

rsc = protection.get("required_status_checks", {})
rpr = protection.get("required_pull_request_reviews", {})
ea  = protection.get("enforce_admins", {})

current = {
    "strict":                 rsc.get("strict"),
    "contexts":               sorted(rsc.get("contexts", [])),
    "require_code_owner":     rpr.get("require_code_owner_reviews"),
    "approving_count":        rpr.get("required_approving_review_count"),
    "dismiss_stale":          rpr.get("dismiss_stale_reviews"),
    "last_push_approval":     rpr.get("require_last_push_approval"),
    "enforce_admins":         ea.get("enabled"),
    "allow_auto_merge":       repo.get("allow_auto_merge"),
    "allow_squash_merge":     repo.get("allow_squash_merge"),
    "delete_branch_on_merge": repo.get("delete_branch_on_merge"),
    "allow_merge_commit":     repo.get("allow_merge_commit"),
    "allow_rebase_merge":     repo.get("allow_rebase_merge"),
}

drifted = []
lines   = [""]
lines.append(f"  {'SETTING':<30}  {'DESIRED':<28}  {'CURRENT':<28}  STATUS")
lines.append("  " + "-" * 95)

for key in sorted(desired):
    d = desired[key]
    c = current.get(key)
    match = (d == c)
    status = "OK" if match else "DRIFT"
    if not match:
        drifted.append(key)
    lines.append(f"  {key:<30}  {str(d):<28}  {str(c):<28}  {status}")

lines.append("")
if drifted:
    lines.append(f"  DRIFT DETECTED in: {', '.join(drifted)}")
    lines.append("  Run with --apply to remediate.")
else:
    lines.append("  No drift detected -- settings match desired state.")

print("\n".join(lines))
sys.exit(1 if drifted else 0)
PYEOF
  )" || pyexit=$?
  DRIFT_REPORT="$pyout"
  DRIFT_EXIT="$pyexit"
}

print_drift_report() {
  echo "$DRIFT_REPORT"
}

# ---------------------------------------------------------------------------
# Apply desired state
# ---------------------------------------------------------------------------

apply_state() {
  log "Applying desired branch-protection to ${REPO}:${BRANCH}..."

  # Build checks array: [{"context":"Lint"},{"context":"Security Scan Gate"}]
  local checks_json
  checks_json="$(python3 -c "
import json, sys
ctxs = json.loads(sys.argv[1])
print(json.dumps([{'context': c} for c in ctxs]))
" "${DESIRED_CONTEXTS}")"

  # PUT branch protection — full body required; partial PUT wipes unspecified fields
  gh api \
    --method PUT \
    "repos/${REPO}/branches/${BRANCH}/protection" \
    --input - <<JSON
{
  "required_status_checks": {
    "strict": ${DESIRED_STRICT},
    "checks": ${checks_json}
  },
  "enforce_admins": ${DESIRED_ENFORCE_ADMINS},
  "required_pull_request_reviews": {
    "require_code_owner_reviews": ${DESIRED_CODE_OWNER_REVIEWS},
    "required_approving_review_count": ${DESIRED_APPROVING_COUNT},
    "dismiss_stale_reviews": ${DESIRED_DISMISS_STALE},
    "require_last_push_approval": ${DESIRED_LAST_PUSH_APPROVAL}
  },
  "restrictions": null
}
JSON
  log "Branch protection applied."

  log "Applying desired repo merge settings to ${REPO}..."
  gh api \
    --method PATCH \
    "repos/${REPO}" \
    --input - <<JSON
{
  "allow_auto_merge": ${DESIRED_AUTO_MERGE},
  "allow_squash_merge": ${DESIRED_SQUASH_MERGE},
  "delete_branch_on_merge": ${DESIRED_DELETE_BRANCH},
  "allow_merge_commit": ${DESIRED_MERGE_COMMIT},
  "allow_rebase_merge": ${DESIRED_REBASE_MERGE}
}
JSON
  log "Repo merge settings applied."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

check_deps
read_current_state
compute_drift

log "Mode: ${MODE}"
print_drift_report

if [[ "$MODE" == "apply" ]]; then
  if [[ "$DRIFT_EXIT" -eq 0 ]]; then
    log "No drift detected -- nothing to apply."
    exit 0
  fi
  apply_state
  log "Re-reading state to verify apply succeeded..."
  read_current_state
  compute_drift
  print_drift_report
  if [[ "$DRIFT_EXIT" -ne 0 ]]; then
    err "Drift remains after apply -- manual investigation required."
    exit 1
  fi
  log "Apply verified -- settings now match desired state."
  exit 0
else
  # dry-run: exit non-zero if drift detected
  exit "$DRIFT_EXIT"
fi
