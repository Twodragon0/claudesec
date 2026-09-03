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
# require_code_owner_reviews=FALSE, and this is the deliberate value.
#
# With required_approving_review_count=0, the ONLY thing code-owner review
# enforced was a manual approval on PRs not authored by the sole code owner —
# i.e. Dependabot's. Measured across all 16 Dependabot PRs: every merged one
# carries a `Twodragon0` APPROVED review, and #388 (the one without) sat
# `BLOCKED` with 22/22 checks green, zero conflicts and `mergeable: MERGEABLE`
# until it was closed and reapplied by hand as #400. Meanwhile the owner's own
# PRs merge with no review at all (#398, #400 — `reviewDecision` is empty on
# both, because the count is 0), so the setting bought no review that was not
# already optional.
#
# What still gates a merge, unchanged: the two required contexts below (Lint,
# Security Scan Gate), strict up-to-date-branch, enforce_admins, and the
# `test_ci_*` config-regression guard suite.
#
# What this does NOT open up: an outside contributor's PR comes from a fork and
# nobody but a write-holder can merge it, and `dependabot-auto-merge.yml`'s fork
# guard (`head.repo.full_name == github.repository`) keeps a fork PR from ever
# being auto-armed. CODEOWNERS itself stays in place and still auto-requests the
# owner as a reviewer — it just no longer BLOCKS.
#
# Revisit trigger: the moment a second person gets write access, this should go
# back to "true" with a non-zero approving count. A lone maintainer approving
# their own work is theatre; two people reviewing each other is not.
#
# required_approving_review_count=0: no numeric approval requirement.
# dismiss_stale_reviews=false: avoids blocking auto-merge on trivial rebases.
# require_last_push_approval=false: no approval to dismiss, so the rule is moot.
DESIRED_CODE_OWNER_REVIEWS="false"
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
warn() { echo "[sync-repo-protection] WARNING: $*" >&2; }

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
COLLABORATORS_JSON="[]"

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

  # Read for the review PRECONDITION check below, not to configure anything.
  # DESIRED_APPROVING_COUNT=0 is only defensible while there is exactly one
  # person who could review; the comment above records that as a revisit
  # trigger, and prose does not fire. Failing to read it is reported as
  # "unknown" rather than assumed fine — an unread precondition is not a met one.
  log "Reading collaborators for ${REPO} (review-precondition check)..."
  COLLABORATORS_JSON="$(gh api "repos/${REPO}/collaborators" --paginate)" || {
    warn "Failed to read collaborators — the review precondition cannot be checked."
    COLLABORATORS_JSON="null"
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
  pyout="$(COLLABORATORS_JSON="${COLLABORATORS_JSON}" python3 - \
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
import json, os, sys

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

# ---------------------------------------------------------------------------
# Review PRECONDITION -- reported separately because --apply cannot fix it.
#
# `approving_count = 0` is deliberate and is documented above with a revisit
# trigger: "the moment a second person gets write access, this should go back to
# true with a non-zero approving count." That trigger lived only in prose, so
# nothing would ever fire it. This is the mechanism.
#
# It is NOT folded into `drifted`: the live settings match the codified desire,
# so calling it drift would be false, and the "Run with --apply" line would be
# advice that cannot work. What changed is the WORLD the desire was chosen for.
#
# Counted by push access, not membership, so a read-only or bot collaborator
# does not trip it.
precondition_failed = False
raw = os.environ.get("COLLABORATORS_JSON", "null")
try:
    collaborators = json.loads(raw)
except ValueError:
    collaborators = None

if desired["approving_count"] == 0:
    lines.append("")
    if collaborators is None:
        lines.append("  REVIEW PRECONDITION: UNKNOWN -- collaborator list could not be read.")
        lines.append("  approving_count=0 assumes a single reviewer; that was not verified.")
        precondition_failed = True
    else:
        pushers = sorted(
            c.get("login", "?") for c in collaborators
            if (c.get("permissions") or {}).get("push")
        )
        if len(pushers) > 1:
            lines.append(f"  REVIEW PRECONDITION FAILED: {len(pushers)} collaborators have push: {', '.join(pushers)}")
            lines.append("  approving_count=0 was chosen because a lone maintainer approving their")
            lines.append("  own work is theatre. That is no longer the situation.")
            lines.append("  DECIDE: raise DESIRED_APPROVING_COUNT (and likely DESIRED_CODE_OWNER_REVIEWS)")
            lines.append("  in this script, or record why 0 is still right. --apply cannot fix this.")
            precondition_failed = True
        else:
            who = pushers[0] if pushers else "<none>"
            lines.append(f"  Review precondition OK: 1 collaborator with push ({who}); approving_count=0 stands.")

print("\n".join(lines))
sys.exit(1 if (drifted or precondition_failed) else 0)
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
