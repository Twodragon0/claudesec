#!/usr/bin/env bash
# ClaudeSec — CI/CD: Execution Freshness Checks
#
# WHY THIS FILE IS SEPARATE FROM pipeline.sh
# Every check in pipeline.sh (CICD-001..008) greps static files: does a workflow
# declare `permissions:`, is a SAST tool named somewhere. That axis answers "is
# the control DECLARED" and is blind to "is the control RUNNING".
#
# The blind spot is not hypothetical, and all three shapes look identical:
#   - a deploy workflow whose manifest path drifted fails on every `main` push.
#     The workflow file still reads perfectly, so the static axis scores it 100.
#   - a dependency-submission job that breaks on a runtime incompatibility stops
#     reporting, and the alert count drops to zero.
#   - access logs turned off produce "zero anomalies observed".
# In all three, A TRUE ZERO AND A FAILED PRODUCTION ARE THE SAME PIXELS. The one
# piece of evidence that separates them is the LAST SUCCESSFUL RUN TIME, not a
# count — a count just relocates the ambiguity onto how you read its zero.
#
# So these checks read run history from the GitHub API rather than the file tree.
# Every one of them is `skip` when that history cannot be read (no `gh`, not
# authenticated, not a GitHub remote, or insufficient scope): an unanswerable
# question must not be scored as either a pass or a fail.

# Maximum age of the newest successful security-scan run before CICD-011 fails.
# Conservative on purpose: scan and dependency-submission workflows are normally
# scheduled daily or on every push, so a week of silence is already an outage,
# not a quiet period. Override with CLAUDESEC_CICD_SCAN_MAX_AGE_DAYS.
CICD_FRESHNESS_SCAN_MAX_AGE_DAYS="${CLAUDESEC_CICD_SCAN_MAX_AGE_DAYS:-7}"

# How many runs of one workflow to read when looking back for the last success.
# Bounds both the API page size and the work done per workflow.
CICD_FRESHNESS_RUN_HISTORY_LIMIT=50

# Timeout for each `gh` round-trip. The scanner must not hang on a slow or
# unreachable API; a timed-out call yields empty output and degrades to `skip`.
CICD_FRESHNESS_API_TIMEOUT_SEC=15

# Workflow-name patterns. Matched case-insensitively against the workflow file
# name, which is the only workflow identity available without a second API call.
CICD_FRESHNESS_DEPLOY_PATTERN='deploy|release|publish|rollout|promote|(^|[-_.])cd([-_.]|$)'
CICD_FRESHNESS_SCAN_PATTERN='codeql|semgrep|snyk|trivy|gitleaks|sast|sca|depend|scan|audit|security'

# Run conclusions that count as an accumulating failure. `cancelled` and `skipped`
# are deliberately excluded — neither means the pipeline is broken — and an
# in-progress run has an empty conclusion, so it is ignored too.
CICD_FRESHNESS_FAILED_CONCLUSIONS='failure|timed_out|startup_failure'

# ── Helpers ──────────────────────────────────────────────────────────────────

# owner/repo parsed from the git remote, or "" when the remote is not GitHub.
# Mirrors the extraction already used by checks/saas/api-checks.sh.
_cicd_freshness_repo_slug() {
  local remote slug
  remote=$(git_remote_url)
  if [[ "$remote" =~ github\.com[:/]([^/]+/[^/.]+) ]]; then
    slug="${BASH_REMATCH[1]}"
    echo "${slug%.git}"
  else
    echo ""
  fi
}

# True only when run history is actually readable: `gh` installed, a git repo,
# a GitHub remote, and an authenticated session. Any missing piece means the
# checks below cannot observe anything and must skip rather than guess.
#
# Not has_github_credentials(): that helper is satisfied by a bare GH_TOKEN in
# the environment, but every call below shells out to `gh`, so the binary is a
# hard requirement here. The auth probe is the same exit-code test that helper
# uses — `gh auth status` exits non-zero when logged out, so its output is never
# parsed and never has to be kept out of the suppressed stderr stream.
_cicd_freshness_gh_ready() {
  has_command gh || return 1
  is_git_repo || return 1
  [[ -n "$(_cicd_freshness_repo_slug)" ]] || return 1
  run_with_timeout "$CICD_FRESHNESS_API_TIMEOUT_SEC" gh auth status >/dev/null 2>&1
}

# Workflow file names under .github/workflows whose name matches $1.
_cicd_freshness_workflows() {
  local pattern="$1" path base
  [[ -d "$SCAN_DIR/.github/workflows" ]] || return 0
  for path in "$SCAN_DIR"/.github/workflows/*.yml "$SCAN_DIR"/.github/workflows/*.yaml; do
    [[ -f "$path" ]] || continue
    base=$(basename "$path")
    if echo "$base" | grep -qEi "$pattern"; then
      echo "$base"
    fi
  done
}

# "<conclusion>\t<updatedAt>" per run of workflow $2 on branch $3, newest first.
_cicd_freshness_runs() {
  local slug="$1" workflow="$2" branch="$3"
  run_with_timeout "$CICD_FRESHNESS_API_TIMEOUT_SEC" \
    gh run list --repo "$slug" --workflow "$workflow" --branch "$branch" \
      --limit "$CICD_FRESHNESS_RUN_HISTORY_LIMIT" \
      --json conclusion,updatedAt \
      --jq '.[] | [.conclusion, .updatedAt] | @tsv' 2>/dev/null || echo ""
}

# Epoch seconds for an ISO-8601 UTC timestamp; empty when unparseable.
# GNU date takes -d, BSD/macOS date takes -j -f; try both rather than assume.
_cicd_freshness_epoch() {
  local iso="$1"
  [[ -n "$iso" ]] || return 0
  date -u -d "$iso" +%s 2>/dev/null && return 0
  date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$iso" +%s 2>/dev/null && return 0
  return 0
}

# ── Preconditions ────────────────────────────────────────────────────────────

_cf_ready=0
_cf_slug=""
_cf_branch=""
_cf_skip_reason="GitHub run history not readable (gh CLI missing, not authenticated, or not a GitHub repository)"

if _cicd_freshness_gh_ready; then
  _cf_slug=$(_cicd_freshness_repo_slug)
  _cf_branch=$(run_with_timeout "$CICD_FRESHNESS_API_TIMEOUT_SEC" \
    gh api "repos/${_cf_slug}" --jq '.default_branch' 2>/dev/null || echo "")
  if [[ -n "$_cf_branch" ]]; then
    _cf_ready=1
  else
    _cf_skip_reason="Unable to resolve the default branch for ${_cf_slug}"
  fi
fi

# CICD-011's verdict gates CICD-012, so it is tracked explicitly rather than
# re-derived. 0 means "freshness not established", which includes the skip case.
_cf_scan_fresh=0

# ── CICD-010: Deployment path liveness ───────────────────────────────────────
# Failures piling up after the last success means `main` cannot ship. A repo in
# that state has no working remediation path, which is why this is `high` even
# though nothing in the workflow file is wrong.

if [[ "$_cf_ready" -eq 0 ]]; then
  skip "CICD-010" "Deployment path liveness" "$_cf_skip_reason"
else
  _cf_deploy_workflows=$(_cicd_freshness_workflows "$CICD_FRESHNESS_DEPLOY_PATTERN")
  if [[ -z "$_cf_deploy_workflows" ]]; then
    skip "CICD-010" "Deployment path liveness" \
      "No deployment or release workflow found under .github/workflows"
  else
    _cf_broken=""
    _cf_never=""
    while IFS= read -r _cf_wf; do
      [[ -n "$_cf_wf" ]] || continue
      _cf_seen_success=0
      _cf_fails=0
      while IFS=$'\t' read -r _cf_conclusion _cf_updated; do
        [[ -n "$_cf_conclusion" ]] || continue
        if [[ "$_cf_conclusion" == "success" ]]; then
          _cf_seen_success=1
          break
        fi
        if echo "$_cf_conclusion" | grep -qE "^(${CICD_FRESHNESS_FAILED_CONCLUSIONS})$"; then
          _cf_fails=$((_cf_fails + 1))
        fi
      done <<< "$(_cicd_freshness_runs "$_cf_slug" "$_cf_wf" "$_cf_branch")"

      if [[ "$_cf_seen_success" -eq 1 && "$_cf_fails" -gt 0 ]]; then
        _cf_broken+="${_cf_wf} (${_cf_fails} failed since last success) "
      elif [[ "$_cf_seen_success" -eq 0 ]]; then
        _cf_never+="${_cf_wf} "
      fi
    done <<< "$_cf_deploy_workflows"

    if [[ -n "$_cf_broken" ]]; then
      fail "CICD-010" "Deployment workflow failing since its last success" "high" \
        "On ${_cf_branch}: ${_cf_broken}— the declared pipeline is intact but no longer ships" \
        "Fix the failing deployment run before relying on this pipeline for remediation" \
        ".github/workflows"
    elif [[ -n "$_cf_never" ]]; then
      warn "CICD-010" "Deployment workflow has never succeeded on ${_cf_branch}" \
        "No successful run found for: ${_cf_never}— liveness cannot be confirmed"
    else
      pass "CICD-010" "Deployment workflows succeeded most recently on ${_cf_branch}"
    fi
  fi
fi

# ── CICD-011: Security scan freshness ────────────────────────────────────────
# The age of the newest successful scan run. This is the evidence CICD-012
# consumes, which is why it is measured as a time and not as a finding count.

if [[ "$_cf_ready" -eq 0 ]]; then
  skip "CICD-011" "Security scan freshness" "$_cf_skip_reason"
else
  _cf_scan_workflows=$(_cicd_freshness_workflows "$CICD_FRESHNESS_SCAN_PATTERN")
  if [[ -z "$_cf_scan_workflows" ]]; then
    skip "CICD-011" "Security scan freshness" \
      "No security scan or dependency submission workflow found under .github/workflows"
  else
    # One `gh` round-trip costs seconds, and a repo can declare several
    # scan-shaped workflows. The question here is "did ANY scan succeed
    # recently", so the first workflow that answers yes ends the search — a
    # healthy repo pays one call instead of one per workflow. Only the failing
    # case, where no workflow is fresh, walks the whole list, and it has to:
    # the newest timestamp across all of them is what the message reports.
    _cf_cutoff=$(( $(date -u +%s) - CICD_FRESHNESS_SCAN_MAX_AGE_DAYS * 86400 ))
    _cf_newest_epoch=""
    _cf_newest_iso=""
    while IFS= read -r _cf_wf; do
      [[ -n "$_cf_wf" ]] || continue
      while IFS=$'\t' read -r _cf_conclusion _cf_updated; do
        [[ "$_cf_conclusion" == "success" ]] || continue
        _cf_epoch=$(_cicd_freshness_epoch "$_cf_updated")
        [[ -n "$_cf_epoch" ]] || continue
        if [[ -z "$_cf_newest_epoch" || "$_cf_epoch" -gt "$_cf_newest_epoch" ]]; then
          _cf_newest_epoch="$_cf_epoch"
          _cf_newest_iso="$_cf_updated"
        fi
        break
      done <<< "$(_cicd_freshness_runs "$_cf_slug" "$_cf_wf" "$_cf_branch")"
      if [[ -n "$_cf_newest_epoch" && "$_cf_newest_epoch" -ge "$_cf_cutoff" ]]; then
        break
      fi
    done <<< "$_cf_scan_workflows"

    if [[ -z "$_cf_newest_epoch" ]]; then
      fail "CICD-011" "Security scan has never succeeded on ${_cf_branch}" "high" \
        "A scan workflow is declared but no successful run exists, so no scan result is current" \
        "Run the scan workflow and fix whatever prevents it from completing" \
        ".github/workflows"
    else
      _cf_age_days=$(( ( $(date -u +%s) - _cf_newest_epoch ) / 86400 ))
      if [[ "$_cf_age_days" -gt "$CICD_FRESHNESS_SCAN_MAX_AGE_DAYS" ]]; then
        fail "CICD-011" "Security scan results are stale (${_cf_age_days}d old)" "high" \
          "Newest successful scan run was ${_cf_newest_iso}, past the ${CICD_FRESHNESS_SCAN_MAX_AGE_DAYS}d threshold" \
          "Restore the scan schedule, or raise CLAUDESEC_CICD_SCAN_MAX_AGE_DAYS if this cadence is intended" \
          ".github/workflows"
      else
        _cf_scan_fresh=1
        pass "CICD-011" "Security scan succeeded ${_cf_age_days}d ago (threshold ${CICD_FRESHNESS_SCAN_MAX_AGE_DAYS}d)"
      fi
    fi
  fi
fi

# ── CICD-012: Evidence behind a zero alert count ─────────────────────────────
# Zero open alerts is only good news if something is known to have looked. When
# CICD-011 did not establish freshness, the same zero is equally consistent with
# a scan that stopped running — so it is reported as the absence of evidence it
# is, not as a clean bill of health.

if [[ "$_cf_ready" -eq 0 ]]; then
  skip "CICD-012" "Zero-alert justification" "$_cf_skip_reason"
else
  _cf_alerts=$(run_with_timeout "$CICD_FRESHNESS_API_TIMEOUT_SEC" \
    gh api "repos/${_cf_slug}/dependabot/alerts?state=open&per_page=1" --jq 'length' \
    2>/dev/null || echo "")
  if [[ ! "$_cf_alerts" =~ ^[0-9]+$ ]]; then
    skip "CICD-012" "Zero-alert justification" \
      "Unable to read Dependabot alerts (alerts disabled or token lacks security_events scope)"
  elif [[ "$_cf_alerts" -gt 0 ]]; then
    pass "CICD-012" "Alert count is non-zero, so it is not an absence to explain"
  elif [[ "$_cf_scan_fresh" -eq 1 ]]; then
    pass "CICD-012" "Zero open alerts, backed by a fresh successful scan (CICD-011)"
  else
    fail "CICD-012" "Zero open alerts with no fresh scan behind them" "high" \
      "Zero is not a safety signal here: CICD-011 did not establish that a scan recently succeeded, so 'clean' and 'not scanned' are indistinguishable" \
      "Make CICD-011 pass first — a zero alert count means nothing until the scan that produces it is known to run" \
      ".github/workflows"
  fi
fi
