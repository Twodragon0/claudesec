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
#
# HOW IGNORANCE IS GRADED, AND WHY IT IS NOT A `fail`
# An unanswerable question must not be scored as a pass or a fail. The first
# version of this file declared that and then broke it: it skipped when the API
# could not be READ, but returned `fail`/`high` when the API came back EMPTY.
# Those are the same epistemic state — nobody knows whether a scan ran — and
# grading them differently is the exact confusion these checks exist to expose.
# It also misfires in practice: GitHub disables Actions on forks by default, so
# run history is permanently empty there and every fork would have collected two
# spurious `high` findings from a toolkit meant to run on other people's repos.
#
# The three states are kept apart deliberately:
#   skip  the question could not be asked — no `gh`, logged out, non-GitHub
#         remote, insufficient scope, rate limit, or a failed query.
#   warn  the question was asked and the answer is "nothing has ever run".
#         Not knowing is reported, not punished.
#   fail  something DID run and the answer is bad — failures piling up after a
#         success (CICD-010), or a scan that ran but is now stale (CICD-011/012).
# Only the third is a security finding; the first two are reports about evidence.
#
# KNOWN LIMITATION — CICD-011 AND CICD-012 DO NOT READ THE SAME PRODUCER
# CICD-011 measures the freshness of ANY scan-shaped workflow, while CICD-012
# reads the Dependabot alert count. A container or DAST scan succeeding says
# nothing about whether Dependabot is still producing alerts, so a fresh
# CICD-011 can certify a zero that a different, silently broken producer emitted.
# The argument ("clean and unscanned are indistinguishable") holds; this
# particular evidence link is weaker than the argument needs. CICD-011's pass
# message therefore names the workflow that certified freshness, so a reader can
# judge whether that producer is the one the alert count comes from.

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
#
# The deploy pattern is deliberately NOT narrowed, and the scan pattern is.
# They are not symmetric, because their loops are not:
#   CICD-010 AGGREGATES over every match, so an extra match can only add a
#     finding — and that finding names the workflow, so a human can dismiss it
#     in one glance. Narrowing it could silently drop a real deployment path,
#     which nothing would report.
#   CICD-011 STOPS at the first match that proves freshness, so an extra match
#     can SUPPRESS the real signal. Measured: with a bare `depend`/`audit`, the
#     alphabetically-first match in this repo was `dependabot-auto-merge.yml`,
#     and a merge-automation bot was certifying "the security scan is fresh".
# Over-matching is a false positive on one side and a false NEGATIVE on the
# other, so only the side that can lie by omission is tightened.
CICD_FRESHNESS_DEPLOY_PATTERN='deploy|release|publish|rollout|promote|(^|[-_.])cd([-_.]|$)'
# Scanner vocabulary plus separator-bounded generic words. Bare `sca` is gone
# (it hit `scale`, `scaffold`, `escalate`, and `scan` already covered it); bare
# `depend` and bare `audit` are gone for the reason above — `dependency-review`
# and `npm-audit` are still matched by name, `dependabot-auto-merge` and
# `guard-audit-reminder` are not. Kept narrower than CICD-005's tool list on
# purpose: that list includes linters like `shellcheck`, and a lint workflow
# running hourly must not be allowed to certify security-scan freshness.
CICD_FRESHNESS_SCAN_PATTERN='codeql|semgrep|sonarqube|snyk|trivy|grype|gitleaks|trufflehog|osv|sast|dast|zap|(^|[-_.])scan([-_.]|$)|dependency[-_.](review|submission|check|scan|audit)|(npm|pip|yarn|pnpm|cargo|bundler)[-_.]audit|security[-_.]audit'

# Monitors are excluded from BOTH sets. A workflow that watches whether another
# workflow ran is not itself a producer, and letting one certify freshness is
# the same defect as letting a merge bot certify it — the watcher runs on
# schedule and looks perfectly fresh while the thing it watches is dead.
#
# Measured on this repository: `dast-freshness-watch.yml` sorts before
# `dast-full-scan.yml` and `security-scan.yml`, so it won CICD-011's early exit
# and certified "the security scan is fresh". Its own header says
# "NOTIFICATION-ONLY workflow" that runs no scan at all.
#
# This is a negative filter on a monitoring vocabulary, and it is deliberately
# allowed to be imperfect, because its two error directions are not equal:
# wrongly EXCLUDING a real scan leaves CICD-011 with another workflow or with
# "unknown", which now grades as warn/skip; wrongly INCLUDING a monitor
# produces a false PASS. Only one of those lies.
CICD_FRESHNESS_MONITOR_PATTERN='(^|[-_.])(watch|watcher|monitor|reminder|notice|notify|alert|drift)([-_.]|$)'

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
#
# Built-ins only — no `basename`, no `grep` subprocess per file. The first
# version forked twice per workflow, which is invisible in a scan (one pass over
# ~17 files) but not in the unit test, which classifies a 26-name fixture once
# per assertion; that alone pushed the suite past the repo's 30s per-test cap.
# `nocasematch` is restored to whatever it was, so sourcing this check cannot
# change how any later check's `[[ ... ]]` behaves.
_cicd_freshness_workflows() {
  local pattern="$1" path base was_nocasematch=1
  [[ -d "$SCAN_DIR/.github/workflows" ]] || return 0
  shopt -q nocasematch || was_nocasematch=0
  shopt -s nocasematch
  for path in "$SCAN_DIR"/.github/workflows/*.yml "$SCAN_DIR"/.github/workflows/*.yaml; do
    [[ -f "$path" ]] || continue
    base="${path##*/}"
    [[ "$base" =~ $CICD_FRESHNESS_MONITOR_PATTERN ]] && continue
    if [[ "$base" =~ $pattern ]]; then
      echo "$base"
    fi
  done
  [[ "$was_nocasematch" -eq 1 ]] || shopt -u nocasematch
  return 0
}

# "<conclusion>\t<updatedAt>" per run of workflow $2 on branch $3, newest first.
#
# THE EXIT STATUS IS LOAD-BEARING — do not add `|| echo ""`. An earlier version
# did, which collapsed "the API refused us" (403 rate limit, missing scope) into
# the same empty string as "this workflow has no runs". Callers must be able to
# tell a failed question from an empty answer, because the first is a `skip` and
# the second is a `warn`. `run_with_timeout` already suppresses stderr and
# forwards the exit code (124 on timeout), so both failure shapes arrive here.
_cicd_freshness_runs() {
  local slug="$1" workflow="$2" branch="$3"
  run_with_timeout "$CICD_FRESHNESS_API_TIMEOUT_SEC" \
    gh run list --repo "$slug" --workflow "$workflow" --branch "$branch" \
      --limit "$CICD_FRESHNESS_RUN_HISTORY_LIMIT" \
      --json conclusion,updatedAt \
      --jq '.[] | [.conclusion, .updatedAt] | @tsv'
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
# re-derived. THREE states, not a boolean: the boolean version lumped "a scan
# ran and is stale" together with "we have no idea whether anything ran", and
# CICD-012 then graded both as a `high`. Only the first is a security finding.
#   fresh    a scan succeeded inside the threshold
#   stale    a scan ran, but its newest success is past the threshold
#   unknown  nothing ran, or the question could not be asked at all
_cf_scan_state="unknown"
# Which workflow certified freshness — reported so a reader can check that the
# producer CICD-012 leans on is actually the one that ran. See the limitation
# note at the top of this file.
_cf_fresh_wf=""

# Reason text for a per-check skip when the query itself failed, as opposed to
# the preconditions failing before any call was made.
_cf_query_skip_reason="GitHub run history query failed (rate limit, revoked scope, or timeout) — history state is unknown, not empty"

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
    _cf_query_failed=0
    while IFS= read -r _cf_wf; do
      [[ -n "$_cf_wf" ]] || continue
      if ! _cf_runs=$(_cicd_freshness_runs "$_cf_slug" "$_cf_wf" "$_cf_branch"); then
        _cf_query_failed=1
        break
      fi
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
      done <<< "$_cf_runs"

      if [[ "$_cf_seen_success" -eq 1 && "$_cf_fails" -gt 0 ]]; then
        _cf_broken+="${_cf_wf} (${_cf_fails} failed since last success) "
      elif [[ "$_cf_seen_success" -eq 0 ]]; then
        _cf_never+="${_cf_wf} "
      fi
    done <<< "$_cf_deploy_workflows"

    if [[ "$_cf_query_failed" -eq 1 ]]; then
      skip "CICD-010" "Deployment path liveness" "$_cf_query_skip_reason"
    elif [[ -n "$_cf_broken" ]]; then
      fail "CICD-010" "Deployment workflow failing since its last success" "high" \
        "On ${_cf_branch}: ${_cf_broken}— the declared pipeline is intact but no longer ships" \
        "Fix the failing deployment run before relying on this pipeline for remediation" \
        ".github/workflows"
    elif [[ -n "$_cf_never" ]]; then
      # Not a `fail`: "never ran" is the normal state of a fork, where GitHub
      # disables Actions by default. Reported, not scored as a defect.
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
    _cf_newest_wf=""
    _cf_query_failed=0
    while IFS= read -r _cf_wf; do
      [[ -n "$_cf_wf" ]] || continue
      if ! _cf_runs=$(_cicd_freshness_runs "$_cf_slug" "$_cf_wf" "$_cf_branch"); then
        _cf_query_failed=1
        break
      fi
      while IFS=$'\t' read -r _cf_conclusion _cf_updated; do
        [[ "$_cf_conclusion" == "success" ]] || continue
        _cf_epoch=$(_cicd_freshness_epoch "$_cf_updated")
        [[ -n "$_cf_epoch" ]] || continue
        if [[ -z "$_cf_newest_epoch" || "$_cf_epoch" -gt "$_cf_newest_epoch" ]]; then
          _cf_newest_epoch="$_cf_epoch"
          _cf_newest_iso="$_cf_updated"
          _cf_newest_wf="$_cf_wf"
        fi
        break
      done <<< "$_cf_runs"
      if [[ -n "$_cf_newest_epoch" && "$_cf_newest_epoch" -ge "$_cf_cutoff" ]]; then
        break
      fi
    done <<< "$_cf_scan_workflows"

    if [[ "$_cf_query_failed" -eq 1 ]]; then
      skip "CICD-011" "Security scan freshness" "$_cf_query_skip_reason"
    elif [[ -z "$_cf_newest_epoch" ]]; then
      # `warn`, not `fail`: a declared workflow with no successful run is the
      # default state of every fork, and CICD-005 already fails `high` when no
      # scan tooling is configured at all. Scoring this as a second `high`
      # double-counted one cause and punished the absence of evidence.
      warn "CICD-011" "Security scan has never succeeded on ${_cf_branch}" \
        "A scan workflow is declared but no successful run exists, so scan freshness is unknown rather than bad"
    else
      _cf_age_days=$(( ( $(date -u +%s) - _cf_newest_epoch ) / 86400 ))
      if [[ "$_cf_age_days" -gt "$CICD_FRESHNESS_SCAN_MAX_AGE_DAYS" ]]; then
        # A `fail` here is earned: the scan demonstrably runs, so its silence
        # is a regression rather than an unknown.
        _cf_scan_state="stale"
        fail "CICD-011" "Security scan results are stale (${_cf_age_days}d old)" "high" \
          "Newest successful scan run was ${_cf_newest_wf} at ${_cf_newest_iso}, past the ${CICD_FRESHNESS_SCAN_MAX_AGE_DAYS}d threshold" \
          "Restore the scan schedule, or raise CLAUDESEC_CICD_SCAN_MAX_AGE_DAYS if this cadence is intended" \
          ".github/workflows"
      else
        _cf_scan_state="fresh"
        _cf_fresh_wf="$_cf_newest_wf"
        pass "CICD-011" "Security scan succeeded ${_cf_age_days}d ago via ${_cf_newest_wf} (threshold ${CICD_FRESHNESS_SCAN_MAX_AGE_DAYS}d)"
      fi
    fi
  fi
fi

# ── CICD-012: Evidence behind a zero alert count ─────────────────────────────
# Zero open alerts is only good news if something is known to have looked. What
# that zero means depends on WHICH of CICD-011's three states produced it:
#   fresh    a scan recently succeeded — the zero has a producer behind it.
#   stale    a scan runs but its results are old — the zero is being read as
#            current when it is not. This is the real finding, and the only
#            `high` here.
#   unknown  nothing is known to have looked. Reported as missing evidence, not
#            as a defect, because "unknown" is also what a fork and a
#            permission-limited token look like.

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
  elif [[ "$_cf_scan_state" == "fresh" ]]; then
    pass "CICD-012" "Zero open alerts, backed by a fresh successful scan (CICD-011 via ${_cf_fresh_wf})"
  elif [[ "$_cf_scan_state" == "stale" ]]; then
    fail "CICD-012" "Zero open alerts read as clean while the scan behind them is stale" "high" \
      "The scan demonstrably runs, so this zero looks current and is not: CICD-011 measured its newest success past the freshness threshold" \
      "Restore the scan cadence — until CICD-011 passes, this zero reflects the last successful run, not the current tree" \
      ".github/workflows"
  else
    warn "CICD-012" "Zero open alerts with nothing known to have looked" \
      "CICD-011 could not establish that any scan has run, so 'clean' and 'not scanned' are indistinguishable. Not scored as a defect — an unanswered question is not a finding"
  fi
fi
