#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Dev Machine Hardening (macOS)
#
# Addresses the three host-state checks that the scanner reports as failures
# on typical developer machines:
#
#   MAC-005  — Automatic software update checks are disabled
#   CIS-002  — Audit logging daemon (auditd) is not running
#   CIS-005  — Outdated Homebrew packages detected
#
# ----------------------------------------------------------------------------
# Default mode is DRY-RUN: the script only REPORTS current state and prints
# the exact commands that would fix each issue. Nothing is executed and no
# system state is changed. Pass --apply to actually run the remediation
# commands (you will be prompted for sudo and will still need to approve each
# step that requires elevation).
#
# Usage:
#   bash scripts/dev-machine-hardening.sh            # dry-run (default)
#   bash scripts/dev-machine-hardening.sh --dry-run  # explicit dry-run
#   bash scripts/dev-machine-hardening.sh --apply    # actually remediate
#   bash scripts/dev-machine-hardening.sh --help     # show usage
#
# This script intentionally prints one section per CIS ID so it can be scanned,
# diffed, or referenced from compliance docs without running anything.
# ============================================================================

set -uo pipefail

APPLY=0
DRY_RUN=1

print_usage() {
  sed -n '3,24p' "$0" | sed 's|^# \?||'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)    APPLY=1; DRY_RUN=0; shift ;;
    --dry-run)  APPLY=0; DRY_RUN=1; shift ;;
    -h|--help)  print_usage; exit 0 ;;
    *)          echo "Unknown option: $1" >&2; print_usage; exit 2 ;;
  esac
done

RED="$(tput setaf 1 2>/dev/null || true)"
GRN="$(tput setaf 2 2>/dev/null || true)"
YLW="$(tput setaf 3 2>/dev/null || true)"
DIM="$(tput dim 2>/dev/null || true)"
RST="$(tput sgr0 2>/dev/null || true)"

# OS guard — this script only supports macOS.
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "${RED}This script targets macOS only. Detected: $(uname -s)${RST}" >&2
  exit 1
fi

header() {
  printf '\n%s==[ %s ]==%s\n' "${YLW}" "$1" "${RST}"
}

step() {
  local label="$1" cmd="$2"
  printf '  %s$%s %s\n' "${DIM}" "${RST}" "$cmd"
  if [[ "$APPLY" -eq 1 ]]; then
    # shellcheck disable=SC2086
    eval "$cmd" && printf '    %s✓ applied%s\n' "${GRN}" "${RST}" \
      || printf '    %s✗ failed (exit %d)%s\n' "${RED}" "$?" "${RST}"
  else
    printf '    %s(dry-run — not executed)%s\n' "${DIM}" "${RST}"
  fi
  printf '  %s-- %s --%s\n' "${DIM}" "$label" "${RST}"
}

# ── MAC-005: Automatic software update checks ──────────────────────────────
mac_005_report() {
  header "MAC-005 — macOS Automatic Software Update Checks"
  local current
  current=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "unset")
  printf '  current state: AutomaticCheckEnabled=%s\n' "$current"
  if [[ "$current" == "1" ]]; then
    printf '  %s✓ already compliant%s\n' "${GRN}" "${RST}"
    return 0
  fi
  step "enable automatic update checks" \
    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true"
  step "enable background auto-download" \
    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true"
  step "enable critical security update install" \
    "sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true"
}

# ── CIS-002: auditd logging daemon ─────────────────────────────────────────
cis_002_report() {
  header "CIS-002 — Audit Logging Daemon (auditd)"
  local plist="/System/Library/LaunchDaemons/com.apple.auditd.plist"
  if launchctl list 2>/dev/null | grep -q 'com.apple.auditd'; then
    printf '  %s✓ auditd is currently loaded%s\n' "${GRN}" "${RST}"
    return 0
  fi
  printf '  current state: auditd not loaded in launchctl\n'
  if [[ ! -f "$plist" ]]; then
    printf '  %s! plist missing: %s (nothing to load)%s\n' "${RED}" "$plist" "${RST}"
    return 1
  fi
  step "load and enable auditd" \
    "sudo launchctl load -w $plist"
  step "verify auditd is running" \
    "launchctl list | grep com.apple.auditd"
}

# ── CIS-005: outdated Homebrew packages ────────────────────────────────────
cis_005_report() {
  header "CIS-005 — Outdated Homebrew Packages"
  if ! command -v brew >/dev/null 2>&1; then
    printf '  %s(brew not installed — nothing to do)%s\n' "${DIM}" "${RST}"
    return 0
  fi
  local outdated
  outdated=$(brew outdated --quiet 2>/dev/null | wc -l | tr -d ' ')
  printf '  current state: %s outdated package(s)\n' "$outdated"
  if [[ "$outdated" == "0" ]]; then
    printf '  %s✓ already compliant%s\n' "${GRN}" "${RST}"
    return 0
  fi
  step "refresh package metadata" "brew update"
  step "upgrade all outdated formulae" "brew upgrade"
  step "upgrade cask applications"    "brew upgrade --cask"
  step "prune old versions"           "brew cleanup -s"
}

main() {
  printf '%s== ClaudeSec Dev Machine Hardening (macOS) ==%s\n' "${YLW}" "${RST}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '%smode: DRY-RUN (no changes will be made; pass --apply to execute)%s\n' "${DIM}" "${RST}"
  else
    printf '%smode: APPLY (changes WILL be made; sudo prompts may appear)%s\n' "${RED}" "${RST}"
  fi

  mac_005_report
  cis_002_report
  cis_005_report

  printf '\n%s== verify with the scanner ==%s\n' "${YLW}" "${RST}"
  printf '  bash scanner/claudesec scan -c macos --format json | python3 -m json.tool | less\n'

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '\n%sNo system changes were made. Review the commands above, then rerun with --apply.%s\n' "${DIM}" "${RST}"
  fi
}

main
