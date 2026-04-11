#!/usr/bin/env bash
# ============================================================================
# ClaudeSec — Git pre-push hook
#
# Blocks direct `git push` to protected branches (main, master) so that
# changes must flow through a feature branch + pull request.
#
# Install once per clone:
#   ln -sf ../../scripts/pre-push.sh .git/hooks/pre-push
#
# Bypass (use sparingly, e.g. for hotfixes that have explicit approval):
#   ALLOW_MAIN_PUSH=1 git push origin main
#
# Why this exists:
#   GitHub branch protection on this repo already requires PRs on main,
#   but admins (including the repo owner) can bypass that rule by default.
#   This client-side hook gives the same safeguard to any developer who
#   installs it, regardless of their GitHub permissions.
# ============================================================================

set -uo pipefail

PROTECTED_BRANCHES=(main master)

red()  { printf '\033[31m%s\033[0m' "$*"; }
dim()  { printf '\033[2m%s\033[0m' "$*"; }
bold() { printf '\033[1m%s\033[0m' "$*"; }

# git feeds one line per pushed ref on stdin:
#   <local_ref> <local_sha> <remote_ref> <remote_sha>
while read -r _local_ref _local_sha remote_ref _remote_sha; do
  [[ -z "${remote_ref:-}" ]] && continue

  for protected in "${PROTECTED_BRANCHES[@]}"; do
    if [[ "$remote_ref" == "refs/heads/$protected" ]]; then
      if [[ "${ALLOW_MAIN_PUSH:-0}" == "1" ]]; then
        dim "[pre-push] ALLOW_MAIN_PUSH=1 — allowing direct push to '$protected'"
        printf '\n'
        continue
      fi

      printf '\n'
      red "  ✗ pre-push blocked: direct push to '$protected' is not allowed."
      printf '\n\n'
      printf '  Use a feature branch + PR instead:\n'
      printf '    %s\n' "$(bold "git switch -c feature/<name>")"
      printf '    %s\n' "$(bold "git push -u origin feature/<name>")"
      printf '    %s\n' "$(bold "gh pr create --fill")"
      printf '\n'
      printf '  If this push is authorized (e.g. hotfix), override with:\n'
      printf '    %s\n\n' "$(bold "ALLOW_MAIN_PUSH=1 git push origin $protected")"
      exit 1
    fi
  done
done

exit 0
