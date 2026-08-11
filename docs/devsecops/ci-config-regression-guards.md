---
title: CI Config Regression Guards
description: Catalog of ClaudeSec's pytest guards that prevent CI security/quality gates from being silently weakened or removed
tags: [ci-cd, supply-chain, devsecops, testing, branch-protection]
---

# CI Config Regression Guards

ClaudeSec's CI gates (coverage floors, action SHA pins, required-check topology,
the security-scan severity block) are the controls that stand between a
regression and a green build. They are also easy to weaken **silently** — a
lowered threshold, a job dropped from an aggregator's `needs:`, or a tag
re-introduced in a `uses:` line passes review unnoticed and disables enforcement
without any visible failure.

This is a recognised CI/CD risk class: **OWASP CICD-SEC-1 (Insufficient Flow
Control Mechanisms)** and **CICD-SEC-7 (Insecure System Configuration)**, and
the supply-chain integrity expectations of **NIST SSDF (SP 800-218) PO.3 /
PW.4**. To make any such weakening explicit and reviewable, ClaudeSec ships
small **config regression guards**: stdlib-only `pytest` tests that read the
workflow YAML and assert each invariant still holds.

## Conventions

All guards follow the same rules (see the existing files for reference):

- **Location**: `scanner/tests/test_ci_*.py`, executed by the `scanner-unit-tests`
  job (`python3 -m pytest scanner/tests/`).
- **Stdlib-only**: regex / line scanning, **no PyYAML** — it is not in
  `requirements-ci.txt`, so `import yaml` would fail in CI. (The
  `workflow-fork-guard` job installs PyYAML separately for its own script, from
  its own pinned `requirements-fork-guard.txt` — kept out of `requirements-ci.txt`
  precisely so this premise stays true.)
- **No `scanner/lib` import**: guards add tests without touching the measured
  coverage, so they never move the 99% `scanner/lib` floor.
- **Direction-explicit semantics**: floors use `>=` (ratcheting a floor *up*
  stays green; lowering/removing trips it); pins use exact/`==`; presence checks
  assert a trigger/flag still exists. State the direction in the docstring.
- **Non-vacuous**: prove the guard fires on the regression it targets (simulate
  it) before shipping. Avoid regexes that match commentary in the workflow.
- **Dual-runner**: pass under both `pytest` (CI) and `python3 -m unittest`.
- **Shared primitives**: comment-stripping, continuation-joining, and `on:`-block
  extraction live in `scanner/tests/_ci_guard_util.py` (`strip_comment_lines`,
  `non_comment_lines`, `join_continuations`, `extract_on_block`), together with the
  YAML-shape primitives added in #393 — `yaml_key_pattern` (a key is bare OR
  quoted), `explicit_key_lines` (fail closed on `? key` / `: value`), and
  `workflow_and_action_files` (workflows in BOTH extensions plus composite
  `action.yml`), the single-sourced `uses_refs` action-ref matcher, and the two
  block primitives added 2026-08-11 — `block_ends_at` (a blank or COMMENT line ends
  no mapping block) and `key_column` (derive a block's key column ignoring blank and
  comment lines). **Never write `key\s*:` by hand** — compose `yaml_key_pattern` —
  and **never hand-roll a block terminator or a `min(indent)` derivation**: five
  copies of the latter existed and the comment case was wrong in every one. Import them as a
  top-level module after putting the test dir on `sys.path` so they resolve under
  both runners. The `_`-prefixed name keeps the module out of pytest collection
  and the `test_ci_*.py` catalog glob (no Catalog row needed). **Always strip
  comments and scope tokens** before a presence check — a token in a `#` comment
  or a second weaker assignment must not satisfy an invariant (the false-negative
  class hardened across these guards).

## Catalog

| Guard | Protects | Key assertions | Landed |
|-------|----------|----------------|--------|
| `scanner/tests/test_ci_coverage_thresholds.py` | Coverage floors in `lint.yml` | pytest `--cov-fail-under >= 99`; bash kcov `threshold >= 90.0`. Both floors are read from shell inside `run:` blocks, so the scan strips comments with the bash-aware `strip_inline_comment_sh` — a floor surviving only in a `;#`/`&#`/backtick comment is not an active gate | #200 |
| `scanner/tests/test_ci_gate_topology.py` | Enforcement topology of EVERY workflow hosting a required aggregator | every `uses:` is 40-hex SHA-pinned (OWASP A08) across all `.github/workflows/*.yml`/`*.yaml` **and** composite `.github/actions/**/action.yml` (a composite carries `steps[].uses`, and a tag pin planted there was unreachable — the directory was never globbed); every job is in `lint-gate.needs` or a tiny documented allowlist. The `uses:`, `jobs:`, `lint-gate:` and sibling-job keys are read bare OR quoted, and `? uses`/`? jobs`/`? needs` explicit-key forms fail closed — a quoted key hid an action ref from the SHA scan, and a quoted sibling job smuggled a foreign `needs:` entry into lint-gate's list. **Generalised 2026-08-10 — it had only ever read `lint.yml`.** The every-job-is-gated rule was hardcoded to that one file, so a job added to `security-scan.yml` and left out of `security-scan-gate.needs` was invisible to the entire suite (**1952 passed** with a rogue `run: exit 1` job that could never block a merge) — even though "Why two required checks matter" above states this is precisely the gap the topology guards catch. It was true for one of the two required workflows. The scope is now DERIVED from the codified `DESIRED_CONTEXTS` via the shared `required_aggregators()` — the same fix #407 applied to the disable class — so a third required workflow is covered the day it appears rather than after the next audit. `UNGATED_JOBS_ALLOWLIST` is keyed by `(workflow, job)`: a flat name set was harmless while one file was read and becomes an allowlist that silently widens the moment a second is. The hand-rolled `_lint_gate_needs` parser is gone, replaced by the shared `job_block`/`job_needs` after verifying they agree on the real `lint.yml` (15 identical entries) and on the quoted-sibling fixture that proved the hardening — that mutation test is KEPT, since the point of a replacement is that the hardening survives it. Mutation self-tests cover an ungated job in BOTH required workflows, the aggregator-resolution vacuity canary, and the file-scoping of the allowlist | #201 (allowlist tightened in #203), #393, this PR |
| `scanner/tests/test_ci_security_gate.py` | `Security Scan Gate` + DAST signals | `security-scan-gate` keeps `name`, `if: always()`, `needs: ⊇ {changes, scan, lighthouse}`, pass-set `not in (success, skipped)`; `dast-baseline.yml` keeps its `pull_request` trigger; `dast-full-scan.yml` keeps its `schedule:` trigger AND a `coverage-notice` job that opens an issue when `DAST_TARGET_URL` is unset — the trigger alone is not enough, since the scan job is gated on that variable and 42 consecutive nightly runs reported a clean `skipped` (six weeks of ZERO automated DAST, no red build, workflow name still promising nightly coverage). Comment-stripped scan, so a `#`-parked notice job does not satisfy it | #205, #216, #397, #406 **The severity block is no longer guarded here — see the `test_ci_security_gate_behaviour.py` row.** Finding #1 from the 2026-08-07 audit (`conditional_body_from` searched the block ANCHOR in RAW text while comment-stripping only the body it returned, so one line `# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi` anchored the scan inside itself, returned ` exit 1; ` and certified a DELETED gate while bash exited 0 on a CRITICAL) is CLOSED — by deleting the function and its six comment-evasion self-tests, not by patching them. Three successive line-scanner fixes were each defeated (1 shape, then 4, then 6: quoted string, heredoc body, multi-line YAML scalar, space-indented heredoc terminator, two heredocs on a line, split/non-word delimiters), which is ADR-001 §4's redesign signal. The invariant now lives in a check that EXECUTES the gate, and the HIGH-stays-non-blocking direction — the one thing the text version uniquely covered — moved with it as a third fixture. Keeping the text assertion as belt-and-braces was considered and rejected: a second, weaker proof of an already-behavioural invariant is not redundancy, it is a defect with a maintenance cost and a standing `KNOWN_STRIP_ORDER_EXCEPTIONS` entry (that baseline is EMPTY again). What remains in this file is the enforcement TOPOLOGY, which has no runtime to execute. |
| `scanner/tests/test_ci_required_jobs_exist.py` | Existence of security/enforcement jobs in `lint.yml` | `{gitleaks, pii-check, dependency-review, workflow-fork-guard, scanner-unit-tests, scanner-shell-coverage}` are all present — deleting a whole job is a silent control loss the topology guard cannot see. **Made non-vacuous 2026-08-10:** `REQUIRED - jobs` is empty both when every job is present and when the parser silently returns everything, and only the second half was covered (`test_parser_canary`, for one key). The check is now `missing_required_jobs()`, mutation-tested by deleting each required job's block from the REAL `lint.yml` one at a time and asserting THAT job is the one reported — a synthetic fixture would not have proven the parser matches this file's actual indentation. Also pins a job demoted to a `#` comment (the substring `gitleaks:` survives, so a raw-text presence check reads green) and two no-false-alarm directions: an added unrelated job, and a required job written with a quoted `"gitleaks":` key | #215 |
| `scanner/tests/test_ci_codeql_single_model.py` | Single CodeQL model (default setup only) | no workflow uses `github/codeql-action/init` or `/analyze` (a repo-level analysis would duplicate the default-setup model); `upload-sarif` is allowed (DAST SARIF upload, not analysis). Scans workflows in BOTH extensions plus composite `action.yml` (a `codeql.yaml` or a composite invoking `init` is just as much a second model and neither was enumerated), reads the `uses:` key and its value bare OR quoted, and fails closed on `? uses` | #215, #394 |
| `scanner/tests/test_ci_npm_publish.py` | npm release supply-chain integrity + auto-release wiring (`npm-publish.yml`) | every `npm publish` carries `--provenance` (SLSA attestation); workflow-level `permissions:` stays `contents: read` (job-level `id-token: write` + `contents: write` are not flagged) — the write-grant scan reads a quoted VALUE (`packages: "write"` returned an EMPTY grant list, so the scan reported nothing while the permission was live) and now runs BEFORE the whole-block anchor, because behind it the fixed scan could never be the reporter and its correctness was unobservable; the publish job upgrades npm (`npm install -g npm`, OIDC needs >= 11.5.1 but Node 22 ships npm 10.x); the `on:` block keeps a push-to-`main` trigger (version-bump auto-publish) and a `contents: write` exists for pushing the `vX.Y.Z` tag. **2026-08-11: the block EXTRACTOR was the bypass, not either assertion.** It ended the block at the first `^\S` line — "dedent to the next top-level key" — and a column-0 `#` comment matches that, while PyYAML discards comment lines before structure. One comment under `permissions:` hid everything below it: PyYAML resolved `{'contents': 'read', 'packages': 'write'}` on the real file while this guard reported **12 passed**. Both least-privilege assertions fell together, including the whole-block anchor described above as "a structural catch-all for any added key the write-grant scan does not classify" — it is a catch-all only over what the extractor RETURNS, and the truncated block really was exactly `contents: read`. Now uses the shared `block_ends_at`, with a mutation test on the real file and a no-widening direction (a job-level `id-token: write` must stay outside the scan) | #216, #262, this PR |
| `scanner/tests/test_ci_cross_os_non_required.py` | Cross-OS live-runner workflow stays non-required | `cross-os-checks.yml` exists and keeps `workflow_dispatch` (standalone informational lane); `lint.yml` references none of `{cross-os, live-os-checks, macos-latest, windows-latest}` — so the costly/flaky macOS+Windows runs never become a required merge gate. The `runs-on:`/matrix `os:` key is read bare OR quoted (`"runs-on": macos-14` selected the same runner past the bare-only regex), the job-name collision check accepts a quoted key AND a quoted value (`"name": "Lint"` masqueraded as the required context), and `? name`/`? runs-on` fail closed | #228, #394 |
| `scanner/tests/test_ci_net005_fail_escalation.py` | NET-005 SSH-open-to-world FAIL escalation (`network/tls.sh`) | NET-005 keeps `fail "NET-005" ... "critical"` and an ERE `(0\.0\.0\.0/0.*22\|port.*22.*0\.0\.0\.0/0)` alternation; no `\|` literal-pipe regression (which silently downgraded it to WARN, fixed in #224) | #228 |
| `scanner/tests/test_ci_dependabot_automerge.py` | Dependabot auto-arm safety (`dependabot-auto-merge.yml`, a `pull_request_target` write-token workflow) | keeps the fork guard (`actor==dependabot[bot]` AND `head.repo.full_name==github.repository`), the hard-exclude path arms (`Dockerfile*`/`.github`/`scanner`/`hooks`/`scripts`), the `semver-patch\|minor`-only update-type allowlist + `semver-major` exclude, the `pip\|docker\|github-actions` ecosystem allowlist, and `gh pr merge --auto`; forbids `--admin` (a wholesale branch-protection bypass — still forbidden now that code-owner review is off, since `enforce_admins` and the two required contexts remain the real gate) and the `pr review --approve` bot self-approve removed in #249 (OWASP CICD-SEC-1/-4). Every check — the aggregate validator AND the narrower per-invariant tests — runs against the bash-comment-stripped text (`strip_inline_comment_sh`), so an arm parked behind `;#` neither satisfies a REQUIRED token nor false-trips a FORBIDDEN one | #249, #250 |
| `scanner/tests/test_ci_codeowners_invariants.py` | `.github/CODEOWNERS` keeps security-sensitive paths code-owner gated | every required pattern (`*`, `.github/workflows/`, `.github/CODEOWNERS`, `hooks/`, `scanner/`, `scripts/`, `templates/`, `Dockerfile*`, `docker-compose*.yml`) is present AND has a non-empty `@owner`; the global `*` default must have an owner — else those paths merge with NO code-owner review (CODEOWNERS now drives reviewer AUTO-REQUEST only — `require_code_owner_reviews` is false, so an owner-less pattern means nobody is notified rather than nobody can merge) | #248 |
| `scanner/tests/test_ci_no_ere_pipe_regression.py` | No literal `\|` in an ERE context in `scanner/checks/**` + `scanner/lib/**` `.sh` | flags `\|` (literal-pipe, NOT alternation) inside `grep -[qnrlc]*E`, the `_code_grep`/`files_contain`/`file_contains` helpers, and bash `[[ =~ ]]` — the silent detection-breaking bug class fixed in #221/#223/#224; two intentional literals (`code/injection.sh` `\|safe`, `solutions.sh` `curl\|sh`) are allowlisted and asserted still present | #244, #246 |
| `scanner/tests/test_ci_prowler_provider_guard_ordering.py` | `_prowler_provider_available` precedes `_prowler_report` per provider (`scanner/checks/prowler/integration.sh`) | within each provider section of the Provider Scans block, `min(guard line) < min(report line)` — reordering would silently regress the #238 build-parity fix (lean image would emit a misleading auth warning instead of an accurate "not in this build" skip); promotes the shell-level `#241` assertion into the pytest CI gate. `integration.sh` is pure bash, so guard/report call detection strips trailing comments with `strip_inline_comment_sh`: a decoy `echo x;#_prowler_provider_available "…"` must not lend its early line number to `min(guard)` and mask a real guard that now sits after the report | #242 |
| `scanner/tests/test_ci_catalog_completeness.py` | Completeness of this catalog vs the on-disk guard suite | every `scanner/tests/test_ci_*.py` file has its repo-relative path listed in this catalog (presence) — a new guard added without a Catalog row is silent documentation drift that makes the inventory understate coverage; the meta-guard documents itself so the invariant is uniform. HTML-comment-stripped, so a row parked in `<!-- ... -->` (invisible when rendered, the Markdown comment-evasion form) does NOT satisfy the presence check. Mutation self-tests | #254 |
| `scanner/tests/test_ci_catalog_no_ghost_rows.py` | No ghost rows in this catalog vs the on-disk guard suite | every concrete `scanner/tests/test_ci_<name>.py` path cited in this catalog resolves to a real file (existence) — the reverse of the completeness guard: a renamed/deleted guard left in the table is a ghost row that makes the inventory overstate coverage. Together the two guards verify a 1:1 catalog↔suite mapping. HTML-comment-stripped, the opposite direction from the completeness guard: a row parked in `<!-- ... -->` claims no coverage, so flagging it as a ghost would be a false alarm — a test pins that a commented ghost still does not mask a live one. Mutation self-tests | #255 |
| `scanner/tests/test_ci_branch_protection_codified.py` | Codified branch protection (`scripts/sync-repo-protection.sh`) + its nightly notifier (`protection-drift-watch.yml`) | the desired state keeps `DESIRED_CONTEXTS=["Lint","Security Scan Gate"]` (both required checks — an exact two-sided pin: dropping a context un-requires that aggregator, and silently *adding* a third required context is equally caught, proven by appended+prepended mutation self-tests), `DESIRED_ENFORCE_ADMINS="true"` (admins not exempt — no force-push to main), `strict` true and `require_code_owner_reviews` **false** (pinned exactly, so a flip in either direction is reviewable — see the script for why: with `required_approving_review_count=0` it only ever blocked non-owner-authored PRs, i.e. Dependabot's, and #388 sat BLOCKED at 22/22 green until it was reapplied by hand as #400), `set -euo pipefail`, and the default-arm dry-run; the `DRIFT DETECTED` marker contract holds on both producer (script) and consumer (`grep -q`) sides; the watch keeps `schedule:` + tooling-error `exit 1` and its `on:` block never gains a `pull_request(_target)` trigger (scheduled notifier, must not become a required PR check). Protects the #250/#251 codification | #256 |
| `scanner/tests/test_ci_dependabot_config.py` | `.github/dependabot.yml` update coverage + alpine version freeze | all four ecosystems stay declared (`github-actions`, `npm`, `pip`, `docker`) so no surface silently stops getting update PRs (OWASP CICD-SEC-3); the `docker` `ignore` keeps the `alpine` `semver-minor`+`semver-major` freeze that holds alpine on its py3.12 minor line — loosening it would let Dependabot propose the bump that ships py3.14 and crashes prowler (pydantic v1, incident #220). Distinct from `test_ci_dependabot_automerge.py` (guards the *workflow*, not this *config*) | #256 |
| `scanner/tests/test_ci_prowler_version_pinned.py` | prowler install pin in `Dockerfile` | prowler is installed via an exact `==` pin through the `PROWLER_VERSION` build arg (version-shaped value), never a bare unpinned `pip install ... prowler`. An unpinned spec silently backtracks to ancient prowler 3.11.3 (pydantic v1) on a newer Python and crashes at runtime (incident #237). Pins the *pinning*, so a lockstep version bump stays green | #258 |
| `scanner/tests/test_ci_trivy_version_pinned.py` | Trivy install pin + integrity in `Dockerfile` | Trivy is `curl`-downloaded from a hardcoded `ARG TRIVY_VERSION` that Dependabot's `docker` ecosystem cannot track. The guard asserts an exact version-shaped `TRIVY_VERSION` pin (no blank/second override), a pinned `v${TRIVY_VERSION}` download tag (never floating `/releases/latest/`), and a `sha256sum -c` integrity check on the downloaded binary. Pins the *pinning + integrity*, so a version bump stays green | P3 cleanup |
| `scanner/tests/test_ci_dockerfile_base_pinned.py` | Container base-image pins (`Dockerfile`, `Dockerfile.nginx`) | every `FROM` carries an `@sha256:` digest (OWASP A08 — no moving-tag swap); the prowler `Dockerfile` holds every `FROM alpine:` on the `alpine:3.20` (py3.12) minor line and resolves site-packages with the version-agnostic `find ... -name 'python3.*'` glob (no hardcoded `python3.<n>/site-packages`, #234). Complements `test_ci_dependabot_config.py` (config freeze policy) by locking the actual image | #258 |
| `scanner/tests/test_ci_changes_job_merge_base.py` | **Every** `changes` (Detect changed paths) job that diffs a PR base against its head computes changed files in a way that CANNOT hard-fail with `fatal: no merge base` (discovery-based: `lint.yml`, `security-scan.yml`, `dashboard-control-smoke.yml`) | The path-gating job diffs PR base↔head. A `--depth=1` base fetch + three-dot (`BASE...HEAD`) diff hard-fails with `fatal: no merge base` when the branch is behind a moved `main`, cascading to the Lint / Security Scan Gate aggregators and blocking the merge. The guard asserts the base is fetched WITH ancestry (not shallow-only) and the three-dot diff has a two-endpoint (`\|\|  git diff`) fallback, so a missing merge base degrades instead of failing **Scope widened (this PR):** the guard was `lint.yml`-only, which is exactly how the bug survived — the identical shallow-only shape was still live in `security-scan.yml` and `dashboard-control-smoke.yml`, and both hard-failed on the first PR branched from a `main` that then moved (`fatal: c8a89c8...e52f07e: no merge base`, runs 31150981399 / 31150982066). The two consequences differ and both are bad: `security-scan.yml` cascades to the REQUIRED `Security Scan Gate` and blocks the merge loudly, while `dashboard-control-smoke.yml` makes the smoke job report `skipping` — coverage silently lost, job reads green. Discovery is by SHAPE (`"$X"..."$Y"`, any variable names) over `_ci_guard_util.workflow_and_action_files()`; the first version keyed on the literal `"$BASE_SHA"..."$HEAD_SHA"` and hand-rolled the workflow glob, so the identical bug renamed to `"$BASE"..."$HEAD"`, or planted in one of this repo's two composite actions, was invisible (both proven green-while-defeated in the #401 adversarial review). Discovery, so a NEW workflow copying the buggy shape is caught rather than needing to be remembered; `_REQUIRED_IN_SCOPE` is asserted as a canary so a rewrite cannot silently drop a workflow out of reach and make the guard vacuous. | CI robustness |
| `scanner/tests/test_ci_compose_dashboard_hardening.py` | Dashboard container hardening (`docker-compose.yml`, `docker-compose.quickstart.yml`) | the network-exposed static-content dashboard service keeps its CIS hardening — `read_only: true` (+ tmpfs-backed writable paths), `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and `mem_limit`/`pids_limit`. Block-scoped so hardening on a sibling service can't satisfy it — and the scoping is now done on comment-STRIPPED text, because a sibling key written `redis:  # cache sidecar` (two-space indent) did not match the service terminator and merged the sibling into the dashboard block. Reproduced on the real `docker-compose.yml` (2026-08-07 audit): with all six directives deleted from the dashboard service, `missing_directives` returned `[]`; with the same sibling key written plainly it correctly reported all six. Quoted sibling keys (`"redis":`) terminate the block too. As a security toolkit, ClaudeSec must not silently regress its own container's posture | CI robustness, this PR |
| `scanner/tests/test_ci_npm_files.py` | npm package payload (`package.json` `files[]` allowlist) | `docs/` is NOT in `files[]` (it shipped ~38 MB of `.pptx` not used at runtime — incident #261); the six operator-only scripts keep their `!scripts/<name>` negations (cost-xlsx / license / PC-sheet / full-asset-sync / gsheet-auth×2 — else internal tooling publishes to the public registry); `scripts/` stays included (so the negations have effect) and `CHANGELOG.md` stays shipped. `.npmignore` cannot express these — paths under a `files[]` dir override it (confirmed via `npm publish --dry-run`) | #262 |
| `scanner/tests/test_ci_provenance_verify.py` | Published-package supply-chain monitor (`provenance-verify.yml`) | the workflow keeps a `schedule:` trigger (periodic check of the *published* artifact), keeps a `workflow_run` trigger on "Publish to npm" whose `types:` list still includes `completed` (verifies right after each release — the cadence that maps to when the artifact changes; a `workflow_run` key without `completed` would silently never fire), never gains a `pull_request(_target)` trigger (a zero-dep `npm audit signatures` adds no PR value and must not become a flaky required gate / write-token foot-gun) — matched bare OR quoted (`"pull_request_target":`), with the explicit-key `? pull_request_target` form failing closed, since both re-added the trigger past the bare-only regex, and still RUNS `npm audit signatures` — matched in shell **command position** with whole-line comments dropped and quoted-string matches rejected, because the workflow names the command in four of its own comments and in two `echo "::error::…"` strings, so the former bare-substring check stayed green after the real invocation was deleted (inert-guard class; mutation self-tests pin the gutted-workflow case). Verifies npm registry signature + SLSA provenance, OWASP A08 | #263 |
| `scanner/tests/test_ci_injection_surface.py` | No GitHub Actions script-injection surface in any `.github/workflows/*.yml`/`*.yaml` **or composite action** (`.github/actions/**/action.yml`) | no documented-untrusted `${{ github.event.* }}` context (PR/issue/comment/review/discussion title·body, commit message, `head_ref`, `pages.*.page_name`, …) is interpolated DIRECTLY into a `run:` shell body — the OWASP CICD-SEC-4 / GitHub script-injection RCE class. Scans only `run:` bodies (inline + `\|`/`>` block scalars), threshold at the `run:` column so sibling `env:`/`with:`/`if:` keys aren't slurped; `env:`-block and expression-context (`if:`) interpolation and trusted contexts (`github.sha`, `needs.*`) are NOT flagged. Scans workflows AND composite actions — a composite `steps[].run` is shell too, and a planted `${{ github.event.pull_request.title }}` in one left the guard green (two composite actions exist here). The `run` key is matched plain or quoted (`"run":`), and FOUR tripwires FAIL CLOSED on shapes a line scanner cannot reassemble — multi-line flow scalar, a `${{ }}` split across physical lines, the explicit-key `? run` / `: cmd` form, and a multi-line QUOTED inline scalar. The last was a live bypass found by the 2026-08-07 stripper/haystack audit: collection of an inline scalar ends at the first comment-only line, which is EXACT for a plain scalar (PyYAML: a plain scalar cannot resume after a comment — ParserError) but wrong for a quoted one, where `#` is literal content and the scalar keeps folding. PyYAML resolved `run: "echo` / `# not a comment` / `${{ github.event.pull_request.title }}"` to one command carrying the untrusted context while `injection_violations` reported nothing and no tripwire fired. Zero hits across all 18 scanned files, so failing closed on the shape is free. Direction: presence-of-violation; mutation self-tests prove it fires on inline + block-scalar + quoted-key injection, that each tripwire fires on its shape, and that it stays quiet on the `env:` safe-fix and on a YAML comment beside a `run:`. Incident: `npm-publish.yml` inline `VERSION=` (hardened #266); `og-meta-verify.yml` is `pull_request`+`pull-requests:write` | #270, #391, this PR |
| `scanner/tests/test_ci_npm_oidc_floor.py` | OIDC npm-CLI floor pin in `npm-publish.yml` + `provenance-verify.yml` | both workflows' `npm install -g npm` self-upgrade pins the trusted-publishing floor `npm@'>=11.5.1'` (version-shaped) and is NOT a bare `npm@latest` — OIDC `npm publish --provenance` / `npm audit signatures` break below npm 11.5.1, and Node 22 ships npm 10.x, so the floor must be a *visible* pin (Dependabot cannot track a runner binary installed by a shell command). Reverting to `@latest` trips it, and so does pinning BELOW the floor. Ratcheting the floor up is a PAIRED EDIT — the workflow pin and `FLOOR` here must move together or the guard fails; the catalog and the guard docstring both used to claim ratcheting "stays green", which was never true (`assertIn(FLOOR)` cannot see `>=12.0.0`). The behaviour was right and both descriptions were wrong — a reminder that a row is documentation, not evidence. **Comment evasion (fixed 2026-08-10):** whole-line stripping only, so `npm install -g npm@'>=10.0.0'  # OIDC floor is 11.5.1` was not `@latest` AND contained `11.5.1` — the pin could be dropped a full major below the OIDC floor with this guard green and the publish failing only at runtime. Now strips the trailing SHELL comment (`strip_inline_comment_sh` — bash needs no space before `#` after `;`) BEFORE matching, so a commented-out upgrade line cannot satisfy the canary either. Mutation self-tests: `@latest`, short `npm i -g` form, lowered pin, deleted step, trailing-comment and metachar-adjacent-comment evasion, plus a no-false-alarm case for a `#` that is not at a bash word boundary (OWASP A08; SSDF PW.4) | #264 |
| `scanner/tests/test_ci_docker_image_size_gate.py` | Docker image-size cap in `lint.yml` (`dashboard-regression-check`) | the `max_mb=N` size gate is present, breaches the build (`size_mb -gt max_mb` → `exit 1`), and `N <= 600` MB — locking in the ~513 MB scanner image achieved by prowler-provider stripping (was 1.47 GB, cycle #217-#237, issue #11). Loosening the cap back toward the old 1.8 GB or re-adding a stripped ~700 MB provider would slip through; tightening DOWN stays green (CIS Docker Benchmark — minimal image surface). The `exit 1` assertion is scoped to the breach `if … fi` block by balanced depth — unscoped it was satisfied by any of `lint.yml`'s dozen unrelated `exit 1` lines and could not detect removal of this gate's own exit (inert-guard class). Comment-evasion-proof for BOTH the `max_mb` cap and the `exit 1` scan: the whole scan routes through the bash-aware `strip_inline_comment_sh`, so the `;#exit 1` metachar adjacency #383 recorded as a KNOWN OPEN under-strip is closed (primitive from #376) | #11 |
| `scanner/tests/test_ci_lighthouse_perf_gate.py` | Lighthouse Performance/SEO/A11y gate (`lighthouserc.json`, consumed by `lighthouse.yml` against live Pages) | each of `categories:{performance,seo,accessibility}` keeps an `error`-level floor `minScore >= 0.9` (demoting to `warn`/`off` or lowering the floor trips it; ratcheting UP stays green — verified by a mutation test, not just asserted), and `collect.numberOfRuns >= 3` so lhci asserts on the MEDIAN run — reverting to a single run re-introduces the cold-vs-warm-CDN variance that would make the hard Performance gate flaky. Adds the Performance floor from issue #19 (live baseline 0.93 cold / 1.00 warm, 2026-06). **Made non-vacuous 2026-08-10:** the 2026-07-28 audit cleared this guard as "comment-evasion inapplicable by construction (strict `json.loads`)" — true, and beside the point, because nothing proved the assertions fired at all. They were written inline against the real file, so a detector that always passed was indistinguishable. Now expressed as `category_violations()` / `runs_violations()` with mutation tests for a deleted category, `warn`, `off`, a lowered `minScore`, a missing `minScore`, the severity-less bare-object form, and `numberOfRuns: 1` — each also proven against a mutated real `lighthouserc.json`. Malformed rules are now REPORTED rather than raising `AttributeError`/`IndexError`: a gate of the wrong shape is not enforcing, which is a finding, not a test error | #19 |
| `scanner/tests/test_ci_plugin_skills_cli_parity.py` | Marketplace plugin skill ↔ CLI subcommand parity (`.claude-plugin/marketplace.json` ↔ `bin/claudesec-cli.sh`) | every `skills[].command` is `npx claudesec <sub>` where `<sub>` is a real `case` arm in the CLI — a skill pointing at a non-existent/typo'd subcommand would make that installed slash command silently fall through to usage for every user (the manifest and the CLI have no compile-time link); and the `{scan,prowler,compliance,dashboard,setup}` arms stay wired so a CLI refactor cannot silently drop a published surface. Adds the `/prowler` + `/compliance` commands from issue #20 | #20 |
| `scanner/tests/test_ci_lychee_config.py` | lychee link-check exclude allowlist single-source-of-truth (`lychee.toml` ↔ `lint.yml` `link-check`) | `lychee.toml` (undotted, auto-discoverable) exists and the dotted `.lychee.toml` does NOT (a dotted config is never auto-discovered, so it silently goes stale — the original drift); the `link-check` job wires `--config lychee.toml` and carries NO inline `--exclude`/`--exclude-path` flag (so the allowlist cannot drift back into a second copy); `lychee.toml`'s `exclude` includes the release-time `compare/` entry the inline list was missing (the CHANGELOG compare-URL 404 fix) and keeps `node_modules` in `exclude_path`; and `lychee.toml` stays in BOTH the `scanner` and `markdown` change-detection buckets of the `changes` job, so a `lychee.toml`-only PR still triggers this guard AND a live link-check (else the allowlist could change unvalidated at PR time). Comment-stripped + job-scoped; the `v0.23.0` binary pin is owned separately by `test_ci_gate_topology.py` (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_lychee_redirect_sweep.py` | Monthly `lychee-redirect-sweep.yml` stays a scheduled, notifier-only backstop that actually surfaces redirects | workflow exists; `on:` keeps `schedule:`/`cron:` + `workflow_dispatch` and has NO `pull_request` trigger (a broad external-URL fetch on every PR would flake and, once required, block merges — the notifier-only invariant); `permissions: issues: write` (self-healing tracking issue); the lychee run reuses `--config lychee.toml` (single-source excludes) and keeps BOTH teeth — `--max-redirects 0` (report 3xx instead of following to its 200) and strict `--accept '200..=299'` (widening toward the PR job's `100..=599` re-hides rot); `fail: false` (findings become an issue, not a red run); `lycheeVersion: v0.23.0` shared binary pin. Comment-stripped (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_provider_labels_sync.py` | Prowler provider label maps have a single source of truth (`scanner/lib/dashboard_providers.py` ↔ `scanner/lib/output.sh`) | the bash `case` in `output.sh` (`_prowler_dashboard_summary_provider_label`) has EXACTLY the same slug→label pairs as the canonical `PROVIDER_LABELS` — after the refactor consolidated four drifted inline Python dicts into `dashboard_providers.py`, the bash mirror is kept in place for perf (called in a loop) but must not drift; also asserts the shared constants stay complete and consistent (`PROVIDER_LABELS` 16 entries; `PROVIDER_LABELS_SHORT` differs from full ONLY by `kubernetes` → `K8s`, the intentional compact-table distinction; `PROVIDER_SUBTAB_MAP` 7 known keys; `PROWLER_SELECTABLE_ORDER` 7 known keys in the locked selector order). Parser ignores the `*)` default arm and has a mutation self-test | this PR |
| `scanner/tests/test_ci_diagram_gen_canonical_sync.py` | `scanner/lib/diagram-gen.py` single-sources security domains + compliance frameworks | diagram-gen imports `ARCH_DOMAINS` from `dashboard_arch` and `COMPLIANCE_FRAMEWORKS` from `dashboard_compliance`, has NO inline `ARCH_DOMAINS = [` reassignment and NO hand-rolled `frameworks = ["..."]` string list (it derives `frameworks = [f["name"] for f in COMPLIANCE_FRAMEWORKS]`); functional check asserts the loaded module's `ARCH_DOMAINS` IS the canonical object (imported, not copied) — the diagram previously drifted to a stale 6-domain / 6-framework mis-versioned subset (same bug-class as the removed `dashboard_compliance` inline `COMPLIANCE_CONTROL_MAP` fallback). Comment-stripped + mutation self-test (OWASP A08) | this PR |
| `scanner/tests/test_ci_compliance_keyword_guard.py` | `compliance-map.py` control `checks` keyword lists stay free of substring-false-positive tokens (`map_compliance()` marks a control FAIL on a plain substring match, so an over-broad keyword mis-attributes unrelated findings) | REGRESSION PINS: the specific over-broad tokens removed by this PR stay removed from their controls (`policy` from ISMS-P 1.1.1/2.1.1 + ISMS-Simple S-1.1/S-2.1; `api` from 2.6.3; `hsm` from 2.7.2; `waf`+`endpoint` from 2.10.1; `endpoint`+`edr` from 2.10.8; `transfer` from PII cross-border 3.3.4; `port` from CIS-4.1; `node` from CIS-K8s-4.1) AND each edited control keeps >=2 checks (a future edit cannot gut it). COLLISION GUARD: no keyword anywhere in the map is a PROPER substring (keyword != word, so an intended equal-match like 2.6.3/`session` or 2.10.5/`transfer` is not flagged) of a curated benign Prowler-adjacent word list (`support`/`report`/`transport`/`export`/`nodejs`/`node_modules`/`apigateway`/`capital`/`software`/`endpoint`/`dialog`/`login`/`transfer`/`session`); the 12 short (<=3 char) acronyms {cve,iam,kms,mfa,pii,ssl,ssn,sso,tls,vpc,xss} verified NON-colliding so ALLOWLIST is empty. Mutation self-tests: an injected fake `port` keyword fires the detector, and an equal-match keyword stays unflagged (OWASP CICD-SEC-7) | this PR |
| `scanner/tests/test_ci_docker_kcov_parity.py` | Local Docker kcov harness ↔ CI `scanner-shell-coverage` parity (`scripts/verify-shell-coverage-docker.sh` ↔ `lint.yml`) | the harness's `INCLUDE`/`EXCLUDE` declarations equal (as sets) CI's kcov `--include-pattern`/`--exclude-pattern`, and its `FLOOR` equals CI's enforced `threshold` — so the local pre-push mirror measures the exact same SUT files and floor as CI (drift already happened in #336: local `INCLUDE` was missing `checks_credentials.sh`, and `test_run_category_checks.sh` had to be added to `EXCLUDE` in both places at once). Also asserts CI's own tty vs non-tty kcov invocations use identical patterns (a single canonical value to compare). Comment-stripped (a pattern living only in a comment cannot satisfy the check) + mutation self-tests for each drift class | this PR |
| `scanner/tests/test_ci_scanner_lib_reachability.py` | No NEW unreachable (dead) top-level function in the kcov SUT libs (`scanner/lib/{checks,checks_credentials,output,output_prowler}.sh`) | the bash coverage floor measures "executed by a test", not "reachable from the scanner", so a test-only function stays fully covered while being dead (the class removed in the dead-code PR: `compute_trend`, `load_scan_history`, `_html_findings_rows*`, `html_escape`, `api_key_found`, `compliance_map`). For each top-level SUT function the guard requires >=1 reference in the production corpus (`scanner/claudesec` + `scanner/checks/**` + `scanner/lib/**`), comment-stripped, own-def-line excluded, whole-word (a substring/comment does not count). Regression-pin: asserts the dead set EQUALS the documented `KNOWN_UNREFERENCED` baseline (`_prowler_dashboard_summary`, `count_files`, `datadog_validate_api_key` — removal candidates), so a NEW dead function fails AND a stale allowlist entry fails once it is wired-up/removed. Conservative (only under-reports), so it never false-blocks a reachable function. Mutation self-tests | this PR |
| `scanner/tests/test_ci_no_code_injection_regression.py` | No CWE-94 code-injection sites where a bash variable is interpolated directly into a `python3 -c "..."` program body OR an unquoted heredoc feeding an interpreter (`scanner/claudesec`, `scanner/lib/**`, `scanner/checks/**`, `scripts/**`, `hooks/**`) | for every DOUBLE-quoted `python3 -c "..."` / `python -c "..."` site (captured across multi-line bodies, comment-stripped first, concatenation-aware for adjacent quoted segments), flags a `$NAME`/`${...}`/`$(...)` bash expansion inside the program text — splicing a shell value into Python source before parsing is OWASP A03:2021 / CWE-94 injection. ALSO flags an UNQUOTED heredoc (`<<EOF`/`<<-EOF`) whose owning command is a code-executing interpreter (`python`/`python3`/`sh`/`bash`/`awk`/`perl`/`node`/`ruby`, basename-matched, continuation-line-aware) — a quoted delimiter (`<<'EOF'`/`<<"EOF"`) disables expansion and stays safe; a heredoc feeding a non-interpreter (`cat`, `kubectl`, `gh api`, ...) is data, not code, and is never flagged. Regression-pin: asserts the violation set EQUALS the `KNOWN_INJECTION_SITES` baseline, empty after this PR's fix (`scripts/run-prowler-k8s.sh`, `scripts/check-prowler-python-ceiling.sh`, `scripts/sync-scan-to-dashboard.sh` moved the value to the environment, read via `os.environ`), mirroring the #346 `output_prowler.sh`/`prowler_compliance_summary.py` fix. Single-quoted `-c '...'`, argv/stdin/env-var-passed values are explicitly out of scope (safe); quote-concatenation in a `-c` argument is best-effort covered for adjacent quoted segments only (unquoted concatenated runs are not content-checked). Mutation self-tests | this PR |
| `scanner/tests/test_ci_no_raw_output_interpolation.py` | The hand-built JSON / HTML / URL output-assembly sinks in `scanner/lib` keep routing tainted (env / filename / scanned-content) values through an escaper — a source-level regression pin complementing the per-sink behavior tests (`test_output_functions.sh` / `test_datadog_json_payloads.sh` / `test_prowler_dashboard_summary.sh`) | For each known sink, against comment-stripped + continuation-joined source: asserts the required escaper INVOCATION is present AND the specific known RAW-interpolation string is ABSENT. Pins `output.sh::print_json_summary` → `_json_escape_str "$SCAN_DIR"` (`"scan_directory"` not raw `$SCAN_DIR`, #361); `datadog.sh` → `_json_escape_str`/`_url_encode` on `dd_service`/`dd_env` (intake/query JSON #361 + `ddtags=` URL query #363, neither raw); `output_prowler.sh::_prowler_dashboard_summary` → `_prowler_html_escape "$label"` (#362, filename-XSS). Deliberately a narrow pin over KNOWN sinks, not a general raw-interpolation static analyser (false-positive-prone on numeric/enum fields). Mutation self-tests: a removed escaper usage and a reintroduced raw interpolation both fire the detector | this PR |
| `scanner/tests/test_ci_dashboard_control_smoke.py` | Dashboard control-liveness smoke stays hermetic, path-gated, and bounded for BOTH dashboards (`dashboard-control-smoke.yml` + `scanner/tests/{dashboard-control-liveness.mjs,test_dashboard_control_liveness.sh,asset-dashboard-assertions.js,test_asset_dashboard_control_liveness.sh,fixtures/asset-dashboard-data.json}`) | the workflow sets `CLAUDESEC_DASHBOARD_OFFLINE=1` (else the generator makes live GitHub API calls and can hang the job — #190) AND **each** harness wrapper self-exports it too (belt-and-suspenders, not CI-env-dependent); the `changes` job exposes a `dashboard` output and the `smoke` job is path-gated `if: needs.changes.outputs.dashboard == 'true'` (docs-only PRs skip the browser smoke; intentionally NON-required, a simple path-gate not an `always()` aggregator — that pattern is reserved for required checks per the paths-ignore/#186 incident); **each** browser step carries a per-step `timeout-minutes` (a hung headless Chrome can't burn the job budget) — asserted inside the isolated `- name:` step block that invokes THAT wrapper, because unscoped it was satisfied by the workflow's JOB-level `timeout-minutes` keys and could not detect removal of the per-step cap (inert-guard class; mutation self-tests pin job-level, wrong-step, and cross-suite cap leakage) — and invokes the real wrapper; every harness file exists on disk (a workflow pointing at a deleted script is a silent no-op). The path-gate is **EXECUTED, not merely mentioned**: the `grep -E` ERE is extracted from the workflow and run against each covered path (`claudesec-asset-dashboard.html`, both wrappers, the shared runner, the asset suite and its fixture, `scanner/lib/**`, the workflow itself) plus control paths that must NOT match — including the generated `claudesec-asset-dashboard-live.html`, which the `$` anchors correctly reject. Asserting only that the YAML mentions a path proves nothing, and a path-gated job that never runs reads green: the exact mode that left `npm-audit` dark ~7wk and the nightly DAST skipped ~42 nights (#394/#396/#397). Comment-stripped presence checks (OWASP CICD-SEC-1) | this PR |
| `scanner/tests/test_ci_guard_assertion_scoping.py` | **Meta-guard** — no `test_ci_*.py` guard makes a POSITIVE presence assertion against the RAW, whole-file text of the artifact it protects | AST scan (stdlib `ast`, not text) of every guard file: `assertIn(tok, raw)` / `assertRegex(raw, pat)` / `assertTrue(tok in raw)` where the haystack is a name bound directly to `Path.read_text()` is an INERT assertion — commenting the control out leaves the token in the file, so the guard reads green while the control is dead, which is worse than no guard (a reviewer takes the green as proof). Exempts the two non-inert shapes: NEGATIVE assertions (raw scanning for a FORBIDDEN token only over-reports — a false alarm, never a bypass) and LINE-ANCHORED regexes (`(?m)^\s*token`, which a `#`-commented copy cannot satisfy). Regression-pin: the detected set must EQUAL `KNOWN_RAW_PRESENCE_ASSERTIONS`, currently **empty** — a new offender fails AND a stale exemption fails once its site is fixed. Generalizes the two inert guards #383 found by hand (`provenance_verify` `npm audit signatures`, `docker_image_size_gate` `exit 1`) into a check that runs on all 40 guards and on every new one. Under-reports by design (never false-blocks). Mutation self-tests | this PR |
| `scanner/tests/test_ci_strip_before_match.py` | **Meta-guard** — a guard COMMENT-STRIPS before it MATCHES, including when the match is a BLOCK BOUNDARY and including inside its own helper functions | AST scan of every `test_ci_*.py` plus the shared `_ci_guard_util.py`. Two detectors, both generalized from a hand-found bypass in the 2026-08-07 stripper/haystack audit, each with a PoC on the real tool AND the consumer. **match-on-raw-param**: `conditional_body_from` comment-stripped the BODY it returned but searched for the block ANCHOR in raw text, so one line — `# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi` — anchored the scan inside itself and returned ` exit 1; ` as the body; bash exited 0 on a CRITICAL finding while the guard behind the REQUIRED `Security Scan Gate` reported the merge block intact. **strip-after-extract**: `_strip_comments(_dashboard_block(text))` let a sibling service written `redis:  # cache sidecar` (two-space indent) slip past the block terminator, so the sibling's directives satisfied the dashboard's — reproduced on the real `docker-compose.yml` with all six directives deleted and `missing_directives` still `[]`. Stripper ALIASES are resolved to a fixed point (`active_text`, `_strip_comments`, …), which is what turned the 2 hand-found sites into 3 detected ones (measured on base `00b33ed`: `compose_dashboard_hardening:83`, `lychee_config:128`, `security_gate:53` — an earlier draft said 4); a file READER (`read_text`/`glob`) is excluded from detector B, the only two false positives it has had. Scope claim is deliberately narrow: it does NOT detect over-stripping in general — "a stripper must never remove a line containing the asserted token" is FALSE by design, since removing a `#`-commented copy or another job's `exit 1` is exactly what scoping is for — only the mechanizable ORDERING precondition. Regression-pin: detected set must EQUAL `KNOWN_STRIP_ORDER_EXCEPTIONS`, currently **empty**; an extractor whose boundaries ARE comments (a `# NET-005` banner) is the legitimate exception shape. Under-reports by design. Mutation self-tests on both real shapes | this PR |
| `scanner/tests/test_ci_drift_watch_not_silent.py` | `protection-drift-watch.yml` never degrades SILENTLY | when `REPO_ADMIN_TOKEN` is absent the workflow must ESCALATE, not just log: a step gated on `token_present == 'false'` must call `gh issue create/edit`, and the existing-issue lookup must be reachable in that same condition (else it opens a duplicate every run, which gets muted — silence again). Incident: Actions has NO `neutral` conclusion for a regular job (success/failure/cancelled/skipped only; the Docker exit-78 neutral was removed in 2019), so the original log-and-exit-0 branch reported **success** daily while the drift check had never once run since #251 — branch protection unmonitored with no signal (`actions/secrets` `total_count: 0` confirmed the absence). Also pins the `schedule:` trigger and forbids `pull_request(_target)` (a notifier must never become a required check — its header always said so, nothing enforced it). Comment-stripped, step-attributed scan; deliberately does NOT require the job to FAIL (daily-red notifier = fatigue, documented trade-off). Mutation self-tests including the REAL pre-fix workflow | #396 |
| `scanner/tests/test_ci_pr_trigger_scope.py` | The two REQUIRED workflows (`lint.yml` → `Lint`, `security-scan.yml` → `Security Scan Gate`) keep an UNSCOPED `pull_request:` trigger | no `branches:` / `branches-ignore:` and no workflow-level `paths:` / `paths-ignore:` under `pull_request:`. Two opposite failure directions of one root cause — a workflow-level trigger filter on a required check. `branches:` filters by the PR's BASE ref, so `branches: [main]` hid both required checks from stacked PRs entirely: PR #384 (base = a feature branch) got 3 checks with neither required context, the same branch retargeted to `main` (#385) got 28 — the change was unverifiable until its base merged. `paths-ignore:` is the #186 mode: the required check never reports for a PR that DOES target `main`, so protection blocks the merge forever. Not symmetric — removing `branches:` is strictly additive (PRs targeting `main` behave identically, so #186 cannot recur), adding `paths-ignore:` IS #186. Job-level gating with the `changes` job + an `always()` aggregator stays the sanctioned pattern. Scoped to the two required workflows only: `dast-baseline.yml` legitimately carries both filters and is out of scope. Block membership is by indentation under the `on:` → `pull_request:` key, so a sibling `push: branches:` cannot false-trip it and `pull_request_target:` is never matched; flow-style values on the key line are captured. Both the `pull_request:` key and each forbidden filter key are read bare OR quoted, and the explicit-key form fails closed — `"branches": [main]` silently restored the #384 loss past the bare-only regex. Mutation self-tests | #386, #393 |
| `scanner/tests/test_ci_dead_schedule_arm.py` | Path-gated jobs keep a REAL periodic escape hatch | for every workflow, IF any job `if:` gates on the `schedule` event THEN the workflow's `on:` must declare `schedule:` — direction is CONSISTENCY, so removing the trigger while leaving the arms trips it, and so does adding an arm to a workflow with no trigger. `lint.yml` had SEVEN such arms and no `schedule:` trigger (verified over 1118 runs: 654 pull_request + 464 push, zero schedule), so `npm-audit` had ZERO real executions for ~7 weeks / 117 main commits and `pip-audit` accumulated `setuptools` PYSEC-2026-3447 unnoticed until an unrelated PR touched a requirements file and ate the failure. A `skipped` job reads as green, so nothing alerted. The arm is detected by CO-OCCURRENCE of `github.event_name` and a quoted `schedule` token on one line rather than by enumerating comparison shapes — the first attempt enumerated `==`, the reversed form and `contains(...)`, and the `contains` pattern immediately failed on `fromJSON('["schedule",…]')` because `[^)]*` cannot span the inner `)`. `? schedule` fails closed. Cadence is NOT checked (no policy set). Mutation self-tests, including the real pre-fix `lint.yml` | #394 |
| `scanner/tests/test_ci_requirements_pinned.py` | Every requirement in every ROOT `requirements*.txt` keeps an exact `==` pin, and every manifest a workflow installs is one this guard reads | direction is PIN, not floor: `>=`, `~=`, `<=`, `!=`, a bare name, a `${VAR}` version, a PEP 508 direct reference and `-r`/`-c`/`-e` indirection all trip it, while changing a pinned version stays green (that reviewable diff is the point). Incident, measured on `GET /dependency-graph/compare` (2026-08-07) — the two manifests were blind to DIFFERENT degrees, and conflating them was the first draft's error: `requirements-scripts.txt` (unconstrained) recorded `version: ""`, nothing to match, and its history proves the effect (two commits ever, never touched by Dependabot); `requirements-ci.txt` (`>=`) recorded the RANGE `Pillow >= 12.3.0` and Dependabot DID bump it (#141/#236/#272/#321) — not blind, weaker, though the SBOM purl stayed versionless (ten of eleven pypi entries, vs `pkg:pypi/pyyaml@6.0.3`). The shared reason is unreviewed CI input: a floating range resolves at job time, and `pip-audit` is path-gated on `requirements.*\.txt` so drift is not audited AT THE MOMENT IT HAPPENS — it waits for the weekly `schedule:` arm added in #394. Five bypasses were found by adversarial review of the first version and each is now a `test_bypass_*` PoC: a prose comment ending in `\` absorbed the next line and deleted a live `pytest>=9.1.1` from the scan (pip's `join_lines` exempts comments; the shared `join_continuations` does not, so this guard carries its own), base64 `==` padding in a direct reference, `--extra-index-url …?t=YQ==`, a VCS ref, and `pytest==${VAR}`. Options are judged against an enumerated SAFE set (`--require-hashes`, `--only-binary`, …) so an unknown option is REPORTED, never accepted. Known limits with direction: `--require-hashes` and direct references are REJECTED though stronger than `==` (false positive — extend the guard first if adopted); discovery is ROOT-ONLY (bounded false negative — a repo-wide `rglob` red-lit dev machines on untracked `build/`/`scratch/` dirs and `git ls-files` is barred by the no-subprocess rule, so the gap that mattered is closed directly by cross-checking every `-r <path>` in `.github/workflows/**`). Manifest set asserted as an EQUALITY, so a new root manifest fails until listed | #398 |
| `scanner/tests/test_ci_template_pin_policy.py` | The workflow templates ClaudeSec INSTALLS into other repositories are SHA-pinned to the refs this repo runs; the ones it only illustrates say they are not | codifies the pin policy #415 left open as "a PRODUCT decision". The two halves of `templates/` are different artifacts: `scripts/setup.sh` copies `codeql.yml` and `dependency-review.yml` straight into a user's `.github/workflows/`, where a mutable tag is a supply-chain exposure WE created (OWASP CICD-SEC-3; a tag is repointable — `tj-actions/changed-files`, 2025), so those are 40-hex pinned; `prowler.yml`/`sbom.yml`/`scorecard.yml`/`security-scan-suite.yml` are copy-me examples and stay tag-pinned with a note telling the reader to pin before adopting. The split is about who can keep a pin FRESH, not aesthetics: Dependabot's `github-actions` ecosystem scans `.github/workflows/` and never an arbitrary directory, and the repo proved the consequence — the templates carried a hand-written `actions/checkout@b4ffde65 # v4.1.1` while this repo moved to `# v7.0.1`, **three major versions of silent rot, shipped to every `setup.sh` user**. So installed pins must MATCH ours (`test_installed_template_pins_match_ours`), which makes our own Dependabot the upstream freshness signal and the user's Dependabot (via the installed `templates/dependabot.yml`) the downstream one; no pin depends on a human remembering. Example templates get no pin they cannot keep — those actions are not run here, so there is no ref to mirror and a SHA would rot exactly as the checkout pin did. The INSTALLED SET IS DERIVED from `setup.sh`'s `cp` lines (comment-stripped, continuations joined), so a third installed template is covered the day it lands (#407/#413's generalisation lesson) and an installer this guard can no longer parse fails a vacuity canary instead of scanning an empty set. Mutation self-tests: a tag reintroduced, a quoted key, a quoted VALUE, `? uses` failing closed, drift from our ref, the note reworded away, a new/commented-out/line-wrapped `cp`, plus two no-false-alarm directions (a ref in a comment; an action we do not run). **Found while building it:** `test_ci_gate_topology`'s SHA-pin matcher could not see a QUOTED VALUE — `uses: "actions/checkout@main"` in the real `lint.yml` left that guard at **15 passed** with a mutable branch ref in a required workflow. The matcher now lives once, in `_ci_guard_util.uses_refs` | this PR |

| `scanner/tests/test_ci_security_gate_behaviour.py` | The `Security Scan Gate` severity block actually FAILS on a CRITICAL — proven by RUNNING it | direction is BEHAVIOUR, not presence: reformatting or reordering the gate stays green, deleting it or making it unreachable AT THE SHELL LEVEL trips it. Replaces a line scanner that was defeated three times running (1 shape, then 4, then 6 — quoted string, heredoc body, multi-line YAML scalar, space-indented heredoc terminator, two heredocs on a line, split/non-word delimiters, plus the shell reachability shapes `if false; then`, an unreachable `elif` and `case … never) exit 1`, which no text matcher reaches at all). ADR-001 §4: a third patch to an enumeration is a redesign signal. Executing collapses the whole class — either the process exits non-zero on a CRITICAL or it does not. **Execution safety is the load-bearing part**: a first prototype used a greedy regex, captured the rest of the file and really did start `python3 -m http.server 8080` and `npx lighthouse` on a developer's machine. Three fail-closed guardrails: indentation-bounded extraction, a `_MAX_BLOCK_LINES` ceiling, and an `_ALLOWED_COMMANDS` allowlist that ABORTS before running anything unrecognised (a legitimate new command fails the test and demands a reviewed one-line update). The allowlist's statement splitter is QUOTE-AWARE — a naive split cut inside the gate's own `grep -ci '✗.*critical\|CRITICAL.*Fail'` and invented two phantom commands, the ERE-pipe class this repo has hit before. **WORKFLOW-level disables are a separate concern and each needed its own check**: executing the `run:` body cannot see the step's `if:` or `continue-on-error:` keys, so either one left the suite green while the step never ran (or its `exit 1` was discarded by the runner). `continue-on-error` had ZERO enforcement anywhere in the repo and is already used in three workflows, so adding it to the gate would read as routine. Both are now asserted on the step mapping; job-level `if:` stays allowed (`scan` is legitimately path-gated and the gate treats `skipped` as passing). **Extraction is step-SCOPED twice over**, after review showed the first version was not: `- name:` matched by substring and first-wins, so a preceding `… (advisory preview)` step shadowed the real gate; and the `run:` key was found by scanning FORWARD from the step, so `run: |-` — semantically identical, a one-character edit — walked out of the step into the `lighthouse` job and the suite really did execute `python3 -m http.server 8080` and `npx lighthouse`. Now: exact name equality, duplicates REFUSED rather than guessed, `run:` taken from inside the step block, and only a literal `|`/`|-`/`|+` scalar accepted (folded `>` changes shell meaning → fails closed). The allowlist is a PRECONDITION of `run_gate`, not a separate assertion — it previously stopped nothing, and under `unittest`'s alphabetical order the execution test ran first. The fixture is pinned to `scanner/lib/output.sh`'s real `✗ FAIL … (CRITICAL)` shape, so the gate's grep and the emitter cannot drift apart silently. Mutation self-tests cover five shell disable-shapes and two workflow-level ones, each with a no-op guard, plus ALL THREE directions: a CRITICAL must fail, a clean scan must pass, and a HIGH must WARN and still exit 0 (#206 policy — only CRITICAL blocks a merge). The HIGH direction was the one thing the older text guard uniquely covered, so moving it here is what let `test_ci_security_gate.conditional_body_from` be deleted outright (#406) and cleared the last `KNOWN_STRIP_ORDER_EXCEPTIONS` entry. It carries its own mutation self-test in the OPPOSITE direction to every other case — the mutant makes the gate MORE aggressive (blocking on HIGH), because an assertion that only ever sees a passing gate cannot be shown to fail | this PR |
| `scanner/tests/test_ci_required_graph_not_disabled.py` | NO job in a REQUIRED check's dependency graph can be neutered by a runner-consumed key | #404 proved the severity gate by EXECUTING it, which closes the shell-level class completely — but execution is blind to keys the RUNNER consumes, and #404 asserted those for exactly ONE step. The 2026-08-08 audit measured the rest: required contexts `["Lint","Security Scan Gate"]`, `lint-gate` 15 dependencies + itself, `security-scan-gate` 3 + itself — **20 jobs, of which 1 step was protected**. Every one concludes `success` from a single job-level `continue-on-error: true`, and BOTH aggregators accept `success`/`skipped` from every dependency. Reproduced on the real files: `security-scan-gate` + job-level `continue-on-error` makes the required check itself conclude success regardless of its own `sys.exit(1)`, while `test_gate_runs_always`, `test_gate_aggregates_required_needs` and `test_gate_passset_not_loosened` ALL stay green (they inspect `if: always()`, the `needs:` list and the pass-set string — none of which the mutation touches); `dependency-review` + job/step `continue-on-error` or step `if: false` lets a HIGH/CRITICAL advisory or a GPL/AGPL violation stop blocking while `test_ci_gate_topology` and `test_ci_required_jobs_exist` both stay green. **Measured end-to-end**: on a mutated real `security-scan.yml`, the four pre-existing gate guards (63 tests) ALL PASSED and this one failed. Generalisation is the point — guarding the three sites the audit named would leave 17 jobs of the same class open, so it walks the graph from the codified `DESIRED_CONTEXTS` and covers jobs added later too. `continue-on-error` is forbidden at job AND step level (for a gating job there is no legitimate use — the key exists to make failure not count); legitimate steps are ALLOWLISTED by `(workflow, job, step)`, currently one (Codecov upload, whose coverage FLOOR is separately and blockingly enforced). Step-level `if:` is ALSO forbidden unless it is bare `always()` or allowlisted (2 entries). The first version of this guard excluded that key, arguing conditional steps are ordinary — an argument sized against every workflow in the repo rather than the graph, which holds 105 steps of which exactly SEVEN carry an `if:` (five bare `always()`). The gap was real and measured: step `continue-on-error` on `Run gitleaks` FAILED this guard while step `if: false` on the SAME step passed it 14/14, because a job whose only failing step is skipped concludes `success` by DEFAULT — no job-level key needed. Direction is an ALLOWLIST of legitimate conditions, never a blocklist of disable shapes: enumerating ways to spell "false" is what got defeated three times in #402/#404, so a mutation test pins six conditions that are not literally `false` (`${{ 1 == 2 }}`, `github.event_name == 'never'`, `always() && false`, ...) and must still be caught. `always()` is exempt by MEANING — it forces the step to run — and only in its bare form. Fails CLOSED on an unresolvable graph, with `test_graph_is_populated` as the vacuity canary. Mutation self-tests cover job-level on both required checks and on a dependency, step-level, the quoted `"continue-on-error":` spelling, the `? continue-on-error` explicit-key form, a dedented `steps:` list, and both no-false-alarm directions.  **Extended 2026-08-10 — a second runner-consumed class, REDIRECT.** The audit rule this guard's own retrospective added ("list the text an executed proof cannot see") found `working-directory:` and `shell:`, which do not SKIP a step — they let it run, report success, and check something else. Proven on the real `security-scan.yml`: one line, `working-directory: docs` on the `Check for critical/high failures` step, left the ENTIRE suite green (**1945 passed**) while the required `Security Scan Gate` stopped blocking a CRITICAL. The mechanism is arithmetic: the gate greps `scan-output.txt` relative to cwd, `grep` on a missing file is swallowed by `|| true`, `CRITS` becomes empty, and `[ "" -gt 0 ]` errors — but a failing `[` is a CONDITION, which `bash -e` deliberately does not treat as fatal, so the `exit 1` never runs and the step exits 0 (verified by execution: cwd=root → `Critical: 1` → exit 1; cwd=docs → an EMPTY `Critical:` count → exit 0). `shell: cat {0}` is strictly worse — it prints the script instead of running it. #404's executed proof is blind to both by construction: it runs the `run:` body in the test's own cwd under its own interpreter. Covered at step level, at job level, and at WORKFLOW level via `defaults.run.*` (one top-level block redirects every job in the file, and neither a job scan nor a step scan looks at column 0), in bare, quoted and `? explicit` spellings. Population counted inside the graph rather than across the repo — the rule #407 itself got wrong: of 105 steps and 20 jobs, `working-directory` 0, `shell` 0, `defaults` 0, so `ALLOWED_STEP_REDIRECT` ships EMPTY. After the fix the same mutation produces 9 failures. That dedent case caught a real bug in this guard's own extractor while it was being written — a block sequence may legally sit at its parent key's indent, and the first `_steps_of` broke on `indent <= job_col`, reporting clean on a workflow whose steps it had never looked at. **Extended 2026-08-11 — the extractor's own blind spot.** Its step-item collector ended a block at any non-blank line at or left of the dash column, and a `#` comment matches that while YAML does not: a comment at the `scan` job's key column (at the job's END — placement decides, at the START it truncates `steps:` away and reads as caught) left `jobs.scan.continue-on-error = True` live per PyYAML with this guard plus the behavioural one at **61 passed**, and the same shape at a step's dash column did it one level in. Fixed by the shared `block_ends_at`, which then exposed that FIVE `min(indent)` key-column derivations existed — including one inline in `graph_violations` — all of which inherit the hazard the moment comments live inside a block: a column-2 divider comment dragged `job_col` to 2 so `_declares(block, 2, 'continue-on-error')` looked a level out from the key. Now `key_column`. Three mutation tests, one of them a no-false-alarm direction (a bare comment is not a disable, and a shallow one must not blind the step scan — on `main` it produced `7 failed`, so that half is a false alarm rather than a bypass) | this PR |

### Related enforcement (not a pytest guard)

- **`workflow-fork-guard`** (`lint.yml`) audits `pull_request_target` workflows
  for the head-repo fork guard (OWASP A08); wired into `lint-gate.needs` so it is
  merge-blocking (#203).
- **`Security Scan Gate` severity block** (`security-scan.yml`) fails the build
  on any CRITICAL scanner finding; HIGH findings warn only (#206).

## Why two required checks matter

`main` branch protection requires exactly two status checks: **`Lint`** (the
`lint-gate` aggregator in `lint.yml`) and **`Security Scan Gate`** (the
aggregator in `security-scan.yml`). Both use the `if: always()` +
"`skipped` counts as success" pattern so that path-gated jobs don't block
docs-only PRs (see the `paths-ignore` vs branch-protection incident, #186).

The consequence: **any job that is not wired into one of these two aggregators'
`needs:` is invisible to branch protection** — it can fail without blocking a
merge. That is precisely the gap the topology guards
(`test_ci_gate_topology.py`, `test_ci_security_gate.py`) exist to catch.

The topology guards check that every *present* job is gated; they cannot see a
job that is **deleted entirely** (a removed job simply leaves the gated set, and
the aggregator stays green). `test_ci_required_jobs_exist.py` closes that
complementary gap by asserting the load-bearing security jobs still exist.

## Unguarded invariants backlog

A standing list of CI invariants that are **not yet** protected by a guard,
triaged by the same bar used to add one (an incident, past or plausible, where
*silent* weakening disables enforcement — no incident means it likely is not
worth a guard, to avoid sprawl). Reviewed 2026-06-19; re-triaged 2026-06-22
(all Tier-3 workflows confirmed KEEP-AS-MONITOR — decision unchanged; the
`workflow_run` trigger added to `provenance-verify.yml` in #263/#264 is already
covered by `test_ci_provenance_verify.py`). **Quarterly ADR-001 adversarial
audit 2026-07-28** (issue #297): all 38 `test_ci_*.py` guards re-audited — see
"Quarterly audit 2026-07-28" below for the comment/unhandled-form findings fixed
and the matcher-completeness backlog opened. **Re-reviewed 2026-08-10** (see
"Backlog sweep 2026-08-10" below): the Tier-3 list was checked against the live
workflow set for the first time and was found to be *stale by omission* —
`guard-audit-reminder.yml` had never been triaged into it.

### Tier 2 — incident-backed (now implemented)

Both former Tier-2 candidates landed in #258 and are now in the Catalog above:

- `test_ci_prowler_version_pinned.py` — exact `prowler==${PROWLER_VERSION}` pin
  in `Dockerfile` (#237).
- `test_ci_dockerfile_base_pinned.py` — `@sha256:` digest pins + `alpine:3.20`
  minor freeze + version-agnostic site resolution (#233/#234/#220).

### Tier 3 — monitor only (no guard yet; would be sprawl)

- **Auxiliary scheduled workflows** — `prowler-python-watch.yml`,
  `dashboard-refresh.yml`, `og-meta-verify.yml`: none is a required status check
  and none runs on `pull_request_target` with a write token, so silent weakening
  does not disable a merge gate. Add a guard only if one later gains enforcement
  responsibility (becomes required, or gains a write-token PR trigger).

  **Decision (2026-06-19): no dedicated "promotion-watch" guard.** Both ways one
  of these could *become* enforcement-bearing are already covered, so a guard
  asserting "they stay non-required / non-`pull_request_target`" would be
  redundant (the no-incident-it-catches bar fails):
  - *Gains a `pull_request_target` trigger* → the `workflow-fork-guard` job audits
    **every** `pull_request_target` workflow for the head-repo fork guard and is
    wired into `lint-gate.needs`, so a promoted-but-unguarded workflow fails the
    required `Lint` check.
  - *Becomes a required status check* → that is branch-protection drift:
    `test_ci_branch_protection_codified.py` pins `DESIRED_CONTEXTS` to exactly
    `Lint` + `Security Scan Gate`, and `protection-drift-watch.yml` reports any
    live divergence nightly.

  (`og-meta-verify.yml` already runs on `pull_request` — not `_target` — with
  `pull-requests: write`; a switch to `pull_request_target` is the case the
  fork-guard job catches.)
- **DAST trigger invariants** — `dast-baseline.yml` (`pull_request`) and
  `dast-full-scan.yml` (`schedule:`) triggers are already asserted by
  `test_ci_security_gate.py`; no separate guard needed.

- **`guard-audit-reminder.yml`** — the quarterly ADR-001 audit notifier. Added to
  this list 2026-08-10; it had been the ONE workflow with zero mentions anywhere
  in this document, which is itself the finding: the Tier-3 list was written as a
  point-in-time triage and nothing re-checked it against the live workflow set,
  so a workflow added later was neither guarded nor consciously un-guarded.

  **Decision (2026-08-10): KEEP-AS-MONITOR, no dedicated guard.** Its header
  states two invariants — never `pull_request`/`pull_request_target`, never a
  required status check — and both are covered by the same two mechanisms that
  cover the other Tier-3 workflows (`workflow-fork-guard` in `lint-gate.needs`;
  `DESIRED_CONTEXTS` in `test_ci_branch_protection_codified.py` plus the nightly
  `protection-drift-watch.yml`). Note the asymmetry with
  `protection-drift-watch.yml`, which DID earn a guard
  (`test_ci_drift_watch_not_silent.py`): that one is a *drift detector* whose
  silence means "no drift", so a degraded notifier actively misleads. This one
  only opens a reminder issue; if it silently stops firing, the audit is late,
  which is visible the moment anyone looks at the issue list. Different blast
  radius, different tier. Promote it if it ever gains enforcement responsibility.

- **`uses:` version-comment correctness vs the pinned SHA.**

  **Decision (2026-06-24): no version-comment guard.** A guard asserting the
  `# vX.Y.Z` comment matches the pinned SHA's actual tag would need to resolve
  SHA → tag via the GitHub API — a **network call**, which violates the
  stdlib-only / offline / no-subprocess constraint every guard here holds.
  A weaker *presence* check (every `uses:` has *some* version comment) is
  offline-feasible but would NOT have caught the real incident (a Dependabot bump
  that updated the SHA but left a STALE `# v4.2.2` comment on a `v7.0.0` SHA,
  normalized in the checkout-v7 cleanup) — it only catches a *missing* comment,
  not a wrong one. Crucially, the comment is **cosmetic**: `test_ci_gate_topology.py`
  already pins the 40-hex SHA (the actual supply-chain control), so a wrong
  comment is a readability/doc-accuracy wart, not a security regression — below
  the incident bar. Mitigation is a one-time normalization on each major action
  bump, not a guard.

### Stripper / haystack-narrowing audit 2026-08-07 (ADR-001 §6)

Scope: every function in `scanner/tests/test_ci_*.py`, `_ci_guard_util.py` and
`test_dashboard_no_inline_handlers.py` that NARROWS a haystack before an
assertion — comment strippers, block extractors, `case`/`esac` scopers,
step-block attribution, `on:`-block extraction, quote-state trackers,
continuation joiners. The question asked of each: *can it delete or skip a region
that CONTAINS the control being asserted, so the guard reads green while the
control is dead or absent?* Every finding below carries a runnable PoC on BOTH
sides — the real tool (bash / PyYAML / an HTML parser) and the consumer guard
function returning "invariant holds" — and each PoC is landed as a self-test.

Confirmed and fixed:

- **CRITICAL, `test_ci_security_gate.conditional_body_from`** — the block ANCHOR
  was searched in RAW text while only the BODY was comment-stripped. One line,
  `# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi`, anchored the scan inside
  itself and returned ` exit 1; ` as the body. Bash exited 0 on a CRITICAL
  finding (merge allowed) while the guard behind the REQUIRED `Security Scan
  Gate` certified the merge block intact.
- **HIGH (live), `test_ci_docker_image_size_gate.breach_block`** — the balanced
  if/fi counter matched `\bif\b` anywhere, so the English word in
  `echo "… check the base image if this is unexpected"` unbalanced it; the
  function then returned the rest of `lint.yml` and an unrelated prowler `exit 1`
  9.5 KB away satisfied the gate. Measured: a 900 MB image against a 600 MB cap
  exited 0 in bash while the guard stayed green.
- **HIGH (latent), same root cause in `conditional_body_from`** — commenting the
  severity block out line-by-line leaves the count unbalanced, so the body ran to
  EOF; one ordinary `… || exit 1` step anywhere later in `security-scan.yml`
  turns that canonical "temporarily disable" edit green.
  **Both are now CLOSED, by different routes.** The docker-size half was fixed in
  place: it counts `if` only in bash command position and fails CLOSED when
  unbalanced. `conditional_body_from` was DELETED (#406) — three line-scanner
  fixes had each been defeated, so the invariant moved to a check that executes
  the gate and the defective function went with it. Deleting the consumer is a
  legitimate way to close a strip-order finding; for a defect this class it is
  the only one that scales.
- **CRITICAL, `test_ci_injection_surface.run_block_lines`** — collection of an
  inline `run:` scalar ends at the first comment-only line. That is EXACT for a
  plain scalar (PyYAML raises ParserError if one resumes after a comment) and
  WRONG for a quoted one, where `#` is literal content and the scalar keeps
  folding. PyYAML resolved `run: "echo` / `# not a comment` /
  `${{ github.event.pull_request.title }}"` to one command carrying the untrusted
  context; `injection_violations` reported nothing and none of the three
  tripwires fired — a CICD-SEC-4 RCE hidden in the scanner's blind spot. Closed
  by a fourth fail-closed tripwire (`unscannable_inline_runs`, zero hits on all
  18 scanned files).
- **MEDIUM (latent), `test_ci_compose_dashboard_hardening`** — `strip(extract(…))`
  ordering: a sibling service key written `redis:  # cache sidecar` (two-space indent) did not
  terminate the dashboard block, so the sibling's directives satisfied it.
- **MEDIUM (latent), `test_ci_dashboard_control_smoke.harness_step_block`** —
  step blocks ran to EOF, so a later job's job-level `timeout-minutes:` satisfied
  the per-step-cap assertion once the per-step cap was deleted.
- **HIGH (latent), `test_dashboard_no_inline_handlers._strip_scripts_styles`** —
  a literal `<script` inside an attribute value or an HTML comment opened a strip
  region, deleting live markup up to the next end tag. The previous docstring
  filed this under "direction FALSE POSITIVE (safe)" while describing it as
  removing MORE text than intended; those are opposite directions and the second
  is the bypass — the same mislabelling that hid #376's CRITICAL. Replaced with a
  tokenizer. `html.parser.HTMLParser` was rejected as the implementation: on
  Python 3.9.6 it swallows the markup after `</script/>` and
  `</script foo="a">` (fixed in ≥3.12), so it would make the guard's correctness
  interpreter-version-dependent in the miss direction.

Attacks executed that the guards REPELLED (recorded so the pass is auditable, per
ADR-001 §3 — a bare "CLEAN" is not a completed pass): a whole-block comment-out
of the severity gate (`conditional_body_from` returned no `exit 1`);
`jobs:  # comment` and `"jobs":  # comment` headers, which make `top_level_jobs`
return `[]` but trip the `assertIn("changes", jobs)` canary and the stale-allowlist
check in `test_ci_gate_topology`; `permissions:  # least privilege` in
`npm-publish.yml`, caught by the non-empty block canary; a commented sibling job
key against `test_ci_lychee_config._extract_job_block`, whose terminator already
tolerates `(#.*)?$` (the ordering there was inert, and is reversed anyway so the
new meta-guard's baseline stays empty); deleting the real per-step
`timeout-minutes` with no later job present (guard fired).

Codified as `test_ci_strip_before_match.py` (Catalog above): the two ORDERING
shapes are mechanically detectable, and resolving stripper aliases to a fixed
point turned the 2 hand-found sites into 3 detected ones. General over-stripping
is **not** mechanizable and no meta-guard is claimed for it — see that guard's
"What this guard does NOT claim".

### Quarterly audit 2026-07-28 (ADR-001, issue #297)

A full adversarial re-audit of all 38 `test_ci_*.py` guards (three independent
review passes; every finding reproduced with an executed proof, not a static
read). Three guards were confirmed CLEAN with the comment-evasion class
inapplicable by construction: `test_ci_lighthouse_perf_gate.py` (strict
`json.loads`), `test_ci_codeowners_invariants.py` (mirrors GitHub's own
CODEOWNERS grammar — no inline-comment syntax exists), `test_ci_compliance_keyword_guard.py`
(executes the real module and inspects the runtime `COMPLIANCE_CONTROL_MAP`, no
text surface).

**Fixed (Class 1 — comment/unhandled-form evasion; the natural "comment out the
control" regression path, the exact class ADR-001 §1/§3 target):**

- `test_ci_net005_fail_escalation.py` — section built from raw lines; a
  `# fail "NET-005" ... "critical"` comment satisfied the escalation check while
  active code downgraded to WARN → now routes through `strip_comment_lines` +
  comment-survival mutation test.
- `test_ci_changes_job_merge_base.py` — imported only `join_continuations`; the
  `|| git diff` fallback / non-shallow fetch tokens satisfied the check from a
  comment → now `join_continuations(strip_comment_lines(text))` + mutation test.
- `test_ci_compose_dashboard_hardening.py` — `_strip_comments` kept trailing
  inline comments and the `no-new-privileges` regex is (necessarily) unanchored,
  so the token rode a trailing comment on an unrelated line → now strips trailing
  inline comments via `strip_inline_comment` + mutation test.
- `test_ci_dependabot_config.py` — used `non_comment_lines` (whole-line only); a
  required ecosystem token rode a trailing inline comment → now composes
  `strip_inline_comment` + mutation test.
- `test_ci_security_gate.py` (**required `Security Scan Gate` merge-block**, the
  #271 F-1 incident class) — surfaced by the mandated ADR-001 §2 review chain: a
  `;#exit 1` (a REAL bash comment — no space before `#`, verified the `exit 1`
  never runs) survived `strip_inline_comment` and satisfied the CRITICAL
  merge-block check while the active code was warn-only. Root cause was the
  SHARED primitive: `strip_inline_comment` required whitespace before `#`, but
  bash starts a comment after a command separator (`;`/`&`/`|`) with no space.
  Added a quote-aware, bash-word-boundary `strip_inline_comment_sh` and routed
  the three shell-scanning guards (`security_gate`, `net005_fail_escalation`,
  `changes_job_merge_base`) through it (+ metachar AND backtick mutation tests).
  The comment-start boundary set (whitespace + the bash metacharacters
  `;`/`&`/`|`/`(`/`)`/`<`/`>` + backtick) was proven complete by enumerating
  every ASCII preceding char against real `bash` (a further review pass found the
  backtick `` `#… ` `` form after the initial metachar set; both are now closed
  and confirmed). The whitespace-only `strip_inline_comment` is retained for
  YAML/Dockerfile callers, where `;#` is literal scalar content, not a comment.
  A **5th-pass** review (ADR-001 §2) then found the ANSI-C `$'...'` case was NOT
  an over-strip but an **UNDER-strip** (false negative): `$'\''` is one escape-
  aware string, and a single-quote branch with no escape awareness ran off the
  line "in a quote" and never stripped the trailing `#`, hiding a dead `exit 1`
  from the gate. Modeled it (a `'` after an unescaped `$` opens an escape-aware
  string) + added ANSI-C mutation tests to the primitive, `security_gate`, and
  `net005_fail_escalation`. Remaining documented **over-strip** limitations
  (opposite direction — they drop live text → a false ALARM, never a silent
  bypass; none is triggered by the scanned blocks): cross-line quoted strings,
  heredoc bodies, and a command substitution `$(...)` closing inside a word
  (`x=$(cmd)#c` keeps `#c` literal, but the single preceding-char model cannot
  tell that `)` from a subshell `)`) — see the `strip_inline_comment_sh` docstring.
- `test_ci_injection_surface.py` — the twice-hardened block-scalar rule still
  missed single-line flow-style step mappings
  (`steps: [{run: "…${{ github.event.* }}…"}]`), leaving that `run:` body
  unscanned → added a grammar-complete flow-style extractor (ADR-001 §4) +
  mutation test. The multi-line-quoted flow scalar (unreassemblable by a
  no-PyYAML line scanner) is now caught by a **tripwire** (`unscannable_flow_runs`)
  that FAILS on the unscannable shape so an injection cannot hide in it — the
  author must use a block scalar or a single-line flow value (dormant on this
  repo: all `run:` are block style, so zero false positives). The
  multi-line-split `${{ }}` block-scalar form is **now closed the same way** —
  see the entry below.

**Class B follow-up — `strip_inline_comment_sh` adoption (this PR):**

The #383 sweep classified three further guards as **Class B**: they *do* catch a
plain deletion of the control, but they scanned shell with the whitespace-boundary
`strip_inline_comment`, so the same `;#` metachar adjacency that hid a dead
`exit 1` from the Security Scan Gate applied to them too. They waited on the
primitive rather than growing a divergent local copy of the bash boundary logic.
All three are now routed through `strip_inline_comment_sh`, together with the one
gap #383 recorded against itself:

- `test_ci_coverage_thresholds.py` — `pytest scanner/;#--cov-fail-under=99` left
  the floor token in the file with no gate running.
- `test_ci_dependabot_automerge.py` — `echo skip;#scanner/*|scanner)` parked a
  hard-exclude arm in a comment, so a `pull_request_target` write-token workflow
  would auto-arm `scanner/` changes with the guard green. The four narrower
  per-invariant tests additionally asserted against the **raw** file text, which
  made them inert against a plain comment-out; they now share the stripped scan.
- `test_ci_prowler_provider_guard_ordering.py` — a decoy
  `echo x;#_prowler_provider_available "…"` lent its early line number to
  `min(guard)` and masked a real guard placed after the report (the F-8 masking,
  reached via a metacharacter instead of leading whitespace).
- `test_ci_docker_image_size_gate.py` — the `exit 1` breach-block scan, the gap
  #383 documented in the function docstring and the catalog row; `;#exit 1` made
  a 900 MB image merge with a green guard.

Each was reproduced with an executed proof against real `bash` before the change,
and each fix ships mutation self-tests proven non-vacuous (all 10 FAIL when the
primitive is reverted to `strip_inline_comment`). The over-strip direction is
pinned too: a `#` inside quotes is literal and must not truncate a live control.

**Inert-assertion class, promoted to a meta-guard (this PR):**

The two inert guards #383 found (`provenance_verify`, `docker_image_size_gate`)
shared one shape: a positive presence assertion aimed at the **raw whole-file
text**. Hand triage caught them, but it does not scale to 40 guards and does not
run on new ones, so the triage is now codified as
`test_ci_guard_assertion_scoping.py` — an AST scan of the guard suite itself.

Running it found **seven more** live instances, each confirmed inert by executing
the guard against a commented-out artifact (green before the fix, red after —
same mutant, only the haystack changed):

| Site | Control left dead while the guard read green |
|---|---|
| `test_ci_branch_protection_codified.py` ×2 | `DESIRED_CONTEXTS` (both required merge contexts) and `DESIRED_ENFORCE_ADMINS="true"` commented out |
| `test_ci_branch_protection_codified.py` ×2 | the `DRIFT DETECTED` producer/consumer marker contract on both ends |
| `test_ci_cross_os_non_required.py` | the `macos-latest` runner canary |
| `test_ci_npm_publish.py` ×2 | the push-`branches: [main]` auto-release trigger |

All seven now assert against the guard's comment-stripped scan; the
branch-protection pair additionally moved to `strip_inline_comment_sh`, since
both artifacts are shell-bearing and were open to the same `;#` adjacency. The
baseline `KNOWN_RAW_PRESENCE_ASSERTIONS` therefore ships **empty**, and its
set-equality pin fails on a stale entry as well as a new offender.

The meta-guard deliberately exempts the two shapes that are not inert: negative
(FORBIDDEN-token) assertions, where raw scanning only over-reports, and
line-anchored regexes (`(?m)^\s*token`), which a `#`-commented copy cannot
satisfy — three guards rely on that form correctly and are not flagged.

**Catalog meta-guards hardened (this PR — closes the last non-deferred Class 2
item):**

`test_ci_catalog_completeness.py` and `test_ci_catalog_no_ghost_rows.py` shipped
with **no mutation self-test** — they only ever ran against the real catalog, so
a parser regression would have gone unnoticed and both would have passed
vacuously. Detectors are now extracted to module level (`missing_rows`,
`cited_paths` / `ghost_rows`) and exercised on synthetic input: undocumented
guard, ghost row, prose glob, duplicate citations, empty catalog.

Both also scanned the catalog RAW. Markdown has no `#` comment, so `<!-- ... -->`
is the escape hatch, and a row parked inside one renders as nothing while still
satisfying a substring check — a guard could vanish from the published inventory
with `catalog_completeness` green. Both now route through a shared
`strip_html_comments` in `_ci_guard_util.py`. The strip cuts **both ways, and
both are correct**: it makes `completeness` STRICTER (a hidden row no longer
satisfies presence) and `no_ghost_rows` more LENIENT (a commented row claims no
coverage, so flagging it would be a false alarm) — with a test pinning that a
commented ghost still does not mask a live one. An unclosed `<!--` degrades to
no-strip rather than blanking the document, which would fail every consumer at
once.

Non-vacuous: neutering `strip_html_comments` fails 3 of the new tests.

**`injection_surface` split-expression gap closed by tripwire (2026-08-06):**

The one remaining Class 2 row — a `${{ }}` split across two physical lines inside
a `run:` body — is no longer a documented gap. It is closed the way its flow-style
sibling was: `unscannable_block_runs` **fails closed on the unscannable shape**
(an opened `${{` with no `}}` on the same physical line inside a run body) instead
of guessing at semantics the guard cannot verify. The remediation is trivial and
always available — keep each expression on one line, which is how every `${{ }}`
in this repo is already written — so the shape ban costs nothing. Reassembling
folded YAML lines would need a real parser (stdlib-only / no-PyYAML), and whether
the Actions expression lexer even accepts the split form stays **unverified**;
failing on the shape makes that question moot rather than load-bearing.

Building it surfaced an **adjacent hole the audit had not recorded**, which a
tripwire alone would have left open: a multi-line **plain** scalar
(`run: echo` followed by a deeper-indented `'${{ github.event.issue.title }}'`)
folds into one command at runtime, but the continuation line was dropped from the
body entirely — so the interpolation was invisible to the scanner AND to the new
tripwire (the expression closes on its own line, it is the *body extraction* that
was incomplete). Fixed by scanning it: an inline `run:` value now shares the
block scalar's deeper-indented collection loop, since YAML applies the same
indentation rule to both styles. Error direction is safe — over-collecting can
only raise a false alarm, and a sibling `env:`/`with:` key aligns with the `run:`
column and still terminates the scan (pinned by a new test, the inline analog of
the existing block-scalar case).

The mandated ADR-001 §2 adversarial pass then found **four more**, all confirmed
by executing the detector against PyYAML's resolved document as ground truth
(PyYAML is available outside the CI test job, so it can serve as an oracle for
what the guard *should* see without becoming a dependency of the guard):

| Finding | Class | Resolution |
|---|---|---|
| **Quoted mapping key** — `"run": echo '${{ … }}'` resolves to the same `run` key, but both the block and flow matchers hard-required an unquoted `run:` → guard green, injection live | Class 2, **pre-existing** | `_RUN_KEY` now accepts `run` / `"run"` / `'run'` across all three matchers. Not exotic: GitHub's own docs normalize `"on":` for the YAML-1.1 boolean collision, so a quoted key is a plausible style, not a contrived evasion |
| **Explicit-key form** — `- ? run` then `: echo '${{ … }}'` puts key and value on different lines, so the substring `run:` never appears and no line matcher can see it | Class 2, **pre-existing** | Third tripwire, `unscannable_run_keys` — fail closed on the shape, same rationale as the other two |
| **`.yaml` extension** — `_workflow_files()` globbed only `*.yml`, while Actions honours both, so a whole `.yaml` workflow would be silently unscanned | Class 2, **pre-existing** (latent: repo has no `.yaml` workflow) | Glob both extensions; pinned behaviourally against a fixture directory, not by reading this file's own source (that would be the inert shape the AST meta-guard rejects) |
| **Comment false positive** — a `# never do this: ${{ github.event.issue.title }}` warning comment beside an inline `run:` was collected as scalar continuation and scanned as shell | **introduced by this change** | Stop collection at a comment-only line for inline values *only*. This is exact rather than conservative: PyYAML rejects `run: echo` / `# c` / `hi` as a parse error, so a plain scalar cannot resume after a comment. In a block scalar the same line is literal body text and is still collected |

The review also flagged the new sibling-key boundary test as **vacuous** — an
absence-only assertion that also passes when continuation collection is deleted
outright, the same inert shape the AST meta-guard exists to reject. It now pairs
a positive control (a genuine continuation IS collected) with the negative one,
so it fails under that mutant too.

Every change ships a mutation self-test proven non-vacuous **by execution** — six
mutants, each failing exactly its own test(s) and nothing else: neuter
`_expr_unterminated`; restore the early `continue`; revert `_RUN_KEY` to unquoted;
neuter `unscannable_run_keys`; drop the comment-stop; revert the `.yaml` glob.
All are dormant on the real workflows (zero unterminated `${{`, zero inline-`run:`
continuation lines, zero quoted/explicit keys, no `.yaml` file), so none adds a
false positive today.

**Lesson, again:** the first fix left residual holes — the fifth instance of the
pattern ADR-001 predicts. Note the direction: the tripwire this PR set out to add
would NOT have closed the plain-scalar hole or the two key-form holes, because a
tripwire only fires on a shape the extractor already reaches. Banning an
unscannable shape and *verifying the extractor reaches every shape* are separate
obligations.

**Composite actions folded in (same PR, found by the follow-up guard-wide sweep):**

Fixing the `.yaml` extension raised the obvious next question — *which file sets
does this guard enumerate at all?* — and the answer was still incomplete. A
composite action (`.github/actions/<name>/action.yml`, `runs.using: composite`)
declares `steps[].run` shell bodies that interpolate `${{ }}` exactly like a
workflow step, and required workflows call them. Two already exist here
(`datadog-ci-collect`, `token-expiry-gate`), and a live
`${{ github.event.pull_request.title }}` planted in one of them left the
**already-hardened** guard green — the very CICD-SEC-4 RCE it exists to prevent:

| Fixture | Before the fold | After |
|---|---|---|
| RCE in a composite `action.yml` | `30 passed` (green) | `2 failed` (caught) |
| RCE in a `.yaml` workflow (control) | `2 failed` | `2 failed` |

`_workflow_files()` is therefore now `_scanned_files()`, covering workflow
`*.yml`/`*.yaml` plus nested `action.yml`/`action.yaml` — matched by those two
canonical entrypoint names only, so an unrelated helper YAML in that directory is
not treated as shell. The canary is split per file set, since a broken
`ACTION_DIR` would otherwise be masked by the workflows still matching and the
whole composite-action scan would pass vacuously. Scanned files: 16 → 18.

Neither existing composite action has a live violation (both correctly use `env:`
indirection), so this is latent coverage, not a live incident.

**The same sweep found this enumeration/key-quoting class in 10 OTHER guards**
(`gate_topology` never globs `.github/actions/**` at all, so a tag-pinned `uses:`
there defeats SHA pinning; `pr_trigger_scope` misses a quoted `"branches":`, which
defeats the measured #384 stacked-PR incident fix; and more). Those are tracked as
follow-up work — the fix belongs in **shared `_ci_guard_util.py` primitives** (an
optionally-quoted key matcher, an explicit-key tripwire, one file enumerator)
rather than ten separate patches, since ten sites is a grammar-modeling failure and
not ten typos.

**Guard-wide key-quoting / file-enumeration sweep (#393):**

The `injection_surface` work above closed a quoted `"run":` key and a `*.yml`-only
glob in ONE guard, which raised the obvious question: how many others share the
shape? A sweep of all ~20 guards found the class in **10 more**, each verified by
executing the guard against a mutated artifact and watching it stay GREEN while the
control was gone. PyYAML — available outside the CI test job — served as the oracle
for "what would the real parser resolve this to", without becoming a dependency of
any guard.

Why quoted keys are realistic rather than contrived: bare `on:` resolves to the
YAML-1.1 boolean `True`, which is exactly why GitHub's own docs normalize `"on":`.

This PR fixes the five HIGH instances by adding **shared primitives** rather than
five local regexes — ten sites is a grammar-modeling failure, not ten typos
(ADR-001 §4, and the 6th recurrence of "enumerate the form" losing to "model the
grammar"):

| Before → after (all executed) | Defeated control |
|---|---|
| tag-pinned `uses:` in a composite `action.yml`: `5 passed` → `1 failed` | SHA pinning (OWASP A08) — `.github/actions/**` was never globbed |
| unpinned `uses:` in `evil.yaml`: `5 passed` → `1 failed` | same, via the `*.yml`-only glob |
| `"branches": [main]` under `pull_request:`: `11 passed` → `1 failed` | the stacked-PR required-check loss — the **measured** #384 incident (3 checks vs 28) |
| quoted `"pull_request_target":` on `provenance-verify.yml`: `11 passed` → `1 failed` | no write-token PR trigger on the release-attestation workflow |
| explicit `? pull_request_target`: `11 passed` → `1 failed` | same |
| quoted `"uses":` key in `lint.yml`: `5 passed` → `1 failed` | SHA pinning |
| explicit `? uses` key: `5 passed` → `1 failed` | same |
| quoted ungated job key `"rogue":`: `5 passed` → `1 failed` | `lint-gate.needs` completeness — a job invisible to branch protection AND to the guard |

The primitives: `yaml_key_pattern(key)` (bare or quoted, composable),
`explicit_key_lines(text, *keys)` (fail closed on `? key` / `: value`, the tripwire
pattern from `unscannable_run_keys`), and `workflow_and_action_files()` (both
extensions plus composite entrypoints, matched by the two canonical filenames only
so an unrelated helper YAML there is not treated as executable). `top_level_jobs`
now reads a quoted job key and a quoted `"jobs":` header — an unparsed header would
return an empty job list, which satisfies "every job is gated" vacuously.

Each fix ships a mutation self-test. Enumeration canaries are split per file set,
since a broken `ACTION_DIR` would otherwise be masked by the workflows still
matching.

**Deliberately NOT changed, so nobody re-audits them:** every guard naming a single
`.yml` path asserts `is_file()` or has a parse canary, so a `.yaml` rename turns it
RED (proved by renaming `lint.yml`, `docker-compose.yml`, `.github/dependabot.yml`).
Presence-direction guards are fail-closed by construction — quoting a *required*
token removes it, so they over-report rather than bypass. `extract_on_block` already
handles `"on"`/`'on'` and returns `""` for `? on`, which makes all four consumers
RED. Non-YAML guards (Markdown, AST, CODEOWNERS, JSON, Dockerfile, bash) are
structurally inapplicable, and shape C never occurs independently of shape B.

**Remaining from the sweep (MEDIUM/LOW):** all closed in #394 — see the next
section. The sweep backlog is empty.

**Sweep remainder + the dead-schedule-arm class (#394):**

Closes the MEDIUM/LOW tail of the #393 sweep and one structurally different defect
found alongside it.

*Sweep remainder* — `codeql_single_model` (dual-extension + composite-action
enumeration, quoted `uses:` key/value, `? uses` tripwire), `cross_os_non_required`
(quoted `runs-on:`/`os:` key, quoted key AND value in the `"name": Lint`
masquerade check, `? name`/`? runs-on` tripwire), and the `npm_publish` false
negative. All verified before/after by execution:

| Mutation | Before | After |
|---|---|---|
| `codeql-action/init` in a `codeql.yaml` | `2 passed` | `1 failed` |
| quoted `"uses": codeql-action/init` | `2 passed` | `1 failed` |
| quoted `"runs-on": macos-14` in `lint.yml` | `13 passed` | `1 failed` |
| quoted `"name": Lint` masquerade | `13 passed` | `1 failed` |

The `npm_publish` case needed **two** fixes, and the second only became visible by
checking *which* assertion reported. Fixing the scan to read a quoted grant value
(`packages: "write"` had produced an EMPTY grant list) left the test failing on the
unrelated whole-block anchor instead — the precise message never appeared
(`matches=0`). The scan was still unobservable, so the ordering was inverted: the
write-grant scan now runs first and reports `packages: "write"` by name, while the
anchor remains as a structural catch-all for additions the scan does not classify.
**Lesson: "the test goes red" is not the same as "the fix is load-bearing" — check
which assertion fires.**

*Dead schedule arm* — a different class, and worse, because nothing ever went red.
Path-gated jobs carry `|| github.event_name == 'schedule'` as their periodic
escape hatch, but `lint.yml` had **no `schedule:` trigger at all** (verified over
1118 runs: 654 `pull_request` + 464 `push`, zero `schedule`), so that arm could
never be true for seven jobs. Measured: `npm-audit` had **zero** real executions
for ~7 weeks / 117 `main` commits (bucket last touched in `e5b9bbb`), and
`pip-audit` sat dark until a requirements edit fired it and it failed on the spot
with accumulated runner drift (`setuptools` PYSEC-2026-3447) — a failure that
looked like it belonged to the unrelated PR that surfaced it. A `skipped` job reads
as green, so there was no signal to notice.

Fixed with a weekly `schedule:` on `lint.yml` (Wednesday 05:00 UTC, off the
existing cron slots), which cannot block a merge: required contexts are evaluated
per-commit on pull requests and are unaffected. `test_ci_dead_schedule_arm.py`
keeps the promise repo-wide — the trap is generic, and the next workflow to grow a
schedule arm should not have to rediscover it.

Its detector is worth noting as a small ADR-001 §4 rehearsal: the first version
enumerated comparison shapes (`==`, the reversed form, `contains(...)`) and the
`contains` pattern failed immediately on
`contains(fromJSON('["schedule","push"]'), github.event_name)`, because `[^)]*`
cannot span the `)` inside `fromJSON(...)`. Replaced by the invariant that actually
holds for every spelling: **co-occurrence** of `github.event_name` and a quoted
`schedule` token on one line. Over-reporting direction only (a stray `echo`
mentioning both demands a trigger — a false alarm, never a bypass).

**Backlog (Class 2 — matcher-completeness / enumeration gaps; require a
deliberate, unusual edit rather than a comment-out, so lower natural-regression
risk — triaged as follow-up, not blocking):**

> **RE-TRIAGED 2026-08-10 — seven of these eight sub-items were already CLOSED
> and this list had gone stale.** Each was re-checked by applying the bypass to
> the REAL file and running the guard, not by re-reading the code. A backlog
> that lists solved problems as open costs a cycle to rediscover, and worse,
> invites "that's a known gap" when it is not. Evidence below; only the last
> entry survives.

| claimed gap | verdict | how it was checked |
|---|---|---|
| `no_ere_pipe`: `--extended-regexp` long flag | **CLOSED** | added `grep --extended-regexp 'foo\|bar'` to `checks.sh` → guard failed (it also carries a dedicated mutation test) |
| `npm_files`: glob not grammar-complete | **CLOSED** | appended `docs/**` to `files[]` → guard failed |
| `npm_files`: order-blind to a re-added positive | **CLOSED** | re-appended a `!scripts/…`-negated path after its negation → guard failed |
| `plugin_skills_cli_parity`: `*)` ordering | **CLOSED** | moved the top-level catch-all above the `scan)` arm → 3 tests failed |
| `provider_labels_sync`: `*)` ordering | **CLOSED** | moved `aws)` below `*)` → guard failed |
| `cross_os_non_required`: fixed 4-string enumeration | **CLOSED** | switched a `lint.yml` job to `macos-14` → guard failed (the matcher is now shape-based and version/case-agnostic, #394) |
| `cross_os_non_required`: omits the `"Lint"` context | **CLOSED** | added a rogue job with `"name": "Lint"` → guard failed (`REQUIRED_CONTEXTS` covers both) |

A note on the method, because it nearly produced a false finding: the
`provider_labels_sync` probe first reported a GAP. The mutation was wrong — it
moved `aws)` to sit immediately *before* `*)`, where the arm is still perfectly
reachable, so the guard was right to stay green. Attack the harness before
believing its verdict (the stripper-false-negative lesson, applied to a mutation
fixture instead of a stripper).

**Still open — the only survivor:**

- `test_ci_no_ere_pipe_regression.py` — cross-line variable indirection:
  `PATTERN="foo\|bar"` on one line, `grep -E "$PATTERN"` on another. Confirmed
  undetected by probe. **Decision (2026-08-10): stays deferred, now with a
  measurement rather than an assertion of difficulty.** The true fix needs
  cross-line dataflow. The only tractable approximation — flag every `\|` inside
  a string assignment — false-fires on this repo's own CORRECT usage: four live
  sites in `checks_credentials.sh` write `grep -q 'sso_start_url\|sso_session'`,
  where `\|` is GNU **BRE** alternation and entirely right, and they become
  indistinguishable from the bug the moment anyone extracts the pattern into a
  variable. Live instances of the indirection shape: **zero**. Revisit if one
  lands.

Both `test_ci_injection_surface.py` rows that were listed here are now **closed**
by shape tripwires rather than deferred — see "split-expression gap closed by
tripwire" above.

### Backlog sweep 2026-08-10

Clears the three items the 2026-08-08 runner-key audit (#407) left open. Nothing
here was found by a new adversarial pass; all three were already written down and
simply not done, which is the point of recording them at this granularity.

**1 — DRY debt in `test_ci_injection_surface.py`.** It carried verbatim private
copies of four shared primitives: `_RUN_KEY` (= `yaml_key_pattern("run")`),
`_EXPLICIT_RUN_KEY_RE` (= the `explicit_key_lines` pattern), `_scanned_files()`
(= `workflow_and_action_files()`), and its own `WORKFLOW_DIR`/`ACTION_DIR`. Every
copy was correct, so this was not a live bug — it was the *mechanism* of
the #391/#393/#394 incident sitting in the one guard that had already paid
for it: independent copies of a matcher drift independently, and `yaml_key_pattern`'s
docstring exists specifically to say "compose this instead of writing `key\\s*:`".
Now routed through the shared module.

The de-dup also moved a self-test onto the shared helper, which is where the real
gain is. `test_scanned_files_covers_yaml_extension_and_composite_actions`
patched this guard's PRIVATE dir globals, so it proved the `*.yaml` /
composite-action enumeration for one guard only. It now patches
`_ci_guard_util`'s, so the enumeration every guard depends on is the thing under
test — verified by mutating `workflow_and_action_files` to drop `*.yaml` and
watching it fail.

**2 — three guards with no mutation self-test.** `test_ci_npm_oidc_floor.py`,
`test_ci_required_jobs_exist.py`, `test_ci_lighthouse_perf_gate.py`. Each is now
a named detector with mutation tests in both directions, proven against a
mutated copy of the real file it protects (see their Catalog rows). One of the
three turned out to hide a live false negative rather than merely lacking
evidence — the npm OIDC floor could be pinned a full major below the documented
requirement with the guard green.

That is the lesson worth keeping: "no mutation self-test" was filed as *process*
debt, and one of the three was a *defect*. An assertion nobody has watched fail
is not weak evidence of correctness; it is no evidence, and the only way to find
out which one you have is to mutate it. Note also that
`test_ci_lighthouse_perf_gate.py` had been explicitly CLEARED by the 2026-07-28
audit — correctly, for the class that audit was scanning (comment evasion, which
strict `json.loads` makes inapplicable). "Clean for the audited class" is not
"clean", and a clean verdict scoped to one class should be recorded with that
scope attached.

**3 — Tier-3 documentation gap.** `guard-audit-reminder.yml` was the only
workflow with zero mentions in this document. Triaged into the Tier-3 list above
with an explicit KEEP-AS-MONITOR decision and the reason it sits at a different
tier than `protection-drift-watch.yml`. The check that found it is worth
repeating each audit and takes one command: diff `ls .github/workflows/` against
the workflow names appearing in this file.

**Follow-up (same date).** Three items that came out of the sweep rather than
being on its list:

- **The shared-helper test file was itself duplicated.**
  `scanner/tests/test_guard_util.py` had grown up independently beside
  `test__ci_guard_util.py`, both direct-unit-testing `_ci_guard_util`, with
  `TestStripCommentLines` and the `extract_on_block` cases present in both at
  different coverage. That is the module's own defect class turned on its tests:
  "is this primitive covered?" had two answers and neither file was
  authoritative. Merged into `test__ci_guard_util.py` (the name the reminder
  workflow, ADR-001 and the `ci-config-guard-claudesec` skill already point at);
  all 47 distinct cases preserved, verified by diffing test-method names.
- **Five primitives had no direct test in either file** — `yaml_key_pattern`,
  `explicit_key_lines`, `keys_at_column`, `job_block`, `job_needs` — despite each
  docstring naming a specific incident it exists to prevent. Those incidents are
  now pinned directly rather than only wherever a consumer guard happened to hit
  them, and each new case was proven by mutating the primitive and watching it
  fail. One mutation (`job_block` bounded on "the next two-space `<key>:`"
  instead of on indentation) initially did NOT fail, exposing a gap in the test:
  the
  discriminating case is a job followed by a TOP-LEVEL key, where a job-column
  bound never fires and the block runs to EOF. Added. One mutation is documented
  as non-discriminating on purpose: `keys_at_column`'s explicit comment skip is
  redundant today because the key regex's `[^\s:#]+` already cannot start at `#`,
  so the test pins the behaviour rather than that line.
- **The quarterly reminder now carries the rules, not just the ritual.**
  `guard-audit-reminder.yml`'s checklist gained the execution-proof boundary
  question, the transitive-`needs:` scoping rule, the name-the-population rule,
  the workflow-set-vs-doc diff above, and "record the CLASS a guard is clean
  for". Rationale lives in
  [the retrospective](../reports/runner-key-audit-retrospective.md).

### Redirect-surface survey 2026-08-10 (post-#412)

PR #412 closed the REDIRECT class inside the required graph. This survey asked
where else those keys can reach, and found the exposure is nil — but found a
different, larger gap on the way.

**Redirect keys outside the required graph: none.** The only `working-directory`/
`shell`/`defaults` sites repo-wide are `shell: bash` in the two composite
actions, which GitHub *requires* on a composite `run:` step. `lint.yml` has a
line that greps as `shell:` — it is an **output name** under `outputs:`, not a
step key, and the column-derived matcher correctly ignores it (a naive
`grep shell:` would have raised it as a finding).

**The composite actions are not called by this repo at all.** No `uses: ./`
appears anywhere under `.github/workflows/`. They are called from
`templates/prowler.yml` and `templates/security-scan-suite.yml`, which ship to
OTHER repositories. A docstring in `_ci_guard_util.workflow_and_action_files`
asserted the opposite ("required workflows call them") and is corrected.

**The real finding: `templates/` was scanned by nobody.** `scripts/setup.sh`
copies `templates/codeql.yml` and `templates/dependency-review.yml` straight
into a target repo's `.github/workflows/`, and both composite actions alongside
them. So an injection there executes in someone else's repo with their token —
strictly higher blast radius than this repo's own CI — and
`workflow_and_action_files()` returned 18 files, none under `templates/`.

`test_ci_injection_surface.py` now scans all 13 templates. Baseline is clean
(zero untrusted-context interpolations, zero unscannable shapes), so it is a
pure ratchet, with a canary and a mutation test that plants a live
`${{ github.event.issue.title }}` in the real `templates/codeql.yml`.

**Deliberately NOT changed — a product decision, not a guard's to make.** The
templates carry ~30 tag-pinned `uses:` refs (`@v3`, `@v4`) while this repo
enforces 40-hex SHA pins on its own workflows. That is why the template glob was
added to *this guard* rather than to the shared `workflow_and_action_files()`:
widening the shared enumerator would have enrolled the templates in
`test_ci_gate_topology.test_every_uses_is_sha_pinned` and failed the build on a
question nobody has decided. Injection is not a policy question and is closed
now; whether a shipped *example* should carry SHA pins (and who then keeps them
fresh in the user's repo) is left open and visible.

> **DECIDED 2026-08-11 — see `test_ci_template_pin_policy.py` above.** Neither
> all-SHA nor all-tag. `setup.sh` **installs** `codeql.yml` and
> `dependency-review.yml` into a user's `.github/workflows/`, so those are
> SHA-pinned to the refs this repo runs (parity-guarded, which makes our
> Dependabot the freshness signal Dependabot cannot provide inside
> `templates/`). The example-only templates stay tag-pinned and carry a note to
> pin before adopting, because ClaudeSec does not run those actions and a pin it
> cannot refresh rots — which is exactly what happened to the one hand-written
> SHA in there (`actions/checkout` sat three major versions behind). The
> scoping decision above therefore **stands**: the two halves have different pin
> rules, and only the injection rule applies to both.

### Mutation-fixture helpers (2026-08-10)

`apply_mutation` and `assert_disables` in `_ci_guard_util`. Added because FIVE
probes in one audit failed the same way — the fixture did not change the thing
it claimed to — and each nearly produced a "fix" to a guard that was correct:

1. a `case` arm moved just BEFORE the `*)` catch-all — still reachable;
2. a section HEADER edited instead of the entry beneath it;
3. a `job_block` case written only for end-of-file, where the discriminating
   shape is a following top-level key;
4. `if: always()` deleted from a gate whose explanatory COMMENTS quote it
   verbatim — this repo's own comment-evasion class, biting the fixture rather
   than the guard;
5. text injected onto a TestCase class that `setUpClass` then overwrote from
   disk, so the assertion ran against the unmutated real file.

`apply_mutation` closes 2 and 5 mechanically: the substring must be present, and
the result must differ, or it raises at the point of the mistake. **1, 3 and 4
are semantic** — whether the edit disables the CONTROL, not whether it changed
bytes — and no helper decides that; the docstring says so rather than implying
coverage it does not have. Migrated the six literal-`replace` fixtures;
`re.sub`-based ones in `test_ci_security_gate_behaviour.py` are left alone
rather than forced into a substring API.

### Verified already-guarded during this review (not backlog)

> **Re-checked 2026-08-10. One entry had gone false, and the section's shape is
> why nobody noticed:** it recorded eight verdicts with no class, no evidence and
> no date, so it reads as an unqualified "these are fine" forever. A verdict is
> only meaningful with the class it was checked against and the guard that now
> owns it — see the audit-checklist rule "record the CLASS a guard is clean for".

| invariant | owning guard (verified 2026-08-10) | class checked |
|---|---|---|
| lychee `v0.23.0` pin | `test_ci_gate_topology.py` | exact-version pin, not a floor |
| `Security Scan Gate` CRITICAL `exit 1` | **`test_ci_security_gate_behaviour.py`** — *not* `test_ci_security_gate.py`, which is what this line used to say | behavioural: the gate is RUN and must exit non-zero on a CRITICAL |
| CODEOWNERS coverage | `test_ci_codeowners_invariants.py` | pattern coverage + review requirement |
| ERE-pipe regressions | `test_ci_no_ere_pipe_regression.py` | `\|` inside an ERE consumer, same line only |
| prowler provider ordering | `test_ci_prowler_provider_guard_ordering.py` | arm order / reachability |
| coverage floors | `test_ci_coverage_thresholds.py` | floor not lowered, comment-immune |
| npm `--provenance` | `test_ci_npm_publish.py` | flag present on every publish |
| cross-OS non-required | `test_ci_cross_os_non_required.py` | runner labels absent from the required lint pipeline |

The correction that matters: **#406 moved the CRITICAL `exit 1` coverage out of
`test_ci_security_gate.py`** (its text-based `conditional_body_from` was deleted
after being defeated six ways) and into the behavioural guard. The only `exit 1`
left in the old file is one line of prose in its docstring. So this section
asserted, for over a month, that a control was owned by a guard that no longer
checked it — the precise failure mode a scoped, dated verdict prevents.

## Block-collector enumeration (2026-08-11)

Every indentation-bounded block collector in `scanner/tests/`, with its verdict.
Recorded as a table rather than a prose summary because the comment-truncation
class was found by enumerating them, and an enumeration nobody wrote down is
re-derived from scratch by the next audit (the #411 stale-backlog lesson in the
other direction).

Ground truth throughout is PyYAML on the real file, not reasoning: in a **mapping**
a comment line ends nothing (`a:\n  x: 1\n# c\n  y: 2` → `{'a': {'x': 1, 'y': 2}}`),
while in a **block scalar** a less-indented comment is a `ParserError` — it does not
keep the scalar alive. Collectors must follow whichever context they read.

| Collector | Reads | Verdict |
|---|---|---|
| `_ci_guard_util.job_block` | mapping | **FIXED** — `block_ends_at`; shared, so every consumer got it at once |
| `test_ci_security_gate_behaviour.find_step_blocks` | mapping | **FIXED** — was a live bypass (step `continue-on-error` hidden, 61 passed) |
| `test_ci_security_gate_behaviour.enclosing_job_block` | mapping | **FIXED** — same class one level out |
| `test_ci_required_graph_not_disabled._steps_of` (item collector) | mapping | **FIXED** — was a live bypass (job `continue-on-error` hidden, 61 passed) |
| `test_ci_npm_publish._top_level_permissions_block` | mapping | **FIXED** — was a live bypass (`packages: write` hidden, 12 passed) |
| `test_ci_security_gate_behaviour.extract_run_block` | block scalar | **CORRECT AS-IS** — must keep breaking; ignoring a `#` line there would over-capture shell out of a workflow file, the execution-safety hazard that guard exists to avoid |
| `test_ci_lychee_redirect_sweep` (`args: >-` body) | folded scalar | **CORRECT AS-IS** for comments (same reason); already skips blank lines, which are legal inside a folded scalar |
| `test_ci_pr_trigger_scope.pull_request_block` | mapping | **VERIFIED FAILS CLOSED** — probed with a comment at the `pull_request:` key column plus a `paths:` filter below it: PyYAML `{'paths': ['docs/**']}`, guard `1 failed` |
| `test_ci_drift_watch_not_silent.steps_gated_on_token_absent` | mapping | **IMMUNE BY CONSTRUCTION** — calls `strip_comment_lines` before collecting, which is the pattern the others now match |
| `test_ci_dashboard_control_smoke` (step blocks) | mapping | **NO OBSERVABLE EFFECT** — probed at a step's dash column before a step-level `timeout-minutes`; PyYAML still resolved both caps and the guard stayed green in both directions. Not proven immune, only unaffected on this file; left alone rather than changed without evidence |

Five `min(indent)` key-column derivations existed alongside these, all of which
inherit the hazard the moment comments live inside a block. They now call the
shared `key_column`; the one exception is `extract_run_block`'s scalar dedent,
where a `#` line is shell content and must be counted.

### Key/value spelling sweep, same date

A quoted KEY or a quoted VALUE resolves to the identical document. Which direction
that breaks depends on what the check asserts, and the distinction is the reusable
part:

- **Violation checks** (`assert offenders == []`) — a missed line is an offender
  that never existed. **Silent bypass.** This is what `uses:` was (#417).
- **Presence / pin checks** (`assert the control is there / equals X`) — a missed
  line reads as a control that is gone. **Fail-closed false alarm**, but still
  fixed: #414 established that a guard an ordinary authoring style breaks gets
  weakened, not repaired.

Probed across the pin/presence guards: **zero further bypasses**, five false
alarms, all fixed with both directions pinned — docker-compose hardening keys
(`read_only`/`cap_drop`/`tmpfs`/`mem_limit`/`pids_limit` + the service header),
`lycheeVersion:` (also now trailing-comment-immune, so a bump is reported as a bump
instead of as a missing pin), the `permissions:` header, and the `ARG
TRIVY_VERSION=` / `ARG PROWLER_VERSION=` defaults (Docker strips quotes, so a
quoted default is the identical pin).

## Adding a new guard

1. Identify a CI invariant whose silent weakening would disable enforcement, and
   name a concrete past or plausible incident (no incident → likely not worth a
   guard; avoid guard sprawl).
2. Add `scanner/tests/test_ci_<thing>.py` following the conventions above.
3. Decide and document the regression **direction** (floor `>=`, pin `==`,
   presence).
4. Prove it is **non-vacuous**: temporarily mutate the workflow (or simulate the
   parse) so the guard fails, then revert.
5. Confirm it passes under `pytest` and `python3 -m unittest`, and that it does
   not import `scanner/lib`.

## References

- OWASP Top 10 CI/CD Security Risks — CICD-SEC-1 (Insufficient Flow Control),
  CICD-SEC-3 (Dependency Chain Abuse), CICD-SEC-7 (Insecure System
  Configuration): <https://owasp.org/www-project-top-10-ci-cd-security-risks/>
- NIST SP 800-218 (Secure Software Development Framework, SSDF) — PO.3, PW.4:
  <https://csrc.nist.gov/pubs/sp/800/218/final>
- OWASP Top 10:2021 A08 — Software and Data Integrity Failures:
  <https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/>
- In-repo: `.github/workflows/lint.yml`, `.github/workflows/security-scan.yml`,
  `scanner/tests/test_ci_*.py`
- Decision record: [ADR-001 — CI Guard Hardening Discipline & Periodic
  Adversarial Audit](./adr-001-ci-guard-hardening-and-audit-cadence.md)
