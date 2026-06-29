# Changelog

All notable changes to ClaudeSec are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are published to npm via the `npm-publish.yml` workflow (Trusted
Publisher + SLSA provenance), triggered by pushing a `v*` tag. For the complete
per-commit history, see the git log and `MEMORY.md` (delta log).

## [Unreleased]

### Added

- **Two new marketplace plugin slash commands** (issue #20). `npx claudesec
  prowler` runs a Prowler multi-cloud scan (thin alias for `scan -c prowler`),
  and `npx claudesec compliance [framework]` runs a compliance gap scan that
  maps findings to a framework (`scan --compliance`, default `isms-p`). Both are
  registered in `.claude-plugin/marketplace.json` so they surface as `/prowler`
  and `/compliance` once the plugin is installed. Marketplace↔CLI parity is
  guarded by `scanner/tests/test_ci_plugin_skills_cli_parity.py`.

## [0.7.2]

### Added

- **Supply-chain provenance verification.** New scheduled `provenance-verify.yml`
  workflow installs the published `claudesec` package weekly and runs
  `npm audit signatures` to confirm the npm registry signature and SLSA provenance
  attestation are intact; on a genuine failure it opens an idempotent
  `provenance-watch` issue (transient registry blips are a no-op). Guarded by
  `scanner/tests/test_ci_provenance_verify.py`.
- README **"Verify supply-chain integrity"** section documenting
  `npm audit signatures` for end users (OWASP A08; SLSA).

### Fixed

- Regenerated the stale `package-lock.json` (it still declared `0.6.0` /
  `node >=16`; now matches `package.json` at `0.7.2` / `node >=18`), restoring
  reproducible `npm ci`.

## [0.7.1]

### Changed

- Upgraded the Node.js engine baseline and CI to **Node 22 LTS**.
- Bumped the embedded version string across the CLI, dashboard generator, and
  agent docs to keep them in sync with `package.json`.
- Synced the Claude plugin manifest version (`.claude-plugin/marketplace.json`).
- Cleaned up `shellcheck` warnings across the scanner test suite and hooks
  (`SC2034` test-stub directives, `SC2188` redirection fixes in
  `scanner/checks/saas/api-checks.sh`).
- Refreshed the `MEMORY.md` backlog to mark the Dependabot auto-merge policy as
  resolved (#249/#250/#251).

### Fixed

- **npm release actually works now (OIDC).** Node 22 bundles npm 10.x, but OIDC
  tokenless trusted publishing needs npm ≥ 11.5.1, so prior publish runs failed
  silently and the registry was stuck at 0.6.1. `npm-publish.yml` now upgrades
  npm, publishes tokenless with `--provenance`, auto-detects a version bump on
  `main` (idempotent), and auto-creates the `vX.Y.Z` tag. Guarded by an extended
  `test_ci_npm_publish.py`.
- **npm package slimming.** The published tarball dropped from ~43 MB to ~580 kB
  (536 → 220 files): removed `docs/` from the `files` allowlist (not needed at
  runtime — it shipped two large `.pptx` seminar templates totalling ~38 MB), and
  excluded operator-only scripts (cost/license/PC-sheet and Google-Sheets-auth
  helpers) via negated `files` patterns (`.npmignore` is overridden by `files`).
  Added `CHANGELOG.md` to `files`. Guarded by `scanner/tests/test_ci_npm_files.py`.

## [0.7.0]

### Added

- DAST reference target (`docker-compose.staging.yml`) and integration tests
  for the scanner pipeline.

### Fixed

- DAST workflow configuration.
- Security code-quality pass (CRITICAL/HIGH/MEDIUM findings remediated).

### Highlights since 0.6.x

This release rolls up a large body of scanner-correctness, CI-hardening, and
supply-chain work (see `MEMORY.md` delta log for the full cycle history):

- **Scanner correctness:** repaired a class of `grep -E` ERE bugs — lookahead,
  `\|`-as-alternation, and `IFS` pipe-split detections — across the AI, SaaS,
  network, cloud, and prowler check modules (#221, #223, #224, #227, #229, #231).
- **Supply chain / Docker:** base images pinned by digest with Dependabot
  tracking; the builder stage made Python-version-agnostic; `prowler==5.30.1`
  pinned for reproducible builds; prowler providers absent from the lean build
  are now skipped instead of emitting a misleading auth warning (#218, #233,
  #237, #238).
- **CI hardening:** kcov shell-coverage offline guard fixed a multi-minute hang
  (120s → ~3.7s); per-test timeout capped at 30s; job-level path gating with an
  `always()` aggregator replaces workflow-level `paths-ignore` so required
  checks still report on docs PRs (#186, #190, #193). A family of CI config
  regression guards (`scanner/tests/test_ci_*.py`) protects coverage floors,
  action SHA pins, required-check topology, and severity gates.
- **Dependabot auto-merge:** dropped the broken approve-as-bot step; auto-merge
  is now armed only for safe semver-patch/minor pip/docker/actions updates, with
  human code-owner approval remaining the gate (#249/#250/#251).

## [0.6.5] and earlier

Branding (OG social cards, light-mode variants), accessibility fixes, Docker
image size optimization (1.47 GB → 479 MB), the Claude plugin manifest, and the
quickstart Docker flow. See the git history for details.

[0.7.2]: https://github.com/Twodragon0/claudesec/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/Twodragon0/claudesec/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/Twodragon0/claudesec/compare/v0.6.5...v0.7.0
[0.6.5]: https://github.com/Twodragon0/claudesec/releases/tag/v0.6.5
