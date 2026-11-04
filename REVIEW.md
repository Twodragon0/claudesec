# Code Review Criteria

What to check when reviewing a ClaudeSec change. It complements [CONTRIBUTING.md](CONTRIBUTING.md) (how to contribute) and [`.github/workflows/lint.yml`](.github/workflows/lint.yml) (what CI enforces). Where this file and CI disagree, CI is the current behavior: raise the mismatch in the review.

The recurring defect in this repo is a check that looks active but cannot fail. Ask of every change: **what would make this go red, and has that been shown?**

## Severity

| Level | Meaning | Action |
|-------|---------|--------|
| Blocker | Exposed secret, exploitable injection, unpinned action, a scanner or gate that can no longer fail | Do not merge |
| Major | Wrong scanner verdict, missing test for new behavior, weakened gate without rationale | Fix before merge |
| Minor | Clarity, naming, or small maintainability issues | Fix or record why not |

## Security

### Scanner correctness

A wrong security verdict is worse than no verdict, because users act on it.

- [ ] The check detects what its ID and message claim, and its failing branch is reachable. Verify with a fixture that triggers it, as well as a clean one.
- [ ] Tests exercise both pass and fail outcomes. A pass-only test cannot tell a working detector from an inert one.
- [ ] Missing tools, empty input, and failed lookups are not reported as a pass. "Could not check" stays distinct from "checked and clean".
- [ ] Severity and compliance mappings match the finding, and any security claim cites OWASP, NIST, or CIS (MITRE ATLAS for AI/LLM guidance).
- [ ] Network calls sit behind an offline guard, and the scanner never targets a real external system in CI without explicit authorization.

### Injection

Reference: OWASP Top 10 (Injection), CWE-78, CWE-79.

- [ ] Shell: all expansions are quoted; no `eval` or unquoted command building from file contents, repo names, or config values.
- [ ] Workflows: untrusted `${{ github.* }}` values reach `run:` through `env:`, not direct interpolation (see the `detect` step in `lint.yml`). Reference: OWASP CICD-SEC-4, Poisoned Pipeline Execution.
- [ ] Python: `subprocess` uses argument lists rather than `shell=True` with interpolated input; YAML is parsed with a safe loader.
- [ ] Dashboard: scanned file names, findings, and API responses are HTML-escaped before rendering. The scanned repository is untrusted input.
- [ ] Paths from scanned projects cannot escape the intended directory.

### Supply chain

Reference: OWASP CICD-SEC-3, Dependency Chain Abuse.

- [ ] Every third-party action is pinned to a full 40-character commit SHA, with a version comment where one applies, for example `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1`.
- [ ] A SHA bump is applied consistently, including `templates/` copies that mirror it (`test_ci_template_pin_policy.py`).
- [ ] Binaries fetched with `curl` are pinned by version and sha256, verified before use, and the two values are bumped together (see `actionlint`).
- [ ] Python tools are pinned in a `requirements*.txt` that `pip-audit` installs; a manifest only one job installs is otherwise never audited.
- [ ] New dependencies are justified. `dependency-review` fails on high severity and denies GPL-3.0 and AGPL-3.0.
- [ ] New `--ignore-vuln` entries state what they hide and when to remove them; `pip-audit` does not warn when an ignore is no longer needed.
- [ ] Workflow `permissions:` are least privilege (`lint.yml` uses `contents: read`), and any broader grant is explained.
- [ ] No repo-level CodeQL workflow is added; CodeQL stays in default setup.

## Tests

### Local commands

```bash
npm test                                   # pytest scanner/tests/
python3 -m pytest scanner/tests/ -v
bash scanner/tests/test_<name>.sh
CLAUDESEC_DASHBOARD_OFFLINE=1 bash scanner/tests/test_generate_html_dashboard.sh
```

### Review points

- [ ] New scanner checks and bug fixes come with a test in `scanner/tests/`, and a bug-fix test fails without the fix.
- [ ] Tests are hermetic: no live API, no real repository paths, no machine state, and no real PII in fixtures.
- [ ] Any test calling `generate_html_dashboard` exports `CLAUDESEC_DASHBOARD_OFFLINE=1` itself. Without it the test can hang on live GitHub API calls.
- [ ] A new `scanner/tests/test_*.sh` is added to the explicit list in `scanner-unit-tests`. That list does not auto-discover, and `test_ci_reachability.py` fails on an omission.
- [ ] CI guards in `scanner/tests/test_ci_*.py` stay stdlib-only, because `ci-guards` installs nothing.
- [ ] Coverage is not treated as proof of usefulness: dead code can be fully covered. Assertions must check behavior.

### CI jobs in `lint.yml`

| Job | Runs on | Enforces |
|-----|---------|----------|
| `changes` | every run | Path buckets that gate the jobs below |
| `dependency-review` | pull requests | Vulnerable or denied-license dependencies |
| `npm-audit` | `npm_deps` | `npm audit --audit-level=high` |
| `pip-audit` | `python_deps` | `pip-audit --strict` |
| `shell-lint` | `shell` | ShellCheck v0.11.0, `severity: error` |
| `python-lint` | `python` | Ruff with `ruff.toml` |
| `ci-guards` | `ci_config` | `test_ci_*.py` guards, stdlib only |
| `renderer-canary` | `ci_config` | Markdown guards against `markdown-it-py` |
| `actionlint` | `ci_config` | Workflow lint, with a second pass for SC2154 |
| `scanner-unit-tests` | `scanner` | Shell tests, pytest, 99% `scanner/lib` floor |
| `scanner-shell-coverage` | `scanner` | kcov, 90% floor |

The audit, lint, guard, and scanner jobs above also run on the weekly schedule. Docs-only PRs still run `markdown-lint`, `link-check`, `gitleaks`, `pii-check`, and `frontmatter-check`. A `skipping` heavy job is expected on unrelated changes.

### Changes to gates

- [ ] Required checks use job-level gating with an `always()` aggregator, never workflow-level `paths-ignore`.
- [ ] A path-gated job's bucket includes every file that can change its verdict, including its own workflow. Over-inclusion is the safe direction.
- [ ] A narrowed or deferred verdict (`|| true`, `set +e`, `fail_on_failure: false`) says what it hides and where the real verdict is raised.
- [ ] A gate fails closed when it ran nothing: "0 tests" or "0 files" is a failure.
- [ ] Coverage floors are not lowered, and `--cov-precision=2` stays in place.

## Secrets Handling

Enforced by `gitleaks` and `pii-check` in `lint.yml`, GitGuardian as a separate PR check, and the pre-commit hooks. These are a backstop, so still read the diff.

- [ ] No API keys, passwords, tokens, or kubeconfig contents, including in fixtures, logs, screenshots, and generated reports.
- [ ] No real names, emails, hostnames, IP addresses, account IDs, company names, or internal paths. Use placeholders such as `~/.kube/config`, `/path/to/kubeconfig`, and `your-api-key-here`.
- [ ] `.claudesec.yml` is not committed; users copy from `templates/*.example.yml`.
- [ ] Credentials come from environment variables or gitignored local files, and are not passed as command-line arguments or written to logs and dashboards.
- [ ] New `.gitleaks.toml` allowlist entries are narrow and explained.
- [ ] Review comments never quote a secret; mask it.

If a real secret is found: stop the review, treat it as a Blocker, and have it rotated. Deleting it from the branch does not make it safe, because it stays in history.

## Style and Lint

### Python (Ruff)

```bash
python3 -m pip install -r requirements-lint.txt
ruff check . --no-cache
```

- `ruff.toml` selects `E9`, `F`, `B`, and `PLE`, and ignores `F541`.
- Widening `select` changes a required check, so it is a separate decision. The rejected families and their measurements are recorded in `ruff.toml`.
- Blind `except` is not linted, so review it by hand: degrading is acceptable only where intended, and must not turn a failed check into a pass.
- Use `zip(..., strict=)` deliberately (B905); silent truncation hides data.

### Shell (ShellCheck)

```bash
SHELLCHECK_OPTS=-x shellcheck path/to/script.sh
```

- Scripts start with `set -euo pipefail` and quote all expansions.
- CI fails only on `error` severity, so warnings such as SC2086 must be caught in review.
- CI skips `templates/`, `examples/`, `docs/`, `assets/`, `.claude/`, and `.github/`. Shell shipped from `templates/` and `examples/` reaches users unchecked, so review it by hand.
- Changing `SHELLCHECK_OPTS` requires updating `docs/guides/shell-lint-policy.md` in the same PR.

### Markdown

```bash
markdownlint "**/*.md"
lychee "**/*.md"
```

- Files use kebab-case names and ATX headers, and fenced code blocks declare a language.
- Docs under `docs/` have `title`, `description`, and `tags` frontmatter.
- Examples are runnable, and guides give "why" context before "how".

### General

- Changes are minimal and every changed line traces to the PR's purpose.
- Comments on gates and workarounds explain the reason, and are updated with the code.
- Hard-coded counts in prose are avoided; give the command that lists the items.

## PR Checklist

- [ ] Branched from an up-to-date `origin/main`; nothing was pushed to `main`.
- [ ] `git diff --stat origin/main` lists only files this PR intends to change.
- [ ] Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, ...).
- [ ] The PR body explains why, and includes a test plan with commands and results.
- [ ] Relevant local tests pass, and new behavior has been seen failing and passing.
- [ ] Docs changes pass `markdownlint` and `lychee`; Python and shell changes pass `ruff` and `shellcheck`.
- [ ] Pre-commit hooks ran (`pre-commit install`) and were not bypassed.
- [ ] The Secrets Handling section has been checked against the full diff.
- [ ] Injection and scanner correctness have been reviewed for changed code paths.
- [ ] New or updated actions are SHA-pinned, with `templates/` kept in step.
- [ ] Security claims cite an authoritative source.
- [ ] Required checks are green, and any skipped job is explained by its path gate.
- [ ] An external action download `401` was rerun up to 2 times before triage.
- [ ] Open PRs stacked on this branch are retargeted before merging it.
- [ ] Merge by squash with `--delete-branch`, then confirm the squash contains only this PR's files with `git show --stat --format="" <squash-sha>`.
