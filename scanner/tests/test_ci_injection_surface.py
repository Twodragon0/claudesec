"""
Regression guard: no GitHub Actions **script-injection** surface in any workflow.

THE RISK (OWASP CICD-SEC-4 / GitHub script injection)
-----------------------------------------------------
Interpolating an attacker-controllable `${{ github.event.* }}` value DIRECTLY
into a `run:` shell body is remote-code-execution: a crafted PR title, branch
name, issue/comment body, or commit message can break out of the intended
command and run with the workflow's token. GitHub documents this exact class and
the specific untrusted contexts in "Security hardening for GitHub Actions"
(https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections).

The safe pattern is to pass the value through an `env:` block and reference the
shell variable (`env: { TITLE: ${{ ... }} }` then `"$TITLE"`), which never lets
the value be parsed as script. This guard asserts no workflow regresses to the
unsafe inline form.

WHY IT IS NEEDED HERE (incident-backed bar)
-------------------------------------------
- `npm-publish.yml` interpolated a step output inline (`VERSION="${{ ... }}"`),
  hardened to an `env:` block in #266 — a concrete (if low-risk) instance.
- `og-meta-verify.yml` runs on `pull_request` with `pull-requests: write`; a
  future edit there interpolating PR title/body into a `run:` would be the exact
  RCE incident. This guard makes that regression fail loudly and reviewably.

WHAT IT CHECKS / DOES NOT
-------------------------
- Scans ONLY `run:` shell bodies (inline `run: cmd` and block scalars `run: |` /
  `run: >`). Interpolation in `if:`, `with:`, `name:`, or an `env:` mapping is a
  GitHub-expression / assignment context, NOT shell injection, and is ignored.
- Flags only the **documented-untrusted** contexts (free-text fields an external
  actor controls), not every `${{ }}` — `github.sha`, `github.ref`,
  `needs.*.outputs.*`, etc. are safe and not flagged. This keeps the guard
  low-noise and non-vacuous (direction: presence-of-violation — the unsafe inline
  interpolation must be ABSENT).

If a workflow legitimately must reference one of these in a `run:`, move it to an
`env:` block (the documented fix) — do not weaken this guard.

stdlib-only (regex/line scanning, no PyYAML — absent from requirements-ci.txt).
No network, no subprocess. Passes under pytest (the CI runner) and
`python3 -m unittest`. Does not import scanner/lib, so it never moves the
measured coverage gate.
"""

import re
import unittest
from glob import glob
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# GitHub-documented untrusted-input contexts (the free-text fields an external
# actor controls). Each is a regex searched INSIDE a `${{ ... }}` expression that
# appears in a `run:` body. Indexed paths (commits[0].message, pages[0].page_name)
# are matched with `.*` between the collection and the leaf field.
UNTRUSTED_CONTEXT_PATTERNS = [
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.pull_request\.(title|body)",
    # head.ref/label and ANY head.repo.* field (full_name/name/clone_url/
    # owner.login are all attacker-chosen on a fork PR).
    r"github\.event\.pull_request\.head\.(ref|label|repo\.[^}\s]+)",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.discussion\.(title|body)",
    r"github\.event\.discussion_comment\.comment\.body",
    r"github\.event\.(commits|head_commit)\b[^}]*\.(message|author\.(email|name))",
    r"github\.event\.pages\b[^}]*\.page_name",
    # workflow_dispatch inputs (attacker-controllable free-text for string inputs;
    # write-access-gated but still a documented untrusted context).
    r"github\.event\.inputs\.[^}\s]+",
    # workflow_run: runs at base-branch perms with data from the untrusted head.
    r"github\.event\.workflow_run\.(head_branch|head_sha|display_title|name)",
    r"github\.event\.workflow_run\.head_commit\b[^}]*\.(message|author\.(email|name))",
    r"github\.event\.workflow_run\.head_repository\.[^}\s]+",
    r"github\.event\.sender\.login",
    r"github\.event\.label\.name",
    r"github\.event\.milestone\.(title|description)",
    # `edited` events expose the previous (attacker-controlled) text in changes.*.
    r"github\.event\.changes\.(title|body)\.from",
    # `release` events: name/body/tag are author free-text.
    r"github\.event\.release\.(body|name|tag_name)",
    r"github\.head_ref",
]
_UNTRUSTED_RE = re.compile("|".join(UNTRUSTED_CONTEXT_PATTERNS))
_EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}")
# Capture the FULL prefix before `run:` (indent + an optional `- ` list-item
# marker) so the block-scalar body threshold is the COLUMN of `run:` itself — a
# sibling step key (e.g. `name:`) aligns with `run:` and must end the body, while
# the body is indented deeper.
_RUN_RE = re.compile(r"^(\s*(?:-\s+)?)run:\s?(.*)$")


def _lead_width(s: str) -> int:
    """Leading-whitespace width of `s` in columns, with tabs expanded to 8 — so
    a tab-indented line is measured on the same scale as a space-indented one."""
    e = s.expandtabs(8)
    return len(e) - len(e.lstrip())


def run_block_lines(text: str) -> list:
    """The shell-body lines of every `run:` step in `text`.

    Handles inline `run: <cmd>` (one line) and block scalars (`run: |` / `run: >`
    with optional chomping/indent indicators): a block body is the following
    lines that are blank or indented DEEPER than the `run:` key, up to the first
    non-blank line indented at-or-below the key. This is intentionally
    indentation-based — YAML block scalars are defined by indentation, and we do
    not need a full YAML parser (PyYAML is unavailable in the CI test job)."""
    lines = text.splitlines()
    out, i, n = [], 0, len(lines)
    while i < n:
        m = _RUN_RE.match(lines[i])
        if not m:
            i += 1
            continue
        # The threshold is the COLUMN where `run:` starts = the full display
        # width of its prefix (indent + optional `- `), tabs expanded. NOT
        # _lead_width: the prefix isn't pure whitespace (the `- ` marker), so its
        # leading-whitespace width would wrongly be the dash column and slurp
        # sibling keys. Body lines ARE leading-whitespace, so they use _lead_width.
        indent = len(m.group(1).expandtabs(8))
        rest = m.group(2).rstrip()
        # In YAML a scalar value that STARTS with `|` or `>` is a block scalar —
        # those are the only two block-scalar indicators; the remainder of that
        # line is chomping/indent indicators and an optional `# comment`, never
        # shell. Any other non-empty value is an inline command. This first-char
        # rule is complete by the YAML grammar, unlike a header-enumerating regex
        # (which missed `|2-` and `| # comment` across two reviews).
        if rest and rest[0] not in "|>":
            out.append(rest)  # inline `run: <cmd>`
            i += 1
            continue
        # Block scalar: collect deeper-indented (or blank) following lines.
        i += 1
        while i < n:
            ln = lines[i]
            if ln.strip() == "":
                out.append(ln)
                i += 1
                continue
            if _lead_width(ln) > indent:
                out.append(ln)
                i += 1
            else:
                break
    return out


def injection_violations(text: str) -> list:
    """`(line, context)` for every untrusted `${{ }}` interpolation inside a
    `run:` shell body of `text`."""
    out = []
    for line in run_block_lines(text):
        for expr in _EXPR_RE.findall(line):
            m = _UNTRUSTED_RE.search(expr)
            if m:
                out.append((line.strip(), m.group(0)))
    return out


def _workflow_files():
    return sorted(glob(str(WORKFLOW_DIR / "*.yml")))


class TestNoInjectionSurface(unittest.TestCase):
    def test_workflow_dir_canary(self):
        # If the glob finds nothing the path broke — fail loudly rather than
        # vacuously "passing" the injection scan below.
        self.assertTrue(
            _workflow_files(),
            f"No workflow files found under {WORKFLOW_DIR} — path assumption broke",
        )

    def test_no_untrusted_interpolation_in_run_blocks(self):
        offenders = []
        for path in _workflow_files():
            text = Path(path).read_text(encoding="utf-8")
            for line, ctx in injection_violations(text):
                offenders.append(f"{Path(path).name}: ${{{{ ...{ctx}... }}}}  in:  {line}")
        self.assertEqual(
            offenders,
            [],
            "Untrusted `${{ github.event.* }}` interpolated directly into a `run:` "
            "shell body — script-injection / RCE surface (OWASP CICD-SEC-4). Move "
            "the value into an `env:` block and reference `$VAR` in the shell:\n  "
            + "\n  ".join(offenders),
        )


class TestInjectionDetectorMutation(unittest.TestCase):
    """Non-vacuity: the detector must FIRE on the unsafe inline form and stay
    QUIET on the safe `env:`/expression-context forms and the real workflows."""

    _UNSAFE_INLINE = "\n".join(
        [
            "jobs:",
            "  greet:",
            "    runs-on: ubuntu-latest",
            "    steps:",
            "      - name: comment",
            "        run: echo '${{ github.event.issue.title }}'",
        ]
    )
    _UNSAFE_BLOCK = "\n".join(
        [
            "jobs:",
            "  greet:",
            "    steps:",
            "      - run: |",
            "          TITLE='${{ github.event.pull_request.title }}'",
            "          echo \"$TITLE\"",
        ]
    )
    _SAFE_ENV = "\n".join(
        [
            "jobs:",
            "  greet:",
            "    steps:",
            "      - env:",
            "          TITLE: ${{ github.event.issue.title }}",
            "        run: echo \"$TITLE\"",
        ]
    )
    _SAFE_IF_AND_TRUSTED = "\n".join(
        [
            "jobs:",
            "  build:",
            "    steps:",
            "      - if: ${{ github.event.pull_request.title != '' }}",
            "        run: echo '${{ github.sha }}' && echo '${{ needs.x.outputs.v }}'",
        ]
    )

    def test_fires_on_unsafe_inline(self):
        v = injection_violations(self._UNSAFE_INLINE)
        self.assertTrue(
            any("github.event.issue.title" in c for _, c in v),
            "Mutation FAILED: inline `run:` interpolation of an untrusted PR/issue "
            "field was NOT detected.",
        )

    def test_fires_on_unsafe_block_scalar(self):
        v = injection_violations(self._UNSAFE_BLOCK)
        self.assertTrue(
            any("github.event.pull_request.title" in c for _, c in v),
            "Mutation FAILED: untrusted interpolation inside a `run: |` block "
            "scalar was NOT detected.",
        )

    def test_quiet_on_env_block(self):
        # The documented-safe fix (value via env:) must NOT be flagged — only the
        # `run:` body is shell, and here it references $TITLE, not the expression.
        self.assertEqual(
            injection_violations(self._SAFE_ENV),
            [],
            "False positive: an `env:`-block interpolation (the documented-safe "
            "pattern) was treated as a run-body injection.",
        )

    _SAFE_SIBLING_KEY = "\n".join(
        [
            "jobs:",
            "  j:",
            "    steps:",
            "      - run: |",
            "          echo safe",
            "        with:",
            "          title: ${{ github.event.issue.title }}",
        ]
    )

    def test_block_body_stops_at_sibling_key(self):
        # A `with:`/`env:` sibling key aligns with the `run:` column and must END
        # the block body — its (non-shell) interpolation must NOT be slurped into
        # the run body and flagged. (Regression: the indent threshold must be the
        # `run:` column, not the `- ` marker column.)
        self.assertEqual(
            injection_violations(self._SAFE_SIBLING_KEY),
            [],
            "False positive: a sibling step key after a `run:` block scalar was "
            "slurped into the run body — block-scalar indent threshold is wrong.",
        )

    def test_quiet_on_if_and_trusted_contexts(self):
        # `if:` is an expression context (not shell); github.sha / needs.* are
        # trusted. None should be flagged.
        self.assertEqual(
            injection_violations(self._SAFE_IF_AND_TRUSTED),
            [],
            "False positive: an `if:` expression or a trusted context "
            "(github.sha / needs.*) was treated as an injection surface.",
        )

    def test_fires_on_digit_chomping_block_scalar(self):
        # Finding 1 (CRITICAL): `run: |2-` (indent-then-chomping) must NOT be
        # mistaken for an inline command — the body has to be scanned.
        for indicator in ("|2-", "|-2", "|2", "|-", ">+", ">1+"):
            wf = "\n".join(
                [
                    "jobs:",
                    "  j:",
                    "    steps:",
                    f"      - run: {indicator}",
                    "          echo '${{ github.event.issue.title }}'",
                ]
            )
            with self.subTest(indicator=indicator):
                self.assertTrue(
                    any("github.event.issue.title" in c for _, c in injection_violations(wf)),
                    f"Mutation FAILED: `run: {indicator}` block body was not scanned "
                    "— the scalar-indicator regex is too narrow (guard evasion).",
                )

    def test_fires_on_block_scalar_with_trailing_comment(self):
        # Second-review CRITICAL: a trailing YAML comment on the block-scalar
        # header (`run: | # note`) is valid YAML — the body must still be scanned.
        for indicator in ("| # shell", "> # script", "|2 # c", "|- # strip"):
            wf = "\n".join(
                [
                    "jobs:", "  j:", "    steps:",
                    f"      - run: {indicator}",
                    "          echo '${{ github.event.issue.title }}'",
                ]
            )
            with self.subTest(indicator=indicator):
                self.assertTrue(
                    any("github.event.issue.title" in c for _, c in injection_violations(wf)),
                    f"Mutation FAILED: `run: {indicator}` body not scanned — a "
                    "comment in the scalar header evaded the guard.",
                )

    def test_fires_on_changes_and_release_contexts(self):
        for expr in (
            "github.event.changes.title.from",
            "github.event.changes.body.from",
            "github.event.release.body",
            "github.event.release.tag_name",
        ):
            wf = "\n".join(
                ["jobs:", "  j:", "    steps:", f"      - run: echo '${{{{ {expr} }}}}'"]
            )
            with self.subTest(expr=expr):
                self.assertTrue(
                    injection_violations(wf),
                    f"Mutation FAILED: untrusted context `{expr}` not detected.",
                )

    def test_fires_on_workflow_dispatch_input(self):
        wf = "\n".join(
            ["jobs:", "  j:", "    steps:",
             "      - run: curl \"${{ github.event.inputs.target_url }}\""]
        )
        self.assertTrue(
            any("github.event.inputs" in c for _, c in injection_violations(wf)),
            "Mutation FAILED: workflow_dispatch input interpolation not detected.",
        )

    def test_fires_on_workflow_run_and_head_repo(self):
        for expr in (
            "github.event.workflow_run.head_branch",
            "github.event.pull_request.head.repo.full_name",
            "github.event.sender.login",
            "github.event.label.name",
        ):
            wf = "\n".join(
                ["jobs:", "  j:", "    steps:", f"      - run: echo '${{{{ {expr} }}}}'"]
            )
            with self.subTest(expr=expr):
                self.assertTrue(
                    injection_violations(wf),
                    f"Mutation FAILED: untrusted context `{expr}` not detected.",
                )

    def test_fires_on_tab_indented_body(self):
        # Finding 7: a tab-indented block body must still be measured as deeper
        # than the space-indented `run:` key and therefore scanned.
        wf = "      - run: |\n\t\t\techo '${{ github.event.comment.body }}'"
        wf = "jobs:\n  j:\n    steps:\n" + wf
        self.assertTrue(
            any("github.event.comment.body" in c for _, c in injection_violations(wf)),
            "Mutation FAILED: tab-indented block body bypassed the indent check.",
        )

    def test_real_workflows_clean(self):
        for path in _workflow_files():
            text = Path(path).read_text(encoding="utf-8")
            self.assertEqual(
                injection_violations(text),
                [],
                f"{Path(path).name} has an untrusted run-body interpolation "
                "(see TestNoInjectionSurface for the remediation).",
            )


if __name__ == "__main__":
    unittest.main()
