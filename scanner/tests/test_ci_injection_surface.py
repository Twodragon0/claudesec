"""
Regression guard: no GitHub Actions **script-injection** surface in any workflow
(`.github/workflows/*.yml`/`*.yaml`) or composite action (`.github/actions/**/
action.yml`) — see `_scanned_files` for why both file sets count.

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
- Scans ONLY `run:` shell bodies (inline `run: cmd` — including its multi-line
  plain/quoted scalar continuation lines — and block scalars `run: |` / `run: >`).
  Interpolation in `if:`, `with:`, `name:`, or an `env:` mapping is a
  GitHub-expression / assignment context, NOT shell injection, and is ignored.
- The `run` key is matched plain OR quoted (`"run":` / `'run':` — same key to any
  YAML parser, and a real authoring style since GitHub's docs normalize `"on":`).
- Whatever a line scanner cannot reassemble is not scanned but is **flagged as an
  unscannable shape**, so an injection cannot hide where the scanner is blind.
  Three tripwires fail closed: `unscannable_flow_runs` (multi-line flow scalar),
  `unscannable_block_runs` (a `${{ }}` split across physical lines), and
  `unscannable_run_keys` (YAML explicit-key `? run` / `: cmd`, where the literal
  `run:` never appears at all). Each has a trivial, always-available remediation.
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
import tempfile
import unittest
from glob import glob
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
# Composite actions: `runs.using: composite` steps run shell too (see `_scanned_files`).
ACTION_DIR = REPO_ROOT / ".github" / "actions"

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
# The mapping key itself may be quoted — `"run": cmd` resolves to the same `run`
# key (verified against PyYAML), and a quoted key is not exotic in this ecosystem:
# GitHub's own docs normalize `"on":` to dodge the YAML-1.1 boolean collision, so
# `"run":` is a plausible authoring style, not a contrived evasion. An adversarial
# review pass proved both the block and flow matchers were blind to it.
_RUN_KEY = r"""(?:run|"run"|'run')"""
_RUN_RE = re.compile(rf"^(\s*(?:-\s+)?){_RUN_KEY}:\s?(.*)$")
# YAML's explicit-key form (`? run` on one line, `: cmd` on the next) yields the
# same `run` key with the substring `run:` never appearing — so no line matcher can
# see it. Reassembling it needs a real parser, so it joins the unscannable SHAPES
# that fail closed (see `unscannable_run_keys`).
_EXPLICIT_RUN_KEY_RE = re.compile(rf"""^\s*(?:-\s+)?\?\s*{_RUN_KEY}\s*(?::|$|#)""")
# Flow-style step mapping — `steps: [{name: x, run: "cmd"}]` — puts `run:`
# mid-line after a `{`/`,`, so the line-anchored block scan above never sees it.
# Match each flow-style run value (double/single-quoted or bare) so its `${{ }}`
# interpolations are scanned too. Closes the single-physical-line flow form per
# ADR-001 §4 (flow style is spec-standard YAML sugar, not an edge form).
#
# KNOWN LIMITATION (backlog, catalog "Quarterly audit 2026-07-28"): a flow-style
# run value whose quoted string SPANS MULTIPLE physical lines is not reassembled
# here — the closing quote must be on the same line. A full flow-YAML string
# scanner is infeasible under the stdlib-only / no-PyYAML constraint; the risk is
# minimal (a multi-line-quoted flow-style `run:` string is a pathological form no
# author writes) and is tracked rather than half-closed with a fragile
# bracket-depth heuristic that could false-positive on block-scalar shell bodies.
_FLOW_RUN_RE = re.compile(
    rf"""[{{,]\s*{_RUN_KEY}:\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,}}\]]+)"""
)
# A flow-style `run:` whose quoted value is NOT closed on its physical line — a
# multi-line flow scalar. A stdlib/no-PyYAML line scanner cannot reassemble it
# (bracket-depth folding can't tell YAML flow braces from shell `${..}`/`{ ..; }`
# without a real parser), so its `${{ }}` interpolations would go UNSCANNED. We
# don't try to scan it — we FLAG its presence so a would-be injection can't hide
# in an unscannable shape (see `unscannable_flow_runs`). The value is unterminated
# when, after the opening quote, no matching close appears before end-of-line.
_FLOW_RUN_UNTERMINATED_RE = re.compile(
    rf"""[{{,]\s*{_RUN_KEY}:\s*(?:"(?:[^"\\]|\\.)*|'(?:[^'\\]|\\.)*)$"""
)


# An opened `${{` with no `}}` after it on the SAME physical line — a GitHub
# expression split across lines. YAML folds the newline away, so the runner sees
# one expression, but a line scanner sees two halves and `_EXPR_RE` (non-greedy,
# single-line) matches neither: the untrusted context would go UNSCANNED. Scanned
# as a character walk rather than a regex because `${{`/`}}` may repeat on a line
# and only the LAST opener's termination matters.
def _expr_unterminated(line: str) -> bool:
    i = 0
    while True:
        start = line.find("${{", i)
        if start == -1:
            return False
        end = line.find("}}", start + 3)
        if end == -1:
            return True
        i = end + 2


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
        inline = bool(rest) and rest[0] not in "|>"
        if inline:
            out.append(rest)  # inline `run: <cmd>` (first physical line)
        # Fall through to the SAME deeper-indented collection loop for both cases.
        # For a block scalar those lines are the body. For an inline value they are
        # the continuation lines of a multi-line plain/quoted scalar (`run: echo`
        # then a deeper `'${{ ... }}'` line) — legal YAML that folds into one
        # command, and previously dropped entirely, so an untrusted interpolation
        # on a continuation line went unscanned. The indentation rule is the same
        # for both scalar styles, and its error direction is safe: over-collecting
        # a non-continuation line can only raise a false ALARM (a sibling key
        # aligns with `run:` and still terminates the scan — see
        # `test_block_body_stops_at_sibling_key`), never a silent bypass.
        i += 1
        while i < n:
            ln = lines[i]
            if ln.strip() == "":
                out.append(ln)
                i += 1
                continue
            # A comment-only line ENDS an inline (plain/quoted) scalar: PyYAML
            # rejects `run: echo` / `# c` / `hi` as a parse error, so a plain
            # scalar cannot resume after a comment — anything below is not part of
            # the command. Stopping here is exact, not conservative, and it removes
            # a false positive (a `# never do: ${{ github.event.issue.title }}`
            # warning comment beside the step used to be scanned as shell). In a
            # BLOCK scalar the same line is literal body text, so it is still
            # collected there.
            if inline and ln.lstrip().startswith("#"):
                break
            if _lead_width(ln) > indent:
                out.append(ln)
                i += 1
            else:
                break
    # Flow-style `run:` values (see _FLOW_RUN_RE) — one physical line may hold
    # several step mappings, each contributing its command string. A bare/quoted
    # value is unwrapped so `_EXPR_RE` sees the same shell text the runner would.
    for ln in lines:
        for fm in _FLOW_RUN_RE.finditer(ln):
            val = fm.group(1).strip()
            if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
                val = val[1:-1]  # unquote
            out.append(val)
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


def unscannable_flow_runs(text: str) -> list:
    """Lines with a flow-style `run:` whose quoted value spans multiple physical
    lines (see `_FLOW_RUN_UNTERMINATED_RE`).

    Such a value cannot be statically reassembled under the stdlib/no-PyYAML
    constraint, so `injection_violations` would silently miss an untrusted
    `${{ }}` inside it. Rather than half-close that gap with a fragile
    bracket-depth heuristic, this tripwire flags the unscannable SHAPE so the
    author restructures to a block scalar (fully scanned) or a single-line flow
    value (already scanned) — ADR-001 §4 (prefer a rule complete by construction
    over an incomplete reassembler). Dormant on this repo (all `run:` are block
    style), so it is false-positive-free today."""
    return [ln.strip() for ln in text.splitlines() if _FLOW_RUN_UNTERMINATED_RE.search(ln)]


def unscannable_block_runs(text: str) -> list:
    """Run-body lines that open a `${{` without closing it on the same physical
    line (see `_expr_unterminated`) — a GitHub expression split across lines.

    The sibling tripwire to `unscannable_flow_runs`, closing the last documented
    scanner gap of this guard. YAML folds the newline, so the runner evaluates one
    expression, but `injection_violations` matches `${{ ... }}` per line and sees
    neither half — an untrusted context split as `'${{\\n  github.event.issue.title
    }}'` inside a `run: |` body was therefore NOT flagged. Reassembling folded
    lines correctly needs a real YAML parser (unavailable: stdlib-only /
    no-PyYAML), and whether the Actions expression lexer even accepts the split
    form is unverified — so this fails CLOSED on the SHAPE instead of guessing at
    the semantics: the author keeps each `${{ ... }}` on one physical line (always
    possible, and how every expression in this repo is already written).

    ADR-001 §4 — prefer a rule complete by construction over an incomplete
    reassembler. Dormant on this repo (zero unterminated `${{` in any run body),
    so it is false-positive-free today."""
    return [ln.strip() for ln in run_block_lines(text) if _expr_unterminated(ln)]


# An INLINE `run:` whose quoted scalar is not closed on its own physical line —
# `run: "echo` continued on the following lines. YAML folds those lines into one
# command and a `#` inside the quotes is literal content, NOT a comment (verified
# with PyYAML: `run: "echo` / `# c` / `hi"` -> `echo # c hi`), while a PLAIN
# scalar genuinely cannot resume after a comment line (same check: ParserError).
# `run_block_lines` breaks at the comment line for BOTH styles, so for the quoted
# style everything below it — the natural place for the payload — silently left
# the haystack. Single-quoted YAML escapes a quote by doubling it (`''`).
_INLINE_QUOTED_RUN_UNTERMINATED = {
    '"': re.compile(r'"(?:[^"\\]|\\.)*"'),
    "'": re.compile(r"'(?:[^']|'')*'"),
}


def unscannable_inline_runs(text: str) -> list:
    """Lines with an inline `run:` whose QUOTED scalar spans multiple physical
    lines (see `_INLINE_QUOTED_RUN_UNTERMINATED`).

    The block-style twin of `unscannable_flow_runs`, and the last of the four
    unscannable SHAPES. Found by the 2026-08-07 stripper/haystack audit with a
    runnable PoC: PyYAML resolves

        - run: "echo
            # not a comment, this is scalar content
            ${{ github.event.pull_request.title }}"

    to a single command carrying the untrusted context, while
    `injection_violations` reported nothing and no tripwire fired — the exact
    CICD-SEC-4 RCE this guard exists to prevent, hidden in the scanner's blind
    spot. Reassembling a folded multi-line quoted scalar (escapes, `''`, folding
    rules) needs a real YAML parser, so this fails CLOSED on the shape instead
    (ADR-001 §4). Remediation is trivial and always available: a block scalar
    (`run: |`, fully scanned) or a single-line value (already scanned). Zero hits
    across all 18 scanned files today, so it is false-positive-free."""
    out = []
    for ln in text.splitlines():
        m = _RUN_RE.match(ln)
        if not m:
            continue
        rest = m.group(2).strip()
        pat = _INLINE_QUOTED_RUN_UNTERMINATED.get(rest[:1])
        if pat is not None and not pat.match(rest):
            out.append(ln.strip())
    return out


def unscannable_run_keys(text: str) -> list:
    """Lines declaring a `run` step with YAML's explicit-key form (`? run` /
    `: cmd` — see `_EXPLICIT_RUN_KEY_RE`).

    The third unscannable SHAPE, and the one with no substring to match at all:
    the key and its value sit on different lines, so the literal `run:` never
    appears and every line matcher here is blind by construction (confirmed
    against PyYAML: `- ? run` / `  : echo '${{ github.event.issue.title }}'`
    resolves to a real `run` command). Fails closed rather than pretending to
    scan it — the fix is the ordinary `run: cmd` form. Dormant on this repo."""
    return [ln.strip() for ln in text.splitlines() if _EXPLICIT_RUN_KEY_RE.match(ln)]


def _scanned_files():
    """Every file in this repo whose `run:` bodies GitHub Actions executes.

    Two enumeration gaps were found by adversarial review, both silent (a whole
    file simply never scanned, so the guard passed vacuously over it):

    - BOTH extensions: Actions honours `.yaml` as well as `.yml`, so a
      `evil.yaml` workflow was invisible.
    - COMPOSITE ACTIONS: `.github/actions/<name>/action.yml` declares
      `runs.using: composite` with `steps[].run` shell bodies that interpolate
      `${{ }}` exactly like a workflow step, and required workflows call them.
      Two already exist here (`datadog-ci-collect`, `token-expiry-gate`), and a
      live `${{ github.event.pull_request.title }}` planted in one of them left
      this guard green — the same CICD-SEC-4 RCE it exists to prevent.

    Composite actions are matched by their canonical filenames only (`action.yml`
    /`action.yaml` — the two names Actions resolves), not by every `*.yml` under
    the directory, so an unrelated helper YAML there is not treated as shell."""
    out = []
    for name in ("*.yml", "*.yaml"):
        out += glob(str(WORKFLOW_DIR / name))
    for name in ("action.yml", "action.yaml"):
        out += glob(str(ACTION_DIR / "**" / name), recursive=True)
    return sorted(out)


class TestNoInjectionSurface(unittest.TestCase):
    def test_workflow_dir_canary(self):
        # If the glob finds nothing the path broke — fail loudly rather than
        # vacuously "passing" the injection scan below.
        found = _scanned_files()
        self.assertTrue(
            found,
            f"No workflow files found under {WORKFLOW_DIR} — path assumption broke",
        )
        # Per-file-set canaries: a broken ACTION_DIR path (or a workflows-only
        # regression) would otherwise be masked by the other set still matching,
        # and the whole composite-action scan would go vacuously green.
        self.assertTrue(
            [p for p in found if "/workflows/" in p],
            f"No files matched under {WORKFLOW_DIR} — path assumption broke",
        )
        self.assertTrue(
            [p for p in found if "/actions/" in p],
            f"No composite `action.yml` matched under {ACTION_DIR}. This repo has "
            "two; if they were intentionally removed, delete this canary in the "
            "same commit rather than leaving the scan silently empty.",
        )

    def test_no_untrusted_interpolation_in_run_blocks(self):
        offenders = []
        for path in _scanned_files():
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

    def test_no_unscannable_multiline_flow_run(self):
        # A multi-line-quoted flow-style `run:` cannot be scanned for injection
        # under the no-PyYAML constraint; forbid the shape so nothing hides in it.
        offenders = []
        for path in _scanned_files():
            for ln in unscannable_flow_runs(Path(path).read_text(encoding="utf-8")):
                offenders.append(f"{Path(path).name}:  {ln}")
        self.assertEqual(
            offenders,
            [],
            "Flow-style `run:` with a quoted value spanning multiple physical "
            "lines — this cannot be statically scanned for `${{ }}` injection "
            "(stdlib/no-PyYAML). Use a block scalar (`run: |`) or keep the flow "
            "value on one line:\n  " + "\n  ".join(offenders),
        )

    def test_no_unscannable_split_expression_in_run_body(self):
        # A `${{ }}` split across two physical lines inside a run body cannot be
        # reassembled without a YAML parser; forbid the shape so nothing hides.
        offenders = []
        for path in _scanned_files():
            for ln in unscannable_block_runs(Path(path).read_text(encoding="utf-8")):
                offenders.append(f"{Path(path).name}:  {ln}")
        self.assertEqual(
            offenders,
            [],
            "A `${{` in a `run:` shell body is not closed on the same physical "
            "line — a line scanner cannot reassemble the split expression, so it "
            "cannot be checked for untrusted-context injection (stdlib/no-PyYAML). "
            "Keep each `${{ ... }}` on one line (and prefer moving the value into "
            "an `env:` block):\n  " + "\n  ".join(offenders),
        )

    def test_no_unscannable_multiline_inline_run(self):
        # An inline `run:` with a quoted scalar continued on later lines folds a
        # `#` line into the command as literal content, so `run_block_lines`
        # stopped scanning exactly where a payload would sit. Forbid the shape.
        offenders = []
        for path in _scanned_files():
            for ln in unscannable_inline_runs(Path(path).read_text(encoding="utf-8")):
                offenders.append(f"{Path(path).name}:  {ln}")
        self.assertEqual(
            offenders,
            [],
            "An inline `run:` whose QUOTED value is not closed on the same "
            "physical line. YAML folds the continuation lines into one command "
            "and a `#` inside the quotes is content, not a comment, so this "
            "guard cannot scan the command for `${{ }}` injection "
            "(stdlib/no-PyYAML). Use a block scalar (`run: |`) or keep the "
            "value on one line:\n  " + "\n  ".join(offenders),
        )

    def test_no_explicit_key_run_step(self):
        # `? run` / `: cmd` declares a run step with no `run:` substring anywhere,
        # so no line matcher here can see its body. Forbid the shape.
        offenders = []
        for path in _scanned_files():
            for ln in unscannable_run_keys(Path(path).read_text(encoding="utf-8")):
                offenders.append(f"{Path(path).name}:  {ln}")
        self.assertEqual(
            offenders,
            [],
            "A `run` step declared with YAML's explicit-key form (`? run` on one "
            "line, `: cmd` on the next). The literal `run:` never appears, so this "
            "guard cannot scan the command for injection. Use the ordinary "
            "`run: cmd` / `run: |` form:\n  " + "\n  ".join(offenders),
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

    def test_fires_on_flow_style_step(self):
        # Flow-style step mapping (spec-standard YAML) puts `run:` mid-line; the
        # untrusted interpolation must still be detected (ADR-001 §4).
        wf = (
            "jobs:\n  j:\n    steps: "
            "[{name: x, run: \"echo '${{ github.event.issue.title }}'\"}]\n"
        )
        v = injection_violations(wf)
        self.assertTrue(
            any("github.event.issue.title" in ctx for _, ctx in v),
            f"flow-style run: interpolation not detected: {v}",
        )

    def test_tripwire_flags_multiline_flow_scalar(self):
        # A multi-line-quoted flow `run:` is unscannable → the tripwire must flag
        # it (and single-line/block forms must NOT be flagged).
        multiline = 'jobs:\n  j:\n    steps: [{name: x, run: "echo\n      ${{ github.event.issue.title }}"}]\n'
        self.assertTrue(
            unscannable_flow_runs(multiline),
            "tripwire FAILED: a multi-line flow-style run: scalar was not flagged.",
        )
        single_line = 'jobs:\n  j:\n    steps: [{name: x, run: "echo hi"}]\n'
        block = "jobs:\n  j:\n    steps:\n      - run: |\n          echo hi\n"
        self.assertEqual(
            unscannable_flow_runs(single_line), [],
            "tripwire false-positive on a single-line flow value.",
        )
        self.assertEqual(
            unscannable_flow_runs(block), [],
            "tripwire false-positive on a block scalar.",
        )

    _SPLIT_EXPR_BLOCK = "\n".join(
        [
            "jobs:",
            "  j:",
            "    steps:",
            "      - run: |",
            "          echo '${{",
            "            github.event.issue.title }}'",
        ]
    )

    def test_tripwire_flags_split_expression_in_block_scalar(self):
        # Reproduced before the fix: `injection_violations` returns [] on this
        # input (each half-line has no complete `${{ ... }}`), so the tripwire is
        # the ONLY thing standing between a split interpolation and a green guard.
        self.assertEqual(
            injection_violations(self._SPLIT_EXPR_BLOCK),
            [],
            "Precondition changed: the split expression is now scanned directly — "
            "re-derive whether the shape tripwire is still the load-bearing check.",
        )
        self.assertTrue(
            unscannable_block_runs(self._SPLIT_EXPR_BLOCK),
            "tripwire FAILED: a `${{` split across two physical lines inside a "
            "`run: |` body was not flagged — an injection can hide there.",
        )

    def test_tripwire_quiet_on_single_line_expressions(self):
        # Complete expressions (trusted or untrusted, inline or block) are
        # scannable and must NOT be flagged as an unscannable shape — otherwise
        # the tripwire fires on every workflow and gets deleted.
        for wf in (
            self._UNSAFE_INLINE,
            self._UNSAFE_BLOCK,
            self._SAFE_ENV,
            self._SAFE_IF_AND_TRUSTED,
            self._SAFE_SIBLING_KEY,
            "jobs:\n  j:\n    steps:\n      - run: echo '${{ github.sha }}' '${{ github.ref }}'\n",
        ):
            with self.subTest(wf=wf.splitlines()[-1]):
                self.assertEqual(
                    unscannable_block_runs(wf),
                    [],
                    "tripwire false-positive: a `${{ ... }}` that closes on its own "
                    "physical line was reported as unscannable.",
                )

    def test_tripwire_ignores_split_expression_outside_run_body(self):
        # Scope: only `run:` bodies are shell. A split expression in an `env:`
        # mapping is an assignment context, never shell — flagging it would be
        # noise the guard cannot justify.
        wf = "\n".join(
            [
                "jobs:", "  j:", "    steps:",
                "      - env:",
                "          TITLE: ${{",
                "            github.event.issue.title }}",
                "        run: echo \"$TITLE\"",
            ]
        )
        self.assertEqual(
            unscannable_block_runs(wf),
            [],
            "tripwire false-positive: a split expression outside a run body "
            "(env: mapping) was flagged.",
        )

    _MULTILINE_PLAIN_SCALAR = "\n".join(
        [
            "jobs:",
            "  j:",
            "    steps:",
            "      - run: echo",
            "          '${{ github.event.issue.title }}'",
        ]
    )

    def test_fires_on_multiline_plain_scalar_continuation(self):
        # A multi-line plain scalar `run:` folds into `echo '${{ ... }}'` at
        # runtime. The continuation line used to be dropped from the body
        # entirely, so this injection was invisible to BOTH the scanner and the
        # split-expression tripwire (the expression closes on its own line).
        self.assertTrue(
            any(
                "github.event.issue.title" in c
                for _, c in injection_violations(self._MULTILINE_PLAIN_SCALAR)
            ),
            "Mutation FAILED: an untrusted interpolation on the continuation line "
            "of a multi-line plain `run:` scalar was not scanned.",
        )

    def test_inline_run_body_stops_at_sibling_key(self):
        # The continuation collection must not slurp a sibling step key that
        # aligns with the `run:` column (the inline-value analog of
        # `test_block_body_stops_at_sibling_key`).
        #
        # Paired with a POSITIVE control so the test is not vacuous: an
        # absence-only assertion would also pass if continuation collection were
        # deleted outright (nothing collected -> nothing slurped -> green), which
        # is exactly the inert shape ADR-001 warns about. Asserting that a real
        # continuation IS still collected pins both directions in one test.
        for sibling in ("env:", "with:"):
            wf = "\n".join(
                [
                    "jobs:", "  j:", "    steps:",
                    "      - run: echo safe",
                    f"        {sibling}",
                    "          title: ${{ github.event.issue.title }}",
                ]
            )
            with self.subTest(sibling=sibling):
                self.assertEqual(
                    injection_violations(wf),
                    [],
                    f"False positive: a `{sibling}` sibling key after an inline "
                    "`run:` was slurped into the run body as a scalar continuation.",
                )
                # Positive control: same step, but the deeper line is a genuine
                # scalar continuation rather than a sibling key.
                live = wf.replace(
                    f"        {sibling}\n          title: ", "          "
                )
                self.assertTrue(
                    any(
                        "github.event.issue.title" in c
                        for _, c in injection_violations(live)
                    ),
                    "Vacuous: the sibling-key boundary passed only because inline "
                    "continuation collection is not running at all.",
                )

    _COMMENT_BESIDE_INLINE_RUN = "\n".join(
        [
            "jobs:",
            "  j:",
            "    steps:",
            "      - run: echo hi",
            "          # never do this: echo '${{ github.event.issue.title }}'",
        ]
    )

    def test_quiet_on_comment_line_after_inline_run(self):
        # PyYAML resolves this step's command to exactly `echo hi` — the comment is
        # not part of the scalar (and a plain scalar cannot even resume after a
        # comment line: `run: echo` / `# c` / `hi` is a parse error). Scanning it
        # as shell would fail CI on a maintainer documenting the unsafe pattern.
        self.assertEqual(
            injection_violations(self._COMMENT_BESIDE_INLINE_RUN),
            [],
            "False positive: a YAML comment beside an inline `run:` was collected "
            "as a scalar continuation and scanned as shell.",
        )

    def test_fires_on_quoted_run_key(self):
        # `"run": cmd` resolves to the same `run` key (verified with PyYAML). A
        # quoted key is a real authoring style in this ecosystem — GitHub's docs
        # normalize `"on":` for the YAML-1.1 boolean collision — and BOTH the block
        # and flow matchers were blind to it before this fix.
        for wf in (
            "jobs:\n  j:\n    steps:\n      - \"run\": echo '${{ github.event.issue.title }}'\n",
            "jobs:\n  j:\n    steps:\n      - 'run': echo '${{ github.event.issue.title }}'\n",
            "jobs:\n  j:\n    steps: [{name: x, \"run\": \"echo '${{ github.event.issue.title }}'\"}]\n",
            "jobs:\n  j:\n    steps:\n      - \"run\": |\n          echo '${{ github.event.issue.title }}'\n",
        ):
            with self.subTest(wf=wf.splitlines()[-1].strip()):
                self.assertTrue(
                    any(
                        "github.event.issue.title" in c
                        for _, c in injection_violations(wf)
                    ),
                    "Mutation FAILED: a quoted `run` key hid the command from the "
                    "scan — guard evasion via standard YAML key quoting.",
                )

    def test_quoted_run_key_does_not_match_other_keys(self):
        # The quoted-key alternation must not widen into unrelated keys: `runs-on`
        # and a `"name"` value mentioning an untrusted context are not shell.
        wf = "\n".join(
            [
                "jobs:", "  j:",
                "    runs-on: ubuntu-latest",
                "    steps:",
                "      - \"name\": check ${{ github.event.issue.title }}",
                "        run: echo safe",
            ]
        )
        self.assertEqual(
            injection_violations(wf),
            [],
            "False positive: the quoted-run-key pattern matched a non-`run` key.",
        )

    def test_tripwire_flags_explicit_key_run_step(self):
        # `? run` / `: cmd` — the key and value are on different lines, so the
        # literal `run:` never appears and nothing here can scan the body.
        for wf in (
            "jobs:\n  j:\n    steps:\n      - ? run\n        : echo '${{ github.event.issue.title }}'\n",
            "jobs:\n  j:\n    steps:\n      - ? \"run\"\n        : echo hi\n",
            "jobs:\n  j:\n    steps:\n      - ? run  # explicit\n        : echo hi\n",
        ):
            with self.subTest(wf=wf.splitlines()[3].strip()):
                self.assertEqual(
                    injection_violations(wf),
                    [],
                    "Precondition changed: the explicit-key form is now scanned "
                    "directly — re-derive whether the shape tripwire is still the "
                    "load-bearing check.",
                )
                self.assertTrue(
                    unscannable_run_keys(wf),
                    "tripwire FAILED: an explicit-key (`? run`) step was not "
                    "flagged, and its body is unscannable.",
                )

    def test_explicit_key_tripwire_quiet_on_normal_steps(self):
        for wf in (self._UNSAFE_INLINE, self._UNSAFE_BLOCK, self._SAFE_ENV,
                   "jobs:\n  j:\n    steps:\n      - run: echo '? run'\n",
                   "jobs:\n  j:\n    steps:\n      - ? runner\n        : x\n"):
            with self.subTest(wf=wf.splitlines()[-1].strip()):
                self.assertEqual(
                    unscannable_run_keys(wf),
                    [],
                    "tripwire false-positive: a normal step (or a non-`run` "
                    "explicit key) was reported as an explicit-key run step.",
                )

    def test_tripwire_flags_multiline_quoted_inline_run(self):
        # 2026-08-07 audit finding. PyYAML resolves each of these to ONE command
        # carrying the untrusted context (`echo # … ${{ … }}`), because a `#`
        # inside a quoted scalar is content — but `run_block_lines` breaks at the
        # comment line, so the payload never reaches `injection_violations`.
        for wf in (
            'jobs:\n  j:\n    steps:\n      - run: "echo\n'
            "          # not a comment\n"
            "          ${{ github.event.pull_request.title }}\"\n",
            "jobs:\n  j:\n    steps:\n      - run: 'echo\n"
            "          # not a comment\n"
            "          ${{ github.event.issue.title }}'\n",
        ):
            with self.subTest(wf=wf.splitlines()[3].strip()):
                self.assertEqual(
                    injection_violations(wf),
                    [],
                    "Precondition changed: the folded quoted scalar is now scanned "
                    "directly — re-derive whether the shape tripwire is still the "
                    "load-bearing check.",
                )
                self.assertTrue(
                    unscannable_inline_runs(wf),
                    "tripwire FAILED: an inline `run:` with a multi-line quoted "
                    "scalar was not flagged, and its command is unscannable — a "
                    "live `${{ github.event.* }}` interpolation hides there.",
                )

    def test_inline_run_tripwire_quiet_on_normal_steps(self):
        for wf in (
            self._UNSAFE_INLINE,
            self._UNSAFE_BLOCK,
            self._SAFE_ENV,
            # Closed on the same line, in both quote styles.
            "jobs:\n  j:\n    steps:\n      - run: \"echo hi\"\n",
            "jobs:\n  j:\n    steps:\n      - run: 'echo hi'\n",
            # An escaped/doubled quote inside a value that IS closed.
            'jobs:\n  j:\n    steps:\n      - run: "echo \\"hi\\""\n',
            "jobs:\n  j:\n    steps:\n      - run: 'echo ''hi'''\n",
            # A plain scalar starting with a quote-free word, and a block scalar.
            "jobs:\n  j:\n    steps:\n      - run: echo \"unbalanced\n",
            "jobs:\n  j:\n    steps:\n      - run: |\n          echo hi\n",
        ):
            with self.subTest(wf=wf.splitlines()[3].strip()):
                self.assertEqual(
                    unscannable_inline_runs(wf),
                    [],
                    "tripwire false-positive: a `run:` value that is closed on its "
                    "own line (or is not a quoted scalar at all) was reported as "
                    "unscannable.",
                )

    def test_scanned_files_covers_yaml_extension_and_composite_actions(self):
        # GitHub Actions runs `.yaml` workflows too, and a composite action's
        # `steps[].run` is shell all the same — globbing only
        # `.github/workflows/*.yml` left both entirely unscanned. Asserted
        # BEHAVIOURALLY (redirect the scanned dirs at a fixture), not by reading
        # this file's own source — a source-text assertion is the inert shape
        # `test_ci_guard_assertion_scoping.py` exists to reject.
        global WORKFLOW_DIR, ACTION_DIR
        original_wf, original_act = WORKFLOW_DIR, ACTION_DIR
        with tempfile.TemporaryDirectory() as tmp:
            wf = Path(tmp, "workflows")
            wf.mkdir()
            Path(wf, "a.yml").write_text("jobs: {}\n", encoding="utf-8")
            Path(wf, "b.yaml").write_text("jobs: {}\n", encoding="utf-8")
            Path(wf, "notes.txt").write_text("ignored\n", encoding="utf-8")
            act = Path(tmp, "actions")
            # Nested one level deep, the layout Actions requires.
            (act / "c").mkdir(parents=True)
            (act / "d").mkdir(parents=True)
            Path(act, "c", "action.yml").write_text("runs: {}\n", encoding="utf-8")
            Path(act, "d", "action.yaml").write_text("runs: {}\n", encoding="utf-8")
            # NOT a composite-action entrypoint — Actions only resolves
            # `action.yml`/`action.yaml`, so a helper YAML here is not shell.
            Path(act, "c", "helper.yml").write_text("x: 1\n", encoding="utf-8")
            try:
                WORKFLOW_DIR, ACTION_DIR = wf, act
                found = sorted(Path(p).name for p in _scanned_files())
            finally:
                WORKFLOW_DIR, ACTION_DIR = original_wf, original_act
        self.assertEqual(
            found,
            ["a.yml", "action.yaml", "action.yml", "b.yaml"],
            "`_scanned_files()` must find workflow `*.yml` AND `*.yaml` AND nested "
            "composite `action.yml`/`action.yaml`, and nothing else (no `.txt`, no "
            "non-entrypoint `helper.yml`). Actions honours both extensions and "
            "executes composite `steps[].run` as shell, so anything missed here is "
            f"a whole file scanned by nobody. Found: {found}",
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
        for path in _scanned_files():
            text = Path(path).read_text(encoding="utf-8")
            self.assertEqual(
                injection_violations(text),
                [],
                f"{Path(path).name} has an untrusted run-body interpolation "
                "(see TestNoInjectionSurface for the remediation).",
            )


if __name__ == "__main__":
    unittest.main()
