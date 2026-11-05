"""
Regression guard: two CI failures that were fixed must not silently return.

1. Exact Bash/coreutils diagnostics in test code (scanner/tests/**/*.py, *.sh).
   `test_ci_security_gate_behaviour.py` counted `integer expression expected`;
   Bash 5.3 prints `integer expected`, so the test went red on a runner upgrade
   with no product change (PR #594). Such wording belongs to the tool version,
   so a test may only match it through a tolerant regex, spelled so the phrase
   does not appear verbatim: `integer (?:expression )?expected`.

   Rule: no phrase in DIAGNOSTIC_PHRASES in a live string literal. Deliberately
   every literal rather than only assert/count arguments, because
   `PHRASE = "..."; err.count(PHRASE)` passes an argument-only check, and a bare
   statement string (docstring) or a comment cannot affect a test. Python goes
   through `ast`, so concatenated literals, f-strings and escapes are seen as
   the interpreter sees them.

   Residual limits. False alarm: a fixture that merely prints a phrase, or a
   verbatim alternation (`command not found|not found`) — rewrite it with an
   optional group. False negative, accepted as contrived: a phrase assembled at
   runtime (`"integer " + word`), and `.sh` text after a `#` that
   `strip_inline_comment_sh` misreads inside a heredoc or multi-line string.

2. Downloads piped straight into an extractor or shell, in
   .github/workflows/*.y*ml and scripts/docker/*Dockerfile: `curl ... | tar`,
   `| sh`, `| bash`. Nothing can verify the bytes before they are consumed, and
   a pipeline fails on the wrong stage's exit code (PR #595 fixes the kcov one).
   Exact-match: an entry names a file and the whole `curl ... | tar` span, is
   counted, and must still exist, so a new, edited or duplicated download fails
   and so does an entry whose line has gone — a stale entry would silently
   re-admit the exact line that was fixed.

   Direction: an intermediate stage still counts (`curl | tee f | sh`), quoted
   text is searched (`bash -c "curl x | sh"`), scalars YAML folds onto one line
   are joined first, and quoted or wrapped consumers count (`| "bash"`,
   `| env bash`). Over-reports: a `curl` in a `name:` beside a pipe, a more-indented
   line in a folded scalar (YAML keeps that newline), `| time grep sh`.
   Out of scope, not piped: `sh -c "$(curl ...)"`, `bash <(curl ...)`.
   False negatives, accepted because this guards accidents and not an adversary:
   a value on the line after its key (`run:` alone cannot be told from a mapping),
   `| (cd d && tar xz)`, `| "$SHELL"`, `| ba''sh`.

The kcov/CMake invariant itself is `test_ci_docker_kcov_parity.py` (PR #595).
"""

import ast
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import (  # noqa: E402
    apply_mutation,
    assert_disables,
    strip_inline_comment_sh,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
THIS_FILE = Path(__file__).resolve().name

DIAGNOSTIC_PHRASES = (
    "integer expression expected",
    "integer expected",
    "unary operator expected",
    "binary operator expected",
    "command not found",
    "too many arguments",
)

# Live on main until PR #595 merges, which replaces both lines with a download
# verified by sha256 before extraction. Remove these entries in that PR (or here
# if it lands first); test_no_stale_entries fails until they are gone.
KNOWN_PENDING = (
    (
        ".github/workflows/lint.yml",
        "curl -fsSL https://github.com/SimonKagstrom/kcov/archive/refs/tags/v42.tar.gz | tar",
    ),
    (
        "scripts/docker/shell-coverage.Dockerfile",
        'curl -fsSL "https://github.com/SimonKagstrom/kcov/archive/refs/tags/v${KCOV_VERSION}.tar.gz" | tar',
    ),
)

# One word of a command: a quoted string, an escape, or a character that neither
# ends the command nor opens a quote. The alternatives are disjoint, so a failed
# match cannot backtrack exponentially.
_ATOM = r"""(?:"(?:[^"\\]|\\.)*"|'[^']*'|\\.|&(?!&)|[^;|&'"\\])"""
_PIPE = r"\|(?!\|)&?"
# Words before the consumer: `FOO=1`, then a wrapper that runs its arguments. Its
# flags and operands are not modelled, so any later word may be the consumer.
_WORD = r"[^\s;|&]+"
_WRAPPER = r"(?:\S*/)?(?:sudo|doas|env|exec|command|nice|nohup|time|busybox)"
_CONSUMER_PREFIX = rf"(?:\w+=\S*\s+)*(?:{_WRAPPER}\s+(?:{_WORD}\s+)*?)?"
PIPED_DOWNLOAD = re.compile(
    rf"(?<![\w.-])(?:curl|wget)(?![\w.-])"
    rf"{_ATOM}*(?:{_PIPE}{_ATOM}*)*?"
    rf"{_PIPE}\s*{_CONSUMER_PREFIX}"
    r"""(?P<quote>["']?)\\?(?:[^\s;|&'"]*/)?(?:tar|sh|bash)(?P=quote)(?![\w.-])"""
)
# A line ending in a pipe continues, except `run: |`, which opens a YAML block
# scalar (`|-` and `|+` do not end in a pipe at all).
_TRAILING_PIPE = re.compile(r"(?<![:\s])\s*\|$")
# `key: value` whose value YAML folds with any deeper lines that follow: `>`, plain
# and quoted scalars alike. Not `key: |`, a literal scalar, which keeps its newlines.
_FOLDING_KEY = re.compile(r"^(\s*(?:-\s+)*)\S+:\s+(?!\|)\S")
_FOLD_HEADER = re.compile(r":\s+>[-+\d]*$")


def literal_diagnostics_py(source: str) -> list:
    """(lineno, phrase) for each phrase in a live Python string literal."""
    tree = ast.parse(source)
    inert = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or id(node) in inert:
            continue
        value = node.value
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if isinstance(value, str):
            found += [(node.lineno, p) for p in DIAGNOSTIC_PHRASES if p in value]
    return found


def literal_diagnostics_sh(source: str) -> list:
    """(lineno, phrase) for each phrase on a shell line, comments removed."""
    return [
        (lineno, p)
        for lineno, line in enumerate(source.splitlines(), 1)
        for p in DIAGNOSTIC_PHRASES
        if p in strip_inline_comment_sh(line)
    ]


def diagnostic_violations(root: Path) -> list:
    """`path:line: phrase` for test code under `root`/scanner/tests."""
    violations = []
    tests = root / "scanner" / "tests"
    for suffix, detect in ((".py", literal_diagnostics_py), (".sh", literal_diagnostics_sh)):
        for path in sorted(tests.rglob(f"*{suffix}")):
            if path.name == THIS_FILE:
                continue
            rel = path.relative_to(root).as_posix()
            hits = detect(path.read_text(encoding="utf-8"))
            violations += [f"{rel}:{line}: {phrase}" for line, phrase in hits]
    return violations


def logical_lines(text: str) -> list:
    """Comment-free lines, with `\\`, trailing-`|`, leading-`|` and YAML-folded
    continuations joined so a pipeline split across lines is one string."""
    lines = []
    fold_col = None  # column of the key whose scalar is being folded
    folding = False  # the previous line folds into this one; a blank line ends it
    for raw in text.splitlines():
        code = strip_inline_comment_sh(raw)
        line = code.strip()
        if not line:
            folding = False
            continue
        col = len(code) - len(code.lstrip())
        if fold_col is not None and col <= fold_col:
            fold_col, folding = None, False
        prev = lines[-1] if lines else ""
        if (
            folding
            or prev.endswith("\\")
            or _TRAILING_PIPE.search(prev)
            or (prev and line.startswith("|"))
        ):
            lines[-1] = f"{prev.rstrip(chr(92)).rstrip()} {line}"
        else:
            lines.append(line)
        key = _FOLDING_KEY.match(code) if fold_col is None else None
        if key:
            fold_col = key.end(1)
        # `key: >` holds no text of its own, so its first body line starts fresh.
        folding = fold_col is not None and _FOLD_HEADER.search(line) is None
    return lines


def piped_downloads(text: str) -> list:
    """The `curl ... | tar` spans in a workflow or Dockerfile."""
    return [m.group(0) for line in logical_lines(text) for m in PIPED_DOWNLOAD.finditer(line)]


def download_targets(root: Path) -> list:
    workflows = root / ".github" / "workflows"
    docker = root / "scripts" / "docker"
    return sorted(
        [*workflows.glob("*.yml"), *workflows.glob("*.yaml"), *docker.glob("*Dockerfile")]
    )


def download_findings(root: Path) -> Counter:
    """Counter of (repo-relative path, span) across the download targets."""
    return Counter(
        (path.relative_to(root).as_posix(), span)
        for path in download_targets(root)
        for span in piped_downloads(path.read_text(encoding="utf-8"))
    )


def download_violations(found: Counter, pending=KNOWN_PENDING) -> tuple:
    """(unallowed, stale). Multiset difference, so a second copy of an
    allowlisted line is new rather than covered by the first."""
    allowed = Counter(pending)
    return sorted((found - allowed).elements()), sorted((allowed - found).elements())


class TestNoExactDiagnosticsLive(unittest.TestCase):
    def test_scan_set_exists(self):
        tests = REPO_ROOT / "scanner" / "tests"
        self.assertTrue(list(tests.glob("test_ci_*.py")), "no Python tests found")
        self.assertTrue(list(tests.glob("test_*.sh")), "no shell tests found")

    def test_no_exact_diagnostics(self):
        violations = diagnostic_violations(REPO_ROOT)
        self.assertEqual(
            violations,
            [],
            "exact Bash/coreutils wording changes between versions; match it "
            "with a tolerant regex, e.g. r'integer (?:expression )?expected'.",
        )


class TestLiteralDiagnosticsDetector(unittest.TestCase):
    def test_regression_594_fails_and_its_fix_passes(self):
        fixed = (
            "self.assertEqual(len(re.findall("
            "r'integer (?:expression )?expected', r.stderr)), 2)\n"
        )
        mutant = apply_mutation(
            fixed,
            "len(re.findall(r'integer (?:expression )?expected', r.stderr))",
            "r.stderr.count('integer expression expected')",
        )
        found = assert_disables(literal_diagnostics_py, fixed, mutant, "#594")
        self.assertEqual(found, [(1, "integer expression expected")])

    def test_each_phrase_fires(self):
        for phrase in DIAGNOSTIC_PHRASES:
            with self.subTest(phrase=phrase):
                self.assertEqual(
                    literal_diagnostics_py(f"self.assertIn({phrase!r}, err)\n"),
                    [(1, phrase)],
                )
                self.assertEqual(
                    literal_diagnostics_sh(f'assert_contains "x" "$out" "{phrase}"\n'),
                    [(1, phrase)],
                )

    def test_python_shapes_that_must_fire(self):
        for source in (
            "PHRASE = 'too many arguments'\nerr.count(PHRASE)\n",
            "self.assertIn('too many ' 'arguments', err)\n",
            "self.assertIn(f'{name}: too many arguments', err)\n",
            "self.assertIn(b'too many arguments', err)\n",
            "self.assertIn('too many\\x20arguments', err)\n",
        ):
            with self.subTest(source=source):
                self.assertTrue(literal_diagnostics_py(source))

    def test_python_shapes_that_must_stay_quiet(self):
        for source in (
            '"""Module docstring: command not found."""\n',
            'def f():\n    """too many arguments"""\n',
            "# unary operator expected\nx = 1\n",
            "self.assertRegex(err, r'(?:command )?not found')\n",
            "x = 1\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(literal_diagnostics_py(source), [])

    def test_shell_comments_stay_quiet(self):
        for source in (
            "# command not found\n",
            "echo ok  # command not found\n",
            "echo ok;# command not found\n",
            "grep -qE 'integer (expression )?expected' \"$err\"\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(literal_diagnostics_sh(source), [])

    def test_shell_count_fires(self):
        self.assertEqual(
            literal_diagnostics_sh('grep -c "integer expression expected" "$err"\n'),
            [(1, "integer expression expected")],
        )

    def test_self_exclusion_is_what_keeps_this_file_green(self):
        own = Path(__file__).read_text(encoding="utf-8")
        self.assertTrue(literal_diagnostics_py(own))

    def test_scan_walks_nested_files_and_excludes_only_this_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "scanner" / "tests" / "nested"
            nested.mkdir(parents=True)
            (nested / "test_a.py").write_text("x = 'command not found'\n", encoding="utf-8")
            (nested / "test_b.sh").write_text('echo "too many arguments"\n', encoding="utf-8")
            (nested / THIS_FILE).write_text("x = 'command not found'\n", encoding="utf-8")
            self.assertEqual(
                diagnostic_violations(root),
                [
                    "scanner/tests/nested/test_a.py:1: command not found",
                    "scanner/tests/nested/test_b.sh:1: too many arguments",
                ],
            )


class TestNoPipedDownloadsLive(unittest.TestCase):
    def test_scan_set_exists(self):
        names = {p.name for p in download_targets(REPO_ROOT)}
        self.assertIn("lint.yml", names)
        self.assertIn("shell-coverage.Dockerfile", names)

    def test_no_new_entries(self):
        unallowed, _ = download_violations(download_findings(REPO_ROOT))
        self.assertEqual(
            unallowed,
            [],
            "download to a file and verify its sha256 before extracting or "
            "running it. KNOWN_PENDING is only for what PR #595 is replacing.",
        )

    def test_no_stale_entries(self):
        _, stale = download_violations(download_findings(REPO_ROOT))
        self.assertEqual(
            stale,
            [],
            "these lines are gone; remove them from KNOWN_PENDING so they "
            "cannot return allowlisted.",
        )


class TestPipedDownloadDetector(unittest.TestCase):
    def test_shapes_that_must_fire(self):
        for text in (
            "curl -fsSL https://x/a.tgz | tar xz",
            "wget -qO- https://x/a.tgz | tar xz",
            "curl https://x/i.sh | sh",
            "curl https://x/i.sh | bash -s -- --yes",
            "curl https://x/i.sh|bash",
            "curl https://x/i.sh |& sh",
            "curl https://x/i.sh | sudo -E bash",
            "curl https://x/i.sh | /bin/sh",
            "/usr/bin/curl https://x/i.sh | sh",
            "curl https://x/i.sh | tee i.sh | sh",
            'curl "https://x/a?b=1;c=2&d=3" | sh',
            'curl "https://x/a|b" | sh',
            'bash -c "curl https://x/i.sh | sh"',
            "      - run: curl https://x/i.sh | sh",
            "curl https://x/a.tgz \\\n  | tar xz",
            "curl https://x/a.tgz |\n  tar xz",
            "      run: >\n        curl https://x/a.tgz\n        | tar xz",
            "RUN set -eu; \\\n    curl https://x/a.tgz | tar xz; \\\n    make",
            "curl https://x/a.tgz \\\n  # a comment line\n  | tar xz",
        ):
            with self.subTest(text=text):
                self.assertEqual(len(piped_downloads(text)), 1)

    def test_scalars_yaml_folds_onto_one_line_must_fire(self):
        for text in (
            "      run: >\n        curl -fsSL\n        https://x/a.tgz | tar xz",
            "      - run: >-\n          curl -fsSL\n          https://x/a.tgz | tar xz",
            "      run: >+\n        curl\n        -fsSL\n        https://x/a.tgz\n        | tar xz",
            "      run: curl -fsSL\n        https://x/a.tgz | tar xz",
            '      run: "curl -fsSL\n        https://x/i.sh | sh"',
        ):
            with self.subTest(text=text):
                self.assertEqual(len(piped_downloads(text)), 1)

    def test_fold_boundaries_must_stay_quiet(self):
        for text in (
            # A blank line is a real newline in a folded scalar.
            "      run: >\n        curl -o a https://x/a\n\n        cat a | sh",
            # A sibling key ends the scalar.
            "      run: >\n        curl -o a https://x/a\n      name: cat a | sh",
            "      name: fetch with curl\n      run: cat a | sh",
            # A literal scalar keeps its newlines.
            "      run: |\n        curl -o a https://x/a\n        cat a | sh",
            # A `#` line is folded in as content, so bash reads the rest as a comment.
            "      run: >\n        curl -fsSL\n        # c\n        https://x/a.tgz | tar xz",
        ):
            with self.subTest(text=text):
                self.assertEqual(piped_downloads(text), [])

    def test_quoted_and_wrapped_consumers_must_fire(self):
        for consumer in (
            '"bash"',
            "'sh'",
            '"tar" xz',
            '"/bin/sh"',
            "\\bash",
            "env bash",
            "/usr/bin/env bash",
            "env -i FOO=1 bash",
            "FOO=1 bash",
            "sudo -u root bash",
            'sudo env "bash"',
            "exec sh",
            "command sh",
            "nice -n 5 sh",
            "nohup sh",
            "time bash",
            "doas sh",
            "busybox sh",
        ):
            with self.subTest(consumer=consumer):
                self.assertEqual(len(piped_downloads(f"curl https://x/i | {consumer}")), 1)

    def test_lookalike_consumers_must_stay_quiet(self):
        for consumer in (
            "env",
            "envsubst",
            '"jq" .',
            "'tar-tool'",
            '"shasum"',
            "sudo tee a",
            "time jq .",
            "bashful",
        ):
            with self.subTest(consumer=consumer):
                self.assertEqual(piped_downloads(f"curl https://x/i | {consumer}"), [])

    def test_shapes_that_must_stay_quiet(self):
        for text in (
            "curl -fsSL -o a.tgz https://x/a.tgz",
            "curl https://x/i.sh || bash fallback.sh",
            "curl https://x/i.sh ||\n  bash fallback.sh",
            "curl https://x/a.tgz | sha256sum -c -",
            "curl https://x/a.json | jq -r .tag",
            "curl https://x/a.txt | grep tar",
            "curl -o i.sh https://x/i.sh; cat i.sh | sh",
            "curl -o a.tgz https://x/a.tgz && tar xzf a.tgz",
            "# curl https://x/i.sh | sh",
            "echo ok;# curl https://x/i.sh | sh",
            "apt-get install -y libcurl4 | tar",
            "      run: |\n        tar xzf a.tgz",
            "      - run: |\n        curl -o a.tgz https://x/a.tgz\n        tar xzf a.tgz",
            "curl -fsSL -o k.tgz https://x/k.tgz\n"
            'echo "${SHA}  k.tgz" | sha256sum -c -\ntar xzf k.tgz',
        ):
            with self.subTest(text=text):
                self.assertEqual(piped_downloads(text), [])

    def test_regression_595_shape_fails_and_its_fix_passes(self):
        fixed = "curl -fsSL -o k.tgz https://x/k.tgz; tar xzf k.tgz\n"
        mutant = apply_mutation(
            fixed,
            "curl -fsSL -o k.tgz https://x/k.tgz; tar xzf k.tgz",
            "curl -fsSL https://x/k.tgz | tar xz",
        )
        self.assertEqual(
            assert_disables(piped_downloads, fixed, mutant, "#595"),
            ["curl -fsSL https://x/k.tgz | tar"],
        )

    def test_nonmatching_long_line_is_fast(self):
        line = "curl " + '"a" ' * 5000
        self.assertEqual(piped_downloads(line), [])
        wrapped = "curl https://x/a | env " + "a " * 5000
        self.assertEqual(piped_downloads(wrapped), [])


class TestAllowlistIsExactMatch(unittest.TestCase):
    ENTRY = ("a.yml", "curl https://x/a | tar")

    def test_listed_entry_passes(self):
        self.assertEqual(download_violations(Counter([self.ENTRY]), (self.ENTRY,)), ([], []))

    def test_new_line_fails(self):
        found = Counter([self.ENTRY, ("a.yml", "curl https://x/b | sh")])
        unallowed, _ = download_violations(found, (self.ENTRY,))
        self.assertEqual(unallowed, [("a.yml", "curl https://x/b | sh")])

    def test_edited_url_fails_and_leaves_entry_stale(self):
        edited = ("a.yml", "curl https://x/a2 | tar")
        self.assertEqual(
            download_violations(Counter([edited]), (self.ENTRY,)), ([edited], [self.ENTRY])
        )

    def test_same_line_in_another_file_fails(self):
        other = ("b.yml", self.ENTRY[1])
        unallowed, _ = download_violations(Counter([self.ENTRY, other]), (self.ENTRY,))
        self.assertEqual(unallowed, [other])

    def test_second_copy_in_the_same_file_fails(self):
        unallowed, _ = download_violations(Counter([self.ENTRY, self.ENTRY]), (self.ENTRY,))
        self.assertEqual(unallowed, [self.ENTRY])

    def test_fixed_line_makes_the_entry_stale(self):
        self.assertEqual(download_violations(Counter(), (self.ENTRY,)), ([], [self.ENTRY]))

    def test_known_pending_only_names_the_kcov_download(self):
        for path, span in KNOWN_PENDING:
            with self.subTest(path=path):
                self.assertIn("/SimonKagstrom/kcov/", span)

    def test_scan_reads_workflows_and_dockerfiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflows = root / ".github" / "workflows"
            docker = root / "scripts" / "docker"
            workflows.mkdir(parents=True)
            docker.mkdir(parents=True)
            line = "curl https://x/a | sh\n"
            (workflows / "a.yml").write_text(line, encoding="utf-8")
            (workflows / "b.yaml").write_text(line, encoding="utf-8")
            (docker / "c.Dockerfile").write_text(line, encoding="utf-8")
            (docker / "notes.txt").write_text(line, encoding="utf-8")
            span = "curl https://x/a | sh"
            self.assertEqual(
                download_findings(root),
                Counter(
                    {
                        (".github/workflows/a.yml", span): 1,
                        (".github/workflows/b.yaml", span): 1,
                        ("scripts/docker/c.Dockerfile", span): 1,
                    }
                ),
            )


if __name__ == "__main__":
    unittest.main()
