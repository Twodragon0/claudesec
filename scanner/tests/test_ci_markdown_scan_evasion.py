"""
Meta-guard for the Markdown scan-evasion class.

A guard whose subject is a PUBLISHED Markdown document — a catalog row, a table
row, a heading — has to read the document the way a reader sees it. Four
constructs make raw text and rendered text disagree, and each one lets a row be
removed from what readers see while a raw scan still finds it:

| construct              | what CommonMark renders            |
|------------------------|------------------------------------|
| `<!-- ... -->`         | nothing                            |
| ```` ``` ```` fence    | sample code, not document structure|
| `<div>`…`</div>` block | raw HTML passthrough, not a row    |
| unterminated `<!--`    | NOTHING, to end of document        |

`test_ci_adr_decision_numbering` closed all four for ADR decisions (#528). This
file exists because that fix was INLINE in that one guard while five others
scanned the same kind of document with less: two stripped only closed comments,
and three — `test_ci_collector_table_completeness`,
`test_ci_compliance_doc_table`, `test_ci_kisa_control_alignment` — stripped
nothing at all, so even a plainly commented-out row parsed as live.

Two independent things are pinned here, because either alone goes quiet:

1. **The vectors, against the REAL detectors.** Each case below calls the actual
   function the guard uses in production — `missing_rows`, `cited_paths`,
   `table_files`, `parse_doc_rows`, `guide_titles` — never a local
   re-implementation. A self-test that drives a surrogate proves the surrogate
   works; that is how the `trigger_block()` sweep stayed green while the live
   site was defeated.

2. **The census, so a NEW guard cannot join uncovered.** Enumerated from
   `git ls-files` by AST rather than from a hand-written list: a literal list of
   source files in a guard is the same drift one level up, and this repo has
   already shipped one that had fallen 12 files behind (#501). Any tracked
   `test_ci_*.py` that names a `.md` literal and performs a read must either use
   `rendered_markdown` or declare `MARKDOWN_SCAN_EXEMPT` with a reason.

The exemption is a module CONSTANT, not a comment: it is read back with `ast`,
so it cannot be satisfied by a string sitting in a docstring or a `#` line, and
it is visible to a reviewer at the top of the file it excuses.

stdlib-only, no PyYAML, no `scanner/lib` import. Passes under pytest and
`python3 -m unittest`.

OWASP CICD-SEC-7 (Insecure System Configuration); NIST SP 800-218 (SSDF) PO.3:
an inventory that a reader cannot see is not an inventory, and a guard that
reads past the renderer certifies one that does not exist.
"""

import ast
import random
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import REPO_ROOT, rendered_markdown  # noqa: E402

TESTS_REL = "scanner/tests"
EXEMPT_NAME = "MARKDOWN_SCAN_EXEMPT"
PIPELINE_NAME = "rendered_markdown"

# In-class guards whose reduction is EXECUTED by a probe living somewhere other
# than `_detectors()`. Not exemptions — coverage that already exists elsewhere,
# named so the registration check below cannot be satisfied by silence.
COVERED_ELSEWHERE = {
    "test_ci_adr_decision_numbering.py": (
        "its own TestTheParseAgreesWithCommonMark drives `parsed_decisions` "
        "against markdown-it-py over 12 cases, which is a stronger probe than "
        "the vector table here"
    ),
    "test_ci_markdown_scan_evasion.py": (
        "this file itself: flagged only because `scans_markdown` carries the "
        "`.md` detection string as a LITERAL, the same self-reference "
        "`test_ci_collector_table_completeness` excludes itself for. It reads no "
        "Markdown document"
    ),
}


# --------------------------------------------------------------------------
# The four evasion vectors, as a reader sees them.
# --------------------------------------------------------------------------
def wrap(kind: str, payload: str) -> str:
    """`payload` hidden by `kind`, or returned plainly for the control case.

    The control matters as much as the vectors: a probe whose payload does not
    match the detector's real shape reports "blind" for every case and reads as
    a clean pass. Two of these detectors did exactly that on the first probe
    written against them, because the payload lacked the section heading and the
    column count they anchor on."""
    return {
        "plain": payload,
        "closed-comment": f"<!--\n{payload}\n-->",
        "code-fence": f"```\n{payload}\n```",
        "html-block": f"<div>\n{payload}\n</div>",
        "unclosed-comment": f"<!-- retiring this\n{payload}",
    }[kind]


VECTORS = ("closed-comment", "code-fence", "html-block", "unclosed-comment")


class TestRenderedMarkdownMatchesTheRenderer(unittest.TestCase):
    """`rendered_markdown` itself, before anything is built on it."""

    def test_the_control_survives(self):
        # Fail-closed canary: if the reduction ate ordinary text, every "hidden"
        # assertion below would pass for free.
        self.assertIn("| CC1 | live |", rendered_markdown("# D\n\n| CC1 | live |\n"))

    def test_each_vector_is_removed(self):
        payload = "| CC1 | hidden |"
        for kind in VECTORS:
            with self.subTest(vector=kind):
                out = rendered_markdown("# D\n\n" + wrap(kind, payload) + "\n")
                self.assertNotIn(
                    payload,
                    out,
                    f"{kind} survived the reduction — a row hidden this way "
                    "renders as nothing a reader can act on, but would still "
                    "satisfy a presence check",
                )

    def test_order_is_not_commutative(self):
        # Pins WHY the order is fixed rather than merely that a chain runs: a
        # `<!--` shown as sample code inside a fence is not an HTML block, so
        # truncating before fences are blanked deletes content that renders
        # perfectly well. Measured against markdown-it-py 4.0.0 in #528.
        #
        # The fence must be TILDE. Written with backticks, this test pinned
        # NOTHING: `_CODE_SPAN_RE` is lazy and DOTALL, so it matched the opening
        # and closing ``` runs as one giant inline code span, which made
        # `truncate_at_unclosed_html_comment` a no-op on the probe REGARDLESS of
        # where it sat in the chain. An adversarial review substituted all 24
        # permutations of the four primitives and every one passed. With a tilde
        # fence the same sweep REJECTS 12, including all three orderings that
        # truncate before fences — CTFB, CTBF, CBTF — each of which deletes the
        # row below. The 12 that still pass were then diffed against the shipped
        # order over the three real docs plus five adversarial ones and differ
        # only in TRAILING WHITESPACE, so they are equivalent for every consumer
        # on the corpus measured. That is a measurement over documents, not a
        # proof of general equivalence.
        doc = "# D\n\n~~~\n<!-- this is sample code\n~~~\n\n| CC1 | live |\n"
        self.assertIn(
            "| CC1 | live |",
            rendered_markdown(doc),
            "a `<!--` inside a fence truncated the document — fences must be "
            "blanked before the unclosed-opener search runs",
        )

    def test_an_html_block_cannot_hide_the_opener_from_the_truncation(self):
        # C1, the defect that made the previous commit's claim false. When
        # `strip_html_blocks` ran BEFORE the truncation it blanked every non-blank
        # line inside an HTML block — including a `<!--` opener — leaving the
        # truncation nothing to find. Two lines, no backticks, and it defeated
        # all five converted guards on the real catalog with markdownlint green.
        # Found by differential fuzz; unreachable by reading.
        doc = "# Catalog\n\n</div>\n<!--\n\n| a | ROWMARKER |\n"
        self.assertNotIn(
            "ROWMARKER",
            rendered_markdown(doc),
            "an HTML block hid the unterminated opener from the truncation — a "
            "browser stops rendering at that opener, so the row below is invisible",
        )

    def test_a_backticked_opener_is_not_a_comment(self):
        # Prose that spells the opener in backticks is ordinary documentation,
        # and this catalog writes it. Without code-span masking in
        # `strip_html_comments`, that span paired with the next `-->` anywhere
        # below and deleted 641 lines of the real catalog — armed on the
        # published file, one added closer away. Found by review, not by this
        # suite, which is why it is pinned here.
        doc = "See `<!--` in prose.\n\n| CC1 | live |\n\n<!-- a real one -->\n"
        out = rendered_markdown(doc)
        self.assertIn("| CC1 | live |", out, "a backticked opener ate live content")
        self.assertNotIn("a real one", out, "a genuine comment stopped being removed")


# --------------------------------------------------------------------------
# The live detectors. Imported at use, so a rename fails loudly here rather
# than silently reducing this file to the census alone.
# --------------------------------------------------------------------------
def _detectors():
    # `test_ci_catalog_completeness`, `test_ci_catalog_no_ghost_rows` and
    # `test_ci_collector_table_completeness` are deliberately ABSENT: they now
    # compare against `ci-guard-inventory.toml` and read no Markdown at all, so
    # there is nothing here to probe. Their prose reading collapsed into
    # `test_ci_catalog_doc_sync`, which is what these two entries drive.
    from test_ci_catalog_doc_sync import documented_collectors, documented_guards
    from test_ci_compliance_doc_table import parse_doc_rows
    from test_ci_kisa_control_alignment import guide_titles

    guard_row = "| `scanner/tests/test_ci_x.py` | verdict |"
    return (
        (
            "test_ci_catalog_doc_sync.documented_guards",
            guard_row,
            "# Catalog\n\n{}\n",
            lambda doc: bool(documented_guards(doc)),
        ),
        (
            "test_ci_catalog_doc_sync.documented_collectors",
            "| `test_ci_x.py` | verdict |",
            "# Catalog\n\n## Block-collector enumeration\n\n{}\n",
            lambda doc: bool(documented_collectors(doc)),
        ),
        (
            "test_ci_compliance_doc_table.parse_doc_rows",
            "| CC9 Some control | PASS | 1 | `kw-one`, `kw-two` |",
            "# Guide\n\n{}\n",
            lambda doc: bool(parse_doc_rows(doc)),
        ),
        (
            "test_ci_kisa_control_alignment.guide_titles",
            "| 2.9.3 | 백업 및 복구 관리 | 백업 정책 |",
            "# Guide\n\n{}\n",
            lambda doc: bool(guide_titles(doc)),
        ),
    )


class TestLiveDetectorsRejectEveryVector(unittest.TestCase):
    def test_controls_see_the_payload(self):
        # Without this, a detector that returns empty for EVERY input would pass
        # the evasion assertions below and prove nothing at all.
        for label, payload, tmpl, sees in _detectors():
            with self.subTest(detector=label):
                self.assertTrue(
                    sees(tmpl.format(wrap("plain", payload))),
                    f"{label} did not see its own control payload — the probe is "
                    "measuring the wrong shape, not a working guard",
                )

    def test_no_detector_sees_a_hidden_row(self):
        for label, payload, tmpl, sees in _detectors():
            for kind in VECTORS:
                with self.subTest(detector=label, vector=kind):
                    self.assertFalse(
                        sees(tmpl.format(wrap(kind, payload))),
                        f"{label} still sees a row hidden by {kind}: the "
                        "published document and this guard disagree about what "
                        "is listed",
                    )

    def test_no_detector_sees_a_row_under_a_hidden_ANCHOR(self):
        """The vector above the row, not around it.

        Every template puts the payload AFTER whatever heading its detector
        anchors on, so wrapping the payload never exercises the anchor. A
        detector that reduces AFTER its own search instead of before — moving
        one call across two lines, keeping the import, the call and the whole
        docstring — passed all twenty payload cases while genuinely defeated:
        an unterminated opener placed above the heading, or the heading itself
        parked in a fence, made it report a row the renderer does not show.

        Prepending the opener is the general form: it hides everything below,
        anchor included, so any detector that still returns a row is reading
        text no reader receives."""
        for label, payload, tmpl, sees in _detectors():
            doc = "# Doc\n\n<!-- retiring the whole section\n" + tmpl.format(payload)
            with self.subTest(detector=label, position="above-anchor"):
                self.assertFalse(
                    sees(doc),
                    f"{label} sees a row under an anchor that an unterminated "
                    "comment opener has already swallowed — the reduction is "
                    "running after the search, not before it",
                )


# --------------------------------------------------------------------------
# Differential fuzz against the renderer.
# --------------------------------------------------------------------------
# The measured residual. `rendered_markdown` does NOT close the evasion class —
# a stdlib regex cannot model CommonMark's block structure — and this number is
# the honest size of what is left. It is pinned as a CEILING so the residual can
# shrink freely but cannot grow in silence, which is the only property worth
# asserting about a known-incomplete reduction.
#
# Both figures come from the corpus below at SEED 1234, so the constant and the
# generator move together: 45 shapes before the HTML-block/truncation order was
# fixed, 14 after. Raising this number is a review moment, not a maintenance
# chore — it means a change made the reduction worse.
FUZZ_SEED = 1234
FUZZ_DOCS = 16831
MAX_SILENT_PASS_SHAPES = 14

_FUZZ_TOKENS = (
    "<!--", "-->", "```", "~~~", "`", "<div>", "</div>", "# H", "",
    "| a | ROWMARKER |", "text", "<table>", "</table>",
)


def _browser_sees(md, src: str, needle: str = "ROWMARKER") -> bool:
    """Whether a BROWSER displays `needle`, not whether the HTML string holds it.

    The distinction is the whole finding. markdown-it passes raw HTML through, so
    an unbalanced `<!--` is emitted verbatim into the output and the browser then
    consumes the rest of the document as a comment. A containment check over the
    rendered string therefore reports the row as visible when no reader sees it —
    that exact mistake made a first pass at C1 read as "renderer and guard
    agree". markdown -> HTML -> consume comments is the correct oracle."""
    out = md.render(src)
    out = re.sub(r"<!--.*?-->", "", out, flags=re.DOTALL)
    opener = out.find("<!--")
    if opener != -1:
        out = out[:opener]
    return needle in out


def _fuzz_corpus() -> list:
    rng = random.Random(FUZZ_SEED)
    docs = []
    row = "| a | ROWMARKER |"
    for _ in range(FUZZ_DOCS):
        n = rng.randint(3, 7)
        lines = [rng.choice(_FUZZ_TOKENS) for _ in range(n)]
        if row not in lines:
            lines.insert(rng.randrange(n + 1), row)
        docs.append("\n".join(lines) + "\n")
    return docs


class TestTheResidualIsBounded(unittest.TestCase):
    """Differential property test: the reduction vs the renderer, at scale.

    Every hand-built case in this file was written by someone who already had a
    theory of the evasion. This class has no theory: it generates documents from
    a 13-token vocabulary and compares the reduction against what a browser would
    show. It is how C1 was found, after two review passes of careful reading
    missed it, and it is the only test here that can find the NEXT one.

    SKIPPED when `markdown-it-py` is absent so `ci-guards` stays package-free.
    That skip is why two silent passes shipped, so `scanner-unit-tests` now
    installs the pin and `test_the_renderer_is_available_under_pytest` below
    fails rather than skips when it is missing under pytest."""

    @classmethod
    def setUpClass(cls):
        try:
            from markdown_it import MarkdownIt
        except ImportError:  # pragma: no cover - depends on the local env
            raise unittest.SkipTest("markdown-it-py not installed") from None
        cls.md = MarkdownIt("commonmark")
        cls.docs = _fuzz_corpus()

    def test_the_oracle_is_not_vacuous(self):
        # Without this, a `_browser_sees` that always returned True would report
        # zero silent passes and the ceiling below would assert nothing.
        self.assertTrue(_browser_sees(self.md, "| a | ROWMARKER |\n"))
        self.assertFalse(_browser_sees(self.md, "<!--\n| a | ROWMARKER |\n-->\n"))
        self.assertFalse(_browser_sees(self.md, "<!-- open\n| a | ROWMARKER |\n"))

    def test_silent_passes_stay_within_the_measured_ceiling(self):
        silent = [
            d
            for d in self.docs
            if "ROWMARKER" in rendered_markdown(d) and not _browser_sees(self.md, d)
        ]
        self.assertLessEqual(
            len(silent),
            MAX_SILENT_PASS_SHAPES,
            f"silent-pass shapes rose to {len(silent)} (ceiling "
            f"{MAX_SILENT_PASS_SHAPES}): the reduction got WORSE. First example:\n"
            f"{silent[0]!r}" if silent else "",
        )

    def test_the_corpus_actually_exercises_the_primitives(self):
        # A canary on the generator: if the corpus stopped producing documents
        # the reduction changes at all, the ceiling would pass for free.
        changed = sum(1 for d in self.docs if rendered_markdown(d) != d)
        self.assertGreater(
            changed,
            self.docs.__len__() // 4,
            "the fuzz corpus barely exercises the reduction — the generator or "
            "the token vocabulary broke",
        )


class TestTheRendererCrossCheckActuallyRuns(unittest.TestCase):
    def test_the_renderer_is_available_under_pytest(self):
        """FAILS, not skips, when the adjudication authority is missing.

        The renderer-agreement classes skip on ImportError, which is right for
        the package-free `ci-guards` job and wrong everywhere else: in
        `scanner-unit-tests` the skip meant `testsRun=0, OK (skipped=1)` and the
        only check that could catch a primitive/renderer divergence silently did
        not run. Two silent passes shipped behind it. This test fails closed
        under pytest — which only ever runs with `requirements-ci.txt`
        installed — so a dropped pin is loud."""
        if "pytest" not in sys.modules:
            raise unittest.SkipTest("unittest runner: ci-guards is package-free")
        try:
            import markdown_it
        except ImportError:  # pragma: no cover - the failure this pins
            self.fail(
                "markdown-it-py is missing under pytest — it is pinned in "
                "requirements-ci.txt precisely so the renderer cross-check "
                "cannot fail open again"
            )
        self.assertEqual(
            markdown_it.__version__,
            "4.0.0",
            "markdown-it-py moved off the adjudicated version; re-measure the "
            "residual ceiling before changing the pin",
        )


# --------------------------------------------------------------------------
# Census.
# --------------------------------------------------------------------------
def tracked_guards() -> list:
    """Tracked `test_ci_*.py` paths, from git rather than the filesystem.

    A gitignored scratch copy is red locally and absent in CI, which is the
    asymmetry that made an earlier sweep disagree with itself between the two.

    Index entries with no file on disk are dropped. `git ls-files` still lists a
    path that is staged-but-deleted, and reading it raised `FileNotFoundError`
    through every test in the census — measured while cleaning up a probe file,
    and an opaque traceback where a verdict belongs. CI always has a consistent
    tree, so this only ever discards transient local state: a guard that is gone
    from disk has nothing left to check.

    THE TRADEOFF, so it is not rediscovered as a bug: a brand-new guard file that
    has not been `git add`ed is invisible here, so the census reports a clean
    tree locally while the new guard is unchecked. Measured while adding
    `test_ci_catalog_doc_sync.py`, which the census could not see until it was
    staged. CI only ever runs on committed trees, so the gap is local-only and
    the alternative — globbing the filesystem — reintroduces the worse
    asymmetry this function exists to avoid (a gitignored scratch copy red
    locally and absent in CI). Stage before trusting a local green."""
    out = subprocess.run(
        ["git", "ls-files", f"{TESTS_REL}/test_ci_*.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    paths = [REPO_ROOT / line for line in out.stdout.split("\n") if line.strip()]
    return [p for p in paths if p.is_file()]


def scans_markdown(tree: ast.AST) -> bool:
    """True when the module names a `.md` literal AND performs a read.

    Deliberately BROAD. A narrower version that traced the `.md` literal through
    assignments to the name actually passed to `read_text` was written first and
    missed both ADR guards, whose path arrives through a glob and a comprehension
    variable — the precise-looking answer that is wrong. Over-inclusion here
    costs an `MARKDOWN_SCAN_EXEMPT` line on a guard that does not parse Markdown;
    under-inclusion costs a guard silently exempted from the whole class."""
    has_md = any(
        isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and n.value.endswith(".md")
        for n in ast.walk(tree)
    )
    reads = any(_is_read_call(n) for n in ast.walk(tree))
    return has_md and reads


# `read_text` alone missed a guard that reads the real catalog with
# `with open(CATALOG) as fh: fh.read()` and carries no reduction at all —
# measured passing the whole census. A bare `open(` counts too, for the same
# reason.
_READ_ATTRS = ("read_text", "read_bytes", "read", "readlines", "glob", "rglob")


def _is_read_call(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in _READ_ATTRS
    return isinstance(node.func, ast.Name) and node.func.id == "open"


def applies_reduction(tree: ast.AST) -> bool:
    """True when the module CALLS `rendered_markdown`, by AST.

    A substring over the source was the first version and it was defeated the
    same day: the token in a `#` comment, or in a docstring, satisfied it while
    the guard scanned raw. `exemption()` below is AST-based precisely to stop
    that, and the pipeline half had no such protection — the presence-vs-
    attribution shape this repo has now hit in three separate sweeps. Proving a
    token EXISTS is never proof it belongs to the code that runs."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == PIPELINE_NAME:
            return True
        if isinstance(func, ast.Attribute) and func.attr == PIPELINE_NAME:
            return True
    return False


def exemption(tree: ast.AST):
    """The module's `MARKDOWN_SCAN_EXEMPT` string, or None.

    Read from the AST so only a real module-level constant counts — the token
    appearing in a docstring or a `#` comment does not exempt anything."""
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name) and t.id == EXEMPT_NAME for t in node.targets
        ):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
            # A computed exemption (an f-string, a join, a name) is not a
            # declared one. Catching only ValueError let the rest escape as an
            # opaque traceback where a verdict belongs.
            return None
        return value if isinstance(value, str) and value.strip() else None
    return None


class TestEveryMarkdownScanningGuardIsCovered(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = {
            p.name: ast.parse(p.read_text(encoding="utf-8")) for p in tracked_guards()
        }

    def test_the_census_finds_guards(self):
        # Canary: if `git ls-files` or the glob breaks, every check below
        # iterates over nothing and passes vacuously.
        self.assertTrue(self.modules, "no tracked test_ci_*.py found — census broke")

    def test_the_census_finds_the_known_scanners(self):
        # Anchors the AST heuristic to cases known to be in-class. If
        # `scans_markdown` stops recognising them, the sweep below would report a
        # clean tree while checking almost nothing.
        #
        # The anchors were `test_ci_catalog_completeness` and
        # `test_ci_compliance_doc_table` until the catalog guards moved to
        # `ci-guard-inventory.toml` and stopped reading Markdown. That made this
        # test fail — correctly, and it is the anchor's job to notice. Anchoring
        # on a guard that later leaves the class is not a flaw in the anchor; the
        # alternative is an anchor nothing can invalidate.
        found = {n for n, t in self.modules.items() if scans_markdown(t)}
        self.assertIn("test_ci_catalog_doc_sync.py", found)
        self.assertIn("test_ci_compliance_doc_table.py", found)

    def test_the_converted_guards_have_left_the_class(self):
        """The three catalog guards must read NO Markdown.

        The positive half of the refactor, asserted rather than assumed. Each of
        these compares against the TOML inventory now, which is what puts the
        measured 14-shape residual permanently out of their path. If one of them
        starts reading the published document again — the tempting shortcut when
        a message wants a row's prose — this fails and says why."""
        found = {n for n, t in self.modules.items() if scans_markdown(t)}
        for name in (
            "test_ci_catalog_completeness.py",
            "test_ci_catalog_no_ghost_rows.py",
            "test_ci_collector_table_completeness.py",
        ):
            with self.subTest(module=name):
                self.assertIn(name, self.modules, f"{name} is not tracked")
                self.assertNotIn(
                    name,
                    found,
                    f"{name} reads Markdown again. Its invariant is supposed to "
                    "compare against ci-guard-inventory.toml, so the Markdown "
                    "reduction's residual cannot reach it — route prose reading "
                    "through test_ci_catalog_doc_sync.py instead.",
                )

    def test_every_scanner_reduces_or_declares_why_not(self):
        offenders = []
        for name, tree in sorted(self.modules.items()):
            if not scans_markdown(tree):
                continue
            if applies_reduction(tree) or exemption(tree):
                continue
            offenders.append(name)
        self.assertEqual(
            offenders,
            [],
            "guard(s) read a Markdown document without reducing it to what a "
            f"reader sees: {offenders}. Either route the text through "
            f"`{PIPELINE_NAME}()`, or set `{EXEMPT_NAME} = \"<why>\"` at module "
            "level if the `.md` literal is a path or fixture rather than a "
            "document this parses.",
        )

    def test_every_covered_guard_has_a_LIVE_detector(self):
        """The census proves a call NODE exists, never that the text flows
        through it. This closes that gap by requiring registration.

        `applies_reduction` is AST-based, which killed the docstring and `#`
        comment vectors, but a review then showed three that survive: the call
        sitting in a never-invoked helper, under `if False:`, or applied to a
        DIFFERENT variable while the scanned text goes raw. All three still
        present a real `ast.Call` node. Static analysis cannot decide
        attribution, so the fix is not a smarter matcher — it is that every
        in-class guard must appear in `_detectors()`, whose probes EXECUTE the
        real function. An unregistered guard fails here instead of riding on a
        dead call."""
        mods = self.modules
        in_class = {n for n, t in mods.items() if scans_markdown(t)}
        unexcused = {n for n in in_class if not exemption(mods[n])}
        registered = {label.split(".")[0] + ".py" for label, _, _, _ in _detectors()}
        missing = sorted(unexcused - registered - set(COVERED_ELSEWHERE))
        self.assertEqual(
            missing,
            [],
            f"in-class guard(s) with no live detector probe: {missing}. Add an "
            "entry to `_detectors()` with a control payload, or to "
            "`COVERED_ELSEWHERE` naming what already executes the real call. "
            "A census pass alone can be satisfied by a call that never runs.",
        )

    def test_the_covered_elsewhere_entries_are_still_in_class(self):
        # A stale exemption is an exemption for nothing. If one of these stops
        # scanning Markdown, its entry should go rather than sit here implying
        # coverage that no longer has a subject.
        in_class = {n for n, t in self.modules.items() if scans_markdown(t)}
        for name in COVERED_ELSEWHERE:
            with self.subTest(module=name):
                self.assertIn(
                    name,
                    in_class,
                    f"{name} is listed in COVERED_ELSEWHERE but the census no "
                    "longer flags it — drop the entry",
                )

    def test_exemptions_carry_a_reason(self):
        # A LENGTH FLOOR, and nothing more: 35 junk characters satisfy it, as a
        # review measured. No automated check can read prose, so this catches
        # only the empty and one-word forms and the real protection is review —
        # said plainly here rather than left implying a rigour it does not have.
        # The exemption hole that mattered was the substring pipeline check, now
        # `applies_reduction`.
        for name, tree in sorted(self.modules.items()):
            for node in tree.body:
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == EXEMPT_NAME
                    for t in node.targets
                ):
                    with self.subTest(module=name):
                        why = exemption(tree)
                        self.assertTrue(
                            why and len(why) > 30,
                            f"{name} declares {EXEMPT_NAME} without a usable "
                            "reason — say what the `.md` literal actually is",
                        )


if __name__ == "__main__":
    unittest.main()
