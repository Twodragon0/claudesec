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
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import REPO_ROOT, rendered_markdown  # noqa: E402

TESTS_REL = "scanner/tests"
EXEMPT_NAME = "MARKDOWN_SCAN_EXEMPT"
PIPELINE_NAME = "rendered_markdown"


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
    from test_ci_catalog_completeness import missing_rows
    from test_ci_catalog_no_ghost_rows import cited_paths
    from test_ci_collector_table_completeness import table_files
    from test_ci_compliance_doc_table import parse_doc_rows
    from test_ci_kisa_control_alignment import guide_titles

    guard_row = "| `scanner/tests/test_ci_x.py` | verdict |"
    return (
        (
            "test_ci_catalog_completeness.missing_rows",
            guard_row,
            "# Catalog\n\n{}\n",
            lambda doc: not missing_rows(doc, ["test_ci_x.py"]),
        ),
        (
            "test_ci_catalog_no_ghost_rows.cited_paths",
            guard_row,
            "# Catalog\n\n{}\n",
            lambda doc: bool(cited_paths(doc)),
        ),
        (
            "test_ci_collector_table_completeness.table_files",
            "| `test_ci_x.py` | verdict |",
            "# Catalog\n\n## Block-collector enumeration\n\n{}\n",
            lambda doc: bool(table_files(doc)),
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
    from disk has nothing left to check."""
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
        # Anchors the AST heuristic to a case known to be in-class. If
        # `scans_markdown` stops recognising the catalog guards, the sweep below
        # would report a clean tree while checking almost nothing.
        found = {n for n, t in self.modules.items() if scans_markdown(t)}
        self.assertIn("test_ci_catalog_completeness.py", found)
        self.assertIn("test_ci_compliance_doc_table.py", found)

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
