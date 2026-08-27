"""
Regression guard: every `<style>` the dashboards emit carries the CSP nonce, and
the meta-CSP that makes the nonce load-bearing stays in place.

WHY
---
`style-src` stopped being `'unsafe-inline'` on 2026-08-27 (ZAP rule 10055, found
by the first nightly DAST run that actually scanned something). It is now
`style-src 'nonce-{{CSP_NONCE}}'` plus an explicit `style-src-attr
'unsafe-inline'` for the ~105 inline `style=` attributes the builders emit via
`innerHTML`.

That makes an un-nonced `<style>` element BLOCKED rather than merely untidy.

THE MISS THIS CODIFIES
----------------------
The first version of that change nonced the two `<style>` elements visible in the
template `.html` files and shipped. CI then failed with
`directive=style-src-elem blockedURI=inline line=1090` — a THIRD `<style>`, inside
`_INLINE_ARCH_SVG` in `scanner/lib/dashboard_template.py`, which no `.html` file
contains.

It was invisible locally for a reason worth remembering: that string is the
FALLBACK branch, taken only when `docs/architecture/*.svg` is absent. Those files
are GITIGNORED, so a developer machine that has generated the diagrams takes the
other branch (base64 into `<img src="data:image/svg+xml">`, where an inner
`<style>` is a separate script-less document and never sees the page's style-src)
while CI — which never has them — always takes the fallback. Green locally, red in
CI. Reproduced by moving the two SVGs aside: same violation, same line 1090.

So the runtime CSP recorder in the liveness harnesses is not enough on its own.
It is strictly stronger where it looks — it proves real blocking — but it only
sees the branch that ran. This guard is branch-INDEPENDENT: it reads source, so a
`<style>` on a path no test happens to exercise is still caught.

DIRECTION
---------
- Sources are enumerated by GLOB over `git ls-files`, never a hand-maintained
  list. The sibling `test_dashboard_no_inline_handlers.py` carries an explicit
  `_SOURCE_FILES` of ten paths and `scanner/lib/dashboard_template.py` — the file
  that held this very defect — is not among them. A list is a thing to forget.
- `git ls-files`, not the filesystem: a gitignored or untracked local file is not
  what CI builds from, and scanning it makes results differ by machine, which is
  the exact asymmetry above.
- The CSP assertions are the other half. A nonce'd `<style>` proves nothing if
  the policy reverts to `'unsafe-inline'`, and dropping `style-src-attr` unstyles
  the page without producing a single violation report.

stdlib-only (`re`, `subprocess` for `git ls-files`, `pathlib`, `unittest`). No
network. Runs under pytest and `python3 -m unittest`.

OWASP A05 (Security Misconfiguration); OWASP Secure Headers Project (CSP).
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_html_comments  # noqa: E402

# Reused, NOT re-implemented. `_strip_py_comments` is tokenizer-based and already
# carries the fix for the hazard a second copy would walk straight into: a
# `line.split("#", 1)[0]` stripper cuts at the first `#` anywhere on the line,
# including inside a string literal, and the arch-SVG string this file scans is
# full of them (`fill:#e2e8f0`, `stroke="#38bdf8"`). That truncation would hide
# the real `<style>` tag — a false NEGATIVE, the dangerous direction. Duplicating
# strippers is also how #471 fixed one of two copies of the same loader and left
# the guard importing the fixed one.
from test_dashboard_no_inline_handlers import _strip_py_comments  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

NONCE_PLACEHOLDER = "{{CSP_NONCE}}"

# The two CSP'd dashboard pages. Their policies are asserted directly.
DASHBOARD_PAGES = (
    "scanner/lib/dashboard-template.html",
    "claudesec-asset-dashboard.html",
)

# Globs covering every source that contributes markup to those pages. Matched
# against `git ls-files` output.
SOURCE_GLOBS = (
    "scanner/lib/dashboard*.html",
    "scanner/lib/dashboard*.py",
    "scanner/lib/dashboard_*.py",
    "claudesec-asset-dashboard.html",
)

# `<style` followed by anything up to the closing `>` of the OPENING tag. `[^>]*`
# rather than a greedy match so a later `>` in the stylesheet body cannot extend
# the span past the tag it is meant to describe.
STYLE_OPEN_TAG_RE = re.compile(r"<style\b[^>]*>", re.IGNORECASE)


def tracked_files() -> list:
    """Repo-relative paths of every git-TRACKED file.

    Tracked, not on-disk: an untracked or gitignored file is not what CI builds
    from, so scanning it would make this guard's verdict depend on the machine.
    """
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line]


def dashboard_sources() -> list:
    """Tracked files matching any SOURCE_GLOBS pattern, de-duplicated and sorted."""
    tracked = tracked_files()
    hits = set()
    for pattern in SOURCE_GLOBS:
        hits.update(p for p in tracked if Path(p).match(pattern))
    return sorted(hits)


def strip_comments_for(rel: str, text: str) -> str:
    """`text` with comments removed, by source language.

    Necessary in both directions, and the first version of this file got it
    wrong: scanning raw source flagged three tags that were this module's own
    prose explaining the rule (`` the `<style>` below carries the nonce ``), which
    cannot be nonced. Comments must go — but with a tokenizer for `.py`, never a
    `#` split, because the arch-SVG string is full of `#` colour literals.
    """
    if rel.endswith(".py"):
        return _strip_py_comments(text)
    if rel.endswith((".html", ".htm")):
        return strip_html_comments(text)
    return text


def unnonced_style_tags(text: str) -> list:
    """Opening `<style ...>` tags in `text` that do not carry the nonce.

    Operates on already-comment-stripped text; see `strip_comments_for`.
    """
    return [
        tag
        for tag in STYLE_OPEN_TAG_RE.findall(text)
        if f'nonce="{NONCE_PLACEHOLDER}"' not in tag
    ]


def source_text(rel: str) -> str:
    """Comment-stripped contents of a tracked dashboard source."""
    return strip_comments_for(
        rel, (REPO_ROOT / rel).read_text(encoding="utf-8")
    )


class TestDashboardSourceEnumeration(unittest.TestCase):
    def test_globs_find_the_known_sources(self):
        """Vacuity canary: an empty/short source list makes everything below pass.

        Pins the three files that actually carry `<style>` today, including
        `dashboard_template.py` — the one the hand-maintained list in
        `test_dashboard_no_inline_handlers.py` omits.
        """
        sources = dashboard_sources()
        self.assertGreaterEqual(
            len(sources),
            10,
            f"the source globs matched only {len(sources)} tracked file(s): "
            f"{sources}. They are returning too little, so the scan below proves "
            "nothing.",
        )
        for required in (
            "scanner/lib/dashboard-template.html",
            "scanner/lib/dashboard_template.py",
            "claudesec-asset-dashboard.html",
        ):
            self.assertIn(
                required,
                sources,
                f"{required} is no longer matched by SOURCE_GLOBS. It emits "
                "dashboard markup, so a `<style>` added to it would go unchecked.",
            )

    def test_scanner_finds_the_style_tags(self):
        """Anti-tautology: the tag regex must actually match real source.

        Without this, a `STYLE_OPEN_TAG_RE` that matched nothing would satisfy
        every assertion in this file.
        """
        total = 0
        for rel in dashboard_sources():
            total += len(STYLE_OPEN_TAG_RE.findall(source_text(rel)))
        self.assertGreaterEqual(
            total,
            3,
            f"found only {total} `<style>` opening tag(s) across the dashboard "
            "sources; at least three exist (two templates and the inline arch "
            "SVG fallback). The regex is matching too little.",
        )


class TestEveryStyleTagIsNonced(unittest.TestCase):
    def test_no_unnonced_style_tag_in_any_source(self):
        offenders = {}
        for rel in dashboard_sources():
            bad = unnonced_style_tags(source_text(rel))
            if bad:
                offenders[rel] = bad
        self.assertEqual(
            offenders,
            {},
            "`<style>` tag(s) without the CSP nonce:\n"
            + "\n".join(f"  {rel}: {tags}" for rel, tags in offenders.items())
            + f'\nAdd nonce="{NONCE_PLACEHOLDER}" to the opening tag. Since '
            "2026-08-27 `style-src` is nonce-based, so an un-nonced `<style>` is "
            "BLOCKED, not merely untidy — this is how the inline arch-SVG "
            "fallback in dashboard_template.py reddened CI while passing locally "
            "(the preferred branch needs gitignored SVGs that CI never has).",
        )


class TestDashboardCspShape(unittest.TestCase):
    """The policy that makes the nonces load-bearing."""

    def _csp_of(self, rel: str) -> str:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        m = re.search(
            r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"',
            text,
            re.IGNORECASE,
        )
        self.assertIsNotNone(m, f"{rel} has no meta-CSP tag")
        return m.group(1)

    def test_style_src_is_nonce_based(self):
        for rel in DASHBOARD_PAGES:
            csp = self._csp_of(rel)
            self.assertNotIn(
                "style-src 'unsafe-inline'",
                csp,
                f"{rel} reverted style-src to 'unsafe-inline' — the exact finding "
                "ZAP rule 10055 reported on 2026-08-26.",
            )
            self.assertIn(
                f"style-src 'nonce-{NONCE_PLACEHOLDER}'",
                csp,
                f"{rel} no longer uses a nonce for style-src, so every "
                "`<style nonce=...>` in the dashboard sources is decoration.",
            )

    def test_style_src_attr_is_explicit(self):
        """Dropping this unstyles the page and reports nothing.

        The CSP fallback chain is style-src-attr -> style-src -> default-src, so
        without an explicit style-src-attr the ~105 inline `style=` attributes
        the builders emit fall through to a nonce-only style-src and are all
        blocked. Verified in headless Chrome: a `style=` attribute resolves to
        rgb(1,2,3) with the directive present and rgb(0,0,0) without it.
        style-src-attr is Baseline widely available (MDN: across browsers since
        December 2022).
        """
        for rel in DASHBOARD_PAGES:
            self.assertIn(
                "style-src-attr 'unsafe-inline'",
                self._csp_of(rel),
                f"{rel} lost `style-src-attr 'unsafe-inline'`. Inline style "
                "attributes then fall back to the nonce-only style-src and the "
                "dashboard renders unstyled — with no CSP violation to explain "
                "it, because the page is doing exactly what the policy says.",
            )

    def test_script_src_stays_nonce_based(self):
        """Unchanged by the style-src work; asserted so this file's edits to the
        same string cannot loosen the script half unnoticed."""
        for rel in DASHBOARD_PAGES:
            csp = self._csp_of(rel)
            self.assertIn(f"script-src 'nonce-{NONCE_PLACEHOLDER}'", csp)
            self.assertNotIn("script-src 'unsafe-inline'", csp)


class TestStyleNonceMutation(unittest.TestCase):
    """Mutation self-tests for the detector. Strings only, never the real files."""

    def test_unnonced_tag_is_detected(self):
        self.assertEqual(
            unnonced_style_tags("<style>.a{color:red}</style>"),
            ["<style>"],
        )

    def test_nonced_tag_is_not_flagged(self):
        self.assertEqual(
            unnonced_style_tags('<style nonce="{{CSP_NONCE}}">.a{color:red}</style>'),
            [],
        )

    def test_wrong_nonce_value_is_detected(self):
        """A hard-coded nonce cannot match the per-request/per-build value."""
        self.assertEqual(
            unnonced_style_tags('<style nonce="hardcoded">.a{}</style>'),
            ['<style nonce="hardcoded">'],
        )

    def test_body_brace_does_not_extend_the_tag_span(self):
        """`[^>]*` must stop at the opening tag's own `>`.

        A greedy `.*>` would swallow the stylesheet body and the closing tag, so a
        nonce appearing ANYWHERE later in the file would satisfy the check for a
        tag that does not carry it.
        """
        self.assertEqual(
            unnonced_style_tags(
                '<style>.a{content:">"}</style>\n<style nonce="{{CSP_NONCE}}"></style>'
            ),
            ["<style>"],
        )

    def test_py_stripper_does_not_truncate_at_a_hash_in_a_string(self):
        r"""The stripper must not cut at a `#` colour literal.

        This is the whole reason `_strip_py_comments` is imported instead of
        re-implemented. A `line.split("#", 1)[0]` stripper would cut this line at
        `fill:#e2e8f0` — BEFORE the `<style>` tag on the same line in the real
        source — and report zero offenders on an un-nonced tag. False negative,
        the dangerous direction, and invisible because the guard goes green.
        """
        line = (
            'SVG = """<svg><style>.a{fill:#e2e8f0}</style>'
            '<rect stroke="#38bdf8"/></svg>"""\n'
        )
        stripped = strip_comments_for("x.py", line)
        self.assertIn(
            "<style>",
            stripped,
            "the python comment stripper removed a `<style>` tag that follows a "
            "`#` colour literal — it is cutting inside a string.",
        )
        self.assertEqual(unnonced_style_tags(stripped), ["<style>"])

    def test_py_stripper_does_remove_real_comments(self):
        """The other direction: an actual `#` comment must still go, or this
        module's own prose about `<style>` re-enters the haystack."""
        self.assertEqual(
            unnonced_style_tags(
                strip_comments_for("x.py", "# the `<style>` below is nonced\nX = 1\n")
            ),
            [],
        )

    def test_html_comments_are_stripped(self):
        self.assertEqual(
            unnonced_style_tags(
                strip_comments_for("x.html", "<!-- a bare <style> in prose -->\n")
            ),
            [],
        )

    def test_the_real_arch_svg_fallback_is_nonced(self):
        """Regression pin on the specific string that reddened CI."""
        src = (REPO_ROOT / "scanner" / "lib" / "dashboard_template.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '<style nonce="{{CSP_NONCE}}">.arch-txt{',
            src,
            "_INLINE_ARCH_SVG's `<style>` lost its nonce. This is the FALLBACK "
            "branch and the only one CI ever takes (docs/architecture/*.svg is "
            "gitignored), so this regresses red in CI and green locally.",
        )


if __name__ == "__main__":
    unittest.main()
