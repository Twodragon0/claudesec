"""CI config regression guard: lychee link-check exclude allowlist stays a
single source of truth in `lychee.toml`.

WHAT THIS PROTECTS
------------------
The `link-check` job in `.github/workflows/lint.yml` runs lychee over `**/*.md`.
Its exclude allowlist (sites that block CI crawlers, release-time-only CHANGELOG
`compare/` tags, etc.) used to be duplicated: a long inline `--exclude` list in
the workflow AND a stale dotted `.lychee.toml` that lychee never auto-discovered
(only an undotted `lychee.toml` is auto-loaded). The two copies drifted — the
inline list was missing the `compare/` exclude, so every PR's link-check
re-fetched the CHANGELOG version-compare URLs that 404 by design.

The fix consolidated the allowlist into one auto-discoverable `lychee.toml`
consumed via `lychee --config lychee.toml`. This guard keeps it that way:

INVARIANTS (direction in parentheses)
- `lychee.toml` exists at the repo root (presence) and the dotted
  `.lychee.toml` does NOT (absence) — a dotted file silently reverts to the
  never-auto-discovered footgun this consolidation removed.
- `lychee.toml` carries a populated `exclude` list that includes the
  release-time `compare/` entry (the specific 404 fix) and `node_modules` in
  `exclude_path` (presence).
- The `link-check` job wires `--config lychee.toml` (presence) and carries NO
  inline `--exclude ` flag (absence) — so the allowlist cannot drift back into a
  second copy in the workflow.

Maps to OWASP CICD-SEC-7 (Insecure System Configuration): a config split-brain
that silently disables/weakens a check. The lychee BINARY pin (`v0.23.0`) is a
separate invariant owned by `test_ci_gate_topology.py`; this guard does not
duplicate it.

stdlib-only; no PyYAML; no `scanner/lib` import. Passes under pytest and
`python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"
LYCHEE_TOML = REPO_ROOT / "lychee.toml"
DOTTED_LYCHEE_TOML = REPO_ROOT / ".lychee.toml"

# The one exclude entry the inline list was missing — its presence in the
# config file is the concrete regression this guard targets.
COMPARE_EXCLUDE = "github.com/Twodragon0/claudesec/compare/"

# Links that redirect BY DESIGN to an auth gate or a file, so the written URL is
# correct as-is and must NOT be "resolved" to its redirect target. They are
# excluded to silence lychee's redirect WARN; dropping an entry re-surfaces the
# WARN and invites a well-meaning "fix" that rewrites the URL into its broken
# target (auth-login page) or a fragile deep file path. Added with PR #291.
INTENTIONAL_REDIRECT_EXCLUDES = (
    # GitHub "report a vulnerability" form -> 302 to login when unauthenticated.
    "github.com/Twodragon0/claudesec/security/advisories/new",
    # Kakao OG-tag debugger tool -> 302/303 to accounts.kakao.com login.
    "developers.kakao.com/tool/debugger/sharing",
    # NIST position paper -> 302 to a versioned PDF; the /document/ landing page
    # is the stable citation (the deep PDF path rots faster, not slower).
    "nist.gov/document/cybersecurity-labeling-position-paper-owasp-samm",
)


def _extract_job_block(text, job_name):
    """Return the lines of a single 2-space-indented job block from a workflow,
    from `  <job_name>:` up to (not including) the next `  <name>:` job key or a
    dedent to a top-level key. Returns "" if the job is absent."""
    lines = text.splitlines()
    out, in_job = [], False
    job_re = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")
    start_re = re.compile(r"^  " + re.escape(job_name) + r":\s*(#.*)?$")
    for line in lines:
        if not in_job:
            if start_re.match(line):
                in_job = True
                out.append(line)
            continue
        # A new top-level key (col 0) or a sibling job key ends the block.
        if line and not line[0].isspace():
            break
        if job_re.match(line) and not start_re.match(line):
            break
        out.append(line)
    return "\n".join(out)


def _extract_redirect_section_entries(toml_text):
    """Return the quoted URL entries inside the `# --- Intentional redirects`
    section of a lychee.toml body.

    The section runs from its `# --- Intentional redirect...` header up to (not
    including) the next `# ---` section header. Only lines whose first
    non-space char is a double-quote count as entries, so an example URL quoted
    inside a `#  * ...` comment line (e.g. "report a vulnerability") is never
    miscounted. Pure function over text — no file I/O — so a self-test can feed
    it a mutated copy without touching the real lychee.toml."""
    section, in_section = [], False
    header_re = re.compile(r"^\s*#\s*---")
    # First non-space char is a quote → an exclude entry, not a `#` comment.
    # Backref \1 accepts either quote style (TOML allows both) without matching
    # a mismatched-quote pair.
    entry_re = re.compile(r"""^\s*(["'])(.+?)\1""")
    for line in toml_text.splitlines():
        if in_section:
            if header_re.match(line):
                break
            m = entry_re.match(line)
            if m:
                section.append(m.group(2))
        elif header_re.match(line) and "Intentional redirect" in line:
            in_section = True
    return section


class TestCiLycheeConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lint_text = LINT_YML.read_text(encoding="utf-8") if LINT_YML.is_file() else ""
        cls.toml_text = LYCHEE_TOML.read_text(encoding="utf-8") if LYCHEE_TOML.is_file() else ""
        # Comments stripped so the explanatory "# ... exclude allowlist ..."
        # comment in the job cannot satisfy/trip a token check.
        cls.link_check_block = strip_comment_lines(
            _extract_job_block(cls.lint_text, "link-check")
        )

    def test_lint_yml_exists(self):
        self.assertTrue(LINT_YML.is_file(), f"{LINT_YML} not found")

    def test_lychee_toml_exists(self):
        self.assertTrue(
            LYCHEE_TOML.is_file(),
            "lychee.toml (undotted, auto-discoverable) is missing — the "
            "link-check exclude allowlist must live here as the single source "
            "of truth.",
        )

    def test_no_dotted_lychee_toml(self):
        # A dotted .lychee.toml is NOT auto-discovered by lychee, so it silently
        # goes stale (the original drift). Forbid its return.
        self.assertFalse(
            DOTTED_LYCHEE_TOML.is_file(),
            ".lychee.toml (dotted) must not exist — lychee does not "
            "auto-discover a dotted config, so it silently goes stale. Use the "
            "undotted lychee.toml instead.",
        )

    def test_link_check_block_found(self):
        self.assertTrue(
            self.link_check_block,
            "Could not locate the `link-check` job block in lint.yml — if it was "
            "renamed, update this guard.",
        )

    def test_link_check_uses_config_file(self):
        self.assertIn(
            "--config lychee.toml",
            self.link_check_block,
            "The link-check job must invoke lychee with `--config lychee.toml` so "
            "the externalized exclude allowlist is actually consumed.",
        )

    def test_link_check_has_no_inline_excludes(self):
        # `--exclude ` (trailing space) matches the per-URL flag but NOT
        # `--exclude-path`; either way, neither should reappear inline — the
        # allowlist belongs in lychee.toml.
        self.assertNotRegex(
            self.link_check_block,
            r"--exclude(-path)?\b",
            "The link-check job must NOT carry inline `--exclude`/`--exclude-path` "
            "flags — the exclude allowlist is owned by lychee.toml. Add new "
            "exclusions there, not in the workflow, or they will drift.",
        )

    def test_toml_exclude_populated_with_compare_fix(self):
        toml_no_comments = strip_comment_lines(self.toml_text)
        self.assertRegex(
            toml_no_comments,
            r"exclude\s*=\s*\[",
            "lychee.toml must declare an `exclude = [ ... ]` allowlist.",
        )
        self.assertIn(
            COMPARE_EXCLUDE,
            toml_no_comments,
            "lychee.toml must exclude the release-time CHANGELOG compare URLs "
            f"({COMPARE_EXCLUDE!r}) — they 404 by design at PR time. Dropping "
            "this re-introduces the CHANGELOG compare-URL 404 noise.",
        )

    def test_toml_keeps_intentional_redirect_excludes(self):
        # These URLs redirect by design (auth gate / file). They are excluded so
        # lychee's redirect WARN stays quiet AND so the next link-rot sweep does
        # not "resolve" them into their broken targets. Dropping any one is a
        # silent weakening of that intent — keep all of them present.
        toml_no_comments = strip_comment_lines(self.toml_text)
        for entry in INTENTIONAL_REDIRECT_EXCLUDES:
            self.assertIn(
                entry,
                toml_no_comments,
                f"lychee.toml must keep the intentional-redirect exclude "
                f"{entry!r}. It redirects by design (auth gate or file); without "
                "the exclude, lychee re-flags it as a redirect and a future "
                "link-rot sweep may rewrite it into its broken target. See PR "
                "#291.",
            )

    def test_toml_intentional_redirect_excludes_are_exactly_registered(self):
        # Exact-count pin (#292 hardening). The all-present check above catches
        # a REMOVED entry; this catches an ADDED one — a 4th redirect-shaped
        # exclude smuggled into lychee.toml's "Intentional redirects" section
        # without registering it in INTENTIONAL_REDIRECT_EXCLUDES here. Such a
        # smuggle would let genuine link rot masquerade as an "intentional
        # redirect" and slip past review. Require the section to match the
        # registered set EXACTLY (both membership and count).
        entries = _extract_redirect_section_entries(self.toml_text)
        self.assertEqual(
            len(entries),
            len(INTENTIONAL_REDIRECT_EXCLUDES),
            "lychee.toml's `# --- Intentional redirects` section has "
            f"{len(entries)} entries but {len(INTENTIONAL_REDIRECT_EXCLUDES)} "
            "are registered in INTENTIONAL_REDIRECT_EXCLUDES. A redirect "
            "exclude was added or removed without updating this guard — if it "
            "is a genuine intentional redirect, register it here; otherwise it "
            "may be link rot disguised as a redirect. Entries found: "
            f"{entries!r}",
        )
        self.assertEqual(
            set(entries),
            set(INTENTIONAL_REDIRECT_EXCLUDES),
            "lychee.toml's `# --- Intentional redirects` section does not match "
            "the registered INTENTIONAL_REDIRECT_EXCLUDES set. Unregistered: "
            f"{sorted(set(entries) - set(INTENTIONAL_REDIRECT_EXCLUDES))!r}; "
            f"missing from file: "
            f"{sorted(set(INTENTIONAL_REDIRECT_EXCLUDES) - set(entries))!r}",
        )

    def test_exact_count_guard_catches_a_smuggled_fourth_exclude(self):
        # Mutate-then-verify self-test: prove the exact-count guard is NOT a
        # false-negative (project memory warns substring guards repeatedly
        # shipped CRITICAL false-negatives). Inject a 4th redirect-shaped
        # exclude into a COPY of the lychee.toml body — never the real file —
        # and assert the section parser now surfaces it, i.e. the exact-count
        # test above WOULD fail. Also confirm the parser ignores the example
        # URL quoted inside the section's `#  * ...` comment lines.
        last = INTENTIONAL_REDIRECT_EXCLUDES[-1]
        marker = f'"{last}",'
        smuggled = "example.com/link-rot-disguised-as-redirect"
        mutated = self.toml_text.replace(
            marker, f'{marker}\n  "{smuggled}",', 1
        )
        self.assertNotEqual(
            mutated,
            self.toml_text,
            "self-test setup failed: could not locate the last registered "
            f"redirect exclude ({marker!r}) in lychee.toml to inject after.",
        )
        entries = _extract_redirect_section_entries(mutated)
        self.assertIn(
            smuggled,
            entries,
            "false-negative: the section parser did not surface a smuggled 4th "
            "redirect exclude, so the exact-count guard would not catch it.",
        )
        self.assertEqual(
            len(entries),
            len(INTENTIONAL_REDIRECT_EXCLUDES) + 1,
            "false-negative: a smuggled 4th redirect exclude did not raise the "
            f"section entry count. Parsed {entries!r}.",
        )
        # Sanity: the unmutated body still parses to exactly the registered set,
        # confirming the comment-line example URLs are not miscounted.
        self.assertEqual(
            set(_extract_redirect_section_entries(self.toml_text)),
            set(INTENTIONAL_REDIRECT_EXCLUDES),
        )

    def test_toml_excludes_node_modules_path(self):
        self.assertRegex(
            strip_comment_lines(self.toml_text),
            r"exclude_path\s*=\s*\[[^\]]*node_modules",
            "lychee.toml must keep `node_modules` in `exclude_path` (moved from "
            "the inline `--exclude-path node_modules`).",
        )

    def test_toml_excludes_claudesec_sources_path(self):
        # `.claudesec-sources` is a gitignored local cache of fetched upstream
        # docs. It is absent in CI (never committed) but present on dev machines,
        # where a local sweep would otherwise walk it and report rot in
        # third-party docs we do not own. Keep it in `exclude_path` so the local
        # verify command matches CI's committed-file-only view.
        self.assertRegex(
            strip_comment_lines(self.toml_text),
            r"exclude_path\s*=\s*\[[^\]]*\.claudesec-sources",
            "lychee.toml must keep `.claudesec-sources` in `exclude_path` so a "
            "local sweep does not scan the gitignored upstream-source cache.",
        )

    def test_lychee_toml_is_change_detected(self):
        # The `changes` job path-gates link-check on the `markdown` bucket and
        # scanner-unit-tests (this guard) on the `scanner` bucket. If lychee.toml
        # falls out of BOTH, a lychee.toml-only PR edits the exclude allowlist
        # with neither a live link-check NOR this guard running — the allowlist
        # silently changes unvalidated. Assert it stays in both detect patterns.
        for bucket in ("scanner", "markdown"):
            m = re.search(
                r'echo\s+"' + bucket + r'=\$\(match\s+\'([^\']*)\'',
                self.lint_text,
            )
            self.assertTrue(
                m, f"Could not find the `{bucket}=` match pattern in lint.yml's "
                "`changes` job — if it was restructured, update this guard.",
            )
            self.assertRegex(
                m.group(1),
                r"lychee\\\.toml",
                f"lychee.toml dropped from the `{bucket}` change-detection "
                "bucket in lint.yml — a lychee.toml-only PR would skip its "
                "PR-time validation. Keep `lychee\\.toml` in the match pattern.",
            )


if __name__ == "__main__":
    unittest.main()
