"""
Regression guard: the version LABEL on a SHA-pinned `uses:` ref must be a
consistent claim across the repo.

THE DEFECT THIS EXISTS FOR, MEASURED (2026-09-17). `.github/workflows/lint.yml`
pinned `actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97  # v6.1.0`.
That SHA is `v7.0.0` (and `v7`); the real `v6.1.0` is `83679a892e2d`, an eight
-month-older commit. The SHA is what Actions executes, so nothing misbehaved —
the cost is that a reader, a reviewer, or the next person bumping the pin
reasons about a version one MAJOR below what runs. This is the incident #552
quotes as its deliberately-wrong narrative example ("a stale `# v4.2.2` comment
on a `v7.0.0` SHA"), found live.

WHAT THIS GUARD CANNOT DO, STATED SO NOBODY READS MORE INTO ITS GREEN.
It cannot verify a label against the real tag. That requires resolving the SHA
through the GitHub API, and guards run offline and stdlib-only (`ci-guards`
installs zero packages; hermetic tests are a repo invariant). A guard that
pretended otherwise would be the vacuous kind this repo hunts. What IS decidable
offline is INTERNAL CONSISTENCY, and that is all this asserts:

  A. one (repo, sha) -> at most one label     a label edited without the SHA
  B. one (repo, label) -> at most one sha     a SHA edited without the label
  C. a (repo, sha) labelled anywhere is labelled EVERYWHERE

C is not cosmetic: A and B only bite where two sites can disagree, so an action
pinned at seven sites with one label has nothing to contradict. That was exactly
the shape of the live defect — six bare `setup-python` refs and one wrong label.
C converts single-site drift into a detectable conflict at the next site.

Verifying a label against the actual tag needs network and therefore belongs in
a scheduled watch workflow (the `protection-drift-watch` / `dast-freshness-watch`
pattern), not here. Not built yet; recorded so the gap is a decision and not an
oversight.

DIRECTION: equality (`==`). Any divergence trips. A legitimate bump changes the
SHA and the label together at every site, which stays green.

Refs: OWASP CICD-SEC-1 (Insufficient Flow Control) and CICD-SEC-7 (Insecure
System Configuration); NIST SSDF PW.4 / PO.3 (verify third-party components and
their provenance).
"""

import unittest
from collections import defaultdict
from pathlib import Path

from _ci_guard_util import (
    tracked_files,
    uses_refs_labeled,
    workflow_and_action_files,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

# Only 40-hex SHA pins carry a version label worth cross-checking. Tag-pinned
# (`@v4`) and local (`./`) refs name their own version and are out of scope.
_SHA_LEN = 40

# Measured 2026-09-18 over `label_corpus()`: 74 labelled, 4 bare, 78 total.
MIN_LABELLED_PINS = 74


def _split_ref(ref: str):
    """`owner/repo/sub@sha` -> `("owner/repo", sha)`, or `None` when the ref is
    not SHA-pinned. The action's IDENTITY is the first two path components: a
    subpath (`github/codeql-action/init`) is the same released artifact as its
    siblings and shares their SHA, so keying on the full path would split one
    action into three and hide a disagreement between them."""
    if "@" not in ref:
        return None
    path, _, rev = ref.rpartition("@")
    if len(rev) != _SHA_LEN or not all(c in "0123456789abcdef" for c in rev):
        return None
    parts = path.split("/")
    if len(parts) < 2 or path.startswith(".") or "://" in path:
        return None
    return "/".join(parts[:2]), rev


def label_problems(docs) -> list:
    """The detector. `docs` is an iterable of `(display_path, text)`.

    Kept a pure function of its input so the fixtures below drive THIS code and
    not a re-implementation of it — the surrogate-detector failure #536 spent
    four rounds on."""
    by_sha = defaultdict(lambda: defaultdict(list))   # (repo, sha) -> label -> sites
    by_label = defaultdict(lambda: defaultdict(list))  # (repo, label) -> sha -> sites
    for path, text in docs:
        for lineno, ref, label in uses_refs_labeled(text):
            split = _split_ref(ref)
            if split is None:
                continue
            repo, sha = split
            by_sha[(repo, sha)][label].append(f"{path}:{lineno}")
            if label is not None:
                by_label[(repo, label)][sha].append(f"{path}:{lineno}")

    problems = []
    for (repo, sha), labels in sorted(by_sha.items()):
        named = {k: v for k, v in labels.items() if k is not None}
        if len(named) > 1:
            detail = "; ".join(
                f"{lab} at {', '.join(sites)}" for lab, sites in sorted(named.items())
            )
            problems.append(
                f"A: {repo}@{sha[:12]} is labelled {len(named)} different ways -> "
                f"{detail}. One SHA is one release; fix the label that is wrong."
            )
        if named and None in labels:
            lab = sorted(named)[0]
            problems.append(
                f"C: {repo}@{sha[:12]} is labelled '{lab}' at "
                f"{', '.join(sorted(s for v in named.values() for s in v))} but bare at "
                f"{', '.join(labels[None])}. Label every site or none — a lone label "
                f"has nothing to disagree with, which is how the v6.1.0/v7.0.0 drift "
                f"survived six sibling refs."
            )
    for (repo, label), shas in sorted(by_label.items()):
        if len(shas) > 1:
            detail = "; ".join(
                f"{s[:12]} at {', '.join(sites)}" for s, sites in sorted(shas.items())
            )
            problems.append(
                f"B: {repo} '{label}' maps to {len(shas)} different SHAs -> {detail}. "
                f"A released tag is one commit; a bump that moved the SHA without the "
                f"label (or the reverse) looks exactly like this."
            )
    return problems


def label_corpus() -> list:
    """Repo-relative paths whose `uses:` labels are in scope.

    `workflow_and_action_files()` is NOT enough. It covers what THIS repo runs;
    `templates/` is what `scripts/setup.sh` installs into OTHER people's
    repositories, and a version label there is read by maintainers who cannot
    see our history — the highest-cost place for a wrong one, and the lowest
    chance of anyone noticing. The false-negative review of #557 found a real C
    violation living in exactly that gap
    (`dependency-review-action` labelled in `templates/` and reading as bare in
    `lint.yml`, because the annotated form parsed to None).

    Enumerated from `git ls-files`, not the filesystem: an untracked local file
    is not what CI builds from (`tracked_files`)."""
    paths = {str(Path(p).relative_to(REPO_ROOT)) for p in workflow_and_action_files()}
    paths |= {
        p for p in tracked_files()
        if p.startswith("templates/") and p.endswith((".yml", ".yaml"))
    }
    return sorted(paths)


def _real_docs() -> list:
    return [
        (p, (REPO_ROOT / p).read_text(encoding="utf-8")) for p in label_corpus()
    ]


class TestActionPinLabels(unittest.TestCase):
    def test_workflow_files_exist(self):
        """Canary: a moved workflow dir must fail loudly, not pass vacuously."""
        files = workflow_and_action_files()
        self.assertGreater(len(files), 5, "workflow enumeration collapsed")

    def test_labelled_pin_count_does_not_regress(self):
        """Non-vacuity of the SUBJECT, as a RATCHET rather than a floor.

        A/B/C are all trivially satisfiable over unlabelled refs, so labels going
        dark disarms this guard without failing it. A loose threshold does not
        notice that: the first version of this test allowed anything above 20
        while 74 pins were labelled, so an entire action could lose its labels —
        the exact silent-degradation path the false-negative review of #557
        demonstrated — with the canary still green.

        Ratchet direction: `>=`. Adding a labelled pin is fine and RAISES the
        baseline; removing one is a decision that has to be made here, in this
        constant, where a reviewer sees it."""
        labelled = [
            (p, ln, ref)
            for p, text in _real_docs()
            for ln, ref, lab in uses_refs_labeled(text)
            if lab is not None and _split_ref(ref)
        ]
        self.assertGreaterEqual(
            len(labelled), MIN_LABELLED_PINS,
            f"labelled SHA pins fell to {len(labelled)}, below the "
            f"{MIN_LABELLED_PINS} baseline. Labels going dark disarms A/B/C "
            f"silently — if a pin was legitimately removed, lower the constant "
            f"in this file and say why in the PR."
        )

    def test_labels_are_internally_consistent(self):
        problems = label_problems(_real_docs())
        self.assertEqual(
            [], problems,
            "action version labels disagree with each other:\n  "
            + "\n  ".join(problems),
        )


class TestDetectorFiresOnEachShape(unittest.TestCase):
    """Non-vacuous: each planted defect must be REPORTED, and the clean control
    must differ from the mutant by exactly that report — a delta, not an empty
    list (#553: a negative fixture asserting `[]` also passes when an unrelated
    real regression appears, and then blames the wrong shape)."""

    SHA_A = "a" * 40
    SHA_B = "b" * 40

    def _doc(self, body):
        return [("fixture.yml", body)]

    def test_clean_fixture_reports_nothing(self):
        clean = self._doc(
            f"jobs:\n  x:\n    steps:\n"
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
        )
        self.assertEqual([], label_problems(clean))

    def test_A_same_sha_two_labels(self):
        clean = (
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
        )
        mutant = clean.replace("# v7.0.1\n", "# v6.0.0\n", 1)
        self.assertNotEqual(clean, mutant, "fixture stale: no substitution made")
        before, after = label_problems(self._doc(clean)), label_problems(self._doc(mutant))
        self.assertEqual([], before)
        self.assertEqual(1, len(after) - len(before), f"expected one new finding: {after}")
        self.assertTrue(after[0].startswith("A:"), after)

    def test_B_same_label_two_shas(self):
        clean = (
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
        )
        mutant = clean.replace(self.SHA_A, self.SHA_B, 1)
        self.assertNotEqual(clean, mutant, "fixture stale: no substitution made")
        after = label_problems(self._doc(mutant))
        self.assertEqual([], label_problems(self._doc(clean)))
        self.assertTrue(any(p.startswith("B:") for p in after), after)

    def test_C_labelled_at_one_site_bare_at_another(self):
        clean = (
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
        )
        mutant = clean.replace("@" + self.SHA_A + "  # v7.0.1", "@" + self.SHA_A, 1)
        self.assertNotEqual(clean, mutant, "fixture stale: no substitution made")
        after = label_problems(self._doc(mutant))
        self.assertEqual([], label_problems(self._doc(clean)))
        self.assertTrue(any(p.startswith("C:") for p in after), after)

    def test_a_commented_out_ref_is_not_a_site(self):
        """`uses_refs_labeled` skips whole-line comments, so a ref quoted in
        prose cannot manufacture a conflict (a FALSE ALARM here, not a bypass —
        but a guard that cries wolf gets ignored)."""
        body = (
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
            f"      # - uses: actions/checkout@{self.SHA_B}  # v6.0.0\n"
        )
        self.assertEqual([], label_problems(self._doc(body)))

    def test_subpaths_of_one_action_share_an_identity(self):
        """codeql-action/init and /analyze are one release: a disagreement
        BETWEEN them must be reported, which keying on the full path would hide.
        This is the #478/#483/#511/#549 four-site shape."""
        body = (
            f"      - uses: github/codeql-action/init@{self.SHA_A}  # v4.38.0\n"
            f"      - uses: github/codeql-action/analyze@{self.SHA_A}  # v4.37.9\n"
        )
        problems = label_problems(self._doc(body))
        self.assertTrue(any(p.startswith("A:") for p in problems), problems)

    def test_annotated_labels_do_not_disarm_A(self):
        """Regression pin for the HIGH the false-negative review of #557 found.

        With the old `fullmatch` rule, adopting this repo's existing
        `# v5.0.0 (node24)` style across an action's sites made every one of them
        read as unlabelled, so a MAJOR drift among them produced NO finding —
        a green guard over the exact incident it was written for. Both arms are
        asserted: the drift must fire, and the consistent-annotated case must
        NOT, because a guard that cries wolf on a legal style gets disabled."""
        annotated = "".join(
            f"      - uses: actions/setup-python@{self.SHA_A}  # v7.0.0 (node24)\n"
            for _ in range(3)
        )
        self.assertEqual([], label_problems(self._doc(annotated)))
        drifted = annotated.replace("# v7.0.0 (node24)", "# v6.1.0 (node24)", 1)
        self.assertNotEqual(annotated, drifted, "fixture stale")
        problems = label_problems(self._doc(drifted))
        self.assertTrue(any(p.startswith("A:") for p in problems), problems)

    def test_templates_are_in_scope(self):
        """Regression pin for the second HIGH: `templates/` ships to OTHER
        repositories via `scripts/setup.sh`, so a wrong label there is read by
        maintainers with none of our context — and it was outside the corpus,
        hiding a live C violation."""
        corpus = label_corpus()
        self.assertTrue(
            any(p.startswith("templates/") for p in corpus),
            "templates/ dropped out of the corpus; a label that ships to other "
            "repos would stop being checked",
        )

    def test_tag_pinned_and_local_refs_are_out_of_scope(self):
        body = (
            "      - uses: actions/checkout@v4\n"
            "      - uses: ./.github/actions/setup\n"
            "      - uses: docker://alpine:3.23\n"
        )
        self.assertEqual([], label_problems(self._doc(body)))


if __name__ == "__main__":
    unittest.main()
