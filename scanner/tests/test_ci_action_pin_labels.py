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

THE SECOND THING IT CANNOT DO: an action pinned at exactly ONE site. A, B and C
all need two sites sharing an identity, so a lone wrong label is undetectable
here by construction. Measured 2026-09-18: 11 of 19 identities in the corpus are
single-site (58%) — down from 68% before `templates/` was folded in, which is
part of why widening the corpus was worth doing, but still most of it. Adding
`templates/` raised coverage; only the tag-resolving watch closes the rest.

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

import re
import unittest
from collections import defaultdict
from pathlib import Path

from _ci_guard_util import (
    _USES_LINE_RE,
    strip_inline_comment,
    tracked_files,
    uses_refs_labeled,
    version_tokens,
    workflow_and_action_files,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

# Only 40-hex SHA pins carry a version label worth cross-checking. Tag-pinned
# (`@v4`) and local (`./`) refs name their own version and are out of scope.
_SHA_LEN = 40

# The actions that carry NO version label anywhere in the corpus, pinned as an
# EXACT SET (measured 2026-09-18). Deliberately not a count: a count is payable
# by unrelated additions, which is how the previous `MIN_LABELLED_PINS = 74`
# floor failed — add a four-step workflow (live 74 -> 78) and every `setup-node`
# label could then be stripped back to 74 with the check still green and A/B/C
# reporting nothing. Measured by the false-positive review of #557.
#
# Two-sided, following `DESIRED_CONTEXTS`: an action going dark ADDS a member
# and fails; labelling one of these REMOVES a member and also fails, so the
# improvement is recorded here rather than silently absorbed. Adding a labelled
# pin changes nothing, so ordinary work stays green.
UNLABELLED_ACTIONS = frozenset({
    "docker/build-push-action",
    "ludeeus/action-shellcheck",
    "lycheeverse/lychee-action",
})


def _split_ref(ref: str):
    """`owner/repo/sub@sha` -> `("owner/repo", sha)`, or `None` when the ref is
    not SHA-pinned. The action's IDENTITY is the first two path components: a
    subpath (`github/codeql-action/init`) is the same released artifact as its
    siblings and shares their SHA, so keying on the full path would split one
    action into three and hide a disagreement between them."""
    if "@" not in ref:
        return None
    path, _, rev = ref.rpartition("@")
    rev = rev.lower()  # git prints lowercase, but an uppercase pin is the SAME
    # commit — case-folding here keeps it from being SILENTLY skipped, and keeps
    # two spellings of one sha from becoming two identities.
    if len(rev) != _SHA_LEN or not all(c in "0123456789abcdef" for c in rev):
        return None
    parts = path.split("/")
    if len(parts) < 2 or path.startswith(".") or "://" in path:
        return None
    # The PATH is case-folded for the same reason the sha is: GitHub resolves
    # `Actions/Checkout` to `actions/checkout` (verified against the API), so
    # leaving it case-sensitive SPLITS one action into two identities and hides
    # a disagreement between them — the silent direction, and the one the
    # unlabelled-set pin cannot see either.
    return "/".join(parts[:2]).lower(), rev


# A `uses:` inside a YAML FLOW mapping (`- { uses: x@sha, with: {...} }`). Actions
# runs it — PyYAML resolves the step fully — but `_USES_LINE_RE` anchors the key to
# the start of the line, so the whole ref is invisible to every line-scanning guard
# in this repo, not just this one. Rather than widen the shared matcher (which
# would change what the SHA-pin and gate-topology guards see, in one PR, as a side
# effect), this FAILS CLOSED on the form: ADR-001 §5's rule for a shape the scanner
# provably cannot read. The broader gap is reported separately.
# The VALUE must look like an action ref (`owner/repo…@something`), not just the
# key. Matching the key alone fired on five ordinary lines that are not steps —
# a step `- name:` containing the word `uses:`, an `if:` expression quoting it,
# and three `run:` bodies with `{uses: …}` in jq/JSON/python — measured by the
# false-positive review of #557. Live hits were 0 either way, so this is the
# cry-wolf direction rather than a bypass, but a check that fires on a step name
# is one someone deletes rather than obeys.
_FLOW_USES_RE = re.compile(
    r"[{,]\s*['\"]?uses['\"]?\s*:\s*['\"]?[\w.-]+/[\w./-]+@[\w./-]+", re.IGNORECASE
)


def ambiguous_label_lines(text: str) -> list:
    """`(lineno, body)` for a SHA-pinned `uses:` whose comment names TWO OR MORE
    versions. `version_tokens` refuses to guess which is the label, so without
    this the site would drop out of A/B/C in silence — the same bypass shape the
    old parsing rules had. Reported instead: a false alarm at worst."""
    out = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        m = _USES_LINE_RE.match(strip_inline_comment(raw))
        if not m or not _split_ref(m.group("ref")):
            continue
        cm = re.search(r"\s+#(.*)$", raw)
        if cm and len(version_tokens(cm.group(1))) > 1:
            out.append((lineno, cm.group(1).strip()))
    return out


def unscannable_uses_lines(text: str) -> list:
    """`(lineno, line)` for every flow-style `uses:` the line matcher cannot see."""
    out = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        if _FLOW_USES_RE.search(raw):
            out.append((lineno, raw.strip()))
    return out


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
    def test_the_whole_corpus_is_enumerated(self):
        """Canary over `label_corpus()` — what the guard actually reads.

        It used to assert over `workflow_and_action_files()` alone: 19 files
        against a 32-file corpus, so the 13 `templates/` entries this guard adds
        — the half that ships to other repositories — had NO enumeration canary
        and could collapse silently. A regression introduced by the scope
        widening itself, found by the false-positive review of #557.

        `test_templates_are_in_scope` does not cover it either: `any()` is still
        satisfied when 13 files become 1."""
        corpus = label_corpus()
        workflows = [p for p in corpus if p.startswith(".github/")]
        self.assertGreaterEqual(
            len(workflows), 15, f"workflow enumeration collapsed: {workflows}"
        )
        # The templates half is floored on the files that CONTRIBUTE a SHA-pinned
        # ref, not on the raw count. Only 2 of 13 do; the rest are scanner-config
        # examples with no `uses:` at all. A raw floor of 13 had zero slack and
        # fired on retiring `templates/scorecard.yml` — a file with no refs,
        # whose removal changes nothing this guard measures — while reporting
        # "enumeration collapsed", which is not what happened. Measured by the
        # false-positive review of #557. Counting contributors is also TIGHTER
        # against the failure this canary exists for: if the glob or the suffix
        # filter breaks, contributors go to 0.
        contributing = [
            p for p in corpus
            if p.startswith("templates/")
            and any(
                _split_ref(ref)
                for _, ref, _ in uses_refs_labeled(
                    (REPO_ROOT / p).read_text(encoding="utf-8")
                )
            )
        ]
        self.assertGreaterEqual(
            len(contributing), 2,
            "no templates/ file contributes a SHA-pinned `uses:` any more. Either "
            "the glob broke (the collapse this checks for) or the pinned "
            "templates were retired — if retired, lower this floor and say so.",
        )

    def test_no_action_goes_dark(self):
        """Non-vacuity of the SUBJECT, pinned per ACTION rather than as a total.

        A/B/C are all trivially satisfiable over unlabelled refs, so an action
        losing every label disarms this guard without failing it — and C cannot
        see it, because C compares labelled sites against bare ones and there is
        nothing left to compare.

        Two earlier versions of this check were both payable. `> 20` against 74
        live was slack by construction. `>= 74` looked like a ratchet and was
        not: the constant only moves when a human edits it, so adding one
        four-step workflow (74 -> 78) funded stripping all four `setup-node`
        labels back to 74 — measured, with every check green. A total that
        unrelated additions can pay for is a floor wearing a ratchet's
        docstring.

        So the pin is the SET of actions that carry no label, which additions
        cannot fund."""
        # Keyed on (action, SHA), NOT on the action. A/B/C compare within one
        # (action, sha), so an action-level pin holds as long as ANY one of its
        # SHAs stays labelled — and every site of a DIFFERENT sha can go dark
        # unseen. Measured: a partial bump moves 3 of 7 `setup-python` sites to
        # a new sha (ordinary), those three get annotated in a style the parser
        # missed, one drifts a MAJOR out, and the action never enters the dark
        # set because the OLD sha keeps its labels. Every check green with a
        # wrong label live. Found by the false-negative review of #557 as the
        # successor to the count-based pin it had just replaced.
        labelled, bare = set(), set()
        for _, text in _real_docs():
            for _, ref, lab in uses_refs_labeled(text):
                split = _split_ref(ref)
                if split:
                    (labelled if lab else bare).add(split)
        dark = {action for action, _ in bare - labelled}
        # The message states the FACT, not a diagnosis. An action appearing here
        # may have lost its labels or may be newly added and never have had any,
        # and this check cannot tell those apart — only a second pinned set
        # could, at a maintenance cost the distinction does not earn, BECAUSE
        # THE REMEDY IS THE SAME for both. Saying "went dark" (an earlier
        # version did) is wrong for the newly-added case and sends the reader
        # after a regression that never happened — measured by the
        # false-positive review of #557 on a new third-party action.
        self.assertEqual(
            UNLABELLED_ACTIONS, dark,
            "the set of actions carrying NO version label anywhere changed.\n"
            f"  no label anywhere: {sorted(dark - UNLABELLED_ACTIONS)}\n"
            "    -> either label EVERY site of it (preferred: that puts it under "
            "A/B/C), or add it to UNLABELLED_ACTIONS if the action has no "
            "meaningful version to name.\n"
            f"  now labelled: {sorted(UNLABELLED_ACTIONS - dark)}\n"
            "    -> good; drop it from UNLABELLED_ACTIONS.",
        )

    def test_no_label_in_the_repo_is_ambiguous(self):
        """A comment naming two versions leaves its site out of A/B/C, so the
        repo must contain none."""
        found = [
            f"{p}:{ln}  # {body}"
            for p, text in _real_docs()
            for ln, body in ambiguous_label_lines(text)
        ]
        self.assertEqual(
            [], found,
            "a pin's comment names more than one version, so which one is the "
            "label cannot be decided and the site drops out of the consistency "
            "check. Name exactly one:\n  " + "\n  ".join(found),
        )

    def test_no_uses_is_written_in_a_form_the_scanner_cannot_read(self):
        """Fail closed on flow-style `uses:`, which Actions executes and the line
        matcher cannot see — so A/B/C would pass over it in silence."""
        found = [
            f"{p}:{ln}  {line}"
            for p, text in _real_docs()
            for ln, line in unscannable_uses_lines(text)
        ]
        self.assertEqual(
            [], found,
            "a `uses:` is written in YAML flow style, which every line-scanning "
            "guard in this repo is blind to (this one, the SHA-pin check and the "
            "gate topology check). Rewrite it as a block mapping:\n  "
            + "\n  ".join(found),
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
        """A ref quoted in prose must not manufacture a conflict — the FALSE
        ALARM direction, since a guard that cries wolf gets disabled.

        The commented ref carries the SAME sha as the live one ON PURPOSE. An
        earlier version of this fixture used a different sha, which made it
        VACUOUS: two identities can never be compared, so `[]` came back whether
        or not the comment was skipped, and deleting the comment-skip did not
        change the result. Found by the false-positive review of #557 — this
        file cites #553's "assert a delta, not an empty list" and then broke it.

        With one sha, comment-blindness is observable: the commented line would
        register as a second, UNLABELLED site of the same action and trip C. So
        `[]` here is now evidence that the skip ran."""
        body = (
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
            f"      # - uses: actions/checkout@{self.SHA_A}  # v6.0.0\n"
        )
        self.assertEqual([], label_problems(self._doc(body)))

    def test_the_comment_skip_is_what_makes_that_green(self):
        """The positive control for the test above: with the skip removed, the
        SAME fixture must produce a finding. Without this, `[]` there certifies
        whichever mechanism happened to abort first rather than the control."""
        body = (
            f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.1\n"
            f"      # - uses: actions/checkout@{self.SHA_A}  # v6.0.0\n"
        )
        uncommented = body.replace("      # - uses:", "      - uses:")
        self.assertNotEqual(body, uncommented, "fixture stale")
        problems = label_problems(self._doc(uncommented))
        self.assertTrue(
            any(p.startswith("A:") for p in problems),
            f"the fixture cannot distinguish a comment-blind parser: {problems}",
        )

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
        """Asserted against `_split_ref` DIRECTLY, not through the detector.

        Routing it through `label_problems` was vacuous: none of these forms
        carries a version label, so `[]` came back even with `_split_ref`
        monkeypatched to accept everything — measured. The same shape as the
        commented-ref fixture above, found by the same review pass."""
        for ref in (
            "actions/checkout@v4",
            "actions/checkout@main",
            "./.github/actions/setup",
            "docker://alpine:3.23",
            # The two above carry no `@` at all, so they exit on the first line
            # and never reach the `.`-prefix and `://` filters. These do, and are
            # the cases that actually exercise them:
            "./.github/actions/setup@" + "a" * 40,
            "docker://ghcr.io/x@" + "a" * 40,
            "actions/checkout@" + "a" * 39,   # too short
            "checkout@" + "a" * 40,            # no owner
            "actions/checkout@" + "g" * 40,    # not hex
        ):
            with self.subTest(ref=ref):
                self.assertIsNone(_split_ref(ref))

    def test_a_case_varied_path_is_the_same_identity(self):
        """GitHub resolves `Actions/Checkout` to `actions/checkout`, so leaving
        the path case-sensitive would SPLIT one action in two and hide the
        disagreement — and the unlabelled-set pin cannot see that either."""
        lower = f"actions/checkout@{self.SHA_A}"
        mixed = f"Actions/Checkout@{self.SHA_A}"
        self.assertEqual(_split_ref(lower), _split_ref(mixed))
        body = (
            f"      - uses: {lower}  # v7.0.1\n"
            f"      - uses: {mixed}  # v6.0.0\n"
        )
        problems = label_problems(self._doc(body))
        self.assertTrue(any(p.startswith("A:") for p in problems), problems)

    def test_a_partial_bump_cannot_hide_a_dark_sha(self):
        """The dark-set key must be (action, SHA), not the action.

        A partial bump — the ordinary way an action ends up at two SHAs — can
        leave every site of the NEW sha bare while the old sha keeps its labels.
        Keyed on the action, membership is unchanged and nothing fires; A/B/C
        are blind too, because they compare within one (action, sha) and the new
        one has no labelled site to compare against."""
        docs = [("f.yml",
                 f"      - uses: actions/setup-python@{self.SHA_A}  # v7.0.0\n"
                 f"      - uses: actions/setup-python@{self.SHA_B}\n")]
        by_action, by_pair = set(), set()
        for _, text in docs:
            for _, ref, lab in uses_refs_labeled(text):
                split = _split_ref(ref)
                if split and not lab:
                    by_action.add(split[0])
                    by_pair.add(split)
            for _, ref, lab in uses_refs_labeled(text):
                split = _split_ref(ref)
                if split and lab:
                    by_action.discard(split[0])
                    by_pair.discard(split)
        self.assertEqual(set(), by_action, "per-action keying misses the dark sha")
        self.assertEqual(1, len(by_pair), "per-(action,sha) keying must see it")
        self.assertEqual([], label_problems(docs), "A/B/C are blind here by design")

    def test_an_ambiguous_label_is_reported_not_guessed(self):
        """Two versions in one comment: the parser refuses to pick, so the line
        must be REPORTED. Dropping it silently is the bypass the old parsing
        rules had."""
        one = f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.0\n"
        two = f"      - uses: actions/checkout@{self.SHA_A}  # v7.0.0 -> v8.0.0\n"
        self.assertEqual([], ambiguous_label_lines(one))
        self.assertEqual(1, len(ambiguous_label_lines(two)))
        self.assertIsNone(uses_refs_labeled(two)[0][2], "must not guess a label")

    def test_flow_style_uses_is_reported_not_skipped(self):
        """Actions executes a flow-style step; the line matcher cannot see it.
        Silence there would be a bypass, so the form itself is the finding."""
        flow = (
            '      - { uses: "actions/setup-python@%s", with: { python-version: "3.11" } }\n'
            % self.SHA_A
        )
        self.assertEqual([], unscannable_uses_lines(
            f"      - uses: actions/setup-python@{self.SHA_A}  # v7.0.0\n"
        ))
        self.assertEqual(1, len(unscannable_uses_lines(flow)))

    def test_flow_check_does_not_fire_on_lines_that_merely_say_uses(self):
        """The cry-wolf direction. Matching the `uses:` KEY alone fired on a step
        name, an `if:` expression and three `run:` bodies; the value must look
        like an action ref for the line to be a step."""
        for line in (
            "      - name: check refs, uses: are pinned\n",
            "      - if: contains(github.event.head_commit.message, 'uses:')\n",
            "      - run: jq '.steps[] | {uses: .uses}' x.json\n",
            '      - run: echo \'{"uses": "actions/checkout"}\'\n',
            "      - run: python3 -c \"d={'uses': 1}\"\n",
            '      - run: grep -n "uses:" .github/workflows/*.yml\n',
        ):
            with self.subTest(line=line.strip()):
                self.assertEqual([], unscannable_uses_lines(line))

    def test_an_uppercase_sha_is_the_same_identity(self):
        """A pin spelled in uppercase hex is the same commit. Rejecting it would
        SKIP the ref silently; treating it as a separate identity would split one
        action in two and hide a disagreement. Case-folded, so neither happens."""
        lower, upper = "a" * 40, "A" * 40
        self.assertEqual(
            _split_ref(f"actions/checkout@{upper}"),
            _split_ref(f"actions/checkout@{lower}"),
        )
        body = (
            f"      - uses: actions/checkout@{lower}  # v7.0.1\n"
            f"      - uses: actions/checkout@{upper}  # v6.0.0\n"
        )
        problems = label_problems(self._doc(body))
        self.assertTrue(any(p.startswith("A:") for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
