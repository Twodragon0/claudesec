#!/usr/bin/env python3
"""Run the renderer-adjudicated guard classes; print how many were adjudicated.

Sibling of `_ci_guard_runner.py`, for the same measured reason: the previous
version of `renderer-canary` decided its own SCOPE and VERDICT inside a shell
loop that parsed `unittest -v` text, and text the run produces is text a failing
run can shape. A red class whose output happened to contain a column-0 `OK` line
satisfied the shell's `grep -qE '^OK( |$)'` check once the `|| { exit 1; }`
branch was weakened — measured, published a genuine count with the suite red.

Here the verdict is `TestResult.wasSuccessful()` and the per-adjudicator check is
`TestResult` bookkeeping, not a regex over `... ok` lines. That also removes the
reason the old step had to pass `descriptions=False`: nothing parses the runner's
prose any more.

SPEC LIVES HERE, ONCE. `test_ci_guard_self_verify.CANARY_CLASSES` is pinned
equal to `ADJUDICATORS` by a guard test, so the two cannot drift — this repo has
already paid for a drifted second copy of a constant more than once.

Takes no arguments, for the same reason the sibling does not: an appended filter
narrows what the job proves while leaving the count it publishes genuine.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

GUARD_DIR = Path(__file__).resolve().parent

#: (class dotted path, the ONE method in it that adjudicates real repository
#: content against the renderer). A count alone cannot tell that this specific
#: method ran: parking it left its class at two synthetic-fixture tests, "Ran 3
#: tests / OK", exit 0, and the measured residual payload live in the catalog.
ADJUDICATORS = (
    (
        "test_ci_catalog_doc_sync.TestTheDocAgreesWithTheRenderer",
        "test_the_reduction_and_the_renderer_agree_on_the_real_catalog",
    ),
    (
        "test_ci_adr_decision_numbering.TestTheParseAgreesWithCommonMark",
        "test_the_parse_matches_the_renderer_on_every_stripper_case",
    ),
    (
        "test_ci_markdown_scan_evasion.TestTheResidualIsBounded",
        "test_silent_passes_stay_within_the_measured_ceiling",
    ),
)

#: The renderer oracle these classes adjudicate against. They SKIP on
#: ImportError, which is correct in the package-free job and is exactly the
#: fail-open this runner exists to close, so a missing or wrong version is a
#: hard failure here rather than a skip.
ORACLE_VERSION = "4.0.0"


def _oracle_problem() -> str | None:
    try:
        import markdown_it
    except ImportError as exc:  # pragma: no cover - exercised in CI only
        return f"markdown-it-py is not importable ({exc})"
    got = getattr(markdown_it, "__version__", None)
    if got != ORACLE_VERSION:
        return (
            f"markdown-it-py is {got}, not the adjudicated {ORACLE_VERSION} — "
            "re-measure before repinning"
        )
    return None


def main(argv: list) -> int:
    if argv:
        print(
            f"{Path(__file__).name} takes no arguments, got {argv!r}.",
            file=sys.stderr,
        )
        return 2

    problem = _oracle_problem()
    if problem:
        print(f"::error::{problem}", file=sys.stderr)
        return 2

    sys.path.insert(0, str(GUARD_DIR))
    adjudicated = 0
    for cls, method in ADJUDICATORS:
        name = f"{cls}.{method}"
        try:
            suite = unittest.defaultTestLoader.loadTestsFromName(name)
        except Exception as exc:
            print(
                f"::error::{name} could not be loaded ({exc}) — the "
                "adjudicating test is gone or renamed",
                file=sys.stderr,
            )
            return 1
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)
        # A SKIP is not a pass. `unittest` counts a skipped test in `Ran N` and
        # exits 0, which is why a count-based check could never see one.
        if result.skipped:
            print(
                f"::error::{name} SKIPPED in the job that exists to run it: "
                f"{result.skipped[0][1].strip()}",
                file=sys.stderr,
            )
            return 1
        if result.testsRun != 1 or not result.wasSuccessful():
            print(
                f"::error::{name} did not run and pass "
                f"(ran={result.testsRun}, ok={result.wasSuccessful()})",
                file=sys.stderr,
            )
            return 1
        adjudicated += 1

    if adjudicated != len(ADJUDICATORS):  # pragma: no cover - defensive
        print(f"::error::adjudicated {adjudicated} of {len(ADJUDICATORS)}",
              file=sys.stderr)
        return 1
    # `ran=<count>` — see the sibling runner.
    print(f"ran={adjudicated}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
