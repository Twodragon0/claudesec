#!/usr/bin/env python3
"""Run the CI config regression guards and print the count ONLY if they passed.

WHY THIS FILE EXISTS
--------------------
`ci-guards` used to run the suite straight from its `run:` body:

    cd scanner/tests
    out=$(python3 -m unittest discover -s . -p 'test_ci_*.py' 2>&1) || { ...; exit 1; }
    printf '%s\\n' "$out" | grep -qE '^Ran [1-9][0-9]* tests? in '
    printf '%s\\n' "$out" | grep -qE '^OK( |$)'
    ran=$(... sed ... "$out" ...)

Three separate adversarial passes defeated successive versions of that. The last
one found the shape the others shared: **the proof was derived from a blob whose
SCOPE and VERDICT are both decided inside the same blob.** Measured, each on the
real body, each with every static guard returning `[]`:

    cd /tmp/decoy (one trivial test file)   exit 0, published ran=1,  0 real guards ran
    `-k '*bucket*'` appended to discover    exit 0, published ran=18, 18 of 1264 ran
    red suite whose output has an `OK ` line
      + the `|| { exit 1; }` branch neutered  exit 0, published ran=2, suite FAILED

None of those forges anything. The count is REAL — the `cd` target, everything
after `-p`, and the presence of a column-0 `OK` line were simply never pinned,
and `2>&1` hands a failing run the ability to put `OK` in its own output.

WHAT THIS FIXES, AND HOW
------------------------
Each of the three unpinned things moves out of shell text into code that is
itself a tracked, reviewed, guard-covered file:

  SCOPE    the discovery root is computed from `__file__`, so `cd` cannot
           redirect it. Running this script from any directory scans the same
           tree.
  FILTER   it takes NO arguments and hard-fails when given any, so there is no
           `-k` to append.
  VERDICT  the exit status and the printed count come from
           `TestResult.wasSuccessful()`, a structural property of the run — not
           from grepping text the run itself produced.

NOT A CLAIM OF CLOSURE. This file is editable like any other. What it buys is
that weakening the proof now means editing a tracked Python file under
`scanner/tests/`, which is inside the `ci_config` path bucket and inside the
guard suite's own `git ls-files` sweeps — a reviewable diff rather than an
argument appended to a shell line. The regress still terminates outside the
workflow: branch protection requiring `Lint`, and GitHub evaluating `needs:`.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

#: Guard modules live beside this file. Derived from `__file__` ON PURPOSE — the
#: whole point is that the working directory cannot redirect the scan.
GUARD_DIR = Path(__file__).resolve().parent
PATTERN = "test_ci_*.py"


def main(argv: list) -> int:
    # NO ARGUMENTS. `-k '*bucket*'` appended to the old shell invocation cut the
    # run from 1264 tests to 18 while every check still passed, so accepting
    # arguments at all is the hole. Refusing them is one line.
    if argv:
        print(
            f"{Path(__file__).name} takes no arguments, got {argv!r}. It runs "
            "the whole guard suite by design; a filter would narrow what the "
            "job proves while leaving the count it publishes genuine.",
            file=sys.stderr,
        )
        return 2

    files = sorted(GUARD_DIR.glob(PATTERN))
    if not files:
        print(
            f"no {PATTERN} under {GUARD_DIR} — the suite would pass vacuously "
            "(`unittest` exits 0 on 'Ran 0 tests')",
            file=sys.stderr,
        )
        return 2

    # DISCOVERED ONE FILE AT A TIME, and the union is what runs. `discover` is
    # given the resolved directory as BOTH start and top level so it does not
    # walk upward looking for a package root; the pattern is the file's own name.
    #
    # WHY PER FILE, AND WHY BY CONSTRUCTION
    # -------------------------------------
    # A `testsRun < len(files)` floor was walked through by two lines in any
    # guard module —
    #
    #     def load_tests(loader, tests, pattern):
    #         return unittest.TestSuite()
    #
    # — which make `discover` collect NOTHING from it while the file still
    # exists, is still tracked, still matches `PATTERN`, and so still counts in
    # `len(files)`. Measured: 1262 tests became 1251 with the whole suite at
    # `OK` and the published count genuine. `load_tests` is a documented
    # `unittest` hook, so that is a supported way for a module to leave the run.
    # Invisible from the other side too — pytest does not honour `load_tests`,
    # so the same file gave `Ran 0 tests / NO TESTS RAN` under `unittest` and
    # `11 passed` under pytest, and `scanner-unit-tests` is gated on the
    # `scanner` bucket, which the PRs this job exists for do not match.
    #
    # The FIRST attempt at a per-file check walked the aggregate suite and read
    # `type(test).__module__`. That is attribution by ATTRIBUTE, and the
    # attribute is writable: one line, `C.__module__ = "test_ci_<victim>"`, lets
    # a class defined anywhere claim any guard file's stem (measured directly
    # against the old helper). Discovering each file separately makes the
    # attribution structural — a sub-suite comes from the file it was discovered
    # in, whatever its classes claim about themselves.
    #
    # Checked BEFORE the run, so the verdict does not depend on what the run
    # reports.
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    silent = []
    for path in files:
        one = loader.discover(
            start_dir=str(GUARD_DIR), pattern=path.name, top_level_dir=str(GUARD_DIR)
        )
        if one.countTestCases() == 0:
            silent.append(path.name)
        suite.addTest(one)
    if silent:
        print(
            f"{len(silent)} guard file(s) contributed NO tests, so the run was "
            f"narrowed while the count stayed genuine: {silent}",
            file=sys.stderr,
        )
        return 1
    # Everything human-readable goes to stderr; stdout carries the count and
    # nothing else, so the caller's `$( )` cannot pick up stray text.
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1).run(suite)

    if not result.wasSuccessful():
        print(
            f"guard suite FAILED: {len(result.failures)} failure(s), "
            f"{len(result.errors)} error(s) out of {result.testsRun} test(s)",
            file=sys.stderr,
        )
        return 1
    # `ran=<count>`, not a bare count. The caller appends this straight to
    # `$GITHUB_OUTPUT`, so no shell variable ever holds the value — see the
    # step body for the measured reason.
    print(f"ran={result.testsRun}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
