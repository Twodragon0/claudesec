---
title: Coverage Ratchet Playbook
description: A four-phase template for driving coverage metrics from unobservable to CI-enforced floors, derived from the ClaudeSec bash coverage journey (2026-04-21/22)
tags: [ci, coverage, testing, devsecops]
---

# Coverage Ratchet Playbook

Use this playbook when a project has a coverage metric that is either invisible in CI, ungated, or stuck at a floor that has not been reviewed in months. The playbook moves through four sequential phases: make the metric visible, lift the baseline with real tests, enforce a gate, then iterate the floor upward. For a concrete example of every phase applied in practice, see [ci-coverage-journey.md](./ci-coverage-journey.md).

## When to use

- The CI job that reports coverage uses `continue-on-error: true` or equivalent soft-failure mode.
- Coverage numbers appear in some runs but not others, or differ between local and CI environments.
- No enforcement step exists: the metric is reported but never fails the build.
- The coverage floor has not changed in more than one release cycle.
- A measurement tool was recently upgraded and output paths may have changed.

## Phase 1 -- Discovery (make the metric CI-visible)

Make the measurement pipeline produce a reliable, human-readable number in CI logs before doing anything else.

- Audit the CI job that runs coverage measurement. If the job carries a soft-failure flag, treat that as a red flag: the job may be silently erroring and producing no number at all.
- Run the CI job on a branch and confirm a log line of the form `<metric>: <N>%` appears in the output. If it does not appear, the rest of the playbook cannot proceed.
- When a measurement tool has been recently upgraded, verify its output directory layout. Tools sometimes change where they write merged results across major versions. Prefer dynamic path discovery (for example, `find`) over hard-coded paths when the tool's output structure may vary.
- Leave the soft-failure flag in place until the number is reliably observable across at least two consecutive main-branch runs.

Exit criterion: a CI log line of the form `<metric>: <N>%` appears on at least two consecutive main-branch runs.

## Phase 2 -- Fixture tests (lift the baseline with observable test work)

Add targeted tests to raise the baseline before any gate is introduced.

- Identify functions or modules with low or zero coverage. Prefer candidates that are pure, deterministic, and free of network or process-spawning dependencies -- they are fastest to test and least likely to introduce flakiness.
- Write fixture-based tests. Use temporary directories created and cleaned up within the test itself. Aim for at least ten distinct assertions per test file so each file contributes meaningfully to coverage.
- Write one test file per target module or function. Follow the existing test-file naming and style conventions in the repository.
- Verify each test file runs to completion locally in isolation before pushing.
- After merging, confirm the baseline has risen and is stable.

Exit criterion: the observed baseline has risen by at least 3 percentage points (recommended default) and that rise is stable across two consecutive main-branch runs.

## Phase 3 -- Gate (enforce against the observed baseline)

Introduce a hard failure so that coverage regressions block merges.

- Remove the soft-failure flag from the measurement job.
- Add an enforcement step that parses the reported metric value and exits with a non-zero code if the value is below a threshold. Do not rely on the measurement tool's own exit code -- parse the number explicitly.
- Set the initial threshold approximately 20 percentage points below the observed baseline (recommended default). This conservative gap gives headroom for measurement variance and avoids immediately blocking unrelated PRs.
- Add the enforcement job to any aggregate required-status gate (for example, a "CI must pass" job in branch protection).
- Validate the enforcement logic locally with three cases before merging: a value at the threshold (should pass), a value just below the threshold (should fail), and a missing or malformed report file (should fail).

Exit criterion: the enforcement job is listed as required on the main branch and passes on the first post-merge run.

## Phase 4 -- Ratchet (iterate the floor upward)

Incrementally raise the floor toward the observed baseline in small, safe steps.

- Change only the threshold value in each ratchet PR. Do not combine a threshold change with test additions, refactors, or unrelated CI changes.
- Before merging a ratchet PR, confirm that the current observed coverage is at least 5 percentage points above the proposed new floor (recommended default). This gap is the safety buffer against measurement noise.
- Wait for at least two consecutive clean main-branch runs at the new floor before opening the next ratchet PR (recommended default).
- If a ratchet PR merges and then fails on the next main-branch run, revert the threshold change immediately. Do not patch forward by adding tests within the same ratchet step; complete the revert, investigate the variance, and then decide whether to re-open the ratchet or run another Phase 2 cycle first.

Exit criterion: the floor is within 4 percentage points of the observed baseline, or the team has decided to stop ratcheting and document the current floor as the maintained target.

## Stop conditions

Do not continue ratcheting when any of the following is true:

- The proposed new floor would be less than 4 percentage points below the current observed baseline (recommended default). Closing that gap requires new tests, not a threshold change alone.
- The observed baseline has been unstable (varying by more than 2 percentage points) across recent main-branch runs. Stabilize the measurement first.
- The last ratchet step required a revert. Investigate and resolve the root cause before resuming.
- Coverage gains are coming from trivial or generated code rather than logic paths that matter for correctness or security.

## Anti-patterns

- Enforcing before observing: adding a gate before Phase 1 is complete means the gate may fail for measurement reasons unrelated to actual coverage.
- Ratcheting on a single run: one passing run is not a stable baseline. Noise in coverage measurement can make a threshold appear safe when it is not.
- Bundling multiple threshold changes in one PR: if the PR needs to be reverted, the revert is harder to scope and may discard unrelated work.
- Setting the initial gate too close to the baseline: a gate that fails on the next unrelated PR will be disabled or soft-failed by the team, reversing all Phase 3 progress.
- Mixing test additions with threshold changes: combining both in one PR makes it impossible to revert only the threshold change cleanly.
- Treating coverage percentage as a quality proxy without reviewing which lines are covered: a high percentage built on trivial assertions does not reduce defect risk.

## Related

- [ci-coverage-journey.md](./ci-coverage-journey.md) — concrete example of all four phases applied to a bash coverage campaign
