#!/usr/bin/env python3
# Audit .github/workflows/*.yml for pull_request_target triggers and ensure
# every job in such workflows has a head.repo.full_name == github.repository
# fork-guard in its `if:` expression.
#
# pull_request_target runs with the upstream's write-scoped GITHUB_TOKEN even
# for fork PRs (OWASP A08 — Software & Data Integrity Failures). Without the
# guard, malicious fork-origin PRs can run privileged jobs.
#
# Exit code: 0 if all guarded, 1 if any unguarded job found.

from __future__ import annotations

import sys
from pathlib import Path

import yaml

GUARD_TOKEN = "head.repo.full_name == github.repository"
WORKFLOWS_DIR = Path(".github/workflows")


def has_guard(if_expr: str | None) -> bool:
    if not if_expr:
        return False
    normalized = " ".join(str(if_expr).split())
    return GUARD_TOKEN in normalized


def main() -> int:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml")) + sorted(WORKFLOWS_DIR.glob("*.yaml"))
    if not workflows:
        print(f"::error::No workflows found under {WORKFLOWS_DIR}")
        return 1

    failures: list[str] = []
    audited = 0

    for wf in workflows:
        with wf.open() as fh:
            try:
                doc = yaml.safe_load(fh)
            except yaml.YAMLError as exc:
                print(f"::error file={wf}::YAML parse error: {exc}")
                failures.append(str(wf))
                continue

        if not isinstance(doc, dict):
            continue
        triggers = doc.get(True) or doc.get("on")
        if not _has_pull_request_target(triggers):
            continue

        audited += 1
        jobs = doc.get("jobs") or {}
        if not isinstance(jobs, dict):
            print(f"::error file={wf}::workflow has no parseable jobs map")
            failures.append(str(wf))
            continue

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if has_guard(job.get("if")):
                continue
            failures.append(f"{wf}::{job_name}")
            print(
                f"::error file={wf}::job '{job_name}' is missing the fork-guard "
                f"`{GUARD_TOKEN}` in its top-level `if:` expression"
            )

    if audited == 0:
        print("No pull_request_target workflows found — audit passes by vacuity.")
        return 0

    if failures:
        print(
            f"\nFAIL: {len(failures)} unguarded job(s) across "
            f"{audited} pull_request_target workflow(s).",
            file=sys.stderr,
        )
        print(
            "Add `if: github.event.pull_request.head.repo.full_name == github.repository`",
            file=sys.stderr,
        )
        print(
            "(or merge it into the existing `if:` with `&&`) to each listed job.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {audited} pull_request_target workflow(s) audited, all jobs fork-guarded.")
    return 0


def _has_pull_request_target(triggers: object) -> bool:
    if triggers is None:
        return False
    if isinstance(triggers, str):
        return triggers == "pull_request_target"
    if isinstance(triggers, list):
        return "pull_request_target" in triggers
    if isinstance(triggers, dict):
        return "pull_request_target" in triggers
    return False


if __name__ == "__main__":
    sys.exit(main())
