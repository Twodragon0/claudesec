"""
ClaudeSec — Prowler OCSF compliance-summary builder.

Extracted from the inline ``python3 -c "..."`` heredoc previously embedded in
``output_prowler.sh``'s ``_prowler_compliance_summary_json`` (see
scanner/lib/output_prowler.sh). The extraction exists purely for coverage
measurability: kcov instruments bash heredoc string content as if it were
executable bash, which it never is, so ~21 lines of unreachable "coverage"
polluted output_prowler.sh's kcov numbers. As a standalone module, real
coverage is enforced by pytest instead
(scanner/tests/test_prowler_compliance_summary.py).

Behavior is unchanged from the original heredoc: read every
``prowler-*.ocsf.json`` file in a directory, collect FAIL findings, and
return a compact JSON compliance summary via compliance-map.py (NIST SP
800-53 Rev5 / ISO 27001:2022 / KISA ISMS-P mappings — see
compliance-map.py). Malformed or unreadable files are tolerated per-file so
one bad Prowler output does not blank the whole summary (fail-safe defaults,
aligned with OWASP ASVS V1.1 / NIST SP 800-218 SSDF PW.7).
"""

import glob
import importlib.util
import json
import os
import sys


def _load_compliance_map():
    """Load the sibling compliance-map.py module.

    The filename has a hyphen, so a normal ``import`` statement cannot
    reference it; resolve it relative to this file's directory instead
    (same scanner/lib/ dir the module previously lived in as part of
    output.sh).
    """
    module_dir = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "compliance_map", os.path.join(module_dir, "compliance-map.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_findings(prowler_dir):
    """Collect FAIL findings from every prowler-*.ocsf.json file in prowler_dir.

    Each OCSF file may be a JSON array or newline-delimited JSON (NDJSON).
    A malformed or unreadable file is skipped rather than aborting the whole
    scan — one bad Prowler artifact should not blank the compliance summary.
    """
    findings = []
    for file_path in glob.glob(os.path.join(prowler_dir, "prowler-*.ocsf.json")):
        try:
            with open(file_path, encoding="utf-8") as fh:
                raw = fh.read().strip()
            data = (
                json.loads(raw)
                if raw.startswith("[")
                else [json.loads(line) for line in raw.splitlines() if line.strip()]
            )
            for item in data:
                if item.get("status_code") != "FAIL":
                    continue
                findings.append(
                    {
                        "check": item.get("metadata", {}).get("event_code", ""),
                        "title": item.get("finding_info", {}).get("title", ""),
                        "message": item.get("message", ""),
                        "compliance": item.get("unmapped", {}).get("compliance", {}),
                    }
                )
        except Exception:
            pass
    return findings


def build_summary(prowler_dir):
    """Return a compact JSON compliance-summary string for prowler_dir.

    Returns "" when there are no FAIL findings — no OCSF artifacts, only
    PASS findings, or every file was malformed.
    """
    findings = _read_findings(prowler_dir)
    if not findings:
        return ""
    compliance_map = _load_compliance_map()
    summary = compliance_map.compliance_summary(compliance_map.map_compliance(findings))
    return json.dumps(summary, separators=(",", ":"))


def main(argv=None):
    """CLI entry point: build_summary(argv[0]) and print it if non-empty.

    Called by output_prowler.sh's _prowler_compliance_summary_json as
    ``python3 prowler_compliance_summary.py <prowler_dir>``. Missing argv is
    handled gracefully (returns 0, prints nothing) so the calling bash
    (already wrapped in ``timeout ... || true``) never breaks.
    """
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        return 0
    result = build_summary(args[0])
    if result:
        print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
