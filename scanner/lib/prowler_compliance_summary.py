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


def _provider_of(file_path):
    """`.../prowler-aws.ocsf.json` -> `aws`, with k8s variants merged.

    Mirrors `dashboard_data_loader._normalize_provider` so a provider-scoped
    compliance source (800-171 is AWS-only) sees the same slugs on both the
    dashboard path and this one.
    """
    name = os.path.basename(file_path)
    name = name[len("prowler-"):] if name.startswith("prowler-") else name
    name = name.split(".ocsf.json")[0]
    if name.startswith("k8s") or name.startswith("kubernetes") or "eks" in name:
        return "kubernetes"
    return name


def _read_findings(prowler_dir):
    """Collect FAIL findings from every prowler-*.ocsf.json file in prowler_dir.

    Each OCSF file may be a JSON array or newline-delimited JSON (NDJSON).
    A malformed or unreadable file is skipped rather than aborting the whole
    scan — one bad Prowler artifact should not blank the compliance summary.

    Returns `(findings, providers)`. `providers` is every provider that produced
    a readable artifact, including ones with zero FAIL findings: a clean
    provider is invisible in the findings list, and a provider-scoped native
    mapping must be able to tell "clean" from "not scanned".
    """
    findings = []
    providers = set()
    for file_path in glob.glob(os.path.join(prowler_dir, "prowler-*.ocsf.json")):
        try:
            with open(file_path, encoding="utf-8") as fh:
                raw = fh.read().strip()
            data = (
                json.loads(raw)
                if raw.startswith("[")
                else [json.loads(line) for line in raw.splitlines() if line.strip()]
            )
            provider = _provider_of(file_path)
            providers.add(provider)
            for item in data:
                if item.get("status_code") != "FAIL":
                    continue
                findings.append(
                    {
                        "check": item.get("metadata", {}).get("event_code", ""),
                        "title": item.get("finding_info", {}).get("title", ""),
                        "message": item.get("message", ""),
                        "compliance": item.get("unmapped", {}).get("compliance", {}),
                        "provider": provider,
                    }
                )
        except Exception:
            pass
    return findings, providers


def build_summary(prowler_dir):
    """Return a compact JSON compliance-summary string for prowler_dir.

    Returns "" when there are no FAIL findings — no OCSF artifacts, only
    PASS findings, or every file was malformed.
    """
    findings, providers = _read_findings(prowler_dir)
    if not findings:
        return ""
    compliance_map = _load_compliance_map()
    summary = compliance_map.compliance_summary(
        compliance_map.map_compliance(findings, scanned_providers=providers)
    )
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
