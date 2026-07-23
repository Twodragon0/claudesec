#!/usr/bin/env python3
"""
ClaudeSec — findings-JSON builder for the dashboard's scan-report.json.

Extracted from the inline bash string-concatenation previously embedded in
scanner/lib/output.sh's ``_emit_finding_json`` (see that file's
``generate_html_dashboard``). The bash version only escaped double-quotes,
so a finding ``details``/``remediation``/``location`` value containing a
literal backslash (e.g. a Windows path like ``C:\\temp``) produced invalid
JSON. Using ``json.dumps`` here handles backslashes, quotes, control
characters, and Unicode correctly, matching the extraction pattern already
used for ``prowler_compliance_summary.py`` (kcov cannot usefully measure
coverage of logic embedded in a bash heredoc/subshell, so real coverage is
enforced by pytest instead — see
scanner/tests/test_findings_json_pure.py).

Input contract (stdin): a NUL (``\\0``)-delimited stream of finding
records. Within each record, fields are Unit-Separator (``\\x1f``)-delimited
in this fixed order::

    severity_label, id, title, remediation, details, category, location

This mirrors the ``\\x1f``-packed ``FINDINGS_*`` array entries built by
``fail()``/``warn()`` in output.sh (severity_label, id, title, and category
are supplied separately by the bash caller; category is computed via the
single-source-of-truth ``_finding_id_to_category``).
"""

import json
import sys

_NUM_FIELDS = 7  # severity_label, id, title, remediation, details, category, location


def build_findings_json(records):
    """Return a compact JSON array string for an iterable of finding records.

    Each record is a 7-item sequence in the fixed order documented above.
    Key order in the emitted dict matches the pre-refactor schema exactly:
    id, title, severity, category, then details/remediation/location, each
    omitted when empty.
    """
    items = []
    for severity_label, finding_id, title, remediation, details, category, location in records:
        item = {
            "id": finding_id,
            "title": title,
            "severity": severity_label,
            "category": category,
        }
        if details:
            item["details"] = details
        if remediation:
            item["remediation"] = remediation
        if location:
            item["location"] = location
        items.append(item)
    return json.dumps(items, ensure_ascii=False, separators=(",", ":"))


def _iter_records(raw):
    """Yield 7-tuples parsed from a NUL-delimited, \\x1f-separated blob.

    A trailing NUL (the terminator of the last record) produces one empty
    trailing chunk after splitting on "\\0"; that chunk is skipped.
    """
    if not raw:
        return
    for chunk in raw.split("\0"):
        if chunk == "":
            continue
        fields = chunk.split("\x1f")
        if len(fields) != _NUM_FIELDS:
            raise ValueError(
                f"expected {_NUM_FIELDS} \\x1f-delimited fields, got {len(fields)}: {fields!r}"
            )
        yield tuple(fields)


def main():
    """CLI entry point: read NUL-delimited records from stdin, print the JSON array.

    Called by output.sh's generate_html_dashboard as
    ``python3 findings_json.py`` with the record stream piped in. Missing/
    empty stdin yields ``[]``, matching the pre-refactor empty-findings
    behavior. Takes no CLI arguments — the module is entirely stdin-driven.
    """
    raw = sys.stdin.read()
    records = list(_iter_records(raw))
    print(build_findings_json(records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
