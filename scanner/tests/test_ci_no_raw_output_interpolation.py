"""
Regression guard: the hand-built JSON / HTML / URL output-assembly sink sites in
`scanner/lib` keep routing their tainted (env / filename / scanned-content)
values through an escaper — a future edit cannot silently reintroduce a RAW
interpolation at one of these sinks.

Background
----------
The 2026-07-27 escaping audit found several sinks that spliced a free-form value
straight into a structured output string, producing invalid — or structurally
injected — JSON / HTML / URL:

* `output.sh::print_json_summary` interpolated `$SCAN_DIR` raw into the
  `--format json` `"scan_directory"` field (#361).
* `datadog.sh::collect_datadog_dashboard_artifacts` interpolated `$dd_service` /
  `$dd_env` / `$dd_query` raw into the intake/query JSON payloads (#361) and the
  `ddtags=` URL query (#363).
* `output_prowler.sh::_prowler_dashboard_summary` interpolated the filename-
  derived `$label` raw into a `<td>` cell — stored XSS via a crafted OCSF
  filename (#362).

Each was fixed by routing the value through the right escaper first:
`_json_escape_str` (JSON), `_url_encode` (URL query value), or
`_prowler_html_escape` (HTML element text).

What this guard does (and does NOT do)
--------------------------------------
The per-sink shell tests (`test_output_functions.sh`,
`test_datadog_json_payloads.sh`, `test_prowler_dashboard_summary.sh`) already
mutation-verify the *behavior*. This guard is the complementary *source-level*
regression pin: for each sink file it asserts (against comment-stripped,
line-continuation-joined source)

1. the required escaper INVOCATION is present, and
2. the specific known RAW-interpolation string is ABSENT.

It is deliberately a narrow regression pin over the KNOWN sinks — not a general
"detect any new raw interpolation anywhere" static analyser, which would be
false-positive-prone (numeric fields, enums, already-escaped vars). A NEW sink
elsewhere is out of scope here; reverting one of these fixes trips the guard.

stdlib-only; no PyYAML, no `scanner/lib` import (so it never touches the 99%
`scanner/lib` coverage gate). Passes under pytest and `python3 -m unittest`.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import join_continuations, strip_comment_lines  # noqa: E402


# (relpath, [required escaper-usage substrings], [forbidden raw-interp substrings])
SINKS = [
    (
        "scanner/lib/output.sh",
        [
            '_json_escape_str "$SCAN_DIR"',
            '"scan_directory": "$scan_dir_esc"',
        ],
        [
            '"scan_directory": "$SCAN_DIR"',
        ],
    ),
    (
        "scanner/lib/datadog.sh",
        [
            '_json_escape_str "$dd_service"',
            '_url_encode "$dd_service"',
            '"service": "${dd_service_j}"',
            "service:${dd_service_u}",
        ],
        [
            # raw value in the intake JSON payload
            '"service": "${dd_service}"',
            # raw value in the ddtags URL query (post-#363 uses ${dd_service_u})
            "service:${dd_service},env:${dd_env}",
        ],
    ),
    (
        "scanner/lib/output_prowler.sh",
        [
            '_prowler_html_escape "$label"',
        ],
        [],
    ),
]


def _normalized_source(relpath):
    """Return the sink file's source with whole-line `#` comments removed and
    backslash line-continuations joined, so a substring match reflects real code
    (not a doc-comment example) and survives a value being wrapped across lines."""
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    return join_continuations(strip_comment_lines(text))


def _violations(source, required, forbidden):
    """List of human-readable violations for one sink's normalized source."""
    out = []
    for needle in required:
        if needle not in source:
            out.append(f"MISSING required escaper usage: {needle!r}")
    for needle in forbidden:
        if needle in source:
            out.append(f"PRESENT forbidden raw interpolation: {needle!r}")
    return out


class TestNoRawOutputInterpolation(unittest.TestCase):
    def test_sink_files_exist(self):
        for relpath, _req, _forb in SINKS:
            self.assertTrue(
                (REPO_ROOT / relpath).is_file(),
                f"sink file not found: {relpath}",
            )

    def test_escapers_pinned_at_each_sink(self):
        all_violations = {}
        for relpath, required, forbidden in SINKS:
            source = _normalized_source(relpath)
            v = _violations(source, required, forbidden)
            if v:
                all_violations[relpath] = v
        self.assertEqual(
            all_violations,
            {},
            "raw output-interpolation regression at one or more sinks:\n"
            + "\n".join(
                f"  {f}:\n    " + "\n    ".join(vs)
                for f, vs in sorted(all_violations.items())
            ),
        )

    def test_mutation_missing_escaper_is_detected(self):
        """Removing a required escaper usage must be reported as a violation."""
        relpath, required, forbidden = SINKS[0]
        source = _normalized_source(relpath)
        mutated = source.replace(required[0], "", 1)
        self.assertNotEqual(mutated, source, "mutation pattern not present in source")
        self.assertTrue(
            _violations(mutated, required, forbidden),
            "guard failed to detect a removed escaper usage",
        )

    def test_mutation_reintroduced_raw_interp_is_detected(self):
        """Reintroducing a forbidden raw interpolation must be reported."""
        relpath, required, forbidden = SINKS[1]  # datadog.sh has forbidden entries
        source = _normalized_source(relpath)
        injected = source + "\n" + forbidden[0] + "\n"
        self.assertTrue(
            _violations(injected, required, forbidden),
            "guard failed to detect a reintroduced raw interpolation",
        )


if __name__ == "__main__":
    unittest.main()
