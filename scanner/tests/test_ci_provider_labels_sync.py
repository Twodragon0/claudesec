"""
Parity guard: Prowler provider label maps have a single source of truth.

Background
----------
The provider slug → human-readable label mapping was historically duplicated as
inline dict literals across four Python modules and a bash ``case`` statement,
and it had drifted (one Python copy was missing six providers, and the
kubernetes label differed between copies). The refactor consolidated the Python
side into ``scanner/lib/dashboard_providers.py`` (the canonical source) and left
the bash ``case`` in ``scanner/lib/output.sh`` in place for performance (it runs
in a loop; spawning python per call would be wasteful).

This test keeps the bash mirror honest and asserts the shared Python constants
are complete, so a future edit that drifts either side is caught at lint-time.

Invariants asserted
--------------------
1. The bash ``case`` in output.sh
   (``_prowler_dashboard_summary_provider_label``) has EXACTLY the same
   slug→label pairs as ``PROVIDER_LABELS`` — no missing, extra, or changed
   entries.
2. The shared Python constants are non-empty and internally consistent:
   - ``PROVIDER_LABELS`` has 16 entries.
   - ``PROVIDER_LABELS_SHORT`` == ``PROVIDER_LABELS`` except ``kubernetes`` is
     "K8s" (the intentional compact-table distinction).
   - ``PROVIDER_SUBTAB_MAP`` has 7 keys, all present in ``PROVIDER_LABELS``.
   - ``PROWLER_SELECTABLE_ORDER`` has 7 keys, all present in
     ``PROVIDER_LABELS``, and preserves the historical selector order.

stdlib-only: no PyYAML, no third-party deps. Runs under pytest (CI) and
``python3 -m unittest``. No network, no subprocess.
"""

import os
import re
import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
# The bash provider-label `case` was split out of output.sh into output_prowler.sh
# (still sourced by output.sh); the parity guard follows it there.
OUTPUT_SH = REPO_ROOT / "scanner" / "lib" / "output_prowler.sh"

# Load the canonical Python source (dashboard_providers.py lives in scanner/lib).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from dashboard_providers import (  # noqa: E402
    PROVIDER_LABELS,
    PROVIDER_LABELS_SHORT,
    PROVIDER_SUBTAB_MAP,
    PROWLER_SELECTABLE_ORDER,
)

# The bash function that mirrors PROVIDER_LABELS.
_FUNC_RE = re.compile(
    r"_prowler_dashboard_summary_provider_label\(\)\s*\{(.*?)\}",
    re.DOTALL,
)
# A single case arm:  aws) echo "AWS" ;;
# Excludes the default arm (`*) echo "$1" ;;`) which is the fallthrough.
_ARM_RE = re.compile(r'^\s*([a-z0-9]+)\)\s*echo\s+"([^"]*)"\s*;;', re.MULTILINE)


def _parse_bash_case(text: str) -> dict:
    """Extract slug→label pairs from the output.sh provider-label bash case."""
    m = _FUNC_RE.search(text)
    if not m:
        return {}
    body = m.group(1)
    pairs = {}
    for slug, label in _ARM_RE.findall(body):
        pairs[slug] = label
    return pairs


class TestProviderLabelsBashParity(unittest.TestCase):
    """The bash case in output.sh must match PROVIDER_LABELS exactly."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = OUTPUT_SH.read_text(encoding="utf-8") if OUTPUT_SH.is_file() else ""
        cls.bash_labels = _parse_bash_case(cls.text)

    def test_output_sh_exists(self) -> None:
        self.assertTrue(
            OUTPUT_SH.is_file(),
            f"output.sh not found at {OUTPUT_SH} — path assumption broke",
        )

    def test_bash_case_parsed(self) -> None:
        """The parser must find the case arms — an empty result means the
        function was renamed/restructured and this guard needs updating."""
        self.assertGreater(
            len(self.bash_labels),
            0,
            "Could not parse any provider-label case arms from output.sh — the "
            "_prowler_dashboard_summary_provider_label function structure "
            "changed and this parity guard needs to be updated.",
        )

    def test_bash_case_matches_python_source(self) -> None:
        """The bash mirror must have exactly the same slug→label pairs as the
        canonical PROVIDER_LABELS. This is the drift guard."""
        self.assertEqual(
            self.bash_labels,
            dict(PROVIDER_LABELS),
            "output.sh bash provider-label case has drifted from the canonical "
            "PROVIDER_LABELS in dashboard_providers.py. Update output.sh to "
            "match (they are a deliberate perf mirror, not two sources).",
        )


class TestProviderLabelsConstants(unittest.TestCase):
    """The shared Python constants must be complete and internally consistent."""

    def test_provider_labels_has_16_entries(self) -> None:
        self.assertEqual(len(PROVIDER_LABELS), 16)

    def test_kubernetes_full_label(self) -> None:
        self.assertEqual(PROVIDER_LABELS["kubernetes"], "Kubernetes")

    def test_short_differs_only_by_kubernetes(self) -> None:
        self.assertEqual(PROVIDER_LABELS_SHORT["kubernetes"], "K8s")
        # Every other key must be identical to the full map.
        for key, label in PROVIDER_LABELS.items():
            if key == "kubernetes":
                continue
            self.assertEqual(
                PROVIDER_LABELS_SHORT[key],
                label,
                f"PROVIDER_LABELS_SHORT[{key!r}] diverges from PROVIDER_LABELS "
                "for a non-kubernetes key — only kubernetes may differ.",
            )
        self.assertEqual(
            set(PROVIDER_LABELS_SHORT), set(PROVIDER_LABELS),
            "PROVIDER_LABELS_SHORT must have the same key set as PROVIDER_LABELS.",
        )

    def test_subtab_map_has_7_keys_all_known(self) -> None:
        self.assertEqual(len(PROVIDER_SUBTAB_MAP), 7)
        for key in PROVIDER_SUBTAB_MAP:
            self.assertIn(
                key, PROVIDER_LABELS,
                f"PROVIDER_SUBTAB_MAP key {key!r} is not a known provider.",
            )

    def test_selectable_order_has_7_keys_all_known(self) -> None:
        self.assertEqual(len(PROWLER_SELECTABLE_ORDER), 7)
        self.assertEqual(
            len(set(PROWLER_SELECTABLE_ORDER)), 7,
            "PROWLER_SELECTABLE_ORDER has duplicate keys.",
        )
        for key in PROWLER_SELECTABLE_ORDER:
            self.assertIn(
                key, PROVIDER_LABELS,
                f"PROWLER_SELECTABLE_ORDER key {key!r} is not a known provider.",
            )

    def test_selectable_order_preserved(self) -> None:
        """The selector display order is significant and must not change."""
        self.assertEqual(
            PROWLER_SELECTABLE_ORDER,
            ["aws", "gcp", "googleworkspace", "kubernetes", "azure", "m365", "iac"],
        )


class TestBashCaseParserSelfTest(unittest.TestCase):
    """Mutation-style self-test: the parser must catch a drifted bash case."""

    _GOOD = """\
_prowler_dashboard_summary_provider_label() {
  case "$1" in
    aws) echo "AWS" ;;
    kubernetes) echo "Kubernetes" ;;
    *) echo "$1" ;;
  esac
}
"""
    _DRIFTED = """\
_prowler_dashboard_summary_provider_label() {
  case "$1" in
    aws) echo "AWS" ;;
    kubernetes) echo "K8s" ;;
    *) echo "$1" ;;
  esac
}
"""

    def test_parser_ignores_default_arm(self) -> None:
        parsed = _parse_bash_case(self._GOOD)
        self.assertEqual(parsed, {"aws": "AWS", "kubernetes": "Kubernetes"})

    def test_parser_detects_drift(self) -> None:
        good = _parse_bash_case(self._GOOD)
        drifted = _parse_bash_case(self._DRIFTED)
        self.assertNotEqual(
            good, drifted,
            "Parser failed to distinguish a drifted kubernetes label — the "
            "parity guard would silently pass on real drift.",
        )


if __name__ == "__main__":
    unittest.main()
