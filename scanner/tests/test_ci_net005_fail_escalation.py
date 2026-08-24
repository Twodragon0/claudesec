"""
Regression guard: NET-005 must ESCALATE SSH-open-to-the-world to FAIL.

`scanner/checks/network/tls.sh` NET-005 flags an IaC ingress rule that exposes
SSH (port 22) to `0.0.0.0/0` as a CRITICAL FAIL. The inner detection pattern is
an ERE alternation passed to `files_contain` (which uses `grep -E`):

    (0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)

It previously used `\\|` for the alternation. Under `grep -E` (ERE) `\\|` is a
LITERAL pipe, not alternation, so the SSH-port-22 case never matched and NET-005
silently downgraded to a mere WARN ("Ingress rule allows 0.0.0.0/0"). Fixed in
PR #224; the behavioral RED/GREEN test lives in test_check_network_tls.sh.

This is the fast STATIC tripwire that complements that behavioral test: it fails
immediately if the alternation regresses to `\\|` or the FAIL escalation is
removed — even if someone also weakened the behavioral test.

stdlib-only, no network/subprocess. Passes under pytest and `python3 -m unittest`.
"""

import sys
import unittest
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
TLS_SH = REPO_ROOT / "scanner" / "checks" / "network" / "tls.sh"

# Shared comment-stripping primitive. Import as a top-level module so it resolves
# under both pytest and `python3 -m unittest`.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import strip_comment_lines, strip_inline_comment_sh  # noqa: E402


def net005_section(text: str) -> str:
    """The NET-005 block of `text` (from its `# NET-005` banner to the next
    `# NET-` banner or EOF) with `#` comment lines stripped.

    Stripping comments is load-bearing: a `fail "NET-005" ... "critical"`
    surviving only in a comment must NOT satisfy the escalation check while the
    active code has been silently downgraded to a mere WARN (ADR-001 §1; the same
    class as the `# exit 1` Security-Scan-Gate evasion, #271). BOTH whole-line
    (`strip_comment_lines`) AND trailing-inline SHELL (`strip_inline_comment_sh`)
    comments are removed — a `fail ... "critical"` riding a trailing comment on
    the active `warn` line is the same evasion, INCLUDING the bash
    command-separator form (`warn ...;#fail ... "critical"`) that a whitespace-only
    stripper misses. The banner search runs on the RAW lines (the delimiter IS a
    comment) before stripping."""
    lines = text.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if "NET-005" in ln and ln.lstrip().startswith("#")),
        None,
    )
    if start is None:
        return ""
    end = len(lines)
    for j in range(start + 1, len(lines)):
        s = lines[j].lstrip()
        if s.startswith("# NET-") and "NET-005" not in lines[j]:
            end = j
            break
    body = strip_comment_lines("\n".join(lines[start:end]))
    return "\n".join(strip_inline_comment_sh(ln) for ln in body.splitlines())


class TestNet005FailEscalation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = TLS_SH.read_text(encoding="utf-8") if TLS_SH.is_file() else ""
        cls.section = net005_section(cls.text)

    def test_tls_check_exists(self):
        self.assertTrue(TLS_SH.is_file(), f"{TLS_SH} not found")

    def test_net005_section_found(self):
        self.assertTrue(
            self.section,
            "NET-005 section not found in tls.sh — parsing assumption broke.",
        )

    def test_net005_escalates_to_critical_fail(self):
        self.assertRegex(
            self.section,
            r'fail\s+"NET-005"[^\n]*"critical"',
            'NET-005 no longer emits a CRITICAL `fail "NET-005" ... "critical"`. '
            "SSH open to 0.0.0.0/0 must escalate to FAIL, not WARN.",
        )

    def test_net005_uses_ere_alternation_not_literal_pipe(self):
        # The port-22 detection must use a real ERE alternation `(a|b)`.
        self.assertRegex(
            self.section,
            r"\(0\\\.0\\\.0\\\.0/0\.\*22\|port\.\*22\.\*0\\\.0\\\.0\\\.0/0\)",
            "NET-005's SSH-port-22 detection pattern changed shape. It must stay an "
            r"ERE alternation `(0\.0\.0\.0/0.*22|port.*22.*0\.0\.0\.0/0)`.",
        )
        # And it must NOT contain a backslash-pipe (the broken literal-pipe form
        # that disabled the match under grep -E).
        self.assertNotRegex(
            self.section,
            r"22\\\|port",
            r"NET-005 reintroduced a literal `\|` in its grep -E detection pattern "
            "(it means a LITERAL pipe in ERE, not alternation, and silently breaks "
            r"detection). Use `(a|b)` alternation instead.",
        )


class TestNet005SectionMutation(unittest.TestCase):
    """Mutation self-tests for the comment-stripping section builder (ADR-001 §4)."""

    # Active code downgraded to WARN, but the CRITICAL `fail` survives ONLY in a
    # `#` comment. A comment-blind section builder would satisfy the escalation
    # check here — the exact false-negative this guard must not have.
    _COMMENT_EVASION = "\n".join(
        [
            "# NET-005: Firewall rules (cloud/IaC)",
            "if files_contain \"*.tf\" '(0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)'; then",
            '  # historically: fail "NET-005" "SSH open to 0.0.0.0/0" "critical"',
            '  warn "NET-005" "Ingress rule allows 0.0.0.0/0 (including SSH)" "Review"',
            "fi",
            "# NET-006: next check",
        ]
    )

    _ACTIVE_FAIL = "\n".join(
        [
            "# NET-005: Firewall rules (cloud/IaC)",
            "if files_contain \"*.tf\" '(0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)'; then",
            '  fail "NET-005" "SSH open to 0.0.0.0/0" "critical"',
            "fi",
            "# NET-006: next check",
        ]
    )

    # Active code WARNs, but the CRITICAL `fail` rides a TRAILING inline comment
    # on the active `warn` line — `strip_comment_lines` (whole-line only) does not
    # touch it; `strip_inline_comment` must.
    _TRAILING_COMMENT_EVASION = "\n".join(
        [
            "# NET-005: Firewall rules (cloud/IaC)",
            "if files_contain \"*.tf\" '(0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)'; then",
            '  warn "NET-005" "Ingress rule allows 0.0.0.0/0" "Review"  '
            '# fail "NET-005" "SSH open to 0.0.0.0/0" "critical"',
            "fi",
            "# NET-006: next check",
        ]
    )

    _RX = r'fail\s+"NET-005"[^\n]*"critical"'

    def test_critical_fail_in_comment_does_not_satisfy_escalation(self):
        self.assertNotRegex(
            net005_section(self._COMMENT_EVASION), self._RX,
            "comment-evasion regression: a `# fail ... critical` comment satisfied "
            "the NET-005 escalation check while the active code only WARNs.",
        )

    # No space before `#`: bash treats `;#...` as a real comment. A
    # whitespace-only stripper misses it (ADR-001 §1, 3rd-pass finding).
    _METACHAR_COMMENT_EVASION = "\n".join(
        [
            "# NET-005: Firewall rules (cloud/IaC)",
            "if files_contain \"*.tf\" '(0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)'; then",
            '  warn "NET-005" "Ingress rule allows 0.0.0.0/0" "Review";'
            '#fail "NET-005" "SSH open to 0.0.0.0/0" "critical"',
            "fi",
            "# NET-006: next check",
        ]
    )

    def test_critical_fail_in_trailing_comment_does_not_satisfy_escalation(self):
        self.assertNotRegex(
            net005_section(self._TRAILING_COMMENT_EVASION), self._RX,
            "trailing-inline comment-evasion regression: a `warn ...  # fail ... "
            "critical` line satisfied the NET-005 escalation check.",
        )

    # `` `#... ` `` — a `#` right after an opening backtick is also a real bash
    # comment (4th-pass finding); the tail never runs.
    _BACKTICK_COMMENT_EVASION = "\n".join(
        [
            "# NET-005: Firewall rules (cloud/IaC)",
            "if files_contain \"*.tf\" '(0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)'; then",
            '  warn "NET-005" "Ingress rule allows 0.0.0.0/0" "Review"`'
            '#fail "NET-005" "SSH open to 0.0.0.0/0" "critical"`',
            "fi",
            "# NET-006: next check",
        ]
    )

    def test_critical_fail_in_metachar_comment_does_not_satisfy_escalation(self):
        self.assertNotRegex(
            net005_section(self._METACHAR_COMMENT_EVASION), self._RX,
            "metachar-adjacent comment-evasion regression: a `warn ...;#fail ... "
            "critical` line (real bash comment, no space) satisfied the escalation "
            "check.",
        )

    def test_critical_fail_in_backtick_comment_does_not_satisfy_escalation(self):
        self.assertNotRegex(
            net005_section(self._BACKTICK_COMMENT_EVASION), self._RX,
            "backtick comment-evasion regression: a `` warn ...`#fail ... critical` "
            "`` line satisfied the escalation check.",
        )

    # `$'\''` is one ANSI-C string (escaped literal quote), so the trailing
    # ` #fail ... critical` is a real bash comment — 5th-pass finding (ADR-001 §3).
    # A single-quote stripper with no escape awareness misses it (UNDER-strip).
    _ANSI_C_COMMENT_EVASION = "\n".join(
        [
            "# NET-005: Firewall rules (cloud/IaC)",
            "if files_contain \"*.tf\" '(0\\.0\\.0\\.0/0.*22|port.*22.*0\\.0\\.0\\.0/0)'; then",
            '  warn "NET-005" "Ingress rule allows 0.0.0.0/0" "Review" '
            + r"""$'\'' #fail "NET-005" "SSH open to 0.0.0.0/0" "critical" """.rstrip(),
            "fi",
            "# NET-006: next check",
        ]
    )

    def test_critical_fail_in_ansi_c_comment_does_not_satisfy_escalation(self):
        self.assertNotRegex(
            net005_section(self._ANSI_C_COMMENT_EVASION), self._RX,
            "ANSI-C comment-evasion regression: a `warn ... $'\\'' #fail ... "
            "critical` line (real bash comment) satisfied the escalation check.",
        )

    def test_active_critical_fail_is_recognized(self):
        self.assertRegex(
            net005_section(self._ACTIVE_FAIL), self._RX,
            "section builder dropped the real active `fail ... critical` — the "
            "positive control must still match.",
        )


if __name__ == "__main__":
    unittest.main()
