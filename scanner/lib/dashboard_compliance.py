"""
dashboard_compliance.py — Compliance-framework mapping data and helpers.

Extracted from dashboard_mapping.py to keep that module under the 800-line
cap (coding-style rule). Re-exported by dashboard_mapping for backward
compatibility; importers may use either path.

Public names: COMPLIANCE_FRAMEWORKS, COMPLIANCE_CONTROL_MAP,
_match_prowler_compliance, map_compliance.

The compliance control map itself is defined once, in compliance-map.py (the
single source of truth, also loaded directly by output.sh). This module imports
it rather than duplicating it. If that import fails we raise RuntimeError — a
previous inline fallback copy drifted badly out of sync (missing whole
frameworks and controls), so serving a stale duplicate silently is a
correctness hazard, not resilience. Fail loud instead.

Frameworks anchor on ISO 27001:2022, NIST CSF, and CIS Controls v8.
"""

import os

# ── Compliance Frameworks ────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = [
    {
        "name": "OWASP Top 10:2025",
        "url": "https://owasp.org/Top10/2025/",
        "desc": "Web application security risks Top 10 (2025)",
    },
    {
        "name": "OWASP LLM Top 10",
        "url": "https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/",
        "desc": "LLM application security risks Top 10 (2025)",
    },
    {
        "name": "NIST 800-53 Rev5",
        "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "desc": "US federal information system security controls",
    },
    {
        "name": "NIST CSF 2.0",
        "url": "https://www.nist.gov/cyberframework",
        "desc": "Cybersecurity Framework 2.0",
    },
    {
        "name": "ISO 27001:2022",
        "url": "https://www.iso.org/isoiec-27001-information-security.html",
        "desc": "Information security management system (ISMS) international standard",
    },
    {
        "name": "ISO 27701:2025",
        "url": "https://www.iso.org/standard/85819.html",
        "desc": "Privacy information management (PIMS) — certifiable",
    },
    {
        "name": "PCI-DSS v4.0.1",
        "url": "https://www.pcisecuritystandards.org/document_library/?category=pcidss",
        "desc": "Payment Card Industry Data Security Standard",
    },
    {
        "name": "KISA ISMS-P",
        "url": "https://isms.kisa.or.kr/main/ispims/intro/",
        "desc": "Korea information security and privacy management certification",
    },
    {
        "name": "CIS Benchmarks",
        "url": "https://www.cisecurity.org/cis-benchmarks",
        "desc": "Center for Internet Security benchmarks",
    },
    {
        "name": "SLSA v1.0",
        "url": "https://slsa.dev/spec/v1.0/",
        "desc": "Supply chain Levels for Software Artifacts",
    },
    {
        "name": "MITRE ATT&CK",
        "url": "https://attack.mitre.org/",
        "desc": "Cyber attack tactics, techniques, and procedures (TTP) knowledge base",
    },
]

# ── Compliance control map (single source of truth: compliance-map.py) ────────
#
# compliance-map.py is loaded once here and re-exported. There is intentionally
# no inline fallback copy: a stale duplicate is worse than a loud failure, so a
# load error is fatal.
import importlib.util as _ilu

try:
    _cm_spec = _ilu.spec_from_file_location(
        "compliance_map",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "compliance-map.py"),
    )
    if not (_cm_spec and _cm_spec.loader):
        raise ImportError("could not build a module spec with a loader for compliance-map.py")
    _cm_mod = _ilu.module_from_spec(_cm_spec)
    _cm_spec.loader.exec_module(_cm_mod)
except Exception as e:
    raise RuntimeError(f"compliance-map.py load failed: {e}") from e

COMPLIANCE_CONTROL_MAP = _cm_mod.COMPLIANCE_CONTROL_MAP
_match_prowler_compliance = _cm_mod._match_prowler_compliance
map_compliance = _cm_mod.map_compliance
