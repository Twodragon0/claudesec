"""
ClaudeSec — load Prowler's own compliance requirement→check mapping.

WHY
---
`COMPLIANCE_CONTROL_MAP` assigns a finding to a control by substring-matching
keywords against the finding's text. Prowler assigns checks to requirements by
INTENT, in data it ships. Those are different functions, and measurement showed
how different: on the 16 KISA ISMS-P controls where both have an opinion, the
keyword lists reproduce 41.5% of Prowler's mapping — with `2.9.4` (백업·복구)
scoring 0 of 58 despite listing `backup`, `snapshot` and `restore`, because
Prowler's backup checks do not contain those literal substrings.

Every miss rate and every false positive found in this file's history is a
symptom of that approximation: `sso` inside "associated", `sast` inside
"disaster", `change` at 97.5% wrong. Exact check-id membership has nothing to
approximate.

WHAT THIS IS NOT
----------------
A replacement. Prowler's mapping is SPARSE: its KISA file carries 101
requirements, only 26 of which map to any check at all — governance and process
requirements a scanner cannot evidence. Of the repo's 42 KISA controls, 16 have
native checks and 26 do not. Those 26 keep the keyword path, which is why
`map_compliance()` treats this as a preferred source rather than the only one.

Prowler is also an optional dependency. Everything here degrades to an empty
mapping when it is absent, so the scanner and its tests run unchanged without it.

ID ALIGNMENT
------------
Requirement ids do not agree across frameworks, so each source carries a
normalizer:

    KISA ISMS-P      `2.9.4`      identical to the repo's ids
    ISO 27001:2022   `A.8.5`      identical
    SOC 2 (TSC)      `cc_6_1`     -> `CC6`   (the repo maps at series level)
    NIST 800-53      `ac_2_1`     -> `AC-2`
    PCI-DSS v4.0.1   `1.2.5.1`    -> `Req 1`

stdlib only. No network.
"""

import glob
import json
import os
import re

# ── Locating the installed Prowler package ───────────────────────────────────


def prowler_compliance_dirs():
    """Directories holding Prowler's `<framework>_<provider>.json` files.

    `CLAUDESEC_PROWLER_COMPLIANCE_DIR` overrides discovery — used by the tests,
    which must not depend on Prowler being installed, and useful when Prowler
    lives outside the interpreter running the dashboard.
    """
    override = os.environ.get("CLAUDESEC_PROWLER_COMPLIANCE_DIR", "").strip()
    if override:
        return [override] if os.path.isdir(override) else []
    try:
        import importlib.util

        spec = importlib.util.find_spec("prowler")
    except Exception:
        return []
    if spec is None:
        return []
    roots = list(getattr(spec, "submodule_search_locations", []) or [])
    if not roots and spec.origin:
        roots = [os.path.dirname(spec.origin)]
    out = []
    for root in roots:
        d = os.path.join(root, "compliance")
        if os.path.isdir(d):
            out.append(d)
    return out


# ── Requirement-id normalizers ───────────────────────────────────────────────


def _identity(rid):
    return rid


def _soc2_series(rid):
    """`cc_6_1` / `CC6.1` -> `CC6`. The repo maps SOC 2 at series granularity."""
    m = re.match(r"cc[_\-. ]?(\d)", rid.strip().lower())
    return "CC" + m.group(1) if m else None


def _nist_control(rid):
    """`ac_2_1` / `ac-2(1)` -> `AC-2`."""
    m = re.match(r"([a-z]{2})[_\-]?(\d+)", rid.strip().lower())
    return f"{m.group(1).upper()}-{m.group(2)}" if m else None


def _pci_requirement(rid):
    """`1.2.5.1` -> `Req 1`."""
    m = re.match(r"(\d+)\.", rid.strip())
    return f"Req {m.group(1)}" if m else None


# framework name -> (filename glob, requirement-id normalizer)
FRAMEWORK_SOURCES = {
    "KISA ISMS-P": ("kisa_isms_p_*_[!k]*.json", _identity),
    "ISO 27001:2022": ("iso27001_2022_*.json", _identity),
    "SOC 2 (TSC)": ("soc2_*.json", _soc2_series),
    "NIST 800-53 Rev5": ("nist_800_53_revision_5_*.json", _nist_control),
    "PCI-DSS v4.0.1": ("pci_4.0_*.json", _pci_requirement),
}


# ── Loading ──────────────────────────────────────────────────────────────────


def _requirements(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    reqs = data.get("Requirements")
    return reqs if isinstance(reqs, list) else []


def load_framework(framework):
    """`{control_id: frozenset(check_ids)}` for one framework, `{}` if unavailable.

    Merges every provider file for the framework (aws + azure + gcp + ...), since
    a control is satisfied by evidence from whichever provider was scanned.
    Requirements with no checks are omitted rather than stored empty: an empty
    set and "no native opinion" must not be confused, because the first would
    silently mark a control as having zero evidence.
    """
    source = FRAMEWORK_SOURCES.get(framework)
    if not source:
        return {}
    pattern, normalize = source
    merged = {}
    for directory in prowler_compliance_dirs():
        for path in sorted(glob.glob(os.path.join(directory, "*", pattern))):
            for req in _requirements(path):
                checks = req.get("Checks") or []
                if not checks:
                    continue
                control = normalize(str(req.get("Id", "")))
                if not control:
                    continue
                merged.setdefault(control, set()).update(
                    c for c in checks if isinstance(c, str) and c
                )
    return {k: frozenset(v) for k, v in merged.items() if v}


def load_all():
    """`{framework: {control_id: frozenset(check_ids)}}` for every known source."""
    out = {}
    for framework in FRAMEWORK_SOURCES:
        native = load_framework(framework)
        if native:
            out[framework] = native
    return out
