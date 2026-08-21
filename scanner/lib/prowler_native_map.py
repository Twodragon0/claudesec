"""
ClaudeSec — load Prowler's own compliance requirement→check mapping.

WHY
---
`COMPLIANCE_CONTROL_MAP` assigns a finding to a control by substring-matching
keywords against the finding's text. Prowler assigns checks to requirements by
INTENT, in data it ships. Those are different functions, and measurement showed
how different: on the KISA ISMS-P controls where both have an opinion, the
keyword lists reproduce roughly half of Prowler's mapping (48.8% over 565
mappings, measured at 5.30.1 after the control realignment below).

The figure used to be quoted as 41.5%, with `2.9.4` (백업·복구) "scoring 0 of
58". That example was wrong: `compliance-map.py` had 2.9.3/2.9.4 swapped
relative to the standard, so the backup keywords were being scored against
Prowler's *logging* checks. Relabelling the four affected controls
(2.6.1, 2.9.3, 2.9.4, 2.10.8, plus 2.10.9 restored) moved framework agreement
31.5% -> 48.8%. The approximation is still an approximation — but measure a
miss rate against the requirement the id actually names.

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
    CMMC 2.0 L2      `3_1_1`      -> `AC`    (800-171 family -> CMMC domain)

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


# 800-171 requirement family -> CMMC 2.0 domain. CMMC 2.0 Level 2's 110
# practices ARE NIST SP 800-171 rev2's requirements, so the family number is the
# domain — no interpretation step, unlike the CIS case rejected below.
CMMC_DOMAINS = {
    "3_1": "AC",   # Access Control
    "3_2": "AT",   # Awareness and Training
    "3_3": "AU",   # Audit and Accountability
    "3_4": "CM",   # Configuration Management
    "3_5": "IA",   # Identification and Authentication
    "3_6": "IR",   # Incident Response
    "3_7": "MA",   # Maintenance
    "3_8": "MP",   # Media Protection
    "3_9": "PS",   # Personnel Security
    "3_10": "PE",  # Physical Protection
    "3_11": "RA",  # Risk Assessment
    "3_12": "CA",  # Security Assessment
    "3_13": "SC",  # System and Communications Protection
    "3_14": "SI",  # System and Information Integrity
}


def _cmmc_domain(rid):
    """`3_1_1` -> `AC`. The repo maps CMMC at domain granularity.

    Prowler writes 800-171 ids with underscores (`3_13_5`), not the dotted form
    the standard prints (`3.13.5`); both are accepted so a future Prowler
    re-spelling does not silently drop every requirement. The family is taken
    greedily so `3_13_*` reads as family 13 (SC) and not family 1 (AC).
    """
    m = re.match(r"3[_.](\d+)[_.]", rid.strip())
    return CMMC_DOMAINS.get(f"3_{m.group(1)}") if m else None


# framework name -> (filename glob, requirement-id normalizer)
FRAMEWORK_SOURCES = {
    "KISA ISMS-P": ("kisa_isms_p_*_[!k]*.json", _identity),
    "ISO 27001:2022": ("iso27001_2022_*.json", _identity),
    "SOC 2 (TSC)": ("soc2_*.json", _soc2_series),
    "NIST 800-53 Rev5": ("nist_800_53_revision_5_*.json", _nist_control),
    "PCI-DSS v4.0.1": ("pci_4.0_*.json", _pci_requirement),
    # CMMC has no `cmmc_*.json` of its own — 800-171 rev2 IS its practice set.
    # Measured against the pinned Prowler 5.30.1 file (50 requirements, 49 with
    # checks, 87 distinct checks): 9 of the 14 domains carry checks — SC 50,
    # AC 43, AU 21, CM 21, IA 21, IR 14, SI 13, CA 9, RA 3 — and AT/MA/MP/PE/PS
    # carry none, which is why the repo's CMMC controls are `native_only` and
    # report N/A rather than a keyword guess. See
    # docs/plans/compliance-native-mapping-and-cmmc.md (its per-family counts
    # were measured on 5.38 and differ slightly from the pinned version).
    "CMMC 2.0 Level 2": ("nist_800_171_revision_2_*.json", _cmmc_domain),
    # DELIBERATELY ABSENT: "CIS Benchmarks".
    #
    # Prowler ships 34 `cis_*.json` files with real check arrays, so wiring this
    # in looks like a one-line win. It is not. The repo's CIS control ids are a
    # hand-rolled scheme that matches no real CIS Controls version: `CIS-6.1`
    # here is "Audit log management", which in CIS Controls v8 is Safeguard
    # **8.1** — v8's 6.1 is "Establish an Access Granting Process". An identity
    # normalizer would therefore attach real checks to the WRONG controls
    # silently, which is worse than the keyword approximation it replaced.
    #
    # Adding CIS needs a control-id remap pass first, done against a named CIS
    # Controls version. See docs/plans/compliance-native-mapping-and-cmmc.md.
}


# ── Provider scope ───────────────────────────────────────────────────────────
#
# WHY THIS EXISTS. `load_framework()` reads the INSTALLED Prowler package, not
# the scan. Prowler ships each framework for some providers and not others, so
# the mapping is populated whenever Prowler is installed — including on a run
# that scanned none of those providers, where no finding can ever match a check
# id and every natively-mapped control falls through to `count == 0 -> PASS`.
# The shipped image makes this reachable: the Dockerfile strips
# `prowler/providers/{azure,gcp,...}` but never `prowler/compliance/**`.
#
# Measured on a Kubernetes-only scan against Prowler 5.30.1 with 62 real k8s
# check ids as FAIL findings:
#
#   NIST 800-53 Rev5   10 pass /  0 fail   all 10 from `prowler`, zero evidence
#   SOC 2 (TSC)         6 pass /  0 fail   all 6 assessable, zero evidence
#   KISA ISMS-P        16 of 42 controls decided by AWS check ids
#   PCI-DSS v4.0.1      0 pass /  7 fail   correct — Prowler ships a k8s file
#   ISO 27001:2022      3 pass /  3 fail   correct — ditto
#
# DERIVED, NOT DECLARED. This was a hand-written `{framework: providers}` dict
# when #455 scoped CMMC alone. A dict cannot be right for long: the answer is
# already on disk in the directory each file was loaded from, it differs per
# Prowler version, and the measurement above shows a hand-list would have had
# to name three more frameworks the moment it was written. Reading the layout
# `load_framework()` already walks removes both the drift and the omission.


# The scope itself is built by `load_framework_and_providers()` below, in the
# same pass and by the same test as the mapping it scopes.


# ── Loading ──────────────────────────────────────────────────────────────────


def _requirements(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    reqs = data.get("Requirements")
    return reqs if isinstance(reqs, list) else []


def load_framework_and_providers(framework):
    """`({control: frozenset(checks)}, {control: frozenset(providers)})`.

    Merges every provider file for the framework (aws + azure + gcp + ...), since
    a control is satisfied by evidence from whichever provider was scanned.
    Requirements with no checks are omitted rather than stored empty: an empty
    set and "no native opinion" must not be confused, because the first would
    silently mark a control as having zero evidence.

    The provider map is built PER CONTROL, in the same pass and by the same
    test as the mapping: a provider is recorded for a control only once one of
    its requirements survived into `merged`. Both properties are load-bearing.

    Per control, because the merge is what hides the gap. A framework-level
    scope says "ISO ships for kubernetes", which is true, while ISO `A.8.9`'s
    twenty checks are all AWS — so on a Kubernetes run that control matches
    nothing and reports PASS with no evidence it could ever have read. Measured
    at 5.30.1, ISO alone has such controls in both directions: `A.8.9`, `A.8.4`,
    `A.8.7` (aws-only) and `A.5.2` (kubernetes-only).

    From content, because existence is not contribution. A file that parses to
    no control (unparseable JSON, every requirement checkless, every id
    unnormalizable) would otherwise widen the scope past the evidence.
    """
    source = FRAMEWORK_SOURCES.get(framework)
    if not source:
        return {}, {}
    pattern, normalize = source
    merged = {}
    providers = {}
    for directory in prowler_compliance_dirs():
        for path in sorted(glob.glob(os.path.join(directory, "*", pattern))):
            provider = os.path.basename(os.path.dirname(path))
            for req in _requirements(path):
                checks = [c for c in (req.get("Checks") or []) if isinstance(c, str) and c]
                if not checks:
                    continue
                control = normalize(str(req.get("Id", "")))
                if not control:
                    continue
                merged.setdefault(control, set()).update(checks)
                providers.setdefault(control, set()).add(provider)
    return (
        {k: frozenset(v) for k, v in merged.items() if v},
        {k: frozenset(v) for k, v in providers.items() if merged.get(k)},
    )


def load_framework(framework):
    """`{control_id: frozenset(check_ids)}` for one framework, `{}` if unavailable."""
    return load_framework_and_providers(framework)[0]


def control_providers(framework):
    """`{control: frozenset(providers)}` — who can evidence each control."""
    return load_framework_and_providers(framework)[1]


def framework_providers(framework):
    """Union of `control_providers()` — every provider this framework reads."""
    out = set()
    for provs in control_providers(framework).values():
        out |= provs
    return frozenset(out)


def native_control_providers():
    """`{framework: {control: frozenset(providers)}}` for every loaded framework.

    A framework that contributed nothing is omitted rather than mapped empty:
    it has no native mapping to gate, and an empty map would read as "reachable
    by nobody" — which would gate a framework already running on keywords.
    """
    out = {}
    for framework in FRAMEWORK_SOURCES:
        mapping, providers = load_framework_and_providers(framework)
        if mapping and providers:
            out[framework] = providers
    return out


def load_all():
    """`{framework: {control_id: frozenset(check_ids)}}` for every known source."""
    out = {}
    for framework in FRAMEWORK_SOURCES:
        native = load_framework(framework)
        if native:
            out[framework] = native
    return out
