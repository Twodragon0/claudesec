#!/usr/bin/env python3
"""
dashboard_providers.py — Single source of truth for Prowler provider labels.

This module is the canonical Python-side definition of the provider slug →
human-readable label mapping used across the dashboard generator and its HTML
section builders. It replaces the inline dict literals that had previously been
duplicated (and drifted) across dashboard_html_sections.py,
dashboard_html_builders.py, dashboard_html_overview.py and dashboard-gen.py.

Stdlib-only: no imports of other dashboard modules, no third-party deps.

The bash `case` in scanner/lib/output.sh
(`_prowler_dashboard_summary_provider_label`) intentionally mirrors
PROVIDER_LABELS in shell for performance (it is called in a loop, so spawning
python per call would be wasteful). That mirror is kept honest by the parity
guard test scanner/tests/test_ci_provider_labels_sync.py, which parses the
bash case and asserts it has exactly the same slug→label pairs as
PROVIDER_LABELS.

Public names:
  - PROVIDER_LABELS       — canonical full-label map (16 entries)
  - PROVIDER_LABELS_SHORT — compact-table variant (kubernetes → "K8s")
  - PROVIDER_SUBTAB_MAP   — provider slug → dashboard subtab id (7 entries)
  - PROWLER_SELECTABLE_ORDER — ordered selectable provider keys (7 entries)
"""

# Canonical, full-label provider map. Mirrors the bash `case` in
# scanner/lib/output.sh (kubernetes → "Kubernetes"). Order is preserved to
# match the historical bash case for readability; consumers index by key.
PROVIDER_LABELS = {
    "aws": "AWS",
    "kubernetes": "Kubernetes",
    "azure": "Azure",
    "gcp": "GCP",
    "github": "GitHub",
    "googleworkspace": "Google Workspace",
    "m365": "Microsoft 365",
    "cloudflare": "Cloudflare",
    "nhn": "NHN Cloud",
    "iac": "IaC",
    "llm": "LLM",
    "image": "Container Image",
    "oraclecloud": "Oracle Cloud",
    "alibabacloud": "Alibaba Cloud",
    "openstack": "OpenStack",
    "mongodbatlas": "MongoDB Atlas",
}

# Compact-table variant: identical to PROVIDER_LABELS except kubernetes is
# abbreviated to "K8s" to fit dense provider tables/cards. This distinction is
# intentional and is locked by dashboard builder/gen tests.
PROVIDER_LABELS_SHORT = {**PROVIDER_LABELS, "kubernetes": "K8s"}

# Provider slug → dashboard subtab id (used to route the Prowler selector and
# the provider summary rows to their per-provider subtab).
PROVIDER_SUBTAB_MAP = {
    "aws": "aws",
    "gcp": "gcp",
    "googleworkspace": "gws",
    "kubernetes": "k8s",
    "azure": "azure",
    "m365": "m365",
    "iac": "iac",
}

# Ordered list of the selectable provider keys exposed in dashboard-gen's
# Prowler provider selector. The order is significant (it is the display order
# of the <option> elements) and must be preserved.
PROWLER_SELECTABLE_ORDER = [
    "aws",
    "gcp",
    "googleworkspace",
    "kubernetes",
    "azure",
    "m365",
    "iac",
]
