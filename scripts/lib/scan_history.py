"""Scanner run-history loading, shared by the dashboard-sync operator scripts.

Extracted from `scripts/build-dashboard.py` and `scripts/sync-cost-xlsx.py`,
whose copies differed only by one comment line.
"""

import json
from pathlib import Path

HISTORY_KEEP = 30


def collect_scan_history(history_dir: Path, keep: int = HISTORY_KEEP) -> list[dict]:
    """Oldest-to-newest `scan-*.json` entries from `history_dir`, last `keep`.

    An unreadable entry is skipped rather than aborting the run: history is
    supplementary, and one truncated file from a killed scan must not cost the
    whole trend line.
    """
    if not history_dir.exists():
        return []
    history = []
    for f in sorted(history_dir.glob("scan-*.json")):
        try:
            history.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    history.sort(key=lambda x: x.get("timestamp", ""))
    return history[-keep:]
