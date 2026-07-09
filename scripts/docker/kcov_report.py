#!/usr/bin/env python3
"""Print merged kcov bash-coverage summary and enforce a floor.

Usage: kcov_report.py <coverage.json> <floor_percent>
Exit 0 if merged percent_covered >= floor, else 2. Kept as a standalone file
(not an inline heredoc) so the docker `bash -c` wrapper in
verify-shell-coverage-docker.sh has no nested-quoting hazards.
"""
import json
import sys


def main() -> int:
    cov_path, floor = sys.argv[1], float(sys.argv[2])
    with open(cov_path, encoding="utf-8") as f:
        data = json.load(f)
    pct = float(data.get("percent_covered", 0) or 0)
    print(f"MERGED bash coverage: {pct:.2f}% (floor {floor}%)")
    for entry in sorted(data.get("files", []), key=lambda x: x.get("file", "")):
        name = entry.get("file", "?").split("/")[-1]
        fpct = float(entry.get("percent_covered", 0) or 0)
        print(f"  {name:24} {fpct:.2f}%")
    return 0 if pct >= floor else 2


if __name__ == "__main__":
    sys.exit(main())
