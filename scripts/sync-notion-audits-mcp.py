#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE_PATH = ROOT / ".claudesec-assets" / "notion-security-audits.json"


def build_schema() -> str:
    return json.dumps(
        {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["ok", "empty", "error"]},
                "audits": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "date": {"type": "string"},
                            "title": {"type": "string"},
                            "status": {"type": "string"},
                            "priority": {"type": "string"},
                            "impact": {"type": "string"},
                            "tags": {"type": "array", "items": {"type": "string"}},
                            "summary": {"type": "string"},
                            "url": {"type": "string"},
                            "task_id": {"type": "string"},
                        },
                        "required": [
                            "date",
                            "title",
                            "status",
                            "priority",
                            "impact",
                            "tags",
                            "summary",
                            "url",
                            "task_id",
                        ],
                        "additionalProperties": False,
                    },
                },
                "note": {"type": "string"},
            },
            "required": ["status", "audits", "note"],
            "additionalProperties": False,
        },
        separators=(",", ":"),
    )


def build_prompt() -> str:
    return (
        "Use the configured Notion MCP tools to find recent Notion pages related to 보안로그 정기점검. "
        "Return up to 20 audits sorted by newest first. "
        "For each audit return date,title,status,priority,impact,tags,summary,url,task_id. "
        "Use empty strings or [] when a field is unavailable. "
        "If no matching pages exist, return status=empty with audits=[]. "
        "If the Notion MCP server is unavailable or needs authentication, return status=error with a short note."
    )


def run_claude() -> dict[str, object]:
    claude_path = shutil.which("claude")
    if not claude_path:
        raise RuntimeError("claude CLI not found")

    result = subprocess.run(
        [
            claude_path,
            "-p",
            "--permission-mode",
            "dontAsk",
            "--allowedTools",
            "mcp__notion__*",
            "--output-format",
            "json",
            "--json-schema",
            build_schema(),
            build_prompt(),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        raise RuntimeError(message or "claude command failed")

    payload = json.loads(result.stdout)
    if isinstance(payload, dict) and isinstance(payload.get("structured_output"), dict):
        return payload["structured_output"]
    if isinstance(payload, dict):
        return payload
    raise RuntimeError("invalid claude output")


def main() -> int:
    cache_path = Path(os.environ.get("NOTION_MCP_CACHE_PATH", "") or DEFAULT_CACHE_PATH)
    cache_path = cache_path.expanduser()
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = run_claude()
    except Exception as exc:
        print(f"Notion MCP sync failed: {exc}", file=sys.stderr)
        return 1

    status = data.get("status")
    note = data.get("note", "")
    audits = data.get("audits", [])

    if not isinstance(status, str):
        print("Notion MCP sync failed: invalid status", file=sys.stderr)
        return 1
    if not isinstance(note, str):
        note = ""
    if not isinstance(audits, list):
        print("Notion MCP sync failed: invalid audits payload", file=sys.stderr)
        return 1

    normalized = []
    for item in audits:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "date": str(item.get("date", "")),
                "title": str(item.get("title", "")),
                "status": str(item.get("status", "")),
                "priority": str(item.get("priority", "")),
                "impact": str(item.get("impact", "")),
                "tags": [
                    str(tag) for tag in item.get("tags", []) if isinstance(tag, str)
                ],
                "summary": str(item.get("summary", "")),
                "url": str(item.get("url", "")),
                "task_id": str(item.get("task_id", "")),
            }
        )

    if status == "error":
        print(f"Notion MCP sync failed: {note or 'MCP unavailable'}", file=sys.stderr)
        return 1

    cache_path.write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Wrote {len(normalized)} audits to {cache_path}")
    if note:
        print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
