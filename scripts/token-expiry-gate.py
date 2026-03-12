#!/usr/bin/env python3
"""CI gate for OAuth token expiry windows.

Environment variables:
- GH_TOKEN_EXPIRES_AT / GITHUB_TOKEN_EXPIRES_AT
- OKTA_OAUTH_TOKEN_EXPIRES_AT
- DATADOG_TOKEN_EXPIRES_AT / DD_TOKEN_EXPIRES_AT / DD_API_KEY_EXPIRES_AT
- SLACK_TOKEN_EXPIRES_AT / SLACK_BOT_TOKEN_EXPIRES_AT
- CLAUDESEC_TOKEN_EXPIRY_GATE_MODE: 24h (default) | 7d | off
- CLAUDESEC_TOKEN_EXPIRY_PROVIDERS: github,okta (default)
- CLAUDESEC_TOKEN_EXPIRY_STRICT_PROVIDERS: false (default)
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone


PROVIDER_ENV_KEYS = {
    "github": ("GH_TOKEN_EXPIRES_AT", "GITHUB_TOKEN_EXPIRES_AT"),
    "okta": ("OKTA_OAUTH_TOKEN_EXPIRES_AT",),
    "datadog": (
        "DATADOG_TOKEN_EXPIRES_AT",
        "DD_TOKEN_EXPIRES_AT",
        "DD_API_KEY_EXPIRES_AT",
    ),
    "slack": ("SLACK_TOKEN_EXPIRES_AT", "SLACK_BOT_TOKEN_EXPIRES_AT"),
}

PROVIDER_LABELS = {
    "github": "GitHub",
    "okta": "Okta OAuth",
    "datadog": "Datadog",
    "slack": "Slack",
}


def parse_expiry(raw: str) -> datetime | None:
    value = (raw or "").strip()
    if not value:
        return None
    if value.isdigit():
        return datetime.fromtimestamp(int(value), timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_provider_list(raw: str) -> tuple[list[str], list[str]]:
    providers: list[str] = []
    unknown: list[str] = []
    for token in (raw or "").split(","):
        key = token.strip().lower()
        if not key:
            continue
        if key in PROVIDER_ENV_KEYS:
            if key not in providers:
                providers.append(key)
        elif key not in unknown:
            unknown.append(key)
    return providers, unknown


def resolve_expiry_env(provider: str) -> str:
    for key in PROVIDER_ENV_KEYS.get(provider, ()):
        value = (os.getenv(key, "") or "").strip()
        if value:
            return value
    return ""


def parse_bool_flag(raw: str | None) -> bool:
    value = (raw or "").strip().lower()
    return value in ("1", "true", "yes", "on")


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate CI by token expiry windows")
    parser.add_argument(
        "--providers",
        default=None,
        help=(
            "Comma-separated providers to check. "
            "Supported: github,okta,datadog,slack "
            "(default: CLAUDESEC_TOKEN_EXPIRY_PROVIDERS or github,okta)"
        ),
    )
    parser.add_argument(
        "--strict-providers",
        default=None,
        help=(
            "Fail when selected provider expiry metadata is missing. "
            "Values: true/false (default: CLAUDESEC_TOKEN_EXPIRY_STRICT_PROVIDERS or false)"
        ),
    )
    args = parser.parse_args()

    mode = (
        (os.getenv("CLAUDESEC_TOKEN_EXPIRY_GATE_MODE", "24h") or "24h").strip().lower()
    )
    if mode in ("off", "none", "0", "false"):
        print("::notice::Token expiry gate disabled")
        return 0

    threshold_hours = 168 if mode == "7d" else 24
    threshold_seconds = threshold_hours * 3600
    now = datetime.now(timezone.utc)

    provider_raw = (
        args.providers
        if args.providers is not None
        else os.getenv("CLAUDESEC_TOKEN_EXPIRY_PROVIDERS", "github,okta")
    )
    strict_providers = parse_bool_flag(
        args.strict_providers
        if args.strict_providers is not None
        else os.getenv("CLAUDESEC_TOKEN_EXPIRY_STRICT_PROVIDERS", "false")
    )
    providers, unknown_providers = parse_provider_list(provider_raw)
    if unknown_providers:
        print(f"::warning::Unknown providers ignored: {', '.join(unknown_providers)}")
    if not providers:
        print("::error::No valid providers selected for token expiry gate")
        return 1

    candidates = {PROVIDER_LABELS[p]: resolve_expiry_env(p) for p in providers}

    violations: list[str] = []
    for provider, raw in candidates.items():
        try:
            expiry = parse_expiry(raw)
        except Exception:
            if strict_providers:
                violations.append(f"{provider} expiry metadata format is invalid")
            else:
                print(
                    f"::warning::{provider} expiry metadata format invalid (skip gate for this token)"
                )
            continue

        if expiry is None:
            if strict_providers:
                violations.append(f"{provider} expiry metadata is required but missing")
            else:
                print(
                    f"::warning::{provider} expiry metadata not set (skip gate for this token)"
                )
            continue

        remaining = int((expiry - now).total_seconds())
        if remaining <= 0:
            violations.append(f"{provider} token expired")
        elif remaining <= threshold_seconds:
            violations.append(
                f"{provider} token expires within gate window ({threshold_hours}h)"
            )

    if violations:
        for msg in violations:
            print(f"::error::{msg}")
        return 1

    print(
        "Token expiry gate passed "
        f"(mode={mode}, window={threshold_hours}h, providers={','.join(providers)}, strict_providers={str(strict_providers).lower()})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
