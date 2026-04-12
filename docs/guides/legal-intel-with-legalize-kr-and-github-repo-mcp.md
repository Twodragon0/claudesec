---
title: Legal Intelligence with legalize-kr and GitHub Repo MCP
description: Set up ClaudeSec to use a local legalize-kr mirror plus GitHub Repo MCP for Korean compliance and policy review workflows.
tags: [legalize-kr, github-repo-mcp, mcp, compliance, isms-p, setup]
---

# Legal Intelligence with legalize-kr and GitHub Repo MCP

ClaudeSec can use two complementary sources for Korean compliance work:

- A **local mirror** of [`legalize-kr/legalize-kr`](https://github.com/legalize-kr/legalize-kr), which stores Korean statutes as Markdown files with Git history by promulgation date.
- A **GitHub MCP server** based on [`Ryan0204/github-repo-mcp`](https://github.com/Ryan0204/github-repo-mcp), which lets your AI client browse public repositories over MCP.

Use the local mirror when you need fast grep, local history inspection, or deterministic offline reference. Use GitHub Repo MCP when your AI client needs repository browsing tools without loading the full repository into the local project.

## What ClaudeSec adds

ClaudeSec ships three helper scripts:

| Script | Purpose |
|--------|---------|
| `scripts/setup-legal-intel.sh` | Clone/update `legalize-kr` and `github-repo-mcp`, build the MCP server, and write `.mcp.json` |
| `scripts/legalize-search.sh` | Search local Korean law Markdown files and inspect Git history |
| `scripts/run-github-repo-mcp.sh` | Start the downloaded GitHub Repo MCP build, with `npx` fallback |

The local mirror lives in `.claudesec-sources/`, which is ignored by Git.

## Quick setup

```bash
./scripts/setup-legal-intel.sh
```

This does three things:

1. Clones or updates `legalize-kr/legalize-kr`
2. Clones or updates `Ryan0204/github-repo-mcp`
3. Writes `.mcp.json` in the target repository so MCP-capable clients can launch `scripts/run-github-repo-mcp.sh`

If you already have the mirrors and only want to refresh `.mcp.json`:

```bash
./scripts/setup-legal-intel.sh --write-config-only
```

## Search Korean laws locally

Search for a term across the entire local law tree:

```bash
./scripts/legalize-search.sh "개인정보"
```

Search within a specific law:

```bash
./scripts/legalize-search.sh "정보통신서비스" 개인정보보호법
```

Inspect the Git history for one law file:

```bash
./scripts/legalize-search.sh --history 개인정보보호법 법률.md
```

List available law directories:

```bash
./scripts/legalize-search.sh --list-laws
```

## MCP configuration

`scripts/setup-legal-intel.sh` writes a local `.mcp.json` like this:

```json
{
  "mcpServers": {
    "github-repo-mcp": {
      "command": "/absolute/path/to/scripts/run-github-repo-mcp.sh",
      "args": [],
      "cwd": "/absolute/path/to/claudesec",
      "enabled": true
    }
  }
}
```

For higher GitHub API rate limits, set `GITHUB_TOKEN` in the MCP client environment that launches the server.

## Suggested workflows

### Compliance mapping

Use the local `legalize-kr` mirror to check exact statutory wording and revision history, then map those findings into ClaudeSec controls such as KISA ISMS-P, NIST CSF, or internal policy requirements.

### Repository review

Use GitHub Repo MCP to inspect public repository files directly from the AI client when comparing upstream examples, policy templates, or external compliance artifacts.

### Change tracking

When a Korean law changes, refresh the local mirror and use `git log` over the relevant law directory to understand effective-date context before updating internal controls or scanner guidance.

## Notes

- `legalize-kr` may force-push its history after pipeline improvements. If that happens, re-run `./scripts/setup-legal-intel.sh` or manually reset the local mirror.
- `github-repo-mcp` works without a token, but unauthenticated GitHub API access is rate-limited.
- `.mcp.json` is intentionally ignored by Git because it contains machine-local paths.

## References

- [legalize-kr/legalize-kr](https://github.com/legalize-kr/legalize-kr)
- [Ryan0204/github-repo-mcp](https://github.com/Ryan0204/github-repo-mcp)
- [국가법령정보센터 OpenAPI](https://open.law.go.kr)
