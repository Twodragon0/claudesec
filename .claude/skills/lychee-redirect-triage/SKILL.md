---
name: lychee-redirect-triage
description: Triage and resolve a lychee redirect / link-rot finding in ClaudeSec — classify 3xx redirects vs 4xx/5xx rot, resolve to canonical URLs or register an intentional-redirect exclude in BOTH lychee.toml and its guard, then verify. Use when the monthly redirect-sweep opens an issue, lychee prints a redirect/404 WARN, or a link needs triaging before a docs PR.
user-invocable: true
---

# Lychee Redirect / Link-Rot Triage Playbook

Actionable consolidation of ClaudeSec's link-hygiene knowledge (PRs #290–#296).
Use it to turn a redirect / dead-link finding into the *right* fix — not a
reflexive exclude that hides real rot. Source of truth is always the live
`lychee.toml` + `.github/workflows/lint.yml`; re-read them before quoting a flag.

## The one thing to internalize first

**CI cannot catch link rot for you.** The PR-time `link-check` job runs lychee
with `--accept '100..=599'`, so every 3xx/4xx/5xx response *passes* CI by design
(this stops flaky external sites from blocking docs merges). So a green
`link-check` does **not** mean links are healthy. Two backstops exist instead:

- The **monthly redirect-sweep** (`lychee-redirect-sweep.yml`) re-runs lychee
  with `--max-redirects 0 --accept '200..=299'` and files a self-healing issue.
- **This manual playbook**, when you hit a WARN locally or triage a sweep issue.

Corollary: when you inspect a link, **capture its FINAL status code, not just
the effective URL.** A URL that "resolves" in a browser can still be a 404 or an
unwanted redirect that CI silently accepted.

## Triage decision tree

For each flagged URL, curl it and read the *first* status (don't let curl follow
redirects — you want to see the 3xx itself):

```bash
curl -sS -o /dev/null -w '%{http_code} -> %{redirect_url}\n' --max-redirs 0 "<URL>"
```

Then classify:

1. **200 (clean)** — not a finding; it slipped in via the broad PR accept range
   or a transient. No action.

2. **3xx redirect → a working canonical target** — **rewrite the Markdown link**
   to the final canonical URL. This is the default for redirects. Do NOT add an
   exclude; excludes are for redirects that must stay as-written.

3. **3xx redirect BY DESIGN** (the written URL is the correct entry point and its
   target is an auth gate / a versioned file you must not hardcode) — add a
   **path-specific** exclude (see "Registering an intentional redirect"). Known
   members of this class in this repo:
   - `github.com/Twodragon0/claudesec/security/advisories/new` → 302 to login
     when unauthenticated; the `/security/advisories/new` URL is canonical.
   - `developers.kakao.com/tool/debugger/sharing` → 302/303 to a Kakao login.
   - `nist.gov/document/...-owasp-samm` → 302 to a versioned PDF; the
     `/document/` landing page is the stable citation (the deep PDF path rots
     faster, not slower).

4. **4xx / 5xx dead link** — **fix or replace the URL.** Only add a `lychee.toml`
   exclude if the host merely bot-blocks CI (403/429/RST/timeout) but is fine in
   a browser — then it goes in the "blocks bots / times out" section, NOT the
   intentional-redirect section.

5. **Release-time 404 (by design)** — CHANGELOG version-compare links
   (`github.com/Twodragon0/claudesec/compare/...`) 404 until the tag publishes.
   Already excluded; keep it.

## Where excludes live (single source of truth)

All excludes live in **`lychee.toml`** (undotted, auto-discovered), consumed via
`lychee --config lychee.toml`. NEVER add an inline `--exclude` to `lint.yml` —
`test_ci_lychee_config.py` fails if one reappears (it would split-brain the
allowlist). A dotted `.lychee.toml` is also forbidden (never auto-discovered →
goes stale).

`lychee.toml` sections (match by substring of the URL, so a host suppresses
everything under it — prefer a path-specific entry to keep siblings checked):
- Korean gov / public-sector (SSL / bot-block)
- "blocks bots / times out / resets" hosts
- upstream URL-structure churn
- GitHub features not enabled on this repo
- CHANGELOG `compare/` release-time 404s
- **`# --- Intentional redirects`** ← this section is guarded by an EXACT-COUNT check
- localhost / file://

## Registering an intentional redirect (case 3) — BOTH files

`test_ci_lychee_config.py` pins the intentional-redirect section to an **exact
count**, so adding an entry to `lychee.toml` alone breaks the guard on purpose
(that's the point — it forces a reviewer to confirm the entry is a real
intentional redirect, not rot disguised as one). Update **both**:

1. `lychee.toml` — add a path-specific entry under `# --- Intentional redirects`,
   with a comment explaining *why* it redirects and why the written URL is
   canonical.
2. `scanner/tests/test_ci_lychee_config.py` — add the same URL string to the
   `INTENTIONAL_REDIRECT_EXCLUDES` tuple, with a matching comment.

The guard's `test_toml_intentional_redirect_excludes_are_exactly_registered`
asserts the section and the tuple match exactly (membership + count), and a
mutate-then-verify self-test proves it catches a smuggled 4th entry.

## Verify (before opening the docs PR)

```bash
# Reproduce the sweep locally (strict): should list only your intended targets.
lychee --config lychee.toml --max-redirects 0 --accept '200..=299' '**/*.md'

# Standard PR-time link check (broad accept — should be clean of hard errors).
lychee "**/*.md"        # or: markdownlint "**/*.md" && lychee "**/*.md"

# If you touched lychee.toml or the guard, run the guard:
python3 -m pytest scanner/tests/test_ci_lychee_config.py -q
```

Success criteria:
- Every real redirect rewritten to its canonical URL (verified 200).
- Every real 404/5xx fixed or replaced.
- Every intentional redirect registered in BOTH files; guard passes.
- No inline `--exclude` in `lint.yml`; no dotted `.lychee.toml`.

## Pitfalls

- **Don't "resolve" an intentional-redirect URL into its target.** Rewriting
  `/security/advisories/new` to its login-page redirect target, or the NIST
  `/document/` page to a deep versioned PDF path, makes the link *more* fragile.
  That's exactly why those are excluded, not rewritten.
- **Prefer path-specific excludes.** A bare host exclude silences every link on
  that host, including ones you *do* want checked (e.g. Kakao's non-redirecting
  `developers.kakao.com/docs/...` links stay checked).
- **The lychee binary pin is load-bearing:** keep `lycheeVersion: v0.23.0`.
  v0.24.x nests the binary in a `lychee-<triple>/` subdir the pinned
  lychee-action installer can't find (`install: cannot stat`). #204 bumped it
  and broke CI; reverted in #209/#210.
- **codecov badge SVG** stays on apex `codecov.io` (not `app.codecov.io`) — the
  apex is the canonical badge host; don't "fix" its redirect.
- **A green PR `link-check` is not proof of link health** — see the top section.

## Related

- `scanner/tests/test_ci_lychee_config.py` — the exclude single-source + exact-count guard.
- `scanner/tests/test_ci_lychee_redirect_sweep.py` — guards the monthly sweep workflow.
- `.github/workflows/lychee-redirect-sweep.yml` — the automated monthly backstop.
- `ci-config-guard-claudesec` skill — for authoring a new guard around any of this.
