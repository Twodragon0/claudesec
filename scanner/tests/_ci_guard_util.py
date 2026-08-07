"""
Shared text-scanning helpers for the `test_ci_*.py` CI config regression guards.

WHY THIS FILE EXISTS
--------------------
The guards harden the same false-negative classes the same way: drop `#`
comment lines before a token-presence check (so a token surviving only in a
comment cannot satisfy an invariant), join backslash line-continuations (so a
wrapped instruction is still seen as one command), and locate a workflow's
top-level `on:` trigger block (handling flow-style and quoted keys). Those
primitives were introduced independently — `_strip_comment_lines` /
`_extract_on_block` (branch-protection), `_non_comment_lines` (dependabot),
`_active_text` (prowler), `_no_comments` (dockerfile) — with divergent
implementations. This module is the single canonical home so the hardening stays
consistent across guards and future guards can reuse it.

CONSTRAINTS (same as every guard)
---------------------------------
- **stdlib-only** — no PyYAML, no third-party imports.
- **Not `scanner/lib`** — lives under `scanner/tests/`, so it never touches the
  99% `scanner/lib` coverage gate.
- **Not collected / not catalogued** — the leading underscore and absence of a
  `test_` prefix keep pytest from collecting it, and it does not match the
  `test_ci_*.py` glob the catalog meta-guards enforce (so it needs no Catalog
  row).

IMPORT CONTRACT (dual-runner)
-----------------------------
Guards put their own directory on `sys.path` and import this as a top-level
module, which works under BOTH pytest (prepend import mode) and
`python3 -m unittest scanner.tests.<mod>` (namespace-package import from repo
root):

    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _ci_guard_util import strip_comment_lines, extract_on_block
"""

import re
from glob import glob
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
ACTION_DIR = REPO_ROOT / ".github" / "actions"


def yaml_key_pattern(key: str) -> str:
    """A regex FRAGMENT matching a YAML mapping key `key` bare OR quoted.

    `"uses": x` and `'uses': x` resolve to the identical document as `uses: x`
    (verified against PyYAML), so a matcher that hard-requires the bare form is
    bypassable by a *standard* authoring style — not a contrived evasion. The
    ecosystem proves it: bare `on:` resolves to the YAML-1.1 boolean `True`, which
    is exactly why GitHub's own docs normalize `"on":`.

    A guard-wide sweep (2026-08-06) found EIGHT guards blind to this in matchers
    for `uses:`, `branches:`, `pull_request_target:`, `runs-on:`, `name:` and job
    keys — each verified green while its control was gone. Compose this fragment
    instead of writing `key\\s*:` so the ninth guard cannot repeat it.

    Returns a non-capturing group, safe to embed in a larger pattern."""
    k = re.escape(key)
    return rf'(?:{k}|"{k}"|\'{k}\')'


_EXPLICIT_KEY_RE_CACHE = {}


def explicit_key_lines(text: str, *keys: str) -> list:
    """Stripped lines where one of `keys` is declared with YAML's EXPLICIT-key
    form (`? key` on one line, `: value` on the next).

    That form yields the same mapping key while the substring `key:` never appears
    anywhere, so no line matcher can reach the value — it is *unscannable*, not
    merely unmatched. Guards therefore FAIL CLOSED on the shape (the tripwire
    pattern established by `unscannable_run_keys` in
    `test_ci_injection_surface.py`, ADR-001 §4: prefer a rule complete by
    construction over an incomplete reassembler). Remediation is always available
    and trivial — write the ordinary `key: value` form.

    Matches `? key`, `? "key"`, `? key  # comment`, and the single-line
    `? key : value`."""
    out = []
    for key in keys:
        pat = _EXPLICIT_KEY_RE_CACHE.get(key)
        if pat is None:
            pat = re.compile(
                rf"^\s*(?:-\s+)?\?\s*{yaml_key_pattern(key)}\s*(?::|$|#)"
            )
            _EXPLICIT_KEY_RE_CACHE[key] = pat
        out += [ln.strip() for ln in text.splitlines() if pat.match(ln)]
    return out


def workflow_and_action_files() -> list:
    """Every file whose contents GitHub Actions executes as a workflow or a
    composite action, sorted.

    Two enumeration gaps, both SILENT (a whole file simply never scanned, so the
    guard passed vacuously over it) and both found by adversarial review:

    - Actions honours `.yaml` as well as `.yml`, so an `evil.yaml` workflow was
      invisible to every guard globbing `*.yml`.
    - `.github/actions/<name>/action.yml` (`runs.using: composite`) carries
      `steps[].uses` and `steps[].run` exactly like a workflow, and required
      workflows call them — yet no guard globbed that directory at all. A
      tag-pinned `uses:` planted there defeated the SHA-pin check with the suite
      green.

    Composite actions are matched by their two canonical entrypoint names only
    (the names Actions resolves), so an unrelated helper YAML in that directory is
    not mistaken for executable workflow content."""
    out = []
    for name in ("*.yml", "*.yaml"):
        out += glob(str(WORKFLOW_DIR / name))
    for name in ("action.yml", "action.yaml"):
        out += glob(str(ACTION_DIR / "**" / name), recursive=True)
    return sorted(out)


def non_comment_lines(text: str) -> list:
    """The lines of `text` with whole-line `#` comments dropped."""
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def strip_comment_lines(text: str) -> str:
    """`text` with whole-line `#` comments removed, so a token living only in a
    comment cannot satisfy a presence check."""
    return "\n".join(non_comment_lines(text))


def strip_inline_comment(line: str) -> str:
    """A SINGLE line with a trailing inline `# ...` comment removed
    (e.g. `uses: foo@<sha>  # v1.2.3` -> `uses: foo@<sha>`). Requires whitespace
    before the `#` so a `#` inside a token (a URL fragment, a quoted value) is
    not stripped. Per-line and distinct from strip_comment_lines/non_comment_lines,
    which drop WHOLE comment lines from a multi-line text — several guards need
    the trailing-comment form when scanning one `run:`/`uses:` line at a time.

    Whitespace-only boundary: correct for YAML/Dockerfile lines (where `;#` is
    literal scalar content, NOT a comment). For SHELL lines use
    `strip_inline_comment_sh`, because bash starts a comment after a command
    separator with no intervening space (`echo x;#exit 1`)."""
    return re.sub(r"\s+#.*$", "", line)


# Positions after which a `#` begins a bash comment when it starts a new word,
# with NO intervening space: start-of-line, whitespace, the bash metacharacters
# (`;`, `&`, `|`, `(`, `)`, `<`, `>`), and the backtick (opening a command
# substitution starts a fresh command context, so `` `#cmd` `` is a comment too —
# verified by execution). A `#` preceded by a word char (`foo#bar`) or `$`/`{`
# (`${#var}`) is NOT a word start, so it is preserved.
_SH_COMMENT_BOUNDARY = " \t;&|()<>`"


def strip_inline_comment_sh(line: str) -> str:
    """A SINGLE shell line with its trailing bash comment removed, quote-aware.

    Unlike `strip_inline_comment` (whitespace-only), a `#` here begins a comment
    when it starts a bash word — after start-of-line, whitespace, a bash
    metacharacter (`;`, `&`, `|`, `(`, `)`, `<`, `>`), or a backtick — AND is not
    inside a single-/double-quoted string. Real bash treats `echo x;#exit 1`,
    `FILES=$(cmd)#…`, and `` echo x`#exit 1` `` as comments (the tail never runs)
    with no space before `#`; a whitespace-only stripper misses them, letting a
    token that survives only in such a comment satisfy a shell-scanning guard's
    presence check (ADR-001 §1; the class that hid a `;#exit 1` from the
    Security-Scan-Gate guard). A `#` inside quotes, or mid-word (`foo#bar`,
    `${#var}`), is preserved.

    ANSI-C `$'...'` quoting IS modeled: a `'` immediately preceded by an
    unescaped `$` opens an escape-aware string (bash reads `\\'` as a literal
    quote there), so `$'\\''` is one string and a trailing `#` is a real comment.
    Missing this was an UNDER-strip (false NEGATIVE) that hid a dead `exit 1` from
    the Security-Scan-Gate guard (ADR-001 §2 5th-pass finding), NOT the over-strip
    the earlier docstring claimed.

    KNOWN LIMITATIONS (all OVER-strip direction — they drop live text, causing a
    guard to see LESS, so a false ALARM, never a silent security bypass; none is
    triggered by the shell blocks the current guards scan, so they are documented
    rather than modeled): (1) per-line operation does not carry cross-line quote
    state, so a `#` on a continuation line of a multi-line double-quoted string is
    treated as a comment; (2) heredoc bodies are not recognized, so a literal `;#`
    inside a heredoc would be stripped; (3) a command substitution `$(...)` closing
    inside a word keeps the `#` literal (`x=$(cmd)#c` -> value `…#c`), but a single
    preceding-char model cannot tell that `)` from a subshell `)` (a real command
    boundary), so it over-strips. Revisit if a scanned guard block adopts one."""
    in_s = in_d = in_ansi = False
    prev = ""  # previous unescaped char; "" == start-of-line boundary
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_ansi:  # ANSI-C $'...': backslash escapes the next char (unlike '...')
            if c == "\\" and i + 1 < n:
                prev = "x"
                i += 2
                continue
            if c == "'":
                in_ansi = False
            prev = c
            i += 1
            continue
        if in_s:  # plain single quotes: no escaping in bash
            if c == "'":
                in_s = False
            prev = c
            i += 1
            continue
        if in_d:
            if c == "\\" and i + 1 < n:
                prev = "x"
                i += 2
                continue
            if c == '"':
                in_d = False
            prev = c
            i += 1
            continue
        if c == "\\" and i + 1 < n:  # unquoted escape
            prev = "x"
            i += 2
            continue
        if c == "'":
            # `$'` opens an ANSI-C (escape-aware) string; a plain `'` does not.
            if prev == "$":
                in_ansi = True
            else:
                in_s = True
            prev = c
            i += 1
            continue
        if c == '"':
            in_d = True
            prev = c
            i += 1
            continue
        if c == "#" and (prev == "" or prev in _SH_COMMENT_BOUNDARY):
            return line[:i].rstrip()
        prev = c
        i += 1
    return line


# `if` is counted ONLY where bash reads it as the reserved word opening a
# compound command (start of line, or after `;`/`&`/`|`/`(`/`)`/`{`/`}`/`then`/
# `else`/`do`); `fi` is counted wherever it is a word. The asymmetry is the whole
# safety argument — see `shell_if_body`.
_IF_OPENER_RE = re.compile(r"(?m)(?:^|[;&|(){}]|\b(?:then|else|do)\b)\s*(?P<kw>if)\b")
_FI_CLOSER_RE = re.compile(r"\bfi\b")


# Heredoc redirection opener: `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"`.
_HEREDOC_OPEN_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def blank_heredoc_bodies(text: str) -> str:
    """`text` with heredoc BODIES blanked out, so a shell-looking line inside one
    can never be read as a command. Line count is preserved.

    Comment-stripping alone was not enough. After #402 closed the `#`-comment
    anchor evasion, three decoys re-opened it verbatim — each anchored the scan
    inside itself and yielded a body containing `exit 1` while the real gate was
    deleted and bash exited 0:

        echo 'legacy policy was: if [ "$CRITS" -gt 0 ]; then exit 1; fi'
        cat <<'NOTE' … if [ "$CRITS" -gt 0 ]; then exit 1; fi … NOTE
        - name: legacy if [ "$CRITS" -gt 0 ]; then exit 1; fi     (a YAML scalar)

    The first and third are killed by requiring the anchor at the start of a line
    (they begin `echo` / `- name:`); only the heredoc genuinely starts a line with
    `if`, so this handles that one. Blanking quoted CONTENTS was tried and
    reverted: the anchor itself legitimately contains `"$CRITS"`, so it destroyed
    the control case.

    Direction is OVER-blank -> false alarm: an unterminated heredoc blanks to end
    of text, which can only hide a token from a presence check, never satisfy
    one."""
    out, term = [], None
    for line in text.splitlines():
        if term is not None:
            out.append("")
            if line.strip() == term:
                term = None
            continue
        out.append(line)
        h = _HEREDOC_OPEN_RE.search(line)
        if h:
            term = h.group(2)
    return "\n".join(out)


def shell_if_body(text: str, anchor: str):
    """The body of the shell `if <anchor> … ; then … fi` in `text`, or None.

    `anchor` is a regex matching the condition through its `then`. Used by guards
    that must bound an `exit 1` (or another control) to ONE `if` block: the files
    they scan hold a dozen unrelated `exit 1` lines, so an unscoped presence check
    is inert (ADR-001 §2).

    Three properties, each of which was a demonstrated bypass before the
    2026-08-07 stripper audit; all PoCs ran bash AND the consumer guard:

    1. **Comment-stripped BEFORE the anchor is searched.** `conditional_body_from`
       used to search the raw text and only strip the body, so one comment line —
       `# was: if [ "$CRITS" -gt 0 ]; then exit 1; fi` — anchored the scan inside
       itself and yielded ` exit 1; ` as the body while bash exited 0 on a
       CRITICAL finding. Strip, THEN match; the anchor is part of the haystack.
    2. **Fails CLOSED on an unbalanced count.** Returning "the rest of the text"
       when no closing `fi` is reached hands the consumer every later `exit 1` in
       the file. Verified against the real `lint.yml`: one extra `if` token made
       the returned body 9546 chars instead of 110 and an `exit 1` from an
       unrelated prowler step certified the gutted image-size gate.
    3. **Only command-position `if` opens a nesting level.** `\\bif\\b` matched the
       English word in `echo "… check the base image if this is unexpected"`,
       which is what unbalanced the count in (2). With (2) failing closed, a
       liberal `if` rule would also turn any such message edit into a false alarm.

    4. **The anchor must be in shell COMMAND position.** Property 1 only removed
       `#` comments, so the identical evasion worked with a quoted string, a
       heredoc body, or a YAML scalar (all three proven green-while-defeated in
       the adversarial review of #402). The haystack now also blanks heredoc
       bodies (`blank_heredoc_bodies`), and the anchor must be
       preceded on its line by nothing but whitespace and `if`.

    KNOWN GAP — direction UNDER-report, i.e. a real BYPASS, deliberately not
    closed. A syntactically present but non-executing control still satisfies the
    scan, because deciding reachability is interpretation, not scanning:

        if false; then  <the real gate>  fi
        elif [ "$CRITS" -gt 999 ]; then exit 1
        case "$MODE" in never) exit 1 ;; esac

    Each yields bash `exit=0` on a CRITICAL finding with the guard GREEN. The cost
    argument for shipping it: the only line-scanner rule that would catch these —
    reject any `if`/`case` between the anchor and the control — would fire on
    every legitimately nested conditional, and all three shapes are a glaring,
    reviewable edit adjacent to the severity gate rather than a plausible
    accidental regression. Revisit trigger: if any of them ever lands in a real
    workflow, this needs a bash parser, not another regex. Do NOT record finding
    #1 as fully closed while this stands.

    Residual direction on the `if`/`fi` COUNT is over-count -> the body ends LATE,
    which is the SILENT direction, not the false-alarm one the previous revision
    claimed. `_IF_OPENER_RE` has no YAML awareness, so `if: always()` and a Python
    `if bad:` inside the gate's own heredoc are counted as openers — 5 spurious in
    `security-scan.yml`, 13 in `lint.yml`. Blanking heredocs above removes most of
    them; the YAML `if:` keys remain. On today's files the surplus fails closed
    (verified by sweeping 1..6 injected openers), but the balance changes with the
    next workflow edit."""
    active = blank_heredoc_bodies(
        "\n".join(strip_inline_comment_sh(ln) for ln in text.splitlines())
    )
    # `if` is OPTIONAL because callers differ: the size-gate anchor already
    # includes it, the severity-gate anchor does not. Line-anchoring is what
    # blocks the decoys (they begin `echo` / `- name:`), not the `if` itself,
    # and a bare `[ … ]; then` with no `if` is not valid shell anyway.
    m = re.search(r"(?m)^[ \t]*(?:if[ \t]+)?(?:" + anchor + ")", active)
    if not m:
        return None
    rest = active[m.end():]
    tokens = sorted(
        [(t.start("kw"), 1) for t in _IF_OPENER_RE.finditer(rest)]
        + [(t.start(), -1) for t in _FI_CLOSER_RE.finditer(rest)]
    )
    depth = 1
    for pos, delta in tokens:
        depth += delta
        if depth == 0:
            return rest[:pos]
    return None


def strip_html_comments(text: str) -> str:
    """`text` with HTML/Markdown comments (`<!-- ... -->`, possibly multi-line)
    removed.

    Markdown has no `#` comment, so the `strip_comment_lines` family does not
    apply to the docs the catalog meta-guards scan. `<!-- -->` is the equivalent
    escape hatch: a catalog row parked inside one is invisible when rendered but
    still satisfies a raw substring presence check, so a guard could be dropped
    from the published inventory while `test_ci_catalog_completeness` stays
    green (the comment-evasion class of ADR-001 §1, in Markdown).

    An UNCLOSED `<!--` is left intact rather than eating the rest of the file:
    the pattern requires a closing `-->`, so a stray opener degrades to
    no-strip (under-strip, a false NEGATIVE for that one row) instead of
    blanking the document (which would make every consumer fail at once)."""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


_JOB_KEY_RE = re.compile(r"""^  (?:"([A-Za-z0-9_-]+)"|'([A-Za-z0-9_-]+)'|([A-Za-z0-9_-]+)):\s*$""")


def top_level_jobs(text: str) -> list:
    """The job keys under a workflow's top-level `jobs:` map (2-space-indented
    `name:` lines), in document order. Stops at the dedent to the next top-level
    key, and strips trailing inline comments so `build:  # x` still matches.
    Returns a list; callers wrap in `set()` where set semantics are needed.

    The job key is read bare OR quoted (`"rogue":`). A quoted key used to be
    invisible here, which mattered because the consumer
    (`test_ci_gate_topology.test_every_job_is_gated_or_allowlisted`) asserts every
    job is in `lint-gate.needs` — so a quoted job was hidden from BOTH branch
    protection and the guard meant to notice that. Verified: the guard read green
    with an ungated `"rogue":` job present.

    Also reads the `jobs:` header bare or quoted, since a quoted `"jobs":` would
    otherwise skip the whole scan and return [] — an empty job list satisfies an
    "every job is gated" check vacuously."""
    jobs, in_jobs = [], False
    for raw in text.splitlines():
        if re.match(rf"^{yaml_key_pattern('jobs')}:\s*$", raw):
            in_jobs = True
            continue
        if in_jobs:
            if re.match(r"^\S", raw):  # dedent back to a top-level key
                break
            m = _JOB_KEY_RE.match(strip_inline_comment(raw))
            if m:
                jobs.append(m.group(1) or m.group(2) or m.group(3))
    return jobs


def join_continuations(text: str) -> str:
    """Join backslash-newline line continuations onto one line, so a shell/Docker
    instruction that wraps an argument onto the next line is seen as one command
    (e.g. `RUN pip install \\` + `prowler`)."""
    return text.replace("\\\n", " ")


def on_key_inline(line: str):
    """If `line` is a top-level GitHub Actions `on:` mapping key — bare or quoted
    (`on:` / `'on':` / `"on":`) — return the text after the colon (possibly empty,
    or flow-style content like `[push, pull_request]`). Otherwise return None.

    Only un-indented lines qualify: a nested `on:` under another key is not the
    workflow trigger."""
    s = line.rstrip()
    if s != s.lstrip():  # indented → not a top-level key
        return None
    for key in ("on:", "'on':", '"on":'):
        if s == key:
            return ""
        if s.startswith(key):
            return s[len(key):]
    return None


def extract_on_block(text: str) -> str:
    """Return a workflow's top-level `on:` trigger content: the inline remainder
    of the `on:` line (flow style) PLUS the indented child lines under it, up to
    the next top-level key. Whole-line comments are dropped AND trailing inline
    `#` comments are stripped per retained line (F-7), so neither a prose line nor
    a trailing comment mentioning a trigger can satisfy a consumer's presence
    check; bare/quoted `on:` keys are both handled."""
    body = []
    in_on = False
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if not in_on:
            inline = on_key_inline(line)
            if inline is not None:
                in_on = True
                inline = strip_inline_comment(inline)
                if inline.strip():
                    body.append(inline)  # flow-style content on the `on:` line
            continue
        # A new top-level key (non-space first char, non-empty) ends the block.
        if line and not line[0].isspace():
            break
        body.append(strip_inline_comment(line))
    return "\n".join(body)
