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

import json
import re
from glob import glob
from pathlib import Path

# scanner/tests/this_file -> parents[2] == repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
ACTION_DIR = REPO_ROOT / ".github" / "actions"
PROTECTION_SCRIPT = REPO_ROOT / "scripts" / "sync-repo-protection.sh"


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
      `steps[].uses` and `steps[].run` exactly like a workflow — yet no guard
      globbed that directory at all. (They are called from `templates/`, which
      ships to user repos, NOT from this repo's own workflows; an earlier version
      of this docstring claimed the latter and was wrong — verified 2026-08-10:
      no `uses: ./` appears anywhere under `.github/workflows/`.) A
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


# `uses:` bare OR quoted, with an optionally QUOTED VALUE.
_USES_LINE_RE = re.compile(
    rf"""^\s*-?\s*{yaml_key_pattern('uses')}\s*:\s*['"]?(?P<ref>[^\s#'"]+)"""
)


def uses_refs(text: str) -> list:
    """`(lineno, ref)` for every `uses:` value in `text`, comment-immune.

    Canonical home for the action-ref matcher, which has now been fixed in three
    directions and must not exist twice:

    - the KEY may be quoted (`- "uses": …`) — the 2026-08-06 sweep, #391/#393;
    - there may be whitespace before the colon (`uses : …`), the shape pinned in
      `test_ci_security_gate_behaviour`;
    - the VALUE may be quoted (`uses: "actions/checkout@main"`) — found
      2026-08-11 while deciding the template pin policy, and it was live. The
      previous matcher's value class excluded `'` and `"` with no leading-quote
      allowance, so a quoted scalar produced NO MATCH AT ALL and the ref was not
      merely unpinned but invisible. Measured on the real `lint.yml`: replacing
      the `actions/checkout` SHA with `uses: "actions/checkout@main"` — a mutable
      BRANCH ref in a required workflow — left `test_ci_gate_topology.py` at
      **15 passed**. An absence reads exactly like compliance, which is why the
      matcher lives here now instead of in two guards.

    Whole-line `#` comments are skipped and a trailing comment stripped, so a ref
    quoted in prose is not mistaken for an executed step. Returns the ref
    verbatim; callers decide what is pinnable (`./`, `docker://`)."""
    out = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if raw.lstrip().startswith("#"):
            continue
        m = _USES_LINE_RE.match(strip_inline_comment(raw))
        if m:
            out.append((lineno, m.group("ref")))
    return out


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


# A mapping key at the start of a line, bare or quoted, capturing the key NAME.
#
# Deliberately generic rather than composed from `yaml_key_pattern`: that
# fragment takes one KNOWN key and matches its three spellings, whereas this
# reads whichever key is there and unquotes it, so comparison happens once on the
# parsed name and no call site can forget a spelling. That is the blindness that
# hit eight guards in #391/#393/#394.
_KEY_LINE_RE = re.compile(
    r"""^\s*(?:"(?P<dq>[^"]+)"|'(?P<sq>[^']+)'|(?P<bare>[^\s:#]+))\s*:(?:\s|$)"""
)


def keys_at_column(block: str, col: int) -> list:
    """The mapping keys declared at EXACTLY `col` spaces of indent in `block`.

    Column equality, not `^\\s{N}` and not "anywhere in the block". A key nested
    one level deeper belongs to some other mapping (a step's `env:` may legally
    hold a variable named `if`), and a key higher up belongs to the parent. Both
    directions matter: the first is a false alarm, the second is the silent miss
    that lets a disable hide inside the block.

    Never hardcode the column — DERIVE it from the construct you are inspecting.
    Dedenting a whole `steps:` list by 2 is valid YAML (a block sequence may sit
    at its parent key's indent) and a cosmetic diff, and it walks every step key
    out from under a fixed `^\\s{8}` anchor with the suite green.

    Introduced for #404's `workflow_level_disables`; shared here so the
    required-graph guard does not re-derive it."""
    out = []
    for raw in block.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if (len(raw) - len(raw.lstrip())) != col:
            continue
        m = _KEY_LINE_RE.match(raw)
        if m:
            out.append(m.group("dq") or m.group("sq") or m.group("bare"))
    return out


def job_block(text: str, job_key: str):
    """The block of the top-level job `job_key`, or None if not found uniquely.

    Bounded by INDENTATION (the first later line at 2 columns or less ends it),
    not by "the next `  <key>:`" — a bound that reads correct and breaks on the
    last job in a file. The header is matched bare or quoted, and comment lines
    cannot open a block, so a `#  scan:` decoy neither shadows the real job nor
    invents one.

    Returns None rather than guessing when the key appears zero or many times, so
    callers can fail CLOSED."""
    lines = text.splitlines()
    pat = re.compile(rf"^  {yaml_key_pattern(job_key)}\s*:\s*(?:#.*)?$")
    starts = [i for i, ln in enumerate(lines) if pat.match(strip_inline_comment(ln))]
    if len(starts) != 1:
        return None
    start = starts[0]
    out = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= 2:
            break
        out.append(line)
    return "\n".join(out)


def desired_contexts(script_text: str = None):
    """The required status-check names codified in `sync-repo-protection.sh`.

    That script is the repo's source of truth for branch protection and is itself
    pinned against live drift by `test_ci_branch_protection_codified.py`, so
    reading it keeps ONE source rather than a second hand-maintained list that
    could disagree with the real gate. Returns None when it cannot be parsed, so
    callers fail closed instead of proceeding on an empty set.

    Lives here rather than in one guard because more than one guard needs to know
    what the required checks are, and the second copy is where they drift apart —
    the class this module exists to end (#391/#393/#394). Reads the real script
    by default; pass `script_text` to test against a mutated copy."""
    if script_text is None:
        if not PROTECTION_SCRIPT.is_file():
            return None
        script_text = PROTECTION_SCRIPT.read_text(encoding="utf-8")
    m = re.search(
        r"""^\s*DESIRED_CONTEXTS=(['"])(?P<json>\[.*?\])\1""", script_text, re.M
    )
    if not m:
        return None
    try:
        value = json.loads(m.group("json"))
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, list) else None


def job_display_name(block: str, job_key: str) -> str:
    """A job's rendered check name: its `name:` value, else the job key itself —
    which is what GitHub uses, and what branch protection matches on.

    The `name:` key is read at the job's own indent column so a step's `name:`
    (deeper) cannot be mistaken for the job's."""
    body = [ln for ln in block.splitlines()[1:] if ln.strip()]
    if not body:
        return job_key
    col = min(len(ln) - len(ln.lstrip()) for ln in body)
    pat = re.compile(rf"^ {{{col}}}{yaml_key_pattern('name')}\s*:\s*(.+?)\s*$")
    for raw in block.splitlines()[1:]:
        m = pat.match(strip_inline_comment(raw))
        if m:
            return m.group(1).strip("\"'")
    return job_key


def required_aggregators(texts: dict):
    """`{filename: job_key}` for every job whose DISPLAY NAME is a codified
    required status check, plus fail-closed problems.

    Returns `(mapping, problems)`. A required context that resolves to zero or
    many jobs is a problem, not a silent skip: a guard walking an empty set of
    aggregators passes vacuously, which is exactly how one goes quietly dead."""
    contexts = desired_contexts()
    if not contexts:
        return {}, ["could not parse DESIRED_CONTEXTS from the protection script"]
    index = {}
    problems = []
    for fname, text in sorted(texts.items()):
        for key in top_level_jobs(text):
            block = job_block(text, key)
            if block is None:
                continue
            index.setdefault(job_display_name(block, key), []).append((fname, key))
    out = {}
    for ctx in contexts:
        hits = index.get(ctx, [])
        if len(hits) != 1:
            problems.append(
                f"required check {ctx!r} resolves to {len(hits)} jobs {hits} — "
                "a guard scoped by this mapping would run on the wrong file or "
                "on nothing at all"
            )
            continue
        fname, key = hits[0]
        out[fname] = key
    return out, problems


def job_needs(block: str) -> list:
    """The jobs listed under a job block's own `needs:` key, block- or flow-style.

    Scoped to the `needs:` sub-block at the job's key column, so a `- name` list
    item elsewhere in the job (a matrix entry, a step input) cannot masquerade as
    a dependency — nor mask one that was dropped."""
    lines = block.splitlines()
    if len(lines) < 2:
        return []
    body = [ln for ln in lines[1:] if ln.strip()]
    if not body:
        return []
    col = min(len(ln) - len(ln.lstrip()) for ln in body)
    needs, in_needs = [], False
    key_re = re.compile(rf"^ {{{col}}}{yaml_key_pattern('needs')}\s*:\s*(.*)$")
    for raw in lines[1:]:
        line = strip_inline_comment(raw)
        m = key_re.match(line)
        if m:
            rest = m.group(1).strip()
            if rest.startswith("["):
                needs += re.findall(r"[A-Za-z0-9_.-]+", rest)
                in_needs = False
            elif rest:
                needs.append(rest.strip("\"'"))
                in_needs = False
            else:
                in_needs = True
            continue
        if in_needs:
            item = re.match(r"^\s+-\s*(.+?)\s*$", line)
            if item:
                needs.append(item.group(1).strip("\"'"))
            elif line.strip():
                in_needs = False
    return needs


def apply_mutation(text: str, old: str, new: str, *, count: int = 1) -> str:
    """`text` with `old` replaced by `new`, REFUSING to return an unchanged copy.

    Every mutation self-test rests on a fixture that must genuinely disable the
    control, and a fixture that quietly fails to apply turns the test into a
    tautology: the guard passes, the author reads "not caught", and either a real
    gap is missed or a correct guard gets "fixed".

    That is not hypothetical. The 2026-08-10 audit produced FIVE wrong probes,
    all of this one shape:

    1. a bash `case` arm moved to just BEFORE the `*)` catch-all — still
       perfectly reachable, so the guard was right to stay green;
    2. a section HEADER edited instead of the entry beneath it;
    3. a `job_block` case written only for end-of-file, where the discriminating
       shape is a following TOP-LEVEL key;
    4. `if: always()` deleted from a gate whose explanatory COMMENTS quote it
       verbatim — the repo's own comment-evasion class, biting the fixture
       instead of the guard;
    5. text injected onto a TestCase class that `setUpClass` then overwrote from
       disk, so the assertion ran against the unmutated real file.

    This helper closes shapes 2 and 5 mechanically (the substring must be present
    and the result must differ). Shapes 1, 3 and 4 are semantic — whether the
    edit disables the CONTROL, not merely whether it changed bytes — and no
    helper can decide them; use `assert_disables` for those, and state in the
    test why the mutant is really broken.

    Raises AssertionError rather than returning, so a stale fixture fails at the
    point of the mistake instead of surfacing as a confusing downstream pass.

    For a fixture whose target is a REGION rather than a substring (a whole
    `if … fi` block, the inside of a quoted argument), use
    `apply_regex_mutation` — not bare `re.sub`, which no-ops on a miss exactly
    like `str.replace`."""
    if old not in text:
        raise AssertionError(
            f"mutation fixture is stale: {old!r} not found in the target text — "
            "the file changed under the test, so this case proves nothing"
        )
    out = text.replace(old, new, count)
    if out == text:
        raise AssertionError(f"mutation {old!r} -> {new!r} left the text unchanged")
    return out


def apply_regex_mutation(text: str, pattern: str, repl: str, *, count: int = 1, flags: int = 0) -> str:
    """`apply_mutation` for fixtures whose target is a REGION, not a substring.

    Some mutations cannot be expressed as a literal: deleting a whole `if … fi`
    block, or rewriting the contents of a quoted argument, needs a pattern. The
    fixtures that did so called `re.sub` directly and so opted out of every check
    `apply_mutation` exists to provide — and `re.sub` fails the same silent way
    `str.replace` does, returning the input unchanged when nothing matched.

    Same two mechanical checks (the pattern must match; the result must differ),
    plus one the literal API does not need:

    **The match must not be ambiguous.** With a substring you can eyeball where it
    occurs; with a pattern you cannot, and this repo has already executed a
    stranger's `run:` body because a greedy regex matched more than its author
    believed (`test_ci_security_gate_behaviour`'s prototype started
    `python3 -m http.server`). So more matches than `count` is an error rather
    than a silent first-wins: narrow the pattern, or raise `count` deliberately.
    `count=0` means "every match" (`re.sub`'s own convention) and skips that
    check.

    It cannot check that the pattern matched the region you MEANT — that is the
    same semantic limit `apply_mutation` documents. Read the mutant."""
    matches = list(re.finditer(pattern, text, flags))
    if not matches:
        raise AssertionError(
            f"mutation fixture is stale: pattern {pattern!r} matched nothing in the "
            "target text — the file changed under the test, so this case proves nothing"
        )
    if count > 0 and len(matches) > count:
        raise AssertionError(
            f"pattern {pattern!r} matched {len(matches)} times but count={count} — "
            "refusing to guess which occurrence the fixture meant. Narrow the "
            "pattern, or pass the count you intend (0 for all)."
        )
    out = re.sub(pattern, repl, text, count=count, flags=flags)
    if out == text:
        raise AssertionError(f"mutation {pattern!r} -> {repl!r} left the text unchanged")
    return out


def assert_disables(detector, clean_text: str, mutant_text: str, label: str = ""):
    """Assert `detector` is quiet on `clean_text` and fires on `mutant_text`.

    Pins BOTH directions in one place, because either alone is satisfiable by a
    broken detector: one that always fires passes the mutant half, and one that
    never fires passes the clean half. Returns the mutant findings so a caller
    can assert on their content."""
    where = f" [{label}]" if label else ""
    clean = detector(clean_text)
    if clean:
        raise AssertionError(f"detector fired on the CLEAN text{where}: {clean!r}")
    found = detector(mutant_text)
    if not found:
        raise AssertionError(
            f"detector did NOT fire on the mutant{where} — either the guard has a "
            "gap, or the mutation does not actually disable the control. Check the "
            "SECOND possibility first (see apply_mutation)."
        )
    return found
