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
    the trailing-comment form when scanning one `run:`/`uses:` line at a time."""
    return re.sub(r"\s+#.*$", "", line)


def top_level_jobs(text: str) -> list:
    """The job keys under a workflow's top-level `jobs:` map (2-space-indented
    `name:` lines), in document order. Stops at the dedent to the next top-level
    key, and strips trailing inline comments so `build:  # x` still matches.
    Returns a list; callers wrap in `set()` where set semantics are needed."""
    jobs, in_jobs = [], False
    for raw in text.splitlines():
        if re.match(r"^jobs:\s*$", raw):
            in_jobs = True
            continue
        if in_jobs:
            if re.match(r"^\S", raw):  # dedent back to a top-level key
                break
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", strip_inline_comment(raw))
            if m:
                jobs.append(m.group(1))
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
