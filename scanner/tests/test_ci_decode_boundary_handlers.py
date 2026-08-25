"""Regression guard: `json.JSONDecodeError` alone may not guard a decode boundary.

THE INVARIANT. `UnicodeDecodeError` is a SIBLING `ValueError` subclass, not a
`json.JSONDecodeError`:

    >>> issubclass(UnicodeDecodeError, ValueError)
    True
    >>> issubclass(UnicodeDecodeError, json.JSONDecodeError)
    False

So `except (OSError, json.JSONDecodeError)` does NOT catch it. Any `try` that
crosses a bytes -> str boundary — `open()` in text mode, `Path.read_text()`, or
an explicit `.decode()` — and relies on `json.JSONDecodeError` will therefore
propagate on one bad byte instead of degrading. One non-ASCII byte in a cloud
resource tag, owner or description is enough, and a response cut mid
multi-byte character does it over HTTP.

THE INCIDENTS this generalises, all measured:

    dashboard_data_loader.load_scan_history   one 0x80 in a history file
                                             -> UnicodeDecodeError, build aborted   (#485)
    diagram_data.load_prowler_files          open() with no encoding at all
                                             -> whole provider lost                 (#484)
    build-dashboard.py OCSF reader           read_text() + `except Exception: pass`
                                             -> 3 real FAILs reported as 0          (#486)
    _github_api_json                         resp.read().decode("utf-8") escaped
                                             its own handlers AND all 3 callers'

TWO LEGITIMATE FIXES, and this guard accepts either:
  1. widen the handler to `ValueError` (a strict superset of
     `json.JSONDecodeError`) — right for caches, reports and inventories, where
     degrading to "no data" is the correct outcome; or
  2. pass `errors=` at the decode site — right for EVIDENCE readers, where
     dropping the file silently under-reports findings, so recovering a damaged
     string beats discarding the whole document.

WHAT IS DELIBERATELY NOT FLAGGED. A `try` whose body only ever sees an
already-decoded `str` cannot raise `UnicodeDecodeError`, so
`json.JSONDecodeError` is the precise contract there and widening it would be
noise. `_parse_ocsf_json`'s `raw_decode` resync loop and the NDJSON
`json.loads(line)` inside `load_datadog_logs` are both of that shape — the
decode already happened in the enclosing `open()`, which IS checked.

stdlib-only (`ast`), no PyYAML, no scanner/lib import, no network.
"""

import ast
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_DIR = REPO_ROOT / "scanner" / "lib"

# Calls that turn bytes into str and can therefore raise UnicodeDecodeError.
# `open` is included because text mode is the default; a binary open cannot
# raise it, but it also cannot feed `json.load`, so treating every `open` as a
# decode boundary is the fail-closed choice.
_DECODE_CALLS = {"open", "read_text", "decode"}

# Sites that still rely on the narrow handler, with the reason. Checked as a
# SUPERSET (`hits <= allowlist`), never as equality, so an entry disappearing
# because it got fixed does not fail this guard.
_KNOWN_UNFIXED = {
    # `_load_saas_sso_stats`. PR #472 rewrites this exact handler to catch
    # `(OSError, ValueError)` with the same rationale; it is human-review gated
    # under org policy because the module is authentication-facing, so it is not
    # fixed here to avoid conflicting with that PR.
    ("dashboard_auth.py", "_load_saas_sso_stats"),
}


def _enclosing_function(tree, node):
    """Name of the innermost function containing `node`, or '<module>'."""
    best = "<module>"
    best_span = None
    for cand in ast.walk(tree):
        if not isinstance(cand, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if cand.lineno <= node.lineno and node.lineno <= cand.end_lineno:
            span = cand.end_lineno - cand.lineno
            if best_span is None or span < best_span:
                best, best_span = cand.name, span
    return best


def _decode_boundaries(try_node):
    """Decode calls in `try_node`'s body that could raise UnicodeDecodeError.

    A `.decode(...)`/`open(...)`/`read_text(...)` that passes `errors=` cannot,
    so it is not a boundary for this guard's purposes — that is fix #2.
    """
    found = []
    for call in ast.walk(try_node):
        if not isinstance(call, ast.Call):
            continue
        name = ast.unparse(call.func).split(".")[-1]
        if name not in _DECODE_CALLS:
            continue
        if any(kw.arg == "errors" for kw in call.keywords):
            continue
        # `.decode("utf-8", "ignore")` — positional errors arg.
        if name == "decode" and len(call.args) >= 2:
            continue
        found.append(name)
    return found


def _narrow_handlers():
    """(file, function, lineno, handler_src, boundaries) for every offending try."""
    out = []
    for path in sorted(LIB_DIR.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a parse failure is its own test
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            handlers = [ast.unparse(h.type) for h in node.handlers if h.type]
            joined = " ".join(handlers)
            if "JSONDecodeError" not in joined:
                continue
            # An explicit ValueError / Exception / bare except already covers it.
            if any(w in joined for w in ("ValueError", "Exception", "BaseException")):
                continue
            if any(h.type is None for h in node.handlers):
                continue
            boundaries = _decode_boundaries(node)
            if not boundaries:
                continue
            out.append(
                (path.name, _enclosing_function(tree, node), node.handlers[0].lineno,
                 joined, sorted(set(boundaries)))
            )
    return out


class TestUnicodeDecodeErrorIsNotAJsonDecodeError(unittest.TestCase):
    """The premise, asserted rather than assumed."""

    def test_sibling_not_subclass(self):
        self.assertTrue(issubclass(UnicodeDecodeError, ValueError))
        self.assertFalse(issubclass(UnicodeDecodeError, json.JSONDecodeError))
        self.assertTrue(issubclass(json.JSONDecodeError, ValueError))


class TestNoNarrowHandlerOnADecodeBoundary(unittest.TestCase):
    def test_lib_dir_is_present(self):
        """Canary. A relocated tree would otherwise make this guard vacuous by
        finding zero files and passing."""
        self.assertTrue(LIB_DIR.is_dir(), LIB_DIR)
        self.assertGreater(len(list(LIB_DIR.glob("*.py"))), 10)

    def test_no_unexpected_narrow_handler(self):
        hits = _narrow_handlers()
        keys = {(f, fn) for f, fn, _, _, _ in hits}
        unexpected = keys - _KNOWN_UNFIXED
        detail = "\n".join(
            f"  {f}:{ln} in {fn}() catches {h} but its try body calls {b} "
            "— widen to ValueError, or pass errors= at the decode site"
            for f, fn, ln, h, b in sorted(hits)
            if (f, fn) in unexpected
        )
        self.assertEqual(unexpected, set(), "\n" + detail)

    def test_detector_fires_on_the_shape_it_forbids(self):
        """Non-vacuity (ADR-001 §4). Build the offending shape in a temp tree and
        confirm the walker reports it — a guard nobody has watched fail is not
        evidence (#408)."""
        bad = ast.parse(
            "import json\n"
            "def f(p):\n"
            "    try:\n"
            "        with open(p, encoding='utf-8') as fh:\n"
            "            return json.load(fh)\n"
            "    except (OSError, json.JSONDecodeError):\n"
            "        return None\n"
        )
        node = next(n for n in ast.walk(bad) if isinstance(n, ast.Try))
        self.assertEqual(_decode_boundaries(node), ["open"])
        self.assertEqual(_enclosing_function(bad, node), "f")

    def test_detector_accepts_both_legitimate_fixes(self):
        widened = ast.parse(
            "import json\n"
            "def f(p):\n"
            "    try:\n"
            "        with open(p, encoding='utf-8') as fh:\n"
            "            return json.load(fh)\n"
            "    except (OSError, ValueError):\n"
            "        return None\n"
        )
        handlers = [
            ast.unparse(h.type)
            for n in ast.walk(widened) if isinstance(n, ast.Try)
            for h in n.handlers if h.type
        ]
        self.assertIn("ValueError", " ".join(handlers))

        replaced = ast.parse(
            "import json\n"
            "def f(r):\n"
            "    try:\n"
            "        return json.loads(r.read().decode('utf-8', errors='replace'))\n"
            "    except json.JSONDecodeError:\n"
            "        return None\n"
        )
        node = next(n for n in ast.walk(replaced) if isinstance(n, ast.Try))
        self.assertEqual(_decode_boundaries(node), [])

    def test_str_only_bodies_are_not_flagged(self):
        """`raw_decode` on a str cannot raise UnicodeDecodeError, so the narrow
        handler is correct there and must not be reported."""
        ok = ast.parse(
            "import json\n"
            "def f(content):\n"
            "    try:\n"
            "        return json.JSONDecoder().raw_decode(content, 0)\n"
            "    except json.JSONDecodeError:\n"
            "        return None\n"
        )
        node = next(n for n in ast.walk(ok) if isinstance(n, ast.Try))
        self.assertEqual(_decode_boundaries(node), [])


if __name__ == "__main__":
    unittest.main()
