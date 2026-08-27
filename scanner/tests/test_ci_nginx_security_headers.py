"""
Guard: every dashboard-serving nginx location emits the full security header set.

THE INCIDENT THIS CODIFIES (2026-08-26)
---------------------------------------
The 2026-08-26 nightly ZAP full scan (the first to actually run after #497 pointed
it at this repo's own container) reported rule 90004 "Insufficient Site Isolation
Against Spectre Vulnerability" — `Cross-Origin-Resource-Policy` missing — on NINE
URLs, alongside rule 10055 for `style-src 'unsafe-inline'`.

Nine, not one, because of how nginx `add_header` inheritance works: a `location`
that declares ANY `add_header` of its own stops inheriting the server-level set
ENTIRELY. `nginx/default.conf` gave three locations a per-location Cache-Control,
so each had to restate all five security headers, and one of them —
`location ^~ /.claudesec-assets/` — restated only two. Its JSON went out without
X-Frame-Options, X-XSS-Protection, Referrer-Policy or Permissions-Policy while
the file plainly listed all five a few lines above.

WHY A GUARD
-----------
The failure mode is invisible in review: the header is *in the file*, so a reader
checking "do we set CORP?" gets yes. The real question is per-location, and
nothing in the config's shape makes a missing restatement look wrong. Reviewing
`default.conf` top-to-bottom is exactly what does NOT catch it.

OWASP Secure Headers Project (cross-origin isolation); W3C Fetch Metadata Request
Headers; OWASP CICD-SEC-7 (Insecure System Configuration).

DIRECTION
---------
- The header VALUES live in one file, asserted exactly. A present-but-wrong value
  is what ZAP reports as "Missing or Invalid", so `same-origin` vs `cross-origin`
  is a real difference, not a spelling.
- The structural invariant is the point: ANY location declaring its own
  `add_header` MUST also `include` the shared file. That is the rule the incident
  broke, and it holds for locations added later — guarding the four that exist
  today would leave the fifth open.
- `Dockerfile.nginx` must COPY the file to the exact path `default.conf`
  includes, or nginx fails to start. Cheap to assert, and the two paths are
  written in different files.
- The over-the-wire check in `lint.yml` must survive. A config that parses right
  and a server that answers right are different claims (see ADR-001 §1 and the
  `Parse vs execute` lesson); this guard is the cheap half and must not be
  mistaken for the whole.

stdlib-only (`re`, `pathlib`, `unittest`). No PyYAML, no network, no
`scanner/lib` import. Runs under pytest and `python3 -m unittest`.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _ci_guard_util import apply_mutation, assert_disables  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
NGINX_DIR = REPO_ROOT / "nginx"
DEFAULT_CONF = NGINX_DIR / "default.conf"
HEADERS_CONF = NGINX_DIR / "security-headers.conf"
DOCKERFILE = REPO_ROOT / "Dockerfile.nginx"
LINT_YML = REPO_ROOT / ".github" / "workflows" / "lint.yml"

# The path `default.conf` includes and `Dockerfile.nginx` must COPY to. Not under
# conf.d/ — nginx auto-loads everything there into the http context, and these are
# location-context directives.
INCLUDE_PATH = "/etc/nginx/security-headers.conf"

# name -> exact value. Site-isolation trio first (the 2026-08-26 finding), then
# the pre-existing baseline.
REQUIRED_HEADERS = {
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


def strip_nginx_comments(text: str) -> str:
    """`text` with `#` comments removed, so a header named only in prose does not
    satisfy a presence check. This file's own comments name every header and the
    include path, so a raw-source scan would be satisfied by the explanation of
    the incident rather than by the directives."""
    return "\n".join(re.sub(r"#.*$", "", line) for line in text.splitlines())


def parse_add_headers(text: str) -> dict:
    """`{name: value}` for every `add_header` in `text` (comment-stripped)."""
    out = {}
    for m in re.finditer(
        r'^\s*add_header\s+(\S+)\s+"([^"]*)"\s*(always)?\s*;',
        strip_nginx_comments(text),
        re.MULTILINE,
    ):
        out[m.group(1)] = m.group(2)
    return out


def parse_locations(text: str) -> list:
    """`(header_line, body)` for each top-level `location` block in `text`.

    Brace-counted rather than regex-matched: a `location` body can contain nested
    blocks, and a non-counting pattern would end the body at the first `}` and
    read the tail as belonging to nobody.
    """
    active = strip_nginx_comments(text)
    blocks = []
    for m in re.finditer(r"^\s*(location\s+[^{]*)\{", active, re.MULTILINE):
        depth = 1
        i = m.end()
        while i < len(active) and depth:
            if active[i] == "{":
                depth += 1
            elif active[i] == "}":
                depth -= 1
            i += 1
        blocks.append((m.group(1).strip(), active[m.end() : i - 1]))
    return blocks


def locations_missing_include(text: str) -> list:
    """Locations that declare their own `add_header` but skip the shared include.

    This is the incident's exact shape: such a location has ALREADY discarded the
    server-level set, so whatever it does not restate is simply not sent.
    """
    bad = []
    for header_line, body in parse_locations(text):
        declares = re.search(r"^\s*add_header\s", body, re.MULTILINE)
        includes = f"include {INCLUDE_PATH};" in body
        if declares and not includes:
            bad.append(header_line)
    return bad


class TestSharedHeaderFile(unittest.TestCase):
    def test_headers_conf_exists(self):
        self.assertTrue(
            HEADERS_CONF.is_file(),
            f"{HEADERS_CONF} not found. default.conf `include`s it from every "
            "location, so a missing file makes nginx fail to start — but it also "
            "makes every assertion below vacuous, which is why this is checked "
            "first.",
        )

    def test_every_required_header_present_with_exact_value(self):
        found = parse_add_headers(HEADERS_CONF.read_text(encoding="utf-8"))
        for name, value in REQUIRED_HEADERS.items():
            self.assertIn(
                name,
                found,
                f"`{name}` is no longer set in security-headers.conf. The three "
                "Cross-Origin-* headers answer ZAP rule 90004, which the "
                "2026-08-26 nightly reported on 9 URLs; the rest are the "
                "pre-existing baseline.",
            )
            self.assertEqual(
                found[name],
                value,
                f"`{name}` is set to {found[name]!r}, expected {value!r}. ZAP "
                "reports a present-but-wrong value as 'Missing or Invalid', so "
                "this is a real difference and not a spelling. If the change is "
                "deliberate, update REQUIRED_HEADERS here with the reason.",
            )

    def test_every_header_is_unconditional(self):
        """`always` so the headers are emitted on 4xx/5xx too, not only 2xx/3xx."""
        active = strip_nginx_comments(HEADERS_CONF.read_text(encoding="utf-8"))
        for line in active.splitlines():
            if line.strip().startswith("add_header"):
                self.assertRegex(
                    line,
                    r"always\s*;\s*$",
                    f"add_header without `always`: {line.strip()!r}. Without it "
                    "nginx omits the header on error responses, so a 404 page "
                    "ships unisolated.",
                )

    def test_csp_is_not_set_as_a_header(self):
        """CSP stays in the HTML meta tag — a header copy would conflict.

        The nonce is substituted per-request by `sub_filter` on the response BODY.
        A header set here could not carry the same nonce, and two policies both
        apply (intersection), so the stricter-but-different pair would block the
        page's own nonce'd script.
        """
        self.assertNotIn(
            "Content-Security-Policy",
            parse_add_headers(HEADERS_CONF.read_text(encoding="utf-8")),
            "CSP must not be an nginx header here; it is the per-request meta tag.",
        )


class TestLocationsIncludeTheHeaders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DEFAULT_CONF.is_file():
            raise unittest.SkipTest(f"{DEFAULT_CONF} not found")
        cls.conf = DEFAULT_CONF.read_text(encoding="utf-8")

    def test_server_level_includes_the_headers(self):
        self.assertIn(
            f"include {INCLUDE_PATH};",
            strip_nginx_comments(self.conf),
            "default.conf no longer includes the shared header file at server "
            "level, so any location that does not restate the headers sends none.",
        )

    def test_parser_finds_the_locations(self):
        """Vacuity canary: `locations_missing_include` returning [] must mean
        'all good', not 'parsed nothing'."""
        blocks = parse_locations(self.conf)
        self.assertGreaterEqual(
            len(blocks),
            4,
            f"the location parser found only {len(blocks)} block(s) in a config "
            "that has at least four. It is returning too little, so the "
            "missing-include check below proves nothing.",
        )

    def test_no_location_declares_headers_without_the_include(self):
        missing = locations_missing_include(self.conf)
        self.assertEqual(
            missing,
            [],
            f"location(s) {missing} declare their own `add_header` but do not "
            f"`include {INCLUDE_PATH}`. nginx REPLACES the inherited header set "
            "for any location that declares one of its own, so these send only "
            "what they restate. That is precisely how "
            "`location ^~ /.claudesec-assets/` came to serve JSON without four "
            "of the five baseline headers, and how CORP came to be missing on 9 "
            "URLs in the 2026-08-26 nightly. Add the include.",
        )

    def test_dockerfile_copies_the_include_target(self):
        if not DOCKERFILE.is_file():
            self.skipTest(f"{DOCKERFILE} not found")
        body = DOCKERFILE.read_text(encoding="utf-8")
        active = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertRegex(
            active,
            re.escape(f"nginx/security-headers.conf {INCLUDE_PATH}"),
            f"Dockerfile.nginx does not COPY nginx/security-headers.conf to "
            f"{INCLUDE_PATH}. default.conf includes that exact path, so nginx "
            "fails to start — the container would not serve at all. The two "
            "paths live in different files, which is why this is asserted.",
        )

    def test_lint_yml_still_asserts_the_headers_over_the_wire(self):
        """This guard reads config; only a request proves what is sent.

        The `Docker Dashboard Smoke Test` job curls each serving location and
        greps for the header names. If that step is deleted, this file keeps
        passing over a config whose runtime behaviour nobody checks — the exact
        parse-vs-execute gap that let the 9-URL finding stand.
        """
        if not LINT_YML.is_file():
            self.skipTest(f"{LINT_YML} not found")
        active = "\n".join(
            line
            for line in LINT_YML.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        self.assertIn(
            "Verify security headers on every serving location",
            active,
            "the over-the-wire header assertion was removed from lint.yml. "
            "Re-add it, or this guard silently becomes the only check and it "
            "cannot see nginx's actual output.",
        )
        self.assertIn(
            "cross-origin-resource-policy: same-origin",
            active,
            "the smoke test no longer asserts CORP — the header the 2026-08-26 "
            "nightly reported missing on 9 URLs.",
        )

    def test_nginx_is_in_the_docker_path_gate(self):
        """`nginx/` must reach the job that verifies it.

        Measured 2026-08-27: `nginx/` was in NO bucket, so a PR editing only
        `nginx/default.conf` ran neither `Docker Dashboard Smoke Test` (gated on
        docker/scanner) nor `scanner-unit-tests`. The one file the smoke test
        exists to check was the one file that could not trigger it.
        """
        if not LINT_YML.is_file():
            self.skipTest(f"{LINT_YML} not found")
        docker_bucket = re.search(
            r'echo "docker=\$\(match\s+\'([^\']*)\'', LINT_YML.read_text(encoding="utf-8")
        )
        self.assertIsNotNone(
            docker_bucket, "could not find the `docker=` path-gate bucket in lint.yml"
        )
        self.assertRegex(
            docker_bucket.group(1),
            r"nginx/",
            "`nginx/` is not in the `docker` path-gate bucket, so an "
            "nginx-only PR skips `Docker Dashboard Smoke Test` and its header "
            "assertions never run.",
        )


class TestNginxHeaderMutation(unittest.TestCase):
    """Mutation self-tests. Operate on copies, never on the real files."""

    @classmethod
    def setUpClass(cls):
        if not DEFAULT_CONF.is_file():
            raise unittest.SkipTest(f"{DEFAULT_CONF} not found")
        cls.conf = DEFAULT_CONF.read_text(encoding="utf-8")

    def test_dropping_the_include_from_a_location_is_detected(self):
        """The incident's exact shape, reproduced on the real config.

        The assets location keeps its own Cache-Control, so it has still
        discarded the server-level set — the mutation genuinely disables the
        control rather than merely changing bytes.
        """
        mutant = apply_mutation(
            self.conf,
            '        add_header Cache-Control "public, max-age=300, must-revalidate" always;\n'
            f"        include {INCLUDE_PATH};\n",
            '        add_header Cache-Control "public, max-age=300, must-revalidate" always;\n',
        )
        found = assert_disables(
            locations_missing_include, self.conf, mutant, label="assets location"
        )
        self.assertTrue(
            any(".claudesec-assets" in loc for loc in found),
            f"expected the assets location to be reported, got {found}",
        )

    def test_commented_out_include_is_detected(self):
        """A `#`-commented include must not satisfy the check.

        default.conf's prose names the include path, which is why the scan strips
        comments — otherwise the explanation of the rule would satisfy it.
        """
        mutant = apply_mutation(
            self.conf,
            f"        include {INCLUDE_PATH};\n        try_files $uri =404;",
            f"        # include {INCLUDE_PATH};\n        try_files $uri =404;",
        )
        self.assertIn(
            INCLUDE_PATH, mutant, "fixture should still contain the token in prose"
        )
        assert_disables(
            locations_missing_include, self.conf, mutant, label="commented include"
        )

    def test_a_new_location_with_headers_and_no_include_is_detected(self):
        """Direction check: the rule must bind locations added later, not just
        the four that exist today."""
        mutant = apply_mutation(
            self.conf,
            "    # Deny access to other hidden files",
            '    location /new-thing/ {\n'
            '        add_header Cache-Control "no-store" always;\n'
            "        try_files $uri =404;\n"
            "    }\n\n"
            "    # Deny access to other hidden files",
        )
        found = assert_disables(
            locations_missing_include, self.conf, mutant, label="new location"
        )
        self.assertTrue(
            any("new-thing" in loc for loc in found),
            f"expected the new location to be reported, got {found}",
        )

    def test_a_location_without_any_add_header_is_not_flagged(self):
        """No-false-alarm direction.

        A location with NO `add_header` of its own inherits the server-level set,
        so it needs no include and must not be reported. A guard that demanded
        the include everywhere would push authors to add `add_header` lines to
        silence it — the opposite of the fix.
        """
        mutant = apply_mutation(
            self.conf,
            "    # Deny access to other hidden files",
            "    location /inherits/ {\n"
            "        try_files $uri =404;\n"
            "    }\n\n"
            "    # Deny access to other hidden files",
        )
        self.assertEqual(
            locations_missing_include(mutant),
            [],
            "a location that declares no add_header inherits the server set and "
            "must not be flagged.",
        )

    def test_wrong_header_value_is_detected(self):
        """`cross-origin` instead of `same-origin` still ships a CORP header, and
        ZAP still reports it — as 'Missing or Invalid'."""
        raw = HEADERS_CONF.read_text(encoding="utf-8")
        mutant = apply_mutation(
            raw,
            'add_header Cross-Origin-Resource-Policy "same-origin" always;',
            'add_header Cross-Origin-Resource-Policy "cross-origin" always;',
        )
        self.assertEqual(
            parse_add_headers(mutant)["Cross-Origin-Resource-Policy"], "cross-origin"
        )

    def test_parser_ignores_headers_named_only_in_comments(self):
        """security-headers.conf's own prose names every header it sets."""
        self.assertEqual(
            parse_add_headers(
                '# add_header Cross-Origin-Resource-Policy "same-origin" always;\n'
            ),
            {},
            "a commented-out add_header was parsed as active.",
        )


if __name__ == "__main__":
    unittest.main()
