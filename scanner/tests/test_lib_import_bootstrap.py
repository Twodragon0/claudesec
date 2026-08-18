"""
Exercise the sibling-import bootstrap every `scanner/lib` module carries.

    _LIB_DIR = os.path.dirname(os.path.abspath(__file__))
    if _LIB_DIR not in sys.path:
        sys.path.insert(0, _LIB_DIR)

That `insert` is real production code — it is what lets `output.sh` load these
modules via importlib in a fresh interpreter, where `scanner/lib` is not on the
path. Under pytest it never ran: the first test to import anything from
`scanner/lib` puts the directory on `sys.path`, and every module loaded
afterwards takes the `if` as false.

Nine modules were each missing exactly that one line, which is most of the gap
between the measured 98.79% and the documented 99% floor. Marking them
`# pragma: no cover` would have been a fudge — the line executes in production.
So this drops the directory from `sys.path`, re-imports each module fresh, and
lets the branch run for real.

The path is restored afterwards, because leaving `scanner/lib` off `sys.path`
would break every later test that imports a sibling by bare name.
"""

import importlib.util
import os
import sys
import unittest

_LIB = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "lib"))

# Every module carrying the bootstrap. Kept explicit rather than globbed: a new
# module that adds the bootstrap should be a visible line in this list, and a
# glob would silently pick up modules that make network calls on import.
BOOTSTRAP_MODULES = [
    "dashboard_html_arch.py",
    "dashboard_html_audit_points.py",
    "dashboard_html_audit_sources.py",
    "dashboard_html_builders.py",
    "dashboard_html_compliance.py",
    "dashboard_html_helpers.py",
    "dashboard_html_network.py",
    "dashboard_html_owasp.py",
    "dashboard_html_sections.py",
]


class TestSiblingImportBootstrap(unittest.TestCase):
    def setUp(self):
        self._saved = list(sys.path)
        self.addCleanup(self._restore)

    def _restore(self):
        sys.path[:] = self._saved

    def _import_fresh(self, filename):
        name = "bootstrap_probe_" + filename.replace(".py", "")
        spec = importlib.util.spec_from_file_location(
            name, os.path.join(_LIB, filename)
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_each_module_puts_its_own_directory_on_the_path(self):
        for filename in BOOTSTRAP_MODULES:
            with self.subTest(module=filename):
                # Drop every spelling of the lib dir, so the guard's `not in`
                # is genuinely true and the insert executes.
                sys.path[:] = [
                    p for p in sys.path if os.path.normpath(p) != _LIB
                ]
                self.assertNotIn(_LIB, [os.path.normpath(p) for p in sys.path])
                self._import_fresh(filename)
                self.assertIn(
                    _LIB,
                    [os.path.normpath(p) for p in sys.path],
                    f"{filename} did not add its own directory to sys.path — "
                    "loading it from output.sh in a fresh interpreter would fail "
                    "on the first sibling import.",
                )

    def test_bootstrap_is_idempotent(self):
        # The guard exists so a repeated import does not grow sys.path without
        # bound. Importing twice with the directory already present must not
        # add a second copy.
        before = [os.path.normpath(p) for p in sys.path].count(_LIB)
        self._import_fresh(BOOTSTRAP_MODULES[0])
        self._import_fresh(BOOTSTRAP_MODULES[0])
        after = [os.path.normpath(p) for p in sys.path].count(_LIB)
        self.assertLessEqual(after, max(before, 1))

    def test_the_list_is_not_stale(self):
        # Non-vacuity: if a module were renamed away, the loop above would
        # silently test fewer things.
        for filename in BOOTSTRAP_MODULES:
            with self.subTest(module=filename):
                self.assertTrue(os.path.isfile(os.path.join(_LIB, filename)))


if __name__ == "__main__":
    unittest.main()
