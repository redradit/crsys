"""Run the whole CRSYS test suite.

    python tests/run_all.py            everything
    python tests/run_all.py -v         verbose
    python tests/run_all.py tamper     only modules matching "tamper"
"""

from __future__ import annotations

import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
for path in (HERE, os.path.dirname(HERE)):
    if path not in sys.path:
        sys.path.insert(0, path)

MODULES = [
    "test_keys",
    "test_kdf",
    "test_container",
    "test_tamper",
    "test_signing",
    "test_vectors",
    "test_fuzz",
    "test_cli",
    "test_gui",
]


def main(argv):
    verbosity = 2 if "-v" in argv else 1
    filters = [a for a in argv if not a.startswith("-")]
    modules = [m for m in MODULES if not filters or any(f in m for f in filters)]
    if not modules:
        print("no module matches %r" % filters)
        return 1

    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromName(m) for m in modules)

    print("CRSYS -- %d modules, %d tests" % (len(modules), suite.countTestCases()))
    start = time.perf_counter()
    result = unittest.TextTestRunner(verbosity=verbosity, buffer=False).run(suite)
    elapsed = time.perf_counter() - start

    print(
        "\n%s  %d tests in %.2fs (%d failures, %d errors)"
        % (
            "OK" if result.wasSuccessful() else "FAILED",
            result.testsRun,
            elapsed,
            len(result.failures),
            len(result.errors),
        )
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
