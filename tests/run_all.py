"""Run the whole CRSYS test suite.

    python tests/run_all.py                  everything
    python tests/run_all.py -v               verbose
    python tests/run_all.py tamper           only modules matching "tamper"
    python tests/run_all.py -x streaming     everything except those modules

Every run reports the slowest tests. That is not decoration: CI failures on one
configuration have correlated with how long the job took rather than with any
code change, and a suite that cannot say where its time goes leaves you guessing
at exactly the moment you need a fact.
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
    "test_defensive",
    "test_signing",
    "test_streaming",
    "test_vectors",
    "test_fuzz",
    "test_cli",
    "test_gui",
]

SLOWEST_SHOWN = 8


class TimedResult(unittest.TextTestResult):
    """Records how long each test took, so the report can name the slow ones."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.durations: list = []
        self._started_at = None

    def startTest(self, test) -> None:
        self._started_at = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test) -> None:
        super().stopTest(test)
        if self._started_at is not None:
            self.durations.append((time.perf_counter() - self._started_at, str(test)))
            self._started_at = None


def _report_slowest(durations, total) -> None:
    if not durations:
        return
    ranked = sorted(durations, reverse=True)[:SLOWEST_SHOWN]
    print("\nslowest tests:")
    for seconds, name in ranked:
        share = (100.0 * seconds / total) if total else 0.0
        print("  %6.2fs  %4.1f%%  %s" % (seconds, share, name))


def main(argv):
    verbosity = 2 if "-v" in argv else 1

    excluded = []
    filters = []
    expecting_exclusion = False
    for arg in argv:
        if arg in ("-x", "--exclude"):
            expecting_exclusion = True
        elif arg.startswith("-"):
            continue
        elif expecting_exclusion:
            excluded.append(arg)
            expecting_exclusion = False
        else:
            filters.append(arg)

    modules = [m for m in MODULES if not filters or any(f in m for f in filters)]
    modules = [m for m in modules if not any(x in m for x in excluded)]
    if not modules:
        print("no module matches %r (excluding %r)" % (filters, excluded))
        return 1

    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromName(m) for m in modules)

    label = "CRSYS -- %d modules, %d tests" % (len(modules), suite.countTestCases())
    if excluded:
        label += "  (excluding %s)" % ", ".join(excluded)
    print(label)

    start = time.perf_counter()
    result = unittest.TextTestRunner(
        verbosity=verbosity, buffer=False, resultclass=TimedResult).run(suite)
    elapsed = time.perf_counter() - start

    _report_slowest(getattr(result, "durations", []), elapsed)

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
