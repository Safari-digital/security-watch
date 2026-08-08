#!/usr/bin/env python3
"""
Version-comparison tests -- the risky core of the correlation.

A wrong `True` invents an exposure; a wrong `False` hides one. The only
acceptable verdict under doubt is `None` (= needs review).

Run:  python watch/test_correlate.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from correlate import compare_versions, parse_version, version_in_range  # noqa: E402

CASES = [
    # (installed version, vulnerable range, expected)
    ("4.17.11", "< 4.17.21", True),
    ("4.17.21", "< 4.17.21", False),
    ("4.17.22", "< 4.17.21", False),
    ("1.26.0", "<= 1.26.0", True),
    ("1.26.1", "<= 1.26.0", False),
    ("5.0.2", "= 5.0.2", True),
    ("5.0.3", "= 5.0.2", False),

    # Two-sided ranges
    ("28.0.0", ">= 27.0.0-rc.0, < 29.0.0-rc.3", True),
    ("26.9.9", ">= 27.0.0-rc.0, < 29.0.0-rc.3", False),
    ("29.0.0", ">= 27.0.0-rc.0, < 29.0.0-rc.3", False),
    ("1.5.0", ">= 1.0.0, < 2.0.0", True),
    ("2.0.0", ">= 1.0.0, < 2.0.0", False),

    # Different component counts: 1.2 == 1.2.0
    ("1.2", "< 1.10", True),
    ("1.10", "< 1.2", False),
    ("1.2", "<= 1.2.0", True),

    # Prereleases: a release outranks its own prerelease
    ("1.0.0", "< 1.0.0", False),
    ("1.0.0-rc.1", "< 1.0.0", True),
    ("1.0.0-rc.2", ">= 1.0.0-rc.1, < 1.0.0", True),
    # Classic trap: lexically, 'rc.10' < 'rc.2'
    ("1.0.0-rc.10", ">= 1.0.0-rc.2, < 1.0.0", True),

    # Undeterminable -> None, never False
    ("pas-une-version", "< 1.0.0", None),
    ("1.0.0", "plage bizarre", None),
    ("1.0.0", "", None),
    (None, "< 1.0.0", None),
    ("1.0.0", "^1.0.0", None),
]

ORDER_CASES = [
    ("1.0.0", "1.0.1", -1),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.0", 0),
    ("1.0.0", "1.0", 0),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("1.0.0-rc.2", "1.0.0-rc.10", -1),
    ("2.0.0", "10.0.0", -1),
]


def main():
    failures = []

    for installed, vrange, expected in CASES:
        actual = version_in_range(installed, vrange)
        if actual is not expected:
            failures.append(
                f"version_in_range({installed!r}, {vrange!r}) = {actual!r}, attendu {expected!r}")

    for left, right, expected in ORDER_CASES:
        actual = compare_versions(parse_version(left), parse_version(right))
        if actual != expected:
            failures.append(
                f"compare_versions({left!r}, {right!r}) = {actual}, attendu {expected}")

    total = len(CASES) + len(ORDER_CASES)
    if failures:
        print(f"ECHEC : {len(failures)}/{total}")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK : {total}/{total} cas passent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
