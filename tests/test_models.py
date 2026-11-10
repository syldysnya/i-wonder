"""Tests for auditor.models."""

from __future__ import annotations

import unittest

from auditor.models import Severity


class SeverityTest(unittest.TestCase):
    def test_sorting_puts_most_severe_first(self) -> None:
        worst_first = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        shuffled = [worst_first[i] for i in (2, 0, 4, 1, 3)]
        self.assertEqual(sorted(shuffled, reverse=True), worst_first)


if __name__ == "__main__":
    unittest.main()
