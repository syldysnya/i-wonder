"""Tests for auditor.grading."""

from __future__ import annotations

import unittest

from auditor.grading import grade
from auditor.models import Finding, Severity, Status


def _finding(severity: Severity) -> Finding:
    return Finding("RX", severity, "title", "reason", "fix", ())


class GradeTest(unittest.TestCase):
    def test_no_findings_passes(self) -> None:
        self.assertEqual(grade([]), Status.PASS)

    def test_grade_follows_the_worst_finding(self) -> None:
        expected = {
            Severity.INFO: Status.PASS,
            Severity.LOW: Status.REVIEW,
            Severity.MEDIUM: Status.REVIEW,
            Severity.HIGH: Status.FAIL,
            Severity.CRITICAL: Status.FAIL,
        }
        for severity, status in expected.items():
            with self.subTest(severity=severity.name):
                findings = [_finding(Severity.INFO), _finding(severity)]
                self.assertEqual(grade(findings), status)

    def test_order_of_findings_does_not_matter(self) -> None:
        findings = [_finding(Severity.HIGH), _finding(Severity.LOW)]
        self.assertEqual(grade(findings), grade(list(reversed(findings))))


if __name__ == "__main__":
    unittest.main()
