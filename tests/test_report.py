"""Tests for auditor.report."""

from __future__ import annotations

import json
import unittest

from auditor.audit import audit_all
from auditor.report import TEXT_WIDTH, render_json, render_text
from tests.configs import ASSIGNMENT_EXAMPLE, SAFE_CONFIG

POLICY = "Test policy."


class RenderTextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = render_text(audit_all([ASSIGNMENT_EXAMPLE, SAFE_CONFIG]), POLICY)

    def test_shows_policy_status_and_summary(self) -> None:
        self.assertIn("Policy:  Test policy.", self.text)
        self.assertIn("[FAIL] customer-script-01", self.text)
        self.assertIn("[PASS] safe-script", self.text)
        self.assertIn("No issues found.", self.text)
        self.assertIn("Summary: 1 FAIL, 0 REVIEW, 1 PASS", self.text)

    def test_every_finding_has_severity_reason_and_fix(self) -> None:
        self.assertIn("CRITICAL R1", self.text)
        self.assertEqual(self.text.count("Why:"), 5)
        self.assertEqual(self.text.count("Fix:"), 5)

    def test_lines_fit_the_width(self) -> None:
        for line in self.text.splitlines():
            self.assertLessEqual(len(line), TEXT_WIDTH, line)


class RenderJsonTest(unittest.TestCase):
    def test_is_valid_json_with_the_same_results(self) -> None:
        document = json.loads(render_json(audit_all([ASSIGNMENT_EXAMPLE]), POLICY))
        self.assertEqual(document["policy"], POLICY)
        self.assertEqual(document["summary"], {"FAIL": 1, "REVIEW": 0, "PASS": 0})
        container = document["containers"][0]
        self.assertEqual(container["status"], "FAIL")
        first = container["findings"][0]
        self.assertEqual(first["severity"], "CRITICAL")
        self.assertEqual(
            set(first), {"rule_id", "severity", "title", "reason", "fix", "sources"}
        )


if __name__ == "__main__":
    unittest.main()
