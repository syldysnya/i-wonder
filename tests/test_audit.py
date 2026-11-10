"""Tests for auditor.audit: the safe, unsafe and mixed cases from the assignment."""

from __future__ import annotations

import unittest

from auditor.audit import audit_all, audit_container
from auditor.models import Severity, Status
from tests.configs import ASSIGNMENT_EXAMPLE, SAFE_CONFIG, safe_config_with


class AuditContainerTest(unittest.TestCase):
    def test_safe_config_passes_with_no_findings(self) -> None:
        report = audit_container(SAFE_CONFIG, 1)
        self.assertEqual(report.status, Status.PASS)
        self.assertEqual(report.findings, ())
        self.assertEqual(report.name, "safe-script")

    def test_assignment_example_fails_on_all_five_rules(self) -> None:
        report = audit_container(ASSIGNMENT_EXAMPLE, 1)
        self.assertEqual(report.status, Status.FAIL)
        self.assertEqual(
            sorted(f.rule_id for f in report.findings), ["R1", "R2", "R3", "R4", "R5"]
        )

    def test_findings_are_sorted_worst_first(self) -> None:
        report = audit_container(ASSIGNMENT_EXAMPLE, 1)
        severities = [f.severity for f in report.findings]
        self.assertEqual(severities, sorted(severities, reverse=True))
        self.assertEqual(severities[0], Severity.CRITICAL)

    def test_only_a_writable_filesystem_needs_review(self) -> None:
        report = audit_container(safe_config_with(read_only_root_filesystem=False), 1)
        self.assertEqual(report.status, Status.REVIEW)

    def test_allowlisted_network_still_passes(self) -> None:
        config = safe_config_with(
            network_enabled=True, egress_allowlist=["api.weather.com"]
        )
        report = audit_container(config, 1)
        self.assertEqual(report.status, Status.PASS)
        self.assertEqual([f.rule_id for f in report.findings], ["R5-ok"])

    def test_non_object_entry_fails_closed(self) -> None:
        for entry in (42, "text", None, [SAFE_CONFIG]):
            with self.subTest(entry=entry):
                report = audit_container(entry, 3)
                self.assertEqual(report.status, Status.FAIL)
                self.assertEqual([f.rule_id for f in report.findings], ["V-shape"])
                self.assertEqual(report.name, "#3")

    def test_unnamed_container_gets_its_position_as_label(self) -> None:
        for name in (None, "", 7):
            with self.subTest(name=name):
                report = audit_container(safe_config_with(container_name=name), 2)
                self.assertEqual(report.name, "#2")

    def test_rules_can_be_swapped_for_another_set(self) -> None:
        report = audit_container(ASSIGNMENT_EXAMPLE, 1, rules=())
        self.assertEqual(report.status, Status.PASS)


class AuditAllTest(unittest.TestCase):
    def test_one_bad_entry_does_not_stop_the_others(self) -> None:
        reports = audit_all([SAFE_CONFIG, 42, ASSIGNMENT_EXAMPLE])
        self.assertEqual(
            [r.status for r in reports], [Status.PASS, Status.FAIL, Status.FAIL]
        )
        self.assertEqual(reports[1].name, "#2")


if __name__ == "__main__":
    unittest.main()
