"""Tests for auditor.rules.settings (R1–R3)."""

from __future__ import annotations

import unittest

from auditor.models import Severity
from auditor.rules.settings import SETTING_RULES, BoolSettingRule
from tests.configs import SAFE_CONFIG, safe_config_with, safe_config_without

RULES_BY_KEY = {rule.key: rule for rule in SETTING_RULES}

# key -> (rule id, unsafe value, expected severity), as documented in README.md.
EXPECTED = {
    "privileged": ("R1", True, Severity.CRITICAL),
    "run_as_root": ("R2", True, Severity.HIGH),
    "read_only_root_filesystem": ("R3", False, Severity.MEDIUM),
}


class BoolSettingRulesTest(unittest.TestCase):
    def test_each_required_setting_has_a_rule(self) -> None:
        self.assertEqual(set(RULES_BY_KEY), set(EXPECTED))

    def test_safe_values_produce_no_findings(self) -> None:
        for rule in SETTING_RULES:
            with self.subTest(key=rule.key):
                self.assertEqual(rule(SAFE_CONFIG), [])

    def test_unsafe_value_is_flagged_with_its_severity(self) -> None:
        for key, (rule_id, unsafe_value, severity) in EXPECTED.items():
            with self.subTest(key=key):
                findings = RULES_BY_KEY[key](safe_config_with(**{key: unsafe_value}))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].rule_id, rule_id)
                self.assertEqual(findings[0].severity, severity)
                self.assertTrue(findings[0].fix)

    def test_missing_setting_fails_closed_with_the_rules_severity(self) -> None:
        for key, (_, _, severity) in EXPECTED.items():
            with self.subTest(key=key):
                findings = RULES_BY_KEY[key](safe_config_without(key))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].rule_id, f"V-{key}")
                self.assertEqual(findings[0].severity, severity)
                self.assertIn("missing", findings[0].reason)

    def test_wrong_types_are_never_coerced(self) -> None:
        rule = RULES_BY_KEY["privileged"]
        for value in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(value=value):
                findings = rule(safe_config_with(privileged=value))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].rule_id, "V-privileged")
                self.assertEqual(findings[0].severity, Severity.CRITICAL)
                self.assertIn("Expected true/false", findings[0].reason)

    def test_quoted_false_is_described_as_text(self) -> None:
        findings = RULES_BY_KEY["privileged"](safe_config_with(privileged="false"))
        self.assertIn("got text ('false')", findings[0].reason)

    def test_fix_for_unverifiable_setting_names_the_safe_value(self) -> None:
        findings = RULES_BY_KEY["read_only_root_filesystem"](
            safe_config_without("read_only_root_filesystem")
        )
        self.assertIn("true", findings[0].fix)

    def test_a_new_row_works_without_new_code(self) -> None:
        rule = BoolSettingRule(
            rule_id="RX",
            key="no_new_privileges",
            unsafe_value=False,
            severity=Severity.LOW,
            title="t",
            reason="r",
            fix="f",
            sources=(),
        )
        self.assertEqual(rule({"no_new_privileges": True}), [])
        self.assertEqual(rule({"no_new_privileges": False})[0].rule_id, "RX")


if __name__ == "__main__":
    unittest.main()
