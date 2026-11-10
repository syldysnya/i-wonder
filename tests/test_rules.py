"""Tests for the RULES registry: every check is wired in and has the same shape."""

from __future__ import annotations

import unittest

from auditor.rules import RULES
from tests.configs import ASSIGNMENT_EXAMPLE, SAFE_CONFIG


def _run_all(config: dict[str, object]) -> list[str]:
    return [finding.rule_id for rule in RULES for finding in rule(config)]


class RulesRegistryTest(unittest.TestCase):
    def test_safe_config_passes_every_rule(self) -> None:
        self.assertEqual(_run_all(SAFE_CONFIG), [])

    def test_assignment_example_triggers_r1_to_r5(self) -> None:
        self.assertEqual(
            sorted(_run_all(ASSIGNMENT_EXAMPLE)), ["R1", "R2", "R3", "R4", "R5"]
        )

    def test_empty_config_fails_closed_on_every_setting(self) -> None:
        expected = [
            "V-mounts",
            "V-network_enabled",
            "V-privileged",
            "V-read_only_root_filesystem",
            "V-run_as_root",
        ]
        self.assertEqual(sorted(_run_all({})), expected)


if __name__ == "__main__":
    unittest.main()
