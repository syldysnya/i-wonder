"""Tests for auditor.rules.network (R5)."""

from __future__ import annotations

import unittest
from typing import Any

from auditor.models import Severity
from auditor.rules.network import check_network
from tests.configs import SAFE_CONFIG, safe_config_with, safe_config_without


def _network_on(**overrides: Any) -> list[tuple[str, Severity]]:
    config = safe_config_with(network_enabled=True, **overrides)
    return [(f.rule_id, f.severity) for f in check_network(config)]


class CheckNetworkTest(unittest.TestCase):
    def test_network_off_is_fine(self) -> None:
        self.assertEqual(check_network(SAFE_CONFIG), [])

    def test_network_off_ignores_a_bad_allowlist(self) -> None:
        config = safe_config_with(network_enabled=False, egress_allowlist=["*"])
        self.assertEqual(check_network(config), [])

    def test_valid_allowlist_is_compliant_not_a_failure(self) -> None:
        findings = check_network(
            safe_config_with(
                network_enabled=True,
                egress_allowlist=["api.weather.com", "api.stripe.com"],
            )
        )
        self.assertEqual([f.rule_id for f in findings], ["R5-ok"])
        self.assertEqual(findings[0].severity, Severity.INFO)
        self.assertIn("api.weather.com, api.stripe.com", findings[0].title)

    def test_missing_allowlist_is_unrestricted(self) -> None:
        self.assertEqual(_network_on(), [("R5", Severity.HIGH)])

    def test_invalid_allowlists_count_as_none(self) -> None:
        cases: dict[str, object] = {
            "empty": [],
            "null": None,
            "not a list": "api.weather.com",
            "match-all star": ["api.weather.com", "*"],
            "match-all IPv4": ["0.0.0.0/0"],
            "match-all IPv6": ["::/0"],
            "blank entry": ["  "],
            "non-string entry": [42],
        }
        for label, allowlist in cases.items():
            with self.subTest(label):
                self.assertEqual(
                    _network_on(egress_allowlist=allowlist), [("R5", Severity.HIGH)]
                )

    def test_reason_explains_what_is_wrong_with_the_allowlist(self) -> None:
        config = safe_config_with(network_enabled=True, egress_allowlist=["*"])
        self.assertIn("allows every destination", check_network(config)[0].reason)

    def test_metadata_service_in_allowlist_is_flagged(self) -> None:
        for host in (
            "169.254.169.254",
            "http://169.254.169.254/latest/meta-data",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "Metadata.Google.Internal",
        ):
            with self.subTest(host=host):
                self.assertEqual(
                    _network_on(egress_allowlist=["api.weather.com", host]),
                    [("R5a", Severity.HIGH)],
                )

    def test_missing_network_setting_fails_closed(self) -> None:
        findings = check_network(safe_config_without("network_enabled"))
        self.assertEqual([f.rule_id for f in findings], ["V-network_enabled"])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_quoted_network_setting_is_not_coerced(self) -> None:
        findings = check_network(safe_config_with(network_enabled="false"))
        self.assertEqual([f.rule_id for f in findings], ["V-network_enabled"])


if __name__ == "__main__":
    unittest.main()
