"""Tests for auditor.rules.mounts (R4)."""

from __future__ import annotations

import unittest

from auditor.models import Severity
from auditor.rules.mounts import check_docker_socket, host_path
from tests.configs import SAFE_CONFIG, safe_config_with, safe_config_without


def _rule_ids(mounts: object) -> list[str]:
    return [f.rule_id for f in check_docker_socket(safe_config_with(mounts=mounts))]


class HostPathTest(unittest.TestCase):
    def test_canonical_forms(self) -> None:
        cases = {
            "/var/run/docker.sock": "/var/run/docker.sock",
            "/var/run/docker.sock:/sock:ro": "/var/run/docker.sock",
            "/var/run/../run/docker.sock": "/var/run/docker.sock",
            "/tmp/../run/docker.sock": "/run/docker.sock",
            "/var/run/": "/var/run",
            "/var//run/./docker.sock": "/var/run/docker.sock",
            "//var/run": "/var/run",
            "///": "/",
        }
        for entry, expected in cases.items():
            with self.subTest(entry=entry):
                self.assertEqual(host_path(entry), expected)


class CheckDockerSocketTest(unittest.TestCase):
    def test_safe_mounts_produce_no_findings(self) -> None:
        self.assertEqual(check_docker_socket(SAFE_CONFIG), [])

    def test_no_mounts_is_safe(self) -> None:
        self.assertEqual(_rule_ids([]), [])

    def test_socket_is_flagged_however_it_is_spelled(self) -> None:
        for entry in (
            "/var/run/docker.sock",
            "/var/run/docker.sock:/sock:ro",
            "/run/docker.sock",
            "/var/run/../run/docker.sock",
            "/home/dev/.docker/run/docker.sock",
        ):
            with self.subTest(entry=entry):
                findings = check_docker_socket(safe_config_with(mounts=[entry]))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].rule_id, "R4")
                self.assertEqual(findings[0].severity, Severity.CRITICAL)
                self.assertIn(entry, findings[0].title)

    def test_folders_holding_the_socket_are_flagged(self) -> None:
        for entry in ("/", "/run", "/var/run", "/var/run/", "/var/run:/host-run"):
            with self.subTest(entry=entry):
                self.assertEqual(_rule_ids([entry]), ["R4"])

    def test_lookalike_paths_are_not_flagged(self) -> None:
        for entry in ("/var/run/docker.sock.bak", "/var/runner", "/data/docker"):
            with self.subTest(entry=entry):
                self.assertEqual(_rule_ids([entry]), [])

    def test_each_offending_mount_gets_its_own_finding(self) -> None:
        mounts = ["/data", "/var/run/docker.sock", "/run"]
        self.assertEqual(_rule_ids(mounts), ["R4", "R4"])

    def test_missing_mounts_fails_closed(self) -> None:
        findings = check_docker_socket(safe_config_without("mounts"))
        self.assertEqual([f.rule_id for f in findings], ["V-mounts"])
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_mounts_that_is_not_a_list_fails_closed(self) -> None:
        for value in ("/var/run/docker.sock", None, {"src": "/data"}):
            with self.subTest(value=value):
                self.assertEqual(_rule_ids(value), ["V-mounts"])

    def test_non_path_entries_fail_closed_but_others_are_still_checked(self) -> None:
        self.assertEqual(
            _rule_ids([42, "", "/var/run/docker.sock"]),
            ["V-mounts", "V-mounts", "R4"],
        )


if __name__ == "__main__":
    unittest.main()
