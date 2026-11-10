"""Tests for auditor.cli: exit codes, formats and the --fail-on threshold."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from auditor.cli import ExitCode, main
from tests.configs import ASSIGNMENT_EXAMPLE, SAFE_CONFIG, safe_config_with

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class MainTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def _write(self, data: object) -> str:
        path = self.dir / "configs.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    def _run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_safe_config_exits_clean(self) -> None:
        code, out, _ = self._run(self._write(SAFE_CONFIG))
        self.assertEqual(code, ExitCode.CLEAN)
        self.assertIn("[PASS]", out)

    def test_unsafe_config_exits_with_findings(self) -> None:
        code, out, _ = self._run(self._write(ASSIGNMENT_EXAMPLE))
        self.assertEqual(code, ExitCode.FINDINGS)
        self.assertIn("[FAIL] customer-script-01", out)

    def test_missing_file_exits_with_input_error(self) -> None:
        code, out, err = self._run(str(self.dir / "missing.json"))
        self.assertEqual(code, ExitCode.INPUT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("error: cannot read", err)

    def test_invalid_json_exits_with_input_error(self) -> None:
        path = self.dir / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        code, _, err = self._run(str(path))
        self.assertEqual(code, ExitCode.INPUT_ERROR)
        self.assertIn("not valid JSON", err)

    def test_fail_on_threshold(self) -> None:
        medium_only = self._write(safe_config_with(read_only_root_filesystem=False))
        cases = {"high": ExitCode.CLEAN, "medium": ExitCode.FINDINGS}
        for level, expected in cases.items():
            with self.subTest(level=level):
                code, _, _ = self._run(medium_only, "--fail-on", level)
                self.assertEqual(code, expected)

    def test_info_findings_never_fail_the_build(self) -> None:
        allowlisted = safe_config_with(
            network_enabled=True, egress_allowlist=["api.weather.com"]
        )
        code, _, _ = self._run(self._write(allowlisted), "--fail-on", "low")
        self.assertEqual(code, ExitCode.CLEAN)

    def test_json_format_is_parseable(self) -> None:
        code, out, _ = self._run(self._write(ASSIGNMENT_EXAMPLE), "--format", "json")
        self.assertEqual(code, ExitCode.FINDINGS)
        self.assertEqual(json.loads(out)["containers"][0]["status"], "FAIL")


class ExampleFilesTest(unittest.TestCase):
    """The README's commands run against these files, so keep them honest."""

    def test_example_files_give_the_documented_results(self) -> None:
        cases = {
            "safe.json": (ExitCode.CLEAN, {"FAIL": 0, "REVIEW": 0, "PASS": 1}),
            "unsafe.json": (ExitCode.FINDINGS, {"FAIL": 1, "REVIEW": 0, "PASS": 0}),
            "mixed.json": (ExitCode.FINDINGS, {"FAIL": 4, "REVIEW": 1, "PASS": 1}),
        }
        for name, (exit_code, summary) in cases.items():
            with self.subTest(name=name):
                path = PROJECT_ROOT / "examples" / name
                out = io.StringIO()
                with redirect_stdout(out):
                    code = main([str(path), "--format", "json"])
                self.assertEqual(code, exit_code)
                self.assertEqual(json.loads(out.getvalue())["summary"], summary)


class ModuleEntryPointTest(unittest.TestCase):
    def test_python_dash_m_auditor_runs_and_returns_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c.json"
            path.write_text(json.dumps(ASSIGNMENT_EXAMPLE), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "auditor", str(path)],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, ExitCode.FINDINGS)
        self.assertIn("customer-script-01", result.stdout)


if __name__ == "__main__":
    unittest.main()
