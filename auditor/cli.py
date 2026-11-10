"""Command line: read a file, audit it, print the report, return an exit code.

This is the only module that prints.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from enum import IntEnum, StrEnum
from pathlib import Path

from auditor.audit import audit_all
from auditor.loader import ConfigError, load_configs
from auditor.models import ContainerReport, Severity
from auditor.report import render_json, render_text
from auditor.rules.network import NETWORK_POLICY

DEFAULT_FAIL_ON = Severity.HIGH


class ExitCode(IntEnum):
    CLEAN = 0  # nothing at or above the --fail-on threshold
    FINDINGS = 1  # at least one finding at or above it
    INPUT_ERROR = 2  # the file couldn't be read or isn't valid


class OutputFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


Renderer = Callable[[Sequence[ContainerReport], str], str]
RENDERERS: dict[OutputFormat, Renderer] = {
    OutputFormat.TEXT: render_text,
    OutputFormat.JSON: render_json,
}

# INFO findings are compliant, so they can never be a threshold.
FAIL_ON_CHOICES = {s.name.lower(): s for s in Severity if s > Severity.INFO}


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        configs = load_configs(args.path)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.INPUT_ERROR

    reports = audit_all(configs)
    print(RENDERERS[args.format](reports, NETWORK_POLICY))

    threshold = FAIL_ON_CHOICES[args.fail_on]
    if any(f.severity >= threshold for r in reports for f in r.findings):
        return ExitCode.FINDINGS
    return ExitCode.CLEAN


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m auditor",
        description="Audit container configs for settings that weaken isolation.",
    )
    parser.add_argument("path", type=Path, help="JSON file with one config or a list")
    parser.add_argument(
        "--format",
        type=OutputFormat,
        choices=list(OutputFormat),
        default=OutputFormat.TEXT,
        help="report format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_CHOICES),
        default=DEFAULT_FAIL_ON.name.lower(),
        help="exit with code 1 if any finding is at or above this severity "
        f"(default: {DEFAULT_FAIL_ON.name.lower()})",
    )
    return parser.parse_args(argv)
