"""Audit one container config: run every rule, sort findings, grade the result."""

from __future__ import annotations

from collections.abc import Sequence

from auditor.grading import grade
from auditor.models import ConfigKey, ContainerReport, Finding, Severity
from auditor.rules import RULES, RuleCheck
from auditor.rules.verification import (
    FAIL_CLOSED_SOURCES,
    UNVERIFIED_PREFIX,
    json_type_name,
)

SHAPE_RULE_ID = f"{UNVERIFIED_PREFIX}shape"


def audit_container(
    entry: object, index: int, rules: Sequence[RuleCheck] = RULES
) -> ContainerReport:
    """Audit one entry from the input file. `index` labels unnamed entries."""
    if not isinstance(entry, dict):
        findings: list[Finding] = [_shape_finding(entry)]
    else:
        findings = [finding for rule in rules for finding in rule(entry)]
    # sorted() is stable, so findings of equal severity keep the rule order.
    findings = sorted(findings, key=lambda f: f.severity, reverse=True)
    return ContainerReport(
        name=container_label(entry, index),
        status=grade(findings),
        findings=tuple(findings),
    )


def audit_all(
    entries: Sequence[object], rules: Sequence[RuleCheck] = RULES
) -> list[ContainerReport]:
    """Audit every entry. A bad entry is reported, never skipped."""
    return [audit_container(entry, i, rules) for i, entry in enumerate(entries, 1)]


def container_label(entry: object, index: int) -> str:
    """The container's name, or '#<index>' if it has no usable name."""
    if isinstance(entry, dict):
        name = entry.get(ConfigKey.CONTAINER_NAME)  # optional: label only
        if isinstance(name, str) and name.strip():
            return name
    return f"#{index}"


def _shape_finding(entry: object) -> Finding:
    return Finding(
        rule_id=SHAPE_RULE_ID,
        severity=Severity.CRITICAL,
        title="Entry is not a container config",
        reason=(
            f"Expected an object with settings, got {json_type_name(entry)} "
            f"({entry!r}). None of its settings can be verified, so it is "
            "treated as unsafe."
        ),
        fix="Replace the entry with a JSON object holding the container's settings.",
        sources=FAIL_CLOSED_SOURCES,
    )
