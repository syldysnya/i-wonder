"""Render audit results as readable text or JSON. Presentation only, no decisions."""

from __future__ import annotations

import json
import textwrap
from collections import Counter
from collections.abc import Sequence

from auditor.models import ContainerReport, Finding, Status

TEXT_WIDTH = 88
JSON_INDENT = 2
FINDING_INDENT = " " * 2
SEVERITY_WIDTH = len("CRITICAL")
RULE_ID_WIDTH = len("R5-ok")
# Details start where the finding's title starts: indent, severity, id, spaces.
DETAIL_INDENT = FINDING_INDENT + " " * (SEVERITY_WIDTH + RULE_ID_WIDTH + 2)
LABEL_WIDTH = len("Sources: ")  # the longest label
STATUS_ORDER = (Status.FAIL, Status.REVIEW, Status.PASS)


def status_counts(reports: Sequence[ContainerReport]) -> dict[str, int]:
    """Number of containers per status, worst status first."""
    counts = Counter(report.status for report in reports)
    return {status.value: counts[status] for status in STATUS_ORDER}


def render_text(reports: Sequence[ContainerReport], policy: str) -> str:
    """A human-readable report: policy, each container's findings, a summary."""
    lines = [
        f"Container Config Audit — {len(reports)} container(s)",
        _labelled("Policy:", policy, indent=""),
    ]
    for report in reports:
        lines += ["", f"[{report.status}] {report.name}"]
        if not report.findings:
            lines.append(f"{FINDING_INDENT}No issues found.")
        for finding in report.findings:
            lines += _finding_lines(finding)
    counts = status_counts(reports)
    summary = ", ".join(f"{count} {status}" for status, count in counts.items())
    lines += ["", f"Summary: {summary}"]
    return "\n".join(lines)


def render_json(reports: Sequence[ContainerReport], policy: str) -> str:
    """The same results as JSON, for other tools."""
    document = {
        "policy": policy,
        "containers": [
            {
                "name": report.name,
                "status": report.status.value,
                "findings": [_finding_dict(f) for f in report.findings],
            }
            for report in reports
        ],
        "summary": status_counts(reports),
    }
    return json.dumps(document, indent=JSON_INDENT, ensure_ascii=False)


def _finding_lines(finding: Finding) -> list[str]:
    header = (
        f"{FINDING_INDENT}{finding.severity.name:<{SEVERITY_WIDTH}} "
        f"{finding.rule_id:<{RULE_ID_WIDTH}} "
    )
    return [
        header + finding.title,
        _labelled("Why:", finding.reason, DETAIL_INDENT),
        _labelled("Fix:", finding.fix, DETAIL_INDENT),
        _labelled("Sources:", ", ".join(finding.sources), DETAIL_INDENT),
    ]


def _labelled(label: str, text: str, indent: str) -> str:
    """'Label:  text', wrapped so continuation lines align with the text."""
    return textwrap.fill(
        f"{label:<{LABEL_WIDTH}}{text}",
        width=TEXT_WIDTH,
        initial_indent=indent,
        subsequent_indent=indent + " " * LABEL_WIDTH,
    )


def _finding_dict(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.name,
        "title": finding.title,
        "reason": finding.reason,
        "fix": finding.fix,
        "sources": [str(source) for source in finding.sources],
    }
