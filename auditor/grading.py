"""Turn a container's findings into an overall grade."""

from __future__ import annotations

from collections.abc import Sequence

from auditor.models import Finding, Severity, Status

# Lowest severity that makes a container FAIL or need REVIEW.
FAIL_AT = Severity.HIGH
REVIEW_AT = Severity.LOW


def grade(findings: Sequence[Finding]) -> Status:
    """Grade one container from its findings.

    FAIL   if any finding is at or above FAIL_AT (HIGH or CRITICAL)
    REVIEW if the worst finding is at or above REVIEW_AT (MEDIUM or LOW)
    PASS   otherwise: no findings, or only INFO ones (e.g. allowlisted network)
    """
    worst = max((f.severity for f in findings), default=Severity.INFO)
    if worst >= FAIL_AT:
        return Status.FAIL
    if worst >= REVIEW_AT:
        return Status.REVIEW
    return Status.PASS
