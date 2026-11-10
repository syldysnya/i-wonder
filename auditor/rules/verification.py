"""Findings for settings that can't be verified (missing or wrong type).

Every rule shares this policy: a setting we can't confirm is safe is treated
as unsafe ("fail closed", see CWE-636). The finding gets the severity of the
rule it blocks, so leaving out a dangerous setting can never make a config pass.
"""

from __future__ import annotations

from auditor.models import Finding, Severity
from auditor.sources import Source

UNVERIFIED_PREFIX = "V-"
FAIL_CLOSED_SOURCES = (Source.CWE_636, Source.OWASP_SCP)
MISSING_PROBLEM = "The setting is missing"
JSON_BOOL = "true/false"

# JSON names for Python types, so messages match what the user wrote.
_JSON_TYPE_NAMES: dict[type, str] = {
    bool: JSON_BOOL,
    int: "number",
    float: "number",
    str: "text",
    list: "list",
    dict: "object",
    type(None): "null",
}


def json_type_name(value: object) -> str:
    """Name a parsed JSON value's type the way JSON does (e.g. "text", "null")."""
    return _JSON_TYPE_NAMES.get(type(value), type(value).__name__)


def wrong_type_problem(value: object, expected: str) -> str:
    """Describe a value whose type is wrong, e.g. 'Expected true/false, got text'."""
    return f"Expected {expected}, got {json_type_name(value)} ({value!r})"


def unverified_finding(
    key: str, severity: Severity, problem: str, expected: str
) -> Finding:
    """Build the finding for a setting that can't be verified."""
    return Finding(
        rule_id=f"{UNVERIFIED_PREFIX}{key}",
        severity=severity,
        title=f"Cannot verify '{key}'",
        reason=(
            f"{problem}. A setting that can't be verified is treated as unsafe, "
            "never assumed to be safe."
        ),
        fix=f"Set '{key}' explicitly to {expected}.",
        sources=FAIL_CLOSED_SOURCES,
    )
