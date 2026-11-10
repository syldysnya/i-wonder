"""R1–R3: yes/no settings that must not have their unsafe value.

Each rule is a row in SETTING_RULES. Adding another yes/no check means adding
a row, not writing a new function.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from auditor.models import ConfigKey, ContainerConfig, Finding, RuleId, Severity
from auditor.rules.verification import (
    JSON_BOOL,
    MISSING_PROBLEM,
    unverified_finding,
    wrong_type_problem,
)
from auditor.sources import Source


@dataclass(frozen=True)
class BoolSettingRule:
    """Flags a true/false setting when it holds its unsafe value."""

    rule_id: str
    key: str
    unsafe_value: bool
    severity: Severity
    title: str
    reason: str
    fix: str
    sources: tuple[Source, ...]

    def __call__(self, config: ContainerConfig) -> list[Finding]:
        safe_value = json.dumps(not self.unsafe_value)
        if self.key not in config:
            return [
                unverified_finding(
                    self.key, self.severity, MISSING_PROBLEM, safe_value
                )
            ]
        value = config[self.key]
        # Check the type before the value: in Python the text "false" counts
        # as true, so a quoted value must never be guessed at.
        if not isinstance(value, bool):
            problem = wrong_type_problem(value, JSON_BOOL)
            return [unverified_finding(self.key, self.severity, problem, safe_value)]
        if value is not self.unsafe_value:
            return []
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=self.title,
                reason=self.reason,
                fix=self.fix,
                sources=self.sources,
            )
        ]


SETTING_RULES: tuple[BoolSettingRule, ...] = (
    BoolSettingRule(
        rule_id=RuleId.PRIVILEGED,
        key=ConfigKey.PRIVILEGED,
        unsafe_value=True,
        severity=Severity.CRITICAL,
        title="Privileged mode is on",
        reason=(
            "Privileged mode gives the container every Linux kernel capability and "
            "turns off almost every isolation safeguard, so the script can act "
            "almost like the host itself."
        ),
        fix=(
            "Set privileged: false. Drop all capabilities (--cap-drop all), add "
            "back only those the script needs (--cap-add ...), and set "
            "no-new-privileges."
        ),
        sources=(
            Source.OWASP_CS_3,
            Source.OWASP_CS_4,
            Source.OWASP_DG,
            Source.K8S_PSS,
        ),
    ),
    BoolSettingRule(
        rule_id=RuleId.ROOT_USER,
        key=ConfigKey.RUN_AS_ROOT,
        unsafe_value=True,
        severity=Severity.HIGH,
        title="Runs as root",
        reason=(
            "The script runs as the all-powerful root user. That makes privilege "
            "escalation easier, and if the script breaks out of the container it "
            "is root on the host too, unless user namespaces remap it."
        ),
        fix=(
            "Set run_as_root: false and run as an unprivileged user (USER 1000 in "
            "the image, or -u 1000). Optionally enable user-namespace remapping or "
            "rootless mode."
        ),
        sources=(Source.OWASP_CS_2, Source.DOCK_USERNS, Source.K8S_PSS),
    ),
    BoolSettingRule(
        rule_id=RuleId.WRITABLE_ROOT_FS,
        key=ConfigKey.READ_ONLY_ROOT_FILESYSTEM,
        unsafe_value=False,
        severity=Severity.MEDIUM,
        title="Root filesystem is writable",
        reason=(
            "The script can change files inside the container, for example to "
            "plant tools or modify binaries. The damage stays inside the "
            "container, which is why this ranks below the host-level risks."
        ),
        fix=(
            "Set read_only_root_filesystem: true (--read-only) and give the script "
            "a small scratch area with --tmpfs /tmp."
        ),
        sources=(Source.OWASP_CS_8, Source.OWASP_DG, Source.TEN_CIS),
    ),
)
