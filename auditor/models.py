"""Records passed between the auditor's stages. They hold data, not logic."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum, StrEnum

from auditor.sources import Source

# One container's settings as parsed from JSON. Values are untyped on purpose:
# the rules check each value's type and report anything unexpected.
ContainerConfig = Mapping[str, object]


class Severity(IntEnum):
    """How serious a finding is. Ordered, so findings sort and compare by value."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ConfigKey(StrEnum):
    """Setting names in a container config (the input schema)."""

    CONTAINER_NAME = "container_name"
    PRIVILEGED = "privileged"
    RUN_AS_ROOT = "run_as_root"
    READ_ONLY_ROOT_FILESYSTEM = "read_only_root_filesystem"
    NETWORK_ENABLED = "network_enabled"
    EGRESS_ALLOWLIST = "egress_allowlist"
    MOUNTS = "mounts"


class RuleId(StrEnum):
    """Identifiers of the rules, as shown in the report."""

    PRIVILEGED = "R1"
    ROOT_USER = "R2"
    WRITABLE_ROOT_FS = "R3"
    DOCKER_SOCKET = "R4"
    UNRESTRICTED_EGRESS = "R5"
    METADATA_EGRESS = "R5a"
    ALLOWLISTED_EGRESS = "R5-ok"


class Status(StrEnum):
    """Overall grade for one container."""

    PASS = "PASS"
    REVIEW = "REVIEW"
    FAIL = "FAIL"


@dataclass(frozen=True)
class Finding:
    """One risky (or noteworthy) setting found in a container config."""

    rule_id: str  # a RuleId, or "V-<key>" for a setting that can't be verified
    severity: Severity
    title: str
    reason: str
    fix: str
    sources: tuple[Source, ...]


@dataclass(frozen=True)
class ContainerReport:
    """Audit result for one container: its grade and findings, worst first."""

    name: str
    status: Status
    findings: tuple[Finding, ...]
