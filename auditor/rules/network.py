"""R5: outbound network access must be limited to named destinations.

Policy (see README.md): network access is not unsafe by itself. It is acceptable
when `egress_allowlist` names the specific destinations the script needs.
A missing, empty or invalid allowlist, or one that matches everything, counts
as no allowlist.
"""

from __future__ import annotations

import json

from auditor.models import ConfigKey, ContainerConfig, Finding, RuleId, Severity
from auditor.rules.verification import (
    JSON_BOOL,
    MISSING_PROBLEM,
    json_type_name,
    unverified_finding,
    wrong_type_problem,
)
from auditor.sources import Source

NETWORK_POLICY = (
    "Customer scripts are untrusted. Outbound network access is denied by "
    "default. It is allowed only when egress_allowlist names the specific "
    "destinations the script needs. A missing, empty or invalid allowlist, or "
    "one that allows everything, counts as no allowlist."
)

SEVERITY = Severity.HIGH
NETWORK_OFF = json.dumps(False)
MATCH_ALL_ENTRIES = frozenset({"*", "0.0.0.0/0", "::/0"})
# Cloud metadata services hand out the host's cloud credentials. Matching is
# by substring, so "http://169.254.169.254/latest" and the IPv4-mapped IPv6
# form "::ffff:169.254.169.254" are caught too.
METADATA_ADDRESSES = (
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
)

EGRESS_SOURCES = (
    Source.NIST_190,
    Source.VERCEL,
    Source.BLAXEL,
    Source.AWS_EKS_IAM,
)


class InvalidAllowlistError(ValueError):
    """The allowlist doesn't restrict anything. The message says why."""
EGRESS_FIX = (
    "Turn the network off (network_enabled: false, i.e. --network none), or "
    "list only the exact hosts the script needs in egress_allowlist, "
    'e.g. ["api.weather.com"].'
)


def check_network(config: ContainerConfig) -> list[Finding]:
    """Flag network access that isn't limited by a valid allowlist."""
    if ConfigKey.NETWORK_ENABLED not in config:
        return [_unverified(MISSING_PROBLEM)]
    enabled = config[ConfigKey.NETWORK_ENABLED]
    if not isinstance(enabled, bool):
        return [_unverified(wrong_type_problem(enabled, JSON_BOOL))]
    if not enabled:
        return []

    # egress_allowlist is optional: leaving it out is a valid choice that
    # means "no allowlist", so it is a policy finding, not an unverified one.
    if ConfigKey.EGRESS_ALLOWLIST not in config:
        return [_unrestricted_finding("There is no egress_allowlist")]
    try:
        hosts = allowlist_hosts(config[ConfigKey.EGRESS_ALLOWLIST])
    except InvalidAllowlistError as exc:
        return [_unrestricted_finding(str(exc))]

    metadata_hosts = [host for host in hosts if _is_metadata_address(host)]
    if metadata_hosts:
        return [_metadata_finding(host) for host in metadata_hosts]
    return [_allowlisted_finding(hosts)]


def allowlist_hosts(allowlist: object) -> list[str]:
    """Return the allowlist's hosts, or raise InvalidAllowlistError saying why
    the list doesn't actually restrict anything."""
    if not isinstance(allowlist, list):
        raise InvalidAllowlistError(
            f"egress_allowlist must be a list, not {json_type_name(allowlist)}"
        )
    if not allowlist:
        raise InvalidAllowlistError("egress_allowlist is empty")
    hosts: list[str] = []
    for entry in allowlist:
        if not isinstance(entry, str) or not entry.strip():
            raise InvalidAllowlistError(
                f"egress_allowlist entry {entry!r} is not a host name"
            )
        if entry.strip() in MATCH_ALL_ENTRIES:
            raise InvalidAllowlistError(
                f"egress_allowlist entry '{entry}' allows every destination"
            )
        hosts.append(entry)
    return hosts


def _is_metadata_address(host: str) -> bool:
    lowered = host.lower()
    return any(address in lowered for address in METADATA_ADDRESSES)


def _unverified(problem: str) -> Finding:
    return unverified_finding(
        ConfigKey.NETWORK_ENABLED, SEVERITY, problem, NETWORK_OFF
    )


def _unrestricted_finding(problem: str) -> Finding:
    return Finding(
        rule_id=RuleId.UNRESTRICTED_EGRESS,
        severity=SEVERITY,
        title="Network is on with no valid allowlist",
        reason=(
            f"{problem}, so the untrusted script can reach any destination. It "
            "could send customer data anywhere, probe internal systems, or steal "
            "the host's cloud credentials from the metadata service."
        ),
        fix=EGRESS_FIX,
        sources=EGRESS_SOURCES,
    )


def _metadata_finding(host: str) -> Finding:
    return Finding(
        rule_id=RuleId.METADATA_EGRESS,
        severity=SEVERITY,
        title=f"Allowlist includes the cloud metadata service: {host}",
        reason=(
            "The cloud metadata service hands out the host's cloud credentials "
            "to any process that can reach it."
        ),
        fix=(
            f"Remove '{host}' from egress_allowlist, and block link-local "
            "addresses (169.254.0.0/16) at the network layer."
        ),
        sources=(
            Source.AWS_IMDS,
            Source.GCP_MD,
            Source.AZ_IMDS,
            Source.OWASP_SSRF,
        ),
    )


def _allowlisted_finding(hosts: list[str]) -> Finding:
    return Finding(
        rule_id=RuleId.ALLOWLISTED_EGRESS,
        severity=Severity.INFO,
        title=f"Network limited to: {', '.join(hosts)}",
        reason=(
            "Outbound access is limited to named destinations, which meets the "
            "policy: egress should be controlled, not necessarily banned."
        ),
        fix="No change needed. Keep the list as short as the script allows.",
        sources=(Source.NIST_190, Source.NIST_GLOSS, Source.K8S_NP),
    )
