"""R4: the Docker socket must not be reachable through a mount."""

from __future__ import annotations

import posixpath

from auditor.models import ConfigKey, ContainerConfig, Finding, RuleId, Severity
from auditor.rules.verification import (
    MISSING_PROBLEM,
    unverified_finding,
    wrong_type_problem,
)
from auditor.sources import Source

MOUNTS_EXPECTED = "a list of host paths"
MOUNT_SEPARATOR = ":"
SOCKET_NAME = "docker.sock"
# Folders that contain the socket. /var/run is a symlink to /run, and / holds both.
SOCKET_PARENT_DIRS = frozenset({"/", "/run", "/var/run"})

SEVERITY = Severity.CRITICAL
SOURCES = (
    Source.OWASP_CS_1,
    Source.NETDATA,
    Source.OWASP_DG,
    Source.DD_CIS531,
    Source.DOCK_POST,
)
FIX = (
    "Remove the mount. If the script really needs the Docker API, send those "
    "requests through an external, authenticated gateway instead."
)


def host_path(entry: str) -> str:
    """Return the canonical host side of a mount entry.

    Accepts a plain path ("/var/run/docker.sock") or "host:container[:options]";
    only the host part is kept. The path is normalised so that spellings like
    "/var/run/../run/docker.sock" or "/var/run/" compare equal to their plain
    form.

    Not covered: symlinks other than the known /var/run -> /run (the file
    system isn't consulted), and relative paths stay relative.
    """
    host = entry.split(MOUNT_SEPARATOR, 1)[0]
    path = posixpath.normpath(host)
    # POSIX keeps exactly two leading slashes ("//var") as-is; collapse them.
    if path.startswith(posixpath.sep * 2):
        path = posixpath.sep + path.lstrip(posixpath.sep)
    return path


def check_docker_socket(config: ContainerConfig) -> list[Finding]:
    """Flag every mount that exposes the Docker socket, read-only or not."""
    if ConfigKey.MOUNTS not in config:
        return [_unverified(MISSING_PROBLEM)]
    mounts = config[ConfigKey.MOUNTS]
    if not isinstance(mounts, list):
        return [_unverified(wrong_type_problem(mounts, MOUNTS_EXPECTED))]

    findings: list[Finding] = []
    for entry in mounts:
        if not isinstance(entry, str) or not entry.strip():
            findings.append(_unverified(f"Mount entry {entry!r} is not a path"))
            continue
        path = host_path(entry)
        if posixpath.basename(path) == SOCKET_NAME:
            title = f"Docker socket mounted: {entry}"
        elif path in SOCKET_PARENT_DIRS:
            title = f"Folder holding the Docker socket mounted: {entry}"
        else:
            continue
        findings.append(_socket_finding(entry, title))
    return findings


def _unverified(problem: str) -> Finding:
    return unverified_finding(ConfigKey.MOUNTS, SEVERITY, problem, MOUNTS_EXPECTED)


def _socket_finding(entry: str, title: str) -> Finding:
    return Finding(
        rule_id=RuleId.DOCKER_SOCKET,
        severity=SEVERITY,
        title=title,
        reason=(
            f"'{entry}' gives the container access to docker.sock, the control "
            "panel for Docker itself. Whoever reaches it can start a new, fully "
            "privileged container and take over the host. Mounting it read-only "
            "doesn't help: that only stops writes to the file, not commands sent "
            "through it."
        ),
        fix=FIX,
        sources=SOURCES,
    )
