"""Container configs shared by several test modules."""

from __future__ import annotations

from typing import Any

SAFE_CONFIG: dict[str, Any] = {
    "container_name": "safe-script",
    "privileged": False,
    "run_as_root": False,
    "read_only_root_filesystem": True,
    "network_enabled": False,
    "mounts": ["/data/input"],
}

# The example config from the assignment, unchanged.
ASSIGNMENT_EXAMPLE: dict[str, Any] = {
    "container_name": "customer-script-01",
    "privileged": True,
    "run_as_root": True,
    "read_only_root_filesystem": False,
    "network_enabled": True,
    "mounts": ["/var/run/docker.sock"],
}


def safe_config_with(**overrides: Any) -> dict[str, Any]:
    """Return a copy of SAFE_CONFIG with some settings replaced."""
    return {**SAFE_CONFIG, **overrides}


def safe_config_without(key: str) -> dict[str, Any]:
    """Return a copy of SAFE_CONFIG with one setting removed."""
    return {k: v for k, v in SAFE_CONFIG.items() if k != key}
