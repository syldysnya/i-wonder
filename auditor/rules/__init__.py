"""Registry of every check the auditor runs.

Each check has the same shape: it takes one container config and returns a
list of findings (empty when the config is fine). Adding a check means adding
one entry to RULES.
"""

from __future__ import annotations

from collections.abc import Callable

from auditor.models import ContainerConfig, Finding
from auditor.rules.mounts import check_docker_socket
from auditor.rules.network import check_network
from auditor.rules.settings import SETTING_RULES

RuleCheck = Callable[[ContainerConfig], list[Finding]]

RULES: tuple[RuleCheck, ...] = (
    *SETTING_RULES,
    check_docker_socket,
    check_network,
)
