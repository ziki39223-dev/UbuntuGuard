"""Rule registry for the baseline audit."""

from __future__ import annotations

from ..firewall.rules import FIREWALL_RULES
from ..network.rules import NETWORK_RULES
from ..ssh.rules import SSH_RULES
from ..system.rules import SYSCTL_RULES
from ..users.rules import ACCOUNT_RULES
from .rules import Rule

ALL_RULES: tuple[Rule, ...] = (
    SSH_RULES + ACCOUNT_RULES + FIREWALL_RULES + NETWORK_RULES + SYSCTL_RULES
)
