"""UFW firewall state collector."""

from __future__ import annotations

import re

from ..core.executor import CommandExecutor
from ..errors import CommandExecutionError, CommandFailedError
from ..models import FirewallInfo, FirewallRule

_DEFAULT_RE = re.compile(
    r"Default:\s*(\S+)\s*\(incoming\),\s*(\S+)\s*\(outgoing\)"
)
_ACTIONS = frozenset({"ALLOW", "DENY", "REJECT", "LIMIT"})


def collect_firewall(executor: CommandExecutor) -> FirewallInfo:
    try:
        output = executor.run(["ufw", "status", "verbose"], check=True).stdout
    except CommandExecutionError:
        return FirewallInfo(available=False, readable=False)
    except CommandFailedError:
        return FirewallInfo(available=True, readable=False)
    return parse_ufw(output)


def parse_ufw(text: str) -> FirewallInfo:
    active = False
    default_incoming = ""
    default_outgoing = ""
    rules: list[FirewallRule] = []

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("status:"):
            active = stripped.split(":", 1)[1].strip().lower() == "active"
            continue
        match = _DEFAULT_RE.search(stripped)
        if match:
            default_incoming = match.group(1).lower()
            default_outgoing = match.group(2).lower()
            continue
        if stripped.startswith(("To ", "--", "Logging:")):
            continue
        parts = stripped.split()
        action_index = next(
            (index for index, token in enumerate(parts) if token in _ACTIONS), None
        )
        if action_index is not None:
            target = " ".join(parts[:action_index]).replace(" (v6)", "").strip()
            rules.append(
                FirewallRule(
                    to=target,
                    action=parts[action_index],
                    source=parts[-1],
                )
            )

    return FirewallInfo(
        available=True,
        readable=True,
        active=active,
        default_incoming=default_incoming,
        default_outgoing=default_outgoing,
        rules=tuple(rules),
    )
