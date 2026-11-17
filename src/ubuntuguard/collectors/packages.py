"""Installed package and update status collector."""

from __future__ import annotations

import re
from pathlib import Path

from ..core.executor import CommandExecutor
from ..models import PackageInfo

DEFAULT_REBOOT_FLAG = Path("/var/run/reboot-required")
_UPGRADED_RE = re.compile(r"(\d+)\s+upgraded")


def collect_packages(
    executor: CommandExecutor,
    reboot_flag: Path = DEFAULT_REBOOT_FLAG,
) -> PackageInfo:
    status = executor.run(
        ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\n"], check=True
    )
    installed = sum(1 for line in status.stdout.splitlines() if line.startswith("ii"))

    upgradable = 0
    simulation = executor.run(["apt-get", "-s", "-q", "upgrade"], timeout=60.0)
    if simulation.ok:
        upgradable = parse_upgradable(simulation.stdout)

    fail2ban = executor.run(
        ["dpkg-query", "-W", "-f=${Status}", "fail2ban"]
    )

    return PackageInfo(
        installed=installed,
        upgradable=upgradable,
        reboot_required=reboot_flag.is_file(),
        fail2ban_installed=fail2ban.ok and "install ok installed" in fail2ban.stdout,
    )


def parse_upgradable(text: str) -> int:
    match = _UPGRADED_RE.search(text)
    return int(match.group(1)) if match else 0
