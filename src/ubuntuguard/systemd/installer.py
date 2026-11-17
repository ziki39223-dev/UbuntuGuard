"""systemd unit installation helpers."""

from __future__ import annotations

import re
from pathlib import Path

from ..core.executor import CommandExecutor

UNIT_DIR = Path("/etc/systemd/system")
DEFAULT_BINARY = "/usr/bin/ubuntuguard"
_INTERVAL_RE = re.compile(r"^\d+[smhd]$")

AUDIT_SERVICE = """\
[Unit]
Description=UbuntuGuard scheduled security report
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={binary} report --format html --out /var/lib/ubuntuguard/reports/latest.html
Nice=10
"""

AUDIT_TIMER = """\
[Unit]
Description=Run the UbuntuGuard security report periodically

[Timer]
OnBootSec=10min
OnUnitActiveSec={interval}
Persistent=true
Unit=ubuntuguard-audit.service

[Install]
WantedBy=timers.target
"""

MONITOR_SERVICE = """\
[Unit]
Description=UbuntuGuard health check
After=network-online.target

[Service]
Type=oneshot
ExecStart={binary} monitor check
Nice=10
"""

MONITOR_TIMER = """\
[Unit]
Description=Run the UbuntuGuard health check periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval}
Persistent=true
Unit=ubuntuguard-monitor.service

[Install]
WantedBy=timers.target
"""


def valid_interval(value: str) -> bool:
    return bool(_INTERVAL_RE.match(value))


def unit_files(
    interval: str = "6h",
    monitor_interval: str = "5min",
    binary: str = DEFAULT_BINARY,
) -> dict[str, str]:
    return {
        "ubuntuguard-audit.service": AUDIT_SERVICE.format(binary=binary),
        "ubuntuguard-audit.timer": AUDIT_TIMER.format(interval=interval),
        "ubuntuguard-monitor.service": MONITOR_SERVICE.format(binary=binary),
        "ubuntuguard-monitor.timer": MONITOR_TIMER.format(interval=monitor_interval),
    }


def install(
    executor: CommandExecutor,
    unit_dir: Path = UNIT_DIR,
    interval: str = "6h",
    monitor_interval: str = "5min",
    binary: str = DEFAULT_BINARY,
) -> tuple[str, ...]:
    unit_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name, content in unit_files(interval, monitor_interval, binary).items():
        path = unit_dir / name
        path.write_text(content, encoding="utf-8")
        written.append(str(path))

    executor.run(["systemctl", "daemon-reload"], check=True)
    for timer in ("ubuntuguard-audit.timer", "ubuntuguard-monitor.timer"):
        executor.run(["systemctl", "enable", "--now", timer], check=True)
    return tuple(written)


def uninstall(
    executor: CommandExecutor,
    unit_dir: Path = UNIT_DIR,
) -> tuple[str, ...]:
    for timer in ("ubuntuguard-audit.timer", "ubuntuguard-monitor.timer"):
        executor.run(["systemctl", "disable", "--now", timer])

    removed: list[str] = []
    for name in unit_files():
        path = unit_dir / name
        if path.is_file():
            path.unlink()
            removed.append(str(path))
    executor.run(["systemctl", "daemon-reload"])
    return tuple(removed)
