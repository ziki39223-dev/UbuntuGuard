"""sysctl parameter collector (reads /proc/sys, no root required)."""

from __future__ import annotations

from pathlib import Path

from ..models import SysctlInfo

DEFAULT_KEYS = (
    "kernel.randomize_va_space",
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
    "fs.protected_hardlinks",
    "fs.protected_symlinks",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.icmp_echo_ignore_broadcasts",
)

PROC_SYS_ROOT = Path("/proc/sys")


def collect_sysctl(
    keys: tuple[str, ...] = DEFAULT_KEYS,
    root: Path = PROC_SYS_ROOT,
) -> SysctlInfo:
    values: dict[str, str] = {}
    for key in keys:
        try:
            raw = (root / key.replace(".", "/")).read_text(encoding="utf-8")
        except OSError:
            continue
        values[key] = raw.strip()
    return SysctlInfo(values=values)
