"""Snapshot aggregation.

Each collector is isolated: a failure is recorded in `errors` and the rest of
the snapshot remains usable. Collectors are strictly read-only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypeVar

from ..core.executor import CommandExecutor
from ..models import (
    CpuInfo,
    DiskInfo,
    FilePermission,
    FirewallInfo,
    HostInfo,
    LoginDefsInfo,
    MemoryInfo,
    NetworkInfo,
    PackageInfo,
    PortInfo,
    ProcessInfo,
    ServiceInfo,
    ShadowInfo,
    SshInfo,
    SudoersInfo,
    SysctlInfo,
    SystemSnapshot,
    UserInfo,
)
from .accounts import (
    collect_login_defs,
    collect_shadow,
    collect_sudoers,
    collect_users,
)
from .files import collect_permissions
from .firewall import collect_firewall
from .network import collect_network
from .packages import collect_packages
from .ports import collect_ports
from .processes import collect_processes
from .services import collect_services
from .ssh import collect_ssh
from .storage import collect_disks
from .sysctl import collect_sysctl
from .system import collect_cpu, collect_host, collect_memory

T = TypeVar("T")


def collect_system(
    executor: CommandExecutor, logger: logging.Logger | None = None
) -> SystemSnapshot:
    log = logger or logging.getLogger("ubuntuguard.collectors")
    errors: list[str] = []

    host = _safe(
        "host",
        collect_host,
        HostInfo(
            hostname="",
            os_id="unknown",
            os_version="unknown",
            os_pretty_name="",
            kernel="",
        ),
        errors,
        log,
    )
    cpu = _safe("cpu", collect_cpu, CpuInfo(model="", cores=0), errors, log)
    memory = _safe(
        "memory",
        collect_memory,
        MemoryInfo(
            total_bytes=0,
            available_bytes=0,
            used_bytes=0,
            used_percent=0.0,
        ),
        errors,
        log,
    )

    empty_disks: tuple[DiskInfo, ...] = ()
    disks = _safe("disks", collect_disks, empty_disks, errors, log)

    network = _safe(
        "network", lambda: collect_network(executor), NetworkInfo(), errors, log
    )

    empty_users: tuple[UserInfo, ...] = ()
    users = _safe("users", collect_users, empty_users, errors, log)

    empty_processes: tuple[ProcessInfo, ...] = ()
    processes = _safe(
        "processes",
        lambda: collect_processes(executor),
        empty_processes,
        errors,
        log,
    )

    empty_services: tuple[ServiceInfo, ...] = ()
    services = _safe(
        "services", lambda: collect_services(executor), empty_services, errors, log
    )

    empty_ports: tuple[PortInfo, ...] = ()
    ports = _safe("ports", lambda: collect_ports(executor), empty_ports, errors, log)

    packages = _safe(
        "packages", lambda: collect_packages(executor), PackageInfo(), errors, log
    )

    ssh = _safe("ssh", lambda: collect_ssh(executor), SshInfo(), errors, log)
    shadow = _safe("shadow", collect_shadow, ShadowInfo(), errors, log)
    sudoers = _safe("sudoers", collect_sudoers, SudoersInfo(), errors, log)
    login_defs = _safe("login_defs", collect_login_defs, LoginDefsInfo(), errors, log)

    empty_permissions: tuple[FilePermission, ...] = ()
    file_permissions = _safe(
        "permissions", collect_permissions, empty_permissions, errors, log
    )

    firewall = _safe(
        "firewall", lambda: collect_firewall(executor), FirewallInfo(), errors, log
    )
    sysctl = _safe("sysctl", collect_sysctl, SysctlInfo(), errors, log)

    return SystemSnapshot(
        collected_at=datetime.now(tz=timezone.utc)
        .astimezone()
        .isoformat(timespec="seconds"),
        host=host,
        cpu=cpu,
        memory=memory,
        disks=disks,
        network=network,
        users=users,
        processes=processes,
        services=services,
        ports=ports,
        packages=packages,
        ssh=ssh,
        shadow=shadow,
        sudoers=sudoers,
        login_defs=login_defs,
        file_permissions=file_permissions,
        firewall=firewall,
        sysctl=sysctl,
        errors=tuple(errors),
    )


def _safe(
    name: str,
    func: Callable[[], T],
    default: T,
    errors: list[str],
    logger: logging.Logger,
) -> T:
    try:
        return func()
    except Exception as exc:  # collector isolation: one failure must not abort
        errors.append(f"{name}: {exc}")
        logger.warning("collector %s failed: %s", name, exc)
        return default
