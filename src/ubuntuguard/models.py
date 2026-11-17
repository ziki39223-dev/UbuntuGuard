"""Shared data structures used across modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class CommandResult:
    """Structured result of a system command execution."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass(frozen=True)
class Finding:
    """Single audit finding. Evidence must point at real system state."""

    id: str
    title: str
    severity: Severity
    category: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class HostInfo:
    hostname: str
    os_id: str
    os_version: str
    os_pretty_name: str
    kernel: str
    uptime_seconds: float | None = None


@dataclass(frozen=True)
class CpuInfo:
    model: str
    cores: int
    load_average: tuple[float, ...] = ()


@dataclass(frozen=True)
class MemoryInfo:
    total_bytes: int
    available_bytes: int
    used_bytes: int
    used_percent: float
    swap_total_bytes: int = 0
    swap_used_bytes: int = 0


@dataclass(frozen=True)
class DiskInfo:
    device: str
    mountpoint: str
    fstype: str
    total_bytes: int
    used_bytes: int
    used_percent: float


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    addresses: tuple[str, ...]
    mac: str | None = None
    state: str | None = None


@dataclass(frozen=True)
class NetworkInfo:
    interfaces: tuple[NetworkInterface, ...] = ()
    default_gateways: tuple[str, ...] = ()


@dataclass(frozen=True)
class UserInfo:
    name: str
    uid: int
    gid: int
    group: str
    home: str
    shell: str
    supplemental_groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int
    user: str
    cpu_percent: float
    mem_percent: float
    command: str


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    load: str
    active: str
    sub: str
    description: str


@dataclass(frozen=True)
class PortInfo:
    protocol: str
    local_address: str
    port: int
    state: str
    process: str | None = None


@dataclass(frozen=True)
class PackageInfo:
    installed: int = 0
    upgradable: int = 0
    reboot_required: bool = False
    fail2ban_installed: bool = False


@dataclass(frozen=True)
class SshInfo:
    """Effective sshd configuration (preferred source: `sshd -T`)."""

    effective: dict[str, str] = field(default_factory=dict)
    source: str = "unavailable"
    config_files: tuple[str, ...] = ()

    def get(self, key: str) -> str | None:
        return self.effective.get(key.lower())


@dataclass(frozen=True)
class ShadowEntry:
    name: str
    password: str
    max_days: str = ""
    warn_days: str = ""


@dataclass(frozen=True)
class ShadowInfo:
    readable: bool = False
    entries: tuple[ShadowEntry, ...] = ()


@dataclass(frozen=True)
class SudoEntry:
    file: str
    line: int
    text: str
    nopasswd: bool


@dataclass(frozen=True)
class SudoersInfo:
    readable: bool = False
    entries: tuple[SudoEntry, ...] = ()


@dataclass(frozen=True)
class LoginDefsInfo:
    readable: bool = False
    values: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class FilePermission:
    path: str
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None


@dataclass(frozen=True)
class FirewallRule:
    to: str
    action: str = ""
    source: str = ""


@dataclass(frozen=True)
class FirewallInfo:
    available: bool = False
    readable: bool = False
    active: bool = False
    default_incoming: str = ""
    default_outgoing: str = ""
    rules: tuple[FirewallRule, ...] = ()


@dataclass(frozen=True)
class SysctlInfo:
    values: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Change:
    """Single reversible system change."""

    target: str
    method: str
    before: str = ""
    after: str = ""
    note: str = ""
    rollback: str = ""


@dataclass(frozen=True)
class ChangePlan:
    """Previewable set of changes produced by one hardening action."""

    action: str
    title: str
    changes: tuple[Change, ...]
    risk: str = ""
    targets: tuple[str, ...] = ()


@dataclass(frozen=True)
class ActionResult:
    action: str
    applied: bool
    verified: bool
    detail: str = ""


@dataclass(frozen=True)
class SystemSnapshot:
    """Point-in-time, read-only view of the host used by audit rules."""

    collected_at: str
    host: HostInfo
    cpu: CpuInfo
    memory: MemoryInfo
    disks: tuple[DiskInfo, ...] = ()
    network: NetworkInfo = field(default_factory=NetworkInfo)
    users: tuple[UserInfo, ...] = ()
    processes: tuple[ProcessInfo, ...] = ()
    services: tuple[ServiceInfo, ...] = ()
    ports: tuple[PortInfo, ...] = ()
    packages: PackageInfo = field(default_factory=PackageInfo)
    ssh: SshInfo = field(default_factory=SshInfo)
    shadow: ShadowInfo = field(default_factory=ShadowInfo)
    sudoers: SudoersInfo = field(default_factory=SudoersInfo)
    login_defs: LoginDefsInfo = field(default_factory=LoginDefsInfo)
    file_permissions: tuple[FilePermission, ...] = ()
    firewall: FirewallInfo = field(default_factory=FirewallInfo)
    sysctl: SysctlInfo = field(default_factory=SysctlInfo)
    errors: tuple[str, ...] = ()
