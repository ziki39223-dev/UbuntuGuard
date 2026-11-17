"""Built-in configuration defaults.

Keep in sync with the schema documented in docs/TECHNICAL_DESIGN.md.
"""

from __future__ import annotations

from typing import Any

DEFAULT_CONFIG_PATH = "/etc/ubuntuguard/config.yaml"

DEFAULTS: dict[str, Any] = {
    "version": 1,
    "general": {
        "log_level": "info",
        "log_dir": "/var/log/ubuntuguard",
        "state_dir": "/var/lib/ubuntuguard",
        "timeout_seconds": 30,
    },
    "audit": {
        "fail_on": "high",
        "include": ["ssh", "users", "firewall", "sysctl", "permissions", "ports"],
        "engine": "native",
    },
    "harden": {
        "require_confirmation": True,
        "backup_before_change": True,
        "verify_after_apply": True,
        "rollback_on_failure": True,
    },
    "ssh": {
        "port": 22,
        "permit_root_login": "prohibit-password",
        "password_authentication": False,
        "allow_users": [],
    },
    "firewall": {
        "enabled": True,
        "default_incoming": "deny",
        "allow_ports": ["22/tcp"],
    },
    "fail2ban": {
        "enabled": True,
        "maxretry": 5,
        "bantime": "1h",
    },
    "sysctl": {
        "net.ipv4.conf.all.rp_filter": 1,
        "net.ipv4.tcp_syncookies": 1,
        "net.ipv6.conf.all.disable_ipv6": 0,
    },
    "monitoring": {
        "thresholds": {
            "cpu_percent": 85,
            "memory_percent": 85,
            "disk_percent": 85,
            "load_per_core": 1.5,
        },
        "disk_mounts": ["/"],
        "services": ["ssh"],
        "node_exporter": {
            "enabled": False,
            "url": "http://127.0.0.1:9100/metrics",
        },
        "webhook": {
            "enabled": False,
            "url": "",
            "timeout_seconds": 5,
        },
    },
    "backup": {
        "dir": "/var/lib/ubuntuguard/backups",
        "compress": True,
        "retention_days": 30,
        "retention_count": 20,
    },
    "notifications": {
        "retry": 2,
        "retry_interval_seconds": 3,
    },
}

# Security invariants: these must never be disabled through configuration.
SECURITY_INVARIANTS: tuple[tuple[str, Any], ...] = (
    ("harden.require_confirmation", True),
    ("harden.backup_before_change", True),
)

LOG_LEVELS = frozenset({"debug", "info", "warning", "error"})
FAIL_ON_LEVELS = frozenset({"none", "low", "medium", "high", "critical"})
AUDIT_ENGINES = frozenset({"native", "lynis", "all"})
PERMIT_ROOT_LOGIN_VALUES = frozenset(
    {"yes", "no", "prohibit-password", "forced-commands-only"}
)
FIREWALL_POLICIES = frozenset({"allow", "deny", "reject"})
