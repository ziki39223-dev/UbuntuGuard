"""Configuration loading, merging and validation.

Precedence: built-in defaults <- config file <- CLI overrides (handled by callers).
Unknown keys are kept and reported as warnings for forward compatibility.
"""

from __future__ import annotations

import copy
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ...errors import ConfigError
from .defaults import (
    AUDIT_ENGINES,
    DEFAULT_CONFIG_PATH,
    DEFAULTS,
    FAIL_ON_LEVELS,
    FIREWALL_POLICIES,
    LOG_LEVELS,
    PERMIT_ROOT_LOGIN_VALUES,
    SECURITY_INVARIANTS,
)

_PORT_RULE = re.compile(r"^\d{1,5}/(tcp|udp)$")


@dataclass
class Config:
    """Validated effective configuration."""

    data: dict[str, Any]
    path: Path | None
    source: str
    warnings: list[str] = field(default_factory=list)

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, Mapping) or part not in node:
                return default
            node = node[part]
        return node


def resolve_config_path(explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    env_path = os.environ.get("UBUNTUGUARD_CONFIG")
    if env_path:
        return Path(env_path)
    return Path(DEFAULT_CONFIG_PATH)


def load_config(explicit: str | Path | None = None) -> Config:
    """Load and validate configuration, falling back to defaults when absent."""
    path = resolve_config_path(explicit)
    warnings: list[str] = []

    if not path.is_file():
        warnings.append(f"config file not found: {path}; using built-in defaults")
        merged = copy.deepcopy(DEFAULTS)
        source = "defaults"
        resolved_path: Path | None = None
    else:
        raw = _read_yaml(path)
        merged = _deep_merge(copy.deepcopy(DEFAULTS), raw)
        source = "file"
        resolved_path = path
        _warn_unknown_top_level(raw, warnings)

    validate_config(merged)
    return Config(data=merged, path=resolved_path, source=source, warnings=warnings)


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"config root must be a mapping, got {type(raw).__name__}")
    return raw


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        current = base.get(key)
        if isinstance(current, dict) and isinstance(value, Mapping):
            base[key] = _deep_merge(current, value)
        else:
            base[key] = value
    return base


def _warn_unknown_top_level(raw: Mapping[str, Any], warnings: list[str]) -> None:
    for key in raw:
        if key not in DEFAULTS:
            warnings.append(f"unknown config section: {key} (ignored)")


def validate_config(data: Mapping[str, Any]) -> None:
    """Raise ConfigError on invalid types, values or violated invariants."""
    if data.get("version") != 1:
        raise ConfigError(f"unsupported config version: {data.get('version')!r} (expected 1)")

    general = _section(data, "general")
    _require_choice(general, "general.log_level", LOG_LEVELS)
    _require_str(general, "general.log_dir")
    _require_str(general, "general.state_dir")
    _require_int(general, "general.timeout_seconds", minimum=1)

    audit = _section(data, "audit")
    _require_choice(audit, "audit.fail_on", FAIL_ON_LEVELS)
    _require_choice(audit, "audit.engine", AUDIT_ENGINES)
    _require_str_list(audit, "audit.include")

    harden = _section(data, "harden")
    for key in (
        "require_confirmation",
        "backup_before_change",
        "verify_after_apply",
        "rollback_on_failure",
    ):
        _require_bool(harden, f"harden.{key}")
    for dotted, expected in SECURITY_INVARIANTS:
        if _get_dotted(data, dotted) is not expected:
            raise ConfigError(f"{dotted} must be {expected!s} (security invariant)")

    ssh = _section(data, "ssh")
    _require_int(ssh, "ssh.port", minimum=1, maximum=65535)
    _require_choice(ssh, "ssh.permit_root_login", PERMIT_ROOT_LOGIN_VALUES)
    _require_bool(ssh, "ssh.password_authentication")
    _require_str_list(ssh, "ssh.allow_users")

    firewall = _section(data, "firewall")
    _require_bool(firewall, "firewall.enabled")
    _require_choice(firewall, "firewall.default_incoming", FIREWALL_POLICIES)
    ports = _require_str_list(firewall, "firewall.allow_ports")
    for port in ports:
        if not _PORT_RULE.match(port):
            raise ConfigError(
                f"firewall.allow_ports entry invalid: {port!r} (expected e.g. 22/tcp)"
            )

    fail2ban = _section(data, "fail2ban")
    _require_bool(fail2ban, "fail2ban.enabled")
    _require_int(fail2ban, "fail2ban.maxretry", minimum=1)
    _require_str(fail2ban, "fail2ban.bantime")

    sysctl = _section(data, "sysctl")
    for key, value in sysctl.items():
        if not isinstance(value, int) or isinstance(value, bool):
            raise ConfigError(f"sysctl.{key} must be an integer")

    monitoring = _section(data, "monitoring")
    thresholds = _require_mapping(monitoring, "monitoring.thresholds")
    for key in ("cpu_percent", "memory_percent", "disk_percent"):
        _require_int(thresholds, f"monitoring.thresholds.{key}", minimum=0, maximum=100)
    _require_number(thresholds, "monitoring.thresholds.load_per_core", minimum=0.0)
    _require_str_list(monitoring, "monitoring.services")
    _require_str_list(monitoring, "monitoring.disk_mounts")
    node_exporter = _require_mapping(monitoring, "monitoring.node_exporter")
    _require_bool(node_exporter, "monitoring.node_exporter.enabled")
    _require_str(node_exporter, "monitoring.node_exporter.url")
    webhook = _require_mapping(monitoring, "monitoring.webhook")
    _require_bool(webhook, "monitoring.webhook.enabled")
    _require_str(webhook, "monitoring.webhook.url")
    _require_int(webhook, "monitoring.webhook.timeout_seconds", minimum=1)

    backup = _section(data, "backup")
    _require_str(backup, "backup.dir")
    _require_bool(backup, "backup.compress")
    _require_int(backup, "backup.retention_days", minimum=1)
    _require_int(backup, "backup.retention_count", minimum=1)

    notifications = _section(data, "notifications")
    _require_int(notifications, "notifications.retry", minimum=0)
    _require_number(notifications, "notifications.retry_interval_seconds", minimum=0.0)


def _get_dotted(data: Mapping[str, Any], dotted: str) -> Any:
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _section(data: Mapping[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _require_mapping(section: Mapping[str, Any], path: str) -> dict[str, Any]:
    key = path.split(".")[-1]
    value = section.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must be a mapping")
    return value


def _require_bool(section: Mapping[str, Any], path: str) -> bool:
    value = section.get(path.split(".")[-1])
    if not isinstance(value, bool):
        raise ConfigError(f"{path} must be a boolean")
    return value


def _require_int(
    section: Mapping[str, Any],
    path: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    value = section.get(path.split(".")[-1])
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{path} must be an integer")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{path} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{path} must be <= {maximum}")
    return value


def _require_number(section: Mapping[str, Any], path: str, minimum: float | None = None) -> float:
    value = section.get(path.split(".")[-1])
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{path} must be a number")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{path} must be >= {minimum}")
    return float(value)


def _require_str(section: Mapping[str, Any], path: str) -> str:
    value = section.get(path.split(".")[-1])
    if not isinstance(value, str):
        raise ConfigError(f"{path} must be a string")
    return value


def _require_str_list(section: Mapping[str, Any], path: str) -> list[str]:
    value = section.get(path.split(".")[-1])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{path} must be a list of strings")
    return list(value)


def _require_choice(section: Mapping[str, Any], path: str, allowed: frozenset[str]) -> str:
    value = _require_str(section, path)
    if value not in allowed:
        raise ConfigError(f"{path} must be one of: {', '.join(sorted(allowed))}")
    return value
