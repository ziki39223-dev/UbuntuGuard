"""Auditd and AIDE integrity status collection."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..core.executor import CommandExecutor
from ..errors import UbuntuGuardError

DEFAULT_RULE_SOURCES = (
    Path("/etc/audit/rules.d"),
    Path("/etc/audit/audit.rules"),
)
DEFAULT_AIDE_DATABASES = (
    Path("/var/lib/aide/aide.db"),
    Path("/var/lib/aide/aide.db.gz"),
)
_WATCH_RE = re.compile(r"^\s*-w\s+(?P<path>\S+)")


@dataclass(frozen=True)
class AuditdStatus:
    available: bool = False
    active: bool = False
    rule_count: int = 0
    watched_paths: tuple[str, ...] = ()
    files: tuple[str, ...] = ()


@dataclass(frozen=True)
class AideStatus:
    installed: bool = False
    database_present: bool = False
    database_path: str | None = None
    last_modified: str | None = None


def collect_auditd(
    executor: CommandExecutor,
    sources: tuple[Path, ...] = DEFAULT_RULE_SOURCES,
) -> AuditdStatus:
    files: list[str] = []
    rule_count = 0
    watched: set[str] = set()

    for source in sources:
        candidates = (
            sorted(source.glob("*.rules")) if source.is_dir() else [source]
        )
        for candidate in candidates:
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files.append(str(candidate))
            count, paths = parse_audit_rules(text)
            rule_count += count
            watched.update(paths)

    active = False
    try:
        result = executor.run(["systemctl", "is-active", "auditd"])
        active = result.ok and result.stdout.strip() == "active"
    except UbuntuGuardError:
        active = False

    available = bool(files) or shutil.which("auditctl") is not None
    return AuditdStatus(
        available=available,
        active=active,
        rule_count=rule_count,
        watched_paths=tuple(sorted(watched)),
        files=tuple(files),
    )


def parse_audit_rules(text: str) -> tuple[int, tuple[str, ...]]:
    count = 0
    watched: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-"):
            count += 1
        match = _WATCH_RE.match(stripped)
        if match:
            watched.append(match.group("path"))
    return count, tuple(watched)


def collect_aide(
    candidates: tuple[Path, ...] = DEFAULT_AIDE_DATABASES,
    installed: bool | None = None,
) -> AideStatus:
    present = shutil.which("aide") is not None if installed is None else installed
    for candidate in candidates:
        if not candidate.is_file():
            continue
        modified = datetime.fromtimestamp(
            candidate.stat().st_mtime, tz=timezone.utc
        ).astimezone()
        return AideStatus(
            installed=present,
            database_present=True,
            database_path=str(candidate),
            last_modified=modified.isoformat(timespec="seconds"),
        )
    return AideStatus(installed=present)
