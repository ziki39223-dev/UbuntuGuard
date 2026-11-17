"""Default backup targets and path expansion."""

from __future__ import annotations

import glob
from collections.abc import Iterable
from pathlib import Path

DEFAULT_BACKUP_PATHS: tuple[str, ...] = (
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d",
    "/etc/ssh/sshd_config.d/00-ubuntuguard.conf",
    "/etc/sysctl.d/99-ubuntuguard.conf",
    "/etc/fail2ban/jail.d",
    "/etc/fail2ban/jail.d/99-ubuntuguard.local",
    "/etc/ufw",
)


def expand_paths(
    patterns: Iterable[str], include_missing: bool = False
) -> tuple[Path, ...]:
    """Expand files, directories and glob patterns into a deduplicated file list.

    With ``include_missing`` literal paths that do not exist are kept so the
    snapshot records their absence and restore can remove them later.
    """
    collected: list[Path] = []
    for raw in patterns:
        if any(character in raw for character in "*?["):
            for match in sorted(glob.glob(raw, recursive=True)):
                candidate = Path(match)
                if candidate.is_file():
                    collected.append(candidate)
            continue
        path = Path(raw)
        if path.is_dir():
            collected.extend(sorted(item for item in path.rglob("*") if item.is_file()))
        elif path.is_file() or include_missing:
            collected.append(path)

    seen: set[str] = set()
    result: list[Path] = []
    for path in collected:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return tuple(result)
