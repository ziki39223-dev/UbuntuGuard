"""Critical file permission collector (metadata only, never contents)."""

from __future__ import annotations

import os
from collections.abc import Iterable

from ..models import FilePermission

DEFAULT_CRITICAL_FILES = (
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
)


def collect_permissions(
    paths: Iterable[str] = DEFAULT_CRITICAL_FILES,
) -> tuple[FilePermission, ...]:
    result: list[FilePermission] = []
    for raw_path in paths:
        try:
            stats = os.stat(raw_path)
        except OSError:
            result.append(FilePermission(path=raw_path))
            continue
        result.append(
            FilePermission(
                path=raw_path,
                mode=stats.st_mode & 0o7777,
                uid=stats.st_uid,
                gid=stats.st_gid,
            )
        )
    return tuple(result)


def permission_for(
    permissions: tuple[FilePermission, ...], path: str
) -> FilePermission | None:
    for entry in permissions:
        if entry.path == path:
            return entry
    return None


__all__ = ["DEFAULT_CRITICAL_FILES", "collect_permissions", "permission_for"]
