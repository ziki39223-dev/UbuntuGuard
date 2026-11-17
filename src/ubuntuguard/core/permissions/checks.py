"""Platform, privilege and dependency checks."""

from __future__ import annotations

import os
import platform
import shutil
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from ...errors import PermissionDeniedError, UnsupportedPlatformError

SUPPORTED_VERSIONS = ("22.04", "24.04")
OS_RELEASE_PATH = Path("/etc/os-release")


@dataclass(frozen=True)
class EnvironmentStatus:
    os_id: str
    version_id: str
    supported: bool
    is_root: bool
    python_version: str
    missing_dependencies: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "os": {"id": self.os_id, "version": self.version_id},
            "supported": self.supported,
            "is_root": self.is_root,
            "python": self.python_version,
            "missing_dependencies": list(self.missing_dependencies),
        }


def read_os_release(path: Path = OS_RELEASE_PATH) -> dict[str, str]:
    """Parse /etc/os-release key/value pairs; returns empty on missing file."""
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        values[key.strip()] = raw.strip().strip('"').strip("'")
    return values


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def require_root(action: str) -> None:
    if not is_root():
        raise PermissionDeniedError(f"{action} requires root privileges")


def missing_dependencies(names: Iterable[str]) -> tuple[str, ...]:
    return tuple(name for name in names if shutil.which(name) is None)


def check_environment(required: Iterable[str] = ()) -> EnvironmentStatus:
    os_release: Mapping[str, str] = read_os_release()
    os_id = os_release.get("ID", "unknown")
    version_id = os_release.get("VERSION_ID", "unknown")
    supported = os_id == "ubuntu" and version_id in SUPPORTED_VERSIONS
    return EnvironmentStatus(
        os_id=os_id,
        version_id=version_id,
        supported=supported,
        is_root=is_root(),
        python_version=platform.python_version(),
        missing_dependencies=missing_dependencies(required),
    )


def require_supported_platform(status: EnvironmentStatus | None = None) -> EnvironmentStatus:
    current = status or check_environment()
    if not current.supported:
        raise UnsupportedPlatformError(
            f"unsupported platform: {current.os_id} {current.version_id} "
            f"(supported: Ubuntu {' / '.join(SUPPORTED_VERSIONS)})"
        )
    return current
